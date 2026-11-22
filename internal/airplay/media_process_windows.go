package airplay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

func mediaFilePath(path string) string {
	if len(path) >= 4 && path[0] == '/' && path[2:4] == ":/" {
		path = path[1:]
	}
	return filepath.FromSlash(path)
}

func mediaURIPath(path string) string {
	path = filepath.ToSlash(path)
	if len(path) >= 3 && path[1:3] == ":/" {
		return "/" + path
	}
	return path
}

func launchMediaGraphProcess(ctx context.Context, uri string, videoArgs, audioArgs []string) (*runningGStreamerPipeline, io.ReadCloser, error) {
	// Windows exec cannot inherit an extra POSIX descriptor. Keep video on
	// stdout and deliver audio over a per-playback local named pipe.
	name := `\\.\pipe\doubletake-media-` + rand.Text()
	pcm, err := newMediaPipeReader(name)
	if err != nil {
		return nil, nil, fmt.Errorf("create media audio pipe: %w", err)
	}

	index := slices.Index(audioArgs, "fdsink")
	if index < 0 {
		_ = pcm.Close()
		return nil, nil, errors.New("media audio pipeline has no output sink")
	}
	audioArgs = append(audioArgs[:index], "filesink", "location="+filepath.ToSlash(name), "buffer-mode=unbuffered", "sync=false", "async=false")
	args := append([]string{"--quiet"}, mediaGraphArgs(uri, videoArgs, audioArgs)...)
	pipeline, err := launchGStreamerProcess(ctx, args, nil, uri == "fd://0")
	if err != nil {
		_ = pcm.Close()
		return nil, nil, err
	}
	done := make(chan error, 1)
	wait := pipeline.waitResult
	pipeline.waitResult = done
	go func() {
		err := <-wait
		// playbin never opens this sink when the input has no audio.
		pcm.cancelUnconnected()
		done <- err
	}()
	return pipeline, pcm, nil
}

type mediaPipeReader struct {
	handle     windows.Handle
	connect    windows.Overlapped
	readEvent  windows.Handle
	ready      chan struct{}
	connectErr error

	// Closing cancels outstanding operations before releasing the file and
	// events. reads protects the event and serializes calls to Read.
	mu     sync.Mutex
	reads  sync.Mutex
	closed bool
}

func newMediaPipeReader(name string) (*mediaPipeReader, error) {
	path, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	acl, err := windows.SecurityDescriptorFromString("D:P(A;;GA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return nil, err
	}
	attrs := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: acl}
	handle, err := windows.CreateNamedPipe(path,
		windows.PIPE_ACCESS_INBOUND|windows.FILE_FLAG_OVERLAPPED|windows.FILE_FLAG_FIRST_PIPE_INSTANCE,
		windows.PIPE_TYPE_BYTE|windows.PIPE_REJECT_REMOTE_CLIENTS, 1, 0, 64<<10, 0, &attrs)
	if err != nil {
		return nil, err
	}
	connectEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	readEvent, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		_ = windows.CloseHandle(connectEvent)
		_ = windows.CloseHandle(handle)
		return nil, err
	}
	p := &mediaPipeReader{
		handle: handle, connect: windows.Overlapped{HEvent: connectEvent},
		readEvent: readEvent, ready: make(chan struct{}),
	}
	switch err := windows.ConnectNamedPipe(handle, &p.connect); {
	case errors.Is(err, windows.ERROR_IO_PENDING):
		go func() {
			var n uint32
			p.connectErr = windows.GetOverlappedResult(handle, &p.connect, &n, true)
			close(p.ready)
		}()
	case err == nil || errors.Is(err, windows.ERROR_PIPE_CONNECTED):
		close(p.ready)
	default:
		close(p.ready)
		_ = p.Close()
		return nil, err
	}
	return p, nil
}

func (p *mediaPipeReader) cancelUnconnected() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		_ = windows.CancelIoEx(p.handle, &p.connect)
	}
}

func (p *mediaPipeReader) Read(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	<-p.ready
	if errors.Is(p.connectErr, windows.ERROR_OPERATION_ABORTED) {
		return 0, io.EOF
	}
	if p.connectErr != nil {
		return 0, p.connectErr
	}

	p.reads.Lock()
	defer p.reads.Unlock()
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return 0, os.ErrClosed
	}
	if err := windows.ResetEvent(p.readEvent); err != nil {
		p.mu.Unlock()
		return 0, err
	}
	var n uint32
	operation := windows.Overlapped{HEvent: p.readEvent}
	// The kernel continues using these addresses after ReadFile returns pending.
	var pin runtime.Pinner
	pin.Pin(&data[0])
	pin.Pin(&n)
	pin.Pin(&operation)
	defer pin.Unpin()
	err := windows.ReadFile(p.handle, data, &n, &operation)
	p.mu.Unlock()
	if errors.Is(err, windows.ERROR_IO_PENDING) {
		err = windows.GetOverlappedResult(p.handle, &operation, &n, true)
	}
	if errors.Is(err, windows.ERROR_BROKEN_PIPE) || errors.Is(err, windows.ERROR_NO_DATA) {
		err = io.EOF
	}
	return int(n), err
}

func (p *mediaPipeReader) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	_ = windows.CancelIoEx(p.handle, nil)
	p.mu.Unlock()
	<-p.ready
	p.reads.Lock()
	defer p.reads.Unlock()
	_ = windows.CloseHandle(p.readEvent)
	_ = windows.CloseHandle(p.connect.HEvent)
	return windows.CloseHandle(p.handle)
}
