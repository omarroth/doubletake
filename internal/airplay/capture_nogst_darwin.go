//go:build cgo && no_gstreamer

package airplay

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework AVFoundation -framework AVFAudio -framework ScreenCaptureKit -framework CoreMedia -framework CoreGraphics -framework CoreVideo -framework VideoToolbox
#include <stdint.h>
#include <stdlib.h>
void *dt_mac_open(int audio, int test, int width, int height, int fps, int bitrate,
	int hevc, int hardware, int cursor, int *using_hardware, char **message);
int dt_mac_pull(void *handle, void **data, size_t *length, int64_t *age, char **message);
void dt_mac_retain(void *handle);
void dt_mac_release(void *handle);
void dt_mac_shutdown(void *handle);
int dt_mac_bitrate(void *handle, int bitrate);
void dt_mac_fps(void *handle, int fps);
void dt_mac_keyframe(void *handle);
int dt_mac_dimensions(int *width, int *height);
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"sync"
	"time"
	"unsafe"
)

func init() {
	openNativeVideo = startMacVideo
	openNativeMonitor = func(context.Context) (nativePCMInput, error) {
		stream, _, err := openMacCapture(CaptureConfig{}, true, false, nil)
		if err != nil {
			return nativePCMInput{}, err
		}
		return nativePCMInput{read: stream.read, close: stream.close}, nil
	}
}

type macCapture struct {
	mu     sync.Mutex
	handle unsafe.Pointer
	cancel context.CancelFunc
}

func macBool(v bool) C.int {
	if v {
		return 1
	}
	return 0
}

func openMacCapture(cfg CaptureConfig, audio, test bool, cancel context.CancelFunc) (*macCapture, bool, error) {
	var hardware C.int
	var message *C.char
	handle := C.dt_mac_open(macBool(audio), macBool(test), C.int(cfg.MaxWidth), C.int(cfg.MaxHeight),
		C.int(cfg.FPS), C.int(captureBitrateKbps(cfg)*1000), macBool(cfg.VideoCodec == VideoCodecHEVC),
		macBool(cfg.HWAccel != "none"), macBool(cfg.ShowCursor), &hardware, &message)
	if message != nil {
		defer C.free(unsafe.Pointer(message))
	}
	if handle == nil {
		if message == nil {
			return nil, false, fmt.Errorf("could not allocate native macOS capture")
		}
		return nil, false, fmt.Errorf("macOS capture: %s", C.GoString(message))
	}
	return &macCapture{handle: handle, cancel: cancel}, hardware != 0, nil
}

func startMacVideo(startup, lifetime context.Context, cfg CaptureConfig, test bool) (*ScreenCapture, error) {
	if cfg.FPS <= 0 {
		cfg.FPS = 30
	}
	if cfg.FPS > 240 {
		return nil, fmt.Errorf("native capture supports up to 240 fps")
	}
	if cfg.MaxWidth <= 0 || cfg.MaxHeight <= 0 {
		width, height := C.int(testCaptureWidth), C.int(testCaptureHeight)
		if !test && C.dt_mac_dimensions(&width, &height) == 0 {
			return nil, fmt.Errorf("could not detect the main macOS display size")
		}
		cfg.MaxWidth, cfg.MaxHeight = int(width), int(height)
	}
	cfg.MaxWidth, cfg.MaxHeight = cfg.MaxWidth&^1, cfg.MaxHeight&^1
	if cfg.MaxWidth < 2 || cfg.MaxHeight < 2 || cfg.MaxWidth > 8192 || cfg.MaxHeight > 8192 {
		return nil, fmt.Errorf("unsupported VideoToolbox dimensions %dx%d", cfg.MaxWidth, cfg.MaxHeight)
	}

	bitrate := captureBitrateKbps(cfg)
	if bitrate <= 0 || bitrate > (1<<31-1)/1000 {
		return nil, fmt.Errorf("bitrate is outside the VideoToolbox range")
	}
	ctx, cancel := context.WithCancel(lifetime)
	stream, hardware, err := openMacCapture(cfg, false, test, cancel)
	if err != nil {
		cancel()
		return nil, err
	}
	enc := encoderResult{name: "VideoToolbox", codec: cfg.VideoCodec, hardware: hardware, bitrateKbps: bitrate}
	capture := &ScreenCapture{frames: stream, runtime: stream, cancel: cancel, waitCh: make(chan struct{}), format: captureFormat(cfg, enc)}
	capture.enableAutomaticVideoRateControl(cfg)
	go func() {
		<-ctx.Done()
		stream.close()
		close(capture.waitCh)
	}()
	probe, done := context.WithTimeout(startup, captureStartupProbeTimeout(cfg.FPS))
	defer done()
	if err := probeVideoCaptureStartup(probe, capture, cfg.VideoCodec, true); err != nil {
		capture.Stop()
		return nil, fmt.Errorf("native macOS video startup: %w", err)
	}
	return capture, nil
}

func (s *macCapture) read() (nativePCMBlock, error) {
	s.mu.Lock()
	handle := s.handle
	if handle != nil {
		C.dt_mac_retain(handle)
	}
	s.mu.Unlock()
	if handle == nil {
		return nativePCMBlock{}, io.EOF
	}
	defer C.dt_mac_release(handle)

	var data unsafe.Pointer
	var size C.size_t
	var age C.int64_t
	var message *C.char
	rc := C.dt_mac_pull(handle, &data, &size, &age, &message)
	pts := time.Now().Add(-time.Duration(age))
	if data != nil {
		defer C.free(data)
	}
	if message != nil {
		defer C.free(unsafe.Pointer(message))
		return nativePCMBlock{}, fmt.Errorf("macOS capture: %s", C.GoString(message))
	}
	if rc == 0 {
		return nativePCMBlock{}, io.EOF
	}
	if rc < 0 || size == 0 || size > maxVideoAccessUnitBytes {
		return nativePCMBlock{}, fmt.Errorf("invalid native capture buffer of %d bytes", size)
	}
	return nativePCMBlock{samples: C.GoBytes(data, C.int(size)), pts: pts}, nil
}

func (s *macCapture) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	block, err := s.read()
	return VideoAccessUnit{AnnexB: block.samples, PTS: block.pts}, err
}

func (s *macCapture) setBitrateKbps(bitrate int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return io.ErrClosedPipe
	}
	if bitrate <= 0 || bitrate > (1<<31-1)/1000 {
		return fmt.Errorf("bitrate is outside the VideoToolbox range")
	}
	if status := C.dt_mac_bitrate(s.handle, C.int(bitrate*1000)); status != 0 {
		return fmt.Errorf("VideoToolbox bitrate update failed (%d)", status)
	}
	return nil
}

func (s *macCapture) setFrameRate(fps int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return io.ErrClosedPipe
	}
	if fps <= 0 || fps > 240 {
		return fmt.Errorf("frame rate is outside the native capture range")
	}
	C.dt_mac_fps(s.handle, C.int(fps))
	return nil
}

func (s *macCapture) requestKeyFrame() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.handle == nil {
		return io.ErrClosedPipe
	}
	C.dt_mac_keyframe(s.handle)
	return nil
}

func (s *macCapture) stop() { s.cancel() }

func (s *macCapture) close() {
	s.mu.Lock()
	handle := s.handle
	s.handle = nil
	s.mu.Unlock()
	if handle != nil {
		C.dt_mac_shutdown(handle)
		C.dt_mac_release(handle)
	}
}
