package airplay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

const portalTestInterface = "org.doubletake.PortalTest"

func TestProbeWaylandDisplayUsesCompositorSocket(t *testing.T) {
	runtimeDir := t.TempDir()
	relativePath := "wayland-test"
	absolutePath := filepath.Join(runtimeDir, relativePath)
	listener, err := net.Listen("unix", absolutePath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

	if err := probeWaylandDisplay(context.Background(), relativePath); err != nil {
		t.Fatalf("relative Wayland display probe: %v", err)
	}
	if err := probeWaylandDisplay(context.Background(), absolutePath); err != nil {
		t.Fatalf("absolute Wayland display probe: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := probeWaylandDisplay(canceled, absolutePath); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled Wayland display probe = %v, want context canceled", err)
	}

	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := probeWaylandDisplay(context.Background(), absolutePath); err == nil || !strings.Contains(err.Error(), "reachable compositor") {
		t.Fatalf("closed Wayland display probe = %v, want reachability error", err)
	}

	t.Setenv("XDG_RUNTIME_DIR", "")
	if err := probeWaylandDisplay(context.Background(), "wayland-missing"); err == nil || !strings.Contains(err.Error(), "XDG_RUNTIME_DIR is empty") {
		t.Fatalf("relative Wayland probe without runtime dir = %v, want location error", err)
	}

	regularPath := filepath.Join(runtimeDir, "not-a-socket")
	if err := os.WriteFile(regularPath, []byte("not a display"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := probeWaylandDisplay(context.Background(), regularPath); err == nil {
		t.Fatal("regular file was accepted as a Wayland display")
	}
}

func TestPortalRequestObservesResponseEmittedBeforeMethodReturn(t *testing.T) {
	service, client := startPrivatePortalBus(t)
	path, err := portalPathForToken(client, portalRequestPathPrefix, "immediate")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]dbus.Variant{"proof": dbus.MakeVariant("immediate")}
	mock := &portalRequestMock{conn: service, path: path, result: want}
	if err := service.Export(mock, portalObjectPath, portalTestInterface); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := performPortalRequest(ctx, client, path, 500*time.Millisecond,
		func(callCtx context.Context) (dbus.ObjectPath, error) {
			var handle dbus.ObjectPath
			call := client.Object(portalBusName, portalObjectPath).CallWithContext(
				callCtx, portalTestInterface+".Request", 0)
			if call.Err != nil {
				return "", call.Err
			}
			return handle, call.Store(&handle)
		})
	if err != nil {
		t.Fatal(err)
	}
	if proof, ok := got["proof"]; !ok || proof.Value() != "immediate" {
		t.Fatalf("portal result = %#v, want immediate response proof", got)
	}
}

func TestPortalRequestWaitsForInteractiveResponseBeyondDispatchDeadline(t *testing.T) {
	service, client := startPrivatePortalBus(t)
	path, err := portalPathForToken(client, portalRequestPathPrefix, "interactive")
	if err != nil {
		t.Fatal(err)
	}
	mock := &portalRequestMock{
		conn: service, path: path, emitDelay: 200 * time.Millisecond,
		result: map[string]dbus.Variant{"proof": dbus.MakeVariant("interactive")},
	}
	if err := service.Export(mock, portalObjectPath, portalTestInterface); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	started := time.Now()
	got, err := performPortalRequest(ctx, client, path, 100*time.Millisecond,
		func(callCtx context.Context) (dbus.ObjectPath, error) {
			var handle dbus.ObjectPath
			call := client.Object(portalBusName, portalObjectPath).CallWithContext(
				callCtx, portalTestInterface+".Request", 0)
			if call.Err != nil {
				return "", call.Err
			}
			return handle, call.Store(&handle)
		})
	if err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < mock.emitDelay {
		t.Fatalf("portal response returned after %v, before delayed response at %v", elapsed, mock.emitDelay)
	}
	if proof := got["proof"].Value(); proof != "interactive" {
		t.Fatalf("portal proof = %#v, want interactive", proof)
	}
}

func TestPortalRequestCancellationClosesRemoteRequest(t *testing.T) {
	service, client := startPrivatePortalBus(t)
	path, err := portalPathForToken(client, portalRequestPathPrefix, "canceled")
	if err != nil {
		t.Fatal(err)
	}
	closed := &portalCloseRecorder{}
	mock := &portalRequestMock{conn: service, path: path, closeRecorder: closed, omitResponse: true}
	if err := service.Export(mock, portalObjectPath, portalTestInterface); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = performPortalRequest(ctx, client, path, 500*time.Millisecond,
		func(callCtx context.Context) (dbus.ObjectPath, error) {
			var handle dbus.ObjectPath
			call := client.Object(portalBusName, portalObjectPath).CallWithContext(
				callCtx, portalTestInterface+".Request", 0)
			if call.Err != nil {
				return "", call.Err
			}
			return handle, call.Store(&handle)
		})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("portal cancellation error = %v, want deadline exceeded", err)
	}
	if got := closed.calls.Load(); got != 1 {
		t.Fatalf("Request.Close calls = %d, want 1", got)
	}
}

func TestPortalRequestBoundsMethodDispatch(t *testing.T) {
	_, client := startPrivatePortalBus(t)
	path, err := portalPathForToken(client, portalRequestPathPrefix, "blocked_dispatch")
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = performPortalRequest(context.Background(), client, path, 50*time.Millisecond,
		func(callCtx context.Context) (dbus.ObjectPath, error) {
			<-callCtx.Done()
			return "", callCtx.Err()
		})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("portal dispatch error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("portal dispatch timeout took %v", elapsed)
	}
}

func TestPortalSessionCloseClosesSessionOnceBeforeConnection(t *testing.T) {
	service, client := startPrivatePortalBus(t)
	sessionPath, err := portalPathForToken(client, portalSessionPathPrefix, "session")
	if err != nil {
		t.Fatal(err)
	}
	closed := &portalCloseRecorder{}
	if err := service.Export(closed, sessionPath, portalSessionInterface); err != nil {
		t.Fatal(err)
	}
	session := &screenCastPortalSession{conn: client, sessionPath: sessionPath}

	firstErr := session.Close()
	secondErr := session.Close()
	if !errors.Is(secondErr, firstErr) && secondErr != firstErr {
		t.Fatalf("repeated session Close errors differ: first %v, second %v", firstErr, secondErr)
	}
	if got := closed.calls.Load(); got != 1 {
		t.Fatalf("Session.Close calls = %d, want 1", got)
	}
	if client.Connected() {
		t.Fatal("portal D-Bus connection remains open after Session.Close")
	}
}

type portalRequestMock struct {
	conn          *dbus.Conn
	path          dbus.ObjectPath
	result        map[string]dbus.Variant
	emitDelay     time.Duration
	closeRecorder *portalCloseRecorder
	omitResponse  bool
}

func (p *portalRequestMock) Request() (dbus.ObjectPath, *dbus.Error) {
	if p.closeRecorder != nil {
		if err := p.conn.Export(p.closeRecorder, p.path, portalRequestInterface); err != nil {
			return "", dbus.MakeFailedError(err)
		}
	}
	if p.omitResponse {
		return p.path, nil
	}
	emit := func() {
		_ = p.conn.Emit(p.path, portalRequestInterface+".Response", uint32(0), p.result)
	}
	if p.emitDelay > 0 {
		go func() {
			time.Sleep(p.emitDelay)
			emit()
		}()
	} else {
		emit()
	}
	return p.path, nil
}

type portalCloseRecorder struct {
	calls atomic.Int32
}

func (r *portalCloseRecorder) Close() *dbus.Error {
	r.calls.Add(1)
	return nil
}

func startPrivatePortalBus(t *testing.T) (*dbus.Conn, *dbus.Conn) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon is unavailable")
	}
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start private dbus-daemon: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-waitCh:
			case <-time.After(2 * time.Second):
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				<-waitCh
			}
		})
	}
	t.Cleanup(stop)

	type addressResult struct {
		value string
		err   error
	}
	ready := make(chan addressResult, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		ready <- addressResult{value: strings.TrimSpace(line), err: readErr}
	}()
	var address string
	select {
	case result := <-ready:
		if result.err != nil {
			stop()
			t.Fatalf("read private bus address: %v (%s)", result.err, stderr.String())
		}
		address = result.value
	case <-time.After(3 * time.Second):
		stop()
		t.Fatalf("private dbus-daemon did not become ready (%s)", stderr.String())
	}
	if address == "" {
		stop()
		t.Fatal("private dbus-daemon returned an empty address")
	}

	service, err := dbus.Connect(address)
	if err != nil {
		stop()
		t.Fatalf("connect portal service to private bus: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	reply, err := service.RequestName(portalBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		t.Fatalf("own portal bus name: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("portal bus name reply = %d", reply)
	}

	client, err := dbus.Connect(address)
	if err != nil {
		t.Fatalf("connect portal client to private bus: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return service, client
}
