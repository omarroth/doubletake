package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"doubletake/internal/airplay"
)

func TestDaemonStreamsToTwoPasswordReceivers(t *testing.T) {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("gst-launch-1.0 is required for the headless capture integration test")
	}
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		t.Skip("GStreamer openh264enc is required for the headless capture integration test")
	}

	receiverCtx, cancelReceivers := context.WithCancel(context.Background())
	defer cancelReceivers()
	type runningReceiver struct {
		server *airplay.ReceiverServer
		done   chan error
		code   string
	}
	receivers := make([]runningReceiver, 0, 2)
	defer func() {
		cancelReceivers()
		for i, receiver := range receivers {
			_ = receiver.server.Close()
			select {
			case err := <-receiver.done:
				if err != nil {
					t.Errorf("receiver %d stopped with error: %v", i+1, err)
				}
			case <-time.After(3 * time.Second):
				t.Errorf("receiver %d did not stop", i+1)
			}
		}
	}()
	for i, cfg := range []struct {
		address string
		name    string
		code    string
	}{
		{address: "127.0.0.1:0", name: "First TV", code: "first password"},
		{address: "127.0.0.2:0", name: "Second TV", code: "second password"},
	} {
		server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
			ListenAddress: cfg.address,
			Profile:       airplay.ReceiverProfileRoku,
			Auth:          airplay.ReceiverAuthCombined,
			Code:          cfg.code,
			Name:          cfg.name,
			Logger:        log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("start receiver %d: %v", i+1, err)
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(receiverCtx) }()
		receivers = append(receivers, runningReceiver{server: server, done: done, code: cfg.code})
	}

	socketPath := filepath.Join(t.TempDir(), "doubletake.sock")
	d, err := New(Config{
		SocketPath:  socketPath,
		CredBackend: "file",
		CredFile:    filepath.Join(t.TempDir(), "credentials.json"),
		FPS:         10,
		Bitrate:     500,
		HWAccel:     "openh264",
		TestMode:    true,
		NoAudio:     false,
	})
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- d.Run(daemonCtx) }()
	defer func() {
		cancelDaemon()
		d.Shutdown()
		select {
		case err := <-daemonDone:
			if err != nil {
				t.Errorf("daemon stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	}()
	waitForDaemonSocket(t, socketPath)

	for i, receiver := range receivers {
		addr := receiver.server.Addr().(*net.TCPAddr)
		resp := sendDaemonSocketRequest(t, socketPath, Request{
			Cmd:    "connect",
			Target: addr.IP.String(),
			Port:   addr.Port,
		})
		if !resp.OK {
			t.Fatalf("queue receiver %d: %+v", i+1, resp)
		}
	}

	status := waitForDaemonSocketStatus(t, socketPath, 10*time.Second, func(resp Response) bool {
		return len(resp.Streams) == 2 &&
			resp.Streams[0].State == StatePINRequired &&
			resp.Streams[1].State == StatePINRequired
	})
	for i, stream := range status.Streams {
		if stream.CredentialKind != CredentialKindPassword {
			t.Fatalf("stream %d credential kind = %q, want password", i+1, stream.CredentialKind)
		}
	}

	// Submit each password to its own still-live pairing connection. The first
	// target may advance while the second remains independently promptable.
	firstAddr := receivers[0].server.Addr().(*net.TCPAddr)
	resp := sendDaemonSocketRequest(t, socketPath, Request{
		Cmd:    "connect",
		Target: firstAddr.IP.String(),
		Pin:    receivers[0].code,
	})
	if !resp.OK {
		t.Fatalf("submit first password: %+v", resp)
	}
	status = waitForDaemonSocketStatus(t, socketPath, 3*time.Second, func(resp Response) bool {
		for _, stream := range resp.Streams {
			if stream.DeviceIP == receivers[1].server.Addr().(*net.TCPAddr).IP.String() {
				return stream.State == StatePINRequired && stream.CredentialKind == CredentialKindPassword
			}
		}
		return false
	})
	if !status.NeedsCredential {
		t.Fatalf("second prompt disappeared after first submission: %+v", status)
	}

	secondAddr := receivers[1].server.Addr().(*net.TCPAddr)
	resp = sendDaemonSocketRequest(t, socketPath, Request{
		Cmd:    "connect",
		Target: secondAddr.IP.String(),
		Pin:    receivers[1].code,
	})
	if !resp.OK {
		t.Fatalf("submit second password: %+v", resp)
	}

	waitForDaemonSocketStatus(t, socketPath, 15*time.Second, func(resp Response) bool {
		if len(resp.Streams) != 2 {
			return false
		}
		for _, stream := range resp.Streams {
			if stream.State != StateStreaming {
				return false
			}
		}
		return true
	})

	deadline := time.Now().Add(8 * time.Second)
	for {
		firstStats := receivers[0].server.Stats()
		secondStats := receivers[1].server.Stats()
		if firstStats.VideoPackets >= 3 && secondStats.VideoPackets >= 3 && firstStats.AudioPackets >= 5 && secondStats.AudioPackets >= 5 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("both receivers did not get sustained video: first=%+v second=%+v", firstStats, secondStats)
		}
		time.Sleep(10 * time.Millisecond)
	}
	d.mu.Lock()
	if len(d.captureGroups) != 1 {
		t.Errorf("equal receiver ceilings created %d capture groups, want 1", len(d.captureGroups))
	}
	d.mu.Unlock()
	status = sendDaemonSocketRequest(t, socketPath, Request{Cmd: "status"})
	if status.SharedAudio.Sources != 1 || status.SharedAudio.Encoders != 1 || status.SharedAudio.Receivers != 2 || status.VideoEncoders != 1 || status.PlayoutLatencyMS != 250 {
		t.Fatalf("multiroom sharing = %+v", status)
	}
	before := receivers[1].server.Stats().AudioPackets
	if resp := sendDaemonSocketRequest(t, socketPath, Request{Cmd: "disconnect", Target: firstAddr.IP.String()}); !resp.OK {
		t.Fatal(resp.Error)
	}
	waitForDaemonSocketStatus(t, socketPath, 5*time.Second, func(resp Response) bool {
		return len(resp.Streams) == 1 && resp.SharedAudio.Sources == 1 && resp.SharedAudio.Encoders == 1 && resp.SharedAudio.Receivers == 1 && receivers[1].server.Stats().AudioPackets > before+5
	})
}

func TestDaemonCaptureGroupsRespectReceiverCeilingsInEitherOrder(t *testing.T) {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("gst-launch-1.0 is required for the headless capture integration test")
	}
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		t.Skip("GStreamer openh264enc is required for the headless capture integration test")
	}

	tests := []struct {
		name  string
		first [2]int
		last  [2]int
	}{
		{name: "1080p then 720p", first: [2]int{1920, 1080}, last: [2]int{1280, 720}},
		{name: "720p then 1080p", first: [2]int{1280, 720}, last: [2]int{1920, 1080}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			testDaemonCaptureGroupOrder(t, test.first, test.last)
		})
	}
}

func testDaemonCaptureGroupOrder(t *testing.T, firstSize, secondSize [2]int) {
	t.Helper()
	receiverCtx, cancelReceivers := context.WithCancel(context.Background())
	t.Cleanup(cancelReceivers)

	type runningReceiver struct {
		server *airplay.ReceiverServer
		done   chan error
		max    [2]int
	}
	receivers := make([]runningReceiver, 0, 2)
	for index, cfg := range []struct {
		address string
		size    [2]int
	}{
		{address: "127.0.0.1:0", size: firstSize},
		{address: "127.0.0.2:0", size: secondSize},
	} {
		server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
			ListenAddress: cfg.address,
			Profile:       airplay.ReceiverProfileRoku,
			Name:          fmt.Sprintf("Canvas receiver %d", index+1),
			DisplayWidth:  cfg.size[0],
			DisplayHeight: cfg.size[1],
			Logger:        log.New(io.Discard, "", 0),
		})
		if err != nil {
			t.Fatalf("start receiver %d: %v", index+1, err)
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(receiverCtx) }()
		receivers = append(receivers, runningReceiver{server: server, done: done, max: cfg.size})
	}
	t.Cleanup(func() {
		cancelReceivers()
		for index, receiver := range receivers {
			_ = receiver.server.Close()
			select {
			case err := <-receiver.done:
				if err != nil {
					t.Errorf("receiver %d stopped with error: %v", index+1, err)
				}
			case <-time.After(3 * time.Second):
				t.Errorf("receiver %d did not stop", index+1)
			}
		}
	})

	socketPath := filepath.Join(t.TempDir(), "doubletake.sock")
	d, err := New(Config{
		SocketPath:  socketPath,
		CredBackend: "file",
		CredFile:    filepath.Join(t.TempDir(), "credentials.json"),
		FPS:         10,
		Bitrate:     500,
		HWAccel:     "openh264",
		TestMode:    true,
		NoAudio:     true,
	})
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	daemonCtx, cancelDaemon := context.WithCancel(context.Background())
	daemonDone := make(chan error, 1)
	go func() { daemonDone <- d.Run(daemonCtx) }()
	t.Cleanup(func() {
		cancelDaemon()
		d.Shutdown()
		select {
		case err := <-daemonDone:
			if err != nil {
				t.Errorf("daemon stopped with error: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	waitForDaemonSocket(t, socketPath)

	connect := func(receiver runningReceiver) string {
		addr := receiver.server.Addr().(*net.TCPAddr)
		target := addr.IP.String()
		resp := sendDaemonSocketRequest(t, socketPath, Request{
			Cmd:    "connect",
			Target: target,
			Port:   addr.Port,
		})
		if !resp.OK {
			t.Fatalf("queue %s receiver: %+v", target, resp)
		}
		waitForDaemonSocketStatus(t, socketPath, 15*time.Second, func(resp Response) bool {
			for _, stream := range resp.Streams {
				if stream.DeviceIP == target {
					return stream.State == StateStreaming
				}
			}
			return false
		})
		waitForReceiverVideoSize(t, receiver.server, receiver.max, 15*time.Second)
		return target
	}

	firstTarget := connect(receivers[0])
	firstBeforeJoin := receivers[0].server.Stats().VideoPackets
	secondTarget := connect(receivers[1])
	secondBeforeSustain := receivers[1].server.Stats().VideoPackets

	deadline := time.Now().Add(10 * time.Second)
	for {
		firstStats := receivers[0].server.Stats()
		secondStats := receivers[1].server.Stats()
		status := sendDaemonSocketRequest(t, socketPath, Request{Cmd: "status"})
		streaming := len(status.Streams) == 2
		for _, stream := range status.Streams {
			if stream.State != StateStreaming {
				streaming = false
			}
		}
		if streaming && firstStats.VideoPackets >= firstBeforeJoin+3 && secondStats.VideoPackets >= secondBeforeSustain+3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("resolution groups did not sustain both streams (%s, %s): first=%+v second=%+v status=%+v",
				firstTarget, secondTarget, firstStats, secondStats, status)
		}
		time.Sleep(10 * time.Millisecond)
	}

	d.mu.Lock()
	if len(d.captureGroups) != 2 {
		t.Errorf("active capture groups = %d, want 2", len(d.captureGroups))
	}
	d.mu.Unlock()
}

func waitForReceiverVideoSize(t *testing.T, server *airplay.ReceiverServer, want [2]int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		stats := server.Stats()
		if stats.VideoWidth > 0 && stats.VideoHeight > 0 {
			if stats.VideoWidth > uint64(want[0]) || stats.VideoHeight > uint64(want[1]) {
				t.Fatalf("encoded video %dx%d exceeds receiver ceiling %dx%d", stats.VideoWidth, stats.VideoHeight, want[0], want[1])
			}
			if stats.VideoWidth != uint64(want[0]) || stats.VideoHeight != uint64(want[1]) {
				t.Fatalf("encoded video %dx%d, want capture group canvas %dx%d", stats.VideoWidth, stats.VideoHeight, want[0], want[1])
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("receiver did not observe a codec canvas: %+v", stats)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestDisconnectDuringCaptureGroupStartupLeavesNoCapture(t *testing.T) {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("gst-launch-1.0 is required for the headless capture integration test")
	}
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		t.Skip("GStreamer openh264enc is required for the headless capture integration test")
	}

	d, err := New(Config{
		CredBackend: "file",
		CredFile:    filepath.Join(t.TempDir(), "credentials.json"),
		FPS:         10,
		Bitrate:     500,
		HWAccel:     "openh264",
		TestMode:    true,
		NoAudio:     true,
	})
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	t.Cleanup(d.Shutdown)
	streamCtx, cancelStream := context.WithCancel(context.Background())
	const target = "192.0.2.10"
	entry := &activeStream{
		deviceIP: target,
		state:    StateConnecting,
		cancelFn: cancelStream,
	}
	d.streams[target] = entry

	type captureResult struct {
		broadcast *airplay.BroadcastCapture
		err       error
	}
	resultCh := make(chan captureResult, 1)
	go func() {
		broadcast, err := d.getOrStartCaptureGroup(entry, "", "", 640, 480)
		resultCh <- captureResult{broadcast: broadcast, err: err}
	}()

	// Wait until startup has published its cancellation hook (or completed), then
	// remove the only consumer exactly as a targeted disconnect would.
	deadline := time.Now().Add(3 * time.Second)
	for {
		d.mu.Lock()
		group := d.captureGroups[normalizedVideoCaptureKey(640, 480)]
		startupVisible := group != nil && group.cancel != nil
		d.mu.Unlock()
		if startupVisible {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("capture startup did not publish its cancellation hook")
		}
		time.Sleep(time.Millisecond)
	}
	d.mu.Lock()
	cleanup := d.detachStreamLocked(target)
	d.mu.Unlock()
	cleanup.run()

	var result captureResult
	select {
	case result = <-resultCh:
	case <-time.After(5 * time.Second):
		t.Fatal("capture startup did not stop after its final stream was removed")
	}
	if result.err != nil && !errors.Is(result.err, context.Canceled) {
		t.Fatalf("capture startup returned unexpected error: %v", result.err)
	}
	select {
	case <-streamCtx.Done():
	default:
		t.Fatal("removing the stream did not cancel its context")
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.captureGroups) != 0 {
		t.Fatalf("disconnect left %d orphan capture groups: %+v", len(d.captureGroups), d.captureGroups)
	}
}

func waitForDaemonSocket(t *testing.T, socketPath string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		conn, err := net.DialTimeout("unix", socketPath, 50*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon socket did not become ready: %v", err)
		}
		time.Sleep(time.Millisecond)
	}
}

func sendDaemonSocketRequest(t *testing.T, socketPath string, req Request) Response {
	t.Helper()
	conn, err := net.DialTimeout("unix", socketPath, time.Second)
	if err != nil {
		t.Fatalf("connect to daemon socket: %v", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("set daemon socket deadline: %v", err)
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		t.Fatalf("send daemon request: %v", err)
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		t.Fatalf("read daemon response: %v", err)
	}
	return resp
}

func waitForDaemonSocketStatus(t *testing.T, socketPath string, timeout time.Duration, ready func(Response) bool) Response {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last Response
	for {
		last = sendDaemonSocketRequest(t, socketPath, Request{Cmd: "status"})
		if ready(last) {
			return last
		}
		if last.Error != "" {
			t.Fatalf("daemon failed while waiting for status: %+v", last)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for daemon status; last response: %+v", last)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
