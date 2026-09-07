package airplay

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestCaptureStartupProbeTimeoutTracksFrameRate(t *testing.T) {
	if got := captureStartupProbeTimeout(30); got != minimumCaptureStartupProbeTimeout {
		t.Fatalf("30 fps startup timeout = %v, want %v", got, minimumCaptureStartupProbeTimeout)
	}
	if got := captureStartupProbeTimeout(1); got != 5*time.Second {
		t.Fatalf("1 fps startup timeout = %v, want 5s", got)
	}
	if got := captureStartupProbeTimeout(0); got != minimumCaptureStartupProbeTimeout {
		t.Fatalf("default startup timeout = %v, want %v", got, minimumCaptureStartupProbeTimeout)
	}
}

func TestProbeX11CaptureSourceUsesRealXHandshake(t *testing.T) {
	requireX11CaptureTestStack(t)
	display, stop := startTestXvfb(t)
	if err := probeX11CaptureSource(context.Background(), display, CaptureConfig{}); err != nil {
		t.Fatalf("live X11 source probe: %v", err)
	}

	stop()
	started := time.Now()
	err := probeX11CaptureSource(context.Background(), display, CaptureConfig{})
	if err == nil {
		t.Fatal("stale X11 display passed the source probe")
	}
	for _, want := range []string{display, "GStreamer stderr"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("stale X11 source error %q is missing %q", err, want)
		}
	}
	if elapsed := time.Since(started); elapsed > displaySourceProbeTimeout+time.Second {
		t.Fatalf("stale X11 source probe took %v", elapsed)
	}
}

func TestX11CaptureValidatesAndRetainsLiveXvfbPipeline(t *testing.T) {
	requireX11CaptureTestStack(t)
	display, _ := startTestXvfb(t)
	t.Setenv("DISPLAY", display)

	cfg := CaptureConfig{
		FPS: 10, Bitrate: 500, HWAccel: "none", VideoCodec: VideoCodecH264,
		MaxWidth: 320, MaxHeight: 240,
	}
	encoder, err := detectGstEncoder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelStartup()
	lifetimeCtx, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	capture, err := startPreparedX11Capture(startupCtx, lifetimeCtx, cfg, encoder, true)
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()

	prefetched, ok := capture.frames.(*prefetchedVideoAccessUnitReader)
	if !ok || len(prefetched.units) < 2 {
		t.Fatalf("validated X11 capture retained %#v, want prefetched live access units", capture.frames)
	}
	if capture.cmd == nil || capture.cmd.Process == nil {
		t.Fatal("validated X11 capture did not retain its production process")
	}
	select {
	case <-capture.waitCh:
		t.Fatalf("validated X11 production process exited early: %v", capture.waitErr)
	default:
	}
	if _, err := capture.ReadVideoAccessUnit(); err != nil {
		t.Fatalf("read prefetched X11 access unit: %v", err)
	}
	cancelLifetime()
	select {
	case <-capture.waitCh:
	case <-time.After(3 * time.Second):
		t.Fatal("X11 production process ignored its lifetime context")
	}
}

func TestX11CaptureStartupHonorsPreparationContext(t *testing.T) {
	requireX11CaptureTestStack(t)
	display, _ := startTestXvfb(t)
	t.Setenv("DISPLAY", display)

	cfg := CaptureConfig{
		FPS: 10, Bitrate: 500, HWAccel: "none", VideoCodec: VideoCodecH264,
		MaxWidth: 320, MaxHeight: 240,
	}
	encoder, err := detectGstEncoder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	startupCtx, cancelStartup := context.WithCancel(context.Background())
	cancelStartup()
	lifetimeCtx, cancelLifetime := context.WithCancel(context.Background())
	defer cancelLifetime()
	started := time.Now()
	capture, err := startPreparedX11Capture(startupCtx, lifetimeCtx, cfg, encoder, true)
	if capture != nil {
		capture.Stop()
		t.Fatal("canceled preparation context returned a live X11 capture")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled preparation error = %v, want context canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("canceled X11 startup took %v", elapsed)
	}
}

func TestX11CaptureRejectsStaleDisplayWithGStreamerEvidence(t *testing.T) {
	requireX11CaptureTestStack(t)
	display, stop := startTestXvfb(t)
	stop()
	t.Setenv("DISPLAY", display)

	cfg := CaptureConfig{
		FPS: 30, Bitrate: 500, HWAccel: "none", VideoCodec: VideoCodecH264,
		MaxWidth: 320, MaxHeight: 240,
	}
	encoder, err := detectGstEncoder(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	started := time.Now()
	capture, err := startPreparedX11Capture(ctx, ctx, cfg, encoder, true)
	if capture != nil {
		capture.Stop()
		t.Fatal("stale DISPLAY returned a live capture")
	}
	if err == nil {
		t.Fatal("stale DISPLAY returned no error")
	}
	for _, want := range []string{"failed startup validation", "GStreamer stderr", display} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("stale DISPLAY error %q is missing %q", err, want)
		}
	}
	if elapsed := time.Since(started); elapsed > captureStartupProbeTimeout(cfg.FPS)+2*time.Second {
		t.Fatalf("stale DISPLAY validation took %v", elapsed)
	}
}

func requireX11CaptureTestStack(t *testing.T) {
	t.Helper()
	for _, executable := range []string{"Xvfb", "gst-launch-1.0"} {
		if _, err := exec.LookPath(executable); err != nil {
			t.Skipf("%s is unavailable", executable)
		}
	}
	for _, element := range []string{"ximagesrc", "fakesink", "x264enc", "h264parse", "rtph264pay", "rtponviftimestamp", "rtpstreampay"} {
		if !hasGstElement(element) {
			t.Skipf("GStreamer element %s is unavailable", element)
		}
	}
}

func startTestXvfb(t *testing.T) (string, func()) {
	t.Helper()
	cmd := exec.Command("Xvfb", "-displayfd", "1", "-screen", "0", "320x240x24", "-nolisten", "tcp")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Xvfb: %v", err)
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

	type displayResult struct {
		value string
		err   error
	}
	ready := make(chan displayResult, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		ready <- displayResult{value: strings.TrimSpace(line), err: readErr}
	}()
	select {
	case result := <-ready:
		if result.err != nil {
			stop()
			t.Fatalf("read Xvfb display number: %v (%s)", result.err, stderr.String())
		}
		if _, err := strconv.Atoi(result.value); err != nil {
			stop()
			t.Fatalf("Xvfb display number %q: %v", result.value, err)
		}
		return ":" + result.value, stop
	case <-time.After(3 * time.Second):
		stop()
		t.Fatalf("Xvfb did not become ready (%s)", stderr.String())
	}
	return "", stop
}
