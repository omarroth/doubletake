package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"
)

// CaptureConfig holds screen capture settings.
type CaptureConfig struct {
	Width   int
	Height  int
	FPS     int
	HWAccel string // "auto", "vaapi", "none"
}

// ScreenCapture manages Wayland screen capture via xdg-desktop-portal + ffmpeg.
type ScreenCapture struct {
	cmd      *exec.Cmd
	stdout   io.ReadCloser
	cancel   context.CancelFunc
	pwNodeID uint32
	waitCh   chan error
}

// StartCapture detects the display server (Wayland or X11) and initiates screen
// capture accordingly. On Wayland it uses xdg-desktop-portal + PipeWire; on X11
// it uses GStreamer's ximagesrc.
func StartCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		return startWaylandCapture(ctx, cfg)
	}
	if os.Getenv("DISPLAY") != "" {
		return startX11Capture(ctx, cfg)
	}
	return nil, fmt.Errorf("no display server detected (neither WAYLAND_DISPLAY nor DISPLAY is set)")
}

func startWaylandCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	if err := gstSupportsPipeWire(); err != nil {
		return nil, err
	}

	nodeID, pwFd, err := requestScreencast(ctx)
	if err != nil {
		return nil, fmt.Errorf("screencast portal: %w", err)
	}
	log.Printf("pipewire node ID: %d", nodeID)

	captureCtx, cancel := context.WithCancel(ctx)

	// ExtraFiles are inherited by the child starting at fd 3 (after stdin/stdout/stderr).
	// The PipeWire remote fd will be fd 3 in gst-launch-1.0.
	const pwFdNum = 3
	args := buildGStreamerArgs(cfg, nodeID, pwFdNum)
	log.Printf("[CAPTURE] launching gst-launch-1.0 %s", strings.Join(args, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", args...)
	cmd.ExtraFiles = []*os.File{pwFd}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		pwFd.Close()
		return nil, fmt.Errorf("gst-launch stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		pwFd.Close()
		return nil, fmt.Errorf("gst-launch stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		pwFd.Close()
		return nil, fmt.Errorf("start gst-launch: %w", err)
	}
	// Child inherited the fd; close the parent's copy.
	pwFd.Close()

	go scanCaptureStderr(stderr)
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	return &ScreenCapture{
		cmd:      cmd,
		stdout:   stdout,
		cancel:   cancel,
		pwNodeID: nodeID,
		waitCh:   waitCh,
	}, nil
}

func gstSupportsPipeWire() error {
	if err := exec.Command("gst-inspect-1.0", "pipewiresrc").Run(); err != nil {
		return fmt.Errorf("GStreamer 'pipewiresrc' plugin not found; install gst-pipewire (e.g. gstreamer1.0-pipewire or pipewire-gst)")
	}
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		return fmt.Errorf("GStreamer 'openh264enc' encoder not found; install gst-openh264 (e.g. gstreamer1.0-plugins-bad or gst-plugins-bad)")
	}
	return nil
}

func (sc *ScreenCapture) Read(buf []byte) (int, error) {
	select {
	case err := <-sc.waitCh:
		if err != nil {
			return 0, fmt.Errorf("gst-launch exited: %w", err)
		}
		return 0, io.EOF
	default:
	}
	return sc.stdout.Read(buf)
}

func (sc *ScreenCapture) Stop() {
	if sc.cancel == nil || sc.cmd == nil {
		return
	}
	sc.cancel()
	if sc.cmd.Process != nil {
		_ = sc.cmd.Process.Signal(os.Interrupt)
	}
	done := make(chan struct{})
	go func() {
		if sc.waitCh != nil {
			<-sc.waitCh
		} else {
			_ = sc.cmd.Wait()
		}
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		if sc.cmd.Process != nil {
			_ = sc.cmd.Process.Kill()
		}
		<-done
	}
}

// buildGStreamerArgs constructs the gst-launch-1.0 arguments for encoding the PipeWire stream to H.264 Annex-B.
// pwFdNum is the file descriptor number (in the child process) for the portal's PipeWire remote.
func buildGStreamerArgs(cfg CaptureConfig, nodeID uint32, pwFdNum int) []string {
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	return []string{
		"--quiet",
		// fd= connects to the portal's restricted PipeWire remote (from OpenPipeWireRemote).
		// Without fd=, pipewiresrc connects to the global instance which cannot negotiate the
		// portal node format and returns EINVAL (-22).
		"pipewiresrc", fmt.Sprintf("fd=%d", pwFdNum), fmt.Sprintf("path=%d", nodeID), "do-timestamp=true",
		"!", "queue",
		"!", "videoconvert",
		"!", "videoscale",
		"!", fmt.Sprintf("video/x-raw,format=I420,width=%d,height=%d,framerate=%d/1", cfg.Width, cfg.Height, fps),
		"!", "openh264enc", "usage-type=screen", "rate-control=bitrate", "complexity=0", fmt.Sprintf("gop-size=%d", fps), "bitrate=4000000",
		"!", "h264parse", "config-interval=-1",
		"!", "video/x-h264,stream-format=byte-stream,alignment=au",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	}
}

// StartTestCapture creates a synthetic H.264 video stream using FFmpeg's libx264 encoder
// with High profile to match what Apple TV expects for screen mirroring.
func StartTestCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	// Use ffmpeg with libx264 High profile, Annex-B byte stream output
	// Note: -tune zerolatency forces Constrained Baseline, so we skip it and use
	// -preset veryfast with explicit CABAC/8x8dct to ensure actual High profile output.
	ffmpegArgs := []string{
		"-f", "lavfi",
		"-i", fmt.Sprintf("testsrc=duration=10:size=%dx%d:rate=%d", cfg.Width, cfg.Height, fps),
		"-pix_fmt", "yuv420p",
		"-c:v", "libx264",
		"-profile:v", "high",
		"-level", "4.0",
		"-preset", "veryfast",
		"-g", fmt.Sprintf("%d", fps), // keyframe interval
		"-bf", "0", // no B-frames
		"-b:v", "4000k",
		"-maxrate", "4000k",
		"-bufsize", "8000k",
		"-x264-params", "cabac=1:8x8dct=1:bframes=0",
		"-f", "h264",
		"-",
	}

	log.Printf("[CAPTURE] launching ffmpeg (test mode) %s", strings.Join(ffmpegArgs, " "))
	cmd := exec.CommandContext(captureCtx, "ffmpeg", ffmpegArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ffmpeg stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ffmpeg stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start ffmpeg: %w", err)
	}

	go scanCaptureStderr(stderr)
	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	return &ScreenCapture{
		cmd:    cmd,
		stdout: stdout,
		cancel: cancel,
		waitCh: waitCh,
	}, nil
}

func scanCaptureStderr(r io.Reader) {
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		log.Printf("[GST] %s", scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[GST] stderr read error: %v", err)
	}
}

// requestScreencast uses the xdg-desktop-portal D-Bus API to request screen capture
// permission and returns a PipeWire node ID and an fd for the portal's PipeWire remote.
func requestScreencast(ctx context.Context) (uint32, *os.File, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return 0, nil, fmt.Errorf("connect session bus: %w", err)
	}
	defer conn.Close()

	portal := conn.Object("org.freedesktop.portal.Desktop",
		"/org/freedesktop/portal/desktop")

	senderName := conn.Names()[0]
	token := "airplay_cast"

	// Create session
	sessionOpts := map[string]dbus.Variant{
		"handle_token":         dbus.MakeVariant(token),
		"session_handle_token": dbus.MakeVariant(token),
	}

	var sessionHandle dbus.ObjectPath
	call := portal.Call("org.freedesktop.portal.ScreenCast.CreateSession", 0, sessionOpts)
	if call.Err != nil {
		return 0, nil, fmt.Errorf("CreateSession: %w", call.Err)
	}
	if err := call.Store(&sessionHandle); err != nil {
		return 0, nil, fmt.Errorf("store session handle: %w", err)
	}

	// Wait for session response via signal
	sessionPath, err := waitForResponse(conn, senderName, token)
	if err != nil {
		return 0, nil, fmt.Errorf("session response: %w", err)
	}

	// Select sources (screen)
	selectOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(token + "_select"),
		"types":        dbus.MakeVariant(uint32(1)), // MONITOR=1, WINDOW=2
		"multiple":     dbus.MakeVariant(false),
		"cursor_mode":  dbus.MakeVariant(uint32(2)), // EMBEDDED=2 (cursor in stream)
	}

	call = portal.Call("org.freedesktop.portal.ScreenCast.SelectSources", 0,
		dbus.ObjectPath(sessionPath), selectOpts)
	if call.Err != nil {
		return 0, nil, fmt.Errorf("SelectSources: %w", call.Err)
	}

	_, err = waitForResponse(conn, senderName, token+"_select")
	if err != nil {
		return 0, nil, fmt.Errorf("select response: %w", err)
	}

	// Start the screencast
	startOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(token + "_start"),
	}

	call = portal.Call("org.freedesktop.portal.ScreenCast.Start", 0,
		dbus.ObjectPath(sessionPath), "", startOpts)
	if call.Err != nil {
		return 0, nil, fmt.Errorf("Start: %w", call.Err)
	}

	startResult, err := waitForResponseWithResult(conn, senderName, token+"_start")
	if err != nil {
		return 0, nil, fmt.Errorf("start response: %w", err)
	}

	// Extract PipeWire node ID from the result
	streams, ok := startResult["streams"]
	if !ok {
		return 0, nil, fmt.Errorf("no streams in start response")
	}

	var nodeID uint32
	streamList, ok := streams.Value().([][]interface{})
	if !ok {
		// Try alternate format
		if v, ok2 := streams.Value().([]interface{}); ok2 && len(v) > 0 {
			if tuple, ok3 := v[0].([]interface{}); ok3 && len(tuple) > 0 {
				if nid, ok4 := tuple[0].(uint32); ok4 {
					nodeID = nid
				} else {
					return 0, nil, fmt.Errorf("unexpected node ID type: %T", tuple[0])
				}
			} else {
				return 0, nil, fmt.Errorf("unexpected streams format: %T", streams.Value())
			}
		} else {
			return 0, nil, fmt.Errorf("unexpected streams format: %T", streams.Value())
		}
	} else {
		if len(streamList) == 0 || len(streamList[0]) == 0 {
			return 0, nil, fmt.Errorf("empty streams list")
		}
		nid, ok2 := streamList[0][0].(uint32)
		if !ok2 {
			return 0, nil, fmt.Errorf("unexpected node ID type: %T", streamList[0][0])
		}
		nodeID = nid
	}

	// OpenPipeWireRemote returns a Unix fd for the portal's PipeWire remote.
	// pipewiresrc MUST use this fd to connect; without it, it connects to the
	// global PipeWire instance which does not have the portal node and returns EINVAL.
	call = portal.Call("org.freedesktop.portal.ScreenCast.OpenPipeWireRemote", 0,
		dbus.ObjectPath(sessionPath), map[string]dbus.Variant{})
	if call.Err != nil {
		return 0, nil, fmt.Errorf("OpenPipeWireRemote: %w", call.Err)
	}
	var pwFD dbus.UnixFD
	if err := call.Store(&pwFD); err != nil {
		return 0, nil, fmt.Errorf("store pipewire fd: %w", err)
	}

	return nodeID, os.NewFile(uintptr(pwFD), "pipewire-remote"), nil
}

func waitForResponse(conn *dbus.Conn, sender, token string) (string, error) {
	result, err := waitForResponseWithResult(conn, sender, token)
	if err != nil {
		return "", err
	}
	_ = result
	return buildSessionHandle(sender, token), nil
}

func waitForResponseWithResult(conn *dbus.Conn, sender, token string) (map[string]dbus.Variant, error) {
	ch := make(chan *dbus.Signal, 1)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)

	matchRule := "type='signal',interface='org.freedesktop.portal.Request',member='Response'"
	conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule)

	select {
	case sig := <-ch:
		if len(sig.Body) < 2 {
			return nil, fmt.Errorf("signal body too short")
		}
		status, ok := sig.Body[0].(uint32)
		if !ok {
			return nil, fmt.Errorf("unexpected status type")
		}
		if status != 0 {
			return nil, fmt.Errorf("portal request failed with status %d", status)
		}
		result, ok := sig.Body[1].(map[string]dbus.Variant)
		if !ok {
			return nil, fmt.Errorf("unexpected result type: %T", sig.Body[1])
		}
		return result, nil

	case <-make(chan struct{}): // Would use ctx.Done() with actual context
		return nil, fmt.Errorf("timeout waiting for portal response")
	}
}

func buildSessionHandle(sender, token string) string {
	// Convert sender name like ":1.234" to "1_234"
	clean := ""
	for _, c := range sender {
		if c == '.' || c == ':' {
			if c == '.' {
				clean += "_"
			}
		} else {
			clean += string(c)
		}
	}
	return fmt.Sprintf("/org/freedesktop/portal/desktop/session/%s/%s", clean, token)
}
