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
	cmd      *exec.Cmd // primary process (ffmpeg encoder)
	gstCmd   *exec.Cmd // GStreamer raw capture for Wayland (nil for X11)
	stdout   io.ReadCloser
	cancel   context.CancelFunc
	pwNodeID uint32
	waitCh   chan error
}

// StartCapture detects the display server (Wayland or X11) and initiates screen
// capture accordingly. On Wayland it uses xdg-desktop-portal + PipeWire for raw
// capture and ffmpeg/libx264 for encoding; on X11 it uses ffmpeg x11grab directly.
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
	// Check dependencies
	if err := exec.Command("gst-inspect-1.0", "pipewiresrc").Run(); err != nil {
		return nil, fmt.Errorf("GStreamer 'pipewiresrc' plugin not found; install gst-pipewire")
	}
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return nil, fmt.Errorf("ffmpeg not found in PATH; install ffmpeg with libx264 support")
	}

	nodeID, pwFd, err := requestScreencast(ctx)
	if err != nil {
		return nil, fmt.Errorf("screencast portal: %w", err)
	}
	log.Printf("pipewire node ID: %d", nodeID)

	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	// Step 1: GStreamer captures raw I420 frames from the PipeWire portal.
	// We only use GStreamer for capture — encoding is done by ffmpeg/libx264.
	const pwFdNum = 3
	gstArgs := []string{
		"--quiet",
		"pipewiresrc", fmt.Sprintf("fd=%d", pwFdNum), fmt.Sprintf("path=%d", nodeID), "do-timestamp=true",
		"!", "video/x-raw",
		"!", "queue",
		"!", "videoconvert",
		"!", "videoscale",
		"!", "videorate",
		"!", fmt.Sprintf("video/x-raw,format=I420,width=%d,height=%d,framerate=%d/1", cfg.Width, cfg.Height, fps),
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	}
	log.Printf("[CAPTURE] gst-launch-1.0 (raw capture) %s", strings.Join(gstArgs, " "))
	gstCmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)
	gstCmd.ExtraFiles = []*os.File{pwFd}

	// Step 2: FFmpeg encodes raw I420 → H.264 High profile Annex-B byte stream
	ffmpegArgs := buildFFmpegEncodeArgs(cfg, "pipe:0")
	log.Printf("[CAPTURE] ffmpeg (encode) %s", strings.Join(ffmpegArgs, " "))
	ffmpegCmd := exec.CommandContext(captureCtx, "ffmpeg", ffmpegArgs...)

	// Create OS pipe: GStreamer raw stdout → FFmpeg stdin
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		cancel()
		pwFd.Close()
		return nil, fmt.Errorf("create pipe: %w", err)
	}
	gstCmd.Stdout = pipeW
	ffmpegCmd.Stdin = pipeR

	ffmpegStdout, err := ffmpegCmd.StdoutPipe()
	if err != nil {
		cancel()
		pwFd.Close()
		pipeR.Close()
		pipeW.Close()
		return nil, fmt.Errorf("ffmpeg stdout pipe: %w", err)
	}

	gstStderr, _ := gstCmd.StderrPipe()
	ffmpegStderr, _ := ffmpegCmd.StderrPipe()

	// Start GStreamer first so the pipe write-end is ready
	if err := gstCmd.Start(); err != nil {
		cancel()
		pwFd.Close()
		pipeR.Close()
		pipeW.Close()
		return nil, fmt.Errorf("start gst-launch: %w", err)
	}
	pwFd.Close()  // child inherited it
	pipeW.Close() // parent closes write end

	if err := ffmpegCmd.Start(); err != nil {
		gstCmd.Process.Kill()
		gstCmd.Wait()
		cancel()
		pipeR.Close()
		return nil, fmt.Errorf("start ffmpeg: %w", err)
	}
	pipeR.Close() // parent closes read end

	go logStderr("GST", gstStderr)
	go logStderr("FFMPEG", ffmpegStderr)

	waitCh := make(chan error, 1)
	go func() {
		err := ffmpegCmd.Wait()
		gstCmd.Process.Kill()
		gstCmd.Wait()
		waitCh <- err
	}()

	return &ScreenCapture{
		cmd:      ffmpegCmd,
		gstCmd:   gstCmd,
		stdout:   ffmpegStdout,
		cancel:   cancel,
		pwNodeID: nodeID,
		waitCh:   waitCh,
	}, nil
}

func startX11Capture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		return nil, fmt.Errorf("ffmpeg not found in PATH; install ffmpeg with libx264 support")
	}

	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	display := os.Getenv("DISPLAY")
	ffmpegArgs := []string{
		"-nostdin",
		"-f", "x11grab",
		"-framerate", fmt.Sprintf("%d", fps),
		"-video_size", fmt.Sprintf("%dx%d", cfg.Width, cfg.Height),
		"-i", display,
		"-pix_fmt", "yuv420p",
		"-c:v", "libx264",
		"-profile:v", "high",
		"-level:v", "4.0",
		"-tune", "zerolatency",
		"-preset", "ultrafast",
		"-x264-params", "cabac=1:aud=1",
		"-g", fmt.Sprintf("%d", fps),
		"-keyint_min", fmt.Sprintf("%d", fps),
		"-bf", "0",
		"-b:v", "4000k",
		"-maxrate", "4000k",
		"-bufsize", "8000k",
		"-f", "h264",
		"pipe:1",
	}

	log.Printf("[CAPTURE] launching ffmpeg (x11) %s", strings.Join(ffmpegArgs, " "))
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

	go logStderr("FFMPEG", stderr)
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
	if sc.gstCmd != nil && sc.gstCmd.Process != nil {
		_ = sc.gstCmd.Process.Signal(os.Interrupt)
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
		if sc.gstCmd != nil && sc.gstCmd.Process != nil {
			_ = sc.gstCmd.Process.Kill()
		}
		<-done
	}
}

// buildFFmpegEncodeArgs constructs ffmpeg arguments for encoding raw I420 video
// (or from another input) to H.264 High profile Annex-B byte stream.
func buildFFmpegEncodeArgs(cfg CaptureConfig, input string) []string {
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	return []string{
		"-nostdin",
		"-f", "rawvideo",
		"-pixel_format", "yuv420p",
		"-video_size", fmt.Sprintf("%dx%d", cfg.Width, cfg.Height),
		"-framerate", fmt.Sprintf("%d", fps),
		"-i", input,
		"-c:v", "libx264",
		"-profile:v", "high",
		"-level:v", "4.0",
		"-tune", "zerolatency",
		"-preset", "ultrafast",
		"-x264-params", "cabac=1:aud=1",
		"-g", fmt.Sprintf("%d", fps),
		"-keyint_min", fmt.Sprintf("%d", fps),
		"-bf", "0",
		"-b:v", "4000k",
		"-maxrate", "4000k",
		"-bufsize", "8000k",
		"-f", "h264",
		"pipe:1",
	}
}

// StartTestCapture creates a synthetic H.264 video stream using GStreamer's
// videotestsrc + x264enc, producing High profile Annex-B byte stream output.
// This replicates the same GStreamer pipeline ecosystem that UxPlay uses on the
// receiver side, avoiding any ffmpeg/libx264 encoding differences.
func StartTestCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	// GStreamer pipeline: videotestsrc → timeoverlay → x264enc High profile → Annex-B byte stream → stdout
	// pattern=18 = ball (bouncing ball with motion); timeoverlay adds a frame counter
	gstArgs := []string{
		"--quiet",
		"videotestsrc", "pattern=18", fmt.Sprintf("num-buffers=%d", 10*fps),
		"!", fmt.Sprintf("video/x-raw,width=%d,height=%d,framerate=%d/1", cfg.Width, cfg.Height, fps),
		"!", "timeoverlay",
		"!", "videoconvert",
		"!", "x264enc",
		"tune=zerolatency",
		fmt.Sprintf("bitrate=%d", 4000),
		fmt.Sprintf("key-int-max=%d", fps),
		"bframes=0",
		"sliced-threads=false",
		"threads=1",
		"byte-stream=true",
		"!", "video/x-h264,profile=high,stream-format=byte-stream",
		"!", "fdsink", "fd=1",
	}

	log.Printf("[CAPTURE] launching gst-launch-1.0 (test mode) %s", strings.Join(gstArgs, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gst stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start gst-launch-1.0: %w", err)
	}

	go logStderr("GST", stderr)
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

func logStderr(prefix string, r io.Reader) {
	if r == nil {
		return
	}
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		log.Printf("[%s] %s", prefix, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[%s] stderr read error: %v", prefix, err)
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
