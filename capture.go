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
	Bitrate int    // Video bitrate in kbps (0 = auto)
	HWAccel string // "auto", "vaapi", "none"
}

// ScreenCapture manages Wayland screen capture via xdg-desktop-portal + ffmpeg.
type ScreenCapture struct {
	cmd      *exec.Cmd // primary process (ffmpeg encoder)
	gstCmd   *exec.Cmd // GStreamer raw capture for Wayland (nil for X11)
	stdout   io.ReadCloser
	cancel   context.CancelFunc
	pwNodeID uint32
	dbusConn *dbus.Conn    // portal session D-Bus connection (must stay open for Wayland)
	waitCh   chan struct{} // closed when process exits
	waitErr  error         // set before waitCh is closed
	stopped  bool
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

	nodeID, pwFd, dbusConn, err := requestScreencast(ctx)
	if err != nil {
		return nil, fmt.Errorf("screencast portal: %w", err)
	}
	dbg("pipewire node ID: %d", nodeID)

	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	encoderParts := detectGstEncoder(cfg)

	// Single GStreamer pipeline: capture from PipeWire portal and encode to H.264.
	// Keep the pipeline simple — pipewiresrc ! videoconvert handles DMA-BUF to
	// system memory conversion automatically.  videoscale and videorate are applied
	// after conversion so caps negotiation isn't blocked.
	const pwFdNum = 3
	gstArgs := []string{
		"--quiet",
		"pipewiresrc", fmt.Sprintf("fd=%d", pwFdNum), fmt.Sprintf("path=%d", nodeID), "do-timestamp=true",
		"!", "videoconvert",
		"!", "videoscale",
		"!", "videorate",
		"!", fmt.Sprintf("video/x-raw,width=%d,height=%d,framerate=%d/1", cfg.Width, cfg.Height, fps),
	}
	gstArgs = append(gstArgs, "!")
	gstArgs = append(gstArgs, encoderParts...)
	gstArgs = append(gstArgs,
		"!", "h264parse",
		"!", "video/x-h264,stream-format=byte-stream,alignment=au",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	)

	dbg("[CAPTURE] gst-launch-1.0 (wayland) %s", strings.Join(gstArgs, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)
	cmd.ExtraFiles = []*os.File{pwFd}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		pwFd.Close()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		cancel()
		pwFd.Close()
		return nil, fmt.Errorf("start gst-launch: %w", err)
	}
	pwFd.Close() // child inherited it

	go logStderr("GST", stderr)

	capture := &ScreenCapture{
		cmd:      cmd,
		stdout:   stdout,
		cancel:   cancel,
		pwNodeID: nodeID,
		dbusConn: dbusConn,
		waitCh:   make(chan struct{}),
	}
	go func() {
		capture.waitErr = cmd.Wait()
		close(capture.waitCh)
	}()

	return capture, nil
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

	bitrate := cfg.Bitrate
	if bitrate <= 0 {
		bitrate = 10000
	}
	bitrateStr := fmt.Sprintf("%dk", bitrate)
	bufsizeStr := fmt.Sprintf("%dk", bitrate/fps+1)

	ffmpegArgs := []string{
		"-nostdin",
	}

	// VAAPI needs the device opened before the input
	encoder, encoderArgs := detectFFmpegEncoder(cfg)
	if encoder == "h264_vaapi" {
		ffmpegArgs = append(ffmpegArgs, "-vaapi_device", "/dev/dri/renderD128")
	}

	ffmpegArgs = append(ffmpegArgs,
		"-f", "x11grab",
		"-framerate", fmt.Sprintf("%d", fps),
		"-video_size", fmt.Sprintf("%dx%d", cfg.Width, cfg.Height),
		"-i", display,
	)

	// VAAPI needs hwupload filter
	if encoder == "h264_vaapi" {
		ffmpegArgs = append(ffmpegArgs, "-vf", "format=nv12,hwupload")
	} else {
		ffmpegArgs = append(ffmpegArgs, "-pix_fmt", "yuv420p")
	}

	ffmpegArgs = append(ffmpegArgs, encoderArgs...)
	ffmpegArgs = append(ffmpegArgs,
		"-g", fmt.Sprintf("%d", fps*2),
		"-keyint_min", fmt.Sprintf("%d", fps),
		"-bf", "0",
		"-b:v", bitrateStr,
		"-maxrate", bitrateStr,
		"-bufsize", bufsizeStr,
		"-f", "h264",
		"pipe:1",
	)

	dbg("[CAPTURE] launching ffmpeg (x11) %s", strings.Join(ffmpegArgs, " "))
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

	capture := &ScreenCapture{
		cmd:    cmd,
		stdout: stdout,
		cancel: cancel,
		waitCh: make(chan struct{}),
	}
	go func() {
		capture.waitErr = cmd.Wait()
		close(capture.waitCh)
	}()

	return capture, nil
}

func (sc *ScreenCapture) Read(buf []byte) (int, error) {
	select {
	case <-sc.waitCh:
		if sc.waitErr != nil {
			return 0, fmt.Errorf("capture exited: %w", sc.waitErr)
		}
		return 0, io.EOF
	default:
	}
	return sc.stdout.Read(buf)
}

func (sc *ScreenCapture) Stop() {
	if sc.stopped || sc.cmd == nil {
		return
	}
	sc.stopped = true
	if sc.cancel != nil {
		sc.cancel()
	}

	// Close stdout to unblock any pending Read() call
	if sc.stdout != nil {
		sc.stdout.Close()
	}

	if sc.dbusConn != nil {
		sc.dbusConn.Close()
	}
	if sc.cmd.Process != nil {
		_ = sc.cmd.Process.Signal(os.Interrupt)
	}
	if sc.gstCmd != nil && sc.gstCmd.Process != nil {
		_ = sc.gstCmd.Process.Signal(os.Interrupt)
	}

	select {
	case <-sc.waitCh:
	case <-time.After(2 * time.Second):
		if sc.cmd.Process != nil {
			_ = sc.cmd.Process.Kill()
		}
		if sc.gstCmd != nil && sc.gstCmd.Process != nil {
			_ = sc.gstCmd.Process.Kill()
		}
		<-sc.waitCh
	}
}

// detectGstEncoder probes for available GStreamer H.264 encoders and returns
// the encoder element + properties as gst-launch-1.0 arguments.
// Priority: nvh264enc > vah264enc > x264enc (software fallback).
func detectGstEncoder(cfg CaptureConfig) []string {
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	bitrate := cfg.Bitrate
	if bitrate <= 0 {
		bitrate = 10000
	}
	hwaccel := cfg.HWAccel

	// Try NVENC
	if hwaccel == "auto" || hwaccel == "nvenc" {
		if exec.Command("gst-inspect-1.0", "nvh264enc").Run() == nil {
			log.Printf("[CAPTURE] using NVENC hardware encoding (nvh264enc)")
			return []string{
				"nvh264enc",
				fmt.Sprintf("bitrate=%d", bitrate),
				fmt.Sprintf("gop-size=%d", fps*2),
				"bframes=0",
				"rc-mode=cbr",
				"preset=low-latency-hq",
			}
		}
		if hwaccel == "nvenc" {
			dbg("[CAPTURE] nvh264enc not available, falling back to software")
		}
	}

	// Try VAAPI
	if hwaccel == "auto" || hwaccel == "vaapi" {
		if exec.Command("gst-inspect-1.0", "vah264enc").Run() == nil {
			log.Printf("[CAPTURE] using VAAPI hardware encoding (vah264enc)")
			return []string{
				"vah264enc",
				fmt.Sprintf("bitrate=%d", bitrate),
			}
		}
		if hwaccel == "vaapi" {
			dbg("[CAPTURE] vah264enc not available, falling back to software")
		}
	}

	// Software fallback: x264enc
	log.Printf("[CAPTURE] using software encoding (x264enc)")
	return []string{
		"x264enc",
		"tune=zerolatency",
		"speed-preset=superfast",
		fmt.Sprintf("bitrate=%d", bitrate),
		fmt.Sprintf("key-int-max=%d", fps*2),
		"bframes=0",
		"sliced-threads=false",
		"byte-stream=true",
	}
}

// detectFFmpegEncoder probes for available ffmpeg H.264 encoders and returns
// the encoder name and encoder-specific ffmpeg arguments.
// Priority: h264_nvenc > h264_vaapi > libx264 (software fallback).
func detectFFmpegEncoder(cfg CaptureConfig) (encoder string, args []string) {
	hwaccel := cfg.HWAccel

	// Try NVENC
	if hwaccel == "auto" || hwaccel == "nvenc" {
		if hasFFmpegEncoder("h264_nvenc") {
			log.Printf("[CAPTURE] using NVENC hardware encoding (h264_nvenc)")
			return "h264_nvenc", []string{
				"-c:v", "h264_nvenc",
				"-profile:v", "high",
				"-level:v", "4.0",
				"-preset", "p4",
				"-tune", "ll",
			}
		}
		if hwaccel == "nvenc" {
			dbg("[CAPTURE] h264_nvenc not available, falling back to software")
		}
	}

	// Try VAAPI
	if hwaccel == "auto" || hwaccel == "vaapi" {
		if _, err := os.Stat("/dev/dri/renderD128"); err == nil && hasFFmpegEncoder("h264_vaapi") {
			log.Printf("[CAPTURE] using VAAPI hardware encoding (h264_vaapi)")
			return "h264_vaapi", []string{
				"-c:v", "h264_vaapi",
				"-profile:v", "high",
				"-level", "40",
			}
		}
		if hwaccel == "vaapi" {
			dbg("[CAPTURE] h264_vaapi not available, falling back to software")
		}
	}

	// Software fallback
	log.Printf("[CAPTURE] using software encoding (libx264)")
	return "libx264", []string{
		"-c:v", "libx264",
		"-profile:v", "high",
		"-level:v", "4.0",
		"-tune", "zerolatency",
		"-preset", "superfast",
		"-x264-params", "cabac=1:aud=1:repeat-headers=1:sliced-threads=0:rc-lookahead=0:sync-lookahead=0:bframes=0",
	}
}

// hasFFmpegEncoder checks if ffmpeg supports the given encoder.
func hasFFmpegEncoder(name string) bool {
	out, err := exec.Command("ffmpeg", "-hide_banner", "-encoders").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), name)
}

// buildFFmpegEncodeArgs constructs ffmpeg arguments for encoding raw I420 video
// (or from another input) to H.264 High profile Annex-B byte stream.
func buildFFmpegEncodeArgs(cfg CaptureConfig, input string) []string {
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	bitrate := cfg.Bitrate
	if bitrate <= 0 {
		bitrate = 10000
	}
	bitrateStr := fmt.Sprintf("%dk", bitrate)
	// bufsize = 1 frame worth of data for minimal encoder latency
	bufsizeStr := fmt.Sprintf("%dk", bitrate/fps+1)

	args := []string{
		"-nostdin",
		"-f", "rawvideo",
		"-pixel_format", "yuv420p",
		"-video_size", fmt.Sprintf("%dx%d", cfg.Width, cfg.Height),
		"-framerate", fmt.Sprintf("%d", fps),
		"-i", input,
	}

	// Try VAAPI hardware encoding if requested
	if cfg.HWAccel == "vaapi" || cfg.HWAccel == "auto" {
		vaArgs := buildVAAPIArgs(cfg, fps, bitrateStr, bufsizeStr, input)
		if vaArgs != nil {
			return vaArgs
		}
		if cfg.HWAccel == "vaapi" {
			dbg("[CAPTURE] VAAPI explicitly requested but not available, falling back to libx264")
		}
	}

	args = append(args,
		"-c:v", "libx264",
		"-profile:v", "high",
		"-level:v", "4.0",
		"-tune", "zerolatency",
		"-preset", "superfast",
		"-x264-params", "cabac=1:aud=1:repeat-headers=1:sliced-threads=0:rc-lookahead=0:sync-lookahead=0:bframes=0",
		"-g", fmt.Sprintf("%d", fps*2), // keyframe every 2 seconds
		"-keyint_min", fmt.Sprintf("%d", fps),
		"-bf", "0",
		"-b:v", bitrateStr,
		"-maxrate", bitrateStr,
		"-bufsize", bufsizeStr,
		"-f", "h264",
		"pipe:1",
	)
	return args
}

// buildVAAPIArgs tries to construct VAAPI hardware encoding args.
// Returns nil if VAAPI is not available.
func buildVAAPIArgs(cfg CaptureConfig, fps int, bitrateStr, bufsizeStr, input string) []string {
	// Check if VAAPI device exists
	if _, err := os.Stat("/dev/dri/renderD128"); err != nil {
		return nil
	}
	// Check if ffmpeg has vaapi_h264 encoder
	out, err := exec.Command("ffmpeg", "-hide_banner", "-encoders").Output()
	if err != nil || !strings.Contains(string(out), "h264_vaapi") {
		return nil
	}
	log.Printf("[CAPTURE] using VAAPI hardware encoding")
	return []string{
		"-nostdin",
		"-vaapi_device", "/dev/dri/renderD128",
		"-f", "rawvideo",
		"-pixel_format", "yuv420p",
		"-video_size", fmt.Sprintf("%dx%d", cfg.Width, cfg.Height),
		"-framerate", fmt.Sprintf("%d", fps),
		"-i", input,
		"-vf", "format=nv12,hwupload",
		"-c:v", "h264_vaapi",
		"-profile:v", "high",
		"-level", "40",
		"-g", fmt.Sprintf("%d", fps*2),
		"-bf", "0",
		"-b:v", bitrateStr,
		"-maxrate", bitrateStr,
		"-bufsize", bufsizeStr,
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

	bitrate := cfg.Bitrate
	if bitrate <= 0 {
		bitrate = 10000
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
		fmt.Sprintf("bitrate=%d", bitrate),
		fmt.Sprintf("key-int-max=%d", fps*2),
		"bframes=0",
		"sliced-threads=false",
		"threads=1",
		"byte-stream=true",
		"!", "video/x-h264,profile=high,stream-format=byte-stream",
		"!", "fdsink", "fd=1",
	}

	dbg("[CAPTURE] launching gst-launch-1.0 (test mode) %s", strings.Join(gstArgs, " "))
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

	capture := &ScreenCapture{
		cmd:    cmd,
		stdout: stdout,
		cancel: cancel,
		waitCh: make(chan struct{}),
	}
	go func() {
		capture.waitErr = cmd.Wait()
		close(capture.waitCh)
	}()

	return capture, nil
}

func logStderr(prefix string, r io.Reader) {
	if r == nil {
		return
	}
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		dbg("[%s] %s", prefix, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		dbg("[%s] stderr read error: %v", prefix, err)
	}
}

// requestScreencast uses the xdg-desktop-portal D-Bus API to request screen capture
// permission and returns a PipeWire node ID, an fd for the portal's PipeWire remote,
// and the D-Bus connection (which must stay open to keep the screencast session alive).
func requestScreencast(ctx context.Context) (uint32, *os.File, *dbus.Conn, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("connect session bus: %w", err)
	}

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
		conn.Close()
		return 0, nil, nil, fmt.Errorf("CreateSession: %w", call.Err)
	}
	if err := call.Store(&sessionHandle); err != nil {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("store session handle: %w", err)
	}

	// Wait for session response via signal
	sessionPath, err := waitForResponse(conn, senderName, token)
	if err != nil {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("session response: %w", err)
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
		conn.Close()
		return 0, nil, nil, fmt.Errorf("SelectSources: %w", call.Err)
	}

	_, err = waitForResponse(conn, senderName, token+"_select")
	if err != nil {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("select response: %w", err)
	}

	// Start the screencast
	startOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(token + "_start"),
	}

	call = portal.Call("org.freedesktop.portal.ScreenCast.Start", 0,
		dbus.ObjectPath(sessionPath), "", startOpts)
	if call.Err != nil {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("Start: %w", call.Err)
	}

	startResult, err := waitForResponseWithResult(conn, senderName, token+"_start")
	if err != nil {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("start response: %w", err)
	}

	// Extract PipeWire node ID from the result
	streams, ok := startResult["streams"]
	if !ok {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("no streams in start response")
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
					conn.Close()
					return 0, nil, nil, fmt.Errorf("unexpected node ID type: %T", tuple[0])
				}
			} else {
				conn.Close()
				return 0, nil, nil, fmt.Errorf("unexpected streams format: %T", streams.Value())
			}
		} else {
			conn.Close()
			return 0, nil, nil, fmt.Errorf("unexpected streams format: %T", streams.Value())
		}
	} else {
		if len(streamList) == 0 || len(streamList[0]) == 0 {
			conn.Close()
			return 0, nil, nil, fmt.Errorf("empty streams list")
		}
		nid, ok2 := streamList[0][0].(uint32)
		if !ok2 {
			conn.Close()
			return 0, nil, nil, fmt.Errorf("unexpected node ID type: %T", streamList[0][0])
		}
		nodeID = nid
	}

	// OpenPipeWireRemote returns a Unix fd for the portal's PipeWire remote.
	// pipewiresrc MUST use this fd to connect; without it, it connects to the
	// global PipeWire instance which does not have the portal node and returns EINVAL.
	call = portal.Call("org.freedesktop.portal.ScreenCast.OpenPipeWireRemote", 0,
		dbus.ObjectPath(sessionPath), map[string]dbus.Variant{})
	if call.Err != nil {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("OpenPipeWireRemote: %w", call.Err)
	}
	var pwFD dbus.UnixFD
	if err := call.Store(&pwFD); err != nil {
		conn.Close()
		return 0, nil, nil, fmt.Errorf("store pipewire fd: %w", err)
	}

	return nodeID, os.NewFile(uintptr(pwFD), "pipewire-remote"), conn, nil
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
