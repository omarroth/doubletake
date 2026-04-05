package airplay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
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

const (
	defaultVideoBitrateKbps = 4500
	minVideoBitrateKbps     = 1800
	maxVideoBitrateKbps     = 12000
)

// ScreenCapture manages screen capture via GStreamer.
type ScreenCapture struct {
	cmd      *exec.Cmd // gst-launch-1.0 process
	stdout   io.ReadCloser
	cancel   context.CancelFunc
	pwNodeID uint32
	dbusConn *dbus.Conn    // portal session D-Bus connection (must stay open for Wayland)
	waitCh   chan struct{} // closed when process exits
	waitErr  error         // set before waitCh is closed
	stopped  bool
}

// StartCapture detects the display server (Wayland or X11) and initiates screen
// capture accordingly. On Wayland it uses xdg-desktop-portal + PipeWire for
// capture; on X11 it uses ximagesrc. Both use GStreamer for H.264 encoding.
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
		"!", "videorate", "drop-only=true", "skip-to-first=true",
		"!", fmt.Sprintf("video/x-raw,width=%d,height=%d,framerate=%d/1", cfg.Width, cfg.Height, fps),
		"!", "queue", "max-size-buffers=1", "max-size-bytes=0", "max-size-time=0", "leaky=downstream",
	}
	if encoderParts.needsVulkan {
		gstArgs = append(gstArgs, "!", "vulkanupload")
	}
	gstArgs = append(gstArgs, "!")
	gstArgs = append(gstArgs, encoderParts.parts...)
	gstArgs = append(gstArgs,
		"!", "h264parse", "config-interval=0",
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
	if err := exec.Command("gst-inspect-1.0", "ximagesrc").Run(); err != nil {
		return nil, fmt.Errorf("GStreamer 'ximagesrc' plugin not found; install gst-plugins-good")
	}

	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	display := os.Getenv("DISPLAY")

	encoder := detectGstEncoder(cfg)

	// Detect primary monitor geometry — ximagesrc captures the full X screen
	// (all monitors combined). On multi-monitor setups this wastes CPU on
	// pixels we don't need. Crop to the primary monitor.
	startX, endX := detectPrimaryMonitor(display, cfg.Width)

	ximageSrcArgs := []string{
		"ximagesrc", fmt.Sprintf("display-name=%s", display), "use-damage=false",
	}
	if endX > startX {
		ximageSrcArgs = append(ximageSrcArgs,
			fmt.Sprintf("startx=%d", startX),
			fmt.Sprintf("endx=%d", endX-1),
		)
		dbg("[CAPTURE] cropping ximagesrc to x=%d..%d", startX, endX-1)
	}

	gstArgs := []string{"--quiet"}
	gstArgs = append(gstArgs, ximageSrcArgs...)
	gstArgs = append(gstArgs,
		"!", fmt.Sprintf("video/x-raw,framerate=%d/1", fps),
		"!", "queue", "max-size-buffers=1", "max-size-bytes=0", "max-size-time=0", "leaky=downstream",
		"!", "videoconvert",
		"!", "videoscale",
		"!", fmt.Sprintf("video/x-raw,width=%d,height=%d", cfg.Width, cfg.Height),
	)
	if encoder.needsVulkan {
		gstArgs = append(gstArgs, "!", "vulkanupload")
	}
	gstArgs = append(gstArgs, "!")
	gstArgs = append(gstArgs, encoder.parts...)
	gstArgs = append(gstArgs,
		"!", "h264parse", "config-interval=0",
		"!", "video/x-h264,stream-format=byte-stream,alignment=au",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	)

	dbg("[CAPTURE] gst-launch-1.0 (x11) %s", strings.Join(gstArgs, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		// If Vulkan encoder failed, retry with software fallback
		if encoder.needsVulkan {
			log.Printf("[CAPTURE] vulkanh264enc pipeline failed, falling back to x264enc")
			cancel()
			cfg.HWAccel = "none"
			return startX11Capture(ctx, cfg)
		}
		cancel()
		return nil, fmt.Errorf("start gst-launch: %w", err)
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

	select {
	case <-sc.waitCh:
	case <-time.After(2 * time.Second):
		if sc.cmd.Process != nil {
			_ = sc.cmd.Process.Kill()
		}
		<-sc.waitCh
	}
}

// detectPrimaryMonitor queries xrandr to find the primary monitor's X offset
// and width. Returns (startX, endX) where endX = startX + monitor_width.
// If detection fails or the screen is already <= targetWidth, returns (0, 0)
// meaning no cropping is needed.
func detectPrimaryMonitor(display string, targetWidth int) (int, int) {
	// Run xrandr to get connected outputs with geometry
	out, err := exec.Command("xrandr", "--display", display, "--query").Output()
	if err != nil {
		dbg("[CAPTURE] xrandr failed: %v, skipping monitor crop", err)
		return 0, 0
	}

	// Parse lines like: "DP-3 connected primary 1920x1080+0+0"
	// or "DP-1 connected 1920x1080+1920+0"
	// Format: <name> connected [primary] <W>x<H>+<X>+<Y>
	var primaryX, primaryW int
	var found bool
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, " connected") {
			continue
		}
		// Try primary first
		if strings.Contains(line, " primary ") {
			if x, w, ok := parseXrandrGeometry(line); ok {
				primaryX, primaryW = x, w
				found = true
				break
			}
		}
	}
	// If no primary found, use the first connected output
	if !found {
		for _, line := range strings.Split(string(out), "\n") {
			if !strings.Contains(line, " connected") {
				continue
			}
			if x, w, ok := parseXrandrGeometry(line); ok {
				primaryX, primaryW = x, w
				found = true
				break
			}
		}
	}

	if !found {
		dbg("[CAPTURE] couldn't parse xrandr output, skipping monitor crop")
		return 0, 0
	}

	// Only crop if the monitor width is close to or larger than targetWidth
	// and we're actually on a multi-monitor setup (total screen > single monitor)
	if primaryW <= 0 || primaryW < targetWidth {
		return 0, 0
	}

	dbg("[CAPTURE] primary monitor: %dx? at x=%d", primaryW, primaryX)
	return primaryX, primaryX + primaryW
}

// parseXrandrGeometry extracts the X offset and width from an xrandr output line.
func parseXrandrGeometry(line string) (xOffset, width int, ok bool) {
	// Match WxH+X+Y pattern
	for _, field := range strings.Fields(line) {
		// e.g. "1920x1080+0+0" or "3840x2160+1920+0"
		parts := strings.SplitN(field, "x", 2)
		if len(parts) != 2 {
			continue
		}
		w, err := strconv.Atoi(parts[0])
		if err != nil || w < 640 {
			continue
		}
		rest := parts[1] // e.g. "1080+0+0"
		plusParts := strings.SplitN(rest, "+", 3)
		if len(plusParts) != 3 {
			continue
		}
		x, err := strconv.Atoi(plusParts[1])
		if err != nil {
			continue
		}
		return x, w, true
	}
	return 0, 0, false
}

// encoderResult holds the detected encoder pipeline parts and whether it needs
// a vulkanupload step before the encoder.
type encoderResult struct {
	parts       []string
	needsVulkan bool // encoder needs vulkanupload ! before it
}

// detectGstEncoder probes for available GStreamer H.264 encoders and returns
// the encoder element + properties as gst-launch-1.0 arguments.
// Priority: vulkanh264enc (NVENC via Vulkan) > nvh264enc > vah264enc > x264enc.
func detectGstEncoder(cfg CaptureConfig) encoderResult {
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	bitrate := captureBitrateKbps(cfg)
	keyframeInterval := keyframeIntervalFrames(fps)
	hwaccel := cfg.HWAccel

	// Try Vulkan H.264 (NVENC via Vulkan API) — lowest latency, no CPU usage
	if hwaccel == "auto" || hwaccel == "nvenc" {
		if exec.Command("gst-inspect-1.0", "vulkanh264enc").Run() == nil {
			log.Printf("[CAPTURE] using NVENC hardware encoding (vulkanh264enc)")
			return encoderResult{
				parts: []string{
					"vulkanh264enc",
					"b-frames=0",
					fmt.Sprintf("idr-period=%d", keyframeInterval),
					"rate-control=cbr",
					fmt.Sprintf("bitrate=%d", bitrate),
				},
				needsVulkan: true,
			}
		}
	}

	// Try legacy NVENC
	if hwaccel == "auto" || hwaccel == "nvenc" {
		if exec.Command("gst-inspect-1.0", "nvh264enc").Run() == nil {
			log.Printf("[CAPTURE] using NVENC hardware encoding (nvh264enc)")
			return encoderResult{parts: []string{
				"nvh264enc",
				fmt.Sprintf("bitrate=%d", bitrate),
				fmt.Sprintf("gop-size=%d", keyframeInterval),
				"bframes=0",
				"rc-mode=cbr",
				"preset=low-latency-hq",
				"zerolatency=true",
			}}
		}
		if hwaccel == "nvenc" {
			dbg("[CAPTURE] nvh264enc not available, falling back to software")
		}
	}

	// Try VAAPI
	if hwaccel == "auto" || hwaccel == "vaapi" {
		if exec.Command("gst-inspect-1.0", "vah264enc").Run() == nil {
			log.Printf("[CAPTURE] using VAAPI hardware encoding (vah264enc)")
			return encoderResult{parts: []string{
				"vah264enc",
				fmt.Sprintf("bitrate=%d", bitrate),
				fmt.Sprintf("key-int-max=%d", keyframeInterval),
				"b-frames=0",
				"rate-control=cbr",
			}}
		}
		if hwaccel == "vaapi" {
			dbg("[CAPTURE] vah264enc not available, falling back to software")
		}
	}

	// Software fallback: x264enc
	log.Printf("[CAPTURE] using software encoding (x264enc)")
	vbvBuf := vbvBufferKbit(bitrate, fps)
	// Use VBR (pass=0) so the encoder can undershoot on simple scenes, saving
	// headroom for complex frames. vbv-buf-capacity + vbv-maxrate cap bursts.
	maxrate := bitrate + bitrate/4 // allow 25% overshoot on peaks
	return encoderResult{parts: []string{
		"x264enc",
		"tune=zerolatency",
		"speed-preset=superfast",
		fmt.Sprintf("bitrate=%d", bitrate),
		fmt.Sprintf("vbv-buf-capacity=%d", vbvBuf),
		fmt.Sprintf("key-int-max=%d", keyframeInterval),
		"pass=0",
		"option-string=" + fmt.Sprintf("vbv-maxrate=%d", maxrate),
		"bframes=0",
		"sliced-threads=true",
		"byte-stream=true",
		"aud=false",
	}}
}

// StartTestCapture creates a synthetic H.264 video stream using GStreamer's
// videotestsrc + x264enc, producing High profile Annex-B byte stream output.
// This replicates the same GStreamer pipeline ecosystem that UxPlay uses on the
// receiver side.
func StartTestCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	bitrate := captureBitrateKbps(cfg)
	keyframeInterval := keyframeIntervalFrames(fps)

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
		"speed-preset=superfast",
		fmt.Sprintf("bitrate=%d", bitrate),
		fmt.Sprintf("key-int-max=%d", keyframeInterval),
		"threads=1",
		"sliced-threads=true",
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

func captureBitrateKbps(cfg CaptureConfig) int {
	if cfg.Bitrate > 0 {
		return cfg.Bitrate
	}

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	width := cfg.Width
	if width <= 0 {
		width = 1920
	}
	height := cfg.Height
	if height <= 0 {
		height = 1080
	}

	bitrate := recommendedBitrateKbps(width, height, fps)
	log.Printf("[CAPTURE] auto bitrate selected: %d kbps for %dx%d@%dfps", bitrate, width, height, fps)
	return bitrate
}

func recommendedBitrateKbps(width, height, fps int) int {
	if width <= 0 || height <= 0 || fps <= 0 {
		return defaultVideoBitrateKbps
	}

	bitrate := (width*height*fps + 7500) / 15000
	if bitrate < minVideoBitrateKbps {
		return minVideoBitrateKbps
	}
	if bitrate > maxVideoBitrateKbps {
		return maxVideoBitrateKbps
	}
	return bitrate
}

func keyframeIntervalFrames(fps int) int {
	if fps <= 0 {
		fps = 30
	}
	return fps * 4
}

// vbvBufferKbit returns the x264 VBV buffer size in kbit for the given bitrate
// and FPS. Sized at ~2 frames of data — enough headroom for the encoder to
// handle scene changes without severe quality oscillation, but tight enough to
// prevent large burst spikes that choke Wi-Fi links.
func vbvBufferKbit(bitrateKbps, fps int) int {
	if bitrateKbps <= 0 || fps <= 0 {
		return 300
	}
	vbv := bitrateKbps * 2 / fps
	if vbv < 200 {
		return 200
	}
	return vbv
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
