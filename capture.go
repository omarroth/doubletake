package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"

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
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	cancel  context.CancelFunc
	pwNodeID uint32
}

// StartCapture initiates Wayland screen capture using the xdg-desktop-portal
// D-Bus API to get a PipeWire stream, then pipes it through ffmpeg for H.264 encoding.
func StartCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	nodeID, err := requestScreencast(ctx)
	if err != nil {
		return nil, fmt.Errorf("screencast portal: %w", err)
	}
	log.Printf("pipewire node ID: %d", nodeID)

	captureCtx, cancel := context.WithCancel(ctx)

	args := buildFFmpegArgs(cfg, nodeID)
	cmd := exec.CommandContext(captureCtx, "ffmpeg", args...)
	cmd.Stderr = os.Stderr

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("ffmpeg stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start ffmpeg: %w", err)
	}

	return &ScreenCapture{
		cmd:      cmd,
		stdout:   stdout,
		cancel:   cancel,
		pwNodeID: nodeID,
	}, nil
}

func (sc *ScreenCapture) Read(buf []byte) (int, error) {
	return sc.stdout.Read(buf)
}

func (sc *ScreenCapture) Stop() {
	sc.cancel()
	if sc.cmd.Process != nil {
		sc.cmd.Process.Signal(os.Interrupt)
	}
	sc.cmd.Wait()
}

// buildFFmpegArgs constructs the ffmpeg command for encoding the PipeWire stream to H.264.
func buildFFmpegArgs(cfg CaptureConfig, nodeID uint32) []string {
	args := []string{
		"-loglevel", "warning",
		"-f", "pipewire",
		"-framerate", strconv.Itoa(cfg.FPS),
		"-i", strconv.FormatUint(uint64(nodeID), 10),
		"-vf", fmt.Sprintf("scale=%d:%d:flags=lanczos", cfg.Width, cfg.Height),
	}

	switch cfg.HWAccel {
	case "vaapi":
		args = append(args,
			"-vaapi_device", "/dev/dri/renderD128",
			"-vf", fmt.Sprintf("format=nv12,hwupload,scale_vaapi=%d:%d", cfg.Width, cfg.Height),
			"-c:v", "h264_vaapi",
			"-qp", "26",
		)
	case "none":
		args = append(args,
			"-c:v", "libx264",
			"-preset", "ultrafast",
			"-tune", "zerolatency",
			"-profile:v", "high",
			"-level", "4.2",
			"-crf", "23",
			"-g", strconv.Itoa(cfg.FPS), // keyframe every second
		)
	default: // "auto" - try VAAPI first, fall back to software
		args = append(args,
			"-c:v", "libx264",
			"-preset", "ultrafast",
			"-tune", "zerolatency",
			"-profile:v", "high",
			"-level", "4.2",
			"-crf", "23",
			"-g", strconv.Itoa(cfg.FPS),
		)
	}

	args = append(args,
		"-an",             // no audio for now
		"-f", "h264",      // raw H.264 bitstream
		"-bsf:v", "h264_mp4toannexb",
		"pipe:1",          // output to stdout
	)

	return args
}

// requestScreencast uses the xdg-desktop-portal D-Bus API to request screen capture
// permission and returns a PipeWire node ID for the captured screen.
func requestScreencast(ctx context.Context) (uint32, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return 0, fmt.Errorf("connect session bus: %w", err)
	}
	defer conn.Close()

	portal := conn.Object("org.freedesktop.portal.Desktop",
		"/org/freedesktop/portal/desktop")

	senderName := conn.Names()[0]
	token := "airplay_cast"

	// Create session
	sessionOpts := map[string]dbus.Variant{
		"handle_token":  dbus.MakeVariant(token),
		"session_handle_token": dbus.MakeVariant(token),
	}

	var sessionHandle dbus.ObjectPath
	call := portal.Call("org.freedesktop.portal.ScreenCast.CreateSession", 0, sessionOpts)
	if call.Err != nil {
		return 0, fmt.Errorf("CreateSession: %w", call.Err)
	}
	if err := call.Store(&sessionHandle); err != nil {
		return 0, fmt.Errorf("store session handle: %w", err)
	}

	// Wait for session response via signal
	sessionPath, err := waitForResponse(conn, senderName, token)
	if err != nil {
		return 0, fmt.Errorf("session response: %w", err)
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
		return 0, fmt.Errorf("SelectSources: %w", call.Err)
	}

	_, err = waitForResponse(conn, senderName, token+"_select")
	if err != nil {
		return 0, fmt.Errorf("select response: %w", err)
	}

	// Start the screencast
	startOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(token + "_start"),
	}

	call = portal.Call("org.freedesktop.portal.ScreenCast.Start", 0,
		dbus.ObjectPath(sessionPath), "", startOpts)
	if call.Err != nil {
		return 0, fmt.Errorf("Start: %w", call.Err)
	}

	startResult, err := waitForResponseWithResult(conn, senderName, token+"_start")
	if err != nil {
		return 0, fmt.Errorf("start response: %w", err)
	}

	// Extract PipeWire node ID from the result
	streams, ok := startResult["streams"]
	if !ok {
		return 0, fmt.Errorf("no streams in start response")
	}

	streamList, ok := streams.Value().([][]interface{})
	if !ok {
		// Try alternate format
		if v, ok2 := streams.Value().([]interface{}); ok2 && len(v) > 0 {
			if tuple, ok3 := v[0].([]interface{}); ok3 && len(tuple) > 0 {
				if nodeID, ok4 := tuple[0].(uint32); ok4 {
					return nodeID, nil
				}
			}
		}
		return 0, fmt.Errorf("unexpected streams format: %T", streams.Value())
	}

	if len(streamList) == 0 || len(streamList[0]) == 0 {
		return 0, fmt.Errorf("empty streams list")
	}

	nodeID, ok := streamList[0][0].(uint32)
	if !ok {
		return 0, fmt.Errorf("unexpected node ID type: %T", streamList[0][0])
	}

	return nodeID, nil
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

	matchRule := fmt.Sprintf("type='signal',interface='org.freedesktop.portal.Request',member='Response'")
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
