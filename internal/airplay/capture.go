package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
)

// CaptureConfig holds screen capture settings.
type CaptureConfig struct {
	FPS        int
	Bitrate    int        // Video bitrate in kbps (0 = auto)
	HWAccel    string     // "auto", "nvenc", "vaapi", "openh264", or "none"
	VideoCodec VideoCodec // empty/h264, auto (resolved before Start), or hevc

	// MaxWidth/MaxHeight select the encoded canvas advertised by the receiver.
	// The captured image is aspect-fitted into it. Zero leaves the capture at
	// its native size.
	MaxWidth  int
	MaxHeight int

	X11WindowID   uint64
	X11WindowName string

	ShowCursor bool // show the mouse cursor in the captured video (Wayland and X11)

	RestoreToken     string
	SaveRestoreToken func(string) error
}

// ValidateHWAccel checks a capture encoder preference. An empty value keeps the
// zero-value CaptureConfig useful and is treated as auto.
func ValidateHWAccel(method string) error {
	switch method {
	case "", "auto", "nvenc", "vaapi", "openh264", "none":
		return nil
	default:
		return fmt.Errorf("unknown encoder %q (want auto, nvenc, vaapi, openh264, or none)", method)
	}
}

const (
	defaultVideoBitrateKbps = 4500
	minVideoBitrateKbps     = 1800
	maxVideoBitrateKbps     = 12000

	// Synthetic test capture has no real display to size itself from, so it
	// uses a fixed resolution.
	testCaptureWidth  = 1920
	testCaptureHeight = 1080
)

// ScreenCapture manages screen capture via GStreamer.
type ScreenCapture struct {
	cmd      *exec.Cmd // gst-launch-1.0 process
	stdout   io.ReadCloser
	frames   videoAccessUnitReader
	cancel   context.CancelFunc
	pwNodeID uint32
	portal   io.Closer     // portal session (must stay open for Wayland)
	waitCh   chan struct{} // closed when process exits
	waitErr  error         // set before waitCh is closed
	stopped  bool
	stopOnce sync.Once
	stderr   *captureStderrTail
}

type pipeWirePortalSession interface {
	io.Closer
	openPipeWireRemote(context.Context) (*os.File, error)
}

type capturePreparationKind uint8

const (
	capturePreparationX11 capturePreparationKind = iota
	capturePreparationWayland
	capturePreparationTest
)

// CapturePreparation performs the potentially interactive part of screen
// capture before the receiver session starts. In particular, a Wayland
// preparation completes the screencast portal request and retains its PipeWire
// connection without starting the encoder. Start can then apply display
// dimensions learned from the receiver's control SETUP without putting portal
// UI inside the receiver's first-frame deadline.
//
// A preparation is single-use. Call Close when it will not be started.
type CapturePreparation struct {
	mu   sync.Mutex
	ctx  context.Context
	cfg  CaptureConfig
	kind capturePreparationKind
	used bool

	timestampedOutput  bool
	automaticHEVCAvail bool
	// measuredVideoLatency is the minimum screen lead measured by the local 4K
	// HEVC preflight. It is zero for H.264 and unmeasured software fallback.
	measuredVideoLatency time.Duration

	pwNodeID   uint32
	pwFd       *os.File
	portal     pipeWirePortalSession
	streamSize [2]int
}

// StartCapture detects the display server (Wayland or X11) and initiates screen
// capture accordingly. On Wayland it uses xdg-desktop-portal + PipeWire for
// capture; on X11 it uses ximagesrc. Both use the selected GStreamer encoder.
func StartCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	if cfg.VideoCodec == VideoCodecAuto {
		return nil, fmt.Errorf("automatic video codec requires PrepareCapture followed by StartWithCodec")
	}
	preparation, err := PrepareCapture(ctx, cfg)
	if err != nil {
		return nil, err
	}
	capture, err := preparation.Start(cfg.MaxWidth, cfg.MaxHeight)
	if err != nil {
		preparation.Close()
		return nil, err
	}
	return capture, nil
}

const displaySourceProbeTimeout = 3 * time.Second

// probeWaylandDisplay verifies the compositor endpoint before invoking a
// portal backend. A long-lived service may retain WAYLAND_DISPLAY after the
// desktop session has removed its socket, in which case the portal chooser can
// otherwise wait forever for a display that no longer exists.
func probeWaylandDisplay(ctx context.Context, display string) error {
	address := display
	if !filepath.IsAbs(address) {
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir == "" {
			return fmt.Errorf("WAYLAND_DISPLAY=%q is set but XDG_RUNTIME_DIR is empty", display)
		}
		address = filepath.Join(runtimeDir, address)
	}
	probeCtx, cancel := context.WithTimeout(normalizeContext(ctx), displaySourceProbeTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(probeCtx, "unix", address)
	if err != nil {
		return fmt.Errorf("WAYLAND_DISPLAY=%q does not identify a reachable compositor at %s: %w", display, address, err)
	}
	if err := conn.Close(); err != nil {
		return fmt.Errorf("close Wayland display probe for %s: %w", address, err)
	}
	return nil
}

// probeX11CaptureSource lets ximagesrc perform the actual X11 handshake rather
// than duplicating DISPLAY parsing or authentication. It runs before receiver
// SETUP so a stale display cannot leave a remote media session half-created.
func probeX11CaptureSource(ctx context.Context, display string, cfg CaptureConfig) error {
	probeCtx, cancel := context.WithTimeout(normalizeContext(ctx), displaySourceProbeTimeout)
	defer cancel()
	source := gstStage{
		"ximagesrc",
		fmt.Sprintf("display-name=%s", display),
		"num-buffers=1",
		"use-damage=false",
	}
	if cfg.X11WindowID != 0 {
		source = append(source, fmt.Sprintf("xid=%d", cfg.X11WindowID))
	} else if cfg.X11WindowName != "" {
		source = append(source, fmt.Sprintf("xname=%s", cfg.X11WindowName))
	}
	args := append([]string{"--quiet"}, source...)
	args = appendGstStage(args, gstStage{"fakesink", "sync=false", "async=false"})
	cmd := exec.CommandContext(probeCtx, "gst-launch-1.0", args...)
	cmd.Stdout = io.Discard
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if probeCtx.Err() != nil {
		return fmt.Errorf("validate X11 capture source on DISPLAY=%q: %w", display, probeCtx.Err())
	}
	if err == nil {
		return nil
	}
	diagnostic := strings.TrimSpace(stderr.String())
	if len(diagnostic) > maxCaptureStderrTailBytes {
		diagnostic = diagnostic[len(diagnostic)-maxCaptureStderrTailBytes:]
	}
	if diagnostic == "" {
		return fmt.Errorf("validate X11 capture source on DISPLAY=%q: %w", display, err)
	}
	return fmt.Errorf("validate X11 capture source on DISPLAY=%q: %w; GStreamer stderr: %s", display, err, diagnostic)
}

// PrepareCapture selects and validates the capture path. Wayland portal access
// is acquired immediately; X11 needs no external session and is merely
// validated until Start is called.
func PrepareCapture(ctx context.Context, cfg CaptureConfig) (*CapturePreparation, error) {
	if err := ValidateVideoCodec(string(cfg.VideoCodec)); err != nil {
		return nil, err
	}
	if err := ValidateHWAccel(cfg.HWAccel); err != nil {
		return nil, err
	}
	kind := capturePreparationX11
	if (cfg.X11WindowID != 0 || cfg.X11WindowName != "") && os.Getenv("DISPLAY") != "" {
		kind = capturePreparationX11
	} else if os.Getenv("WAYLAND_DISPLAY") != "" {
		kind = capturePreparationWayland
	} else if os.Getenv("DISPLAY") == "" {
		return nil, fmt.Errorf("no display server detected (neither WAYLAND_DISPLAY nor DISPLAY is set)")
	}

	validationCfg := cfg
	if validationCfg.VideoCodec == VideoCodecAuto {
		// Auto always retains a working H.264 fallback. HEVC is selected only
		// after SETUP supplies final display metadata.
		validationCfg.VideoCodec = VideoCodecH264
	}
	if _, err := selectGstEncoderWithProbe(validationCfg, hasGstElement, false); err != nil {
		return nil, err
	}
	preparation := &CapturePreparation{
		ctx:               ctx,
		cfg:               cfg,
		kind:              kind,
		timestampedOutput: supportsTimestampedVideoOutput(normalizeVideoCodec(validationCfg.VideoCodec)),
	}
	if cfg.VideoCodec == VideoCodecAuto {
		preparation.automaticHEVCAvail, preparation.measuredVideoLatency = automaticHEVCProfile(cfg.HWAccel, cfg.FPS)
	} else if cfg.VideoCodec == VideoCodecHEVC {
		// Forced NVENC HEVC uses the same local pipeline and benefits from the
		// same scheduling calibration. Explicit software x265 remains a deliberate
		// opt-in and can be tuned with the joint latency override.
		_, preparation.measuredVideoLatency = automaticHEVCProfile(cfg.HWAccel, cfg.FPS)
	}
	if cfg.VideoCodec == VideoCodecHEVC && !preparation.timestampedOutput {
		return nil, fmt.Errorf("HEVC capture requires GStreamer rtph265pay, rtponviftimestamp, and rtpstreampay")
	}
	if cfg.VideoCodec == VideoCodecHEVC && !hasGstElement("h265parse") {
		return nil, fmt.Errorf("HEVC capture requires GStreamer h265parse")
	}
	if !preparation.timestampedOutput {
		log.Printf("[CAPTURE] warning: GStreamer RTP/ONVIF timestamp elements are unavailable; video will use output-time timestamps")
	}
	if kind == capturePreparationX11 {
		if err := exec.Command("gst-inspect-1.0", "ximagesrc").Run(); err != nil {
			return nil, fmt.Errorf("GStreamer 'ximagesrc' plugin not found; install gst-plugins-good")
		}
		if err := probeX11CaptureSource(ctx, os.Getenv("DISPLAY"), cfg); err != nil {
			return nil, err
		}
		return preparation, nil
	}

	if err := exec.Command("gst-inspect-1.0", "pipewiresrc").Run(); err != nil {
		return nil, fmt.Errorf("GStreamer 'pipewiresrc' plugin not found; install gst-pipewire")
	}
	if err := probeWaylandDisplay(ctx, os.Getenv("WAYLAND_DISPLAY")); err != nil {
		return nil, err
	}
	nodeID, pwFd, portal, restoreToken, err := requestScreencast(ctx, cfg.RestoreToken, cfg.ShowCursor, &preparation.streamSize)
	if err != nil {
		return nil, fmt.Errorf("screencast portal: %w", err)
	}
	if restoreToken != "" && cfg.SaveRestoreToken != nil {
		if err := cfg.SaveRestoreToken(restoreToken); err != nil {
			log.Printf("[CAPTURE] warning: failed to save screencast restore token: %v", err)
		}
	}
	dbg("pipewire node ID: %d", nodeID)
	preparation.pwNodeID = nodeID
	preparation.pwFd = pwFd
	preparation.portal = portal
	return preparation, nil
}

// PrepareTestCapture validates a synthetic capture without starting its
// GStreamer process. It mirrors PrepareCapture for callers that negotiate the
// receiver canvas between preparation and encoder startup.
func PrepareTestCapture(ctx context.Context, cfg CaptureConfig) (*CapturePreparation, error) {
	if err := ValidateVideoCodec(string(cfg.VideoCodec)); err != nil {
		return nil, err
	}
	if err := ValidateHWAccel(cfg.HWAccel); err != nil {
		return nil, err
	}
	validationCfg := cfg
	if validationCfg.VideoCodec == VideoCodecAuto {
		validationCfg.VideoCodec = VideoCodecH264
	}
	if _, err := selectGstEncoderWithProbe(validationCfg, hasGstElement, false); err != nil {
		return nil, err
	}
	preparation := &CapturePreparation{
		ctx:               ctx,
		cfg:               cfg,
		kind:              capturePreparationTest,
		timestampedOutput: supportsTimestampedVideoOutput(normalizeVideoCodec(validationCfg.VideoCodec)),
	}
	if cfg.VideoCodec == VideoCodecAuto {
		preparation.automaticHEVCAvail, preparation.measuredVideoLatency = automaticHEVCProfile(cfg.HWAccel, cfg.FPS)
	} else if cfg.VideoCodec == VideoCodecHEVC {
		_, preparation.measuredVideoLatency = automaticHEVCProfile(cfg.HWAccel, cfg.FPS)
	}
	if cfg.VideoCodec == VideoCodecHEVC && !preparation.timestampedOutput {
		return nil, fmt.Errorf("HEVC capture requires GStreamer rtph265pay, rtponviftimestamp, and rtpstreampay")
	}
	if cfg.VideoCodec == VideoCodecHEVC && !hasGstElement("h265parse") {
		return nil, fmt.Errorf("HEVC capture requires GStreamer h265parse")
	}
	return preparation, nil
}

// Start launches the prepared encoder using the supplied nominal receiver
// canvas. Zero dimensions leave the captured source at its native size.
func (p *CapturePreparation) Start(width, height int) (*ScreenCapture, error) {
	return p.startWithContextAndCodec(nil, width, height, "")
}

// StartWithContext is Start with an optional lifetime context for the launched
// encoder. The portal acquisition remains tied to the preparation context, but
// daemon capture groups use an independent context so the encoder can outlive
// the receiver which happened to create that shared group.
func (p *CapturePreparation) StartWithContext(lifetime context.Context, width, height int) (*ScreenCapture, error) {
	return p.startWithContextAndCodec(lifetime, width, height, "")
}

// StartWithCodec launches an automatic preparation after receiver negotiation
// has selected one concrete codec. Explicit preparations accept only their
// configured codec, preventing the capture and AirPlay framing from diverging.
func (p *CapturePreparation) StartWithCodec(width, height int, codec VideoCodec) (*ScreenCapture, error) {
	return p.startWithContextAndCodec(nil, width, height, codec)
}

// StartWithContextAndCodec combines StartWithContext and StartWithCodec for
// daemon capture groups whose encoder may outlive the receiver that created it.
func (p *CapturePreparation) StartWithContextAndCodec(lifetime context.Context, width, height int, codec VideoCodec) (*ScreenCapture, error) {
	return p.startWithContextAndCodec(lifetime, width, height, codec)
}

func (p *CapturePreparation) startWithContextAndCodec(lifetime context.Context, width, height int, selected VideoCodec) (*ScreenCapture, error) {
	if p == nil {
		return nil, fmt.Errorf("capture preparation is nil")
	}
	p.mu.Lock()
	if p.used {
		p.mu.Unlock()
		return nil, fmt.Errorf("capture preparation has already been used")
	}
	cfg := p.cfg
	requested := cfg.VideoCodec
	if requested == "" {
		requested = VideoCodecH264
	}
	if requested == VideoCodecAuto {
		if selected != VideoCodecH264 && selected != VideoCodecHEVC {
			p.mu.Unlock()
			return nil, fmt.Errorf("automatic video codec has not been resolved")
		}
		if selected == VideoCodecHEVC && !p.automaticHEVCAvail {
			p.mu.Unlock()
			return nil, fmt.Errorf("automatic HEVC selection exceeds the prepared local encoder capabilities")
		}
		cfg.VideoCodec = selected
	} else {
		if selected != "" && selected != requested {
			p.mu.Unlock()
			return nil, fmt.Errorf("capture prepared for %s, not %s", requested, selected)
		}
		cfg.VideoCodec = requested
	}
	if err := ValidateVideoCodec(string(cfg.VideoCodec)); err != nil || cfg.VideoCodec == VideoCodecAuto {
		p.mu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("automatic video codec has not been resolved")
	}
	p.used = true
	cfg.MaxWidth = width
	cfg.MaxHeight = height
	kind := p.kind
	captureCtx := lifetime
	if captureCtx == nil {
		captureCtx = p.ctx
	}
	if captureCtx == nil {
		captureCtx = context.Background()
	}
	startupCtx := p.ctx
	if startupCtx == nil {
		startupCtx = captureCtx
	}
	nodeID := p.pwNodeID
	pwFd := p.pwFd
	portal := p.portal
	streamSize := p.streamSize
	timestampedOutput := supportsTimestampedVideoOutput(cfg.VideoCodec)
	p.pwFd = nil
	p.portal = nil
	p.mu.Unlock()
	if cfg.VideoCodec == VideoCodecHEVC && !timestampedOutput {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if portal != nil {
			_ = portal.Close()
		}
		return nil, fmt.Errorf("HEVC capture requires GStreamer rtph265pay, rtponviftimestamp, and rtpstreampay")
	}
	if cfg.VideoCodec == VideoCodecHEVC && !hasGstElement("h265parse") {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if portal != nil {
			_ = portal.Close()
		}
		return nil, fmt.Errorf("HEVC capture requires GStreamer h265parse")
	}
	encoder, err := detectGstEncoder(cfg)
	if err != nil {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if portal != nil {
			_ = portal.Close()
		}
		return nil, err
	}

	switch kind {
	case capturePreparationWayland:
		return startPreparedWaylandCapture(startupCtx, captureCtx, cfg, encoder, nodeID, pwFd, portal, streamSize, timestampedOutput)
	case capturePreparationX11:
		return startPreparedX11Capture(startupCtx, captureCtx, cfg, encoder, timestampedOutput)
	case capturePreparationTest:
		return startPreparedTestCapture(captureCtx, cfg, encoder, timestampedOutput)
	default:
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if portal != nil {
			_ = portal.Close()
		}
		return nil, fmt.Errorf("invalid capture preparation kind %d", kind)
	}
}

// AutomaticHEVCAvailable reports whether preflight found the hardware encoder
// and timestamp-preserving GStreamer elements required by the normal automatic
// high-resolution path. Explicit HEVC may still use x265 software encoding.
func (p *CapturePreparation) AutomaticHEVCAvailable() bool {
	if p == nil {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.automaticHEVCAvail
}

// MeasuredVideoLatency returns the minimum video presentation lead measured by
// the 4K HEVC preflight. Callers pass it into StreamConfig so the
// audio and video timelines can receive the same additional scheduling room.
// It is zero when the selected local encoder path was not measured.
func (p *CapturePreparation) MeasuredVideoLatency() time.Duration {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.measuredVideoLatency
}

// Close releases an unconsumed portal preparation. Once Start has taken
// ownership, ScreenCapture.Stop owns the corresponding resources.
func (p *CapturePreparation) Close() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.used {
		p.mu.Unlock()
		return
	}
	p.used = true
	pwFd := p.pwFd
	portal := p.portal
	p.pwFd = nil
	p.portal = nil
	p.mu.Unlock()
	if pwFd != nil {
		_ = pwFd.Close()
	}
	if portal != nil {
		_ = portal.Close()
	}
}

func hasGstElement(name string) bool {
	return exec.Command("gst-inspect-1.0", name).Run() == nil
}

func supportsTimestampedVideoOutput(codec VideoCodec) bool {
	return supportsTimestampedVideoOutputWithProbe(codec, hasGstElement)
}

func supportsTimestampedVideoOutputWithProbe(codec VideoCodec, hasElement func(string) bool) bool {
	payloader := "rtph264pay"
	if normalizeVideoCodec(codec) == VideoCodecHEVC {
		payloader = "rtph265pay"
	}
	for _, element := range []string{payloader, "rtponviftimestamp", "rtpstreampay"} {
		if !hasElement(element) {
			return false
		}
	}
	return true
}

// automaticHEVCAvailableWithProbe is deliberately stricter than explicit
// HEVC selection. Apple's automatic high-resolution gate asks whether the
// sender has a hardware HEVC-4K path; merely finding x265 is not enough to make
// 4K software encoding the normal default.
func automaticHEVCAvailableWithProbe(hwaccel string, hasElement func(string) bool) bool {
	if hwaccel == "" {
		hwaccel = "auto"
	}
	if hwaccel != "auto" && hwaccel != "nvenc" {
		return false
	}
	for _, element := range []string{"nvh265enc", "h265parse"} {
		if !hasElement(element) {
			return false
		}
	}
	return supportsTimestampedVideoOutputWithProbe(VideoCodecHEVC, hasElement)
}

type automaticHEVCProbeResult struct {
	once sync.Once
	ok   bool
	lead time.Duration
}

var automaticHEVCProbeResults sync.Map // map[int]*automaticHEVCProbeResult, keyed by FPS

const (
	automaticHEVCProbeFrames       = 45
	automaticHEVCProbeWarmupFrames = 10
	liveHEVCProbeFrames            = 20
	liveHEVCProbeWarmupFrames      = 5
	// The screen timestamp equation requires capture, encode, transport, and
	// decoder work to fit inside the presentation lead. Apple's ordinary
	// virtual-display source also bounds queued
	// frames to 67 ms. Apple uses that as an upstream drop ceiling, not a decoder
	// allowance; using the same duration here is Doubletake's conservative
	// delivery-room heuristic after local source-to-AU age. Never reserve less
	// than two frame periods at lower rates.
	ordinaryScreenFrameQueueDuration = 67 * time.Millisecond
	maximumAutomaticVideoLead        = 500 * time.Millisecond
	minimumLiveVideoProbeTimeout     = 3 * time.Second
)

func liveVideoProbeTimeout(fps int) time.Duration {
	if fps <= 0 {
		fps = 30
	}
	frames := liveHEVCProbeWarmupFrames + liveHEVCProbeFrames
	sampleWindow := (time.Duration(frames)*time.Second + time.Duration(fps) - 1) / time.Duration(fps)
	// In addition to the nominal sample window, allow the launched encoder two
	// seconds to negotiate resources and emit its first complete access unit.
	timeout := sampleWindow + 2*time.Second
	if timeout < minimumLiveVideoProbeTimeout {
		return minimumLiveVideoProbeTimeout
	}
	return timeout
}

func automaticVideoDeliveryMargin(fps int) time.Duration {
	if fps <= 0 {
		fps = 30
	}
	margin := (2*time.Second + time.Duration(fps) - 1) / time.Duration(fps)
	if margin < ordinaryScreenFrameQueueDuration {
		margin = ordinaryScreenFrameQueueDuration
	}
	return margin
}

func recommendedAutomaticVideoLatency(ages []time.Duration, fps int) (time.Duration, bool) {
	if len(ages) == 0 {
		return 0, false
	}
	ages = append([]time.Duration(nil), ages...)
	sort.Slice(ages, func(i, j int) bool { return ages[i] < ages[j] })
	// Use p95 so one scheduler outlier does not permanently inflate latency, but
	// normal encoder jitter still has delivery room. Round up to whole ms because
	// RTSP advertises latencyMs and the audio descriptor uses integral samples.
	index := (len(ages)*95 + 99) / 100
	if index < 1 {
		index = 1
	}
	p95 := ages[index-1]
	lead := p95 + automaticVideoDeliveryMargin(fps)
	if lead < defaultVideoLatencyNormal {
		lead = defaultVideoLatencyNormal
	}
	lead = (lead + time.Millisecond - 1) / time.Millisecond * time.Millisecond
	if lead > maximumAutomaticVideoLead {
		return 0, false
	}
	return lead, true
}

func measureVideoCaptureLatency(ctx context.Context, capture *ScreenCapture, fps, warmupFrames, measuredFrames int) (time.Duration, error) {
	if capture == nil {
		return 0, fmt.Errorf("measure video latency: nil capture")
	}
	if warmupFrames < 0 || measuredFrames <= 0 {
		return 0, fmt.Errorf("measure video latency: invalid sample counts %d/%d", warmupFrames, measuredFrames)
	}
	ages := make([]time.Duration, 0, measuredFrames)
	for frame := 0; frame < warmupFrames+measuredFrames; frame++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		unit, err := capture.ReadVideoAccessUnit()
		if err != nil {
			return 0, err
		}
		if frame < warmupFrames || unit.PTS.IsZero() {
			continue
		}
		age := time.Since(unit.PTS)
		if age < 0 || age > maximumAutomaticVideoLead {
			return 0, fmt.Errorf("capture produced implausible source age %v", age)
		}
		ages = append(ages, age)
	}
	lead, ok := recommendedAutomaticVideoLatency(ages, fps)
	if !ok {
		return 0, fmt.Errorf("capture cannot satisfy the bounded presentation lead")
	}
	return lead, nil
}

// MeasureVideoCaptureLatency consumes a short startup sample from an already
// launched timestamped HEVC capture and returns the minimum presentation lead
// for that real source, scaling, and encoder path. It must run before any other
// reader or BroadcastCapture is attached. The discarded startup access units
// are intentional; subsequent fan-out begins with a complete access unit. A
// canceled or timed-out measurement stops the capture to interrupt its reader,
// so callers must discard that capture.
func MeasureVideoCaptureLatency(ctx context.Context, capture *ScreenCapture, fps int) (time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, liveVideoProbeTimeout(fps))
	defer cancel()
	type result struct {
		lead time.Duration
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		lead, err := measureVideoCaptureLatency(probeCtx, capture, fps, liveHEVCProbeWarmupFrames, liveHEVCProbeFrames)
		resultCh <- result{lead: lead, err: err}
	}()

	select {
	case measured := <-resultCh:
		return measured.lead, measured.err
	case <-probeCtx.Done():
		// ReadVideoAccessUnit ultimately blocks in the capture pipe. Destroying a
		// capture which cannot provide startup frames is the only safe interrupt:
		// returning while its reader goroutine remains active would race fan-out.
		// The caller treats this as failed preparation and does not reuse it.
		select {
		case measured := <-resultCh:
			return measured.lead, measured.err
		default:
		}
		capture.Stop()
		<-resultCh
		return 0, probeCtx.Err()
	}
}

func probeAutomaticHEVC(fps int) (bool, time.Duration) {
	if fps <= 0 {
		fps = 30
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cfg := CaptureConfig{
		FPS:        fps,
		Bitrate:    maxVideoBitrateKbps,
		HWAccel:    "nvenc",
		VideoCodec: VideoCodecHEVC,
		MaxWidth:   3840,
		MaxHeight:  2160,
	}
	encoder, err := selectGstEncoderWithProbe(cfg, hasGstElement, false)
	if err != nil {
		dbg("[CAPTURE] automatic HEVC encoder probe failed: %v", err)
		return false, 0
	}
	capture, err := startPreparedTestCapture(ctx, cfg, encoder, true)
	if err != nil {
		dbg("[CAPTURE] automatic HEVC pipeline probe failed: %v", err)
		return false, 0
	}
	defer capture.Stop()

	lead, err := measureVideoCaptureLatency(ctx, capture, fps,
		automaticHEVCProbeWarmupFrames,
		automaticHEVCProbeFrames-automaticHEVCProbeWarmupFrames)
	if err != nil {
		dbg("[CAPTURE] automatic HEVC pipeline timing probe failed: %v", err)
		return false, 0
	}
	return true, lead
}

func automaticHEVCProfile(hwaccel string, fps int) (bool, time.Duration) {
	if !automaticHEVCAvailableWithProbe(hwaccel, hasGstElement) {
		return false, 0
	}
	if fps <= 0 {
		fps = 30
	}
	value, _ := automaticHEVCProbeResults.LoadOrStore(fps, &automaticHEVCProbeResult{})
	result := value.(*automaticHEVCProbeResult)
	result.once.Do(func() {
		// Factory presence alone does not prove that the installed NVIDIA stack
		// can sustain timestamped 4K Main10 within a useful presentation budget.
		// Exercise the actual capture suffix and retain its source-to-AU p95.
		result.ok, result.lead = probeAutomaticHEVC(fps)
		if result.ok {
			dbg("[CAPTURE] automatic HEVC 4K Main10 %dfps probe passed (minimum video lead %v)", fps, result.lead)
		} else {
			dbg("[CAPTURE] automatic HEVC %dfps hardware probe failed; retaining H.264", fps)
		}
	})
	return result.ok, result.lead
}

func automaticHEVCAvailable(hwaccel string) bool {
	ok, _ := automaticHEVCProfile(hwaccel, 30)
	return ok
}

// startGStreamerCommand starts a capture child whose lifetime cannot outlive
// doubletake. Linux delivers Pdeathsig when the creating OS thread exits, not
// strictly when the whole process exits, so the supervising goroutine keeps
// that thread locked until Wait completes.
func startGStreamerCommand(cmd *exec.Cmd) (<-chan error, error) {
	started := make(chan error, 1)
	waitResult := make(chan error, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		err := cmd.Start()
		started <- err
		if err != nil {
			close(waitResult)
			return
		}
		waitResult <- cmd.Wait()
		close(waitResult)
	}()

	if err := <-started; err != nil {
		return nil, err
	}
	return waitResult, nil
}

// gstStage is one GStreamer element (or caps filter) followed by its arguments.
// Keeping separators out of stages makes it difficult for source-specific
// pipelines to accidentally diverge in the shared encoding path.
type gstStage []string

type encoderInputMemory uint8

const (
	encoderInputSystemMemory encoderInputMemory = iota
	encoderInputVAMemory
)

// encoderResult holds the selected encoder stage and its input requirements.
type encoderResult struct {
	parts       gstStage
	needsVulkan bool   // encoder needs vulkanupload immediately before it
	rawFormat   string // raw format accepted by the encoder
	codec       VideoCodec
	inputMemory encoderInputMemory
}

type waylandPipelineMode uint8

const (
	waylandPipelineSystemMemory waylandPipelineMode = iota
	waylandPipelineVAMemory
)

type waylandCapturePlan struct {
	encoder encoderResult
	mode    waylandPipelineMode
}

func (p waylandCapturePlan) String() string {
	encoder := "GStreamer encoder"
	if len(p.encoder.parts) != 0 {
		encoder = p.encoder.parts[0]
	}
	if p.mode == waylandPipelineVAMemory {
		return encoder + " with native VA frame import"
	}
	return encoder + " with system-memory frame staging"
}

func frameRateStage(fps int) gstStage {
	return gstStage{fmt.Sprintf("video/x-raw,framerate=%d/1", fps)}
}

func frameIntervalMillis(fps int) int {
	if fps <= 0 {
		fps = 30
	}
	return max(1, 1000/fps)
}

func pipeWireVideoSourceStage(fd int, nodeID uint32, fps int, alwaysCopy bool) gstStage {
	stage := gstStage{
		"pipewiresrc",
		fmt.Sprintf("fd=%d", fd),
		fmt.Sprintf("path=%d", nodeID),
		"do-timestamp=true",
		fmt.Sprintf("keepalive-time=%d", frameIntervalMillis(fps)),
	}
	if alwaysCopy {
		// Retaining elements downstream must never hold every buffer in the
		// portal's small pool. Native import paths establish their own ownership
		// boundary instead, because pipewiresrc cannot copy every DMA-BUF.
		stage = append(stage, "always-copy=true")
	}
	return stage
}

func lowLatencyVideoQueueStage() gstStage {
	// Drop stale raw frames before encoding. Encoded P-frames may reference
	// earlier frames, so dropping them downstream would corrupt the codec chain.
	return gstStage{
		"queue",
		"max-size-buffers=1",
		"max-size-bytes=0",
		"max-size-time=0",
		"leaky=downstream",
	}
}

func appendGstStage(args []string, stage gstStage) []string {
	if len(stage) == 0 {
		return args
	}
	args = append(args, "!")
	return append(args, stage...)
}

// receiverScaleStages fits the captured image into the receiver's advertised
// canvas without changing its aspect ratio. Exact, even receiver dimensions
// are important here: bounded caps can negotiate an odd fitted width for a
// HiDPI source (for example 3024x1964 becomes 1109x720), which x264 cannot
// encode and some legacy mirror decoders reject. videoscale adds any necessary
// letterbox or pillarbox bars instead of stretching the image.
func receiverScaleStages(maxWidth, maxHeight int) []gstStage {
	if maxWidth <= 0 || maxHeight <= 0 {
		return nil
	}
	// Every encoder consumes 4:2:0 video. Keep each chroma plane integral and
	// never exceed an odd receiver limit.
	maxWidth &^= 1
	maxHeight &^= 1
	if maxWidth == 0 || maxHeight == 0 {
		return nil
	}
	return []gstStage{
		{"videoscale", "add-borders=true"},
		{fmt.Sprintf("video/x-raw,width=%d,height=%d,pixel-aspect-ratio=1/1", maxWidth, maxHeight)},
	}
}

// buildGstVideoPipeline joins source-specific stages to the one scaling,
// encoding, and Annex-B output path used by Wayland, X11, and synthetic test
// capture. beforeConvert and afterScale preserve the few ordering requirements
// that genuinely differ between capture sources.
func buildGstVideoPipeline(source gstStage, beforeConvert, afterScale []gstStage, encoder encoderResult, maxWidth, maxHeight int, timestampedOutput bool) []string {
	args := append([]string{"--quiet"}, source...)
	for _, stage := range beforeConvert {
		args = appendGstStage(args, stage)
	}

	args = appendGstStage(args, gstStage{"videoconvert"})
	args = appendGstStage(args, gstStage{fmt.Sprintf("video/x-raw,format=%s", encoder.rawFormat)})
	for _, stage := range receiverScaleStages(maxWidth, maxHeight) {
		args = appendGstStage(args, stage)
	}
	for _, stage := range afterScale {
		args = appendGstStage(args, stage)
	}
	if encoder.needsVulkan {
		args = appendGstStage(args, gstStage{"vulkanupload"})
	}
	return appendGstVideoEncoding(args, encoder, timestampedOutput)
}

func appendGstVideoEncoding(args []string, encoder encoderResult, timestampedOutput bool) []string {
	args = appendGstStage(args, encoder.parts)
	parser, mediaType, payloader := "h264parse", "video/x-h264", "rtph264pay"
	if encoder.codec == VideoCodecHEVC {
		parser, mediaType, payloader = "h265parse", "video/x-h265", "rtph265pay"
	}
	args = appendGstStage(args, gstStage{parser, "config-interval=-1"})
	args = appendGstStage(args, gstStage{mediaType + ",stream-format=byte-stream,alignment=au"})
	if timestampedOutput {
		// RTP marker bits retain access-unit boundaries, while the ONVIF header
		// extension serializes each encoded buffer's absolute capture PTS. The
		// RFC4571 length prefix makes the packet stream safe to carry over stdout.
		args = appendGstStage(args, gstStage{
			payloader, "pt=96", "mtu=60000", "aggregate-mode=none",
			"timestamp-offset=0", "seqnum-offset=0",
		})
		args = appendGstStage(args, gstStage{
			"rtponviftimestamp", "ntp-offset=-1", "set-e-bit=false", "set-t-bit=false",
		})
		args = appendGstStage(args, gstStage{"rtpstreampay"})
	}
	return appendGstStage(args, gstStage{"fdsink", "fd=1", "sync=false", "async=false"})
}

// buildVAWaylandVideoPipeline imports portal buffers without a CPU copy, then
// keeps conversion, scaling, and encoding in VA memory. PipeWire keepalives
// supply idle frames; videorate limits them to the requested output rate.
func buildVAWaylandVideoPipeline(fd int, nodeID uint32, fps int, encoder encoderResult, maxWidth, maxHeight int, timestampedOutput bool) []string {
	source := pipeWireVideoSourceStage(fd, nodeID, fps, false)
	args := append([]string{"--quiet"}, source...)
	// Desktop pixels are square. Without this constraint, the VA transform can
	// negotiate the minimum of its PAR range and fail to calculate borders.
	args = appendGstStage(args, gstStage{"video/x-raw(ANY),pixel-aspect-ratio=1/1"})
	// Force a fresh surface even when the source already matches the output.
	// Downstream retains the converted surface instead of another portal buffer.
	args = appendGstStage(args, gstStage{"vapostproc", "disable-passthrough=true", "add-borders=true"})
	caps := "video/x-raw(memory:VAMemory),format=NV12"
	if maxWidth > 1 && maxHeight > 1 {
		caps += fmt.Sprintf(",width=%d,height=%d,pixel-aspect-ratio=1/1", maxWidth&^1, maxHeight&^1)
	}
	args = appendGstStage(args, gstStage{caps})
	args = appendGstStage(args, gstStage{"videorate", "drop-only=true", "skip-to-first=true"})
	args = appendGstStage(args, gstStage{caps + fmt.Sprintf(",framerate=%d/1", fps)})
	args = appendGstStage(args, lowLatencyVideoQueueStage())
	return appendGstVideoEncoding(args, encoder, timestampedOutput)
}

func canBuildVAWaylandVideoPipeline(encoder encoderResult, hasElement func(string) bool) bool {
	return encoder.inputMemory == encoderInputVAMemory && hasElement("vapostproc")
}

func waylandCapturePlans(encoder encoderResult, hasElement func(string) bool) []waylandCapturePlan {
	plans := make([]waylandCapturePlan, 0, 2)
	if canBuildVAWaylandVideoPipeline(encoder, hasElement) {
		plans = append(plans, waylandCapturePlan{encoder: encoder, mode: waylandPipelineVAMemory})
	}
	// vah264enc accepts both VAMemory and ordinary NV12. A failed VA import
	// can therefore fall back to a CPU-owned frame without changing the selected
	// encoder backend. Every other encoder has only its normal system-memory plan.
	plans = append(plans, waylandCapturePlan{encoder: encoder, mode: waylandPipelineSystemMemory})
	return plans
}

// systemMemoryStagingFormat deliberately differs from every encoder input
// format we select. Requiring that intermediate layout prevents videoconvert
// from passing through an already matching PipeWire buffer; the second
// conversion must allocate a new ordinary system-memory output buffer.
func systemMemoryStagingFormat(target string) string {
	switch target {
	case "I420":
		return "NV12"
	case "NV12":
		return "I420"
	case "I420_10LE":
		return "P010_10LE"
	case "P010_10LE":
		return "I420_10LE"
	default:
		// All current encoders use one of the formats above. Keeping a distinct
		// fallback still makes an added format fail during startup validation
		// rather than silently retaining a portal-owned buffer.
		return "I420"
	}
}

// buildSystemWaylandVideoPipeline negotiates system memory immediately after
// pipewiresrc, before any element which may retain a portal buffer. Two
// deliberately different raw layouts make the second videoconvert allocate a
// fresh buffer even when the portal already supplies the encoder's format.
func buildSystemWaylandVideoPipeline(fd int, nodeID uint32, fps int, encoder encoderResult, maxWidth, maxHeight int, portalSize [2]int, timestampedOutput bool, hasElement func(string) bool) []string {
	args := append([]string{"--quiet"}, pipeWireVideoSourceStage(fd, nodeID, fps, false)...)
	stagingFormat := systemMemoryStagingFormat(encoder.rawFormat)
	args = appendGstStage(args, gstStage{"videoconvert"})
	args = appendGstStage(args, gstStage{fmt.Sprintf("video/x-raw,format=%s", stagingFormat)})
	args = appendGstStage(args, gstStage{"videoconvert"})
	args = appendGstStage(args, gstStage{fmt.Sprintf("video/x-raw,format=%s", encoder.rawFormat)})

	hasCompositor := portalSize[0] > 0 && portalSize[1] > 0 && hasElement != nil && hasElement("compositor")
	if hasCompositor {
		args = appendGstStage(args, gstStage{"compositor", "force-live=true", "ignore-inactive-pads=true", "background=black"})
		args = appendGstStage(args, gstStage{fmt.Sprintf(
			"video/x-raw,format=%s,width=%d,height=%d,framerate=%d/1",
			encoder.rawFormat, portalSize[0], portalSize[1], fps)})
	}
	for _, stage := range receiverScaleStages(maxWidth, maxHeight) {
		args = appendGstStage(args, stage)
	}
	if !hasCompositor {
		args = appendGstStage(args, gstStage{"videorate", "drop-only=true", "skip-to-first=true"})
		args = appendGstStage(args, frameRateStage(fps))
	}
	args = appendGstStage(args, lowLatencyVideoQueueStage())
	if encoder.needsVulkan {
		args = appendGstStage(args, gstStage{"vulkanupload"})
	}
	return appendGstVideoEncoding(args, encoder, timestampedOutput)
}

func buildWaylandVideoPipeline(fd int, nodeID uint32, fps int, encoder encoderResult, maxWidth, maxHeight int, portalSize [2]int, timestampedOutput bool, hasElement func(string) bool) []string {
	if canBuildVAWaylandVideoPipeline(encoder, hasElement) {
		return buildVAWaylandVideoPipeline(fd, nodeID, fps, encoder, maxWidth, maxHeight, timestampedOutput)
	}
	return buildSystemWaylandVideoPipeline(fd, nodeID, fps, encoder, maxWidth, maxHeight, portalSize, timestampedOutput, hasElement)
}

func buildWaylandVideoPipelineForPlan(fd int, nodeID uint32, fps int, plan waylandCapturePlan, maxWidth, maxHeight int, portalSize [2]int, timestampedOutput bool, hasElement func(string) bool) []string {
	if plan.mode == waylandPipelineVAMemory {
		return buildVAWaylandVideoPipeline(fd, nodeID, fps, plan.encoder, maxWidth, maxHeight, timestampedOutput)
	}
	return buildSystemWaylandVideoPipeline(fd, nodeID, fps, plan.encoder, maxWidth, maxHeight, portalSize, timestampedOutput, hasElement)
}

const (
	minimumCaptureStartupProbeTimeout = 3 * time.Second
	captureStartupBudget              = 10 * time.Second
	maxStartupProbeUnits              = 256
	maxStartupProbeBytes              = 64 << 20
)

// captureStartupProbeTimeout waits through a complete two-second keyframe
// interval plus enough source frames to prove that the encoder continues after
// its random-access point. Slow configured frame rates therefore get more time
// without making normal 30/60 fps startup sluggish.
func captureStartupProbeTimeout(fps int) time.Duration {
	if fps <= 0 {
		fps = 30
	}
	timeout := 2*time.Second + 3*time.Second/time.Duration(fps)
	if timeout < minimumCaptureStartupProbeTimeout {
		return minimumCaptureStartupProbeTimeout
	}
	return timeout
}

type waylandCaptureAttemptStarter func(context.Context, CaptureConfig, waylandCapturePlan, uint32, *os.File, [2]int, bool) (*ScreenCapture, error)
type waylandCaptureProber func(context.Context, *ScreenCapture, VideoCodec, bool) error
type pipeWireRemoteOpener func(context.Context) (*os.File, error)

func startPreparedWaylandCapture(startupCtx, captureCtx context.Context, cfg CaptureConfig, encoder encoderResult, nodeID uint32, pwFd *os.File, portal pipeWirePortalSession, streamSize [2]int, timestampedOutput bool) (*ScreenCapture, error) {
	if portal == nil {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		return nil, fmt.Errorf("prepared Wayland capture is missing portal resources")
	}
	return startPreparedWaylandCapturePlans(startupCtx, captureCtx, cfg,
		waylandCapturePlans(encoder, hasGstElement), nodeID, pwFd, portal,
		portal.openPipeWireRemote, streamSize, timestampedOutput,
		startWaylandCaptureAttempt, probeVideoCaptureStartup)
}

func startPreparedWaylandCapturePlans(
	startupCtx context.Context,
	captureCtx context.Context,
	cfg CaptureConfig,
	plans []waylandCapturePlan,
	nodeID uint32,
	initialRemote *os.File,
	portal io.Closer,
	openRemote pipeWireRemoteOpener,
	streamSize [2]int,
	timestampedOutput bool,
	startAttempt waylandCaptureAttemptStarter,
	probeAttempt waylandCaptureProber,
) (_ *ScreenCapture, resultErr error) {
	if startupCtx == nil {
		startupCtx = context.Background()
	}
	if captureCtx == nil {
		captureCtx = context.Background()
	}
	if initialRemote == nil || portal == nil || openRemote == nil || startAttempt == nil || probeAttempt == nil {
		if initialRemote != nil {
			_ = initialRemote.Close()
		}
		if portal != nil {
			_ = portal.Close()
		}
		return nil, fmt.Errorf("prepared Wayland capture is missing portal resources")
	}
	if len(plans) == 0 {
		_ = initialRemote.Close()
		_ = portal.Close()
		return nil, fmt.Errorf("prepared Wayland capture has no encoder plans")
	}

	startupCtx, cancelStartup := context.WithTimeout(startupCtx, captureStartupBudget)
	defer cancelStartup()
	remote := initialRemote
	portalTransferred := false
	defer func() {
		if remote != nil {
			_ = remote.Close()
		}
		if !portalTransferred {
			_ = portal.Close()
		}
	}()

	attemptErrors := make([]string, 0, len(plans))
	for index, plan := range plans {
		if err := startupCtx.Err(); err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("startup budget: %v", err))
			break
		}
		if index != 0 {
			var err error
			remote, err = openRemote(startupCtx)
			if err != nil {
				if remote != nil {
					_ = remote.Close()
					remote = nil
				}
				attemptErrors = append(attemptErrors, fmt.Sprintf("%s: open a fresh PipeWire remote: %v", plan, err))
				continue
			}
			if remote == nil {
				attemptErrors = append(attemptErrors, fmt.Sprintf("%s: portal returned a nil PipeWire remote", plan))
				continue
			}
		}

		capture, err := startAttempt(captureCtx, cfg, plan, nodeID, remote, streamSize, timestampedOutput)
		_ = remote.Close()
		remote = nil
		if err != nil {
			attemptErrors = append(attemptErrors, fmt.Sprintf("%s: %v", plan, err))
			continue
		}

		probeCtx, cancelProbe := context.WithTimeout(startupCtx, captureStartupProbeTimeout(cfg.FPS))
		err = probeAttempt(probeCtx, capture, plan.encoder.codec, timestampedOutput)
		cancelProbe()
		if err != nil {
			capture.Stop()
			attemptError := fmt.Sprintf("%s: %v", plan, err)
			if stderr := capture.stderrText(); stderr != "" {
				attemptError += "; GStreamer stderr: " + stderr
			}
			attemptErrors = append(attemptErrors, attemptError)
			log.Printf("[CAPTURE] %s failed startup validation: %v", plan, err)
			continue
		}

		capture.portal = portal
		portalTransferred = true
		log.Printf("[CAPTURE] using %s", plan)
		return capture, nil
	}

	return nil, fmt.Errorf("no Wayland capture pipeline produced a decodable startup sequence:\n  %s", strings.Join(attemptErrors, "\n  "))
}

func startWaylandCaptureAttempt(ctx context.Context, cfg CaptureConfig, plan waylandCapturePlan, nodeID uint32, pwFd *os.File, streamSize [2]int, timestampedOutput bool) (*ScreenCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	// Capture from the PipeWire portal. Every plan establishes ownership of its
	// output before a compositor, queue, or encoder can retain a portal buffer.
	const pwFdNum = 3
	gstArgs := buildWaylandVideoPipelineForPlan(
		pwFdNum, nodeID, fps, plan, cfg.MaxWidth, cfg.MaxHeight,
		streamSize, timestampedOutput, hasGstElement)

	dbg("[CAPTURE] gst-launch-1.0 (wayland) %s", strings.Join(gstArgs, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)
	cmd.ExtraFiles = []*os.File{pwFd}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		_ = stdout.Close()
		return nil, fmt.Errorf("gst stderr pipe: %w", err)
	}

	waitResult, err := startGStreamerCommand(cmd)
	if err != nil {
		cancel()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start gst-launch: %w", err)
	}

	stderrTail := newCaptureStderrTail()
	go logStderr("GST", stderr, stderrTail)

	capture := &ScreenCapture{
		cmd:      cmd,
		stdout:   stdout,
		cancel:   cancel,
		pwNodeID: nodeID,
		waitCh:   make(chan struct{}),
		stderr:   stderrTail,
	}
	if timestampedOutput {
		capture.frames = newRTPVideoAccessUnitReader(stdout, plan.encoder.codec)
	}
	go func() {
		capture.waitErr = <-waitResult
		close(capture.waitCh)
	}()

	return capture, nil
}

type prefetchedVideoAccessUnitReader struct {
	units  []VideoAccessUnit
	reader videoAccessUnitReader
}

func (r *prefetchedVideoAccessUnitReader) hasPrefetchedUnit() bool {
	return r != nil && len(r.units) != 0
}

func (r *prefetchedVideoAccessUnitReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	if len(r.units) != 0 {
		unit := r.units[0]
		r.units[0] = VideoAccessUnit{}
		r.units = r.units[1:]
		return unit, nil
	}
	return r.reader.ReadVideoAccessUnit()
}

type prefixedReadCloser struct {
	prefix *bytes.Reader
	reader io.Reader
	closer io.Closer
}

func (r *prefixedReadCloser) Read(p []byte) (int, error) {
	if r.prefix != nil && r.prefix.Len() != 0 {
		return r.prefix.Read(p)
	}
	return r.reader.Read(p)
}

func (r *prefixedReadCloser) hasPrefix() bool {
	return r != nil && r.prefix != nil && r.prefix.Len() != 0
}

func (r *prefixedReadCloser) Close() error {
	return r.closer.Close()
}

type completeAccessUnitEvidence struct {
	codec       VideoCodec
	haveVPS     bool
	haveSPS     bool
	havePPS     bool
	haveRandom  bool
	haveNextVCL bool
}

func (e *completeAccessUnitEvidence) observe(data []byte) error {
	nals := splitAnnexBAccessUnit(data)
	if len(nals) == 0 {
		return fmt.Errorf("encoded access unit is not Annex-B framed")
	}
	hasVCL, hasRandom := false, false
	for _, wrapped := range nals {
		raw := stripStartCode(wrapped)
		if len(raw) == 0 {
			continue
		}
		if normalizeVideoCodec(e.codec) == VideoCodecHEVC {
			typ := hevcNALType(raw)
			switch typ {
			case 32:
				e.haveVPS = true
			case 33:
				e.haveSPS = true
			case 34:
				e.havePPS = true
			}
			if typ <= 31 {
				hasVCL = true
				hasRandom = hasRandom || typ >= 16 && typ <= 21
			}
		} else {
			typ := raw[0] & 0x1f
			switch typ {
			case 7:
				e.haveSPS = true
			case 8:
				e.havePPS = true
			}
			if typ >= 1 && typ <= 5 {
				hasVCL = true
				hasRandom = hasRandom || typ == 5
			}
		}
	}

	if e.haveRandom && hasVCL {
		e.haveNextVCL = true
	}
	if hasRandom && e.haveSPS && e.havePPS &&
		(normalizeVideoCodec(e.codec) != VideoCodecHEVC || e.haveVPS) {
		e.haveRandom = true
	}
	return nil
}

func (e *completeAccessUnitEvidence) ready() bool {
	return e.haveRandom && e.haveNextVCL
}

func (e *completeAccessUnitEvidence) String() string {
	if normalizeVideoCodec(e.codec) == VideoCodecHEVC {
		return fmt.Sprintf("VPS=%t SPS=%t PPS=%t IRAP=%t following-VCL=%t", e.haveVPS, e.haveSPS, e.havePPS, e.haveRandom, e.haveNextVCL)
	}
	return fmt.Sprintf("SPS=%t PPS=%t IDR=%t following-VCL=%t", e.haveSPS, e.havePPS, e.haveRandom, e.haveNextVCL)
}

func readTimestampedCaptureStartup(capture *ScreenCapture, codec VideoCodec) ([]VideoAccessUnit, error) {
	units := make([]VideoAccessUnit, 0, 4)
	evidence := completeAccessUnitEvidence{codec: codec}
	totalBytes := 0
	for len(units) < maxStartupProbeUnits {
		unit, err := capture.ReadVideoAccessUnit()
		if err != nil {
			return nil, fmt.Errorf("read startup access unit (%s): %w", evidence.String(), captureStartupReadError(capture, err))
		}
		if len(unit.AnnexB) == 0 {
			return nil, fmt.Errorf("read startup access unit: empty encoded frame")
		}
		totalBytes += len(unit.AnnexB)
		if totalBytes > maxStartupProbeBytes {
			return nil, fmt.Errorf("startup access units exceeded %d bytes (%s)", maxStartupProbeBytes, evidence.String())
		}
		units = append(units, unit)
		if err := evidence.observe(unit.AnnexB); err != nil {
			return nil, err
		}
		if evidence.ready() {
			return units, nil
		}
	}
	return nil, fmt.Errorf("startup did not produce a decodable sequence within %d access units (%s)", maxStartupProbeUnits, evidence.String())
}

type rawH264AccessUnitEvidence struct {
	haveSPS       bool
	havePPS       bool
	currentVCL    bool
	currentRandom bool
	haveRandom    bool
	haveNextVCL   bool
}

func (e *rawH264AccessUnitEvidence) finishAccessUnit() {
	if !e.currentVCL {
		return
	}
	if e.haveRandom {
		e.haveNextVCL = true
	}
	if e.currentRandom && e.haveSPS && e.havePPS {
		e.haveRandom = true
	}
	e.currentVCL = false
	e.currentRandom = false
}

func (e *rawH264AccessUnitEvidence) observe(nal []byte) {
	raw := stripStartCode(nal)
	if len(raw) == 0 {
		return
	}
	typ := raw[0] & 0x1f
	switch typ {
	case 7:
		e.haveSPS = true
	case 8:
		e.havePPS = true
	case 9:
		e.finishAccessUnit()
	case 1, 2, 3, 4, 5:
		if isFirstSlice(raw) && e.currentVCL {
			e.finishAccessUnit()
		}
		e.currentVCL = true
		e.currentRandom = e.currentRandom || typ == 5
	}
}

func (e *rawH264AccessUnitEvidence) String() string {
	return fmt.Sprintf("SPS=%t PPS=%t IDR=%t following-VCL=%t", e.haveSPS, e.havePPS, e.haveRandom, e.haveNextVCL)
}

func readRawH264CaptureStartup(capture *ScreenCapture) ([]byte, error) {
	parser := newH264Parser()
	evidence := rawH264AccessUnitEvidence{}
	prefix := make([]byte, 0, 256*1024)
	buf := make([]byte, 64*1024)
	for len(prefix) <= maxStartupProbeBytes {
		n, err := capture.Read(buf)
		if n > 0 {
			prefix = append(prefix, buf[:n]...)
			for _, nal := range parser.Push(buf[:n]) {
				evidence.observe(nal)
			}
			if evidence.haveRandom && evidence.haveNextVCL {
				return prefix, nil
			}
		}
		if err != nil {
			return nil, fmt.Errorf("read raw H.264 startup (%s): %w", evidence.String(), captureStartupReadError(capture, err))
		}
	}
	return nil, fmt.Errorf("raw H.264 startup exceeded %d bytes (%s)", maxStartupProbeBytes, evidence.String())
}

func captureStartupReadError(capture *ScreenCapture, readErr error) error {
	if capture == nil || capture.waitCh == nil {
		return readErr
	}
	if readErr == io.EOF || errors.Is(readErr, os.ErrClosed) {
		select {
		case <-capture.waitCh:
		case <-time.After(20 * time.Millisecond):
		}
	}
	select {
	case <-capture.waitCh:
		if capture.waitErr != nil {
			return fmt.Errorf("capture exited: %w", capture.waitErr)
		}
	default:
	}
	return readErr
}

func captureStartupExitError(capture *ScreenCapture) error {
	if capture == nil || capture.waitCh == nil {
		return nil
	}
	select {
	case <-capture.waitCh:
		if capture.waitErr != nil {
			return fmt.Errorf("capture exited after startup validation: %w", capture.waitErr)
		}
		return fmt.Errorf("capture exited after startup validation: %w", io.EOF)
	default:
		return nil
	}
}

func probeVideoCaptureStartup(ctx context.Context, capture *ScreenCapture, codec VideoCodec, timestampedOutput bool) error {
	if capture == nil {
		return fmt.Errorf("startup probe received a nil capture")
	}
	ctx = normalizeContext(ctx)
	type probeResult struct {
		units []VideoAccessUnit
		raw   []byte
		err   error
	}
	resultCh := make(chan probeResult, 1)
	go func() {
		if timestampedOutput {
			units, err := readTimestampedCaptureStartup(capture, codec)
			resultCh <- probeResult{units: units, err: err}
			return
		}
		if normalizeVideoCodec(codec) != VideoCodecH264 {
			resultCh <- probeResult{err: fmt.Errorf("raw startup validation is only supported for H.264")}
			return
		}
		raw, err := readRawH264CaptureStartup(capture)
		resultCh <- probeResult{raw: raw, err: err}
	}()
	applyResult := func(result probeResult) error {
		if result.err != nil {
			return result.err
		}
		// Do not accept a child which emitted just enough buffered output to pass
		// validation and then exited. Once a live capture has been returned, its
		// prefetched data still drains before a later process failure is reported.
		if err := captureStartupExitError(capture); err != nil {
			return err
		}
		if timestampedOutput {
			capture.frames = &prefetchedVideoAccessUnitReader{units: result.units, reader: capture.frames}
		} else {
			stdout := capture.stdout
			capture.stdout = &prefixedReadCloser{prefix: bytes.NewReader(result.raw), reader: stdout, closer: stdout}
		}
		return nil
	}

	select {
	case result := <-resultCh:
		return applyResult(result)
	case <-ctx.Done():
		// Closing stdout and stopping the child is required to interrupt a read
		// from the encoder pipe before another attempt opens a fresh remote.
		select {
		case result := <-resultCh:
			return applyResult(result)
		default:
		}
		capture.Stop()
		<-resultCh
		return fmt.Errorf("startup access-unit probe: %w", ctx.Err())
	}
}

func startPreparedX11Capture(startupCtx, lifetimeCtx context.Context, cfg CaptureConfig, encoder encoderResult, timestampedOutput bool) (*ScreenCapture, error) {
	startupCtx, cancelStartup := context.WithTimeout(normalizeContext(startupCtx), captureStartupBudget)
	defer cancelStartup()
	lifetimeCtx = normalizeContext(lifetimeCtx)
	captureCtx, cancel := context.WithCancel(lifetimeCtx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	display := os.Getenv("DISPLAY")

	ximageSrcArgs := gstStage{
		"ximagesrc",
		fmt.Sprintf("display-name=%s", display),
		"use-damage=false",
		fmt.Sprintf("show-pointer=%t", cfg.ShowCursor),
	}

	if cfg.X11WindowID != 0 {
		ximageSrcArgs = append(ximageSrcArgs, fmt.Sprintf("xid=%d", cfg.X11WindowID))
		dbg("[CAPTURE] capturing X11 window xid=0x%x", cfg.X11WindowID)
	} else if cfg.X11WindowName != "" {
		ximageSrcArgs = append(ximageSrcArgs, fmt.Sprintf("xname=%s", cfg.X11WindowName))
		dbg("[CAPTURE] capturing X11 window name=%q", cfg.X11WindowName)
	} else {
		// Detect primary monitor geometry — ximagesrc captures the full X screen
		// (all monitors combined). On multi-monitor setups this wastes CPU on pixels
		// we don't need, so crop to the primary monitor. The encoded resolution is
		// then the primary monitor's native resolution (no rescaling).
		startX, startY, endX, endY := detectPrimaryMonitor(startupCtx, display)
		if endX > startX && endY > startY {
			ximageSrcArgs = append(ximageSrcArgs,
				fmt.Sprintf("startx=%d", startX),
				fmt.Sprintf("starty=%d", startY),
				fmt.Sprintf("endx=%d", endX-1),
				fmt.Sprintf("endy=%d", endY-1),
			)
			dbg("[CAPTURE] cropping ximagesrc to x=%d..%d y=%d..%d", startX, endX-1, startY, endY-1)
		}
	}
	if err := startupCtx.Err(); err != nil {
		cancel()
		return nil, fmt.Errorf("prepare X11 capture: %w", err)
	}

	beforeConvert := []gstStage{frameRateStage(fps), lowLatencyVideoQueueStage()}
	gstArgs := buildGstVideoPipeline(ximageSrcArgs, beforeConvert, nil, encoder, cfg.MaxWidth, cfg.MaxHeight, timestampedOutput)

	dbg("[CAPTURE] gst-launch-1.0 (x11) %s", strings.Join(gstArgs, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		_ = stdout.Close()
		return nil, fmt.Errorf("gst stderr pipe: %w", err)
	}

	waitResult, err := startGStreamerCommand(cmd)
	if err != nil {
		cancel()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start gst-launch: %w", err)
	}

	stderrTail := newCaptureStderrTail()
	go logStderr("GST", stderr, stderrTail)

	capture := &ScreenCapture{
		cmd:    cmd,
		stdout: stdout,
		cancel: cancel,
		waitCh: make(chan struct{}),
		stderr: stderrTail,
	}
	if timestampedOutput {
		capture.frames = newRTPVideoAccessUnitReader(stdout, encoder.codec)
	}
	go func() {
		capture.waitErr = <-waitResult
		close(capture.waitCh)
	}()

	probeCtx, cancelProbe := context.WithTimeout(startupCtx, captureStartupProbeTimeout(fps))
	err = probeVideoCaptureStartup(probeCtx, capture, encoder.codec, timestampedOutput)
	cancelProbe()
	if err != nil {
		capture.Stop()
		result := fmt.Errorf("X11 capture on DISPLAY=%q failed startup validation: %w", display, err)
		if stderr := capture.stderrText(); stderr != "" {
			result = fmt.Errorf("%w; GStreamer stderr: %s", result, stderr)
		}
		return nil, result
	}

	return capture, nil
}

func (sc *ScreenCapture) Read(buf []byte) (int, error) {
	if prefixed, ok := sc.stdout.(*prefixedReadCloser); ok && prefixed.hasPrefix() {
		return prefixed.Read(buf)
	}
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

// ReadVideoAccessUnit returns one complete encoded frame with its source PTS.
// It is available when the capture pipeline uses the timestamped RTP/ONVIF
// output suffix. Callers must treat the returned AnnexB slice as immutable.
func (sc *ScreenCapture) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	if sc == nil || sc.frames == nil {
		return VideoAccessUnit{}, fmt.Errorf("capture does not provide timestamped access units")
	}
	if prefetched, ok := sc.frames.(*prefetchedVideoAccessUnitReader); ok && prefetched.hasPrefetchedUnit() {
		return prefetched.ReadVideoAccessUnit()
	}
	select {
	case <-sc.waitCh:
		if sc.waitErr != nil {
			return VideoAccessUnit{}, fmt.Errorf("capture exited: %w", sc.waitErr)
		}
		return VideoAccessUnit{}, io.EOF
	default:
	}
	return sc.frames.ReadVideoAccessUnit()
}

func (sc *ScreenCapture) Stop() {
	if sc == nil {
		return
	}
	sc.stopOnce.Do(func() {
		sc.stopped = true
		if sc.cancel != nil {
			sc.cancel()
		}

		// Close stdout to unblock any pending Read() call.
		if sc.stdout != nil {
			_ = sc.stdout.Close()
		}

		if sc.cmd != nil && sc.cmd.Process != nil {
			_ = sc.cmd.Process.Signal(os.Interrupt)
			if sc.waitCh != nil {
				select {
				case <-sc.waitCh:
				case <-time.After(2 * time.Second):
					_ = sc.cmd.Process.Kill()
					<-sc.waitCh
				}
			}
		}

		// Keep the portal session alive until its consumer has stopped, then
		// close it exactly once as the final ownership transition.
		if sc.portal != nil {
			_ = sc.portal.Close()
		}
	})
}

// detectPrimaryMonitor queries xrandr to find the primary monitor's geometry.
// Returns (startX, startY, endX, endY) bounding the primary monitor, where
// endX = startX + monitor_width and endY = startY + monitor_height. If
// detection fails it returns all zeros, meaning no cropping should be applied.
func detectPrimaryMonitor(ctx context.Context, display string) (startX, startY, endX, endY int) {
	// Run xrandr to get connected outputs with geometry
	out, err := exec.CommandContext(normalizeContext(ctx), "xrandr", "--display", display, "--query").Output()
	if err != nil {
		dbg("[CAPTURE] xrandr failed: %v, skipping monitor crop", err)
		return 0, 0, 0, 0
	}

	// Parse lines like: "DP-3 connected primary 1920x1080+0+0"
	// or "DP-1 connected 1920x1080+1920+0"
	// Format: <name> connected [primary] <W>x<H>+<X>+<Y>
	var px, py, pw, ph int
	var found bool
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, " connected") {
			continue
		}
		// Try primary first
		if strings.Contains(line, " primary ") {
			if x, y, w, h, ok := parseXrandrGeometry(line); ok {
				px, py, pw, ph = x, y, w, h
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
			if x, y, w, h, ok := parseXrandrGeometry(line); ok {
				px, py, pw, ph = x, y, w, h
				found = true
				break
			}
		}
	}

	if !found || pw <= 0 || ph <= 0 {
		dbg("[CAPTURE] couldn't parse xrandr output, skipping monitor crop")
		return 0, 0, 0, 0
	}

	dbg("[CAPTURE] primary monitor: %dx%d at +%d+%d", pw, ph, px, py)
	return px, py, px + pw, py + ph
}

// parseXrandrGeometry extracts the X/Y offset and width/height from an xrandr
// output line.
func parseXrandrGeometry(line string) (xOffset, yOffset, width, height int, ok bool) {
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
		h, err := strconv.Atoi(plusParts[0])
		if err != nil {
			continue
		}
		x, err := strconv.Atoi(plusParts[1])
		if err != nil {
			continue
		}
		y, err := strconv.Atoi(plusParts[2])
		if err != nil {
			continue
		}
		return x, y, w, h, true
	}
	return 0, 0, 0, 0, false
}

// detectGstEncoder selects an available GStreamer video encoder. Only auto may
// fall through the priority list; an explicit method either uses its own
// encoder element (or elements, for NVENC) or returns an error.
func detectGstEncoder(cfg CaptureConfig) (encoderResult, error) {
	return selectGstEncoderWithProbe(cfg, hasGstElement, true)
}

func detectGstEncoderWithProbe(cfg CaptureConfig, hasElement func(string) bool) (encoderResult, error) {
	return selectGstEncoderWithProbe(cfg, hasElement, true)
}

func selectGstEncoderWithProbe(cfg CaptureConfig, hasElement func(string) bool, announce bool) (encoderResult, error) {
	if !announce && cfg.Bitrate <= 0 {
		// Preparation only validates element availability. The real automatic
		// bitrate depends on the session-time canvas and is computed by Start.
		cfg.Bitrate = defaultVideoBitrateKbps
	}
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	bitrate := captureBitrateKbps(cfg)
	keyframeInterval := keyframeIntervalFrames(fps)
	hwaccel := cfg.HWAccel
	if hwaccel == "" {
		hwaccel = "auto"
	}
	if err := ValidateHWAccel(hwaccel); err != nil {
		return encoderResult{}, err
	}
	if normalizeVideoCodec(cfg.VideoCodec) == VideoCodecHEVC {
		return selectGstHEVCEncoder(cfg, hasElement, announce, hwaccel, bitrate, keyframeInterval)
	}

	vbvBuf := vbvBufferKbit(bitrate, fps)
	maxrate := bitrate + bitrate/4 // allow 25% overshoot on peaks
	candidates := []struct {
		method  string
		element string
		label   string
		result  encoderResult
	}{
		{
			method:  "nvenc",
			element: "vulkanh264enc",
			label:   "NVENC hardware encoding (vulkanh264enc)",
			result: encoderResult{
				parts: []string{
					"vulkanh264enc",
					"b-frames=0",
					fmt.Sprintf("idr-period=%d", keyframeInterval),
					"rate-control=cbr",
					fmt.Sprintf("bitrate=%d", bitrate),
				},
				needsVulkan: true,
				rawFormat:   "NV12", codec: VideoCodecH264,
			},
		},
		{
			method:  "nvenc",
			element: "nvh264enc",
			label:   "NVENC hardware encoding (nvh264enc)",
			result: encoderResult{rawFormat: "NV12", codec: VideoCodecH264, parts: []string{
				"nvh264enc",
				fmt.Sprintf("bitrate=%d", bitrate),
				fmt.Sprintf("gop-size=%d", keyframeInterval),
				"bframes=0",
				"rc-mode=cbr",
				"preset=low-latency-hq",
				"zerolatency=true",
			}},
		},
		{
			method:  "vaapi",
			element: "vah264enc",
			label:   "VAAPI hardware encoding (vah264enc)",
			result: encoderResult{rawFormat: "NV12", codec: VideoCodecH264, inputMemory: encoderInputVAMemory, parts: []string{
				"vah264enc",
				fmt.Sprintf("bitrate=%d", bitrate),
				fmt.Sprintf("key-int-max=%d", keyframeInterval),
				"b-frames=0",
				"rate-control=cbr",
			}},
		},
		{
			method:  "openh264",
			element: "openh264enc",
			label:   "OpenH264 software encoding (openh264enc)",
			result: encoderResult{rawFormat: "I420", codec: VideoCodecH264, parts: []string{
				"openh264enc",
				fmt.Sprintf("bitrate=%d", bitrate*1000),
				fmt.Sprintf("gop-size=%d", keyframeInterval),
				"rate-control=bitrate",
				"usage-type=screen",
			}},
		},
		{
			method:  "none",
			element: "x264enc",
			label:   "x264 software encoding (x264enc)",
			result: encoderResult{rawFormat: "I420", codec: VideoCodecH264, parts: []string{
				"x264enc",
				"tune=zerolatency",
				"speed-preset=superfast",
				fmt.Sprintf("bitrate=%d", bitrate),
				fmt.Sprintf("vbv-buf-capacity=%d", vbvBuf),
				fmt.Sprintf("key-int-max=%d", keyframeInterval),
				"pass=0",
				fmt.Sprintf("option-string=vbv-maxrate=%d", maxrate),
				"bframes=0",
				"sliced-threads=true",
				"byte-stream=true",
				"aud=true",
			}},
		},
	}

	for _, candidate := range candidates {
		if hwaccel != "auto" && hwaccel != candidate.method {
			continue
		}
		if hasElement(candidate.element) {
			if announce {
				log.Printf("[CAPTURE] using %s", candidate.label)
			}
			return candidate.result, nil
		}
	}

	if hwaccel == "auto" {
		return encoderResult{}, fmt.Errorf("no supported GStreamer H.264 encoder is available")
	}
	if hwaccel == "nvenc" {
		return encoderResult{}, fmt.Errorf("-hwaccel nvenc requires GStreamer element vulkanh264enc or nvh264enc; neither is available")
	}
	for _, candidate := range candidates {
		if candidate.method == hwaccel {
			return encoderResult{}, fmt.Errorf("-hwaccel %s requires GStreamer element %s, but it is not available", hwaccel, candidate.element)
		}
	}
	panic("validated H.264 encoder has no candidate")
}

func selectGstHEVCEncoder(cfg CaptureConfig, hasElement func(string) bool, announce bool, hwaccel string, bitrate, keyframeInterval int) (encoderResult, error) {
	type candidate struct {
		method, element, label string
		result                 encoderResult
	}
	candidates := []candidate{
		{
			method: "nvenc", element: "nvh265enc", label: "NVENC HEVC Main10 hardware encoding (nvh265enc)",
			result: encoderResult{codec: VideoCodecHEVC, rawFormat: "P010_10LE", parts: gstStage{
				"nvh265enc", fmt.Sprintf("bitrate=%d", bitrate), fmt.Sprintf("gop-size=%d", keyframeInterval),
				"bframes=0", "rc-mode=cbr", "preset=p3", "tune=ultra-low-latency", "zerolatency=true", "aud=true",
			}},
		},
		{
			method: "none", element: "x265enc", label: "x265 HEVC Main10 software encoding (x265enc)",
			result: encoderResult{codec: VideoCodecHEVC, rawFormat: "I420_10LE", parts: gstStage{
				"x265enc", fmt.Sprintf("bitrate=%d", bitrate), fmt.Sprintf("key-int-max=%d", keyframeInterval),
				"speed-preset=superfast", "tune=zerolatency", "option-string=bframes=0:repeat-headers=1:aud=1",
			}},
		},
	}
	for _, candidate := range candidates {
		if hwaccel != "auto" && hwaccel != candidate.method {
			continue
		}
		if hasElement(candidate.element) {
			if announce {
				log.Printf("[CAPTURE] using %s", candidate.label)
			}
			return candidate.result, nil
		}
	}
	if hwaccel == "auto" {
		return encoderResult{}, fmt.Errorf("HEVC requires GStreamer nvh265enc or x265enc; neither is available")
	}
	return encoderResult{}, fmt.Errorf("-video-codec hevc is unavailable with -hwaccel %s (use nvenc or none)", hwaccel)
}

// StartTestCapture creates a synthetic stream with the configured encoder.
func StartTestCapture(ctx context.Context, cfg CaptureConfig) (*ScreenCapture, error) {
	if cfg.VideoCodec == VideoCodecAuto {
		return nil, fmt.Errorf("automatic video codec requires PrepareTestCapture followed by StartWithCodec")
	}
	preparation, err := PrepareTestCapture(ctx, cfg)
	if err != nil {
		return nil, err
	}
	capture, err := preparation.Start(cfg.MaxWidth, cfg.MaxHeight)
	if err != nil {
		preparation.Close()
		return nil, err
	}
	return capture, nil
}

func startPreparedTestCapture(ctx context.Context, cfg CaptureConfig, encoder encoderResult, timestampedOutput bool) (*ScreenCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	// pattern=18 = ball (bouncing ball with motion); timeoverlay adds a frame counter.
	// Keep test source live/infinite so long-running audio tests do not stop with EOF.
	source := gstStage{
		"videotestsrc", "pattern=18", "is-live=true", "do-timestamp=true",
	}
	beforeConvert := []gstStage{
		{fmt.Sprintf("video/x-raw,width=%d,height=%d,framerate=%d/1", testCaptureWidth, testCaptureHeight, fps)},
		{"timeoverlay"},
		lowLatencyVideoQueueStage(),
	}
	// Match the production capture paths: if conversion/encoding cannot keep up,
	// keep the newest source frame instead of measuring or streaming a growing
	// raw backlog.
	gstArgs := buildGstVideoPipeline(source, beforeConvert, nil, encoder, cfg.MaxWidth, cfg.MaxHeight, timestampedOutput)

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

	waitResult, err := startGStreamerCommand(cmd)
	if err != nil {
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
	if timestampedOutput {
		capture.frames = newRTPVideoAccessUnitReader(stdout, encoder.codec)
	}
	go func() {
		capture.waitErr = <-waitResult
		close(capture.waitCh)
	}()

	return capture, nil
}

const maxCaptureStderrTailBytes = 32 << 10

type captureStderrTail struct {
	mu   sync.Mutex
	data []byte
	done chan struct{}
}

func newCaptureStderrTail() *captureStderrTail {
	return &captureStderrTail{done: make(chan struct{})}
}

func (t *captureStderrTail) append(line string) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.data = append(t.data, line...)
	t.data = append(t.data, '\n')
	if len(t.data) > maxCaptureStderrTailBytes {
		t.data = append([]byte(nil), t.data[len(t.data)-maxCaptureStderrTailBytes:]...)
	}
}

func (t *captureStderrTail) finish() {
	if t != nil {
		close(t.done)
	}
}

func (t *captureStderrTail) String() string {
	if t == nil {
		return ""
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return strings.TrimSpace(string(t.data))
}

func (sc *ScreenCapture) stderrText() string {
	if sc == nil || sc.stderr == nil {
		return ""
	}
	select {
	case <-sc.stderr.done:
	case <-time.After(100 * time.Millisecond):
	}
	return sc.stderr.String()
}

func logStderr(prefix string, r io.Reader, tails ...*captureStderrTail) {
	if r == nil {
		for _, tail := range tails {
			tail.finish()
		}
		return
	}
	defer func() {
		for _, tail := range tails {
			tail.finish()
		}
	}()
	scanner := bufio.NewScanner(r)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	for scanner.Scan() {
		for _, tail := range tails {
			tail.append(scanner.Text())
		}
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
	width, height := 1920, 1080
	if cfg.MaxWidth > 0 && cfg.MaxHeight > 0 {
		// A decoder ceiling may force H.264 below the normal 1080p budget. HEVC's
		// high-resolution path deliberately budgets the selected maximum canvas.
		// An H.264 ceiling does not prove the source is large enough to justify raising
		// bitrate. Keep 1080p as the automatic upper budget; -bitrate remains the
		// explicit way to allocate more for a genuinely high-resolution source.
		if canvasWidth, canvasHeight := cfg.MaxWidth&^1, cfg.MaxHeight&^1; canvasWidth > 0 && canvasHeight > 0 {
			if normalizeVideoCodec(cfg.VideoCodec) == VideoCodecHEVC || canvasWidth*canvasHeight < width*height {
				width, height = canvasWidth, canvasHeight
			}
		}
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
	// Capture starts before the receiver's media SETUP completes so Wayland's
	// portal prompt stays outside the first-frame deadline. A receiver (or a
	// later daemon sink) can therefore miss the encoder's initial IDR. Keep the
	// next random-access point comfortably inside that deadline.
	return fps * 2
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

type screenCastPortalSession struct {
	conn        *dbus.Conn
	sessionPath dbus.ObjectPath
	closeOnce   sync.Once
	closeErr    error
}

func (s *screenCastPortalSession) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		var closeErrors []error
		if s.sessionPath.IsValid() && s.conn.Connected() {
			ctx, cancel := context.WithTimeout(context.Background(), portalCleanupTimeout)
			call := s.conn.Object(portalBusName, s.sessionPath).CallWithContext(
				ctx, portalSessionInterface+".Close", 0)
			cancel()
			if call.Err != nil {
				closeErrors = append(closeErrors, fmt.Errorf("close screencast portal session: %w", call.Err))
			}
		}
		if err := s.conn.Close(); err != nil {
			closeErrors = append(closeErrors, fmt.Errorf("close screencast portal connection: %w", err))
		}
		s.closeErr = errors.Join(closeErrors...)
	})
	return s.closeErr
}

func (s *screenCastPortalSession) openPipeWireRemote(ctx context.Context) (*os.File, error) {
	if s == nil || s.conn == nil || !s.sessionPath.IsValid() {
		return nil, fmt.Errorf("invalid screencast portal session")
	}
	callCtx, cancel := context.WithTimeout(normalizeContext(ctx), portalMethodTimeout)
	defer cancel()
	portal := s.conn.Object(portalBusName, portalObjectPath)
	call := portal.CallWithContext(callCtx, portalScreenCastInterface+".OpenPipeWireRemote", 0,
		s.sessionPath, map[string]dbus.Variant{})
	if call.Err != nil {
		return nil, fmt.Errorf("OpenPipeWireRemote: %w", call.Err)
	}
	var pwFD dbus.UnixFD
	if err := call.Store(&pwFD); err != nil {
		return nil, fmt.Errorf("store pipewire fd: %w", err)
	}
	return os.NewFile(uintptr(pwFD), "pipewire-remote"), nil
}

const (
	portalBusName             = "org.freedesktop.portal.Desktop"
	portalObjectPath          = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	portalRequestPathPrefix   = dbus.ObjectPath("/org/freedesktop/portal/desktop/request")
	portalSessionPathPrefix   = dbus.ObjectPath("/org/freedesktop/portal/desktop/session")
	portalRequestInterface    = "org.freedesktop.portal.Request"
	portalSessionInterface    = "org.freedesktop.portal.Session"
	portalScreenCastInterface = "org.freedesktop.portal.ScreenCast"

	// Portal methods return a Request object promptly and leave user interaction
	// to its Response signal. The portal API documents a 25-second upper bound
	// for that method-dispatch phase; the chooser itself remains caller-bounded.
	portalMethodTimeout       = 25 * time.Second
	portalControlPhaseTimeout = 25 * time.Second
	portalCleanupTimeout      = 2 * time.Second
)

type portalRequestDispatch func(context.Context) (dbus.ObjectPath, error)

func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// requestScreencast uses the xdg-desktop-portal D-Bus API to request screen capture
// permission and returns a PipeWire node ID, an fd for the portal's PipeWire remote,
// the retained portal session (which must stay open for capture and retries), and a
// fresh restore token when the portal grants persistence.
func requestScreencast(ctx context.Context, restoreToken string, showCursor bool, dimensions *[2]int) (uint32, *os.File, pipeWirePortalSession, string, error) {
	ctx = normalizeContext(ctx)
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return 0, nil, nil, "", fmt.Errorf("connect session bus: %w", err)
	}
	connTransferred := false
	defer func() {
		if !connTransferred {
			_ = conn.Close()
		}
	}()

	portalObject := conn.Object(portalBusName, portalObjectPath)
	portalVersion := screenCastPortalVersion(ctx, portalObject)
	baseToken, err := newPortalHandleToken()
	if err != nil {
		return 0, nil, nil, "", err
	}
	createPath, err := portalPathForToken(conn, portalRequestPathPrefix, baseToken)
	if err != nil {
		return 0, nil, nil, "", err
	}
	sessionToken := baseToken + "_session"
	expectedSessionPath, err := portalPathForToken(conn, portalSessionPathPrefix, sessionToken)
	if err != nil {
		return 0, nil, nil, "", err
	}

	// Create session
	sessionOpts := map[string]dbus.Variant{
		"handle_token":         dbus.MakeVariant(baseToken),
		"session_handle_token": dbus.MakeVariant(sessionToken),
	}
	createCtx, cancelCreate := context.WithTimeout(ctx, portalControlPhaseTimeout)
	createResult, err := performPortalRequest(createCtx, conn, createPath, portalMethodTimeout,
		func(callCtx context.Context) (dbus.ObjectPath, error) {
			var handle dbus.ObjectPath
			call := portalObject.CallWithContext(callCtx, portalScreenCastInterface+".CreateSession", 0, sessionOpts)
			if call.Err != nil {
				return "", call.Err
			}
			if err := call.Store(&handle); err != nil {
				return "", fmt.Errorf("store request handle: %w", err)
			}
			return handle, nil
		})
	cancelCreate()
	if err != nil {
		return 0, nil, nil, "", fmt.Errorf("session response: %w", err)
	}

	sessionPath, err := sessionHandleFromResult(createResult)
	if err != nil {
		return 0, nil, nil, "", fmt.Errorf("session handle: %w", err)
	}
	if sessionPath != expectedSessionPath {
		dbg("[CAPTURE] portal returned session handle %s instead of predicted %s", sessionPath, expectedSessionPath)
	}
	portalSession := &screenCastPortalSession{conn: conn, sessionPath: sessionPath}
	connTransferred = true
	sessionTransferred := false
	defer func() {
		if !sessionTransferred {
			_ = portalSession.Close()
		}
	}()

	// cursor_mode: HIDDEN=1, EMBEDDED=2 (cursor baked into the stream)
	cursorMode := uint32(1)
	if showCursor {
		cursorMode = 2
	}

	// Select sources (screen)
	selectToken := baseToken + "_select"
	selectPath, err := portalPathForToken(conn, portalRequestPathPrefix, selectToken)
	if err != nil {
		return 0, nil, nil, "", err
	}
	selectOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(selectToken),
		"types":        dbus.MakeVariant(uint32(1)), // MONITOR=1, WINDOW=2
		"multiple":     dbus.MakeVariant(false),
		"cursor_mode":  dbus.MakeVariant(cursorMode),
	}
	if portalVersion >= 4 {
		selectOpts["persist_mode"] = dbus.MakeVariant(uint32(2))
		if restoreToken != "" {
			selectOpts["restore_token"] = dbus.MakeVariant(restoreToken)
			dbg("[CAPTURE] requesting screencast restore with saved token")
		}
	}

	selectCtx, cancelSelect := context.WithTimeout(ctx, portalControlPhaseTimeout)
	_, err = performPortalRequest(selectCtx, conn, selectPath, portalMethodTimeout,
		func(callCtx context.Context) (dbus.ObjectPath, error) {
			var handle dbus.ObjectPath
			call := portalObject.CallWithContext(callCtx, portalScreenCastInterface+".SelectSources", 0,
				sessionPath, selectOpts)
			if call.Err != nil {
				return "", call.Err
			}
			if err := call.Store(&handle); err != nil {
				return "", fmt.Errorf("store request handle: %w", err)
			}
			return handle, nil
		})
	cancelSelect()
	if err != nil {
		return 0, nil, nil, "", fmt.Errorf("select response: %w", err)
	}

	// Start the screencast
	startToken := baseToken + "_start"
	startPath, err := portalPathForToken(conn, portalRequestPathPrefix, startToken)
	if err != nil {
		return 0, nil, nil, "", err
	}
	startOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(startToken),
	}

	// Only the dispatch is internally bounded here. Start owns the interactive
	// chooser, so its Response remains governed by the caller's lifetime context.
	startResult, err := performPortalRequest(ctx, conn, startPath, portalMethodTimeout,
		func(callCtx context.Context) (dbus.ObjectPath, error) {
			var handle dbus.ObjectPath
			call := portalObject.CallWithContext(callCtx, portalScreenCastInterface+".Start", 0,
				sessionPath, "", startOpts)
			if call.Err != nil {
				return "", call.Err
			}
			if err := call.Store(&handle); err != nil {
				return "", fmt.Errorf("store request handle: %w", err)
			}
			return handle, nil
		})
	if err != nil {
		return 0, nil, nil, "", fmt.Errorf("start response: %w", err)
	}

	newRestoreToken := ""
	if variant, ok := startResult["restore_token"]; ok {
		value, ok := variant.Value().(string)
		if !ok {
			return 0, nil, nil, "", fmt.Errorf("unexpected restore token type: %T", variant.Value())
		}
		newRestoreToken = value
	}

	// Extract PipeWire node ID from the result
	streams, ok := startResult["streams"]
	if !ok {
		return 0, nil, nil, "", fmt.Errorf("no streams in start response")
	}

	var nodeID uint32
	var streamProperties map[string]dbus.Variant
	streamList, ok := streams.Value().([][]interface{})
	if !ok {
		// Try alternate format
		if v, ok2 := streams.Value().([]interface{}); ok2 && len(v) > 0 {
			if tuple, ok3 := v[0].([]interface{}); ok3 && len(tuple) > 0 {
				if nid, ok4 := tuple[0].(uint32); ok4 {
					nodeID = nid
				} else {
					return 0, nil, nil, "", fmt.Errorf("unexpected node ID type: %T", tuple[0])
				}
				if len(tuple) > 1 {
					streamProperties, _ = tuple[1].(map[string]dbus.Variant)
				}
			} else {
				return 0, nil, nil, "", fmt.Errorf("unexpected streams format: %T", streams.Value())
			}
		} else {
			return 0, nil, nil, "", fmt.Errorf("unexpected streams format: %T", streams.Value())
		}
	} else {
		if len(streamList) == 0 || len(streamList[0]) == 0 {
			return 0, nil, nil, "", fmt.Errorf("empty streams list")
		}
		nid, ok2 := streamList[0][0].(uint32)
		if !ok2 {
			return 0, nil, nil, "", fmt.Errorf("unexpected node ID type: %T", streamList[0][0])
		}
		nodeID = nid
		if len(streamList[0]) > 1 {
			streamProperties, _ = streamList[0][1].(map[string]dbus.Variant)
		}
	}

	if dimensions != nil {
		if width, height, ok := portalStreamDimensions(streamProperties); ok {
			dimensions[0], dimensions[1] = width, height
			dbg("[CAPTURE] portal stream size: %dx%d", width, height)
		} else {
			dbg("[CAPTURE] portal stream properties did not contain a usable size: %#v", streamProperties)
		}
	}

	// Keep the original bus connection and session path together. Each failed
	// GStreamer attempt consumes its PipeWire protocol connection, so retry by
	// asking this same portal session for a fresh remote rather than duping an fd.
	pwFile, err := portalSession.openPipeWireRemote(ctx)
	if err != nil {
		return 0, nil, nil, "", err
	}

	sessionTransferred = true
	return nodeID, pwFile, portalSession, newRestoreToken, nil
}

func portalStreamDimensions(properties map[string]dbus.Variant) (int, int, bool) {
	variant, ok := properties["size"]
	if !ok {
		return 0, 0, false
	}

	var width, height int
	switch size := variant.Value().(type) {
	case []int32:
		if len(size) == 2 {
			width, height = int(size[0]), int(size[1])
		}
	case []uint32:
		if len(size) == 2 {
			width, height = int(size[0]), int(size[1])
		}
	case []interface{}:
		if len(size) == 2 {
			width, _ = portalDimension(size[0])
			height, _ = portalDimension(size[1])
		}
	}
	return width, height, width > 0 && height > 0
}

func portalDimension(value interface{}) (int, bool) {
	switch value := value.(type) {
	case int32:
		return int(value), value > 0
	case uint32:
		return int(value), value > 0
	case int:
		return value, value > 0
	default:
		return 0, false
	}
}

func performPortalRequest(ctx context.Context, conn *dbus.Conn, expectedPath dbus.ObjectPath, dispatchTimeout time.Duration, dispatch portalRequestDispatch) (map[string]dbus.Variant, error) {
	ctx = normalizeContext(ctx)
	if conn == nil || !expectedPath.IsValid() || dispatch == nil {
		return nil, fmt.Errorf("invalid portal request")
	}
	if dispatchTimeout <= 0 {
		dispatchTimeout = portalMethodTimeout
	}

	// Request handles are predictable from handle_token. Subscribe before the
	// method call so a backend which responds before returning the handle cannot
	// race past us. The namespace match also preserves compatibility with older
	// portals which return a different handle under the standard request tree.
	signals := make(chan *dbus.Signal, 4)
	conn.Signal(signals)
	matchOptions := []dbus.MatchOption{
		dbus.WithMatchSender(portalBusName),
		dbus.WithMatchInterface(portalRequestInterface),
		dbus.WithMatchMember("Response"),
		dbus.WithMatchPathNamespace(portalRequestPathPrefix),
	}
	matchCtx, cancelMatch := context.WithTimeout(ctx, dispatchTimeout)
	err := conn.AddMatchSignalContext(matchCtx, matchOptions...)
	cancelMatch()
	if err != nil {
		conn.RemoveSignal(signals)
		return nil, fmt.Errorf("subscribe to portal response: %w", err)
	}
	defer func() {
		conn.RemoveSignal(signals)
		cleanupCtx, cancel := context.WithTimeout(context.Background(), portalCleanupTimeout)
		_ = conn.RemoveMatchSignalContext(cleanupCtx, matchOptions...)
		cancel()
	}()

	dispatchCtx, cancelDispatch := context.WithTimeout(ctx, dispatchTimeout)
	requestHandle, err := dispatch(dispatchCtx)
	cancelDispatch()
	if err != nil {
		closePortalRequest(conn, expectedPath)
		return nil, fmt.Errorf("dispatch portal request: %w", err)
	}
	if !requestHandle.IsValid() {
		closePortalRequest(conn, expectedPath)
		return nil, fmt.Errorf("portal returned invalid request handle %q", requestHandle)
	}
	if requestHandle != expectedPath {
		dbg("[CAPTURE] portal returned request handle %s instead of predicted %s", requestHandle, expectedPath)
		if !portalPathWithinNamespace(requestHandle, portalRequestPathPrefix) {
			closePortalRequest(conn, requestHandle)
			return nil, fmt.Errorf("portal returned request handle outside its request namespace: %s", requestHandle)
		}
	}

	for {
		select {
		case signal, ok := <-signals:
			if !ok {
				return nil, fmt.Errorf("portal connection closed before request %s responded", requestHandle)
			}
			if signal == nil || signal.Name != portalRequestInterface+".Response" || signal.Path != requestHandle {
				continue
			}
			return decodePortalResponse(signal)
		case <-ctx.Done():
			closePortalRequest(conn, requestHandle)
			return nil, fmt.Errorf("wait for portal response: %w", ctx.Err())
		}
	}
}

func decodePortalResponse(signal *dbus.Signal) (map[string]dbus.Variant, error) {
	if signal == nil || len(signal.Body) < 2 {
		return nil, fmt.Errorf("portal response body is too short")
	}
	status, ok := signal.Body[0].(uint32)
	if !ok {
		return nil, fmt.Errorf("unexpected portal response status type: %T", signal.Body[0])
	}
	if status != 0 {
		if status == 1 {
			return nil, fmt.Errorf("portal request was canceled")
		}
		return nil, fmt.Errorf("portal request failed with status %d", status)
	}
	result, ok := signal.Body[1].(map[string]dbus.Variant)
	if !ok {
		return nil, fmt.Errorf("unexpected portal response result type: %T", signal.Body[1])
	}
	return result, nil
}

func closePortalRequest(conn *dbus.Conn, requestPath dbus.ObjectPath) {
	if conn == nil || !requestPath.IsValid() || !conn.Connected() {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), portalCleanupTimeout)
	_ = conn.Object(portalBusName, requestPath).CallWithContext(ctx, portalRequestInterface+".Close", 0).Err
	cancel()
}

func portalPathWithinNamespace(path, namespace dbus.ObjectPath) bool {
	return path == namespace || strings.HasPrefix(string(path), string(namespace)+"/")
}

func portalPathForToken(conn *dbus.Conn, prefix dbus.ObjectPath, token string) (dbus.ObjectPath, error) {
	if conn == nil || !prefix.IsValid() || token == "" || strings.Contains(token, "/") {
		return "", fmt.Errorf("invalid portal path input")
	}
	names := conn.Names()
	if len(names) == 0 || !strings.HasPrefix(names[0], ":") {
		return "", fmt.Errorf("session bus did not assign a unique connection name")
	}
	sender := strings.ReplaceAll(strings.TrimPrefix(names[0], ":"), ".", "_")
	path := dbus.ObjectPath(string(prefix) + "/" + sender + "/" + token)
	if !path.IsValid() {
		return "", fmt.Errorf("generated invalid portal path %q", path)
	}
	return path, nil
}

func newPortalHandleToken() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", fmt.Errorf("generate portal handle token: %w", err)
	}
	return "doubletake_" + hex.EncodeToString(random[:]), nil
}

func screenCastPortalVersion(ctx context.Context, portal dbus.BusObject) uint32 {
	callCtx, cancel := context.WithTimeout(normalizeContext(ctx), portalMethodTimeout)
	defer cancel()
	call := portal.CallWithContext(callCtx, "org.freedesktop.DBus.Properties.Get", 0,
		portalScreenCastInterface, "version")
	var variant dbus.Variant
	if err := call.Store(&variant); err != nil {
		dbg("[CAPTURE] unable to read ScreenCast portal version: %v", err)
		return 0
	}
	version, ok := variant.Value().(uint32)
	if !ok {
		dbg("[CAPTURE] unexpected ScreenCast portal version type: %T", variant.Value())
		return 0
	}
	return version
}

func sessionHandleFromResult(result map[string]dbus.Variant) (dbus.ObjectPath, error) {
	variant, ok := result["session_handle"]
	if !ok {
		return "", fmt.Errorf("missing session_handle in portal response")
	}
	if sessionHandle, ok := variant.Value().(string); ok {
		path := dbus.ObjectPath(sessionHandle)
		if !path.IsValid() {
			return "", fmt.Errorf("invalid session handle %q", sessionHandle)
		}
		return path, nil
	}
	if sessionHandle, ok := variant.Value().(dbus.ObjectPath); ok {
		if !sessionHandle.IsValid() {
			return "", fmt.Errorf("invalid session handle %q", sessionHandle)
		}
		return sessionHandle, nil
	}
	return "", fmt.Errorf("unexpected session_handle type: %T", variant.Value())
}
