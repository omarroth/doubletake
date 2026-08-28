package airplay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
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

	// The isolated Wayland encoder receives copied raw frames over a pipe. Its
	// bounded copy/encode interval exceeds Apple's nominal 75 ms screen lead on
	// the supported integrated-GPU path.
	waylandRawRelayMinimumVideoLead = 250 * time.Millisecond
)

// ScreenCapture manages screen capture via GStreamer.
type ScreenCapture struct {
	cmd       *exec.Cmd // gst-launch-1.0 encoder process
	sourceCmd *exec.Cmd // optional Wayland capture/serialization process
	stdout    io.ReadCloser
	frames    videoAccessUnitReader
	cancel    context.CancelFunc
	pwNodeID  uint32
	dbusConn  *dbus.Conn    // portal session D-Bus connection (must stay open for Wayland)
	waitCh    chan struct{} // closed when process exits
	waitErr   error         // set before waitCh is closed
	stopped   bool
}

type capturePreparationKind uint8

const (
	capturePreparationX11 capturePreparationKind = iota
	capturePreparationWayland
	capturePreparationTest
)

func captureMinimumVideoLead(kind capturePreparationKind, measured time.Duration) time.Duration {
	if kind == capturePreparationWayland && measured < waylandRawRelayMinimumVideoLead {
		return waylandRawRelayMinimumVideoLead
	}
	return measured
}

func waylandRawVideoSize(receiverWidth, receiverHeight int, streamSize [2]int) (int, int) {
	if receiverWidth <= 0 || receiverHeight <= 0 {
		receiverWidth, receiverHeight = streamSize[0], streamSize[1]
	}
	receiverWidth, receiverHeight = fitVideoSize(receiverWidth, receiverHeight, 3840, 2160)
	return receiverWidth &^ 1, receiverHeight &^ 1
}

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
	// measuredVideoLatency is the minimum screen lead required by local capture:
	// the 4K HEVC preflight. minimumVideoLead also includes transport overhead.
	measuredVideoLatency time.Duration
	minimumVideoLead     time.Duration

	pwNodeID   uint32
	pwFd       *os.File
	dbusConn   *dbus.Conn
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
		return preparation, nil
	}

	if err := exec.Command("gst-inspect-1.0", "pipewiresrc").Run(); err != nil {
		return nil, fmt.Errorf("GStreamer 'pipewiresrc' plugin not found; install gst-pipewire")
	}
	nodeID, pwFd, dbusConn, restoreToken, err := requestScreencast(ctx, cfg.RestoreToken, cfg.ShowCursor, &preparation.streamSize)
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
	preparation.dbusConn = dbusConn
	preparation.minimumVideoLead = captureMinimumVideoLead(kind, preparation.measuredVideoLatency)
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
	ctx := lifetime
	if ctx == nil {
		ctx = p.ctx
	}
	nodeID := p.pwNodeID
	pwFd := p.pwFd
	dbusConn := p.dbusConn
	streamSize := p.streamSize
	timestampedOutput := supportsTimestampedVideoOutput(cfg.VideoCodec)
	p.pwFd = nil
	p.dbusConn = nil
	p.mu.Unlock()
	if cfg.VideoCodec == VideoCodecHEVC && !timestampedOutput {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if dbusConn != nil {
			_ = dbusConn.Close()
		}
		return nil, fmt.Errorf("HEVC capture requires GStreamer rtph265pay, rtponviftimestamp, and rtpstreampay")
	}
	if cfg.VideoCodec == VideoCodecHEVC && !hasGstElement("h265parse") {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if dbusConn != nil {
			_ = dbusConn.Close()
		}
		return nil, fmt.Errorf("HEVC capture requires GStreamer h265parse")
	}
	encoder, err := detectGstEncoder(cfg)
	if err != nil {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if dbusConn != nil {
			_ = dbusConn.Close()
		}
		return nil, err
	}

	switch kind {
	case capturePreparationWayland:
		return startPreparedWaylandCapture(ctx, cfg, encoder, nodeID, pwFd, dbusConn, streamSize, timestampedOutput)
	case capturePreparationX11:
		return startPreparedX11Capture(ctx, cfg, encoder, timestampedOutput)
	case capturePreparationTest:
		return startPreparedTestCapture(ctx, cfg, encoder, timestampedOutput)
	default:
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

// MinimumVideoLead returns the full local capture/transport scheduling floor.
func (p *CapturePreparation) MinimumVideoLead() time.Duration {
	if p == nil {
		return 0
	}
	return p.minimumVideoLead
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
	dbusConn := p.dbusConn
	p.pwFd = nil
	p.dbusConn = nil
	p.mu.Unlock()
	if pwFd != nil {
		_ = pwFd.Close()
	}
	if dbusConn != nil {
		_ = dbusConn.Close()
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

// encoderResult holds the selected encoder stage and its input requirements.
type encoderResult struct {
	parts       gstStage
	needsVulkan bool   // encoder needs vulkanupload immediately before it
	rawFormat   string // system-memory format produced by videoconvert
	codec       VideoCodec
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

func pipeWireVideoSourceStage(fd int, nodeID uint32, fps int, copyPortalBuffers bool) gstStage {
	stage := gstStage{
		"pipewiresrc",
		fmt.Sprintf("fd=%d", fd),
		fmt.Sprintf("path=%d", nodeID),
		"do-timestamp=true",
		fmt.Sprintf("keepalive-time=%d", frameIntervalMillis(fps)),
	}
	if copyPortalBuffers {
		// The software path cannot import a portal DMA-BUF through VA-API. Copy
		// immediately so downstream never retains a PipeWire-owned buffer.
		stage = append(stage, "always-copy=true")
	}
	return stage
}

func vaapiVideoImportStages() []gstStage {
	return []gstStage{
		{"vapostproc", "disable-passthrough=true"},
		{"video/x-raw,format=NV12"},
	}
}

func waylandVideoInputStages(fd int, nodeID uint32, fps int, useVAAPI bool) (gstStage, []gstStage) {
	source := pipeWireVideoSourceStage(fd, nodeID, fps, !useVAAPI)
	if !useVAAPI {
		return source, nil
	}
	return source, vaapiVideoImportStages()
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
	return appendGstEncoderPipeline(args, encoder, timestampedOutput)
}

func appendGstEncoderPipeline(args []string, encoder encoderResult, timestampedOutput bool) []string {
	if encoder.needsVulkan {
		args = appendGstStage(args, gstStage{"vulkanupload"})
	}
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

func buildSplitGstVideoPipeline(source gstStage, beforeConvert, afterScale []gstStage, encoder encoderResult, maxWidth, maxHeight, fps int, timestampedOutput bool) (producer, consumer []string) {
	producer = append([]string{"--quiet"}, source...)
	for _, stage := range beforeConvert {
		producer = appendGstStage(producer, stage)
	}
	producer = appendGstStage(producer, gstStage{"videoconvert"})
	producer = appendGstStage(producer, gstStage{fmt.Sprintf("video/x-raw,format=%s", encoder.rawFormat)})
	for _, stage := range receiverScaleStages(maxWidth, maxHeight) {
		producer = appendGstStage(producer, stage)
	}
	for _, stage := range afterScale {
		producer = appendGstStage(producer, stage)
	}
	producer = appendGstStage(producer, gstStage{"fdsink", "fd=1", "sync=false", "async=false"})

	maxWidth &^= 1
	maxHeight &^= 1
	consumer = []string{"--quiet", "fdsrc", "fd=0", "do-timestamp=true"}
	consumer = appendGstStage(consumer, gstStage{
		fmt.Sprintf(
			"video/x-raw,format=%s,width=%d,height=%d,framerate=%d/1",
			encoder.rawFormat, maxWidth, maxHeight, fps,
		),
	})
	consumer = appendGstStage(consumer, gstStage{"rawvideoparse", "use-sink-caps=true"})
	consumer = appendGstEncoderPipeline(consumer, encoder, timestampedOutput)
	return producer, consumer
}

type waylandSplitPipes struct {
	rawFrames     *os.File
	sourceOutput  *os.File
	sourceStderr  *os.File
	sourceErrOut  *os.File
	stdout        *os.File
	encoderOutput *os.File
	encoderStderr *os.File
	encoderErrOut *os.File
}

func openWaylandSplitPipes(sourceCmd, encoderCmd *exec.Cmd) (*waylandSplitPipes, error) {
	pipes := &waylandSplitPipes{}
	var err error
	pipes.rawFrames, pipes.sourceOutput, err = os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("capture serialization pipe: %w", err)
	}
	sourceCmd.Stdout = pipes.sourceOutput
	pipes.sourceStderr, pipes.sourceErrOut, err = os.Pipe()
	if err != nil {
		pipes.close()
		return nil, fmt.Errorf("capture stderr pipe: %w", err)
	}
	sourceCmd.Stderr = pipes.sourceErrOut
	encoderCmd.Stdin = pipes.rawFrames
	pipes.stdout, pipes.encoderOutput, err = os.Pipe()
	if err != nil {
		pipes.close()
		return nil, fmt.Errorf("encoder stdout pipe: %w", err)
	}
	encoderCmd.Stdout = pipes.encoderOutput
	pipes.encoderStderr, pipes.encoderErrOut, err = os.Pipe()
	if err != nil {
		pipes.close()
		return nil, fmt.Errorf("encoder stderr pipe: %w", err)
	}
	encoderCmd.Stderr = pipes.encoderErrOut
	return pipes, nil
}

func (pipes *waylandSplitPipes) close() {
	if pipes == nil {
		return
	}
	for _, closer := range []io.Closer{
		pipes.rawFrames,
		pipes.sourceOutput,
		pipes.sourceStderr,
		pipes.sourceErrOut,
		pipes.stdout,
		pipes.encoderOutput,
		pipes.encoderStderr,
		pipes.encoderErrOut,
	} {
		if closer != nil {
			_ = closer.Close()
		}
	}
}

func startWaylandEncoder(cmd *exec.Cmd, pipes *waylandSplitPipes) (<-chan error, error) {
	wait, err := startGStreamerCommand(cmd)
	if err != nil {
		pipes.close()
		return nil, err
	}
	return wait, nil
}

func startPreparedWaylandCapture(ctx context.Context, cfg CaptureConfig, encoderParts encoderResult, nodeID uint32, pwFd *os.File, dbusConn *dbus.Conn, streamSize [2]int, timestampedOutput bool) (*ScreenCapture, error) {
	if pwFd == nil || dbusConn == nil {
		if pwFd != nil {
			_ = pwFd.Close()
		}
		if dbusConn != nil {
			_ = dbusConn.Close()
		}
		return nil, fmt.Errorf("prepared Wayland capture is missing portal resources")
	}
	captureCtx, cancel := context.WithCancel(ctx)

	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}

	// Capture from the PipeWire portal and feed the shared video pipeline.
	//   - vapostproc imports the portal's DMA-BUF via VA-API when available
	//     Systems without VA-API (such as Asahi Linux) fall back to videoconvert.
	//   - Wayland compositors may stop publishing an undamaged screen. A forced-live
	//     GStreamer compositor repeats its input pad's latest frame at a regular
	//     rate, because AirPlay requires continuous video even for a static image.
	// The encoded dimensions are capped to the receiver's advertised display size
	// when available. The actual result is read back from the codec SPS downstream.
	const pwFdNum = 3
	hasCompositor := streamSize[0] > 0 && streamSize[1] > 0 && hasGstElement("compositor")
	hasVAAPIPostproc := hasGstElement("vapostproc")
	// VA-API needs the portal's original DMA-BUF. pipewiresrc's always-copy path
	// can turn DMA-BUF map failures into black fallback frames before vapostproc
	// gets a chance to import them. The software path still copies immediately
	// so a forced-live compositor cannot exhaust a small portal buffer pool.
	source, beforeConvert := waylandVideoInputStages(pwFdNum, nodeID, fps, hasVAAPIPostproc)
	if !hasVAAPIPostproc {
		log.Printf("[CAPTURE] vapostproc unavailable, using software conversion")
	}

	var afterScale []gstStage
	if hasCompositor {
		beforeConvert = append(beforeConvert,
			gstStage{"compositor", "force-live=true", "ignore-inactive-pads=true", "background=black"},
			gstStage{fmt.Sprintf("video/x-raw,width=%d,height=%d,framerate=%d/1", streamSize[0], streamSize[1], fps)},
			lowLatencyVideoQueueStage(),
		)
	} else {
		log.Printf("[CAPTURE] idle-frame compositor unavailable; using portal frame timing")
	}
	if !hasCompositor {
		afterScale = append(afterScale,
			gstStage{"videorate", "drop-only=true", "skip-to-first=true"},
			frameRateStage(fps),
			lowLatencyVideoQueueStage(),
		)
	}
	rawWidth, rawHeight := waylandRawVideoSize(cfg.MaxWidth, cfg.MaxHeight, streamSize)
	if rawWidth <= 0 || rawHeight <= 0 {
		cancel()
		_ = pwFd.Close()
		_ = dbusConn.Close()
		return nil, fmt.Errorf("Wayland capture is missing both receiver and portal dimensions")
	}
	sourceArgs, encoderArgs := buildSplitGstVideoPipeline(
		source, beforeConvert, afterScale, encoderParts,
		rawWidth, rawHeight, fps, timestampedOutput,
	)
	dbg("[CAPTURE] gst-launch-1.0 (wayland source) %s", strings.Join(sourceArgs, " "))
	dbg("[CAPTURE] gst-launch-1.0 (wayland encoder) %s", strings.Join(encoderArgs, " "))

	sourceCmd := exec.CommandContext(captureCtx, "gst-launch-1.0", sourceArgs...)
	sourceCmd.ExtraFiles = []*os.File{pwFd}
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", encoderArgs...)
	pipes, err := openWaylandSplitPipes(sourceCmd, cmd)
	if err != nil {
		cancel()
		_ = pwFd.Close()
		_ = dbusConn.Close()
		return nil, err
	}

	encoderWait, err := startWaylandEncoder(cmd, pipes)
	if err != nil {
		cancel()
		_ = pwFd.Close()
		_ = dbusConn.Close()
		return nil, fmt.Errorf("start encoder gst-launch: %w", err)
	}
	_ = pipes.rawFrames.Close()
	_ = pipes.encoderOutput.Close()
	_ = pipes.encoderErrOut.Close()
	sourceWait, err := startGStreamerCommand(sourceCmd)
	if err != nil {
		cancel()
		pipes.close()
		_ = pwFd.Close()
		_ = dbusConn.Close()
		<-encoderWait
		return nil, fmt.Errorf("start capture gst-launch: %w", err)
	}
	_ = pipes.sourceOutput.Close()
	_ = pipes.sourceErrOut.Close()
	_ = pwFd.Close() // source child inherited it

	go func() {
		defer pipes.sourceStderr.Close()
		logStderr("GST-SOURCE", pipes.sourceStderr)
	}()
	go func() {
		defer pipes.encoderStderr.Close()
		logStderr("GST-ENCODER", pipes.encoderStderr)
	}()

	capture := &ScreenCapture{
		cmd:       cmd,
		sourceCmd: sourceCmd,
		stdout:    pipes.stdout,
		cancel:    cancel,
		pwNodeID:  nodeID,
		dbusConn:  dbusConn,
		waitCh:    make(chan struct{}),
	}
	if timestampedOutput {
		capture.frames = newRTPVideoAccessUnitReader(pipes.stdout, encoderParts.codec)
	}
	go func() {
		type processResult struct {
			name string
			err  error
		}
		results := make(chan processResult, 2)
		go func() { results <- processResult{name: "capture", err: <-sourceWait} }()
		go func() { results <- processResult{name: "encoder", err: <-encoderWait} }()
		first := <-results
		dbg("[CAPTURE] %s pipeline exited: %v", first.name, first.err)
		cancel()
		<-results
		if first.err != nil {
			capture.waitErr = fmt.Errorf("%s pipeline: %w", first.name, first.err)
		}
		close(capture.waitCh)
	}()

	return capture, nil
}

func startPreparedX11Capture(ctx context.Context, cfg CaptureConfig, encoder encoderResult, timestampedOutput bool) (*ScreenCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

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
		startX, startY, endX, endY := detectPrimaryMonitor(display)
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

	beforeConvert := []gstStage{frameRateStage(fps), lowLatencyVideoQueueStage()}
	gstArgs := buildGstVideoPipeline(ximageSrcArgs, beforeConvert, nil, encoder, cfg.MaxWidth, cfg.MaxHeight, timestampedOutput)

	dbg("[CAPTURE] gst-launch-1.0 (x11) %s", strings.Join(gstArgs, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	stderr, _ := cmd.StderrPipe()

	waitResult, err := startGStreamerCommand(cmd)
	if err != nil {
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
	if timestampedOutput {
		capture.frames = newRTPVideoAccessUnitReader(stdout, encoder.codec)
	}
	go func() {
		capture.waitErr = <-waitResult
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

// ReadVideoAccessUnit returns one complete encoded frame with its source PTS.
// It is available when the capture pipeline uses the timestamped RTP/ONVIF
// output suffix. Callers must treat the returned AnnexB slice as immutable.
func (sc *ScreenCapture) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	if sc == nil || sc.frames == nil {
		return VideoAccessUnit{}, fmt.Errorf("capture does not provide timestamped access units")
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
	if sc.stopped {
		return
	}
	sc.stopped = true
	if sc.cancel != nil {
		sc.cancel()
	}

	// Close stdout to unblock any pending Read() call.
	if sc.stdout != nil {
		sc.stdout.Close()
	}

	if sc.dbusConn != nil {
		sc.dbusConn.Close()
	}

	if sc.cmd != nil && sc.cmd.Process != nil {
		_ = sc.cmd.Process.Signal(os.Interrupt)
	}
	if sc.sourceCmd != nil && sc.sourceCmd.Process != nil {
		_ = sc.sourceCmd.Process.Signal(os.Interrupt)
	}

	select {
	case <-sc.waitCh:
	case <-time.After(2 * time.Second):
		if sc.cmd != nil && sc.cmd.Process != nil {
			_ = sc.cmd.Process.Kill()
		}
		if sc.sourceCmd != nil && sc.sourceCmd.Process != nil {
			_ = sc.sourceCmd.Process.Kill()
		}
		<-sc.waitCh
	}
}

// detectPrimaryMonitor queries xrandr to find the primary monitor's geometry.
// Returns (startX, startY, endX, endY) bounding the primary monitor, where
// endX = startX + monitor_width and endY = startY + monitor_height. If
// detection fails it returns all zeros, meaning no cropping should be applied.
func detectPrimaryMonitor(display string) (startX, startY, endX, endY int) {
	// Run xrandr to get connected outputs with geometry
	out, err := exec.Command("xrandr", "--display", display, "--query").Output()
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
			result: encoderResult{rawFormat: "NV12", codec: VideoCodecH264, parts: []string{
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

// requestScreencast uses the xdg-desktop-portal D-Bus API to request screen capture
// permission and returns a PipeWire node ID, an fd for the portal's PipeWire remote,
// the D-Bus connection (which must stay open to keep the screencast session alive),
// and a fresh restore token when the portal grants persistence.
func requestScreencast(ctx context.Context, restoreToken string, showCursor bool, dimensions *[2]int) (uint32, *os.File, *dbus.Conn, string, error) {
	conn, err := dbus.ConnectSessionBus()
	if err != nil {
		return 0, nil, nil, "", fmt.Errorf("connect session bus: %w", err)
	}

	portal := conn.Object("org.freedesktop.portal.Desktop",
		"/org/freedesktop/portal/desktop")
	portalVersion := screenCastPortalVersion(portal)
	baseToken := newPortalHandleToken()

	// Create session
	sessionOpts := map[string]dbus.Variant{
		"handle_token":         dbus.MakeVariant(baseToken),
		"session_handle_token": dbus.MakeVariant(baseToken + "_session"),
	}

	var requestHandle dbus.ObjectPath
	call := portal.Call("org.freedesktop.portal.ScreenCast.CreateSession", 0, sessionOpts)
	if call.Err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("CreateSession: %w", call.Err)
	}
	if err := call.Store(&requestHandle); err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("store create-session request handle: %w", err)
	}

	createResult, err := waitForResponseWithResult(ctx, conn, requestHandle)
	if err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("session response: %w", err)
	}

	sessionPath, err := sessionHandleFromResult(createResult)
	if err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("session handle: %w", err)
	}

	// cursor_mode: HIDDEN=1, EMBEDDED=2 (cursor baked into the stream)
	cursorMode := uint32(1)
	if showCursor {
		cursorMode = 2
	}

	// Select sources (screen)
	selectOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(baseToken + "_select"),
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

	requestHandle = ""
	call = portal.Call("org.freedesktop.portal.ScreenCast.SelectSources", 0,
		sessionPath, selectOpts)
	if call.Err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("SelectSources: %w", call.Err)
	}
	if err := call.Store(&requestHandle); err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("store select-sources request handle: %w", err)
	}

	if _, err = waitForResponseWithResult(ctx, conn, requestHandle); err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("select response: %w", err)
	}

	// Start the screencast
	startOpts := map[string]dbus.Variant{
		"handle_token": dbus.MakeVariant(baseToken + "_start"),
	}

	requestHandle = ""
	call = portal.Call("org.freedesktop.portal.ScreenCast.Start", 0,
		sessionPath, "", startOpts)
	if call.Err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("Start: %w", call.Err)
	}
	if err := call.Store(&requestHandle); err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("store start request handle: %w", err)
	}

	startResult, err := waitForResponseWithResult(ctx, conn, requestHandle)
	if err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("start response: %w", err)
	}

	newRestoreToken := ""
	if variant, ok := startResult["restore_token"]; ok {
		value, ok := variant.Value().(string)
		if !ok {
			conn.Close()
			return 0, nil, nil, "", fmt.Errorf("unexpected restore token type: %T", variant.Value())
		}
		newRestoreToken = value
	}

	// Extract PipeWire node ID from the result
	streams, ok := startResult["streams"]
	if !ok {
		conn.Close()
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
					conn.Close()
					return 0, nil, nil, "", fmt.Errorf("unexpected node ID type: %T", tuple[0])
				}
				if len(tuple) > 1 {
					streamProperties, _ = tuple[1].(map[string]dbus.Variant)
				}
			} else {
				conn.Close()
				return 0, nil, nil, "", fmt.Errorf("unexpected streams format: %T", streams.Value())
			}
		} else {
			conn.Close()
			return 0, nil, nil, "", fmt.Errorf("unexpected streams format: %T", streams.Value())
		}
	} else {
		if len(streamList) == 0 || len(streamList[0]) == 0 {
			conn.Close()
			return 0, nil, nil, "", fmt.Errorf("empty streams list")
		}
		nid, ok2 := streamList[0][0].(uint32)
		if !ok2 {
			conn.Close()
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

	// OpenPipeWireRemote returns a Unix fd for the portal's PipeWire remote.
	// pipewiresrc MUST use this fd to connect; without it, it connects to the
	// global PipeWire instance which does not have the portal node and returns EINVAL.
	call = portal.Call("org.freedesktop.portal.ScreenCast.OpenPipeWireRemote", 0,
		sessionPath, map[string]dbus.Variant{})
	if call.Err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("OpenPipeWireRemote: %w", call.Err)
	}
	var pwFD dbus.UnixFD
	if err := call.Store(&pwFD); err != nil {
		conn.Close()
		return 0, nil, nil, "", fmt.Errorf("store pipewire fd: %w", err)
	}

	return nodeID, os.NewFile(uintptr(pwFD), "pipewire-remote"), conn, newRestoreToken, nil
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

func waitForResponseWithResult(ctx context.Context, conn *dbus.Conn, requestHandle dbus.ObjectPath) (map[string]dbus.Variant, error) {
	ch := make(chan *dbus.Signal, 1)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)

	matchRule := "type='signal',interface='org.freedesktop.portal.Request',member='Response'"
	if call := conn.BusObject().Call("org.freedesktop.DBus.AddMatch", 0, matchRule); call.Err != nil {
		return nil, fmt.Errorf("add portal response match: %w", call.Err)
	}
	defer conn.BusObject().Call("org.freedesktop.DBus.RemoveMatch", 0, matchRule)

	for {
		select {
		case sig := <-ch:
			if sig == nil || sig.Path != requestHandle {
				continue
			}
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

		case <-ctx.Done():
			return nil, fmt.Errorf("timeout waiting for portal response: %w", ctx.Err())
		}
	}
}

func newPortalHandleToken() string {
	return fmt.Sprintf("airplay_cast_%d", time.Now().UnixNano())
}

func screenCastPortalVersion(portal dbus.BusObject) uint32 {
	variant, err := portal.GetProperty("org.freedesktop.portal.ScreenCast.version")
	if err != nil {
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
		return dbus.ObjectPath(sessionHandle), nil
	}
	if sessionHandle, ok := variant.Value().(dbus.ObjectPath); ok {
		return sessionHandle, nil
	}
	return "", fmt.Errorf("unexpected session_handle type: %T", variant.Value())
}
