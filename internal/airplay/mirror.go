package airplay

import (
	"bytes"
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"howett.net/plist"
)

const (
	timingProtocolNTP          = "NTP"
	timingProtocolPTP          = "PTP"
	sessionInfoFallbackTimeout = 3 * time.Second

	legacyAirPlaySourceVersion = "280.33"
	modernAirPlaySourceVersion = "980.71.1"
)

// mediaClock maps local monotonic time onto the receiver's PTP timeline. The
// receiver's X-Apple-RequestReceivedTimestamp is in the same boot-relative
// domain as its PTP Follow_Up timestamps, so no local PTP stack is required.
type mediaClock struct {
	mu              sync.RWMutex
	anchorLocal     time.Time
	anchorTimestamp uint64
	timelineID      uint64
}

func (c *mediaClock) configureFromSetup(response map[string]interface{}, headers map[string]string, receivedAt time.Time) error {
	peer, _ := response["timingPeerInfo"].(map[string]interface{})
	timelineID := plistUint64(peer["ClockID"])
	if timelineID == 0 {
		return fmt.Errorf("SETUP response omitted timingPeerInfo.ClockID")
	}

	anchorTimestamp, receivedMillis, processingMillis, err := receiverClockTimestamp(headers)
	if err != nil {
		// Keep the receiver's identity even when the private clock-anchor headers
		// are absent. The fallback can then anchor local boot time to the actual
		// advertised PTP timeline.
		c.mu.Lock()
		c.timelineID = timelineID
		c.mu.Unlock()
		return err
	}

	c.mu.Lock()
	c.timelineID = timelineID
	c.anchorLocal = receivedAt
	c.anchorTimestamp = anchorTimestamp
	c.mu.Unlock()
	dbg("[PTP] receiver clock: timeline=0x%016x anchor=%dms processing=%dms",
		timelineID, receivedMillis, processingMillis)
	return nil
}

// configureFromLocalClock anchors a PTP timeline to the sender's boot clock.
// Some third-party PTP receivers return ClockID but omit Apple's private clock
// headers. A ClockID remains mandatory: inventing one would describe a timeline
// the receiver has never advertised and would make both audio and video invalid.
func (c *mediaClock) configureFromLocalClock() error {
	anchorLocal := time.Now()
	anchorTimestamp := compactTimestamp(bootRelativeNow())

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.timelineID == 0 {
		return fmt.Errorf("cannot configure local PTP clock without receiver ClockID")
	}
	c.anchorLocal = anchorLocal
	c.anchorTimestamp = anchorTimestamp
	return nil
}

func (c *mediaClock) identity() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.timelineID
}

func receiverClockTimestamp(headers map[string]string) (timestamp, receivedMillis, processingMillis uint64, err error) {
	receivedMillis, err = strconv.ParseUint(headers["x-apple-requestreceivedtimestamp"], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid X-Apple-RequestReceivedTimestamp %q", headers["x-apple-requestreceivedtimestamp"])
	}
	processingMillis, err = strconv.ParseUint(headers["x-apple-processingtime"], 10, 64)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("invalid X-Apple-ProcessingTime %q", headers["x-apple-processingtime"])
	}
	maxMillis := uint64(math.MaxInt64 / int64(time.Millisecond))
	if receivedMillis > maxMillis || processingMillis > maxMillis-receivedMillis {
		return 0, 0, 0, fmt.Errorf("receiver timestamp is out of range")
	}
	return compactTimestamp(time.Duration(receivedMillis+processingMillis) * time.Millisecond), receivedMillis, processingMillis, nil
}

func (c *mediaClock) reanchor(headers map[string]string, receivedAt time.Time) error {
	anchorTimestamp, _, _, err := receiverClockTimestamp(headers)
	if err != nil {
		return err
	}
	c.mu.Lock()
	// A feedback response carries the receiver's earlier request/processing
	// timestamp but is observed only when the response reaches us. Network delay
	// can therefore make a fresh sample appear older than the mapping already in
	// use. Never move the shared clock backwards: audio and video must observe the
	// same continuous timeline instead of relying on video-only packet clamping.
	if !c.anchorLocal.IsZero() && !receivedAt.Before(c.anchorLocal) {
		projected := c.anchorTimestamp + compactTimestamp(receivedAt.Sub(c.anchorLocal))
		if anchorTimestamp < projected {
			anchorTimestamp = projected
		}
	}
	c.anchorTimestamp = anchorTimestamp
	c.anchorLocal = receivedAt
	c.mu.Unlock()
	return nil
}

// updateTimingPeerInfo switches to a newly advertised PTP timeline without
// introducing a timestamp discontinuity. Event-channel timing updates contain
// only peer metadata (not a receiver timestamp), so carry the current estimate
// forward to the instant the command was received and update both atomically.
func (c *mediaClock) updateTimingPeerInfo(peer map[string]interface{}, receivedAt time.Time) error {
	timelineID := plistUint64(peer["ClockID"])
	if timelineID == 0 {
		return fmt.Errorf("updateTimingPeerInfo omitted ClockID")
	}

	c.mu.Lock()
	previousTimeline := c.timelineID
	if !c.anchorLocal.IsZero() && !receivedAt.Before(c.anchorLocal) {
		c.anchorTimestamp += compactTimestamp(receivedAt.Sub(c.anchorLocal))
		c.anchorLocal = receivedAt
	}
	c.timelineID = timelineID
	c.mu.Unlock()

	dbg("[PTP] event timing peer update: timeline=0x%016x (was 0x%016x)", timelineID, previousTimeline)
	return nil
}

func (c *mediaClock) now(bias time.Duration) (timestamp, timelineID uint64, ok bool) {
	c.mu.RLock()
	anchorLocal := c.anchorLocal
	anchorTimestamp := c.anchorTimestamp
	timelineID = c.timelineID
	c.mu.RUnlock()
	if anchorLocal.IsZero() || timelineID == 0 {
		return 0, 0, false
	}
	return anchorTimestamp + compactTimestamp(time.Since(anchorLocal)+bias), timelineID, true
}

// at maps a local monotonic capture time onto the receiver's PTP timeline.
// Unlike now, it preserves time spent in capture, scaling, and encoding.
func (c *mediaClock) at(local time.Time, bias time.Duration) (timestamp, timelineID uint64, ok bool) {
	c.mu.RLock()
	anchorLocal := c.anchorLocal
	anchorTimestamp := c.anchorTimestamp
	timelineID = c.timelineID
	c.mu.RUnlock()
	if local.IsZero() || anchorLocal.IsZero() || timelineID == 0 {
		return 0, 0, false
	}
	timestamp, ok = addTimestampDuration(anchorTimestamp, local.Sub(anchorLocal)+bias)
	return timestamp, timelineID, ok
}

func addTimestampDuration(timestamp uint64, delta time.Duration) (uint64, bool) {
	if delta >= 0 {
		addition := compactTimestamp(delta)
		if addition > ^uint64(0)-timestamp {
			return 0, false
		}
		return timestamp + addition, true
	}
	subtraction := compactTimestamp(-delta)
	if subtraction > timestamp {
		return 0, false
	}
	return timestamp - subtraction, true
}

// MirrorSession manages an active screen mirroring session.
type MirrorSession struct {
	client      *AirPlayClient
	dataConn    net.Conn
	dataMu      sync.Mutex // protects writes to dataConn
	eventConn   net.Conn
	timingConn  net.PacketConn
	cancel      context.CancelFunc
	closeOnce   sync.Once
	workers     sync.WaitGroup
	closeErr    error
	DataPort    int
	videoWidth  int
	videoHeight int
	videoCodec  VideoCodec
	sessionURI  string // RTSP session URI for TEARDOWN

	streamCipher       func([]byte) []byte // AES-CTR encryption
	chachaCipher       cipher.AEAD         // ChaCha20-Poly1305 AEAD (nil = use AES-CTR)
	chachaNonce        uint64              // per-frame nonce counter
	frameSeq           uint32
	lastFrameTimestamp uint64
	lastSlowWriteLog   time.Time
	firstFrameSent     chan struct{} // closed after first video frame is sent
	latePTSReported    bool
	timestampBias      time.Duration
	frameClockNow      func() time.Time
	timingProtocol     string
	mediaClock         *mediaClock

	// Audio
	audioStream *AudioStream
	noAudio     bool
}

func selectAudioSecurityMode(encrypted bool) audioSecurityMode {
	if encrypted {
		return audioSecurityChaCha
	}
	return audioSecurityLegacyAES
}

type mirrorSetupRequest struct {
	deviceID          string
	sessionUUID       string
	sourceVersion     string
	timingProtocol    string
	timingPort        int
	timingPeerID      string
	timingPeerAddress string
	name              string
}

func (r mirrorSetupRequest) sessionPlist() map[string]interface{} {
	request := map[string]interface{}{
		"deviceID":                 r.deviceID,
		"macAddress":               r.deviceID,
		"sessionUUID":              r.sessionUUID,
		"sourceVersion":            r.sourceVersion,
		"isScreenMirroringSession": true,
		"timingProtocol":           r.timingProtocol,
		"osBuildVersion":           "13F69",
		"model":                    "Linux",
		"name":                     r.name,
	}
	if r.timingProtocol == timingProtocolNTP {
		request["timingPort"] = int64(r.timingPort)
	} else if r.timingProtocol == timingProtocolPTP {
		peer := map[string]interface{}{
			"ID":                                r.timingPeerID,
			"SupportsClockPortMatchingOverride": true,
			"DeviceType":                        int64(0),
			"Addresses":                         []interface{}{r.timingPeerAddress},
		}
		request["timingPeerInfo"] = peer
		request["timingPeerList"] = []interface{}{peer}
	}
	return request
}

func (r mirrorSetupRequest) controlPlist() map[string]interface{} {
	request := r.sessionPlist()
	request["updateSessionRequest"] = false
	// Apple's sender combines GET /info with the control SETUP because display
	// metadata may not exist until this request creates the media session. The
	// receiver returns that ordinary info dictionary under the SETUP response's
	// "info" key before any media stream is configured. A qualifier is used only
	// for Apple's separate protected-display-capabilities exchange.
	request["combinedGetInfoWithControlSetup"] = true
	return request
}

func (r mirrorSetupRequest) legacyStreamPlist(stream map[string]interface{}) map[string]interface{} {
	request := r.sessionPlist()
	request["streams"] = []interface{}{stream}
	return request
}

func streamOnlyPlist(stream map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"streams": []interface{}{stream},
	}
}

func clonePlistMap(source map[string]interface{}) map[string]interface{} {
	clone := make(map[string]interface{}, len(source))
	for key, value := range source {
		clone[key] = value
	}
	return clone
}

func setupShapeRejected(err error) bool {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	switch statusErr.StatusCode {
	case 400, 406, 415, 455, 500, 501:
		return true
	default:
		return false
	}
}

// setupOrderRejected is deliberately narrower than descriptor negotiation.
// These protocol statuses are the bounded evidence used for one transition to
// media-first ordering. A generic server failure, authentication challenge, or
// transport error is not evidence that changing the ordering is valid.
func setupOrderRejected(err error) bool {
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) {
		return false
	}
	switch statusErr.StatusCode {
	case 400, 405, 406, 415, 455, 501:
		return true
	default:
		return false
	}
}

func audioLayoutName(layout audioConnectionLayout) string {
	if layout == audioLayoutStreamConnections {
		return "streamConnections"
	}
	return "controlPort"
}

func (c *AirPlayClient) requestSetup(uri, phase string, request map[string]interface{}) (map[string]interface{}, map[string]string, time.Time, error) {
	body, err := plist.Marshal(request, plist.BinaryFormat)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("marshal %s SETUP: %w", phase, err)
	}
	responseBody, headers, err := c.rtspRequest("SETUP", uri, "application/x-apple-binary-plist", body, nil)
	receivedAt := time.Now()
	if err != nil {
		return nil, nil, receivedAt, fmt.Errorf("%s SETUP: %w", phase, err)
	}
	var response map[string]interface{}
	if _, err := plist.Unmarshal(responseBody, &response); err != nil {
		return nil, nil, receivedAt, fmt.Errorf("unmarshal %s SETUP response: %w", phase, err)
	}
	dbg("[SETUP] %s response: %+v", phase, response)
	return response, headers, receivedAt, nil
}

// setupMirrorSession negotiates the mirroring stream with the Apple TV.
func (c *AirPlayClient) setupMirrorSession(ctx context.Context, cfg StreamConfig, prepareVideoCapture func(width, height int, codec VideoCodec) (VideoPreparationResult, error), captureMayReportMinimumLead bool) (*MirrorSession, error) {
	if err := ValidateVideoCodec(string(cfg.VideoCodec)); err != nil {
		return nil, err
	}
	sessionUUID := generateUUID()
	clientDeviceID := uuidToMAC(c.sessionID)
	senderName := pairingClientName()
	policy, err := compatibilityForReceiver(c.info, c.encrypted, !cfg.NoAudio)
	if err != nil {
		return nil, fmt.Errorf("negotiate screen audio: %w", err)
	}
	sourceVersion := policy.sourceVersion()
	timingProtocol := policy.timing
	var clock *mediaClock
	if timingProtocol == timingProtocolPTP {
		clock = &mediaClock{}
	}
	setupRequest := mirrorSetupRequest{
		deviceID:       clientDeviceID,
		sessionUUID:    sessionUUID,
		sourceVersion:  sourceVersion,
		timingProtocol: timingProtocol,
		name:           senderName,
	}
	if timingProtocol == timingProtocolPTP {
		localAddress, err := localIPForConnection(c.conn)
		if err != nil {
			return nil, fmt.Errorf("determine PTP peer address: %w", err)
		}
		setupRequest.timingPeerID = generateUUID()
		setupRequest.timingPeerAddress = localAddress
		dbg("[PTP] local timing peer: id=%s address=%s", setupRequest.timingPeerID, localAddress)
	}
	dbg("[SETUP] timing protocol: %s (sourceVersion=%s)", timingProtocol, sourceVersion)

	// Determine stream encryption key
	encKey := c.fpKey
	encIV := c.fpIV
	if encKey == nil {
		if c.streamKey == nil {
			if err := c.deriveStreamKeys(); err != nil {
				return nil, fmt.Errorf("derive stream keys: %w", err)
			}
		}
		encKey = c.streamKey
		encIV = c.streamIV
	}

	if cfg.NoEncrypt {
		dbg("[SETUP] video frame encryption DISABLED (--no-encrypt mode)")
		encKey = nil
		encIV = nil
	} else if encKey != nil {
		dbg("[SETUP] using encryption (key: %d bytes, IV: %d bytes)", len(encKey), len(encIV))
	}

	// Allocate separate consecutive sockets for timing, RTCP, and RTP. Only the
	// RTCP port is advertised; the receiver accepts RTP from the data socket's
	// independently allocated source port.
	audioPorts, err := allocateConsecutiveUDPPortsInRange(3, cfg.PortMin, cfg.PortMax)
	if err != nil {
		return nil, fmt.Errorf("allocate audio ports: %w", err)
	}
	timingConn := audioPorts[0]
	audioCtrlConn := audioPorts[1]
	audioDataConn := audioPorts[2]
	sessionCtx, cancelSession := context.WithCancel(ctx)
	var receiverEventConn, dataConn net.Conn
	setupSucceeded := false
	defer func() {
		if setupSucceeded {
			return
		}
		cancelSession()
		if dataConn != nil {
			dataConn.Close()
		}
		if receiverEventConn != nil {
			receiverEventConn.Close()
		}
		for _, conn := range audioPorts {
			conn.Close()
		}
	}()
	timingPort := timingConn.LocalAddr().(*net.UDPAddr).Port
	setupRequest.timingPort = timingPort
	dbg("[SETUP] consecutive UDP ports: base=%d ctrl=%d data=%d", timingPort, timingPort+1, timingPort+2)

	// NTP sessions establish their mapping by probing this port during SETUP.
	// PTP sessions instead use the receiver's advertised network clock.
	if timingProtocol == timingProtocolNTP {
		go ntpTimingResponder(sessionCtx, timingConn)
	}

	// The transport currently exposes no semantic connection-latency hint, so
	// use Apple's ordinary connection policy. Timing protocol only changes the
	// clock conversion; it does not select a different playout lead.
	latencies := screenLatenciesForHint(connectionLatencyNormal)
	dbg("[SETUP] base screen latency policy: video=%v audio=%v", latencies.video, latencies.audio)

	// Apple's sender prepares the receiver with a control-only SETUP before it
	// creates media streams. Older protocol implementations can explicitly
	// reject that control shape; in that case, make exactly one transition to
	// the legacy media-first sequence. No receiver identity or unrelated feature
	// bit is used to infer SETUP ordering.
	sessionFirstSetup := true

	audioStreamConnectionID := int64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFF)
	selectedAudioCodec := policy.audioCodec
	// Real Apple senders use streamConnectionID as the RTSP URI path.
	// Control, audio, RECORD, and SET_PARAMETER share the audio URI; video uses
	// a separate URI with its own streamConnectionID.
	audioURI := fmt.Sprintf("rtsp://%s:%d/%d", c.host, c.port, audioStreamConnectionID)
	audioMode := policy.audioSecurity
	var audioKey, audioIV, audioChaChaKey []byte
	if audioMode == audioSecurityChaCha {
		var err error
		audioChaChaKey, err = generateAudioChaChaKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate ChaCha20-Poly1305 audio key: %w", err)
		}
		dbg("[SETUP] audio encryption: ChaCha20-Poly1305 direct stream key (streamConnectionID=%d, shk=%d bytes)", audioStreamConnectionID, len(audioChaChaKey))
	}
	if audioMode == audioSecurityLegacyAES && c.fpKey != nil && c.fpIV != nil {
		audioKey = c.fpKey
		audioIV = c.fpIV
		dbg("[SETUP] audio encryption: AES-128-CBC (fpKey/hashed %d bytes)", len(audioKey))
	} else if audioMode == audioSecurityLegacyAES {
		dbg("[SETUP] audio encryption: disabled (no FairPlay key available)")
	}

	audioDataPort := 0
	audioControlPort := 0
	var receiverEventPort int
	var attemptedEventPort int
	audioControlLPort := audioCtrlConn.LocalAddr().(*net.UDPAddr).Port
	if !targetLatencyIsExplicit() {
		latencies = latencies.withMinimumVideoLead(cfg.MinimumVideoLead)
	}
	audioLatencySamples := samplesFor44k1(latencies.audio)
	measuredLatencyApplied := false
	audioSetupCommitted := false
	applyMeasuredCaptureLatency := func(codec VideoCodec, minimumVideoLead time.Duration) error {
		if measuredLatencyApplied || codec != VideoCodecHEVC || targetLatencyIsExplicit() || minimumVideoLead <= latencies.video {
			return nil
		}
		if audioSetupCommitted {
			// A legacy media-first receiver has already accepted latencyMax. Failing
			// is safer than creating a descriptor/TimeAnnounce mismatch after that
			// protocol boundary. Automatic selection avoids this path by choosing H.264
			// before the production capture is launched.
			return fmt.Errorf("production HEVC requires %v video lead, but media-first audio SETUP already committed %v; use automatic/H.264 or an explicit joint target of at least %v", minimumVideoLead, latencies.video, minimumVideoLead)
		}
		before := latencies
		latencies = latencies.withMinimumVideoLead(minimumVideoLead)
		audioLatencySamples = samplesFor44k1(latencies.audio)
		measuredLatencyApplied = true
		dbg("[SETUP] local capture budget raised playout leads: video=%v->%v audio=%v->%v",
			before.video, latencies.video, before.audio, latencies.audio)
		return nil
	}
	skipRecord := false

	firstSetup := true
	sendSetup := func(uri, phase string, request map[string]interface{}) (map[string]interface{}, map[string]string, time.Time, error) {
		if !firstSetup {
			return c.requestSetup(uri, phase, request)
		}
		firstSetup = false
		setupHintDone := make(chan struct{})
		go func() {
			select {
			case <-setupHintDone:
			case <-time.After(3 * time.Second):
				log.Printf("warning: Apple TV at %s has not responded to SETUP after 3s.", c.host)
				if timingProtocol == timingProtocolNTP {
					log.Printf("  this usually means a host firewall is blocking the receiver's NTP probe.")
					log.Printf("  re-run with -port-range MIN-MAX (e.g. -port-range 60000-60010) and allow")
					log.Printf("  that UDP range inbound from %s. See the Firewall section of the README.", c.host)
				}
			}
		}()
		defer close(setupHintDone)
		return c.requestSetup(uri, phase, request)
	}

	recordSession := func() error {
		recordHeaders := map[string]string{
			"Session":  sessionUUID,
			"Range":    "npt=0-",
			"RTP-Info": "seq=0;rtptime=0",
		}
		_, responseHeaders, err := c.rtspRequest("RECORD", audioURI, "", nil, recordHeaders)
		if err != nil {
			return fmt.Errorf("RECORD: %w", err)
		}
		if value, ok := responseHeaders["audio-latency"]; ok {
			parsed, parseErr := strconv.ParseUint(value, 10, 32)
			if parseErr != nil {
				dbg("[SETUP] invalid Audio-Latency header %q: %v", value, parseErr)
			} else if parsed > 0 {
				receiverLatency := time.Duration(parsed) * time.Second / 44100
				dbg("[SETUP] receiver Audio-Latency telemetry: %d samples (%v)", parsed, receiverLatency)
			}
		}
		return nil
	}

	connectEvent := func() error {
		if receiverEventConn != nil {
			return nil
		}
		if receiverEventPort == 0 {
			return nil
		}
		if attemptedEventPort == receiverEventPort {
			return nil
		}
		attemptedEventPort = receiverEventPort
		var err error
		receiverEventConn, err = c.connectEventChannel(sessionCtx, receiverEventPort, clock)
		if err != nil {
			return fmt.Errorf("connect receiver event channel: %w", err)
		}
		return nil
	}
	observeEventPort := func(response map[string]interface{}) {
		if port := plistInt(response["eventPort"]); port > 0 {
			receiverEventPort = port
		}
	}
	timingProbesStarted := false
	startReceiverTimingProbes := func(response map[string]interface{}) {
		if timingProbesStarted || timingProtocol != timingProtocolNTP {
			return
		}
		receiverTimingPort := plistInt(response["timingPort"])
		if receiverTimingPort <= 0 {
			return
		}
		timingProbesStarted = true
		go sendNTPTimingProbes(sessionCtx, timingConn, c.host, receiverTimingPort)
	}
	configurePTPClock := func(response map[string]interface{}, headers map[string]string, receivedAt time.Time) error {
		if timingProtocol != timingProtocolPTP {
			return nil
		}
		if err := clock.configureFromSetup(response, headers, receivedAt); err != nil {
			if policy.permitsLocalPTPClock() {
				if fallbackErr := clock.configureFromLocalClock(); fallbackErr == nil {
					dbg("[PTP] %v; using local boot time on receiver timeline 0x%016x", err, clock.identity())
					return nil
				}
			}
			return fmt.Errorf("configure PTP media clock: %w", err)
		}
		return nil
	}

	dbg("[SETUP] phase 1 (control): preparing media session")
	controlPlist := setupRequest.controlPlist()
	if policy.fairPlayOnControl() {
		addFairPlayRootFields(controlPlist, c.FpEkey, c.fpIV, true)
	}
	controlResp, controlHeaders, receivedAt, err := sendSetup(audioURI, "control", controlPlist)
	videoPrepared := false
	videoCodec := VideoCodecH264
	prepareVideo := func(info *ReceiverInfo) error {
		if videoPrepared {
			return nil
		}
		videoPrepared = true
		selection, selectionErr := info.selectVideo(cfg.VideoCodec, cfg.AutomaticHEVCAvailable)
		if selectionErr != nil {
			return selectionErr
		}
		if selection.codec == VideoCodecHEVC && cfg.VideoCodec == VideoCodecAuto && audioSetupCommitted &&
			!targetLatencyIsExplicit() && (cfg.MeasuredVideoLatency > latencies.video || captureMayReportMinimumLead) {
			// The legacy media-first flow exposes dynamic display metadata only after
			// latencyMax has been accepted. Keep the descriptor and TimeAnnounce
			// coherent by retaining the nominal H.264 path for this session rather
			// than selecting a calibrated HEVC clock too late.
			selection, selectionErr = info.selectVideo(VideoCodecH264, false)
			if selectionErr != nil {
				return selectionErr
			}
			selection.reason = "media-first audio latency was committed before HEVC calibration"
		}
		videoCodec = selection.codec
		canvasW, canvasH := selection.width, selection.height
		maxW, maxH := info.MaxVideoSize()
		dbg("[SETUP] receiver video canvas: %dx%d (maximum %dx%d, codec=%s, requested=%s: %s)", canvasW, canvasH, maxW, maxH, videoCodec, normalizeVideoCodec(cfg.VideoCodec), selection.reason)
		minimumVideoLead := cfg.MeasuredVideoLatency
		if prepareVideoCapture == nil {
			return applyMeasuredCaptureLatency(videoCodec, minimumVideoLead)
		}
		result, err := prepareVideoCapture(canvasW, canvasH, videoCodec)
		if err != nil {
			return fmt.Errorf("prepare %dx%d video capture: %w", canvasW, canvasH, err)
		}
		if result.MinimumVideoLead > minimumVideoLead {
			minimumVideoLead = result.MinimumVideoLead
		}
		return applyMeasuredCaptureLatency(videoCodec, minimumVideoLead)
	}
	refreshSessionInfo := func(phase string) (*ReceiverInfo, error) {
		refreshed, refreshErr := c.getInfoWithTimeout(sessionInfoFallbackTimeout)
		if refreshErr == nil {
			return refreshed, nil
		}
		// A complete HTTP error response has been consumed, so the connection is
		// still synchronized and the provisional snapshot remains usable. A Digest
		// challenge here is too late for the ordinary whole-SETUP retry: the receiver
		// has already accepted control or audio SETUP and may own media-session state.
		// Report it as a non-retryable setup error so the next connection can begin
		// with the credential configured. Any transport/read failure is also fatal:
		// continuing after a timed-out sequential request would let its late response
		// be mistaken for the following SETUP response.
		if errors.Is(refreshErr, ErrCredentialsRequired) {
			return nil, fmt.Errorf("%s GET /info requested credentials after session creation; reconnect with the receiver code/password configured before SETUP (%v)", phase, refreshErr)
		}
		var statusErr *HTTPStatusError
		if errors.As(refreshErr, &statusErr) {
			dbg("[SETUP] %s GET /info fallback was declined: %v", phase, refreshErr)
			return c.info, nil
		}
		return nil, fmt.Errorf("%s GET /info fallback: %w", phase, refreshErr)
	}
	if err != nil {
		if !setupOrderRejected(err) {
			return nil, err
		}
		sessionFirstSetup = false
		dbg("[SETUP] receiver rejected control-first SETUP; negotiating legacy media-first SETUP")
	} else {
		resolvedInfo := c.info
		sessionDisplayResolved := false
		if update, ok := controlResp["info"].(map[string]interface{}); ok {
			updatedInfo, updateErr := c.applyReceiverInfoUpdate(update, controlHeaders["server"])
			if updateErr != nil {
				dbg("[SETUP] invalid combined receiver info: %v", updateErr)
			} else {
				resolvedInfo = updatedInfo
				_, displaysPresent := update["displays"]
				displayW, displayH := updatedInfo.DisplaySize()
				sessionDisplayResolved = displaysPresent && displayW > 0 && displayH > 0
			}
		}
		// Combined GetInfo is optional, and older implementations may accept its
		// keys without returning an info dictionary. Once control SETUP has created
		// the media session, a normal encrypted GET /info observes the same dynamic
		// display state. Refresh whenever the accepted combined response did not
		// explicitly supply a usable display; a nonzero pre-session display can be
		// provisional too.
		if prepareVideoCapture != nil && !sessionDisplayResolved {
			refreshed, refreshErr := refreshSessionInfo("post-control")
			if refreshErr != nil {
				return nil, refreshErr
			}
			resolvedInfo = refreshed
		}
		if err := prepareVideo(resolvedInfo); err != nil {
			return nil, err
		}
		startReceiverTimingProbes(controlResp)
		skipRecord, _ = controlResp["skipRecord"].(bool)
		if err := configurePTPClock(controlResp, controlHeaders, receivedAt); err != nil {
			return nil, err
		}
		observeEventPort(controlResp)
		if err := connectEvent(); err != nil {
			return nil, err
		}
		if skipRecord {
			dbg("[SETUP] receiver returned skipRecord=true; session was started by control SETUP")
		} else if err := recordSession(); err != nil {
			return nil, err
		}
	}
	// Create the audio stream after the control-first probe, or make it the first
	// accepted request after a legacy-order rejection.
	audioCT, audioSPF, audioFmt, latMin, latMax, _ := selectedAudioCodec.Info()
	// Screen audio has no sender-side minimum latency. The maximum is the
	// playout lead carried by TimeAnnounce; using that lead as the minimum too
	// makes the receiver add it again when calculating its render offset.
	latMin = 0
	latMax = int64(audioLatencySamples)
	audioStreamBase := map[string]interface{}{
		"type":               int64(96),
		"streamConnectionID": audioStreamConnectionID,
		"ct":                 audioCT,
		"spf":                audioSPF,
		"sr":                 int64(44100),
		"audioFormat":        audioFmt,
		"audioMode":          "default",
		"usingScreen":        true,
		"latencyMin":         latMin,
		"latencyMax":         latMax,
	}
	if useAudioFEC(selectedAudioCodec, audioMode == audioSecurityChaCha) {
		audioStreamBase["redundantAudio"] = int64(2)
	}

	// Audio encryption and descriptor shape are separate protocol axes. The
	// advertised stream-connection capability selects the initial shape; a
	// protocol rejection below permits one alternate-shape probe.
	audioLayout := policy.audioConnections
	buildAudioSetup := func(layout audioConnectionLayout) (map[string]interface{}, map[string]interface{}) {
		stream := clonePlistMap(audioStreamBase)
		addScreenAudioStreamFields(stream, audioChaChaKey, audioControlLPort, layout)
		var request map[string]interface{}
		if sessionFirstSetup {
			request = streamOnlyPlist(stream)
		} else {
			request = setupRequest.legacyStreamPlist(stream)
		}
		if policy.fairPlayOnStreams() {
			if !addFairPlayRootFields(request, c.FpEkey, c.fpIV, true) && audioMode == audioSecurityLegacyAES {
				dbg("[SETUP] WARNING: no FairPlay ekey/eiv — audio will likely not work")
			}
		}
		return request, stream
	}
	audioSetupPlist, audioStreamDesc := buildAudioSetup(audioLayout)
	debugDumpPlist("audio setup plist", audioSetupPlist)
	debugDumpPlist("audio stream descriptor", audioStreamDesc)

	audioPhase := 1
	videoPhase := 2
	if sessionFirstSetup {
		audioPhase = 2
		videoPhase = 3
	}
	dbg("[SETUP] phase %d (audio): ct=%d spf=%d audioFormat=0x%x controlPort=%d", audioPhase, audioCT, audioSPF, audioFmt, audioControlLPort)
	audioResp, audioRespHeaders, audioRespReceivedAt, err := sendSetup(audioURI, "audio stream", audioSetupPlist)
	// Feature 59 is Apple's advertised streamConnections selector. If the peer
	// explicitly rejects that shape (or the legacy shape selected when it is
	// absent), negotiate the alternate descriptor exactly once. This never
	// changes an already accepted SETUP.
	if err != nil && setupShapeRejected(err) {
		alternate := audioLayoutControlPort
		if audioLayout == audioLayoutControlPort {
			alternate = audioLayoutStreamConnections
		}
		dbg("[SETUP] receiver rejected %s audio descriptor; retrying with %s", audioLayoutName(audioLayout), audioLayoutName(alternate))
		audioSetupPlist, audioStreamDesc = buildAudioSetup(alternate)
		debugDumpPlist("alternate audio setup plist", audioSetupPlist)
		debugDumpPlist("alternate audio stream descriptor", audioStreamDesc)
		audioResp, audioRespHeaders, audioRespReceivedAt, err = sendSetup(audioURI, "audio stream alternate descriptor", audioSetupPlist)
		if err == nil {
			audioLayout = alternate
		}
	}
	if err != nil {
		return nil, err
	}
	audioSetupCommitted = true
	startReceiverTimingProbes(audioResp)
	observeEventPort(audioResp)
	if err := connectEvent(); err != nil {
		return nil, err
	}
	if !sessionFirstSetup {
		skipRecord, _ = audioResp["skipRecord"].(bool)
		if err := configurePTPClock(audioResp, audioRespHeaders, audioRespReceivedAt); err != nil {
			return nil, err
		}
		resolvedInfo := c.info
		// A media-first receiver creates its session with the accepted audio
		// SETUP, so this is the earliest point where its dynamic display metadata
		// can exist. It has no combined-control response; refresh once before the
		// video stream is configured.
		if prepareVideoCapture != nil {
			refreshed, refreshErr := refreshSessionInfo("post-audio")
			if refreshErr != nil {
				return nil, refreshErr
			}
			resolvedInfo = refreshed
		}
		if err := prepareVideo(resolvedInfo); err != nil {
			return nil, err
		}
	}

	// Extract audio ports
	if streams, ok := audioResp["streams"].([]interface{}); ok {
		for _, s := range streams {
			stream, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			streamType := plistInt(stream["type"])
			if streamType == 96 {
				audioDataPort, audioControlPort = plistStreamPorts(stream)
				if latency := plistInt(stream["arrivalToRenderLatencyMs"]); latency > 0 {
					// This is the receiver's platform/I/O delay, not the RTP
					// playout lead negotiated in latencyMax and TimeAnnounce.
					dbg("[SETUP] receiver arrival-to-render latency: %dms", latency)
				}
				dbg("[SETUP] audio stream: dataPort=%d controlPort=%d", audioDataPort, audioControlPort)
			}
		}
	}

	// Attach the video stream to the prepared session.
	// Video SETUP uses the same sessionUUID but a different streamConnectionID.
	// The Apple TV attaches this video stream to the existing session.
	videoStreamConnectionID := int64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFF)
	videoURI := fmt.Sprintf("rtsp://%s:%d/%d", c.host, c.port, videoStreamConnectionID)

	videoStreamDesc := map[string]interface{}{
		"type":               int64(110),
		"streamConnectionID": videoStreamConnectionID,
		"latencyMs":          latencies.video.Milliseconds(),
		"timestampInfo": []interface{}{
			map[string]interface{}{"name": "SubSu"},
			map[string]interface{}{"name": "BePxT"},
			map[string]interface{}{"name": "AfPxT"},
			map[string]interface{}{"name": "BefEn"},
			map[string]interface{}{"name": "EmEnc"},
		},
	}

	// Encryption keys: shk/shiv go inside the video stream descriptor
	if encKey != nil {
		videoStreamDesc["shk"] = encKey
		videoStreamDesc["shiv"] = encIV
	}

	var videoSetupPlist map[string]interface{}
	if sessionFirstSetup {
		videoSetupPlist = streamOnlyPlist(videoStreamDesc)
	} else {
		videoSetupPlist = setupRequest.legacyStreamPlist(videoStreamDesc)
	}
	// Legacy FairPlay sessions derive video keys from material at the SETUP root,
	// independent of whether the plist is stream-only.
	if policy.fairPlayOnStreams() && encKey != nil {
		addFairPlayRootFields(videoSetupPlist, c.FpEkey, encIV, false)
	}
	dbg("[SETUP] phase %d (video): streamConnectionID=%d", videoPhase, videoStreamConnectionID)

	var dataPort int
	videoResp, _, _, err := sendSetup(videoURI, "video stream", videoSetupPlist)
	if err != nil {
		return nil, err
	}
	startReceiverTimingProbes(videoResp)
	observeEventPort(videoResp)

	if receiverEventConn == nil {
		if err := connectEvent(); err != nil {
			return nil, err
		}
		if receiverEventConn == nil {
			dbg("[EVENT] receiver omitted or declined the optional event channel; continuing without it")
		}
	}

	// Extract video data port
	if streams, ok := videoResp["streams"].([]interface{}); ok {
		for _, s := range streams {
			stream, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			streamType := plistInt(stream["type"])
			if streamType == 110 {
				dataPort = plistInt(stream["dataPort"])
			}
		}
	}

	if dataPort == 0 {
		return nil, fmt.Errorf("no video data port in SETUP response")
	}

	// Connect to the video data port
	dataAddr := net.JoinHostPort(c.host, strconv.Itoa(dataPort))
	dataConn, err = net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect data port %s: %w", dataAddr, err)
	}
	if tc, ok := dataConn.(*net.TCPConn); ok {
		tc.SetNoDelay(true)
		tc.SetWriteBuffer(64 * 1024)
	}
	dbg("[SETUP] data channel connected: %s (TCP_NODELAY, sndbuf=64K)", dataAddr)

	// Legacy receivers prepare the session with their combined audio SETUP and
	// start it only after both streams exist.
	if !sessionFirstSetup {
		if skipRecord {
			dbg("[SETUP] receiver returned skipRecord=true; session was started by SETUP")
		} else if err := recordSession(); err != nil {
			return nil, err
		}
	}

	// Set volume to 0 dB (full scale). Positive dB values are invalid here and
	// current receivers may interpret them as zero gain.
	volumeBody := audioVolumeBody(false)
	_, _, err = c.rtspRequest("SET_PARAMETER", audioURI, "text/parameters", volumeBody, nil)
	if err != nil {
		dbg("[SETUP] SET_PARAMETER volume failed (non-fatal): %v", err)
	} else {
		dbg("[SETUP] SET_PARAMETER volume=0 sent")
	}
	// Send volume twice (pcap shows real senders do this)
	_, _, _ = c.rtspRequest("SET_PARAMETER", audioURI, "text/parameters", volumeBody, nil)

	if timingProtocol == timingProtocolPTP {
		// PTP uses the receiver's fixed 319/320 ports. The first socket was only
		// reserved while allocating consecutive audio control/data ports.
		_ = timingConn.Close()
		timingConn = nil
	}

	session := &MirrorSession{
		client:         c,
		dataConn:       dataConn,
		eventConn:      receiverEventConn,
		cancel:         cancelSession,
		DataPort:       dataPort,
		videoCodec:     videoCodec,
		firstFrameSent: make(chan struct{}),
		noAudio:        cfg.NoAudio,
		sessionURI:     audioURI,
		timingConn:     timingConn,
		timestampBias:  latencies.video,
		timingProtocol: timingProtocol,
		mediaClock:     clock,
	}

	// Set up the video cipher. Encrypted pair-verify uses ChaCha20-Poly1305 with
	// an HKDF-derived key; plaintext pair-verify uses AES-CTR.
	if encKey != nil && c.encrypted && ((c.PairKeys != nil && len(c.PairKeys.SharedSecret) > 0) || c.fpAesKey != nil) {
		// ChaCha20-Poly1305 path: HKDF-SHA512 key derivation.
		// The receiver's _GetDataStreamSecurityKeys calls the FP helper's HKDF method.
		// The sender side uses PairingSessionDeriveKey via the PairingClient, which
		// does HKDF with the pair-verify X25519 ECDH shared secret as IKM.
		ikm := c.fpAesKey
		if c.PairKeys != nil && len(c.PairKeys.SharedSecret) > 0 {
			ikm = c.PairKeys.SharedSecret
			dbg("[SETUP] using pair-verify shared secret as DataStream HKDF IKM (%d bytes)", len(ikm))
		} else {
			dbg("[SETUP] using raw FairPlay AES key as DataStream HKDF IKM (%d bytes)", len(ikm))
		}
		chachaKey, err := deriveChaChaKey(ikm, videoStreamConnectionID)
		if err != nil {
			return nil, fmt.Errorf("derive chacha key: %w", err)
		}
		aead, err := chacha20poly1305.New(chachaKey)
		if err != nil {
			return nil, fmt.Errorf("chacha20poly1305: %w", err)
		}
		session.chachaCipher = aead
		dbg("[SETUP] using ChaCha20-Poly1305 (HKDF-SHA512)")
		dbg("[SETUP] streamConnectionID: %d", videoStreamConnectionID)
		dbg("[SETUP] IKM (%d bytes):   %02x", len(ikm), ikm)
		dbg("[SETUP] chacha key:       %02x", chachaKey)
	} else if encKey != nil {
		// AES-CTR path: SHA-512-derived key from shk + streamConnectionID.
		var cipherKey, cipherIV []byte
		if cfg.DirectKey {
			cipherKey = encKey
			cipherIV = encIV
			dbg("[SETUP] using DIRECT key mode (no SHA-512 derivation)")
		} else {
			cipherKey, cipherIV = deriveVideoKeys(encKey, videoStreamConnectionID)
			dbg("[SETUP] using SHA-512 derived keys (AES-CTR)")
		}
		dbg("[SETUP] streamConnectionID: %d", videoStreamConnectionID)
		dbg("[SETUP] shk (raw key):    %02x", encKey)
		dbg("[SETUP] shiv (raw IV):    %02x", encIV)
		dbg("[SETUP] cipher key:       %02x", cipherKey)
		dbg("[SETUP] cipher IV:        %02x", cipherIV)
		mc, err := newMirrorCipher(cipherKey, cipherIV)
		if err != nil {
			return nil, fmt.Errorf("stream cipher: %w", err)
		}
		session.streamCipher = mc.EncryptFrame
	} else {
		dbg("[SETUP] no video cipher — frames will be sent unencrypted")
	}

	// Set up audio stream if the receiver provided audio ports
	if audioDataPort > 0 {
		audioCT := byte(selectedAudioCodec) // ALAC=2 (matches SETUP descriptor)
		as, err := session.setupAudioStream(audioDataPort, audioControlPort, audioKey, audioIV, audioChaChaKey, audioMode, audioCT, audioLatencySamples, audioCtrlConn, audioDataConn)
		if err != nil {
			audioCtrlConn.Close()
			audioDataConn.Close()
			dbg("[SETUP] audio stream setup failed: %v (continuing without audio)", err)
		} else {
			session.audioStream = as
			dbg("[SETUP] audio stream ready")
		}
	} else {
		audioCtrlConn.Close()
		audioDataConn.Close()
		dbg("[SETUP] receiver did not provide audio ports, skipping audio")
	}

	// Monitor data connection for incoming data from Apple TV
	if dataConn != nil {
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := dataConn.Read(buf)
				if err != nil {
					dbg("[DATA-READ] data conn closed: %v", err)
					return
				}
				dbg("[DATA-READ] received %d bytes from Apple TV: %02x", n, buf[:min(n, 64)])
			}
		}()
	}

	// Keep video alive with the data-channel heartbeat and /feedback. Do not
	// additionally send GET_PARAMETER on this RTSP connection: some receivers
	// leave it unanswered, and every control request is serialized on the same
	// connection. A stuck GET_PARAMETER would therefore block /feedback long
	// enough for the receiver to stop rendering video while audio continues.
	session.startWorker(func() { session.dataHeartbeatLoop(sessionCtx) })
	session.startWorker(func() { session.feedbackLoop(sessionCtx) })

	setupSucceeded = true
	return session, nil
}

func addModernScreenAudioStreamFields(stream map[string]interface{}, key []byte, controlPort int) {
	// Modern connection dictionaries replace the legacy top-level controlPort.
	delete(stream, "controlPort")
	if len(key) > 0 {
		stream["shk"] = key
	} else {
		delete(stream, "shk")
	}
	// Screen audio is routed separately from the receiver's primary media
	// session. usingScreen identifies it as screen audio; isMedia=true instead
	// sends grouped Apple TVs through the main-media readiness path and can leave
	// their audio output waiting indefinitely.
	stream["isMedia"] = false
	stream["supportsDynamicStreamID"] = true
	stream["streamConnections"] = map[string]interface{}{
		"streamConnectionTypeRTP": map[string]interface{}{
			"streamConnectionKeyUseStreamEncryptionKey": len(key) > 0,
		},
		"streamConnectionTypeRTCP": map[string]interface{}{
			"streamConnectionKeyPort": int64(controlPort),
		},
	}
}

func addScreenAudioStreamFields(stream map[string]interface{}, key []byte, controlPort int, layout audioConnectionLayout) {
	if layout == audioLayoutStreamConnections {
		addModernScreenAudioStreamFields(stream, key, controlPort)
		dbg("[SETUP] audio stream descriptor includes shk (%d bytes) with streamConnections", len(key))
		return
	}

	stream["controlPort"] = int64(controlPort)
	if len(key) == chacha20poly1305.KeySize {
		stream["shk"] = key
		dbg("[SETUP] audio stream descriptor includes shk (%d bytes) with legacy controlPort", len(key))
	}
}

func addFairPlayRootFields(request map[string]interface{}, ekey, eiv []byte, includeEncryptionType bool) bool {
	if len(ekey) == 0 || len(eiv) == 0 {
		return false
	}
	request["ekey"] = ekey
	request["eiv"] = eiv
	if includeEncryptionType {
		request["et"] = int64(32)
	}
	dbg("[SETUP] FairPlay root fields: ekey=%d bytes, eiv=%d bytes", len(ekey), len(eiv))
	return true
}

// StreamFrames reads H.264 frames from the capture pipeline and sends them to the Apple TV.
// Protocol (from UxPlay/raop_rtp_mirror.c):
//   - SPS+PPS: sent as unencrypted codec frame (header[4]=0x01) in avcC format
//   - IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x00, AVCC payload
//   - non-IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x00, AVCC payload
func (s *MirrorSession) StreamFrames(ctx context.Context, capture *ScreenCapture, startDelay time.Duration) error {
	if normalizeVideoCodec(s.videoCodec) == VideoCodecHEVC {
		return s.streamHEVCFrames(ctx, capture, startDelay)
	}
	if startDelay > 0 {
		dbg("[STREAM] waiting %v before sending first frame...", startDelay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(startDelay):
			dbg("[STREAM] delay complete, starting frame send")
		}
	}

	buf := make([]byte, 256*1024)
	parser := newH264Parser()

	var latestSPS, latestPPS []byte // raw NAL data WITHOUT start code
	var sentSPS, sentPPS []byte     // most recently advertised decoder configuration
	var vclBuf []byte               // AVCC-formatted data accumulating for current access unit
	var vclPTS time.Time            // capture PTS for the access unit in vclBuf
	var pendingKeyframe bool        // true if vclBuf contains IDR slice(s)
	var codecSent bool              // true if codec frame sent for current keyframe
	var streamPrimed bool           // true after first SPS/PPS+IDR has been sent
	var frameCount int
	var lastProgressLog time.Time
	var nalLog strings.Builder

	resetVCL := func() {
		vclBuf = vclBuf[:0]
		vclPTS = time.Time{}
		pendingKeyframe = false
		codecSent = false
		nalLog.Reset()
	}

	// flushVCL sends the accumulated VCL data as a single encrypted frame.
	// This handles multi-slice frames by combining all slices of one access unit.
	flushVCL := func() error {
		if len(vclBuf) == 0 {
			return nil
		}

		// New sessions can attach mid-stream when using broadcast capture. Until we
		// have an IDR plus current SPS/PPS, drop VCL units to avoid sending
		// undecodable non-IDR frames that may cause receivers to close the stream.
		if !streamPrimed {
			if !pendingKeyframe || latestSPS == nil || latestPPS == nil {
				resetVCL()
				return nil
			}
		}

		packetTimestamp, packetTimeline, mapped := s.frameTimeAt(vclPTS)
		if !mapped {
			return fmt.Errorf("map capture PTS %v to receiver clock", vclPTS)
		}

		// Send SPS+PPS as an unencrypted avcC codec frame initially and whenever
		// the encoder changes them. Repeating an identical configuration before
		// every IDR is unnecessary and some receivers treat it as reconfiguration.
		if pendingKeyframe && !codecSent && latestSPS != nil && latestPPS != nil &&
			codecConfigNeedsSend(streamPrimed, latestSPS, latestPPS, sentSPS, sentPPS) {
			// Derive the encoded content dimensions from the SPS itself so the
			// codec header reports exactly what the encoder produced, regardless
			// of the captured surface size (which we no longer pin to a config
			// value — Wayland surfaces in particular are not pixel-perfect).
			if w, h, ok := spsDimensions(latestSPS); ok && (s.videoWidth != w || s.videoHeight != h) {
				dbg("[STREAM] encoded content size from SPS: %dx%d", w, h)
				s.videoWidth, s.videoHeight = w, h
			}
			avcC := buildAVCCConfig(latestSPS, latestPPS)
			if frameCount < 20 {
				dbg("[STREAM] sending codec frame avcC len=%d hdr=%02x", len(avcC), avcC[:min(8, len(avcC))])
			}
			if err := s.sendCodecFrame(avcC, packetTimestamp); err != nil {
				return fmt.Errorf("send codec: %w", err)
			}
			codecSent = true
			streamPrimed = true
			sentSPS = append(sentSPS[:0], latestSPS...)
			sentPPS = append(sentPPS[:0], latestPPS...)
		}

		frameData := vclBuf
		if s.streamCipher != nil {
			if frameCount < 5 {
				dbg("[CRYPTO] frame %d plain[0:20]=%02x", frameCount, vclBuf[:min(20, len(vclBuf))])
			}
			frameData = s.streamCipher(vclBuf)
			if frameCount < 5 {
				dbg("[CRYPTO] frame %d  enc[0:20]=%02x", frameCount, frameData[:min(20, len(frameData))])
			}
		}

		keyframeStr := "non-IDR"
		if pendingKeyframe {
			keyframeStr = "IDR"
		}
		if frameCount < 20 {
			dbg("[STREAM] %s frame %d: avcc_payload=%d encrypted=%v", keyframeStr, frameCount, len(vclBuf), s.streamCipher != nil)
			dbg("[STREAM] NAL sequence for frame %d: %s", frameCount, nalLog.String())
		}
		nalLog.Reset()

		sentPTS := vclPTS
		if err := s.sendFrame(frameData, pendingKeyframe, packetTimestamp, packetTimeline); err != nil {
			return fmt.Errorf("send %s: %w", keyframeStr, err)
		}
		// Codec configuration alone is not a displayed picture. Start audio and
		// data heartbeats only after the receiver has a successfully written VCL
		// frame to present against the shared media clock.
		if frameCount == 0 {
			select {
			case <-s.firstFrameSent:
			default:
				close(s.firstFrameSent)
			}
		}
		resetVCL()
		frameCount++
		if time.Since(lastProgressLog) >= 5*time.Second {
			if sentPTS.IsZero() {
				dbg("[STREAM] video progress: sent frame %d (%s, %d bytes), source PTS unavailable",
					frameCount, keyframeStr, len(frameData))
			} else {
				age := time.Since(sentPTS)
				dbg("[STREAM] video progress: sent frame %d (%s, %d bytes), source age=%v local presentation slack=%v",
					frameCount, keyframeStr, len(frameData), age, s.timestampBias-age)
			}
			lastProgressLog = time.Now()
		}
		return nil
	}

	processNAL := func(nal []byte, capturedAt time.Time) error {
		nt := nalType(nal)
		raw := stripStartCode(nal)

		if frameCount < 20 {
			fmt.Fprintf(&nalLog, "NAL type=%d len=%d ", nt, len(raw))
			if len(raw) > 0 {
				fmt.Fprintf(&nalLog, "hdr=%02x", raw[0])
			}
			nalLog.WriteByte('|')
		}

		setPTS := func() {
			if len(vclBuf) == 0 {
				vclPTS = capturedAt
			}
		}
		switch nt {
		case 9: // AUD — access unit delimiter, flush previous frame
			return flushVCL()
		case 7: // SPS — flush before keyframe
			if err := flushVCL(); err != nil {
				return err
			}
			latestSPS = raw
		case 8: // PPS
			latestPPS = raw
		case 6: // SEI — skip, don't include in VCL data
		case 5: // IDR VCL slice — accumulate (may be multi-slice)
			if len(vclBuf) > 0 && !pendingKeyframe {
				if err := flushVCL(); err != nil {
					return err
				}
			}
			if len(vclBuf) > 0 && pendingKeyframe && isFirstSlice(raw) {
				if err := flushVCL(); err != nil {
					return err
				}
			}
			setPTS()
			pendingKeyframe = true
			vclBuf = append(vclBuf, avccWrap(raw)...)
		case 1, 2, 3, 4: // non-IDR VCL slice — accumulate
			if len(vclBuf) > 0 && pendingKeyframe {
				if err := flushVCL(); err != nil {
					return err
				}
			}
			if len(vclBuf) > 0 && !pendingKeyframe && isFirstSlice(raw) {
				if err := flushVCL(); err != nil {
					return err
				}
			}
			setPTS()
			vclBuf = append(vclBuf, avccWrap(raw)...)
		default:
			if frameCount < 20 {
				dbg("[STREAM] ignoring NAL type=%d len=%d", nt, len(raw))
			}
		}
		return nil
	}

	if capture.frames != nil {
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			accessUnit, err := capture.ReadVideoAccessUnit()
			if len(accessUnit.AnnexB) > 0 {
				if frameCount == 0 {
					dbg("[CAPTURE] read timestamped access unit: %d bytes pts=%v", len(accessUnit.AnnexB), accessUnit.PTS)
				}
				for _, nal := range splitAnnexBAccessUnit(accessUnit.AnnexB) {
					if processErr := processNAL(nal, accessUnit.PTS); processErr != nil {
						return processErr
					}
				}
				// RTP's marker bit gives us the exact end of this access unit, so
				// there is no one-frame lookahead before its timestamp is sent.
				if flushErr := flushVCL(); flushErr != nil {
					return flushErr
				}
			}
			if err != nil {
				if err == io.EOF {
					if ctx.Err() != nil {
						return ctx.Err()
					}
					return fmt.Errorf("capture process exited unexpectedly (EOF)")
				}
				return fmt.Errorf("read timestamped capture: %w", err)
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := capture.Read(buf)
		if err != nil {
			if err == io.EOF {
				// Flush any remaining VCL data
				if flushErr := flushVCL(); flushErr != nil {
					return flushErr
				}
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("capture process exited unexpectedly (EOF)")
			}
			return fmt.Errorf("read capture: %w", err)
		}
		if n == 0 {
			continue
		}
		if frameCount == 0 {
			dbg("[CAPTURE] read %d bytes start=% x", n, buf[:min(n, 16)])
		}

		nals := parser.Push(buf[:n])
		for _, nal := range nals {
			if err := processNAL(nal, time.Time{}); err != nil {
				return err
			}
		}
	}
}

func codecConfigNeedsSend(streamPrimed bool, latestSPS, latestPPS, sentSPS, sentPPS []byte) bool {
	return !streamPrimed || !bytes.Equal(latestSPS, sentSPS) || !bytes.Equal(latestPPS, sentPPS)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// h264Parser incrementally extracts NAL units from either Annex-B or length-prefixed AVC streams.
type h264Parser struct {
	buf []byte
}

func newH264Parser() *h264Parser {
	return &h264Parser{buf: make([]byte, 0, 512*1024)}
}

func (p *h264Parser) Push(data []byte) [][]byte {
	p.buf = append(p.buf, data...)

	if hasStartCode(p.buf) {
		return p.pushAnnexB()
	}
	return p.pushAVCC()
}

func (p *h264Parser) pushAnnexB() [][]byte {
	var out [][]byte

	for {
		start := findStartCode(p.buf, 0)
		if start < 0 {
			if len(p.buf) > 1024*1024 {
				p.buf = p.buf[len(p.buf)-128*1024:]
			}
			break
		}

		next := findStartCode(p.buf, start+3)
		if next < 0 {
			if start > 0 {
				p.buf = append([]byte(nil), p.buf[start:]...)
			}
			break
		}

		nal := append([]byte(nil), p.buf[start:next]...)
		out = append(out, nal)
		p.buf = p.buf[next:]
	}

	return out
}

func (p *h264Parser) pushAVCC() [][]byte {
	var out [][]byte

	for {
		if len(p.buf) < 4 {
			break
		}

		nalLen := int(binary.BigEndian.Uint32(p.buf[:4]))
		if nalLen <= 0 || nalLen > 16*1024*1024 {
			dbg("[STREAM] invalid AVCC NAL length %d, dropping %d buffered bytes", nalLen, len(p.buf))
			p.buf = p.buf[:0]
			break
		}
		if len(p.buf) < 4+nalLen {
			break
		}

		nal := make([]byte, 4+nalLen)
		binary.BigEndian.PutUint32(nal[:4], uint32(1))
		copy(nal[4:], p.buf[4:4+nalLen])
		out = append(out, nal)
		p.buf = p.buf[4+nalLen:]
	}

	return out
}

func hasStartCode(b []byte) bool {
	return findStartCode(b, 0) >= 0
}

func findStartCode(b []byte, from int) int {
	if from < 0 {
		from = 0
	}
	for i := from; i+3 < len(b); i++ {
		if b[i] == 0x00 && b[i+1] == 0x00 {
			if b[i+2] == 0x01 {
				return i
			}
			if i+3 < len(b) && b[i+2] == 0x00 && b[i+3] == 0x01 {
				return i
			}
		}
	}
	return -1
}

// splitAnnexBAccessUnit splits a complete, marker-delimited access unit. Unlike
// h264Parser it can return the final NAL immediately because the RTP marker has
// already established the end of the frame.
func splitAnnexBAccessUnit(data []byte) [][]byte {
	start := findStartCode(data, 0)
	if start < 0 {
		return nil
	}
	var nals [][]byte
	for start >= 0 {
		next := findStartCode(data, start+3)
		if next < 0 {
			nals = append(nals, data[start:])
			break
		}
		nals = append(nals, data[start:next])
		start = next
	}
	return nals
}

// stripStartCode removes the Annex-B start code prefix (00 00 01 or 00 00 00 01).
func stripStartCode(nal []byte) []byte {
	if len(nal) > 4 && nal[0] == 0 && nal[1] == 0 && nal[2] == 0 && nal[3] == 1 {
		return nal[4:]
	}
	if len(nal) > 3 && nal[0] == 0 && nal[1] == 0 && nal[2] == 1 {
		return nal[3:]
	}
	return nal
}

// avccWrap prepends a 4-byte big-endian length to a raw NAL unit (AVCC format).
func avccWrap(raw []byte) []byte {
	b := make([]byte, 4+len(raw))
	binary.BigEndian.PutUint32(b[:4], uint32(len(raw)))
	copy(b[4:], raw)
	return b
}

// h264BitReader reads bits and Exp-Golomb codes from an H.264 RBSP byte slice.
type h264BitReader struct {
	data []byte
	pos  int  // bit position
	err  bool // set if a read ran past the end of data
}

func (r *h264BitReader) readBit() uint {
	if r.pos >= len(r.data)*8 {
		r.err = true
		return 0
	}
	b := r.data[r.pos>>3]
	bit := (b >> uint(7-(r.pos&7))) & 1
	r.pos++
	return uint(bit)
}

func (r *h264BitReader) readBits(n int) uint {
	var v uint
	for i := 0; i < n; i++ {
		v = (v << 1) | r.readBit()
	}
	return v
}

// readUE reads an unsigned Exp-Golomb coded value.
func (r *h264BitReader) readUE() uint {
	zeros := 0
	for r.readBit() == 0 {
		if r.err || zeros > 31 {
			r.err = true
			return 0
		}
		zeros++
	}
	if zeros == 0 {
		return 0
	}
	return (1 << uint(zeros)) - 1 + r.readBits(zeros)
}

// readSE reads a signed Exp-Golomb coded value.
func (r *h264BitReader) readSE() int {
	k := r.readUE()
	if k&1 != 0 {
		return int((k + 1) / 2)
	}
	return -int(k / 2)
}

// stripEmulationPrevention removes H.264 emulation prevention bytes
// (00 00 03 -> 00 00) from an RBSP byte slice.
func stripEmulationPrevention(b []byte) []byte {
	out := make([]byte, 0, len(b))
	zeros := 0
	for i := 0; i < len(b); i++ {
		if zeros >= 2 && b[i] == 0x03 && i+1 < len(b) && b[i+1] <= 0x03 {
			zeros = 0
			continue // drop the emulation prevention byte
		}
		if b[i] == 0 {
			zeros++
		} else {
			zeros = 0
		}
		out = append(out, b[i])
	}
	return out
}

// spsDimensions parses an H.264 SPS NAL (raw, including the 1-byte NAL header,
// without a start code) and returns the coded picture width and height in
// pixels. ok is false if the SPS could not be parsed. Crop offsets are
// interpreted assuming 4:2:0 chroma, which is the only format the capture
// encoders emit.
func spsDimensions(sps []byte) (width, height int, ok bool) {
	if len(sps) < 4 || sps[0]&0x1f != 7 {
		return 0, 0, false
	}
	r := &h264BitReader{data: stripEmulationPrevention(sps[1:])}

	profileIDC := r.readBits(8)
	r.readBits(8) // constraint_set flags + reserved
	r.readBits(8) // level_idc
	r.readUE()    // seq_parameter_set_id

	switch profileIDC {
	case 100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135:
		chromaFormatIDC := r.readUE()
		if chromaFormatIDC == 3 {
			r.readBit() // separate_colour_plane_flag
		}
		r.readUE()  // bit_depth_luma_minus8
		r.readUE()  // bit_depth_chroma_minus8
		r.readBit() // qpprime_y_zero_transform_bypass_flag
		if r.readBit() == 1 {
			n := 8
			if chromaFormatIDC == 3 {
				n = 12
			}
			for i := 0; i < n; i++ {
				if r.readBit() == 1 {
					size := 16
					if i >= 6 {
						size = 64
					}
					lastScale := 8
					nextScale := 8
					for j := 0; j < size; j++ {
						if nextScale != 0 {
							nextScale = (lastScale + r.readSE() + 256) % 256
						}
						if nextScale != 0 {
							lastScale = nextScale
						}
					}
				}
			}
		}
	}

	r.readUE() // log2_max_frame_num_minus4
	picOrderCntType := r.readUE()
	if picOrderCntType == 0 {
		r.readUE() // log2_max_pic_order_cnt_lsb_minus4
	} else if picOrderCntType == 1 {
		r.readBit() // delta_pic_order_always_zero_flag
		r.readSE()  // offset_for_non_ref_pic
		r.readSE()  // offset_for_top_to_bottom_field
		for n := r.readUE(); n > 0; n-- {
			r.readSE() // offset_for_ref_frame[i]
		}
	}
	r.readUE()  // max_num_ref_frames
	r.readBit() // gaps_in_frame_num_value_allowed_flag

	picWidthInMbsMinus1 := r.readUE()
	picHeightInMapUnitsMinus1 := r.readUE()
	frameMbsOnlyFlag := r.readBit()
	if frameMbsOnlyFlag == 0 {
		r.readBit() // mb_adaptive_frame_field_flag
	}
	r.readBit() // direct_8x8_inference_flag

	var cropLeft, cropRight, cropTop, cropBottom uint
	if r.readBit() == 1 { // frame_cropping_flag
		cropLeft = r.readUE()
		cropRight = r.readUE()
		cropTop = r.readUE()
		cropBottom = r.readUE()
	}
	if r.err {
		return 0, 0, false
	}

	w := int(picWidthInMbsMinus1+1) * 16
	h := int(2-frameMbsOnlyFlag) * int(picHeightInMapUnitsMinus1+1) * 16
	// 4:2:0: CropUnitX = SubWidthC = 2, CropUnitY = SubHeightC*(2-frameMbsOnlyFlag).
	cropUnitX := 2
	cropUnitY := 2 * int(2-frameMbsOnlyFlag)
	w -= int(cropLeft+cropRight) * cropUnitX
	h -= int(cropTop+cropBottom) * cropUnitY
	if w <= 0 || h <= 0 {
		return 0, 0, false
	}
	return w, h, true
}

// buildAVCCConfig builds an AVCDecoderConfigurationRecord (avcC) from raw SPS and PPS.
// Includes 4-byte trailer (02 00 00 00) observed in iPhone captures.
func buildAVCCConfig(sps, pps []byte) []byte {
	avcCLen := 6 + 2 + len(sps) + 1 + 2 + len(pps)
	payload := make([]byte, avcCLen+4) // +4 for trailer
	payload[0] = 0x01                  // configurationVersion = 1
	payload[1] = sps[1]                // AVCProfileIndication
	payload[2] = sps[2]                // profile_compatibility
	payload[3] = sps[3]                // AVCLevelIndication
	payload[4] = 0xff                  // lengthSizeMinusOne = 3 (4-byte NALU lengths)
	payload[5] = 0xe1                  // numSequenceParameterSets = 1
	binary.BigEndian.PutUint16(payload[6:8], uint16(len(sps)))
	copy(payload[8:], sps)
	off := 8 + len(sps)
	payload[off] = 0x01 // numPictureParameterSets = 1
	binary.BigEndian.PutUint16(payload[off+1:off+3], uint16(len(pps)))
	copy(payload[off+3:], pps)
	// 4-byte trailer observed in iPhone captures
	payload[avcCLen] = 0x02
	return payload
}

// nalType returns the H.264 NAL unit type from a NAL that may begin with a start code.
func nalType(nal []byte) byte {
	// Skip start code: 00 00 01 or 00 00 00 01
	for i := 0; i+1 < len(nal); i++ {
		if nal[i] == 0x01 && i >= 2 && nal[i-1] == 0x00 && nal[i-2] == 0x00 {
			if i+1 < len(nal) {
				return nal[i+1] & 0x1f
			}
		}
	}
	return 0
}

// isFirstSlice returns true if the raw NAL (without start code) represents the
// first slice of a new access unit. It reads first_mb_in_slice (the first
// Exp-Golomb coded value in the slice header, right after the NAL header byte).
// A value of 0 means this slice starts at macroblock 0 — i.e. a new frame.
// This is used to detect AU boundaries when AUD NALUs are absent.
func isFirstSlice(raw []byte) bool {
	if len(raw) < 2 {
		return false
	}
	// raw[0] is the NAL header byte; slice header starts at raw[1].
	// first_mb_in_slice is Exp-Golomb coded: leading zeros + 1 + value bits.
	// If the first bit is 1, the value is 0 (i.e. first macroblock).
	return raw[1]&0x80 != 0
}

// sendCodecFrame sends an unencrypted decoder-configuration packet (header
// type 0x01 0x00). H.264 carries avcC with option 0x16; HEVC carries a complete
// hvc1/hvcC sample description with option 0x1e.
func (s *MirrorSession) sendCodecFrame(payload []byte, ntpTimestamp uint64, codecs ...VideoCodec) error {
	s.frameSeq++
	var header [128]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(payload)))
	header[4] = 0x01 // payload type = SPS+PPS codec packet (unencrypted)
	header[5] = 0x00
	codec := normalizeVideoCodec(s.videoCodec)
	if len(codecs) > 0 {
		codec = normalizeVideoCodec(codecs[0])
	}
	header[6] = 0x16 // H.264 generic format description
	if codec == VideoCodecHEVC {
		header[6] = 0x1e // HEVC hvc1/hvcC generic format description
	}
	header[7] = 0x01
	binary.LittleEndian.PutUint64(header[8:16], ntpTimestamp)
	// APScreenProtocolHeader carries the encoded video size followed by source
	// and destination CGRects. Genuine senders populate the rects from sample
	// buffer metadata. Our capture has no separate placement metadata, so both
	// rects describe the complete encoded raster with zero origins. The receiver's
	// advertised display size is a decoder/capture constraint, not a substitute
	// destination rect.
	putFloat32LE(header[16:20], float32(s.videoWidth))
	putFloat32LE(header[20:24], float32(s.videoHeight))
	putFloat32LE(header[40:44], float32(s.videoWidth))
	putFloat32LE(header[44:48], float32(s.videoHeight))
	putFloat32LE(header[56:60], float32(s.videoWidth))
	putFloat32LE(header[60:64], float32(s.videoHeight))

	dbg("[SEND] codec frame: seq=%d payLen=%d hdr[4:6]=%02x%02x ts=%d",
		s.frameSeq, len(payload), header[4], header[5], ntpTimestamp)
	dbg("[SEND] codec full header: %02x", header)
	dbg("[SEND] codec payload: %02x", payload)

	bufs := net.Buffers{header[:], payload}
	s.dataMu.Lock()
	s.dataConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_, err := bufs.WriteTo(s.dataConn)
	s.dataMu.Unlock()
	return err
}

// sendFrame writes a single encrypted VCL frame with the mirroring protocol header.
// payload must be AVCC-encoded (4-byte BE length per NALU, no start codes).
// Header layout (128 bytes), matching APScreenProtocolHeader:
//
//	[0:4]   payload size (LE uint32)
//	[4]     payload type: 0x00 = encrypted video data
//	[5]     0x10 = IDR (keyframe), 0x00 = non-IDR
//	[6:8]   payload option: 0x00 0x00 for encrypted packets
//	[8:16]  NTP network time (LE seconds.32-bit-fraction)
//	[40:48] timeline ID (zero for NTP, receiver ClockID for PTP)
func (s *MirrorSession) sendFrame(auData []byte, isKeyframe bool, networkTimestamp, timelineID uint64) error {
	s.frameSeq++

	// For ChaCha20-Poly1305, the header size includes the 16-byte Poly1305 tag.
	payloadSize := len(auData)
	if s.chachaCipher != nil {
		payloadSize += s.chachaCipher.Overhead() // +16 for Poly1305 tag
	}

	var header [128]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(payloadSize))
	header[4] = 0x00 // payload type = encrypted video data
	if isKeyframe {
		header[5] = 0x10 // IDR frame indicator
	} else {
		header[5] = 0x00 // non-IDR
	}
	// header[6:8] = 0x00 0x00 for encrypted packets (already zeroed)
	binary.LittleEndian.PutUint64(header[8:16], networkTimestamp)
	binary.LittleEndian.PutUint64(header[40:48], timelineID)

	var framePayload []byte
	if s.chachaCipher != nil {
		// ChaCha20-Poly1305: encrypt with 128-byte header as AAD.
		// Receiver uses chacha20_poly1305_init_64x64 (64-bit counter + 64-bit nonce).
		// Go's IETF ChaCha20-Poly1305 uses 32-bit counter + 96-bit nonce.
		// To make IETF state match 64x64: nonce = [0,0,0,0] + LE64(N)
		// so state[13]=0, state[14]=N_lo, state[15]=N_hi (matching 64x64 layout).
		var nonce [12]byte
		binary.LittleEndian.PutUint64(nonce[4:], s.chachaNonce)
		framePayload = s.chachaCipher.Seal(nil, nonce[:], auData, header[:])
		if s.frameSeq <= 3 {
			dbg("[CHACHA] nonce=%d nonce_hex=%02x plaintext_len=%d ciphertext_len=%d",
				s.chachaNonce, nonce[:], len(auData), len(framePayload))
			dbg("[CHACHA] plaintext[0:min(32)]=%02x", auData[:min(32, len(auData))])
			dbg("[CHACHA] ciphertext[0:min(32)]=%02x", framePayload[:min(32, len(framePayload))])
			dbg("[CHACHA] tag=%02x", framePayload[len(framePayload)-16:])
		}
		s.chachaNonce++
	} else {
		framePayload = auData
	}

	keyframeStr := "non-IDR"
	if isKeyframe {
		keyframeStr = "IDR"
	}

	if s.frameSeq <= 3 {
		dbg("[SEND] %s full header: %02x", keyframeStr, header)
	}

	if s.frameSeq <= 3 || s.frameSeq%300 == 0 {
		dbg("[SEND] %s frame: seq=%d payLen=%d hdr[4:6]=%02x%02x ts=%d",
			keyframeStr, s.frameSeq, len(auData), header[4], header[5], networkTimestamp)
	}

	// Use vectored I/O (writev) to send header + payload in a single syscall,
	// avoiding a copy into a combined buffer.
	bufs := net.Buffers{header[:], framePayload}
	writeStarted := time.Now()
	s.dataMu.Lock()
	s.dataConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := bufs.WriteTo(s.dataConn)
	writeEnded := time.Now()
	reportSlowWrite := writeEnded.Sub(writeStarted) >= 25*time.Millisecond &&
		(s.lastSlowWriteLog.IsZero() || writeEnded.Sub(s.lastSlowWriteLog) >= 5*time.Second)
	if reportSlowWrite {
		s.lastSlowWriteLog = writeEnded
	}
	s.dataMu.Unlock()
	if err != nil {
		dbg("[SEND] write error on frame seq=%d: %v", s.frameSeq, err)
	} else if reportSlowWrite {
		dbg("[SEND] video frame seq=%d spent %v waiting for/local-writing to the TCP socket", s.frameSeq, writeEnded.Sub(writeStarted))
	}
	return err
}

// writeAll handles short writes from an io.Writer.
func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return fmt.Errorf("short write: wrote %d of %d bytes", n, len(data))
		}
		data = data[n:]
	}
	return nil
}

func putFloat32LE(dst []byte, value float32) {
	binary.LittleEndian.PutUint32(dst, math.Float32bits(value))
}

// deriveVideoKeys derives the AES-128-CTR key/IV for video encryption.
// Per UxPlay mirror_buffer.c: SHA-512("AirPlayStreamKey<id>" + shk)[:16] and SHA-512("AirPlayStreamIV<id>" + shk)[:16].
func deriveVideoKeys(shk []byte, streamConnectionID int64) (key, iv []byte) {
	h := sha512.New()
	h.Write([]byte(fmt.Sprintf("AirPlayStreamKey%d", uint64(streamConnectionID))))
	h.Write(shk)
	key = h.Sum(nil)[:16]

	h.Reset()
	h.Write([]byte(fmt.Sprintf("AirPlayStreamIV%d", uint64(streamConnectionID))))
	h.Write(shk)
	iv = h.Sum(nil)[:16]
	return
}

// generateAudioChaChaKey creates the direct 32-byte RTP audio key Apple publishes in shk.
// Modern buffered audio does not HKDF-derive this key from the HAP session; the sender
// generates a fresh random key, creates the audio cryptor from it, and publishes that same
// value via shk + streamConnectionKeyUseStreamEncryptionKey.
func generateAudioChaChaKey(randReader io.Reader) ([]byte, error) {
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(randReader, key); err != nil {
		return nil, fmt.Errorf("generate audio chacha key: %w", err)
	}
	return key, nil
}

// deriveChaChaKey derives a 32-byte ChaCha20-Poly1305 key using HKDF-SHA512.
// This matches Apple's _GetDataStreamSecurityKeys / PairingSessionDeriveKey for
// mirroring data streams such as encrypted video/control channels, not RTP audio:
//   - IKM: pair-verify X25519 ECDH shared secret (or raw FP aesKey as fallback)
//   - Salt: "DataStream-Salt" + decimal(streamConnectionID)
//   - Info: "DataStream-Output-Encryption-Key" (sender→receiver screen data direction)
//
// The receiver's _ScreenSetup derives only "DataStream-Output-Encryption-Key" for screen
// mirroring — "Output" refers to the sender's output direction.
func deriveChaChaKey(ikm []byte, streamConnectionID int64) ([]byte, error) {
	salt := []byte(fmt.Sprintf("DataStream-Salt%d", uint64(streamConnectionID)))
	info := []byte("DataStream-Output-Encryption-Key")

	hkdfReader := hkdf.New(sha512.New, ikm, salt, info)
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("hkdf expand: %w", err)
	}
	return key, nil
}

// dataHeartbeatLoop sends periodic heartbeat frames on the data channel.
// AirMyPC sends these every ~1s: 128-byte header with byte4=0x02, bytes6-7=0x1e00, no payload.
// Waits until the first video frame has been sent before starting.
func (s *MirrorSession) dataHeartbeatLoop(ctx context.Context) {
	// Wait for first video frame before sending heartbeats
	select {
	case <-ctx.Done():
		return
	case <-s.firstFrameSent:
	}

	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			header := make([]byte, 128)
			header[4] = 0x02
			header[6] = 0x1e
			s.dataMu.Lock()
			s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writeAll(s.dataConn, header)
			s.dataMu.Unlock()
			if err != nil {
				dbg("[HEARTBEAT] data channel heartbeat failed: %v", err)
				return
			}
		}
	}
}

// feedbackLoop sends periodic POST /feedback requests like AirMyPC (every 2s).
// Sends an immediate first feedback to prevent UxPlay's 3-second timeout from
// killing the connection before the first ticker fires.
func (s *MirrorSession) feedbackLoop(ctx context.Context) {
	// Start immediately after SETUP. Wayland's permission UI can delay the first
	// captured frame for several seconds, but the receiver's feedback timeout is
	// already running by then.
	sendFeedback := func() {
		body, headers, err := s.client.rtspRequest("POST", "/feedback", "", nil, nil)
		receivedAt := time.Now()
		if err != nil {
			dbg("[FEEDBACK] error: %v", err)
			return
		}
		if s.mediaClock != nil {
			if err := s.mediaClock.reanchor(headers, receivedAt); err != nil {
				dbg("[PTP] feedback clock update ignored: %v", err)
			}
		}
		if len(body) == 0 {
			return
		}
		var fbResp map[string]interface{}
		if _, err := plist.Unmarshal(body, &fbResp); err == nil {
			dbg("[FEEDBACK] response: %+v", fbResp)
		} else {
			dbg("[FEEDBACK] response (%d bytes): %02x", len(body), body)
		}
	}

	// Send immediate first feedback — iPhone does this within ~1s of streaming.
	sendFeedback()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Use bare /feedback path — UxPlay matches against exact path "/feedback",
			// not the full RTSP URI with session UUID prefix.
			sendFeedback()
		}
	}
}

func (s *MirrorSession) startWorker(worker func()) {
	s.workers.Add(1)
	go func() {
		defer s.workers.Done()
		worker()
	}()
}

func (s *MirrorSession) Close() error {
	s.closeOnce.Do(func() {
		if s.cancel != nil {
			s.cancel()
		}
		s.workers.Wait()

		// Send TEARDOWN to cleanly end the RTSP session on the receiver.
		if s.sessionURI != "" && s.client != nil {
			_, _, err := s.client.rtspRequest("TEARDOWN", s.sessionURI, "", nil, nil)
			if err != nil {
				dbg("[TEARDOWN] error: %v", err)
			} else {
				dbg("[TEARDOWN] sent for %s", s.sessionURI)
			}
		}
		if s.audioStream != nil {
			s.audioStream.Close()
		}
		if s.eventConn != nil {
			_ = s.eventConn.Close()
		}
		if s.timingConn != nil {
			_ = s.timingConn.Close()
		}
		if s.dataConn != nil {
			s.closeErr = s.dataConn.Close()
		}
	})
	return s.closeErr
}

// plistInt extracts an integer from a plist value (uint64, int64, or float64).
func plistInt(v interface{}) int {
	switch n := v.(type) {
	case uint64:
		return int(n)
	case uint32:
		return int(n)
	case int64:
		return int(n)
	case int32:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

func plistUint64(v interface{}) uint64 {
	switch n := v.(type) {
	case uint64:
		return n
	case uint32:
		return uint64(n)
	case int64:
		return uint64(n)
	case int32:
		return uint64(n)
	case int:
		return uint64(n)
	}
	return 0
}

func localIPForConnection(conn net.Conn) (string, error) {
	if conn == nil {
		return "", fmt.Errorf("connection is not open")
	}
	address, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || address.IP == nil || address.IP.IsUnspecified() {
		return "", fmt.Errorf("connection has unusable local address %v", conn.LocalAddr())
	}
	return address.IP.String(), nil
}

// plistStreamPorts extracts RTP/RTCP ports from either legacy stream fields or
// modern streamConnections dictionaries.
func plistStreamPorts(stream map[string]interface{}) (dataPort, controlPort int) {
	dataPort = plistInt(stream["dataPort"])
	controlPort = plistInt(stream["controlPort"])

	streamConnections, ok := stream["streamConnections"].(map[string]interface{})
	if !ok {
		return dataPort, controlPort
	}
	if rtp, ok := streamConnections["streamConnectionTypeRTP"].(map[string]interface{}); ok {
		if port := plistInt(rtp["streamConnectionKeyPort"]); port > 0 {
			dataPort = port
		}
	}
	if rtcp, ok := streamConnections["streamConnectionTypeRTCP"].(map[string]interface{}); ok {
		if port := plistInt(rtcp["streamConnectionKeyPort"]); port > 0 {
			controlPort = port
		}
	}
	return dataPort, controlPort
}

// HasAudio returns true if the session has an active audio stream.
func (s *MirrorSession) HasAudio() bool {
	return s.audioStream != nil
}

// SetAudioMuted updates mirrored audio volume on the receiver.
// AirPlay uses SET_PARAMETER volume where 0 dB is max and -144 dB is muted.
func (s *MirrorSession) SetAudioMuted(muted bool) error {
	if s == nil || s.client == nil || s.sessionURI == "" {
		return fmt.Errorf("audio control unavailable")
	}

	if _, _, err := s.client.rtspRequest("SET_PARAMETER", s.sessionURI, "text/parameters", audioVolumeBody(muted), nil); err != nil {
		return fmt.Errorf("set audio muted=%t: %w", muted, err)
	}
	return nil
}

func audioVolumeBody(muted bool) []byte {
	if muted {
		return []byte("volume: -144.000000\r\n")
	}
	return []byte("volume: 0.000000\r\n")
}

// AudioStream returns the audio stream for this session (may be nil).
func (s *MirrorSession) AudioStream() *AudioStream {
	return s.audioStream
}

// ntpTimingResponder replies to NTP timing requests from the Apple TV.
func ntpTimingResponder(ctx context.Context, conn net.PacketConn) {
	buf := make([]byte, 128)
	for {
		select {
		case <-ctx.Done():
			conn.Close()
			return
		default:
		}
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			dbg("[NTP] read error: %v", err)
			return
		}
		dbg("[NTP] received %d bytes from %s: %02x", n, addr, buf[:min(n, 32)])

		// 0xd2 is the timing request and 0xd3 its response. A receiver may
		// answer a sender-initiated probe on this same socket; never answer that
		// response or the peers form a response loop.
		if !isNTPTimingRequest(buf[:n]) {
			continue
		}

		// Log the Apple TV's send timestamp for timing analysis
		senderTS := binary.BigEndian.Uint64(buf[24:32])
		dbg("[NTP] Apple TV transmit timestamp: 0x%016x (sec=%d)", senderTS, senderTS>>32)

		// Build response: echo back with our timestamps.
		// Use boot-relative time + NTP epoch, matching what real Apple senders do.
		// UxPlay subtracts the NTP epoch from timing responses (account_for_epoch=true)
		// but NOT from video frame timestamps (account_for_epoch=false). Video frames
		// use raw boot-relative time via ntpTimeNow(). By adding the NTP epoch here,
		// both resolve to the same boot-relative time base after UxPlay's conversion.
		reply := make([]byte, 32)
		copy(reply, buf[:32])
		reply[0] = 0x80
		reply[1] = 0xd3

		now := ntpBootTimestamp()
		// Bytes 8-15: Reference = sender's transmit timestamp
		copy(reply[8:16], buf[24:32])
		// Bytes 16-23: Receive timestamp = now (NTP format, BE)
		binary.BigEndian.PutUint64(reply[16:24], now)
		// Bytes 24-31: Transmit timestamp = now (NTP format, BE)
		binary.BigEndian.PutUint64(reply[24:32], now)

		if _, err := conn.WriteTo(reply, addr); err != nil {
			dbg("[NTP] write error: %v", err)
		} else {
			dbg("[NTP] sent timing reply to %s", addr)
		}
	}
}

func isNTPTimingRequest(packet []byte) bool {
	return len(packet) >= 32 && packet[0] == 0x80 && packet[1] == 0xd2
}

// sendNTPTimingProbes initiates timing with receivers that return their own
// timingPort instead of probing the sender's advertised port. The responder on
// conn consumes and ignores the corresponding 0xd3 packets.
func sendNTPTimingProbes(ctx context.Context, conn net.PacketConn, host string, port int) {
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		dbg("[NTP] resolve receiver timing port: %v", err)
		return
	}
	for sequence := uint16(1); sequence <= 3; sequence++ {
		request := make([]byte, 32)
		request[0], request[1] = 0x80, 0xd2
		binary.BigEndian.PutUint16(request[2:4], sequence)
		binary.BigEndian.PutUint64(request[24:32], ntpBootTimestamp())
		if _, err := conn.WriteTo(request, addr); err != nil {
			dbg("[NTP] send timing probe to %s: %v", addr, err)
			return
		}
		if sequence == 3 {
			return
		}

		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-timer.C:
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return
		}
	}
}

// uuidToMAC converts a UUID-ish string to a stable locally-administered MAC address.
// Falls back to a fixed MAC if the UUID does not contain enough hex digits.
func uuidToMAC(id string) string {
	hex := strings.ReplaceAll(strings.ToLower(id), "-", "")
	if len(hex) < 12 {
		return "02:00:00:00:00:01"
	}
	b := []byte(hex[:12])
	parts := []string{
		string(b[0:2]),
		string(b[2:4]),
		string(b[4:6]),
		string(b[6:8]),
		string(b[8:10]),
		string(b[10:12]),
	}
	parts[0] = "02"
	return strings.ToUpper(strings.Join(parts, ":"))
}

// appStartTime is the fallback reference when a system boot clock is unavailable.
var appStartTime = time.Now()

// ntpTimeNow returns a 64-bit NTP fixed-point timestamp for mirroring frame headers.
// Format: upper 32 bits = seconds, lower 32 bits = fractional seconds (1/2^32).
// Uses boot-relative time (no epoch offset), matching real Apple senders.
//
// A forward bias is added so that frame timestamps are intentionally ahead of
// wall-clock boot time. This avoids first-frame base_time edge cases and also
// acts as the sender-side playout latency target.
func videoTimestampBias() time.Duration {
	bias := TargetLatency()
	if bias < 5*time.Millisecond {
		return 5 * time.Millisecond
	}
	return bias
}

func ntpTimeNow() uint64 {
	return ntpTimeWithBias(videoTimestampBias())
}

// frameTimeNow returns one atomic timestamp/timeline pair for a VCL header.
func (s *MirrorSession) frameTimeNow() (timestamp, timelineID uint64) {
	timestamp, timelineID, _ = s.frameTimeAt(time.Time{})
	return timestamp, timelineID
}

// frameTimeAt converts an encoded access unit's original local capture PTS to
// the receiver's media timeline, then adds this session's negotiated playout
// lead. Apple's sbpd sender path reads CMSampleBuffer's output presentation
// timestamp and adds its screen lead before network-clock conversion; an
// expired PTS therefore cannot be repaired by assigning old content a new
// output-time timestamp. Plausible late frames keep their original timestamp:
// dropping an encoded reference picture would invalidate the rest of its GOP,
// while Apple's receiver records lateness and still enqueues the frame. A false
// result is reserved for an invalid or unmappable timestamp and terminates the
// stream rather than silently poisoning the decoder reference chain.
// Only a zero PTS, used by the legacy unframed capture path, intentionally
// retains the historical output-time fallback. A malformed nonzero PTS is not
// safe to relabel and is rejected.
func (s *MirrorSession) frameTimeAt(capturedAt time.Time) (timestamp, timelineID uint64, mapped bool) {
	now := time.Now()
	if s.frameClockNow != nil {
		now = s.frameClockNow()
	}
	return s.frameTimeAtNow(capturedAt, now)
}

func (s *MirrorSession) frameTimeAtNow(capturedAt, now time.Time) (timestamp, timelineID uint64, mapped bool) {
	bias := s.timestampBias
	if bias <= 0 {
		bias = videoTimestampBias()
	}
	if !capturedAt.IsZero() {
		age := now.Sub(capturedAt)
		if age >= -time.Second && age <= 30*time.Second {
			// Leave a small delivery margin for diagnostics. A late encoded frame must
			// still be sent at its original deadline so H.264 reference continuity is
			// preserved; the receiver decides whether its presentation is too late.
			if age > bias-5*time.Millisecond {
				if !s.latePTSReported {
					dbg("[STREAM] capture PTS is %v old with %v playout lead; forwarding late frame with original timestamp", age, bias)
				}
				s.latePTSReported = true
			}
			if s.mediaClock != nil {
				if timestamp, timelineID, ok := s.mediaClock.at(capturedAt, bias); ok {
					return s.monotonicFrameTime(timestamp), timelineID, true
				}
			} else if presentation, ok := addDurationToBootTime(capturedAt.Sub(now) + bias); ok {
				return s.monotonicFrameTime(compactTimestamp(presentation)), 0, true
			}
			if !s.latePTSReported {
				dbg("[STREAM] could not map nonzero capture PTS")
			}
			s.latePTSReported = true
			return 0, 0, false
		} else {
			if !s.latePTSReported {
				dbg("[STREAM] capture PTS has implausible age %v", age)
			}
			s.latePTSReported = true
			return 0, 0, false
		}
	}
	if s.mediaClock != nil {
		if timestamp, timelineID, ok := s.mediaClock.at(now, bias); ok {
			return s.monotonicFrameTime(timestamp), timelineID, true
		}
	}
	return s.monotonicFrameTime(ntpTimeWithBias(bias)), 0, true
}

func addDurationToBootTime(delta time.Duration) (time.Duration, bool) {
	presentation := bootRelativeNow() + delta
	if presentation < 0 {
		return 0, false
	}
	return presentation, true
}

func (s *MirrorSession) monotonicFrameTime(timestamp uint64) uint64 {
	if timestamp <= s.lastFrameTimestamp {
		timestamp = s.lastFrameTimestamp + 1
	}
	s.lastFrameTimestamp = timestamp
	return timestamp
}

// audioClockNow returns the current clock time without video's playout lead.
// The receiver applies the negotiated audio latency separately.
func (s *MirrorSession) audioClockNow() (timestamp, timelineID uint64) {
	if s.mediaClock != nil {
		if timestamp, timelineID, ok := s.mediaClock.now(0); ok {
			return timestamp, timelineID
		}
	}
	return ntpBootTimestamp(), 0
}

func ntpTimeWithBias(bias time.Duration) uint64 {
	if bias < 5*time.Millisecond {
		bias = 5 * time.Millisecond
	}
	return compactTimestamp(bootRelativeNow() + bias)
}

func compactTimestamp(d time.Duration) uint64 {
	if d < 0 {
		d = 0
	}
	sec := uint64(d / time.Second)
	nsecFrac := uint64(d % time.Second)
	frac := (nsecFrac << 32) / uint64(time.Second)
	return (sec << 32) | frac
}

// allocateConsecutiveUDPPorts allocates `count` consecutive UDP port numbers.
// Real Apple AirPlay senders use consecutive ports: timing(N), control(N+1), data(N+2).
func allocateConsecutiveUDPPorts(count int) ([]net.PacketConn, error) {
	return allocateConsecutiveUDPPortsInRange(count, 0, 0)
}

// allocateConsecutiveUDPPortsInRange allocates `count` consecutive UDP ports.
// When portMin/portMax are zero, the OS picks ephemeral ports. Otherwise the
// search is limited to [portMin, portMax] inclusive.
func allocateConsecutiveUDPPortsInRange(count, portMin, portMax int) ([]net.PacketConn, error) {
	if portMin == 0 && portMax == 0 {
		for attempt := 0; attempt < 20; attempt++ {
			conns, ok := tryConsecutiveUDP(0, count)
			if ok {
				return conns, nil
			}
			for _, c := range conns {
				c.Close()
			}
		}
		return nil, fmt.Errorf("could not allocate %d consecutive UDP ports after 20 attempts", count)
	}
	if portMin <= 0 || portMax <= 0 || portMin > portMax {
		return nil, fmt.Errorf("invalid UDP port range %d-%d", portMin, portMax)
	}
	if portMax-portMin+1 < count {
		return nil, fmt.Errorf("UDP port range %d-%d too small for %d consecutive ports", portMin, portMax, count)
	}
	for base := portMin; base <= portMax-count+1; base++ {
		conns, ok := tryConsecutiveUDP(base, count)
		if ok {
			return conns, nil
		}
		for _, c := range conns {
			c.Close()
		}
	}
	return nil, fmt.Errorf("no %d consecutive free UDP ports in range %d-%d", count, portMin, portMax)
}

// tryConsecutiveUDP attempts to bind `count` consecutive UDP ports starting at
// `base`. When base==0 the first port is OS-assigned and subsequent ports are
// base+1, base+2, ... Returns the conns and whether all binds succeeded;
// caller is responsible for closing partial results on failure.
func tryConsecutiveUDP(base, count int) ([]net.PacketConn, bool) {
	first, err := net.ListenPacket("udp", fmt.Sprintf(":%d", base))
	if err != nil {
		return nil, false
	}
	actualBase := first.LocalAddr().(*net.UDPAddr).Port
	conns := []net.PacketConn{first}
	for i := 1; i < count; i++ {
		c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", actualBase+i))
		if err != nil {
			return conns, false
		}
		conns = append(conns, c)
	}
	return conns, true
}

// ntpBootTimestamp returns a 64-bit NTP fixed-point timestamp using boot-relative
// time with the NTP epoch (1900-01-01) added. UxPlay subtracts the NTP epoch from
// timing responses (account_for_epoch=true), yielding the same boot-relative seconds
// that video frame headers carry via ntpTimeNow(). Apple TV adapts to any time base.
const secondsFrom1900To1970 = 2208988800

func ntpBootTimestamp() uint64 {
	d := bootRelativeNow()
	sec := uint64(d/time.Second) + secondsFrom1900To1970
	nsecFrac := uint64(d % time.Second)
	frac := (nsecFrac << 32) / uint64(time.Second)
	return (sec << 32) | frac
}

func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// debugDumpPlist logs a plist map in a stable key order, summarising byte
// slices by length and hex prefix. Lets the whole SETUP descriptor be diffed
// between receiver configurations that accept it and ones that reject it.
func debugDumpPlist(label string, m map[string]interface{}) {
	if !DebugMode() {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	dbg("[SETUP] %s (%d keys):", label, len(keys))
	for _, k := range keys {
		switch v := m[k].(type) {
		case []byte:
			dbg("[SETUP]   %s = <%d bytes> %s", k, len(v), hex.EncodeToString(v[:min(len(v), 16)]))
		case map[string]interface{}:
			inner := make([]string, 0, len(v))
			for ik := range v {
				inner = append(inner, ik)
			}
			sort.Strings(inner)
			dbg("[SETUP]   %s = map%v", k, inner)
		case []interface{}:
			dbg("[SETUP]   %s = list of %d", k, len(v))
		default:
			dbg("[SETUP]   %s = %v", k, v)
		}
	}
}
