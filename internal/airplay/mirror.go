package airplay

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"howett.net/plist"
)

// MirrorSession manages an active screen mirroring session.
type MirrorSession struct {
	client        *AirPlayClient
	dataConn      net.Conn
	dataMu        sync.Mutex // protects writes to dataConn
	eventConn     net.Conn
	timingConn    net.PacketConn
	eventListener net.Listener
	DataPort      int
	videoWidth    int
	videoHeight   int
	sessionURI    string // RTSP session URI for TEARDOWN

	streamCipher   func([]byte) []byte // AES-CTR encryption
	chachaCipher   cipher.AEAD         // ChaCha20-Poly1305 AEAD (nil = use AES-CTR)
	chachaNonce    uint64              // per-frame nonce counter
	frameSeq       uint32
	firstFrameSent chan struct{} // closed after first video frame is sent

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

// setupMirrorSession negotiates the mirroring stream with the Apple TV.
func (c *AirPlayClient) setupMirrorSession(ctx context.Context, cfg StreamConfig) (*MirrorSession, error) {
	sessionUUID := generateUUID()
	clientDeviceID := uuidToMAC(c.sessionID)

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

	// Allocate 3 consecutive UDP ports for audio: timing(N), control(N+1), data(N+2).
	// Real Apple senders (AirMyPC, etc.) use consecutive ports; the Apple TV
	// classifies incoming audio by source port and expects this pattern.
	audioPorts, err := allocateConsecutiveUDPPorts(3)
	if err != nil {
		return nil, fmt.Errorf("allocate audio ports: %w", err)
	}
	timingConn := audioPorts[0]
	audioCtrlConn := audioPorts[1]
	audioDataConn := audioPorts[2]
	timingPort := timingConn.LocalAddr().(*net.UDPAddr).Port
	dbg("[SETUP] consecutive UDP ports: timing=%d ctrl=%d data=%d", timingPort, timingPort+1, timingPort+2)

	// Start NTP timing responder BEFORE sending SETUP so it's ready
	// when the Apple TV probes us
	go ntpTimingResponder(ctx, timingConn)

	// Start a TCP listener for the event (reverse) channel
	eventListener, err := net.Listen("tcp", ":0")
	if err != nil {
		timingConn.Close()
		return nil, fmt.Errorf("listen event port: %w", err)
	}
	eventPort := eventListener.Addr().(*net.TCPAddr).Port
	dbg("[SETUP] event listener on TCP port %d", eventPort)

	// Accept event connection asynchronously
	go func() {
		conn, err := eventListener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				dbg("[EVENT] accept error: %v", err)
			}
			return
		}
		dbg("[EVENT] Apple TV connected for reverse events from %s", conn.RemoteAddr())
		// Keep connection open; log received data
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					dbg("[EVENT] event channel closed: %v", err)
					return
				}
				dbg("[EVENT] received %d bytes: %02x", n, buf[:min(n, 64)])
			}
		}()
	}()

	// ---- Working SETUP sequence ----
	// The receiver expects the audio session to be created first, then the video
	// stream to be attached to that session, and only then does it accept RECORD.
	// The practical ordering for current Apple receivers is:
	//   1. SETUP audio (type=96) with full session context + timingPort
	//   2. SETUP video (type=110) with a different streamConnectionID
	//   3. RECORD on the audio URI
	//   4. SET_PARAMETER volume (twice)

	audioStreamConnectionID := int64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFF)
	selectedAudioCodec := AudioCodecALAC
	// Real Apple senders use streamConnectionID as the RTSP URI path.
	// Audio SETUP, RECORD, and SET_PARAMETER all use the audio URI.
	// Video SETUP uses a separate URI with its own streamConnectionID.
	audioURI := fmt.Sprintf("rtsp://%s:%d/%d", c.host, c.port, audioStreamConnectionID)
	controlURI := audioURI
	audioMode := selectAudioSecurityMode(c.encrypted)
	var audioKey, audioIV, audioChaChaKey []byte
	if audioMode == audioSecurityChaCha {
		var err error
		audioChaChaKey, err = generateAudioChaChaKey(rand.Reader)
		if err != nil {
			dbg("[SETUP] audio encryption: chacha key generation failed: %v; falling back to AES-CBC", err)
			audioMode = audioSecurityLegacyAES
		} else {
			dbg("[SETUP] audio encryption: ChaCha20-Poly1305 direct stream key (streamConnectionID=%d, shk=%d bytes)", audioStreamConnectionID, len(audioChaChaKey))
		}
	}
	if audioMode == audioSecurityLegacyAES && c.fpKey != nil && c.fpIV != nil {
		audioKey = c.fpKey
		audioIV = c.fpIV
		dbg("[SETUP] audio encryption: AES-128-CBC (fpKey/hashed %d bytes)", len(audioKey))
	} else if audioMode == audioSecurityLegacyAES {
		dbg("[SETUP] audio encryption: disabled (no FairPlay key available)")
	}

	// ---- Phase 1: SETUP audio stream (creates session) ----
	audioDataPort := 0
	audioControlPort := 0
	var receiverEventPort int
	var receiverEventConn net.Conn

	audioControlLPort := audioCtrlConn.LocalAddr().(*net.UDPAddr).Port

	audioCT, audioSPF, audioFmt, latMin, latMax, _ := selectedAudioCodec.Info()
	audioFormatIndex := selectedAudioCodec.AudioFormatIndex()
	audioRedundant := int64(0)
	if useAudioFEC(audioMode == audioSecurityChaCha) {
		audioRedundant = 2
	}
	disableRetransmits := audioRedundant == 0

	audioStreamDesc := map[string]interface{}{
		"type":               int64(96),
		"streamConnectionID": audioStreamConnectionID,
		"ct":                 audioCT,
		"spf":                audioSPF,
		"sr":                 int64(44100),
		"audioFormat":        audioFmt,
		"audioFormatIndex":   audioFormatIndex,
		"controlPort":        int64(audioControlLPort),
		"audioMode":          "default",
		"usingScreen":        true,
		"latencyMin":         latMin,
		"latencyMax":         latMax,
		"redundantAudio":     audioRedundant,
	}
	if disableRetransmits {
		audioStreamDesc["disableRetransmits"] = true
	}

	audioSetupPlist := map[string]interface{}{
		"deviceID":       clientDeviceID,
		"macAddress":     clientDeviceID,
		"sessionUUID":    sessionUUID,
		"sourceVersion":  "280.33",
		"timingProtocol": "NTP",
		"timingPort":     int64(timingPort),
		"osBuildVersion": "13F69",
		"model":          "Linux",
		"name":           "Linux",
		"streams":        []interface{}{audioStreamDesc},
	}

	// Modern HAP receivers look for shk on the audio stream descriptor.
	// supportsDynamicStreamID must be false; true triggers a negotiation path
	// that Apple TV firmware does not complete, causing a 400 Bad Request.
	// streamConnections is omitted — Apple TV does not expect it from senders
	// and including it (as a dict) causes the SETUP to be rejected.
	if audioMode == audioSecurityChaCha && len(audioChaChaKey) == 32 {
		audioStreamDesc["shk"] = audioChaChaKey
		audioStreamDesc["isMedia"] = true
		audioStreamDesc["supportsDynamicStreamID"] = false
		dbg("[SETUP] audio stream descriptor includes shk (%d bytes)", len(audioChaChaKey))
	}
	if c.FpEkey != nil && c.fpIV != nil {
		audioSetupPlist["et"] = int64(32)
		audioSetupPlist["ekey"] = c.FpEkey
		audioSetupPlist["eiv"] = c.fpIV
		dbg("[SETUP] FairPlay ekey=%d bytes, eiv=%d bytes, et=32", len(c.FpEkey), len(c.fpIV))
	} else if audioMode != audioSecurityChaCha || len(audioChaChaKey) != 32 {
		dbg("[SETUP] WARNING: no FairPlay ekey/eiv — audio will likely not work")
	}

	dbg("[SETUP] phase 1 (audio+session): ct=%d spf=%d audioFormat=0x%x controlPort=%d", audioCT, audioSPF, audioFmt, audioControlLPort)

	audioSetupBody, err2 := plist.Marshal(audioSetupPlist, plist.BinaryFormat)
	if err2 != nil {
		audioCtrlConn.Close()
		audioDataConn.Close()
		return nil, fmt.Errorf("marshal audio setup: %w", err2)
	}

	audioRespBody, _, err2 := c.rtspRequest("SETUP", audioURI, "application/x-apple-binary-plist", audioSetupBody, nil)
	if err2 != nil {
		audioCtrlConn.Close()
		audioDataConn.Close()
		return nil, fmt.Errorf("SETUP phase 1 (audio): %w", err2)
	}

	var audioResp map[string]interface{}
	if _, err2 := plist.Unmarshal(audioRespBody, &audioResp); err2 != nil {
		audioCtrlConn.Close()
		audioDataConn.Close()
		return nil, fmt.Errorf("unmarshal audio setup response: %w", err2)
	}
	dbg("[SETUP] phase 1 response: %+v", audioResp)

	// Log timing port from receiver if present
	if tp, ok := audioResp["timingPort"]; ok {
		dbg("[SETUP] Apple TV timingPort: %v", tp)
	}
	// Check for any audio-specific parameters
	for k, v := range audioResp {
		if k != "streams" && k != "eventPort" {
			dbg("[SETUP] response field: %s=%v", k, v)
		}
	}

	// Extract event port from audio SETUP response
	if ep, ok := audioResp["eventPort"]; ok {
		switch v := ep.(type) {
		case uint64:
			receiverEventPort = int(v)
		case int64:
			receiverEventPort = int(v)
		case float64:
			receiverEventPort = int(v)
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
				dbg("[SETUP] audio stream: dataPort=%d controlPort=%d", audioDataPort, audioControlPort)
			}
		}
	}

	audioLatencySamples := uint32(0)

	// ---- Phase 2: SETUP video stream ----
	// Video SETUP uses the same sessionUUID but a different streamConnectionID.
	// The Apple TV attaches this video stream to the existing session.
	videoStreamConnectionID := int64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFF)
	videoURI := fmt.Sprintf("rtsp://%s:%d/%d", c.host, c.port, videoStreamConnectionID)

	videoStreamDesc := map[string]interface{}{
		"type":               int64(110),
		"streamConnectionID": videoStreamConnectionID,
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

	videoSetupPlist := map[string]interface{}{
		"deviceID":                 clientDeviceID,
		"macAddress":               clientDeviceID,
		"sessionUUID":              sessionUUID,
		"sourceVersion":            "280.33",
		"isScreenMirroringSession": true,
		"timingProtocol":           "NTP",
		"timingPort":               int64(timingPort),
		"osBuildVersion":           "13F69",
		"model":                    "Linux",
		"name":                     "Linux",
		"streams":                  []interface{}{videoStreamDesc},
	}
	// UxPlay reads ekey/eiv from the root level of the SETUP request to derive
	// the video decryption key. Without these, video decryption won't work on UxPlay.
	if c.FpEkey != nil && encKey != nil {
		videoSetupPlist["ekey"] = c.FpEkey
		videoSetupPlist["eiv"] = encIV
		dbg("[SETUP] video SETUP includes FairPlay ekey=%d bytes, eiv=%d bytes", len(c.FpEkey), len(encIV))
	}
	dbg("[SETUP] phase 2 (video): streamConnectionID=%d", videoStreamConnectionID)

	var dataConn net.Conn
	var dataPort int
	videoSetupBody, err := plist.Marshal(videoSetupPlist, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("marshal video setup: %w", err)
	}

	videoRespBody, _, err := c.rtspRequest("SETUP", videoURI, "application/x-apple-binary-plist", videoSetupBody, nil)
	if err != nil {
		return nil, fmt.Errorf("SETUP phase 2 (video): %w", err)
	}

	var videoResp map[string]interface{}
	if _, err := plist.Unmarshal(videoRespBody, &videoResp); err != nil {
		return nil, fmt.Errorf("unmarshal video setup response: %w", err)
	}
	dbg("[SETUP] phase 2 response: %+v", videoResp)
	if receiverEventPort == 0 {
		if ep, ok := videoResp["eventPort"]; ok {
			switch v := ep.(type) {
			case uint64:
				receiverEventPort = int(v)
			case int64:
				receiverEventPort = int(v)
			case float64:
				receiverEventPort = int(v)
			}
		}
	}

	// Connect to receiver event port if available.
	if receiverEventPort > 0 {
		eventAddr := net.JoinHostPort(c.host, strconv.Itoa(receiverEventPort))
		receiverEventConn, err = net.DialTimeout("tcp", eventAddr, 3*time.Second)
		if err != nil {
			dbg("[EVENT] connect to receiver event port %s failed: %v", eventAddr, err)
		} else {
			dbg("[EVENT] connected to receiver event port %s", eventAddr)
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

	// ---- RECORD to start the session ----
	recordHeaders := map[string]string{
		"Session":  sessionUUID,
		"Range":    "npt=0-",
		"RTP-Info": "seq=0;rtptime=0",
	}
	recordBody, recordRespHeaders, err := c.rtspRequest("RECORD", audioURI, "", nil, recordHeaders)
	if err != nil {
		return nil, fmt.Errorf("RECORD: %w", err)
	}
	if recordRespHeaders != nil {
		dbg("[SETUP] RECORD response headers: %+v", recordRespHeaders)
	}
	if len(recordBody) > 0 {
		dbg("[SETUP] RECORD response body: %02x", recordBody)
	}
	if value, ok := recordRespHeaders["audio-latency"]; ok {
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil {
			dbg("[SETUP] invalid Audio-Latency header %q: %v", value, parseErr)
		} else if parsed > 0 {
			audioLatencySamples = uint32(parsed)
			dbg("[SETUP] receiver audio latency: %d samples", audioLatencySamples)
		}
	}

	// Set volume to maximum (0 dB)
	volumeBody := []byte("volume: 0.000000\r\n")
	_, _, err = c.rtspRequest("SET_PARAMETER", audioURI, "text/parameters", volumeBody, nil)
	if err != nil {
		dbg("[SETUP] SET_PARAMETER volume failed (non-fatal): %v", err)
	} else {
		dbg("[SETUP] SET_PARAMETER volume=0 (max) sent")
	}
	// Send volume twice (pcap shows real senders do this)
	_, _, _ = c.rtspRequest("SET_PARAMETER", audioURI, "text/parameters", volumeBody, nil)

	session := &MirrorSession{
		client:         c,
		dataConn:       dataConn,
		eventConn:      receiverEventConn,
		eventListener:  eventListener,
		DataPort:       dataPort,
		videoWidth:     cfg.Width,
		videoHeight:    cfg.Height,
		firstFrameSent: make(chan struct{}),
		noAudio:        cfg.NoAudio,
		sessionURI:     controlURI,
		timingConn:     timingConn,
	}

	// Set up video cipher.
	// AppleTV (encrypted pair-verify) uses ChaCha20-Poly1305 with HKDF-derived key.
	// UxPlay (plaintext pair-verify) uses AES-CTR with SHA-512-derived key.
	if encKey != nil && c.encrypted && c.fpAesKey != nil {
		// ChaCha20-Poly1305 path: HKDF-SHA512 key derivation.
		// The receiver's _GetDataStreamSecurityKeys calls the FP helper's HKDF method.
		// The sender side uses PairingSessionDeriveKey via the PairingClient, which
		// does HKDF with the pair-verify X25519 ECDH shared secret as IKM.
		// Try the pair-verify shared secret first; fall back to raw FP aesKey.
		ikm := c.fpAesKey
		if c.PairKeys != nil && len(c.PairKeys.SharedSecret) > 0 {
			ikm = c.PairKeys.SharedSecret
			dbg("[SETUP] using pair-verify shared secret as HKDF IKM (%d bytes)", len(ikm))
		}
		chachaKey, err := deriveChaChaKey(ikm, videoStreamConnectionID)
		if err != nil {
			dataConn.Close()
			return nil, fmt.Errorf("derive chacha key: %w", err)
		}
		aead, err := chacha20poly1305.New(chachaKey)
		if err != nil {
			dataConn.Close()
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
			dataConn.Close()
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

	// Start heartbeat in background
	go session.heartbeatLoop(ctx, controlURI, sessionUUID)
	go session.dataHeartbeatLoop(ctx)
	go session.feedbackLoop(ctx, controlURI)

	return session, nil
}

// StreamFrames reads H.264 frames from the capture pipeline and sends them to the Apple TV.
// Protocol (from UxPlay/raop_rtp_mirror.c):
//   - SPS+PPS: sent as unencrypted codec frame (header[4]=0x01) in avcC format
//   - IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x00, AVCC payload
//   - non-IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x00, AVCC payload
func (s *MirrorSession) StreamFrames(ctx context.Context, capture *ScreenCapture, startDelay time.Duration) error {
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
	var vclBuf []byte               // AVCC-formatted data accumulating for current access unit
	var pendingKeyframe bool        // true if vclBuf contains IDR slice(s)
	var codecSent bool              // true if codec frame sent for current keyframe
	var streamPrimed bool           // true after first SPS/PPS+IDR has been sent
	var frameCount int
	var nalLog strings.Builder

	// Congestion controller: EWMA-smoothed send rate vs. bitrate budget.
	// Graduated response avoids oscillating between "all frames" and "no frames".
	cc := newCongestionController()

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
				vclBuf = vclBuf[:0]
				nalLog.Reset()
				return nil
			}
		}

		// Graduated P-frame dropping based on congestion level.
		// Keyframes are never dropped — the decoder needs them.
		if !pendingKeyframe && cc.shouldDrop(frameCount) {
			vclBuf = vclBuf[:0]
			nalLog.Reset()
			return nil
		}

		packetTimestamp := ntpTimeNow()

		// Send SPS+PPS as unencrypted avcC codec frame before keyframes
		if pendingKeyframe && !codecSent && latestSPS != nil && latestPPS != nil {
			avcC := buildAVCCConfig(latestSPS, latestPPS)
			if frameCount < 20 {
				dbg("[STREAM] sending codec frame avcC len=%d hdr=%02x", len(avcC), avcC[:min(8, len(avcC))])
			}
			if err := s.sendCodecFrame(avcC, packetTimestamp); err != nil {
				return fmt.Errorf("send codec: %w", err)
			}
			// Signal that the first frame has been sent (unblocks data heartbeat)
			select {
			case <-s.firstFrameSent:
			default:
				close(s.firstFrameSent)
			}
			codecSent = true
			streamPrimed = true
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

		sendStart := time.Now()
		if err := s.sendFrame(frameData, pendingKeyframe, packetTimestamp); err != nil {
			return fmt.Errorf("send %s: %w", keyframeStr, err)
		}
		cc.recordSend(len(frameData)+128, time.Since(sendStart))
		vclBuf = vclBuf[:0]
		pendingKeyframe = false
		codecSent = false
		frameCount++
		return nil
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
			nt := nalType(nal)
			raw := stripStartCode(nal)

			// Log first 20 AU sequences in detail
			if frameCount < 20 {
				fmt.Fprintf(&nalLog, "NAL type=%d len=%d ", nt, len(raw))
				if len(raw) > 0 {
					fmt.Fprintf(&nalLog, "hdr=%02x", raw[0])
				}
				nalLog.WriteByte('|')
			}

			switch nt {
			case 9: // AUD — access unit delimiter, flush previous frame
				if err := flushVCL(); err != nil {
					return err
				}
			case 7: // SPS — flush before keyframe
				if err := flushVCL(); err != nil {
					return err
				}
				latestSPS = raw
			case 8: // PPS
				latestPPS = raw
			case 6: // SEI — skip, don't include in VCL data
			case 5: // IDR VCL slice — accumulate (may be multi-slice)
				// If IDR appears while non-IDR data is buffered, close previous AU first.
				if len(vclBuf) > 0 && !pendingKeyframe {
					if err := flushVCL(); err != nil {
						return err
					}
				}
				// New AU (first slice) within an IDR sequence → flush previous IDR AU.
				if len(vclBuf) > 0 && pendingKeyframe && isFirstSlice(raw) {
					if err := flushVCL(); err != nil {
						return err
					}
				}
				pendingKeyframe = true
				vclBuf = append(vclBuf, avccWrap(raw)...)
			case 1, 2, 3, 4: // non-IDR VCL slice — accumulate
				// Flush when transitioning from keyframe AU to non-IDR AU.
				if len(vclBuf) > 0 && pendingKeyframe {
					if err := flushVCL(); err != nil {
						return err
					}
				}
				// New AU (first slice) — flush the previous P-frame.
				// Without this, consecutive P-frames accumulate if AUDs
				// are absent (some encoders/h264parse versions).
				if len(vclBuf) > 0 && !pendingKeyframe && isFirstSlice(raw) {
					if err := flushVCL(); err != nil {
						return err
					}
				}
				vclBuf = append(vclBuf, avccWrap(raw)...)
			default:
				if frameCount < 20 {
					dbg("[STREAM] ignoring NAL type=%d len=%d", nt, len(raw))
				}
			}
		}
	}
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

// sendCodecFrame sends an unencrypted SPS+PPS codec packet (header type 0x01 0x00).
// payload is an AVCDecoderConfigurationRecord (avcC format).
func (s *MirrorSession) sendCodecFrame(payload []byte, ntpTimestamp uint64) error {
	s.frameSeq++
	var header [128]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(payload)))
	header[4] = 0x01 // payload type = SPS+PPS codec packet (unencrypted)
	header[5] = 0x00
	header[6] = 0x16 // h264 SPS+PPS option
	header[7] = 0x01
	binary.LittleEndian.PutUint64(header[8:16], ntpTimestamp)
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
// Header layout (128 bytes):
//
//	[0:4]   payload size (LE uint32)
//	[4]     payload type: 0x00 = encrypted video data
//	[5]     0x10 = IDR (keyframe), 0x00 = non-IDR
//	[6:8]   payload option: 0x00 0x00 for encrypted packets
//	[8:16]  NTP timestamp (LE uint64, boot-relative)
//	[16:128] zeroed (no image-size data for VCL packets)
func (s *MirrorSession) sendFrame(auData []byte, isKeyframe bool, ntpTimestamp uint64) error {
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
	binary.LittleEndian.PutUint64(header[8:16], ntpTimestamp)

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

	dbg("[SEND] %s frame: seq=%d payLen=%d hdr[4:6]=%02x%02x ts=%d",
		keyframeStr, s.frameSeq, len(auData), header[4], header[5], ntpTimestamp)

	// Use vectored I/O (writev) to send header + payload in a single syscall,
	// avoiding a copy into a combined buffer.
	bufs := net.Buffers{header[:], framePayload}
	s.dataMu.Lock()
	s.dataConn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err := bufs.WriteTo(s.dataConn)
	s.dataMu.Unlock()
	if err != nil {
		dbg("[SEND] write error on frame seq=%d: %v", s.frameSeq, err)
	}
	return err
}

// writeFull writes all bytes to conn, handling short writes from net.Conn.Write.
func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
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

// ---------------------------------------------------------------------------
// congestionController — EWMA-based send-rate tracker with graduated response
// ---------------------------------------------------------------------------

// congestionLevel represents the graduated congestion state.
type congestionLevel int

const (
	congestionNone   congestionLevel = 0 // send every frame
	congestionLight  congestionLevel = 1 // drop every 3rd P-frame
	congestionMedium congestionLevel = 2 // drop every 2nd P-frame
	congestionHeavy  congestionLevel = 3 // drop every P-frame
)

type congestionController struct {
	// EWMA of write duration per byte (nanoseconds/byte). A rising value
	// means the TCP send buffer is filling up, i.e. the link is saturated.
	ewmaNsPerByte float64
	samples       int
	level         congestionLevel
	skipped       int
	lastLog       time.Time
}

func newCongestionController() *congestionController {
	return &congestionController{}
}

// recordSend updates the EWMA with one frame's write timing and adjusts the
// congestion level. Called after every successful sendFrame.
func (cc *congestionController) recordSend(bytes int, dur time.Duration) {
	if bytes <= 0 {
		return
	}
	nsPerByte := float64(dur.Nanoseconds()) / float64(bytes)

	const alpha = 0.3 // weight of new sample (reacts in ~3 frames)
	if cc.samples == 0 {
		cc.ewmaNsPerByte = nsPerByte
	} else {
		cc.ewmaNsPerByte = alpha*nsPerByte + (1-alpha)*cc.ewmaNsPerByte
	}
	cc.samples++

	// Thresholds in ns/byte. On Wi-Fi, kernel-buffered writes typically
	// complete in 10-500 ns/byte even under normal load. Only trigger
	// congestion when the socket is clearly blocking for extended periods.
	//   light:  ~50ms per 5KB frame  → 10000 ns/byte
	//   medium: ~100ms per 5KB frame → 20000 ns/byte
	//   heavy:  ~250ms per 5KB frame → 50000 ns/byte
	switch {
	case cc.ewmaNsPerByte > 50000:
		cc.setLevel(congestionHeavy)
	case cc.ewmaNsPerByte > 20000:
		cc.setLevel(congestionMedium)
	case cc.ewmaNsPerByte > 10000:
		cc.setLevel(congestionLight)
	default:
		cc.setLevel(congestionNone)
	}
}

func (cc *congestionController) setLevel(l congestionLevel) {
	if l != cc.level {
		if l > congestionNone {
			log.Printf("[STREAM] congestion level %d → %d (ewma %.0f ns/byte)", cc.level, l, cc.ewmaNsPerByte)
		} else if cc.skipped > 0 {
			log.Printf("[STREAM] congestion cleared after skipping %d frames", cc.skipped)
			cc.skipped = 0
		}
		cc.level = l
	}
}

// shouldDrop returns true if the current frame (identified by count) should be
// dropped based on the congestion level. Keyframes are never passed here.
func (cc *congestionController) shouldDrop(frameCount int) bool {
	switch cc.level {
	case congestionLight:
		if frameCount%3 == 0 {
			cc.skipped++
			cc.logDrop()
			return true
		}
	case congestionMedium:
		if frameCount%2 == 0 {
			cc.skipped++
			cc.logDrop()
			return true
		}
	case congestionHeavy:
		cc.skipped++
		cc.logDrop()
		return true
	}
	return false
}

func (cc *congestionController) logDrop() {
	now := time.Now()
	if now.Sub(cc.lastLog) > 500*time.Millisecond {
		dbg("[STREAM] congestion: dropped %d P-frame(s) (level %d, ewma %.0f ns/byte)",
			cc.skipped, cc.level, cc.ewmaNsPerByte)
		cc.lastLog = now
	}
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

// heartbeatLoop sends periodic GET_PARAMETER requests to keep the session alive.
// Some receivers (e.g. Apple TV) may return 400 for GET_PARAMETER; in that case
// we silently stop — the /feedback POST and data-channel heartbeat provide
// redundant keepalive.
func (s *MirrorSession) heartbeatLoop(ctx context.Context, uri, sessionID string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	consecutiveFailures := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := s.client.rtspRequest("GET_PARAMETER", uri, "", nil, map[string]string{
				"Session": sessionID,
			})
			if err != nil {
				consecutiveFailures++
				dbg("[HEARTBEAT] GET_PARAMETER failed (%d): %v", consecutiveFailures, err)
				if consecutiveFailures >= 3 {
					dbg("[HEARTBEAT] disabling GET_PARAMETER after %d failures", consecutiveFailures)
					return
				}
			} else {
				consecutiveFailures = 0
			}
		}
	}
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
			err := writeFull(s.dataConn, header)
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
func (s *MirrorSession) feedbackLoop(ctx context.Context, uri string) {
	// Wait for first video frame before sending feedback
	select {
	case <-ctx.Done():
		return
	case <-s.firstFrameSent:
	}

	// Send immediate first feedback — iPhone does this within ~1s of streaming
	body, _, err := s.client.rtspRequest("POST", "/feedback", "", nil, nil)
	if err != nil {
		dbg("[FEEDBACK] initial error: %v", err)
	} else if len(body) > 0 {
		var fbResp map[string]interface{}
		if _, perr := plist.Unmarshal(body, &fbResp); perr == nil {
			dbg("[FEEDBACK] response: %+v", fbResp)
		} else {
			dbg("[FEEDBACK] response (%d bytes): %02x", len(body), body)
		}
	}

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Use bare /feedback path — UxPlay matches against exact path "/feedback",
			// not the full RTSP URI with session UUID prefix.
			body, _, err := s.client.rtspRequest("POST", "/feedback", "", nil, nil)
			if err != nil {
				dbg("[FEEDBACK] error: %v", err)
			} else if len(body) > 0 {
				var fbResp map[string]interface{}
				if _, perr := plist.Unmarshal(body, &fbResp); perr == nil {
					dbg("[FEEDBACK] response: %+v", fbResp)
				}
			}
		}
	}
}

func (s *MirrorSession) Close() error {
	// Send TEARDOWN to cleanly end the RTSP session on the receiver.
	if s.sessionURI != "" && s.client != nil {
		_, _, err := s.client.rtspRequest("TEARDOWN", s.sessionURI, "", nil, nil)
		if err != nil {
			dbg("[TEARDOWN] error: %v", err)
		} else {
			dbg("[TEARDOWN] sent for %s", s.sessionURI)
		}
		s.sessionURI = "" // prevent double teardown
	}
	if s.audioStream != nil {
		s.audioStream.Close()
	}
	if s.eventConn != nil {
		s.eventConn.Close()
	}
	if s.timingConn != nil {
		s.timingConn.Close()
	}
	if s.eventListener != nil {
		s.eventListener.Close()
	}
	if s.dataConn != nil {
		return s.dataConn.Close()
	}
	return nil
}

// plistInt extracts an integer from a plist value (uint64, int64, or float64).
func plistInt(v interface{}) int {
	switch n := v.(type) {
	case uint64:
		return int(n)
	case int64:
		return int(n)
	case float64:
		return int(n)
	}
	return 0
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

	volume := "0.000000"
	if muted {
		volume = "-144.000000"
	}
	body := []byte("volume: " + volume + "\r\n")
	if _, _, err := s.client.rtspRequest("SET_PARAMETER", s.sessionURI, "text/parameters", body, nil); err != nil {
		return fmt.Errorf("set audio muted=%t: %w", muted, err)
	}
	return nil
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

		if n < 32 {
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

// appStartTime is the reference point for boot-relative timestamps.
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
	d := time.Since(appStartTime) + videoTimestampBias()
	sec := uint64(d / time.Second)
	nsecFrac := uint64(d % time.Second)
	frac := (nsecFrac << 32) / uint64(time.Second)
	return (sec << 32) | frac
}

// allocateConsecutiveUDPPorts allocates `count` consecutive UDP port numbers.
// Real Apple AirPlay senders use consecutive ports: timing(N), control(N+1), data(N+2).
func allocateConsecutiveUDPPorts(count int) ([]net.PacketConn, error) {
	for attempt := 0; attempt < 20; attempt++ {
		// Get a random port
		first, err := net.ListenPacket("udp", ":0")
		if err != nil {
			continue
		}
		base := first.LocalAddr().(*net.UDPAddr).Port

		conns := []net.PacketConn{first}
		ok := true
		for i := 1; i < count; i++ {
			c, err := net.ListenPacket("udp", fmt.Sprintf(":%d", base+i))
			if err != nil {
				ok = false
				break
			}
			conns = append(conns, c)
		}
		if ok {
			return conns, nil
		}
		// Close all and retry
		for _, c := range conns {
			c.Close()
		}
	}
	return nil, fmt.Errorf("could not allocate %d consecutive UDP ports after 20 attempts", count)
}

// ntpBootTimestamp returns a 64-bit NTP fixed-point timestamp using boot-relative
// time with the NTP epoch (1900-01-01) added. UxPlay subtracts the NTP epoch from
// timing responses (account_for_epoch=true), yielding the same boot-relative seconds
// that video frame headers carry via ntpTimeNow(). Apple TV adapts to any time base.
const secondsFrom1900To1970 = 2208988800

func ntpBootTimestamp() uint64 {
	d := time.Since(appStartTime)
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
