package main

import (
	"context"
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

	streamCipher   func([]byte) []byte // AES-CTR encryption
	frameSeq       uint32
	firstFrameSent chan struct{} // closed after first video frame is sent
}

// setupMirrorSession negotiates the mirroring stream with the Apple TV.
func (c *AirPlayClient) setupMirrorSession(ctx context.Context, cfg StreamConfig) (*MirrorSession, error) {
	sessionUUID := generateUUID()
	uri := fmt.Sprintf("rtsp://%s:%d/%s", c.host, c.port, sessionUUID)
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
		log.Printf("[SETUP] video frame encryption DISABLED (--no-encrypt mode)")
		encKey = nil
		encIV = nil
	} else if encKey != nil {
		log.Printf("[SETUP] using encryption (key: %d bytes, IV: %d bytes)", len(encKey), len(encIV))
	}

	// Start NTP timing UDP listener — Apple TV sends timing requests here
	timingConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("listen timing port: %w", err)
	}
	timingPort := timingConn.LocalAddr().(*net.UDPAddr).Port
	log.Printf("[SETUP] NTP timing listener on UDP port %d", timingPort)

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
	log.Printf("[SETUP] event listener on TCP port %d", eventPort)

	// Accept event connection asynchronously
	go func() {
		conn, err := eventListener.Accept()
		if err != nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				log.Printf("[EVENT] accept error: %v", err)
			}
			return
		}
		log.Printf("[EVENT] Apple TV connected for reverse events from %s", conn.RemoteAddr())
		// Keep connection open; log received data
		go func() {
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					log.Printf("[EVENT] event channel closed: %v", err)
					return
				}
				log.Printf("[EVENT] received %d bytes: %02x", n, buf[:min(n, 64)])
			}
		}()
	}()

	// ---- Single combined SETUP (matching AirMyPC structure) ----
	streamConnectionID := int64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFF)
	streamDesc := map[string]interface{}{
		"type":               int64(110),
		"streamConnectionID": streamConnectionID,
		"timestampInfo": []interface{}{
			map[string]interface{}{"name": "SubSu"},
			map[string]interface{}{"name": "BePxT"},
			map[string]interface{}{"name": "AfPxT"},
			map[string]interface{}{"name": "BefEn"},
			map[string]interface{}{"name": "EmEnc"},
		},
	}

	// Encryption keys: shk/shiv go inside the stream descriptor,
	// but ekey/eiv go at the ROOT level of the plist (Apple TV reads them from root).
	if encKey != nil && c.fpEkey == nil {
		streamDesc["shk"] = encKey
		streamDesc["shiv"] = encIV
	}

	setupPlist := map[string]interface{}{
		"deviceID":                 clientDeviceID,
		"macAddress":               clientDeviceID,
		"sessionUUID":              sessionUUID,
		"sourceVersion":            "280.33",
		"timingProtocol":           "NTP",
		"timingPort":               int64(timingPort),
		"isScreenMirroringSession": true,
		"osBuildVersion":           "13F69",
		"model":                    "Linux",
		"name":                     "Linux",
		"streams":                  []interface{}{streamDesc},
	}

	// FairPlay ekey/eiv go at the root level (receiver reads them from req_root_node)
	// Only send when encryption is actually enabled (not in no-encrypt mode)
	if c.fpEkey != nil && encKey != nil {
		setupPlist["ekey"] = c.fpEkey
		setupPlist["eiv"] = encIV
		log.Printf("[SETUP] FairPlay mode: ekey=%d bytes, eiv=%d bytes (at root level)", len(c.fpEkey), len(encIV))
	}
	log.Printf("[SETUP] combined request: %+v", setupPlist)

	setupBody, err := plist.Marshal(setupPlist, plist.BinaryFormat)
	if err != nil {
		eventListener.Close()
		return nil, fmt.Errorf("marshal setup plist: %w", err)
	}

	respBody, _, err := c.rtspRequest("SETUP", uri, "application/x-apple-binary-plist", setupBody, nil)
	if err != nil {
		eventListener.Close()
		return nil, fmt.Errorf("SETUP: %w", err)
	}

	var setupResp map[string]interface{}
	if _, err := plist.Unmarshal(respBody, &setupResp); err != nil {
		return nil, fmt.Errorf("unmarshal setup response: %w", err)
	}
	log.Printf("[SETUP] response: %+v", setupResp)

	// Extract event port from response
	receiverEventPort := 0
	if ep, ok := setupResp["eventPort"]; ok {
		switch v := ep.(type) {
		case uint64:
			receiverEventPort = int(v)
		case int64:
			receiverEventPort = int(v)
		case float64:
			receiverEventPort = int(v)
		}
	}

	// Connect to receiver event port if available
	var receiverEventConn net.Conn
	if receiverEventPort > 0 {
		eventAddr := net.JoinHostPort(c.host, strconv.Itoa(receiverEventPort))
		receiverEventConn, err = net.DialTimeout("tcp", eventAddr, 3*time.Second)
		if err != nil {
			log.Printf("[EVENT] connect to receiver event port %s failed: %v", eventAddr, err)
		} else {
			log.Printf("[EVENT] connected to receiver event port %s", eventAddr)
		}
	}

	// Extract data port from streams response
	dataPort := 0
	if streams, ok := setupResp["streams"].([]interface{}); ok && len(streams) > 0 {
		if stream, ok := streams[0].(map[string]interface{}); ok {
			if dp, ok := stream["dataPort"]; ok {
				switch v := dp.(type) {
				case uint64:
					dataPort = int(v)
				case int64:
					dataPort = int(v)
				case float64:
					dataPort = int(v)
				}
			}
		}
	}

	if dataPort == 0 {
		return nil, fmt.Errorf("no data port in SETUP response")
	}

	// Connect to the data port before RECORD.
	// Some receivers wait for the sender data socket to be ready before
	// acknowledging RECORD, otherwise they timeout and return 500.
	dataAddr := net.JoinHostPort(c.host, strconv.Itoa(dataPort))
	dataConn, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect data port %s: %w", dataAddr, err)
	}
	log.Printf("[SETUP] data channel connected: %s", dataAddr)

	// Send RECORD to start the session.
	// Apple TV expects normal RTSP start headers here; without them it may wait
	// for ~10s and return 500.
	recordHeaders := map[string]string{
		"Session":  sessionUUID,
		"Range":    "npt=0-",
		"RTP-Info": "seq=0;rtptime=0",
	}
	_, _, err = c.rtspRequest("RECORD", uri, "", nil, recordHeaders)
	if err != nil {
		dataConn.Close()
		return nil, fmt.Errorf("RECORD: %w", err)
	}

	session := &MirrorSession{
		client:         c,
		dataConn:       dataConn,
		eventConn:      receiverEventConn,
		eventListener:  eventListener,
		DataPort:       dataPort,
		videoWidth:     cfg.Width,
		videoHeight:    cfg.Height,
		firstFrameSent: make(chan struct{}),
	}

	// Set up video cipher using continuous AES-CTR.
	// UxPlay's mirror_buffer_decrypt uses a continuous CTR stream across frames:
	// leftover keystream from one frame carries into the next. No per-frame
	// block alignment — plain cipher.NewCTR is correct.
	if encKey != nil {
		var cipherKey, cipherIV []byte
		if cfg.DirectKey {
			// Use shk/shiv directly without derivation
			cipherKey = encKey
			cipherIV = encIV
			log.Printf("[SETUP] using DIRECT key mode (no SHA-512 derivation)")
		} else {
			// Derive AES-128-CTR key/IV from shk + streamConnectionID using SHA-512.
			// Matches UxPlay's mirror_buffer_init_aes.
			derivationKey := encKey
			if c.fpEkey != nil && c.pairKeys != nil && c.pairKeys.SharedSecret != nil {
				// FairPlay mode: combine AES key with pair-verify ECDH shared secret
				// eaesKey = SHA-512(aesKey || ecdhShared)[:16]
				h := sha512.New()
				h.Write(encKey)
				h.Write(c.pairKeys.SharedSecret)
				derivationKey = h.Sum(nil)[:16]
				log.Printf("[SETUP] FairPlay eaesKey (combined hash): %02x", derivationKey)
			}
			cipherKey, cipherIV = deriveVideoKeys(derivationKey, streamConnectionID)
			log.Printf("[SETUP] using SHA-512 derived keys")
		}
		log.Printf("[SETUP] streamConnectionID: %d", streamConnectionID)
		log.Printf("[SETUP] shk (raw key):    %02x", encKey)
		log.Printf("[SETUP] shiv (raw IV):    %02x", encIV)
		log.Printf("[SETUP] cipher key:       %02x", cipherKey)
		log.Printf("[SETUP] cipher IV:        %02x", cipherIV)
		mc, err := newMirrorCipher(cipherKey, cipherIV)
		if err != nil {
			dataConn.Close()
			return nil, fmt.Errorf("stream cipher: %w", err)
		}
		session.streamCipher = mc.EncryptFrame
	} else {
		log.Printf("[SETUP] no video cipher — frames will be sent unencrypted")
	}

	// Monitor data connection for incoming data from Apple TV
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := dataConn.Read(buf)
			if err != nil {
				log.Printf("[DATA-READ] data conn closed: %v", err)
				return
			}
			log.Printf("[DATA-READ] received %d bytes from Apple TV: %02x", n, buf[:min(n, 64)])
		}
	}()

	// Start heartbeat in background
	go session.heartbeatLoop(ctx, uri, sessionUUID)
	go session.dataHeartbeatLoop(ctx)
	go session.feedbackLoop(ctx, uri)

	return session, nil
}

// StreamFrames reads H.264 frames from the capture pipeline and sends them to the Apple TV.
// Protocol (from UxPlay/raop_rtp_mirror.c):
//   - SPS+PPS: sent as unencrypted codec frame (header[4]=0x01) in avcC format
//   - IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x00, AVCC payload
//   - non-IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x00, AVCC payload
func (s *MirrorSession) StreamFrames(ctx context.Context, capture *ScreenCapture, startDelay time.Duration) error {
	if startDelay > 0 {
		log.Printf("[STREAM] waiting %v before sending first frame...", startDelay)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(startDelay):
			log.Printf("[STREAM] delay complete, starting frame send")
		}
	}

	buf := make([]byte, 256*1024)
	parser := newH264Parser()

	var latestSPS, latestPPS []byte // raw NAL data WITHOUT start code
	var vclBuf []byte               // AVCC-formatted data accumulating for current access unit
	var pendingKeyframe bool        // true if vclBuf contains IDR slice(s)
	var codecSent bool              // true if codec frame sent for current keyframe
	var frameCount int
	var nalLog strings.Builder
	frameInterval := time.Second / 30 // ~33ms at 30fps
	var lastFrameTime time.Time

	// flushVCL sends the accumulated VCL data as a single encrypted frame.
	// This handles multi-slice frames by combining all slices of one access unit.
	flushVCL := func() error {
		if len(vclBuf) == 0 {
			return nil
		}

		// Pace frames at target framerate
		if !lastFrameTime.IsZero() {
			elapsed := time.Since(lastFrameTime)
			if elapsed < frameInterval {
				time.Sleep(frameInterval - elapsed)
			}
		}
		lastFrameTime = time.Now()

		packetTimestamp := ntpTimeNow()

		// Send SPS+PPS as unencrypted avcC codec frame before keyframes
		if pendingKeyframe && !codecSent && latestSPS != nil && latestPPS != nil {
			avcC := buildAVCCConfig(latestSPS, latestPPS)
			if frameCount < 20 {
				log.Printf("[STREAM] sending codec frame avcC len=%d hdr=%02x", len(avcC), avcC[:min(8, len(avcC))])
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
		}

		frameData := vclBuf
		if s.streamCipher != nil {
			if frameCount < 5 {
				log.Printf("[CRYPTO] frame %d plain[0:20]=%02x", frameCount, vclBuf[:min(20, len(vclBuf))])
			}
			frameData = s.streamCipher(vclBuf)
			if frameCount < 5 {
				log.Printf("[CRYPTO] frame %d  enc[0:20]=%02x", frameCount, frameData[:min(20, len(frameData))])
			}
		}

		keyframeStr := "non-IDR"
		if pendingKeyframe {
			keyframeStr = "IDR"
		}
		if frameCount < 20 {
			log.Printf("[STREAM] %s frame %d: avcc_payload=%d encrypted=%v", keyframeStr, frameCount, len(vclBuf), s.streamCipher != nil)
			log.Printf("[STREAM] NAL sequence for frame %d: %s", frameCount, nalLog.String())
		}
		nalLog.Reset()

		if err := s.sendFrame(frameData, pendingKeyframe, packetTimestamp); err != nil {
			return fmt.Errorf("send %s: %w", keyframeStr, err)
		}
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
			log.Printf("[CAPTURE] read %d bytes start=% x", n, buf[:min(n, 16)])
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
				if frameCount < 20 {
					log.Printf("[STREAM] AUD (access unit delimiter)")
				}
			case 7: // SPS
				latestSPS = raw
				if frameCount < 20 {
					log.Printf("[STREAM] SPS len=%d bytes=%02x", len(raw), raw)
				}
			case 8: // PPS
				latestPPS = raw
				if frameCount < 20 {
					log.Printf("[STREAM] PPS len=%d bytes=%02x", len(raw), raw)
				}
			case 6: // SEI — skip, don't include in VCL data
				if frameCount < 20 {
					log.Printf("[STREAM] skipping SEI NAL len=%d", len(raw))
				}
			case 5: // IDR VCL slice — accumulate (may be multi-slice)
				pendingKeyframe = true
				vclBuf = append(vclBuf, avccWrap(raw)...)
			case 1, 2, 3, 4: // non-IDR VCL slice — accumulate
				vclBuf = append(vclBuf, avccWrap(raw)...)
			default:
				if frameCount < 20 {
					log.Printf("[STREAM] ignoring NAL type=%d len=%d", nt, len(raw))
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
			log.Printf("[STREAM] invalid AVCC NAL length %d, dropping %d buffered bytes", nalLen, len(p.buf))
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
func buildAVCCConfig(sps, pps []byte) []byte {
	payload := make([]byte, 6+2+len(sps)+1+2+len(pps))
	payload[0] = 0x01   // configurationVersion = 1
	payload[1] = sps[1] // AVCProfileIndication
	payload[2] = sps[2] // profile_compatibility
	payload[3] = sps[3] // AVCLevelIndication
	payload[4] = 0xff   // lengthSizeMinusOne = 3 (4-byte NALU lengths)
	payload[5] = 0xe1   // numSequenceParameterSets = 1
	binary.BigEndian.PutUint16(payload[6:8], uint16(len(sps)))
	copy(payload[8:], sps)
	off := 8 + len(sps)
	payload[off] = 0x01 // numPictureParameterSets = 1
	binary.BigEndian.PutUint16(payload[off+1:off+3], uint16(len(pps)))
	copy(payload[off+3:], pps)
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

// sendCodecFrame sends an unencrypted SPS+PPS codec packet (header type 0x01 0x00).
// payload is an AVCDecoderConfigurationRecord (avcC format).
func (s *MirrorSession) sendCodecFrame(payload []byte, ntpTimestamp uint64) error {
	s.frameSeq++
	header := make([]byte, 128)
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

	frame := make([]byte, 128+len(payload))
	copy(frame[:128], header)
	copy(frame[128:], payload)

	log.Printf("[SEND] codec frame: seq=%d payLen=%d hdr[4:6]=%02x%02x ts=%d",
		s.frameSeq, len(payload), header[4], header[5], ntpTimestamp)
	log.Printf("[SEND] codec full header: %02x", header)
	log.Printf("[SEND] codec payload: %02x", payload)

	s.dataMu.Lock()
	s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := writeFull(s.dataConn, frame)
	s.dataMu.Unlock()
	return err
}

// SendTestCodec sends a codec frame for testing purposes.
func (s *MirrorSession) SendTestCodec(avcC []byte) {
	if err := s.sendCodecFrame(avcC, ntpTimeNow()); err != nil {
		log.Printf("[TEST] sendCodecFrame error: %v", err)
	} else {
		log.Println("[TEST] codec frame sent successfully")
	}
}

// SendTestEmptyVCL sends a VCL header with zero-length payload for testing.
func (s *MirrorSession) SendTestEmptyVCL() {
	header := make([]byte, 128)
	// payload size = 0
	header[4] = 0x00 // VCL video data type
	header[5] = 0x00
	header[6] = 0x00
	header[7] = 0x00
	binary.LittleEndian.PutUint64(header[8:16], ntpTimeNow())
	log.Printf("[TEST] sending type 0x00 (VCL) header: %02x", header[:16])
	s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if err := writeFull(s.dataConn, header); err != nil {
		log.Printf("[TEST] type 0x00 write error: %v", err)
	} else {
		log.Println("[TEST] type 0x00 header sent successfully")
	}
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

	header := make([]byte, 128)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(auData)))
	header[4] = 0x00 // payload type = encrypted video data
	if isKeyframe {
		header[5] = 0x10 // IDR frame indicator
	} else {
		header[5] = 0x00 // non-IDR
	}
	// header[6:8] = 0x00 0x00 for encrypted packets (already zeroed)
	binary.LittleEndian.PutUint64(header[8:16], ntpTimestamp)

	frame := make([]byte, 128+len(auData))
	copy(frame[:128], header)
	copy(frame[128:], auData)

	keyframeStr := "non-IDR"
	if isKeyframe {
		keyframeStr = "IDR"
	}

	// Log detailed frame header in hex
	hdrHex := fmt.Sprintf("%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
		header[0], header[1], header[2], header[3],
		header[4], header[5], header[6], header[7],
		header[8], header[9], header[10], header[11],
		header[12], header[13], header[14], header[15])

	if s.frameSeq <= 3 {
		log.Printf("[SEND] %s full header: %02x", keyframeStr, header)
	}

	log.Printf("[SEND] %s frame: seq=%d payLen=%d hdr[4:6]=%02x%02x ts=%d hdr_hex=%s",
		keyframeStr, s.frameSeq, len(auData), header[4], header[5], ntpTimestamp, hdrHex)

	s.dataMu.Lock()
	s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err := writeFull(s.dataConn, frame)
	s.dataMu.Unlock()
	if err != nil {
		log.Printf("[SEND] write error on frame seq=%d: %v", s.frameSeq, err)
		// Log first 20 bytes of encrypted payload for debugging
		if len(auData) > 0 {
			payloadHex := fmt.Sprintf("%02x", auData[:min(20, len(auData))])
			log.Printf("[SEND] payload[0:20]=%s", payloadHex)
		}
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

// heartbeatLoop sends periodic GET_PARAMETER requests to keep the session alive.
func (s *MirrorSession) heartbeatLoop(ctx context.Context, uri, sessionID string) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, _, err := s.client.rtspRequest("GET_PARAMETER", uri, "", nil, map[string]string{
				"Session": sessionID,
			})
			if err != nil {
				log.Printf("heartbeat failed: %v", err)
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
				log.Printf("[HEARTBEAT] data channel heartbeat failed: %v", err)
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
		log.Printf("[FEEDBACK] initial error: %v", err)
	} else if len(body) > 0 {
		var fbResp map[string]interface{}
		if _, perr := plist.Unmarshal(body, &fbResp); perr == nil {
			log.Printf("[FEEDBACK] response: %+v", fbResp)
		} else {
			log.Printf("[FEEDBACK] response (%d bytes): %02x", len(body), body)
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
			_, _, err := s.client.rtspRequest("POST", "/feedback", "", nil, nil)
			if err != nil {
				log.Printf("[FEEDBACK] error: %v", err)
			}
		}
	}
}

func (s *MirrorSession) Close() error {
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
			log.Printf("[NTP] read error: %v", err)
			return
		}
		log.Printf("[NTP] received %d bytes from %s", n, addr)

		if n < 32 {
			continue
		}

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
			log.Printf("[NTP] write error: %v", err)
		} else {
			log.Printf("[NTP] sent timing reply to %s", addr)
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
// A small forward bias is added so that the first frame's converted timestamp
// exceeds the GStreamer pipeline base_time on the receiver. Without this,
// UxPlay's mismatch retry loop in video_process double-applies its
// remote_clock_offset, producing a ~56-year PTS on the first buffer. GStreamer
// prerolls that frame but then drops every subsequent frame whose PTS (correctly
// at 33 ms, 66 ms, …) looks like a massive backwards time jump.
const videoTimestampBias = 100 * time.Millisecond

func ntpTimeNow() uint64 {
	d := time.Since(appStartTime) + videoTimestampBias
	sec := uint64(d / time.Second)
	nsecFrac := uint64(d % time.Second)
	frac := (nsecFrac << 32) / uint64(time.Second)
	return (sec << 32) | frac
}

// ntpBootTimestamp returns a 64-bit NTP fixed-point timestamp using boot-relative
// time with the NTP epoch (1900-01-01) added. Real Apple senders use this format
// for NTP timing responses: (bootUptime + NTPepoch) as seconds. UxPlay subtracts
// the NTP epoch when processing timing responses (account_for_epoch=true), yielding
// the same boot-relative seconds that video frame headers carry via ntpTimeNow().
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
