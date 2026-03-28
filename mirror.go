package main

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"howett.net/plist"
)

// MirrorSession manages an active screen mirroring session.
type MirrorSession struct {
	client        *AirPlayClient
	dataConn      net.Conn
	eventConn     net.Conn
	timingConn    net.PacketConn
	eventListener net.Listener
	DataPort      int

	streamCipher func([]byte) []byte // AES-CTR encryption
	frameSeq     uint32
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
		// Keep connection open; just drain it
		go func() {
			buf := make([]byte, 4096)
			for {
				_, err := conn.Read(buf)
				if err != nil {
					return
				}
			}
		}()
	}()

	// ---- Phase 1: SETUP session (timing/event channels, no streams) ----
	setup1 := map[string]interface{}{
		"deviceID":                 clientDeviceID,
		"macAddress":               clientDeviceID,
		"sessionUUID":              sessionUUID,
		"sourceVersion":            "935.7.1",
		"timingProtocol":           "NTP",
		"timingPort":               int64(timingPort),
		"eventPort":                int64(eventPort),
		"isScreenMirroringSession": true,
		"osName":                   "Linux",
		"osBuildVersion":           "1.0.0",
		"model":                    "Linux",
		"name":                     "Linux",
	}
	log.Printf("[SETUP-1] request: %+v", setup1)

	body1, err := plist.Marshal(setup1, plist.BinaryFormat)
	if err != nil {
		eventListener.Close()
		return nil, fmt.Errorf("marshal setup1 plist: %w", err)
	}

	resp1Body, _, err := c.rtspRequest("SETUP", uri, "application/x-apple-binary-plist", body1, nil)
	if err != nil {
		eventListener.Close()
		return nil, fmt.Errorf("SETUP phase 1: %w", err)
	}

	var resp1 map[string]interface{}
	receiverEventPort := 0
	if len(resp1Body) > 0 {
		if _, err := plist.Unmarshal(resp1Body, &resp1); err != nil {
			eventListener.Close()
			return nil, fmt.Errorf("unmarshal setup1 response: %w", err)
		}
		log.Printf("[SETUP-1] response: %+v", resp1)
		if ep, ok := resp1["eventPort"]; ok {
			switch v := ep.(type) {
			case uint64:
				receiverEventPort = int(v)
			case int64:
				receiverEventPort = int(v)
			case float64:
				receiverEventPort = int(v)
			}
		}
	} else {
		log.Printf("[SETUP-1] empty response body (OK)")
	}

	// Some receivers require an active TCP event channel before RECORD.
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

	// ---- Phase 2: SETUP stream (type 110 = screen mirroring) ----
	streamConnectionID := int64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFF)
	streamDesc := map[string]interface{}{
		"type":               int64(110),
		"streamConnectionID": streamConnectionID,
	}

	// Encryption keys go inside the stream descriptor
	if encKey != nil {
		streamDesc["shk"] = encKey
		streamDesc["shiv"] = encIV
	}

	setup2 := map[string]interface{}{
		"streams": []interface{}{streamDesc},
	}
	log.Printf("[SETUP-2] request: %+v", setup2)

	body2, err := plist.Marshal(setup2, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("marshal setup2 plist: %w", err)
	}

	resp2Body, _, err := c.rtspRequest("SETUP", uri, "application/x-apple-binary-plist", body2, nil)
	if err != nil {
		return nil, fmt.Errorf("SETUP phase 2: %w", err)
	}

	log.Printf("[SETUP-2] response body: %d bytes", len(resp2Body))

	// Parse phase 2 response to get data port
	var setupResp map[string]interface{}
	if _, err := plist.Unmarshal(resp2Body, &setupResp); err != nil {
		return nil, fmt.Errorf("unmarshal setup2 response: %w", err)
	}
	log.Printf("[SETUP-2] response plist: %+v", setupResp)

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
		// Try top-level eventPort or use default
		if ep, ok := setupResp["eventPort"]; ok {
			switch v := ep.(type) {
			case uint64:
				dataPort = int(v)
			case int64:
				dataPort = int(v)
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
		client:        c,
		dataConn:      dataConn,
		eventConn:     receiverEventConn,
		eventListener: eventListener,
		DataPort:      dataPort,
	}

	// Derive actual video cipher keys from shk + streamConnectionID via SHA-512
	// (matches Apple TV's key derivation in mirror_buffer_init_aes).
	if encKey != nil {
		videoKey, videoIV := deriveVideoKeys(encKey, streamConnectionID)
		sc, err := newStreamCipher(videoKey, videoIV)
		if err != nil {
			dataConn.Close()
			return nil, fmt.Errorf("stream cipher: %w", err)
		}
		session.streamCipher = func(data []byte) []byte {
			out := make([]byte, len(data))
			sc.XORKeyStream(out, data)
			return out
		}
	}

	// Start heartbeat in background
	go session.heartbeatLoop(ctx, uri, sessionUUID)

	return session, nil
}

// StreamFrames reads H.264 frames from the capture pipeline and sends them to the Apple TV.
// Protocol (from UxPlay/raop_rtp_mirror.c):
//   - SPS+PPS: sent as unencrypted codec frame (header[4]=0x01) in avcC format
//   - IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x10, AVCC payload
//   - non-IDR VCL: sent encrypted, header[4]=0x00 header[5]=0x00, AVCC payload
func (s *MirrorSession) StreamFrames(ctx context.Context, capture *ScreenCapture) error {
	buf := make([]byte, 256*1024)
	parser := newAnnexBParser()

	var latestSPS, latestPPS []byte // raw NAL data WITHOUT start code
	var vclBuf []byte               // AVCC-formatted data accumulating for current VCL packet

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := capture.Read(buf)
		if err != nil {
			if err == io.EOF {
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

		nals := parser.Push(buf[:n])
		for _, nal := range nals {
			nt := nalType(nal)
			raw := stripStartCode(nal)

			switch nt {
			case 7: // SPS
				latestSPS = raw
			case 8: // PPS
				latestPPS = raw
			case 6: // SEI — accumulate with next VCL
				vclBuf = append(vclBuf, avccWrap(raw)...)
			case 5: // IDR VCL (keyframe)
				// Send SPS+PPS as unencrypted avcC codec frame first.
				if latestSPS != nil && latestPPS != nil {
					if err := s.sendCodecFrame(buildAVCCConfig(latestSPS, latestPPS)); err != nil {
						return fmt.Errorf("send codec: %w", err)
					}
				}
				vclBuf = append(vclBuf, avccWrap(raw)...)
				frameData := vclBuf
				if s.streamCipher != nil {
					frameData = s.streamCipher(vclBuf)
				}
				if err := s.sendFrame(frameData, true); err != nil {
					return fmt.Errorf("send IDR: %w", err)
				}
				vclBuf = vclBuf[:0]
			case 1, 2, 3, 4: // non-IDR VCL
				vclBuf = append(vclBuf, avccWrap(raw)...)
				frameData := vclBuf
				if s.streamCipher != nil {
					frameData = s.streamCipher(vclBuf)
				}
				if err := s.sendFrame(frameData, false); err != nil {
					return fmt.Errorf("send frame: %w", err)
				}
				vclBuf = vclBuf[:0]
			}
		}
	}
}

// annexBParser incrementally extracts complete Annex-B NAL units from a byte stream.
type annexBParser struct {
	buf []byte
}

func newAnnexBParser() *annexBParser {
	return &annexBParser{buf: make([]byte, 0, 512*1024)}
}

func (p *annexBParser) Push(data []byte) [][]byte {
	p.buf = append(p.buf, data...)
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
func (s *MirrorSession) sendCodecFrame(payload []byte) error {
	s.frameSeq++
	header := make([]byte, 128)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(payload)))
	header[4] = 0x01 // payload type = SPS+PPS codec packet (unencrypted)
	header[5] = 0x00
	header[6] = 0x16 // option: standard unencrypted SPS+PPS
	header[7] = 0x01
	binary.BigEndian.PutUint64(header[8:16], ntpTimeNow())
	binary.LittleEndian.PutUint32(header[16:20], s.frameSeq)

	frame := make([]byte, 128+len(payload))
	copy(frame[:128], header)
	copy(frame[128:], payload)
	s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.dataConn.Write(frame)
	return err
}

// sendFrame writes a single encrypted VCL frame with the mirroring protocol header.
// payload must be AVCC-encoded (4-byte BE length per NALU, no start codes).
// isKeyframe=true sets header[5]=0x10 (IDR), false sets header[5]=0x00 (non-IDR).
func (s *MirrorSession) sendFrame(auData []byte, isKeyframe bool) error {
	ntpTimestamp := ntpTimeNow()

	s.frameSeq++

	header := make([]byte, 128)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(auData)))
	// header[4]=0x00 for encrypted VCL; header[5]=0x10 for IDR, 0x00 for non-IDR.
	header[4] = 0x00
	if isKeyframe {
		header[5] = 0x10
	} else {
		header[5] = 0x00
	}
	binary.BigEndian.PutUint64(header[8:16], ntpTimestamp)
	binary.LittleEndian.PutUint32(header[16:20], s.frameSeq)

	frame := make([]byte, 128+len(auData))
	copy(frame[:128], header)
	copy(frame[128:], auData)

	s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.dataConn.Write(frame)
	return err
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

		// Build response: echo back with our timestamps
		reply := make([]byte, 32)
		copy(reply, buf[:32])
		reply[0] = 0x80
		reply[1] = 0xd3

		now := ntpTimeNow()
		// Bytes 8-15: Reference = sender's transmit timestamp
		copy(reply[8:16], buf[24:32])
		// Bytes 16-23: Receive timestamp = now
		binary.BigEndian.PutUint64(reply[16:24], now)
		// Bytes 24-31: Transmit timestamp = now
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

// ntpTimeNow returns the current time as an NTP timestamp (seconds since 1900-01-01).
func ntpTimeNow() uint64 {
	// NTP epoch is 1900-01-01, Unix is 1970-01-01 = 70 years = 2208988800 seconds
	const ntpEpochOffset = 2208988800
	now := time.Now()
	secs := uint64(now.Unix()) + ntpEpochOffset
	frac := uint64(now.Nanosecond()) * (1 << 32) / 1e9
	return secs<<32 | frac
}

func generateUUID() string {
	b := make([]byte, 16)
	rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant 10
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
