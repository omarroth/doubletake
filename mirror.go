package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"time"

	"howett.net/plist"
)

// MirrorSession manages an active screen mirroring session.
type MirrorSession struct {
	client        *AirPlayClient
	dataConn      net.Conn
	eventListener net.Listener
	DataPort      int

	streamCipher func([]byte) []byte // AES-CTR encryption
	startTime    time.Time
	frameSeq     uint32
}

// setupMirrorSession negotiates the mirroring stream with the Apple TV.
func (c *AirPlayClient) setupMirrorSession(ctx context.Context, cfg StreamConfig) (*MirrorSession, error) {
	sessionUUID := generateUUID()
	uri := fmt.Sprintf("rtsp://%s:%d/%s", c.host, c.port, sessionUUID)

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

	// Start a TCP listener for the event (reverse) channel — Apple TV connects back to us
	eventListener, err := net.Listen("tcp", ":0")
	if err != nil {
		return nil, fmt.Errorf("listen event port: %w", err)
	}
	eventPort := eventListener.Addr().(*net.TCPAddr).Port
	log.Printf("[SETUP] event listener on TCP port %d", eventPort)

	// Accept event connection asynchronously
	eventConnCh := make(chan net.Conn, 1)
	go func() {
		conn, err := eventListener.Accept()
		if err != nil {
			log.Printf("[EVENT] accept error: %v", err)
			return
		}
		log.Printf("[EVENT] Apple TV connected for reverse events")
		eventConnCh <- conn
	}()

	// ---- Phase 1: SETUP session (timing channels, no streams) ----
	setup1 := map[string]interface{}{
		"sessionUUID":              sessionUUID,
		"sourceVersion":            "935.7.1",
		"timingProtocol":           "None",
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
	if len(resp1Body) > 0 {
		if _, err := plist.Unmarshal(resp1Body, &resp1); err != nil {
			eventListener.Close()
			return nil, fmt.Errorf("unmarshal setup1 response: %w", err)
		}
		log.Printf("[SETUP-1] response: %+v", resp1)
	} else {
		log.Printf("[SETUP-1] empty response body (OK)")
	}

	// ---- Phase 2: SETUP stream (type 110 = screen mirroring) ----
	streamConnectionID := int64(time.Now().UnixNano() & 0x7FFFFFFFFFFFFFFF)
	streamDesc := map[string]interface{}{
		"type":               110,
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

	// Send RECORD to start the session
	_, _, err = c.rtspRequest("RECORD", uri, "", nil, map[string]string{
		"Session": sessionUUID,
	})
	if err != nil {
		return nil, fmt.Errorf("RECORD: %w", err)
	}

	// Connect to the data port for streaming
	dataAddr := net.JoinHostPort(c.host, strconv.Itoa(dataPort))
	dataConn, err := net.DialTimeout("tcp", dataAddr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect data port %s: %w", dataAddr, err)
	}

	session := &MirrorSession{
		client:        c,
		dataConn:      dataConn,
		eventListener: eventListener,
		DataPort:      dataPort,
		startTime:     time.Now(),
	}

	// Set up stream encryption: prefer FairPlay key, fall back to pair-verify derived key
	encKey = c.fpKey
	encIV = c.fpIV
	if encKey == nil {
		encKey = c.streamKey
		encIV = c.streamIV
	}
	if encKey != nil {
		streamCipher, err := newStreamCipher(encKey, encIV)
		if err != nil {
			dataConn.Close()
			return nil, fmt.Errorf("stream cipher: %w", err)
		}
		session.streamCipher = func(data []byte) []byte {
			out := make([]byte, len(data))
			streamCipher.XORKeyStream(out, data)
			return out
		}
	}

	// Start heartbeat in background
	go session.heartbeatLoop(ctx, uri, sessionUUID)

	return session, nil
}

// StreamFrames reads H.264 frames from the capture pipeline and sends them to the Apple TV.
func (s *MirrorSession) StreamFrames(ctx context.Context, capture *ScreenCapture) error {
	buf := make([]byte, 256*1024) // 256KB read buffer

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := capture.Read(buf)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read capture: %w", err)
		}

		if n == 0 {
			continue
		}

		frameData := buf[:n]

		// Encrypt the frame data if encryption is set up
		if s.streamCipher != nil {
			frameData = s.streamCipher(frameData)
		}

		if err := s.sendFrame(frameData); err != nil {
			return fmt.Errorf("send frame: %w", err)
		}
	}
}

// sendFrame writes a single frame with the mirroring protocol header.
func (s *MirrorSession) sendFrame(nalData []byte) error {
	elapsed := time.Since(s.startTime)
	ntpTimestamp := timeToNTP(elapsed)

	s.frameSeq++

	// 128-byte mirroring frame header
	header := make([]byte, 128)
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(nalData))) // payload size
	binary.LittleEndian.PutUint16(header[4:6], 0)                    // payload type: video
	binary.LittleEndian.PutUint16(header[6:8], 0)                    // reserved
	binary.BigEndian.PutUint64(header[8:16], ntpTimestamp)           // NTP timestamp
	binary.LittleEndian.PutUint32(header[16:20], s.frameSeq)         // sequence number

	// Write header + payload atomically
	frame := make([]byte, 128+len(nalData))
	copy(frame[:128], header)
	copy(frame[128:], nalData)

	s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.dataConn.Write(frame)
	return err
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
	if s.eventListener != nil {
		s.eventListener.Close()
	}
	if s.dataConn != nil {
		return s.dataConn.Close()
	}
	return nil
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

// timeToNTP converts a duration to an NTP timestamp (seconds since 1900 in upper 32 bits,
// fractional seconds in lower 32 bits).
func timeToNTP(d time.Duration) uint64 {
	secs := uint64(d.Seconds())
	frac := uint64((d - time.Duration(secs)*time.Second).Nanoseconds()) * (1 << 32) / 1e9
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
