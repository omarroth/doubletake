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
	client   *AirPlayClient
	dataConn net.Conn
	DataPort int

	streamCipher func([]byte) []byte // AES-CTR encryption
	startTime    time.Time
	frameSeq     uint32
}

// setupMirrorSession negotiates the mirroring stream with the Apple TV.
func (c *AirPlayClient) setupMirrorSession(ctx context.Context, cfg StreamConfig) (*MirrorSession, error) {
	sessionUUID := generateUUID()

	// Build SETUP request body as binary plist
	// Determine stream encryption key to advertise in SETUP
	encKey := c.fpKey
	encIV := c.fpIV
	if encKey == nil {
		// Ensure we have stream keys derived from pair-verify
		if c.streamKey == nil {
			if err := c.deriveStreamKeys(); err != nil {
				return nil, fmt.Errorf("derive stream keys: %w", err)
			}
		}
		encKey = c.streamKey
		encIV = c.streamIV
	}

	streamDesc := map[string]interface{}{
		"type":           110, // Screen mirroring stream
		"streamID":       1,
		"clientTypeUUID": "AirPlayClient",
		"ct":             2,   // H.264
		"spf":            352, // Samples per frame
		"sr":             44100,
		"latencyMin":     11025,
		"latencyMax":     88200,
		"clientCurTime":  uint64(0),
		"supportsDynamicStreamID": true,
		"screenStream": map[string]interface{}{
			"width":     cfg.Width,
			"height":    cfg.Height,
			"fps":       cfg.FPS,
			"codec":     0, // H.264
			"latency":   100,
		},
	}

	// Include encryption key so the receiver can decrypt the stream
	if encKey != nil {
		streamDesc["shk"] = encKey
		streamDesc["shiv"] = encIV
		streamDesc["useEncryptedStream"] = true
	}

	setupReq := map[string]interface{}{
		"deviceID":        c.info.DeviceID,
		"sessionUUID":     sessionUUID,
		"sourceVersion":   "935.7.1",
		"timingProtocol":  "NTP",
		"timingPort":      0,
		"isScreenMirroringSession": true,
		"streams":         []interface{}{streamDesc},
	}

	body, err := plist.Marshal(setupReq, plist.BinaryFormat)
	if err != nil {
		return nil, fmt.Errorf("marshal setup plist: %w", err)
	}

	uri := fmt.Sprintf("rtsp://%s/%s", c.host, sessionUUID)
	respBody, _, err := c.rtspRequest("SETUP", uri, "application/x-apple-binary-plist", body, nil)
	if err != nil {
		return nil, fmt.Errorf("SETUP: %w", err)
	}

	// Parse response to get data port
	var setupResp map[string]interface{}
	if _, err := plist.Unmarshal(respBody, &setupResp); err != nil {
		return nil, fmt.Errorf("unmarshal setup response: %w", err)
	}

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
		client:   c,
		dataConn: dataConn,
		DataPort: dataPort,
		startTime: time.Now(),
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

	// Start NTP time sync in background
	go session.ntpSyncLoop(ctx)

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
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(nalData)))     // payload size
	binary.LittleEndian.PutUint16(header[4:6], 0)                        // payload type: video
	binary.LittleEndian.PutUint16(header[6:8], 0)                        // reserved
	binary.BigEndian.PutUint64(header[8:16], ntpTimestamp)                // NTP timestamp
	binary.LittleEndian.PutUint32(header[16:20], s.frameSeq)             // sequence number

	// Write header + payload atomically
	frame := make([]byte, 128+len(nalData))
	copy(frame[:128], header)
	copy(frame[128:], nalData)

	s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, err := s.dataConn.Write(frame)
	return err
}

// ntpSyncLoop handles NTP time synchronization with the receiver.
func (s *MirrorSession) ntpSyncLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.sendNTPSync()
		}
	}
}

func (s *MirrorSession) sendNTPSync() {
	// NTP sync packet (simplified): 32 bytes
	// The Apple TV expects periodic time sync to maintain A/V sync
	packet := make([]byte, 32)
	packet[0] = 0x80 // Version, mode
	packet[1] = 0xd3 // Type

	elapsed := time.Since(s.startTime)
	ntp := timeToNTP(elapsed)
	binary.BigEndian.PutUint64(packet[24:32], ntp)

	s.dataConn.Write(packet) //nolint: best-effort
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
	if s.dataConn != nil {
		return s.dataConn.Close()
	}
	return nil
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
