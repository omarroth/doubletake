package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"howett.net/plist"
)

// ReceiverInfo contains the capabilities returned by GET /info.
type ReceiverInfo struct {
	Name               string  `plist:"name"`
	Model              string  `plist:"model"`
	DeviceID           string  `plist:"deviceID"`
	ProtocolVersion    string  `plist:"protocolVersion"`
	SourceVersion      string  `plist:"sourceVersion"`
	Features           uint64  `plist:"features"`
	StatusFlags        uint64  `plist:"statusFlags"`
	PK                 []byte  `plist:"pk"`
	HasUDPMirror       bool    `plist:"hasUDPMirroringSupport"`
	HDRCapability      string  `plist:"receiverHDRCapability"`
	VolumeControlType  int     `plist:"volumeControlType"`
	InitialVolume      float64 `plist:"initialVolume"`
	KeepAliveBody      bool    `plist:"keepAliveSendStatsAsBody"`
	PSI                string  `plist:"psi"`
	PI                 string  `plist:"pi"`
	MacAddress         string  `plist:"macAddress"`
}

// AirPlayClient manages the connection to an AirPlay receiver.
type AirPlayClient struct {
	host string
	port int

	conn     net.Conn
	mu       sync.Mutex
	cseq     atomic.Int64
	info     *ReceiverInfo
	pairKeys *PairKeys

	// Encryption state after pair-verify
	encrypted    bool
	encWriteKey  []byte
	encReadKey   []byte
	encWriteNonce uint64
	encReadNonce  uint64
	encCipher    cipher.AEAD

	// FairPlay derived key for stream encryption
	fpKey []byte
	fpIV  []byte

	// Stream encryption key (from FP or pair-verify)
	streamKey []byte
	streamIV  []byte
}

func NewAirPlayClient(host string, port int) *AirPlayClient {
	return &AirPlayClient{
		host: host,
		port: port,
	}
}

func (c *AirPlayClient) Connect(ctx context.Context) error {
	addr := net.JoinHostPort(c.host, fmt.Sprintf("%d", c.port))
	d := net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	c.conn = conn
	return nil
}

func (c *AirPlayClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

func (c *AirPlayClient) GetInfo() (*ReceiverInfo, error) {
	resp, err := c.httpRequest("GET", "/info", "application/x-apple-binary-plist", nil)
	if err != nil {
		return nil, err
	}

	var info ReceiverInfo
	if _, err := plist.Unmarshal(resp, &info); err != nil {
		return nil, fmt.Errorf("decode info plist: %w", err)
	}
	c.info = &info
	return &info, nil
}

func (c *AirPlayClient) Pair(ctx context.Context, pin string) error {
	if pin != "" {
		return c.pairWithPIN(ctx, pin)
	}
	return c.pairTransient(ctx)
}

func (c *AirPlayClient) FairPlaySetup(ctx context.Context) error {
	return c.fairPlaySetup(ctx)
}

func (c *AirPlayClient) SetupMirror(ctx context.Context, cfg StreamConfig) (*MirrorSession, error) {
	return c.setupMirrorSession(ctx, cfg)
}

// httpRequest sends an HTTP/1.1 request over the AirPlay connection and returns the response body.
// Optional extraHeaders are merged into the request.
func (c *AirPlayClient) httpRequest(method, path, contentType string, body []byte, extraHeaders ...map[string]string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seq := c.cseq.Add(1)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s HTTP/1.1\r\n", method, path)
	fmt.Fprintf(&buf, "CSeq: %d\r\n", seq)
	fmt.Fprintf(&buf, "User-Agent: AirPlay/935.7.1\r\n")
	for _, hdrs := range extraHeaders {
		for k, v := range hdrs {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	if contentType != "" && len(body) > 0 {
		fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	buf.WriteString("\r\n")
	buf.Write(body)

	data := buf.Bytes()

	if c.encrypted {
		data = c.encrypt(data)
	}

	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}

	return c.readHTTPResponse()
}

// rtspRequest sends an RTSP/1.0 request (used after pairing for mirror setup).
func (c *AirPlayClient) rtspRequest(method, uri, contentType string, body []byte, extraHeaders map[string]string) ([]byte, map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seq := c.cseq.Add(1)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s RTSP/1.0\r\n", method, uri)
	fmt.Fprintf(&buf, "CSeq: %d\r\n", seq)
	fmt.Fprintf(&buf, "User-Agent: AirPlay/935.7.1\r\n")
	for k, v := range extraHeaders {
		fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
	}
	if contentType != "" && len(body) > 0 {
		fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	buf.WriteString("\r\n")
	buf.Write(body)

	data := buf.Bytes()
	if c.encrypted {
		data = c.encrypt(data)
	}

	if _, err := c.conn.Write(data); err != nil {
		return nil, nil, fmt.Errorf("write request: %w", err)
	}

	respBody, err := c.readHTTPResponse()
	if err != nil {
		return nil, nil, err
	}

	return respBody, nil, nil
}

func (c *AirPlayClient) readHTTPResponse() ([]byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	// Read response in a buffer - we need to handle potentially encrypted data
	var headerBuf bytes.Buffer
	oneByte := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c.conn, oneByte); err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		headerBuf.Write(oneByte)

		b := headerBuf.Bytes()
		if len(b) >= 4 && bytes.Equal(b[len(b)-4:], []byte("\r\n\r\n")) {
			break
		}
		if headerBuf.Len() > 16384 {
			return nil, fmt.Errorf("response header too large")
		}
	}

	header := headerBuf.String()

	// Parse status line
	var statusCode int
	fmt.Sscanf(header, "HTTP/1.1 %d", &statusCode)
	if statusCode == 0 {
		fmt.Sscanf(header, "RTSP/1.0 %d", &statusCode)
	}

	// Parse content-length
	contentLength := 0
	for _, line := range bytes.Split([]byte(header), []byte("\r\n")) {
		l := string(line)
		if len(l) > 16 && (l[:16] == "Content-Length: " || l[:16] == "content-length: ") {
			fmt.Sscanf(l[16:], "%d", &contentLength)
		}
	}

	if statusCode < 200 || statusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d", statusCode)
	}

	if contentLength == 0 {
		return nil, nil
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}

	return body, nil
}

func (c *AirPlayClient) encrypt(data []byte) []byte {
	if !c.encrypted || c.encCipher == nil {
		return data
	}

	// Frame: 2-byte LE length + encrypted data + 16-byte tag
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], c.encWriteNonce)
	c.encWriteNonce++

	// AAD is the 2-byte length
	length := uint16(len(data))
	aad := make([]byte, 2)
	binary.LittleEndian.PutUint16(aad, length)

	encrypted := c.encCipher.Seal(nil, nonce, data, aad)

	result := make([]byte, 2+len(encrypted))
	copy(result[:2], aad)
	copy(result[2:], encrypted)
	return result
}

// StreamConfig holds the configuration for a mirroring session.
type StreamConfig struct {
	Width  int
	Height int
	FPS    int
}

// generateStreamKey creates a random AES-128 key for stream encryption.
func generateStreamKey() (key, iv []byte, err error) {
	key = make([]byte, 16)
	iv = make([]byte, 16)
	if _, err = rand.Read(key); err != nil {
		return nil, nil, err
	}
	if _, err = rand.Read(iv); err != nil {
		return nil, nil, err
	}
	return key, iv, nil
}

// newStreamCipher creates an AES-CTR cipher for stream encryption.
func newStreamCipher(key, iv []byte) (cipher.Stream, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(block, iv), nil
}
