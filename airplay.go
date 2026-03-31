package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"howett.net/plist"
)

// ReceiverInfo contains the capabilities returned by GET /info.
type ReceiverInfo struct {
	Name              string  `plist:"name"`
	Model             string  `plist:"model"`
	DeviceID          string  `plist:"deviceID"`
	ProtocolVersion   string  `plist:"protocolVersion"`
	SourceVersion     string  `plist:"sourceVersion"`
	Features          uint64  `plist:"features"`
	StatusFlags       uint64  `plist:"statusFlags"`
	PK                []byte  `plist:"pk"`
	HasUDPMirror      bool    `plist:"hasUDPMirroringSupport"`
	HDRCapability     string  `plist:"receiverHDRCapability"`
	VolumeControlType int     `plist:"volumeControlType"`
	InitialVolume     float64 `plist:"initialVolume"`
	KeepAliveBody     bool    `plist:"keepAliveSendStatsAsBody"`
	PSI               string  `plist:"psi"`
	PI                string  `plist:"pi"`
	MacAddress        string  `plist:"macAddress"`
}

// AirPlayClient manages the connection to an AirPlay receiver.
type AirPlayClient struct {
	host string
	port int

	conn      net.Conn
	mu        sync.Mutex
	cseq      atomic.Int64
	info      *ReceiverInfo
	pairKeys  *PairKeys
	sessionID string // X-Apple-Session-ID, set once per connection
	pairingID string // Our pairing identifier (UUID)

	// Encryption state after pair-verify
	encrypted     bool
	encWriteKey   []byte
	encReadKey    []byte
	encWriteNonce uint64
	encReadNonce  uint64
	encCipher     cipher.AEAD

	// FairPlay derived key for stream encryption
	fpKey  []byte
	fpIV   []byte
	fpEkey []byte // 72-byte wrapped key for SETUP

	// Stream encryption key (from FP or pair-verify)
	streamKey []byte
	streamIV  []byte
}

func NewAirPlayClient(host string, port int) *AirPlayClient {
	return &AirPlayClient{
		host:      host,
		port:      port,
		sessionID: generateUUID(),
		pairingID: generateUUID(),
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

// ClearSessionID clears the session ID so requests don't include X-Apple-Session-ID.
// Used for the raw/legacy protocol path (raw pair-verify).
func (c *AirPlayClient) ClearSessionID() {
	c.sessionID = ""
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

// httpRequest sends an RTSP/1.0 request over the AirPlay connection and returns the response body.
// Used for /info, /pair-setup, /pair-verify, /fp-setup etc. (RAOP connection type).
// Does NOT send X-Apple-Session-ID (UxPlay classifies CSeq connections as RAOP and
// crashes with an assert if both CSeq and X-Apple-Session-ID are present).
func (c *AirPlayClient) httpRequest(method, path, contentType string, body []byte, extraHeaders ...map[string]string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seq := c.cseq.Add(1)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s RTSP/1.0\r\n", method, path)
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

	log.Printf("[HTTP] -> %s %s (body=%d bytes, encrypted=%v, cseq=%d)", method, path, len(body), c.encrypted, seq)
	if c.encrypted {
		plainLen := len(data)
		data = c.encrypt(data)
		log.Printf("[HTTP] encrypted %d plaintext -> %d ciphertext bytes", plainLen, len(data))
	}

	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("write request: %w", err)
	}
	log.Printf("[HTTP] wrote %d bytes to socket, waiting for response...", len(data))

	return c.readHTTPResponse()
}

// rawRequest sends a bare RTSP/1.0 request without X-Apple-Session-ID or HAP
// encryption. Used for the raw binary pair-verify protocol.
func (c *AirPlayClient) rawRequest(method, path, contentType string, body []byte, extraHeaders ...map[string]string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	seq := c.cseq.Add(1)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "%s %s RTSP/1.0\r\n", method, path)
	fmt.Fprintf(&buf, "Content-Type: %s\r\n", contentType)
	fmt.Fprintf(&buf, "User-Agent: AirPlay/935.7.1\r\n")
	fmt.Fprintf(&buf, "X-Apple-ProtocolVersion: 1\r\n")
	for _, hdrs := range extraHeaders {
		for k, v := range hdrs {
			fmt.Fprintf(&buf, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&buf, "Content-Length: %d\r\n", len(body))
	fmt.Fprintf(&buf, "CSeq: %d\r\n", seq)
	buf.WriteString("\r\n")
	buf.Write(body)

	data := buf.Bytes()
	log.Printf("[RAW] -> %s %s (body=%d bytes, cseq=%d)", method, path, len(body), seq)

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
	// NOTE: Do NOT send X-Apple-Session-ID here. UxPlay classifies CSeq connections
	// as RAOP type and crashes (strcmp against NULL) if session ID is present.
	// Apple TV doesn't need it either since the session is identified by TCP connection.
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
	log.Printf("[RTSP] -> %s %s (body=%d bytes, encrypted=%v, cseq=%d)", method, uri, len(body), c.encrypted, seq)
	if c.encrypted {
		plainLen := len(data)
		data = c.encrypt(data)
		log.Printf("[RTSP] encrypted %d plaintext -> %d ciphertext bytes", plainLen, len(data))
	}

	if _, err := c.conn.Write(data); err != nil {
		return nil, nil, fmt.Errorf("write request: %w", err)
	}
	log.Printf("[RTSP] wrote %d bytes to socket, waiting for response...", len(data))

	respBody, err := c.readHTTPResponse()
	if err != nil {
		return nil, nil, err
	}

	log.Printf("[RTSP] <- response body %d bytes", len(respBody))
	return respBody, nil, nil
}

func (c *AirPlayClient) readHTTPResponse() ([]byte, error) {
	c.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})

	if c.encrypted {
		log.Printf("[READ] reading encrypted response (readKey=%s, readNonce=%d)", hex.EncodeToString(c.encReadKey[:8]), c.encReadNonce)
		return c.readEncryptedHTTPResponse()
	}
	log.Printf("[READ] reading plaintext response")
	return c.readPlaintextHTTPResponse()
}

func (c *AirPlayClient) readPlaintextHTTPResponse() ([]byte, error) {
	// Read headers byte-by-byte until \r\n\r\n
	var headerBuf bytes.Buffer
	oneByte := make([]byte, 1)
	for {
		if _, err := io.ReadFull(c.conn, oneByte); err != nil {
			return nil, fmt.Errorf("read response header (got %d bytes so far: %q): %w", headerBuf.Len(), headerBuf.String(), err)
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
	log.Printf("[READ] plaintext response header:\n%s", header)
	statusCode, contentLength := parseHTTPHeader(header)
	log.Printf("[READ] status=%d content-length=%d", statusCode, contentLength)

	if statusCode < 200 || statusCode >= 300 {
		// Drain body if present
		var errBody []byte
		if contentLength > 0 {
			errBody = make([]byte, contentLength)
			io.ReadFull(c.conn, errBody)
		}
		log.Printf("[READ] error response body (%d bytes): %s", len(errBody), hex.EncodeToString(errBody))
		return nil, fmt.Errorf("HTTP %d (body: %s)", statusCode, string(errBody))
	}

	if contentLength == 0 {
		return nil, nil
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return nil, fmt.Errorf("read body (%d/%d bytes): %w", 0, contentLength, err)
	}

	log.Printf("[READ] plaintext body: %d bytes", len(body))
	return body, nil
}

func (c *AirPlayClient) readEncryptedHTTPResponse() ([]byte, error) {
	// Read and decrypt frames, then parse the HTTP response from decrypted data.
	// We accumulate decrypted data until we have the full response.
	var decrypted []byte
	frameCount := 0

	// Read frames until we have the HTTP headers
	log.Printf("[ENC-READ] starting to read encrypted frames...")
	for {
		frame, err := c.readEncryptedFrame()
		if err != nil {
			log.Printf("[ENC-READ] frame %d read error (decrypted so far=%d bytes): %v", frameCount, len(decrypted), err)
			if len(decrypted) > 0 {
				log.Printf("[ENC-READ] partial decrypted data hex: %s", hex.EncodeToString(decrypted))
			}
			return nil, fmt.Errorf("read encrypted response frame %d: %w", frameCount, err)
		}
		frameCount++
		log.Printf("[ENC-READ] frame %d: %d bytes decrypted", frameCount, len(frame))
		decrypted = append(decrypted, frame...)

		// Check if we have the full headers
		if idx := bytes.Index(decrypted, []byte("\r\n\r\n")); idx >= 0 {
			log.Printf("[ENC-READ] found header end after %d frames, %d total bytes", frameCount, len(decrypted))
			break
		}
		if len(decrypted) > 16384 {
			return nil, fmt.Errorf("encrypted response header too large")
		}
	}

	headerEnd := bytes.Index(decrypted, []byte("\r\n\r\n"))
	header := string(decrypted[:headerEnd+4])
	remaining := decrypted[headerEnd+4:]

	log.Printf("[ENC-READ] decrypted response header:\n%s", header)
	statusCode, contentLength := parseHTTPHeader(header)
	log.Printf("[ENC-READ] status=%d content-length=%d remaining=%d", statusCode, contentLength, len(remaining))

	if statusCode < 200 || statusCode >= 300 {
		// Try to get error body
		for len(remaining) < contentLength && contentLength > 0 {
			frame, err := c.readEncryptedFrame()
			if err != nil {
				break
			}
			remaining = append(remaining, frame...)
		}
		if len(remaining) > contentLength && contentLength > 0 {
			remaining = remaining[:contentLength]
		}
		log.Printf("[ENC-READ] error response body (%d bytes): %s", len(remaining), hex.EncodeToString(remaining))
		return nil, fmt.Errorf("HTTP %d (body: %s)", statusCode, string(remaining))
	}

	if contentLength == 0 {
		return nil, nil
	}

	// Read more frames if we don't have the full body yet
	for len(remaining) < contentLength {
		frame, err := c.readEncryptedFrame()
		if err != nil {
			log.Printf("[ENC-READ] body frame error (have %d/%d bytes): %v", len(remaining), contentLength, err)
			return nil, fmt.Errorf("read encrypted body (%d/%d bytes): %w", len(remaining), contentLength, err)
		}
		remaining = append(remaining, frame...)
	}

	log.Printf("[ENC-READ] complete: %d body bytes in %d+ frames", contentLength, frameCount)
	return remaining[:contentLength], nil
}

func parseHTTPHeader(header string) (statusCode, contentLength int) {
	fmt.Sscanf(header, "HTTP/1.1 %d", &statusCode)
	if statusCode == 0 {
		fmt.Sscanf(header, "RTSP/1.0 %d", &statusCode)
	}

	for _, line := range bytes.Split([]byte(header), []byte("\r\n")) {
		l := string(line)
		if len(l) > 16 && (l[:16] == "Content-Length: " || l[:16] == "content-length: ") {
			fmt.Sscanf(l[16:], "%d", &contentLength)
		}
	}
	return
}

func (c *AirPlayClient) encrypt(data []byte) []byte {
	if !c.encrypted || c.encCipher == nil {
		return data
	}

	// HAP encrypted frame format: split plaintext into max 1024-byte chunks.
	// Each chunk: [2-byte LE plaintext length][encrypted(plaintext) + 16-byte Poly1305 tag]
	// AAD for each chunk is the 2-byte length prefix.
	var result []byte
	chunkNum := 0
	for len(data) > 0 {
		chunk := data
		if len(chunk) > 1024 {
			chunk = chunk[:1024]
		}
		data = data[len(chunk):]

		nonce := make([]byte, 12)
		binary.LittleEndian.PutUint64(nonce[4:], c.encWriteNonce)

		aad := make([]byte, 2)
		binary.LittleEndian.PutUint16(aad, uint16(len(chunk)))

		log.Printf("[ENC-WRITE] chunk %d: %d bytes, writeNonce=%d, aad=%s",
			chunkNum, len(chunk), c.encWriteNonce, hex.EncodeToString(aad))
		c.encWriteNonce++

		encrypted := c.encCipher.Seal(nil, nonce, chunk, aad)

		result = append(result, aad...)
		result = append(result, encrypted...)
		chunkNum++
	}
	log.Printf("[ENC-WRITE] total: %d chunks, %d bytes output", chunkNum, len(result))
	return result
}

// readEncryptedFrame reads and decrypts one HAP encrypted frame from the connection.
func (c *AirPlayClient) readEncryptedFrame() ([]byte, error) {
	// Read 2-byte LE length
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.conn, lengthBuf); err != nil {
		return nil, fmt.Errorf("read frame length: %w (timeout or connection closed)", err)
	}
	plaintextLen := int(binary.LittleEndian.Uint16(lengthBuf))
	log.Printf("[ENC-FRAME] length prefix: %s (plaintext len=%d, will read %d bytes)",
		hex.EncodeToString(lengthBuf), plaintextLen, plaintextLen+16)

	if plaintextLen == 0 || plaintextLen > 16384 {
		log.Printf("[ENC-FRAME] WARNING: suspicious frame length %d — raw bytes on wire may not be encrypted frames", plaintextLen)
		// Peek at a few more bytes for debugging
		peek := make([]byte, 32)
		n, _ := c.conn.Read(peek)
		log.Printf("[ENC-FRAME] next %d bytes on wire: %s", n, hex.EncodeToString(peek[:n]))
		return nil, fmt.Errorf("suspicious frame length %d (expected 1-1024)", plaintextLen)
	}

	// Read ciphertext (plaintext length + 16-byte Poly1305 tag)
	ciphertext := make([]byte, plaintextLen+16)
	if _, err := io.ReadFull(c.conn, ciphertext); err != nil {
		return nil, fmt.Errorf("read frame ciphertext (%d bytes): %w", plaintextLen+16, err)
	}

	// Decrypt
	readCipher, err := chacha20poly1305.New(c.encReadKey)
	if err != nil {
		return nil, fmt.Errorf("read cipher: %w", err)
	}

	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], c.encReadNonce)
	log.Printf("[ENC-FRAME] decrypting with nonce=%d key=%s... aad=%s",
		c.encReadNonce, hex.EncodeToString(c.encReadKey[:8]), hex.EncodeToString(lengthBuf))
	c.encReadNonce++

	plaintext, err := readCipher.Open(nil, nonce, ciphertext, lengthBuf)
	if err != nil {
		log.Printf("[ENC-FRAME] DECRYPT FAILED: nonce=%d ciphertext[:32]=%s",
			c.encReadNonce-1, hex.EncodeToString(ciphertext[:min(32, len(ciphertext))]))
		return nil, fmt.Errorf("decrypt frame (nonce=%d, len=%d): %w", c.encReadNonce-1, plaintextLen, err)
	}

	log.Printf("[ENC-FRAME] decrypted %d bytes OK", len(plaintext))
	return plaintext, nil
}

// readDecryptedBytes reads and decrypts enough bytes from the encrypted channel.
func (c *AirPlayClient) readDecryptedBytes(n int) ([]byte, error) {
	var buf []byte
	for len(buf) < n {
		frame, err := c.readEncryptedFrame()
		if err != nil {
			return nil, err
		}
		buf = append(buf, frame...)
	}
	return buf[:n], nil
}

// StreamConfig holds the configuration for a mirroring session.
type StreamConfig struct {
	Width     int
	Height    int
	FPS       int
	NoEncrypt bool // Disable encryption for debugging
	DirectKey bool // Use shk/shiv directly without SHA-512 derivation
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

// mirrorCipher implements the AirPlay mirroring AES-CTR encryption scheme
// matching the receiver's mirror_buffer_decrypt exactly.
//
// The receiver (mirror_buffer.c) processes each frame as follows:
//  1. XOR the first nextDecryptCount bytes using cached keystream (og buffer)
//     left over from the previous frame's trailing partial block.
//  2. Call aes_ctr_start_fresh_block — advance CTR to next 16-byte boundary.
//  3. Decrypt floor((len - nextDecryptCount) / 16) * 16 bytes (full blocks).
//  4. If trailing partial block: pad to 16, decrypt full block, use needed
//     bytes, cache remaining keystream in og for step 1 of next frame.
//
// The sender must produce ciphertext that decrypts correctly under this scheme.
type mirrorCipher struct {
	stream         cipher.Stream
	blockOffset    int      // bytes consumed in current 16-byte CTR block
	og             [16]byte // cached keystream from previous frame's trailing partial block
	nextCryptCount int      // how many og bytes are available for the next frame's prefix
}

func newMirrorCipher(key, iv []byte) (*mirrorCipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &mirrorCipher{
		stream: cipher.NewCTR(block, iv),
	}, nil
}

// EncryptFrame encrypts a single video frame payload, matching the
// receiver's mirror_buffer_decrypt block-alignment scheme.
func (mc *mirrorCipher) EncryptFrame(payload []byte) []byte {
	inputLen := len(payload)
	out := make([]byte, inputLen)
	pos := 0

	// Step 1: XOR prefix bytes using cached keystream from previous frame's
	// trailing partial block (matches receiver's og buffer usage).
	if mc.nextCryptCount > 0 {
		n := mc.nextCryptCount
		if n > inputLen {
			n = inputLen
		}
		ogStart := 16 - mc.nextCryptCount
		for i := 0; i < n; i++ {
			out[i] = payload[i] ^ mc.og[ogStart+i]
		}
		pos = n
	}

	// Step 2: Advance CTR to next 16-byte boundary (aes_ctr_start_fresh_block).
	if mc.blockOffset > 0 {
		waste := make([]byte, 16-mc.blockOffset)
		mc.stream.XORKeyStream(waste, waste)
		mc.blockOffset = 0
	}

	remaining := inputLen - pos

	// Step 3: Encrypt full 16-byte blocks.
	fullBlocks := (remaining / 16) * 16
	if fullBlocks > 0 {
		mc.stream.XORKeyStream(out[pos:pos+fullBlocks], payload[pos:pos+fullBlocks])
		mc.blockOffset = 0 // still aligned after full blocks
		pos += fullBlocks
	}

	// Step 4: Handle trailing partial block.
	restLen := remaining % 16
	mc.nextCryptCount = 0
	if restLen > 0 {
		// Pad input to 16 bytes, encrypt full block, use first restLen bytes.
		var padded [16]byte
		copy(padded[:restLen], payload[pos:pos+restLen])
		mc.stream.XORKeyStream(padded[:], padded[:])
		copy(out[pos:], padded[:restLen])
		// Cache the full decrypted block for next frame's step 1.
		mc.og = padded
		mc.nextCryptCount = 16 - restLen
		mc.blockOffset = 0 // we encrypted a full 16-byte block
	}

	return out
}
