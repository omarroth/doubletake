package airplay

import (
	"bufio"
	"context"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"howett.net/plist"
)

const (
	eventFrameSizeLimit  = 1024
	eventHeaderSizeLimit = 16 * 1024
	eventBodySizeLimit   = 1024 * 1024
)

// eventChannel is the persistent RTSP connection opened to the eventPort in a
// SETUP response. Its encryption state is independent of the control channel.
type eventChannel struct {
	conn        net.Conn
	readCipher  cipher.AEAD
	writeCipher cipher.AEAD
	readNonce   uint64
	writeNonce  uint64
	readBuf     []byte
	writeMu     sync.Mutex
}

// newEventChannel constructs the sender side of the receiver's event channel.
// The event transport intentionally reverses the normal control-channel key
// direction: receiver commands use the Events-Write key and sender responses
// use the Events-Read key.
func newEventChannel(conn net.Conn, encrypted bool, sharedSecret []byte) (*eventChannel, error) {
	if conn == nil {
		return nil, fmt.Errorf("event connection is nil")
	}
	channel := &eventChannel{conn: conn}
	if !encrypted {
		return channel, nil
	}
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("encrypted event channel has no pair-verify shared secret")
	}

	readKey := hkdfSHA512(sharedSecret, []byte("Events-Salt"), []byte("Events-Write-Encryption-Key"), chacha20poly1305.KeySize)
	writeKey := hkdfSHA512(sharedSecret, []byte("Events-Salt"), []byte("Events-Read-Encryption-Key"), chacha20poly1305.KeySize)
	var err error
	channel.readCipher, err = chacha20poly1305.New(readKey)
	if err != nil {
		return nil, fmt.Errorf("create event read cipher: %w", err)
	}
	channel.writeCipher, err = chacha20poly1305.New(writeKey)
	if err != nil {
		return nil, fmt.Errorf("create event write cipher: %w", err)
	}
	return channel, nil
}

func (c *AirPlayClient) connectEventChannel(ctx context.Context, port int, clock *mediaClock) (net.Conn, error) {
	if port <= 0 {
		return nil, nil
	}
	address := net.JoinHostPort(c.sessionPeerHost(), strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", address, 3*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial event channel %s: %w", address, err)
	}

	var sharedSecret []byte
	if c.PairKeys != nil {
		sharedSecret = c.PairKeys.SharedSecret
	}
	channel, err := newEventChannel(conn, c.encrypted, sharedSecret)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	dbg("[EVENT] connected to receiver event port %s (encrypted=%t)", address, c.encrypted)
	go func() {
		if err := serveEventChannel(ctx, channel, clock); err != nil {
			dbg("[EVENT] channel failed: %v", err)
			_ = conn.Close()
		}
	}()
	return conn, nil
}

// Read exposes the decrypted event stream. HAP frame boundaries are not RTSP
// message boundaries, so unread plaintext is retained for the next call.
func (c *eventChannel) Read(dst []byte) (int, error) {
	if len(dst) == 0 {
		return 0, nil
	}
	if c.readCipher == nil {
		return c.conn.Read(dst)
	}
	if len(c.readBuf) == 0 {
		var sizeBytes [2]byte
		if _, err := io.ReadFull(c.conn, sizeBytes[:]); err != nil {
			return 0, fmt.Errorf("read event frame size: %w", err)
		}
		size := int(binary.LittleEndian.Uint16(sizeBytes[:]))
		if size < 1 || size > eventFrameSizeLimit {
			return 0, fmt.Errorf("invalid event frame size %d", size)
		}

		sealed := make([]byte, size+c.readCipher.Overhead())
		if _, err := io.ReadFull(c.conn, sealed); err != nil {
			return 0, fmt.Errorf("read event frame payload: %w", err)
		}
		nonce := nonceBytes(c.readNonce)
		plain, err := c.readCipher.Open(nil, nonce, sealed, sizeBytes[:])
		if err != nil {
			return 0, fmt.Errorf("decrypt event frame %d: %w", c.readNonce, err)
		}
		c.readNonce++
		c.readBuf = plain
	}

	n := copy(dst, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// Write sends one logical plaintext buffer, splitting it into HAP frames as
// needed while holding the nonce sequence across the complete write.
func (c *eventChannel) Write(plain []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.writeCipher == nil {
		length := len(plain)
		if err := writeAll(c.conn, plain); err != nil {
			return 0, err
		}
		return length, nil
	}

	written := 0
	for len(plain) > 0 {
		chunk := plain
		if len(chunk) > eventFrameSizeLimit {
			chunk = chunk[:eventFrameSizeLimit]
		}

		var sizeBytes [2]byte
		binary.LittleEndian.PutUint16(sizeBytes[:], uint16(len(chunk)))
		frame := append([]byte(nil), sizeBytes[:]...)
		frame = c.writeCipher.Seal(frame, nonceBytes(c.writeNonce), chunk, sizeBytes[:])
		if err := writeAll(c.conn, frame); err != nil {
			return written, fmt.Errorf("write event frame %d: %w", c.writeNonce, err)
		}
		c.writeNonce++

		written += len(chunk)
		plain = plain[len(chunk):]
	}
	return written, nil
}

type eventRequest struct {
	method      string
	path        string
	cseq        uint64
	contentType string
	bodyLength  int
	body        []byte
}

func readEventRequest(reader *bufio.Reader) (eventRequest, error) {
	requestLine, used, err := readEventLine(reader, eventHeaderSizeLimit)
	if err != nil {
		return eventRequest{}, err
	}
	parts := strings.Fields(requestLine)
	if len(parts) != 3 || parts[2] != "RTSP/1.0" {
		return eventRequest{}, fmt.Errorf("invalid event request line %q", requestLine)
	}

	request := eventRequest{
		method: parts[0],
		path:   parts[1],
	}
	contentLength := 0
	hasCSeq := false
	for {
		line, size, err := readEventLine(reader, eventHeaderSizeLimit-used)
		if err != nil {
			return eventRequest{}, err
		}
		used += size
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return eventRequest{}, fmt.Errorf("invalid event header %q", line)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch name {
		case "content-length":
			contentLength, err = strconv.Atoi(value)
			if err != nil || contentLength < 0 || contentLength > eventBodySizeLimit {
				return eventRequest{}, fmt.Errorf("invalid event content length %q", value)
			}
		case "cseq":
			request.cseq, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				return eventRequest{}, fmt.Errorf("invalid event CSeq %q", value)
			}
			hasCSeq = true
		case "content-type":
			request.contentType = value
		}
	}
	if !hasCSeq {
		return eventRequest{}, fmt.Errorf("event request omitted CSeq")
	}

	request.bodyLength = contentLength
	if contentLength > 0 {
		request.body = make([]byte, contentLength)
		if _, err := io.ReadFull(reader, request.body); err != nil {
			return eventRequest{}, fmt.Errorf("read event body: %w", err)
		}
	}
	return request, nil
}

// readEventLine reads one CRLF-terminated line without allowing bufio to grow
// an unbounded allocation for malformed input. The returned size includes CRLF.
func readEventLine(reader *bufio.Reader, limit int) (string, int, error) {
	if limit <= 0 {
		return "", 0, fmt.Errorf("event headers exceed %d bytes", eventHeaderSizeLimit)
	}
	var data []byte
	for {
		fragment, err := reader.ReadSlice('\n')
		if len(data)+len(fragment) > limit {
			return "", 0, fmt.Errorf("event headers exceed %d bytes", eventHeaderSizeLimit)
		}
		data = append(data, fragment...)
		if err == nil {
			break
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return "", 0, err
		}
	}
	if len(data) < 2 || data[len(data)-2] != '\r' {
		return "", 0, fmt.Errorf("event header line is not CRLF terminated")
	}
	return string(data[:len(data)-2]), len(data), nil
}

// handleEventRequest applies the only receiver command that affects the media
// clock. AirPlayReceiver sends this as a binary plist containing
// {type: "updateTimingPeerInfo", value: <timingPeerInfo>} after asynchronous
// PTP setup or a timing-peer change.
func handleEventRequest(request eventRequest, clock *mediaClock, receivedAt time.Time) error {
	if clock == nil || request.method != "POST" || request.path != "/command" || len(request.body) == 0 {
		return nil
	}
	mediaType, _, _ := strings.Cut(request.contentType, ";")
	if mediaType != "" && !strings.EqualFold(strings.TrimSpace(mediaType), "application/x-apple-binary-plist") {
		return nil
	}

	var command map[string]interface{}
	if _, err := plist.Unmarshal(request.body, &command); err != nil {
		return fmt.Errorf("decode event command: %w", err)
	}
	commandType, _ := command["type"].(string)
	if commandType != "updateTimingPeerInfo" {
		return nil
	}
	peer, ok := command["value"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("updateTimingPeerInfo omitted value dictionary")
	}
	return clock.updateTimingPeerInfo(peer, receivedAt)
}

// serveEventChannel acknowledges receiver-to-sender commands until teardown.
// Command decoding is deliberately best-effort: Apple receivers expect a 200
// acknowledgement even when a command is irrelevant to this sender.
func serveEventChannel(ctx context.Context, channel *eventChannel, clock *mediaClock) error {
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = channel.conn.Close()
		case <-done:
		}
	}()
	defer close(done)

	reader := bufio.NewReaderSize(channel, 4096)
	for {
		request, err := readEventRequest(reader)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		receivedAt := time.Now()

		dbg("[EVENT] <- %s %s CSeq=%d body=%d", request.method, request.path, request.cseq, request.bodyLength)
		if err := handleEventRequest(request, clock, receivedAt); err != nil {
			dbg("[EVENT] command ignored: %v", err)
		}

		response := fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: %d\r\nContent-Length: 0\r\n\r\n", request.cseq)
		if _, err := channel.Write([]byte(response)); err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("write event response: %w", err)
		}
		dbg("[EVENT] -> 200 CSeq=%d", request.cseq)
	}
}
