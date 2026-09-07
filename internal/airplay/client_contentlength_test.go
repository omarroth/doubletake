package airplay

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Hostile Content-Length values must be rejected before they can allocate a
// body or leave unframed bytes on the sequential control connection.
func TestReadResponseRejectsHostileContentLength(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   string
	}{
		{"negative", "Content-Length: -1", "invalid Content-Length"},
		{"negative zero", "Content-Length: -0", "invalid Content-Length"},
		{"explicit positive", "Content-Length: +5", "invalid Content-Length"},
		{"large negative", "Content-Length: -2147483648", "invalid Content-Length"},
		{"absurdly large", "Content-Length: 2147483647", "exceeds"},
		{"empty", "Content-Length:", "invalid Content-Length"},
		{"not a number", "Content-Length: nope", "invalid Content-Length"},
		{"trailing junk", "Content-Length: 5junk", "invalid Content-Length"},
		{"integer overflow", "Content-Length: 9999999999999999999999999999", "invalid Content-Length"},
		{"conflicting duplicates", "Content-Length: 0\r\nContent-Length: 5", "conflicting Content-Length"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()

			go func() {
				server.Write([]byte("RTSP/1.0 200 OK\r\n" + tc.header + "\r\n\r\n"))
				time.Sleep(time.Second)
			}()

			c := &AirPlayClient{conn: client}
			done := make(chan error, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panicked instead of returning an error: %v", r)
						done <- nil
					}
				}()
				_, _, err := c.readHTTPResponseWithTimeout(time.Second)
				done <- err
			}()

			select {
			case err := <-done:
				if err == nil {
					t.Fatal("expected an error")
				}
				if !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("error %q does not mention %q", err, tc.want)
				}
				if !hasIncompleteResponse(err) {
					t.Fatalf("invalid response boundary was not marked incomplete: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timed out")
			}
		})
	}
}

func TestReadResponseAcceptsMatchingDuplicateContentLength(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte("RTSP/1.0 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello"))
	}()

	c := &AirPlayClient{conn: client}
	body, _, err := c.readPlaintextHTTPResponse()
	if err != nil {
		t.Fatalf("matching Content-Length values were rejected: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want hello", body)
	}
}

// A well-formed response must still be read normally.
func TestReadResponseAcceptsValidContentLength(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		server.Write([]byte("RTSP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello"))
		time.Sleep(time.Second)
	}()

	c := &AirPlayClient{conn: client}
	body, headers, err := c.readPlaintextHTTPResponse()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want %q", body, "hello")
	}
	if headers["content-length"] != "5" {
		t.Fatalf("content-length header = %q", headers["content-length"])
	}
}

func TestValidateContentLength(t *testing.T) {
	for _, tc := range []struct {
		n  int
		ok bool
	}{
		{-1, false}, {0, true}, {1, true},
		{maxResponseBody, true}, {maxResponseBody + 1, false},
	} {
		if err := validateContentLength(tc.n); (err == nil) != tc.ok {
			t.Errorf("validateContentLength(%d): err=%v, want ok=%v", tc.n, err, tc.ok)
		}
	}
}

func TestReadPlaintextErrorRequiresCompleteBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = server.Write([]byte("RTSP/1.0 500 Error\r\nContent-Length: 5\r\n\r\nno"))
		_ = server.Close()
	}()

	c := &AirPlayClient{conn: client}
	_, _, err := c.readHTTPResponseWithTimeout(time.Second)
	if err == nil || !strings.Contains(err.Error(), "read error response body") {
		t.Fatalf("truncated plaintext error = %v, want body-read failure", err)
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		t.Fatalf("truncated plaintext error was misclassified as HTTP status: %v", err)
	}
}

func TestReadEncryptedErrorRequiresCompleteBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	key := make([]byte, chacha20poly1305.KeySize)
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("RTSP/1.0 500 Error\r\nContent-Length: 5\r\n\r\nno")
	length := make([]byte, 2)
	binary.LittleEndian.PutUint16(length, uint16(len(plaintext)))
	wire := append(append([]byte(nil), length...), aead.Seal(nil, make([]byte, 12), plaintext, length)...)
	go func() {
		_, _ = server.Write(wire)
		_ = server.Close()
	}()

	c := &AirPlayClient{conn: client, encrypted: true, encReadKey: key}
	_, _, err = c.readHTTPResponseWithTimeout(time.Second)
	if err == nil || !strings.Contains(err.Error(), "read encrypted error body") {
		t.Fatalf("truncated encrypted error = %v, want body-read failure", err)
	}
	var statusErr *HTTPStatusError
	if errors.As(err, &statusErr) {
		t.Fatalf("truncated encrypted error was misclassified as HTTP status: %v", err)
	}
}
