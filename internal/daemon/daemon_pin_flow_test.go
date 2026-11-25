package daemon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"doubletake/internal/airplay"
	"howett.net/plist"
)

type pinFlowRequest struct {
	method  string
	path    string
	headers map[string]string
	body    []byte
}

type pinFlowServerResult struct {
	requests []pinFlowRequest
	err      error
}

func TestPINRequiredPairingStaysOnOriginalConnection(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	infoBody, err := plist.Marshal(map[string]any{
		"name":        "PIN TV",
		"model":       "AppleTV-Test",
		"deviceID":    "00:11:22:33:44:55",
		"features":    uint64(airplay.FeatureSystemPairing),
		"statusFlags": uint64(0x200),
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("encode /info response: %v", err)
	}

	requestSeen := make(chan pinFlowRequest, 3)
	serverDone := make(chan pinFlowServerResult, 1)
	go runPINFlowReceiver(listener, infoBody, requestSeen, serverDone)

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split receiver address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse receiver port: %v", err)
	}

	d, err := New(Config{
		CredBackend: "file",
		CredFile:    filepath.Join(t.TempDir(), "credentials.json"),
		NoAudio:     true,
	})
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	t.Cleanup(d.Shutdown)

	response := d.handleConnect(Request{Cmd: "connect", Target: host, Port: port})
	if !response.OK {
		t.Fatalf("initial connect rejected: %+v", response)
	}

	first := pinFlowNextRequest(t, requestSeen)
	if first.method != "GET" || first.path != "/info" {
		t.Fatalf("first request = %s %s, want GET /info", first.method, first.path)
	}
	second := pinFlowNextRequest(t, requestSeen)
	if second.method != "POST" || second.path != "/pair-pin-start" {
		t.Fatalf("second request = %s %s, want POST /pair-pin-start", second.method, second.path)
	}
	if len(second.body) != 0 {
		t.Fatalf("PIN-start body length = %d, want 0", len(second.body))
	}
	for header, want := range map[string]string{
		"x-apple-hkp":                 "5",
		"x-apple-supportedpinlengths": "4",
	} {
		if got := second.headers[header]; got != want {
			t.Fatalf("PIN-start %s = %q, want %q", header, got, want)
		}
	}
	clientID := second.headers["x-apple-client-id"]
	if clientID == "" {
		t.Fatal("PIN-start has no X-Apple-Client-ID header")
	}
	clientName := second.headers["x-apple-client-name"]
	if clientName == "" {
		t.Fatal("PIN-start has no X-Apple-Client-Name header")
	}

	pinFlowWaitForState(t, d, StatePINRequired)
	status := d.handleStatus()
	if !status.NeedsCredential || !status.NeedsPIN || status.CredentialKind != CredentialKindPIN {
		t.Fatalf("PIN status metadata = %+v", status)
	}
	if status.Device != "PIN TV" || status.DeviceIP != host {
		t.Fatalf("PIN status target = %q (%q), want PIN TV (%q)", status.Device, status.DeviceIP, host)
	}
	if len(status.Streams) != 1 || status.Streams[0].CredentialKind != CredentialKindPIN {
		t.Fatalf("PIN stream metadata = %+v", status.Streams)
	}
	response = d.handleConnect(Request{Cmd: "connect", Pin: "1234"})
	if !response.OK {
		t.Fatalf("PIN submission rejected: %+v", response)
	}

	third := pinFlowNextRequest(t, requestSeen)
	if third.method != "POST" || third.path != "/pair-setup" {
		t.Fatalf("third request = %s %s, want POST /pair-setup", third.method, third.path)
	}
	for header, want := range map[string]string{
		"x-apple-hkp":         "5",
		"x-apple-client-id":   clientID,
		"x-apple-client-name": clientName,
	} {
		if got := third.headers[header]; got != want {
			t.Fatalf("pair-setup %s = %q, want %q", header, got, want)
		}
	}
	if len(third.body) == 32 {
		t.Fatal("pair-setup M1 used the 32-byte raw/legacy probe")
	}
	if got := pinFlowTLVValue(third.body, 0x06); !bytes.Equal(got, []byte{0x01}) {
		t.Fatalf("pair-setup state TLV = %x, want 01", got)
	}
	if got := pinFlowTLVValue(third.body, 0x00); !bytes.Equal(got, []byte{0x00}) {
		t.Fatalf("pair-setup method TLV = %x, want 00", got)
	}
	if got := pinFlowTLVValue(third.body, 0x13); got != nil {
		t.Fatalf("pair-setup M1 unexpectedly contains transient flags: %x", got)
	}

	result := pinFlowServerResultWithin(t, serverDone)
	if result.err != nil {
		t.Fatalf("scripted receiver: %v", result.err)
	}
	if len(result.requests) != 3 {
		t.Fatalf("request count = %d, want 3", len(result.requests))
	}
	for i, request := range result.requests {
		if request.headers["cseq"] == "" {
			t.Fatalf("request %d has no CSeq header", i+1)
		}
	}

	// The scripted 500 response terminates pairing before FairPlay or capture.
	// Waiting for idle also proves the connection goroutine consumed that response.
	pinFlowWaitForState(t, d, StateIdle)
}

func TestModernPasswordAndPINFlagsUseTransientPairingWithoutStartingDisplay(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	infoBody, err := plist.Marshal(map[string]any{
		"name":        "Password TV",
		"model":       "AppleTV-Test",
		"deviceID":    "00:11:22:33:44:66",
		"features":    airplay.FeatureScreen | airplay.FeatureSystemPairing | airplay.FeatureTransientPairing | 1<<38 | 1<<46,
		"statusFlags": uint64(0x280), // configured password and on-screen PIN
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("encode /info response: %v", err)
	}

	requestSeen := make(chan pinFlowRequest, 3)
	serverDone := make(chan pinFlowServerResult, 1)
	go runPasswordPrecedenceReceiver(listener, infoBody, requestSeen, serverDone)

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split receiver address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse receiver port: %v", err)
	}

	d, err := New(Config{
		CredBackend: "file",
		CredFile:    filepath.Join(t.TempDir(), "credentials.json"),
		NoAudio:     true,
	})
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	t.Cleanup(d.Shutdown)

	response := d.handleConnect(Request{Cmd: "connect", Target: host, Port: port})
	if !response.OK {
		t.Fatalf("initial connect rejected: %+v", response)
	}

	request := pinFlowNextRequest(t, requestSeen)
	if request.method != "GET" || request.path != "/info" {
		t.Fatalf("first request = %s %s, want GET /info", request.method, request.path)
	}

	request = pinFlowNextRequest(t, requestSeen)
	if request.method != "POST" || request.path != "/pair-setup" {
		t.Fatalf("request after /info = %s %s, want transient POST /pair-setup", request.method, request.path)
	}
	if got := request.headers["x-apple-hkp"]; got != "4" {
		t.Fatalf("pair-setup X-Apple-HKP = %q, want transient type 4", got)
	}
	if got := pinFlowTLVValue(request.body, 0x13); !bytes.Equal(got, []byte{0x10, 0, 0, 0}) {
		t.Fatalf("pair-setup transient flags = %x, want 10000000", got)
	}

	result := pinFlowServerResultWithin(t, serverDone)
	if result.err != nil {
		t.Fatalf("scripted receiver: %v", result.err)
	}
	for _, request := range result.requests {
		if request.path == "/pair-pin-start" {
			t.Fatalf("modern password+PIN flow called /pair-pin-start: %+v", result.requests)
		}
	}
	pinFlowWaitForState(t, d, StateIdle)
}

func TestSubmittedPasswordCompletesPairingWithoutSecondPrompt(t *testing.T) {
	const password = "password with spaces"
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0",
		Profile:       airplay.ReceiverProfileRoku,
		Auth:          airplay.ReceiverAuthCombined,
		Code:          password,
		Logger:        log.New(io.Discard, "", 0),
	})
	if err != nil {
		t.Fatalf("create receiver: %v", err)
	}
	receiverCtx, cancelReceiver := context.WithCancel(context.Background())
	receiverDone := make(chan error, 1)
	go func() { receiverDone <- server.Serve(receiverCtx) }()
	t.Cleanup(func() {
		cancelReceiver()
		_ = server.Close()
		select {
		case err := <-receiverDone:
			if err != nil {
				t.Errorf("receiver Serve: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("receiver did not stop")
		}
	})

	addr := server.Addr().(*net.TCPAddr)
	d, err := New(Config{
		CredBackend: "file",
		CredFile:    filepath.Join(t.TempDir(), "credentials.json"),
		NoAudio:     true,
		TestMode:    true,
	})
	if err != nil {
		t.Fatalf("create daemon: %v", err)
	}
	t.Cleanup(d.Shutdown)

	response := d.handleConnect(Request{Cmd: "connect", Target: addr.IP.String(), Port: addr.Port})
	if !response.OK {
		t.Fatalf("initial connect rejected: %+v", response)
	}
	pinFlowWaitForState(t, d, StatePINRequired)
	status := d.handleStatus()
	if !status.NeedsCredential || status.NeedsPIN || status.CredentialKind != CredentialKindPassword {
		t.Fatalf("password status metadata = %+v", status)
	}
	if starts := server.Stats().PINStarts; starts != 0 {
		t.Fatalf("PIN-start requests before password submission = %d, want 0", starts)
	}

	response = d.handleConnect(Request{Cmd: "connect", Pin: password})
	if !response.OK {
		t.Fatalf("password submission rejected: %+v", response)
	}

	deadline := time.Now().Add(8 * time.Second)
	for {
		stats := server.Stats()
		// Stop at pair-verify: capture intentionally starts before SETUP in the
		// daemon, and CI does not install a GStreamer encoder. Digest reuse is
		// covered without capture by TestReceiverServerCombinedCodePairsAndAnswersDigest.
		if stats.PairSetup == 3 && stats.PairVerify == 2 {
			if stats.PINStarts != 0 {
				t.Fatalf("password flow sent %d PIN-start requests, want 0", stats.PINStarts)
			}
			break
		}
		status = d.handleStatus()
		if status.NeedsCredential {
			t.Fatalf("daemon prompted a second time after password submission: %+v", status)
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for authenticated pairing: receiver stats %+v, daemon status %+v", stats, status)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func runPINFlowReceiver(listener net.Listener, infoBody []byte, requestSeen chan<- pinFlowRequest, done chan<- pinFlowServerResult) {
	result := pinFlowServerResult{}
	finish := func(err error) {
		result.err = err
		done <- result
	}

	conn, err := listener.Accept()
	if err != nil {
		finish(fmt.Errorf("accept initial connection: %w", err))
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)

	steps := []struct {
		method string
		path   string
		status int
		body   []byte
	}{
		{method: "GET", path: "/info", status: 200, body: infoBody},
		{method: "POST", path: "/pair-pin-start", status: 200},
		{method: "POST", path: "/pair-setup", status: 500},
	}

	for i, step := range steps {
		request, err := readPINFlowRequest(conn, reader)
		if err != nil {
			finish(fmt.Errorf("read request %d: %w", i+1, err))
			return
		}
		result.requests = append(result.requests, request)
		requestSeen <- request
		if request.method != step.method || request.path != step.path {
			finish(fmt.Errorf("request %d = %s %s, want %s %s", i+1, request.method, request.path, step.method, step.path))
			return
		}
		contentType := ""
		if i == 0 {
			contentType = "application/x-apple-binary-plist"
		}
		if err := writePINFlowResponse(conn, request.headers["cseq"], step.status, contentType, step.body); err != nil {
			finish(fmt.Errorf("write response %d: %w", i+1, err))
			return
		}
	}

	finish(nil)
}

func runPasswordPrecedenceReceiver(listener net.Listener, infoBody []byte, requestSeen chan<- pinFlowRequest, done chan<- pinFlowServerResult) {
	result := pinFlowServerResult{}
	finish := func(err error) {
		result.err = err
		done <- result
	}

	conn, err := listener.Accept()
	if err != nil {
		finish(fmt.Errorf("accept connection: %w", err))
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	request, err := readPINFlowRequest(conn, reader)
	if err != nil {
		finish(fmt.Errorf("read /info: %w", err))
		return
	}
	result.requests = append(result.requests, request)
	requestSeen <- request
	if request.method != "GET" || request.path != "/info" {
		finish(fmt.Errorf("first request = %s %s, want GET /info", request.method, request.path))
		return
	}
	if err := writePINFlowResponse(conn, request.headers["cseq"], 200, "application/x-apple-binary-plist", infoBody); err != nil {
		finish(fmt.Errorf("write /info: %w", err))
		return
	}

	request, err = readPINFlowRequest(conn, reader)
	if err != nil {
		finish(fmt.Errorf("read password pair-setup: %w", err))
		return
	}
	result.requests = append(result.requests, request)
	requestSeen <- request
	if request.method != "POST" || request.path != "/pair-setup" {
		finish(fmt.Errorf("password request = %s %s, want POST /pair-setup", request.method, request.path))
		return
	}
	if err := writePINFlowResponse(conn, request.headers["cseq"], 500, "", nil); err != nil {
		finish(fmt.Errorf("write pair-setup response: %w", err))
		return
	}

	finish(nil)
}

func readPINFlowRequest(conn net.Conn, reader *bufio.Reader) (pinFlowRequest, error) {
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return pinFlowRequest{}, err
	}
	defer conn.SetReadDeadline(time.Time{})

	line, err := reader.ReadString('\n')
	if err != nil {
		return pinFlowRequest{}, err
	}
	parts := strings.Fields(line)
	if len(parts) < 2 {
		return pinFlowRequest{}, fmt.Errorf("malformed request line %q", strings.TrimSpace(line))
	}
	request := pinFlowRequest{
		method:  parts[0],
		path:    parts[1],
		headers: make(map[string]string),
	}
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return pinFlowRequest{}, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return pinFlowRequest{}, fmt.Errorf("malformed header %q", line)
		}
		request.headers[strings.ToLower(strings.TrimSpace(key))] = strings.TrimSpace(value)
	}

	contentLength := 0
	if value := request.headers["content-length"]; value != "" {
		contentLength, err = strconv.Atoi(value)
		if err != nil || contentLength < 0 {
			return pinFlowRequest{}, fmt.Errorf("invalid Content-Length %q", value)
		}
	}
	request.body = make([]byte, contentLength)
	if _, err := io.ReadFull(reader, request.body); err != nil {
		return pinFlowRequest{}, err
	}
	return request, nil
}

func writePINFlowResponse(conn net.Conn, cseq string, status int, contentType string, body []byte) error {
	reason := "OK"
	if status == 500 {
		reason = "Internal Server Error"
	}
	var response bytes.Buffer
	fmt.Fprintf(&response, "RTSP/1.0 %d %s\r\n", status, reason)
	if cseq != "" {
		fmt.Fprintf(&response, "CSeq: %s\r\n", cseq)
	}
	if contentType != "" {
		fmt.Fprintf(&response, "Content-Type: %s\r\n", contentType)
	}
	fmt.Fprintf(&response, "Content-Length: %d\r\n\r\n", len(body))
	response.Write(body)
	_, err := conn.Write(response.Bytes())
	return err
}

func pinFlowTLVValue(body []byte, tag byte) []byte {
	for len(body) >= 2 {
		length := int(body[1])
		if length > len(body)-2 {
			return nil
		}
		if body[0] == tag {
			return body[2 : 2+length]
		}
		body = body[2+length:]
	}
	return nil
}

func pinFlowNextRequest(t *testing.T, requests <-chan pinFlowRequest) pinFlowRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for receiver request")
		return pinFlowRequest{}
	}
}

func pinFlowServerResultWithin(t *testing.T, results <-chan pinFlowServerResult) pinFlowServerResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for scripted receiver")
		return pinFlowServerResult{}
	}
}

func pinFlowWaitForState(t *testing.T, d *Daemon, want State) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := d.handleStatus().State; got == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("daemon state = %s, want %s", d.handleStatus().State, want)
}
