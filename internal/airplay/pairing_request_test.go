package airplay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestPairHeadersAdvertiseIdentityAndPairingType(t *testing.T) {
	const pairingID = "12345678-1234-4234-8234-123456789abc"
	wantClientName := pairingClientName()

	for _, tt := range []struct {
		name         string
		pairType     int
		wantHKP      string
		wantIdentity bool
	}{
		{name: "zero value defaults to screen capture", wantHKP: "5", wantIdentity: true},
		{name: "PIN screen capture", pairType: pairingTypeScreenCapture, wantHKP: "5", wantIdentity: true},
		{name: "transient", pairType: pairingTypeTransient, wantHKP: "4", wantIdentity: true},
		{name: "legacy", pairType: pairingTypeLegacy, wantHKP: "3"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &AirPlayClient{
				PairingID: pairingID,
				pairType:  tt.pairType,
			}

			headers := client.pairHeaders()
			if got := headers["X-Apple-HKP"]; got != tt.wantHKP {
				t.Fatalf("X-Apple-HKP = %q, want %q", got, tt.wantHKP)
			}
			wantClientID := ""
			wantName := ""
			if tt.wantIdentity {
				wantClientID = pairingID
				wantName = wantClientName
			}
			if got := headers["X-Apple-Client-ID"]; got != wantClientID {
				t.Fatalf("X-Apple-Client-ID = %q, want %q", got, wantClientID)
			}
			if got := headers["X-Apple-Client-Name"]; got != wantName {
				t.Fatalf("X-Apple-Client-Name = %q, want %q", got, wantName)
			}
		})
	}
}

func TestPairVerifyHeadersAdvertisePairedDevice(t *testing.T) {
	client := &AirPlayClient{PairingID: "12345678-1234-4234-8234-123456789abc"}
	headers := client.pairVerifyHeaders()

	if got := headers["X-Apple-PD"]; got != "1" {
		t.Fatalf("X-Apple-PD = %q, want %q", got, "1")
	}
	if got := headers["X-Apple-HKP"]; got != "5" {
		t.Fatalf("X-Apple-HKP = %q, want %q", got, "5")
	}
}

func TestLegacyHAPPairVerifyKeyMixingFollowsCapabilities(t *testing.T) {
	legacy := receiverWithFeatures(27)
	coreUtils38 := receiverWithFeatures(27, 38)
	coreUtils43 := receiverWithFeatures(27, 43)
	coreUtils46 := receiverWithFeatures(27, 46)
	coreUtils48 := receiverWithFeatures(27, 48)
	emulator := receiverWithFeatures()
	for _, test := range []struct {
		name   string
		info   *ReceiverInfo
		wantPD string
	}{
		{name: "unknown capabilities", wantPD: "1"},
		{name: "original legacy pairing", info: &legacy},
		{name: "CoreUtils bit 38 and legacy pairing", info: &coreUtils38, wantPD: "1"},
		{name: "CoreUtils bit 43 and legacy pairing", info: &coreUtils43, wantPD: "1"},
		{name: "CoreUtils bit 46 and legacy pairing", info: &coreUtils46, wantPD: "1"},
		{name: "CoreUtils bit 48 and legacy pairing", info: &coreUtils48, wantPD: "1"},
		{name: "emulated legacy protocol", info: &emulator, wantPD: "1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &AirPlayClient{
				PairingID: "12345678-1234-4234-8234-123456789abc",
				pairType:  pairingTypeLegacy,
				info:      test.info,
			}
			headers := client.pairVerifyHeaders()
			if headers["X-Apple-HKP"] != "3" || headers["X-Apple-PD"] != test.wantPD {
				t.Fatalf("legacy HAP pair-verify headers = %#v, want HKP 3 and PD %q", headers, test.wantPD)
			}
		})
	}
}

func TestPairingTypeFollowsReceiverProfile(t *testing.T) {
	const rokuFeatures = uint64(0x38bcf46007f8ad0)

	for _, tt := range []struct {
		name          string
		info          *ReceiverInfo
		wantTransient int
		wantPIN       int
	}{
		{
			name:          "modern Apple",
			info:          &ReceiverInfo{Features: FeatureSystemPairing | FeatureTransientPairing},
			wantTransient: pairingTypeTransient,
			wantPIN:       pairingTypeScreenCapture,
		},
		{
			name:          "Roku",
			info:          &ReceiverInfo{Features: rokuFeatures},
			wantTransient: pairingTypeLegacy,
			wantPIN:       pairingTypeLegacy,
		},
		{
			name:          "legacy or unknown receiver",
			info:          &ReceiverInfo{},
			wantTransient: pairingTypeLegacy,
			wantPIN:       pairingTypeLegacy,
		},
		{
			name:          "missing receiver info",
			wantTransient: pairingTypeTransient,
			wantPIN:       pairingTypeScreenCapture,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client := &AirPlayClient{info: tt.info}
			if got := client.transientPairingType(); got != tt.wantTransient {
				t.Fatalf("transientPairingType() = %d, want %d", got, tt.wantTransient)
			}
			if got := client.pinPairingType(); got != tt.wantPIN {
				t.Fatalf("pinPairingType() = %d, want %d", got, tt.wantPIN)
			}
			client.pairType = pairingTypeScreenCapture
			if got := client.effectivePairType(); got != tt.wantPIN {
				t.Fatalf("effectivePairType() = %d, want %d", got, tt.wantPIN)
			}
		})
	}
}

func TestSanitizePairingClientName(t *testing.T) {
	for _, tt := range []struct {
		name     string
		hostname string
		want     string
	}{
		{name: "hostname", hostname: "living-room-mac", want: "living-room-mac"},
		{name: "trim surrounding spaces", hostname: "  living-room-mac  ", want: "living-room-mac"},
		{name: "empty", want: defaultPairingClientName},
		{name: "whitespace", hostname: "   ", want: defaultPairingClientName},
		{name: "header injection", hostname: "living-room\r\nX-Forged: value", want: defaultPairingClientName},
		{name: "control character", hostname: "living-room\x00", want: defaultPairingClientName},
		{name: "invalid UTF-8", hostname: string([]byte{0xff}), want: defaultPairingClientName},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizePairingClientName(tt.hostname); got != tt.want {
				t.Fatalf("sanitizePairingClientName(%q) = %q, want %q", tt.hostname, got, tt.want)
			}
		})
	}
}

func TestStartPINDisplayAccepts453AndDrainsBody(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	const pairingID = "12345678-1234-4234-8234-123456789abc"
	wantClientName := pairingClientName()
	client := &AirPlayClient{
		conn:      clientConn,
		PairingID: pairingID,
		pairType:  pairingTypeTransient,
	}

	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		reader := bufio.NewReader(serverConn)
		request, err := readRTSPTestRequest(reader)
		if err != nil {
			serverDone <- fmt.Errorf("read PIN-start request: %w", err)
			return
		}
		if request.method != "POST" || request.uri != "/pair-pin-start" {
			serverDone <- fmt.Errorf("request = %s %s, want POST /pair-pin-start", request.method, request.uri)
			return
		}
		if len(request.body) != 0 {
			serverDone <- fmt.Errorf("PIN-start body length = %d, want 0", len(request.body))
			return
		}
		for header, want := range map[string]string{
			"x-apple-hkp":                 "5",
			"x-apple-client-id":           pairingID,
			"x-apple-client-name":         wantClientName,
			"x-apple-supportedpinlengths": "4",
		} {
			if got := request.headers[header]; got != want {
				serverDone <- fmt.Errorf("%s = %q, want %q", header, got, want)
				return
			}
		}

		// A non-empty body proves that accepting 453 does not leave response bytes
		// queued ahead of the next RTSP response on the retained connection.
		if err := writeRTSPTestResponse(serverConn, 453, nil, []byte("pending")); err != nil {
			serverDone <- fmt.Errorf("write 453 response: %w", err)
			return
		}

		request, err = readRTSPTestRequest(reader)
		if err != nil {
			serverDone <- fmt.Errorf("read request after 453: %w", err)
			return
		}
		if request.method != "GET" || request.uri != "/info" {
			serverDone <- fmt.Errorf("request after 453 = %s %s, want GET /info", request.method, request.uri)
			return
		}
		if err := writeRTSPTestResponse(serverConn, 200, nil, nil); err != nil {
			serverDone <- fmt.Errorf("write response after 453: %w", err)
			return
		}
		serverDone <- nil
	}()

	if err := client.StartPINDisplay(); err != nil {
		t.Fatalf("StartPINDisplay returned error for HTTP 453: %v", err)
	}
	if client.pairType != pairingTypeScreenCapture {
		t.Fatalf("pairType after StartPINDisplay = %d, want %d", client.pairType, pairingTypeScreenCapture)
	}
	if _, err := client.httpRequest("GET", "/info", "", nil); err != nil {
		t.Fatalf("request after HTTP 453 failed; response body may not have been drained: %v", err)
	}
	waitPairingTestServer(t, serverDone)
}

func TestStartPINDisplayRejectsOtherHTTPStatuses(t *testing.T) {
	for _, status := range []int{400, 403, 455, 500} {
		t.Run(fmt.Sprintf("HTTP_%d", status), func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			client := &AirPlayClient{
				conn:      clientConn,
				PairingID: "12345678-1234-4234-8234-123456789abc",
			}
			serverDone := make(chan error, 1)
			go func() {
				defer serverConn.Close()
				request, err := readRTSPTestRequest(bufio.NewReader(serverConn))
				if err != nil {
					serverDone <- err
					return
				}
				if request.uri != "/pair-pin-start" {
					serverDone <- fmt.Errorf("request URI = %q, want /pair-pin-start", request.uri)
					return
				}
				serverDone <- writeRTSPTestResponse(serverConn, status, nil, []byte("rejected"))
			}()

			err := client.StartPINDisplay()
			if err == nil {
				t.Fatalf("StartPINDisplay returned nil for HTTP %d", status)
			}
			var statusErr *HTTPStatusError
			if !errors.As(err, &statusErr) {
				t.Fatalf("error %T (%v) does not wrap HTTPStatusError", err, err)
			}
			if statusErr.StatusCode != status {
				t.Fatalf("status = %d, want %d", statusErr.StatusCode, status)
			}
			if got := string(statusErr.Body); got != "rejected" {
				t.Fatalf("error body = %q, want %q", got, "rejected")
			}
			waitPairingTestServer(t, serverDone)
		})
	}
}

func TestPairTransientStopsWhenReceiverRequiresPINPairing(t *testing.T) {
	client := &AirPlayClient{
		info: &ReceiverInfo{
			Features:    FeatureSystemPairing,
			StatusFlags: statusFlagPINRequiredForPairing,
		},
	}

	err := client.Pair(context.Background(), "")
	if !errors.Is(err, ErrPINRequired) {
		t.Fatalf("Pair without PIN returned %v, want ErrPINRequired", err)
	}
	if client.PairKeys != nil {
		t.Fatal("PIN-required guard generated transient pairing keys")
	}
	if client.pairType == pairingTypeTransient {
		t.Fatal("PIN-required guard entered transient pairing mode")
	}

	if (&ReceiverInfo{}).RequiresPINPairing() {
		t.Fatal("receiver without PIN-required status flag reports PIN pairing")
	}
	if (&ReceiverInfo{StatusFlags: 1 << 3}).RequiresPINPairing() {
		t.Fatal("per-session PIN status flag reports one-time PIN pairing")
	}
	if !(&ReceiverInfo{StatusFlags: statusFlagPasswordRequired}).RequiresPassword() {
		t.Fatal("configured-password status flag did not report a required password")
	}
	if (&ReceiverInfo{StatusFlags: statusFlagPINRequiredForPairing}).RequiresPassword() {
		t.Fatal("one-time PIN status flag reports a configured password")
	}
	if !(&ReceiverInfo{
		Features:    0x38bcf46007f8ad0,
		StatusFlags: statusFlagPINRequiredForPairing,
	}).RequiresPINPairing() {
		t.Fatal("Roku one-time-pairing status did not request a PIN")
	}
	if (*ReceiverInfo)(nil).RequiresPINPairing() {
		t.Fatal("nil ReceiverInfo reports PIN pairing")
	}
	if (*ReceiverInfo)(nil).RequiresPassword() {
		t.Fatal("nil ReceiverInfo reports a configured password")
	}
}

func TestRequiredPairingCredential(t *testing.T) {
	const modernFeatures = FeatureSystemPairing | FeatureTransientPairing | uint64(1<<38) | uint64(1<<46)
	const legacyFeatures = modernFeatures | uint64(1<<51)

	for _, test := range []struct {
		name   string
		info   *ReceiverInfo
		wanted PairingCredential
	}{
		{name: "missing info"},
		{name: "modern transient", info: &ReceiverInfo{Features: modernFeatures}},
		{name: "modern fixed password is Digest only", info: &ReceiverInfo{Features: modernFeatures, StatusFlags: statusFlagPasswordRequired}},
		{name: "modern PIN only", info: &ReceiverInfo{Features: modernFeatures, StatusFlags: statusFlagPINRequiredForPairing}, wanted: PairingCredentialPIN},
		{name: "modern password suppresses PIN", info: &ReceiverInfo{Features: modernFeatures, StatusFlags: statusFlagPasswordRequired | statusFlagPINRequiredForPairing}},
		{name: "legacy fixed password", info: &ReceiverInfo{Features: legacyFeatures, StatusFlags: statusFlagPasswordRequired}, wanted: PairingCredentialPassword},
		{name: "legacy PIN only", info: &ReceiverInfo{Features: legacyFeatures, StatusFlags: statusFlagPINRequiredForPairing}, wanted: PairingCredentialPIN},
		{name: "legacy password wins over PIN", info: &ReceiverInfo{Features: legacyFeatures, StatusFlags: statusFlagPasswordRequired | statusFlagPINRequiredForPairing}, wanted: PairingCredentialPassword},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := test.info.RequiredPairingCredential(); got != test.wanted {
				t.Fatalf("RequiredPairingCredential() = %d, want %d", got, test.wanted)
			}
		})
	}
}

func TestModernPasswordAndPINFlagsStillStartTransientPairing(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	deadline := time.Now().Add(5 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	client := &AirPlayClient{
		conn: clientConn,
		info: &ReceiverInfo{
			Features:    FeatureSystemPairing | FeatureTransientPairing | uint64(1<<38) | uint64(1<<46),
			StatusFlags: statusFlagPasswordRequired | statusFlagPINRequiredForPairing,
		},
	}

	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		request, err := readRTSPTestRequest(bufio.NewReader(serverConn))
		if err != nil {
			serverDone <- err
			return
		}
		if request.method != "POST" || request.uri != "/pair-setup" {
			serverDone <- fmt.Errorf("request = %s %s, want POST /pair-setup", request.method, request.uri)
			return
		}
		if got := request.headers["x-apple-hkp"]; got != "4" {
			serverDone <- fmt.Errorf("X-Apple-HKP = %q, want transient type 4", got)
			return
		}
		message := tlv8Decode(request.body)
		if !bytes.Equal(message[tlvState], []byte{1}) ||
			!bytes.Equal(message[tlvMethod], []byte{0}) ||
			len(message[tlvFlags]) != 4 ||
			binary.LittleEndian.Uint32(message[tlvFlags]) != pairingFlagTransient {
			serverDone <- fmt.Errorf("pair-setup M1 is not transient: %x", request.body)
			return
		}
		serverDone <- writeRTSPTestResponse(serverConn, 500, nil, nil)
	}()

	if err := client.Pair(context.Background(), ""); err == nil {
		t.Fatal("Pair succeeded after the scripted receiver rejected transient setup")
	} else if errors.Is(err, ErrPINRequired) {
		t.Fatalf("modern password+PIN flags incorrectly required full PIN pairing: %v", err)
	}
	waitPairingTestServer(t, serverDone)
}

func TestRokuTransientPairingStartsWithRawProtocol(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	deadline := time.Now().Add(5 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	client := &AirPlayClient{
		conn: clientConn,
		info: &ReceiverInfo{
			Features: 0x38bcf46007f8ad0,
		},
	}

	serverDone := make(chan error, 1)
	go func() {
		defer serverConn.Close()
		request, err := readRTSPTestRequest(bufio.NewReader(serverConn))
		if err != nil {
			serverDone <- err
			return
		}
		if request.method != "POST" || request.uri != "/pair-setup" {
			serverDone <- fmt.Errorf("request = %s %s, want POST /pair-setup", request.method, request.uri)
			return
		}
		if len(request.body) != 32 {
			serverDone <- fmt.Errorf("first pair-setup body = %d bytes, want 32-byte raw public key", len(request.body))
			return
		}
		if got := request.headers["x-apple-hkp"]; got != "" {
			serverDone <- fmt.Errorf("raw pair-setup X-Apple-HKP = %q, want empty", got)
			return
		}
		serverDone <- writeRTSPTestResponse(serverConn, 500, nil, nil)
	}()

	if err := client.Pair(context.Background(), ""); err == nil {
		t.Fatal("Pair succeeded after the scripted receiver rejected raw setup")
	} else if errors.Is(err, ErrPINRequired) {
		t.Fatalf("Roku pairing returned ErrPINRequired instead of probing raw setup: %v", err)
	}
	waitPairingTestServer(t, serverDone)
}

func waitPairingTestServer(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for pairing test server")
	}
}
