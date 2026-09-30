package airplay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

const testModernPairingFeatures = FeatureSystemPairing |
	FeatureTransientPairing |
	uint64(1<<38) |
	uint64(1<<46)

func TestTransientPairingFallsBackFromUnsupportedHAPToRawByProtocol(t *testing.T) {
	for _, identity := range []struct {
		name         string
		receiverName string
		model        string
		source       string
	}{
		{name: "generic identity", receiverName: "Living Room", model: "Receiver1,1"},
		// These strings exercised the old identity fingerprint. Capabilities now
		// select the first probe, and the response selects the actual protocol.
		{name: "formerly fingerprinted identity", receiverName: "AirServer Connect", model: "AppleTV5,3", source: "375.3"},
	} {
		t.Run(identity.name, func(t *testing.T) {
			state := newReceiverPairingTestState(t, "", newReceiverControllerStore())
			clientConn, serverConn := newPairingNegotiationPipe(t)
			defer clientConn.Close()
			defer serverConn.Close()

			client := &AirPlayClient{
				conn:      clientConn,
				PairingID: "12345678-1234-4234-8234-123456789abc",
				info: &ReceiverInfo{
					Name:          identity.receiverName,
					Model:         identity.model,
					SourceVersion: identity.source,
					Features:      testModernPairingFeatures,
					StatusFlags:   statusFlagPasswordRequired,
				},
			}

			serverDone := make(chan error, 1)
			go func() {
				serverDone <- serveHAPRejectionThenRawPairing(serverConn, state, 2, true)
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			const digestPassword = "digest-only password"
			if err := client.Pair(ctx, digestPassword); err != nil {
				t.Fatalf("Pair: %v", err)
			}
			// A later verification must use the protocol which actually succeeded,
			// rather than reclassifying the receiver from its name or feature mask.
			if err := client.PairVerify(ctx); err != nil {
				t.Fatalf("PairVerify after negotiated raw pairing: %v", err)
			}
			waitPairingTestServer(t, serverDone)

			if client.pairingProtocol != pairingProtocolRaw {
				t.Fatalf("pairing protocol = %d, want raw", client.pairingProtocol)
			}
			if got := client.effectivePairType(); got != pairingTypeLegacy {
				t.Fatalf("effective pairing type = %d, want legacy", got)
			}
			if client.encrypted {
				t.Fatal("raw pairing unexpectedly enabled HAP framing")
			}
			if client.PairKeys == nil || !client.PairKeys.MixFairPlayKey {
				t.Fatal("raw X-Apple-PD pairing did not record FairPlay key mixing")
			}
			if client.authPassword != digestPassword {
				t.Fatalf("Digest password = %q, want retained caller value", client.authPassword)
			}
		})
	}
}

func TestRawLegacyPairingOmitsPDAndDoesNotMixFairPlayKey(t *testing.T) {
	testRawLegacyPairingFairPlayKeyMixing(t, false)
}

// Some third-party receivers (e.g. Barco ClickShare) advertise feature 27 but
// require the mixed key; SetMixFairPlayKey must override the heuristic.
func TestRawLegacyPairingForcedMixSendsPDAndMixesFairPlayKey(t *testing.T) {
	testRawLegacyPairingFairPlayKeyMixing(t, true)
}

func testRawLegacyPairingFairPlayKeyMixing(t *testing.T, forceMix bool) {
	state := newReceiverPairingTestState(t, "", newReceiverControllerStore())
	clientConn, serverConn := newPairingNegotiationPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	client := &AirPlayClient{
		conn:      clientConn,
		PairingID: "12345678-1234-4234-8234-123456789abc",
		info: &ReceiverInfo{
			Name:     "Identity Does Not Select Pairing",
			Model:    "Arbitrary1,2",
			Features: FeatureLegacyPairing,
		},
	}
	client.SetMixFairPlayKey(forceMix)
	serverDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		for requestIndex := 0; requestIndex < 3; requestIndex++ {
			request, err := readRTSPTestRequest(reader)
			if err != nil {
				serverDone <- err
				return
			}
			wantPD := forceMix && request.uri == "/pair-verify"
			if got := request.headers["x-apple-pd"]; (got == "1") != wantPD || (!wantPD && got != "") {
				serverDone <- fmt.Errorf("request %d (%s) X-Apple-PD = %q, want present=%t", requestIndex+1, request.uri, got, wantPD)
				return
			}
			var response []byte
			switch request.uri {
			case "/pair-setup":
				response, err = state.pairSetup(request.body)
			case "/pair-verify":
				response, err = state.pairVerify(request.body)
			default:
				err = fmt.Errorf("request %d path = %q", requestIndex+1, request.uri)
			}
			if err != nil {
				serverDone <- err
				return
			}
			if err := writeRTSPTestResponse(serverConn, 200, nil, response); err != nil {
				serverDone <- err
				return
			}
		}
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("Pair: %v", err)
	}
	waitPairingTestServer(t, serverDone)
	if client.PairKeys == nil || client.PairKeys.MixFairPlayKey != forceMix {
		t.Fatalf("legacy raw pairing FairPlay key mixing = %v, want %v", client.PairKeys != nil && client.PairKeys.MixFairPlayKey, forceMix)
	}
}

func TestTransientPairingDoesNotFallbackOnTLVAuthentication(t *testing.T) {
	testNoRawFallbackAfterHAPResponses(t, 1, func(_ int) []byte {
		return tlv8EncodeOrdered([]tlv8Item{
			{Tag: tlvState, Value: []byte{2}},
			{Tag: tlvError, Value: []byte{2}},
		})
	}, "authentication (2)")
}

func TestTransientPairingDoesNotFallbackOnTLVBackoff(t *testing.T) {
	testNoRawFallbackAfterHAPResponses(t, pairSetupBackoffRetries+1, func(_ int) []byte {
		return tlv8EncodeOrdered([]tlv8Item{
			{Tag: tlvState, Value: []byte{2}},
			{Tag: tlvError, Value: []byte{pairingErrorBackoff}},
			{Tag: tlvRetryDelay, Value: []byte{0}},
		})
	}, "persisted")
}

func TestTransientPairingDoesNotFallbackAfterHAPVerificationStarts(t *testing.T) {
	state := newReceiverPairingTestState(t, "", newReceiverControllerStore())
	clientConn, serverConn := newPairingNegotiationPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	client := &AirPlayClient{
		conn:      clientConn,
		PairingID: "12345678-1234-4234-8234-123456789abc",
		info:      &ReceiverInfo{Features: testModernPairingFeatures},
	}
	serverDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		for requestIndex := 0; requestIndex < 3; requestIndex++ {
			request, err := readRTSPTestRequest(reader)
			if err != nil {
				serverDone <- err
				return
			}
			if request.uri != "/pair-setup" {
				serverDone <- fmt.Errorf("setup request %d path = %q", requestIndex+1, request.uri)
				return
			}
			response, err := state.pairSetup(request.body)
			if err != nil {
				serverDone <- err
				return
			}
			if err := writeRTSPTestResponse(serverConn, 200, nil, response); err != nil {
				serverDone <- err
				return
			}
		}

		request, err := readRTSPTestRequest(reader)
		if err != nil {
			serverDone <- err
			return
		}
		if request.uri != "/pair-verify" {
			serverDone <- fmt.Errorf("verification request path = %q, want /pair-verify", request.uri)
			return
		}
		if err := writeRTSPTestResponse(serverConn, 500, nil, nil); err != nil {
			serverDone <- err
			return
		}
		if err := requireNoPairingFallback(reader, serverConn); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Pair(ctx, "")
	if err == nil || !strings.Contains(err.Error(), "pair-verify") {
		t.Fatalf("Pair error = %v, want pair-verify failure", err)
	}
	waitPairingTestServer(t, serverDone)
}

func testNoRawFallbackAfterHAPResponses(
	t *testing.T,
	responseCount int,
	response func(int) []byte,
	wantError string,
) {
	t.Helper()
	clientConn, serverConn := newPairingNegotiationPipe(t)
	defer clientConn.Close()
	defer serverConn.Close()

	client := &AirPlayClient{
		conn:      clientConn,
		PairingID: "12345678-1234-4234-8234-123456789abc",
		info:      &ReceiverInfo{Features: testModernPairingFeatures},
	}
	serverDone := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		for requestIndex := 0; requestIndex < responseCount; requestIndex++ {
			request, err := readRTSPTestRequest(reader)
			if err != nil {
				serverDone <- err
				return
			}
			if err := requireTransientHAPM1(request); err != nil {
				serverDone <- fmt.Errorf("request %d: %w", requestIndex+1, err)
				return
			}
			if err := writeRTSPTestResponse(serverConn, 200, nil, response(requestIndex)); err != nil {
				serverDone <- err
				return
			}
		}

		// If Pair changes protocols, a raw 32-byte request arrives here. A short
		// timeout proves that TLV authentication/backoff was returned to the caller.
		if err := requireNoPairingFallback(reader, serverConn); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.Pair(ctx, "")
	if err == nil || !strings.Contains(err.Error(), wantError) {
		t.Fatalf("Pair error = %v, want %q", err, wantError)
	}
	waitPairingTestServer(t, serverDone)
}

func requireNoPairingFallback(reader *bufio.Reader, conn net.Conn) error {
	if err := conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
		return err
	}
	if request, err := readRTSPTestRequest(reader); err == nil {
		return fmt.Errorf("unexpected fallback request: %s %s (%d bytes)", request.method, request.uri, len(request.body))
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		return fmt.Errorf("read after final HAP response: %w", err)
	}
	return nil
}

func serveHAPRejectionThenRawPairing(
	conn net.Conn,
	state *receiverPairingState,
	verifyExchanges int,
	wantPD bool,
) error {
	reader := bufio.NewReader(conn)
	request, err := readRTSPTestRequest(reader)
	if err != nil {
		return err
	}
	if err := requireTransientHAPM1(request); err != nil {
		return err
	}
	if err := writeRTSPTestResponse(conn, 500, nil, nil); err != nil {
		return err
	}

	request, err = readRTSPTestRequest(reader)
	if err != nil {
		return err
	}
	if request.uri != "/pair-setup" || len(request.body) != 32 {
		return fmt.Errorf("raw fallback = %s %s (%d bytes), want POST /pair-setup with 32 bytes", request.method, request.uri, len(request.body))
	}
	response, err := state.pairSetup(request.body)
	if err != nil {
		return err
	}
	if err := writeRTSPTestResponse(conn, 200, nil, response); err != nil {
		return err
	}

	for requestIndex := 0; requestIndex < verifyExchanges*2; requestIndex++ {
		request, err = readRTSPTestRequest(reader)
		if err != nil {
			return err
		}
		if request.uri != "/pair-verify" || len(request.body) != 68 {
			return fmt.Errorf("raw verify request %d = %s %s (%d bytes)", requestIndex+1, request.method, request.uri, len(request.body))
		}
		if got := request.headers["x-apple-pd"]; (got == "1") != wantPD {
			return fmt.Errorf("raw verify request %d X-Apple-PD = %q, want present=%t", requestIndex+1, got, wantPD)
		}
		response, err = state.pairVerify(request.body)
		if err != nil {
			return err
		}
		if err := writeRTSPTestResponse(conn, 200, nil, response); err != nil {
			return err
		}
	}
	return nil
}

func requireTransientHAPM1(request rtspTestRequest) error {
	if request.method != "POST" || request.uri != "/pair-setup" {
		return fmt.Errorf("request = %s %s, want POST /pair-setup", request.method, request.uri)
	}
	if got := request.headers["x-apple-hkp"]; got != "4" {
		return fmt.Errorf("X-Apple-HKP = %q, want transient type 4", got)
	}
	message := tlv8Decode(request.body)
	if !bytes.Equal(message[tlvState], []byte{1}) ||
		!bytes.Equal(message[tlvMethod], []byte{0}) ||
		len(message[tlvFlags]) != 4 ||
		binary.LittleEndian.Uint32(message[tlvFlags]) != pairingFlagTransient {
		return fmt.Errorf("pair-setup M1 is not transient: %x", request.body)
	}
	return nil
}

func newPairingNegotiationPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	return clientConn, serverConn
}
