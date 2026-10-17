package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

func TestReceiverPairingStateHAPFixedAndTransient(t *testing.T) {
	for _, test := range []struct {
		name      string
		pin       string
		transient bool
	}{
		{name: "fixed PIN", pin: "4827"},
		{name: "transient", transient: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newReceiverControllerStore()
			state := newReceiverPairingTestState(t, test.pin, store)
			client := newReceiverPairingTestClient(t)
			clientConn, serverDone, closePair := runReceiverPairingServer(t, state, 3, 2)
			defer closePair()
			client.conn = clientConn

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			var err error
			if test.transient {
				client.pairType = pairingTypeTransient
				err = client.pairSetupTransient(ctx)
			} else {
				err = client.pairSetup(ctx, test.pin)
			}
			if err != nil {
				t.Fatalf("pair setup: %v", err)
			}
			if err := client.PairVerify(ctx); err != nil {
				t.Fatalf("pair verify: %v", err)
			}
			if err := <-serverDone; err != nil {
				t.Fatalf("receiver: %v", err)
			}

			keys, ok := state.sessionKeys()
			if !ok || !keys.encrypted {
				t.Fatalf("session keys = (%+v, %t), want verified HAP session", keys, ok)
			}
			if !bytes.Equal(keys.sharedSecret, client.PairKeys.SharedSecret) {
				t.Fatal("receiver and controller X25519 secrets differ")
			}
			if !bytes.Equal(keys.readKey, client.PairKeys.WriteKey) {
				t.Fatal("receiver read key does not equal controller write key")
			}
			if !bytes.Equal(keys.writeKey, client.PairKeys.ReadKey) {
				t.Fatal("receiver write key does not equal controller read key")
			}
			_, persisted := store.lookup(client.PairingID)
			if persisted == test.transient {
				t.Fatalf("persisted controller = %t, want %t", persisted, !test.transient)
			}
		})
	}
}

func TestReceiverPairingStateSavedHAPVerify(t *testing.T) {
	store := newReceiverControllerStore()
	firstState := newReceiverPairingTestState(t, "4827", store)
	client := newReceiverPairingTestClient(t)
	clientConn, firstDone, closeFirst := runReceiverPairingServer(t, firstState, 3, 2)
	client.conn = clientConn

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.pairSetup(ctx, "4827"); err != nil {
		closeFirst()
		t.Fatalf("initial pair setup: %v", err)
	}
	if err := client.PairVerify(ctx); err != nil {
		closeFirst()
		t.Fatalf("initial pair verify: %v", err)
	}
	if err := <-firstDone; err != nil {
		closeFirst()
		t.Fatalf("initial receiver: %v", err)
	}
	closeFirst()

	savedClient := restoredTestClient(t, client)
	secondState := newReceiverPairingTestState(t, "4827", store)
	savedConn, secondDone, closeSecond := runReceiverPairingServer(t, secondState, 0, 2)
	defer closeSecond()
	savedClient.conn = savedConn
	if err := savedClient.PairVerify(ctx); err != nil {
		t.Fatalf("saved pair verify: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("saved receiver: %v", err)
	}
	if keys, ok := secondState.sessionKeys(); !ok || !keys.encrypted {
		t.Fatal("saved verification did not establish HAP keys")
	}
}

func TestReceiverPairingStateRawSetupAndVerify(t *testing.T) {
	state := newReceiverPairingTestState(t, "", newReceiverControllerStore())
	client := newReceiverPairingTestClient(t)
	client.info = &ReceiverInfo{}
	clientConn, serverDone, closePair := runReceiverPairingServer(t, state, 1, 2)
	defer closePair()
	client.conn = clientConn

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverPublic, err := client.rawPairSetup(ctx)
	if err != nil {
		t.Fatalf("raw pair setup: %v", err)
	}
	if err := client.completeRawSetupAndVerify(ctx, serverPublic); err != nil {
		t.Fatalf("raw pair verify: %v", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("receiver: %v", err)
	}

	keys, ok := state.sessionKeys()
	if !ok || keys.encrypted {
		t.Fatalf("session keys = (%+v, %t), want verified plaintext session", keys, ok)
	}
	if len(keys.readKey) != 0 || len(keys.writeKey) != 0 {
		t.Fatal("raw verification unexpectedly produced HAP control keys")
	}
	if !bytes.Equal(keys.sharedSecret, client.PairKeys.SharedSecret) {
		t.Fatal("receiver and controller raw X25519 secrets differ")
	}
}

func TestReceiverPairingStateSavedRawVerify(t *testing.T) {
	state := newReceiverPairingTestState(t, "", newReceiverControllerStore())
	client := newReceiverPairingTestClient(t)
	client.info = &ReceiverInfo{}
	clientConn, firstDone, closeFirst := runReceiverPairingServer(t, state, 1, 2)
	client.conn = clientConn

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverPublic, err := client.rawPairSetup(ctx)
	if err != nil {
		closeFirst()
		t.Fatalf("raw pair setup: %v", err)
	}
	if err := client.completeRawSetupAndVerify(ctx, serverPublic); err != nil {
		closeFirst()
		t.Fatalf("initial raw pair verify: %v", err)
	}
	if err := <-firstDone; err != nil {
		closeFirst()
		t.Fatalf("initial receiver: %v", err)
	}
	closeFirst()

	// /info is left empty: a saved pairing is verified against the key it
	// recorded, not against whatever /info says.
	savedClient := restoredTestClient(t, client)
	savedClient.info = &ReceiverInfo{}
	secondConn, secondDone, closeSecond := runReceiverPairingServer(t, state, 0, 2)
	defer closeSecond()
	savedClient.conn = secondConn
	if err := savedClient.PairVerify(ctx); err != nil {
		t.Fatalf("saved raw pair verify: %v", err)
	}
	if err := <-secondDone; err != nil {
		t.Fatalf("saved raw receiver: %v", err)
	}
	if keys, ok := state.sessionKeys(); !ok || keys.encrypted {
		t.Fatal("saved raw verification did not establish a plaintext session")
	}
}

func TestReceiverPairingStatePINRejectsUnauthenticatedModes(t *testing.T) {
	state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
	if _, err := state.pairSetup(bytes.Repeat([]byte{1}, ed25519.PublicKeySize)); !errors.Is(err, errReceiverPairingAuthentication) {
		t.Fatalf("raw setup error = %v, want authentication failure", err)
	}

	flags := make([]byte, 4)
	flags[0] = pairingFlagTransient
	response, err := state.pairSetup(tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvMethod, Value: []byte{0}},
		{Tag: tlvState, Value: []byte{1}},
		{Tag: tlvFlags, Value: flags},
	}))
	if err != nil {
		t.Fatalf("transient setup returned transport error: %v", err)
	}
	message, err := decodeReceiverPairingTLV(response)
	if err != nil {
		t.Fatal(err)
	}
	if got := message[tlvState]; !bytes.Equal(got, []byte{2}) {
		t.Fatalf("response state = %x, want 02", got)
	}
	if got := message[tlvError]; !bytes.Equal(got, []byte{receiverPairingAuthenticationError}) {
		t.Fatalf("response error = %x, want authentication", got)
	}
}

func TestReceiverPairingStateRejectsWrongSRPProof(t *testing.T) {
	state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
	client := newReceiverPairingTestClient(t)
	clientConn, serverDone, closePair := runReceiverPairingServer(t, state, 2, 0)
	defer closePair()
	client.conn = clientConn

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.pairSetup(ctx, "0000")
	if err == nil || !bytes.Contains([]byte(err.Error()), []byte("M4 error")) {
		t.Fatalf("wrong-PIN error = %v, want M4 authentication error", err)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("receiver: %v", err)
	}
	if _, ok := state.sessionKeys(); ok {
		t.Fatal("wrong SRP proof established session keys")
	}
}

func TestReceiverPairingStateRejectsHAPControllerSignature(t *testing.T) {
	store := newReceiverControllerStore()
	controllerPrivate := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	controllerPublic := controllerPrivate.Public().(ed25519.PublicKey)
	const controllerID = "saved-controller"
	if err := store.remember(controllerID, controllerPublic); err != nil {
		t.Fatal(err)
	}
	state := newReceiverPairingTestState(t, "", store)

	clientPrivate := bytes.Repeat([]byte{0x27}, curve25519.ScalarSize)
	clientPublic, err := curve25519.X25519(clientPrivate, curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	v2Body, err := state.pairVerify(tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{1}},
		{Tag: tlvPublicKey, Value: clientPublic},
	}))
	if err != nil {
		t.Fatalf("V1: %v", err)
	}
	v2, err := decodeReceiverPairingTLV(v2Body)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic := v2[tlvPublicKey]
	shared, err := curve25519.X25519(clientPrivate, serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	verifyKey := hkdfSHA512(
		shared,
		[]byte("Pair-Verify-Encrypt-Salt"),
		[]byte("Pair-Verify-Encrypt-Info"),
		chacha20poly1305.KeySize,
	)
	aead, err := chacha20poly1305.New(verifyKey)
	if err != nil {
		t.Fatal(err)
	}
	// The identity is trusted but the proof is deliberately not signed by it.
	identity := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvIdentifier, Value: []byte(controllerID)},
		{Tag: tlvSignature, Value: make([]byte, ed25519.SignatureSize)},
	})
	encrypted := aead.Seal(nil, receiverPairingNonce("PV-Msg03"), identity, nil)
	v4Body, err := state.pairVerify(tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{3}},
		{Tag: tlvEncryptedData, Value: encrypted},
	}))
	if err != nil {
		t.Fatalf("V3 returned transport error: %v", err)
	}
	v4, err := decodeReceiverPairingTLV(v4Body)
	if err != nil {
		t.Fatal(err)
	}
	if got := v4[tlvError]; !bytes.Equal(got, []byte{receiverPairingAuthenticationError}) {
		t.Fatalf("V4 error = %x, want authentication", got)
	}
	if _, ok := state.sessionKeys(); ok {
		t.Fatal("invalid controller signature established session keys")
	}
}

// restoredTestClient is what a later cast starts from: client's pairing, saved
// and loaded back, receiver identity included.
func restoredTestClient(t *testing.T, client *AirPlayClient) *AirPlayClient {
	t.Helper()
	receiver := client.ReceiverIdentity()
	if receiver == nil {
		t.Fatal("pairing recorded no receiver identity to save")
	}
	saved := &SavedCredentials{
		PairingID:         client.PairingID,
		Ed25519Public:     append([]byte(nil), client.PairKeys.Ed25519Public...),
		Ed25519Seed:       append([]byte(nil), client.PairKeys.Ed25519Private.Seed()...),
		PairingProtocol:   client.PairingProtocol(),
		ReceiverID:        receiver.ID,
		ReceiverPublicKey: append([]byte(nil), receiver.PublicKey...),
	}
	restored := NewAirPlayClient("127.0.0.1", 7000)
	if err := restored.RestorePairingCredentials(saved); err != nil {
		t.Fatalf("restore credentials: %v", err)
	}
	return restored
}

func newReceiverPairingTestState(t *testing.T, pin string, store *receiverControllerStore) *receiverPairingState {
	return newReceiverPairingTestStateWithKey(t, pin, store, "receiver-test-id", 0x51)
}

// newReceiverPairingTestStateWithKey is a receiver with its own identity -- a
// different seed is a different device.
func newReceiverPairingTestStateWithKey(t *testing.T, pin string, store *receiverControllerStore, identifier string, seed byte) *receiverPairingState {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	state, err := newReceiverPairingState(receiverPairingConfig{
		identifier:  identifier,
		privateKey:  privateKey,
		pin:         pin,
		controllers: store,
		random:      bytes.NewReader(bytes.Repeat([]byte{0x6a}, 1024)),
	})
	if err != nil {
		t.Fatalf("new receiver state: %v", err)
	}
	return state
}

func newReceiverPairingTestClient(t *testing.T) *AirPlayClient {
	t.Helper()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	return &AirPlayClient{
		PairingID: "12345678-1234-4234-8234-123456789abc",
		PairKeys: &PairKeys{
			Ed25519Public:  append(ed25519.PublicKey(nil), privateKey[ed25519.SeedSize:]...),
			Ed25519Private: privateKey,
		},
	}
}

func runReceiverPairingServer(
	t *testing.T,
	state *receiverPairingState,
	setupRequests int,
	verifyRequests int,
) (net.Conn, <-chan error, func()) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		reader := bufio.NewReader(serverConn)
		for i := 0; i < setupRequests+verifyRequests; i++ {
			request, err := readRTSPTestRequest(reader)
			if err != nil {
				done <- fmt.Errorf("read request %d: %w", i+1, err)
				return
			}
			var response []byte
			switch request.uri {
			case "/pair-setup":
				response, err = state.pairSetup(request.body)
			case "/pair-verify":
				response, err = state.pairVerify(request.body)
			default:
				err = fmt.Errorf("unexpected path %q", request.uri)
			}
			if err != nil {
				done <- fmt.Errorf("handle request %d: %w", i+1, err)
				return
			}
			if err := writeRTSPTestResponse(serverConn, 200, nil, response); err != nil {
				done <- fmt.Errorf("write response %d: %w", i+1, err)
				return
			}
		}
		done <- nil
	}()
	return clientConn, done, func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	}
}
