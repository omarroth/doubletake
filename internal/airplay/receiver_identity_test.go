package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

// These tests are the attack: something on the LAN answers at an already
// paired receiver's address. Before the receiver's identity was recorded and
// checked, pair-verify accepted any X25519 key from it, and the stream -- the
// screen -- went to the impersonator.

func pairWithReceiver(t *testing.T, state *receiverPairingState) *AirPlayClient {
	t.Helper()
	client := newReceiverPairingTestClient(t)
	clientConn, done, closePair := runReceiverPairingServer(t, state, 3, 2)
	defer closePair()
	client.conn = clientConn
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.pairSetup(ctx, "4827"); err != nil {
		t.Fatalf("pair setup: %v", err)
	}
	if err := client.PairVerify(ctx); err != nil {
		t.Fatalf("pair verify: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("receiver: %v", err)
	}
	return client
}

func TestSavedHAPPairingRejectsAnImpostorReceiver(t *testing.T) {
	for _, test := range []struct {
		name       string
		identifier string
	}{
		// The impostor copies the receiver's identifier from mDNS, but cannot
		// copy its private key.
		{"same identifier, own key", "receiver-test-id"},
		{"own identifier, own key", "impostor-id"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := newReceiverControllerStore()
			client := pairWithReceiver(t, newReceiverPairingTestState(t, "4827", store))

			// Worst case: the impostor even accepts this controller.
			impostor := newReceiverPairingTestStateWithKey(t, "", store, test.identifier, 0x52)
			saved := restoredTestClient(t, client)
			conn, done, closePair := runReceiverPairingServer(t, impostor, 0, 1)
			defer closePair()
			saved.conn = conn

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := saved.PairVerify(ctx)
			if !errors.Is(err, ErrReceiverNotAuthenticated) {
				t.Fatalf("pair-verify with an impostor = %v, want ErrReceiverNotAuthenticated", err)
			}
			<-done
			if _, ok := impostor.sessionKeys(); ok {
				t.Fatal("the impostor completed pair-verify")
			}
		})
	}
}

// Raw pairing's receiver key used to come from /info, which the device at the
// address writes itself. An impersonator only had to publish its own key there.
func TestSavedRawPairingIsNotVerifiedAgainstInfo(t *testing.T) {
	real := newReceiverPairingTestState(t, "", newReceiverControllerStore())
	client := newReceiverPairingTestClient(t)
	client.info = &ReceiverInfo{}
	conn, done, closeFirst := runReceiverPairingServer(t, real, 1, 2)
	client.conn = conn
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	serverPublic, err := client.rawPairSetup(ctx)
	if err != nil {
		t.Fatalf("raw pair setup: %v", err)
	}
	if err := client.completeRawSetupAndVerify(ctx, serverPublic); err != nil {
		t.Fatalf("raw pair verify: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("receiver: %v", err)
	}
	closeFirst()

	impostorKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x52}, ed25519.SeedSize))
	impostor := newReceiverPairingTestStateWithKey(t, "", newReceiverControllerStore(), "receiver-test-id", 0x52)
	// Worst case: the impostor accepts this controller.
	if _, err := impostor.pairSetup(append([]byte(nil), client.PairKeys.Ed25519Public...)); err != nil {
		t.Fatalf("introduce controller to impostor: %v", err)
	}
	saved := restoredTestClient(t, client)
	// The impostor's /info names the impostor's own key.
	saved.info = &ReceiverInfo{PK: append(plistData(nil), impostorKey.Public().(ed25519.PublicKey)...)}
	conn2, done2, closeSecond := runReceiverPairingServer(t, impostor, 0, 1)
	defer closeSecond()
	saved.conn = conn2

	err = saved.PairVerify(ctx)
	if !errors.Is(err, ErrReceiverNotAuthenticated) {
		t.Fatalf("raw pair-verify against a substituted /info key = %v, want ErrReceiverNotAuthenticated", err)
	}
	closeSecond()
	<-done2
}

// A pairing saved before the receiver's identity was recorded has nothing to
// verify against. It is refused -- the caller pairs again -- rather than
// trusting whatever answers, and nothing is sent.
func TestPairVerifyWithoutAReceiverIdentityIsRefused(t *testing.T) {
	for _, protocol := range []PairingProtocol{PairingProtocolHAP, PairingProtocolRaw} {
		t.Run(string(protocol), func(t *testing.T) {
			key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
			client := NewAirPlayClient("127.0.0.1", 7000)
			client.info = &ReceiverInfo{PK: append(plistData(nil), key.Public().(ed25519.PublicKey)...)}
			if err := client.RestorePairingCredentials(&SavedCredentials{
				PairingID:       "12345678-1234-4234-8234-123456789abc",
				Ed25519Public:   key.Public().(ed25519.PublicKey),
				Ed25519Seed:     key.Seed(),
				PairingProtocol: protocol,
			}); err != nil {
				t.Fatal(err)
			}
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			client.conn = clientConn
			sent := make(chan struct{}, 1)
			go func() {
				if _, err := bufio.NewReader(serverConn).ReadByte(); err == nil {
					sent <- struct{}{}
				}
			}()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if err := client.PairVerify(ctx); !errors.Is(err, ErrReceiverNotAuthenticated) {
				t.Fatalf("PairVerify = %v, want ErrReceiverNotAuthenticated", err)
			}
			clientConn.Close()
			select {
			case <-sent:
				t.Fatal("pair-verify sent a request with nothing to verify against")
			case <-time.After(100 * time.Millisecond):
			}
		})
	}
}

// hapVerifyFault is one way a receiver's pair-verify reply can fail to prove it.
type hapVerifyFault int

const (
	hapVerifyHonest hapVerifyFault = iota
	hapVerifyNoProof
	hapVerifyWrongIdentifier
	hapVerifyBadSignature
	hapVerifyEmptyV4
	hapVerifyV4WithoutState
	hapVerifyMalformedV2Error
	hapVerifyMalformedV4Error
)

func TestSavedHAPVerifyRequiresTheReceiversProof(t *testing.T) {
	for _, test := range []struct {
		name  string
		fault hapVerifyFault
	}{
		{"V2 without encrypted proof", hapVerifyNoProof},
		{"V2 naming another receiver", hapVerifyWrongIdentifier},
		{"V2 signature by another key", hapVerifyBadSignature},
		{"empty V4", hapVerifyEmptyV4},
		{"V4 without state 4", hapVerifyV4WithoutState},
		{"V2 empty error TLV", hapVerifyMalformedV2Error},
		{"V4 empty error TLV", hapVerifyMalformedV4Error},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := verifyAgainstFakeReceiver(t, test.fault)
			if !errors.Is(err, ErrReceiverNotAuthenticated) {
				t.Fatalf("PairVerify = %v, want ErrReceiverNotAuthenticated", err)
			}
		})
	}
}

// The fake receiver itself is right when it behaves: the faults above are what
// fail, not the fake.
func TestSavedHAPVerifyAcceptsTheHonestReceiver(t *testing.T) {
	if err := verifyAgainstFakeReceiver(t, hapVerifyHonest); err != nil {
		t.Fatalf("PairVerify with the paired receiver: %v", err)
	}
}

func verifyAgainstFakeReceiver(t *testing.T, fault hapVerifyFault) error {
	t.Helper()
	receiverKey := ed25519.NewKeyFromSeed(pinSetupReceiverSeed)
	controllerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	client := NewAirPlayClient("127.0.0.1", 7000)
	if err := client.RestorePairingCredentials(&SavedCredentials{
		PairingID:         "12345678-1234-4234-8234-123456789abc",
		Ed25519Public:     controllerKey.Public().(ed25519.PublicKey),
		Ed25519Seed:       controllerKey.Seed(),
		PairingProtocol:   PairingProtocolHAP,
		ReceiverID:        pinSetupReceiverID,
		ReceiverPublicKey: receiverKey.Public().(ed25519.PublicKey),
	}); err != nil {
		t.Fatal(err)
	}
	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	_ = clientConn.SetDeadline(deadline)
	_ = serverConn.SetDeadline(deadline)
	defer clientConn.Close()
	defer serverConn.Close()
	client.conn = clientConn
	go serveFakeHAPVerify(serverConn, receiverKey, fault)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return client.PairVerify(ctx)
}

func serveFakeHAPVerify(conn net.Conn, receiverKey ed25519.PrivateKey, fault hapVerifyFault) error {
	reader := bufio.NewReader(conn)
	v1Request, err := readRTSPTestRequest(reader)
	if err != nil {
		return err
	}
	clientPublic := tlv8Decode(v1Request.body)[tlvPublicKey]
	serverPrivate := bytes.Repeat([]byte{0x2c}, curve25519.ScalarSize)
	serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		return err
	}
	shared, err := curve25519.X25519(serverPrivate, clientPublic)
	if err != nil {
		return err
	}
	verifyKey := hkdfSHA512(shared, []byte("Pair-Verify-Encrypt-Salt"), []byte("Pair-Verify-Encrypt-Info"), 32)

	identifier := []byte(pinSetupReceiverID)
	if fault == hapVerifyWrongIdentifier {
		identifier = []byte("another-receiver")
	}
	signingKey := receiverKey
	if fault == hapVerifyBadSignature {
		signingKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
	}
	signature := ed25519.Sign(signingKey, bytes.Join([][]byte{serverPublic, identifier, clientPublic}, nil))
	aead, err := chacha20poly1305.New(verifyKey)
	if err != nil {
		return err
	}
	v2Items := []tlv8Item{
		{Tag: tlvState, Value: []byte{0x02}},
		{Tag: tlvPublicKey, Value: serverPublic},
	}
	if fault != hapVerifyNoProof {
		proof := tlv8EncodeOrdered([]tlv8Item{
			{Tag: tlvIdentifier, Value: identifier},
			{Tag: tlvSignature, Value: signature},
		})
		v2Items = append(v2Items, tlv8Item{Tag: tlvEncryptedData,
			Value: aead.Seal(nil, receiverPairingNonce("PV-Msg02"), proof, nil)})
	}
	if fault == hapVerifyMalformedV2Error {
		v2Items = append(v2Items, tlv8Item{Tag: tlvError})
	}
	if err := writeRTSPTestResponse(conn, 200, nil, tlv8EncodeOrdered(v2Items)); err != nil {
		return err
	}

	if _, err := readRTSPTestRequest(reader); err != nil {
		return err
	}
	var v4 []byte
	switch fault {
	case hapVerifyEmptyV4:
	case hapVerifyMalformedV4Error:
		v4 = tlv8EncodeOrdered([]tlv8Item{{Tag: tlvError}})
	case hapVerifyV4WithoutState:
		v4 = tlv8EncodeOrdered([]tlv8Item{{Tag: tlvSalt, Value: []byte{0}}})
	default:
		v4 = tlv8EncodeOrdered([]tlv8Item{{Tag: tlvState, Value: []byte{0x04}}})
	}
	return writeRTSPTestResponse(conn, 200, nil, v4)
}

// Credentials that cannot authenticate the receiver are never written.
func TestSavePairingRefusesAPairingWithoutTheReceiversIdentity(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	receiverKey := ed25519.NewKeyFromSeed(pinSetupReceiverSeed).Public().(ed25519.PublicKey)
	for _, test := range []struct {
		name     string
		protocol PairingProtocol
		receiver *ReceiverIdentity
	}{
		{"no identity", PairingProtocolHAP, nil},
		{"short key", PairingProtocolHAP, &ReceiverIdentity{ID: "r", PublicKey: receiverKey[:16]}},
		{"HAP without identifier", PairingProtocolHAP, &ReceiverIdentity{PublicKey: receiverKey}},
	} {
		if err := store.SavePairing("device", "pair-id", pub, key, test.protocol, test.receiver); err == nil {
			t.Errorf("%s: saved", test.name)
		}
		if store.Lookup("device") != nil {
			t.Fatalf("%s: something was written", test.name)
		}
	}

	// And a later pairing never inherits an earlier receiver's identity.
	if err := store.SavePairing("device", "pair-id", pub, key, PairingProtocolHAP,
		&ReceiverIdentity{ID: "first", PublicKey: receiverKey}); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePairing("device", "pair-id", pub, key, PairingProtocolRaw,
		&ReceiverIdentity{PublicKey: receiverKey}); err != nil {
		t.Fatal(err)
	}
	if got := store.Lookup("device"); got == nil || got.ReceiverID != "" || !got.HasReceiverIdentity() {
		t.Fatalf("after re-pairing, saved = %+v; the first receiver's identifier must not survive", got)
	}
}

// What an impersonator puts in /info to be paired with transiently: a modern
// receiver whose password belongs to HTTP Digest, needing no pairing code.
func modernPasswordInfo() *ReceiverInfo {
	return &ReceiverInfo{Features: uint64(1) << 43, StatusFlags: statusFlagPasswordRequired}
}

// Pairing again with a receiver this machine has paired with must take the
// code, whatever /info says. Pair, given the same code and this /info, goes
// transient -- which is how a "pair again with a code" used to hand the stream
// to whoever wrote /info.
func TestPairWithCodeNeverGoesTransientWhateverInfoSays(t *testing.T) {
	if modernPasswordInfo().RequiredPairingCredential() != PairingCredentialNone {
		t.Fatal("test /info does not claim to need no pairing code")
	}

	t.Run("Pair goes transient", func(t *testing.T) {
		state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
		client := newReceiverPairingTestClient(t)
		client.info = modernPasswordInfo()
		conn, done, closePair := runReceiverPairingServer(t, state, 1, 0)
		defer closePair()
		client.conn = conn
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// The PIN receiver refuses transient setup, so Pair fails: it never
		// tried the code.
		if err := client.Pair(ctx, "4827"); err == nil {
			t.Fatal("Pair used the code; this test no longer shows the transient path")
		}
		closePair()
		<-done
	})

	t.Run("PairWithCode uses the code", func(t *testing.T) {
		state := newReceiverPairingTestState(t, "4827", newReceiverControllerStore())
		client := newReceiverPairingTestClient(t)
		client.info = modernPasswordInfo()
		conn, done, closePair := runReceiverPairingServer(t, state, 3, 2)
		defer closePair()
		client.conn = conn
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := client.PairWithCode(ctx, "4827"); err != nil {
			t.Fatalf("PairWithCode: %v", err)
		}
		if err := <-done; err != nil {
			t.Fatalf("receiver: %v", err)
		}
		if client.ReceiverIdentity() == nil {
			t.Fatal("PairWithCode succeeded without recording the receiver's identity")
		}
	})

	t.Run("no code", func(t *testing.T) {
		client := newReceiverPairingTestClient(t)
		if err := client.PairWithCode(context.Background(), ""); !errors.Is(err, ErrReceiverNotAuthenticated) {
			t.Fatalf("PairWithCode(\"\") = %v, want ErrReceiverNotAuthenticated", err)
		}
	})
}

// The device ID in /info is written by the device. A saved pairing found only
// by it is skipped by an impersonator that names itself as something new.
func TestLookupReceiverUsesTheReceiverMeant(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	receiverKey := ed25519.NewKeyFromSeed(pinSetupReceiverSeed).Public().(ed25519.PublicKey)
	if err := store.SavePairing("AA:BB:CC:DD:EE:01", "pair-id", key.Public().(ed25519.PublicKey), key,
		PairingProtocolHAP, &ReceiverIdentity{ID: pinSetupReceiverID, PublicKey: receiverKey}); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name               string
		expected, reported string
		wantPairing        bool
		wantRefused        bool
	}{
		{"nothing expected: the reported ID", "", "AA:BB:CC:DD:EE:01", true, false},
		{"the receiver meant", "AA:BB:CC:DD:EE:01", "AA:BB:CC:DD:EE:01", true, false},
		{"case differs only", "aa:bb:cc:dd:ee:01", "AA:BB:CC:DD:EE:01", true, false},
		{"impostor names itself as new", "AA:BB:CC:DD:EE:01", "11:22:33:44:55:66", false, true},
		{"a receiver never paired with", "11:22:33:44:55:66", "77:88:99:AA:BB:CC", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			saved, err := store.LookupReceiver(test.expected, test.reported)
			if test.wantRefused {
				if !errors.Is(err, ErrReceiverNotAuthenticated) || saved != nil {
					t.Fatalf("LookupReceiver = (%v, %v), want refusal", saved, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("LookupReceiver: %v", err)
			}
			if got := saved.HasPairingCredentials(); got != test.wantPairing {
				t.Fatalf("found a pairing = %t, want %t", got, test.wantPairing)
			}
		})
	}
}

// lockedBackend is a credential store that cannot be read, like a locked
// keyring.
type lockedBackend struct{ CredentialBackend }

func (lockedBackend) Lookup(string) (*SavedCredentials, error) {
	return nil, errors.New("keyring is locked")
}

// Unreadable is not "never paired": that would pair from scratch with
// whatever answers.
func TestLookupReceiverRefusesWhenTheStoreCannotBeRead(t *testing.T) {
	store := &CredentialStore{backend: lockedBackend{}}
	for _, expected := range []string{"", "AA:BB:CC:DD:EE:01", "11:22:33:44:55:66"} {
		if saved, err := store.LookupReceiver(expected, "AA:BB:CC:DD:EE:01"); err == nil {
			t.Errorf("expected %q: LookupReceiver = (%v, nil) from an unreadable store", expected, saved)
		}
	}
}
