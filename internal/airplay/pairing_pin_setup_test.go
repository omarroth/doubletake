package airplay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type pinSetupServerObservation struct {
	proofValid bool
	receivedM5 bool
	sharedKey  []byte
	pairingID  []byte
	publicKey  []byte
	acl        []byte
}

// pinSetupReceiverSeed and pinSetupReceiverID are the fake receiver's
// long-term identity, which it proves in M6.
var pinSetupReceiverSeed = bytes.Repeat([]byte{0x77}, ed25519.SeedSize)

const pinSetupReceiverID = "fake-receiver-id"

// pinSetupServerOptions makes the fake receiver misbehave in one way.
type pinSetupServerOptions struct {
	omitM4Proof bool
	m6          pinSetupM6
}

type pinSetupM6 int

const (
	m6Valid         pinSetupM6 = iota
	m6Empty                    // state only, no identity: what this fake used to send
	m6BadSignature             // identity present, signature made with another key
	m6NoIdentifier             // key and signature but no identifier
	m6Undecryptable            // encrypted under the wrong key
)

type pinSetupServerOutcome struct {
	observation pinSetupServerObservation
	err         error
}

func TestPINPairSetupIncludesScreenCaptureACL(t *testing.T) {
	const pin = "4827"

	client, serverDone, closePair := newPINSetupTestPair(t, pin)
	defer closePair()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := client.pairSetup(ctx, pin); err != nil {
		t.Fatalf("pairSetup: %v", err)
	}

	result := waitPINSetupServer(t, serverDone)
	if !result.proofValid {
		t.Fatal("receiver rejected the client's SRP proof")
	}
	if !result.receivedM5 {
		t.Fatal("receiver did not receive encrypted M5")
	}
	if !bytes.Equal(client.PairKeys.SharedSecret, result.sharedKey) {
		t.Fatal("client and receiver derived different SRP session keys")
	}
	// The receiver's identity from M6 is what every later pair-verify checks.
	receiver := client.ReceiverIdentity()
	wantKey := ed25519.NewKeyFromSeed(pinSetupReceiverSeed).Public().(ed25519.PublicKey)
	if receiver == nil || receiver.ID != pinSetupReceiverID || !bytes.Equal(receiver.PublicKey, wantKey) {
		t.Fatalf("receiver identity = %+v, want %q with the receiver's key", receiver, pinSetupReceiverID)
	}
	if got, want := string(result.pairingID), client.PairingID; got != want {
		t.Fatalf("encrypted pairing identifier = %q, want %q", got, want)
	}
	if !bytes.Equal(result.publicKey, client.PairKeys.Ed25519Public) {
		t.Fatal("encrypted controller public key differs from the client's key")
	}

	wantACL, err := hex.DecodeString("e157636f6d2e6170706c652e53637265656e4361707475726501")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.acl, wantACL) {
		t.Fatalf("encrypted screen-capture ACL = %x, want %x", result.acl, wantACL)
	}
}

func TestPINPairSetupRejectsWrongPINAtM3(t *testing.T) {
	client, serverDone, closePair := newPINSetupTestPair(t, "4827")
	defer closePair()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := client.pairSetup(ctx, "0000")
	if err == nil {
		t.Fatal("pairSetup accepted an incorrect PIN")
	}
	if !strings.Contains(err.Error(), "M4 error") {
		t.Fatalf("wrong-PIN error = %q, want M4 authentication rejection", err)
	}

	result := waitPINSetupServer(t, serverDone)
	if result.proofValid {
		t.Fatal("receiver accepted the M3 proof generated with an incorrect PIN")
	}
	if result.receivedM5 {
		t.Fatal("client sent M5 after its M3 proof was rejected")
	}
}

// A PIN pairing must learn and prove whom it paired with. Each of these used to
// be accepted -- M6 was never read -- leaving a saved pairing with no receiver
// key, so pair-verify could not tell the receiver from anything else.
func TestPINPairSetupRequiresTheReceiversProvenIdentity(t *testing.T) {
	for _, test := range []struct {
		name string
		opts pinSetupServerOptions
	}{
		{"M6 without identity", pinSetupServerOptions{m6: m6Empty}},
		{"M6 signed by another key", pinSetupServerOptions{m6: m6BadSignature}},
		{"M6 without identifier", pinSetupServerOptions{m6: m6NoIdentifier}},
		{"M6 encrypted under another key", pinSetupServerOptions{m6: m6Undecryptable}},
		{"M4 without SRP proof", pinSetupServerOptions{omitM4Proof: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			const pin = "4827"
			client, serverDone, closePair := newPINSetupTestPairWith(t, pin, test.opts)
			defer closePair()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			err := client.pairSetup(ctx, pin)
			if !errors.Is(err, ErrReceiverNotAuthenticated) {
				t.Fatalf("pairSetup error = %v, want ErrReceiverNotAuthenticated", err)
			}
			if client.ReceiverIdentity() != nil {
				t.Fatal("a receiver that did not prove itself was recorded")
			}
			closePair()
			<-serverDone
		})
	}
}

func newPINSetupTestPair(t *testing.T, receiverPIN string) (*AirPlayClient, <-chan pinSetupServerOutcome, func()) {
	return newPINSetupTestPairWith(t, receiverPIN, pinSetupServerOptions{})
}

func newPINSetupTestPairWith(t *testing.T, receiverPIN string, opts pinSetupServerOptions) (*AirPlayClient, <-chan pinSetupServerOutcome, func()) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	deadline := time.Now().Add(5 * time.Second)
	if err := clientConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}
	if err := serverConn.SetDeadline(deadline); err != nil {
		t.Fatal(err)
	}

	seed := bytes.Repeat([]byte{0x42}, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	client := &AirPlayClient{
		conn:      clientConn,
		PairingID: "12345678-1234-4234-8234-123456789abc",
		PairKeys: &PairKeys{
			Ed25519Public:  publicKey,
			Ed25519Private: privateKey,
		},
	}

	serverDone := make(chan pinSetupServerOutcome, 1)
	go func() {
		observation, err := servePINPairSetup(serverConn, receiverPIN, opts)
		serverDone <- pinSetupServerOutcome{observation: observation, err: err}
	}()

	return client, serverDone, func() {
		clientConn.Close()
		serverConn.Close()
	}
}

func waitPINSetupServer(t *testing.T, done <-chan pinSetupServerOutcome) pinSetupServerObservation {
	t.Helper()
	select {
	case outcome := <-done:
		if outcome.err != nil {
			t.Fatalf("PIN setup server: %v", outcome.err)
		}
		return outcome.observation
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for PIN setup server")
		return pinSetupServerObservation{}
	}
}

func servePINPairSetup(conn net.Conn, pin string, opts pinSetupServerOptions) (pinSetupServerObservation, error) {
	var observation pinSetupServerObservation
	reader := bufio.NewReader(conn)

	m1Request, err := readRTSPTestRequest(reader)
	if err != nil {
		return observation, fmt.Errorf("read M1: %w", err)
	}
	if err := validatePINSetupRequest(m1Request, 1); err != nil {
		return observation, err
	}

	// Fixed server parameters keep this side of the exchange deterministic while
	// the client is still free to generate a fresh SRP private value.
	salt := []byte("fixed-test-salt")
	b := new(big.Int).SetBytes(bytes.Repeat([]byte{0x5a}, 32))
	x := pinSetupTestX(salt, pin)
	v := new(big.Int).Exp(srpG, x, srpN)
	k := pinSetupTestMultiplier()
	gb := new(big.Int).Exp(srpG, b, srpN)
	B := new(big.Int).Mul(k, v)
	B.Add(B, gb)
	B.Mod(B, srpN)

	m2 := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{0x02}},
		{Tag: tlvSalt, Value: salt},
		{Tag: tlvPublicKey, Value: padTo(B.Bytes(), 384)},
	})
	if err := writeRTSPTestResponse(conn, 200, nil, m2); err != nil {
		return observation, fmt.Errorf("write M2: %w", err)
	}

	m3Request, err := readRTSPTestRequest(reader)
	if err != nil {
		return observation, fmt.Errorf("read M3: %w", err)
	}
	if err := validatePINSetupRequest(m3Request, 3); err != nil {
		return observation, err
	}
	m3 := tlv8Decode(m3Request.body)
	ABytes, ok := m3[tlvPublicKey]
	if !ok || len(ABytes) != 384 {
		return observation, fmt.Errorf("M3 public key length = %d, want 384", len(ABytes))
	}
	A := new(big.Int).SetBytes(ABytes)
	if A.Sign() == 0 || new(big.Int).Mod(new(big.Int).Set(A), srpN).Sign() == 0 {
		return observation, fmt.Errorf("M3 contains an invalid SRP public key")
	}

	uHash := pinSetupTestHash(padTo(A.Bytes(), 384), padTo(B.Bytes(), 384))
	u := new(big.Int).SetBytes(uHash)
	vu := new(big.Int).Exp(v, u, srpN)
	serverBase := new(big.Int).Mul(A, vu)
	serverBase.Mod(serverBase, srpN)
	S := new(big.Int).Exp(serverBase, b, srpN)
	sharedKey := pinSetupTestHash(S.Bytes())
	observation.sharedKey = append([]byte(nil), sharedKey...)

	wantM3Proof := pinSetupTestClientProof(salt, A, B, sharedKey)
	observation.proofValid = bytes.Equal(m3[tlvProof], wantM3Proof)
	if !observation.proofValid {
		m4 := tlv8EncodeOrdered([]tlv8Item{
			{Tag: tlvState, Value: []byte{0x04}},
			{Tag: tlvError, Value: []byte{0x02}},
		})
		if err := writeRTSPTestResponse(conn, 200, nil, m4); err != nil {
			return observation, fmt.Errorf("write M4 rejection: %w", err)
		}
		return observation, nil
	}

	serverProof := pinSetupTestHash(A.Bytes(), wantM3Proof, sharedKey)
	m4Items := []tlv8Item{{Tag: tlvState, Value: []byte{0x04}}}
	if !opts.omitM4Proof {
		m4Items = append(m4Items, tlv8Item{Tag: tlvProof, Value: serverProof})
	}
	if err := writeRTSPTestResponse(conn, 200, nil, tlv8EncodeOrdered(m4Items)); err != nil {
		return observation, fmt.Errorf("write M4: %w", err)
	}
	if opts.omitM4Proof {
		return observation, nil // the client must stop here
	}

	m5Request, err := readRTSPTestRequest(reader)
	if err != nil {
		return observation, fmt.Errorf("read M5: %w", err)
	}
	if err := validatePINSetupRequest(m5Request, 5); err != nil {
		return observation, err
	}
	observation.receivedM5 = true
	m5 := tlv8Decode(m5Request.body)
	encrypted, ok := m5[tlvEncryptedData]
	if !ok {
		return observation, fmt.Errorf("M5 is missing encrypted data")
	}

	sessionKey := pinSetupTestHKDF(sharedKey, []byte("Pair-Setup-Encrypt-Salt"), []byte("Pair-Setup-Encrypt-Info"), 32)
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return observation, fmt.Errorf("create M5 cipher: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce[4:], "PS-Msg05")
	plaintext, err := aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return observation, fmt.Errorf("decrypt M5: %w", err)
	}
	subTLV := tlv8Decode(plaintext)
	observation.pairingID = append([]byte(nil), subTLV[tlvIdentifier]...)
	observation.publicKey = append([]byte(nil), subTLV[tlvPublicKey]...)
	observation.acl = append([]byte(nil), subTLV[tlvACL]...)

	signature := subTLV[tlvSignature]
	signKey := pinSetupTestHKDF(sharedKey, []byte("Pair-Setup-Controller-Sign-Salt"), []byte("Pair-Setup-Controller-Sign-Info"), 32)
	signed := bytes.Join([][]byte{signKey, observation.pairingID, observation.publicKey}, nil)
	if len(observation.publicKey) != ed25519.PublicKeySize || !ed25519.Verify(observation.publicKey, signed, signature) {
		return observation, fmt.Errorf("M5 controller signature is invalid")
	}

	m6 := pinSetupTestM6(opts.m6, sharedKey, sessionKey)
	if err := writeRTSPTestResponse(conn, 200, nil, m6); err != nil {
		return observation, fmt.Errorf("write M6: %w", err)
	}
	return observation, nil
}

// pinSetupTestM6 builds the receiver's M6: its identifier and long-term key,
// signed over HKDF(K, Accessory-Sign) || identifier || key, encrypted with the
// pair-setup session key -- or one of the ways of getting that wrong.
func pinSetupTestM6(kind pinSetupM6, sharedKey, sessionKey []byte) []byte {
	if kind == m6Empty {
		return tlv8EncodeOrdered([]tlv8Item{{Tag: tlvState, Value: []byte{0x06}}})
	}
	receiverKey := ed25519.NewKeyFromSeed(pinSetupReceiverSeed)
	receiverPublic := receiverKey.Public().(ed25519.PublicKey)
	identifier := []byte(pinSetupReceiverID)
	signKey := pinSetupTestHKDF(sharedKey, []byte("Pair-Setup-Accessory-Sign-Salt"), []byte("Pair-Setup-Accessory-Sign-Info"), 32)
	signingKey := receiverKey
	if kind == m6BadSignature {
		signingKey = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x13}, ed25519.SeedSize))
	}
	signature := ed25519.Sign(signingKey, bytes.Join([][]byte{signKey, identifier, receiverPublic}, nil))
	items := []tlv8Item{{Tag: tlvIdentifier, Value: identifier}}
	if kind == m6NoIdentifier {
		items = nil
	}
	items = append(items,
		tlv8Item{Tag: tlvPublicKey, Value: receiverPublic},
		tlv8Item{Tag: tlvSignature, Value: signature},
	)
	encryptKey := sessionKey
	if kind == m6Undecryptable {
		encryptKey = bytes.Repeat([]byte{0x99}, 32)
	}
	aead, err := chacha20poly1305.New(encryptKey)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, aead.NonceSize())
	copy(nonce[4:], "PS-Msg06")
	return tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{0x06}},
		{Tag: tlvEncryptedData, Value: aead.Seal(nil, nonce, tlv8EncodeOrdered(items), nil)},
	})
}

func validatePINSetupRequest(request rtspTestRequest, state byte) error {
	if request.method != "POST" || request.uri != "/pair-setup" {
		return fmt.Errorf("state %d request = %s %s, want POST /pair-setup", state, request.method, request.uri)
	}
	if got := request.headers["x-apple-hkp"]; got != "5" {
		return fmt.Errorf("state %d X-Apple-HKP = %q, want 5", state, got)
	}
	message := tlv8Decode(request.body)
	if got := message[tlvState]; !bytes.Equal(got, []byte{state}) {
		return fmt.Errorf("pair-setup state = %x, want %02x", got, state)
	}
	return nil
}

func pinSetupTestX(salt []byte, pin string) *big.Int {
	inner := pinSetupTestHash([]byte("Pair-Setup:" + pin))
	return new(big.Int).SetBytes(pinSetupTestHash(salt, inner))
}

func pinSetupTestMultiplier() *big.Int {
	return new(big.Int).SetBytes(pinSetupTestHash(padTo(srpN.Bytes(), 384), padTo(srpG.Bytes(), 384)))
}

func pinSetupTestClientProof(salt []byte, A, B *big.Int, sharedKey []byte) []byte {
	hn := pinSetupTestHash(srpN.Bytes())
	hg := pinSetupTestHash(srpG.Bytes())
	hxor := make([]byte, sha512.Size)
	for i := range hxor {
		hxor[i] = hn[i] ^ hg[i]
	}
	return pinSetupTestHash(hxor, pinSetupTestHash([]byte("Pair-Setup")), salt, A.Bytes(), B.Bytes(), sharedKey)
}

func pinSetupTestHash(parts ...[]byte) []byte {
	hash := sha512.New()
	for _, part := range parts {
		hash.Write(part)
	}
	return hash.Sum(nil)
}

func pinSetupTestHKDF(secret, salt, info []byte, size int) []byte {
	key := make([]byte, size)
	if _, err := io.ReadFull(hkdf.New(sha512.New, secret, salt, info), key); err != nil {
		panic(err)
	}
	return key
}
