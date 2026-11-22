package airplay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

const receiverPairingAuthenticationError byte = 0x02

var errReceiverPairingAuthentication = errors.New("pairing authentication failed")

// receiverPairingConfig describes the stable identity and access policy of a
// receiver. A receiverControllerStore is shared by all TCP connections to the
// same receiver; receiverPairingState itself belongs to one connection.
type receiverPairingConfig struct {
	identifier  string
	privateKey  ed25519.PrivateKey
	pin         string
	controllers *receiverControllerStore
	random      io.Reader
}

// receiverControllerStore is the receiver-side equivalent of the sender's
// credential store. It deliberately stores public keys only.
type receiverControllerStore struct {
	mu          sync.RWMutex
	controllers map[string]ed25519.PublicKey
}

func newReceiverControllerStore() *receiverControllerStore {
	return &receiverControllerStore{controllers: make(map[string]ed25519.PublicKey)}
}

func (s *receiverControllerStore) remember(identifier string, publicKey ed25519.PublicKey) error {
	if s == nil {
		return fmt.Errorf("controller store is nil")
	}
	if identifier == "" {
		return fmt.Errorf("controller identifier is empty")
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("controller public key has length %d, want %d", len(publicKey), ed25519.PublicKeySize)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.controllers == nil {
		s.controllers = make(map[string]ed25519.PublicKey)
	}
	s.controllers[identifier] = append(ed25519.PublicKey(nil), publicKey...)
	return nil
}

func (s *receiverControllerStore) lookup(identifier string) (ed25519.PublicKey, bool) {
	if s == nil {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	publicKey, ok := s.controllers[identifier]
	return append(ed25519.PublicKey(nil), publicKey...), ok
}

// receiverPairingSessionKeys are available after a successful pair-verify.
// readKey and writeKey are named from the receiver's perspective. Raw legacy
// verification has a shared secret but leaves encrypted false and both control
// keys empty.
type receiverPairingSessionKeys struct {
	sharedSecret []byte
	readKey      []byte
	writeKey     []byte
	encrypted    bool
}

type receiverPairingState struct {
	identifier  string
	privateKey  ed25519.PrivateKey
	publicKey   ed25519.PublicKey
	pin         string
	controllers *receiverControllerStore
	random      io.Reader

	setup                *receiverSRPSetupState
	verify               *receiverHAPVerifyState
	rawVerify            *receiverRawVerifyState
	rawControllerKey     ed25519.PublicKey
	transientControllers map[string]ed25519.PublicKey
	session              receiverPairingSessionKeys
	verified             bool
	mediaTransient       bool
}

type receiverSRPSetupState struct {
	salt      []byte
	b         *big.Int
	v         *big.Int
	serverPub *big.Int
	sharedKey []byte
	transient bool
}

type receiverHAPVerifyState struct {
	clientPublic []byte
	serverPublic []byte
	sharedSecret []byte
	verifyKey    []byte
}

type receiverRawVerifyState struct {
	clientPublic []byte
	serverPublic []byte
	clientKey    ed25519.PublicKey
	sharedSecret []byte
	aesKey       []byte
	aesIV        []byte
}

func newReceiverPairingState(cfg receiverPairingConfig) (*receiverPairingState, error) {
	if cfg.identifier == "" {
		return nil, fmt.Errorf("receiver identifier is empty")
	}
	if len(cfg.privateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("receiver private key has length %d, want %d", len(cfg.privateKey), ed25519.PrivateKeySize)
	}
	derived := ed25519.NewKeyFromSeed(cfg.privateKey.Seed())
	if subtle.ConstantTimeCompare(derived, cfg.privateKey) != 1 {
		return nil, fmt.Errorf("receiver private key is internally inconsistent")
	}
	if cfg.controllers == nil {
		cfg.controllers = newReceiverControllerStore()
	}
	if cfg.random == nil {
		cfg.random = cryptorand.Reader
	}

	privateKey := append(ed25519.PrivateKey(nil), cfg.privateKey...)
	publicKey := append(ed25519.PublicKey(nil), privateKey[ed25519.SeedSize:]...)
	return &receiverPairingState{
		identifier:           cfg.identifier,
		privateKey:           privateKey,
		publicKey:            publicKey,
		pin:                  cfg.pin,
		controllers:          cfg.controllers,
		random:               cfg.random,
		transientControllers: make(map[string]ed25519.PublicKey),
	}, nil
}

// pairSetup handles either the raw 32-byte legacy exchange or one message of
// an SRP/TLV8 pair-setup exchange. Authentication failures in a TLV exchange
// are returned as TLV error responses; malformed transport input is an error.
func (s *receiverPairingState) pairSetup(body []byte) ([]byte, error) {
	if len(body) == ed25519.PublicKeySize {
		if s.pin != "" {
			return nil, errReceiverPairingAuthentication
		}
		s.resetVerification()
		s.setup = nil
		clear(s.transientControllers)
		s.rawControllerKey = append(ed25519.PublicKey(nil), body...)
		return append([]byte(nil), s.publicKey...), nil
	}

	message, err := decodeReceiverPairingTLV(body)
	if err != nil {
		return nil, fmt.Errorf("decode pair-setup TLV: %w", err)
	}
	state, err := receiverTLVByte(message, tlvState)
	if err != nil {
		return nil, fmt.Errorf("pair-setup state: %w", err)
	}

	switch state {
	case 1:
		return s.beginSRPSetup(message)
	case 3:
		return s.verifySRPProof(message)
	case 5:
		return s.finishSRPSetup(message)
	default:
		return nil, fmt.Errorf("unexpected pair-setup state %d", state)
	}
}

func (s *receiverPairingState) beginSRPSetup(message map[byte][]byte) ([]byte, error) {
	method, err := receiverTLVByte(message, tlvMethod)
	if err != nil || method != 0 {
		return receiverPairingTLVError(2), nil
	}

	transient := false
	if flags, ok := message[tlvFlags]; ok {
		if s.mediaTransient {
			if !bytes.Equal(flags, []byte{0x10}) {
				return receiverPairingTLVError(2), nil
			}
		} else if len(flags) != 4 || binary.LittleEndian.Uint32(flags) != pairingFlagTransient {
			return receiverPairingTLVError(2), nil
		}
		transient = true
	}
	// A configured password cannot be bypassed by asking for transient pairing.
	if transient && s.pin != "" {
		return receiverPairingTLVError(2), nil
	}

	s.resetVerification()
	s.rawControllerKey = nil
	clear(s.transientControllers)

	salt := make([]byte, 16)
	if _, err := io.ReadFull(s.random, salt); err != nil {
		return nil, fmt.Errorf("generate SRP salt: %w", err)
	}
	bBytes := make([]byte, 32)
	if _, err := io.ReadFull(s.random, bBytes); err != nil {
		return nil, fmt.Errorf("generate SRP private key: %w", err)
	}
	b := new(big.Int).SetBytes(bBytes)
	if b.Sign() == 0 {
		b.SetInt64(1)
	}

	pin := s.pin
	if transient {
		pin = ""
		if s.mediaTransient {
			pin = "3939"
		}
	}
	x := receiverSRPX(salt, pin)
	v := new(big.Int).Exp(srpG, x, srpN)
	k := receiverSRPMultiplier()
	serverPub := new(big.Int).Mul(k, v)
	serverPub.Add(serverPub, new(big.Int).Exp(srpG, b, srpN))
	serverPub.Mod(serverPub, srpN)
	if serverPub.Sign() == 0 {
		return nil, fmt.Errorf("generated invalid SRP server public key")
	}

	s.setup = &receiverSRPSetupState{
		salt:      append([]byte(nil), salt...),
		b:         b,
		v:         v,
		serverPub: serverPub,
		transient: transient,
	}
	return tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{2}},
		{Tag: tlvSalt, Value: salt},
		{Tag: tlvPublicKey, Value: padTo(serverPub.Bytes(), 384)},
	}), nil
}

func (s *receiverPairingState) verifySRPProof(message map[byte][]byte) ([]byte, error) {
	setup := s.setup
	if setup == nil || setup.sharedKey != nil {
		return receiverPairingTLVError(4), nil
	}
	clientPublicBytes := message[tlvPublicKey]
	clientProof := message[tlvProof]
	if len(clientPublicBytes) != 384 || len(clientProof) != sha512.Size {
		s.setup = nil
		return receiverPairingTLVError(4), nil
	}
	clientPublic := new(big.Int).SetBytes(clientPublicBytes)
	if clientPublic.Sign() <= 0 || clientPublic.Cmp(srpN) >= 0 ||
		new(big.Int).Mod(new(big.Int).Set(clientPublic), srpN).Sign() == 0 {
		s.setup = nil
		return receiverPairingTLVError(4), nil
	}

	u := new(big.Int).SetBytes(receiverPairingHash(
		padTo(clientPublic.Bytes(), 384),
		padTo(setup.serverPub.Bytes(), 384),
	))
	if u.Sign() == 0 {
		s.setup = nil
		return receiverPairingTLVError(4), nil
	}
	vu := new(big.Int).Exp(setup.v, u, srpN)
	base := new(big.Int).Mul(clientPublic, vu)
	base.Mod(base, srpN)
	shared := new(big.Int).Exp(base, setup.b, srpN)
	sharedKey := receiverPairingHash(shared.Bytes())
	wantProof := receiverSRPClientProof(setup.salt, clientPublic, setup.serverPub, sharedKey)
	if subtle.ConstantTimeCompare(clientProof, wantProof) != 1 {
		s.setup = nil
		return receiverPairingTLVError(4), nil
	}

	setup.sharedKey = append([]byte(nil), sharedKey...)
	serverProof := receiverPairingHash(clientPublic.Bytes(), wantProof, sharedKey)
	if s.mediaTransient && setup.transient {
		s.enableControl(sharedKey)
		s.setup = nil
	}
	return tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{4}},
		{Tag: tlvProof, Value: serverProof},
	}), nil
}

func (s *receiverPairingState) finishSRPSetup(message map[byte][]byte) ([]byte, error) {
	setup := s.setup
	if setup == nil || len(setup.sharedKey) != sha512.Size {
		return receiverPairingTLVError(6), nil
	}
	encrypted := message[tlvEncryptedData]
	if len(encrypted) < chacha20poly1305.Overhead {
		s.setup = nil
		return receiverPairingTLVError(6), nil
	}

	sessionKey := hkdfSHA512(
		setup.sharedKey,
		[]byte("Pair-Setup-Encrypt-Salt"),
		[]byte("Pair-Setup-Encrypt-Info"),
		chacha20poly1305.KeySize,
	)
	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return nil, fmt.Errorf("create pair-setup cipher: %w", err)
	}
	plain, err := aead.Open(nil, receiverPairingNonce("PS-Msg05"), encrypted, nil)
	if err != nil {
		s.setup = nil
		return receiverPairingTLVError(6), nil
	}
	identity, err := decodeReceiverPairingTLV(plain)
	if err != nil {
		s.setup = nil
		return receiverPairingTLVError(6), nil
	}
	identifier := identity[tlvIdentifier]
	publicKey := identity[tlvPublicKey]
	signature := identity[tlvSignature]
	if len(identifier) == 0 || len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		s.setup = nil
		return receiverPairingTLVError(6), nil
	}

	signKey := hkdfSHA512(
		setup.sharedKey,
		[]byte("Pair-Setup-Controller-Sign-Salt"),
		[]byte("Pair-Setup-Controller-Sign-Info"),
		32,
	)
	signed := bytes.Join([][]byte{signKey, identifier, publicKey}, nil)
	if !ed25519.Verify(ed25519.PublicKey(publicKey), signed, signature) {
		s.setup = nil
		return receiverPairingTLVError(6), nil
	}

	controllerID := string(identifier)
	if setup.transient {
		s.transientControllers[controllerID] = append(ed25519.PublicKey(nil), publicKey...)
	} else if err := s.controllers.remember(controllerID, ed25519.PublicKey(publicKey)); err != nil {
		return nil, fmt.Errorf("remember paired controller: %w", err)
	}

	accessorySignKey := hkdfSHA512(
		setup.sharedKey,
		[]byte("Pair-Setup-Accessory-Sign-Salt"),
		[]byte("Pair-Setup-Accessory-Sign-Info"),
		32,
	)
	receiverID := []byte(s.identifier)
	accessorySigned := bytes.Join([][]byte{accessorySignKey, receiverID, s.publicKey}, nil)
	accessorySignature := ed25519.Sign(s.privateKey, accessorySigned)
	responseIdentity := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvIdentifier, Value: receiverID},
		{Tag: tlvPublicKey, Value: s.publicKey},
		{Tag: tlvSignature, Value: accessorySignature},
	})
	responseEncrypted := aead.Seal(nil, receiverPairingNonce("PS-Msg06"), responseIdentity, nil)
	s.setup = nil
	return tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{6}},
		{Tag: tlvEncryptedData, Value: responseEncrypted},
	}), nil
}

// pairVerify handles one raw legacy or HAP/TLV8 pair-verify message. HAP V4
// is returned as plaintext; callers must write it before enabling the control
// keys returned by sessionKeys.
func (s *receiverPairingState) pairVerify(body []byte) ([]byte, error) {
	if s.rawVerify != nil || receiverLooksLikeRawVerifyV1(body) {
		return s.handleRawPairVerify(body)
	}

	message, err := decodeReceiverPairingTLV(body)
	if err != nil {
		return nil, fmt.Errorf("decode pair-verify TLV: %w", err)
	}
	state, err := receiverTLVByte(message, tlvState)
	if err != nil {
		return nil, fmt.Errorf("pair-verify state: %w", err)
	}
	switch state {
	case 1:
		return s.beginHAPVerify(message)
	case 3:
		return s.finishHAPVerify(message)
	default:
		return nil, fmt.Errorf("unexpected pair-verify state %d", state)
	}
}

func (s *receiverPairingState) beginHAPVerify(message map[byte][]byte) ([]byte, error) {
	clientPublic := message[tlvPublicKey]
	if len(clientPublic) != curve25519.ScalarSize {
		return receiverPairingTLVError(2), nil
	}
	s.resetVerification()

	serverPrivate := make([]byte, curve25519.ScalarSize)
	if _, err := io.ReadFull(s.random, serverPrivate); err != nil {
		return nil, fmt.Errorf("generate pair-verify private key: %w", err)
	}
	serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
	if err != nil {
		return nil, fmt.Errorf("derive pair-verify public key: %w", err)
	}
	shared, err := curve25519.X25519(serverPrivate, clientPublic)
	if err != nil {
		return receiverPairingTLVError(2), nil
	}
	verifyKey := hkdfSHA512(
		shared,
		[]byte("Pair-Verify-Encrypt-Salt"),
		[]byte("Pair-Verify-Encrypt-Info"),
		chacha20poly1305.KeySize,
	)

	receiverID := []byte(s.identifier)
	signed := bytes.Join([][]byte{serverPublic, receiverID, clientPublic}, nil)
	signature := ed25519.Sign(s.privateKey, signed)
	identity := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvIdentifier, Value: receiverID},
		{Tag: tlvSignature, Value: signature},
	})
	aead, err := chacha20poly1305.New(verifyKey)
	if err != nil {
		return nil, fmt.Errorf("create pair-verify cipher: %w", err)
	}
	encrypted := aead.Seal(nil, receiverPairingNonce("PV-Msg02"), identity, nil)

	s.verify = &receiverHAPVerifyState{
		clientPublic: append([]byte(nil), clientPublic...),
		serverPublic: append([]byte(nil), serverPublic...),
		sharedSecret: append([]byte(nil), shared...),
		verifyKey:    append([]byte(nil), verifyKey...),
	}
	return tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{2}},
		{Tag: tlvPublicKey, Value: serverPublic},
		{Tag: tlvEncryptedData, Value: encrypted},
	}), nil
}

func (s *receiverPairingState) finishHAPVerify(message map[byte][]byte) ([]byte, error) {
	verify := s.verify
	if verify == nil {
		return receiverPairingTLVError(4), nil
	}
	encrypted := message[tlvEncryptedData]
	if len(encrypted) < chacha20poly1305.Overhead {
		s.verify = nil
		return receiverPairingTLVError(4), nil
	}
	aead, err := chacha20poly1305.New(verify.verifyKey)
	if err != nil {
		return nil, fmt.Errorf("create pair-verify cipher: %w", err)
	}
	plain, err := aead.Open(nil, receiverPairingNonce("PV-Msg03"), encrypted, nil)
	if err != nil {
		s.verify = nil
		return receiverPairingTLVError(4), nil
	}
	identity, err := decodeReceiverPairingTLV(plain)
	if err != nil {
		s.verify = nil
		return receiverPairingTLVError(4), nil
	}
	identifier := identity[tlvIdentifier]
	signature := identity[tlvSignature]
	if len(identifier) == 0 || len(signature) != ed25519.SignatureSize {
		s.verify = nil
		return receiverPairingTLVError(4), nil
	}

	controllerID := string(identifier)
	controllerKey, ok := s.transientControllers[controllerID]
	if !ok {
		controllerKey, ok = s.controllers.lookup(controllerID)
	}
	if !ok {
		s.verify = nil
		return receiverPairingTLVError(4), nil
	}
	signed := bytes.Join([][]byte{verify.clientPublic, identifier, verify.serverPublic}, nil)
	if !ed25519.Verify(controllerKey, signed, signature) {
		s.verify = nil
		return receiverPairingTLVError(4), nil
	}

	s.enableControl(verify.sharedSecret)
	s.verify = nil
	return tlv8EncodeOrdered([]tlv8Item{{Tag: tlvState, Value: []byte{4}}}), nil
}

func (s *receiverPairingState) enableControl(secret []byte) {
	shared := append([]byte(nil), secret...)
	s.session = receiverPairingSessionKeys{
		sharedSecret: shared,
		// The sender writes with Control-Write and reads with Control-Read,
		// so the receiver's direction is the reverse.
		readKey: hkdfSHA512(
			shared,
			[]byte("Control-Salt"),
			[]byte("Control-Write-Encryption-Key"),
			chacha20poly1305.KeySize,
		),
		writeKey: hkdfSHA512(
			shared,
			[]byte("Control-Salt"),
			[]byte("Control-Read-Encryption-Key"),
			chacha20poly1305.KeySize,
		),
		encrypted: true,
	}
	s.verified = true
}

func receiverLooksLikeRawVerifyV1(body []byte) bool {
	return len(body) == 68 && bytes.Equal(body[:4], []byte{1, 0, 0, 0})
}

func (s *receiverPairingState) handleRawPairVerify(body []byte) ([]byte, error) {
	if s.pin != "" {
		return nil, errReceiverPairingAuthentication
	}
	if s.rawVerify == nil {
		if !receiverLooksLikeRawVerifyV1(body) {
			return nil, fmt.Errorf("invalid raw pair-verify V1")
		}
		if len(s.rawControllerKey) != ed25519.PublicKeySize ||
			subtle.ConstantTimeCompare(s.rawControllerKey, body[36:68]) != 1 {
			return nil, errReceiverPairingAuthentication
		}

		clientPublic := append([]byte(nil), body[4:36]...)
		clientKey := append(ed25519.PublicKey(nil), body[36:68]...)
		serverPrivate := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(s.random, serverPrivate); err != nil {
			return nil, fmt.Errorf("generate raw pair-verify private key: %w", err)
		}
		serverPublic, err := curve25519.X25519(serverPrivate, curve25519.Basepoint)
		if err != nil {
			return nil, fmt.Errorf("derive raw pair-verify public key: %w", err)
		}
		shared, err := curve25519.X25519(serverPrivate, clientPublic)
		if err != nil {
			return nil, errReceiverPairingAuthentication
		}
		aesKey := sha512DeriveKey("Pair-Verify-AES-Key", shared)
		aesIV := sha512DeriveKey("Pair-Verify-AES-IV", shared)
		block, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, fmt.Errorf("create raw pair-verify cipher: %w", err)
		}

		signature := ed25519.Sign(s.privateKey, bytes.Join([][]byte{serverPublic, clientPublic}, nil))
		encryptedSignature := make([]byte, ed25519.SignatureSize)
		cipher.NewCTR(block, aesIV).XORKeyStream(encryptedSignature, signature)
		response := make([]byte, 32+ed25519.SignatureSize)
		copy(response[:32], serverPublic)
		copy(response[32:], encryptedSignature)
		s.rawVerify = &receiverRawVerifyState{
			clientPublic: append([]byte(nil), clientPublic...),
			serverPublic: append([]byte(nil), serverPublic...),
			clientKey:    clientKey,
			sharedSecret: append([]byte(nil), shared...),
			aesKey:       append([]byte(nil), aesKey...),
			aesIV:        append([]byte(nil), aesIV...),
		}
		return response, nil
	}

	verify := s.rawVerify
	if len(body) != 68 || !bytes.Equal(body[:4], []byte{0, 0, 0, 0}) {
		s.rawVerify = nil
		return nil, fmt.Errorf("invalid raw pair-verify V3")
	}
	block, err := aes.NewCipher(verify.aesKey)
	if err != nil {
		return nil, fmt.Errorf("create raw pair-verify cipher: %w", err)
	}
	stream := cipher.NewCTR(block, verify.aesIV)
	discard := make([]byte, ed25519.SignatureSize)
	stream.XORKeyStream(discard, discard)
	signature := make([]byte, ed25519.SignatureSize)
	stream.XORKeyStream(signature, body[4:])
	signed := bytes.Join([][]byte{verify.clientPublic, verify.serverPublic}, nil)
	if !ed25519.Verify(verify.clientKey, signed, signature) {
		s.rawVerify = nil
		return nil, errReceiverPairingAuthentication
	}

	s.session = receiverPairingSessionKeys{
		sharedSecret: append([]byte(nil), verify.sharedSecret...),
		encrypted:    false,
	}
	s.verified = true
	s.rawVerify = nil
	return nil, nil
}

func (s *receiverPairingState) resetVerification() {
	s.verify = nil
	s.rawVerify = nil
	s.session = receiverPairingSessionKeys{}
	s.verified = false
}

func (s *receiverPairingState) sessionKeys() (receiverPairingSessionKeys, bool) {
	if !s.verified {
		return receiverPairingSessionKeys{}, false
	}
	return receiverPairingSessionKeys{
		sharedSecret: append([]byte(nil), s.session.sharedSecret...),
		readKey:      append([]byte(nil), s.session.readKey...),
		writeKey:     append([]byte(nil), s.session.writeKey...),
		encrypted:    s.session.encrypted,
	}, true
}

func receiverPairingTLVError(state byte) []byte {
	return tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{state}},
		{Tag: tlvError, Value: []byte{receiverPairingAuthenticationError}},
	})
}

func receiverTLVByte(message map[byte][]byte, tag byte) (byte, error) {
	value := message[tag]
	if len(value) != 1 {
		return 0, fmt.Errorf("tag 0x%02x has length %d, want 1", tag, len(value))
	}
	return value[0], nil
}

// decodeReceiverPairingTLV is strict about truncation while preserving TLV8's
// continuation rule for values longer than 255 bytes.
func decodeReceiverPairingTLV(data []byte) (map[byte][]byte, error) {
	result := make(map[byte][]byte)
	for len(data) > 0 {
		if len(data) < 2 {
			return nil, fmt.Errorf("truncated TLV header")
		}
		tag, length := data[0], int(data[1])
		data = data[2:]
		if length > len(data) {
			return nil, fmt.Errorf("tag 0x%02x length %d exceeds remaining %d", tag, length, len(data))
		}
		result[tag] = append(result[tag], data[:length]...)
		data = data[length:]
	}
	return result, nil
}

func receiverSRPX(salt []byte, pin string) *big.Int {
	inner := receiverPairingHash([]byte("Pair-Setup:" + pin))
	return new(big.Int).SetBytes(receiverPairingHash(salt, inner))
}

func receiverSRPMultiplier() *big.Int {
	return new(big.Int).SetBytes(receiverPairingHash(padTo(srpN.Bytes(), 384), padTo(srpG.Bytes(), 384)))
}

func receiverSRPClientProof(salt []byte, clientPublic, serverPublic *big.Int, sharedKey []byte) []byte {
	hashN := receiverPairingHash(srpN.Bytes())
	hashG := receiverPairingHash(srpG.Bytes())
	xor := make([]byte, sha512.Size)
	for i := range xor {
		xor[i] = hashN[i] ^ hashG[i]
	}
	return receiverPairingHash(
		xor,
		receiverPairingHash([]byte("Pair-Setup")),
		salt,
		clientPublic.Bytes(),
		serverPublic.Bytes(),
		sharedKey,
	)
}

func receiverPairingHash(parts ...[]byte) []byte {
	hash := sha512.New()
	for _, part := range parts {
		_, _ = hash.Write(part)
	}
	return hash.Sum(nil)
}

func receiverPairingNonce(label string) []byte {
	nonce := make([]byte, chacha20poly1305.NonceSize)
	copy(nonce[4:], label)
	return nonce
}
