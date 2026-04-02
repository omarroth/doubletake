package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

// PairKeys holds the long-term and session keys from pairing.
type PairKeys struct {
	Ed25519Public  ed25519.PublicKey
	Ed25519Private ed25519.PrivateKey
	SharedSecret   []byte
	WriteKey       []byte
	ReadKey        []byte
}

// TLV8 types for HomeKit-style pairing.
const (
	tlvMethod        = 0x00
	tlvIdentifier    = 0x01
	tlvSalt          = 0x02
	tlvPublicKey     = 0x03
	tlvProof         = 0x04
	tlvEncryptedData = 0x05
	tlvState         = 0x06
	tlvError         = 0x07
	tlvSignature     = 0x0A
	tlvFlags         = 0x13
)

// Pairing flags.
const (
	pairingFlagTransient = 0x00000010 // Bit 4: ephemeral/transient pairing
)

// pairHeaders returns extra HTTP headers required for pair-setup / pair-verify.
func (c *AirPlayClient) pairHeaders() map[string]string {
	return map[string]string{
		"X-Apple-HKP": "3",
	}
}

// SRP-6a parameters (3072-bit group from RFC 5054).
var (
	srpN, _ = new(big.Int).SetString(
		"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"+
			"29024E088A67CC74020BBEA63B139B22514A08798E3404DD"+
			"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"+
			"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"+
			"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"+
			"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"+
			"83655D23DCA3AD961C62F356208552BB9ED529077096966D"+
			"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"+
			"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"+
			"DE2BCBF6955817183995497CEA956AE515D2261898FA0510"+
			"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"+
			"ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"+
			"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"+
			"F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"+
			"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"+
			"43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16)
	srpG = big.NewInt(5)
)

// pairTransient performs transient pairing (no PIN required).
func (c *AirPlayClient) pairTransient(ctx context.Context) error {
	// Generate Ed25519 key pair for this session
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519: %w", err)
	}

	c.PairKeys = &PairKeys{
		Ed25519Public:  pub,
		Ed25519Private: priv,
	}

	return c.performTransientSetupAndVerify(ctx)
}

// performTransientSetupAndVerify does transient (PIN-less) pair-setup + pair-verify.
func (c *AirPlayClient) performTransientSetupAndVerify(ctx context.Context) error {
	dbg("[PAIR] starting transient pair-setup")

	// Try raw binary pair-setup first (UxPlay / legacy AirPlay protocol).
	// Send 32-byte Ed25519 public key, expect 32-byte server public key back.
	dbg("[PAIR] trying raw binary pair-setup (UxPlay-compatible)")
	serverPub, err := c.rawPairSetup(ctx)
	if err != nil {
		// Fall back to TLV8/HomeKit-style pair-setup (Apple TV)
		dbg("[PAIR] raw pair-setup failed (%v), trying TLV8 pair-setup", err)
		if err := c.pairSetupTransient(ctx); err != nil {
			return fmt.Errorf("pair-setup: %w", err)
		}
		dbg("[PAIR] transient pair-setup complete, starting HAP pair-verify")
		if err := c.PairVerify(ctx); err != nil {
			return fmt.Errorf("pair-verify: %w", err)
		}
		dbg("[PAIR] pair-verify complete, channel is now encrypted")
		return nil
	}

	// Raw pair-setup succeeded — store server's Ed25519 public key and use raw pair-verify
	dbg("[PAIR] raw pair-setup OK, server Ed25519 pub: %02x", serverPub[:8])
	if c.info == nil {
		c.info = &ReceiverInfo{}
	}
	c.info.PK = serverPub

	dbg("[PAIR] starting raw pair-verify (no HAP encryption)")
	if err := c.rawPairVerify(ctx); err != nil {
		return fmt.Errorf("raw pair-verify: %w", err)
	}
	dbg("[PAIR] raw pair-verify complete (connection stays plaintext)")
	return nil
}

// rawPairSetup sends a 32-byte Ed25519 public key to /pair-setup and expects
// a 32-byte server Ed25519 public key back. This is the UxPlay / legacy AirPlay
// transient pair-setup protocol.
func (c *AirPlayClient) rawPairSetup(ctx context.Context) ([]byte, error) {
	resp, err := c.httpRequest("POST", "/pair-setup", "application/octet-stream", c.PairKeys.Ed25519Public)
	if err != nil {
		return nil, fmt.Errorf("pair-setup: %w", err)
	}
	if len(resp) != 32 {
		return nil, fmt.Errorf("pair-setup: expected 32 bytes, got %d", len(resp))
	}
	return resp, nil
}

// pairSetupTransient performs a transient (ephemeral, no-PIN) pair-setup.
func (c *AirPlayClient) pairSetupTransient(ctx context.Context) error {
	// Transient M1: method=0, state=1, flags=transient
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, pairingFlagTransient)

	m1 := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvMethod, Value: []byte{0x00}},
		{Tag: tlvState, Value: []byte{0x01}},
		{Tag: tlvFlags, Value: flags},
	})

	m2Bytes, err := c.httpRequest("POST", "/pair-setup", "application/octet-stream", m1, c.pairHeaders())
	if err != nil {
		return fmt.Errorf("M1: %w", err)
	}

	m2 := tlv8Decode(m2Bytes)
	if errTLV, ok := m2[tlvError]; ok {
		return fmt.Errorf("pair-setup M2 error: %d", errTLV[0])
	}

	serverPub := m2[tlvPublicKey]
	serverSalt := m2[tlvSalt]
	if serverPub == nil {
		return fmt.Errorf("M2: missing server public key")
	}

	// SRP-6a exchange with empty PIN for transient
	return c.completeSRPExchange(ctx, "", serverSalt, serverPub)
}

// StartPINDisplay triggers the PIN display on the Apple TV.
// Call this before prompting the user so the PIN is visible when they're asked.
func (c *AirPlayClient) StartPINDisplay() error {
	if _, err := c.httpRequest("POST", "/pair-pin-start", "", nil, c.pairHeaders()); err != nil {
		return fmt.Errorf("pair-pin-start: %w", err)
	}
	return nil
}

// pairWithPIN performs PIN-based pairing.
func (c *AirPlayClient) pairWithPIN(ctx context.Context, pin string) error {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ed25519: %w", err)
	}

	c.PairKeys = &PairKeys{
		Ed25519Public:  pub,
		Ed25519Private: priv,
	}

	return c.performPairSetupAndVerify(ctx, pin)
}

func (c *AirPlayClient) performPairSetupAndVerify(ctx context.Context, pin string) error {
	if err := c.pairSetup(ctx, pin); err != nil {
		return fmt.Errorf("pair-setup: %w", err)
	}
	if err := c.PairVerify(ctx); err != nil {
		return fmt.Errorf("pair-verify: %w", err)
	}
	return nil
}

// pairSetup implements the SRP6a pair-setup exchange (PIN-based).
func (c *AirPlayClient) pairSetup(ctx context.Context, pin string) error {
	// M1: Send pairing method + state
	m1 := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvMethod, Value: []byte{0x00}},
		{Tag: tlvState, Value: []byte{0x01}},
	})

	m2Bytes, err := c.httpRequest("POST", "/pair-setup", "application/octet-stream", m1, c.pairHeaders())
	if err != nil {
		return fmt.Errorf("M1: %w", err)
	}

	m2 := tlv8Decode(m2Bytes)
	if errTLV, ok := m2[tlvError]; ok {
		return fmt.Errorf("pair-setup M2 error: %d", errTLV[0])
	}

	salt := m2[tlvSalt]
	serverPubB := m2[tlvPublicKey]
	if salt == nil || serverPubB == nil {
		return fmt.Errorf("M2: missing salt or public key")
	}

	return c.completeSRPExchange(ctx, pin, salt, serverPubB)
}

// completeSRPExchange finishes SRP from M3 onward (shared by PIN and transient flows).
func (c *AirPlayClient) completeSRPExchange(ctx context.Context, pin string, salt, serverPubB []byte) error {
	username := []byte("Pair-Setup")
	password := []byte(pin)

	// x = H(salt, H(username, ":", password))
	innerHash := sha512.Sum512(append(append(username, ':'), password...))
	xInput := append(append([]byte{}, salt...), innerHash[:]...)
	xHash := sha512.Sum512(xInput)
	x := new(big.Int).SetBytes(xHash[:])

	// k = H(N, pad(g))
	padN := padTo(srpN.Bytes(), 384)
	padG := padTo(srpG.Bytes(), 384)
	kHash := sha512.Sum512(append(padN, padG...))
	k := new(big.Int).SetBytes(kHash[:])

	aBytes := make([]byte, 32)
	rand.Read(aBytes)
	a := new(big.Int).SetBytes(aBytes)
	A := new(big.Int).Exp(srpG, a, srpN)

	B := new(big.Int).SetBytes(serverPubB)

	uHash := sha512.Sum512(append(padTo(A.Bytes(), 384), padTo(B.Bytes(), 384)...))
	u := new(big.Int).SetBytes(uHash[:])

	// S = (B - k * g^x mod N)^(a + u*x) mod N
	gx := new(big.Int).Exp(srpG, x, srpN)
	kgx := new(big.Int).Mul(k, gx)
	kgx.Mod(kgx, srpN)
	diff := new(big.Int).Sub(B, kgx)
	if diff.Sign() < 0 {
		diff.Add(diff, srpN)
	}
	exp := new(big.Int).Mul(u, x)
	exp.Add(exp, a)
	S := new(big.Int).Exp(diff, exp, srpN)

	// K = H(S) — S uses natural (unpadded) byte representation
	sHash := sha512.Sum512(S.Bytes())
	K := sHash[:]

	// M1 proof = H(H(N) XOR H(g), H(I), s, A, B, K)
	// Per SRP-6a: proof uses natural (unpadded) byte representations
	hnHash := sha512.Sum512(srpN.Bytes())
	hgHash := sha512.Sum512(srpG.Bytes())
	hxor := make([]byte, 64)
	for i := range hxor {
		hxor[i] = hnHash[i] ^ hgHash[i]
	}
	huHash := sha512.Sum512(username)

	proofInput := bytes.Join([][]byte{
		hxor, huHash[:], salt,
		A.Bytes(), B.Bytes(), K,
	}, nil)
	m1Proof := sha512.Sum512(proofInput)

	// M3: Send client public key + proof
	m3 := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{0x03}},
		{Tag: tlvPublicKey, Value: padTo(A.Bytes(), 384)},
		{Tag: tlvProof, Value: m1Proof[:]},
	})
	m4Bytes, err := c.httpRequest("POST", "/pair-setup", "application/octet-stream", m3, c.pairHeaders())
	if err != nil {
		return fmt.Errorf("M3: %w", err)
	}

	m4 := tlv8Decode(m4Bytes)
	if errTLV, ok := m4[tlvError]; ok {
		return fmt.Errorf("pair-setup M4 error: %d", errTLV[0])
	}

	// Verify server proof: H(A, M1, K) — A unpadded
	m2ProofInput := bytes.Join([][]byte{A.Bytes(), m1Proof[:], K}, nil)
	m2ProofExpected := sha512.Sum512(m2ProofInput)
	if serverProof, ok := m4[tlvProof]; ok {
		if !bytes.Equal(serverProof, m2ProofExpected[:]) {
			return fmt.Errorf("server proof mismatch")
		}
	}

	// M5: Exchange Ed25519 keys over encrypted channel
	hkdfSalt := []byte("Pair-Setup-Encrypt-Salt")
	hkdfInfo := []byte("Pair-Setup-Encrypt-Info")
	sessionKey := hkdfSHA512(K, hkdfSalt, hkdfInfo, 32)

	clientID := []byte(c.PairingID)

	sigSalt := []byte("Pair-Setup-Controller-Sign-Salt")
	sigInfo := []byte("Pair-Setup-Controller-Sign-Info")
	sigKey := hkdfSHA512(K, sigSalt, sigInfo, 32)

	sigInput := bytes.Join([][]byte{sigKey, clientID, c.PairKeys.Ed25519Public}, nil)
	signature := ed25519.Sign(c.PairKeys.Ed25519Private, sigInput)

	subTLV := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvIdentifier, Value: clientID},
		{Tag: tlvPublicKey, Value: c.PairKeys.Ed25519Public},
		{Tag: tlvSignature, Value: signature},
	})

	aead, err := chacha20poly1305.New(sessionKey)
	if err != nil {
		return fmt.Errorf("chacha20: %w", err)
	}
	nonce := make([]byte, 12)
	copy(nonce[4:], "PS-Msg05")
	encrypted := aead.Seal(nil, nonce, subTLV, nil)

	m5 := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{0x05}},
		{Tag: tlvEncryptedData, Value: encrypted},
	})
	m6Bytes, err := c.httpRequest("POST", "/pair-setup", "application/octet-stream", m5, c.pairHeaders())
	if err != nil {
		return fmt.Errorf("M5: %w", err)
	}

	m6 := tlv8Decode(m6Bytes)
	if errTLV, ok := m6[tlvError]; ok {
		return fmt.Errorf("pair-setup M6 error: %d", errTLV[0])
	}

	c.PairKeys.SharedSecret = K
	return nil
}

// pairVerify establishes an encrypted channel using X25519 + Ed25519.
func (c *AirPlayClient) PairVerify(ctx context.Context) error {
	// Generate ephemeral X25519 key pair
	var clientPrivate, clientPublic [32]byte
	rand.Read(clientPrivate[:])
	curve25519.ScalarBaseMult(&clientPublic, &clientPrivate)

	// V1: Send our ephemeral X25519 public key only.
	// The Ed25519 long-term key was already exchanged during pair-setup M5.
	v1 := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{0x01}},
		{Tag: tlvPublicKey, Value: clientPublic[:]},
	})
	dbg("[PAIR-VERIFY] V1: sending %d-byte X25519 public key", len(clientPublic[:]))
	v2Bytes, err := c.httpRequest("POST", "/pair-verify", "application/octet-stream", v1, c.pairHeaders())
	if err != nil {
		return fmt.Errorf("V1: %w", err)
	}

	v2 := tlv8Decode(v2Bytes)
	if errTLV, ok := v2[tlvError]; ok {
		return fmt.Errorf("pair-verify V2 error: %d", errTLV[0])
	}

	serverKeyData := v2[tlvPublicKey]
	serverEncrypted := v2[tlvEncryptedData]
	dbg("[PAIR-VERIFY] V2: server pubkey=%d bytes, encrypted=%d bytes", len(serverKeyData), len(serverEncrypted))

	if len(serverKeyData) < 32 {
		return fmt.Errorf("V2: server public key too short")
	}

	// Extract server's X25519 public key
	var serverPublic [32]byte
	copy(serverPublic[:], serverKeyData[:32])

	// Compute shared secret
	shared, err := curve25519.X25519(clientPrivate[:], serverPublic[:])
	if err != nil {
		return fmt.Errorf("x25519: %w", err)
	}

	// Derive session encryption key
	verifyKey := hkdfSHA512(shared, []byte("Pair-Verify-Encrypt-Salt"), []byte("Pair-Verify-Encrypt-Info"), 32)

	// Decrypt and verify server's response if encrypted data present
	if len(serverEncrypted) > 0 {
		aead, err := chacha20poly1305.New(verifyKey)
		if err != nil {
			return fmt.Errorf("chacha20: %w", err)
		}
		nonce := make([]byte, 12)
		copy(nonce[4:], "PV-Msg02")
		_, err = aead.Open(nil, nonce, serverEncrypted, nil)
		if err != nil {
			return fmt.Errorf("decrypt V2: %w", err)
		}
	}

	// V3: Send our encrypted proof
	// HAP spec: sign(clientX25519Public || pairingID || serverX25519Public)
	clientIDBytes := []byte(c.PairingID)
	sigInput := bytes.Join([][]byte{clientPublic[:], clientIDBytes, serverPublic[:]}, nil)
	signature := ed25519.Sign(c.PairKeys.Ed25519Private, sigInput)
	dbg("[PAIR-VERIFY] V3: sig input = clientPub(%d) || pairingID(%d) || serverPub(%d) = %d bytes",
		len(clientPublic), len(clientIDBytes), len(serverPublic), len(sigInput))

	subTLV := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvIdentifier, Value: clientIDBytes},
		{Tag: tlvSignature, Value: signature},
	})

	aead, err := chacha20poly1305.New(verifyKey)
	if err != nil {
		return fmt.Errorf("chacha20: %w", err)
	}
	nonce := make([]byte, 12)
	copy(nonce[4:], "PV-Msg03")
	encrypted := aead.Seal(nil, nonce, subTLV, nil)

	v3 := tlv8EncodeOrdered([]tlv8Item{
		{Tag: tlvState, Value: []byte{0x03}},
		{Tag: tlvEncryptedData, Value: encrypted},
	})
	dbg("[PAIR-VERIFY] V3: sending encrypted proof")
	v4Bytes, err := c.httpRequest("POST", "/pair-verify", "application/octet-stream", v3, c.pairHeaders())
	if err != nil {
		return fmt.Errorf("V3: %w", err)
	}
	// Check V4 response for TLV errors
	if len(v4Bytes) > 0 {
		v4 := tlv8Decode(v4Bytes)
		if errTLV, ok := v4[tlvError]; ok {
			return fmt.Errorf("pair-verify V4 error: %d", errTLV[0])
		}
		dbg("[PAIR-VERIFY] V4: response %d bytes, no error", len(v4Bytes))
	} else {
		dbg("[PAIR-VERIFY] V4: empty response (OK)")
	}

	// After pair-verify, the AirPlay control channel is encrypted using HAP framing.
	// Derive channel encryption keys from the X25519 shared secret.
	c.PairKeys.SharedSecret = shared
	c.encWriteKey = hkdfSHA512(shared, []byte("Control-Salt"), []byte("Control-Write-Encryption-Key"), 32)
	c.encReadKey = hkdfSHA512(shared, []byte("Control-Salt"), []byte("Control-Read-Encryption-Key"), 32)
	c.PairKeys.WriteKey = c.encWriteKey
	c.PairKeys.ReadKey = c.encReadKey

	dbg("[PAIR-VERIFY] shared secret: %s...", hex.EncodeToString(shared[:16]))
	dbg("[PAIR-VERIFY] writeKey: %s...", hex.EncodeToString(c.encWriteKey[:8]))
	dbg("[PAIR-VERIFY] readKey:  %s...", hex.EncodeToString(c.encReadKey[:8]))

	writeCipher, err := chacha20poly1305.New(c.encWriteKey)
	if err != nil {
		return fmt.Errorf("write cipher: %w", err)
	}
	c.encCipher = writeCipher
	c.encWriteNonce = 0
	c.encReadNonce = 0
	c.encrypted = true
	dbg("[PAIR-VERIFY] encryption ENABLED (HAP framing, nonces at 0)")

	return nil
}

// TLV8 encoding/decoding

// tlv8Item is an ordered tag-value pair for deterministic encoding.
type tlv8Item struct {
	Tag   byte
	Value []byte
}

// tlv8EncodeOrdered encodes TLV8 items in the order given.
func tlv8EncodeOrdered(items []tlv8Item) []byte {
	var buf bytes.Buffer
	for _, item := range items {
		value := item.Value
		if len(value) == 0 {
			buf.WriteByte(item.Tag)
			buf.WriteByte(0)
			continue
		}
		for len(value) > 0 {
			chunk := value
			if len(chunk) > 255 {
				chunk = chunk[:255]
			}
			buf.WriteByte(item.Tag)
			buf.WriteByte(byte(len(chunk)))
			buf.Write(chunk)
			value = value[len(chunk):]
		}
	}
	return buf.Bytes()
}

// tlv8Encode encodes TLV8 items from a map (order not guaranteed).
// Prefer tlv8EncodeOrdered for protocol messages.
func tlv8Encode(items map[byte][]byte) []byte {
	var ordered []tlv8Item
	for tag, value := range items {
		ordered = append(ordered, tlv8Item{Tag: tag, Value: value})
	}
	return tlv8EncodeOrdered(ordered)
}

func tlv8Decode(data []byte) map[byte][]byte {
	result := make(map[byte][]byte)
	for len(data) >= 2 {
		tag := data[0]
		length := int(data[1])
		data = data[2:]
		if length > len(data) {
			break
		}
		result[tag] = append(result[tag], data[:length]...)
		data = data[length:]
	}
	return result
}

// hkdfSHA512 derives a key using HKDF-SHA-512.
func hkdfSHA512(secret, salt, info []byte, length int) []byte {
	r := hkdf.New(sha512.New, secret, salt, info)
	key := make([]byte, length)
	if _, err := io.ReadFull(r, key); err != nil {
		panic(fmt.Sprintf("hkdf read: %v", err))
	}
	return key
}

// padTo pads data with leading zeros to the specified length.
func padTo(data []byte, size int) []byte {
	if len(data) >= size {
		return data
	}
	padded := make([]byte, size)
	copy(padded[size-len(data):], data)
	return padded
}

// nonceBytes converts a uint64 nonce to a 12-byte nonce for ChaCha20.
func nonceBytes(n uint64) []byte {
	nonce := make([]byte, 12)
	binary.LittleEndian.PutUint64(nonce[4:], n)
	return nonce
}

// rawPairVerify performs a non-HAP ("AirMyPC-style") pair-verify that keeps the
// connection in plaintext. This is required because Apple TV rejects FairPlay
// fp-setup phase 2 over HAP-encrypted connections.
//
// Protocol (raw binary, NOT TLV8):
//
//	V1 (client→server, 68 bytes): \x01\x00\x00\x00 + X25519_pub(32) + Ed25519_pub(32)
//	V2 (server→client, 96 bytes): server_X25519_pub(32) + AES-CTR(server_sig, offset=0)(64)
//	V3 (client→server, 68 bytes): \x00\x00\x00\x00 + AES-CTR(client_sig, offset=64)(64)
//	V4 (server→client, 0 bytes): empty 200 OK
//
// AES-CTR key derivation (SHA-512, NOT HKDF):
//
//	key = SHA-512("Pair-Verify-AES-Key" || X25519_shared_secret)[:16]
//	iv  = SHA-512("Pair-Verify-AES-IV"  || X25519_shared_secret)[:16]
func (c *AirPlayClient) rawPairVerify(ctx context.Context) error {
	// Generate ephemeral X25519 key pair
	var clientPrivate [32]byte
	rand.Read(clientPrivate[:])
	var clientPublic [32]byte
	curve25519.ScalarBaseMult(&clientPublic, &clientPrivate)

	// V1: flags(4) + X25519_pub(32) + Ed25519_pub(32) = 68 bytes
	v1 := make([]byte, 68)
	v1[0] = 0x01 // flags: auth type=1
	copy(v1[4:36], clientPublic[:])
	copy(v1[36:68], c.PairKeys.Ed25519Public)

	dbg("[RAW-PV] V1: sending 68 bytes (X25519 pub + Ed25519 pub)")
	dbg("[RAW-PV] V1 hex: %02x", v1)
	v2, err := c.rawRequest("POST", "/pair-verify", "application/octet-stream", v1)
	if err != nil {
		return fmt.Errorf("V1: %w", err)
	}
	dbg("[RAW-PV] V2: received %d bytes", len(v2))

	if len(v2) != 96 {
		return fmt.Errorf("V2: expected 96 bytes, got %d", len(v2))
	}

	// Extract server's X25519 public key (first 32 bytes)
	var serverPublic [32]byte
	copy(serverPublic[:], v2[:32])
	encryptedServerSig := v2[32:96]

	// Compute X25519 shared secret
	shared, err := curve25519.X25519(clientPrivate[:], serverPublic[:])
	if err != nil {
		return fmt.Errorf("x25519: %w", err)
	}

	// Derive AES-128-CTR key and IV from shared secret using SHA-512
	aesKey := sha512DeriveKey("Pair-Verify-AES-Key", shared)
	aesIV := sha512DeriveKey("Pair-Verify-AES-IV", shared)

	// Decrypt server's signature (at AES-CTR offset 0)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	serverSig := make([]byte, 64)
	cipher.NewCTR(block, aesIV).XORKeyStream(serverSig, encryptedServerSig)

	// Verify server's Ed25519 signature over (server_X25519 || client_X25519)
	serverSigMsg := make([]byte, 64)
	copy(serverSigMsg[:32], serverPublic[:])
	copy(serverSigMsg[32:], clientPublic[:])

	// Use the server's Ed25519 public key from /info
	if c.info == nil || len(c.info.PK) < 32 {
		return fmt.Errorf("server Ed25519 public key not available (call GetInfo first)")
	}
	serverEd25519Pub := ed25519.PublicKey(c.info.PK[:32])
	if !ed25519.Verify(serverEd25519Pub, serverSigMsg, serverSig) {
		return fmt.Errorf("server signature verification failed")
	}
	dbg("[RAW-PV] server signature verified OK")

	// Sign our proof: Ed25519_sign(client_X25519 || server_X25519)
	clientSigMsg := make([]byte, 64)
	copy(clientSigMsg[:32], clientPublic[:])
	copy(clientSigMsg[32:], serverPublic[:])
	clientSig := ed25519.Sign(c.PairKeys.Ed25519Private, clientSigMsg)

	// Encrypt client signature at AES-CTR offset 64 (skip first 64 bytes)
	block2, _ := aes.NewCipher(aesKey)
	ctr := cipher.NewCTR(block2, aesIV)
	skip := make([]byte, 64)
	ctr.XORKeyStream(skip, skip) // advance CTR by 64 bytes
	encryptedClientSig := make([]byte, 64)
	ctr.XORKeyStream(encryptedClientSig, clientSig)

	// V3: flags(4) + encrypted_client_sig(64) = 68 bytes
	v3 := make([]byte, 68)
	// v3[0:4] = 0x00000000 (already zero)
	copy(v3[4:68], encryptedClientSig)

	dbg("[RAW-PV] V3: sending encrypted proof (68 bytes)")
	v4, err := c.rawRequest("POST", "/pair-verify", "application/octet-stream", v3)
	if err != nil {
		return fmt.Errorf("V3: %w", err)
	}

	if len(v4) != 0 {
		dbg("[RAW-PV] V4: unexpected %d bytes in response", len(v4))
	}
	dbg("[RAW-PV] pair-verify complete (connection stays PLAINTEXT)")

	// Store shared secret for potential stream key derivation,
	// but do NOT enable HAP encryption on the control channel
	c.PairKeys.SharedSecret = shared
	return nil
}

// sha512DeriveKey derives a 16-byte key: SHA-512(salt || secret)[:16]
func sha512DeriveKey(salt string, secret []byte) []byte {
	h := sha512.New()
	h.Write([]byte(salt))
	h.Write(secret)
	return h.Sum(nil)[:16]
}
