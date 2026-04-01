package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/hex"
	"testing"

	"airplay/playfair"
)

func TestFairPlayLocalRoundtripClientServer(t *testing.T) {
	m3Bytes, err := hex.DecodeString(message3KnownHexA)
	if err != nil {
		t.Fatalf("decode m3: %v", err)
	}
	var m3 [164]byte
	copy(m3[:], m3Bytes)

	plainKey := [16]byte{0xda, 0x98, 0x33, 0x7c, 0x29, 0x23, 0x06, 0x42, 0x45, 0xa6, 0x34, 0xf6, 0xaf, 0xf1, 0x15, 0x64}

	// Client: wrap stream key into ekey.
	ekey := playfair.Encrypt(m3, plainKey)

	// Server: recover stream key from ekey using m3 from fp-setup phase 2.
	recovered := playfair.Decrypt(m3, ekey)
	if recovered != plainKey {
		t.Fatalf("server failed to recover FairPlay key: got %x want %x", recovered, plainKey)
	}

	scid := int64(2562744207480275294)
	txKey, txIV := deriveVideoKeys(plainKey[:], scid)
	rxKey, rxIV := deriveVideoKeys(recovered[:], scid)

	sender, err := newMirrorCipher(txKey, txIV)
	if err != nil {
		t.Fatalf("sender cipher: %v", err)
	}
	receiver, err := newMirrorCipher(rxKey, rxIV)
	if err != nil {
		t.Fatalf("receiver cipher: %v", err)
	}

	frames := [][]byte{
		bytes.Repeat([]byte{0x11}, 7),
		bytes.Repeat([]byte{0x22}, 16),
		bytes.Repeat([]byte{0x33}, 31),
		bytes.Repeat([]byte{0x44}, 128),
		bytes.Repeat([]byte{0x55}, 1023),
	}

	for i, frame := range frames {
		ciphertext := sender.EncryptFrame(frame)
		plaintext := receiver.EncryptFrame(ciphertext)
		if !bytes.Equal(plaintext, frame) {
			t.Fatalf("frame %d decrypt mismatch", i)
		}
	}
}

func TestFairPlayKeyMustNotBeMixedWithPairVerifySecret(t *testing.T) {
	fpKey := [16]byte{0xda, 0x98, 0x33, 0x7c, 0x29, 0x23, 0x06, 0x42, 0x45, 0xa6, 0x34, 0xf6, 0xaf, 0xf1, 0x15, 0x64}
	shared := []byte("pair-verify-shared-secret-example")
	scid := int64(1234567890123456789)

	goodKey, goodIV := deriveVideoKeys(fpKey[:], scid)

	h := sha512.New()
	h.Write(fpKey[:])
	h.Write(shared)
	mixed := h.Sum(nil)[:16]
	badKey, badIV := deriveVideoKeys(mixed, scid)

	if bytes.Equal(goodKey, badKey) || bytes.Equal(goodIV, badIV) {
		t.Fatalf("expected mixed and unmixed derivations to differ")
	}

	sender, err := newMirrorCipher(badKey, badIV)
	if err != nil {
		t.Fatalf("sender cipher: %v", err)
	}
	receiver, err := newMirrorCipher(goodKey, goodIV)
	if err != nil {
		t.Fatalf("receiver cipher: %v", err)
	}

	frame := bytes.Repeat([]byte{0xab}, 97)
	ciphertext := sender.EncryptFrame(frame)
	plaintext := receiver.EncryptFrame(ciphertext)
	if bytes.Equal(plaintext, frame) {
		t.Fatalf("unexpected decrypt success with mixed FairPlay key derivation")
	}
}
