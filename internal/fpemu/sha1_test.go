//go:build !emulate

package fpemu

import (
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestIsSHA1 tests if the signature could be standard SHA-1 of the m2 challenge data.
func TestIsSHA1(t *testing.T) {
	// Known: zero m2 challenge → sig 6f627565f3e77f5b5ede91beee7baf92e4241e0b
	// The m2 challenge is bytes [14:142] of the m2 message (128 zero bytes for this case)

	zeroChallenge := make([]byte, 128)

	// Test 1: SHA-1 of just the 128 zero bytes
	h1 := sha1.Sum(zeroChallenge)
	t.Logf("SHA-1(zero_128):   %s", hex.EncodeToString(h1[:]))

	// Test 2: SHA-1 of the full 142-byte m2
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03
	h2 := sha1.Sum(m2)
	t.Logf("SHA-1(full_m2):    %s", hex.EncodeToString(h2[:]))

	// Test 3: SHA-1 of the 130-byte m2 payload (after FPLY header)
	h3 := sha1.Sum(m2[12:])
	t.Logf("SHA-1(m2_payload): %s", hex.EncodeToString(h3[:]))

	expectedSig := "6f627565f3e77f5b5ede91beee7baf92e4241e0b"
	t.Logf("expected sig:      %s", expectedSig)

	// None of these will match (white-box crypto), but worth checking
	if hex.EncodeToString(h1[:]) == expectedSig || hex.EncodeToString(h2[:]) == expectedSig || hex.EncodeToString(h3[:]) == expectedSig {
		t.Log("MATCH: it IS standard SHA-1!")
	} else {
		t.Log("No standard SHA-1 match")
	}

	// Test HMAC-SHA1 with various keys
	// The SAP IV from playfair.go: 2B84FB79DA75B904 6C2473F7D1C4AB0E 2B84FB7975B9046C 2473
	// Let's try a few obvious key candidates
	hmacKeys := [][]byte{
		{0x2B, 0x84, 0xFB, 0x79, 0xDA, 0x75, 0xB9, 0x04, 0x6C, 0x24, 0x73, 0xF7, 0xD1, 0xC4, 0xAB, 0x0E},
		{0xA1, 0x1A, 0x4A, 0x83, 0xF2, 0x7A, 0x75, 0xEE, 0xA2, 0x1A, 0x7D, 0xB8, 0x8D, 0x77, 0x92, 0xAB},
		{0xDC, 0xDC, 0xF3, 0xB9, 0x0B, 0x74, 0xDC, 0xFB, 0x86, 0x7F, 0xF7, 0x60, 0x16, 0x72, 0x90, 0x51},
	}

	for i, key := range hmacKeys {
		import_hmac := sha1.New
		_ = import_hmac
		// HMAC-SHA1(key, message) = SHA1((key ⊕ opad) || SHA1((key ⊕ ipad) || message))
		// Just test SHA-1(key || message) as a simpler variant
		data := append(key, zeroChallenge...)
		h := sha1.Sum(data)
		t.Logf("SHA-1(key%d || zero_128): %s", i, hex.EncodeToString(h[:]))

		data2 := append(zeroChallenge, key...)
		h2 := sha1.Sum(data2)
		t.Logf("SHA-1(zero_128 || key%d): %s", i, hex.EncodeToString(h2[:]))
	}
}
