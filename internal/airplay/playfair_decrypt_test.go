package airplay

import (
	"encoding/hex"
	"testing"
)

// TestPlayfairDecryptDeterministic verifies that playfairDecrypt produces a
// consistent, non-zero key from a known m3 and ekey.
func TestPlayfairDecryptDeterministic(t *testing.T) {
	// Build a fixed m3 with mode=3 and deterministic payload.
	m3 := make([]byte, 164)
	copy(m3[0:4], []byte("FPLY"))
	m3[4] = 0x03
	m3[5] = 0x01
	m3[6] = 0x03
	m3[11] = 0x98
	m3[12] = 0x03 // mode byte
	for i := 13; i < 164; i++ {
		m3[i] = byte(i * 7)
	}

	ekey := buildEkey()

	key1 := playfairDecrypt(m3, ekey[:])
	key2 := playfairDecrypt(m3, ekey[:])

	if key1 != key2 {
		t.Fatalf("playfairDecrypt is not deterministic:\n  key1=%s\n  key2=%s",
			hex.EncodeToString(key1[:]), hex.EncodeToString(key2[:]))
	}

	// Verify key is non-zero.
	allZero := true
	for _, b := range key1 {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("playfairDecrypt produced all-zero key")
	}

	t.Logf("playfairDecrypt key: %s", hex.EncodeToString(key1[:]))
}

// TestPlayfairDecryptModes verifies all 4 valid mode bytes produce distinct keys.
func TestPlayfairDecryptModes(t *testing.T) {
	ekey := buildEkey()
	keys := make(map[string]byte)

	for mode := byte(0); mode <= 3; mode++ {
		m3 := make([]byte, 164)
		copy(m3[0:4], []byte("FPLY"))
		m3[4] = 0x03
		m3[5] = 0x01
		m3[6] = 0x03
		m3[11] = 0x98
		m3[12] = mode
		// Same fill for all modes (only mode byte differs).
		for i := 13; i < 164; i++ {
			m3[i] = byte(i)
		}

		key := playfairDecrypt(m3, ekey[:])
		hexKey := hex.EncodeToString(key[:])
		t.Logf("mode=%d key=%s", mode, hexKey)

		if prev, ok := keys[hexKey]; ok {
			t.Errorf("mode %d produced same key as mode %d: %s", mode, prev, hexKey)
		}
		keys[hexKey] = mode
	}
}

