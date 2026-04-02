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

// TestBuildM1Native verifies the m1 structure is well-formed FPLY.
func TestBuildM1Native(t *testing.T) {
	m1 := buildM1Native()
	if len(m1) != 16 {
		t.Fatalf("m1 length = %d, want 16", len(m1))
	}
	if string(m1[0:4]) != "FPLY" {
		t.Errorf("m1 magic = %q, want FPLY", string(m1[0:4]))
	}
	if m1[6] != 0x01 {
		t.Errorf("m1 type = %d, want 1", m1[6])
	}
	// Payload length = 4.
	if m1[11] != 0x04 {
		t.Errorf("m1 payload length byte = %d, want 4", m1[11])
	}
}

// TestBuildM3Native verifies the m3 structure is well-formed FPLY with valid mode.
func TestBuildM3Native(t *testing.T) {
	m3 := buildM3Native()
	if len(m3) != 164 {
		t.Fatalf("m3 length = %d, want 164", len(m3))
	}
	if string(m3[0:4]) != "FPLY" {
		t.Errorf("m3 magic = %q, want FPLY", string(m3[0:4]))
	}
	if m3[6] != 0x03 {
		t.Errorf("m3 type = %d, want 3", m3[6])
	}
	if m3[11] != 0x98 {
		t.Errorf("m3 payload length byte = %d, want 0x98", m3[11])
	}
	mode := m3[12]
	if mode > 3 {
		t.Errorf("m3 mode byte = %d, must be 0-3", mode)
	}

	// Verify key derivation doesn't panic.
	ekey := buildEkey()
	key := playfairDecrypt(m3, ekey[:])
	t.Logf("derived key: %s", hex.EncodeToString(key[:]))
}

// TestNativeKeyDerivationConsistency verifies that two calls to buildM3Native
// produce different m3 (randomized) but each one derives a valid key.
func TestNativeKeyDerivationConsistency(t *testing.T) {
	m3a := buildM3Native()
	m3b := buildM3Native()
	ekey := buildEkey()

	keyA := playfairDecrypt(m3a, ekey[:])
	keyB := playfairDecrypt(m3b, ekey[:])

	// Different random m3 should produce different keys (with overwhelming probability).
	if keyA == keyB {
		t.Error("two random m3 produced the same key — extremely unlikely")
	}

	// But each key should be non-zero.
	for _, key := range [][16]byte{keyA, keyB} {
		allZero := true
		for _, b := range key {
			if b != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Error("derived key is all zeros")
		}
	}
}
