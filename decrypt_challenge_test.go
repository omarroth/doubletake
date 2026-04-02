package main

import (
	"encoding/hex"
	"testing"

	"airplay/internal/airplay"
	"airplay/playfair"
)

// TestCGoVsGoPlayfairDecrypt compares the C (CGo) playfair_decrypt
// with the pure Go playfairDecrypt for several known inputs.
// If they disagree, the pure Go port has a bug.
func TestCGoVsGoPlayfairDecrypt(t *testing.T) {
	// Build an all-zero ekey with FPLY header (same as buildEkey in fairplay.go)
	var ekey [72]byte
	copy(ekey[0:4], []byte("FPLY"))
	ekey[4] = 0x01
	ekey[5] = 0x02
	ekey[6] = 0x01
	ekey[11] = 0x3c

	// Test with mode bytes 0, 1, 2, 3
	for mode := byte(0); mode <= 3; mode++ {
		// Create a deterministic 164-byte m3
		m3 := make([]byte, 164)
		for i := range m3 {
			m3[i] = byte((i * 7) + int(mode)*13)
		}
		// Set FPLY header
		copy(m3[0:4], []byte("FPLY"))
		m3[4] = 0x03
		m3[5] = 0x01
		m3[6] = 0x03
		m3[12] = mode // mode byte used by decryptMessage

		// C implementation (CGo)
		cKey := playfair.Decrypt(m3, ekey[:])

		// Go implementation
		goKey := airplay.PlayfairDecryptExported(m3, ekey[:])

		if cKey != goKey {
			t.Errorf("mode=%d: C vs Go mismatch!\n  C:  %s\n  Go: %s",
				mode, hex.EncodeToString(cKey[:]), hex.EncodeToString(goKey[:]))
		} else {
			t.Logf("mode=%d: match OK: %s", mode, hex.EncodeToString(cKey[:]))
		}
	}
}
