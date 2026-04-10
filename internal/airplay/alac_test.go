package airplay

import (
	"encoding/hex"
	"math"
	"testing"
)

func TestALACVerbatimEncoding(t *testing.T) {
	// Generate a 440 Hz sine wave frame: 352 samples, stereo, 16-bit, 44100 Hz
	const spf = 352
	const channels = 2
	const sampleRate = 44100
	const freq = 440.0

	pcm := make([]byte, spf*channels*2)
	for i := 0; i < spf; i++ {
		sample := int16(math.Sin(2*math.Pi*freq*float64(i)/sampleRate) * 16000)
		// S16LE format
		for ch := 0; ch < channels; ch++ {
			off := (i*channels + ch) * 2
			pcm[off] = byte(sample)
			pcm[off+1] = byte(sample >> 8)
		}
	}

	// Encode
	out := make([]byte, 4096)
	n := encodeALACVerbatim(out, pcm, spf, channels, 16)
	out = out[:n]

	t.Logf("ALAC frame: %d bytes", n)
	t.Logf("First 16 bytes (hex): %s", hex.EncodeToString(out[:min(16, n)]))

	// Verify header bits
	// Byte 0: 001 0000 0 = 0x20 (TYPE_CPE=1, elemTag=0, unused starts)
	if out[0] != 0x20 {
		t.Errorf("byte 0: got 0x%02x, want 0x20", out[0])
	}
	// Byte 1: 00000000 (unused continuation)
	if out[1] != 0x00 {
		t.Errorf("byte 1: got 0x%02x, want 0x00", out[1])
	}
	// Byte 2 contains packed flag/sample-count boundary bits; keep this check
	// loose and rely on the exact known-good prefix below.
	if out[2] == 0x00 {
		t.Errorf("byte 2 unexpectedly zero")
	}
	if n >= 8 {
		wantPrefix := "200012000002c0"
		gotPrefix := hex.EncodeToString(out[:7])
		if gotPrefix != wantPrefix {
			t.Errorf("header prefix: got %s, want %s", gotPrefix, wantPrefix)
		}
	}

	// Expected frame size: hasSize=1, with 32-bit numSamples field
	// = 23 header bits + 32 numSamples + 352*2*16 sample bits + 3 end bits
	// = 23 + 32 + 11264 + 3 = 11322 bits = 1415.25 → 1416 bytes
	expectedSize := (23 + 32 + spf*channels*16 + 3 + 7) / 8 // round up
	t.Logf("Expected size: %d bytes", expectedSize)
	if n != expectedSize {
		t.Errorf("frame size: got %d, want %d", n, expectedSize)
	}

	// Verify that encoded data has non-zero samples (sine wave, not silence)
	// Sample data starts at bit 55 (byte 6, bit 7)
	// Just check that bytes 7-20 aren't all zero
	allZero := true
	for i := 7; i < min(20, n); i++ {
		if out[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("sample data appears to be all zeros (silence)")
	}

	// Test with all-zero PCM (silence) to verify encoding still works
	silentPCM := make([]byte, spf*channels*2)
	silentOut := make([]byte, 4096)
	sn := encodeALACVerbatim(silentOut, silentPCM, spf, channels, 16)
	t.Logf("Silent frame: %d bytes, first 16: %s", sn, hex.EncodeToString(silentOut[:min(16, sn)]))
}
