package airplay

import (
	"bytes"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestCongestionController_LevelTransitions(t *testing.T) {
	cc := newCongestionController()

	// First sample at low ns/byte → no congestion.
	cc.recordSend(5000, 10*time.Microsecond) // 2 ns/byte
	if cc.level != congestionNone {
		t.Fatalf("expected congestionNone, got %d", cc.level)
	}

	// Feed high ns/byte samples to push into heavy congestion.
	for i := 0; i < 20; i++ {
		cc.recordSend(1000, 100*time.Millisecond) // 100000 ns/byte
	}
	if cc.level != congestionHeavy {
		t.Fatalf("expected congestionHeavy, got %d", cc.level)
	}

	// Feed low samples to recover.
	for i := 0; i < 30; i++ {
		cc.recordSend(5000, 5*time.Microsecond) // 1 ns/byte
	}
	if cc.level != congestionNone {
		t.Fatalf("expected recovery to congestionNone, got %d", cc.level)
	}
}

func TestCongestionController_ShouldDrop(t *testing.T) {
	cc := newCongestionController()

	// No congestion → never drop.
	cc.level = congestionNone
	for i := 0; i < 10; i++ {
		if cc.shouldDrop(i) {
			t.Fatalf("congestionNone should not drop frame %d", i)
		}
	}

	// Light → drop every 3rd frame (frameCount%3 == 0).
	cc.level = congestionLight
	cc.skipped = 0
	drops := 0
	for i := 0; i < 9; i++ {
		if cc.shouldDrop(i) {
			drops++
		}
	}
	if drops != 3 {
		t.Fatalf("congestionLight: expected 3 drops in 9 frames, got %d", drops)
	}

	// Medium → drop every 2nd frame.
	cc.level = congestionMedium
	cc.skipped = 0
	drops = 0
	for i := 0; i < 10; i++ {
		if cc.shouldDrop(i) {
			drops++
		}
	}
	if drops != 5 {
		t.Fatalf("congestionMedium: expected 5 drops in 10 frames, got %d", drops)
	}

	// Heavy → drop all.
	cc.level = congestionHeavy
	cc.skipped = 0
	for i := 0; i < 10; i++ {
		if !cc.shouldDrop(i) {
			t.Fatalf("congestionHeavy should drop frame %d", i)
		}
	}
}

func TestCongestionController_ZeroBytes(t *testing.T) {
	cc := newCongestionController()
	cc.recordSend(0, time.Millisecond)
	if cc.samples != 0 {
		t.Fatal("zero-byte send should be ignored")
	}
}

func TestIsFirstSlice(t *testing.T) {
	// NAL header 0x61 (type 1), slice header starts with bit 1 → first_mb_in_slice=0
	if !isFirstSlice([]byte{0x61, 0x80}) {
		t.Fatal("expected first slice (first_mb_in_slice=0)")
	}
	// NAL header 0x61, slice header starts with bit 0 → first_mb_in_slice > 0
	if isFirstSlice([]byte{0x61, 0x40}) {
		t.Fatal("expected non-first slice (first_mb_in_slice > 0)")
	}
	// Too short
	if isFirstSlice([]byte{0x61}) {
		t.Fatal("expected false for single-byte NAL")
	}
}

func TestPlistStreamPortsLegacy(t *testing.T) {
	stream := map[string]interface{}{
		"dataPort":    uint64(6100),
		"controlPort": uint64(6101),
	}

	dataPort, controlPort := plistStreamPorts(stream)
	if dataPort != 6100 || controlPort != 6101 {
		t.Fatalf("expected legacy ports 6100/6101, got %d/%d", dataPort, controlPort)
	}
}

func TestPlistStreamPortsStreamConnections(t *testing.T) {
	stream := map[string]interface{}{
		"dataPort":    uint64(6100),
		"controlPort": uint64(6101),
		"streamConnections": map[string]interface{}{
			"streamConnectionTypeRTP": map[string]interface{}{
				"streamConnectionKeyPort": uint64(7100),
			},
			"streamConnectionTypeRTCP": map[string]interface{}{
				"streamConnectionKeyPort": uint64(7101),
			},
		},
	}

	dataPort, controlPort := plistStreamPorts(stream)
	if dataPort != 7100 || controlPort != 7101 {
		t.Fatalf("expected streamConnections ports 7100/7101, got %d/%d", dataPort, controlPort)
	}
}

func TestGenerateAudioChaChaKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x5a}, chacha20poly1305.KeySize)

	key, err := generateAudioChaChaKey(bytes.NewReader(want))
	if err != nil {
		t.Fatalf("generateAudioChaChaKey returned error: %v", err)
	}
	if !bytes.Equal(key, want) {
		t.Fatalf("generated key = %x, want %x", key, want)
	}
}

func TestGenerateAudioChaChaKeyShortRead(t *testing.T) {
	if _, err := generateAudioChaChaKey(bytes.NewReader(make([]byte, 8))); err == nil {
		t.Fatal("expected short reader to fail")
	}
}
