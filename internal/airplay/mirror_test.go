package airplay

import (
	"testing"
	"time"
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
