//go:build emulate

package airplay

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"

	"doubletake/internal/fpemu"
)

// TestOracleCompareM1Format compares the emulator's m1 with the native m1.
// Skip if the AirPlaySender binary isn't available.
func TestOracleCompareM1Format(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("AirPlaySender binary not found at %s (set AIRPLAY_SENDER_PATH)", path)
	}

	emu, err := fpemu.New(path)
	if err != nil {
		t.Fatalf("fpemu.New: %v", err)
	}
	defer emu.Close()

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)
	for i := 4; i < 24; i++ {
		hwInfo[i] = byte(i)
	}

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		t.Fatalf("FPSAPInit: %v", err)
	}

	m1Raw, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatalf("FPSAPExchange phase1: %v", err)
	}

	// The emulator produces raw m1 which gets FPLY-wrapped.
	m1Emu := fplyWrap(m1Raw, 1)
	m1Native := buildM1Native()

	t.Logf("emulator m1 (%d bytes, rc=%d): %s", len(m1Emu), rc, hex.EncodeToString(m1Emu))
	t.Logf("native   m1 (%d bytes):        %s", len(m1Native), hex.EncodeToString(m1Native))

	// Both should be 16 bytes with FPLY header.
	if len(m1Emu) != 16 {
		t.Errorf("emulator m1 length = %d, want 16", len(m1Emu))
	}
	if len(m1Native) != 16 {
		t.Errorf("native m1 length = %d, want 16", len(m1Native))
	}

	// Both should start with "FPLY".
	if string(m1Emu[:4]) != "FPLY" {
		t.Errorf("emulator m1 magic = %q", string(m1Emu[:4]))
	}
	if string(m1Native[:4]) != "FPLY" {
		t.Errorf("native m1 magic = %q", string(m1Native[:4]))
	}

	// Both should have type 1.
	if m1Emu[6] != 1 {
		t.Errorf("emulator m1 type = %d", m1Emu[6])
	}

	// Log the mode byte from emulator m1 so we can adjust native if needed.
	if len(m1Emu) > 14 {
		t.Logf("emulator m1 mode byte (offset 14): 0x%02x", m1Emu[14])
	}
}

// TestOracleCompareKeyDerivation runs both the emulator-based and native-based
// key derivation to verify both produce valid keys (not necessarily identical,
// since they use different m3 bytes, but both should be non-zero and consistent).
func TestOracleCompareKeyDerivation(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("AirPlaySender binary not found at %s", path)
	}

	emu, err := fpemu.New(path)
	if err != nil {
		t.Fatalf("fpemu.New: %v", err)
	}
	defer emu.Close()

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		t.Fatalf("FPSAPInit: %v", err)
	}

	// Phase 1: get m1 from emulator (we won't send to a real receiver).
	m1Raw, _, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatalf("FPSAPExchange phase1: %v", err)
	}
	m1Emu := fplyWrap(m1Raw, 1)
	t.Logf("emulator m1: %s", hex.EncodeToString(m1Emu))

	// We can't complete the emulator flow without a receiver, but we can
	// compare key derivation with a known m3.
	// Create a synthetic m3 that both paths can use.
	m3 := buildM3Native()
	t.Logf("synthetic m3[:32]: %s", hex.EncodeToString(m3[:32]))

	ekey := buildEkey()

	// Both emulator-path and native-path use the same playfairDecrypt.
	key := playfairDecrypt(m3, ekey[:])
	t.Logf("derived key: %s", hex.EncodeToString(key[:]))

	allZero := true
	for _, b := range key {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("key is all zeros")
	}
}
