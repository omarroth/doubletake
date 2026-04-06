//go:build !emulate

package airplay

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"
)

// TestFPSetupWithoutEmulator tests whether the Apple TV accepts a m3 with
// correct constant bytes but random 20-byte tail (i.e., without running
// FPSAPExchange / the ARM64 emulator).
//
// If the Apple TV accepts it, we can eliminate the emulator entirely.
//
// Usage:
//
//	APPLE_TV=192.168.1.77 go test -run TestFPSetupWithoutEmulator ./internal/airplay/ -v -count=1
func TestFPSetupWithoutEmulator(t *testing.T) {
	host := os.Getenv("APPLE_TV")
	if host == "" {
		t.Skip("Set APPLE_TV=<ip> to test")
	}

	DebugMode = true
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	credStore, err := NewCredentialStore(DefaultCredentialsPath())
	if err != nil {
		t.Fatalf("load credentials: %v", err)
	}

	client := NewAirPlayClient(host, 7000)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()

	info, err := client.GetInfo()
	if err != nil {
		t.Fatalf("get info: %v", err)
	}
	t.Logf("Device: %s (%s), ID: %s", info.Name, info.Model, info.DeviceID)

	savedCreds := credStore.Lookup(info.DeviceID)
	if savedCreds == nil {
		t.Fatal("no saved credentials. Run doubletake with --pair first")
	}

	pub, priv := savedCreds.Ed25519Keys()
	client.PairingID = savedCreds.PairingID
	client.PairKeys = &PairKeys{
		Ed25519Public:  pub,
		Ed25519Private: priv,
	}

	if err := client.PairVerify(ctx); err != nil {
		t.Fatalf("pair-verify: %v", err)
	}
	t.Log("pair-verify succeeded")

	// Phase 1: Send m1, get m2
	m1 := mustDecodeHexFP("46504c590301010000000004020003bb")
	m2, err := client.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		t.Fatalf("fp-setup phase 1: %v", err)
	}
	t.Logf("m2 (%d bytes): %s", len(m2), hex.EncodeToString(m2))

	// Phase 2: Build m3 WITHOUT the emulator
	// First 144 bytes are constant (from previous emulator runs)
	constM3Hex := "46504c590301030000000098" + // FPLY header (12 bytes)
		"038f1a9c991ea22c511e45ba97f1af8d" +
		"fb0f86f550c54486fe6b3ab233da431e" +
		"f8e5fc1156dba321fffeabb1b392b09d" +
		"227e88c712202866eb7bbf310015aa1d" +
		"19a5df36d5dfd8d3ca1639b376eaece9" +
		"46edfe8b7a66cd302d04aac3c1251714" +
		"019bd5f2d49b543e11eed1646291ec8e" +
		"fd96b69101b849fd93a02860d1a0dff5" +
		"cd4414aa" // ends at offset 144

	constM3, _ := hex.DecodeString(constM3Hex)
	if len(constM3) != 144 {
		t.Fatalf("expected 144 constant bytes, got %d", len(constM3))
	}

	// Append 20 random bytes as the tail
	tail := make([]byte, 20)
	if _, err := rand.Read(tail); err != nil {
		t.Fatal(err)
	}
	m3 := append(constM3, tail...)
	t.Logf("m3 (%d bytes, random tail): %s", len(m3), hex.EncodeToString(m3))

	// Send fake m3 to Apple TV
	m4, err := client.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		t.Fatalf("fp-setup phase 2 (fake m3): %v", err)
	}

	t.Logf("Apple TV ACCEPTED fake m3!")
	t.Logf("m4 (%d bytes): %s", len(m4), hex.EncodeToString(m4))

	// Check if m4 contains the last 20 bytes of m3 (echo pattern)
	m4Payload := fplyUnwrap(m4)
	if len(m4Payload) >= 20 {
		echoed := m4Payload[:20]
		t.Logf("m4 payload first 20 bytes: %s", hex.EncodeToString(echoed))
		t.Logf("m3 tail:                   %s", hex.EncodeToString(tail))
		if hex.EncodeToString(echoed) == hex.EncodeToString(tail) {
			t.Log("CONFIRMED: Apple TV echoes back our random tail! No emulator needed!")
		}
	}
}
