package main

import (
	"bytes"
	"testing"
)

// TestFairPlaySAPClientRoundtrip validates the FairPlay SAP message exchange works end-to-end
func TestFairPlaySAPClientRoundtrip(t *testing.T) {
	// Create a client with a known device ID
	deviceID := [20]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
	}
	client := NewFairPlaySAPClient(deviceID[:])

	// Step 1: Generate m1
	m1, err := client.Message1()
	if err != nil {
		t.Fatalf("MessageI failed: %v", err)
	}
	if len(m1) != 16 {
		t.Fatalf("m1 should be 16 bytes, got %d", len(m1))
	}

	// Step 2: Simulate server response (m2)
	// In a real scenario, this would come from the AirPlay receiver
	m2 := make([]byte, 142)
	copy(m2[0:5], []byte("FPLAY"))
	m2[5] = 0x03
	m2[6] = 0x02 // Type = 2
	// Fill with some deterministic data
	for i := 8; i < len(m2); i++ {
		m2[i] = byte(i % 256)
	}

	// Step 3: Client processes m2 and generates m3
	m3, err := client.Message3(m2)
	if err != nil {
		t.Fatalf("Message3 failed: %v", err)
	}
	if len(m3) != 164 {
		t.Fatalf("m3 should be 164 bytes, got %d", len(m3))
	}

	// Step 4: Verify m3 headers are correct
	if !bytes.Equal(m3[0:5], []byte("FPLAY")) {
		t.Errorf("m3 magic wrong: %s", string(m3[0:5]))
	}
	if m3[6] != 0x03 {
		t.Errorf("m3 type wrong: %d", m3[6])
	}

	// Step 5: Simulate server accepting m3 and returning m4
	m4 := make([]byte, 48)
	copy(m4[0:5], []byte("FPLAY"))
	m4[5] = 0x03
	m4[6] = 0x04 // Type = 4
	// Place session key at bytes 32-48
	for i := 32; i < 48; i++ {
		m4[i] = byte((i * 0x13) % 256) // Deterministic test session key
	}

	// Step 6: Client extracts session key from m4
	sessionKey, err := client.SessionKey(m4)
	if err != nil {
		t.Fatalf("SessionKey failed: %v", err)
	}

	// Verify session key content
	expectedKey := [16]byte{}
	for i := 0; i < 16; i++ {
		expectedKey[i] = byte(((i + 32) * 0x13) % 256)
	}
	if sessionKey != expectedKey {
		t.Errorf("session key mismatch:\n  got:  %x\n  want: %x", sessionKey[:], expectedKey[:])
	}

	t.Logf("✓ FairPlay SAP roundtrip successful:")
	t.Logf("  m1: %d bytes", len(m1))
	t.Logf("  m2: %d bytes", len(m2))
	t.Logf("  m3: %d bytes", len(m3))
	t.Logf("  m4: %d bytes", len(m4))
	t.Logf("  session key: %x", sessionKey[:])
}

// TestFairPlaySAPMessageConsistency ensures repeated calls produce consistent results for valid input
func TestFairPlaySAPMessageConsistency(t *testing.T) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	// Create a mock m2
	m2 := make([]byte, 142)
	copy(m2[0:5], []byte("FPLAY"))
	m2[5] = 0x03
	m2[6] = 0x02
	for i := 8; i < len(m2); i++ {
		m2[i] = byte(i % 256)
	}

	// Generate m3 multiple times - the structure should be consistent
	// (though some fields may be randomized for security)
	m3_1, _ := client.Message3(m2)
	m3_2, _ := client.Message3(m2)

	// Headers should be identical
	if !bytes.Equal(m3_1[0:8], m3_2[0:8]) {
		t.Errorf("m3 headers differ between calls")
	}

	// Type and version must match
	if m3_1[6] != m3_2[6] {
		t.Errorf("m3 type differs")
	}

	t.Logf("✓ m3 structure consistent across calls (randomized content OK)")
}

// BenchmarkFairPlaySAPRoundtrip benchmarks the full SAP exchange
func BenchmarkFairPlaySAPRoundtrip(b *testing.B) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	m2 := make([]byte, 142)
	copy(m2[0:5], []byte("FPLAY"))
	m2[5] = 0x03
	m2[6] = 0x02

	m4 := make([]byte, 48)
	copy(m4[0:5], []byte("FPLAY"))
	m4[5] = 0x03
	m4[6] = 0x04

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Message1()
		_, _ = client.Message3(m2)
		_, _ = client.SessionKey(m4)
	}
}
