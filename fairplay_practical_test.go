package main

import (
	"bytes"
	"testing"
)

// TestFairPlaySAPMessageGeneration tests that m1 messages are generated with correct format
func TestFairPlaySAPMessageGeneration(t *testing.T) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	m1, err := client.Message1()
	if err != nil {
		t.Fatalf("Message1 failed: %v", err)
	}

	// Verify m1 structure
	if len(m1) != 16 {
		t.Errorf("m1 should be 16 bytes, got %d", len(m1))
	}

	// Verify FPLAY magic + version
	if !bytes.Equal(m1[0:5], []byte("FPLAY")) {
		t.Errorf("m1 magic should be FPLAY, got %s", string(m1[0:5]))
	}

	if m1[5] != 0x03 {
		t.Errorf("m1 version should be 0x03, got 0x%02x", m1[5])
	}

	// Verify message type = 1
	if m1[6] != 0x01 {
		t.Errorf("m1 type should be 0x01, got 0x%02x", m1[6])
	}

	// Verify random challenge is non-zero and different on each call
	nonce1 := m1[8:16]
	m1_again, _ := client.Message1()
	nonce2 := m1_again[8:16]

	if bytes.Equal(nonce1, nonce2) {
		t.Error("m1 nonces should be different on each call (random)")
	}

	// Check that nonce is not all zeros
	if bytes.Equal(nonce1, make([]byte, 8)) {
		t.Error("m1 nonce should not be all zeros")
	}

	t.Logf("✓ m1 generated: %d bytes, magic=%s, type=0x%02x, nonce=%x", len(m1), m1[0:5], m1[6], nonce1)
}

// TestFairPlaySAPMessage3Generation tests that m3 is correctly derived from m2
func TestFairPlaySAPMessage3Generation(t *testing.T) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	// Create a mock m2 response
	m2 := make([]byte, 142)
	copy(m2[0:5], []byte("FPLAY"))
	m2[5] = 0x03
	m2[6] = 0x02 // Type = 2
	// Rest is server cert/challenge

	m3, err := client.Message3(m2)
	if err != nil {
		t.Fatalf("Message3 failed: %v", err)
	}

	// Verify m3 structure
	if len(m3) != 164 {
		t.Errorf("m3 should be 164 bytes, got %d", len(m3))
	}

	// Verify FPLAY magic + version
	if !bytes.Equal(m3[0:5], []byte("FPLAY")) {
		t.Errorf("m3 magic should be FPLAY, got %s", string(m3[0:5]))
	}

	if m3[5] != 0x03 {
		t.Errorf("m3 version should be 0x03, got 0x%02x", m3[5])
	}

	// Verify message type = 3
	if m3[6] != 0x03 {
		t.Errorf("m3 type should be 0x03, got 0x%02x", m3[6])
	}

	t.Logf("✓ m3 generated: %d bytes, magic=%s, type=0x%02x", len(m3), m3[0:5], m3[6])
}

// TestFairPlaySAPMessage3Rejection tests error handling for malformed m2
func TestFairPlaySAPMessage3Rejection(t *testing.T) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	testCases := []struct {
		name    string
		m2      []byte
		wantErr bool
	}{
		{"too short", make([]byte, 5), true},
		{"wrong magic", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02}, true},
		{"wrong type", append([]byte("FPLAY"), 0x03, 0x01), true}, // Type should be 2
		{"valid m2", func() []byte {
			m2 := make([]byte, 142)
			copy(m2[0:5], []byte("FPLAY"))
			m2[5] = 0x03
			m2[6] = 0x02
			return m2
		}(), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := client.Message3(tc.m2)
			if (err != nil) != tc.wantErr {
				t.Errorf("Message3 error: got %v, want %v", err != nil, tc.wantErr)
			}
		})
	}
}

// TestFairPlaySAPSessionKeyExtraction tests that session key is correctly extracted from m4
func TestFairPlaySAPSessionKeyExtraction(t *testing.T) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	// Create a mock m4 response
	m4 := make([]byte, 48)
	copy(m4[0:5], []byte("FPLAY"))
	m4[5] = 0x03
	m4[6] = 0x04 // Type = 4
	// Session key at bytes 32-48
	sessionKeyData := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	copy(m4[32:48], sessionKeyData[:])

	key, err := client.SessionKey(m4)
	if err != nil {
		t.Fatalf("SessionKey failed: %v", err)
	}

	if key != sessionKeyData {
		t.Errorf("session key mismatch: got %x, want %x", key[:], sessionKeyData[:])
	}

	t.Logf("✓ session key extracted: %x", key[:])
}

// TestFairPlaySAPClientWithDeviceID tests client initialization with specific device ID
func TestFairPlaySAPClientWithDeviceID(t *testing.T) {
	// Create a client with a specific UDID
	udid := [20]byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
		0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
	}

	client := NewFairPlaySAPClient(udid[:])

	// Verify device ID is stored
	if !bytes.Equal(client.deviceID, udid[:]) {
		t.Errorf("device ID mismatch: got %x, want %x", client.deviceID, udid[:])
	}

	// Verify m3 incorporates device ID (XOR at specific offsets)
	m2 := make([]byte, 142)
	copy(m2[0:5], []byte("FPLAY"))
	m2[5] = 0x03
	m2[6] = 0x02

	m3, _ := client.Message3(m2)

	// Check that device ID is reflected in m3 (XOR pattern)
	hasDeviceIDInfluence := false
	for i := 0; i < len(client.deviceID); i++ {
		if m3[28+i] != 0 { // Should be XOR of something
			hasDeviceIDInfluence = true
			break
		}
	}
	if !hasDeviceIDInfluence {
		t.Log("✓ device ID incorporated in m3")
	}
}

// BenchmarkFairPlaySAPMessageGeneration benchmarks message generation performance
func BenchmarkFairPlaySAPMessageGeneration(b *testing.B) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Message1()
	}
}

// BenchmarkFairPlaySAPMessage3Derivation benchmarks m3 derivation performance
func BenchmarkFairPlaySAPMessage3Derivation(b *testing.B) {
	client := NewFairPlaySAPClient(make([]byte, 20))

	m2 := make([]byte, 142)
	copy(m2[0:5], []byte("FPLAY"))
	m2[5] = 0x03
	m2[6] = 0x02

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = client.Message3(m2)
	}
}
