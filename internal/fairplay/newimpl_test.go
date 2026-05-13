package fairplay

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestNewClientComputeM3CapturedM2(t *testing.T) {
	client := NewClient{}
	m3, err := client.ComputeM3(capturedM2)
	if err != nil {
		t.Fatalf("ComputeM3 failed: %v", err)
	}

	if len(m3) != 164 {
		t.Fatalf("m3 length = %d, want 164", len(m3))
	}
	if !bytes.Equal(m3[:12], m3FrameHeader) {
		t.Fatalf("m3 header = %x, want %x", m3[:12], m3FrameHeader)
	}
	if !bytes.Equal(m3[12:144], m3ConstPayload) {
		t.Fatalf("m3 constant payload mismatch")
	}

	wantTail := mustHashHex(t, "4b911e48af23d8406368aeafbb61bfcd569e3e55")
	if got := m3[144:164]; !bytes.Equal(got, wantTail[:]) {
		t.Fatalf("m3 hash tail = %x, want %x", got, wantTail)
	}

	server := NewServer{FixedM2: capturedM2}
	if err := server.VerifyM3(capturedM2, m3); err != nil {
		t.Fatalf("VerifyM3 failed: %v", err)
	}
}

func TestWBHashGoldenVectors(t *testing.T) {
	tests := []struct {
		name string
		data [128]byte
		hash string
	}{
		{name: "all-zeros", hash: "6f627565f3e77f5b5ede91beee7baf92e4241e0b"},
		{name: "all-0xFF", data: filledPayload(0xff), hash: "dc2cc74f2ed55484f59f95b96082f0f5c017dd17"},
		{name: "capturedM2", data: capturedPayload(), hash: "4b911e48af23d8406368aeafbb61bfcd569e3e55"},
		{name: "0x42-at-0", data: payloadWithByte(0, 0x42), hash: "9bfb9556b8659c2ac94b7ef9e587d71e159ea624"},
		{name: "0x42-at-63", data: payloadWithByte(63, 0x42), hash: "150d9fa4eb456e73ba48de5779c5c996b16b3b23"},
		{name: "0x42-at-64", data: payloadWithByte(64, 0x42), hash: "a167db30424ff8890d085c0f1c92b2c5cc06fc45"},
		{name: "0x42-at-127", data: payloadWithByte(127, 0x42), hash: "d246ec5e7adc8118994b8df77146529486ac7caf"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := WBHash(tc.data)
			if err != nil {
				t.Fatalf("WBHash failed: %v", err)
			}

			want := mustHashHex(t, tc.hash)
			if got != want {
				t.Fatalf("WBHash = %x, want %x", got, want)
			}
		})
	}
}

func capturedPayload() [128]byte {
	var payload [128]byte
	copy(payload[:], capturedM2[14:142])
	return payload
}

func filledPayload(value byte) [128]byte {
	var payload [128]byte
	for i := range payload {
		payload[i] = value
	}
	return payload
}

func payloadWithByte(index int, value byte) [128]byte {
	var payload [128]byte
	payload[index] = value
	return payload
}

func mustHashHex(t *testing.T, value string) [20]byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hash %q: %v", value, err)
	}
	if len(decoded) != 20 {
		t.Fatalf("decoded hash length = %d, want 20", len(decoded))
	}
	var out [20]byte
	copy(out[:], decoded)
	return out
}
