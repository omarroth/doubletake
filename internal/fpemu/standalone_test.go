package fpemu

import (
	"encoding/hex"
	"testing"
)

// Known-good hashes verified against the ARM64 emulator.
var goldenVectors = []struct {
	name string
	data [128]byte
	hash string // hex of 20-byte WB-AES hash
}{
	{name: "all-zeros", hash: "6f627565f3e77f5b5ede91beee7baf92e4241e0b"},
	{name: "all-0xFF", hash: "dc2cc74f2ed55484f59f95b96082f0f5c017dd17"},
	{name: "capturedM2", hash: "4b911e48af23d8406368aeafbb61bfcd569e3e55"},
	{name: "0x42-at-0", hash: "9bfb9556b8659c2ac94b7ef9e587d71e159ea624"},
	{name: "0x42-at-63", hash: "150d9fa4eb456e73ba48de5779c5c996b16b3b23"},
	{name: "0x42-at-64", hash: "a167db30424ff8890d085c0f1c92b2c5cc06fc45"},
	{name: "0x42-at-127", hash: "d246ec5e7adc8118994b8df77146529486ac7caf"},
}

func init() {
	for i := range goldenVectors[1].data {
		goldenVectors[1].data[i] = 0xFF
	}
	copy(goldenVectors[2].data[:], capturedM2[14:142])
	goldenVectors[3].data[0] = 0x42
	goldenVectors[4].data[63] = 0x42
	goldenVectors[5].data[64] = 0x42
	goldenVectors[6].data[127] = 0x42
}

func TestStandalone(t *testing.T) {
	for _, tc := range goldenVectors {
		t.Run(tc.name, func(t *testing.T) {
			got := FPSAPExchangeStandalone(tc.data)
			gotHex := hex.EncodeToString(got[:])
			if gotHex != tc.hash {
				t.Errorf("got %s, want %s", gotHex, tc.hash)
			}
		})
	}
}

func TestFPSAPExchangeM3(t *testing.T) {
	m2 := make([]byte, 142)
	copy(m2, capturedM2)
	m3, err := FPSAPExchangeM3(m2)
	if err != nil {
		t.Fatal(err)
	}
	if len(m3) != 164 {
		t.Fatalf("m3 length %d, want 164", len(m3))
	}
	// Check FPLY header
	if string(m3[:4]) != "FPLY" {
		t.Errorf("m3 missing FPLY header")
	}
	// Check hash portion matches golden vector
	gotHash := hex.EncodeToString(m3[144:])
	if gotHash != "4b911e48af23d8406368aeafbb61bfcd569e3e55" {
		t.Errorf("m3 hash = %s, want 4b911e48af23d8406368aeafbb61bfcd569e3e55", gotHash)
	}
}
