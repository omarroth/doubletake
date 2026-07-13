package airplay

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestFPSAPTableData(t *testing.T) {
	const want = "28d0986abebe30458348dfa2957aa1d52d6f3ad5a9468c5d8a9c4139b7ca2b43"
	if len(fpsapTableData) != 90128 {
		t.Fatalf("table length = %d, want 90128", len(fpsapTableData))
	}
	got := sha256.Sum256(fpsapTableData[:])
	if gotHex := hex.EncodeToString(got[:]); gotHex != want {
		t.Fatalf("table checksum = %s, want %s", gotHex, want)
	}
}

func TestFPSAPExchangeGoldenVectors(t *testing.T) {
	capturedM2 := mustDecodeHexFP("46504c59030102000000008202034a114c26b77d4e2eec2c8f89fdb653b5b32d3576bc176816d110a14c3f53c08dbb936183bfdfe0a4f3c12e85216003b46f738c40c54da6c436d29d1b342d63c7b314309ae79a33bb1787709ef077cbfe4190117a3423e270fd1a2eac44da1a7934f59dc681d1b70783f228c4d077c2d495f5285c3bf8df586fc2ebfe17fb5b65")
	tests := []struct {
		name    string
		payload [128]byte
		want    string
	}{
		{name: "all-zeros", want: "6f627565f3e77f5b5ede91beee7baf92e4241e0b"},
		{name: "all-ff", payload: filledFPSAPPayload(0xff), want: "dc2cc74f2ed55484f59f95b96082f0f5c017dd17"},
		{name: "captured-m2", payload: func() (p [128]byte) { copy(p[:], capturedM2[14:142]); return }(), want: "4b911e48af23d8406368aeafbb61bfcd569e3e55"},
		{name: "42-at-0", payload: sparseFPSAPPayload(0), want: "9bfb9556b8659c2ac94b7ef9e587d71e159ea624"},
		{name: "42-at-63", payload: sparseFPSAPPayload(63), want: "150d9fa4eb456e73ba48de5779c5c996b16b3b23"},
		{name: "42-at-64", payload: sparseFPSAPPayload(64), want: "a167db30424ff8890d085c0f1c92b2c5cc06fc45"},
		{name: "42-at-127", payload: sparseFPSAPPayload(127), want: "d246ec5e7adc8118994b8df77146529486ac7caf"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fpsapExchangeStandalone(tc.payload)
			if gotHex := hex.EncodeToString(got[:]); gotHex != tc.want {
				t.Fatalf("hash = %s, want %s", gotHex, tc.want)
			}
		})
	}
}

func TestFPSAPDescriptor(t *testing.T) {
	tests := []struct {
		name    string
		payload [128]byte
		want    string
	}{
		{name: "zero", want: "7e38958ffe4ed433743919fe7eb16376afa4eb9e"},
		{name: "one-at-zero", payload: func() (p [128]byte) { p[0] = 1; return }(), want: "ea46797d726c6a9be43ffa72385ff97ce1c54f1b"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := fpsapDescriptor(fpsapDynamicSAP(tc.payload))
			if gotHex := hex.EncodeToString(got[:]); gotHex != tc.want {
				t.Fatalf("descriptor = %s, want %s", gotHex, tc.want)
			}
		})
	}
}

func TestFPSAPExchangeM3(t *testing.T) {
	m2 := make([]byte, 142)
	m3, err := fpsapExchangeM3(m2)
	if err != nil {
		t.Fatal(err)
	}
	if len(m3) != 164 {
		t.Fatalf("m3 length = %d, want 164", len(m3))
	}
	if string(m3[:4]) != "FPLY" {
		t.Fatalf("m3 header = %q", m3[:4])
	}
	const wantHash = "6f627565f3e77f5b5ede91beee7baf92e4241e0b"
	if gotHash := hex.EncodeToString(m3[144:]); gotHash != wantHash {
		t.Fatalf("m3 hash = %s, want %s", gotHash, wantHash)
	}
	if _, err := fpsapExchangeM3(make([]byte, 141)); err == nil {
		t.Fatal("short m2 was accepted")
	}
}

func filledFPSAPPayload(value byte) (payload [128]byte) {
	for i := range payload {
		payload[i] = value
	}
	return payload
}

func sparseFPSAPPayload(index int) (payload [128]byte) {
	payload[index] = 0x42
	return payload
}
