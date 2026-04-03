//go:build !emulate

package fpemu

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

func TestBuildM3FromSignatureKnownVectors(t *testing.T) {
	cases := []struct {
		name    string
		fill    func(*[128]byte)
		wantSig string
	}{
		{
			name:    "zero",
			fill:    func(ch *[128]byte) {},
			wantSig: "6f627565f3e77f5b5ede91beee7baf92e4241e0b",
		},
		{
			name: "sequential",
			fill: func(ch *[128]byte) {
				for i := range ch {
					ch[i] = byte(i)
				}
			},
			wantSig: "84449e19d306930b66942aacfb71395a903878ef",
		},
	}

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	for _, tc := range cases {
		var ch [128]byte
		tc.fill(&ch)
		m2 := buildTestM2(ch)

		sig, err := SignatureFromM2(hwInfo, m2)
		if err != nil {
			t.Fatalf("%s: signature error: %v", tc.name, err)
		}
		gotSig := hex.EncodeToString(sig[:])
		if gotSig != tc.wantSig {
			t.Fatalf("%s: sig mismatch got=%s want=%s", tc.name, gotSig, tc.wantSig)
		}

		m3 := BuildM3FromSignature(sig)
		if len(m3) != 164 {
			t.Fatalf("%s: m3 len=%d want=164", tc.name, len(m3))
		}
		if string(m3[:4]) != "FPLY" {
			t.Fatalf("%s: missing FPLY header", tc.name)
		}

		payload := m3[12:]
		if !bytes.Equal(payload[:132], m3StaticPayload) {
			t.Fatalf("%s: static payload mismatch", tc.name)
		}
		if !bytes.Equal(payload[132:], sig[:]) {
			t.Fatalf("%s: signature suffix mismatch", tc.name)
		}
	}
}
