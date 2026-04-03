//go:build !emulate

package fpemu

import (
	"encoding/hex"
	"fmt"
)

// m3StaticPayload is the 132-byte constant section of the m3 payload.
// Deobfuscation result: these bytes do not depend on m2, m1, or hwInfo.
const m3StaticPayloadHex = "038f1a9c991ea22c511e45ba97f1af8dfb0f86f550c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c712202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b69101b849fd93a02860d1a0dff5cd4414aa"

var m3StaticPayload = mustDecodeHex(m3StaticPayloadHex)

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// BuildM3FromSignature constructs the full FPLY-framed m3 from the dynamic
// 20-byte signature. The 132-byte payload prefix is constant.
func BuildM3FromSignature(sig [20]byte) []byte {
	m3 := make([]byte, 12+132+20)
	copy(m3[0:4], []byte("FPLY"))
	m3[4] = 0x03
	m3[5] = 0x01
	m3[6] = 0x03
	m3[7] = 0x00
	m3[8] = 0x00
	m3[9] = 0x00
	m3[10] = 0x00
	m3[11] = 0x98 // 152-byte payload
	copy(m3[12:12+132], m3StaticPayload)
	copy(m3[12+132:], sig[:])
	return m3
}

// SignatureFromM2 computes the dynamic 20-byte m3 signature from m2.
//
// Current state: this still uses the snapshot-backed emulator as the oracle.
// Future deobfuscation work should replace this with a native Go implementation
// of the signature algorithm.
func SignatureFromM2(hwInfo []byte, m2 []byte) ([20]byte, error) {
	var sig [20]byte
	emu, err := NewFromSnapshot()
	if err != nil {
		return sig, fmt.Errorf("load snapshot: %w", err)
	}
	defer emu.Close()
	ctx, err := SnapshotCtx()
	if err != nil {
		return sig, fmt.Errorf("snapshot ctx: %w", err)
	}

	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		return sig, fmt.Errorf("FPSAPExchange: %w", err)
	}

	payload := m3
	if len(m3) >= 12 && string(m3[:4]) == "FPLY" {
		payload = m3[12:]
	}
	if len(payload) != 152 {
		return sig, fmt.Errorf("unexpected m3 payload length: %d", len(payload))
	}
	copy(sig[:], payload[132:152])
	return sig, nil
}
