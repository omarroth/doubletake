package fairplay

import (
	"bytes"
	"fmt"
)

// NewClient is the FairPlay v3 SAP client implementation.
//
// The structure of m3 is well-known:
//
//	m3 = "FPLY" || 0x03 0x01 0x03 0x00 || u32be(0x98)        (12 bytes header)
//	   || m3ConstPayload                                      (132 bytes)
//	   || H(m2[14:142])                                       (20 bytes)
//
// where m3ConstPayload is invariant across sessions/devices and H is Apple's
// white-box hash.
type NewClient struct{}

func (NewClient) Name() string { return "new" }

func (NewClient) M1() []byte {
	out := make([]byte, len(FixedM1))
	copy(out, FixedM1)
	return out
}

// m3FrameHeader is the constant 12-byte FPLY framing prepended to
// every v3 m3 (mode 3, payload length 0x98 = 152 bytes).
var m3FrameHeader = []byte{
	'F', 'P', 'L', 'Y',
	0x03, 0x01, 0x03, 0x00,
	0x00, 0x00, 0x00, 0x98,
}

// m3ConstPayload is the 132-byte constant tail observed in every m3.
// Captured from the emulator-backed path; identical across all
// sessions and devices we have observed.
var m3ConstPayload = mustHexFP(
	"038f1a9c991ea22c511e45ba97f1af8d" +
		"fb0f86f550c54486fe6b3ab233da431e" +
		"f8e5fc1156dba321fffeabb1b392b09d" +
		"227e88c712202866eb7bbf310015aa1d" +
		"19a5df36d5dfd8d3ca1639b376eaece9" +
		"46edfe8b7a66cd302d04aac3c1251714" +
		"019bd5f2d49b543e11eed1646291ec8e" +
		"fd96b69101b849fd93a02860d1a0dff5" +
		"cd4414aa")

func (NewClient) ComputeM3(m2 []byte) ([]byte, error) {
	if len(m2) < 142 {
		return nil, fmt.Errorf("fairplay: m2 too short: %d bytes (need >= 142)", len(m2))
	}
	var payload [128]byte
	copy(payload[:], m2[14:142])

	hash, err := WBHash(payload)
	if err != nil {
		return nil, fmt.Errorf("WBHash: %w", err)
	}

	out := make([]byte, 0, 164)
	out = append(out, m3FrameHeader...)
	out = append(out, m3ConstPayload...)
	out = append(out, hash[:]...)
	return out, nil
}

// NewServer is the in-process pure-Go server. Per the project plan
// (see the user's "O1" choice), m1→m2 has no oracle: we have never
// observed Apple TV's m1-to-m2 transformation rule, so this server
// returns a fixed well-formed m2 (the previously-captured Apple TV
// response by default).
//
// VerifyM3 cross-checks the hash tail using WBHash.
type NewServer struct {
	FixedM2 []byte
}

func (NewServer) Name() string { return "new" }

func (s *NewServer) ComputeM2(m1 []byte) ([]byte, error) {
	if len(m1) < 16 {
		return nil, fmt.Errorf("fairplay: m1 too short: %d bytes", len(m1))
	}
	if s.FixedM2 != nil {
		out := make([]byte, len(s.FixedM2))
		copy(out, s.FixedM2)
		return out, nil
	}
	out := make([]byte, len(capturedM2))
	copy(out, capturedM2)
	return out, nil
}

func (s *NewServer) VerifyM3(m2, m3 []byte) error {
	if len(m3) < 164 {
		return fmt.Errorf("%w: m3 length %d < 164", ErrM3Invalid, len(m3))
	}
	if len(m2) < 142 {
		return fmt.Errorf("%w: m2 length %d < 142", ErrM3Invalid, len(m2))
	}
	var payload [128]byte
	copy(payload[:], m2[14:142])
	expected, err := WBHash(payload)
	if err != nil {
		return fmt.Errorf("WBHash: %w", err)
	}
	if !bytes.Equal(m3[144:164], expected[:]) {
		return fmt.Errorf("%w: hash tail mismatch\n  got:  %x\n  want: %x",
			ErrM3Invalid, m3[144:164], expected[:])
	}
	return nil
}
