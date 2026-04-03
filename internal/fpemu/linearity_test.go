//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

func goEmuSetup(t *testing.T) (*Emulator, uint64, []byte) {
	t.Helper()
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	emu, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		emu.Close()
		t.Fatalf("FPSAPInit: %v", err)
	}

	// Phase 1: generate m1
	_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		emu.Close()
		t.Fatalf("FPSAPExchange phase1: %v", err)
	}

	return emu, ctx, hwInfo
}

func buildTestM2(challenge [128]byte) []byte {
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03
	copy(m2[14:], challenge[:])
	return m2
}

func getSig(t *testing.T, challenge [128]byte) []byte {
	t.Helper()
	emu, ctx, hwInfo := goEmuSetup(t)
	defer emu.Close()

	m2 := buildTestM2(challenge)
	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatalf("FPSAPExchange: %v", err)
	}

	// Strip FPLY header if present
	payload := m3
	if len(m3) > 12 && string(m3[:4]) == "FPLY" {
		payload = m3[12:]
	}
	if len(payload) != 152 {
		t.Fatalf("unexpected payload length: %d", len(payload))
	}
	// Last 20 bytes are the signature
	sig := make([]byte, 20)
	copy(sig, payload[132:])
	return sig
}

func xorBytes(a, b []byte) []byte {
	r := make([]byte, len(a))
	for i := range r {
		r[i] = a[i] ^ b[i]
	}
	return r
}

// TestLinearitySig tests whether the 20-byte signature is an affine/linear function
// in GF(2) of the 128-byte m2 challenge.
// If f(a^b) = f(a)^f(b)^f(0), it's affine and can be computed as a bit matrix.
func TestLinearitySig(t *testing.T) {
	// f(0)
	var zero [128]byte
	sig0 := getSig(t, zero)
	t.Logf("f(0)   = %s", hex.EncodeToString(sig0))

	// f(a): single byte set
	var a [128]byte
	a[0] = 0x01
	sigA := getSig(t, a)
	t.Logf("f(a)   = %s", hex.EncodeToString(sigA))

	// f(b): different byte set
	var b [128]byte
	b[1] = 0x01
	sigB := getSig(t, b)
	t.Logf("f(b)   = %s", hex.EncodeToString(sigB))

	// f(a^b): both bytes set
	var ab [128]byte
	ab[0] = 0x01
	ab[1] = 0x01
	sigAB := getSig(t, ab)
	t.Logf("f(a^b) = %s", hex.EncodeToString(sigAB))

	// Affine test: f(a^b) should equal f(a) ^ f(b) ^ f(0)
	expected := xorBytes(xorBytes(sigA, sigB), sig0)
	t.Logf("f(a)^f(b)^f(0) = %s", hex.EncodeToString(expected))

	if hex.EncodeToString(sigAB) == hex.EncodeToString(expected) {
		t.Log("AFFINE CONFIRMED: f(a^b) = f(a) ^ f(b) ^ f(0)")
	} else {
		t.Log("NOT AFFINE: f(a^b) != f(a) ^ f(b) ^ f(0)")
		// Show where they differ
		for i := 0; i < 20; i++ {
			if sigAB[i] != expected[i] {
				t.Logf("first diff at byte %d: got 0x%02x, want 0x%02x", i, sigAB[i], expected[i])
				break
			}
		}
		return
	}

	// Additional verification with more test vectors
	var c [128]byte
	c[63] = 0x80
	sigC := getSig(t, c)

	var ac [128]byte
	ac[0] = 0x01
	ac[63] = 0x80
	sigAC := getSig(t, ac)

	expectedAC := xorBytes(xorBytes(sigA, sigC), sig0)
	if hex.EncodeToString(sigAC) == hex.EncodeToString(expectedAC) {
		t.Log("AFFINE CONFIRMED (second test): f(a^c) = f(a) ^ f(c) ^ f(0)")
	} else {
		t.Log("NOT AFFINE (second test failed)")
	}

	// Triple XOR test
	var abc [128]byte
	abc[0] = 0x01
	abc[1] = 0x01
	abc[63] = 0x80
	sigABC := getSig(t, abc)

	// For affine: f(a^b^c) = f(a) ^ f(b) ^ f(c) ^ f(0) ^ f(0) = f(a) ^ f(b) ^ f(c) ^ f(0)
	// Actually for affine f(x) = Mx + b where b = f(0):
	// f(a^b^c) = M(a^b^c) + b = Ma ^ Mb ^ Mc ^ b = (f(a)-b) ^ (f(b)-b) ^ (f(c)-b) ^ b
	//          = f(a) ^ f(b) ^ f(c) ^ b ^ b ^ b ^ b = f(a) ^ f(b) ^ f(c) ^ f(0)
	// Wait, let me be more careful. f(x) = Mx ^ f(0)
	// f(a^b^c) = M(a^b^c) ^ f(0) = Ma ^ Mb ^ Mc ^ f(0)
	//   = (f(a) ^ f(0)) ^ (f(b) ^ f(0)) ^ (f(c) ^ f(0)) ^ f(0)
	//   = f(a) ^ f(b) ^ f(c) ^ f(0) ^ f(0) ^ f(0) ^ f(0)
	//   = f(a) ^ f(b) ^ f(c) ^ f(0)   [since f(0)^f(0) = 0]
	// Hmm no. Let's count: 3 f(0)s from expanding + 1 explicit = 4 f(0)s, which is even, so they cancel:
	// f(a) ^ f(b) ^ f(c) ^ (f(0) ^ f(0) ^ f(0) ^ f(0))
	// = f(a) ^ f(b) ^ f(c) ^ 0 = f(a) ^ f(b) ^ f(c)
	// Wait that doesn't look right either. Let me redo:
	// f(x) = Mx ⊕ c where c = f(0)
	// f(a⊕b⊕c_challenge) = M(a⊕b⊕c_challenge) ⊕ c = Ma ⊕ Mb ⊕ Mc_challenge ⊕ c
	// f(a) ⊕ f(b) ⊕ f(c_challenge) ⊕ f(0) ⊕ f(0) = (Ma⊕c) ⊕ (Mb⊕c) ⊕ (Mc_challenge⊕c) ⊕ c ⊕ c
	//   = Ma ⊕ Mb ⊕ Mc_challenge ⊕ c ⊕ c ⊕ c ⊕ c ⊕ c = Ma ⊕ Mb ⊕ Mc_challenge ⊕ c
	// So: f(a⊕b⊕c) = f(a) ⊕ f(b) ⊕ f(c) ⊕ f(0) ⊕ f(0)  = f(a) ⊕ f(b) ⊕ f(c)
	// No wait... 2 f(0)s = 0, so it's just f(a) ⊕ f(b) ⊕ f(c).
	// Hmm, let me just recount. For affine: f(a⊕b) = f(a)⊕f(b)⊕f(0).
	// f(a⊕b⊕c) = f((a⊕b)⊕c) = f(a⊕b) ⊕ f(c) ⊕ f(0) = f(a)⊕f(b)⊕f(0)⊕f(c)⊕f(0) = f(a)⊕f(b)⊕f(c)
	expectedABC := xorBytes(xorBytes(sigA, sigB), sigC)
	if hex.EncodeToString(sigABC) == hex.EncodeToString(expectedABC) {
		t.Log("AFFINE CONFIRMED (triple test): f(a^b^c) = f(a) ^ f(b) ^ f(c)")
	} else {
		t.Log("NOT AFFINE (triple test failed)")
	}

	t.Logf("\nTotal tests: 3, each using fresh emulator state")
}
