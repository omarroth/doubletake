//go:build emulate

package fpemu

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// buildM2 creates a synthetic 142-byte m2 message (with FPLY header).
// The binary receives the full message including the FPLY wrapper.
func buildM2(challenge [128]byte) []byte {
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03 // version
	m2[5] = 0x01 // sub-version
	m2[6] = 0x02 // type = 2
	// m2[7] = 0x00 (padding)
	binary.BigEndian.PutUint32(m2[8:12], 130) // payload length
	m2[12] = 0x02                             // type echo
	m2[13] = 0x03                             // mode echo
	copy(m2[14:], challenge[:])
	return m2
}

func setupEmulator(t *testing.T) (*Emulator, uint64, []byte) {
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
	m1, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		emu.Close()
		t.Fatalf("FPSAPExchange phase1: %v", err)
	}
	t.Logf("m1: %d bytes, rc=%d, hex=%s", len(m1), rc, hex.EncodeToString(m1))

	return emu, ctx, hwInfo
}

// TestProbeExchangeZeroM2 feeds an all-zero m2 challenge to understand baseline m3.
func TestProbeExchangeZeroM2(t *testing.T) {
	emu, ctx, hwInfo := setupEmulator(t)
	defer emu.Close()

	var challenge [128]byte // all zeros
	m2 := buildM2(challenge)
	t.Logf("m2 payload (%d bytes): %s", len(m2), hex.EncodeToString(m2))

	m3, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatalf("FPSAPExchange phase2: %v", err)
	}
	t.Logf("m3: %d bytes, rc=%d", len(m3), rc)
	t.Logf("m3 hex: %s", hex.EncodeToString(m3))
}

// TestProbeExchangeBitFlip feeds different m2 values to detect which m2 bytes affect m3.
func TestProbeExchangeBitFlip(t *testing.T) {
	// Run with a known m2 first, then flip one byte at a time
	results := make(map[string]string) // m2_desc -> m3_hex

	for trial := 0; trial < 5; trial++ {
		var challenge [128]byte
		desc := ""
		switch trial {
		case 0:
			desc = "all_zero"
		case 1:
			challenge[0] = 0xFF
			desc = "byte0=FF"
		case 2:
			challenge[127] = 0xFF
			desc = "byte127=FF"
		case 3:
			for i := range challenge {
				challenge[i] = byte(i)
			}
			desc = "sequential"
		case 4:
			for i := range challenge {
				challenge[i] = 0xFF
			}
			desc = "all_FF"
		}

		// Each trial needs fresh emulator state
		emu, ctx, hwInfo := setupEmulator(t)
		m2 := buildM2(challenge)
		m3, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
		emu.Close()

		if err != nil {
			t.Logf("[%s] ERROR: %v", desc, err)
			continue
		}
		hex3 := hex.EncodeToString(m3)
		results[desc] = hex3
		t.Logf("[%s] m3 (%d bytes, rc=%d): %s", desc, len(m3), rc, hex3)
	}

	// Compare results to find patterns
	if r0, ok := results["all_zero"]; ok {
		for desc, r := range results {
			if desc == "all_zero" {
				continue
			}
			diffs := 0
			minLen := len(r0)
			if len(r) < minLen {
				minLen = len(r)
			}
			for i := 0; i < minLen; i++ {
				if r0[i] != r[i] {
					diffs++
				}
			}
			t.Logf("diff [all_zero vs %s]: %d hex chars differ of %d", desc, diffs, minLen)
		}
	}
}

// TestProbeExchangeRepeatability tests if same m2 with fresh state produces same m3.
func TestProbeExchangeRepeatability(t *testing.T) {
	var challenge [128]byte
	challenge[0] = 0x42

	m3s := make([]string, 3)
	for i := 0; i < 3; i++ {
		emu, ctx, hwInfo := setupEmulator(t)
		m2 := buildM2(challenge)
		m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
		emu.Close()
		if err != nil {
			t.Fatalf("trial %d: %v", i, err)
		}
		m3s[i] = hex.EncodeToString(m3)
		t.Logf("trial %d: m3=%s", i, m3s[i])
	}

	if m3s[0] == m3s[1] && m3s[1] == m3s[2] {
		t.Log("DETERMINISTIC: same m2 always produces same m3 (no internal randomness)")
	} else {
		t.Log("NON-DETERMINISTIC: same m2 produces different m3 (internal randomness present)")
		// Show which bytes differ
		for i := 0; i < len(m3s[0]) && i < len(m3s[1]); i++ {
			if m3s[0][i] != m3s[1][i] {
				t.Logf("  first diff at hex offset %d", i)
				break
			}
		}
	}
}

// TestProbeRealM2 processes an actual captured m2 from Apple TV.
func TestProbeRealM2(t *testing.T) {
	// From a real Apple TV session (the second emulated run)
	m2Full, err := hex.DecodeString(
		"46504c5903010200000000820203cc5b68830f7e9163690593f14c034352cb79c02de2417b4a2c0d27476a9fc539cb33bf5dfeaead5022b2855f024d0174b75dea450168defc910b76c91224eb61fe7ea3d3a0317650c949396674d0349536a9361e1777f8b7f46a993b134e5942cef0762b7341df218499b0bf708d4dc6f0c96c6cca7fa9caa7870a1ab41193e9")
	if err != nil {
		t.Fatal(err)
	}

	// Pass the full m2 including FPLY header (that's what the binary expects)
	t.Logf("m2 full (%d bytes): %s", len(m2Full), hex.EncodeToString(m2Full))

	emu, ctx, hwInfo := setupEmulator(t)
	defer emu.Close()

	m3, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, m2Full)
	if err != nil {
		t.Fatalf("FPSAPExchange: %v", err)
	}
	t.Logf("m3 (%d bytes, rc=%d): %s", len(m3), rc, hex.EncodeToString(m3))
	t.Logf("m3 first 20: %s", hex.EncodeToString(m3[:20]))

	if len(m3) >= 20 {
		t.Logf("m3 last 20: %s", hex.EncodeToString(m3[len(m3)-20:]))
	}

	// Check if this matches what the real Apple TV accepted
	fmt.Printf("\n=== m3 Analysis ===\n")
	fmt.Printf("m3 length: %d bytes\n", len(m3))
	if len(m3) > 0 {
		fmt.Printf("m3[0] (type marker?): 0x%02x\n", m3[0])
	}
}

// TestProbeLinearity tests if the 20-byte signature is a linear (XOR) function of m2.
// If f(a⊕b) = f(a)⊕f(b)⊕f(0), then f is affine in GF(2) and can be computed as a matrix.
func TestProbeLinearity(t *testing.T) {
	sig := func(challenge [128]byte) []byte {
		emu, ctx, hwInfo := setupEmulator(t)
		m2 := buildM2(challenge)
		m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
		emu.Close()
		if err != nil {
			t.Fatal(err)
		}
		return m3[len(m3)-20:]
	}

	xorBytes := func(a, b []byte) []byte {
		r := make([]byte, len(a))
		for i := range r {
			r[i] = a[i] ^ b[i]
		}
		return r
	}

	// f(0)
	var zero [128]byte
	sig0 := sig(zero)
	t.Logf("f(0) = %s", hex.EncodeToString(sig0))

	// Test vectors
	var a, b, ab [128]byte
	a[0] = 0x01
	b[1] = 0x01
	ab[0] = 0x01
	ab[1] = 0x01

	sigA := sig(a)
	sigB := sig(b)
	sigAB := sig(ab)

	t.Logf("f(a) = %s", hex.EncodeToString(sigA))
	t.Logf("f(b) = %s", hex.EncodeToString(sigB))
	t.Logf("f(a^b) = %s", hex.EncodeToString(sigAB))

	// For affine function: f(a^b) = f(a) ^ f(b) ^ f(0)
	expected := xorBytes(xorBytes(sigA, sigB), sig0)
	t.Logf("f(a)^f(b)^f(0) = %s", hex.EncodeToString(expected))
	if hex.EncodeToString(expected) == hex.EncodeToString(sigAB) {
		t.Log("LINEAR: the signature IS an affine/linear function of m2!")
	} else {
		t.Log("NON-LINEAR: the signature is not a simple XOR function")
	}

	// Also check with larger changes
	var c [128]byte
	for i := range c {
		c[i] = byte(i)
	}
	sigC := sig(c)
	t.Logf("f(seq) = %s", hex.EncodeToString(sigC))
}

// TestProbeSAPContext dumps the SAP context and heap to search for static m3 bytes.
func TestProbeSAPContext(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	emu, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer emu.Close()

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("SAP context pointer: 0x%x", ctx)

	// Dump heap after init
	heapAddr, heapData := emu.HeapDump()
	t.Logf("Heap after init: base=0x%x, used=%d bytes", heapAddr, len(heapData))

	// Do m1 exchange
	m1, _, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("m1: %d bytes: %s", len(m1), hex.EncodeToString(m1))

	// Dump heap after m1
	_, heapDataAfterM1 := emu.HeapDump()
	t.Logf("Heap after m1: used=%d bytes", len(heapDataAfterM1))

	// Search for the first 16 bytes of the static m3 content
	m3Static16, _ := hex.DecodeString("038f1a9c991ea22c511e45ba97f1af8d")

	searchIn := func(data []byte, label string, baseAddr uint64) {
		for off := 0; off <= len(data)-16; off++ {
			match := true
			for j := 0; j < 16; j++ {
				if data[off+j] != m3Static16[j] {
					match = false
					break
				}
			}
			if match {
				t.Logf("FOUND in %s at offset 0x%x (addr 0x%x)!", label, off, baseAddr+uint64(off))
				end := off + 152
				if end > len(data) {
					end = len(data)
				}
				t.Logf("  data[0x%x:0x%x] = %s", off, end, hex.EncodeToString(data[off:end]))
			}
		}
	}

	searchIn(heapDataAfterM1, "heap-after-m1", heapAddr)

	// Also do an exchange with a zero m2 to get the full m3
	var challenge [128]byte
	m2 := buildM2(challenge)
	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("m3: %d bytes", len(m3))

	_, heapDataAfterM3 := emu.HeapDump()
	t.Logf("Heap after m3: used=%d bytes", len(heapDataAfterM3))
	searchIn(heapDataAfterM3, "heap-after-m3", heapAddr)

	// Also search for the output in the data segment
	// __DATA: 0x1b10a17c0 size=0x18dd8
	dataSegAddr := uint64(0x1b10a17c0)
	dataSize := 0x18dd8
	dataSeg := emu.ReadMem(dataSegAddr, dataSize)
	searchIn(dataSeg, "data-segment", dataSegAddr)

	// Dump heap around the m3 output area for intermediate values
	m3Off := 0x174dc // where we found m3 on heap
	dumpStart := m3Off - 256
	if dumpStart < 0 {
		dumpStart = 0
	}
	dumpEnd := m3Off + 512
	if dumpEnd > len(heapDataAfterM3) {
		dumpEnd = len(heapDataAfterM3)
	}
	heapDump := heapDataAfterM3[dumpStart:dumpEnd]
	t.Logf("\nHeap around m3 output (offset 0x%x to 0x%x):", dumpStart, dumpEnd)
	for i := 0; i < len(heapDump); i += 32 {
		end := i + 32
		if end > len(heapDump) {
			end = len(heapDump)
		}
		allZero := true
		for _, b := range heapDump[i:end] {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			off := dumpStart + i
			t.Logf("  heap[0x%05x]: %s", off, hex.EncodeToString(heapDump[i:end]))
		}
	}
}

// TestProbeHwInfoEffect tests if hwInfo affects the static part of m3.
func TestProbeHwInfoEffect(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	var challenge [128]byte // all zeros

	for trial := 0; trial < 3; trial++ {
		emu, err := New(path)
		if err != nil {
			t.Fatal(err)
		}

		hwInfo := make([]byte, 24)
		binary.LittleEndian.PutUint32(hwInfo, 20)
		switch trial {
		case 0:
			// hwInfo[4:] = all zeros
		case 1:
			hwInfo[4] = 0xFF // different device ID
		case 2:
			for i := 4; i < 24; i++ {
				hwInfo[i] = byte(i)
			}
		}

		ctx, err := emu.FPSAPInit(hwInfo)
		if err != nil {
			emu.Close()
			t.Fatal(err)
		}
		_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, nil) // m1
		if err != nil {
			emu.Close()
			t.Fatal(err)
		}

		m2 := buildM2(challenge)
		m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
		emu.Close()
		if err != nil {
			t.Fatalf("trial %d: %v", trial, err)
		}
		t.Logf("trial %d (hwInfo[4]=0x%02x): m3=%s", trial, hwInfo[4], hex.EncodeToString(m3))
	}
}

// TestProbeHashAlgo tries to figure out what hash produces the last 20 bytes.
func TestProbeHashAlgo(t *testing.T) {
	// From the bitflip test, all_zero m2 produces m3 with last 20 bytes:
	// 6f627565f3e77f5b5ede91beee7baf92e4241e0b

	m3Static, _ := hex.DecodeString(
		"038f1a9c991ea22c511e45ba97f1af8d" +
			"fb0f86f550c54486fe6b3ab233da431e" +
			"f8e5fc1156dba321fffeabb1b392b09d" +
			"227e88c712202866eb7bbf310015aa1d" +
			"19a5df36d5dfd8d3ca1639b376eaece9" +
			"46edfe8b7a66cd302d04aac3c1251714" +
			"019bd5f2d49b543e11eed1646291ec8e" +
			"fd96b69101b849fd93a02860d1a0dff5" +
			"cd4414aa")
	expected, _ := hex.DecodeString("6f627565f3e77f5b5ede91beee7baf92e4241e0b")

	m2Challenge := make([]byte, 128) // all zeros
	m2Payload := make([]byte, 130)
	m2Payload[0] = 0x02
	m2Payload[1] = 0x03
	m2Full := buildM2([128]byte{})

	type trial struct {
		name string
		data []byte
	}
	trials := []trial{
		{"SHA1(m2_challenge)", m2Challenge},
		{"SHA1(m2_payload)", m2Payload},
		{"SHA1(m2_full)", m2Full},
		{"SHA1(m3static)", m3Static},
		{"SHA1(m3static || m2_challenge)", append(append([]byte{}, m3Static...), m2Challenge...)},
		{"SHA1(m2_challenge || m3static)", append(append([]byte{}, m2Challenge...), m3Static...)},
		{"SHA1(m3static || m2_payload)", append(append([]byte{}, m3Static...), m2Payload...)},
		{"SHA1(m2_payload || m3static)", append(append([]byte{}, m2Payload...), m3Static...)},
		{"SHA1(m3static || m2_full)", append(append([]byte{}, m3Static...), m2Full...)},
		{"SHA1(m2_full || m3static)", append(append([]byte{}, m2Full...), m3Static...)},
	}

	// Also try HMAC-SHA1 with various keys
	hmacTrials := []trial{
		{"HMAC-SHA1(m3static, m2_challenge)", m2Challenge},
		{"HMAC-SHA1(m3static, m2_payload)", m2Payload},
		{"HMAC-SHA1(m3static, m2_full)", m2Full},
	}

	h := sha1.New()
	for _, tr := range trials {
		h.Reset()
		h.Write(tr.data)
		got := h.Sum(nil)
		match := hex.EncodeToString(got) == hex.EncodeToString(expected)
		if match {
			t.Logf("MATCH: %s = %s", tr.name, hex.EncodeToString(got))
		} else {
			t.Logf("       %s = %s", tr.name, hex.EncodeToString(got))
		}
	}

	for _, tr := range hmacTrials {
		mac := hmac.New(sha1.New, m3Static)
		mac.Write(tr.data)
		got := mac.Sum(nil)
		match := hex.EncodeToString(got) == hex.EncodeToString(expected)
		if match {
			t.Logf("MATCH: %s", tr.name)
		} else {
			t.Logf("       %s = %s", tr.name, hex.EncodeToString(got))
		}
	}

	// Also try SHA-256 truncated to 20 bytes
	h256 := sha256.New()
	for _, tr := range []trial{
		{"SHA256[:20](m2_challenge || m3static)", append(append([]byte{}, m2Challenge...), m3Static...)},
		{"SHA256[:20](m3static || m2_challenge)", append(append([]byte{}, m3Static...), m2Challenge...)},
	} {
		h256.Reset()
		h256.Write(tr.data)
		got := h256.Sum(nil)[:20]
		if hex.EncodeToString(got) == hex.EncodeToString(expected) {
			t.Logf("MATCH: %s", tr.name)
		}
	}
}
