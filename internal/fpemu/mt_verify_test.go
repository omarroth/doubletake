//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// TestVerifyMersenneTwister checks whether the hot loop implements a modified
// Mersenne Twister by examining the magic constants and state array.
func TestVerifyMersenneTwister(t *testing.T) {
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
	_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	// Capture register state at Loop 1 entry to find:
	// - X24: table base address
	// - X13: second table base
	// - SP+0x98, SP+0x9C: magic constants
	type state struct {
		x  [31]uint64
		sp uint64
	}
	var firstEntry state
	captured := false

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		if pc == 0x1a12d052c && !captured {
			firstEntry.x = emu.cpu.X
			firstEntry.sp = emu.cpu.SP
			captured = true
		}
	}

	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatal(err)
	}
	emu.cpu.Trace = nil
	payload := m3
	if len(m3) > 12 && string(m3[:4]) == "FPLY" {
		payload = m3[12:]
	}
	t.Logf("sig: %s", hex.EncodeToString(payload[132:]))

	sp := firstEntry.sp
	t.Logf("\nLoop 1 entry state:")
	t.Logf("  SP = 0x%x", sp)
	t.Logf("  X24 (table base) = 0x%x", firstEntry.x[24])
	t.Logf("  X13 (table2 base) = 0x%x", firstEntry.x[13])
	t.Logf("  X25 (jump table) = 0x%x", firstEntry.x[25])
	t.Logf("  X16 (code base) = 0x%x", firstEntry.x[16])
	t.Logf("  X15 = %d (should be 25 for MT624 state size factor)", firstEntry.x[15])
	t.Logf("  X8 = %d (initial counter)", firstEntry.x[8])
	t.Logf("  X9 = %d (initial index)", firstEntry.x[9])
	t.Logf("  X7 = 0x%x (iteration counter)", firstEntry.x[7])
	t.Logf("  X14 = 0x%x", firstEntry.x[14])

	// Check magic constants at SP+0x98 and SP+0x9C
	magicA := emu.Mem().Read32(sp + 0x98)
	magicB := emu.Mem().Read32(sp + 0x9C)
	t.Logf("\n  [SP+0x98] = 0x%08x (magic constant 0, matrix A when bit=0)", magicA)
	t.Logf("  [SP+0x9C] = 0x%08x (magic constant 1, matrix A when bit=1)", magicB)

	// Standard MT19937 uses: matrix_a = 0x9908B0DF
	t.Logf("  Standard MT19937 matrix_a = 0x9908B0DF")
	if magicB == 0x9908B0DF {
		t.Log("  *** MATCH: Standard MT19937 magic constant! ***")
	} else {
		t.Logf("  Modified: 0x%08x vs standard 0x9908B0DF", magicB)
	}

	// Dump the state array at X24
	x24 := firstEntry.x[24]
	t.Logf("\n  State array at X24=0x%x (first 32 uint32 values):", x24)
	for i := 0; i < 32; i++ {
		val := emu.Mem().Read32(x24 + uint64(i*4))
		t.Logf("    [%3d] = 0x%08x", i, val)
	}

	// Check state array size: in standard MT, state is 624 words
	// The loop runs 7491 times. 7491 = 624*12 + 3
	// Or maybe the state array is smaller/larger
	// Let's see: Loop 1 uses W9 as index, starts at 0, advances by 1 each iter
	// and also uses W9 + 0x18D (397) as a secondary index
	// This is the classic MT twist: state[i] = state[i+m] ^ (upper|lower) ^ mag
	// where m=397 for MT19937

	// The loop processes entries[0..N) where the back-edge BR goes back to start
	// with W9 advancing by 1 each time. The CMP W9, #0xE3 (227) suggests
	// the loop has phase transitions at index 227.
	t.Logf("\n  Loop index analysis:")
	t.Logf("    MT19937 N=624, m=397, N-m=227")
	t.Logf("    CMP in loop: W9 vs 0xE3 = 227")
	t.Logf("    This matches MT19937: first phase processes [0..227)")
	t.Logf("    where state[i] = state[i+397] ^ twist(state[i], state[i+1])")
	t.Logf("    Second phase processes [227..624)")
	t.Logf("    where state[i] = state[i+397-624] ^ twist(state[i], state[i+1])")

	// Let's verify: how many entries in the state array?
	// The total loop iterations: 7491. If it does 624 entries per "generation"
	// then 7491/624 = 12.0 with 3 remaining. Hmm, not clean.
	// But maybe each generation isn't exactly 624 iterations due to obfuscation.

	// Check the table at X13 (address 0x1a130e910)
	x13 := firstEntry.x[13]
	t.Logf("\n  Table at X13=0x%x:", x13)
	t.Logf("    This is in the DATA segment")
	// Is this a permutation table or a simple sequence?
	for i := 0; i < 16; i++ {
		val := emu.Mem().Read32(x13 + uint64(i*4))
		t.Logf("    [%3d] = 0x%08x", i, val)
	}

	// Now check Loop 2 entry state
	captured = false
	var firstEntry2 state
	emu2, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer emu2.Close()
	hwInfo2 := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo2, 20)
	ctx2, err := emu2.FPSAPInit(hwInfo2)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = emu2.FPSAPExchange(3, hwInfo2, ctx2, nil)
	if err != nil {
		t.Fatal(err)
	}

	emu2.cpu.Trace = func(pc uint64, inst uint32) {
		if pc == 0x1a12d0620 && !captured {
			firstEntry2.x = emu2.cpu.X
			firstEntry2.sp = emu2.cpu.SP
			captured = true
		}
	}
	m3b, _, err := emu2.FPSAPExchange(3, hwInfo2, ctx2, m2)
	if err != nil {
		t.Fatal(err)
	}
	emu2.cpu.Trace = nil
	pb := m3b
	if len(m3b) > 12 && string(m3b[:4]) == "FPLY" {
		pb = m3b[12:]
	}
	_ = pb

	t.Logf("\nLoop 2 entry state:")
	t.Logf("  SP = 0x%x", firstEntry2.sp)
	t.Logf("  X0=%016x X1=%016x X2=%016x X3=%016x", firstEntry2.x[0], firstEntry2.x[1], firstEntry2.x[2], firstEntry2.x[3])
	t.Logf("  X4=%016x X5=%016x X6=%016x X7=%016x", firstEntry2.x[4], firstEntry2.x[5], firstEntry2.x[6], firstEntry2.x[7])
	t.Logf("  X8=%016x X9=%016x X10=%016x X11=%016x", firstEntry2.x[8], firstEntry2.x[9], firstEntry2.x[10], firstEntry2.x[11])
	t.Logf("  X12=%016x X13=%016x X14=%016x X15=%016x", firstEntry2.x[12], firstEntry2.x[13], firstEntry2.x[14], firstEntry2.x[15])

	// Check Loop 2 magic constants (uses same SP-relative pattern)
	sp2 := firstEntry2.sp
	magicA2 := emu2.Mem().Read32(sp2 + 0x98)
	magicB2 := emu2.Mem().Read32(sp2 + 0x9C)
	t.Logf("  [SP+0x98] = 0x%08x", magicA2)
	t.Logf("  [SP+0x9C] = 0x%08x", magicB2)

	// Check X12 in Loop 2 — it's used for LDR at +0x390 and STR at +0x38C
	// This might be the output buffer base
	t.Logf("  X12 (buffer?) = 0x%x", firstEntry2.x[12])
	t.Logf("  X17 (code?) = 0x%x", firstEntry2.x[17])
	t.Logf("  X25 = 0x%x", firstEntry2.x[25])
	t.Logf("  X14 (text) = 0x%x", firstEntry2.x[14])

	// Verify 624 state entries at X24
	x24_2 := firstEntry.x[24]
	// Check: does the state array have 624 entries?
	// If we look 624 entries ahead, does the value make sense?
	v0 := emu.Mem().Read32(x24_2)
	v623 := emu.Mem().Read32(x24_2 + 623*4)
	v624 := emu.Mem().Read32(x24_2 + 624*4)
	t.Logf("\n  Verifying state array size:")
	t.Logf("    state[0]   = 0x%08x", v0)
	t.Logf("    state[623] = 0x%08x", v623)
	t.Logf("    state[624] = 0x%08x (boundary check)", v624)

	_ = fmt.Sprintf // suppress import
}
