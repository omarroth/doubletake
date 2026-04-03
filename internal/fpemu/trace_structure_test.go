//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// TestTraceOuterLoop captures the state at each outer loop iteration to understand:
// 1. How challenge bytes enter the computation
// 2. What inner loops execute per outer iteration
// 3. How the signature is extracted at the end
func TestTraceOuterLoop(t *testing.T) {
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

	// Use challenge bytes 0x00, 0x01, ..., 0x7F to track which byte is used when
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03
	for i := 0; i < 128; i++ {
		m2[14+i] = byte(i)
	}

	// Outer loop header = 0x1a12cfba0
	// Track: what PCs execute between outer loop iterations
	const outerHeader = 0x1a12cfba0
	const loop1Header = 0x1a12d052c
	const loop2Header = 0x1a12d0620

	type iterInfo struct {
		instCount int
		loop1Runs int
		loop2Runs int
		// registers at outer loop header
		x  [31]uint64
		sp uint64
	}

	var iters []iterInfo
	var current iterInfo
	instSinceOuter := 0
	loop1Count := 0
	loop2Count := 0
	prevPC := uint64(0)

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		instSinceOuter++
		if pc == loop1Header && prevPC > pc {
			loop1Count++
		}
		if pc == loop2Header && prevPC > pc {
			loop2Count++
		}
		if pc == outerHeader && prevPC > pc {
			// Back-edge to outer loop = end of one iteration
			if instSinceOuter > 1 {
				current.instCount = instSinceOuter
				current.loop1Runs = loop1Count
				current.loop2Runs = loop2Count
				iters = append(iters, current)
			}
			instSinceOuter = 0
			loop1Count = 0
			loop2Count = 0
			current = iterInfo{}
			current.x = emu.cpu.X
			current.sp = emu.cpu.SP
		}
		if pc == outerHeader && prevPC <= pc && len(iters) == 0 {
			// First entry to outer loop (not a back-edge)
			current.x = emu.cpu.X
			current.sp = emu.cpu.SP
		}
		prevPC = pc
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

	t.Logf("\nOuter loop iterations: %d", len(iters))

	// Show first few and last few iterations
	showIter := func(i int, it iterInfo) {
		t.Logf("\n  Iter %3d: %d insts, loop1=%d, loop2=%d",
			i, it.instCount, it.loop1Runs, it.loop2Runs)

		// Look for challenge byte in registers or memory
		// The challenge bytes at m2[14:142] are 0x00..0x7F
		// Check which registers might hold the current byte index or value
		t.Logf("    X0=%08x X1=%08x X2=%08x X3=%08x X4=%08x",
			uint32(it.x[0]), uint32(it.x[1]), uint32(it.x[2]), uint32(it.x[3]), uint32(it.x[4]))
		t.Logf("    X5=%08x X6=%08x X7=%08x X8=%08x X9=%08x",
			uint32(it.x[5]), uint32(it.x[6]), uint32(it.x[7]), uint32(it.x[8]), uint32(it.x[9]))
		t.Logf("    X19=%08x X20=%08x X21=%08x X22=%08x X23=%08x X24=%08x",
			uint32(it.x[19]), uint32(it.x[20]), uint32(it.x[21]), uint32(it.x[22]), uint32(it.x[23]), uint32(it.x[24]))
	}

	for i := 0; i < len(iters) && i < 5; i++ {
		showIter(i, iters[i])
	}
	if len(iters) > 10 {
		t.Log("\n  ...")
		for i := len(iters) - 3; i < len(iters); i++ {
			showIter(i, iters[i])
		}
	}

	// Check: are all iterations identical in structure?
	allSame := true
	for i := 1; i < len(iters); i++ {
		if iters[i].instCount != iters[0].instCount ||
			iters[i].loop1Runs != iters[0].loop1Runs ||
			iters[i].loop2Runs != iters[0].loop2Runs {
			allSame = false
			break
		}
	}
	t.Logf("\n  All iterations identical structure: %v", allSame)
	if !allSame {
		t.Log("  Unique structures:")
		type key struct{ inst, l1, l2 int }
		counts := map[key]int{}
		for _, it := range iters {
			counts[key{it.instCount, it.loop1Runs, it.loop2Runs}]++
		}
		for k, c := range counts {
			t.Logf("    inst=%d loop1=%d loop2=%d — %d times", k.inst, k.l1, k.l2, c)
		}
	}

	_ = fmt.Sprintf
}

// TestTraceRegistersPerIteration traces which registers carry the challenge byte
// index/value across the outer loop boundary.
func TestTraceRegistersPerIteration(t *testing.T) {
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

	// Use identifiable challenge bytes
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03
	for i := 0; i < 128; i++ {
		m2[14+i] = byte(i)
	}

	const outerHeader = 0x1a12cfba0

	// Capture ALL register states at the outer loop header
	type regSnap struct {
		x  [31]uint64
		sp uint64
	}
	var snaps []regSnap
	prevPC := uint64(0)
	first := true

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		if pc == outerHeader {
			if first || prevPC > pc {
				snaps = append(snaps, regSnap{x: emu.cpu.X, sp: emu.cpu.SP})
				first = false
			}
		}
		prevPC = pc
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
	t.Logf("snapshots captured: %d", len(snaps))

	// For each register, check if it correlates with iteration index
	// i.e., does Xr at iter i contain (or relate to) i?
	t.Log("\nLooking for iteration counter/byte index registers:")
	for r := 0; r < 31; r++ {
		// Check if Xr == iter_index for all iterations
		matchesIndex := true
		matchesByte := true
		constant := true
		for i, s := range snaps {
			if i >= 128 {
				break
			}
			if uint32(s.x[r]) != uint32(i) {
				matchesIndex = false
			}
			if uint32(s.x[r]) != uint32(m2[14+i]) {
				matchesByte = false
			}
			if i > 0 && s.x[r] != snaps[0].x[r] {
				constant = false
			}
		}
		if matchesIndex {
			t.Logf("  X%d = iteration index (0..127)", r)
		}
		if matchesByte {
			t.Logf("  X%d = challenge byte value", r)
		}
		if constant {
			t.Logf("  X%d = constant 0x%x", r, snaps[0].x[r])
		}
	}

	// Show register deltas between iterations
	t.Log("\nRegister values at first 5 iterations:")
	for i := 0; i < 5 && i < len(snaps); i++ {
		s := snaps[i]
		t.Logf("  Iter %d:", i)
		nonzero := []string{}
		for r := 0; r < 31; r++ {
			if s.x[r] != 0 {
				nonzero = append(nonzero, fmt.Sprintf("X%d=%x", r, s.x[r]))
			}
		}
		for j := 0; j < len(nonzero); j += 5 {
			end := j + 5
			if end > len(nonzero) {
				end = len(nonzero)
			}
			t.Logf("    %v", nonzero[j:end])
		}
	}

	// Also look at the state array X24 at each iteration to see how it evolves
	if len(snaps) > 2 {
		x24 := snaps[0].x[24]
		t.Logf("\nState array X24=0x%x first 4 words across iterations:", x24)
		// We need a separate run for this since we can't read memory at past points
		// Instead, let's compare the initial vs final state
		t.Logf("  (need memory snapshots for cross-iteration comparison)")
	}
}

// TestTraceOutputExtraction traces what happens after the 128 outer loop iterations
// to extract the 20-byte signature from the final state.
func TestTraceOutputExtraction(t *testing.T) {
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

	const outerHeader = 0x1a12cfba0

	// Capture the LAST outer loop iteration and then all instructions after
	var pcTrace []uint64
	outerCount := 0
	recording := false
	prevPC := uint64(0)

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		if pc == outerHeader && (prevPC > pc || outerCount == 0) {
			outerCount++
			if outerCount >= 128 {
				recording = true
			}
		}
		if recording {
			pcTrace = append(pcTrace, pc)
		}
		prevPC = pc
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
	t.Logf("outer loop count: %d", outerCount)
	t.Logf("instructions after iter 128 start: %d", len(pcTrace))

	// Show the PC trace after the loop exits
	// The loop exits when the back-edge is NOT taken (falls through)
	// Find where the outer loop stops iterating
	lastOuter := -1
	for i := len(pcTrace) - 1; i >= 0; i-- {
		if pcTrace[i] == outerHeader {
			lastOuter = i
			break
		}
	}

	if lastOuter >= 0 {
		t.Logf("\nLast outer loop header at trace index %d", lastOuter)
		t.Logf("Instructions after last outer header: %d", len(pcTrace)-lastOuter)

		// Show unique PCs in the post-loop trace
		postLoop := pcTrace[lastOuter:]
		uniquePCs := map[uint64]int{}
		for _, pc := range postLoop {
			uniquePCs[pc]++
		}
		t.Logf("Unique PCs in post-loop: %d", len(uniquePCs))

		// Show the first 50 PCs after the last outer loop iteration
		show := 50
		if len(postLoop) < show {
			show = len(postLoop)
		}
		t.Log("\nFirst PCs after last outer iteration:")
		for i := 0; i < show; i++ {
			t.Logf("  [%d] 0x%x", i, postLoop[i])
		}
	}

	_ = fmt.Sprintf
}
