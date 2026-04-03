//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// TestDifferentialTrace runs the signature computation twice with different inputs
// and identifies which operations are input-dependent vs constant.
// Since the code is branchless (identical PC trace), we can compare register values
// at each step. Instructions that produce the same result regardless of input are
// "constant" and can be folded away. Only input-dependent instructions need to be
// in the final Go implementation.
func TestDifferentialTrace(t *testing.T) {
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
	_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, nil) // m1
	if err != nil {
		t.Fatal(err)
	}
	snap := emu.Mem().Snapshot()
	hp := emu.HeapPtr()

	makeM2 := func(challenge [128]byte) []byte {
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

	type regSnap struct {
		x  [31]uint64
		sp uint64
	}

	// Run #1: zero challenge
	emu.Mem().Restore(snap)
	emu.SetHeapPtr(hp)
	var trace1 []regSnap
	emu.cpu.Trace = func(pc uint64, inst uint32) {
		var s regSnap
		s.x = emu.cpu.X
		s.sp = emu.cpu.SP
		trace1 = append(trace1, s)
	}
	var ch1 [128]byte
	m3a, _, err := emu.FPSAPExchange(3, hwInfo, ctx, makeM2(ch1))
	if err != nil {
		t.Fatal(err)
	}
	emu.cpu.Trace = nil
	pa := m3a
	if len(m3a) > 12 && string(m3a[:4]) == "FPLY" {
		pa = m3a[12:]
	}
	sig1 := hex.EncodeToString(pa[132:])
	t.Logf("sig1 (zero): %s", sig1)
	t.Logf("trace1 length: %d", len(trace1))

	// Run #2: sequential challenge
	emu.Mem().Restore(snap)
	emu.SetHeapPtr(hp)
	var trace2 []regSnap
	emu.cpu.Trace = func(pc uint64, inst uint32) {
		var s regSnap
		s.x = emu.cpu.X
		s.sp = emu.cpu.SP
		trace2 = append(trace2, s)
	}
	var ch2 [128]byte
	for i := range ch2 {
		ch2[i] = byte(i)
	}
	m3b, _, err := emu.FPSAPExchange(3, hwInfo, ctx, makeM2(ch2))
	if err != nil {
		t.Fatal(err)
	}
	emu.cpu.Trace = nil
	pb := m3b
	if len(m3b) > 12 && string(m3b[:4]) == "FPLY" {
		pb = m3b[12:]
	}
	sig2 := hex.EncodeToString(pb[132:])
	t.Logf("sig2 (sequential): %s", sig2)
	t.Logf("trace2 length: %d", len(trace2))

	if len(trace1) != len(trace2) {
		t.Fatalf("trace length mismatch: %d vs %d", len(trace1), len(trace2))
	}

	// Compare traces: count how many instructions produce different register values
	totalInst := len(trace1)
	diffInst := 0
	diffRegs := make(map[int]int) // register index -> count of different values

	for i := 0; i < totalInst; i++ {
		anyDiff := false
		for r := 0; r < 31; r++ {
			if trace1[i].x[r] != trace2[i].x[r] {
				diffRegs[r]++
				anyDiff = true
			}
		}
		if trace1[i].sp != trace2[i].sp {
			anyDiff = true
		}
		if anyDiff {
			diffInst++
		}
	}

	t.Logf("\nDifferential analysis:")
	t.Logf("  Total instructions: %d", totalInst)
	t.Logf("  Instructions with different register state: %d (%.1f%%)",
		diffInst, 100.0*float64(diffInst)/float64(totalInst))
	t.Logf("  Instructions with identical register state: %d (%.1f%%)",
		totalInst-diffInst, 100.0*float64(totalInst-diffInst)/float64(totalInst))

	t.Log("  Registers differing:")
	for r := 0; r < 31; r++ {
		if diffRegs[r] > 0 {
			t.Logf("    X%d: %d times (%.1f%%)", r, diffRegs[r], 100.0*float64(diffRegs[r])/float64(totalInst))
		}
	}

	// Find the FIRST instruction where registers diverge
	firstDiff := -1
	for i := 0; i < totalInst; i++ {
		for r := 0; r < 31; r++ {
			if trace1[i].x[r] != trace2[i].x[r] {
				firstDiff = i
				break
			}
		}
		if firstDiff >= 0 {
			break
		}
	}

	if firstDiff >= 0 {
		// Also record the PC trace for context
		emu.Mem().Restore(snap)
		emu.SetHeapPtr(hp)
		var pcs []uint64
		emu.cpu.Trace = func(pc uint64, inst uint32) {
			pcs = append(pcs, pc)
		}
		emu.FPSAPExchange(3, hwInfo, ctx, makeM2(ch1))
		emu.cpu.Trace = nil

		t.Logf("\n  First divergence at instruction %d (PC=0x%x)", firstDiff, pcs[firstDiff])
		t.Logf("    Registers at divergence:")
		for r := 0; r < 16; r++ {
			if trace1[firstDiff].x[r] != trace2[firstDiff].x[r] {
				t.Logf("    X%d: %016x vs %016x", r, trace1[firstDiff].x[r], trace2[firstDiff].x[r])
			}
		}
		// Show context: 10 instructions before
		if firstDiff > 10 {
			t.Log("    Context (10 instructions before first diff):")
			for i := firstDiff - 10; i <= firstDiff; i++ {
				diff := ""
				for r := 0; r < 16; r++ {
					if trace1[i].x[r] != trace2[i].x[r] {
						diff += fmt.Sprintf(" X%d", r)
					}
				}
				if diff == "" {
					diff = " (same)"
				}
				t.Logf("    [%d] PC=0x%x diff:%s", i, pcs[i], diff)
			}
		}

		// Count transitions: how many times do we go from "same state" to "different"
		transitions := 0
		prevDiff := false
		for i := 0; i < totalInst; i++ {
			anyDiff := false
			for r := 0; r < 31; r++ {
				if trace1[i].x[r] != trace2[i].x[r] {
					anyDiff = true
					break
				}
			}
			if anyDiff && !prevDiff {
				transitions++
			}
			prevDiff = anyDiff
		}
		t.Logf("\n  Transitions from constant→variable: %d", transitions)

		// Analyze: in the 128-iter main loop, how many instructions per iteration differ?
		mainLoopHeader := uint64(0x1a12cfba0)
		loopStarts := []int{}
		for i := 0; i < len(pcs); i++ {
			if pcs[i] == mainLoopHeader {
				loopStarts = append(loopStarts, i)
			}
		}
		if len(loopStarts) >= 2 {
			bodyLen := loopStarts[1] - loopStarts[0]
			t.Logf("\n  Main loop (128 iters):")
			t.Logf("    First iteration starts at instruction %d", loopStarts[0])
			t.Logf("    Instructions per iteration: %d", bodyLen)

			diffPerIter := make([]int, 0)
			for iter := 0; iter < len(loopStarts)-1 && iter < 5; iter++ {
				start := loopStarts[iter]
				end := loopStarts[iter+1]
				diffs := 0
				for i := start; i < end; i++ {
					for r := 0; r < 31; r++ {
						if trace1[i].x[r] != trace2[i].x[r] {
							diffs++
							break
						}
					}
				}
				diffPerIter = append(diffPerIter, diffs)
				t.Logf("    Iter %d: %d/%d instructions differ (%.1f%%)",
					iter, diffs, end-start, 100.0*float64(diffs)/float64(end-start))
			}
		}
	}

	_ = os.Getenv // suppress unused import
}
