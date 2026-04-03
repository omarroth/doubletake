//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// TestBranchlessCheck runs FPSAPExchange with two different m2 values and
// compares the exact PC traces to see if the computation is branchless
// (same instructions execute regardless of input data).
func TestBranchlessCheck(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	buildM2 := func(challenge [128]byte) []byte {
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

	collectTrace := func(challenge [128]byte) ([]uint64, string) {
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

		m2 := buildM2(challenge)

		var pcTrace []uint64
		emu.cpu.Trace = func(pc uint64, inst uint32) {
			if pc >= 0x1a1210000 && pc < 0x1a1316000 {
				pcTrace = append(pcTrace, pc)
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
		return pcTrace, hex.EncodeToString(payload[132:])
	}

	// Trace 1: zero challenge
	var zero [128]byte
	trace1, sig1 := collectTrace(zero)
	t.Logf("trace1 (zero):       %d PCs, sig=%s", len(trace1), sig1)

	// Trace 2: sequential challenge
	var seq [128]byte
	for i := range seq {
		seq[i] = byte(i)
	}
	trace2, sig2 := collectTrace(seq)
	t.Logf("trace2 (sequential): %d PCs, sig=%s", len(trace2), sig2)

	if len(trace1) != len(trace2) {
		t.Logf("DIFFERENT LENGTH: %d vs %d", len(trace1), len(trace2))
		// Find where they diverge
		minLen := len(trace1)
		if len(trace2) < minLen {
			minLen = len(trace2)
		}
		for i := 0; i < minLen; i++ {
			if trace1[i] != trace2[i] {
				t.Logf("first divergence at instruction %d: 0x%x vs 0x%x", i, trace1[i], trace2[i])
				break
			}
		}
	} else {
		// Same length, check if every PC matches
		allMatch := true
		firstDiff := -1
		for i := range trace1 {
			if trace1[i] != trace2[i] {
				if firstDiff == -1 {
					firstDiff = i
				}
				allMatch = false
			}
		}
		if allMatch {
			t.Log("BRANCHLESS: identical PC traces for different inputs!")
			t.Logf("both: %d instructions, %d total", len(trace1), len(trace1))
		} else {
			t.Logf("BRANCHING: traces differ (first at instruction %d)", firstDiff)
			// Count total differences
			diffs := 0
			for i := range trace1 {
				if trace1[i] != trace2[i] {
					diffs++
				}
			}
			t.Logf("  total differing PCs: %d of %d (%.1f%%)", diffs, len(trace1), float64(diffs)/float64(len(trace1))*100)
		}
	}

	// Also write traces to files for comparison
	f1, _ := os.Create("/tmp/fp_trace_zero.txt")
	f2, _ := os.Create("/tmp/fp_trace_seq.txt")
	if f1 != nil && f2 != nil {
		for _, pc := range trace1 {
			fmt.Fprintf(f1, "0x%x\n", pc)
		}
		for _, pc := range trace2 {
			fmt.Fprintf(f2, "0x%x\n", pc)
		}
		f1.Close()
		f2.Close()
	}
}
