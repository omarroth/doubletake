//go:build emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"testing"
)

// TestCollectPCTrace runs FPSAPExchange with tracing and dumps the PC addresses
// for offline analysis with capstone.
func TestCollectPCTrace(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	os.Setenv("FPEMU_TRACE", "1")
	defer os.Unsetenv("FPEMU_TRACE")

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

	// Phase 1: m1
	m1, _, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("m1: %s", hex.EncodeToString(m1))
	initTrace := emu.LastPCTrace()
	t.Logf("Phase 1 (m1): %d unique PCs", len(initTrace))

	// Phase 2: m2 → m3 with a zero challenge
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("m3: %d bytes", len(m3))
	exchangeTrace := emu.LastPCTrace()
	t.Logf("Phase 2 (exchange): %d unique PCs", len(exchangeTrace))

	// Combine and sort all PCs
	allPCs := make(map[uint64]bool)
	for pc := range initTrace {
		allPCs[pc] = true
	}
	for pc := range exchangeTrace {
		allPCs[pc] = true
	}

	sorted := make([]uint64, 0, len(allPCs))
	for pc := range allPCs {
		sorted = append(sorted, pc)
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	t.Logf("Total unique PCs: %d", len(sorted))
	t.Logf("PC range: 0x%x - 0x%x", sorted[0], sorted[len(sorted)-1])

	// Compute contiguous ranges
	type addrRange struct {
		start, end uint64
	}
	var ranges []addrRange
	var cur addrRange
	for _, pc := range sorted {
		if cur.start == 0 {
			cur = addrRange{pc, pc + 4}
		} else if pc <= cur.end+32 { // Allow small gaps
			cur.end = pc + 4
		} else {
			ranges = append(ranges, cur)
			cur = addrRange{pc, pc + 4}
		}
	}
	if cur.start != 0 {
		ranges = append(ranges, cur)
	}
	t.Logf("Contiguous ranges: %d", len(ranges))
	totalBytes := uint64(0)
	for _, r := range ranges {
		totalBytes += r.end - r.start
		if r.end-r.start > 256 {
			t.Logf("  0x%x - 0x%x (%d bytes)", r.start, r.end, r.end-r.start)
		}
	}
	t.Logf("Total code bytes: %d", totalBytes)

	// Write PCs to a file for offline analysis
	outFile := "/tmp/fp_pc_trace.txt"
	f, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range sorted {
		fmt.Fprintf(f, "0x%x\n", pc)
	}
	f.Close()
	t.Logf("Written PC trace to %s", outFile)
}
