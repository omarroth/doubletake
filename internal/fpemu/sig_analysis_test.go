//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"testing"
)

// TestAnalyzeSignature instruments the emulator to understand the 20-byte
// signature computation. Since the signature is nonlinear, we need to
// reverse-engineer the actual algorithm.
func TestAnalyzeSignature(t *testing.T) {
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

	// Phase 1: m1
	_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Phase 2: trace the exchange to understand the signature computation
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	// Track function call structure and memory access patterns
	type pcInfo struct {
		count     int
		firstInst int
		lastInst  int
	}
	pcStats := make(map[uint64]*pcInfo)
	textInstN := 0

	// Track calls to stub/external functions
	type stubCall struct {
		instN int
		addr  uint64
		x0    uint64
		x1    uint64
		x2    uint64
		lr    uint64
	}
	var stubCalls []stubCall

	// Track memory write pattern in the output region
	type memWrite struct {
		instN int
		pc    uint64
		addr  uint64
		size  int
	}
	var outputWrites []memWrite

	// We know the output buffer is on the heap. Let's find where m3 is assembled.
	// Track all writes to heap addresses during the exchange.
	emu.cpu.Trace = func(pc uint64, inst uint32) {
		if pc >= 0x1a1210000 && pc < 0x1a1316000 {
			textInstN++
			info := pcStats[pc]
			if info == nil {
				info = &pcInfo{}
				pcStats[pc] = info
			}
			info.count++
			if info.firstInst == 0 {
				info.firstInst = textInstN
			}
			info.lastInst = textInstN
		}
	}

	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatal(err)
	}
	emu.cpu.Trace = nil

	t.Logf("m3: %d bytes", len(m3))
	t.Logf("total TEXT instructions: %d", textInstN)
	t.Logf("unique PCs: %d", len(pcStats))

	_ = outputWrites
	_ = stubCalls

	// Sort PCs by first occurrence
	type pcEntry struct {
		addr uint64
		info *pcInfo
	}
	var entries []pcEntry
	for addr, info := range pcStats {
		entries = append(entries, pcEntry{addr, info})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].info.firstInst < entries[j].info.firstInst })

	// Find hot loops (PCs with highest hit counts)
	sort.Slice(entries, func(i, j int) bool { return entries[i].info.count > entries[j].info.count })
	t.Log("\nTop 20 hottest PCs:")
	for i := 0; i < 20 && i < len(entries); i++ {
		e := entries[i]
		inst := emu.mem.Read32(e.addr)
		t.Logf("  PC=0x%x count=%d first=%d last=%d inst=0x%08x", e.addr, e.info.count, e.info.firstInst, e.info.lastInst, inst)
	}

	// Find contiguous code ranges (functions)
	var pcs []uint64
	for addr := range pcStats {
		pcs = append(pcs, addr)
	}
	sort.Slice(pcs, func(i, j int) bool { return pcs[i] < pcs[j] })

	type codeRange struct {
		start, end uint64
		instCount  int
		hitCount   int
	}
	var ranges []codeRange
	var cur codeRange
	for _, pc := range pcs {
		info := pcStats[pc]
		if cur.start == 0 {
			cur = codeRange{pc, pc + 4, 1, info.count}
		} else if pc <= cur.end+64 { // Allow small gaps
			cur.end = pc + 4
			cur.instCount++
			cur.hitCount += info.count
		} else {
			ranges = append(ranges, cur)
			cur = codeRange{pc, pc + 4, 1, info.count}
		}
	}
	if cur.start != 0 {
		ranges = append(ranges, cur)
	}

	sort.Slice(ranges, func(i, j int) bool { return ranges[i].hitCount > ranges[j].hitCount })
	t.Log("\nCode ranges by total hits:")
	for i := 0; i < 15 && i < len(ranges); i++ {
		r := ranges[i]
		t.Logf("  0x%x-0x%x (%d bytes, %d unique PCs, %d total hits)",
			r.start, r.end, r.end-r.start, r.instCount, r.hitCount)
	}

	// Write a full disassembly listing of the hot region
	t.Log("\nLooking for the signature computation block...")
	// The signature is the last 20 bytes of the 152-byte payload
	// It should be written late in the execution
	payload := m3
	if len(m3) > 12 && string(m3[:4]) == "FPLY" {
		payload = m3[12:]
	}
	sigHex := hex.EncodeToString(payload[132:])
	t.Logf("signature: %s", sigHex)
}

// TestTraceSignatureWrites traces all memory writes during FPSAPExchange
// to find where the 20-byte signature is computed and written.
func TestTraceSignatureWrites(t *testing.T) {
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

	// Two runs: zero m2 and sequential m2, compare which memory locations change
	snapBefore := emu.Mem().Snapshot()
	savedHP := emu.HeapPtr()

	// Run 1: zero challenge
	m2a := make([]byte, 142)
	copy(m2a[0:4], []byte("FPLY"))
	m2a[4] = 0x03
	m2a[5] = 0x01
	m2a[6] = 0x02
	binary.BigEndian.PutUint32(m2a[8:12], 130)
	m2a[12] = 0x02
	m2a[13] = 0x03

	m3a, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2a)
	if err != nil {
		t.Fatal(err)
	}
	snapAfterA := emu.Mem().Snapshot()

	// Run 2: sequential challenge
	emu.Mem().Restore(snapBefore)
	emu.SetHeapPtr(savedHP)

	m2b := make([]byte, 142)
	copy(m2b[0:4], []byte("FPLY"))
	m2b[4] = 0x03
	m2b[5] = 0x01
	m2b[6] = 0x02
	binary.BigEndian.PutUint32(m2b[8:12], 130)
	m2b[12] = 0x02
	m2b[13] = 0x03
	for i := 0; i < 128; i++ {
		m2b[14+i] = byte(i)
	}

	m3b, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2b)
	if err != nil {
		t.Fatal(err)
	}
	snapAfterB := emu.Mem().Snapshot()

	t.Logf("m3a (zero):       %s", hex.EncodeToString(m3a))
	t.Logf("m3b (sequential): %s", hex.EncodeToString(m3b))

	// Compare snapAfterA vs snapAfterB to find which pages/bytes differ
	allPages := make(map[uint64]bool)
	for addr := range snapAfterA {
		allPages[addr] = true
	}
	for addr := range snapAfterB {
		allPages[addr] = true
	}

	type diffInfo struct {
		addr      uint64
		diffBytes int
		firstDiff int
		lastDiff  int
	}
	var diffs []diffInfo

	for addr := range allPages {
		pageA := snapAfterA[addr]
		pageB := snapAfterB[addr]
		if pageA == nil || pageB == nil {
			continue
		}
		ndiff := 0
		first, last := -1, -1
		for i := 0; i < 4096; i++ {
			if pageA[i] != pageB[i] {
				ndiff++
				if first == -1 {
					first = i
				}
				last = i
			}
		}
		if ndiff > 0 {
			diffs = append(diffs, diffInfo{addr, ndiff, first, last})
		}
	}

	sort.Slice(diffs, func(i, j int) bool { return diffs[i].addr < diffs[j].addr })
	t.Logf("\nPages that differ between zero and sequential m2:")
	for _, d := range diffs {
		region := "?"
		switch {
		case d.addr >= heapBase && d.addr < heapBase+heapSize:
			region = "heap"
		case d.addr >= stackBase && d.addr < stackBase+stackSize:
			region = "stack"
		case d.addr >= 0x1a1210000 && d.addr < 0x1a1316000:
			region = "TEXT"
		case d.addr >= 0x1b10a17c0 && d.addr < 0x1b10ba598:
			region = "DATA"
		case d.addr >= 0x1aeaaf360 && d.addr < 0x1aeabd908:
			region = "DATA_CONST"
		}
		t.Logf("  page 0x%x [%s]: %d bytes differ (offset 0x%x-0x%x)", d.addr, region, d.diffBytes, d.firstDiff, d.lastDiff)

		// If it's a small number of diffs, show them
		if d.diffBytes <= 64 {
			pageA := snapAfterA[d.addr]
			pageB := snapAfterB[d.addr]
			for i := 0; i < 4096; i++ {
				if pageA[i] != pageB[i] {
					t.Logf("    0x%x+0x%x: %02x -> %02x", d.addr, i, pageA[i], pageB[i])
				}
			}
		}
	}

	// Also dump the m3 signature difference
	pa := m3a
	if len(m3a) > 12 && string(m3a[:4]) == "FPLY" {
		pa = m3a[12:]
	}
	pb := m3b
	if len(m3b) > 12 && string(m3b[:4]) == "FPLY" {
		pb = m3b[12:]
	}
	t.Logf("\nm3 sig (zero):       %s", hex.EncodeToString(pa[132:]))
	t.Logf("m3 sig (sequential): %s", hex.EncodeToString(pb[132:]))

	// Write out a dump of the diff pages for analysis
	f, _ := os.Create("/tmp/fp_diff_analysis.txt")
	if f != nil {
		for _, d := range diffs {
			pageA := snapAfterA[d.addr]
			pageB := snapAfterB[d.addr]
			fmt.Fprintf(f, "PAGE 0x%x: %d bytes differ\n", d.addr, d.diffBytes)
			for i := 0; i < 4096; i++ {
				if pageA[i] != pageB[i] {
					fmt.Fprintf(f, "  +0x%03x: %02x -> %02x\n", i, pageA[i], pageB[i])
				}
			}
		}
		f.Close()
	}
}
