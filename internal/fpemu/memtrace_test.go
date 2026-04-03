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

// TestMemoryTrace captures all memory reads/writes during the signature computation
// to understand the data flow from challenge bytes to signature output.
func TestMemoryTrace(t *testing.T) {
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

	// Use sequential challenge bytes
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

	// Take a snapshot of all mutable memory BEFORE the computation
	// so we can compare AFTER
	preState := map[uint64]byte{} // only track pages that get written

	// First, do a dry run with zero challenge to find the write set
	m2zero := make([]byte, 142)
	copy(m2zero, m2)
	for i := 0; i < 128; i++ {
		m2zero[14+i] = 0
	}

	// Track which pages are accessed
	const outerHeader = 0x1a12cfba0
	const sigAddr = 0x80017560 // known signature output address

	// Approach: Run 2 computations with different inputs
	// Diff the memory after each to find which bytes depend on input

	// Run 1: zero challenge
	emu1, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	defer emu1.Close()
	hwInfo1 := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo1, 20)
	ctx1, err := emu1.FPSAPInit(hwInfo1)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = emu1.FPSAPExchange(3, hwInfo1, ctx1, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Snapshot memory before m2 exchange
	mem1Before := snapshotWritablePages(emu1)

	m3_1, _, err := emu1.FPSAPExchange(3, hwInfo1, ctx1, m2zero)
	if err != nil {
		t.Fatal(err)
	}
	mem1After := snapshotWritablePages(emu1)

	// Run 2: sequential challenge
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

	m3_2, _, err := emu2.FPSAPExchange(3, hwInfo2, ctx2, m2)
	if err != nil {
		t.Fatal(err)
	}
	mem2After := snapshotWritablePages(emu2)

	// Extract signatures
	getSig := func(m3 []byte) []byte {
		p := m3
		if len(m3) > 12 && string(m3[:4]) == "FPLY" {
			p = m3[12:]
		}
		return p[132:]
	}
	sig1 := getSig(m3_1)
	sig2 := getSig(m3_2)
	t.Logf("sig (zero):  %s", hex.EncodeToString(sig1))
	t.Logf("sig (seq):   %s", hex.EncodeToString(sig2))

	// Find which memory locations changed between before and after (absolute changes)
	changedBytes1 := 0
	for addr, before := range mem1Before {
		if after, ok := mem1After[addr]; ok && before != after {
			changedBytes1++
		}
	}
	for addr := range mem1After {
		if _, ok := mem1Before[addr]; !ok {
			changedBytes1++
		}
	}

	// Find which memory locations differ between the two runs (input-dependent)
	inputDependentBytes := 0
	inputDepRegions := map[uint64]int{} // page -> count
	for addr, v1 := range mem1After {
		if v2, ok := mem2After[addr]; ok && v1 != v2 {
			inputDependentBytes++
			page := addr &^ 0xFFF
			inputDepRegions[page]++
		}
	}
	for addr := range mem2After {
		if _, ok := mem1After[addr]; !ok {
			inputDependentBytes++
			page := addr &^ 0xFFF
			inputDepRegions[page]++
		}
	}

	t.Logf("\nMemory analysis:")
	t.Logf("  Total changed bytes (run 1): %d", changedBytes1)
	t.Logf("  Input-dependent bytes: %d", inputDependentBytes)
	t.Logf("  Input-dependent pages: %d", len(inputDepRegions))

	// Sort pages by input-dependent byte count
	type pageInfo struct {
		addr  uint64
		count int
	}
	var pages []pageInfo
	for a, c := range inputDepRegions {
		pages = append(pages, pageInfo{a, c})
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].count > pages[j].count })
	t.Log("  Top input-dependent pages:")
	for i, p := range pages {
		if i >= 10 {
			break
		}
		region := "unknown"
		if p.addr >= 0x70000000 && p.addr < 0x71000000 {
			region = "STACK"
		} else if p.addr >= 0x80000000 && p.addr < 0x81000000 {
			region = "HEAP"
		} else if p.addr >= 0x1b10a0000 && p.addr < 0x1b10bb000 {
			region = "DATA"
		} else if p.addr >= 0x1aeaaf000 && p.addr < 0x1aeabe000 {
			region = "DATA_CONST"
		}
		t.Logf("    0x%x (%s): %d bytes", p.addr, region, p.count)
	}

	_ = preState
	_ = fmt.Sprintf
}

// snapshotWritablePages returns a byte-level snapshot of writable memory pages only
func snapshotWritablePages(emu *Emulator) map[uint64]byte {
	snap := map[uint64]byte{}
	for pageAddr, data := range emu.Mem().Pages() {
		// Only snapshot writable regions (stack, heap, DATA)
		// Skip TEXT (read-only code+tables)
		isStack := pageAddr >= 0x70000000 && pageAddr < 0x71000000
		isHeap := pageAddr >= 0x80000000 && pageAddr < 0x81000000
		isData := pageAddr >= 0x1b10a0000 && pageAddr < 0x1b10bc000
		isDataConst := pageAddr >= 0x1aeaaf000 && pageAddr < 0x1aeabe000
		if isStack || isHeap || isData || isDataConst {
			for i, b := range data {
				snap[pageAddr+uint64(i)] = b
			}
		}
	}
	return snap
}
