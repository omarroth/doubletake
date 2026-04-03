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

// TestAnalyzeLoopStructure captures the full PC trace and identifies all loops
// in the signature computation. This is the foundation for generating a
// compiled Go implementation.
func TestAnalyzeLoopStructure(t *testing.T) {
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

	// Record complete PC trace
	var pcs []uint64
	emu.cpu.Trace = func(pc uint64, inst uint32) {
		pcs = append(pcs, pc)
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
	t.Logf("total instructions: %d", len(pcs))

	// Find back-edges: i where pcs[i] < pcs[i-1] (backward jump = loop back-edge)
	type loopInfo struct {
		header  uint64 // target of back-edge (loop start)
		backPC  uint64 // PC that jumps back
		count   int    // number of iterations
		bodyLen int    // instructions per iteration
	}

	loops := make(map[uint64]*loopInfo) // keyed by loop header PC
	for i := 1; i < len(pcs); i++ {
		if pcs[i] < pcs[i-1] {
			// Found a back-edge: from pcs[i-1]+4 to pcs[i]
			header := pcs[i]
			if l, ok := loops[header]; ok {
				l.count++
			} else {
				loops[header] = &loopInfo{
					header: header,
					backPC: pcs[i-1],
					count:  1,
				}
			}
		}
	}

	// For each loop, measure the body length (instructions between consecutive visits to header)
	for _, l := range loops {
		firstVisit := -1
		secondVisit := -1
		for i := 0; i < len(pcs); i++ {
			if pcs[i] == l.header {
				if firstVisit == -1 {
					firstVisit = i
				} else {
					secondVisit = i
					break
				}
			}
		}
		if firstVisit >= 0 && secondVisit >= 0 {
			l.bodyLen = secondVisit - firstVisit
		}
	}

	// Sort loops by iteration count (most frequent first)
	var sortedLoops []*loopInfo
	for _, l := range loops {
		sortedLoops = append(sortedLoops, l)
	}
	sort.Slice(sortedLoops, func(i, j int) bool {
		return sortedLoops[i].count > sortedLoops[j].count
	})

	t.Logf("\nFound %d unique loops:", len(sortedLoops))
	totalLooped := 0
	for i, l := range sortedLoops {
		if i < 30 {
			t.Logf("  header=0x%x  backPC=0x%x  iters=%d  body=%d inst  total=%d",
				l.header, l.backPC, l.count, l.bodyLen, l.count*l.bodyLen)
		}
		totalLooped += l.count * l.bodyLen
	}
	t.Logf("total looped instructions: %d / %d = %.1f%%", totalLooped, len(pcs),
		100.0*float64(totalLooped)/float64(len(pcs)))

	// Record the hierarchical structure: which loops are nested inside which
	// A loop B is nested in loop A if B's header is between A's header and A's backPC
	t.Log("\nLoop nesting structure:")
	for _, outer := range sortedLoops {
		for _, inner := range sortedLoops {
			if inner == outer {
				continue
			}
			if inner.header > outer.header && inner.header <= outer.backPC {
				t.Logf("  0x%x (iters=%d) contains 0x%x (iters=%d)",
					outer.header, outer.count, inner.header, inner.count)
			}
		}
	}

	// Now identify the top-level structure: partition the trace into regions
	// Find the first and last occurrence of each loop header
	t.Log("\nPC range analysis:")
	pcMin := pcs[0]
	pcMax := pcs[0]
	for _, pc := range pcs {
		if pc < pcMin {
			pcMin = pc
		}
		if pc > pcMax {
			pcMax = pc
		}
	}
	t.Logf("  PC range: 0x%x - 0x%x", pcMin, pcMax)

	// Bin the PCs into 4KB pages and count
	pageCounts := make(map[uint64]int)
	for _, pc := range pcs {
		pageCounts[pc&^0xFFF]++
	}
	type pageEntry struct {
		addr  uint64
		count int
	}
	var pages []pageEntry
	for addr, count := range pageCounts {
		pages = append(pages, pageEntry{addr, count})
	}
	sort.Slice(pages, func(i, j int) bool { return pages[i].addr < pages[j].addr })
	t.Log("\nInstruction pages (4KB blocks):")
	for _, p := range pages {
		bar := ""
		for j := 0; j < p.count/10000; j++ {
			bar += "#"
		}
		t.Logf("  0x%x: %7d  %s", p.addr, p.count, bar)
	}
}

// removed classifyInst and TestMinimalReplay

// TestExtractProgram extracts the complete fixed instruction sequence and
// constant table data needed for a pure Go implementation.
func TestExtractProgram(t *testing.T) {
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

	// Save state before m2 exchange
	snap := emu.Mem().Snapshot()
	hp := emu.HeapPtr()

	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	// 1. Record trace of (PC, instruction) pairs
	type pcInst struct {
		pc   uint64
		inst uint32
	}
	var trace []pcInst
	emu.cpu.Trace = func(pc uint64, inst uint32) {
		trace = append(trace, pcInst{pc, inst})
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
	t.Logf("trace length: %d", len(trace))

	// 2. Classify all unique instructions by the ARM64 major encoding groups
	type instInfo struct {
		encoding uint32
		count    int
		example  uint64 // example PC
	}
	// Group by top-level opcode class
	classMap := make(map[string]int)
	for _, tr := range trace {
		inst := tr.inst
		class := "?"
		if inst&0xFFE0001F == 0xD4200000 {
			class = "BRK"
		} else if inst == 0 {
			class = "NOP/ZERO"
		} else {
			op0 := (inst >> 25) & 0xF
			switch {
			case op0>>1 == 4: // 100x: DP Immediate
				subop := (inst >> 23) & 0x7
				switch subop {
				case 0, 1:
					class = "ADR/ADRP"
				case 2:
					if inst>>29&1 != 0 {
						class = "ADDS/SUBS_imm"
					} else if inst>>30&1 != 0 {
						class = "SUB_imm"
					} else {
						class = "ADD_imm"
					}
				case 4:
					opc := inst >> 29 & 3
					switch opc {
					case 0:
						class = "AND_imm"
					case 1:
						class = "ORR_imm"
					case 2:
						class = "EOR_imm"
					case 3:
						class = "ANDS_imm"
					}
				case 5:
					opc := inst >> 29 & 3
					switch opc {
					case 0:
						class = "MOVN"
					case 2:
						class = "MOVZ"
					case 3:
						class = "MOVK"
					}
				case 6:
					opc := inst >> 29 & 3
					switch opc {
					case 0:
						class = "SBFM"
					case 1:
						class = "BFM"
					case 2:
						class = "UBFM"
					}
				case 7:
					class = "EXTR"
				}
			case op0>>1 == 5: // 101x: Branches
				if inst>>26 == 0x25 { // B
					class = "B"
				} else if inst>>26 == 0x25|0x20 { // BL
					class = "BL"
				} else if inst>>25 == 0x6B { // B.cond
					class = "B_cond"
				} else if inst>>25 == 0x6A { // CBZ/CBNZ
					class = "CBZ/CBNZ"
				} else if inst>>24 == 0xD6 { // BR/BLR/RET
					op := inst >> 21 & 3
					switch op {
					case 0:
						class = "BR"
					case 1:
						class = "BLR"
					case 2:
						class = "RET"
					}
				} else {
					class = fmt.Sprintf("BRANCH_%08x", inst>>20)
				}
			case op0&5 == 4: // x1x0: Load/Store
				if inst>>22&0x3FF == 0x3E5 { // LDR (immediate, unsigned offset)
					class = "LDR_uoff"
				} else if inst>>21&0x7FF == 0x7C1 { // LDR (register)
					class = "LDR_reg"
				} else if inst>>22&0x3FF == 0x3E4 { // STR (unsigned offset)
					class = "STR_uoff"
				} else if inst>>22&0x3FF == 0x3E1 { // LDP
					class = "LDP"
				} else if inst>>22&0x3FF == 0x3E0 { // STP
					class = "STP"
				} else {
					sz := inst >> 30
					v := inst >> 26 & 1
					opc := inst >> 22 & 3
					class = fmt.Sprintf("LS_sz%d_v%d_opc%d_%03x", sz, v, opc, inst>>21&0x7FF)
				}
			case op0&7 == 5: // x101: DP Register
				if inst>>21&0x7FF == 0x550 { // CSEL/CSINC etc
					op2 := inst >> 10 & 3
					switch op2 {
					case 0:
						if inst>>30&1 == 0 {
							class = "CSEL"
						} else {
							class = "CSINV"
						}
					case 1:
						if inst>>30&1 == 0 {
							class = "CSINC"
						} else {
							class = "CSNEG"
						}
					}
				} else if inst>>24&0x1F == 0x0A { // logical shifted
					opc := inst >> 29 & 3
					switch opc {
					case 0:
						class = "AND_reg"
					case 1:
						class = "ORR_reg"
					case 2:
						class = "EOR_reg"
					case 3:
						class = "ANDS_reg"
					}
				} else if inst>>24&0x1F == 0x0B { // add/sub shifted
					if inst>>30&1 == 0 {
						class = "ADD_reg"
					} else {
						class = "SUB_reg"
					}
				} else if inst>>24&0xFF == 0x1B { // MADD/MSUB
					class = "MADD"
				} else if inst>>21&0x7FF == 0x6B0 { // UDIV/SDIV
					class = "UDIV"
				} else {
					class = fmt.Sprintf("DPR_%03x", inst>>21&0x7FF)
				}
			case op0&7 == 7: // x111: SIMD/FP
				class = fmt.Sprintf("SIMD_%02x", inst>>24&0xFF)
			}
		}
		classMap[class]++
	}

	// Sort by count
	type classEntry struct {
		name  string
		count int
	}
	var classes []classEntry
	for name, count := range classMap {
		classes = append(classes, classEntry{name, count})
	}
	sort.Slice(classes, func(i, j int) bool { return classes[i].count > classes[j].count })

	t.Log("\nInstruction class distribution:")
	for _, c := range classes {
		pct := 100.0 * float64(c.count) / float64(len(trace))
		t.Logf("  %-16s %7d  %5.1f%%", c.name, c.count, pct)
	}

	// 3. Capture memory access patterns: which addresses are read from/written to
	emu.Mem().Restore(snap)
	emu.SetHeapPtr(hp)

	// Clear ReadPages tracking
	for k := range emu.Mem().ReadPages {
		delete(emu.Mem().ReadPages, k)
	}

	// Run again with a dual-input approach to separate tables from state
	emu.cpu.Trace = nil
	m3, _, err = emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatal(err)
	}
	readPages1 := make(map[uint64]bool)
	for k, v := range emu.Mem().ReadPages {
		if v {
			readPages1[k] = true
		}
	}

	// Classify pages
	textRange := func(a uint64) bool { return a >= 0x1a1210000 && a < 0x1a1316000 }
	dataConstRange := func(a uint64) bool { return a >= 0x1aeaaf000 && a < 0x1aeabe000 }
	dataRange := func(a uint64) bool { return a >= 0x1b10a0000 && a < 0x1b10bb000 }
	stackRange := func(a uint64) bool { return a >= 0x70000000 && a < 0x70800000 }
	heapRange := func(a uint64) bool { return a >= 0x80000000 && a < 0x80100000 }

	var textPages, dcPages, dPages, sPages, hPages, otherPages []uint64
	for pg := range readPages1 {
		switch {
		case textRange(pg):
			textPages = append(textPages, pg)
		case dataConstRange(pg):
			dcPages = append(dcPages, pg)
		case dataRange(pg):
			dPages = append(dPages, pg)
		case stackRange(pg):
			sPages = append(sPages, pg)
		case heapRange(pg):
			hPages = append(hPages, pg)
		default:
			otherPages = append(otherPages, pg)
		}
	}

	t.Logf("\nMemory pages read during m2 exchange:")
	t.Logf("  TEXT:       %d pages", len(textPages))
	t.Logf("  DATA_CONST: %d pages (%d bytes)", len(dcPages), len(dcPages)*4096)
	t.Logf("  DATA:       %d pages (%d bytes)", len(dPages), len(dPages)*4096)
	t.Logf("  Stack:      %d pages", len(sPages))
	t.Logf("  Heap:       %d pages", len(hPages))
	t.Logf("  Other:      %d pages", len(otherPages))
	for _, pg := range otherPages {
		t.Logf("    0x%x", pg)
	}

	// 4. Extract state: find which stack/heap bytes actually change during computation
	// Compare memory before and after the exchange
	snapAfterM2 := emu.Mem().Snapshot()
	changedBytes := 0
	for pg := range snapAfterM2 {
		if !stackRange(pg) && !heapRange(pg) {
			continue
		}
		before := snap[pg]
		after := snapAfterM2[pg]
		if before == nil {
			changedBytes += 4096
			continue
		}
		for i := 0; i < 4096; i++ {
			if before[i] != after[i] {
				changedBytes++
			}
		}
	}
	t.Logf("  Changed bytes (stack+heap): %d", changedBytes)
}
