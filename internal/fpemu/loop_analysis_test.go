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

// TestExtractLoop traces the hot loop to understand its structure for translation to Go.
func TestExtractLoop(t *testing.T) {
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

	// Hot loop range: 0x1a12d052c - 0x1a12d0aa4
	hotStart := uint64(0x1a12d052c)
	hotEnd := uint64(0x1a12d0aa4)

	// Track reads from DATA_CONST segment (tables)
	type tableAccess struct {
		addr uint64
		pc   uint64
		iter int
	}
	var tableReads []tableAccess

	// Track iterations by counting entries at the loop header
	loopIter := 0
	textInstN := 0
	inHotLoop := false

	// Also track all register values at hot loop entry
	type iterSnapshot struct {
		n  int
		x  [16]uint64
		sp uint64
	}
	var iterSnaps []iterSnapshot

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		if pc >= 0x1a1210000 && pc < 0x1a1316000 {
			textInstN++
		}
		if pc >= hotStart && pc <= hotEnd {
			if !inHotLoop || pc == hotStart {
				if pc == hotStart {
					loopIter++
					inHotLoop = true
					if loopIter <= 3 || loopIter == 13068 {
						var snap iterSnapshot
						snap.n = loopIter
						for i := 0; i < 16; i++ {
							snap.x[i] = emu.cpu.X[i]
						}
						snap.sp = emu.cpu.SP
						iterSnaps = append(iterSnaps, snap)
					}
				}
			}
		} else if inHotLoop {
			inHotLoop = false
		}
	}

	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatal(err)
	}
	emu.cpu.Trace = nil

	_ = tableReads
	t.Logf("total iterations of hot loop: %d", loopIter)
	t.Logf("total TEXT instructions: %d", textInstN)

	// Show register values at loop entry for first few iterations
	for _, s := range iterSnaps {
		t.Logf("iter %d: X0=%x X1=%x X2=%x X3=%x X4=%x X5=%x X6=%x X7=%x X8=%x X9=%x X10=%x X11=%x X12=%x X13=%x X14=%x X15=%x SP=%x",
			s.n, s.x[0], s.x[1], s.x[2], s.x[3], s.x[4], s.x[5], s.x[6], s.x[7],
			s.x[8], s.x[9], s.x[10], s.x[11], s.x[12], s.x[13], s.x[14], s.x[15], s.sp)
	}

	// Now dump the raw instructions in the hot loop
	t.Log("\nHot loop disassembly (raw instructions):")
	f, _ := os.Create("/tmp/fp_hot_loop.txt")
	if f != nil {
		for addr := hotStart; addr <= hotEnd; addr += 4 {
			inst := emu.mem.Read32(addr)
			fmt.Fprintf(f, "0x%x: 0x%08x\n", addr, inst)
		}
		f.Close()
		t.Logf("wrote hot loop to /tmp/fp_hot_loop.txt (%d instructions)", (hotEnd-hotStart)/4+1)
	}

	// Dump DATA_CONST pages that were read during exchange
	t.Log("\nDATA_CONST read pages:")
	readPages := emu.Mem().ReadPages
	var constPages []uint64
	for addr := range readPages {
		if addr >= 0x1aeaaf000 && addr < 0x1aeabe000 {
			constPages = append(constPages, addr)
		}
	}
	sort.Slice(constPages, func(i, j int) bool { return constPages[i] < constPages[j] })
	for _, addr := range constPages {
		t.Logf("  0x%x", addr)
	}
	t.Logf("total DATA_CONST pages read: %d", len(constPages))

	// Dump DATA segment pages read
	var dataPages []uint64
	for addr := range readPages {
		if addr >= 0x1b10a1000 && addr < 0x1b10bb000 {
			dataPages = append(dataPages, addr)
		}
	}
	sort.Slice(dataPages, func(i, j int) bool { return dataPages[i] < dataPages[j] })
	t.Logf("total DATA pages read: %d", len(dataPages))

	payload := m3
	if len(m3) > 12 && string(m3[:4]) == "FPLY" {
		payload = m3[12:]
	}
	t.Logf("m3 sig: %s", hex.EncodeToString(payload[132:]))
}

// TestExtractTables dumps the DATA_CONST tables used during the computation.
func TestExtractTables(t *testing.T) {
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

	// Clear read tracking
	emu.Mem().ReadPages = make(map[uint64]bool)

	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	// Instrument the hot loop to capture every memory read address
	type memRead struct {
		pc   uint64
		addr uint64
	}
	var dataReads []memRead

	hotStart := uint64(0x1a12d052c)
	hotEnd := uint64(0x1a12d0aa4)

	// Instrument: before each instruction in the hot loop, capture memory reads
	// by checking what the LDR instructions do
	iterCount := 0
	emu.cpu.Trace = func(pc uint64, inst uint32) {
		if pc == hotStart {
			iterCount++
		}
		if pc < hotStart || pc > hotEnd {
			return
		}
		// Only capture first iteration data reads
		if iterCount > 1 {
			return
		}
		// Check if this is a LDR instruction that reads from DATA_CONST
		// We post-process by looking at LDR/LDRB patterns
	}

	_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatal(err)
	}
	emu.cpu.Trace = nil

	_ = dataReads
	t.Logf("hot loop iterations: %d", iterCount)

	// Dump the full DATA_CONST segment that was read
	f, _ := os.Create("/tmp/fp_data_const.bin")
	if f != nil {
		start := uint64(0x1aeaaf360)
		size := 0xe5a8
		data := emu.ReadMem(start, size)
		f.Write(data)
		f.Close()
		t.Logf("wrote DATA_CONST to /tmp/fp_data_const.bin (%d bytes)", size)
	}

	// Dump the DATA segment
	f2, _ := os.Create("/tmp/fp_data.bin")
	if f2 != nil {
		start := uint64(0x1b10a17c0)
		size := 0x18dd8
		data := emu.ReadMem(start, size)
		f2.Write(data)
		f2.Close()
		t.Logf("wrote DATA to /tmp/fp_data.bin (%d bytes)", size)
	}

	// Dump the TEXT segment for the hot loop region
	f3, _ := os.Create("/tmp/fp_hot_text.bin")
	if f3 != nil {
		start := uint64(0x1a12d0000)
		size := 0x1000
		data := emu.ReadMem(start, size)
		f3.Write(data)
		f3.Close()
		t.Logf("wrote hot TEXT page to /tmp/fp_hot_text.bin (%d bytes)", size)
	}
}
