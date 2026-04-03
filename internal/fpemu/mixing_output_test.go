//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"os"
	"sort"
	"testing"
)

func align16(n uint64) uint64 { return (n + 15) &^ 15 }

// TestChallengeByteMixingMap tracks exact reads of m2 challenge bytes (m2[14:142])
// and reports how each input byte participates in the signature computation.
func TestChallengeByteMixingMap(t *testing.T) {
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

	// Build m2 with identifiable challenge bytes 0..127.
	var ch [128]byte
	for i := range ch {
		ch[i] = byte(i)
	}
	m2 := buildTestM2(ch)

	// In FPSAPExchange, hwInfo is allocated first, then input (m2).
	hpBefore := emu.HeapPtr()
	m2Addr := hpBefore + align16(uint64(len(hwInfo)))
	challengeBase := m2Addr + 14

	var currentPC uint64
	var readCount [128]int
	var firstPC [128]uint64
	var lastPC [128]uint64
	var readEvents int

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		currentPC = pc
		_ = inst
	}
	oldOnRead := emu.Mem().OnRead
	emu.Mem().OnRead = func(addr uint64, n int) {
		for i := 0; i < n; i++ {
			a := addr + uint64(i)
			if a < challengeBase || a >= challengeBase+128 {
				continue
			}
			idx := int(a - challengeBase)
			readCount[idx]++
			if firstPC[idx] == 0 {
				firstPC[idx] = currentPC
			}
			lastPC[idx] = currentPC
			readEvents++
		}
	}

	_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, m2)
	emu.Mem().OnRead = oldOnRead
	emu.cpu.Trace = nil
	if err != nil {
		t.Fatal(err)
	}

	missing := 0
	totalReads := 0
	maxReads := 0
	for i := 0; i < 128; i++ {
		totalReads += readCount[i]
		if readCount[i] == 0 {
			missing++
		}
		if readCount[i] > maxReads {
			maxReads = readCount[i]
		}
	}

	t.Logf("challenge base: 0x%x", challengeBase)
	t.Logf("tracked read events (byte-precision): %d", readEvents)
	t.Logf("challenge byte coverage: %d/128 read at least once", 128-missing)
	t.Logf("total per-byte reads: %d, max per-byte reads: %d", totalReads, maxReads)

	if missing > 0 {
		t.Fatalf("%d challenge bytes were never read", missing)
	}

	// Print a compact read profile.
	t.Log("first 16 challenge bytes: reads, firstPC, lastPC")
	for i := 0; i < 16; i++ {
		t.Logf("  [%3d]: %4d reads, first=0x%x last=0x%x", i, readCount[i], firstPC[i], lastPC[i])
	}
}

// TestSignatureOutputWriteMap tracks writes into the 20-byte signature area and
// identifies extraction order and writer PCs.
func TestSignatureOutputWriteMap(t *testing.T) {
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

	var ch [128]byte
	for i := range ch {
		ch[i] = byte(i)
	}
	m2 := buildTestM2(ch)

	const sigAddr = uint64(0x80017560)
	const sigLen = 20

	type evt struct {
		pc   uint64
		addr uint64
	}
	var events []evt
	var currentPC uint64
	var firstWrite [sigLen]evt
	var wrote [sigLen]bool

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		currentPC = pc
		_ = inst
	}
	oldOnWrite := emu.Mem().OnWrite
	emu.Mem().OnWrite = func(addr uint64, n int) {
		for i := 0; i < n; i++ {
			a := addr + uint64(i)
			if a < sigAddr || a >= sigAddr+sigLen {
				continue
			}
			e := evt{pc: currentPC, addr: a}
			events = append(events, e)
			off := int(a - sigAddr)
			if !wrote[off] {
				wrote[off] = true
				firstWrite[off] = e
			}
		}
	}

	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	emu.Mem().OnWrite = oldOnWrite
	emu.cpu.Trace = nil
	if err != nil {
		t.Fatal(err)
	}

	payload := m3
	if len(payload) >= 12 && string(payload[:4]) == "FPLY" {
		payload = payload[12:]
	}
	sig := payload[132:152]
	t.Logf("sig: %x", sig)
	t.Logf("signature write events: %d", len(events))

	for i := 0; i < sigLen; i++ {
		if !wrote[i] {
			t.Fatalf("signature byte %d was never written", i)
		}
	}

	// Summarize writes by PC.
	pcCounts := map[uint64]int{}
	for _, e := range events {
		pcCounts[e.pc]++
	}
	type pcEntry struct {
		pc    uint64
		count int
	}
	pcs := make([]pcEntry, 0, len(pcCounts))
	for pc, c := range pcCounts {
		pcs = append(pcs, pcEntry{pc: pc, count: c})
	}
	sort.Slice(pcs, func(i, j int) bool {
		if pcs[i].count == pcs[j].count {
			return pcs[i].pc < pcs[j].pc
		}
		return pcs[i].count > pcs[j].count
	})

	t.Log("top signature-writer PCs:")
	for i := 0; i < len(pcs) && i < 8; i++ {
		t.Logf("  0x%x -> %d writes", pcs[i].pc, pcs[i].count)
	}

	t.Log("first-write order by byte offset:")
	for i := 0; i < sigLen; i++ {
		t.Logf("  sig[%02d] first written at PC=0x%x", i, firstWrite[i].pc)
	}
}
