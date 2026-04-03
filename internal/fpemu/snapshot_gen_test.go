//go:build !emulate

// Run with: go test -run TestGenerateSnapshot ./internal/fpemu/ -v
// Set GENERATE_SNAPSHOT=1 to actually write the file.
// This generates the snapshot_data.gz file used by NewFromSnapshot.

package fpemu

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/hex"
	"os"
	"sort"
	"testing"
)

func TestGenerateSnapshot(t *testing.T) {
	if os.Getenv("GENERATE_SNAPSHOT") == "" {
		t.Skip("set GENERATE_SNAPSHOT=1 to run")
	}

	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	emu, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer emu.Close()

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		t.Fatalf("FPSAPInit: %v", err)
	}

	// Phase 1: generate m1 to complete init
	m1, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatalf("FPSAPExchange phase1: %v", err)
	}
	t.Logf("m1: %d bytes, rc=%d, hex=%s", len(m1), rc, hex.EncodeToString(m1))

	// Take a snapshot of memory right now. The emulator is in a state where
	// calling FPSAPExchange with m2 will produce m3.
	// First, clear ReadPages so we can track what's needed for exchange.

	emu.Mem().ReadPages = make(map[uint64]bool)

	// Do a probe exchange with a zero m2 to discover which pages are needed
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	// Save full state before the probe
	fullSnap := emu.Mem().Snapshot()
	savedHeapPtr := emu.HeapPtr()

	m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatalf("probe exchange: %v", err)
	}
	t.Logf("probe m3: %d bytes, hex=%s", len(m3), hex.EncodeToString(m3))

	// Collect pages that were read during the exchange
	readPages := make(map[uint64]bool)
	for addr := range emu.Mem().ReadPages {
		readPages[addr] = true
	}
	t.Logf("pages read during exchange: %d", len(readPages))

	// Do a second probe with different m2 to catch any additional pages
	emu.Mem().Restore(fullSnap)
	emu.SetHeapPtr(savedHeapPtr)
	emu.Mem().ReadPages = make(map[uint64]bool)

	var challenge2 [128]byte
	for i := range challenge2 {
		challenge2[i] = byte(i)
	}
	m2b := make([]byte, 142)
	copy(m2b[0:4], []byte("FPLY"))
	m2b[4] = 0x03
	m2b[5] = 0x01
	m2b[6] = 0x02
	binary.BigEndian.PutUint32(m2b[8:12], 130)
	m2b[12] = 0x02
	m2b[13] = 0x03
	copy(m2b[14:], challenge2[:])

	m3b, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2b)
	if err != nil {
		t.Fatalf("probe exchange 2: %v", err)
	}
	t.Logf("probe m3b: %d bytes", len(m3b))

	for addr := range emu.Mem().ReadPages {
		readPages[addr] = true
	}
	t.Logf("total unique pages after 2 probes: %d", len(readPages))

	// Generate the snapshot from the pre-exchange state
	// Sort pages by address for deterministic output
	var pageAddrs []uint64
	for addr := range readPages {
		pageAddrs = append(pageAddrs, addr)
	}
	sort.Slice(pageAddrs, func(i, j int) bool { return pageAddrs[i] < pageAddrs[j] })

	// Build the snapshot binary
	var buf bytes.Buffer

	// Header
	hdr := snapshotHeader{
		NPages:  uint32(len(pageAddrs)),
		HeapPtr: savedHeapPtr,
		Ctx:     ctx,
	}
	binary.Write(&buf, binary.LittleEndian, hdr)

	// Named stubs
	stubNames := emu.StubNames()
	for addr, name := range stubNames {
		binary.Write(&buf, binary.LittleEndian, addr)
		binary.Write(&buf, binary.LittleEndian, uint16(len(name)))
		buf.WriteString(name)
	}
	// Sentinel
	binary.Write(&buf, binary.LittleEndian, uint64(0))

	// Pages (from the pre-exchange snapshot)
	for _, addr := range pageAddrs {
		binary.Write(&buf, binary.LittleEndian, addr)
		page := fullSnap[addr]
		if page == nil {
			page = make([]byte, 4096)
		}
		buf.Write(page)
	}

	t.Logf("raw snapshot: %d bytes (%d pages)", buf.Len(), len(pageAddrs))

	// Compress with gzip
	var gzbuf bytes.Buffer
	gw, _ := gzip.NewWriterLevel(&gzbuf, gzip.BestCompression)
	gw.Write(buf.Bytes())
	gw.Close()

	outPath := "snapshot_data.gz"
	if err := os.WriteFile(outPath, gzbuf.Bytes(), 0644); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	t.Logf("wrote %s: %d bytes compressed (%.1f KB)", outPath, gzbuf.Len(), float64(gzbuf.Len())/1024)
}
