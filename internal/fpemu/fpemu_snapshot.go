//go:build !emulate

package fpemu

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"crypto/sha512"
	_ "embed"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"sync"

	"doubletake/internal/arm64emu"
)

//go:embed snapshot_data.gz
var snapshotData []byte

// NewFromSnapshot creates an Emulator from the embedded memory snapshot.
// This eliminates the need for the Apple AirPlaySender binary — it contains
// only the minimal memory pages needed for FPSAPExchange after Init + m1.
func NewFromSnapshot() (*Emulator, error) {
	return loadSnapshot(snapshotData)
}

// snapshotHeader is the fixed-size header at the start of the snapshot.
type snapshotHeader struct {
	NPages  uint32
	HeapPtr uint64
	Ctx     uint64
}

// loadSnapshot decodes a gzipped snapshot into an Emulator.
//
// Format:
//
//	[gzip envelope]
//	  header: nPages(u32) | heapPtr(u64) | ctx(u64)
//	  n × named stubs: addr(u64) | nameLen(u16) | name(bytes)
//	  sentinel: addr=0
//	  nPages × page: addr(u64) | data(4096 bytes)
func loadSnapshot(data []byte) (*Emulator, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip open: %w", err)
	}
	raw, err := io.ReadAll(gz)
	gz.Close()
	if err != nil {
		return nil, fmt.Errorf("gzip read: %w", err)
	}

	r := bytes.NewReader(raw)

	// Read header
	var hdr snapshotHeader
	if err := binary.Read(r, binary.LittleEndian, &hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}

	mem := arm64emu.NewMemory()
	cpu := arm64emu.NewCPU(mem)

	e := &Emulator{
		cpu:       cpu,
		mem:       mem,
		heapPtr:   hdr.HeapPtr,
		shaCtxs:   make(map[uint64]hash.Hash),
		aesCtxs:   make(map[uint64]*aesCTRCtx),
		stubNames: make(map[uint64]string),
	}

	// Read named stubs
	handlers := e.makeHandlers()
	for {
		var addr uint64
		if err := binary.Read(r, binary.LittleEndian, &addr); err != nil {
			return nil, fmt.Errorf("read stub addr: %w", err)
		}
		if addr == 0 {
			break // sentinel
		}
		var nameLen uint16
		if err := binary.Read(r, binary.LittleEndian, &nameLen); err != nil {
			return nil, fmt.Errorf("read stub name len: %w", err)
		}
		name := make([]byte, nameLen)
		if _, err := io.ReadFull(r, name); err != nil {
			return nil, fmt.Errorf("read stub name: %w", err)
		}
		nameStr := string(name)
		handler := handlers[nameStr]
		if handler == nil {
			handler = sNop
		}
		e.registerStub(addr, nameStr, handler)
	}

	// Read pages
	for i := uint32(0); i < hdr.NPages; i++ {
		var addr uint64
		if err := binary.Read(r, binary.LittleEndian, &addr); err != nil {
			return nil, fmt.Errorf("read page %d addr: %w", i, err)
		}
		page := make([]byte, 4096)
		if _, err := io.ReadFull(r, page); err != nil {
			return nil, fmt.Errorf("read page %d data: %w", i, err)
		}
		mem.Map(addr, 4096)
		mem.Write(addr, page)
	}

	// Set up trampoline and misc regions (may already be in snapshot, but ensure)
	mem.Map(trampolineAddr, 0x1000)
	mem.Write(trampolineAddr, []byte{0x00, 0x01, 0x3F, 0xD6, 0x00, 0x00, 0x20, 0xD4})
	mem.Map(miscBase, 0x1000)
	mem.Write(miscBase, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	mem.Write(nestedRetAddr, []byte{0x00, 0x00, 0x20, 0xD4})

	// Register fault handler for any shared-cache stubs we haven't seen
	cpu.OnFault = func(cpu *arm64emu.CPU, pc uint64, inst uint32) error {
		mem.Write(pc, []byte{0x00, 0x00, 0x20, 0xD4})
		cpu.Stubs[pc] = e.makeDynStub(pc)
		dbg("[EMU-SNAP] registered dynamic stub at 0x%x (LR=0x%x X0=0x%x X1=0x%x)", pc, cpu.X[30], cpu.X[0], cpu.X[1])
		return nil
	}

	dbg("[EMU-SNAP] loaded snapshot: %d pages, heapPtr=0x%x, ctx=0x%x", hdr.NPages, hdr.HeapPtr, hdr.Ctx)
	return e, nil
}

// SnapshotCtx returns the SAP context pointer stored in the snapshot header.
// This is needed because NewFromSnapshot skips FPSAPInit.
func SnapshotCtx() (uint64, error) {
	gz, err := gzip.NewReader(bytes.NewReader(snapshotData))
	if err != nil {
		return 0, err
	}
	defer gz.Close()
	var hdr snapshotHeader
	if err := binary.Read(gz, binary.LittleEndian, &hdr); err != nil {
		return 0, err
	}
	return hdr.Ctx, nil
}

// SHA1/SHA512/AES stubs needed by makeHandlers — reused from fpemu_goemu.go.
// They're the same functions, so they're shared via the package.
var _ = sha1.New
var _ = sha512.New
var _ = aes.NewCipher
var _ = cipher.NewCTR
var _ hash.Hash
var _ sync.Mutex
