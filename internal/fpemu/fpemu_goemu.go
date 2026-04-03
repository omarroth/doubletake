//go:build !emulate

// fpemu_goemu.go provides the same Emulator API as the Unicorn-based fpemu.go,
// but uses the pure Go ARM64 interpreter from internal/arm64emu instead.
// This eliminates the CGo/Unicorn dependency for the default build.
package fpemu

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"os"
	"sync"

	"doubletake/internal/arm64emu"

	"github.com/blacktop/go-macho"
)

const (
	trampolineAddr uint64 = 0x10000000
	stackBase      uint64 = 0x70000000
	stackSize      uint64 = 0x800000 // 8 MB
	heapBase       uint64 = 0x80000000
	heapSize       uint64 = 0x4000000 // 64 MB
	stubPageBase   uint64 = 0x20000000
	stubPageSize   uint64 = 0x10000
	miscBase       uint64 = 0x30000000
	nestedRetAddr  uint64 = miscBase + 0x800
)

const (
	symFPSAPInit     uint64 = 0x1a12c6468
	symFPSAPExchange uint64 = 0x1a12bfb88
)

type stubFunc func(e *Emulator) error

type aesCTRCtx struct {
	stream cipher.Stream
}

type Emulator struct {
	mu        sync.Mutex
	cpu       *arm64emu.CPU
	mem       *arm64emu.Memory
	heapPtr   uint64
	shaCtxs   map[uint64]hash.Hash
	aesCtxs   map[uint64]*aesCTRCtx
	stubNames map[uint64]string
}

func New(binaryPath string) (*Emulator, error) {
	data, err := os.ReadFile(binaryPath)
	if err != nil {
		return nil, fmt.Errorf("read binary: %w", err)
	}

	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse macho: %w", err)
	}

	mem := arm64emu.NewMemory()
	cpu := arm64emu.NewCPU(mem)

	e := &Emulator{
		cpu:       cpu,
		mem:       mem,
		heapPtr:   heapBase,
		shaCtxs:   make(map[uint64]hash.Hash),
		aesCtxs:   make(map[uint64]*aesCTRCtx),
		stubNames: make(map[uint64]string),
	}

	// Map fixed regions
	mem.Map(trampolineAddr, 0x1000)
	mem.Map(stackBase, stackSize)
	mem.Map(heapBase, heapSize)
	mem.Map(stubPageBase, stubPageSize)
	mem.Map(miscBase, 0x1000)

	// Trampoline: BLR X8; BRK #0
	mem.Write(trampolineAddr, []byte{0x00, 0x01, 0x3F, 0xD6, 0x00, 0x00, 0x20, 0xD4})

	// Fill stub page with BRK #0
	brks := make([]byte, stubPageSize)
	for i := 0; i < len(brks); i += 4 {
		binary.LittleEndian.PutUint32(brks[i:], 0xD4200000)
	}
	mem.Write(stubPageBase, brks)

	// Stack canary
	mem.Write(miscBase, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})

	// BRK at nested-return sentinel
	mem.Write(nestedRetAddr, []byte{0x00, 0x00, 0x20, 0xD4})

	// Load Mach-O segments
	for _, seg := range f.Segments() {
		if seg.Name == "__LINKEDIT" || seg.Memsz == 0 {
			continue
		}
		mem.Map(seg.Addr, seg.Memsz)
		if seg.Filesz > 0 {
			segData := data[seg.Offset : seg.Offset+seg.Filesz]
			mem.Write(seg.Addr, segData)
		}
		dbg("[EMU] segment %s: 0x%x size=0x%x", seg.Name, seg.Addr, seg.Memsz)
	}

	// Patch GOT entries with BRK stubs
	handlers := e.makeHandlers()
	stubAddr := stubPageBase + 4
	for _, sec := range f.Sections {
		if sec.Name != "__la_symbol_ptr" && sec.Name != "__got" {
			continue
		}
		nEntries := int(sec.Size / 8)
		for i := 0; i < nEntries; i++ {
			isymIdx := int(sec.Reserved1) + i
			if isymIdx >= len(f.Dysymtab.IndirectSyms) {
				continue
			}
			symIdx := f.Dysymtab.IndirectSyms[isymIdx]
			if symIdx == 0x40000000 || symIdx == 0x80000000 || symIdx == 0xC0000000 {
				continue
			}
			if int(symIdx) >= len(f.Symtab.Syms) {
				continue
			}
			name := f.Symtab.Syms[symIdx].Name
			gotSlot := sec.Addr + uint64(i)*8

			if sec.Name == "__got" {
				if name == "___stack_chk_guard" {
					e.write64(gotSlot, miscBase)
					continue
				}
				zeroAddr := e.heapAlloc(256)
				e.write64(gotSlot, zeroAddr)
				continue
			}

			// __la_symbol_ptr
			handler := handlers[name]
			if handler == nil {
				handler = sNop
			}
			e.registerStub(stubAddr, name, handler)
			e.write64(gotSlot, stubAddr)
			stubAddr += 4
		}
	}

	// Register fault handler for shared-cache function calls
	cpu.OnFault = func(cpu *arm64emu.CPU, pc uint64, inst uint32) error {
		// Write BRK at this address so future hits are caught by Stubs
		mem.Write(pc, []byte{0x00, 0x00, 0x20, 0xD4})
		// Register a dynamic stub using heuristic classification
		cpu.Stubs[pc] = e.makeDynStub(pc)
		dbg("[EMU] registered dynamic stub at 0x%x (LR=0x%x X0=0x%x X1=0x%x)", pc, cpu.X[30], cpu.X[0], cpu.X[1])
		return nil
	}

	dbg("[EMU] loaded binary with pure Go ARM64 interpreter")
	return e, nil
}

func (e *Emulator) Close() error { return nil }

func (e *Emulator) registerStub(addr uint64, name string, handler stubFunc) {
	e.stubNames[addr] = name
	e.cpu.Stubs[addr] = func(cpu *arm64emu.CPU) error {
		return handler(e)
	}
}

func (e *Emulator) callFunc(addr uint64, args ...uint64) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	sp := stackBase + stackSize - 0x100
	e.cpu.SP = sp
	for i := 0; i < 8; i++ {
		v := uint64(0)
		if i < len(args) {
			v = args[i]
		}
		e.cpu.SetReg(uint32(i), v)
	}
	e.cpu.SetReg(8, addr) // X8 = target

	// Run BLR X8 then halt at BRK (trampoline+4)
	e.cpu.PC = trampolineAddr
	haltPC := trampolineAddr + 4
	if err := e.cpu.Run(haltPC); err != nil {
		return 0, err
	}
	return e.cpu.X[0], nil
}

func (e *Emulator) heapAlloc(n uint64) uint64 {
	n = (n + 15) &^ 15
	addr := e.heapPtr
	e.heapPtr += n
	return addr
}

func (e *Emulator) writeToHeap(data []byte) uint64 {
	addr := e.heapAlloc(uint64(len(data)))
	e.mem.Write(addr, data)
	return addr
}

func (e *Emulator) read64(addr uint64) uint64 {
	return e.mem.Read64(addr)
}

func (e *Emulator) write64(addr, val uint64) {
	e.mem.Write64(addr, val)
}

func (e *Emulator) write32(addr uint64, val uint32) {
	e.mem.Write32(addr, val)
}

func (e *Emulator) read32(addr uint64) uint32 {
	return e.mem.Read32(addr)
}

// ReadMem reads n bytes from the emulated address space.
func (e *Emulator) ReadMem(addr uint64, n int) []byte {
	return e.mem.Read(addr, n)
}

// HeapDump returns (heapBase, usedBytes) for the entire used heap.
func (e *Emulator) HeapDump() (uint64, []byte) {
	used := int(e.heapPtr - heapBase)
	if used <= 0 {
		return heapBase, nil
	}
	return heapBase, e.mem.Read(heapBase, used)
}

func x0(e *Emulator) uint64       { return e.cpu.X[0] }
func x1(e *Emulator) uint64       { return e.cpu.X[1] }
func x2(e *Emulator) uint64       { return e.cpu.X[2] }
func x3(e *Emulator) uint64       { return e.cpu.X[3] }
func setX0(e *Emulator, v uint64) { e.cpu.X[0] = v }

// FPSAPInit calls _cp2g1b9ro(&ctxRef, hwInfo).
func (e *Emulator) FPSAPInit(hwInfo []byte) (uint64, error) {
	if len(hwInfo) == 0 {
		hwInfo = make([]byte, 24)
		binary.LittleEndian.PutUint32(hwInfo, 20)
	}
	hwAddr := e.writeToHeap(hwInfo)
	ctxOutAddr := e.heapAlloc(8)
	e.write64(ctxOutAddr, 0)

	ret, err := e.callFunc(symFPSAPInit, ctxOutAddr, hwAddr)
	if err != nil {
		return 0, fmt.Errorf("FPSAPInit: %w", err)
	}
	if int32(ret) != 0 {
		return 0, fmt.Errorf("FPSAPInit returned %d", int32(ret))
	}
	ctx := e.read64(ctxOutAddr)
	dbg("[EMU] FPSAPInit: ctx=0x%x", ctx)
	return ctx, nil
}

// FPSAPExchange calls _Mib5yocT(version, hwInfo, ctx, inBuf, inLen, &outBuf, &outLen, &rc).
func (e *Emulator) FPSAPExchange(version uint32, hwInfo []byte, ctx uint64, input []byte) ([]byte, int32, error) {
	if len(hwInfo) == 0 {
		hwInfo = make([]byte, 24)
	}
	hwAddr := e.writeToHeap(hwInfo)

	var inAddr uint64
	if len(input) > 0 {
		inAddr = e.writeToHeap(input)
	}
	outPtrAddr := e.heapAlloc(8)
	outLenAddr := e.heapAlloc(4)
	rcAddr := e.heapAlloc(4)
	e.write64(outPtrAddr, 0)
	e.write32(outLenAddr, 0)
	e.write32(rcAddr, 0)

	ret, err := e.callFunc(symFPSAPExchange,
		uint64(version), hwAddr, ctx, inAddr,
		uint64(len(input)), outPtrAddr, outLenAddr, rcAddr,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("FPSAPExchange: %w", err)
	}

	rc := int32(e.read32(rcAddr))
	if int32(ret) != 0 {
		return nil, rc, fmt.Errorf("FPSAPExchange returned %d (rc=%d)", int32(ret), rc)
	}

	outPtr := e.read64(outPtrAddr)
	outLen := e.read32(outLenAddr)
	var output []byte
	if outLen > 0 && outPtr != 0 {
		output = e.mem.Read(outPtr, int(outLen))
	}
	return output, rc, nil
}

// ---- Stub handlers ----

func (e *Emulator) makeHandlers() map[string]stubFunc {
	return map[string]stubFunc{
		"_malloc": sMalloc, "_calloc": sCalloc, "_realloc": sRealloc, "_free": sNop,
		"_memcpy": sMemcpy, "_memmove": sMemcpy, "___memcpy_chk": sMemcpy,
		"_memset": sMemset, "___memset_chk": sMemset,
		"_memcmp": sMemcmp, "_bzero": sBzero, "_strlen": sStrlen,

		"_CC_SHA1_Init": sSHA1Init, "_CC_SHA1_Update": sSHA1Update, "_CC_SHA1_Final": sSHA1Final,
		"_CC_SHA512_Init": sSHA512Init, "_CC_SHA512_Update": sSHA512Update, "_CC_SHA512_Final": sSHA512Final,

		"_AES_CTR_Init": sAESCTRInit, "_AES_CTR_Update": sAESCTRUpdate, "_AES_CTR_Final": sAESCTRFinal,
		"_AES_CBCFrame_Init": sNop, "_AES_CBCFrame_Update": sNop, "_AES_CBCFrame_Final": sNop,

		"_Dk7hjUuq": sNop,

		"_pthread_mutex_init": sNop, "_pthread_mutex_lock": sNop,
		"_pthread_mutex_unlock": sNop, "_pthread_mutex_destroy": sNop,
		"_pthread_once": sPthreadOnce, "_pthread_create": sNop,
		"_pthread_join": sNop, "_pthread_setname_np": sNop,

		"_FigThreadRunOnce":     sPthreadOnce,
		"_FigSimpleMutexCreate": sNop, "_FigSimpleMutexDestroy": sNop,
		"_FigSimpleMutexLock": sNop, "_FigSimpleMutexUnlock": sNop,

		"_ASPrintF": sNop, "_CPrintF": sNop, "_FPrintF": sNop,
		"_fprintf": sNop, "_printf": sNop,
		"_abort": sAbort, "_arc4random": sArc4random,
		"_getenv": sNop, "_sysctl": sMinusOne, "_sysctlbyname": sMinusOne,
		"_open": sMinusOne, "_close": sNop, "_read": sMinusOne, "_dlsym": sNop,

		"_ADClientAddValueForScalarKey": sNop, "_ADClientPushValueForDistributionKey": sNop,
		"_FigGetUpTimeNanoseconds": sGetTime, "_FigSignalErrorAt2": sNop,
		"_CFRetain": sReturnFirst, "_CFRelease": sNop,
		"_dispatch_once": sDispatchOnce,
	}
}

func sNop(e *Emulator) error         { setX0(e, 0); return nil }
func sMinusOne(e *Emulator) error    { setX0(e, ^uint64(0)); return nil }
func sReturnFirst(e *Emulator) error { return nil }

func sMalloc(e *Emulator) error {
	size := x0(e)
	if size == 0 {
		size = 16
	}
	setX0(e, e.heapAlloc(size))
	return nil
}

func sCalloc(e *Emulator) error {
	total := x0(e) * x1(e)
	if total == 0 {
		total = 16
	}
	addr := e.heapAlloc(total)
	e.mem.Write(addr, make([]byte, total))
	setX0(e, addr)
	return nil
}

func sRealloc(e *Emulator) error {
	size := x1(e)
	if size == 0 {
		size = 16
	}
	setX0(e, e.heapAlloc(size))
	return nil
}

func sMemcpy(e *Emulator) error {
	dst, src, n := x0(e), x1(e), x2(e)
	if n > 0 && src != 0 && dst != 0 {
		e.mem.Write(dst, e.mem.Read(src, int(n)))
	}
	setX0(e, dst)
	return nil
}

func sMemset(e *Emulator) error {
	dst, val, n := x0(e), byte(x1(e)), x2(e)
	if n > 0 {
		buf := make([]byte, n)
		for i := range buf {
			buf[i] = val
		}
		e.mem.Write(dst, buf)
	}
	setX0(e, dst)
	return nil
}

func sMemcmp(e *Emulator) error {
	a, b, n := x0(e), x1(e), x2(e)
	if n == 0 {
		setX0(e, 0)
		return nil
	}
	da, db := e.mem.Read(a, int(n)), e.mem.Read(b, int(n))
	for i := 0; i < int(n); i++ {
		if da[i] != db[i] {
			if da[i] < db[i] {
				setX0(e, ^uint64(0))
			} else {
				setX0(e, 1)
			}
			return nil
		}
	}
	setX0(e, 0)
	return nil
}

func sBzero(e *Emulator) error {
	dst, n := x0(e), x1(e)
	if n > 0 {
		e.mem.Write(dst, make([]byte, n))
	}
	return nil
}

func sStrlen(e *Emulator) error {
	addr := x0(e)
	n := uint64(0)
	for {
		b := e.mem.Read8(addr + n)
		if b == 0 {
			break
		}
		n++
		if n > 1<<20 {
			break
		}
	}
	setX0(e, n)
	return nil
}

func sSHA1Init(e *Emulator) error {
	e.shaCtxs[x0(e)] = sha1.New()
	setX0(e, 1)
	return nil
}
func sSHA1Update(e *Emulator) error {
	ctx, data, n := x0(e), x1(e), x2(e)
	h, ok := e.shaCtxs[ctx]
	if !ok {
		h = sha1.New()
		e.shaCtxs[ctx] = h
	}
	if n > 0 {
		h.Write(e.mem.Read(data, int(n)))
	}
	setX0(e, 1)
	return nil
}
func sSHA1Final(e *Emulator) error {
	digest, ctx := x0(e), x1(e)
	if h, ok := e.shaCtxs[ctx]; ok {
		e.mem.Write(digest, h.Sum(nil)[:20])
		delete(e.shaCtxs, ctx)
	} else {
		e.mem.Write(digest, make([]byte, 20))
	}
	setX0(e, 1)
	return nil
}

func sSHA512Init(e *Emulator) error {
	e.shaCtxs[x0(e)] = sha512.New()
	setX0(e, 1)
	return nil
}
func sSHA512Update(e *Emulator) error {
	ctx, data, n := x0(e), x1(e), x2(e)
	h, ok := e.shaCtxs[ctx]
	if !ok {
		h = sha512.New()
		e.shaCtxs[ctx] = h
	}
	if n > 0 {
		h.Write(e.mem.Read(data, int(n)))
	}
	setX0(e, 1)
	return nil
}
func sSHA512Final(e *Emulator) error {
	digest, ctx := x0(e), x1(e)
	if h, ok := e.shaCtxs[ctx]; ok {
		e.mem.Write(digest, h.Sum(nil)[:64])
		delete(e.shaCtxs, ctx)
	} else {
		e.mem.Write(digest, make([]byte, 64))
	}
	setX0(e, 1)
	return nil
}

func sAESCTRInit(e *Emulator) error {
	ctxPtr, keyPtr, keyLen, ivPtr := x0(e), x1(e), x2(e), x3(e)
	key := e.mem.Read(keyPtr, int(keyLen))
	iv := e.mem.Read(ivPtr, 16)
	block, err := aes.NewCipher(key)
	if err != nil {
		setX0(e, ^uint64(0))
		return nil
	}
	e.aesCtxs[ctxPtr] = &aesCTRCtx{stream: cipher.NewCTR(block, iv)}
	setX0(e, 0)
	return nil
}
func sAESCTRUpdate(e *Emulator) error {
	ctxPtr, inPtr, inLen, outPtr := x0(e), x1(e), x2(e), x3(e)
	if ctx, ok := e.aesCtxs[ctxPtr]; ok && inLen > 0 {
		in := e.mem.Read(inPtr, int(inLen))
		out := make([]byte, inLen)
		ctx.stream.XORKeyStream(out, in)
		e.mem.Write(outPtr, out)
	}
	setX0(e, 0)
	return nil
}
func sAESCTRFinal(e *Emulator) error {
	delete(e.aesCtxs, x0(e))
	setX0(e, 0)
	return nil
}

func sAbort(e *Emulator) error {
	return fmt.Errorf("abort() called from LR=0x%x", e.cpu.X[30])
}

func sArc4random(e *Emulator) error {
	b := make([]byte, 4)
	rand.Read(b)
	setX0(e, uint64(binary.LittleEndian.Uint32(b)))
	return nil
}

func sGetTime(e *Emulator) error { setX0(e, 1000000000); return nil }

func sPthreadOnce(e *Emulator) error {
	ctrl := x0(e)
	if e.mem.Read8(ctrl) == 0 {
		e.mem.Write(ctrl, []byte{1, 0, 0, 0})
		dbg("[EMU] pthread_once: skipping init routine")
	}
	setX0(e, 0)
	return nil
}

func sDispatchOnce(e *Emulator) error {
	pred := x0(e)
	if e.read64(pred) == 0 {
		e.write64(pred, 1)
		dbg("[EMU] dispatch_once: skipping block")
	}
	return nil
}

// makeDynStub creates a dynamic stub for an unmapped shared-cache function.
// It classifies the function by heuristics on the first call.
func (e *Emulator) makeDynStub(addr uint64) func(cpu *arm64emu.CPU) error {
	return func(cpu *arm64emu.CPU) error {
		a0, a1, a2 := cpu.X[0], cpu.X[1], cpu.X[2]

		isText := func(v uint64) bool { return v >= 0x1a1210000 && v < 0x1a1316000 }
		isGlobalData := func(v uint64) bool { return v >= 0x1a0000000 && v < 0x1c0000000 }

		// dispatch_once: predicate in global DATA, init func in TEXT
		if isGlobalData(a0) {
			var initFunc uint64
			if isText(a1) {
				initFunc = a1
			} else if isText(a2) {
				initFunc = a2
			}
			if initFunc != 0 {
				dbg("[EMU] dynstub 0x%x: classified as dispatch_once", addr)
				handler := func(cpu *arm64emu.CPU) error {
					pred := cpu.X[0]
					fn := cpu.X[1]
					if !isText(fn) {
						fn = cpu.X[2]
					}
					if !isText(fn) {
						cpu.X[0] = 0
						return nil
					}
					if e.read64(pred) == 0 {
						e.write64(pred, ^uint64(0))
						dbg("[EMU] dispatch_once 0x%x: calling init 0x%x", addr, fn)
						savedLR := cpu.X[30]
						cpu.X[30] = nestedRetAddr
						cpu.PC = fn
						if err := cpu.Run(nestedRetAddr); err != nil {
							dbg("[EMU] dispatch_once init error: %v", err)
						}
						cpu.X[30] = savedLR
					}
					cpu.X[0] = 0
					return nil
				}
				cpu.Stubs[addr] = handler
				return handler(cpu)
			}
		}

		// Small X0 → malloc
		if a0 > 0 && a0 < 0x100000 {
			dbg("[EMU] dynstub 0x%x: classified as malloc", addr)
			mallocHandler := func(cpu *arm64emu.CPU) error {
				size := cpu.X[0]
				if size == 0 {
					size = 16
				}
				cpu.X[0] = e.heapAlloc(size)
				return nil
			}
			cpu.Stubs[addr] = mallocHandler
			return mallocHandler(cpu)
		}

		// Default: nop returning 0
		dbg("[EMU] dynstub 0x%x: classified as nop (X0=0x%x X1=0x%x X2=0x%x)", addr, a0, a1, a2)
		nopHandler := func(cpu *arm64emu.CPU) error {
			cpu.X[0] = 0
			return nil
		}
		cpu.Stubs[addr] = nopHandler
		return nopHandler(cpu)
	}
}

// Mem returns the underlying Memory for snapshot generation.
func (e *Emulator) Mem() *arm64emu.Memory { return e.mem }

// HeapPtr returns the current heap allocation pointer.
func (e *Emulator) HeapPtr() uint64 { return e.heapPtr }

// SetHeapPtr sets the heap allocation pointer (used when restoring from snapshot).
func (e *Emulator) SetHeapPtr(v uint64) { e.heapPtr = v }

// StubNames returns a map from stub addresses to their handler names.
func (e *Emulator) StubNames() map[uint64]string {
	names := make(map[uint64]string)
	for addr, name := range e.stubNames {
		names[addr] = name
	}
	return names
}
