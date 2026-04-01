// Package fpemu emulates FairPlay SAP functions from an iOS ARM64 AirPlaySender binary
// using the Unicorn CPU emulator.
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
	"log"
	"os"
	"sync"

	"github.com/blacktop/go-macho"
	uc "github.com/unicorn-engine/unicorn/bindings/go/unicorn"
)

const (
	trampolineAddr uint64 = 0x10000000
	trampolineSize uint64 = 0x1000
	stackBase      uint64 = 0x70000000
	stackSize      uint64 = 0x800000 // 8 MB
	heapBase       uint64 = 0x80000000
	heapSize       uint64 = 0x4000000 // 64 MB
	stubPageBase   uint64 = 0x20000000
	stubPageSize   uint64 = 0x10000
	miscBase       uint64 = 0x30000000
	miscSize       uint64 = 0x1000
)

// Symbol addresses from llvm-nm of iOS 11 AirPlaySender.
const (
	symFPSAPInit     uint64 = 0x1a12c6468 // _cp2g1b9ro
	symFPSAPExchange uint64 = 0x1a12bfb88 // _Mib5yocT
)

type Emulator struct {
	mu      sync.Mutex
	engine  uc.Unicorn
	heapPtr uint64
	stubs   map[uint64]stubFunc
	shaCtxs map[uint64]hash.Hash
	aesCtxs map[uint64]*aesCTRCtx
}

type stubFunc func(e *Emulator) error

type aesCTRCtx struct {
	stream cipher.Stream
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

	engine, err := uc.NewUnicorn(uc.ARCH_ARM64, uc.MODE_ARM)
	if err != nil {
		return nil, fmt.Errorf("unicorn: %w", err)
	}

	e := &Emulator{
		engine:  engine,
		heapPtr: heapBase,
		stubs:   make(map[uint64]stubFunc),
		shaCtxs: make(map[uint64]hash.Hash),
		aesCtxs: make(map[uint64]*aesCTRCtx),
	}

	// Map fixed regions
	for _, m := range [][2]uint64{
		{trampolineAddr, trampolineSize},
		{stackBase, stackSize},
		{heapBase, heapSize},
		{stubPageBase, stubPageSize},
		{miscBase, miscSize},
	} {
		if err := engine.MemMap(m[0], m[1]); err != nil {
			return nil, fmt.Errorf("map 0x%x: %w", m[0], err)
		}
	}

	// Trampoline: BLR X8; BRK #0
	engine.MemWrite(trampolineAddr, []byte{0x00, 0x01, 0x3F, 0xD6, 0x00, 0x00, 0x20, 0xD4})

	// Fill stub page with BRK #0
	brks := make([]byte, stubPageSize)
	for i := 0; i < len(brks); i += 4 {
		binary.LittleEndian.PutUint32(brks[i:], 0xD4200000)
	}
	engine.MemWrite(stubPageBase, brks)

	// Stack canary
	engine.MemWrite(miscBase, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})

	// Nested return sentinel (BRK #0 at known address for dispatch_once init calls)
	engine.MemWrite(nestedRetAddr, []byte{0x00, 0x00, 0x20, 0xD4})

	// Load segments
	pageSet := make(map[uint64]bool)
	for _, seg := range f.Segments() {
		if seg.Name == "__LINKEDIT" || seg.Memsz == 0 {
			continue
		}
		pageStart := seg.Addr & ^uint64(0xFFF)
		pageEnd := (seg.Addr + seg.Memsz + 0xFFF) & ^uint64(0xFFF)
		for p := pageStart; p < pageEnd; p += 0x1000 {
			if pageSet[p] {
				continue
			}
			pageSet[p] = true
			engine.MemMap(p, 0x1000)
		}
		if seg.Filesz > 0 {
			segData := data[seg.Offset : seg.Offset+seg.Filesz]
			engine.MemWrite(seg.Addr, segData)
		}
		log.Printf("[fpemu] segment %s: 0x%x size=0x%x", seg.Name, seg.Addr, seg.Memsz)
	}

	// Patch GOT entries
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
				// Non-lazy GOT entries
				if name == "___stack_chk_guard" {
					e.writeU64(gotSlot, miscBase)
					continue
				}
				// Allocate zero buffer for data symbol references
				zeroAddr := e.heapAlloc(256)
				e.writeU64(gotSlot, zeroAddr)
				continue
			}

			// __la_symbol_ptr: patch with our stub
			handler := sNop
			if h, ok := handlers[name]; ok {
				handler = h
			}
			e.stubs[stubAddr] = handler
			e.writeU64(gotSlot, stubAddr)
			stubAddr += 4
		}
	}

	log.Printf("[fpemu] patched %d import stubs", len(e.stubs))

	// Add hooks for unmapped memory access (shared cache pointers in __DATA)
	engine.HookAdd(uc.HOOK_MEM_UNMAPPED, func(_ uc.Unicorn, typ int, addr uint64, size int, value int64) bool {
		pageAddr := addr & ^uint64(0xFFF)
		if err := engine.MemMap(pageAddr, 0x1000); err != nil {
			log.Printf("[fpemu] MemMap 0x%x failed: %v", pageAddr, err)
		}

		if typ == uc.MEM_FETCH_UNMAPPED {
			// Code fetch: write BRK #0 and register dynamic stub
			engine.MemWrite(addr, []byte{0x00, 0x00, 0x20, 0xD4})
			if _, exists := e.stubs[addr]; !exists {
				e.stubs[addr] = e.makeDynStub(addr)
				lr, _ := engine.RegRead(uc.ARM64_REG_LR)
				x0v, _ := engine.RegRead(uc.ARM64_REG_X0)
				x1v, _ := engine.RegRead(uc.ARM64_REG_X1)
				log.Printf("[fpemu] registered dynamic stub 0x%x (LR=0x%x X0=0x%x X1=0x%x)", addr, lr, x0v, x1v)
			}
		}
		// Read/write unmapped: zero page is fine
		return true
	}, 0, ^uint64(0))

	return e, nil
}

func (e *Emulator) Close() error { return e.engine.Close() }

// execLoop runs the emulator starting at pc until it hits the sentinel address.
// It handles BRK stubs (both static GOT and dynamic shared-cache) along the way.
func (e *Emulator) execLoop(pc, sentinel uint64) error {
	for {
		err := e.engine.Start(pc, ^uint64(0))
		curPC, _ := e.engine.RegRead(uc.ARM64_REG_PC)

		if curPC == sentinel {
			return nil
		}

		if handler, ok := e.stubs[curPC]; ok {
			if herr := handler(e); herr != nil {
				return fmt.Errorf("stub 0x%x: %w", curPC, herr)
			}
			lr, _ := e.engine.RegRead(uc.ARM64_REG_LR)
			pc = lr
			continue
		}

		if err != nil {
			return fmt.Errorf("stop at PC=0x%x: %w", curPC, err)
		}
		return nil
	}
}

func (e *Emulator) callFunc(addr uint64, args ...uint64) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	sp := stackBase + stackSize - 0x100
	e.engine.RegWrite(uc.ARM64_REG_SP, sp)

	xregs := []int{uc.ARM64_REG_X0, uc.ARM64_REG_X1, uc.ARM64_REG_X2, uc.ARM64_REG_X3,
		uc.ARM64_REG_X4, uc.ARM64_REG_X5, uc.ARM64_REG_X6, uc.ARM64_REG_X7}
	for i, r := range xregs {
		v := uint64(0)
		if i < len(args) {
			v = args[i]
		}
		e.engine.RegWrite(r, v)
	}
	e.engine.RegWrite(uc.ARM64_REG_X8, addr)

	if err := e.execLoop(trampolineAddr, trampolineAddr+4); err != nil {
		return 0, err
	}

	ret, _ := e.engine.RegRead(uc.ARM64_REG_X0)
	return ret, nil
}

func (e *Emulator) heapAlloc(n uint64) uint64 {
	n = (n + 15) & ^uint64(15)
	addr := e.heapPtr
	e.heapPtr += n
	return addr
}

func (e *Emulator) writeToHeap(data []byte) uint64 {
	addr := e.heapAlloc(uint64(len(data)))
	e.engine.MemWrite(addr, data)
	return addr
}

func (e *Emulator) readMem(addr uint64, n int) []byte {
	b, _ := e.engine.MemRead(addr, uint64(n))
	return b
}

func (e *Emulator) readU64(addr uint64) uint64 {
	return binary.LittleEndian.Uint64(e.readMem(addr, 8))
}

func (e *Emulator) readU32(addr uint64) uint32 {
	return binary.LittleEndian.Uint32(e.readMem(addr, 4))
}

func (e *Emulator) writeU64(addr, val uint64) {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, val)
	e.engine.MemWrite(addr, b)
}

func (e *Emulator) writeU32(addr uint64, val uint32) {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, val)
	e.engine.MemWrite(addr, b)
}

func x0(e *Emulator) uint64       { v, _ := e.engine.RegRead(uc.ARM64_REG_X0); return v }
func x1(e *Emulator) uint64       { v, _ := e.engine.RegRead(uc.ARM64_REG_X1); return v }
func x2(e *Emulator) uint64       { v, _ := e.engine.RegRead(uc.ARM64_REG_X2); return v }
func x3(e *Emulator) uint64       { v, _ := e.engine.RegRead(uc.ARM64_REG_X3); return v }
func setX0(e *Emulator, v uint64) { e.engine.RegWrite(uc.ARM64_REG_X0, v) }

// FPSAPInit calls _cp2g1b9ro(&ctxRef, hwInfo) — note: ctxRef first, hwInfo second.
func (e *Emulator) FPSAPInit(hwInfo []byte) (uint64, error) {
	if len(hwInfo) == 0 {
		hwInfo = make([]byte, 24)
		binary.LittleEndian.PutUint32(hwInfo, 20) // IDLength
	}
	hwAddr := e.writeToHeap(hwInfo)
	ctxOutAddr := e.heapAlloc(8)
	e.writeU64(ctxOutAddr, 0)

	ret, err := e.callFunc(symFPSAPInit, ctxOutAddr, hwAddr)
	if err != nil {
		return 0, fmt.Errorf("FPSAPInit: %w", err)
	}
	if int32(ret) != 0 {
		return 0, fmt.Errorf("FPSAPInit returned %d", int32(ret))
	}
	ctx := e.readU64(ctxOutAddr)
	log.Printf("[fpemu] FPSAPInit: ctx=0x%x", ctx)
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
	e.writeU64(outPtrAddr, 0)
	e.writeU32(outLenAddr, 0)
	e.writeU32(rcAddr, 0)

	ret, err := e.callFunc(symFPSAPExchange,
		uint64(version), hwAddr, ctx, inAddr,
		uint64(len(input)), outPtrAddr, outLenAddr, rcAddr,
	)
	if err != nil {
		return nil, 0, fmt.Errorf("FPSAPExchange: %w", err)
	}

	rc := int32(e.readU32(rcAddr))
	if int32(ret) != 0 {
		return nil, rc, fmt.Errorf("FPSAPExchange returned %d (rc=%d)", int32(ret), rc)
	}

	outPtr := e.readU64(outPtrAddr)
	outLen := e.readU32(outLenAddr)
	var output []byte
	if outLen > 0 && outPtr != 0 {
		output = e.readMem(outPtr, int(outLen))
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
	e.engine.MemWrite(addr, make([]byte, total))
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
		e.engine.MemWrite(dst, e.readMem(src, int(n)))
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
		e.engine.MemWrite(dst, buf)
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
	da, db := e.readMem(a, int(n)), e.readMem(b, int(n))
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
		e.engine.MemWrite(dst, make([]byte, n))
	}
	return nil
}

func sStrlen(e *Emulator) error {
	addr := x0(e)
	n := uint64(0)
	for {
		b := e.readMem(addr+n, 1)
		if len(b) == 0 || b[0] == 0 {
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
		h.Write(e.readMem(data, int(n)))
	}
	setX0(e, 1)
	return nil
}
func sSHA1Final(e *Emulator) error {
	digest, ctx := x0(e), x1(e)
	if h, ok := e.shaCtxs[ctx]; ok {
		e.engine.MemWrite(digest, h.Sum(nil)[:20])
		delete(e.shaCtxs, ctx)
	} else {
		e.engine.MemWrite(digest, make([]byte, 20))
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
		h.Write(e.readMem(data, int(n)))
	}
	setX0(e, 1)
	return nil
}
func sSHA512Final(e *Emulator) error {
	digest, ctx := x0(e), x1(e)
	if h, ok := e.shaCtxs[ctx]; ok {
		e.engine.MemWrite(digest, h.Sum(nil)[:64])
		delete(e.shaCtxs, ctx)
	} else {
		e.engine.MemWrite(digest, make([]byte, 64))
	}
	setX0(e, 1)
	return nil
}

func sAESCTRInit(e *Emulator) error {
	ctxPtr, keyPtr, keyLen, ivPtr := x0(e), x1(e), x2(e), x3(e)
	key := e.readMem(keyPtr, int(keyLen))
	iv := e.readMem(ivPtr, 16)
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
		in := e.readMem(inPtr, int(inLen))
		out := make([]byte, inLen)
		ctx.stream.XORKeyStream(out, in)
		e.engine.MemWrite(outPtr, out)
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
	lr, _ := e.engine.RegRead(uc.ARM64_REG_LR)
	return fmt.Errorf("abort() from 0x%x", lr)
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
	if e.readMem(ctrl, 1)[0] == 0 {
		e.engine.MemWrite(ctrl, []byte{1, 0, 0, 0})
		// Cannot call init routine recursively; skip for now
		log.Printf("[fpemu] pthread_once: skipping init routine")
	}
	setX0(e, 0)
	return nil
}
func sDispatchOnce(e *Emulator) error {
	pred := x0(e)
	if e.readU64(pred) == 0 {
		e.writeU64(pred, 1)
		log.Printf("[fpemu] dispatch_once: skipping block")
	}
	return nil
}

// Sentinel for nested calls — BRK at a known address
const nestedRetAddr uint64 = miscBase + 0x800

// makeDynStub returns a stub handler for an unmapped shared-cache function.
// On the FIRST call, it classifies the function by argument heuristics and
// replaces itself with a specific handler for all future calls.
func (e *Emulator) makeDynStub(addr uint64) stubFunc {
	return func(e *Emulator) error {
		a0, a1, a2 := x0(e), x1(e), x2(e)

		isText := func(v uint64) bool { return v >= 0x1a1210000 && v < 0x1a1316000 }
		// Predicate must be in the binary's DATA segments (global variable), not heap/stack
		isGlobalData := func(v uint64) bool { return v >= 0x1a0000000 && v < 0x1c0000000 }

		// dispatch_once_f / FigThreadRunOnce: predicate in global DATA, init func in TEXT
		if isGlobalData(a0) {
			var initFunc uint64
			if isText(a1) {
				initFunc = a1
			} else if isText(a2) {
				initFunc = a2
			}
			if initFunc != 0 {
				log.Printf("[fpemu] dynstub 0x%x: classified as dispatch_once", addr)
				handler := func(e *Emulator) error {
					pred := x0(e)
					fn := x1(e)
					if !isText(fn) {
						fn = x2(e)
					}
					if !isText(fn) {
						setX0(e, 0)
						return nil
					}
					if e.readU64(pred) == 0 {
						e.writeU64(pred, ^uint64(0))
						log.Printf("[fpemu] dispatch_once 0x%x: calling init 0x%x", addr, fn)
						savedLR, _ := e.engine.RegRead(uc.ARM64_REG_LR)
						e.engine.RegWrite(uc.ARM64_REG_LR, nestedRetAddr)
						if err := e.execLoop(fn, nestedRetAddr); err != nil {
							log.Printf("[fpemu] dispatch_once init error: %v", err)
						}
						e.engine.RegWrite(uc.ARM64_REG_LR, savedLR)
					}
					setX0(e, 0)
					return nil
				}
				e.stubs[addr] = handler
				return handler(e)
			}
		}

		// Small X0 → malloc(size)
		if a0 > 0 && a0 < 0x100000 {
			log.Printf("[fpemu] dynstub 0x%x: classified as malloc", addr)
			e.stubs[addr] = sMalloc
			return sMalloc(e)
		}

		// Default: nop returning 0
		log.Printf("[fpemu] dynstub 0x%x: classified as nop (X0=0x%x X1=0x%x X2=0x%x)", addr, a0, a1, a2)
		e.stubs[addr] = sNop
		return sNop(e)
	}
}
