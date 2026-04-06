// fpexchange_interp.go is a self-contained ARM64 interpreter for
// the FairPlay SAP exchange function. It uses the embedded data from
// fpexchange_data.go and requires no external emulator dependency.
package fpemu

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
)

// Memory layout constants.
const (
	fpTrampolineAddr uint64 = 0x10000000
	fpStackBase      uint64 = 0x70000000
	fpStackSz        uint64 = 0x800000 // 8 MB
	fpHeapBase       uint64 = 0x80000000
	fpCodeBase       uint64 = 0x1a1210000
	fpCodeEnd        uint64 = 0x1a1316000
	fpDataBase       uint64 = 0x1b10a3000
	fpGOTBase        uint64 = 0x1aeab6000
	fpEntry          uint64 = 0x1a12bfb88
)

// fpCPU is a minimal ARM64 processor state.
type fpCPU struct {
	x          [31]uint64 // X0-X30 (X30=LR); X31 reads as 0
	sp         uint64
	pc         uint64
	n, z, c, v bool          // NZCV
	vreg       [32][2]uint64 // NEON 128-bit as [lo64, hi64]
}

func (c *fpCPU) reg(n uint32) uint64 {
	if n >= 31 {
		return 0
	}
	return c.x[n]
}
func (c *fpCPU) setReg(n uint32, v uint64) {
	if n < 31 {
		c.x[n] = v
	}
}
func (c *fpCPU) regSP(n uint32) uint64 {
	if n == 31 {
		return c.sp
	}
	return c.x[n]
}
func (c *fpCPU) setRegSP(n uint32, v uint64) {
	if n == 31 {
		c.sp = v
	} else {
		c.x[n] = v
	}
}

// fpMem provides paged memory for the standalone interpreter.
const fpPageCacheN = 16

type fpPageCacheEntry struct {
	pa   uint64
	page []byte
}

type fpMem struct {
	pages     map[uint64][]byte
	pcache    [fpPageCacheN]fpPageCacheEntry
	codeInsts []uint32
	codeBase  uint64
	codeEnd   uint64
}

func newFPMem() *fpMem {
	return &fpMem{pages: make(map[uint64][]byte)}
}

func (m *fpMem) pageCached(addr uint64) []byte {
	pa := addr &^ 0xFFF
	idx := (pa >> 12) & (fpPageCacheN - 1)
	ce := &m.pcache[idx]
	if ce.pa == pa && ce.page != nil {
		return ce.page
	}
	if p, ok := m.pages[pa]; ok {
		ce.pa = pa
		ce.page = p
		return p
	}
	p := make([]byte, 4096)
	m.pages[pa] = p
	ce.pa = pa
	ce.page = p
	return p
}

func (m *fpMem) fetchInst(pc uint64) uint32 {
	if pc >= m.codeBase && pc < m.codeEnd {
		return m.codeInsts[(pc-m.codeBase)>>2]
	}
	p := m.pages[pc&^0xFFF]
	if p == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(p[pc&0xFFF:])
}

func (m *fpMem) read8(a uint64) uint8     { return m.pageCached(a)[a&0xFFF] }
func (m *fpMem) write8(a uint64, v uint8) { m.pageCached(a)[a&0xFFF] = v }

func (m *fpMem) read16(a uint64) uint16 {
	if a&0xFFF <= 0xFFE {
		return binary.LittleEndian.Uint16(m.pageCached(a)[a&0xFFF:])
	}
	return uint16(m.read8(a)) | uint16(m.read8(a+1))<<8
}
func (m *fpMem) write16(a uint64, v uint16) {
	if a&0xFFF <= 0xFFE {
		binary.LittleEndian.PutUint16(m.pageCached(a)[a&0xFFF:], v)
		return
	}
	m.write8(a, uint8(v))
	m.write8(a+1, uint8(v>>8))
}

func (m *fpMem) read32(a uint64) uint32 {
	if a&0xFFF <= 0xFFC {
		return binary.LittleEndian.Uint32(m.pageCached(a)[a&0xFFF:])
	}
	return uint32(m.read8(a)) | uint32(m.read8(a+1))<<8 | uint32(m.read8(a+2))<<16 | uint32(m.read8(a+3))<<24
}
func (m *fpMem) write32(a uint64, v uint32) {
	if a&0xFFF <= 0xFFC {
		binary.LittleEndian.PutUint32(m.pageCached(a)[a&0xFFF:], v)
		return
	}
	m.write8(a, uint8(v))
	m.write8(a+1, uint8(v>>8))
	m.write8(a+2, uint8(v>>16))
	m.write8(a+3, uint8(v>>24))
}

func (m *fpMem) read64(a uint64) uint64 {
	if a&0xFFF <= 0xFF8 {
		return binary.LittleEndian.Uint64(m.pageCached(a)[a&0xFFF:])
	}
	return uint64(m.read32(a)) | uint64(m.read32(a+4))<<32
}
func (m *fpMem) write64(a uint64, v uint64) {
	if a&0xFFF <= 0xFF8 {
		binary.LittleEndian.PutUint64(m.pageCached(a)[a&0xFFF:], v)
		return
	}
	m.write32(a, uint32(v))
	m.write32(a+4, uint32(v>>32))
}

func (m *fpMem) readN(addr uint64, n int) []byte {
	b := make([]byte, n)
	off := 0
	for off < n {
		pa := (addr + uint64(off)) &^ 0xFFF
		pageOff := int((addr + uint64(off)) & 0xFFF)
		p := m.pageCached(pa)
		nc := copy(b[off:], p[pageOff:])
		off += nc
	}
	return b
}

func (m *fpMem) writeN(addr uint64, data []byte) {
	off := 0
	for off < len(data) {
		pa := (addr + uint64(off)) &^ 0xFFF
		pageOff := int((addr + uint64(off)) & 0xFFF)
		p := m.pageCached(pa)
		nc := copy(p[pageOff:], data[off:])
		off += nc
	}
}

func (m *fpMem) mapRange(addr, size uint64) {
	for p := addr &^ 0xFFF; p < addr+size; p += 0x1000 {
		m.pageCached(p)
	}
}

func (m *fpMem) setCodeRegion(base, end uint64) {
	n := (end - base) / 4
	m.codeInsts = make([]uint32, n)
	m.codeBase = base
	m.codeEnd = end
	for i := uint64(0); i < n; i++ {
		addr := base + i*4
		pa := addr &^ 0xFFF
		if p, ok := m.pages[pa]; ok {
			off := addr & 0xFFF
			m.codeInsts[i] = binary.LittleEndian.Uint32(p[off:])
		}
	}
}

// --- Stub handling ---

type fpAESCTRCtx struct {
	stream cipher.Stream
}

type fpState struct {
	cpu     fpCPU
	mem     *fpMem
	heapPtr uint64
	shaCtxs map[uint64]hash.Hash
	aesCtxs map[uint64]*fpAESCTRCtx
	stubs   map[uint64]string // stub address → name
}

func (s *fpState) heapAlloc(n uint64) uint64 {
	n = (n + 15) &^ 15
	addr := s.heapPtr
	s.heapPtr += n
	return addr
}

func (s *fpState) handleStub(name string) error {
	x0 := s.cpu.x[0]
	x1 := s.cpu.x[1]
	x2 := s.cpu.x[2]
	x3 := s.cpu.x[3]

	switch name {
	case "_malloc":
		sz := x0
		if sz == 0 {
			sz = 16
		}
		s.cpu.x[0] = s.heapAlloc(sz)
	case "_calloc":
		total := x0 * x1
		if total == 0 {
			total = 16
		}
		addr := s.heapAlloc(total)
		s.mem.writeN(addr, make([]byte, total))
		s.cpu.x[0] = addr
	case "_realloc":
		sz := x1
		if sz == 0 {
			sz = 16
		}
		s.cpu.x[0] = s.heapAlloc(sz)
	case "_free":
		s.cpu.x[0] = 0
	case "_memcpy", "_memmove", "___memcpy_chk":
		if x2 > 0 && x1 != 0 && x0 != 0 {
			s.mem.writeN(x0, s.mem.readN(x1, int(x2)))
		}
		s.cpu.x[0] = x0
	case "_memset", "___memset_chk":
		if x2 > 0 {
			buf := make([]byte, x2)
			v := byte(x1)
			for i := range buf {
				buf[i] = v
			}
			s.mem.writeN(x0, buf)
		}
		s.cpu.x[0] = x0
	case "_memcmp":
		if x2 == 0 {
			s.cpu.x[0] = 0
			break
		}
		a, b := s.mem.readN(x0, int(x2)), s.mem.readN(x1, int(x2))
		r := uint64(0)
		for i := 0; i < int(x2); i++ {
			if a[i] != b[i] {
				if a[i] < b[i] {
					r = ^uint64(0)
				} else {
					r = 1
				}
				break
			}
		}
		s.cpu.x[0] = r
	case "_bzero":
		if x1 > 0 {
			s.mem.writeN(x0, make([]byte, x1))
		}
	case "_strlen":
		n := uint64(0)
		for {
			if s.mem.read8(x0+n) == 0 {
				break
			}
			n++
			if n > 1<<20 {
				break
			}
		}
		s.cpu.x[0] = n

	case "_CC_SHA1_Init":
		s.shaCtxs[x0] = sha1.New()
		s.cpu.x[0] = 1
	case "_CC_SHA1_Update":
		h, ok := s.shaCtxs[x0]
		if !ok {
			h = sha1.New()
			s.shaCtxs[x0] = h
		}
		if x2 > 0 {
			h.Write(s.mem.readN(x1, int(x2)))
		}
		s.cpu.x[0] = 1
	case "_CC_SHA1_Final":
		if h, ok := s.shaCtxs[x1]; ok {
			s.mem.writeN(x0, h.Sum(nil)[:20])
			delete(s.shaCtxs, x1)
		} else {
			s.mem.writeN(x0, make([]byte, 20))
		}
		s.cpu.x[0] = 1
	case "_CC_SHA512_Init":
		s.shaCtxs[x0] = sha512.New()
		s.cpu.x[0] = 1
	case "_CC_SHA512_Update":
		h, ok := s.shaCtxs[x0]
		if !ok {
			h = sha512.New()
			s.shaCtxs[x0] = h
		}
		if x2 > 0 {
			h.Write(s.mem.readN(x1, int(x2)))
		}
		s.cpu.x[0] = 1
	case "_CC_SHA512_Final":
		if h, ok := s.shaCtxs[x1]; ok {
			s.mem.writeN(x0, h.Sum(nil)[:64])
			delete(s.shaCtxs, x1)
		} else {
			s.mem.writeN(x0, make([]byte, 64))
		}
		s.cpu.x[0] = 1

	case "_AES_CTR_Init":
		key := s.mem.readN(x1, int(x2))
		iv := s.mem.readN(x3, 16)
		block, err := aes.NewCipher(key)
		if err != nil {
			s.cpu.x[0] = ^uint64(0)
			break
		}
		s.aesCtxs[x0] = &fpAESCTRCtx{stream: cipher.NewCTR(block, iv)}
		s.cpu.x[0] = 0
	case "_AES_CTR_Update":
		if ctx, ok := s.aesCtxs[x0]; ok && x2 > 0 {
			in := s.mem.readN(x1, int(x2))
			out := make([]byte, x2)
			ctx.stream.XORKeyStream(out, in)
			s.mem.writeN(x3, out)
		}
		s.cpu.x[0] = 0
	case "_AES_CTR_Final":
		delete(s.aesCtxs, x0)
		s.cpu.x[0] = 0

	case "_abort":
		return fmt.Errorf("abort() called from LR=0x%x", s.cpu.x[30])
	case "_arc4random":
		b := make([]byte, 4)
		rand.Read(b)
		s.cpu.x[0] = uint64(binary.LittleEndian.Uint32(b))
	case "_FigGetUpTimeNanoseconds":
		s.cpu.x[0] = 1000000000
	case "_CFRetain":
		// return X0 unchanged
	case "_pthread_once", "_FigThreadRunOnce":
		if s.mem.read8(x0) == 0 {
			s.mem.writeN(x0, []byte{1, 0, 0, 0})
		}
		s.cpu.x[0] = 0
	case "_dispatch_once":
		if s.mem.read64(x0) == 0 {
			s.mem.write64(x0, ^uint64(0))
		}
		s.cpu.x[0] = 0

	default:
		// nop returning 0
		s.cpu.x[0] = 0
	}
	return nil
}

// --- Helpers ---

func fpSignExtend(val uint64, bits uint32) uint64 {
	if val&(1<<(bits-1)) != 0 {
		return val | (^uint64(0) << bits)
	}
	return val
}

func fpAddWithCarry64(x, y, carry uint64) (result uint64, n, z, c, v bool) {
	result = x + y + carry
	n = (result >> 63) != 0
	z = result == 0
	if carry == 0 {
		c = result < x
	} else {
		c = result <= x
	}
	v = (((x ^ result) & (y ^ result)) >> 63) != 0
	return
}

func fpAddWithCarry32(x, y, carry uint32) (result uint32, n, z, cc, v bool) {
	s := uint64(x) + uint64(y) + uint64(carry)
	result = uint32(s)
	n = (result >> 31) != 0
	z = result == 0
	cc = s > 0xFFFFFFFF
	v = (((x ^ result) & (y ^ result)) >> 31) != 0
	return
}

func fpDecodeBitMasks(nBit, imms, immr uint32, is64 bool) (uint64, uint64) {
	combined := (nBit << 6) | (^imms & 0x3F)
	length := 0
	for i := 6; i >= 1; i-- {
		if combined&(1<<uint(i)) != 0 {
			length = i
			break
		}
	}
	esize := uint32(1) << uint(length)
	levels := esize - 1
	S := imms & levels
	R := immr & levels
	diff := (S - R) & levels

	welem := uint64((uint64(1) << (S + 1)) - 1)
	if R != 0 {
		welem = (welem >> R) | (welem << (esize - R))
		welem &= (uint64(1) << esize) - 1
	}
	telem := uint64((uint64(1) << (diff + 1)) - 1)

	var wmask, tmask uint64
	for i := uint32(0); i < 64; i += esize {
		wmask |= welem << i
		tmask |= telem << i
	}
	if !is64 {
		wmask &= 0xFFFFFFFF
		tmask &= 0xFFFFFFFF
	}
	return wmask, tmask
}

func fpShiftVal(val uint64, shiftType, amount uint32, is64 bool) uint64 {
	if amount == 0 {
		return val
	}
	bits := uint32(64)
	if !is64 {
		bits = 32
		val &= 0xFFFFFFFF
	}
	amount &= bits - 1
	switch shiftType {
	case 0:
		val <<= amount
	case 1:
		val >>= amount
	case 2:
		if is64 {
			val = uint64(int64(val) >> amount)
		} else {
			val = uint64(uint32(int32(uint32(val)) >> amount))
		}
	case 3:
		val = (val >> amount) | (val << (bits - amount))
	}
	if !is64 {
		val &= 0xFFFFFFFF
	}
	return val
}

func (c *fpCPU) condHolds(cond uint32) bool {
	var r bool
	switch cond >> 1 {
	case 0:
		r = c.z
	case 1:
		r = c.c
	case 2:
		r = c.n
	case 3:
		r = c.v
	case 4:
		r = c.c && !c.z
	case 5:
		r = c.n == c.v
	case 6:
		r = c.n == c.v && !c.z
	case 7:
		r = true
	}
	if cond&1 != 0 && cond != 15 {
		r = !r
	}
	return r
}

func fpRev32(v uint32) uint32 { return (v>>24)&0xFF | (v>>8)&0xFF00 | (v<<8)&0xFF0000 | (v << 24) }
func fpRev64(v uint64) uint64 { return uint64(fpRev32(uint32(v)))<<32 | uint64(fpRev32(uint32(v>>32))) }

func fpRbit64(v uint64) uint64 {
	v = (v&0x5555555555555555)<<1 | (v&0xAAAAAAAAAAAAAAAA)>>1
	v = (v&0x3333333333333333)<<2 | (v&0xCCCCCCCCCCCCCCCC)>>2
	v = (v&0x0F0F0F0F0F0F0F0F)<<4 | (v&0xF0F0F0F0F0F0F0F0)>>4
	return fpRev64(v)
}
func fpRbit32(v uint32) uint32 {
	v = (v&0x55555555)<<1 | (v&0xAAAAAAAA)>>1
	v = (v&0x33333333)<<2 | (v&0xCCCCCCCC)>>2
	v = (v&0x0F0F0F0F)<<4 | (v&0xF0F0F0F0)>>4
	return fpRev32(v)
}
func fpRev16_64(v uint64) uint64 {
	return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8)
}
func fpRev16_32(v uint32) uint32 { return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8) }

func fpClz64(v uint64) int {
	if v == 0 {
		return 64
	}
	n := 0
	for v&(1<<63) == 0 {
		n++
		v <<= 1
	}
	return n
}
func fpClz32(v uint32) int {
	if v == 0 {
		return 32
	}
	n := 0
	for v&(1<<31) == 0 {
		n++
		v <<= 1
	}
	return n
}

func fpMulhi64(a, b uint64) uint64 {
	aHi, aLo := a>>32, a&0xFFFFFFFF
	bHi, bLo := b>>32, b&0xFFFFFFFF
	mid1 := aHi * bLo
	mid2 := aLo * bHi
	lo := aLo * bLo
	hi := aHi * bHi
	carry := (lo>>32 + (mid1 & 0xFFFFFFFF) + (mid2 & 0xFFFFFFFF)) >> 32
	return hi + (mid1 >> 32) + (mid2 >> 32) + carry
}
func fpSmulhi64(a, b uint64) uint64 {
	result := fpMulhi64(a, b)
	if int64(a) < 0 {
		result -= b
	}
	if int64(b) < 0 {
		result -= a
	}
	return result
}

func fpVfpExpandImm32(imm8 uint32) uint32 {
	a := (imm8 >> 7) & 1
	b := (imm8 >> 6) & 1
	cdefgh := imm8 & 0x3F
	result := a << 31
	if b != 0 {
		result |= 0x1F << 25
	} else {
		result |= 1 << 30
	}
	result |= cdefgh << 19
	return result
}
func fpVfpExpandImm64(imm8 uint32) uint64 {
	a := uint64((imm8 >> 7) & 1)
	b := uint64((imm8 >> 6) & 1)
	cdefgh := uint64(imm8 & 0x3F)
	result := a << 63
	if b != 0 {
		result |= 0xFF << 54
	} else {
		result |= 1 << 62
	}
	result |= cdefgh << 48
	return result
}

// fpDynStubClassify classifies an unknown stub by heuristic, matching the
// emulator's makeDynStub behavior.
func (s *fpState) fpDynStubClassify(pc uint64) string {
	const stubPB = 0x20000000
	const stubPS = 0x10000
	if pc >= stubPB && pc < stubPB+stubPS {
		return "_nop"
	}
	x0 := s.cpu.x[0]
	x1 := s.cpu.x[1]
	x2 := s.cpu.x[2]
	isText := func(v uint64) bool { return v >= 0x1a1210000 && v < 0x1a1316000 }
	isGlobalData := func(v uint64) bool { return v >= 0x1a0000000 && v < 0x1c0000000 }
	if isGlobalData(x0) {
		if isText(x1) || isText(x2) {
			return "_dispatch_once"
		}
	}
	if x0 > 0 && x0 < 0x100000 {
		return "_malloc"
	}
	return "_nop"
}

// --- Main execution loop ---

func fpRun(s *fpState, haltPC uint64) error {
	count := 0
	var lastPCs [16]uint64
	for s.cpu.pc != haltPC {
		pc := s.cpu.pc
		lastPCs[count&15] = pc
		// Check for stub
		if name, ok := s.stubs[pc]; ok {
			if err := s.handleStub(name); err != nil {
				return err
			}
			s.cpu.pc = s.cpu.x[30]
			count++
			continue
		}
		inst := s.mem.fetchInst(pc)
		if inst == 0 {
			name := s.fpDynStubClassify(pc)
			s.stubs[pc] = name
			if err := s.handleStub(name); err != nil {
				return err
			}
			s.cpu.pc = s.cpu.x[30]
			count++
			continue
		}
		if err := fpStep(s, inst); err != nil {
			return fmt.Errorf("at PC=0x%x (inst #%d): %w", pc, count, err)
		}
		count++
		if count > 100_000_000 {
			msg := fmt.Sprintf("exceeded 100M instructions at PC=0x%x\nlast PCs:", s.cpu.pc)
			for i := 0; i < 16; i++ {
				idx := (count - 15 + i) & 15
				msg += fmt.Sprintf(" 0x%x", lastPCs[idx])
			}
			msg += fmt.Sprintf("\nX0=0x%x X1=0x%x X30=0x%x SP=0x%x", s.cpu.x[0], s.cpu.x[1], s.cpu.x[30], s.cpu.sp)
			return fmt.Errorf("%s", msg)
		}
	}
	return nil
}

func fpStep(s *fpState, inst uint32) error {
	c := &s.cpu
	m := s.mem

	// BRK check — dynamic stub (same as emulator's OnFault + Stubs dispatch)
	if inst&0xFFE0001F == 0xD4200000 {
		name := s.fpDynStubClassify(c.pc)
		s.stubs[c.pc] = name
		if err := s.handleStub(name); err != nil {
			return err
		}
		c.pc = c.x[30]
		return nil
	}

	op0 := (inst >> 25) & 0xF
	switch {
	case op0>>1 == 4:
		return fpExecDPImm(c, m, inst)
	case op0>>1 == 5:
		return fpExecBranch(c, m, inst)
	case op0&5 == 4:
		return fpExecLoadStore(c, m, inst)
	case op0&7 == 5:
		return fpExecDPReg(c, m, inst)
	case op0&7 == 7:
		return fpExecSIMD(c, m, inst)
	}
	return fmt.Errorf("unhandled op0=%04b inst=0x%08x", op0, inst)
}

// ============================================================
// Data Processing — Immediate
// ============================================================

func fpExecDPImm(c *fpCPU, m *fpMem, inst uint32) error {
	op0 := (inst >> 23) & 0x7
	switch op0 {
	case 0, 1:
		return fpExecPCRel(c, inst)
	case 2:
		return fpExecAddSubImm(c, inst)
	case 4:
		return fpExecLogImm(c, inst)
	case 5:
		return fpExecMoveWide(c, inst)
	case 6:
		return fpExecBitfield(c, inst)
	case 7:
		return fpExecExtract(c, inst)
	}
	return fmt.Errorf("unhandled DP-Imm op0=%d inst=0x%08x", op0, inst)
}

func fpExecPCRel(c *fpCPU, inst uint32) error {
	rd := inst & 0x1F
	immhi := (inst >> 5) & 0x7FFFF
	immlo := (inst >> 29) & 0x3
	imm := fpSignExtend(uint64(immhi<<2|immlo), 21)
	if inst>>31 != 0 {
		c.setReg(rd, (c.pc&^0xFFF)+uint64(int64(imm)<<12))
	} else {
		c.setReg(rd, c.pc+imm)
	}
	c.pc += 4
	return nil
}

func fpExecAddSubImm(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	setf := (inst >> 29) & 1
	shift := (inst >> 22) & 3
	imm12 := uint64((inst >> 10) & 0xFFF)
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	if shift == 1 {
		imm12 <<= 12
	}
	a := c.regSP(rn)
	if !is64 {
		a &= 0xFFFFFFFF
	}

	if setf != 0 {
		var y, carry uint64
		if op == 0 {
			y = imm12
			carry = 0
		} else {
			if is64 {
				y = ^imm12
			} else {
				y = uint64(^uint32(imm12))
			}
			carry = 1
		}
		var result uint64
		if is64 {
			result, c.n, c.z, c.c, c.v = fpAddWithCarry64(a, y, carry)
		} else {
			r32, n, z, cc, v := fpAddWithCarry32(uint32(a), uint32(y), uint32(carry))
			result = uint64(r32)
			c.n, c.z, c.c, c.v = n, z, cc, v
		}
		c.setReg(rd, result)
	} else {
		var result uint64
		if op == 0 {
			result = a + imm12
		} else {
			result = a - imm12
		}
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.setRegSP(rd, result)
	}
	c.pc += 4
	return nil
}

func fpExecLogImm(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	nBit := (inst >> 22) & 1
	immr := (inst >> 16) & 0x3F
	imms := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	wmask, _ := fpDecodeBitMasks(nBit, imms, immr, is64)
	a := c.reg(rn)
	if !is64 {
		a &= 0xFFFFFFFF
	}

	var result uint64
	switch opc {
	case 0:
		result = a & wmask
	case 1:
		result = a | wmask
	case 2:
		result = a ^ wmask
	case 3:
		result = a & wmask
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}
	if opc == 3 {
		if is64 {
			c.n = (result >> 63) != 0
		} else {
			c.n = (result >> 31) != 0
		}
		c.z = result == 0
		c.c = false
		c.v = false
		c.setReg(rd, result)
	} else {
		c.setRegSP(rd, result)
	}
	c.pc += 4
	return nil
}

func fpExecMoveWide(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	hw := (inst >> 21) & 0x3
	imm16 := uint64((inst >> 5) & 0xFFFF)
	rd := inst & 0x1F
	shift := hw * 16
	switch opc {
	case 0:
		r := ^(imm16 << shift)
		if sf == 0 {
			r &= 0xFFFFFFFF
		}
		c.setReg(rd, r)
	case 2:
		c.setReg(rd, imm16<<shift)
	case 3:
		mask := uint64(0xFFFF) << shift
		c.setReg(rd, (c.reg(rd)&^mask)|(imm16<<shift))
	default:
		return fmt.Errorf("reserved move-wide opc=%d", opc)
	}
	c.pc += 4
	return nil
}

func fpExecBitfield(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	nBit := (inst >> 22) & 1
	immr := (inst >> 16) & 0x3F
	imms := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	wmask, tmask := fpDecodeBitMasks(nBit, imms, immr, is64)
	datasize := uint32(64)
	if !is64 {
		datasize = 32
	}
	src := c.reg(rn)
	if !is64 {
		src &= 0xFFFFFFFF
	}
	R := immr
	var rotated uint64
	if R == 0 {
		rotated = src
	} else {
		rotated = (src >> R) | (src << (datasize - R))
		if !is64 {
			rotated &= 0xFFFFFFFF
		}
	}

	switch opc {
	case 0: // SBFM
		bot := rotated & wmask
		var top uint64
		if (src>>imms)&1 != 0 {
			top = ^uint64(0)
			if !is64 {
				top &= 0xFFFFFFFF
			}
		}
		result := (top &^ tmask) | (bot & tmask)
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.setReg(rd, result)
	case 1: // BFM
		dst := c.reg(rd)
		if !is64 {
			dst &= 0xFFFFFFFF
		}
		bot := (dst &^ wmask) | (rotated & wmask)
		result := (dst &^ tmask) | (bot & tmask)
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.setReg(rd, result)
	case 2: // UBFM
		bot := rotated & wmask
		result := bot & tmask
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.setReg(rd, result)
	default:
		return fmt.Errorf("reserved bitfield opc=%d", opc)
	}
	c.pc += 4
	return nil
}

func fpExecExtract(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	rm := (inst >> 16) & 0x1F
	imms := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	hi := c.reg(rn)
	lo := c.reg(rm)
	lsb := imms

	var result uint64
	if is64 {
		if lsb == 0 {
			result = lo
		} else {
			result = (hi << (64 - lsb)) | (lo >> lsb)
		}
	} else {
		hi &= 0xFFFFFFFF
		lo &= 0xFFFFFFFF
		if lsb == 0 {
			result = lo
		} else {
			result = ((hi << (32 - lsb)) | (lo >> lsb)) & 0xFFFFFFFF
		}
	}
	c.setReg(rd, result)
	c.pc += 4
	return nil
}

// ============================================================
// Data Processing — Register
// ============================================================

func fpExecDPReg(c *fpCPU, m *fpMem, inst uint32) error {
	top5 := (inst >> 24) & 0x1F
	switch top5 {
	case 0x0A:
		return fpExecLogShiftReg(c, inst)
	case 0x0B:
		if (inst>>21)&1 == 0 {
			return fpExecAddSubShiftReg(c, inst)
		}
		return fpExecAddSubExtReg(c, inst)
	case 0x1A:
		return fpExecDP11010(c, inst)
	case 0x1B:
		return fpExecDP3Src(c, inst)
	}
	return fmt.Errorf("unhandled DP-Reg top5=0x%02x inst=0x%08x", top5, inst)
}

func fpExecLogShiftReg(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	shiftType := (inst >> 22) & 0x3
	nBit := (inst >> 21) & 1
	rm := (inst >> 16) & 0x1F
	imm6 := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.reg(rn)
	b := fpShiftVal(c.reg(rm), shiftType, imm6, is64)
	if nBit != 0 {
		b = ^b
		if !is64 {
			b &= 0xFFFFFFFF
		}
	}
	if !is64 {
		a &= 0xFFFFFFFF
	}

	var result uint64
	switch opc {
	case 0:
		result = a & b
	case 1:
		result = a | b
	case 2:
		result = a ^ b
	case 3:
		result = a & b
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}
	if opc == 3 {
		if is64 {
			c.n = (result >> 63) != 0
		} else {
			c.n = (result >> 31) != 0
		}
		c.z = result == 0
		c.c = false
		c.v = false
	}
	c.setReg(rd, result)
	c.pc += 4
	return nil
}

func fpExecAddSubShiftReg(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	setf := (inst >> 29) & 1
	shiftType := (inst >> 22) & 0x3
	rm := (inst >> 16) & 0x1F
	imm6 := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.reg(rn)
	b := fpShiftVal(c.reg(rm), shiftType, imm6, is64)
	if !is64 {
		a &= 0xFFFFFFFF
		b &= 0xFFFFFFFF
	}

	var y, carry uint64
	if op == 0 {
		y = b
		carry = 0
	} else {
		if is64 {
			y = ^b
		} else {
			y = uint64(^uint32(b))
		}
		carry = 1
	}
	if setf != 0 {
		var result uint64
		if is64 {
			result, c.n, c.z, c.c, c.v = fpAddWithCarry64(a, y, carry)
		} else {
			r32, n, z, cc, v := fpAddWithCarry32(uint32(a), uint32(y), uint32(carry))
			result = uint64(r32)
			c.n, c.z, c.c, c.v = n, z, cc, v
		}
		c.setReg(rd, result)
	} else {
		var result uint64
		if op == 0 {
			result = a + b
		} else {
			result = a - b
		}
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.setReg(rd, result)
	}
	c.pc += 4
	return nil
}

func fpExecAddSubExtReg(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	setf := (inst >> 29) & 1
	rm := (inst >> 16) & 0x1F
	option := (inst >> 13) & 0x7
	imm3 := (inst >> 10) & 0x7
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.regSP(rn)
	rmVal := c.reg(rm)
	var extended uint64
	switch option {
	case 0:
		extended = rmVal & 0xFF
	case 1:
		extended = rmVal & 0xFFFF
	case 2:
		extended = rmVal & 0xFFFFFFFF
	case 3:
		extended = rmVal
	case 4:
		extended = fpSignExtend(rmVal&0xFF, 8)
	case 5:
		extended = fpSignExtend(rmVal&0xFFFF, 16)
	case 6:
		extended = fpSignExtend(rmVal&0xFFFFFFFF, 32)
	case 7:
		extended = rmVal
	}
	extended <<= imm3
	if !is64 {
		a &= 0xFFFFFFFF
		extended &= 0xFFFFFFFF
	}

	if setf != 0 {
		var y, carry uint64
		if op == 0 {
			y = extended
			carry = 0
		} else {
			if is64 {
				y = ^extended
			} else {
				y = uint64(^uint32(extended))
			}
			carry = 1
		}
		var result uint64
		if is64 {
			result, c.n, c.z, c.c, c.v = fpAddWithCarry64(a, y, carry)
		} else {
			r32, n, z, cc, v := fpAddWithCarry32(uint32(a), uint32(y), uint32(carry))
			result = uint64(r32)
			c.n, c.z, c.c, c.v = n, z, cc, v
		}
		c.setReg(rd, result)
	} else {
		var result uint64
		if op == 0 {
			result = a + extended
		} else {
			result = a - extended
		}
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.setRegSP(rd, result)
	}
	c.pc += 4
	return nil
}

func fpExecDP11010(c *fpCPU, inst uint32) error {
	bits2321 := (inst >> 21) & 7
	switch bits2321 {
	case 2, 3:
		return fpExecCondCompare(c, inst)
	case 4:
		return fpExecCondSelect(c, inst)
	case 6:
		if (inst>>30)&1 == 1 {
			return fpExecDP1Src(c, inst)
		}
		return fpExecDP2Src(c, inst)
	}
	return fmt.Errorf("unhandled 11010 sub=%d inst=0x%08x", bits2321, inst)
}

func fpExecCondCompare(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	rm := (inst >> 16) & 0x1F
	cond := (inst >> 12) & 0xF
	rn := (inst >> 5) & 0x1F
	nzcv := inst & 0xF
	is64 := sf != 0
	isImm := (inst>>11)&1 != 0

	if c.condHolds(cond) {
		a := c.reg(rn)
		var b uint64
		if isImm {
			b = uint64(rm)
		} else {
			b = c.reg(rm)
		}
		if !is64 {
			a &= 0xFFFFFFFF
			b &= 0xFFFFFFFF
		}
		var y, carry uint64
		if op == 1 {
			if is64 {
				y = ^b
			} else {
				y = uint64(^uint32(b))
			}
			carry = 1
		} else {
			y = b
			carry = 0
		}
		if is64 {
			_, c.n, c.z, c.c, c.v = fpAddWithCarry64(a, y, carry)
		} else {
			_, c.n, c.z, c.c, c.v = fpAddWithCarry32(uint32(a), uint32(y), uint32(carry))
		}
	} else {
		c.n = (nzcv>>3)&1 != 0
		c.z = (nzcv>>2)&1 != 0
		c.c = (nzcv>>1)&1 != 0
		c.v = nzcv&1 != 0
	}
	c.pc += 4
	return nil
}

func fpExecCondSelect(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	rm := (inst >> 16) & 0x1F
	cond := (inst >> 12) & 0xF
	op2 := (inst >> 10) & 0x3
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	a := c.reg(rn)
	b := c.reg(rm)

	var result uint64
	if c.condHolds(cond) {
		result = a
	} else {
		switch (op << 1) | (op2 & 1) {
		case 0:
			result = b
		case 1:
			result = b + 1
		case 2:
			result = ^b
		case 3:
			result = -b
		}
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}
	c.setReg(rd, result)
	c.pc += 4
	return nil
}

func fpExecDP2Src(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	rm := (inst >> 16) & 0x1F
	opcode := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	a := c.reg(rn)
	b := c.reg(rm)
	if !is64 {
		a &= 0xFFFFFFFF
		b &= 0xFFFFFFFF
	}

	var result uint64
	switch opcode {
	case 2: // UDIV
		if b == 0 {
			result = 0
		} else {
			if is64 {
				result = a / b
			} else {
				result = uint64(uint32(a) / uint32(b))
			}
		}
	case 3: // SDIV
		if b == 0 {
			result = 0
		} else {
			if is64 {
				result = uint64(int64(a) / int64(b))
			} else {
				result = uint64(uint32(int32(uint32(a)) / int32(uint32(b))))
			}
		}
	case 8: // LSLV
		var mask uint32
		if is64 {
			mask = 63
		} else {
			mask = 31
		}
		result = a << (b & uint64(mask))
	case 9: // LSRV
		var mask uint32
		if is64 {
			mask = 63
		} else {
			mask = 31
		}
		result = a >> (b & uint64(mask))
	case 10: // ASRV
		var mask uint32
		if is64 {
			mask = 63
		} else {
			mask = 31
		}
		shift := b & uint64(mask)
		if is64 {
			result = uint64(int64(a) >> shift)
		} else {
			result = uint64(uint32(int32(uint32(a)) >> shift))
		}
	case 11: // RORV
		bits := uint64(64)
		if !is64 {
			bits = 32
		}
		shift := b % bits
		if shift == 0 {
			result = a
		} else {
			result = (a >> shift) | (a << (bits - shift))
		}
	default:
		return fmt.Errorf("unhandled DP-2-source opcode=%d inst=0x%08x", opcode, inst)
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}
	c.setReg(rd, result)
	c.pc += 4
	return nil
}

func fpExecDP1Src(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	opcode := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	val := c.reg(rn)

	var result uint64
	switch opcode {
	case 0:
		if is64 {
			result = fpRbit64(val)
		} else {
			result = uint64(fpRbit32(uint32(val)))
		}
	case 1:
		if is64 {
			result = fpRev16_64(val)
		} else {
			result = uint64(fpRev16_32(uint32(val)))
		}
	case 2:
		if is64 {
			lo := fpRev32(uint32(val))
			hi := fpRev32(uint32(val >> 32))
			result = uint64(lo) | uint64(hi)<<32
		} else {
			result = uint64(fpRev32(uint32(val)))
		}
	case 3:
		result = fpRev64(val)
	case 4:
		if is64 {
			result = uint64(fpClz64(val))
		} else {
			result = uint64(fpClz32(uint32(val)))
		}
	default:
		return fmt.Errorf("unhandled DP-1-source opcode=%d inst=0x%08x", opcode, inst)
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}
	c.setReg(rd, result)
	c.pc += 4
	return nil
}

func fpExecDP3Src(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	op31 := (inst >> 21) & 0x7
	rm := (inst >> 16) & 0x1F
	o0 := (inst >> 15) & 1
	ra := (inst >> 10) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	a := c.reg(rn)
	b := c.reg(rm)
	addend := c.reg(ra)

	var result uint64
	switch op31 {
	case 0:
		if !is64 {
			a &= 0xFFFFFFFF
			b &= 0xFFFFFFFF
			addend &= 0xFFFFFFFF
		}
		prod := a * b
		if o0 == 0 {
			result = addend + prod
		} else {
			result = addend - prod
		}
		if !is64 {
			result &= 0xFFFFFFFF
		}
	case 1: // SMADDL/SMSUBL
		prod := uint64(int64(int32(uint32(a))) * int64(int32(uint32(b))))
		if o0 == 0 {
			result = addend + prod
		} else {
			result = addend - prod
		}
	case 2:
		result = fpSmulhi64(a, b)
	case 5: // UMADDL/UMSUBL
		prod := uint64(uint32(a)) * uint64(uint32(b))
		if o0 == 0 {
			result = addend + prod
		} else {
			result = addend - prod
		}
	case 6:
		result = fpMulhi64(a, b)
	default:
		return fmt.Errorf("unhandled DP-3 op31=%d inst=0x%08x", op31, inst)
	}
	c.setReg(rd, result)
	c.pc += 4
	return nil
}

// ============================================================
// Loads and Stores
// ============================================================

func fpExecLoadStore(c *fpCPU, m *fpMem, inst uint32) error {
	op1 := (inst >> 27) & 7
	v := (inst >> 26) & 1
	switch {
	case op1 == 5 && v == 0:
		return fpExecLdStPair(c, m, inst)
	case op1 == 5 && v == 1:
		return fpExecLdStPairSIMD(c, m, inst)
	case op1 == 7 && v == 0:
		bit24 := (inst >> 24) & 1
		if bit24 == 1 {
			return fpExecLdStUnsigned(c, m, inst)
		}
		bit21 := (inst >> 21) & 1
		if bit21 == 1 {
			return fpExecLdStRegOff(c, m, inst)
		}
		return fpExecLdStImm9(c, m, inst)
	case op1 == 7 && v == 1:
		bit24 := (inst >> 24) & 1
		if bit24 == 1 {
			return fpExecLdStSIMDUnsigned(c, m, inst)
		}
		return fpExecLdStSIMDImm9(c, m, inst)
	case op1 == 3 && v == 0:
		return fpExecLdrLiteral(c, m, inst)
	case op1 == 3 && v == 1:
		return fpExecLdrSIMDLiteral(c, m, inst)
	}
	return fmt.Errorf("unhandled load/store op1=%d v=%d inst=0x%08x", op1, v, inst)
}

func fpDoLoadStore(c *fpCPU, m *fpMem, size, opc uint32, addr uint64, rt uint32) error {
	switch opc {
	case 0: // STR
		switch size {
		case 0:
			m.write8(addr, uint8(c.reg(rt)))
		case 1:
			m.write16(addr, uint16(c.reg(rt)))
		case 2:
			m.write32(addr, uint32(c.reg(rt)))
		case 3:
			m.write64(addr, c.reg(rt))
		}
	case 1: // LDR zero-extend
		var val uint64
		switch size {
		case 0:
			val = uint64(m.read8(addr))
		case 1:
			val = uint64(m.read16(addr))
		case 2:
			val = uint64(m.read32(addr))
		case 3:
			val = m.read64(addr)
		}
		c.setReg(rt, val)
	case 2: // LDRS 64-bit sign-extend
		switch size {
		case 0:
			c.setReg(rt, fpSignExtend(uint64(m.read8(addr)), 8))
		case 1:
			c.setReg(rt, fpSignExtend(uint64(m.read16(addr)), 16))
		case 2:
			c.setReg(rt, fpSignExtend(uint64(m.read32(addr)), 32))
		default: // PRFM nop
		}
	case 3: // LDRS 32-bit
		switch size {
		case 0:
			c.setReg(rt, uint64(uint32(int8(m.read8(addr)))))
		case 1:
			c.setReg(rt, uint64(uint32(int16(m.read16(addr)))))
		default: // PRFM nop
		}
	}
	c.pc += 4
	return nil
}

func fpExecLdStUnsigned(c *fpCPU, m *fpMem, inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm12 := uint64((inst >> 10) & 0xFFF)
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F
	offset := imm12 * (uint64(1) << size)
	return fpDoLoadStore(c, m, size, opc, c.regSP(rn)+offset, rt)
}

func fpExecLdStImm9(c *fpCPU, m *fpMem, inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm9 := fpSignExtend(uint64((inst>>12)&0x1FF), 9)
	idxType := (inst >> 10) & 3
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F
	base := c.regSP(rn)
	var addr uint64
	switch idxType {
	case 0:
		addr = base + imm9
	case 1:
		addr = base
		c.setRegSP(rn, base+imm9)
	case 3:
		addr = base + imm9
		c.setRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved ldst idxType=%d", idxType)
	}
	return fpDoLoadStore(c, m, size, opc, addr, rt)
}

func fpExecLdStRegOff(c *fpCPU, m *fpMem, inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	rm := (inst >> 16) & 0x1F
	option := (inst >> 13) & 7
	s := (inst >> 12) & 1
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F
	base := c.regSP(rn)
	offset := c.reg(rm)
	switch option {
	case 2:
		offset &= 0xFFFFFFFF
	case 3: // LSL
	case 6:
		offset = fpSignExtend(offset&0xFFFFFFFF, 32)
	case 7: // SXTX
	}
	if s != 0 {
		offset <<= size
	}
	return fpDoLoadStore(c, m, size, opc, base+offset, rt)
}

func fpExecLdStPair(c *fpCPU, m *fpMem, inst uint32) error {
	opc := (inst >> 30) & 3
	pairType := (inst >> 23) & 7
	load := (inst >> 22) & 1
	imm7 := fpSignExtend(uint64((inst>>15)&0x7F), 7)
	rt2 := (inst >> 10) & 0x1F
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	var scale uint64
	switch opc {
	case 0:
		scale = 4
	case 1:
		scale = 4
	case 2:
		scale = 8
	default:
		return fmt.Errorf("reserved LDP/STP opc=%d", opc)
	}
	offset := imm7 * scale
	base := c.regSP(rn)
	var addr uint64
	switch pairType {
	case 1:
		addr = base
		c.setRegSP(rn, base+offset)
	case 2:
		addr = base + offset
	case 3:
		addr = base + offset
		c.setRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved LDP/STP type=%d", pairType)
	}
	if load != 0 {
		switch opc {
		case 0:
			c.setReg(rt, uint64(m.read32(addr)))
			c.setReg(rt2, uint64(m.read32(addr+4)))
		case 1:
			c.setReg(rt, fpSignExtend(uint64(m.read32(addr)), 32))
			c.setReg(rt2, fpSignExtend(uint64(m.read32(addr+4)), 32))
		case 2:
			c.setReg(rt, m.read64(addr))
			c.setReg(rt2, m.read64(addr+8))
		}
	} else {
		switch opc {
		case 0:
			m.write32(addr, uint32(c.reg(rt)))
			m.write32(addr+4, uint32(c.reg(rt2)))
		case 2:
			m.write64(addr, c.reg(rt))
			m.write64(addr+8, c.reg(rt2))
		}
	}
	c.pc += 4
	return nil
}

func fpExecLdrLiteral(c *fpCPU, m *fpMem, inst uint32) error {
	opc := (inst >> 30) & 3
	imm19 := fpSignExtend(uint64((inst>>5)&0x7FFFF), 19)
	rt := inst & 0x1F
	addr := c.pc + imm19*4
	switch opc {
	case 0:
		c.setReg(rt, uint64(m.read32(addr)))
	case 1:
		c.setReg(rt, m.read64(addr))
	case 2:
		c.setReg(rt, fpSignExtend(uint64(m.read32(addr)), 32))
	}
	c.pc += 4
	return nil
}

// ============================================================
// Branches
// ============================================================

func fpExecBranch(c *fpCPU, m *fpMem, inst uint32) error {
	top6 := (inst >> 26) & 0x3F
	switch top6 {
	case 0x05:
		return fpExecBUncond(c, inst, false)
	case 0x25:
		return fpExecBUncond(c, inst, true)
	}
	if (inst>>25)&0x3F == 0x1A {
		return fpExecCBx(c, inst)
	}
	if (inst>>25)&0x7F == 0x2A {
		return fpExecBCond(c, inst)
	}
	if (inst>>25)&0x7F == 0x6B {
		return fpExecBranchReg(c, inst)
	}
	// TBZ/TBNZ: bits[30:25] = 011011
	if (inst>>25)&0x3F == 0x1B {
		return fpExecTBx(c, inst)
	}
	return fmt.Errorf("unhandled branch inst=0x%08x", inst)
}

func fpExecBUncond(c *fpCPU, inst uint32, link bool) error {
	imm26 := fpSignExtend(uint64(inst&0x3FFFFFF), 26)
	if link {
		c.x[30] = c.pc + 4
	}
	c.pc = c.pc + imm26*4
	return nil
}

func fpExecBCond(c *fpCPU, inst uint32) error {
	imm19 := fpSignExtend(uint64((inst>>5)&0x7FFFF), 19)
	cond := inst & 0xF
	if c.condHolds(cond) {
		c.pc = c.pc + imm19*4
	} else {
		c.pc += 4
	}
	return nil
}

func fpExecCBx(c *fpCPU, inst uint32) error {
	sf := inst >> 31
	op := (inst >> 24) & 1
	imm19 := fpSignExtend(uint64((inst>>5)&0x7FFFF), 19)
	rt := inst & 0x1F
	val := c.reg(rt)
	if sf == 0 {
		val &= 0xFFFFFFFF
	}
	take := false
	if op == 0 {
		take = val == 0
	} else {
		take = val != 0
	}
	if take {
		c.pc = c.pc + imm19*4
	} else {
		c.pc += 4
	}
	return nil
}

func fpExecBranchReg(c *fpCPU, inst uint32) error {
	opc := (inst >> 21) & 0xF
	rn := (inst >> 5) & 0x1F
	target := c.reg(rn)
	if rn == 31 {
		target = 0
	}
	switch opc {
	case 0:
		c.pc = target
	case 1:
		c.x[30] = c.pc + 4
		c.pc = target
	case 2:
		c.pc = c.x[30]
		if rn != 30 {
			c.pc = c.reg(rn)
		}
	default:
		return fmt.Errorf("unhandled branch-reg opc=%d inst=0x%08x", opc, inst)
	}
	return nil
}

func fpExecTBx(c *fpCPU, inst uint32) error {
	op := (inst >> 24) & 1 // 0=TBZ, 1=TBNZ
	b5 := (inst >> 31) & 1
	b40 := (inst >> 19) & 0x1F
	bit := b5<<5 | b40
	imm14 := fpSignExtend(uint64((inst>>5)&0x3FFF), 14)
	rt := inst & 0x1F
	val := c.reg(rt)
	bitSet := (val>>bit)&1 != 0
	take := false
	if op == 0 {
		take = !bitSet
	} else {
		take = bitSet
	}
	if take {
		c.pc = c.pc + imm14*4
	} else {
		c.pc += 4
	}
	return nil
}

// ============================================================
// SIMD / Floating-Point
// ============================================================

func fpExecSIMD(c *fpCPU, m *fpMem, inst uint32) error {
	// FMOV Dd, Xn
	if inst&0xFFFFFC00 == 0x9E670000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.vreg[rd] = [2]uint64{c.reg(rn), 0}
		c.pc += 4
		return nil
	}
	// FMOV Xd, Dn
	if inst&0xFFFFFC00 == 0x9E660000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.setReg(rd, c.vreg[rn][0])
		c.pc += 4
		return nil
	}
	// FMOV Vd.D[1], Xn
	if inst&0xFFFFFC00 == 0x9EAF0000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.vreg[rd][1] = c.reg(rn)
		c.pc += 4
		return nil
	}
	// FMOV Xd, Vn.D[1]
	if inst&0xFFFFFC00 == 0x9EAE0000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.setReg(rd, c.vreg[rn][1])
		c.pc += 4
		return nil
	}
	// FMOV Sd, Wn
	if inst&0xFFFFFC00 == 0x1E270000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.vreg[rd] = [2]uint64{uint64(uint32(c.reg(rn))), 0}
		c.pc += 4
		return nil
	}
	// FMOV Wd, Sn
	if inst&0xFFFFFC00 == 0x1E260000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.setReg(rd, uint64(uint32(c.vreg[rn][0])))
		c.pc += 4
		return nil
	}

	// DUP
	if inst&0xBFE0FC00 == 0x0E000C00 {
		return fpExecDUP(c, inst)
	}
	// UMOV
	if inst&0xBFE0FC00 == 0x0E003C00 {
		return fpExecUMOV(c, inst)
	}
	// INS
	if inst&0xBFE0FC00 == 0x0E001C00 {
		return fpExecINS(c, inst)
	}
	// SHL
	if inst&0xBF80FC00 == 0x0F005400 {
		return fpExecSHL(c, inst)
	}
	// MOVI
	if inst&0x9FF80400 == 0x0F000400 {
		return fpExecMOVI(c, inst)
	}
	// XTN
	if inst&0xBF3FFC00 == 0x0E212800 {
		return fpExecXTN(c, inst)
	}
	// EXT
	if inst&0xBFE08400 == 0x2E000000 {
		return fpExecEXT(c, inst)
	}
	// REV64 vec
	if inst&0xBF3FFC00 == 0x0E200800 {
		return fpExecREV64Vec(c, inst)
	}
	// AdvSIMD 3-same
	if inst&0x9F200400 == 0x0E200400 {
		return fpExecAdvSIMD3Same(c, inst)
	}
	// FMOV scalar imm
	if inst&0x9F01FC00 == 0x1E201000 {
		rd := inst & 0x1F
		imm8 := (inst >> 13) & 0xFF
		c.vreg[rd] = [2]uint64{fpVfpExpandImm64(imm8), 0}
		c.pc += 4
		return nil
	}

	return fmt.Errorf("unhandled SIMD inst=0x%08x", inst)
}

func fpExecDUP(c *fpCPU, inst uint32) error {
	q := (inst >> 30) & 1
	imm5 := (inst >> 16) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	val := c.reg(rn)
	var result [2]uint64
	switch {
	case imm5&1 == 1:
		b := uint8(val)
		for i := 0; i < 8; i++ {
			result[0] |= uint64(b) << (i * 8)
		}
		if q != 0 {
			result[1] = result[0]
		}
	case imm5&3 == 2:
		h := uint16(val)
		for i := 0; i < 4; i++ {
			result[0] |= uint64(h) << (i * 16)
		}
		if q != 0 {
			result[1] = result[0]
		}
	case imm5&7 == 4:
		s := uint32(val)
		result[0] = uint64(s) | uint64(s)<<32
		if q != 0 {
			result[1] = result[0]
		}
	case imm5&15 == 8:
		result[0] = val
		if q != 0 {
			result[1] = val
		}
	}
	c.vreg[rd] = result
	c.pc += 4
	return nil
}

func fpExecUMOV(c *fpCPU, inst uint32) error {
	imm5 := (inst >> 16) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	lo := c.vreg[rn][0]
	hi := c.vreg[rn][1]
	var val uint64
	switch {
	case imm5&1 == 1:
		idx := imm5 >> 1
		if idx < 8 {
			val = (lo >> (idx * 8)) & 0xFF
		} else {
			val = (hi >> ((idx - 8) * 8)) & 0xFF
		}
	case imm5&3 == 2:
		idx := imm5 >> 2
		if idx < 4 {
			val = (lo >> (idx * 16)) & 0xFFFF
		} else {
			val = (hi >> ((idx - 4) * 16)) & 0xFFFF
		}
	case imm5&7 == 4:
		idx := imm5 >> 3
		if idx == 0 {
			val = lo & 0xFFFFFFFF
		} else if idx == 1 {
			val = lo >> 32
		} else if idx == 2 {
			val = hi & 0xFFFFFFFF
		} else {
			val = hi >> 32
		}
	case imm5&15 == 8:
		idx := imm5 >> 4
		if idx == 0 {
			val = lo
		} else {
			val = hi
		}
	}
	c.setReg(rd, val)
	c.pc += 4
	return nil
}

func fpExecINS(c *fpCPU, inst uint32) error {
	imm5 := (inst >> 16) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	val := c.reg(rn)
	lo := c.vreg[rd][0]
	hi := c.vreg[rd][1]
	switch {
	case imm5&1 == 1:
		idx := imm5 >> 1
		shift := idx * 8
		if idx < 8 {
			lo = (lo &^ (0xFF << shift)) | ((val & 0xFF) << shift)
		} else {
			shift = (idx - 8) * 8
			hi = (hi &^ (0xFF << shift)) | ((val & 0xFF) << shift)
		}
	case imm5&3 == 2:
		idx := imm5 >> 2
		shift := idx * 16
		if idx < 4 {
			lo = (lo &^ (0xFFFF << shift)) | ((val & 0xFFFF) << shift)
		} else {
			shift = (idx - 4) * 16
			hi = (hi &^ (0xFFFF << shift)) | ((val & 0xFFFF) << shift)
		}
	case imm5&7 == 4:
		idx := imm5 >> 3
		shift := idx * 32
		if idx < 2 {
			lo = (lo &^ (0xFFFFFFFF << shift)) | ((val & 0xFFFFFFFF) << shift)
		} else {
			shift = (idx - 2) * 32
			hi = (hi &^ (0xFFFFFFFF << shift)) | ((val & 0xFFFFFFFF) << shift)
		}
	case imm5&15 == 8:
		idx := imm5 >> 4
		if idx == 0 {
			lo = val
		} else {
			hi = val
		}
	}
	c.vreg[rd] = [2]uint64{lo, hi}
	c.pc += 4
	return nil
}

func fpExecSHL(c *fpCPU, inst uint32) error {
	q := (inst >> 30) & 1
	immh := (inst >> 19) & 0xF
	immb := (inst >> 16) & 0x7
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	immhb := (immh << 3) | immb
	srcLo := c.vreg[rn][0]
	srcHi := c.vreg[rn][1]
	var dstLo, dstHi uint64

	switch {
	case immh&0x8 != 0:
		shift := immhb - 64
		dstLo = srcLo << shift
		if q != 0 {
			dstHi = srcHi << shift
		}
	case immh&0xC == 0x4:
		shift := immhb - 32
		lo0 := (srcLo & 0xFFFFFFFF) << shift
		lo1 := ((srcLo >> 32) & 0xFFFFFFFF) << shift
		dstLo = (lo0 & 0xFFFFFFFF) | ((lo1 & 0xFFFFFFFF) << 32)
		if q != 0 {
			hi0 := (srcHi & 0xFFFFFFFF) << shift
			hi1 := ((srcHi >> 32) & 0xFFFFFFFF) << shift
			dstHi = (hi0 & 0xFFFFFFFF) | ((hi1 & 0xFFFFFFFF) << 32)
		}
	case immh&0xE == 0x2:
		shift := immhb - 16
		for i := uint32(0); i < 4; i++ {
			elem := (srcLo >> (i * 16)) & 0xFFFF
			dstLo |= ((elem << shift) & 0xFFFF) << (i * 16)
		}
		if q != 0 {
			for i := uint32(0); i < 4; i++ {
				elem := (srcHi >> (i * 16)) & 0xFFFF
				dstHi |= ((elem << shift) & 0xFFFF) << (i * 16)
			}
		}
	case immh&0xF == 0x1:
		shift := immhb - 8
		for i := uint32(0); i < 8; i++ {
			elem := (srcLo >> (i * 8)) & 0xFF
			dstLo |= ((elem << shift) & 0xFF) << (i * 8)
		}
		if q != 0 {
			for i := uint32(0); i < 8; i++ {
				elem := (srcHi >> (i * 8)) & 0xFF
				dstHi |= ((elem << shift) & 0xFF) << (i * 8)
			}
		}
	}
	c.vreg[rd] = [2]uint64{dstLo, dstHi}
	c.pc += 4
	return nil
}

func fpExecMOVI(c *fpCPU, inst uint32) error {
	q := (inst >> 30) & 1
	op := (inst >> 29) & 1
	cmode := (inst >> 12) & 0xF
	rd := inst & 0x1F

	a := (inst >> 18) & 1
	b := (inst >> 17) & 1
	cc := (inst >> 16) & 1
	d := (inst >> 9) & 1
	e := (inst >> 8) & 1
	f := (inst >> 7) & 1
	g := (inst >> 6) & 1
	h := (inst >> 5) & 1
	imm8 := (a << 7) | (b << 6) | (cc << 5) | (d << 4) | (e << 3) | (f << 2) | (g << 1) | h

	var imm64 uint64
	switch {
	case cmode <= 7 && cmode&1 == 0: // 32-bit shifted
		shift := (cmode / 2) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode <= 7 && cmode&1 == 1:
		shift := (cmode / 2) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode == 0x8 || cmode == 0x9: // 16-bit
		shift := (cmode & 1) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFF
		}
		for i := 0; i < 4; i++ {
			imm64 |= (elem & 0xFFFF) << (i * 16)
		}
	case cmode == 0xA || cmode == 0xB:
		shift := (cmode & 1) * 8
		var elem uint64
		if shift == 0 {
			elem = uint64(imm8)<<8 | 0xFF
		} else {
			elem = uint64(imm8)<<16 | 0xFFFF
		}
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode == 0xC || cmode == 0xD:
		shift := (cmode & 1) * 8
		var elem uint64
		if shift == 0 {
			elem = uint64(imm8)<<8 | 0xFF
		} else {
			elem = uint64(imm8)<<16 | 0xFFFF
		}
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode == 0xE:
		if op == 0 {
			for i := 0; i < 8; i++ {
				imm64 |= uint64(imm8) << (i * 8)
			}
		} else {
			for i := 0; i < 8; i++ {
				if (imm8>>uint(i))&1 != 0 {
					imm64 |= 0xFF << (i * 8)
				}
			}
		}
	case cmode == 0xF:
		if op == 0 {
			imm64 = uint64(fpVfpExpandImm32(imm8))
			imm64 = imm64 | imm64<<32
		} else {
			imm64 = fpVfpExpandImm64(imm8)
		}
	}
	c.vreg[rd][0] = imm64
	if q != 0 {
		c.vreg[rd][1] = imm64
	} else {
		c.vreg[rd][1] = 0
	}
	c.pc += 4
	return nil
}

func fpExecXTN(c *fpCPU, inst uint32) error {
	q := (inst >> 30) & 1
	size := (inst >> 22) & 3
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	srcLo := c.vreg[rn][0]
	srcHi := c.vreg[rn][1]
	var narrow uint64
	switch size {
	case 0:
		for i := 0; i < 4; i++ {
			narrow |= ((srcLo >> (i * 16)) & 0xFF) << (i * 8)
		}
		for i := 0; i < 4; i++ {
			narrow |= ((srcHi >> (i * 16)) & 0xFF) << ((i + 4) * 8)
		}
	case 1:
		for i := 0; i < 2; i++ {
			narrow |= ((srcLo >> (i * 32)) & 0xFFFF) << (i * 16)
		}
		for i := 0; i < 2; i++ {
			narrow |= ((srcHi >> (i * 32)) & 0xFFFF) << ((i + 2) * 16)
		}
	case 2:
		narrow = (srcLo & 0xFFFFFFFF) | ((srcHi & 0xFFFFFFFF) << 32)
	}
	if q == 0 {
		c.vreg[rd] = [2]uint64{narrow, 0}
	} else {
		c.vreg[rd][1] = narrow
	}
	c.pc += 4
	return nil
}

func fpExecEXT(c *fpCPU, inst uint32) error {
	rm := (inst >> 16) & 0x1F
	imm4 := (inst >> 11) & 0xF
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	var src [32]byte
	lo := c.vreg[rn][0]
	hi := c.vreg[rn][1]
	for i := 0; i < 8; i++ {
		src[i] = byte(lo >> (i * 8))
		src[i+8] = byte(hi >> (i * 8))
	}
	lo2 := c.vreg[rm][0]
	hi2 := c.vreg[rm][1]
	for i := 0; i < 8; i++ {
		src[i+16] = byte(lo2 >> (i * 8))
		src[i+24] = byte(hi2 >> (i * 8))
	}
	var dstLo, dstHi uint64
	for i := 0; i < 8; i++ {
		dstLo |= uint64(src[int(imm4)+i]) << (i * 8)
		dstHi |= uint64(src[int(imm4)+i+8]) << (i * 8)
	}
	c.vreg[rd] = [2]uint64{dstLo, dstHi}
	c.pc += 4
	return nil
}

func fpExecREV64Vec(c *fpCPU, inst uint32) error {
	q := (inst >> 30) & 1
	size := (inst >> 22) & 3
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	rev := func(v uint64) uint64 {
		switch size {
		case 0:
			return (v&0xFF)<<56 | (v&0xFF00)<<40 | (v&0xFF0000)<<24 | (v&0xFF000000)<<8 | (v>>8)&0xFF000000 | (v>>24)&0xFF0000 | (v>>40)&0xFF00 | (v>>56)&0xFF
		case 1:
			return (v&0xFFFF)<<48 | ((v>>16)&0xFFFF)<<32 | ((v>>32)&0xFFFF)<<16 | (v >> 48)
		case 2:
			return (v << 32) | (v >> 32)
		}
		return v
	}
	dstLo := rev(c.vreg[rn][0])
	var dstHi uint64
	if q != 0 {
		dstHi = rev(c.vreg[rn][1])
	}
	c.vreg[rd] = [2]uint64{dstLo, dstHi}
	c.pc += 4
	return nil
}

func fpExecAdvSIMD3Same(c *fpCPU, inst uint32) error {
	q := (inst >> 30) & 1
	u := (inst >> 29) & 1
	size := (inst >> 22) & 3
	rm := (inst >> 16) & 0x1F
	opcode := (inst >> 11) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	aLo, aHi := c.vreg[rn][0], c.vreg[rn][1]
	bLo, bHi := c.vreg[rm][0], c.vreg[rm][1]
	var loR, hiR uint64

	switch opcode {
	case 3: // logical
		switch (u << 2) | size {
		case 0:
			loR = aLo & bLo
			hiR = aHi & bHi
		case 1:
			loR = aLo &^ bLo
			hiR = aHi &^ bHi
		case 2:
			loR = aLo | bLo
			hiR = aHi | bHi
		case 3:
			loR = aLo | ^bLo
			hiR = aHi | ^bHi
		case 4:
			loR = aLo ^ bLo
			hiR = aHi ^ bHi
		case 5:
			dLo, dHi := c.vreg[rd][0], c.vreg[rd][1]
			loR = (aLo & dLo) | (bLo &^ dLo)
			hiR = (aHi & dHi) | (bHi &^ dHi)
		case 6:
			dLo, dHi := c.vreg[rd][0], c.vreg[rd][1]
			loR = (aLo & bLo) | (dLo &^ bLo)
			hiR = (aHi & bHi) | (dHi &^ bHi)
		case 7:
			dLo, dHi := c.vreg[rd][0], c.vreg[rd][1]
			loR = (aLo &^ bLo) | (dLo & bLo)
			hiR = (aHi &^ bHi) | (dHi & bHi)
		}
	case 16: // ADD/SUB
		loR, hiR = fpSimd3SameArith(aLo, aHi, bLo, bHi, size, u == 1)
	default:
		return fmt.Errorf("unhandled AdvSIMD3Same opcode=%d u=%d inst=0x%08x", opcode, u, inst)
	}
	c.vreg[rd][0] = loR
	if q != 0 {
		c.vreg[rd][1] = hiR
	} else {
		c.vreg[rd][1] = 0
	}
	c.pc += 4
	return nil
}

func fpSimd3SameArith(aLo, aHi, bLo, bHi uint64, size uint32, isSub bool) (uint64, uint64) {
	op := func(a, b, mask uint64) uint64 {
		if isSub {
			return (a - b) & mask
		}
		return (a + b) & mask
	}
	var loR, hiR uint64
	switch size {
	case 0:
		for i := uint32(0); i < 8; i++ {
			s := i * 8
			loR |= op((aLo>>s)&0xFF, (bLo>>s)&0xFF, 0xFF) << s
			hiR |= op((aHi>>s)&0xFF, (bHi>>s)&0xFF, 0xFF) << s
		}
	case 1:
		for i := uint32(0); i < 4; i++ {
			s := i * 16
			loR |= op((aLo>>s)&0xFFFF, (bLo>>s)&0xFFFF, 0xFFFF) << s
			hiR |= op((aHi>>s)&0xFFFF, (bHi>>s)&0xFFFF, 0xFFFF) << s
		}
	case 2:
		for i := uint32(0); i < 2; i++ {
			s := i * 32
			loR |= op((aLo>>s)&0xFFFFFFFF, (bLo>>s)&0xFFFFFFFF, 0xFFFFFFFF) << s
			hiR |= op((aHi>>s)&0xFFFFFFFF, (bHi>>s)&0xFFFFFFFF, 0xFFFFFFFF) << s
		}
	case 3:
		loR = op(aLo, bLo, ^uint64(0))
		hiR = op(aHi, bHi, ^uint64(0))
	}
	return loR, hiR
}

// SIMD load/store helpers
func fpSimdAccessSize(size, opc uint32) int {
	switch {
	case size == 0 && opc >= 2:
		return 16
	case size == 0:
		return 1
	case size == 1:
		return 2
	case size == 2:
		return 4
	case size == 3:
		return 8
	}
	return 8
}

func fpDoSIMDStore(c *fpCPU, m *fpMem, addr uint64, rt uint32, n int) {
	switch n {
	case 1:
		m.write8(addr, uint8(c.vreg[rt][0]))
	case 2:
		m.write16(addr, uint16(c.vreg[rt][0]))
	case 4:
		m.write32(addr, uint32(c.vreg[rt][0]))
	case 8:
		m.write64(addr, c.vreg[rt][0])
	case 16:
		m.write64(addr, c.vreg[rt][0])
		m.write64(addr+8, c.vreg[rt][1])
	}
}

func fpDoSIMDLoad(c *fpCPU, m *fpMem, addr uint64, rt uint32, n int) {
	c.vreg[rt] = [2]uint64{0, 0}
	switch n {
	case 1:
		c.vreg[rt][0] = uint64(m.read8(addr))
	case 2:
		c.vreg[rt][0] = uint64(m.read16(addr))
	case 4:
		c.vreg[rt][0] = uint64(m.read32(addr))
	case 8:
		c.vreg[rt][0] = m.read64(addr)
	case 16:
		c.vreg[rt][0] = m.read64(addr)
		c.vreg[rt][1] = m.read64(addr + 8)
	}
}

func fpExecLdStSIMDUnsigned(c *fpCPU, m *fpMem, inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm12 := uint64((inst >> 10) & 0xFFF)
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F
	n := fpSimdAccessSize(size, opc)
	offset := imm12 * uint64(n)
	addr := c.regSP(rn) + offset
	if opc&1 == 0 {
		fpDoSIMDStore(c, m, addr, rt, n)
	} else {
		fpDoSIMDLoad(c, m, addr, rt, n)
	}
	c.pc += 4
	return nil
}

func fpExecLdStSIMDImm9(c *fpCPU, m *fpMem, inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm9 := fpSignExtend(uint64((inst>>12)&0x1FF), 9)
	idxType := (inst >> 10) & 3
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F
	n := fpSimdAccessSize(size, opc)
	base := c.regSP(rn)
	var addr uint64
	switch idxType {
	case 0:
		addr = base + imm9
	case 1:
		addr = base
		c.setRegSP(rn, base+imm9)
	case 3:
		addr = base + imm9
		c.setRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved SIMD ldst idxType=%d", idxType)
	}
	if opc&1 == 0 {
		fpDoSIMDStore(c, m, addr, rt, n)
	} else {
		fpDoSIMDLoad(c, m, addr, rt, n)
	}
	c.pc += 4
	return nil
}

func fpExecLdStPairSIMD(c *fpCPU, m *fpMem, inst uint32) error {
	opc := (inst >> 30) & 3
	pairType := (inst >> 23) & 7
	load := (inst >> 22) & 1
	imm7 := fpSignExtend(uint64((inst>>15)&0x7F), 7)
	rt2 := (inst >> 10) & 0x1F
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	var scale uint64
	switch opc {
	case 0:
		scale = 4
	case 1:
		scale = 8
	case 2:
		scale = 16
	default:
		return fmt.Errorf("reserved SIMD LDP/STP opc=%d", opc)
	}
	offset := imm7 * scale
	base := c.regSP(rn)
	var addr uint64
	switch pairType {
	case 1:
		addr = base
		c.setRegSP(rn, base+offset)
	case 2:
		addr = base + offset
	case 3:
		addr = base + offset
		c.setRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved SIMD LDP/STP type=%d", pairType)
	}
	elemSize := int(scale)
	if load != 0 {
		fpDoSIMDLoad(c, m, addr, rt, elemSize)
		fpDoSIMDLoad(c, m, addr+uint64(elemSize), rt2, elemSize)
	} else {
		fpDoSIMDStore(c, m, addr, rt, elemSize)
		fpDoSIMDStore(c, m, addr+uint64(elemSize), rt2, elemSize)
	}
	c.pc += 4
	return nil
}

func fpExecLdrSIMDLiteral(c *fpCPU, m *fpMem, inst uint32) error {
	opc := (inst >> 30) & 3
	imm19 := fpSignExtend(uint64((inst>>5)&0x7FFFF), 19)
	rt := inst & 0x1F
	addr := c.pc + imm19*4
	var n int
	switch opc {
	case 0:
		n = 4
	case 1:
		n = 8
	case 2:
		n = 16
	}
	fpDoSIMDLoad(c, m, addr, rt, n)
	c.pc += 4
	return nil
}

// ============================================================
// FPSAPExchangeStandalone — main entry point
// ============================================================

// FPSAPExchangeStandalone executes the FairPlay SAP exchange using
// a self-contained ARM64 interpreter. It takes a 128-byte payload
// (m2[14:142]) and returns the 20-byte WB-AES hash.
func FPSAPExchangeStandalone(payload [128]byte) [20]byte {
	mem := newFPMem()

	data := snapshotData
	pos := 0
	nPages := binary.LittleEndian.Uint32(data[pos:])
	pos += 4
	heapPtr := binary.LittleEndian.Uint64(data[pos:])
	pos += 8
	ctx := binary.LittleEndian.Uint64(data[pos:])
	pos += 8 // skip ctx

	stubs := make(map[uint64]string)

	// Read named stubs
	for {
		addr := binary.LittleEndian.Uint64(data[pos:])
		pos += 8
		if addr == 0 {
			break
		}
		nameLen := int(binary.LittleEndian.Uint16(data[pos:]))
		pos += 2
		name := string(data[pos : pos+nameLen])
		pos += nameLen
		stubs[addr] = name
	}

	// Read sparse pages
	for i := uint32(0); i < nPages; i++ {
		addr := binary.LittleEndian.Uint64(data[pos:])
		pos += 8
		nSpans := binary.LittleEndian.Uint16(data[pos:])
		pos += 2

		mem.mapRange(addr, 4096)

		if nSpans == 0xFFFF {
			mem.writeN(addr, data[pos:pos+4096])
			pos += 4096
		} else {
			for s := uint16(0); s < nSpans; s++ {
				off := binary.LittleEndian.Uint16(data[pos:])
				pos += 2
				ln := int(binary.LittleEndian.Uint16(data[pos:]))
				pos += 2
				mem.writeN(addr+uint64(off), data[pos:pos+ln])
				pos += ln
			}
		}
	}

	// Apply dedup fixups
	for _, f := range dedupFixups {
		mem.writeN(f.dst, mem.readN(f.src, f.n))
	}

	// Set up trampoline
	mem.mapRange(fpTrampolineAddr, 0x1000)
	mem.write32(fpTrampolineAddr, 0xD63F0100)   // BLR X8
	mem.write32(fpTrampolineAddr+4, 0xD4200000) // BRK #0

	// Misc region
	mem.mapRange(0x30000000, 0x1000)
	mem.writeN(0x30000000, []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE})
	mem.write32(0x30000800, 0xD4200000) // BRK at nestedRetAddr

	// Build code instruction cache
	mem.setCodeRegion(fpCodeBase, fpCodeEnd)

	s := &fpState{
		mem:     mem,
		heapPtr: heapPtr,
		shaCtxs: make(map[uint64]hash.Hash),
		aesCtxs: make(map[uint64]*fpAESCTRCtx),
		stubs:   stubs,
	}

	// Set up function call: FPSAPExchange(version=3, hwInfo, ctx, inBuf, inLen, &outBuf, &outLen, &rc)
	hwAddr := s.heapAlloc(24)
	mem.writeN(hwAddr, make([]byte, 24))

	m2Header, _ := hex.DecodeString("46504c5903010200000000820203")
	m2 := make([]byte, 142)
	copy(m2[:14], m2Header)
	copy(m2[14:], payload[:])
	inAddr := s.heapAlloc(uint64(len(m2)))
	mem.writeN(inAddr, m2)

	outPtrAddr := s.heapAlloc(8)
	outLenAddr := s.heapAlloc(4)
	rcAddr := s.heapAlloc(4)
	mem.write64(outPtrAddr, 0)
	mem.write32(outLenAddr, 0)
	mem.write32(rcAddr, 0)

	sp := fpStackBase + fpStackSz - 0x100
	s.cpu.sp = sp
	s.cpu.x[0] = 3
	s.cpu.x[1] = hwAddr
	s.cpu.x[2] = ctx
	s.cpu.x[3] = inAddr
	s.cpu.x[4] = uint64(len(m2))
	s.cpu.x[5] = outPtrAddr
	s.cpu.x[6] = outLenAddr
	s.cpu.x[7] = rcAddr
	s.cpu.x[8] = fpEntry
	s.cpu.pc = fpTrampolineAddr

	haltPC := fpTrampolineAddr + 4

	if err := fpRun(s, haltPC); err != nil {
		panic(fmt.Sprintf("FPSAPExchangeStandalone: %v", err))
	}

	outPtr := mem.read64(outPtrAddr)
	outLen := mem.read32(outLenAddr)
	var result [20]byte
	if outLen >= 164 && outPtr != 0 {
		out := mem.readN(outPtr, int(outLen))
		copy(result[:], out[144:164])
	}
	return result
}

// m3Prefix is the constant 144-byte header of every FPSAPExchange m3 response.
// It is the same regardless of the input payload.
var m3Prefix, _ = hex.DecodeString(
	"46504c590301030000000098038f1a9c991ea22c511e45ba97f1af8dfb0f86f5" +
		"50c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c7" +
		"12202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b" +
		"7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b691" +
		"01b849fd93a02860d1a0dff5cd4414aa")

// FPSAPExchangeM3 computes the FairPlay SAP m3 response for a given m2.
// It returns the full 164-byte m3 (FPLY-framed prefix + 20-byte WB-AES hash).
func FPSAPExchangeM3(m2 []byte) ([]byte, error) {
	if len(m2) < 142 {
		return nil, fmt.Errorf("m2 too short: %d bytes (need >= 142)", len(m2))
	}
	var payload [128]byte
	copy(payload[:], m2[14:142])
	hash := FPSAPExchangeStandalone(payload)
	m3 := make([]byte, 164)
	copy(m3[:144], m3Prefix)
	copy(m3[144:], hash[:])
	return m3, nil
}
