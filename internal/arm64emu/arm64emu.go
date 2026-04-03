// Package arm64emu provides a minimal pure-Go ARM64 interpreter.
// It supports the ~75 instruction types needed to execute the FairPlay SAP
// exchange function from Apple's AirPlaySender binary, replacing the Unicorn
// CGo dependency.
package arm64emu

import (
	"encoding/binary"
	"fmt"
)

// CPU represents an ARM64 processor state.
type CPU struct {
	X  [31]uint64 // X0-X30 (X30=LR); X31=XZR reads as 0
	SP uint64
	PC uint64
	// NZCV condition flags.
	N, Z, C, V bool
	// NEON/SIMD registers: 128-bit as [lo64, hi64].
	Vreg [32][2]uint64

	Mem   *Memory
	Stubs map[uint64]func(*CPU) error // BRK stub handlers keyed by PC

	// OnFault is called when execution hits an unhandled instruction (e.g. zero
	// page from an unmapped shared-cache address). The handler may patch memory
	// and register a stub, then return nil to retry execution at the same PC.
	OnFault func(cpu *CPU, pc uint64, inst uint32) error

	// Trace, if non-nil, is called before each instruction with (PC, instruction).
	Trace func(pc uint64, inst uint32)

	instCount uint64
}

func NewCPU(mem *Memory) *CPU {
	return &CPU{Mem: mem, Stubs: make(map[uint64]func(*CPU) error)}
}

// Reg reads Xn; n>=31 returns 0 (XZR).
func (c *CPU) Reg(n uint32) uint64 {
	if n >= 31 {
		return 0
	}
	return c.X[n]
}

// SetReg writes Xn; n>=31 discards the write (XZR).
func (c *CPU) SetReg(n uint32, v uint64) {
	if n < 31 {
		c.X[n] = v
	}
}

// RegSP reads Xn|SP; n==31 returns SP.
func (c *CPU) RegSP(n uint32) uint64 {
	if n == 31 {
		return c.SP
	}
	return c.X[n]
}

// SetRegSP writes Xn|SP; n==31 writes SP.
func (c *CPU) SetRegSP(n uint32, v uint64) {
	if n == 31 {
		c.SP = v
	} else {
		c.X[n] = v
	}
}

// Run executes instructions from PC until it reaches haltPC.
func (c *CPU) Run(haltPC uint64) error {
	for c.PC != haltPC {
		inst := c.Mem.Read32(c.PC)
		if c.Trace != nil {
			c.Trace(c.PC, inst)
		}
		c.instCount++
		if err := c.step(inst); err != nil {
			return err
		}
	}
	return nil
}

func (c *CPU) InstCount() uint64 { return c.instCount }

func (c *CPU) step(inst uint32) error {
	// BRK #imm: 1101_0100_001x_xxxx_xxxx_xxxx_xxx0_0000
	if inst&0xFFE0001F == 0xD4200000 {
		if h, ok := c.Stubs[c.PC]; ok {
			if err := h(c); err != nil {
				return err
			}
			c.PC = c.X[30] // return to LR
			return nil
		}
		// No stub registered — try OnFault to dynamically register one.
		if c.OnFault != nil {
			if err := c.OnFault(c, c.PC, inst); err == nil {
				if h, ok := c.Stubs[c.PC]; ok {
					if err := h(c); err != nil {
						return err
					}
					c.PC = c.X[30]
					return nil
				}
			}
		}
		return fmt.Errorf("BRK at 0x%x with no stub", c.PC)
	}

	// Zero instruction (unmapped shared-cache page): invoke fault handler.
	if inst == 0 && c.OnFault != nil {
		if err := c.OnFault(c, c.PC, inst); err == nil {
			// Handler patched memory/stubs — re-read and retry.
			inst = c.Mem.Read32(c.PC)
			return c.step(inst)
		}
		return fmt.Errorf("fault at PC=0x%x: zero instruction", c.PC)
	}

	op0 := (inst >> 25) & 0xF // bits[28:25]
	switch {
	case op0>>1 == 4: // 100x: Data Processing—Immediate
		return c.execDPImm(inst)
	case op0>>1 == 5: // 101x: Branches, Exception, System
		return c.execBranch(inst)
	case op0&5 == 4: // x1x0: Loads and Stores
		return c.execLoadStore(inst)
	case op0&7 == 5: // x101: Data Processing—Register
		return c.execDPReg(inst)
	case op0&7 == 7: // x111: SIMD/FP
		return c.execSIMD(inst)
	}
	return fmt.Errorf("unhandled op0=%04b inst=0x%08x at PC=0x%x", op0, inst, c.PC)
}

// ---- Helpers ----

// condHolds evaluates an ARM64 condition code against current flags.
func (c *CPU) condHolds(cond uint32) bool {
	var r bool
	switch cond >> 1 {
	case 0:
		r = c.Z // EQ/NE
	case 1:
		r = c.C // CS/CC
	case 2:
		r = c.N // MI/PL
	case 3:
		r = c.V // VS/VC
	case 4:
		r = c.C && !c.Z // HI/LS
	case 5:
		r = c.N == c.V // GE/LT
	case 6:
		r = c.N == c.V && !c.Z // GT/LE
	case 7:
		r = true // AL
	}
	if cond&1 != 0 && cond != 15 {
		r = !r
	}
	return r
}

func addWithCarry64(x, y, carry uint64) (result uint64, n, z, c, v bool) {
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

func addWithCarry32(x, y, carry uint32) (result uint32, n, z, cc, v bool) {
	s := uint64(x) + uint64(y) + uint64(carry)
	result = uint32(s)
	n = (result >> 31) != 0
	z = result == 0
	cc = s > 0xFFFFFFFF
	v = (((x ^ result) & (y ^ result)) >> 31) != 0
	return
}

func signExtend(val uint64, bits uint32) uint64 {
	if val&(1<<(bits-1)) != 0 {
		return val | (^uint64(0) << bits)
	}
	return val
}

// decodeBitMasks decodes the ARM64 logical/bitfield immediate encoding,
// returning (wmask, tmask).
func decodeBitMasks(nBit, imms, immr uint32, is64 bool) (uint64, uint64) {
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

// shiftVal applies shift to val: 0=LSL, 1=LSR, 2=ASR, 3=ROR.
func shiftVal(val uint64, shiftType, amount uint32, is64 bool) uint64 {
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
	case 0: // LSL
		val <<= amount
	case 1: // LSR
		val >>= amount
	case 2: // ASR
		if is64 {
			val = uint64(int64(val) >> amount)
		} else {
			val = uint64(uint32(int32(uint32(val)) >> amount))
		}
	case 3: // ROR
		val = (val >> amount) | (val << (bits - amount))
	}
	if !is64 {
		val &= 0xFFFFFFFF
	}
	return val
}

// ---- Memory ----

// Memory provides a paged address space.
type Memory struct {
	pages     map[uint64][]byte
	ReadPages map[uint64]bool // tracks which page addresses have been read
	OnRead    func(addr uint64, n int)
	OnWrite   func(addr uint64, n int)
}

func NewMemory() *Memory {
	return &Memory{pages: make(map[uint64][]byte), ReadPages: make(map[uint64]bool)}
}

func (m *Memory) page(addr uint64) []byte {
	pa := addr &^ 0xFFF
	if p, ok := m.pages[pa]; ok {
		return p
	}
	p := make([]byte, 4096)
	m.pages[pa] = p
	return p
}

// Pages returns a map of all allocated page addresses to their data.
func (m *Memory) Pages() map[uint64][]byte {
	return m.pages
}

// Snapshot returns a copy of all allocated pages.
func (m *Memory) Snapshot() map[uint64][]byte {
	snap := make(map[uint64][]byte, len(m.pages))
	for addr, p := range m.pages {
		cp := make([]byte, 4096)
		copy(cp, p)
		snap[addr] = cp
	}
	return snap
}

// Restore replaces the memory contents with a previously captured snapshot.
func (m *Memory) Restore(snap map[uint64][]byte) {
	m.pages = make(map[uint64][]byte, len(snap))
	for addr, p := range snap {
		cp := make([]byte, 4096)
		copy(cp, p)
		m.pages[addr] = cp
	}
	m.ReadPages = make(map[uint64]bool)
}

func (m *Memory) Read8(addr uint64) uint8 {
	pa := addr &^ 0xFFF
	m.ReadPages[pa] = true
	if m.OnRead != nil {
		m.OnRead(addr, 1)
	}
	return m.page(addr)[addr&0xFFF]
}

func (m *Memory) Write8(addr uint64, v uint8) {
	m.page(addr)[addr&0xFFF] = v
	if m.OnWrite != nil {
		m.OnWrite(addr, 1)
	}
}

func (m *Memory) Read16(a uint64) uint16 {
	m.ReadPages[a&^0xFFF] = true
	if m.OnRead != nil {
		m.OnRead(a, 2)
	}
	if a&0xFFF <= 0xFFE {
		return binary.LittleEndian.Uint16(m.page(a)[a&0xFFF:])
	}
	return uint16(m.Read8(a)) | uint16(m.Read8(a+1))<<8
}

func (m *Memory) Write16(a uint64, v uint16) {
	if a&0xFFF <= 0xFFE {
		binary.LittleEndian.PutUint16(m.page(a)[a&0xFFF:], v)
		if m.OnWrite != nil {
			m.OnWrite(a, 2)
		}
		return
	}
	m.Write8(a, uint8(v))
	m.Write8(a+1, uint8(v>>8))
}

func (m *Memory) Read32(a uint64) uint32 {
	m.ReadPages[a&^0xFFF] = true
	if m.OnRead != nil {
		m.OnRead(a, 4)
	}
	if a&0xFFF <= 0xFFC {
		return binary.LittleEndian.Uint32(m.page(a)[a&0xFFF:])
	}
	return uint32(m.Read8(a)) | uint32(m.Read8(a+1))<<8 |
		uint32(m.Read8(a+2))<<16 | uint32(m.Read8(a+3))<<24
}

func (m *Memory) Write32(a uint64, v uint32) {
	if a&0xFFF <= 0xFFC {
		binary.LittleEndian.PutUint32(m.page(a)[a&0xFFF:], v)
		if m.OnWrite != nil {
			m.OnWrite(a, 4)
		}
		return
	}
	m.Write8(a, uint8(v))
	m.Write8(a+1, uint8(v>>8))
	m.Write8(a+2, uint8(v>>16))
	m.Write8(a+3, uint8(v>>24))
}

func (m *Memory) Read64(a uint64) uint64 {
	m.ReadPages[a&^0xFFF] = true
	if m.OnRead != nil {
		m.OnRead(a, 8)
	}
	if a&0xFFF <= 0xFF8 {
		return binary.LittleEndian.Uint64(m.page(a)[a&0xFFF:])
	}
	return uint64(m.Read32(a)) | uint64(m.Read32(a+4))<<32
}

func (m *Memory) Write64(a uint64, v uint64) {
	if a&0xFFF <= 0xFF8 {
		binary.LittleEndian.PutUint64(m.page(a)[a&0xFFF:], v)
		if m.OnWrite != nil {
			m.OnWrite(a, 8)
		}
		return
	}
	m.Write32(a, uint32(v))
	m.Write32(a+4, uint32(v>>32))
}

// Read reads n bytes starting at addr.
func (m *Memory) Read(addr uint64, n int) []byte {
	if m.OnRead != nil {
		m.OnRead(addr, n)
	}
	b := make([]byte, n)
	off := 0
	for off < n {
		pa := (addr + uint64(off)) &^ 0xFFF
		m.ReadPages[pa] = true
		pageOff := int((addr + uint64(off)) & 0xFFF)
		p := m.page(pa)
		nc := copy(b[off:], p[pageOff:])
		off += nc
	}
	return b
}

// Write writes data starting at addr.
func (m *Memory) Write(addr uint64, data []byte) {
	if m.OnWrite != nil {
		m.OnWrite(addr, len(data))
	}
	off := 0
	for off < len(data) {
		pa := (addr + uint64(off)) &^ 0xFFF
		pageOff := int((addr + uint64(off)) & 0xFFF)
		p := m.page(pa)
		nc := copy(p[pageOff:], data[off:])
		off += nc
	}
}

// Map ensures pages covering [addr, addr+size) are allocated.
func (m *Memory) Map(addr, size uint64) {
	for p := addr &^ 0xFFF; p < addr+size; p += 0x1000 {
		m.page(p)
	}
}
