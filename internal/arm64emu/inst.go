package arm64emu

import "fmt"

// ============================================================
// Data Processing — Immediate
// ============================================================

func (c *CPU) execDPImm(inst uint32) error {
	op0 := (inst >> 23) & 0x7 // bits[25:23]
	switch op0 {
	case 0, 1: // PC-rel addressing (ADR/ADRP)
		return c.execPCRel(inst)
	case 2: // Add/subtract immediate
		return c.execAddSubImm(inst)
	case 4: // Logical immediate
		return c.execLogImm(inst)
	case 5: // Move wide immediate
		return c.execMoveWide(inst)
	case 6: // Bitfield
		return c.execBitfield(inst)
	case 7: // Extract
		return c.execExtract(inst)
	}
	return fmt.Errorf("unhandled DP-Imm op0=%d inst=0x%08x PC=0x%x", op0, inst, c.PC)
}

// ADR/ADRP
func (c *CPU) execPCRel(inst uint32) error {
	rd := inst & 0x1F
	immhi := (inst >> 5) & 0x7FFFF // bits[23:5]
	immlo := (inst >> 29) & 0x3    // bits[30:29]
	imm := signExtend(uint64(immhi<<2|immlo), 21)
	if inst>>31 != 0 { // ADRP
		base := c.PC &^ 0xFFF
		c.SetReg(rd, base+uint64(int64(imm)<<12))
	} else { // ADR
		c.SetReg(rd, c.PC+imm)
	}
	c.PC += 4
	return nil
}

// ADD/SUB/ADDS/SUBS immediate
func (c *CPU) execAddSubImm(inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1    // 0=ADD, 1=SUB
	setf := (inst >> 29) & 1  // set flags
	shift := (inst >> 22) & 3 // 0=none, 1=LSL#12
	imm12 := uint64((inst >> 10) & 0xFFF)
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	if shift == 1 {
		imm12 <<= 12
	}

	a := c.RegSP(rn)
	if !is64 {
		a &= 0xFFFFFFFF
	}

	if setf != 0 {
		var y uint64
		var carry uint64
		if op == 0 { // ADDS
			y = imm12
			carry = 0
		} else { // SUBS/CMP
			if is64 {
				y = ^imm12
			} else {
				y = uint64(^uint32(imm12))
			}
			carry = 1
		}
		var result uint64
		if is64 {
			result, c.N, c.Z, c.C, c.V = addWithCarry64(a, y, carry)
		} else {
			r32, n, z, cc, v := addWithCarry32(uint32(a), uint32(y), uint32(carry))
			result = uint64(r32)
			c.N, c.Z, c.C, c.V = n, z, cc, v
		}
		c.SetReg(rd, result) // XZR for CMP
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
		c.SetRegSP(rd, result) // SP-capable
	}
	c.PC += 4
	return nil
}

// AND/ORR/EOR/ANDS (immediate)
func (c *CPU) execLogImm(inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	nBit := (inst >> 22) & 1
	immr := (inst >> 16) & 0x3F
	imms := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	wmask, _ := decodeBitMasks(nBit, imms, immr, is64)
	a := c.Reg(rn)
	if !is64 {
		a &= 0xFFFFFFFF
	}

	var result uint64
	switch opc {
	case 0:
		result = a & wmask // AND
	case 1:
		result = a | wmask // ORR
	case 2:
		result = a ^ wmask // EOR
	case 3:
		result = a & wmask // ANDS
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}

	if opc == 3 { // ANDS/TST — set flags
		if is64 {
			c.N = (result >> 63) != 0
		} else {
			c.N = (result >> 31) != 0
		}
		c.Z = result == 0
		c.C = false
		c.V = false
		c.SetReg(rd, result)
	} else {
		c.SetRegSP(rd, result) // SP-capable for AND/ORR/EOR imm
	}
	c.PC += 4
	return nil
}

// MOVN/MOVZ/MOVK
func (c *CPU) execMoveWide(inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	hw := (inst >> 21) & 0x3
	imm16 := uint64((inst >> 5) & 0xFFFF)
	rd := inst & 0x1F
	shift := hw * 16

	switch opc {
	case 0: // MOVN
		result := ^(imm16 << shift)
		if sf == 0 {
			result &= 0xFFFFFFFF
		}
		c.SetReg(rd, result)
	case 2: // MOVZ
		c.SetReg(rd, imm16<<shift)
	case 3: // MOVK — keep other bits
		mask := uint64(0xFFFF) << shift
		old := c.Reg(rd)
		c.SetReg(rd, (old&^mask)|(imm16<<shift))
	default:
		return fmt.Errorf("reserved move-wide opc=%d", opc)
	}
	c.PC += 4
	return nil
}

// SBFM/BFM/UBFM
func (c *CPU) execBitfield(inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	nBit := (inst >> 22) & 1
	immr := (inst >> 16) & 0x3F
	imms := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	_ = nBit

	wmask, tmask := decodeBitMasks(nBit, imms, immr, is64)

	datasize := uint32(64)
	if !is64 {
		datasize = 32
	}

	src := c.Reg(rn)
	if !is64 {
		src &= 0xFFFFFFFF
	}

	// ROR(src, R) within datasize
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
	case 0: // SBFM (SXTW, ASR, SBFIZ, SBFX, etc.)
		bot := rotated & wmask
		// top = replicate(src[imms])
		var top uint64
		if (src>>(imms))&1 != 0 {
			top = ^uint64(0)
			if !is64 {
				top &= 0xFFFFFFFF
			}
		}
		result := (top &^ tmask) | (bot & tmask)
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.SetReg(rd, result)
	case 1: // BFM (BFI, BFXIL)
		dst := c.Reg(rd)
		if !is64 {
			dst &= 0xFFFFFFFF
		}
		bot := (dst &^ wmask) | (rotated & wmask)
		result := (dst &^ tmask) | (bot & tmask)
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.SetReg(rd, result)
	case 2: // UBFM (UBFIZ, UBFX, LSL, LSR, UXTB, UXTH)
		bot := rotated & wmask
		result := bot & tmask
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.SetReg(rd, result)
	default:
		return fmt.Errorf("reserved bitfield opc=%d", opc)
	}
	c.PC += 4
	return nil
}

// EXTR
func (c *CPU) execExtract(inst uint32) error {
	sf := inst >> 31
	rm := (inst >> 16) & 0x1F
	imms := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	hi := c.Reg(rn)
	lo := c.Reg(rm)
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
	c.SetReg(rd, result)
	c.PC += 4
	return nil
}

// ============================================================
// Data Processing — Register
// ============================================================

func (c *CPU) execDPReg(inst uint32) error {
	top5 := (inst >> 24) & 0x1F // bits[28:24]
	switch top5 {
	case 0x0A: // 01010: Logical shifted register
		return c.execLogShiftReg(inst)
	case 0x0B: // 01011: Add/subtract shifted/extended register
		if (inst>>21)&1 == 0 {
			return c.execAddSubShiftReg(inst)
		}
		return c.execAddSubExtReg(inst)
	case 0x1A: // 11010: conditional compare/select, DP-1/2-source
		return c.execDP11010(inst)
	case 0x1B: // 11011: Data processing (3 source)
		return c.execDP3Src(inst)
	}
	return fmt.Errorf("unhandled DP-Reg top5=0x%02x inst=0x%08x PC=0x%x", top5, inst, c.PC)
}

// AND/ORR/EOR/BIC/ORN/EON/ANDS/BICS (shifted register)
func (c *CPU) execLogShiftReg(inst uint32) error {
	sf := inst >> 31
	opc := (inst >> 29) & 0x3
	shiftType := (inst >> 22) & 0x3
	nBit := (inst >> 21) & 1 // N: invert Rm
	rm := (inst >> 16) & 0x1F
	imm6 := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.Reg(rn)
	b := shiftVal(c.Reg(rm), shiftType, imm6, is64)
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
		result = a & b // AND / BIC
	case 1:
		result = a | b // ORR / ORN (MOV / MVN aliases)
	case 2:
		result = a ^ b // EOR / EON
	case 3:
		result = a & b // ANDS / BICS
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}

	if opc == 3 { // ANDS/BICS — set flags
		if is64 {
			c.N = (result >> 63) != 0
		} else {
			c.N = (result >> 31) != 0
		}
		c.Z = result == 0
		c.C = false
		c.V = false
	}
	c.SetReg(rd, result)
	c.PC += 4
	return nil
}

// ADD/SUB/ADDS/SUBS/CMP/CMN/NEG (shifted register)
func (c *CPU) execAddSubShiftReg(inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	setf := (inst >> 29) & 1
	shiftType := (inst >> 22) & 0x3
	rm := (inst >> 16) & 0x1F
	imm6 := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.Reg(rn)
	b := shiftVal(c.Reg(rm), shiftType, imm6, is64)
	if !is64 {
		a &= 0xFFFFFFFF
		b &= 0xFFFFFFFF
	}

	var y, carry uint64
	if op == 0 { // ADD(S)
		y = b
		carry = 0
	} else { // SUB(S)
		if is64 {
			y = ^b
		} else {
			y = uint64(^uint32(b))
		}
		carry = 1
	}
	var result uint64
	if setf != 0 {
		if is64 {
			result, c.N, c.Z, c.C, c.V = addWithCarry64(a, y, carry)
		} else {
			r32, n, z, cc, v := addWithCarry32(uint32(a), uint32(y), uint32(carry))
			result = uint64(r32)
			c.N, c.Z, c.C, c.V = n, z, cc, v
		}
		c.SetReg(rd, result)
	} else {
		if op == 0 {
			result = a + b
		} else {
			result = a - b
		}
		if !is64 {
			result &= 0xFFFFFFFF
		}
		c.SetReg(rd, result)
	}
	c.PC += 4
	return nil
}

// ADD/SUB extended register (e.g., add x0, sp, w1, uxtw #2)
func (c *CPU) execAddSubExtReg(inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	setf := (inst >> 29) & 1
	rm := (inst >> 16) & 0x1F
	option := (inst >> 13) & 0x7
	imm3 := (inst >> 10) & 0x7
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.RegSP(rn)
	rmVal := c.Reg(rm)

	// Extend rm
	var extended uint64
	switch option {
	case 0: // UXTB
		extended = rmVal & 0xFF
	case 1: // UXTH
		extended = rmVal & 0xFFFF
	case 2: // UXTW
		extended = rmVal & 0xFFFFFFFF
	case 3: // UXTX
		extended = rmVal
	case 4: // SXTB
		extended = signExtend(rmVal&0xFF, 8)
	case 5: // SXTH
		extended = signExtend(rmVal&0xFFFF, 16)
	case 6: // SXTW
		extended = signExtend(rmVal&0xFFFFFFFF, 32)
	case 7: // SXTX
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
			result, c.N, c.Z, c.C, c.V = addWithCarry64(a, y, carry)
		} else {
			r32, n, z, cc, v := addWithCarry32(uint32(a), uint32(y), uint32(carry))
			result = uint64(r32)
			c.N, c.Z, c.C, c.V = n, z, cc, v
		}
		c.SetReg(rd, result)
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
		c.SetRegSP(rd, result) // SP-capable
	}
	c.PC += 4
	return nil
}

// Sub-decoder for bits[28:24]=11010
func (c *CPU) execDP11010(inst uint32) error {
	bits2321 := (inst >> 21) & 7
	switch bits2321 {
	case 2, 3: // Conditional compare (register/immediate)
		return c.execCondCompare(inst)
	case 4: // Conditional select
		return c.execCondSelect(inst)
	case 6: // DP-1-source (bit30=1) or DP-2-source (bit30=0)
		if (inst>>30)&1 == 1 {
			return c.execDP1Src(inst)
		}
		return c.execDP2Src(inst)
	}
	return fmt.Errorf("unhandled 11010 sub=%d inst=0x%08x PC=0x%x", bits2321, inst, c.PC)
}

// CCMP/CCMN
func (c *CPU) execCondCompare(inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1 // 1=CCMP, 0=CCMN
	rm := (inst >> 16) & 0x1F
	cond := (inst >> 12) & 0xF
	rn := (inst >> 5) & 0x1F
	nzcv := inst & 0xF
	is64 := sf != 0
	isImm := (inst>>11)&1 != 0 // bit11: 1=immediate, 0=register

	if c.condHolds(cond) {
		a := c.Reg(rn)
		var b uint64
		if isImm {
			b = uint64(rm) // imm5
		} else {
			b = c.Reg(rm)
		}
		if !is64 {
			a &= 0xFFFFFFFF
			b &= 0xFFFFFFFF
		}
		var y uint64
		var carry uint64
		if op == 1 { // CCMP (subtract)
			if is64 {
				y = ^b
			} else {
				y = uint64(^uint32(b))
			}
			carry = 1
		} else { // CCMN (add)
			y = b
			carry = 0
		}
		if is64 {
			_, c.N, c.Z, c.C, c.V = addWithCarry64(a, y, carry)
		} else {
			_, c.N, c.Z, c.C, c.V = addWithCarry32(uint32(a), uint32(y), uint32(carry))
		}
	} else {
		c.N = (nzcv>>3)&1 != 0
		c.Z = (nzcv>>2)&1 != 0
		c.C = (nzcv>>1)&1 != 0
		c.V = nzcv&1 != 0
	}
	c.PC += 4
	return nil
}

// CSEL/CSINC/CSINV/CSNEG (and aliases CSET, CINC)
func (c *CPU) execCondSelect(inst uint32) error {
	sf := inst >> 31
	op := (inst >> 30) & 1
	rm := (inst >> 16) & 0x1F
	cond := (inst >> 12) & 0xF
	op2 := (inst >> 10) & 0x3
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.Reg(rn)
	b := c.Reg(rm)

	var result uint64
	if c.condHolds(cond) {
		result = a
	} else {
		switch (op << 1) | (op2 & 1) {
		case 0: // CSEL
			result = b
		case 1: // CSINC
			result = b + 1
		case 2: // CSINV
			result = ^b
		case 3: // CSNEG
			result = -b
		}
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}
	c.SetReg(rd, result)
	c.PC += 4
	return nil
}

// UDIV, SDIV, LSLV, LSRV, ASRV, RORV
func (c *CPU) execDP2Src(inst uint32) error {
	sf := inst >> 31
	rm := (inst >> 16) & 0x1F
	opcode := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.Reg(rn)
	b := c.Reg(rm)
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
		shift := b & uint64(map[bool]uint32{true: 63, false: 31}[is64])
		result = a << shift
	case 9: // LSRV
		shift := b & uint64(map[bool]uint32{true: 63, false: 31}[is64])
		result = a >> shift
	case 10: // ASRV
		shift := b & uint64(map[bool]uint32{true: 63, false: 31}[is64])
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
	c.SetReg(rd, result)
	c.PC += 4
	return nil
}

// REV, REV32, REV16, CLZ, RBIT
func (c *CPU) execDP1Src(inst uint32) error {
	sf := inst >> 31
	opcode := (inst >> 10) & 0x3F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0
	val := c.Reg(rn)

	var result uint64
	switch opcode {
	case 0: // RBIT
		if is64 {
			result = rbit64(val)
		} else {
			result = uint64(rbit32(uint32(val)))
		}
	case 1: // REV16
		if is64 {
			result = rev16_64(val)
		} else {
			result = uint64(rev16_32(uint32(val)))
		}
	case 2: // REV (32-bit) / REV32 (64-bit)
		if is64 {
			// REV32: reverse bytes in each 32-bit half
			lo := rev32(uint32(val))
			hi := rev32(uint32(val >> 32))
			result = uint64(lo) | uint64(hi)<<32
		} else {
			result = uint64(rev32(uint32(val)))
		}
	case 3: // REV (64-bit)
		result = rev64(val)
	case 4: // CLZ
		if is64 {
			result = uint64(clz64(val))
		} else {
			result = uint64(clz32(uint32(val)))
		}
	default:
		return fmt.Errorf("unhandled DP-1-source opcode=%d sf=%d inst=0x%08x", opcode, sf, inst)
	}
	if !is64 {
		result &= 0xFFFFFFFF
	}
	c.SetReg(rd, result)
	c.PC += 4
	return nil
}

func rbit64(v uint64) uint64 {
	v = (v&0x5555555555555555)<<1 | (v&0xAAAAAAAAAAAAAAAA)>>1
	v = (v&0x3333333333333333)<<2 | (v&0xCCCCCCCCCCCCCCCC)>>2
	v = (v&0x0F0F0F0F0F0F0F0F)<<4 | (v&0xF0F0F0F0F0F0F0F0)>>4
	return rev64(v)
}

func rbit32(v uint32) uint32 {
	v = (v&0x55555555)<<1 | (v&0xAAAAAAAA)>>1
	v = (v&0x33333333)<<2 | (v&0xCCCCCCCC)>>2
	v = (v&0x0F0F0F0F)<<4 | (v&0xF0F0F0F0)>>4
	return rev32(v)
}

func rev16_64(v uint64) uint64 {
	return ((v & 0xFF00FF00FF00FF00) >> 8) | ((v & 0x00FF00FF00FF00FF) << 8)
}

func rev16_32(v uint32) uint32 {
	return ((v & 0xFF00FF00) >> 8) | ((v & 0x00FF00FF) << 8)
}

func rev32(v uint32) uint32 {
	return (v>>24)&0xFF | (v>>8)&0xFF00 | (v<<8)&0xFF0000 | (v << 24)
}

func rev64(v uint64) uint64 {
	lo := rev32(uint32(v))
	hi := rev32(uint32(v >> 32))
	return uint64(lo)<<32 | uint64(hi)
}

func clz64(v uint64) int {
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

func clz32(v uint32) int {
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

// MADD/MSUB/UMADDL/UMSUBL/UMULH/SMADDL/SMULH
func (c *CPU) execDP3Src(inst uint32) error {
	sf := inst >> 31
	op31 := (inst >> 21) & 0x7
	rm := (inst >> 16) & 0x1F
	o0 := (inst >> 15) & 1
	ra := (inst >> 10) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F
	is64 := sf != 0

	a := c.Reg(rn)
	b := c.Reg(rm)
	addend := c.Reg(ra)

	var result uint64
	switch op31 {
	case 0: // MADD (o0=0) / MSUB (o0=1) — 32 or 64 bit
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
	case 1: // SMADDL (o0=0) / SMSUBL (o0=1) — signed 32×32→64
		prod := uint64(int64(int32(uint32(a))) * int64(int32(uint32(b))))
		if o0 == 0 {
			result = addend + prod
		} else {
			result = addend - prod
		}
	case 2: // SMULH — signed 64×64→upper 64
		result = smulhi64(a, b)
	case 5: // UMADDL (o0=0) / UMSUBL (o0=1) — unsigned 32×32→64
		prod := uint64(uint32(a)) * uint64(uint32(b))
		if o0 == 0 {
			result = addend + prod
		} else {
			result = addend - prod
		}
	case 6: // UMULH — unsigned 64×64→upper 64
		result = mulhi64(a, b)
	default:
		return fmt.Errorf("unhandled DP-3-source op31=%d inst=0x%08x", op31, inst)
	}
	c.SetReg(rd, result)
	c.PC += 4
	return nil
}

// mulhi64 returns the upper 64 bits of a 128-bit unsigned multiply.
func mulhi64(a, b uint64) uint64 {
	aHi, aLo := a>>32, a&0xFFFFFFFF
	bHi, bLo := b>>32, b&0xFFFFFFFF
	mid1 := aHi * bLo
	mid2 := aLo * bHi
	lo := aLo * bLo
	hi := aHi * bHi
	carry := (lo>>32 + (mid1 & 0xFFFFFFFF) + (mid2 & 0xFFFFFFFF)) >> 32
	return hi + (mid1 >> 32) + (mid2 >> 32) + carry
}

// smulhi64 returns the upper 64 bits of a 128-bit signed multiply.
func smulhi64(a, b uint64) uint64 {
	sa, sb := int64(a), int64(b)
	// Use unsigned mulhi and adjust for sign
	result := mulhi64(a, b)
	if sa < 0 {
		result -= b
	}
	if sb < 0 {
		result -= a
	}
	return result
}

// ============================================================
// Loads and Stores
// ============================================================

func (c *CPU) execLoadStore(inst uint32) error {
	op1 := (inst >> 27) & 7 // bits[29:27]
	v := (inst >> 26) & 1

	switch {
	case op1 == 5 && v == 0: // LDP/STP (GP)
		return c.execLdStPair(inst)
	case op1 == 5 && v == 1: // LDP/STP (SIMD)
		return c.execLdStPairSIMD(inst)
	case op1 == 7 && v == 0: // Load/store register (GP)
		bit24 := (inst >> 24) & 1
		if bit24 == 1 {
			return c.execLdStUnsigned(inst)
		}
		bit21 := (inst >> 21) & 1
		if bit21 == 1 {
			return c.execLdStRegOff(inst)
		}
		return c.execLdStImm9(inst)
	case op1 == 7 && v == 1: // Load/store register (SIMD)
		bit24 := (inst >> 24) & 1
		if bit24 == 1 {
			return c.execLdStSIMDUnsigned(inst)
		}
		return c.execLdStSIMDImm9(inst)
	case op1 == 3 && v == 0: // Load register literal
		return c.execLdrLiteral(inst)
	case op1 == 3 && v == 1: // Load SIMD literal
		return c.execLdrSIMDLiteral(inst)
	}
	return fmt.Errorf("unhandled load/store op1=%d v=%d inst=0x%08x PC=0x%x", op1, v, inst, c.PC)
}

// LDR/STR/LDRB/STRB/LDRH/STRH/LDRSW/LDRSB/LDRSH (unsigned offset)
func (c *CPU) execLdStUnsigned(inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm12 := uint64((inst >> 10) & 0xFFF)
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	// Scale immediate by access size
	scale := uint64(1) << size
	offset := imm12 * scale
	addr := c.RegSP(rn) + offset

	return c.doLoadStore(size, opc, addr, rt)
}

// LDR/STR unscaled (LDUR/STUR) and pre/post-indexed
func (c *CPU) execLdStImm9(inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm9 := signExtend(uint64((inst>>12)&0x1FF), 9)
	idxType := (inst >> 10) & 3 // 00=unscaled, 01=post, 11=pre
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	base := c.RegSP(rn)

	var addr uint64
	switch idxType {
	case 0: // Unscaled (LDUR/STUR)
		addr = base + imm9
	case 1: // Post-index
		addr = base
		c.SetRegSP(rn, base+imm9)
	case 3: // Pre-index
		addr = base + imm9
		c.SetRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved ldst idxType=%d inst=0x%08x", idxType, inst)
	}

	return c.doLoadStore(size, opc, addr, rt)
}

// LDR/STR register offset (e.g., ldr x0, [x1, x2, lsl #3])
func (c *CPU) execLdStRegOff(inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	rm := (inst >> 16) & 0x1F
	option := (inst >> 13) & 7
	s := (inst >> 12) & 1
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	base := c.RegSP(rn)
	offset := c.Reg(rm)

	// Extend offset
	switch option {
	case 2: // UXTW
		offset &= 0xFFFFFFFF
	case 3: // LSL (no extend)
		// offset unchanged
	case 6: // SXTW
		offset = signExtend(offset&0xFFFFFFFF, 32)
	case 7: // SXTX
		// offset unchanged
	}
	if s != 0 {
		offset <<= size
	}

	addr := base + offset
	return c.doLoadStore(size, opc, addr, rt)
}

// Common load/store execution for size + opc.
func (c *CPU) doLoadStore(size, opc uint32, addr uint64, rt uint32) error {
	switch opc {
	case 0: // STR
		switch size {
		case 0:
			c.Mem.Write8(addr, uint8(c.Reg(rt)))
		case 1:
			c.Mem.Write16(addr, uint16(c.Reg(rt)))
		case 2:
			c.Mem.Write32(addr, uint32(c.Reg(rt)))
		case 3:
			c.Mem.Write64(addr, c.Reg(rt))
		}
	case 1: // LDR (zero-extend)
		var val uint64
		switch size {
		case 0:
			val = uint64(c.Mem.Read8(addr))
		case 1:
			val = uint64(c.Mem.Read16(addr))
		case 2:
			val = uint64(c.Mem.Read32(addr))
		case 3:
			val = c.Mem.Read64(addr)
		}
		c.SetReg(rt, val)
	case 2: // LDRS to 64-bit (sign-extend)
		var val uint64
		switch size {
		case 0: // LDRSB → X
			val = signExtend(uint64(c.Mem.Read8(addr)), 8)
		case 1: // LDRSH → X
			val = signExtend(uint64(c.Mem.Read16(addr)), 16)
		case 2: // LDRSW → X
			val = signExtend(uint64(c.Mem.Read32(addr)), 32)
		default:
			// PRFM for size=3, treat as NOP
		}
		c.SetReg(rt, val)
	case 3: // LDRS to 32-bit (sign-extend) or PRFM
		var val uint64
		switch size {
		case 0: // LDRSB → W
			val = uint64(uint32(int8(c.Mem.Read8(addr))))
		case 1: // LDRSH → W
			val = uint64(uint32(int16(c.Mem.Read16(addr))))
		default:
			// PRFM, NOP
		}
		c.SetReg(rt, val)
	}
	c.PC += 4
	return nil
}

// LDP/STP (signed offset, pre-index, post-index)
func (c *CPU) execLdStPair(inst uint32) error {
	opc := (inst >> 30) & 3
	pairType := (inst >> 23) & 7 // bits[25:23]: 001=post, 010=signed, 011=pre
	load := (inst >> 22) & 1
	imm7 := signExtend(uint64((inst>>15)&0x7F), 7)
	rt2 := (inst >> 10) & 0x1F
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	var scale uint64
	switch opc {
	case 0:
		scale = 4 // 32-bit
	case 1:
		scale = 4 // LDPSW: loads 32-bit sign-extends to 64-bit
	case 2:
		scale = 8 // 64-bit
	default:
		return fmt.Errorf("reserved LDP/STP opc=%d", opc)
	}
	offset := imm7 * scale
	base := c.RegSP(rn)

	var addr uint64
	switch pairType {
	case 1: // Post-index
		addr = base
		c.SetRegSP(rn, base+offset)
	case 2: // Signed offset
		addr = base + offset
	case 3: // Pre-index
		addr = base + offset
		c.SetRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved LDP/STP type=%d", pairType)
	}

	if load != 0 {
		switch opc {
		case 0: // LDP 32-bit
			c.SetReg(rt, uint64(c.Mem.Read32(addr)))
			c.SetReg(rt2, uint64(c.Mem.Read32(addr+4)))
		case 1: // LDPSW — sign-extend 32→64
			c.SetReg(rt, signExtend(uint64(c.Mem.Read32(addr)), 32))
			c.SetReg(rt2, signExtend(uint64(c.Mem.Read32(addr+4)), 32))
		case 2: // LDP 64-bit
			c.SetReg(rt, c.Mem.Read64(addr))
			c.SetReg(rt2, c.Mem.Read64(addr+8))
		}
	} else {
		switch opc {
		case 0: // STP 32-bit
			c.Mem.Write32(addr, uint32(c.Reg(rt)))
			c.Mem.Write32(addr+4, uint32(c.Reg(rt2)))
		case 2: // STP 64-bit
			c.Mem.Write64(addr, c.Reg(rt))
			c.Mem.Write64(addr+8, c.Reg(rt2))
		}
	}
	c.PC += 4
	return nil
}

// LDR (literal) — PC-relative
func (c *CPU) execLdrLiteral(inst uint32) error {
	opc := (inst >> 30) & 3
	imm19 := signExtend(uint64((inst>>5)&0x7FFFF), 19)
	rt := inst & 0x1F
	addr := c.PC + imm19*4

	switch opc {
	case 0: // LDR W
		c.SetReg(rt, uint64(c.Mem.Read32(addr)))
	case 1: // LDR X
		c.SetReg(rt, c.Mem.Read64(addr))
	case 2: // LDRSW
		c.SetReg(rt, signExtend(uint64(c.Mem.Read32(addr)), 32))
	}
	c.PC += 4
	return nil
}

// ============================================================
// Branches
// ============================================================

func (c *CPU) execBranch(inst uint32) error {
	top6 := (inst >> 26) & 0x3F
	switch top6 {
	case 0x05: // B
		return c.execBUncond(inst, false)
	case 0x25: // BL
		return c.execBUncond(inst, true)
	}
	// CBZ/CBNZ: bits[30:25] = 011010
	if (inst>>25)&0x3F == 0x1A {
		return c.execCBx(inst)
	}
	// B.cond: bits[31:25] = 0101010
	if (inst>>25)&0x7F == 0x2A {
		return c.execBCond(inst)
	}
	// BR/BLR/RET: bits[31:25] = 1101011
	if (inst>>25)&0x7F == 0x6B {
		return c.execBranchReg(inst)
	}
	return fmt.Errorf("unhandled branch inst=0x%08x PC=0x%x", inst, c.PC)
}

// B / BL
func (c *CPU) execBUncond(inst uint32, link bool) error {
	imm26 := signExtend(uint64(inst&0x3FFFFFF), 26)
	if link {
		c.X[30] = c.PC + 4
	}
	c.PC = c.PC + imm26*4
	return nil
}

// B.cond
func (c *CPU) execBCond(inst uint32) error {
	imm19 := signExtend(uint64((inst>>5)&0x7FFFF), 19)
	cond := inst & 0xF
	if c.condHolds(cond) {
		c.PC = c.PC + imm19*4
	} else {
		c.PC += 4
	}
	return nil
}

// CBZ / CBNZ
func (c *CPU) execCBx(inst uint32) error {
	sf := inst >> 31
	op := (inst >> 24) & 1 // 0=CBZ, 1=CBNZ
	imm19 := signExtend(uint64((inst>>5)&0x7FFFF), 19)
	rt := inst & 0x1F

	val := c.Reg(rt)
	if sf == 0 {
		val &= 0xFFFFFFFF
	}
	take := false
	if op == 0 {
		take = val == 0 // CBZ
	} else {
		take = val != 0 // CBNZ
	}
	if take {
		c.PC = c.PC + imm19*4
	} else {
		c.PC += 4
	}
	return nil
}

// BR / BLR / RET
func (c *CPU) execBranchReg(inst uint32) error {
	opc := (inst >> 21) & 0xF
	rn := (inst >> 5) & 0x1F
	target := c.Reg(rn)
	if rn == 31 {
		target = 0 // XZR (unusual for branches)
	}

	switch opc {
	case 0: // BR
		c.PC = target
	case 1: // BLR
		c.X[30] = c.PC + 4
		c.PC = target
	case 2: // RET
		c.PC = c.X[30]
		if rn != 30 {
			c.PC = c.Reg(rn)
		}
	default:
		return fmt.Errorf("unhandled branch-reg opc=%d inst=0x%08x", opc, inst)
	}
	return nil
}

// ============================================================
// SIMD / Floating-Point
// ============================================================

func (c *CPU) execSIMD(inst uint32) error {
	// FMOV Dd, Xn: 0x9E670000
	if inst&0xFFFFFC00 == 0x9E670000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.Vreg[rd] = [2]uint64{c.Reg(rn), 0}
		c.PC += 4
		return nil
	}
	// FMOV Xd, Dn: 0x9E660000
	if inst&0xFFFFFC00 == 0x9E660000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.SetReg(rd, c.Vreg[rn][0])
		c.PC += 4
		return nil
	}
	// FMOV Vd.D[1], Xn: 0x9EAF0000
	if inst&0xFFFFFC00 == 0x9EAF0000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.Vreg[rd][1] = c.Reg(rn)
		c.PC += 4
		return nil
	}
	// FMOV Xd, Vn.D[1]: 0x9EAE0000
	if inst&0xFFFFFC00 == 0x9EAE0000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.SetReg(rd, c.Vreg[rn][1])
		c.PC += 4
		return nil
	}
	// FMOV Sd, Wn (32-bit GP → single): 0x1E270000
	if inst&0xFFFFFC00 == 0x1E270000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.Vreg[rd] = [2]uint64{uint64(uint32(c.Reg(rn))), 0}
		c.PC += 4
		return nil
	}
	// FMOV Wd, Sn (single → 32-bit GP): 0x1E260000
	if inst&0xFFFFFC00 == 0x1E260000 {
		rn := (inst >> 5) & 0x1F
		rd := inst & 0x1F
		c.SetReg(rd, uint64(uint32(c.Vreg[rn][0])))
		c.PC += 4
		return nil
	}

	// DUP (general): inst & 0xBFE0FC00 == 0x0E000C00
	if inst&0xBFE0FC00 == 0x0E000C00 {
		return c.execDUP(inst)
	}
	// UMOV: inst & 0xBFE0FC00 == 0x0E003C00
	if inst&0xBFE0FC00 == 0x0E003C00 {
		return c.execUMOV(inst)
	}
	// INS (general to element): inst & 0xBFE0FC00 == 0x0E001C00
	if inst&0xBFE0FC00 == 0x0E001C00 {
		return c.execINS(inst)
	}
	// SHL (vector, immediate): inst & 0xBF80FC00 == 0x0F005400
	if inst&0xBF80FC00 == 0x0F005400 {
		return c.execSHL(inst)
	}
	// MOVI class: inst & 0x9FF80400 == 0x0F000400
	if inst&0x9FF80400 == 0x0F000400 {
		return c.execMOVI(inst)
	}
	// XTN/XTN2: inst & 0xBF3FFC00 == 0x0E212800
	if inst&0xBF3FFC00 == 0x0E212800 {
		return c.execXTN(inst)
	}
	// EXT: inst & 0xBFE08400 == 0x2E000000
	if inst&0xBFE08400 == 0x2E000000 {
		return c.execEXT(inst)
	}
	// REV64 (vector): inst & 0xBF3FFC00 == 0x0E200800
	if inst&0xBF3FFC00 == 0x0E200800 {
		return c.execREV64Vec(inst)
	}
	// AdvSIMD three same: 0 Q U 01110 size 1 Rm opcode5 1 Rn Rd
	if inst&0x9F200400 == 0x0E200400 {
		return c.execAdvSIMD3Same(inst)
	}
	// FMOV (scalar immediate): x 00 11110 xx 1 imm8 100 00000 Rd
	if inst&0x9F01FC00 == 0x1E201000 {
		return c.execFMOVImm(inst)
	}

	return fmt.Errorf("unhandled SIMD inst=0x%08x PC=0x%x", inst, c.PC)
}

// DUP Vd.T, Wn/Xn
func (c *CPU) execDUP(inst uint32) error {
	q := (inst >> 30) & 1
	imm5 := (inst >> 16) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	val := c.Reg(rn)
	var result [2]uint64

	switch {
	case imm5&1 == 1: // B
		b := uint8(val)
		for i := 0; i < 8; i++ {
			result[0] |= uint64(b) << (i * 8)
		}
		if q != 0 {
			result[1] = result[0]
		}
	case imm5&3 == 2: // H
		h := uint16(val)
		for i := 0; i < 4; i++ {
			result[0] |= uint64(h) << (i * 16)
		}
		if q != 0 {
			result[1] = result[0]
		}
	case imm5&7 == 4: // S
		s := uint32(val)
		result[0] = uint64(s) | uint64(s)<<32
		if q != 0 {
			result[1] = result[0]
		}
	case imm5&15 == 8: // D
		result[0] = val
		if q != 0 {
			result[1] = val
		}
	}
	c.Vreg[rd] = result
	c.PC += 4
	return nil
}

// UMOV Wd/Xd, Vn.T[index]
func (c *CPU) execUMOV(inst uint32) error {
	imm5 := (inst >> 16) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	// Decode element size and index from imm5
	lo := c.Vreg[rn][0]
	hi := c.Vreg[rn][1]

	var val uint64
	switch {
	case imm5&1 == 1: // B
		idx := imm5 >> 1
		if idx < 8 {
			val = (lo >> (idx * 8)) & 0xFF
		} else {
			val = (hi >> ((idx - 8) * 8)) & 0xFF
		}
	case imm5&3 == 2: // H
		idx := imm5 >> 2
		if idx < 4 {
			val = (lo >> (idx * 16)) & 0xFFFF
		} else {
			val = (hi >> ((idx - 4) * 16)) & 0xFFFF
		}
	case imm5&7 == 4: // S
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
	case imm5&15 == 8: // D
		idx := imm5 >> 4
		if idx == 0 {
			val = lo
		} else {
			val = hi
		}
	}
	c.SetReg(rd, val)
	c.PC += 4
	return nil
}

// INS Vd.Ts[index], Wn/Xn — insert GP register into SIMD element
func (c *CPU) execINS(inst uint32) error {
	imm5 := (inst >> 16) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	val := c.Reg(rn)
	lo := c.Vreg[rd][0]
	hi := c.Vreg[rd][1]

	switch {
	case imm5&1 == 1: // B
		idx := imm5 >> 1
		shift := idx * 8
		if idx < 8 {
			lo = (lo &^ (0xFF << shift)) | ((val & 0xFF) << shift)
		} else {
			shift = (idx - 8) * 8
			hi = (hi &^ (0xFF << shift)) | ((val & 0xFF) << shift)
		}
	case imm5&3 == 2: // H
		idx := imm5 >> 2
		shift := idx * 16
		if idx < 4 {
			lo = (lo &^ (0xFFFF << shift)) | ((val & 0xFFFF) << shift)
		} else {
			shift = (idx - 4) * 16
			hi = (hi &^ (0xFFFF << shift)) | ((val & 0xFFFF) << shift)
		}
	case imm5&7 == 4: // S
		idx := imm5 >> 3
		shift := idx * 32
		if idx < 2 {
			lo = (lo &^ (0xFFFFFFFF << shift)) | ((val & 0xFFFFFFFF) << shift)
		} else {
			shift = (idx - 2) * 32
			hi = (hi &^ (0xFFFFFFFF << shift)) | ((val & 0xFFFFFFFF) << shift)
		}
	case imm5&15 == 8: // D
		idx := imm5 >> 4
		if idx == 0 {
			lo = val
		} else {
			hi = val
		}
	}
	c.Vreg[rd] = [2]uint64{lo, hi}
	c.PC += 4
	return nil
}

// SHL Vd.T, Vn.T, #shift (vector shift left by immediate)
func (c *CPU) execSHL(inst uint32) error {
	q := (inst >> 30) & 1
	immh := (inst >> 19) & 0xF
	immb := (inst >> 16) & 0x7
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	immhb := (immh << 3) | immb

	srcLo := c.Vreg[rn][0]
	srcHi := c.Vreg[rn][1]
	var dstLo, dstHi uint64

	switch {
	case immh&0x8 != 0: // 64-bit elements, shift = immhb - 64
		shift := immhb - 64
		dstLo = srcLo << shift
		if q != 0 {
			dstHi = srcHi << shift
		}
	case immh&0xC == 0x4: // 32-bit elements, shift = immhb - 32
		shift := immhb - 32
		lo0 := (srcLo & 0xFFFFFFFF) << shift
		lo1 := ((srcLo >> 32) & 0xFFFFFFFF) << shift
		dstLo = (lo0 & 0xFFFFFFFF) | ((lo1 & 0xFFFFFFFF) << 32)
		if q != 0 {
			hi0 := (srcHi & 0xFFFFFFFF) << shift
			hi1 := ((srcHi >> 32) & 0xFFFFFFFF) << shift
			dstHi = (hi0 & 0xFFFFFFFF) | ((hi1 & 0xFFFFFFFF) << 32)
		}
	case immh&0xE == 0x2: // 16-bit elements, shift = immhb - 16
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
	case immh&0xF == 0x1: // 8-bit elements, shift = immhb - 8
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
	c.Vreg[rd] = [2]uint64{dstLo, dstHi}
	c.PC += 4
	return nil
}

// MOVI (and related modified immediate)
func (c *CPU) execMOVI(inst uint32) error {
	q := (inst >> 30) & 1
	op := (inst >> 29) & 1
	cmode := (inst >> 12) & 0xF
	rd := inst & 0x1F

	// Extract 8-bit immediate abcdefgh
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
	case cmode&0xE == 0x0: // 32-bit shifted: imm8 << (cmode[2:1] * 8)
		shift := ((cmode >> 1) & 3) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode&0xE == 0x2:
		shift := ((cmode >> 1) & 3) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode&0xE == 0x4:
		shift := ((cmode >> 1) & 3) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode&0xE == 0x6:
		shift := ((cmode >> 1) & 3) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFFFFFF
		}
		imm64 = elem | (elem << 32)
	case cmode == 0x8 || cmode == 0x9: // 16-bit: imm8 or imm8<<8
		shift := (cmode & 1) * 8
		elem := uint64(imm8) << shift
		if op == 1 {
			elem = ^elem & 0xFFFF
		}
		for i := 0; i < 4; i++ {
			imm64 |= (elem & 0xFFFF) << (i * 16)
		}
	case cmode == 0xA || cmode == 0xB: // 32-bit: imm8 ones (shifting ones)
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
	case cmode == 0xE: // 8-bit: byte replication
		if op == 0 {
			for i := 0; i < 8; i++ {
				imm64 |= uint64(imm8) << (i * 8)
			}
		} else {
			// 64-bit: each bit of imm8 expands to a byte
			for i := 0; i < 8; i++ {
				if (imm8>>uint(i))&1 != 0 {
					imm64 |= 0xFF << (i * 8)
				}
			}
		}
	case cmode == 0xF: // FMOV immediate
		if op == 0 {
			// Single-precision immediate replicated
			imm64 = uint64(vfpExpandImm32(imm8))
			imm64 = imm64 | imm64<<32
		} else {
			// Double-precision immediate
			imm64 = vfpExpandImm64(imm8)
		}
	}

	c.Vreg[rd][0] = imm64
	if q != 0 {
		c.Vreg[rd][1] = imm64
	} else {
		c.Vreg[rd][1] = 0
	}
	c.PC += 4
	return nil
}

func vfpExpandImm32(imm8 uint32) uint32 {
	a := (imm8 >> 7) & 1
	b := (imm8 >> 6) & 1
	cdefgh := imm8 & 0x3F
	var result uint32
	result |= a << 31
	if b != 0 {
		result |= 0x1F << 25
	} else {
		result |= 1 << 30
	}
	result |= cdefgh << 19
	return result
}

func vfpExpandImm64(imm8 uint32) uint64 {
	a := uint64((imm8 >> 7) & 1)
	b := uint64((imm8 >> 6) & 1)
	cdefgh := uint64(imm8 & 0x3F)
	var result uint64
	result |= a << 63
	if b != 0 {
		result |= 0xFF << 54
	} else {
		result |= 1 << 62
	}
	result |= cdefgh << 48
	return result
}

// XTN / XTN2: extract narrow
func (c *CPU) execXTN(inst uint32) error {
	q := (inst >> 30) & 1
	size := (inst >> 22) & 3
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	srcLo := c.Vreg[rn][0]
	srcHi := c.Vreg[rn][1]

	var narrow uint64 // narrowed result in lower 64 bits
	switch size {
	case 0: // 8B from 8H: take low byte of each 16-bit element
		for i := 0; i < 4; i++ {
			narrow |= ((srcLo >> (i * 16)) & 0xFF) << (i * 8)
		}
		for i := 0; i < 4; i++ {
			narrow |= ((srcHi >> (i * 16)) & 0xFF) << ((i + 4) * 8)
		}
	case 1: // 4H from 4S: take low halfword of each 32-bit element
		for i := 0; i < 2; i++ {
			narrow |= ((srcLo >> (i * 32)) & 0xFFFF) << (i * 16)
		}
		for i := 0; i < 2; i++ {
			narrow |= ((srcHi >> (i * 32)) & 0xFFFF) << ((i + 2) * 16)
		}
	case 2: // 2S from 2D: take low word of each 64-bit element
		narrow = (srcLo & 0xFFFFFFFF) | ((srcHi & 0xFFFFFFFF) << 32)
	}

	if q == 0 { // XTN: result goes to lower half
		c.Vreg[rd] = [2]uint64{narrow, 0}
	} else { // XTN2: result goes to upper half, preserving lower
		c.Vreg[rd][1] = narrow
	}
	c.PC += 4
	return nil
}

// EXT Vd.16B, Vn.16B, Vm.16B, #imm
func (c *CPU) execEXT(inst uint32) error {
	rm := (inst >> 16) & 0x1F
	imm4 := (inst >> 11) & 0xF
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	// Concatenate Vm:Vn as 32-byte array, extract 16 bytes starting at imm4
	var src [32]byte
	lo := c.Vreg[rn][0]
	hi := c.Vreg[rn][1]
	for i := 0; i < 8; i++ {
		src[i] = byte(lo >> (i * 8))
		src[i+8] = byte(hi >> (i * 8))
	}
	lo2 := c.Vreg[rm][0]
	hi2 := c.Vreg[rm][1]
	for i := 0; i < 8; i++ {
		src[i+16] = byte(lo2 >> (i * 8))
		src[i+24] = byte(hi2 >> (i * 8))
	}

	var dstLo, dstHi uint64
	for i := 0; i < 8; i++ {
		dstLo |= uint64(src[int(imm4)+i]) << (i * 8)
		dstHi |= uint64(src[int(imm4)+i+8]) << (i * 8)
	}

	c.Vreg[rd] = [2]uint64{dstLo, dstHi}
	c.PC += 4
	return nil
}

// REV64 (vector): reverse elements within each 64-bit doubleword
func (c *CPU) execREV64Vec(inst uint32) error {
	q := (inst >> 30) & 1
	size := (inst >> 22) & 3
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	rev := func(v uint64) uint64 {
		switch size {
		case 0: // REV64, 8B: reverse bytes
			return (v&0xFF)<<56 | (v&0xFF00)<<40 | (v&0xFF0000)<<24 | (v&0xFF000000)<<8 |
				(v>>8)&0xFF000000 | (v>>24)&0xFF0000 | (v>>40)&0xFF00 | (v>>56)&0xFF
		case 1: // REV64, 4H: reverse halfwords
			return (v&0xFFFF)<<48 | ((v>>16)&0xFFFF)<<32 | ((v>>32)&0xFFFF)<<16 | (v >> 48)
		case 2: // REV64, 2S: reverse words
			return (v << 32) | (v >> 32)
		}
		return v
	}

	dstLo := rev(c.Vreg[rn][0])
	var dstHi uint64
	if q != 0 {
		dstHi = rev(c.Vreg[rn][1])
	}
	c.Vreg[rd] = [2]uint64{dstLo, dstHi}
	c.PC += 4
	return nil
}

// FMOV (scalar immediate to SIMD)
func (c *CPU) execFMOVImm(inst uint32) error {
	// ptype := (inst >> 22) & 3
	imm8 := (inst >> 13) & 0xFF
	rd := inst & 0x1F
	val := vfpExpandImm64(imm8)
	c.Vreg[rd] = [2]uint64{val, 0}
	c.PC += 4
	return nil
}

// ============================================================
// SIMD Loads and Stores
// ============================================================

// AdvSIMD three same: 0 Q U 01110 size 1 Rm opcode(5) 1 Rn Rd
func (c *CPU) execAdvSIMD3Same(inst uint32) error {
	q := (inst >> 30) & 1
	u := (inst >> 29) & 1
	size := (inst >> 22) & 3
	rm := (inst >> 16) & 0x1F
	opcode := (inst >> 11) & 0x1F
	rn := (inst >> 5) & 0x1F
	rd := inst & 0x1F

	aLo, aHi := c.Vreg[rn][0], c.Vreg[rn][1]
	bLo, bHi := c.Vreg[rm][0], c.Vreg[rm][1]
	var loR, hiR uint64

	switch opcode {
	case 3: // Logical operations: distinguished by U:size
		switch (u << 2) | size {
		case 0: // U=0, size=00: AND
			loR = aLo & bLo
			hiR = aHi & bHi
		case 1: // U=0, size=01: BIC
			loR = aLo &^ bLo
			hiR = aHi &^ bHi
		case 2: // U=0, size=10: ORR
			loR = aLo | bLo
			hiR = aHi | bHi
		case 3: // U=0, size=11: ORN
			loR = aLo | ^bLo
			hiR = aHi | ^bHi
		case 4: // U=1, size=00: EOR
			loR = aLo ^ bLo
			hiR = aHi ^ bHi
		case 5: // U=1, size=01: BSL
			dLo, dHi := c.Vreg[rd][0], c.Vreg[rd][1]
			loR = (aLo & dLo) | (bLo &^ dLo)
			hiR = (aHi & dHi) | (bHi &^ dHi)
		case 6: // U=1, size=10: BIT
			dLo, dHi := c.Vreg[rd][0], c.Vreg[rd][1]
			loR = (aLo & bLo) | (dLo &^ bLo)
			hiR = (aHi & bHi) | (dHi &^ bHi)
		case 7: // U=1, size=11: BIF
			dLo, dHi := c.Vreg[rd][0], c.Vreg[rd][1]
			loR = (aLo &^ bLo) | (dLo & bLo)
			hiR = (aHi &^ bHi) | (dHi & bHi)
		}
	case 16: // U=0: ADD, U=1: SUB (vector integer)
		loR, hiR = simd3SameArith(aLo, aHi, bLo, bHi, size, u == 1)
	default:
		return fmt.Errorf("unhandled AdvSIMD3Same opcode=%d u=%d inst=0x%08x PC=0x%x", opcode, u, inst, c.PC)
	}

	c.Vreg[rd][0] = loR
	if q != 0 {
		c.Vreg[rd][1] = hiR
	} else {
		c.Vreg[rd][1] = 0
	}
	c.PC += 4
	return nil
}

// simd3SameArith performs element-wise add/sub for given size.
func simd3SameArith(aLo, aHi, bLo, bHi uint64, size uint32, isSub bool) (uint64, uint64) {
	op := func(a, b, mask uint64) uint64 {
		if isSub {
			return (a - b) & mask
		}
		return (a + b) & mask
	}
	var loR, hiR uint64
	switch size {
	case 0: // 8-bit elements
		for i := uint32(0); i < 8; i++ {
			s := i * 8
			loR |= op((aLo>>s)&0xFF, (bLo>>s)&0xFF, 0xFF) << s
			hiR |= op((aHi>>s)&0xFF, (bHi>>s)&0xFF, 0xFF) << s
		}
	case 1: // 16-bit elements
		for i := uint32(0); i < 4; i++ {
			s := i * 16
			loR |= op((aLo>>s)&0xFFFF, (bLo>>s)&0xFFFF, 0xFFFF) << s
			hiR |= op((aHi>>s)&0xFFFF, (bHi>>s)&0xFFFF, 0xFFFF) << s
		}
	case 2: // 32-bit elements
		for i := uint32(0); i < 2; i++ {
			s := i * 32
			loR |= op((aLo>>s)&0xFFFFFFFF, (bLo>>s)&0xFFFFFFFF, 0xFFFFFFFF) << s
			hiR |= op((aHi>>s)&0xFFFFFFFF, (bHi>>s)&0xFFFFFFFF, 0xFFFFFFFF) << s
		}
	case 3: // 64-bit elements
		loR = op(aLo, bLo, ^uint64(0))
		hiR = op(aHi, bHi, ^uint64(0))
	}
	return loR, hiR
}

// simdAccessSize returns (accessBytes, isQuad) for SIMD load/store.
// size=bits[31:30], opc=bits[23:22].
func simdAccessSize(size, opc uint32) (int, bool) {
	switch {
	case size == 0 && opc >= 2:
		return 16, true // Q (128-bit)
	case size == 0:
		return 1, false // B (8-bit)
	case size == 1:
		return 2, false // H (16-bit)
	case size == 2:
		return 4, false // S (32-bit)
	case size == 3:
		return 8, false // D (64-bit)
	}
	return 8, false
}

func (c *CPU) doSIMDStore(addr uint64, rt uint32, accessBytes int) {
	switch accessBytes {
	case 1:
		c.Mem.Write8(addr, uint8(c.Vreg[rt][0]))
	case 2:
		c.Mem.Write16(addr, uint16(c.Vreg[rt][0]))
	case 4:
		c.Mem.Write32(addr, uint32(c.Vreg[rt][0]))
	case 8:
		c.Mem.Write64(addr, c.Vreg[rt][0])
	case 16:
		c.Mem.Write64(addr, c.Vreg[rt][0])
		c.Mem.Write64(addr+8, c.Vreg[rt][1])
	}
}

func (c *CPU) doSIMDLoad(addr uint64, rt uint32, accessBytes int) {
	c.Vreg[rt] = [2]uint64{0, 0}
	switch accessBytes {
	case 1:
		c.Vreg[rt][0] = uint64(c.Mem.Read8(addr))
	case 2:
		c.Vreg[rt][0] = uint64(c.Mem.Read16(addr))
	case 4:
		c.Vreg[rt][0] = uint64(c.Mem.Read32(addr))
	case 8:
		c.Vreg[rt][0] = c.Mem.Read64(addr)
	case 16:
		c.Vreg[rt][0] = c.Mem.Read64(addr)
		c.Vreg[rt][1] = c.Mem.Read64(addr + 8)
	}
}

// STR/LDR SIMD (unsigned offset)
func (c *CPU) execLdStSIMDUnsigned(inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm12 := uint64((inst >> 10) & 0xFFF)
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	accessBytes, _ := simdAccessSize(size, opc)
	offset := imm12 * uint64(accessBytes)
	addr := c.RegSP(rn) + offset

	if opc&1 == 0 { // STR
		c.doSIMDStore(addr, rt, accessBytes)
	} else { // LDR
		c.doSIMDLoad(addr, rt, accessBytes)
	}
	c.PC += 4
	return nil
}

// STR/LDR SIMD (unscaled/pre/post-indexed)
func (c *CPU) execLdStSIMDImm9(inst uint32) error {
	size := (inst >> 30) & 3
	opc := (inst >> 22) & 3
	imm9 := signExtend(uint64((inst>>12)&0x1FF), 9)
	idxType := (inst >> 10) & 3
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	accessBytes, _ := simdAccessSize(size, opc)
	base := c.RegSP(rn)

	var addr uint64
	switch idxType {
	case 0: // Unscaled
		addr = base + imm9
	case 1: // Post-index
		addr = base
		c.SetRegSP(rn, base+imm9)
	case 3: // Pre-index
		addr = base + imm9
		c.SetRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved SIMD ldst idxType=%d", idxType)
	}

	if opc&1 == 0 { // STR
		c.doSIMDStore(addr, rt, accessBytes)
	} else { // LDR
		c.doSIMDLoad(addr, rt, accessBytes)
	}
	c.PC += 4
	return nil
}

// LDP/STP SIMD
func (c *CPU) execLdStPairSIMD(inst uint32) error {
	opc := (inst >> 30) & 3
	pairType := (inst >> 23) & 7
	load := (inst >> 22) & 1
	imm7 := signExtend(uint64((inst>>15)&0x7F), 7)
	rt2 := (inst >> 10) & 0x1F
	rn := (inst >> 5) & 0x1F
	rt := inst & 0x1F

	var scale uint64
	switch opc {
	case 0:
		scale = 4 // 32-bit pairs
	case 1:
		scale = 8 // 64-bit pairs
	case 2:
		scale = 16 // 128-bit pairs
	default:
		return fmt.Errorf("reserved SIMD LDP/STP opc=%d", opc)
	}
	offset := imm7 * scale
	base := c.RegSP(rn)

	var addr uint64
	switch pairType {
	case 1: // Post-index
		addr = base
		c.SetRegSP(rn, base+offset)
	case 2: // Signed offset
		addr = base + offset
	case 3: // Pre-index
		addr = base + offset
		c.SetRegSP(rn, addr)
	default:
		return fmt.Errorf("reserved SIMD LDP/STP type=%d", pairType)
	}

	elemSize := int(scale)
	if load != 0 {
		c.doSIMDLoad(addr, rt, elemSize)
		c.doSIMDLoad(addr+uint64(elemSize), rt2, elemSize)
	} else {
		c.doSIMDStore(addr, rt, elemSize)
		c.doSIMDStore(addr+uint64(elemSize), rt2, elemSize)
	}
	c.PC += 4
	return nil
}

// LDR SIMD literal (PC-relative)
func (c *CPU) execLdrSIMDLiteral(inst uint32) error {
	opc := (inst >> 30) & 3
	imm19 := signExtend(uint64((inst>>5)&0x7FFFF), 19)
	rt := inst & 0x1F
	addr := c.PC + imm19*4

	var accessBytes int
	switch opc {
	case 0:
		accessBytes = 4
	case 1:
		accessBytes = 8
	case 2:
		accessBytes = 16
	}
	c.doSIMDLoad(addr, rt, accessBytes)
	c.PC += 4
	return nil
}
