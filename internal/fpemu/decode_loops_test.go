//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

// TestDecodeHotLoops decodes the exact ARM64 instructions in the two hottest
// inner loops and translates them to equivalent Go operations.
func TestDecodeHotLoops(t *testing.T) {
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

	// Dump the instruction bytes for the two hottest loop bodies
	// Loop 1: 0x1a12d052c - 0x1a12d05c0 (38 instructions, 7491 iters)
	// Loop 2: 0x1a12d0620 - 0x1a12d06a8 (35 instructions, 13035 iters)
	t.Log("=== Loop 1: 0x1a12d052c - 0x1a12d05c0 (38 inst, 7491 iters) ===")
	for pc := uint64(0x1a12d052c); pc <= 0x1a12d05c0; pc += 4 {
		inst := emu.Mem().Read32(pc)
		t.Logf("  0x%x: %08x  %s", pc, inst, decodeARM64(inst, pc))
	}

	t.Log("\n=== Loop 2: 0x1a12d0620 - 0x1a12d06a8 (35 inst, 13035 iters) ===")
	for pc := uint64(0x1a12d0620); pc <= 0x1a12d06a8; pc += 4 {
		inst := emu.Mem().Read32(pc)
		t.Logf("  0x%x: %08x  %s", pc, inst, decodeARM64(inst, pc))
	}

	// Also dump the code around the main loop header to understand the setup
	t.Log("\n=== Code around main loop header 0x1a12cfba0 ===")
	for pc := uint64(0x1a12cfb70); pc <= 0x1a12cfbe0; pc += 4 {
		inst := emu.Mem().Read32(pc)
		t.Logf("  0x%x: %08x  %s", pc, inst, decodeARM64(inst, pc))
	}

	// Now run a traced exchange to capture register state at loop entries
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

	// Track registers at the entry to each hot loop
	type loopEntry struct {
		x  [31]uint64
		sp uint64
	}
	var loop1Entries, loop2Entries []loopEntry

	emu.cpu.Trace = func(pc uint64, inst uint32) {
		if pc == 0x1a12d052c && len(loop1Entries) < 5 {
			var e loopEntry
			e.x = emu.cpu.X
			e.sp = emu.cpu.SP
			loop1Entries = append(loop1Entries, e)
		}
		if pc == 0x1a12d0620 && len(loop2Entries) < 5 {
			var e loopEntry
			e.x = emu.cpu.X
			e.sp = emu.cpu.SP
			loop2Entries = append(loop2Entries, e)
		}
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
	t.Logf("\nsig: %s", hex.EncodeToString(payload[132:]))

	t.Log("\n=== Loop 1 entry registers (first 3 iterations) ===")
	for i, e := range loop1Entries {
		if i >= 3 {
			break
		}
		t.Logf("Iter %d:", i)
		t.Logf("  X0=%016x X1=%016x X2=%016x X3=%016x", e.x[0], e.x[1], e.x[2], e.x[3])
		t.Logf("  X4=%016x X5=%016x X6=%016x X7=%016x", e.x[4], e.x[5], e.x[6], e.x[7])
		t.Logf("  X8=%016x X9=%016x X10=%016x X11=%016x", e.x[8], e.x[9], e.x[10], e.x[11])
		t.Logf("  X12=%016x X13=%016x X14=%016x X15=%016x", e.x[12], e.x[13], e.x[14], e.x[15])
		t.Logf("  X16=%016x X17=%016x SP=%016x", e.x[16], e.x[17], e.sp)
	}

	t.Log("\n=== Loop 2 entry registers (first 3 iterations) ===")
	for i, e := range loop2Entries {
		if i >= 3 {
			break
		}
		t.Logf("Iter %d:", i)
		t.Logf("  X0=%016x X1=%016x X2=%016x X3=%016x", e.x[0], e.x[1], e.x[2], e.x[3])
		t.Logf("  X4=%016x X5=%016x X6=%016x X7=%016x", e.x[4], e.x[5], e.x[6], e.x[7])
		t.Logf("  X8=%016x X9=%016x X10=%016x X11=%016x", e.x[8], e.x[9], e.x[10], e.x[11])
		t.Logf("  X12=%016x X13=%016x X14=%016x X15=%016x", e.x[12], e.x[13], e.x[14], e.x[15])
		t.Logf("  X16=%016x X17=%016x SP=%016x", e.x[16], e.x[17], e.sp)
	}

	_ = snap
	_ = hp
}

// decodeARM64 provides a human-readable disassembly of one ARM64 instruction.
func decodeARM64(inst uint32, pc uint64) string {
	// BRK
	if inst&0xFFE0001F == 0xD4200000 {
		imm := (inst >> 5) & 0xFFFF
		return spr("BRK #%d", imm)
	}

	op0 := (inst >> 25) & 0xF

	switch {
	case op0>>1 == 4: // 100x: DP Immediate
		return decodeDPImm(inst, pc)
	case op0>>1 == 5: // 101x: Branches
		return decodeBranch(inst, pc)
	case op0&5 == 4: // x1x0: Load/Store
		return decodeLS(inst, pc)
	case op0&7 == 5: // x101: DP Register
		return decodeDPReg(inst)
	case op0&7 == 7: // x111: SIMD/FP
		return spr("SIMD/FP %08x", inst)
	}
	return spr("??? %08x", inst)
}

func spr(format string, a ...interface{}) string {
	return sprf(format, a...)
}

func sprf(format string, a ...interface{}) string {
	return sprintf(format, a...)
}

var sprintf = func(format string, a ...interface{}) string {
	buf := make([]byte, 0, 64)
	// Simple sprintf replacement
	i := 0
	argIdx := 0
	for i < len(format) {
		if format[i] == '%' && i+1 < len(format) {
			i++
			width := 0
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				width = width*10 + int(format[i]-'0')
				i++
			}
			if i < len(format) {
				switch format[i] {
				case 'd':
					if argIdx < len(a) {
						buf = appendDec(buf, a[argIdx])
						argIdx++
					}
				case 'x':
					if argIdx < len(a) {
						buf = appendHex(buf, a[argIdx], width)
						argIdx++
					}
				case 's':
					if argIdx < len(a) {
						buf = append(buf, a[argIdx].(string)...)
						argIdx++
					}
				}
				i++
			}
		} else {
			buf = append(buf, format[i])
			i++
		}
	}
	return string(buf)
}

func appendDec(buf []byte, v interface{}) []byte {
	switch n := v.(type) {
	case int:
		return appendInt(buf, int64(n))
	case int64:
		return appendInt(buf, n)
	case uint32:
		return appendInt(buf, int64(n))
	case uint64:
		return appendInt(buf, int64(n))
	}
	return buf
}

func appendInt(buf []byte, v int64) []byte {
	if v < 0 {
		buf = append(buf, '-')
		v = -v
	}
	if v == 0 {
		return append(buf, '0')
	}
	tmp := make([]byte, 0, 20)
	for v > 0 {
		tmp = append(tmp, byte('0'+v%10))
		v /= 10
	}
	for i := len(tmp) - 1; i >= 0; i-- {
		buf = append(buf, tmp[i])
	}
	return buf
}

func appendHex(buf []byte, v interface{}, width int) []byte {
	var n uint64
	switch x := v.(type) {
	case int:
		n = uint64(x)
	case int64:
		n = uint64(x)
	case uint32:
		n = uint64(x)
	case uint64:
		n = x
	}
	hex := "0123456789abcdef"
	tmp := make([]byte, 0, 16)
	if n == 0 {
		tmp = append(tmp, '0')
	}
	for n > 0 {
		tmp = append(tmp, hex[n&0xF])
		n >>= 4
	}
	for len(tmp) < width {
		tmp = append(tmp, '0')
	}
	for i := len(tmp) - 1; i >= 0; i-- {
		buf = append(buf, tmp[i])
	}
	return buf
}

func regName(n uint32, sf bool) string {
	if n == 31 {
		if sf {
			return "XZR"
		}
		return "WZR"
	}
	if sf {
		return spr("X%d", int(n))
	}
	return spr("W%d", int(n))
}

func regNameSP(n uint32, sf bool) string {
	if n == 31 {
		return "SP"
	}
	return regName(n, sf)
}

func decodeDPImm(inst uint32, pc uint64) string {
	subop := (inst >> 23) & 0x7
	sf := inst>>31 != 0
	rd := inst & 0x1F
	rn := (inst >> 5) & 0x1F

	switch subop {
	case 0, 1: // ADR/ADRP
		immhi := (inst >> 5) & 0x7FFFF
		immlo := (inst >> 29) & 0x3
		imm := int64(signExtend64(uint64(immhi<<2|immlo), 21))
		if inst>>31 != 0 {
			target := (pc &^ 0xFFF) + uint64(imm<<12)
			return spr("ADRP %s, 0x%x", regName(rd, true), target)
		}
		target := pc + uint64(imm)
		return spr("ADR %s, 0x%x", regName(rd, true), target)

	case 2: // ADD/SUB immediate
		op := (inst >> 30) & 1
		setf := (inst >> 29) & 1
		shift := (inst >> 22) & 3
		imm12 := (inst >> 10) & 0xFFF
		if shift == 1 {
			imm12 <<= 12
		}
		opname := "ADD"
		if op != 0 {
			opname = "SUB"
		}
		if setf != 0 {
			opname += "S"
		}
		return spr("%s %s, %s, #0x%x", opname, regNameSP(rd, sf), regNameSP(rn, sf), imm12)

	case 4: // Logical immediate
		opc := (inst >> 29) & 3
		opnames := [4]string{"AND", "ORR", "EOR", "ANDS"}
		N := (inst >> 22) & 1
		immr := (inst >> 16) & 0x3F
		imms := (inst >> 10) & 0x3F
		val := decodeBitmask(N, imms, immr, sf)
		return spr("%s %s, %s, #0x%x", opnames[opc], regNameSP(rd, sf), regName(rn, sf), val)

	case 5: // Move wide
		opc := (inst >> 29) & 3
		hw := (inst >> 21) & 3
		imm16 := (inst >> 5) & 0xFFFF
		shift := hw * 16
		opnames := map[uint32]string{0: "MOVN", 2: "MOVZ", 3: "MOVK"}
		return spr("%s %s, #0x%x, LSL #%d", opnames[opc], regName(rd, sf), imm16, shift)

	case 6: // Bitfield
		opc := (inst >> 29) & 3
		immr := (inst >> 16) & 0x3F
		imms := (inst >> 10) & 0x3F
		opnames := [4]string{"SBFM", "BFM", "UBFM", "?"}
		// Common aliases
		if opc == 2 { // UBFM
			if imms == 0x1F && !sf { // LSR Wd
				return spr("LSR %s, %s, #%d", regName(rd, sf), regName(rn, sf), immr)
			}
			if imms == 0x3F && sf { // LSR Xd
				return spr("LSR %s, %s, #%d", regName(rd, sf), regName(rn, sf), immr)
			}
			bits := uint32(31)
			if sf {
				bits = 63
			}
			if immr == 0 && imms < bits {
				return spr("UXTB/H %s, %s, #%d", regName(rd, sf), regName(rn, sf), imms+1)
			}
			if imms+1 == immr {
				return spr("LSL %s, %s, #%d", regName(rd, sf), regName(rn, sf), bits-imms)
			}
			if imms < immr {
				width := imms + 1
				lsb := bits + 1 - immr
				return spr("UBFIZ %s, %s, #%d, #%d", regName(rd, sf), regName(rn, sf), lsb, width)
			}
			return spr("UBFX %s, %s, #%d, #%d", regName(rd, sf), regName(rn, sf), immr, imms-immr+1)
		}
		if opc == 1 { // BFM aliases
			if imms < immr {
				width := imms + 1
				bits := uint32(31)
				if sf {
					bits = 63
				}
				lsb := bits + 1 - immr
				return spr("BFI %s, %s, #%d, #%d", regName(rd, sf), regName(rn, sf), lsb, width)
			}
			return spr("BFXIL %s, %s, #%d, #%d", regName(rd, sf), regName(rn, sf), immr, imms-immr+1)
		}
		return spr("%s %s, %s, #%d, #%d", opnames[opc], regName(rd, sf), regName(rn, sf), immr, imms)

	case 7: // EXTR
		rm := (inst >> 16) & 0x1F
		imms := (inst >> 10) & 0x3F
		if rn == rm {
			return spr("ROR %s, %s, #%d", regName(rd, sf), regName(rn, sf), imms)
		}
		return spr("EXTR %s, %s, %s, #%d", regName(rd, sf), regName(rn, sf), regName(rm, sf), imms)
	}
	return spr("DPImm? %08x", inst)
}

func decodeBranch(inst uint32, pc uint64) string {
	if inst>>26 == 0x05 { // B
		imm := signExtend64(uint64(inst&0x3FFFFFF), 26) << 2
		return spr("B 0x%x", pc+imm)
	}
	if inst>>26 == 0x25 { // BL
		imm := signExtend64(uint64(inst&0x3FFFFFF), 26) << 2
		return spr("BL 0x%x", pc+imm)
	}
	if inst>>24&0xFF == 0x54 { // B.cond
		imm := signExtend64(uint64((inst>>5)&0x7FFFF), 19) << 2
		cond := inst & 0xF
		condNames := [16]string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}
		return spr("B.%s 0x%x", condNames[cond], pc+imm)
	}
	if inst>>25&0x7F == 0x34 { // CBZ
		sf := inst >> 31
		op := (inst >> 24) & 1
		imm := signExtend64(uint64((inst>>5)&0x7FFFF), 19) << 2
		rt := inst & 0x1F
		opn := "CBZ"
		if op != 0 {
			opn = "CBNZ"
		}
		return spr("%s %s, 0x%x", opn, regName(rt, sf != 0), pc+imm)
	}
	if inst>>25&0x7F == 0x35 { // TBZ/TBNZ
		op := (inst >> 24) & 1
		b5 := (inst >> 31) & 1
		b40 := (inst >> 19) & 0x1F
		bit := b5<<5 | b40
		imm := signExtend64(uint64((inst>>5)&0x3FFF), 14) << 2
		rt := inst & 0x1F
		opn := "TBZ"
		if op != 0 {
			opn = "TBNZ"
		}
		return spr("%s X%d, #%d, 0x%x", opn, rt, bit, pc+imm)
	}
	if inst>>10 == 0x3587C0 { // BR
		rn := (inst >> 5) & 0x1F
		return spr("BR X%d", rn)
	}
	if inst>>10 == 0x358FC0 { // BLR
		rn := (inst >> 5) & 0x1F
		return spr("BLR X%d", rn)
	}
	if inst>>10 == 0x3597C0 { // RET
		rn := (inst >> 5) & 0x1F
		return spr("RET X%d", rn)
	}
	return spr("BRANCH? %08x", inst)
}

func decodeLS(inst uint32, pc uint64) string {
	size := inst >> 30
	v := (inst >> 26) & 1
	opc := (inst >> 22) & 3

	// Size in bytes: 1<<size for integer, more complex for FP
	szBytes := 1 << size
	if v != 0 {
		szBytes = 1 << ((opc>>1)<<2 | size)
	}

	signed := ""
	regSz := size >= 2 // 32-bit or 64-bit
	loadStore := "LDR"
	if opc == 0 {
		loadStore = "STR"
	}
	if opc == 2 {
		loadStore = "LDR"
		signed = "S"
	}
	if opc == 3 {
		loadStore = "LDR"
		signed = "S"
		regSz = false // sign-extend to 32-bit
	}

	rd := inst & 0x1F

	bits_2124 := (inst >> 21) & 0xF
	bits_10 := (inst >> 10) & 3

	if inst>>27&0x7 == 7 && (inst>>24)&3 == 1 { // unsigned offset
		imm12 := (inst >> 10) & 0xFFF
		rn := (inst >> 5) & 0x1F
		offset := uint64(imm12) * uint64(szBytes)
		if v != 0 {
			return spr("%s%s Q/D/S%d, [%s, #0x%x]", loadStore, signed, rd, regNameSP(rn, true), offset)
		}
		return spr("%s%s %s, [%s, #0x%x]", loadStore, signed, regName(rd, regSz), regNameSP(rn, true), offset)
	}

	if bits_2124 == 1 && bits_10 == 2 { // register offset
		rn := (inst >> 5) & 0x1F
		rm := (inst >> 16) & 0x1F
		option := (inst >> 13) & 7
		s := (inst >> 12) & 1
		extName := [8]string{"UXTB", "UXTH", "UXTW", "LSL", "SXTB", "SXTH", "SXTW", "SXTX"}
		ext := extName[option]
		shift := uint32(0)
		if s != 0 {
			shift = size
		}
		if v != 0 {
			return spr("%s%s Q/D/S%d, [%s, %s, %s #%d]", loadStore, signed, rd, regNameSP(rn, true), regName(rm, option == 3 || option == 7), ext, shift)
		}
		return spr("%s%s %s, [%s, %s, %s #%d]", loadStore, signed, regName(rd, regSz), regNameSP(rn, true), regName(rm, option == 3 || option == 7), ext, shift)
	}

	if bits_10 == 0 && bits_2124&1 == 0 { // unscaled imm
		imm9 := signExtend64(uint64((inst>>12)&0x1FF), 9)
		rn := (inst >> 5) & 0x1F
		return spr("%s%s %s, [%s, #%d] (unscaled)", loadStore, signed, regName(rd, regSz), regNameSP(rn, true), int64(imm9))
	}

	if bits_10 == 1 { // post-index
		imm9 := signExtend64(uint64((inst>>12)&0x1FF), 9)
		rn := (inst >> 5) & 0x1F
		return spr("%s%s %s, [%s], #%d", loadStore, signed, regName(rd, regSz), regNameSP(rn, true), int64(imm9))
	}

	if bits_10 == 3 { // pre-index
		imm9 := signExtend64(uint64((inst>>12)&0x1FF), 9)
		rn := (inst >> 5) & 0x1F
		return spr("%s%s %s, [%s, #%d]!", loadStore, signed, regName(rd, regSz), regNameSP(rn, true), int64(imm9))
	}

	// LDP/STP
	if (inst>>25)&0xF == 5 { // Load/store pair
		opc2 := (inst >> 30) & 3
		imm7 := signExtend64(uint64((inst>>15)&0x7F), 7)
		rt2 := (inst >> 10) & 0x1F
		rn := (inst >> 5) & 0x1F
		rt := inst & 0x1F
		sf2 := opc2 >= 2
		sz := 4
		if opc2 >= 2 {
			sz = 8
		}
		offset := int64(imm7) * int64(sz)
		ldst := "STP"
		if (inst>>22)&1 != 0 {
			ldst = "LDP"
		}
		return spr("%s %s, %s, [%s, #%d]", ldst, regName(rt, sf2), regName(rt2, sf2), regNameSP(rn, true), offset)
	}

	return spr("LS? sz=%d v=%d opc=%d %08x", size, v, opc, inst)
}

func decodeDPReg(inst uint32) string {
	sf := inst>>31 != 0
	rd := inst & 0x1F
	rn := (inst >> 5) & 0x1F
	rm := (inst >> 16) & 0x1F

	bits_2128 := (inst >> 21) & 0xFF
	bits_2124 := (inst >> 21) & 0xF
	bits_1015 := (inst >> 10) & 0x3F

	// Logical shifted register
	if bits_2128>>3 == 0x0A>>3 { // 0000_101x
		opc := (inst >> 29) & 3
		shift := (inst >> 22) & 3
		n := (inst >> 21) & 1
		imm6 := (inst >> 10) & 0x3F
		opnames := [4]string{"AND", "ORR", "EOR", "ANDS"}
		shiftNames := [4]string{"LSL", "LSR", "ASR", "ROR"}
		not := ""
		if n != 0 {
			not = "N"
			opnames = [4]string{"BIC", "ORN", "EON", "BICS"}
		}
		if imm6 == 0 {
			// MOV alias: ORR Rd, XZR, Rm
			if opc == 1 && n == 0 && rn == 31 {
				return spr("MOV %s, %s", regName(rd, sf), regName(rm, sf))
			}
			// MVN alias: ORN Rd, XZR, Rm
			if opc == 1 && n != 0 && rn == 31 {
				return spr("MVN %s, %s", regName(rd, sf), regName(rm, sf))
			}
			// TST alias: ANDS XZR, Xn, Xm
			if opc == 3 && rd == 31 {
				return spr("TST %s, %s", regName(rn, sf), regName(rm, sf))
			}
			return spr("%s%s %s, %s, %s", opnames[opc], not, regName(rd, sf), regName(rn, sf), regName(rm, sf))
		}
		return spr("%s%s %s, %s, %s, %s #%d", opnames[opc], not, regName(rd, sf), regName(rn, sf), regName(rm, sf), shiftNames[shift], imm6)
	}

	// Add/sub shifted register
	if bits_2128>>3 == 0x0B>>3 { // 0000_011x
		op := (inst >> 30) & 1
		setf := (inst >> 29) & 1
		shift := (inst >> 22) & 3
		imm6 := (inst >> 10) & 0x3F
		opn := "ADD"
		if op != 0 {
			opn = "SUB"
		}
		if setf != 0 {
			opn += "S"
		}
		// NEG alias: SUB Rd, XZR, Rm
		if op != 0 && rn == 31 && imm6 == 0 {
			if setf != 0 {
				return spr("NEGS %s, %s", regName(rd, sf), regName(rm, sf))
			}
			return spr("NEG %s, %s", regName(rd, sf), regName(rm, sf))
		}
		// CMP alias: SUBS XZR, Xn, Xm
		if op != 0 && setf != 0 && rd == 31 {
			return spr("CMP %s, %s", regName(rn, sf), regName(rm, sf))
		}
		if imm6 == 0 {
			return spr("%s %s, %s, %s", opn, regName(rd, sf), regName(rn, sf), regName(rm, sf))
		}
		shiftNames := [4]string{"LSL", "LSR", "ASR", "?"}
		return spr("%s %s, %s, %s, %s #%d", opn, regName(rd, sf), regName(rn, sf), regName(rm, sf), shiftNames[shift], imm6)
	}

	// Conditional select
	if bits_2124 == 4 { // x_0_0_11010100
		cond := (inst >> 12) & 0xF
		op2 := (bits_1015) & 1
		op := (inst >> 30) & 1
		condNames := [16]string{"EQ", "NE", "CS", "CC", "MI", "PL", "VS", "VC", "HI", "LS", "GE", "LT", "GT", "LE", "AL", "NV"}
		opnames := [4]string{"CSEL", "CSINC", "CSINV", "CSNEG"}
		idx := op*2 + op2
		// CINC alias: CSINC Rd, Rn, Rn, invert(cond)
		if idx == 1 && rn == rm && cond != 14 && cond != 15 {
			return spr("CINC %s, %s, %s", regName(rd, sf), regName(rn, sf), condNames[cond^1])
		}
		return spr("%s %s, %s, %s, %s", opnames[idx], regName(rd, sf), regName(rn, sf), regName(rm, sf), condNames[cond])
	}

	// Data-processing (3 source): MADD/MSUB
	if bits_2128 == 0x1B || bits_2128 == 0x9B { // MADD W or X
		ra := (inst >> 10) & 0x1F
		o0 := (inst >> 15) & 1
		if o0 == 0 {
			if ra == 31 {
				return spr("MUL %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf))
			}
			return spr("MADD %s, %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf), regName(ra, sf))
		}
		return spr("MSUB %s, %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf), regName(ra, sf))
	}

	// Data processing (2 source)
	if bits_2128 == 0xD6 || bits_2128 == 0x56 {
		opcode := (inst >> 10) & 0x3F
		switch opcode {
		case 2:
			return spr("UDIV %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf))
		case 3:
			return spr("SDIV %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf))
		case 8:
			return spr("LSLV %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf))
		case 9:
			return spr("LSRV %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf))
		case 10:
			return spr("ASRV %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf))
		case 11:
			return spr("RORV %s, %s, %s", regName(rd, sf), regName(rn, sf), regName(rm, sf))
		}
	}

	// Data processing (1 source)
	if bits_2128 == 0xD6 && (inst>>29)&3 == 1 {
		opcode := (inst >> 10) & 0x3F
		switch opcode {
		case 0:
			return spr("RBIT %s, %s", regName(rd, sf), regName(rn, sf))
		case 1:
			return spr("REV16 %s, %s", regName(rd, sf), regName(rn, sf))
		case 2:
			return spr("REV %s, %s", regName(rd, sf), regName(rn, sf))
		case 4:
			return spr("CLZ %s, %s", regName(rd, sf), regName(rn, sf))
		}
	}

	return spr("DPR? %08x bits2128=%x b1015=%x", inst, bits_2128, bits_1015)
}

func signExtend64(val uint64, bits uint32) uint64 {
	if val&(1<<(bits-1)) != 0 {
		return val | (^uint64(0) << bits)
	}
	return val
}

func decodeBitmask(N, imms, immr uint32, sf bool) uint64 {
	// Simplified bitmask decoder
	var size uint32
	if N != 0 {
		size = 64
	} else {
		size = 32
		for i := uint32(5); i > 0; i-- {
			if imms&(1<<i) == 0 {
				size = 1 << i
				break
			}
		}
	}
	mask := uint32(size - 1)
	s := imms & mask
	r := immr & mask
	ones := (uint64(1) << (s + 1)) - 1
	// Rotate right
	result := (ones >> r) | (ones << (size - r))
	result &= (uint64(1) << size) - 1
	if !sf {
		result &= 0xFFFFFFFF
	} else {
		// Replicate
		for rep := size; rep < 64; rep *= 2 {
			result |= result << rep
		}
	}
	return result
}
