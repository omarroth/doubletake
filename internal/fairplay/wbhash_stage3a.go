package fairplay

const (
	wbHashRingInitStop      = uint64(0xd0)
	wbHashRingInitXor       = uint32(0xf4)
	wbHashRingInitCarryMask = uint32(0xe8)
	wbHashRingInitAdd       = uint32(0x1c)

	wbHashRingLen       = 210
	wbHashRingReadBias  = uint32(0x10)
	wbHashRingMixXor    = uint32(0x97)
	wbHashRingCarryMask = uint32(0x2e)
	wbHashRingMixAdd    = uint32(0x79)
	wbHashRingLastStep  = uint32(0x347)
)

func wbHashModU32(value, divisor uint32) uint32 {
	if divisor == 0 {
		return value
	}
	return value % divisor
}

func wbHashRingInitByte(value byte) (uint32, uint32) {
	mixed := uint32(value) ^ wbHashRingInitXor
	return mixed, mixed + (wbHashRingInitCarryMask & (uint32(value) << 1)) + wbHashRingInitAdd
}

func (s *fpState) wbHashRingInitPair(regs *[31]uint64) {
	sourceBase := s.mem.read64(regs[19] + 0x10)
	counter := uint32(regs[9])
	divisor := uint32(regs[10])

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[9], ^wbHashRingInitStop, 1)
	lastPair := boolU64(s.cpu.z)
	regs[0] = (regs[21] + lastPair) & 0xffffffff

	firstXor, first := wbHashRingInitByte(s.mem.read8(sourceBase + uint64(wbHashModU32(counter, divisor))))
	secondXor, second := wbHashRingInitByte(s.mem.read8(sourceBase + uint64(wbHashModU32(counter+1, divisor))))
	dst := regs[11] + regs[9]
	s.mem.write8(dst, byte(first))
	s.mem.write8(dst+1, byte(second))

	regs[1] = uint64(firstXor)
	regs[2] = uint64(secondXor)
	regs[16] = dst
	regs[17] = uint64(first)
	regs[9] += 2
	regs[21] = (((lastPair - ((lastPair << 2) & 0xffffffff)) & 0xffffffff) + regs[21]) & 0xffffffff

	dispatchIndex := (regs[0] - 2) & 0xffffffff
	dispatchOffset := fpSignExtend(dispatchIndex, 32) << 2
	regs[15] = fpSignExtend(uint64(s.mem.read32(regs[8]+dispatchOffset)), 32) + regs[14]
	s.cpu.pc = regs[15]
}

func wbHashRingIndex(counter uint32) uint64 {
	return uint64(counter % wbHashRingLen)
}

func (s *fpState) wbHashRingLoadAdjusted(base uint64, counter uint32) uint32 {
	return uint32(s.mem.read8(base+wbHashRingIndex(counter))) - wbHashRingReadBias
}

func wbHashRingSpread(value uint32, left uint) uint32 {
	lowMask := uint32((1 << left) - 1)
	spreadMask := uint32((1 << (8 + left)) - 1)
	return ((value >> (8 - left)) & lowMask) | (((value & 0xff) << left) &^ lowMask & spreadMask)
}

func (s *fpState) wbHashRingMixByte(base uint64, counter uint32) byte {
	mixed := wbHashRingSpread(s.wbHashRingLoadAdjusted(base, counter-13), 3) ^
		s.wbHashRingLoadAdjusted(base, counter)
	mixed += wbHashRingSpread(s.wbHashRingLoadAdjusted(base, counter-57), 5)
	mixed -= wbHashRingSpread(s.wbHashRingLoadAdjusted(base, counter-155), 7)
	mixed = (mixed ^ wbHashRingMixXor) + (wbHashRingCarryMask & (mixed << 1)) + wbHashRingMixAdd
	return byte(mixed)
}

func (s *fpState) wbHashRingStep(regs *[31]uint64) {
	counter := uint32(regs[9])
	s.mem.write8(regs[14]+wbHashRingIndex(counter), s.wbHashRingMixByte(regs[14], counter))

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(counter, ^wbHashRingLastStep, 1)
	lastStep := boolU64(s.cpu.z)
	regs[1] = (regs[11] + lastStep) & 0xffffffff
	regs[11] = ((regs[11] & 0xffffffff) - ((lastStep << 3) & 0xffffffff)) & 0xffffffff

	dispatchOffset := fpSignExtend(uint64(regs[1]&0xffffffff), 32) << 2
	regs[0] = fpSignExtend(uint64(s.mem.read32(regs[8]+dispatchOffset)), 32) + regs[17]
	regs[9] = (uint64(counter) + 1) & 0xffffffff
	s.cpu.pc = regs[0]
}
