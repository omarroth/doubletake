package fairplay

const (
	wbMTStateWords     = 624
	wbMTMiddleWord     = 397
	wbMTFirstHalfWords = wbMTStateWords - wbMTMiddleWord
	wbMTLastWord       = wbMTStateWords - 1
	wbMTUpperMask      = uint32(0x80000000)
	wbMTLowerMask      = uint32(0x7fffffff)
	wbMTPostXor        = uint32(0x1ad24274)
	wbMTTemperXor      = uint32(0x13467351)
)

func wbMTWordAddr(stateBase uint64, wordIndex uint32) uint64 {
	return stateBase + uint64(wordIndex)*4
}

func (s *fpState) wbMTMag01(lowBit uint32) uint32 {
	addr := ((s.cpu.sp + 0x98) &^ 0x4) | uint64((lowBit&1)<<2)
	return s.mem.read32(addr)
}

func (s *fpState) wbMTTwistWord(stateBase uint64, wordIndex, sourceIndex uint32) uint32 {
	twistInput := (s.mem.read32(wbMTWordAddr(stateBase, wordIndex)) & wbMTUpperMask) |
		(s.mem.read32(wbMTWordAddr(stateBase, wordIndex+1)) & wbMTLowerMask)
	return s.mem.read32(wbMTWordAddr(stateBase, sourceIndex)) ^
		(twistInput >> 1) ^ s.wbMTMag01(twistInput&1) ^ wbMTPostXor
}

func (s *fpState) wbMTEnterFirstTwist(regs *[31]uint64) {
	dispatchOffset := fpSignExtend(uint64((regs[20]+0x26)&0xffffffff), 32) << 3
	stateBase := s.mem.read64(regs[24]+dispatchOffset) - 0xf

	regs[7] = 0x323e88a7
	regs[8] = fpSignExtend(uint64(s.mem.read32(regs[29]+0xffffffffffffff68)), 32) + 0x1a12cfbe4
	regs[24] = stateBase
	regs[19] = regs[23]
	regs[14] = 0xcdc17759
	regs[15] = 0x19
	regs[16] = 0x1a12d05a0
	regs[17] = 0xff6f737d
	regs[0] = 0xddf6eead
	regs[1] = 0xbbeddd58
	regs[2] = 0x908c83
	regs[3] = 0x22091153
	regs[4] = 0xfc8c156c
	regs[5] = 0x7e460ab7
	regs[6] = 0x25f1472f
	regs[20] = 0x1a12d0620
	s.cpu.pc = regs[8]
}

func (s *fpState) wbMTEnterSecondTwist(regs *[31]uint64) {
	regs[9] = uint64(s.mem.read32(regs[24] + 0x38c))
	regs[10] = 0x5109e6bc
	regs[17] = 0x5109e6bc
	regs[0] = 0xffffffffaef61944
	regs[1] = 0x15f5f0b8
	regs[2] = 0x5056c9b4
	regs[3] = 0xffed5bff
	regs[4] = 0xffdab7fc
	regs[5] = 0x12a401
	regs[6] = 0x63e0245c
	regs[7] = 0x31f0122e
	regs[19] = 0x22a4b63
	s.cpu.pc = 0x1a12d0620
}

func (s *fpState) wbMTFirstTwistStep(regs *[31]uint64) {
	stateBase := regs[24]
	wordIndex := uint32(regs[9])
	twisted := s.wbMTTwistWord(stateBase, wordIndex, wordIndex+wbMTMiddleWord)

	regs[19] = (regs[8] - 0x19) & 0xffffffff
	regs[8] = uint64(wordIndex) << 2
	regs[7] = (regs[7] + 1) & 0xffffffff
	regs[9] = uint64(twisted)
	s.mem.write32(wbMTWordAddr(stateBase, wordIndex), twisted)
}

func (s *fpState) wbMTSecondTwistStep(regs *[31]uint64) {
	stateBase := regs[24]
	wordIndex := uint32((regs[10]+regs[0])&0xffffffff) + wbMTFirstHalfWords
	nextWord := s.mem.read32(wbMTWordAddr(stateBase, wordIndex+1))
	twisted := s.wbMTTwistWord(stateBase, wordIndex, wordIndex-wbMTFirstHalfWords)
	s.mem.write32(wbMTWordAddr(stateBase, wordIndex), twisted)

	regs[9] = uint64(nextWord)
	regs[10]++
	lastStep := regs[10] == regs[17]+0x18c
	if lastStep {
		regs[13] = (regs[8] + 1) & 0xffffffff
		regs[8] = (regs[8] + 0x11) & 0xffffffff
	} else {
		regs[13] = regs[8] & 0xffffffff
		regs[8] &= 0xffffffff
	}

	dispatchIndex := (regs[13] + 0xd) & 0xffffffff
	dispatchOffset := fpSignExtend(uint64(dispatchIndex), 32) << 2
	regs[11] = fpSignExtend(uint64(s.mem.read32(regs[25]+dispatchOffset)), 32) + regs[20]
	s.cpu.pc = regs[11]
}

func (s *fpState) wbMTTwistTail(regs *[31]uint64) {
	stateBase := regs[24]
	twistInput := (s.mem.read32(wbMTWordAddr(stateBase, wbMTLastWord)) & wbMTUpperMask) |
		(s.mem.read32(wbMTWordAddr(stateBase, 0)) & wbMTLowerMask)
	twisted := s.mem.read32(wbMTWordAddr(stateBase, wbMTMiddleWord-1)) ^
		(twistInput >> 1) ^ s.wbMTMag01(twistInput&1) ^ wbMTPostXor
	s.mem.write32(wbMTWordAddr(stateBase, wbMTLastWord), twisted)
}

func wbMTTemperWord(word uint32) uint32 {
	word ^= word >> 11
	word ^= (word << 7) & 0x9d2c5680
	word ^= (word << 15) & 0xefc60000
	word ^= word >> 18
	return word ^ wbMTTemperXor
}

func (s *fpState) wbMTNextTemperedWord(regs *[31]uint64) {
	stateBase := regs[24]
	wordIndex := s.mem.read32(s.cpu.sp + 0x94)
	nextWordIndex := wordIndex + 1
	s.mem.write32(s.cpu.sp+0x94, nextWordIndex)

	word := s.mem.read32(wbMTWordAddr(stateBase, wordIndex))
	counterAddr := s.mem.read64(s.cpu.sp + 0x58)
	s.mem.write32(counterAddr, nextWordIndex)

	regs[9] = uint64(word)
	regs[10] = uint64(nextWordIndex)
	regs[11] = counterAddr
	regs[19] = uint64(wbMTTemperWord(word))
	regs[24] = s.mem.read64(s.cpu.sp + 0x60)
}
