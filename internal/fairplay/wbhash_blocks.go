package fairplay

const (
	wbHashXor16DestBias      = uint64(0x10)
	wbHashXor16StackPC       = uint64(0x1a12c2880)
	wbHashXor16ContinuePC    = uint64(0x1a12c21b0)
	wbHashLookupRoundPC      = uint64(0x1a12c224c)
	wbHashLookupRoundSeed    = uint64(0x411b77c8)
	wbHashLookupRoundBase    = uint64(0x232e78def79c7fd8)
	wbHashLookupLayerBias    = uint64(0x24befdda)
	wbHashLookupReturnPC     = uint64(0x1a12c2880)
	wbHashDispatchTablePC    = uint64(0x1a12c295c)
	wbHashDispatchSeed       = uint64(0x275496b2)
	wbHashDispatchMul        = uint64(0x53b34449)
	wbHashDispatchBase       = uint64(0x1aeab68f0)
	wbHashStackGuardAddr     = uint64(0x30000000)
	wbHashStackGuardValue    = uint64(0xbebafecaefbeadde)
	wbHashPointerDispatch    = uint64(0x1a12c28d8)
	wbHashCommitSeed         = uint64(0x3cd610a)
	wbHashVectorMixPC        = uint64(0x1a12c2b10)
	wbHashVectorFillPC       = uint64(0x1a12c2c6c)
	wbHashFinalVectorPC      = uint64(0x1a12c2da8)
	wbHashSmallCodeTablePC   = uint64(0x1a12c0118)
	wbHashEncodedWordAPC     = uint64(0x1a12c30a0)
	wbHashEncodedWordATailPC = uint64(0x1a12ae8b4)
	wbHashEncodedWordADonePC = uint64(0x1a12ae8e4)
	wbHashEncodedWordBPC     = uint64(0x1a12c30f0)
	wbHashEncodedWordBTailPC = uint64(0x1a12d427c)
	wbHashEncodedWordBDonePC = uint64(0x1a12d42b4)
	wbHashEncodedWordCPC     = uint64(0x1a12c58b4)
	wbHashEncodedWordCTailA  = uint64(0x1a12a62d4)
	wbHashEncodedWordCDoneA  = uint64(0x1a12a630c)
	wbHashEncodedWordCTailB  = uint64(0x1a12d6c98)
	wbHashEncodedWordCDoneB  = uint64(0x1a12d6cd0)
)

func (s *fpState) wbHashCopyStaticD3B8CWords(regs *[31]uint64) {
	for index, word := range wbStaticD3B8CWords {
		s.cpu.vreg[0] = [2]uint64{word, 0}
		s.mem.write64(regs[21]+0x18+uint64(index)*8, s.cpu.vreg[0][0])
	}
}

func (s *fpState) wbHashXor16IntoNextBlock(regs *[31]uint64) {
	s.mem.write32(s.cpu.sp+0x110, uint32(regs[16]))
	regs[13] = regs[10] + wbHashXor16DestBias
	regs[8] = (regs[24] - 1) & 0xffffffff

	for offset := uint64(0); offset < 15; offset++ {
		regs[12] = uint64(s.mem.read8(regs[9] + offset))
		regs[11] = (regs[12] ^ uint64(s.mem.read8(regs[13]+offset))) & 0xffffffff
		s.mem.write8(regs[13]+offset, byte(regs[11]))
	}

	regs[11] = uint64(s.mem.read8(regs[13] + 0xf))
	regs[9] = (uint64(s.mem.read8(regs[9]+0xf)) ^ regs[11]) & 0xffffffff
	s.mem.write8(regs[13]+0xf, byte(regs[9]))

	regs[9] = wbHashXor16StackPC
	s.mem.write64(s.cpu.sp+0x118, regs[9])
	s.mem.write64(s.cpu.sp+0x108, regs[13])
	regs[10] = regs[13]
	s.cpu.pc = wbHashXor16ContinuePC
}

func (s *fpState) wbHashPrepareLookupRound(regs *[31]uint64) {
	stateAddr := regs[10]
	keyAddr := regs[21]

	regs[13] = (regs[8] + 2) & 0xffffffff
	keyByte18 := uint64(s.mem.read8(keyAddr + 0x12))
	keyByte19 := uint64(s.mem.read8(keyAddr + 0x13))
	regs[8] = (keyByte18 - 0x1a) & 0xffffffff
	regs[14] = regs[8] & 0xff
	regs[8] = ((keyByte19 - 0x1a) & 0xffffffff) & 0xff

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(keyByte19), ^uint32(0x1b), 1)
	s.mem.write64(s.cpu.sp+0x130, boolU64(!s.cpu.z))

	regs[16] = (2 - (uint64(fpUDiv32(2, uint32(regs[8])))&0xffffffff)*(regs[8]&0xffffffff)) & 0xffffffff
	regs[11] = uint64(fpUDiv32(3, uint32(regs[8])))
	regs[17] = (3 - (regs[11]&0xffffffff)*(regs[8]&0xffffffff)) & 0xffffffff
	regs[0] = wbHashLookupRoundSeed
	regs[8] = wbHashLookupRoundBase

	regs[1] = s.mem.read64(s.cpu.sp+0xb8) + regs[8]
	regs[9] = uint64(s.mem.read8(stateAddr + 0x4))
	regs[3] = uint64(s.mem.read8(stateAddr + 0x8))
	regs[15] = uint64(s.mem.read8(stateAddr + 0xc))
	regs[26] = uint64(s.mem.read8(stateAddr + 0x5))
	regs[12] = uint64(s.mem.read8(stateAddr + 0x9))
	regs[2] = uint64(s.mem.read8(stateAddr + 0xd))
	regs[30] = uint64(s.mem.read8(stateAddr + 0xa))
	regs[6] = uint64(s.mem.read8(stateAddr + 0x6))
	regs[11] = uint64(s.mem.read8(stateAddr + 0xe))
	regs[20] = uint64(s.mem.read8(stateAddr + 0xf))
	regs[24] = uint64(s.mem.read8(stateAddr + 0xb))
	regs[5] = uint64(s.mem.read8(stateAddr + 0x7))
	regs[7] = uint64(s.mem.read8(stateAddr + 0x2))
	regs[4] = wbHashLookupRoundSeed
	s.cpu.pc = wbHashLookupRoundPC
}

func (s *fpState) wbHashApplyLookupLayer(regs *[31]uint64) {
	stateAddr := regs[10]
	regs[21] = s.mem.read64(s.cpu.sp + 0x138)
	tableBase := regs[21]
	lookup := func(tableOffset uint64, index uint64) uint64 {
		return uint64(s.mem.read8(s.mem.read64(tableBase+tableOffset) + (index & 0xff)))
	}

	regs[14] = uint64(s.mem.read8(stateAddr))
	regs[13] = lookup(0x918, regs[14])
	s.mem.write8(stateAddr, byte(regs[13]))

	regs[13] = s.mem.read64(tableBase + 0x958)
	regs[9] = uint64(s.mem.read8(regs[13] + (regs[9] & 0xff)))
	s.mem.write8(stateAddr+0x4, byte(regs[9]))
	regs[9] = lookup(0x998, regs[3])
	s.mem.write8(stateAddr+0x8, byte(regs[9]))
	regs[9] = lookup(0x9d8, regs[15])
	s.mem.write8(stateAddr+0xc, byte(regs[9]))

	regs[9] = lookup(0x968, regs[26])
	regs[13] = uint64(s.mem.read8(stateAddr + 0x1))
	s.mem.write8(stateAddr+0x1, byte(regs[9]))
	regs[12] &= 0xff
	regs[9] = lookup(0x9a8, regs[12])
	s.mem.write8(stateAddr+0x5, byte(regs[9]))
	regs[9] = lookup(0x9e8, regs[2])
	s.mem.write8(stateAddr+0x9, byte(regs[9]))
	regs[9] = lookup(0x928, regs[13])
	s.mem.write8(stateAddr+0xd, byte(regs[9]))

	regs[9] = lookup(0x9b8, regs[30])
	s.mem.write8(stateAddr+0x2, byte(regs[9]))
	regs[9] = lookup(0x938, regs[7])
	s.mem.write8(stateAddr+0xa, byte(regs[9]))
	regs[11] &= 0xff
	regs[9] = lookup(0x9f8, regs[11])
	s.mem.write8(stateAddr+0x6, byte(regs[9]))
	regs[9] = lookup(0x978, regs[6])
	regs[11] = wbHashLookupLayerBias
	s.mem.write8(stateAddr+0xe, byte(regs[9]))

	regs[9] = lookup(0x9c8, regs[24])
	s.mem.write8(stateAddr+0xf, byte(regs[9]))
	regs[9] = lookup(0x988, regs[5])
	s.mem.write8(stateAddr+0xb, byte(regs[9]))
	regs[9] = s.mem.read64(tableBase + 0x948)
	regs[8] = uint64(s.mem.read8(regs[9] + (regs[8] & 0xff)))
	s.mem.write8(stateAddr+0x7, byte(regs[8]))
	regs[8] = lookup(0xa08, regs[20])
	s.mem.write8(stateAddr+0x3, byte(regs[8]))

	regs[8] = (regs[11] + 0x80) & 0xffffffff
	regs[9] = s.mem.read64(s.cpu.sp + 0xc0)
	regs[12] = s.mem.read64(s.cpu.sp + 0x118)
	s.cpu.pc = regs[12]
}

func (s *fpState) wbHashPreparePointerDispatch(regs *[31]uint64) {
	regs[8] = s.mem.read64(s.cpu.sp+0xc8) + 0x84
	regs[11] = wbHashDispatchMul
	regs[10] = (((((regs[29] - 0xa0) & 0xffffffff) ^ 0x3307dbb9) & 0xffffffff) * regs[11]) & 0xffffffff
	regs[9] = (regs[10] ^ (((((uint64(s.mem.read32(s.cpu.sp+0xb4)) & 0xffffffff) * 0x25) & 0xffffffff) + 0x76) & 0xffffffff)) & 0xffffffff
	s.mem.write8(regs[29]+0xffffffffffffff65, byte(regs[9]))
	dispatchWord := (regs[10] + (regs[24] & 0xffffffff)) & 0xffffffff
	dispatchWord = (dispatchWord - 0x4d) & 0xffffffff
	s.mem.write32(regs[29]+0xffffffffffffff60, uint32(dispatchWord))

	regs[9] = s.mem.read64(s.cpu.sp + 0x128)
	s.mem.write64(regs[28]+0x8, regs[9])
	s.mem.write8(regs[29]+0xffffffffffffff64, byte((0x6c-(regs[10]&0xffffffff))&0xffffffff))
	s.mem.write64(regs[28]+0x10, regs[8])

	regs[8] = (regs[24] - 0x2e) & 0xffffffff
	regs[9] = wbHashDispatchBase
	regs[8] = wbStaticPointerTableRead64(regs[9]+(fpSignExtend(regs[8], 32)<<3)) - 0xb
	regs[0] = regs[29] - 0xa0
	regs[20] = wbHashDispatchSeed
	regs[30] = wbHashDispatchTablePC
	s.cpu.pc = regs[8]
}

func (s *fpState) wbHashCommitOutputStatus(regs *[31]uint64) {
	resultPtrAddr := s.mem.read64(s.cpu.sp + 0x148)
	resultPtr := s.mem.read64(s.cpu.sp + 0xa8)
	s.mem.write64(resultPtrAddr, resultPtr)

	resultLenAddr := s.mem.read64(s.cpu.sp + 0x140)
	resultLen := uint64(s.mem.read32(s.cpu.sp + 0x94))
	s.mem.write32(resultLenAddr, uint32(resultLen))
	s.mem.write8(regs[19], 1)

	statusAddr := s.mem.read64(s.cpu.sp + 0x120)
	s.mem.write8(statusAddr+0x1, 9)

	inputWordAddr := s.mem.read64(s.cpu.sp + 0x100)
	regs[8] = uint64(fpRev32(s.mem.read32(inputWordAddr+0x8))) & 0xffffffff
	regs[8], s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), 0xc, 0)
	s.mem.write64(s.cpu.sp+0x170, regs[8])

	regs[9] = (regs[20] - 0x4e) & 0xffffffff
	regs[11] = boolU64(s.cpu.z)
	regs[12] = 0xfffffffa
	nextIndex := ((regs[24] & 0xffffffff) + boolU64(!s.cpu.z)*regs[12]) & 0xffffffff
	regs[20] = (nextIndex + (regs[11]&0xffffffff)*regs[9]) & 0xffffffff
	regs[10] = wbHashPointerDispatch
	dispatchOffset := fpSignExtend((regs[24]+boolU64(s.cpu.z))&0xffffffff, 32) << 2
	regs[9] = fpSignExtend(uint64(s.mem.read32(regs[27]+dispatchOffset)), 32) + regs[10]
	regs[1] = wbHashCommitSeed
	s.cpu.pc = regs[9]
}

func (s *fpState) wbHashResumeLookupReturn(regs *[31]uint64) {
	regs[9] = s.mem.read64(s.cpu.sp + 0x108)
	regs[8] = uint64(s.mem.read32(s.cpu.sp + 0x110))
	s.wbHashDispatchLookupReturn(regs)
}

func (s *fpState) wbHashDispatchLookupReturn(regs *[31]uint64) {
	regs[15] = wbHashDispatchSeed
	regs[16] = (regs[8] - 0x10) & 0xffffffff

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[16]), ^uint32(regs[11]), 1)
	regs[8] = (((regs[15] + 0xd8ab6957) & 0xffffffff) + boolU64(s.cpu.z)) & 0xffffffff
	regs[12] = boolU64(s.cpu.z)
	regs[13] = (uint64(0xd8ab6957) + 0x45) & 0xffffffff
	regs[14] = (uint64(0xd8ab6957) + 0x36) & 0xffffffff
	nextIndex := ((regs[15] & 0xffffffff) + boolU64(!s.cpu.z)*(regs[14]&0xffffffff)) & 0xffffffff
	regs[24] = (nextIndex + (regs[12]&0xffffffff)*(regs[13]&0xffffffff)) & 0xffffffff

	dispatchOffset := fpSignExtend(((regs[8]+0x3b)&0xffffffff), 32) << 2
	regs[8] = fpSignExtend(uint64(s.mem.read32(regs[27]+dispatchOffset)), 32)
	regs[11] = wbU64(0x1a12c2000) + 0x888
	regs[8] += regs[11]
	s.cpu.pc = regs[8]
}

func (s *fpState) wbHashDispatchOutputWord(regs *[31]uint64) {
	regs[11], regs[15] = 0xc7efeebdf6ff1120, (((s.cpu.sp+0x170)^wbU64(0x63f7f75efb7f8897))+(wbU64(0xc7efeebdf6ff1120)&((s.cpu.sp+0x170)<<1)))+wbU64(0xfdedcffb26f6ffff)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), ^uint32(uint64(0x7)), 1)
	regs[9] = boolU64(s.cpu.c && !s.cpu.z)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), ^uint32(uint64(0x8)), 1)
	regs[10] = ((((((((boolU64(!s.cpu.c)) & 0xffffffff) &^ 0x8) | (((((boolU64(!s.cpu.c)) & 0xffffffff) >> 29) | ((boolU64(!s.cpu.c)) & 0xffffffff << 3)) & 0x8)) & 0xffffffff) & 0xffffffff) &^ 0x4) | ((((regs[9] & 0xffffffff) >> 30) | ((regs[9] & 0xffffffff) << 2)) & 0x4)) & 0xffffffff
	regs[14], regs[10], regs[9] = (regs[10]+(regs[20]&0xffffffff))&0xffffffff, (fpSignExtend(uint64(s.mem.read32(regs[27]+(fpSignExtend((ternaryU64(s.cpu.c, regs[20]&0xffffffff, ((regs[20]&0xffffffff)+1)&0xffffffff))&0xffffffff, 32)<<2))), 32))+wbU64(0x1a12c29d4), 0x9e1a38a5dd89776a
	s.cpu.pc = regs[10]
}

func (s *fpState) wbHashDispatchVectorMixAlignment(regs *[31]uint64) {
	regs[10] = regs[8] & 0x7
	regs[12], s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[8], ^regs[10], 1)
	regs[13], regs[11] = ((((((((boolU64(s.cpu.z))&0xffffffff)&^0x4)|(((((boolU64(s.cpu.z))&0xffffffff)>>30)|(((boolU64(s.cpu.z))&0xffffffff)<<2))&0x4))&0xffffffff)+((((boolU64(!s.cpu.z))&0xffffffff)<<2)&0xffffffff))&0xffffffff)+(regs[14]&0xffffffff))&0xffffffff, (fpSignExtend(uint64(s.mem.read32(regs[27]+(fpSignExtend(((regs[14]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32))+wbU64(0x1a12c2a58)
	regs[14] = regs[13]
	s.cpu.pc = regs[11]
}

func (s *fpState) wbHashPrepareVectorMix(regs *[31]uint64) {
	regs[14], regs[11], regs[13] = 0x0, regs[12]+regs[15], (regs[13]-0x6)&0xffffffff
	s.doSIMD(0x4e080de6)
	regs[15] = wbStaticVectorConstPageBase
	s.cpu.vreg[0] = wbStaticVectorConstant(0)
	s.doSIMD(0x4ee084c0)
	s.cpu.vreg[1] = wbStaticVectorConstant(1)
	s.doSIMD(0x4ee184c1)
	s.cpu.vreg[2] = wbStaticVectorConstant(2)
	s.doSIMD(0x4ee284c2)
	s.cpu.vreg[7] = wbStaticVectorConstant(3)
	regs[15] = 0x9e1a38a5dd89776a
	s.doSIMD(0x4e080de3)
	regs[15] = 0xba
	s.doSIMD(0x4e080de4)
	regs[15] = 0x9e1a38a5dd89777b
	s.doSIMDN(0x4e080de5, 0x4ee784c6)
	regs[15] = 0x8
	s.doSIMD(0x4e080de7)
	regs[15] = wbHashVectorMixPC
	s.cpu.pc = wbHashVectorMixPC
}

func (s *fpState) wbHashVectorMixLoop(regs *[31]uint64) {
	for {
		s.doSIMDN(0x4ee38450, 0x4ee384d1, 0x4ee38412, 0x6e241e52, 0x6e241e31, 0x4ee58413, 0x6e241e10, 0x4ee584d4, 0x4ee58455, 0x4e183eb0, 0x4e183e11)
		regs[1] = s.cpu.vreg[16][0]
		regs[0] = regs[1] * s.cpu.vreg[21][0]
		s.doSIMD(0x4e183e81)
		regs[16] = regs[17] * regs[16]
		s.doSIMD(0x4e183e31)
		regs[3] = s.cpu.vreg[17][0]
		regs[2], regs[17] = regs[3]*s.cpu.vreg[20][0], regs[17]*regs[1]
		s.doSIMDN(0x4e183e61, 0x4e183e43)
		regs[1] = regs[3] * regs[1]
		s.cpu.vreg[16] = [2]uint64{regs[0], 0}
		regs[3] = s.cpu.vreg[18][0]
		regs[0] = regs[3] * s.cpu.vreg[19][0]
		s.doSIMDN(0x4ee38431, 0x6e241e31)
		s.cpu.vreg[18] = [2]uint64{regs[2], 0}
		s.doSIMD(0x4ee58433)
		s.cpu.vreg[20] = [2]uint64{regs[0], 0}
		s.doSIMDN(0x4e183e60, 0x4e181e10, 0x4e183e30)
		regs[16], regs[0] = regs[16]*regs[0], s.cpu.vreg[19][0]
		s.doSIMD(0x4e181e32)
		regs[17], regs[0] = s.cpu.vreg[17][0]*regs[0], regs[8]-regs[14]
		s.cpu.vreg[17] = [2]uint64{regs[17], 0}
		s.doSIMDN(0x4e181c34, 0x4e181e11, 0x0ea12a31, 0x4ea12a91, 0x0ea12a52, 0x4ea12a12, 0x0e612a50, 0x4e612a30)
		regs[16], regs[14] = s.mem.read64(s.cpu.sp+0x100)+regs[0], regs[14]+0x8
		s.doSIMDN(0x4ee784c6, 0x0e212a10, 0x4ee78442, 0x4ee78421, 0x4ee78400)
		_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[14], ^regs[12], 1)
		regs[17] = boolU64(s.cpu.z)
		s.doSIMD(0x0e200a10)
		regs[0], regs[13] = (regs[13]+boolU64(s.cpu.z))&0xffffffff, ((regs[13]&0xffffffff)-((regs[17]<<2)&0xffffffff))&0xffffffff
		regs[17] = fpSignExtend(uint64(s.mem.read32(regs[27]+(fpSignExtend(regs[0]&0xffffffff, 32)<<2))), 32) + regs[15]
		s.mem.write64(regs[16]+0xfffffffffffffff8, s.cpu.vreg[16][0])
		s.cpu.pc = regs[17]
		if s.cpu.pc == wbHashVectorMixPC {
			continue
		}
		return
	}
}

func (s *fpState) wbHashDispatchVectorFill(regs *[31]uint64) {
	regs[8] = (wbHashDispatchSeed - 0x46) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[10]), ^uint32(uint64(0x0)), 1)
	regs[8] = ((((((boolU64(!s.cpu.z)) & 0xffffffff) * uint64(0xb)) & 0xffffffff) & 0xffffffff) + (boolU64(s.cpu.z)&0xffffffff)*regs[8]) & 0xffffffff
	regs[14], regs[8] = (regs[8]+(regs[13]&0xffffffff))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[27]+(fpSignExtend(((regs[13]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)
	regs[12], regs[8], regs[15], regs[20] = regs[8]+wbU64(0x1a12c2c20), regs[10], regs[11], regs[14]
	s.cpu.pc = regs[12]
}

func (s *fpState) wbHashVectorFillLoop(regs *[31]uint64) {
	for {
		regs[8], s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[8], ^uint64(0x1), 1)
		regs[10], regs[11] = ((((regs[15]+regs[9])&0xffffffff)^uint64(0xba))&0xffffffff)*(((regs[15]+regs[9])&0xffffffff)+0x11), s.mem.read64(s.cpu.sp+0x100)
		s.mem.write8(regs[11]+regs[8], byte(regs[10]))
		regs[15], regs[20], regs[11] = regs[15]+0x1, ((regs[14]&0xffffffff)+(boolU64(s.cpu.z)&0xffffffff)*((wbHashDispatchSeed-0x51)&0xffffffff))&0xffffffff, wbU64(0x1a12c2000)+0xc6c
		regs[10], regs[14] = fpSignExtend(uint64(s.mem.read32(regs[27]+(fpSignExtend(((regs[14]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)+regs[11], regs[20]
		s.cpu.pc = regs[10]
		if s.cpu.pc == wbHashVectorFillPC {
			continue
		}
		return
	}
}

func (s *fpState) wbHashPrepareFinalVectorMix(regs *[31]uint64) {
	s.mem.write64(s.cpu.sp+0x170, 0)
	regs[1], regs[8] = wbHashCommitSeed, 0
	s.mem.write64(s.cpu.sp+0x160, 0x80)
	regs[12], regs[9], regs[11] = 0xeffffff75ffffbb0, ((((regs[20]&0xffffffff)+uint64(0xd8ab6957))&0xffffffff)+0x2d)&0xffffffff, 0x5ef5b7fefde85bb7
	regs[10] = (((s.cpu.sp + 0x160) ^ wbU64(0xf7fffffbaffffddf)) + (wbU64(0xeffffff75ffffbb0) & ((s.cpu.sp + 0x160) << 1))) + regs[11]
	s.doSIMD(0x4e080d43)
	regs[10] = wbStaticVectorConstPageBase
	s.cpu.vreg[0] = wbStaticVectorConstant(0)
	s.doSIMD(0x4ee08460)
	s.cpu.vreg[1] = wbStaticVectorConstant(1)
	s.doSIMD(0x4ee18461)
	s.cpu.vreg[2] = wbStaticVectorConstant(2)
	s.doSIMD(0x4ee28462)
	s.cpu.vreg[4] = wbStaticVectorConstant(3)
	s.doSIMD(0x4ee48463)
	regs[10] = 0xa90a48055217a66a
	s.doSIMD(0x4e080d44)
	regs[10] = 0xba
	s.doSIMD(0x4e080d45)
	regs[10] = 0xa90a48055217a67b
	s.doSIMD(0x4e080d46)
	regs[10], regs[11] = 0x7f, 0x8
	s.doSIMD(0x4e080d67)
	regs[11], regs[0] = wbHashFinalVectorPC, s.mem.read64(s.cpu.sp+0xa0)
	s.cpu.pc = wbHashFinalVectorPC
}

func (s *fpState) wbHashFinalVectorMixLoop(regs *[31]uint64) {
	for {
		s.doSIMDN(0x4ee48450, 0x4ee48471, 0x4ee48412, 0x4ee48433, 0x6e251e73, 0x6e251e52, 0x6e251e31, 0x4ee68434, 0x6e251e10, 0x4ee68415, 0x4ee68456, 0x4e183ecc, 0x4e183e0d, 0x4ee68477)
		regs[14], regs[15] = s.cpu.vreg[22][0], s.cpu.vreg[16][0]
		s.doSIMD(0x4e183ef0)
		regs[12], regs[13] = regs[13]*regs[12], regs[15]*regs[14]
		s.doSIMD(0x4e183e2e)
		regs[17], regs[14] = s.cpu.vreg[17][0], regs[14]*regs[16]
		regs[15] = regs[17] * s.cpu.vreg[23][0]
		s.doSIMDN(0x4e183eb0, 0x4e183e51)
		s.cpu.vreg[16] = [2]uint64{regs[13], 0}
		s.cpu.vreg[17] = [2]uint64{regs[15], 0}
		regs[13], regs[16] = regs[17]*regs[16], s.cpu.vreg[18][0]
		regs[15] = regs[16] * s.cpu.vreg[21][0]
		s.cpu.vreg[18] = [2]uint64{regs[15], 0}
		s.doSIMDN(0x4e183e8f, 0x4e183e70, 0x4e181d90)
		regs[12], regs[16] = regs[16]*regs[15], s.cpu.vreg[19][0]
		regs[15] = regs[16] * s.cpu.vreg[20][0]
		s.doSIMD(0x4e181dd1)
		regs[14] = regs[10] - regs[8]
		s.cpu.vreg[19] = [2]uint64{regs[15], 0}
		s.doSIMDN(0x4e181d93, 0x4e181db2, 0x0ea12a73, 0x4ea12a53, 0x0ea12a31, 0x4ea12a11, 0x0e612a30, 0x4e612a70)
		regs[13], regs[8] = regs[0]+regs[14], regs[8]+0x8
		s.doSIMDN(0x4ee78421, 0x4ee78442, 0x4ee78463, 0x0e212a10, 0x4ee78400)
		_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[8], ^uint64(0x80), 1)
		regs[12] = ((((((boolU64(s.cpu.z)) & 0xffffffff) &^ 0x4) | (((((boolU64(s.cpu.z)) & 0xffffffff) >> 30) | (((boolU64(s.cpu.z)) & 0xffffffff) << 2)) & 0x4)) & 0xffffffff) + regs[9]) & 0xffffffff
		s.doSIMD(0x0e200a10)
		regs[9] = fpSignExtend(uint64(s.mem.read32(regs[27]+(fpSignExtend(((regs[9]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)
		regs[14], regs[9] = regs[9]+regs[11], regs[12]
		s.mem.write64(regs[13]+0xfffffffffffffff9, s.cpu.vreg[16][0])
		s.cpu.pc = regs[14]
		if s.cpu.pc == wbHashFinalVectorPC {
			continue
		}
		return
	}
}

func (s *fpState) wbHashDispatchFinalVectorOutput(regs *[31]uint64) {
	s.mem.write64(s.cpu.sp+0x160, 0)
	regs[8], regs[15] = (wbHashDispatchSeed-0x3b)&0xffffffff, regs[1]
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[15]), ^uint32(wbHashCommitSeed), 1)
	regs[10], regs[11] = boolU64(s.cpu.z), (regs[12]+boolU64(s.cpu.z))&0xffffffff
	regs[8] = ((((uint64(0) - ((((((boolU64(!s.cpu.z)) & 0xffffffff) &^ 0x20) | (((((boolU64(!s.cpu.z)) & 0xffffffff) >> 27) | (((boolU64(!s.cpu.z)) & 0xffffffff) << 5)) & 0x20)) & 0xffffffff) & 0xffffffff)) & 0xffffffff) & 0xffffffff) + (regs[10]&0xffffffff)*regs[8]) & 0xffffffff
	regs[17], regs[8] = (regs[8]+(regs[12]&0xffffffff))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[27]+(fpSignExtend(regs[11]&0xffffffff, 32)<<2))), 32)
	regs[9], regs[8], regs[21], regs[22] = regs[8]+wbU64(0x1a12c2ebc), wbHashCommitSeed, s.mem.read64(s.cpu.sp+0x140), s.mem.read64(s.cpu.sp+0x100)
	s.cpu.pc = regs[9]
}

func (s *fpState) wbHashStoreEncodedWordA(regs *[31]uint64) {
	for {
		regs[8], regs[9] = (((uint64(s.mem.read32(regs[0]+0x4)))&0xffffffff)-((regs[0]^uint64(0xc9fc1df2))&0xffffffff)*uint64(0x4378db61))&0xffffffff, s.mem.read64(regs[0]+0x8)
		s.mem.write8(regs[9]+0x0, byte((uint64(0x52)^((regs[8]&0xffffffff)>>24))&0xffffffff))
		s.mem.write8(regs[9]+0x1, byte((uint64(0x75)^((regs[8]&0xffffffff)>>16))&0xffffffff))
		regs[10] = (((((regs[8] & 0xffffffff) >> 8) | ((regs[8] & 0xffffffff) << 24)) & 0xffffff) ^ 0x10) & 0xffffffff
		s.mem.write8(regs[9]+0x2, byte(regs[10]))
		regs[8] = (regs[8] ^ 0xffffffcf) & 0xffffffff
		s.mem.write8(regs[9]+0x3, byte(regs[8]))

		s.cpu.pc = regs[30]
		switch s.cpu.pc {
		case wbHashEncodedWordATailPC:
		case wbHashEncodedWordADonePC:
			s.cpu.pc = wbHashEncodedWordADonePC
			return
		default:
			return
		}

		regs[8], regs[9] = uint64(s.mem.read32(regs[20]+0x14)), regs[20]+0x54
		regs[10] = (((uint64(0x54eb11d6) + ((regs[8] << 1) & 0xffffffff)) & 0xffffffff) & regs[24]) & 0xffffffff
		s.mem.write64(s.cpu.sp+0x50, regs[9])
		regs[8] = (((regs[23] + regs[8]) & 0xffffffff) - regs[10]) & 0xffffffff
		s.mem.write32(s.cpu.sp+0x48, uint32(regs[26]))
		s.mem.write32((s.cpu.sp+0x48)+4, uint32(regs[8]))
		regs[0], regs[30] = s.cpu.sp+0x48, wbHashEncodedWordADonePC
	}
}

func (s *fpState) wbHashStoreEncodedWordB(regs *[31]uint64) {
	for {
		regs[8], regs[9] = (((uint64(s.mem.read32(regs[0]+0xc)))&0xffffffff)+((regs[0]^uint64(0x7ea31c7e))&0xffffffff)*uint64(0x1981f355))&0xffffffff, s.mem.read64(regs[0]+0x0)
		s.mem.write8(regs[9]+0x0, byte((uint64(0x54)^((regs[8]&0xffffffff)>>24))&0xffffffff))
		s.mem.write8(regs[9]+0x1, byte((uint64(0xea)^((regs[8]&0xffffffff)>>16))&0xffffffff))
		s.mem.write8(regs[9]+0x2, byte((uint64(0x9e)^((regs[8]&0xffffffff)>>8))&0xffffffff))
		regs[10] = 0x86
		regs[8] = (regs[8] ^ regs[10]) & 0xffffffff
		s.mem.write8(regs[9]+0x3, byte(regs[8]))

		s.cpu.pc = regs[30]
		switch s.cpu.pc {
		case wbHashEncodedWordBTailPC:
		case wbHashEncodedWordBDonePC:
			s.cpu.pc = wbHashEncodedWordBDonePC
			return
		default:
			return
		}

		regs[8], regs[9], regs[11] = uint64(s.mem.read32(regs[20]+0x14)), regs[20]+0x54, 0xa9d53d0c
		regs[10] = (((uint64(0x54eb11d6) + ((regs[8] << 1) & 0xffffffff)) & 0xffffffff) & regs[11]) & 0xffffffff
		regs[8] = (((regs[21] + regs[8]) & 0xffffffff) - regs[10]) & 0xffffffff
		s.mem.write32(s.cpu.sp+0x18, uint32(regs[23]))
		s.mem.write32((s.cpu.sp+0x18)+4, uint32(regs[8]))
		s.mem.write64(s.cpu.sp+0x10, regs[9])
		regs[0], regs[30] = s.cpu.sp+0x10, wbHashEncodedWordBDonePC
	}
}

func (s *fpState) wbHashStoreEncodedWordC(regs *[31]uint64) {
	for {
		source := s.mem.read64(regs[0] + 0x8)
		word := uint64(s.mem.read8(source+0x0)) |
			uint64(s.mem.read8(source+0x1))<<8 |
			uint64(s.mem.read8(source+0x2))<<16 |
			uint64(s.mem.read8(source+0x3))<<24
		word &= 0xffffffff

		regs[10] = 0xf5ca7dfe
		mixed := ((word ^ uint64(0xfae53eff)) + (regs[10] & ((word << 1) & 0xffffffff))) & 0xffffffff
		regs[9] = 0x3fffeb7c
		regs[8] = (mixed + regs[9]) & 0xffffffff
		s.mem.write32(regs[0]+0x0, uint32(regs[8]))

		s.cpu.pc = regs[30]
		switch s.cpu.pc {
		case wbHashEncodedWordCTailA:
		case wbHashEncodedWordCDoneA:
			s.cpu.pc = wbHashEncodedWordCDoneA
			return
		case wbHashEncodedWordCTailB:
		case wbHashEncodedWordCDoneB:
			s.cpu.pc = wbHashEncodedWordCDoneB
			return
		default:
			return
		}

		if s.cpu.pc == wbHashEncodedWordCTailA {
			regs[8] = uint64(s.mem.read32(s.cpu.sp + 0x0))
			s.mem.write32(regs[22]+wbU64(0x232e78def79c7fdc), uint32(regs[8]))
			regs[8], regs[26] = regs[21]+0x4, uint64(s.mem.read32(regs[20]+0x0))
			regs[9] = (regs[26] + 0x4) & 0xffffffff
			s.mem.write32(regs[20]+0x0, uint32(regs[9]))
			s.mem.write32(s.cpu.sp+0x10, uint32(regs[28]))
			s.mem.write64(s.cpu.sp+0x8, regs[8])
			regs[30] = wbHashEncodedWordCDoneA
		} else if s.cpu.pc == wbHashEncodedWordCTailB {
			regs[8] = uint64(s.mem.read32(s.cpu.sp + 0x0))
			s.mem.write32(regs[23]+wbU64(0x232e78def79c7fd8), uint32(regs[8]))
			regs[8], regs[21] = regs[21]+0x8, uint64(s.mem.read32(regs[20]+0x0))
			regs[9] = (regs[21] + 0x4) & 0xffffffff
			s.mem.write32(regs[20]+0x0, uint32(regs[9]))
			s.mem.write32(s.cpu.sp+0x10, uint32(regs[24]))
			s.mem.write64(s.cpu.sp+0x8, regs[8])
			regs[0], regs[30] = s.cpu.sp+0x0, wbHashEncodedWordCDoneB
		}
	}
}

func (s *fpState) wbHashEnterAccumulator(regs *[31]uint64) {
	s.cpu.sp -= 0xa0
	s.stpSPN(0x40, regs[28], regs[27], regs[26], regs[25], regs[24], regs[23], regs[22], regs[21], regs[20], regs[19], regs[29], regs[30])
	regs[29], regs[19], regs[8] = s.cpu.sp+0x90, regs[0], wbHashStackGuardValue
	s.mem.write64(s.cpu.sp+0x38, regs[8])
	regs[8], regs[10] = ((regs[19]&0xffffffff)^uint64(0x7f3c8c36))&0xffffffff, uint64(s.mem.read32(regs[19]+0x0))
	regs[9], regs[20], regs[24], regs[26], regs[21] = (regs[10]+regs[8]*uint64(0xf43b84b))&0xffffffff, s.mem.read64(regs[19]+0x8), s.mem.read64((regs[19]+0x8)+8), s.mem.read64(regs[19]+0x18), s.mem.read64((regs[19]+0x18)+8)
	s.mem.write32(s.cpu.sp+0x4, uint32(uint64(0)))
	s.mem.write32((s.cpu.sp+0x4)+4, uint32(uint64(0)))
	s.mem.write32(s.cpu.sp+0xc, uint32(uint64(0x4f465e39)))
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[26], ^uint64(0x0), 1)
	regs[8] = boolU64(s.cpu.z)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[24], ^wbU64(0x315c9c0472d221ee), 1)
	regs[10] = boolU64(s.cpu.z)
	regs[8] = (regs[8] | regs[10]) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[20], ^uint64(0x0), 1)
	regs[10] = boolU64(s.cpu.z)
	regs[8] = (regs[10] | regs[8]) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[21], ^wbU64(0xdcd1872108638028), 1)
	regs[10], regs[25], regs[8], regs[22], regs[12] = ((regs[8]&0xffffffff)|boolU64(s.cpu.z))&0xffffffff, 0x3ccb976, 0x3ccb976, 0x1a1311700, 0x1a12c32c8
	regs[11] = fpSignExtend(uint64(s.mem.read32(wbU64(0x1a1311700)+(fpSignExtend(((regs[9]&0xffffffff)+regs[10])&0xffffffff, 32)<<2))), 32) + wbU64(0x1a12c32c8)
	s.cpu.pc = regs[11]
}

func (s *fpState) wbHashSeedAccumulator(regs *[31]uint64) {
	regs[8] = (regs[10] ^ 0x1) & 0xffffffff
	regs[27], regs[23] = ((regs[9]&0xffffffff)+((regs[8]<<2)&0xffffffff))&0xffffffff, wbHashCommitSeed
	s.mem.write32(regs[20]+0x0, uint32(uint64(0x2997cfac)))
	regs[8] = (regs[27] - 0x3) & 0xffffffff
	s.mem.write64(s.cpu.sp+0x28, regs[21])
	regs[8] = (regs[8] ^ (((((((s.cpu.sp + 0x10) & 0xffffffff) ^ uint64(0xf396371a)) & 0xffffffff) & 0xffffffff) * uint64(0x34c050e5)) & 0xffffffff)) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x20, uint32(regs[8]))
	regs[8] = s.cpu.sp + 0x4
	s.stpSP(0x10, regs[8], regs[26])
	regs[0], regs[30] = s.cpu.sp+0x10, 0x1a12c3340
	regs[8] = (((regs[0] & 0xffffffff) ^ uint64(0xf396371a)) & 0xffffffff) * uint64(0x34c050e5) & 0xffffffff
	regs[13], regs[8], regs[9], regs[10] = (uint64(s.mem.read32(regs[0]+0x10))^regs[8])&0xffffffff, s.mem.read64(regs[0]+0x0), s.mem.read64((regs[0]+0x0)+8), s.mem.read64(regs[0]+0x18)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[9], ^uint64(0x0), 1)
	regs[11] = boolU64(s.cpu.z)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[8], ^uint64(0x0), 1)
	regs[12] = boolU64(s.cpu.z)
	regs[11] = (regs[11] | regs[12]) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[10], ^wbU64(0xdcd1872108638028), 1)
	regs[14], regs[12], regs[11] = ((regs[11]&0xffffffff)|boolU64(s.cpu.z))&0xffffffff, 0x3ccb976, 0x1a1306c90
	regs[15] = wbStaticSeedBranchTarget(0x1a12aebe4, ((regs[13]&0xffffffff)+regs[14])&0xffffffff)
	s.cpu.pc = regs[15]
}

func (s *fpState) wbHashDispatchAccumulatorSeed(regs *[31]uint64) {
	regs[8] = uint64(s.mem.read32(s.cpu.sp + 0x30))
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), ^uint32(regs[23]), 1)
	regs[9], regs[10], regs[12], regs[11] = boolU64(!s.cpu.z), boolU64(s.cpu.z), 0x1a12c32e8, fpSignExtend(uint64(s.mem.read32(regs[22]+(fpSignExtend(((regs[27]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c32e8)
	s.cpu.pc = regs[11]
}

func (s *fpState) wbHashMixAccumulatorPair(regs *[31]uint64) {
	regs[8] = (regs[10] - regs[9]) & 0xffffffff
	regs[28], regs[8] = ((regs[27]&0xffffffff)+((regs[8]<<2)&0xffffffff))&0xffffffff, uint64(s.mem.read32(s.cpu.sp+0x4))
	regs[26], regs[9] = regs[26]+regs[8], uint64(s.mem.read32(regs[20]+0x0))
	regs[8] = (regs[9] + regs[8]) & 0xffffffff
	s.mem.write32(regs[20]+0x0, uint32(regs[8]))
	regs[8], regs[10] = (regs[28]-0x1)&0xffffffff, 0x66049efd
	regs[9] = ((((((s.cpu.sp + 0x10) & 0xffffffff) ^ uint64(0xd987bb6d)) & 0xffffffff) & 0xffffffff) * regs[10]) & 0xffffffff
	s.mem.write64(s.cpu.sp+0x10, regs[21])
	regs[8] = (regs[8] ^ regs[9]) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x18, uint32(regs[8]))
	s.stpSP(0x20, regs[26], regs[24])
	regs[8] = s.cpu.sp + 0x8
	s.mem.write64(s.cpu.sp+0x30, regs[8])
	regs[8], regs[27] = (regs[28]+0x2b)&0xffffffff, wbHashDispatchBase
	regs[8], regs[0], regs[30] = wbStaticPointerTableRead64(wbHashDispatchBase+(fpSignExtend(regs[8], 32)<<3))-0xf, s.cpu.sp+0x10, 0x1a12c33d8
	s.cpu.pc = regs[8]
}

func (s *fpState) wbHashDispatchAccumulatorPair(regs *[31]uint64) {
	regs[8] = uint64(s.mem.read32(s.cpu.sp + 0x1c))
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), ^uint32(regs[23]), 1)
	regs[9], regs[10], regs[12], regs[11] = boolU64(s.cpu.z), boolU64(!s.cpu.z), 0x1a12c3368, fpSignExtend(uint64(s.mem.read32(regs[22]+(fpSignExtend(((regs[28]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c3368)
	s.cpu.pc = regs[11]
}

func (s *fpState) wbHashGateAccumulatorByte(regs *[31]uint64) {
	regs[8] = ((regs[28] & 0xffffffff) - ((regs[10] << 3) & 0xffffffff)) & 0xffffffff
	regs[10], regs[9] = (regs[8]-((regs[9]<<1)&0xffffffff))&0xffffffff, uint64(s.mem.read32(s.cpu.sp+0x8))
	regs[8] = (uint64(s.mem.read32(regs[20]+0x0)) + regs[9]) & 0xffffffff
	s.mem.write32(regs[20]+0x0, uint32(regs[8]))
	regs[8] = uint64(s.mem.read8(regs[24] + wbU64(0xcea363fb8d2dde16)))
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), ^uint32(uint64(0x1b)), 1)
	regs[11], regs[12], regs[8] = boolU64(s.cpu.z), boolU64(!s.cpu.z), fpSignExtend(uint64(s.mem.read32(regs[22]+(fpSignExtend(ternaryU64(!s.cpu.z, regs[10], (regs[10]+1)&0xffffffff)&0xffffffff, 32)<<2))), 32)
	regs[13], regs[8] = regs[8]+wbU64(0x1a12c3404), (regs[25]+0x3)&0xffffffff
	s.cpu.pc = regs[13]
}

func (s *fpState) wbHashPrepareAccumulatorPointerCall(regs *[31]uint64) {
	regs[8] = ((regs[10] & 0xffffffff) + (regs[12]&0xffffffff)*uint64(0xfffffffa)) & 0xffffffff
	regs[24], regs[8], regs[9], regs[10], regs[11] = (regs[8]-((regs[11]<<2)&0xffffffff))&0xffffffff, regs[26]+regs[9], (((s.cpu.sp+0x10)&0xffffffff)^uint64(0x2781ed8d))&0xffffffff, 0x242c6273, s.cpu.sp+0xc
	s.mem.write64(s.cpu.sp+0x28, regs[11])
	s.stpSP(0x10, regs[21], regs[8])
	regs[8] = (((((regs[24] & 0xffffffff) - (regs[9]&0xffffffff)*(regs[10]&0xffffffff)) & 0xffffffff) & 0xffffffff) - 0x2) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x30, uint32(regs[8]))
	regs[8], regs[0], regs[30] = wbStaticPointerTableRead64(wbHashDispatchBase+(fpSignExtend(((regs[24]+0x4f)&0xffffffff), 32)<<3))-0xb, s.cpu.sp+0x10, 0x1a12c34b0
	s.cpu.pc = regs[8]
}

func (s *fpState) wbHashDispatchAccumulatorPointerCall(regs *[31]uint64) {
	regs[8] = uint64(s.mem.read32(s.cpu.sp + 0x20))
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), ^uint32(regs[23]), 1)
	regs[10], regs[9] = 0x1a12c345c, fpSignExtend(uint64(s.mem.read32(regs[22]+(fpSignExtend(((regs[24]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c345c)
	s.cpu.pc = regs[9]
}

func (s *fpState) wbHashFinishAccumulator(regs *[31]uint64) {
	regs[8], regs[9] = uint64(s.mem.read32(s.cpu.sp+0xc)), uint64(s.mem.read32(regs[20]+0x0))
	regs[8] = (((regs[8] + regs[9]) & 0xffffffff) + uint64(0xb0b9a1c7)) & 0xffffffff
	s.mem.write32(regs[20]+0x0, uint32(regs[8]))
	s.mem.write32(regs[19]+0x28, uint32(wbHashCommitSeed))
	regs[8], regs[9] = s.mem.read64(s.cpu.sp+0x38), wbHashStackGuardValue
	regs[8] = regs[9] - regs[8]
	if s.jmpc(regs[8] != 0, 0x1a12c3534) {
		return
	}
	s.ldpSPInto(0x40, &regs[28], &regs[27], &regs[26], &regs[25], &regs[24], &regs[23], &regs[22], &regs[21], &regs[20], &regs[19], &regs[29], &regs[30])
	s.cpu.sp += 0xa0
	s.cpu.pc = regs[30]
}

func (s *fpState) wbHashEnterPaddingBlock(regs *[31]uint64) {
	s.cpu.sp -= 0xd0
	s.stpSPN(0x70, regs[28], regs[27], regs[26], regs[25], regs[24], regs[23], regs[22], regs[21], regs[20], regs[19], regs[29], regs[30])
	regs[29], regs[19], regs[8] = s.cpu.sp+0xc0, regs[0], wbHashStackGuardValue
	s.mem.write64(regs[29]+0xffffffffffffffa8, regs[8])
	regs[8] = ((regs[19] & 0xffffffff) ^ uint64(0x3849e4e4)) & 0xffffffff
	regs[12], regs[20] = (uint64(s.mem.read32(regs[19]+0x0))+regs[8]*uint64(0x444a28e1))&0xffffffff, s.mem.read64(regs[19]+0x8)
	regs[8] = uint64(s.mem.read32(regs[20] + 0x10))
	regs[10] = (regs[8] + 0xeb) & 0xffffffff
	regs[11] = ((regs[10] >> 3) | (regs[10] << 29)) & 0x3f
	regs[8] = regs[20] + regs[11] + 0x19
	s.mem.write8((regs[20]+regs[11])+0x18, byte(0x80))
	regs[2], regs[3] = 0x53b34449, 0xb0232e5e3307dbb9
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32((regs[11]^0x38)&0xffffffff), ^uint32(uint64(0x7)), 1)
	regs[13] = boolU64(s.cpu.c && !s.cpu.z)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32((regs[11]^0x38)&0xffffffff), ^uint32(uint64(0x8)), 1)
	regs[13], regs[9] = ((((((boolU64(!s.cpu.c))&0xffffffff)*0xc)&0xffffffff)&0xffffffff)-((regs[13]<<2)&0xffffffff))&0xffffffff, 0x1a1311170
	regs[13], regs[14], regs[16], regs[27], regs[15], regs[12] = (regs[13]+regs[12])&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[9]+(fpSignExtend(ternaryU64(s.cpu.c, regs[12], (regs[12]+1)&0xffffffff)&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c492c), wbHashDispatchBase, wbStaticPointerTableRead64(wbHashDispatchBase+(fpSignExtend(((regs[12]+0x4)&0xffffffff), 32)<<3))-0x7, wbStaticPointerTableRead64(wbHashDispatchBase+(fpSignExtend(((regs[12]+0x3)&0xffffffff), 32)<<3)), wbStaticPointerTableRead64(wbHashDispatchBase+(fpSignExtend(((regs[12]+0x1b)&0xffffffff), 32)<<3))
	regs[15], regs[28] = regs[15]-0x6, regs[12]-0xe
	s.stpSP(0x20, regs[28], regs[15])
	s.mem.write64(s.cpu.sp+0x10, regs[27])
	s.cpu.pc = regs[14]
}

func (s *fpState) wbHashDispatchPaddingSize(regs *[31]uint64) {
	regs[10], s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(uint64(0x37)), ^uint32(regs[11]), 1)
	regs[14], regs[11], regs[13] = (regs[13]+boolU64(s.cpu.z))&0xffffffff, ((((((((boolU64(s.cpu.z))&0xffffffff)*uint64(0xb))&0xffffffff)-((((boolU64(!s.cpu.z))&0xffffffff)<<1)&0xffffffff))&0xffffffff)&0xffffffff)+(regs[13]&0xffffffff))&0xffffffff, 0x1a12c4c4c
	regs[12] = fpSignExtend(uint64(s.mem.read32(regs[9]+(fpSignExtend(regs[14]&0xffffffff, 32)<<2))), 32) + wbU64(0x1a12c4c4c)
	s.cpu.pc = regs[12]
}

func (s *fpState) wbHashPreparePaddingZeroFill(regs *[31]uint64) {
	regs[12] = 0
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[10]), ^uint32(uint64(0xf)), 1)
	regs[13] = boolU64(s.cpu.c && !s.cpu.z)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[10]), ^uint32(uint64(0x10)), 1)
	regs[15] = 0x6
	regs[14] = (boolU64(!s.cpu.c) & 0xffffffff) * regs[15] & 0xffffffff
	regs[13] = (regs[14] + ((regs[13] << 2) & 0xffffffff)) & 0xffffffff
	regs[16], regs[11] = (regs[13]+(regs[11]&0xffffffff))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[9]+(fpSignExtend(ternaryU64(s.cpu.c, regs[11]&0xffffffff, ((regs[11]&0xffffffff)+1)&0xffffffff)&0xffffffff, 32)<<2))), 32)
	regs[13], regs[11] = regs[11]+wbU64(0x1a12c4c84), regs[16]
	s.cpu.pc = regs[13]
}

func (s *fpState) wbHashAlignPaddingZeroFill(regs *[31]uint64) {
	regs[12], regs[14], regs[15] = 0, 0, regs[10]&0xf
	regs[13], s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[10], ^regs[15], 1)
	regs[0], regs[11], regs[16], regs[17] = 0xfffffffa, (((((((((boolU64(!s.cpu.z))&0xffffffff)*uint64(0xfffffffa))&0xffffffff)&0xffffffff)+((boolU64(s.cpu.z)<<1)&0xffffffff))&0xffffffff)&0xffffffff)+(regs[16]&0xffffffff))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[9]+(fpSignExtend(((regs[16]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32), 0x1a12c4cc4
	regs[16] += regs[17]
	s.cpu.pc = regs[16]
}

func (s *fpState) wbHashZeroPaddingVector(regs *[31]uint64) {
	regs[12] = regs[8] + regs[14]
	s.doSIMD(0x2f00e400)
	s.mem.write64(regs[12]+0x0, s.cpu.vreg[0][0])
	s.mem.write64((regs[12]+0x0)+8, s.cpu.vreg[0][0])
	regs[14] += 0x10
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[14], ^regs[13], 1)
	regs[12], regs[11] = ((regs[11]&0xffffffff)+(boolU64(s.cpu.z)&0xffffffff)*uint64(0xa))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[9]+(fpSignExtend(((regs[11]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)
	regs[16], regs[11] = regs[11]+wbU64(0x1a12c4d04), regs[12]
	s.cpu.pc = regs[16]
}

func (s *fpState) wbHashDispatchPaddingZeroFill(regs *[31]uint64) {
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[15]), ^uint32(uint64(0x0)), 1)
	regs[15], regs[11] = (regs[12]+boolU64(s.cpu.z))&0xffffffff, (((((((((boolU64(s.cpu.z))&0xffffffff)&^0x4)|(((((boolU64(s.cpu.z))&0xffffffff)>>30)|(((boolU64(s.cpu.z))&0xffffffff)<<2))&0x4))&0xffffffff)-((((boolU64(!s.cpu.z))&0xffffffff)<<1)&0xffffffff))&0xffffffff)&0xffffffff)+(regs[12]&0xffffffff))&0xffffffff
	regs[14], regs[12] = fpSignExtend(uint64(s.mem.read32(regs[9]+(fpSignExtend(regs[15]&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c4d40), regs[13]
	s.cpu.pc = regs[14]
}

func (s *fpState) wbHashEnterPaddingZeroFill(regs *[31]uint64) {
	regs[13] = 0x1a12c4d7c
	s.cpu.pc = 0x1a12c4d7c
}

func (s *fpState) wbHashPaddingZeroFillLoop(regs *[31]uint64) {
	for {
		s.mem.write8(regs[8]+regs[12], 0)
		regs[12]++
		_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[12], ^regs[10], 1)
		regs[14], regs[16] = (regs[11]+boolU64(s.cpu.z))&0xffffffff, (((boolU64(s.cpu.z)&0xffffffff)>>29)|((boolU64(s.cpu.z)&0xffffffff)<<3))&0xfffffff8
		regs[15] = (regs[16] - boolU64(s.cpu.z)) & 0xffffffff
		regs[11], regs[14] = (regs[15]+regs[11])&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[9]+(fpSignExtend(((regs[14]+0x4)&0xffffffff), 32)<<2))), 32)+regs[13]
		s.cpu.pc = regs[14]
		if s.cpu.pc == 0x1a12c4d7c {
			continue
		}
		return
	}
}

func (s *fpState) wbHashPreparePaddingDigestCall(regs *[31]uint64) {
	regs[23], regs[24], regs[8] = (regs[11]-0x7)&0xffffffff, regs[20]+0x18, s.cpu.sp+0x30
	s.mem.write64(s.cpu.sp+0x18, regs[8])
	regs[22], regs[21], regs[19], regs[8] = 0x88e63580c9fc1df2, 0x4378db61, s.mem.read64(regs[19]+0x10), (((s.cpu.sp+0x48)&0xffffffff)^(regs[3]&0xffffffff))&0xffffffff
	regs[28] = (regs[8] * (regs[2] & 0xffffffff)) & 0xffffffff
	regs[8] = (((uint64(0x1c6d04b4) + 0xa) & 0xffffffff) - regs[28]) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x50, uint32(regs[8]))
	regs[8] = ((((regs[23] & 0xffffffff) - regs[28]) & 0xffffffff) - 0x2) & 0xffffffff
	s.mem.write32(s.cpu.sp+0xc, uint32(regs[8]))
	s.mem.write32(s.cpu.sp+0x54, uint32(regs[8]))
	s.mem.write64(s.cpu.sp+0x48, regs[24])
	regs[0], regs[8], regs[30] = s.cpu.sp+0x48, s.mem.read64(s.cpu.sp+0x28), 0x1a12c4e18
	s.cpu.pc = regs[8]
}

func (s *fpState) wbHashPreparePaddingDigestWord0(regs *[31]uint64) {
	regs[8], regs[9], regs[26], regs[27] = uint64(s.mem.read32(regs[20]+0x10)), regs[20]+0x50, 0x54eb11d6, 0xd5b7eb0e
	regs[10], regs[11] = ((((uint64(0x54eb11d6)+((regs[8]<<1)&0xffffffff))&0xffffffff)&0xffffffff)&uint64(0xd5b7eb0e))&0xffffffff, (((s.cpu.sp+0x48)&0xffffffff)^(regs[22]&0xffffffff))&0xffffffff
	regs[22], regs[11] = (regs[11]*(regs[21]&0xffffffff))&0xffffffff, 0x15517e72
	regs[21] = (regs[11] - regs[22]) & 0xffffffff
	regs[8] = (((regs[21] + regs[8]) & 0xffffffff) - regs[10]) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x4c, uint32(regs[8]))
	s.mem.write64(s.cpu.sp+0x50, regs[9])
	regs[8] = ((regs[22] & 0xffffffff) + uint64(0xc1766ea)) & 0xffffffff
	regs[25] = (regs[8] + (regs[23] & 0xffffffff)) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x48, uint32(regs[25]))
	regs[0], regs[30] = s.cpu.sp+0x48, 0x1a12c4e7c
	s.cpu.pc = 0x1a12d95cc
}

func (s *fpState) wbHashPreparePaddingDigestWord1(regs *[31]uint64) {
	regs[8], regs[9] = uint64(s.mem.read32(regs[20]+0x14)), regs[20]+0x54
	regs[10] = (((((regs[26] & 0xffffffff) + ((regs[8] << 1) & 0xffffffff)) & 0xffffffff) & 0xffffffff) & (regs[27] & 0xffffffff)) & 0xffffffff
	regs[8] = ((((regs[21] & 0xffffffff) + regs[8]) & 0xffffffff) - regs[10]) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x48, uint32(regs[25]))
	s.mem.write32((s.cpu.sp+0x48)+4, uint32(regs[8]))
	s.mem.write64(s.cpu.sp+0x50, regs[9])
	regs[0], regs[30] = s.cpu.sp+0x48, 0x1a12c4ea4
	s.cpu.pc = 0x1a12d95cc
}

func (s *fpState) wbHashPreparePaddingTailCall(regs *[31]uint64) {
	regs[8] = (((regs[22] + regs[23]) & 0xffffffff) - 0x1) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x48, uint32(regs[8]))
	regs[8] = ((regs[22] & 0xffffffff) ^ uint64(0x54f2c340)) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x4c, uint32(regs[8]))
	regs[8] = (uint64(0x1b5257bd) - (regs[22] & 0xffffffff)) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x60, uint32(regs[8]))
	regs[8] = s.mem.read64(s.cpu.sp + 0x18)
	s.stpSP(0x50, regs[8], regs[24])
	regs[0], regs[8], regs[30] = s.cpu.sp+0x48, s.mem.read64(s.cpu.sp+0x10), 0x1a12c4ee4
	s.cpu.pc = regs[8]
}

func (s *fpState) wbHashAccumulatePaddingDigest(regs *[31]uint64) {
	regs[8], regs[9], regs[10] = uint64(s.mem.read32(s.cpu.sp+0x30)), uint64(s.mem.read32(regs[20]+0x0)), uint64(s.mem.read32((regs[20]+0x0)+4))
	regs[8] = (regs[9] + regs[8]) & 0xffffffff
	s.mem.write32(regs[20]+0x0, uint32(regs[8]))
	regs[8] = ((regs[10] & 0xffffffff) + (uint64(s.mem.read32(s.cpu.sp+0x34)) & 0xffffffff)) & 0xffffffff
	s.mem.write32(regs[20]+0x4, uint32(regs[8]))
	regs[8], regs[9], regs[10] = uint64(s.mem.read32(s.cpu.sp+0x38)), uint64(s.mem.read32(regs[20]+0x8)), uint64(s.mem.read32((regs[20]+0x8)+4))
	regs[8] = (regs[9] + regs[8]) & 0xffffffff
	s.mem.write32(regs[20]+0x8, uint32(regs[8]))
	regs[8] = ((regs[10] & 0xffffffff) + (uint64(s.mem.read32(s.cpu.sp+0x3c)) & 0xffffffff)) & 0xffffffff
	s.mem.write32(regs[20]+0xc, uint32(regs[8]))
	regs[8] = (((s.cpu.sp + 0x48) & 0xffffffff) ^ (wbU64(0xaaccb5b2781ed8d) & 0xffffffff)) & 0xffffffff
	s.mem.write64(s.cpu.sp+0x48, regs[20])
	regs[9], regs[10] = 0x242c6273, 0xd698f130
	regs[8] = (regs[10] - (regs[8]&0xffffffff)*regs[9]) & 0xffffffff
	regs[23] = (regs[8] + (regs[23] & 0xffffffff)) & 0xffffffff
	s.mem.write32(s.cpu.sp+0x50, uint32(regs[23]))
	s.mem.write64(s.cpu.sp+0x58, regs[24])
	regs[25], regs[0], regs[21], regs[30] = regs[24], s.cpu.sp+0x48, s.mem.read64(s.cpu.sp+0x20), 0x1a12c4f68
	s.cpu.pc = regs[21]
}

func (s *fpState) wbHashPreparePaddingNibbleCall(regs *[31]uint64) {
	regs[8], regs[24] = 0x1c6d04b4, (uint64(0x1c6d04b4)-(regs[28]&0xffffffff))&0xffffffff
	s.mem.write64(s.cpu.sp+0x48, regs[20])
	regs[22] = uint64(s.mem.read32(s.cpu.sp + 0xc))
	s.mem.write32(s.cpu.sp+0x50, uint32(regs[24]))
	s.mem.write32((s.cpu.sp+0x50)+4, uint32(regs[22]))
	regs[0], regs[27], regs[30] = s.cpu.sp+0x48, s.mem.read64(s.cpu.sp+0x28), 0x1a12c4f8c
	s.cpu.pc = regs[27]
}

func (s *fpState) wbHashCopyXorLowNibbleWindow(regs *[31]uint64, src, dst uint64, count int) {
	for offset := uint64(0); offset < uint64(count); offset++ {
		regs[8] = uint64(s.mem.read8(src + offset))
		regs[9] = ((regs[8] << 1) & 0x1e) & 0xffffffff
		regs[8] = (regs[8] ^ wbHashCopyXorByte) & 0xff
		s.mem.write8(dst+offset, uint8(regs[8]))
	}
}

func (s *fpState) wbHashCopyPaddingNibbleBlock(regs *[31]uint64) {
	s.wbHashCopyXorLowNibbleWindow(regs, regs[20], regs[19], 16)
	s.mem.write64(s.cpu.sp+0x48, regs[20])
	regs[26] = regs[22]
	s.mem.write32(s.cpu.sp+0x50, uint32(regs[24]))
	s.mem.write32((s.cpu.sp+0x50)+4, uint32(regs[26]))
	regs[0], regs[22], regs[30] = s.cpu.sp+0x48, regs[27], 0x1a12c50e4
	s.cpu.pc = regs[22]
}

func (s *fpState) wbHashPrepareFinalPaddingCall(regs *[31]uint64) {
	s.mem.write64(s.cpu.sp+0x58, regs[25])
	s.mem.write32(s.cpu.sp+0x50, uint32(regs[23]))
	s.mem.write64(s.cpu.sp+0x48, regs[20])
	regs[0], regs[30] = s.cpu.sp+0x48, 0x1a12c50f8
	s.cpu.pc = regs[21]
}

func (s *fpState) wbHashPrepareShiftedNibbleCall(regs *[31]uint64) {
	s.mem.write32(s.cpu.sp+0x50, uint32(regs[24]))
	s.mem.write32((s.cpu.sp+0x50)+4, uint32(regs[26]))
	s.mem.write64(s.cpu.sp+0x48, regs[20])
	regs[0], regs[30] = s.cpu.sp+0x48, 0x1a12c5108
	s.cpu.pc = regs[22]
}

func (s *fpState) wbHashCopyShiftedNibbleBlockAndFinish(regs *[31]uint64) {
	s.wbHashCopyXorLowNibbleWindow(regs, regs[20], regs[19]+4, 16)
	s.mem.write64(regs[20]+0x0, 0)
	s.mem.write64((regs[20]+0x0)+8, 0)
	regs[8] = 0x558a7715
	s.doSIMDN(0x0e040d00, 0x2f00e401)
	s.mem.write64(regs[20]+0x10, s.cpu.vreg[0][0])
	s.mem.write64((regs[20]+0x10)+8, s.cpu.vreg[1][0])
	s.mem.write64(regs[20]+0x20, s.cpu.vreg[1][0])
	s.mem.write64((regs[20]+0x20)+8, s.cpu.vreg[1][0])
	s.mem.write64(regs[20]+0x30, s.cpu.vreg[1][0])
	s.mem.write64((regs[20]+0x30)+8, s.cpu.vreg[1][0])
	s.mem.write64(regs[20]+0x40, s.cpu.vreg[1][0])
	s.mem.write64((regs[20]+0x40)+8, s.cpu.vreg[1][0])
	s.mem.write64(regs[20]+0x50, s.cpu.vreg[1][0])
	regs[8], regs[9] = s.mem.read64(regs[29]+0xffffffffffffffa8), wbHashStackGuardValue
	regs[8] = regs[9] - regs[8]
	if s.jmpc(regs[8] != 0, 0x1a12c52a8) {
		return
	}
	s.ldpSPInto(0x70, &regs[28], &regs[27], &regs[26], &regs[25], &regs[24], &regs[23], &regs[22], &regs[21], &regs[20], &regs[19], &regs[29], &regs[30])
	s.cpu.sp += 0xd0
	s.cpu.pc = regs[30]
}

func (s *fpState) wbHashEnterRangeTableBuilder(regs *[31]uint64) {
	regs[8] = ((((regs[0] & 0xffffffff) ^ uint64(0xd987bb6d)) & 0xffffffff) * uint64(0x66049efd)) & 0xffffffff
	regs[14], regs[8], regs[13], regs[9], regs[10] = (uint64(s.mem.read32(regs[0]+0x8))^regs[8])&0xffffffff, s.mem.read64(regs[0]+0x10), s.mem.read64((regs[0]+0x10)+8), s.mem.read64(regs[0]+0x20), s.mem.read64(regs[0]+0x0)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[8], ^uint64(0x0), 1)
	regs[11] = boolU64(s.cpu.z)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[13], ^wbU64(0x315c9c0472d221ee), 1)
	regs[12] = boolU64(s.cpu.z)
	regs[11] = (regs[11] | regs[12]) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[9], ^uint64(0x0), 1)
	regs[12] = boolU64(s.cpu.z)
	regs[11] = (regs[12] | regs[11]) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[10], ^wbU64(0xdcd1872108638028), 1)
	regs[15], regs[11] = (regs[11]|boolU64(s.cpu.z))&0xffffffff, 0x3ccb976
	s.cpu.sp -= 0x70
	s.stpSPN(0x10, regs[28], regs[27], regs[26], regs[25], regs[24], regs[23], regs[22], regs[21], regs[20], regs[19], regs[29], regs[30])
	regs[12], regs[17] = 0x1a13106b0, 0x1a12c6744
	regs[16] = fpSignExtend(uint64(s.mem.read32(regs[12]+(fpSignExtend(((regs[14]+regs[15])&0xffffffff), 32)<<2))), 32) + wbU64(0x1a12c6744)
	s.cpu.pc = regs[16]
}

func (s *fpState) wbHashCheckRangeTableSentinel(regs *[31]uint64) {
	regs[15] = (regs[15] ^ 0x1) & 0xffffffff
	regs[14] = ((regs[14] & 0xffffffff) - ((regs[15] << 3) & 0xffffffff)) & 0xffffffff
	s.mem.write32(regs[9]+0x0, 0)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(uint64(s.mem.read8(regs[10]+wbU64(0x232e78def79c7fe9)))), ^uint32(uint64(0x1b)), 1)
	regs[15], regs[16], regs[1], regs[17], regs[11] = boolU64(!s.cpu.z), boolU64(s.cpu.z), 0x1a12c6784, fpSignExtend(uint64(s.mem.read32(regs[12]+(fpSignExtend(ternaryU64(!s.cpu.z, regs[14], (regs[14]+1)&0xffffffff)&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c6784), (regs[11]+0x3)&0xffffffff
	s.cpu.pc = regs[17]
}

func (s *fpState) wbHashCheckRangeTableStartByte(regs *[31]uint64) {
	regs[16], regs[11], regs[14] = (((((regs[14]&0xffffffff)+((regs[15]<<3)&0xffffffff))&0xffffffff)&0xffffffff)+(((((regs[16]&0xffffffff)&^0x4)|((((regs[16]&0xffffffff)>>30)|((regs[16]&0xffffffff)<<2))&0x4))&0xffffffff)&0xffffffff))&0xffffffff, 0x3cd610a, (uint64(s.mem.read8(regs[13]+wbU64(0xcea363fb8d2dde18)))-0x1a)&0xffffffff
	{
		result := regs[14] & 0xff
		s.cpu.n = (result >> 31) != 0
		s.cpu.z = result == 0
		s.cpu.c = false
		s.cpu.v = false
	}
	regs[17], regs[1], regs[2], regs[15] = boolU64(!s.cpu.z), boolU64(s.cpu.z), 0x1a12c67d0, fpSignExtend(uint64(s.mem.read32(regs[12]+(fpSignExtend(((regs[16]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c67d0)
	s.cpu.pc = regs[15]
}

func (s *fpState) wbHashPrepareRangeTableLoop(regs *[31]uint64) {
	regs[2], regs[3] = uint64(s.mem.read8(regs[13]+wbU64(0xcea363fb8d2dde19))), regs[14]&0xff
	regs[13] = (regs[2] - 0x1a) & 0xffffffff
	regs[14] = regs[13] & 0xff
	product := (regs[14] * regs[3]) & 0xffffffff
	regs[15], regs[1] = ((product>>30)|(product<<2))&0xfffffffc, (((regs[1]&0xffffffff)&^0x2)|((((regs[1]&0xffffffff)>>31)|((regs[1]&0xffffffff)<<1))&0x2))&0xffffffff
	regs[16] = (((((regs[16] & 0xffffffff) + ((regs[17] << 1) & 0xffffffff)) & 0xffffffff) & 0xffffffff) + regs[1]) & 0xffffffff
	rotatedByte := (((regs[2] & 0xffffffff) >> 30) | ((regs[2] & 0xffffffff) << 2)) & 0xfffffffc
	regs[26], regs[16], regs[17], regs[1] = (regs[16]-0x5)&0xffffffff, (regs[3]+uint64(0x47c976bc))&0xffffffff, regs[10]+wbU64(0x232e78def79c7fe1), (rotatedByte-0x68)&0xffffffff
	s.mem.write32(s.cpu.sp+0xc, uint32(regs[1]))
	regs[2], regs[24], regs[3], regs[4], regs[5], regs[6], regs[19], regs[20], regs[21], regs[22], regs[23] = 0x6f, 0x5b0484b, 0x6, 0x1a12c68f4, 0x42192e72, 0x1a12c6a2c, 0x232e78def79c8470, 0x232e78def79c8478, 0x232e78def79c8480, 0x232e78def79c8488, 0x1a12c6930
	{
		result := regs[13] & 0xff
		s.cpu.n = (result >> 31) != 0
		s.cpu.z = result == 0
		s.cpu.c = false
		s.cpu.v = false
	}
	regs[27] = (((boolU64(s.cpu.z) & 0xffffffff) &^ 0x8) | ((((boolU64(s.cpu.z) & 0xffffffff) >> 29) | ((boolU64(s.cpu.z) & 0xffffffff) << 3)) & 0x8)) & 0xffffffff
	regs[25], regs[26] = ((((regs[27]+(boolU64(!s.cpu.z)&0xffffffff)*(regs[3]&0xffffffff))&0xffffffff)&0xffffffff)+(regs[26]&0xffffffff))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[12]+(fpSignExtend(((regs[26]+boolU64(s.cpu.z))&0xffffffff)&0xffffffff, 32)<<2))), 32)+wbU64(0x1a12c68f4)
	s.cpu.pc = regs[26]
}

func (s *fpState) wbHashPopulateRangeTableStep(regs *[31]uint64) {
	regs[27], regs[30] = regs[24]+wbU64(0xfffffffffa4fb7b5), (((regs[2]-0x6f)&0xffffffff)&0xff)&0xffffffff
	regs[7] = (uint64(s.mem.read8(regs[17]+0x0)) & 0xffffffff) * regs[30] & 0xffffffff
	regs[30] = uint64(fpUDiv32(uint32(regs[7]), uint32(regs[15])))
	regs[7] = (regs[7] - (regs[30]&0xffffffff)*(regs[15]&0xffffffff)) & 0xffffffff
	regs[7], regs[30] = ((regs[7]>>22)|(regs[7]<<10))&0xfffffc00, regs[10]+(regs[27]<<7)
	regs[7] = regs[8] + regs[7]
	s.mem.write64(regs[30]+regs[19], regs[7])
	regs[7] = (uint64(s.mem.read32(regs[9]+0x0)) + 0x400) & 0xffffffff
	s.mem.write32(regs[9]+0x0, uint32(regs[7]))
	regs[1] = (uint64(s.mem.read8(regs[17]+0x0)) & 0xffffffff) * (((regs[2] - 0x6e) & 0xffffffff) & 0xff) & 0xffffffff
	regs[7] = uint64(fpUDiv32(uint32(regs[1]), uint32(regs[15])))
	regs[1] = (regs[1] - (regs[7]&0xffffffff)*(regs[15]&0xffffffff)) & 0xffffffff
	regs[1] = regs[8] + (((regs[1] >> 22) | (regs[1] << 10)) & 0xfffffc00)
	s.mem.write64(regs[30]+regs[20], regs[1])
	regs[1] = (uint64(s.mem.read32(regs[9]+0x0)) + 0x400) & 0xffffffff
	s.mem.write32(regs[9]+0x0, uint32(regs[1]))
	regs[1] = (uint64(s.mem.read8(regs[17]+0x0)) & 0xffffffff) * (((regs[2] - 0x6d) & 0xffffffff) & 0xff) & 0xffffffff
	regs[7] = uint64(fpUDiv32(uint32(regs[1]), uint32(regs[15])))
	regs[1] = (regs[1] - (regs[7]&0xffffffff)*(regs[15]&0xffffffff)) & 0xffffffff
	regs[1] = regs[8] + (((regs[1] >> 22) | (regs[1] << 10)) & 0xfffffc00)
	s.mem.write64(regs[30]+regs[21], regs[1])
	regs[1] = (uint64(s.mem.read32(regs[9]+0x0)) + 0x400) & 0xffffffff
	s.mem.write32(regs[9]+0x0, uint32(regs[1]))
	regs[1] = (uint64(s.mem.read8(regs[17]+0x0)) & 0xffffffff) * (((regs[2] - 0x6c) & 0xffffffff) & 0xff) & 0xffffffff
	regs[7] = uint64(fpUDiv32(uint32(regs[1]), uint32(regs[15])))
	regs[1], regs[26] = (regs[1]-(regs[7]&0xffffffff)*(regs[15]&0xffffffff))&0xffffffff, uint64(0x0)+0x1
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[26], ^regs[14], 1)
	regs[7], regs[1] = (regs[25]+boolU64(s.cpu.z))&0xffffffff, regs[8]+((((regs[1]&0xffffffff)>>22)|((regs[1]&0xffffffff)<<10))&0xfffffc00)
	s.mem.write64(regs[30]+regs[22], regs[1])
	regs[28], regs[30], regs[1] = (regs[2]+0x4)&0xffffffff, boolU64(s.cpu.z), (uint64(s.mem.read32(regs[9]+0x0))+0x400)&0xffffffff
	regs[25], regs[7] = ((regs[25]&0xffffffff)+((regs[30]<<1)&0xffffffff))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[12]+(fpSignExtend(((regs[7]+0x5)&0xffffffff), 32)<<2))), 32)+regs[23]
	s.mem.write32(regs[9]+0x0, uint32(regs[1]))
	s.cpu.pc = regs[7]
}

func (s *fpState) wbHashAdvanceRangeTableLoop(regs *[31]uint64) {
	regs[25], regs[2], regs[1], regs[24] = (regs[25]+0x1)&0xffffffff, (uint64(s.mem.read32(s.cpu.sp+0xc))+(regs[2]&0xffffffff))&0xffffffff, regs[24]+regs[5], regs[24]+0x1
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[1], ^regs[16], 1)
	regs[1], regs[7], regs[27] = boolU64(s.cpu.c), (((boolU64(!s.cpu.c)&0xffffffff)&^0x8)|((((boolU64(!s.cpu.c)&0xffffffff)>>29)|((boolU64(!s.cpu.c)&0xffffffff)<<3))&0x8))&0xffffffff, ternaryU64(s.cpu.c, regs[25]&0xffffffff, ((regs[25]&0xffffffff)+1)&0xffffffff)
	regs[1] = (((((regs[1] & 0xffffffff) - ((regs[1] << 2) & 0xffffffff)) & 0xffffffff) & 0xffffffff) - regs[7]) & 0xffffffff
	regs[26], regs[1] = (regs[1]+(regs[25]&0xffffffff))&0xffffffff, fpSignExtend(uint64(s.mem.read32(regs[12]+(fpSignExtend(regs[27]&0xffffffff, 32)<<2))), 32)+regs[6]
	s.cpu.pc = regs[1]
}

func (s *fpState) wbHashFinishRangeTableBuilder(regs *[31]uint64) {
	s.mem.write32(regs[0]+0xc, uint32(regs[11]))
	s.ldpSPInto(0x10, &regs[28], &regs[27], &regs[26], &regs[25], &regs[24], &regs[23], &regs[22], &regs[21], &regs[20], &regs[19], &regs[29], &regs[30])
	s.cpu.sp += 0x70
	s.cpu.pc = regs[30]
}
