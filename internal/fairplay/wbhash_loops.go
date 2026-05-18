package fairplay

const (
	wbHashByteReverseStop      = uint32(0x65c52246)
	wbHashDoneDispatchStep     = uint64(0x11)
	wbHashFillE1Byte           = uint8(0xe1)
	wbHashFillE1Stop           = uint32(0xdeddf616)
	wbHashFillE1DispatchStep   = uint64(0xe)
	wbHashFillE1LoopPC         = uint64(0x1a12a5d04)
	wbHashZero16LoopPC         = uint64(0x1a12ae760)
	wbHashZeroFillDispatchBias = uint64(0x8)
	wbHashCopyXorByte          = uint64(0xf)
	wbHashCopyXorDispatchBias  = uint64(0x12)
	wbHashCopyXorWindowLoopPC  = uint64(0x1a12b9748)
	wbHashCopyXorWindowBias    = uint64(0xcd4ae65f)
	wbHashCopyXorWindowNext    = uint64(0xfa9bfeb0)
	wbHashCopyXorWindowStep    = uint64(0xffffffe5)
	wbHashCopyXorTailLoopPC    = uint64(0x1a12b9e10)
	wbHashCopyXorTailBias      = uint64(0xda14279f)
	wbHashCopyXorTailNext      = uint64(0xdfed0dc7)
	wbHashCopyXorTailDestBias  = uint64(0x18)
	wbHashCopyXorTailStep      = uint64(0xffffffe8)
	wbHashCopyXorVectorLoopPC  = uint64(0x1a12b98fc)
	wbHashCopyXorVectorStep    = uint64(0x5)
)

func (s *fpState) wbHashReverseWordBytesStep(regs *[31]uint64) {
	wordAddr := regs[8]
	firstByte := s.mem.read8(wordAddr)
	fourthByte := s.mem.read8(wordAddr + 3)
	s.mem.write8(wordAddr, fourthByte)
	s.mem.write8(wordAddr+3, firstByte)

	regs[11] = (regs[11] - 1) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[11]), ^wbHashByteReverseStop, 1)
	done := boolU64(s.cpu.z)
	oldDispatchIndex := regs[12]
	regs[14] = (oldDispatchIndex + done) & 0xffffffff
	regs[12] = ((oldDispatchIndex & 0xffffffff) + done*0x6) & 0xffffffff

	secondByte := s.mem.read8(wordAddr + 1)
	thirdByte := s.mem.read8(wordAddr + 2)
	s.mem.write8(wordAddr+1, thirdByte)
	s.mem.write8(wordAddr+2, secondByte)

	regs[8] = wordAddr + 4
	regs[13] = wbU64(0x1a12a2000) + 0x560
	dispatchOffset := fpSignExtend(regs[14]&0xffffffff, 32) << 2
	regs[10] = fpSignExtend(uint64(s.mem.read32(regs[9]+dispatchOffset)), 32) + regs[13]
	s.cpu.pc = regs[10]
}

func (s *fpState) wbHashFillE1Step(regs *[31]uint64) {
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[17]), ^uint32(regs[7]), 1)
	firstCarry := boolU64(!s.cpu.c)
	nextBound := (regs[12] + regs[7]) & 0xffffffff

	s.mem.write8(regs[9]+(regs[12]&0xffffffff), wbHashFillE1Byte)
	regs[12] = (regs[12] + 1) & 0xffffffff
	nextBound = (nextBound + 1) & 0xffffffff

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[12]), ^wbHashFillE1Stop, 1)
	stopCrossed := boolU64(s.cpu.c && !s.cpu.z)
	dispatchFlag := (firstCarry ^ stopCrossed) & 0xffffffff

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(nextBound), ^uint32(regs[17]), 1)
	secondCarry := boolU64(!s.cpu.c)

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(dispatchFlag), ^uint32(0), 1)
	dispatchCarry := ternaryU64(!s.cpu.z, firstCarry&0xffffffff, secondCarry&0xffffffff)
	dispatchIndex := (dispatchCarry + regs[15]) & 0xffffffff

	regs[2] = (dispatchCarry ^ 1) & 0xffffffff
	regs[4] = wbHashFillE1DispatchStep
	regs[11] = dispatchIndex
	regs[15] = ((regs[15] & 0xffffffff) + (regs[2]&0xffffffff)*(regs[4]&0xffffffff)) & 0xffffffff
	regs[11] = fpSignExtend(uint64(s.mem.read32(regs[8]+(fpSignExtend(regs[11]&0xffffffff, 32)<<2))), 32)
	regs[2] = wbHashFillE1LoopPC
	regs[11] += regs[2]
	s.cpu.pc = regs[11]
}

func (s *fpState) wbHashZero16Step(regs *[31]uint64) {
	regs[12] = regs[8] + regs[14]
	s.doSIMD(0x2f00e400)
	s.mem.write64(regs[12], s.cpu.vreg[0][0])
	s.mem.write64(regs[12]+8, s.cpu.vreg[0][0])

	regs[14] += 0x10
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[14], ^regs[13], 1)
	done := boolU64(s.cpu.z)
	regs[16] = (regs[11] + done) & 0xffffffff
	regs[11] = ((regs[11] & 0xffffffff) - (((done & 0xffffffff) << 1) & 0xffffffff)) & 0xffffffff

	regs[12] = wbStaticPaddingZeroTarget(wbHashZero16LoopPC, regs[16]&0xffffffff)
	regs[16] = wbHashZero16LoopPC
	s.cpu.pc = regs[12]
}

func (s *fpState) wbHashZeroFillStep(regs *[31]uint64) {
	s.mem.write8(regs[8]+regs[12], 0)
	regs[12]++

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[12], ^regs[10], 1)
	done := boolU64(s.cpu.z)
	regs[14] = (regs[11] + done) & 0xffffffff
	regs[15] = done * wbHashDoneDispatchStep

	dispatchIndex := (regs[14] + wbHashZeroFillDispatchBias) & 0xffffffff
	regs[11] = (regs[15] + regs[11]) & 0xffffffff
	regs[14] = wbStaticPaddingZeroTarget(regs[13], dispatchIndex)
	s.cpu.pc = regs[14]
}

func (s *fpState) wbHashCopyXorNibbleStep(regs *[31]uint64) {
	copyOffset := regs[12] + regs[9]
	regs[13] = copyOffset
	regs[12]++

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[12], ^regs[10], 1)
	done := boolU64(s.cpu.z)
	regs[15] = (regs[20] + done) & 0xffffffff
	regs[14] = (uint64(s.mem.read8(regs[26]+copyOffset)) ^ wbHashCopyXorByte) & 0xffffffff
	s.mem.write8(regs[8]+copyOffset, byte(regs[14]))

	regs[20] = (regs[20] + done*wbHashDoneDispatchStep) & 0xffffffff
	dispatchIndex := (regs[15] + wbHashCopyXorDispatchBias) & 0xffffffff
	dispatchOffset := fpSignExtend(dispatchIndex, 32) << 2
	regs[13] = fpSignExtend(uint64(s.mem.read32(regs[19]+dispatchOffset)), 32) + regs[11]
	s.cpu.pc = regs[13]
}

func (s *fpState) wbHashCopyXorWindowStep(regs *[31]uint64) {
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[10]), ^uint32(regs[9]), 1)
	firstCarry := boolU64(!s.cpu.c)
	offset := (regs[12] + wbHashCopyXorWindowBias) & 0xffffffff
	copyByte := (uint64(s.mem.read8(regs[26]+offset)) ^ wbHashCopyXorByte) & 0xffffffff
	s.mem.write8(regs[8]+offset, byte(copyByte))

	nextCompare := (regs[12] + wbHashCopyXorWindowNext) & 0xffffffff
	regs[12] = (regs[12] + 1) & 0xffffffff

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(nextCompare), ^uint32(regs[9]), 1)
	dispatchFlag := (firstCarry ^ boolU64(!s.cpu.c)) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(nextCompare), ^uint32(regs[10]), 1)
	secondCarry := boolU64(!s.cpu.c)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(dispatchFlag), ^uint32(0), 1)
	dispatchCarry := ternaryU64(!s.cpu.z, firstCarry&0xffffffff, secondCarry&0xffffffff)

	regs[14] = (dispatchCarry ^ 1) & 0xffffffff
	regs[15] = wbHashCopyXorWindowStep
	dispatchOffset := fpSignExtend((dispatchCarry+regs[11])&0xffffffff, 32) << 2
	regs[13] = fpSignExtend(uint64(s.mem.read32(regs[19]+dispatchOffset)), 32)
	regs[11] = ((regs[11] & 0xffffffff) + (regs[14]&0xffffffff)*(regs[15]&0xffffffff)) & 0xffffffff
	regs[14] = wbHashCopyXorWindowLoopPC
	regs[13] += regs[14]
	s.cpu.pc = regs[13]
}

func (s *fpState) wbHashCopyXorTailStep(regs *[31]uint64) {
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(regs[8]), ^uint32(regs[14]), 1)
	firstCarry := boolU64(!s.cpu.c)
	offset := (regs[10] + wbHashCopyXorTailBias) & 0xffffffff
	copyByte := (uint64(s.mem.read8(regs[26]+offset)) ^ wbHashCopyXorByte) & 0xffffffff
	s.mem.write8(regs[21]+offset+wbHashCopyXorTailDestBias, byte(copyByte))

	nextCompare := (regs[10] + wbHashCopyXorTailNext) & 0xffffffff
	regs[10] = (regs[10] + 1) & 0xffffffff

	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(nextCompare), ^uint32(regs[14]), 1)
	dispatchFlag := (firstCarry ^ boolU64(!s.cpu.c)) & 0xffffffff
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(nextCompare), ^uint32(regs[8]), 1)
	secondCarry := boolU64(!s.cpu.c)
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpFlags32(uint32(dispatchFlag), ^uint32(0), 1)
	dispatchCarry := ternaryU64(!s.cpu.z, firstCarry&0xffffffff, secondCarry&0xffffffff)

	regs[12] = (dispatchCarry ^ 1) & 0xffffffff
	regs[13] = wbHashCopyXorTailStep
	dispatchOffset := fpSignExtend((dispatchCarry+regs[9])&0xffffffff, 32) << 2
	regs[11] = fpSignExtend(uint64(s.mem.read32(regs[19]+dispatchOffset)), 32)
	regs[9] = ((regs[9] & 0xffffffff) + (regs[12]&0xffffffff)*(regs[13]&0xffffffff)) & 0xffffffff
	regs[12] = wbHashCopyXorTailLoopPC
	regs[11] += regs[12]
	s.cpu.pc = regs[11]
}

func (s *fpState) wbHashCopyXorVector16Step(regs *[31]uint64) {
	sourceAddr := regs[26] + regs[14]
	s.cpu.vreg[0] = [2]uint64{s.mem.read64(sourceAddr), 0}
	s.cpu.vreg[1] = [2]uint64{s.mem.read64(sourceAddr + 8), 0}

	regs[12] = regs[8] + regs[14]
	s.doSIMDN(0x0f00e5e2, 0x2e221c00, 0x2e221c21)
	s.mem.write64(regs[12], s.cpu.vreg[0][0])
	s.mem.write64(regs[12]+8, s.cpu.vreg[1][0])

	regs[14] += 0x10
	_, s.cpu.n, s.cpu.z, s.cpu.c, s.cpu.v = fpAddWithCarry64(regs[14], ^regs[15], 1)
	done := boolU64(s.cpu.z)
	regs[17] = (regs[16] + done) & 0xffffffff
	regs[16] = ((regs[16] & 0xffffffff) - done*wbHashCopyXorVectorStep) & 0xffffffff

	dispatchOffset := fpSignExtend(regs[17]&0xffffffff, 32) << 2
	regs[12] = fpSignExtend(uint64(s.mem.read32(regs[19]+dispatchOffset)), 32)
	regs[17] = wbHashCopyXorVectorLoopPC
	regs[12] += regs[17]
	s.cpu.pc = regs[12]
}
