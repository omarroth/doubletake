package fairplay

const (
	wbHashXor16ContinuePC  = uint64(0x1a12c21b0)
	wbHashLookupReturnPC   = uint64(0x1a12c2880)
	wbHashDispatchTablePC  = uint64(0x1a12c295c)
	wbHashDispatchBase     = uint64(0x1aeab68f0)
	wbHashStackGuardValue  = uint64(0xbebafecaefbeadde)
	wbHashSmallCodeTablePC = uint64(0x1a12c0118)
)

func (s *fpState) wbHashCopyStaticD3B8CWords(regs *[31]uint64) {
	for index, word := range wbStaticD3B8CWords {
		s.cpu.vreg[0] = [2]uint64{word, 0}
		s.mem.write64(regs[21]+0x18+uint64(index)*8, s.cpu.vreg[0][0])
	}
}
