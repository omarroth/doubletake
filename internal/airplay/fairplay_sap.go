package airplay

// FairPlay's proprietary SAP hash. It is not a standard cryptographic hash.

import "math/bits"

func rotateLeft8(input byte, count int) byte {
	return bits.RotateLeft8(input, count)
}

// rotateLeft8Wide deliberately preserves bits shifted above bit 7. The
// original C promotes the byte before shifting, so this is not an 8-bit rotate.
func rotateLeft8Wide(input byte, count int) uint32 {
	return uint32(input)<<count | uint32(input)>>(8-count)
}

func garbleRotateRight8(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return uint32(bits.RotateLeft8(input, -count))
}

func garbleRotateLeft8(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return uint32(bits.RotateLeft8(input, count))
}

func garbleRotateLeftWide(input byte, count uint32) uint32 {
	if count == 0 {
		return 0
	}
	return uint32(input)<<count ^ uint32(input)>>(8-count)
}

func xorFold16(out *[16]byte, in []byte) {
	for i, value := range in {
		out[i&15] ^= value
	}
}

// wrappedUint32Index preserves the original circuit's unsigned 32-bit
// underflow before reduction; ordinary negative modulo is not equivalent.
func wrappedUint32Index(value, lag, size int) int {
	return int(uint32(value-lag) % uint32(size))
}

func bitMajority(a, b, c uint32) uint32 {
	return (a & b) | ((a | b) & c)
}

func selectBits(mask, ifSet, ifClear uint32) uint32 {
	return (ifSet & mask) | (ifClear & ^mask)
}

var fairplaySAPInitialState = [20]byte{
	0x96, 0x5f, 0xc6, 0x53, 0xf8, 0x46, 0xcc, 0x18, 0xdf, 0xbe,
	0xb2, 0xf8, 0x38, 0xd7, 0xec, 0x22, 0x03, 0xd1, 0x20, 0x8f,
}

var fairplaySAPInitialMatrix = [35]byte{
	0x43, 0x54, 0x62, 0x7a, 0x18, 0xc3, 0xd6, 0xb3, 0x9a, 0x56,
	0xf6, 0x1c, 0x14, 0x3f, 0x0c, 0x1d, 0x3b, 0x36, 0x83, 0xb1,
	0x39, 0x51, 0x4a, 0xaa, 0x09, 0x3e, 0xfe, 0x44, 0xaf, 0xde,
	0xc3, 0x20, 0x9d, 0x42, 0x3a,
}

var fairplaySAPSeed = [21]byte{
	0xed, 0x25, 0xd1, 0xbb, 0xbc, 0x27, 0x9f, 0x02, 0xa2, 0xa9, 0x11,
	0x00, 0x0c, 0xb3, 0x52, 0xc0, 0xbd, 0xe3, 0x1b, 0x49, 0xc7,
}

type fairplaySAPState struct {
	state   [20]byte
	work    [210]byte
	matrix  [35]byte
	scratch [23]byte
}

func fairplaySAPHash(blockIn []byte) (keyOut [16]byte) {
	state := fairplaySAPState{
		state:  fairplaySAPInitialState,
		matrix: fairplaySAPInitialMatrix,
	}
	scratchOutput := [11]int{14, 18, 19, 0, 5, 15, 22, 21, 10, 17, 20}

	// Load input into the working state in reversed four-byte groups.
	for i := 0; i < 210; i++ {
		state.work[i] = blockIn[(i&63)^3]
	}

	// Scramble four complete passes over the 210-byte working state.
	for i := 0; i < 840; i++ {
		x := state.work[wrappedUint32Index(i, 155, len(state.work))]
		y := state.work[wrappedUint32Index(i, 57, len(state.work))]
		z := state.work[wrappedUint32Index(i, 13, len(state.work))]
		w := state.work[i%len(state.work)]
		state.work[i%len(state.work)] = byte(uint32(rotateLeft8(y, 5)) + (uint32(rotateLeft8(z, 3)) ^ uint32(w)) - uint32(rotateLeft8(x, 7)))
	}

	state.garble()

	// Fill output with 0xE1
	for i := 0; i < 16; i++ {
		keyOut[i] = 0xE1
	}

	// Apply scratch
	for i := 0; i < 11; i++ {
		if i == 3 {
			keyOut[i] = 0x3d
		} else {
			keyOut[i] += state.scratch[scratchOutput[i]]
		}
	}

	xorFold16(&keyOut, state.state[:])
	xorFold16(&keyOut, state.matrix[:])
	xorFold16(&keyOut, state.work[:])

	// Reverse scramble
	for j := 0; j < 16; j++ {
		for i := 0; i < 16; i++ {
			x := keyOut[(i-7)&15]
			y := keyOut[i]
			z := keyOut[(i-5)&15]
			w := keyOut[(i-1)&15]
			keyOut[i] = rotateLeft8(x, 1) ^ y ^ rotateLeft8(z, 6) ^ rotateLeft8(w, 5)
		}
	}
	return keyOut
}

// garble applies the fixed proprietary arithmetic circuit at the center of
// the SAP hash. Its operations intentionally use uint32 wrapping followed by
// byte truncation; it is not a standard cryptographic primitive.
func (state *fairplaySAPState) garble() {
	tmp, tmp2 := state.garbleInitialize()
	state.garbleExpand(tmp, tmp2)
	state.garbleMix()
	state.garbleFinalize()
}

func (state *fairplaySAPState) garbleInitialize() (tmp, tmp2 uint32) {
	state20 := &state.state
	work := &state.work
	state35 := &state.matrix
	scratch := &state.scratch
	stateByte := func(i int) uint32 { return uint32(state20[i]) }
	workByte := func(i int) uint32 { return uint32(work[i]) }
	matrixByte := func(i int) uint32 { return uint32(state35[i]) }
	seedByte := func(i int) uint32 { return uint32(fairplaySAPSeed[i]) }

	state35[12] = byte(0x14 + (((workByte(64) & 92) | ((workByte(99) / 3) & 35)) & seedByte(int(rotateLeft8Wide(fairplaySAPSeed[workByte(206)%21], 4)%21))))
	work[4] = byte((workByte(99) / 5) * (workByte(99) / 5) * 2)
	state35[34] = 0xb8
	matrixValue := matrixByte(int(workByte(203) % 35))
	work[153] ^= byte(matrixValue * matrixValue * workByte(190))
	state20[3] -= byte(((seedByte(int(workByte(205)%21)) >> 1) & 80) | 0x40)
	state20[16] = 0x93
	state20[13] = 0x62
	work[33] -= byte(seedByte(int(workByte(36)%21)) & 0xf6)

	tmp2 = matrixByte(int(workByte(67) % 35))
	state35[12] = 0x07

	tmp = stateByte(int(workByte(181) % 20))
	work[2] -= 64

	state20[19] = byte(seedByte(int(workByte(58) % 21)))

	scratch[0] = byte(92 - matrixByte(int(workByte(32)%35)))
	scratch[1] = byte(matrixByte(int(workByte(15)%35)) + 0x9e)
	work[34] += byte(seedByte(int((matrixByte(int(workByte(15)%35))+0x9e)&0xff)%21) / 5)
	state20[19] += byte(uint32(0xe6) - ((stateByte(int(uint32(scratch[1])%20)) >> 1) & 102))

	rotationSeed := seedByte(int(workByte(190) % 21))
	shiftAmt := rotationSeed & 7
	shifted := (workByte(72) >> shiftAmt) ^ (workByte(72) << ((7 - (rotationSeed - 1)) & 7))
	work[15] = byte((3 * (shifted - (3 * seedByte(int(workByte(126)%21))))) ^ workByte(15))

	matrixValue = matrixByte(int(workByte(181) % 35))
	state20[15] ^= byte(matrixValue * matrixValue * matrixValue)
	state35[4] ^= byte(workByte(202) / 3)

	cubeBase := bitMajority(92-stateByte(int(uint32(scratch[0])%20)), ^workByte(105), 0xc6)
	state35[1] += byte(cubeBase * cubeBase * cubeBase)

	state20[19] ^= byte(((224 | (seedByte(int(workByte(92)%21)) & 27)) * matrixByte(int(workByte(41)%35))) / 3)
	work[140] += byte(garbleRotateRight8(92, int(workByte(5)&7)))

	garbleValue := ^workByte(4) ^ matrixByte(int(workByte(12)%35))
	state35[12] += byte(bitMajority(garbleValue, workByte(182), 192))
	work[36] += 125

	mixed := bitMajority(74, workByte(138), stateByte(15))
	mixed = bitMajority(mixed, stateByte(int(workByte(43)%20)), 95)
	work[124] = byte(rotateLeft8Wide(byte(mixed), 4))

	scratch[2] = byte((((stateByte(int(uint32(scratch[1])%20)) & 95) & ((seedByte(int(workByte(68)%21)) & 46) << 1)) | 16) ^ 92)

	sum := workByte(177) + seedByte(int(workByte(79)%21))
	scratchMix := bitMajority(sum>>1, (3*workByte(148))/5, matrixByte(1))
	scratch[3] = byte(uint32(222) - scratchMix)

	leftShift := matrixByte(22) & 7
	rotated := (workByte(33) >> ((8 - leftShift) & 7)) ^ (workByte(33) << leftShift)
	state35[16] += byte(((matrixByte(int(uint32(scratch[0])%35)) & 159) | stateByte(int(uint32(scratch[1])%20)) | 8) - (rotated | 128))

	state20[14] ^= byte(matrixByte(int(uint32(scratch[3]) % 35)))
	return tmp, tmp2
}

func (state *fairplaySAPState) garbleExpand(tmp, tmp2 uint32) {
	state20 := &state.state
	work := &state.work
	state35 := &state.matrix
	scratch := &state.scratch
	stateByte := func(i int) uint32 { return uint32(state20[i]) }
	workByte := func(i int) uint32 { return uint32(work[i]) }
	matrixByte := func(i int) uint32 { return uint32(state35[i]) }
	seedByte := func(i int) uint32 { return uint32(fairplaySAPSeed[i]) }

	// Continue the fixed arithmetic circuit.
	rotated := garbleRotateLeft8(fairplaySAPSeed[stateByte(int(workByte(201)%20))%21], int((matrixByte(int(workByte(112)%35))<<1)&7))
	mask := (stateByte(int(workByte(208)%20)) & 131) | (stateByte(int(workByte(164)%20)) & 124)
	work[19] += byte(bitMajority(rotated, mask/5, 37))

	garbleValue := seedByte(int(workByte(45)%21)) + 92
	state35[8] = byte(garbleRotateRight8(140, int((garbleValue*garbleValue)&7))) ^ scratch[0]
	work[190] = 56

	work[53] = byte(^((stateByte(int(workByte(83)%20)) | 204) / 5))
	state20[13] += byte(stateByte(int(workByte(41) % 20)))
	state20[10] = byte(bitMajority(matrixByte(int(uint32(scratch[0])%35)), workByte(2), uint32(scratch[3])) / 15)

	squareBase := bitMajority(56|(seedByte(int(workByte(2)%21))&68), matrixByte(int(uint32(scratch[2])%35)), 42)
	scratch[4] = byte(squareBase*squareBase + 110)
	scratch[5] = byte(202 - uint32(scratch[4]))
	scratch[6] = work[151]
	state35[13] ^= byte(seedByte(int(uint32(scratch[0]) % 21)))

	squareBase = bitMajority(matrixByte(int(workByte(179)%35))-38, uint32(scratch[3]), 177)
	scratch[7] = byte(30 + squareBase*squareBase)
	scratch[8] = byte(uint32(scratch[7]) + 62)

	// Expand the scratch state.
	garbleValue = uint32(scratch[5]) + (uint32(scratch[0]) & 74)
	tmp3 := bitMajority(garbleValue, ^seedByte(int(uint32(scratch[0])%21)), 121)
	foldBit := bitMajority(tmp3^0xa6, uint32(scratch[0]), 4)
	work[47] = byte((matrixByte(int(workByte(89)%35)) + foldBit) ^ workByte(47))

	scratch[9] = byte(selectBits(stateByte(3), uint32(rotateLeft8(byte((tmp&179)+68), 2)), tmp2) - 15)
	work[123] ^= 221

	difference := (seedByte(int(uint32(scratch[0])%21)) / 3) - matrixByte(int(uint32(scratch[1])%35))
	garbleMask := (((uint32(scratch[0]) & 163) + 92) & 246) | (uint32(scratch[0]) & 92)
	scratch[10] = byte(difference - bitMajority(garbleMask, uint32(scratch[6]), 54))

	scratch[11] = byte(tmp3 ^ 81 ^ (((uint32(scratch[0]) >> 1) & 101) + 26))

	// Fold the expanded state back into the working buffers.
	mixed := bitMajority(uint32(scratch[10]), uint32(scratch[6]), 177)
	seed := seedByte(int(uint32(scratch[0]) % 21))
	leftSeed := (seedByte(int(uint32(scratch[0])%20)) & 177) | 176 | (seed &^ 3)
	rightSeed := ((seed & 1) + 176) | (seed &^ 3)
	combined := (mixed & leftSeed) | (mixed & 199) | (rightSeed & 199)
	scratch[12] = byte(uint32(scratch[1]) + ((combined &^ 27) | (matrixByte(int(uint32(scratch[1])%35)) & 27)))

	state35[33] ^= work[26]
	work[106] ^= byte(uint32(scratch[5]) ^ 133)

	state35[30] = byte(((uint32(scratch[12]) / 3) - (275 | (uint32(scratch[0]) & 247))) ^ stateByte(int(workByte(122)%20)))
	work[22] = byte((matrixByte(int(workByte(90)%35)) & 95) | 68)

	cubeBase := selectBits(184, seedByte(int(uint32(scratch[9])%21)), matrixByte(int(uint32(scratch[11])%35)))
	state35[18] += byte((cubeBase * cubeBase * cubeBase) >> 1)

	state35[5] -= byte(seedByte(int(workByte(92) % 21)))

	leftFactor := (selectBits(24, matrixByte(int(workByte(183)%35)), workByte(41)) & (uint32(scratch[4]) + 53)) | (uint32(scratch[5]) & matrixByte(int(uint32(scratch[5])%35)))
	rightFactor := selectBits(uint32(scratch[11]), stateByte(int(workByte(59)%20)), workByte(17))
	state35[18] ^= byte(leftFactor * rightFactor)

	rotation := garbleRotateRight8(work[11], int(matrixByte(int(workByte(28)%35))&7)) & 7
	garbleValue = selectBits(stateByte(14), 150, stateByte(int(workByte(93)%20)))
	selector := selectBits(28, workByte(7), garbleValue)
	garbleValue = garbleRotateLeft8(state35[uint32(scratch[0])%35], int(rotation))
	state35[22] = byte(bitMajority(selector, garbleValue, matrixByte(33)) + 74)

	seedMask := seedByte(int((stateByte(int(workByte(39)%20)) ^ 217) % 21))
	garbleValue = bitMajority(uint32(scratch[5]), uint32(scratch[0]), 214)
	state20[15] -= byte(bitMajority(garbleValue, seedMask, uint32(scratch[8])))
}

func (state *fairplaySAPState) garbleMix() {
	var A, B, C, D, E, M, J, G, F, R, S, T, U, V, W, X, Y, Z uint32

	state20 := &state.state
	work := &state.work
	state35 := &state.matrix
	scratch := &state.scratch
	stateByte := func(i int) uint32 { return uint32(state20[i]) }
	workByte := func(i int) uint32 { return uint32(work[i]) }
	matrixByte := func(i int) uint32 { return uint32(state35[i]) }
	seedByte := func(i int) uint32 { return uint32(fairplaySAPSeed[i]) }
	var garbleValue uint32

	// Preserve this intermediate for the next circuit stage.
	garbleValue = bitMajority(matrixByte(int(workByte(57)%35)), stateByte(int(uint32(scratch[12])%20)), 95)
	garbleMask := (uint32(scratch[12]) & 45) | 82
	garbleValue = bitMajority(garbleValue, garbleMask, 32)
	D = ((uint32(scratch[0]) / 3) - (uint32(scratch[12]) | workByte(22))) ^ (uint32(scratch[7]) + 62) ^ garbleValue
	T = stateByte(int((D & 0xff) % 20))

	garbleValue = stateByte(int(workByte(99) % 20))
	scratch[13] = byte((garbleValue * garbleValue * garbleValue * garbleValue) | matrixByte(int(uint32(scratch[12])%35)))

	U = stateByte(int(workByte(50) % 20))
	W = matrixByte(int(workByte(138) % 35))
	X = seedByte(int(workByte(39) % 21))
	Y = stateByte(int(workByte(4) % 20))
	Z = seedByte(int(workByte(202) % 21))
	V = stateByte(int(workByte(151) % 20))
	S = matrixByte(int(workByte(14) % 35))
	R = stateByte(int(workByte(145) % 20))

	A = bitMajority(matrixByte(int(uint32(scratch[13])%35)), stateByte(int(workByte(209)%20)), 24)
	B = garbleRotateLeft8(fairplaySAPSeed[workByte(127)%21], int(matrixByte(int(uint32(scratch[13])%35))&7))
	C = selectBits(stateByte(10), A, B)
	D = 7 ^ (seedByte(int(matrixByte(int(uint32(scratch[9])%35))%21)) << 1)
	scratch[14] = byte(selectBits(71, C, D))

	left := selectBits(159, stateByte(int(uint32(scratch[5])%20))<<1, seedByte(int(workByte(190)%21)))
	right := selectBits(110, seedByte(int(uint32(scratch[12])%21)), stateByte(int(workByte(25)%20)))
	right = selectBits(150, workByte(25), right)
	state35[2] += byte(left & right)
	garbleValue = matrixByte(int(uint32(scratch[5])%35)) & (uint32(scratch[14]) ^ matrixByte(int(workByte(100)%35)))
	state35[14] -= byte(selectBits(34, workByte(97), garbleValue))
	state20[17] = 115

	garbleValue = bitMajority(seedByte(int(workByte(17)%21)), stateByte(int(uint32(scratch[5])%20)), uint32(scratch[14]))
	work[23] ^= byte(bitMajority(garbleValue, workByte(50)/3, 246) << 1)

	garbleValue = bitMajority(stateByte(int(uint32(scratch[10])%20)), workByte(10), 82)
	state20[13] = byte(((garbleValue & 209) | ((stateByte(int(workByte(39)%20)) << 1) & 46)) >> 1)

	state35[33] -= byte(workByte(113) & 9)
	state35[28] -= byte(selectBits(223, uint32(scratch[5]), (2|(workByte(110)&222))>>1))

	J = garbleRotateLeft8(byte(V|Z), int(U&7))
	A = selectBits(matrixByte(16), T, W)
	B = selectBits(17, workByte(33), X)
	E = bitMajority(Y, (A+B)/5, 147)
	M = bitMajority(uint32(scratch[10]), seedByte(int((uint32(scratch[2])+J+E)&0xff)%21), matrixByte(23))

	garbleValue = bitMajority(seedByte(int(uint32(scratch[5])%21))-48, 189, ^workByte(184))
	state20[15] = byte(garbleValue & (M * M * M))

	state35[22] += work[183]
	scratch[15] = byte((3 * seedByte(int(workByte(1)%21))) ^ uint32(scratch[0]))

	A = matrixByte(int((uint32(scratch[2]) + (J + E)) & 0xff % 35))
	F = (bitMajority(seedByte(int(workByte(178)%21)), A, 209) * stateByte(int(workByte(13)%20))) * (seedByte(int(workByte(26)%21)) >> 1)
	G = (F+0x733ffff9)*198 - (((F+0x733ffff9)*396 + 212) & 212) + 85
	scratch[16] = byte(uint32(scratch[9]) + (G ^ 148) + ((G ^ 107) << 1) - 127)

	scratch[17] = byte(selectBits(245, matrixByte(int(uint32(scratch[12])%35)), matrixByte(int(uint32(scratch[5])%35))))

	A = stateByte(int(uint32(scratch[13])%20)) | 81
	state35[18] -= byte(selectBits(uint32(state20[15]), uint32(scratch[16])/15, A*A*A))

	scratch[18] = byte(uint32(scratch[2]) + J + E - stateByte(int(workByte(160)%20)) + (seedByte(int(stateByte(int((uint32(scratch[2])+J+E)&255)%20))%21) / 3))

	B = selectBits(198, S*S, R^uint32(scratch[14]))
	F = bitMajority(seedByte(int(workByte(69)%21)), workByte(172), (uint32(scratch[3])-B)+77)
	state20[16] = byte(147 - ((uint32(scratch[14]) & ((F & 251) | 1)) | (((F & 250) | uint32(scratch[14])) & 198)))

	C = (seedByte(int(workByte(168)%21)) & stateByte(int(workByte(29)%20)) & 7) | ((seedByte(int(workByte(168)%21)) | stateByte(int(workByte(29)%20))) & 6)
	F = bitMajority(seedByte(int(workByte(155)%21)), workByte(105), 141)
	state20[3] -= byte(seedByte(int(garbleRotateLeftWide(byte(F), C) % 21)))

	work[5] = byte(garbleRotateRight8(state20[12], int((stateByte(int(workByte(61)%20))/5)&7)) ^ (^matrixByte(int(uint32(scratch[17])%35)) / 5))
}

func (state *fairplaySAPState) garbleFinalize() {
	var A, B, C, D, F, G, H, K uint32

	state20 := &state.state
	work := &state.work
	state35 := &state.matrix
	scratch := &state.scratch
	stateByte := func(i int) uint32 { return uint32(state20[i]) }
	workByte := func(i int) uint32 { return uint32(work[i]) }
	matrixByte := func(i int) uint32 { return uint32(state35[i]) }
	seedByte := func(i int) uint32 { return uint32(fairplaySAPSeed[i]) }
	var garbleValue uint32

	work[198] += work[3]

	A = 162 | matrixByte(int(uint32(scratch[12])%35))
	work[164] += byte((A * A) / 5)

	G = garbleRotateRight8(139, int(uint32(scratch[16])&7))
	garbleValue = seedByte(int(uint32(scratch[12]) % 21))
	C = selectBits(95, garbleValue*garbleValue*garbleValue, stateByte(int(uint32(scratch[10])%20)))
	scratch[19] = byte(bitMajority(G, stateByte(int(uint32(scratch[5])%20)), 12) | C)

	state35[12] += byte(((workByte(103) & 32) | (uint32(scratch[19]) & (workByte(103) | 60)) | 16) / 3)
	A = selectBits(uint32(state35[8]), workByte(35), uint32(scratch[10]))
	B = selectBits(uint32(scratch[12]), A, uint32(scratch[17])/3)
	mask := uint32(86) | ((workByte(172) & 64) >> 1)
	work[143] -= byte(bitMajority(B, mask, 27))

	state35[29] = 162

	A = selectBits(160, seedByte(int(uint32(scratch[18])%21)), stateByte(int(workByte(125)%20))) >> 1
	B = matrixByte(int(workByte(149)%35)) ^ (workByte(43) * workByte(43))
	state20[15] += byte(bitMajority(B, A, 115))

	scratch[20] = byte(uint32(scratch[12]) - stateByte(int(uint32(scratch[10])%20)))
	work[95] = byte(seedByte(int(uint32(scratch[5]) % 21)))

	A = garbleRotateRight8(state35[uint32(scratch[16])%35], int((matrixByte(int(workByte(17)%35))*matrixByte(int(workByte(17)%35))*matrixByte(int(workByte(17)%35)))&7))
	state20[7] -= byte(A * A)

	state35[8] = byte(uint32(state35[8]) - workByte(184) + (seedByte(int(workByte(202)%21)) * seedByte(int(workByte(202)%21)) * seedByte(int(workByte(202)%21))))
	state20[16] = byte((matrixByte(int(workByte(102)%35)) << 1) & 132)

	scratch[21] = byte((seedByte(int(uint32(scratch[10])%21)) >> 1) ^ uint32(scratch[13]))

	garbleValue = selectBits(177, seedByte(int(seedByte(int(uint32(scratch[18])%21))%21)), seedByte(int(workByte(80)%21))<<1)
	state20[7] -= byte(stateByte(int(workByte(191)%20)) - garbleValue)
	state20[6] = byte(stateByte(int(workByte(119) % 20)))

	A = selectBits(209, workByte(118), seedByte(int(workByte(190)%21)))
	B = stateByte(int(uint32(scratch[20])%20)) * stateByte(int(uint32(scratch[20])%20))
	state20[12] = byte((stateByte(int(uint32(scratch[17])%20)) ^ (matrixByte(int(workByte(71)%35)) + matrixByte(int(workByte(15)%35)))) & bitMajority(A, B, 27))

	B = bitMajority(workByte(32), matrixByte(int(uint32(scratch[18])%35)), 23)
	D = (((seedByte(int(workByte(57)%21)) * 231) & 169) | (B & 86))
	F = selectBits(190, selectBits(29, seedByte(int(uint32(scratch[21])%21)), stateByte(int(workByte(82)%20))), seedByte(int(D/5)%21))
	H = stateByte(int(uint32(scratch[10])%20)) * stateByte(int(uint32(scratch[10])%20)) * stateByte(int(uint32(scratch[10])%20))
	K = bitMajority(H, workByte(82), 92)
	scratch[22] = byte(bitMajority(F, K, 192) ^ (D / 5))

	state35[25] ^= byte(((stateByte(int(uint32(scratch[20])%20)) << 1) * workByte(5)) - (garbleRotateLeft8(byte(uint32(scratch[15])), int(seedByte(int(uint32(scratch[21])%21))&7)) & (uint32(scratch[5]) + 110)))

}
