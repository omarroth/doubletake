package airplay

// FairPlay's proprietary SAP hash. It is not a standard cryptographic hash.

import "math/bits"

func rotate8OrZero(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return uint32(bits.RotateLeft8(input, count))
}

func rotateWideOrZero(input byte, count uint32) uint32 {
	if count == 0 {
		return 0
	}
	return uint32(input)<<count | uint32(input)>>(8-count)
}

func xorFold16(out *[16]byte, in []byte) {
	for i, value := range in {
		out[i&15] ^= value
	}
}

func majority(a, b, c uint32) uint32                { return (a & b) | ((a | b) & c) }
func selectBits(mask, ifSet, ifClear uint32) uint32 { return ifClear ^ ((ifSet ^ ifClear) & mask) }
func square(value uint32) uint32                    { return value * value }
func cube(value uint32) uint32                      { return value * value * value }

var sapInitialHash = [20]byte{
	0x96, 0x5f, 0xc6, 0x53, 0xf8, 0x46, 0xcc, 0x18, 0xdf, 0xbe,
	0xb2, 0xf8, 0x38, 0x62, 0xec, 0x22, 0x93, 0xd1, 0x20, 0x8f,
}

var sapInitialMatrix = [35]byte{
	0x43, 0x54, 0x62, 0x7a, 0x18, 0xc3, 0xd6, 0xb3, 0x9a, 0x56,
	0xf6, 0x1c, 0x14, 0x3f, 0x0c, 0x1d, 0x3b, 0x36, 0x83, 0xb1,
	0x39, 0x51, 0x4a, 0xaa, 0x09, 0x3e, 0xfe, 0x44, 0xaf, 0xde,
	0xc3, 0x20, 0x9d, 0x42, 0xb8,
}

var sapSeed = [21]byte{
	0xed, 0x25, 0xd1, 0xbb, 0xbc, 0x27, 0x9f, 0x02, 0xa2, 0xa9, 0x11,
	0x00, 0x0c, 0xb3, 0x52, 0xc0, 0xbd, 0xe3, 0x1b, 0x49, 0xc7,
}

type sapState struct {
	hash   [20]byte
	matrix [35]byte
	aux    [10]byte
	work   [210]byte
}

type sapBytes []byte

func (values sapBytes) at(index byte) uint32     { return uint32(values[index%byte(len(values))]) }
func (values sapBytes) at32(index uint32) uint32 { return uint32(values[index%uint32(len(values))]) }

func (state *sapState) buffers() (sapBytes, sapBytes, sapBytes, sapBytes, *[10]byte) {
	return state.hash[:], state.work[:], state.matrix[:], sapSeed[:], &state.aux
}

func fairplaySAPHash(input []byte) (out [16]byte) {
	var state sapState
	state.hash = sapInitialHash
	state.matrix = sapInitialMatrix
	work := &state.work
	// Load input into the working state in reversed four-byte groups.
	for i := range work {
		work[i] = (*[64]byte)(input)[(i&63)^3]
	}

	// Scramble four complete passes. Converting before modulo preserves the
	// circuit's unsigned underflow during the first pass.
	for i := uint32(0); i < 840; i++ {
		x, y, z, w := work[(i-155)%210], work[(i-57)%210], work[(i-13)%210], work[i%210]
		work[i%210] = bits.RotateLeft8(y, 5) + (bits.RotateLeft8(z, 3) ^ w) - bits.RotateLeft8(x, 7)
	}

	state.nonlinearPrepare()
	state.nonlinearFinish()
	// Include terminal work XORs directly in their folded output lanes.
	copy(out[:3], state.aux[:3])
	copy(out[4:11], state.aux[3:])
	for i := range out {
		out[i] += 0xe1
	}
	out[3], out[11] = 0x3d, 0x3c
	out[10] ^= state.aux[3] ^ 133

	xorFold16(&out, state.hash[:])
	xorFold16(&out, state.matrix[:])
	xorFold16(&out, work[:])

	// Reverse scramble
	for i := range 256 {
		out[i&15] ^= bits.RotateLeft8(out[(i-7)&15], 1) ^
			bits.RotateLeft8(out[(i-5)&15], 6) ^
			bits.RotateLeft8(out[(i-1)&15], 5)
	}
	return
}

// The nonlinear circuit's uint32 wrapping and byte truncation are intentional.
func (state *sapState) nonlinearPrepare() {
	hash, work, matrix, seed, aux := state.buffers()
	seedAtWork92, seedAtWork206, workAt99 := seed.at(work[92]), seed.at(work[206]), work.at(99)
	matrix[12] = byte(0x14 + (((work.at(64) & 92) | ((workAt99 / 3) & 35)) & seed.at32(seedAtWork206<<4|seedAtWork206>>4)))
	work[4] = byte(2 * square(workAt99/5))
	work[153] ^= byte(square(matrix.at(work[203])) * work.at(190))
	hash[3] = 0x13 ^ byte(seed.at(work[205])&0x20)>>1
	work[33] -= byte(seed.at(work[36]) &^ 9)
	previousMatrix, previousHash := matrix.at(work[67]), hash.at(work[181])
	matrix[12] = 0x07
	work[2] -= 64
	aux[5] = byte((previousMatrix&^2 | 1 | (previousHash&0x80)>>6 | (hash.at(3) & 0x10)) - 15)
	hash[19] = byte(seed.at(work[58]))
	aux[4] = byte(92 - matrix.at(work[32]))
	aux[9] = byte(matrix.at(work[15])) + 0x9e
	work[34] += byte(seed.at(aux[9]) / 5)
	hash[19] += 0xe6 - byte((hash.at(aux[9])>>1)&102)
	work[15] = byte((3 * (rotate8OrZero(work[72], -int(seed.at(work[190])&7)) - (3 * seed.at(work[126])))) ^ work.at(15))
	hash[15] ^= byte(cube(matrix.at(work[181])))
	matrix[4] ^= byte(work.at(202) / 3)
	matrix[1] += byte(cube(majority(92-hash.at(aux[4]), ^work.at(105), 0xc6)))
	hash[19] ^= byte(((224 | (seedAtWork92 & 27)) * matrix.at(work[41])) / 3)
	work[140] += byte(rotate8OrZero(92, -int(work.at(5)&7)))
	matrix[12] += byte(majority(^work.at(4)^matrix.at(work[12]), work.at(182), 192))
	work[36] += 125
	work[124] = bits.RotateLeft8(byte(majority(majority(work.at(138), hash.at(15), 74), hash.at(work[43]), 95)), 4)
	hashAtAux9 := hash.at(aux[9])
	aux[1] = byte(^(hashAtAux9 & (seed.at(work[68]) << 1)) & 0x4c)
	aux[2] = 222 - byte(majority((work.at(177)+seed.at(work[79]))>>1, (3*work.at(148))/5, matrix.at(1)))
	matrix[16] += byte(((matrix.at(aux[4]) &^ 0x68) | hashAtAux9 | 8) - (uint32(bits.RotateLeft8(work[33], 2)) | 128))
	hash[14] ^= byte(matrix.at(aux[2]))
	work[19] += byte(majority(rotate8OrZero(seed[byte(hash.at(work[201]))%21], int((matrix.at(work[112])<<1)&7)),
		((hash.at(work[208])&^0x7c)|(hash.at(work[164])&0x7c))/5, 37))
	matrix[8] = byte(rotate8OrZero(140, -int(square(seed.at(work[45]))&7))) ^ aux[4]
	work[190] = 56
	work[53] = ^byte((hash.at(work[83]) | 204) / 5)
	hash[13] += byte(hash.at(work[41]))
	hash[10] = byte(majority(matrix.at(aux[4]), work.at(2), uint32(aux[2])) / 15)
	aux[3] = byte(92 - square(0x28|(matrix.at(aux[1])&(0x12|(seed.at(work[2])&4)))))
	seedBits := seed.at(aux[4])
	matrix[13] ^= byte(seedBits)
	aux[6] = byte(92 + square(majority(matrix.at(work[179])-38, uint32(aux[2]), 177)))
	value := uint32(aux[3]) + (uint32(aux[4]) & 74)
	expansionBits := majority(value, ^seedBits, 121)
	work[47] = byte((matrix.at(work[89]) + majority(expansionBits^0xa6, uint32(aux[4]), 4)) ^ work.at(47))
	workAt151, matrixAtAux9 := work.at(151), matrix.at(aux[9])
	aux[7] = byte((seedBits / 3) - matrixAtAux9 - (0x14 | (workAt151 & 0x62) | (uint32(aux[4]) & (0x22 | (workAt151 &^ 0x77)))))
	expandedSelector := byte(expansionBits ^ ((uint32(aux[4]) >> 1) & 101) ^ 75)
	aux[9] += byte(0x80 | ((uint32(aux[7]) | workAt151) & 0x20) | ((uint32(aux[7])&workAt151 | seedBits) & 0x44) | (matrixAtAux9 & 0x1b))
	matrix[33] ^= work[26]
	matrix[30] = byte(((uint32(aux[9]) / 3) - ((uint32(aux[4]) &^ 8) | 0x13)) ^ hash.at(work[122]))
	work[22] = byte((matrix.at(work[90]) & 0x1b) | 0x44)
	matrix[18] += byte(cube(selectBits(71, matrix.at(expandedSelector), seed.at(aux[5]))) >> 1)
	matrix[5] -= byte(seedAtWork92)
	matrix[18] ^= byte(selectBits(uint32(aux[3]), matrix.at(aux[3]), selectBits(16, matrix.at(work[183]), work.at(41))) *
		selectBits(uint32(expandedSelector), hash.at(work[59]), work.at(17)))
	matrix[22] = byte(majority(selectBits(hash.at(14)|28, (work.at(7)&28)|0x82, hash.at(work[93])),
		rotate8OrZero(byte(matrix.at(aux[4])), int(rotate8OrZero(work[11], -int(matrix.at(work[28])&7))&7)), matrix.at(33)) + 74)
	hash[15] -= byte(majority(majority(uint32(aux[3]), uint32(aux[4]), 214), seed.at(byte(hash.at(work[39]))^217), uint32(aux[6])))
}

func (state *sapState) nonlinearFinish() {
	hash, work, matrix, seed, aux := state.buffers()
	seedAtWork202, matrixAtWork57, hashAtAux9 := seed.at(work[202]), matrix.at(work[57]), hash.at(aux[9])
	workAt172, workAt184 := work.at(172), work.at(184)
	indexedHash := hash.at(byte(((uint32(aux[4]) / 3) - (uint32(aux[9]) | work.at(22))) ^ uint32(aux[6]) ^
		(((matrixAtWork57 | hashAtAux9) & (0x52 | (uint32(aux[9]) & 0x0d))) | ((matrixAtWork57&hashAtAux9 | uint32(aux[9])) & 0x20))))
	aux[6] = byte(square(square(hash.at(work[99]))) | matrix.at(aux[9]))
	mixIndex := uint32(byte(uint32(aux[1]) + rotate8OrZero(byte(hash.at(work[151])|seedAtWork202), int(hash.at(work[50])&7)) +
		majority(hash.at(work[4]), (selectBits(matrix.at(16), indexedHash, matrix.at(work[138]))+selectBits(17, work.at(33), seed.at(work[39])))/5, 147)))
	selectorMatrix := matrix.at(aux[6])
	aux[0] = byte(selectBits(hash.at(10)&7, selectorMatrix&hash.at(work[209]),
		selectBits(0x47, rotate8OrZero(seed[work.at(127)%21], int(selectorMatrix&7)), seed.at(byte(matrix.at(aux[5])))<<1)))
	selectedSquare := selectBits(198, square(matrix.at(work[14])), hash.at(work[145])^uint32(aux[0]))
	seedAtAux9, hashAtAux3 := seed.at(aux[9]), hash.at(aux[3])
	matrix[2] += byte(((hashAtAux3 << 1) & ((work.at(25) & 0x96) | (seedAtAux9 & 8))) | (seedAtAux9 & 0x40))
	matrix[14] -= byte(selectBits(34, work.at(97), matrix.at(aux[3])&(uint32(aux[0])^matrix.at(work[100]))))
	hash[17] = 115
	work[23] ^= byte(majority(majority(seed.at(work[17]), hashAtAux3, uint32(aux[0])), work.at(50)/3, 0x76) << 1)
	hash[13] = byte(((majority(hash.at(aux[7]), work.at(10), 82) >> 1) & 0x68) | (hash.at(work[39]) & 0x17))
	matrix[33] -= byte(work.at(113) & 9)
	matrix[28] -= aux[3]&^0x20 | (work[110]&0x40)>>1
	work[95] = byte(seed.at(aux[3]))
	hash[15] = byte(majority(uint32(work[95])-48, ^workAt184, 189) & cube(majority(uint32(aux[7]), seed.at32(mixIndex), 0xaa)))
	matrix[22] += work[183]
	aux[4] ^= byte(3 * seed.at(work[1]))
	aux[5] += 198 * byte((majority(seed.at(work[178]), matrix.at32(mixIndex), 209)*hash.at(work[13]))*(seed.at(work[26])>>1))
	aux[8] = byte(selectBits(10, matrix.at(aux[3]), matrix.at(aux[9])))
	matrix[18] -= byte(selectBits(uint32(hash[15]), uint32(aux[5])/15, cube(hash.at(aux[6])|81)))
	aux[1] = byte(mixIndex - hash.at(work[160]) + seed.at(byte(hash.at(byte(mixIndex))))/3)
	hash[16] = 147 - byte((uint32(aux[0])&^0x38)|
		(majority(seed.at(work[69]), workAt172, (uint32(aux[2])-selectedSquare)+77)&(uint32(aux[0])|0xc2)&^5))
	rotationSeed, rotationHash := seed.at(work[168]), hash.at(work[29])
	rotationCount := majority(rotationSeed, rotationHash, 6) & 7
	hash[3] -= byte(seed.at32(rotateWideOrZero(byte(majority(seed.at(work[155]), work.at(105), 141)), rotationCount)))
	work[5] = byte(rotate8OrZero(0x38, -int((hash.at(work[61])/5)&7)) ^ (51 - (matrix.at(aux[8])+4)/5))
	work[198] += work[3]
	work[164] += byte(square(162|matrix.at(aux[9])) / 5)
	aux[2] = byte(majority(rotate8OrZero(139, -int(uint32(aux[5])&7)), hash.at(aux[3]), 12) |
		selectBits(95, cube(seedAtAux9), hash.at(aux[7])))
	matrix[12] += byte(((work.at(103) & 32) | (uint32(aux[2]) & (work.at(103) | 60)) | 16) / 3)
	selected := selectBits(uint32(aux[9]), selectBits(uint32(matrix[8]), work.at(35), uint32(aux[7])), uint32(aux[8])/3)
	work[143] -= byte(0x12 | (selected & (0x4d | ((workAt172 & 0x40) >> 1))))
	matrix[29] = 162
	hash[15] += byte(majority(matrix.at(work[149])^square(work.at(43)), selectBits(95, hash.at(work[125]), seed.at(aux[1]))>>1, 115))
	aux[9] -= byte(hash.at(aux[7]))
	hash[7] -= byte(square(rotate8OrZero(byte(matrix.at(aux[5])), -int(matrix.at(work[17])*(matrix.at(work[17])&1)))))
	matrix[8] += byte(cube(seedAtWork202) - workAt184)
	hash[16] = byte(matrix.at(work[102])<<1) & 0x84
	aux[6] ^= byte(seed.at(aux[7]) >> 1)
	hash[7] -= byte(hash.at(work[191]) - selectBits(177, seed.at(byte(seed.at(aux[1]))), seed.at(work[80])<<1))
	hash[6] = byte(hash.at(work[119]))
	hash[12] = byte((hash.at(aux[8]) ^ (matrix.at(work[71]) + matrix.at(work[15]))) &
		majority((work.at(118)&^0x2e)|2, square(hash.at(aux[9])), 27))
	digestIndex := byte(selectBits(0xa9, seed.at(work[57])*231, majority(work.at(32), matrix.at(aux[1]), 23)) / 5)
	seedSample := seed.at(aux[6])
	selected = (seedSample & 0x1c) | (hash.at(work[82]) &^ 0x5d) | (seed.at(digestIndex) & 0x41)
	aux[5] = byte(majority(selected, majority(cube(hash.at(aux[7])), work.at(82), 92), 192)) ^ digestIndex
	matrix[25] ^= byte(((hash.at(aux[9]) << 1) * work.at(5)) - (rotate8OrZero(aux[4], int(seedSample&7)) & (uint32(aux[3]) + 110)))
}
