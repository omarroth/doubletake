package airplay

// This file contains PlayFair's proprietary SAP hash/KDF. The AES block
// operations and MD5-shaped compression live in focused implementations that
// expose which parts are standard and which FairPlay modifies.

import (
	"crypto/aes"
	"encoding/binary"
	"math/bits"
)

var fairplayInitialSessionKey = [16]byte{
	0xDC, 0xDC, 0xF3, 0xB9, 0x0B, 0x74, 0xDC, 0xFB,
	0x86, 0x7F, 0xF7, 0x60, 0x16, 0x72, 0x90, 0x51,
}

var playfairKDFPrefix = [17]byte{
	0xfa, 0x9c, 0xad, 0x4d, 0x4b, 0x68, 0x26, 0x8c,
	0x7f, 0xf3, 0x88, 0x99, 0xde, 0x92, 0x2e, 0x95, 0x1e,
}

var playfairKDFSuffix = [17]byte{
	0xec, 0x4e, 0x27, 0x5e, 0xfd, 0xf2, 0xe8, 0x30,
	0x97, 0xae, 0x70, 0xfb, 0xe0, 0x00, 0x3f, 0x1c, 0x39,
}

// Only the second 128 bytes of the fixed SAP record participate in the KDF.
var defaultSAPTail = [128]byte{
	0x00, 0x01, 0xcc, 0x34, 0x2a, 0x5e, 0x5b, 0x1a, 0x67, 0x73, 0xc2, 0x0e, 0x21, 0xb8, 0x22, 0x4d,
	0xf8, 0x62, 0x48, 0x18, 0x64, 0xef, 0x81, 0x0a, 0xae, 0x2e, 0x37, 0x03, 0xc8, 0x81, 0x9c, 0x23,
	0x53, 0x9d, 0xe5, 0xf5, 0xd7, 0x49, 0xbc, 0x5b, 0x7a, 0x26, 0x6c, 0x49, 0x62, 0x83, 0xce, 0x7f,
	0x03, 0x93, 0x7a, 0xe1, 0xf6, 0x16, 0xde, 0x0c, 0x15, 0xff, 0x33, 0x8c, 0xca, 0xff, 0xb0, 0x9e,
	0xaa, 0xbb, 0xe4, 0x0f, 0x5d, 0x5f, 0x55, 0x8f, 0xb9, 0x7f, 0x17, 0x31, 0xf8, 0xf7, 0xda, 0x60,
	0xa0, 0xec, 0x65, 0x79, 0xc3, 0x3e, 0xa9, 0x83, 0x12, 0xc3, 0xb6, 0x71, 0x35, 0xa6, 0x69, 0x4f,
	0xf8, 0x23, 0x05, 0xd9, 0xba, 0x5c, 0x61, 0x5f, 0xa2, 0x54, 0xd2, 0xb1, 0x83, 0x45, 0x83, 0xce,
	0xe4, 0x2d, 0x44, 0x26, 0xc8, 0x35, 0xa7, 0xa5, 0xf6, 0xc8, 0x42, 0x1c, 0x0d, 0xa3, 0xf1, 0xc7,
}

// --- SAP hash ---

func rotateLeft8(input byte, count int) byte {
	return bits.RotateLeft8(input, count)
}

func rotateLeft8Wide(input byte, count int) uint32 {
	return uint32(bits.RotateLeft8(input, count))
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

func sapHash(blockIn []byte) (keyOut [16]byte) {
	state20 := [20]byte{0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE, 0xB2, 0xF8, 0x38, 0xD7, 0xEC, 0x22, 0x03, 0xD1, 0x20, 0x8F}
	var work [210]byte
	state35 := [35]byte{0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56, 0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1, 0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE, 0xC3, 0x20, 0x9D, 0x42, 0x3A}
	// The original circuit addressed a 132-byte scratch area only at
	// four-byte boundaries, so it is exactly a 33-byte state.
	var scratch [33]byte
	state21 := [21]byte{0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11, 0x00, 0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7}
	i0Index := [11]int{18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30}

	// Load input into work
	for i := 0; i < 210; i++ {
		work[i] = blockIn[(i&63)^3]
	}

	// Scrambling
	for i := 0; i < 840; i++ {
		x := work[wrappedUint32Index(i, 155, len(work))]
		y := work[wrappedUint32Index(i, 57, len(work))]
		z := work[wrappedUint32Index(i, 13, len(work))]
		w := work[i%len(work)]
		work[i%210] = byte((uint32(rotateLeft8(y, 5)) + (uint32(rotateLeft8(z, 3)) ^ uint32(w)) - uint32(rotateLeft8(x, 7))) & 0xff)
	}

	// Garble
	sapGarble(&state20, &work, &state35, &scratch, &state21)

	// Fill output with 0xE1
	for i := 0; i < 16; i++ {
		keyOut[i] = 0xE1
	}

	// Apply scratch
	for i := 0; i < 11; i++ {
		if i == 3 {
			keyOut[i] = 0x3d
		} else {
			keyOut[i] += scratch[i0Index[i]]
		}
	}

	xorFold16(&keyOut, state20[:])
	xorFold16(&keyOut, state35[:])
	xorFold16(&keyOut, work[:])

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

// --- Garble (hand_garble.c) ---

func sapGarble(state20 *[20]byte, work *[210]byte, state35 *[35]byte, scratch *[33]byte, state21 *[21]byte) {
	var tmp, tmp2, tmp3 uint32
	var A, B, C, D, E, M, J, G, F, H, K, R, S, T, U, V, W, X, Y, Z uint32

	b0 := func(i int) uint32 { return uint32(state20[i]) }
	b1 := func(i int) uint32 { return uint32(work[i]) }
	b2 := func(i int) uint32 { return uint32(state35[i]) }
	b4 := func(i int) uint32 { return uint32(state21[i]) }

	state35[12] = byte(0x14 + (((b1(64) & 92) | ((b1(99) / 3) & 35)) & b4(int(rotateLeft8Wide(state21[b1(206)%21], 4)%21))))
	work[4] = byte((b1(99) / 5) * (b1(99) / 5) * 2)
	state35[34] = 0xb8
	work[153] ^= byte(b2(int(b1(203)%35)) * b2(int(b1(203)%35)) * b1(190))
	state20[3] -= byte(((b4(int(b1(205)%21)) >> 1) & 80) | 0x40)
	state20[16] = 0x93
	state20[13] = 0x62
	work[33] -= byte(b4(int(b1(36)%21)) & 0xf6)

	tmp2 = b2(int(b1(67) % 35))
	state35[12] = 0x07

	tmp = b0(int(b1(181) % 20))
	work[2] -= byte(3136 & 0xff)

	state20[19] = byte(b4(int(b1(58) % 21)))

	scratch[0] = byte(92 - b2(int(b1(32)%35)))
	scratch[1] = byte(b2(int(b1(15)%35)) + 0x9e)
	work[34] += byte(b4(int((b2(int(b1(15)%35))+0x9e)&0xff)%21) / 5)
	state20[19] += byte(0xfffffee6 - ((b0(int(uint32(scratch[1])%20)) >> 1) & 102))

	// work[15]
	shiftAmt := b4(int(b1(190)%21)) & 7
	shifted := (b1(72) >> shiftAmt) ^ (b1(72) << ((7 - (b4(int(b1(190)%21)) - 1)) & 7))
	work[15] = byte((3 * (shifted - (3 * b4(int(b1(126)%21))))) ^ b1(15))

	state20[15] ^= byte(b2(int(b1(181)%35)) * b2(int(b1(181)%35)) * b2(int(b1(181)%35)))
	state35[4] ^= byte(b1(202) / 3)

	A = 92 - b0(int(uint32(scratch[0])%20))
	E = (A & 0xc6) | (^b1(105) & 0xc6) | (A & (^b1(105)))
	state35[1] += byte(E * E * E)

	state20[19] ^= byte(((224 | (b4(int(b1(92)%21)) & 27)) * b2(int(b1(41)%35))) / 3)
	work[140] += byte(garbleRotateRight8(92, int(b1(5)&7)))

	state35[12] += byte(((((^b1(4)) ^ b2(int(b1(12)%35))) | b1(182)) & 192) | (((^b1(4)) ^ b2(int(b1(12)%35))) & b1(182)))
	work[36] += 125

	work[124] = byte(rotateLeft8Wide(byte(((74&b1(138))|((74|b1(138))&b0(15)))&b0(int(b1(43)%20)))|byte(((74&b1(138))|((74|b1(138))&b0(15))|b0(int(b1(43)%20)))&95), 4))

	scratch[2] = byte((((b0(int(uint32(scratch[1])%20)) & 95) & ((b4(int(b1(68)%21)) & 46) << 1)) | 16) ^ 92)

	A = b1(177) + b4(int(b1(79)%21))
	D = (((A >> 1) | ((3 * b1(148)) / 5)) & b2(1)) | ((A >> 1) & ((3 * b1(148)) / 5))
	scratch[3] = byte(-34 - int32(D))

	A = 8 - (b2(22) & 7)
	B = b1(33) >> (A & 7)
	C = b1(33) << (b2(22) & 7)
	state35[16] += byte(((b2(int(uint32(scratch[0])%35)) & 159) | b0(int(uint32(scratch[1])%20)) | 8) - ((B ^ C) | 128))

	state20[14] ^= byte(b2(int(uint32(scratch[3]) % 35)))

	// Continue the fixed arithmetic circuit.
	A = garbleRotateLeft8(state21[b0(int(b1(201)%20))%21], int((b2(int(b1(112)%35))<<1)&7))
	D = (b0(int(b1(208)%20)) & 131) | (b0(int(b1(164)%20)) & 124)
	work[19] += byte((A & (D / 5)) | ((A | (D / 5)) & 37))

	state35[8] = byte(garbleRotateRight8(140, int(((b4(int(b1(45)%21))+92)*(b4(int(b1(45)%21))+92))&7)))
	work[190] = 56
	state35[8] ^= scratch[0]

	work[53] = byte(^((b0(int(b1(83)%20)) | 204) / 5))
	state20[13] += byte(b0(int(b1(41) % 20)))
	state20[10] = byte(((b2(int(uint32(scratch[0])%35)) & b1(2)) | ((b2(int(uint32(scratch[0])%35)) | b1(2)) & uint32(scratch[3]))) / 15)

	A = (((56 | (b4(int(b1(2)%21)) & 68)) | b2(int(uint32(scratch[2])%35))) & 42) | (((b4(int(b1(2)%21)) & 68) | 56) & b2(int(uint32(scratch[2])%35)))
	scratch[4] = byte((A * A) + 110)
	scratch[5] = byte(202 - uint32(scratch[4]))
	scratch[6] = work[151]
	state35[13] ^= byte(b4(int(uint32(scratch[0]) % 21)))

	B = ((b2(int(b1(179)%35)) - 38) & 177) | (uint32(scratch[3]) & 177)
	C = (b2(int(b1(179)%35)) - 38) & uint32(scratch[3])
	scratch[7] = byte(30 + ((B | C) * (B | C)))
	scratch[8] = byte(uint32(scratch[7]) + 62)

	// Expand the scratch state.
	A = ((uint32(scratch[5]) + (uint32(scratch[0]) & 74)) | ^b4(int(uint32(scratch[0])%21))) & 121
	B = (uint32(scratch[5]) + (uint32(scratch[0]) & 74)) & ^b4(int(uint32(scratch[0])%21))
	tmp3 = A | B
	C = ((((A | B) ^ 0xffffffa6) | uint32(scratch[0])) & 4) | (((A | B) ^ 0xffffffa6) & uint32(scratch[0]))
	work[47] = byte((b2(int(b1(89)%35)) + C) ^ b1(47))

	scratch[9] = byte(((uint32(rotateLeft8(byte((tmp&179)+68), 2)) & b0(3)) | (tmp2 & ^b0(3))) - 15)
	work[123] ^= 221

	A = (b4(int(uint32(scratch[0])%21)) / 3) - b2(int(uint32(scratch[1])%35))
	C = (((uint32(scratch[0]) & 163) + 92) & 246) | (uint32(scratch[0]) & 92)
	E = ((C | uint32(scratch[6])) & 54) | (C & uint32(scratch[6]))
	scratch[10] = byte(A - E)

	scratch[11] = byte(tmp3 ^ 81 ^ (((uint32(scratch[0]) >> 1) & 101) + 26))
	scratch[12] = byte(b2(int(uint32(scratch[1])%35)) & 27)
	scratch[13] = 27
	scratch[14] = 199

	// Fold the expanded state back into the working buffers.
	scratch[16] = byte(uint32(scratch[1]) + (((((((uint32(scratch[10]) | uint32(scratch[6])) & 177) | (uint32(scratch[10]) & uint32(scratch[6]))) & (((b4(int(uint32(scratch[0])%20)) & 177) | 176) | ((b4(int(uint32(scratch[0]) % 21))) & ^uint32(3)))) | ((((uint32(scratch[10]) & uint32(scratch[6])) | ((uint32(scratch[10]) | uint32(scratch[6])) & 177)) & 199) | ((((b4(int(uint32(scratch[0])%21)) & 1) + 176) | (b4(int(uint32(scratch[0])%21)) &^ uint32(3))) & uint32(scratch[14])))) & (^uint32(scratch[13]))) | uint32(scratch[12])))

	state35[33] ^= work[26]
	work[106] ^= byte(uint32(scratch[5]) ^ 133)

	state35[30] = byte(((uint32(scratch[16]) / 3) - (275 | (uint32(scratch[0]) & 247))) ^ b0(int(b1(122)%20)))
	work[22] = byte((b2(int(b1(90)%35)) & 95) | 68)

	A = (b4(int(uint32(scratch[9])%21)) & 184) | (b2(int(uint32(scratch[11])%35)) & ^uint32(184))
	state35[18] += byte((A * A * A) >> 1)

	state35[5] -= byte(b4(int(b1(92) % 21)))

	A = (((b1(41) & ^uint32(24)) | (b2(int(b1(183)%35)) & 24)) & (uint32(scratch[4]) + 53)) | (uint32(scratch[5]) & b2(int(uint32(scratch[5])%35)))
	B = (b1(17) & (^uint32(scratch[11]))) | (b0(int(b1(59)%20)) & uint32(scratch[11]))
	state35[18] ^= byte(A * B)

	A = garbleRotateRight8(work[11], int(b2(int(b1(28)%35))&7)) & 7
	B = (((b0(int(b1(93)%20)) & ^b0(14)) | (b0(14) & 150)) & ^uint32(28)) | (b1(7) & 28)
	state35[22] = byte(((((B | garbleRotateLeft8(state35[uint32(scratch[0])%35], int(A))) & b2(33)) | (B & garbleRotateLeft8(state35[uint32(scratch[0])%35], int(A)))) + 74) & 0xff)

	A = b4(int((b0(int(b1(39)%20)) ^ 217) % 21))
	state20[15] -= byte(((((uint32(scratch[5]) | uint32(scratch[0])) & 214) | (uint32(scratch[5]) & uint32(scratch[0]))) & A) | ((((uint32(scratch[5]) | uint32(scratch[0])) & 214) | (uint32(scratch[5]) & uint32(scratch[0])) | A) & uint32(scratch[8])))

	// Preserve this intermediate for the next circuit stage.
	B = (((b2(int(b1(57)%35)) & b0(int(uint32(scratch[16])%20))) | ((b0(int(uint32(scratch[16])%20)) | b2(int(b1(57)%35))) & 95) | (uint32(scratch[16]) & 45) | 82) & 32)
	C = ((b2(int(b1(57)%35)) & b0(int(uint32(scratch[16])%20))) | ((b2(int(b1(57)%35)) | b0(int(uint32(scratch[16])%20))) & 95)) & ((uint32(scratch[16]) & 45) | 82)
	D = (((uint32(scratch[0]) / 3) - (uint32(scratch[16]) | b1(22))) ^ (uint32(scratch[7]) + 62) ^ (B | C))
	T = b0(int((D & 0xff) % 20))

	scratch[17] = byte((b0(int(b1(99)%20)) * b0(int(b1(99)%20)) * b0(int(b1(99)%20)) * b0(int(b1(99)%20))) | b2(int(uint32(scratch[16])%35)))

	U = b0(int(b1(50) % 20))
	W = b2(int(b1(138) % 35))
	X = b4(int(b1(39) % 21))
	Y = b0(int(b1(4) % 20))
	Z = b4(int(b1(202) % 21))
	V = b0(int(b1(151) % 20))
	S = b2(int(b1(14) % 35))
	R = b0(int(b1(145) % 20))

	A = (b2(int(uint32(scratch[17])%35)) & b0(int(b1(209)%20))) | ((b2(int(uint32(scratch[17])%35)) | b0(int(b1(209)%20))) & 24)
	B = garbleRotateLeft8(state21[b1(127)%21], int(b2(int(uint32(scratch[17])%35))&7))
	C = (A & b0(10)) | (B & ^b0(10))
	D = 7 ^ (b4(int(b2(int(uint32(scratch[9])%35))%21)) << 1)
	scratch[18] = byte((C & 71) | (D & ^uint32(71)))

	state35[2] += byte(((((b0(int(uint32(scratch[5])%20)) << 1) & 159) | (b4(int(b1(190)%21)) & ^uint32(159))) & ((((b4(int(uint32(scratch[16])%21)) & 110) | (b0(int(b1(25)%20)) & ^uint32(110))) & ^uint32(150)) | (b1(25) & 150))))
	state35[14] -= byte(((b2(int(uint32(scratch[5])%35)) & (uint32(scratch[18]) ^ b2(int(b1(100)%35)))) & ^uint32(34)) | (b1(97) & 34))
	state20[17] = 115

	work[23] ^= byte(((((((b4(int(b1(17)%21)) | b0(int(uint32(scratch[5])%20))) & uint32(scratch[18])) | (b4(int(b1(17)%21)) & b0(int(uint32(scratch[5])%20)))) & (b1(50) / 3)) |
		((((b4(int(b1(17)%21)) | b0(int(uint32(scratch[5])%20))) & uint32(scratch[18])) | (b4(int(b1(17)%21)) & b0(int(uint32(scratch[5])%20))) | (b1(50) / 3)) & 246)) << 1))

	state20[13] = byte(((((((b0(int(uint32(scratch[10])%20)) | b1(10)) & 82) | (b0(int(uint32(scratch[10])%20)) & b1(10))) & 209) |
		((b0(int(b1(39)%20)) << 1) & 46)) >> 1))

	state35[33] -= byte(b1(113) & 9)
	state35[28] -= byte(((((2 | (b1(110) & 222)) >> 1) & ^uint32(223)) | (uint32(scratch[5]) & 223)))

	J = garbleRotateLeft8(byte(V|Z), int(U&7))
	A = (b2(16) & T) | (W & (^b2(16)))
	B = (b1(33) & 17) | (X & ^uint32(17))
	E = ((Y | ((A + B) / 5)) & 147) | (Y & ((A + B) / 5))
	M = (uint32(scratch[10]) & b4(int((uint32(scratch[2])+J+E)&0xff)%21)) |
		((uint32(scratch[10]) | b4(int((uint32(scratch[2])+J+E)&0xff)%21)) & b2(23))

	state20[15] = byte((((b4(int(uint32(scratch[5])%21)) - 48) & (^b1(184))) | ((b4(int(uint32(scratch[5])%21)) - 48) & 189) | (189 & ^b1(184))) & (M * M * M))

	state35[22] += work[183]
	scratch[19] = byte((3 * b4(int(b1(1)%21))) ^ uint32(scratch[0]))

	A = b2(int((uint32(scratch[2]) + (J + E)) & 0xff % 35))
	F = (((b4(int(b1(178)%21)) & A) | ((b4(int(b1(178)%21)) | A) & 209)) * b0(int(b1(13)%20))) * (b4(int(b1(26)%21)) >> 1)
	G = (F+0x733ffff9)*198 - (((F+0x733ffff9)*396 + 212) & 212) + 85
	scratch[20] = byte(uint32(scratch[9]) + (G ^ 148) + ((G ^ 107) << 1) - 127)

	scratch[21] = byte((b2(int(uint32(scratch[16])%35)))&245 | (b2(int(uint32(scratch[5])%35)) & 10))

	A = b0(int(uint32(scratch[17])%20)) | 81
	state35[18] -= byte(((A * A * A) & ^uint32(state20[15])) | ((uint32(scratch[20]) / 15) & uint32(state20[15])))

	scratch[22] = byte(uint32(scratch[2]) + J + E - b0(int(b1(160)%20)) + (b4(int(b0(int((uint32(scratch[2])+J+E)&255)%20))%21) / 3))

	B = ((R ^ uint32(scratch[18])) & ^uint32(198)) | ((S * S) & 198)
	F = (b4(int(b1(69)%21)) & b1(172)) | ((b4(int(b1(69)%21)) | b1(172)) & ((uint32(scratch[3]) - B) + 77))
	state20[16] = byte(147 - ((uint32(scratch[18]) & ((F & 251) | 1)) | (((F & 250) | uint32(scratch[18])) & 198)))

	C = (b4(int(b1(168)%21)) & b0(int(b1(29)%20)) & 7) | ((b4(int(b1(168)%21)) | b0(int(b1(29)%20))) & 6)
	F = (b4(int(b1(155)%21)) & b1(105)) | ((b4(int(b1(155)%21)) | b1(105)) & 141)
	state20[3] -= byte(b4(int(garbleRotateLeftWide(byte(F), C) % 21)))

	work[5] = byte(garbleRotateRight8(state20[12], int((b0(int(b1(61)%20))/5)&7)) ^ ((^b2(int(uint32(scratch[21])%35)) & 0xffffffff) / 5))

	work[198] += work[3]

	A = 162 | b2(int(uint32(scratch[16])%35))
	work[164] += byte((A * A) / 5)

	G = garbleRotateRight8(139, int(uint32(scratch[20])&7))
	C = ((b4(int(uint32(scratch[16])%21)) * b4(int(uint32(scratch[16])%21)) * b4(int(uint32(scratch[16])%21))) & 95) | (b0(int(uint32(scratch[10])%20)) & ^uint32(95))
	scratch[23] = byte((G & 12) | (b0(int(uint32(scratch[5])%20)) & 12) | (G & b0(int(uint32(scratch[5])%20))) | C)

	state35[12] += byte(((b1(103) & 32) | (uint32(scratch[23]) & (b1(103) | 60)) | 16) / 3)
	scratch[24] = work[143]
	scratch[25] = 27

	scratch[26] = byte((((uint32(scratch[10]) & ^uint32(state35[8])) | (b1(35) & uint32(state35[8]))) & uint32(scratch[16])) ^ 119)
	scratch[27] = byte(238 & ((((uint32(scratch[10]) & ^uint32(state35[8])) | (b1(35) & uint32(state35[8]))) & uint32(scratch[16])) << 1))
	scratch[28] = byte((^uint32(scratch[16]) & (uint32(scratch[21]) / 3)) ^ 49)
	scratch[29] = byte(98 & ((^uint32(scratch[16]) & (uint32(scratch[21]) / 3)) << 1))

	// Final circuit stage.
	A = (b1(35) & uint32(state35[8])) | (uint32(scratch[10]) & ^uint32(state35[8]))
	B = (A & uint32(scratch[16])) | ((uint32(scratch[21]) / 3) & ^uint32(scratch[16]))
	work[143] = byte(uint32(scratch[24]) - ((B & (86 + ((b1(172) & 64) >> 1))) | (((((b1(172) & 65) >> 1) ^ 86) | ((^uint32(scratch[16]) & (uint32(scratch[21]) / 3)) | (((uint32(scratch[10]) & ^uint32(state35[8])) | (b1(35) & uint32(state35[8]))) & uint32(scratch[16])))) & uint32(scratch[25]))))

	state35[29] = 162

	A = (((b4(int(uint32(scratch[22])%21)) & 160) | (b0(int(b1(125)%20)) & 95)) >> 1)
	B = b2(int(b1(149)%35)) ^ (b1(43) * b1(43))
	state20[15] += byte((B & A) | ((A | B) & 115))

	scratch[30] = byte(uint32(scratch[16]) - b0(int(uint32(scratch[10])%20)))
	work[95] = byte(b4(int(uint32(scratch[5]) % 21)))

	A = garbleRotateRight8(state35[uint32(scratch[20])%35], int((b2(int(b1(17)%35))*b2(int(b1(17)%35))*b2(int(b1(17)%35)))&7))
	state20[7] -= byte(A * A)

	state35[8] = byte(uint32(state35[8]) - b1(184) + (b4(int(b1(202)%21)) * b4(int(b1(202)%21)) * b4(int(b1(202)%21))))
	state20[16] = byte((b2(int(b1(102)%35)) << 1) & 132)

	scratch[31] = byte((b4(int(uint32(scratch[10])%21)) >> 1) ^ uint32(scratch[17]))

	state20[7] -= byte(b0(int(b1(191)%20)) - (((b4(int(b1(80)%21)) << 1) & ^uint32(177)) | (b4(int(b4(int(uint32(scratch[22])%21))%21)) & 177)))
	state20[6] = byte(b0(int(b1(119) % 20)))

	A = (b4(int(b1(190)%21)) & ^uint32(209)) | (b1(118) & 209)
	B = b0(int(uint32(scratch[30])%20)) * b0(int(uint32(scratch[30])%20))
	state20[12] = byte((b0(int(uint32(scratch[21])%20)) ^ (b2(int(b1(71)%35)) + b2(int(b1(15)%35)))) & ((A & B) | ((A | B) & 27)))

	B = (b1(32) & b2(int(uint32(scratch[22])%35))) | ((b1(32) | b2(int(uint32(scratch[22])%35))) & 23)
	D = (((b4(int(b1(57)%21)) * 231) & 169) | (B & 86))
	F = (((b0(int(b1(82)%20)) & ^uint32(29)) | (b4(int(uint32(scratch[31])%21)) & 29)) & 190) | (b4(int(D/5)%21) & ^uint32(190))
	H = b0(int(uint32(scratch[10])%20)) * b0(int(uint32(scratch[10])%20)) * b0(int(uint32(scratch[10])%20))
	K = (H & b1(82)) | (H & 92) | (b1(82) & 92)
	scratch[32] = byte(((F & K) | ((F | K) & 192)) ^ (D / 5))

	state35[25] ^= byte(((b0(int(uint32(scratch[30])%20)) << 1) * b1(5)) - (garbleRotateLeft8(byte(uint32(scratch[19])), int(b4(int(uint32(scratch[31])%21))&7)) & (uint32(scratch[5]) + 110)))

}

// --- Session key generation ---

func derivePlayfairAESKey(sapTail []byte, message []byte) [16]byte {
	var decrypted [128]byte
	decryptMessage(message, decrypted[:])

	// The KDF input is a 290-byte protocol record followed by ordinary MD5
	// padding. The compression itself is FairPlay's modified MD5/SAP-hash
	// combination, not a standard MD5 digest.
	var material [320]byte
	offset := copy(material[:], playfairKDFPrefix[:])
	offset += copy(material[offset:], decrypted[:])
	offset += copy(material[offset:], sapTail[:128])
	offset += copy(material[offset:], playfairKDFSuffix[:])
	material[offset] = 0x80
	binary.LittleEndian.PutUint64(material[len(material)-8:], uint64(offset)*8)

	state := fairplayWordsFromLittleEndian(fairplayInitialSessionKey)
	for offset := 0; offset < len(material); offset += 64 {
		block := material[offset : offset+64]
		modified := fairplayMD5Compress(state, block, playfairSwapMutation)
		hashed := sapHash(block)
		for word := range state {
			state[word] = modified[word] + binary.LittleEndian.Uint32(hashed[word*4:])
		}
	}
	return fairplayWordsBigEndian(state)
}

// --- Main decrypt function ---

func playfairDecrypt(m3 []byte, ekey []byte) [16]byte {
	aesKey := derivePlayfairAESKey(defaultSAPTail[:], m3)
	cipher, err := aes.NewCipher(aesKey[:])
	if err != nil {
		panic(err) // aesKey always has the fixed AES-128 length.
	}

	var keyOut [16]byte
	cipher.Decrypt(keyOut[:], ekey[56:72])
	for i := range keyOut {
		keyOut[i] ^= ekey[16+i]
	}
	return keyOut
}
