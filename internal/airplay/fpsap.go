package airplay

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// fpsapM3Prefix is the invariant 144-byte portion of a version-3 FairPlay
// SAP response. The final 20 bytes are derived from the 128-byte m2 payload.
var fpsapM3Prefix = mustDecodeHexFP(
	"46504c590301030000000098038f1a9c991ea22c511e45ba97f1af8dfb0f86f5" +
		"50c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c7" +
		"12202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b" +
		"7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b691" +
		"01b849fd93a02860d1a0dff5cd4414aa")

var fpsapDescriptorPrefix = [...]byte{
	0xa0, 0x44, 0x9c, 0x4d, 0x09, 0xe4, 0xbd, 0x7f, 0x6e,
	0xc5, 0xd0, 0xcc, 0x35, 0x9d, 0xa7, 0x46, 0x7a,
}

var fpsapDescriptorSuffix = [...]byte{
	0x97, 0xb5, 0x0f, 0x84, 0xe2, 0x15, 0x5a, 0x9c, 0x24,
	0x99, 0x1c, 0xf4, 0x3a, 0x09, 0x63, 0x55, 0x47,
}

var fpsapFixedBlock = [16]byte{
	0xaf, 0xc2, 0x2b, 0xa0, 0x49, 0xef, 0xfc, 0xfb,
	0xfe, 0x67, 0xac, 0x5e, 0xbe, 0xf6, 0xfb, 0xcb,
}

var fpsapMD5Shift = [64]int{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

var fpsapMD5Constant = [64]uint32{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
}

type fpsapPermutation uint8

const (
	fpsapSwapPermutation fpsapPermutation = iota
	fpsapCyclePermutation
)

// fpsapMD5Compress is MD5's compression function with the one FairPlay
// modification: after round 31, eight message words are permuted using the
// low two nibbles of A, B, C and D. Blocks are read in the byte order used by
// the unobfuscated callers (big endian per word); state words remain native
// MD5 little-endian words.
func fpsapMD5Compress(state [4]uint32, block []byte, permutation fpsapPermutation) [4]uint32 {
	var message [16]uint32
	for i := range message {
		message[i] = binary.BigEndian.Uint32(block[i*4:])
	}

	a, b, c, d := state[0], state[1], state[2], state[3]
	for round := 0; round < 64; round++ {
		var f uint32
		var word int
		switch {
		case round < 16:
			f, word = (b&c)|(^b&d), round
		case round < 32:
			f, word = (d&b)|(^d&c), (5*round+1)&15
		case round < 48:
			f, word = b^c^d, (3*round+5)&15
		default:
			f, word = c^(b|^d), (7*round)&15
		}

		a, b, c, d = d,
			b+bits.RotateLeft32(a+f+fpsapMD5Constant[round]+message[word], fpsapMD5Shift[round]),
			b, c

		if round == 31 {
			indices := [8]int{
				int(a & 15), int(b & 15), int(c & 15), int(d & 15),
				int((a >> 4) & 15), int((b >> 4) & 15),
				int((c >> 4) & 15), int((d >> 4) & 15),
			}
			switch permutation {
			case fpsapSwapPermutation:
				for i, j := range indices {
					message[i], message[j] = message[j], message[i]
				}
			case fpsapCyclePermutation:
				first := message[indices[0]]
				for i := 0; i < len(indices)-1; i++ {
					message[indices[i]] = message[indices[i+1]]
				}
				message[indices[len(indices)-1]] = first
			}
		}
	}

	return [4]uint32{state[0] + a, state[1] + b, state[2] + c, state[3] + d}
}

func fpsapWordsFromLittleEndian(in [16]byte) (out [4]uint32) {
	for i := range out {
		out[i] = binary.LittleEndian.Uint32(in[i*4:])
	}
	return out
}

func fpsapWordsBigEndian(words [4]uint32) (out [16]byte) {
	for i, word := range words {
		binary.BigEndian.PutUint32(out[i*4:], word)
	}
	return out
}

func fpsapDynamicSAP(payload [128]byte) (out [128]byte) {
	message := make([]byte, 144)
	message[12] = 3
	copy(message[16:], payload[:])
	decryptMessage(message, out[:])
	return out
}

// fpsapDescriptor derives the 20 bytes used to key the two table networks.
// It is a five-block streaming hash over the two decrypted SAP values. Each
// block first contributes the existing sapHash, then uses the cycle variant
// of the MD5-shaped compressor. The final padded block is compressed twice.
func fpsapDescriptor(dynamicSAP [128]byte) (out [20]byte) {
	var decryptedPrefix [128]byte
	decryptMessage(fpsapM3Prefix, decryptedPrefix[:])

	message := make([]byte, 290)
	offset := copy(message, fpsapDescriptorPrefix[:])
	offset += copy(message[offset:], decryptedPrefix[:])
	offset += copy(message[offset:], dynamicSAP[:])
	copy(message[offset:], fpsapDescriptorSuffix[:])

	padded := make([]byte, 320)
	copy(padded, message)
	padded[len(message)] = 0x80
	binary.LittleEndian.PutUint64(padded[len(padded)-8:], uint64(len(message))*8)

	state := fpsapWordsFromLittleEndian(initialSessionKey)
	var firstFinal [4]uint32
	for offset := 0; offset < len(padded); offset += 64 {
		block := padded[offset : offset+64]
		var add [16]byte
		sapHash(block, add[:])
		for i := range state {
			state[i] += binary.LittleEndian.Uint32(add[i*4:])
		}
		state = fpsapMD5Compress(state, block, fpsapCyclePermutation)
		if offset == len(padded)-64 {
			firstFinal = state
			state = fpsapMD5Compress(state, block, fpsapCyclePermutation)
		}
	}

	binary.BigEndian.PutUint32(out[:4], firstFinal[0])
	tail := fpsapWordsBigEndian(state)
	copy(out[4:], tail[:])
	return out
}

func fpsapMasks(seed [20]byte) (masks [9][16]byte) {
	state := [4]uint32{0x1d4a4587, 0x92f39fcc, 0x1d87d836, 0xcdc86697}
	suffix := [...]byte{
		0x57, 0xd8, 0xee, 0xcb, 0xde, 0xfb, 0xcf, 0x59,
		0x1c, 0x27, 0xa2, 0xcf, 0xbe, 0xb0, 0x89,
	}
	for i := range masks {
		var block [64]byte
		copy(block[:20], seed[:])
		block[20] = byte(i)
		copy(block[21:36], suffix[:])
		block[36] = 0x80
		binary.LittleEndian.PutUint32(block[56:60], 0x320)
		digest := fpsapWordsBigEndian(fpsapMD5Compress(state, block[:], fpsapSwapPermutation))
		masks[i] = digest
	}
	return masks
}

func fpsapDigest32(left, right [16]byte) [16]byte {
	var block [64]byte
	copy(block[:16], left[:])
	copy(block[16:32], right[:])
	block[32] = 0x80
	binary.LittleEndian.PutUint32(block[56:60], 0x100)
	state := [4]uint32{0xb9f3dcdc, 0xfbdc740b, 0x60f77f86, 0x51907216}
	return fpsapWordsBigEndian(fpsapMD5Compress(state, block[:], fpsapSwapPermutation))
}

func fpsapFirstNetwork(masks [9][16]byte) [16]byte {
	state := [16]byte{
		0x0f, 0x54, 0x5e, 0x5a, 0xb7, 0x7e, 0x16, 0x80,
		0x1a, 0xed, 0xd5, 0x81, 0xd0, 0x87, 0x26, 0xdc,
	}
	forward := [...]int{0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11}
	for bank := 0; bank < 9; bank++ {
		var substituted [16]byte
		for output, input := range forward {
			substituted[output] = fpsapRoundS(0, bank, input, state[input])
		}
		fpsapMix(0, &state, substituted)
		for i := range state {
			state[i] ^= masks[bank][i]
		}
	}
	var out [16]byte
	for output, input := range forward {
		out[output] = fpsapFinalS(0, input, state[input])
	}
	return out
}

func fpsapSecondNetwork(state [16]byte, masks [9][16]byte) [16]byte {
	inverse := [...]int{0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3}
	for bank := 8; bank >= 0; bank-- {
		var substituted [16]byte
		for output, input := range inverse {
			substituted[output] = fpsapRoundS(1, bank, output, state[input]) ^ masks[bank][output]
		}
		fpsapMix(1, &state, substituted)
	}
	finalMask := [...]byte{
		0x67, 0xbc, 0x54, 0xc0, 0x8e, 0x32, 0x85, 0x1b,
		0x50, 0xd2, 0x12, 0x5f, 0x68, 0xb7, 0x40, 0xa5,
	}
	var out [16]byte
	for output, input := range inverse {
		out[output] = fpsapFinalS(1, output, state[input]) ^ finalMask[output]
	}
	return out
}

func fpsapMix(network int, state *[16]byte, substituted [16]byte) {
	for word := 0; word < 4; word++ {
		offset := word * 4
		mixed := fpsapMixT(network, 0, substituted[offset]) ^
			fpsapMixT(network, 1, substituted[offset+1]) ^
			fpsapMixT(network, 2, substituted[offset+2]) ^
			fpsapMixT(network, 3, substituted[offset+3])
		binary.LittleEndian.PutUint32(state[offset:], mixed)
	}
}

func fpsapExchangeStandalone(payload [128]byte) [20]byte {
	dynamicSAP := fpsapDynamicSAP(payload)
	seed := fpsapDescriptor(dynamicSAP)
	masks := fpsapMasks(seed)
	intermediate := fpsapFirstNetwork(masks)
	left := fpsapDigest32(intermediate, fpsapFixedBlock)
	whiteboxOutput := fpsapSecondNetwork(left, masks)
	digest := fpsapDigest32(left, whiteboxOutput)

	var out [20]byte
	copy(out[:4], whiteboxOutput[:4])
	copy(out[4:], digest[:])
	return out
}

func fpsapExchangeM3(m2 []byte) ([]byte, error) {
	if len(m2) < 142 {
		return nil, fmt.Errorf("m2 too short: got %d bytes, need at least 142", len(m2))
	}
	var payload [128]byte
	copy(payload[:], m2[14:142])
	hash := fpsapExchangeStandalone(payload)
	out := make([]byte, 0, len(fpsapM3Prefix)+len(hash))
	out = append(out, fpsapM3Prefix...)
	out = append(out, hash[:]...)
	return out, nil
}
