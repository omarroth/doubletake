package airplay

import (
	"encoding/binary"
	"fmt"
)

// fpsapM3Prefix is the invariant 144-byte portion of a version-3 FairPlay
// SAP response. The final 20 bytes are derived from the 128-byte m2 payload.
var fpsapM3Prefix = mustDecodeHexFP(
	"46504c590301030000000098038f1a9c991ea22c511e45ba97f1af8dfb0f86f5" +
		"50c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c7" +
		"12202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b" +
		"7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b691" +
		"01b849fd93a02860d1a0dff5cd4414aa")

// The descriptor's first two blocks are fixed. This is the compressor state
// after those blocks and the 17 fixed bytes beginning the remaining input.
var fpsapDescriptorInitialState = [4]uint32{
	0xd30fe3ad, 0x8670fb82, 0xc1ebdda2, 0x3fb07aa8,
}

var fpsapDescriptorRemainderPrefix = [...]byte{
	0x9f, 0xa7, 0xc5, 0x13, 0x20, 0xae, 0xa6, 0x2d, 0x29,
	0x49, 0x78, 0x6c, 0x87, 0x64, 0x2e, 0x34, 0xba,
}

var fpsapDescriptorSuffix = [...]byte{
	0x97, 0xb5, 0x0f, 0x84, 0xe2, 0x15, 0x5a, 0x9c, 0x24,
	0x99, 0x1c, 0xf4, 0x3a, 0x09, 0x63, 0x55, 0x47,
}

var fpsapFixedBlock = [16]byte{
	0xaf, 0xc2, 0x2b, 0xa0, 0x49, 0xef, 0xfc, 0xfb,
	0xfe, 0x67, 0xac, 0x5e, 0xbe, 0xf6, 0xfb, 0xcb,
}

var fpsapFirstPositionMap = [...]uint8{
	0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11,
}

var fpsapSecondPositionMap = [...]uint8{
	0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3,
}

func fpsapDynamicSAP(payload [128]byte) (out [128]byte) {
	message := make([]byte, 144)
	message[12] = 3
	copy(message[16:], payload[:])
	decryptFairPlayMessage(message, out[:])
	return out
}

// fpsapDescriptor derives the 20 bytes used to key the two table networks.
// Each remaining block contributes the SAP hash, then uses the cycle variant
// of the MD5-shaped compressor. The final padded block is compressed twice.
func fpsapDescriptor(dynamicSAP [128]byte) (out [20]byte) {
	var padded [192]byte
	offset := copy(padded[:], fpsapDescriptorRemainderPrefix[:])
	offset += copy(padded[offset:], dynamicSAP[:])
	offset += copy(padded[offset:], fpsapDescriptorSuffix[:])
	padded[offset] = 0x80
	binary.LittleEndian.PutUint64(padded[len(padded)-8:], 290*8)

	state := fpsapDescriptorInitialState
	var firstFinal [4]uint32
	for offset := 0; offset < len(padded); offset += 64 {
		block := padded[offset : offset+64]
		add := fairplaySAPHash(block)
		for i := range state {
			state[i] += binary.LittleEndian.Uint32(add[i*4:])
		}
		state = fairplayMD5Compress(state, block, fpsapCycleMutation)
		if offset == len(padded)-64 {
			firstFinal = state
			state = fairplayMD5Compress(state, block, fpsapCycleMutation)
		}
	}

	binary.BigEndian.PutUint32(out[:4], firstFinal[0])
	tail := fairplayWordsBigEndian(state)
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
		digest := fairplayWordsBigEndian(fairplayMD5Compress(state, block[:], fpsapSwapMutation))
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
	return fairplayWordsBigEndian(fairplayMD5Compress(state, block[:], fpsapSwapMutation))
}

func fpsapFirstNetwork(masks [9][16]byte) [16]byte {
	state := fpsapFixedBlock
	for i := range state {
		state[i] ^= fpsapFirstInputMask[i]
	}
	for bank := 0; bank < 9; bank++ {
		var substituted [16]byte
		for output, input := range fpsapFirstPositionMap {
			substituted[output] = fpsapFirstTables.roundSubstitution[bank][input].substitute(state[input])
		}
		fpsapMix(&fpsapFirstTables, &state, substituted)
		for i := range state {
			state[i] ^= masks[bank][i]
		}
	}
	var out [16]byte
	for output, input := range fpsapFirstPositionMap {
		out[output] = fpsapFirstTables.finalSubstitution[input].substitute(state[input])
	}
	return out
}

func fpsapSecondNetwork(state [16]byte, masks [9][16]byte) [16]byte {
	for bank := 8; bank >= 0; bank-- {
		var substituted [16]byte
		for output, input := range fpsapSecondPositionMap {
			substituted[output] = fpsapSecondTables.roundSubstitution[bank][output].substitute(state[input]) ^ masks[bank][output]
		}
		fpsapMix(&fpsapSecondTables, &state, substituted)
	}
	var out [16]byte
	for output, input := range fpsapSecondPositionMap {
		out[output] = fpsapSecondTables.finalSubstitution[output].substitute(state[input]) ^ fpsapSecondOutputMask[output]
	}
	return out
}

func fpsapMix(tables *fpsapNetworkTables, state *[16]byte, substituted [16]byte) {
	for word := 0; word < 4; word++ {
		offset := word * 4
		for outputByte := 0; outputByte < 4; outputByte++ {
			var mixed byte
			for inputByte := 0; inputByte < 4; inputByte++ {
				mixed ^=
					tables.mixColumns[inputByte][outputByte].mix(substituted[offset+inputByte])
			}
			state[offset+outputByte] = mixed
		}
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
