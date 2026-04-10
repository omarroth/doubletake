package airplay

// Pure Go port of playfair_decrypt and supporting functions.
// Ported from playfair.c, omg_hax.c, sap_hash.c, hand_garble.c, modified_md5.c.

import (
	"encoding/binary"
	"math"
)

// --- Constants from omg_hax.c ---

var sapIV = [26]byte{
	0x2B, 0x84, 0xFB, 0x79, 0xDA, 0x75, 0xB9, 0x04, 0x6C, 0x24, 0x73, 0xF7, 0xD1, 0xC4, 0xAB, 0x0E,
	0x2B, 0x84, 0xFB, 0x79, 0x75, 0xB9, 0x04, 0x6C, 0x24, 0x73,
}

var sapKeyMaterial = [16]byte{
	0xA1, 0x1A, 0x4A, 0x83, 0xF2, 0x7A, 0x75, 0xEE,
	0xA2, 0x1A, 0x7D, 0xB8, 0x8D, 0x77, 0x92, 0xAB,
}

var indexMangle = [11]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C}

var initialSessionKey = [16]byte{
	0xDC, 0xDC, 0xF3, 0xB9, 0x0B, 0x74, 0xDC, 0xFB,
	0x86, 0x7F, 0xF7, 0x60, 0x16, 0x72, 0x90, 0x51,
}

var staticSource1 = [17]byte{
	0xFA, 0x9C, 0xAD, 0x4D, 0x4B, 0x68, 0x26, 0x8C,
	0x7F, 0xF3, 0x88, 0x99, 0xDE, 0x92, 0x2E, 0x95,
	0x1E,
}

var staticSource2 = [47]byte{
	0xEC, 0x4E, 0x27, 0x5E, 0xFD, 0xF2, 0xE8, 0x30,
	0x97, 0xAE, 0x70, 0xFB, 0xE0, 0x00, 0x3F, 0x1C,
	0x39, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
}

var defaultSap = [280]byte{
	0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
	0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
	0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
	0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79, 0x79,
	0x79, 0x79, 0x79, 0x79, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x02, 0x53,
	0x00, 0x01, 0xcc, 0x34, 0x2a, 0x5e, 0x5b, 0x1a, 0x67, 0x73, 0xc2, 0x0e, 0x21, 0xb8, 0x22, 0x4d,
	0xf8, 0x62, 0x48, 0x18, 0x64, 0xef, 0x81, 0x0a, 0xae, 0x2e, 0x37, 0x03, 0xc8, 0x81, 0x9c, 0x23,
	0x53, 0x9d, 0xe5, 0xf5, 0xd7, 0x49, 0xbc, 0x5b, 0x7a, 0x26, 0x6c, 0x49, 0x62, 0x83, 0xce, 0x7f,
	0x03, 0x93, 0x7a, 0xe1, 0xf6, 0x16, 0xde, 0x0c, 0x15, 0xff, 0x33, 0x8c, 0xca, 0xff, 0xb0, 0x9e,
	0xaa, 0xbb, 0xe4, 0x0f, 0x5d, 0x5f, 0x55, 0x8f, 0xb9, 0x7f, 0x17, 0x31, 0xf8, 0xf7, 0xda, 0x60,
	0xa0, 0xec, 0x65, 0x79, 0xc3, 0x3e, 0xa9, 0x83, 0x12, 0xc3, 0xb6, 0x71, 0x35, 0xa6, 0x69, 0x4f,
	0xf8, 0x23, 0x05, 0xd9, 0xba, 0x5c, 0x61, 0x5f, 0xa2, 0x54, 0xd2, 0xb1, 0x83, 0x45, 0x83, 0xce,
	0xe4, 0x2d, 0x44, 0x26, 0xc8, 0x35, 0xa7, 0xa5, 0xf6, 0xc8, 0x42, 0x1c, 0x0d, 0xa3, 0xf1, 0xc7,
	0x00, 0x50, 0xf2, 0xe5, 0x17, 0xf8, 0xd0, 0xfa, 0x77, 0x8d, 0xfb, 0x82, 0x8d, 0x40, 0xc7, 0x8e,
	0x94, 0x1e, 0x1e, 0x1e, 0x00, 0x00, 0x00, 0x00,
}

// --- XOR helpers ---

func zXor(in []byte, out []byte, blocks int) {
	for j := 0; j < blocks; j++ {
		for i := 0; i < 16; i++ {
			out[j*16+i] = in[j*16+i] ^ zKey[i]
		}
	}
}

func xXor(in []byte, out []byte, blocks int) {
	for j := 0; j < blocks; j++ {
		for i := 0; i < 16; i++ {
			out[j*16+i] = in[j*16+i] ^ xKey[i]
		}
	}
}

func tXor(in []byte, out []byte) {
	for i := 0; i < 16; i++ {
		out[i] = in[i] ^ tKey[i]
	}
}

func xorBlocks(a, b, out []byte) {
	for i := 0; i < 16; i++ {
		out[i] = a[i] ^ b[i]
	}
}

// --- Table index helpers ---

func tableIndex(i int) []byte {
	off := ((31 * i) % 0x28) << 8
	return tableS1[off : off+256]
}

func messageTableIndex(i int) []byte {
	off := ((97 * i) % 144) << 8
	return tableS2[off : off+256]
}

func permuteTable2(i uint) []byte {
	off := int(((71 * i) % 144)) << 8
	return tableS4[off : off+256]
}

// --- Permutations ---

func permuteBlock1(block []byte) {
	block[0] = tableS3[block[0]]
	block[4] = tableS3[0x400+int(block[4])]
	block[8] = tableS3[0x800+int(block[8])]
	block[12] = tableS3[0xc00+int(block[12])]

	tmp := block[13]
	block[13] = tableS3[0x100+int(block[9])]
	block[9] = tableS3[0xd00+int(block[5])]
	block[5] = tableS3[0x900+int(block[1])]
	block[1] = tableS3[0x500+int(tmp)]

	tmp = block[2]
	block[2] = tableS3[0xa00+int(block[10])]
	block[10] = tableS3[0x200+int(tmp)]
	tmp = block[6]
	block[6] = tableS3[0xe00+int(block[14])]
	block[14] = tableS3[0x600+int(tmp)]

	tmp = block[3]
	block[3] = tableS3[0xf00+int(block[7])]
	block[7] = tableS3[0x300+int(block[11])]
	block[11] = tableS3[0x700+int(block[15])]
	block[15] = tableS3[0xb00+int(tmp)]
}

func permuteBlock2(block []byte, round int) {
	t2 := func(idx int) []byte { return permuteTable2(uint(idx)) }

	block[0] = t2(round*16 + 0)[block[0]]
	block[4] = t2(round*16 + 4)[block[4]]
	block[8] = t2(round*16 + 8)[block[8]]
	block[12] = t2(round*16 + 12)[block[12]]

	tmp := block[13]
	block[13] = t2(round*16 + 13)[block[9]]
	block[9] = t2(round*16 + 9)[block[5]]
	block[5] = t2(round*16 + 5)[block[1]]
	block[1] = t2(round*16 + 1)[tmp]

	tmp = block[2]
	block[2] = t2(round*16 + 2)[block[10]]
	block[10] = t2(round*16 + 10)[tmp]
	tmp = block[6]
	block[6] = t2(round*16 + 6)[block[14]]
	block[14] = t2(round*16 + 14)[tmp]

	tmp = block[3]
	block[3] = t2(round*16 + 3)[block[7]]
	block[7] = t2(round*16 + 7)[block[11]]
	block[11] = t2(round*16 + 11)[block[15]]
	block[15] = t2(round*16 + 15)[tmp]
}

// --- Key schedule generation ---

func generateKeySchedule(keyMaterial []byte, keySchedule *[11][4]uint32) {
	var keyData [4]uint32

	buf := make([]byte, 16)
	tXor(keyMaterial, buf)

	// Copy bytes into keyData (little-endian, matching C layout)
	for i := 0; i < 4; i++ {
		keyData[i] = binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
	}

	ti := 0
	for round := 0; round < 11; round++ {
		// Serialize keyData back to buffer bytes (LE)
		for i := 0; i < 4; i++ {
			binary.LittleEndian.PutUint32(buf[i*4:], keyData[i])
		}

		// H: store keyData[0]
		keySchedule[round][0] = keyData[0]

		// I: S-box substitution
		table1 := tableIndex(ti)
		table2 := tableIndex(ti + 1)
		table3 := tableIndex(ti + 2)
		table4 := tableIndex(ti + 3)
		ti += 4

		buf[0] ^= table1[buf[0x0d]] ^ indexMangle[round]
		buf[1] ^= table2[buf[0x0e]]
		buf[2] ^= table3[buf[0x0f]]
		buf[3] ^= table4[buf[0x0c]]

		// Update keyData from buf
		for i := 0; i < 4; i++ {
			keyData[i] = binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
		}

		// H: store keyData[1]
		keySchedule[round][1] = keyData[1]

		// J: keyData[1] ^= keyData[0]
		keyData[1] ^= keyData[0]

		// H: store keyData[2]
		keySchedule[round][2] = keyData[2]

		// J: keyData[2] ^= keyData[1]
		keyData[2] ^= keyData[1]

		// K, L: store keyData[3], then J
		keySchedule[round][3] = keyData[3]
		keyData[3] ^= keyData[2]
	}
}

// --- AES-like cycle ---

func cycle(block []byte, keySchedule *[11][4]uint32) {
	// XOR with round key 10
	bWords := [4]uint32{
		binary.LittleEndian.Uint32(block[0:4]),
		binary.LittleEndian.Uint32(block[4:8]),
		binary.LittleEndian.Uint32(block[8:12]),
		binary.LittleEndian.Uint32(block[12:16]),
	}
	bWords[0] ^= keySchedule[10][0]
	bWords[1] ^= keySchedule[10][1]
	bWords[2] ^= keySchedule[10][2]
	bWords[3] ^= keySchedule[10][3]
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(block[i*4:], bWords[i])
	}

	permuteBlock1(block)

	for round := 0; round < 9; round++ {
		key0 := [4]byte{
			byte(keySchedule[9-round][0]),
			byte(keySchedule[9-round][0] >> 8),
			byte(keySchedule[9-round][0] >> 16),
			byte(keySchedule[9-round][0] >> 24),
		}

		ptr1 := tableS5[block[3]^key0[3]]
		ptr2 := tableS6[block[2]^key0[2]]
		ptr3 := tableS8[block[0]^key0[0]]
		ptr4 := tableS7[block[1]^key0[1]]
		ab := ptr1 ^ ptr2 ^ ptr3 ^ ptr4
		binary.LittleEndian.PutUint32(block[0:4], ab)

		key1 := [4]byte{
			byte(keySchedule[9-round][1]),
			byte(keySchedule[9-round][1] >> 8),
			byte(keySchedule[9-round][1] >> 16),
			byte(keySchedule[9-round][1] >> 24),
		}
		ptr2 = tableS5[block[7]^key1[3]]
		ptr1 = tableS6[block[6]^key1[2]]
		ptr4 = tableS7[block[5]^key1[1]]
		ptr3 = tableS8[block[4]^key1[0]]
		ab = ptr1 ^ ptr2 ^ ptr3 ^ ptr4
		binary.LittleEndian.PutUint32(block[4:8], ab)

		key2 := [4]byte{
			byte(keySchedule[9-round][2]),
			byte(keySchedule[9-round][2] >> 8),
			byte(keySchedule[9-round][2] >> 16),
			byte(keySchedule[9-round][2] >> 24),
		}
		key3 := [4]byte{
			byte(keySchedule[9-round][3]),
			byte(keySchedule[9-round][3] >> 8),
			byte(keySchedule[9-round][3] >> 16),
			byte(keySchedule[9-round][3] >> 24),
		}

		w2 := tableS5[block[11]^key2[3]] ^
			tableS6[block[10]^key2[2]] ^
			tableS7[block[9]^key2[1]] ^
			tableS8[block[8]^key2[0]]
		binary.LittleEndian.PutUint32(block[8:12], w2)

		w3 := tableS5[block[15]^key3[3]] ^
			tableS6[block[14]^key3[2]] ^
			tableS7[block[13]^key3[1]] ^
			tableS8[block[12]^key3[0]]
		binary.LittleEndian.PutUint32(block[12:16], w3)

		permuteBlock2(block, 8-round)
	}

	bWords[0] = binary.LittleEndian.Uint32(block[0:4]) ^ keySchedule[0][0]
	bWords[1] = binary.LittleEndian.Uint32(block[4:8]) ^ keySchedule[0][1]
	bWords[2] = binary.LittleEndian.Uint32(block[8:12]) ^ keySchedule[0][2]
	bWords[3] = binary.LittleEndian.Uint32(block[12:16]) ^ keySchedule[0][3]
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint32(block[i*4:], bWords[i])
	}
}

// --- Message decryption ---

func decryptMessage(messageIn []byte, decryptedMessage []byte) {
	var buffer [16]byte
	mode := messageIn[12]

	for i := 0; i < 8; i++ {
		// Copy the nth block
		for j := 0; j < 16; j++ {
			if mode == 3 {
				buffer[j] = messageIn[(0x80-0x10*i)+j]
			} else {
				buffer[j] = messageIn[(0x10*(i+1))+j]
			}
		}

		// 9 rounds of permutation
		for j := 0; j < 9; j++ {
			base := 0x80 - 0x10*j

			buffer[0x0] = messageTableIndex(base + 0x0)[buffer[0x0]] ^ messageKey[mode][base+0x0]
			buffer[0x4] = messageTableIndex(base + 0x4)[buffer[0x4]] ^ messageKey[mode][base+0x4]
			buffer[0x8] = messageTableIndex(base + 0x8)[buffer[0x8]] ^ messageKey[mode][base+0x8]
			buffer[0xc] = messageTableIndex(base + 0xc)[buffer[0xc]] ^ messageKey[mode][base+0xc]

			tmp := buffer[0x0d]
			buffer[0xd] = messageTableIndex(base + 0xd)[buffer[0x9]] ^ messageKey[mode][base+0xd]
			buffer[0x9] = messageTableIndex(base + 0x9)[buffer[0x5]] ^ messageKey[mode][base+0x9]
			buffer[0x5] = messageTableIndex(base + 0x5)[buffer[0x1]] ^ messageKey[mode][base+0x5]
			buffer[0x1] = messageTableIndex(base + 0x1)[tmp] ^ messageKey[mode][base+0x1]

			tmp = buffer[0x02]
			buffer[0x2] = messageTableIndex(base + 0x2)[buffer[0xa]] ^ messageKey[mode][base+0x2]
			buffer[0xa] = messageTableIndex(base + 0xa)[tmp] ^ messageKey[mode][base+0xa]
			tmp = buffer[0x06]
			buffer[0x6] = messageTableIndex(base + 0x6)[buffer[0xe]] ^ messageKey[mode][base+0x6]
			buffer[0xe] = messageTableIndex(base + 0xe)[tmp] ^ messageKey[mode][base+0xe]

			tmp = buffer[0x3]
			buffer[0x3] = messageTableIndex(base + 0x3)[buffer[0x7]] ^ messageKey[mode][base+0x3]
			buffer[0x7] = messageTableIndex(base + 0x7)[buffer[0xb]] ^ messageKey[mode][base+0x7]
			buffer[0xb] = messageTableIndex(base + 0xb)[buffer[0xf]] ^ messageKey[mode][base+0xb]
			buffer[0xf] = messageTableIndex(base + 0xf)[tmp] ^ messageKey[mode][base+0xf]

			// T-table mixing
			b0 := tableS9[0x000+uint32(buffer[0x0])] ^
				tableS9[0x100+uint32(buffer[0x1])] ^
				tableS9[0x200+uint32(buffer[0x2])] ^
				tableS9[0x300+uint32(buffer[0x3])]
			b1 := tableS9[0x000+uint32(buffer[0x4])] ^
				tableS9[0x100+uint32(buffer[0x5])] ^
				tableS9[0x200+uint32(buffer[0x6])] ^
				tableS9[0x300+uint32(buffer[0x7])]
			b2 := tableS9[0x000+uint32(buffer[0x8])] ^
				tableS9[0x100+uint32(buffer[0x9])] ^
				tableS9[0x200+uint32(buffer[0xa])] ^
				tableS9[0x300+uint32(buffer[0xb])]
			b3 := tableS9[0x000+uint32(buffer[0xc])] ^
				tableS9[0x100+uint32(buffer[0xd])] ^
				tableS9[0x200+uint32(buffer[0xe])] ^
				tableS9[0x300+uint32(buffer[0xf])]

			binary.LittleEndian.PutUint32(buffer[0:4], b0)
			binary.LittleEndian.PutUint32(buffer[4:8], b1)
			binary.LittleEndian.PutUint32(buffer[8:12], b2)
			binary.LittleEndian.PutUint32(buffer[12:16], b3)
		}

		// Final S-box permutation
		buffer[0x0] = tableS10[(0x0<<8)+int(buffer[0x0])]
		buffer[0x4] = tableS10[(0x4<<8)+int(buffer[0x4])]
		buffer[0x8] = tableS10[(0x8<<8)+int(buffer[0x8])]
		buffer[0xc] = tableS10[(0xc<<8)+int(buffer[0xc])]

		tmp := buffer[0x0d]
		buffer[0xd] = tableS10[(0xd<<8)+int(buffer[0x9])]
		buffer[0x9] = tableS10[(0x9<<8)+int(buffer[0x5])]
		buffer[0x5] = tableS10[(0x5<<8)+int(buffer[0x1])]
		buffer[0x1] = tableS10[(0x1<<8)+int(tmp)]

		tmp = buffer[0x02]
		buffer[0x2] = tableS10[(0x2<<8)+int(buffer[0xa])]
		buffer[0xa] = tableS10[(0xa<<8)+int(tmp)]
		tmp = buffer[0x06]
		buffer[0x6] = tableS10[(0x6<<8)+int(buffer[0xe])]
		buffer[0xe] = tableS10[(0xe<<8)+int(tmp)]

		tmp = buffer[0x3]
		buffer[0x3] = tableS10[(0x3<<8)+int(buffer[0x7])]
		buffer[0x7] = tableS10[(0x7<<8)+int(buffer[0xb])]
		buffer[0xb] = tableS10[(0xb<<8)+int(buffer[0xf])]
		buffer[0xf] = tableS10[(0xf<<8)+int(tmp)]

		// XOR with previous block or IV
		if mode == 2 || mode == 1 || mode == 0 {
			if i > 0 {
				xorBlocks(buffer[:], messageIn[0x10*i:], decryptedMessage[0x10*i:])
			} else {
				xorBlocks(buffer[:], messageIv[mode][:], decryptedMessage[0x10*i:])
			}
		} else {
			if i < 7 {
				xorBlocks(buffer[:], messageIn[0x70-0x10*i:], decryptedMessage[0x70-0x10*i:])
			} else {
				xorBlocks(buffer[:], messageIv[mode][:], decryptedMessage[0x70-0x10*i:])
			}
		}
	}
}

// --- Modified MD5 ---

var md5Shift = [64]int{
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
}

func rol32(input uint32, count int) uint32 {
	return (input << count) | (input >> (32 - count))
}

func modifiedMD5(originalBlockIn []byte, keyIn []byte, keyOut []byte) {
	var blockIn [64]byte
	copy(blockIn[:], originalBlockIn[:64])
	blockWords := (*[16]uint32)((*[16]uint32)(nil))
	// Use slice-based access for blockIn as uint32 words (LE)
	getBlockWord := func(i int) uint32 {
		return binary.LittleEndian.Uint32(blockIn[i*4 : i*4+4])
	}
	setBlockWord := func(i int, v uint32) {
		binary.LittleEndian.PutUint32(blockIn[i*4:], v)
	}
	swapWords := func(a, b int) {
		va, vb := getBlockWord(a), getBlockWord(b)
		setBlockWord(a, vb)
		setBlockWord(b, va)
	}

	keyWords := [4]uint32{
		binary.LittleEndian.Uint32(keyIn[0:4]),
		binary.LittleEndian.Uint32(keyIn[4:8]),
		binary.LittleEndian.Uint32(keyIn[8:12]),
		binary.LittleEndian.Uint32(keyIn[12:16]),
	}

	A := keyWords[0]
	B := keyWords[1]
	C := keyWords[2]
	D := keyWords[3]

	for i := 0; i < 64; i++ {
		var j int
		switch {
		case i < 16:
			j = i
		case i < 32:
			j = (5*i + 1) % 16
		case i < 48:
			j = (3*i + 5) % 16
		default:
			j = (7 * i) % 16
		}

		// Big-endian read of block word
		input := uint32(blockIn[4*j])<<24 | uint32(blockIn[4*j+1])<<16 | uint32(blockIn[4*j+2])<<8 | uint32(blockIn[4*j+3])

		sinVal := math.Abs(math.Sin(float64(i + 1)))
		constant := uint32(sinVal * (1 << 32))

		Z := A + input + constant

		switch {
		case i < 16:
			Z = rol32(Z+((B&C)|(^B&D)), md5Shift[i])
		case i < 32:
			Z = rol32(Z+((B&D)|(C&^D)), md5Shift[i])
		case i < 48:
			Z = rol32(Z+(B^C^D), md5Shift[i])
		default:
			Z = rol32(Z+(C^(B|^D)), md5Shift[i])
		}

		Z = Z + B
		A, B, C, D = D, Z, B, C

		if i == 31 {
			swapWords(int(A&15), int(B&15))
			swapWords(int(C&15), int(D&15))
			swapWords(int((A&(15<<4))>>4), int((B&(15<<4))>>4))
			swapWords(int((A&(15<<8))>>8), int((B&(15<<8))>>8))
			swapWords(int((A&(15<<12))>>12), int((B&(15<<12))>>12))
		}
	}

	binary.LittleEndian.PutUint32(keyOut[0:4], keyWords[0]+A)
	binary.LittleEndian.PutUint32(keyOut[4:8], keyWords[1]+B)
	binary.LittleEndian.PutUint32(keyOut[8:12], keyWords[2]+C)
	binary.LittleEndian.PutUint32(keyOut[12:16], keyWords[3]+D)

	_ = blockWords // suppress unused
}

// --- SAP hash ---

func rol8(input byte, count int) byte {
	return ((input << count) & 0xff) | (input >> (8 - count))
}

func rol8x(input byte, count int) uint32 {
	return uint32((input << count)) | uint32(input>>(8-count))
}

func weirdRor8(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return uint32((input>>count)&0xff) | uint32(input&0xff)<<(8-count)
}

func weirdRol8(input byte, count int) uint32 {
	if count == 0 {
		return 0
	}
	return uint32((input<<count)&0xff) | uint32(input&0xff)>>(8-count)
}

func weirdRol32(input byte, count uint32) uint32 {
	if count == 0 {
		return 0
	}
	return uint32(input)<<count ^ uint32(input)>>(8-count)
}

func sapHash(blockIn []byte, keyOut []byte) {
	blockWords := [16]uint32{}
	for i := 0; i < 16; i++ {
		blockWords[i] = binary.LittleEndian.Uint32(blockIn[i*4 : i*4+4])
	}

	buffer0 := [20]byte{0x96, 0x5F, 0xC6, 0x53, 0xF8, 0x46, 0xCC, 0x18, 0xDF, 0xBE, 0xB2, 0xF8, 0x38, 0xD7, 0xEC, 0x22, 0x03, 0xD1, 0x20, 0x8F}
	var buffer1 [210]byte
	buffer2 := [35]byte{0x43, 0x54, 0x62, 0x7A, 0x18, 0xC3, 0xD6, 0xB3, 0x9A, 0x56, 0xF6, 0x1C, 0x14, 0x3F, 0x0C, 0x1D, 0x3B, 0x36, 0x83, 0xB1, 0x39, 0x51, 0x4A, 0xAA, 0x09, 0x3E, 0xFE, 0x44, 0xAF, 0xDE, 0xC3, 0x20, 0x9D, 0x42, 0x3A}
	var buffer3 [132]byte
	buffer4 := [21]byte{0xED, 0x25, 0xD1, 0xBB, 0xBC, 0x27, 0x9F, 0x02, 0xA2, 0xA9, 0x11, 0x00, 0x0C, 0xB3, 0x52, 0xC0, 0xBD, 0xE3, 0x1B, 0x49, 0xC7}
	i0Index := [11]int{18, 22, 23, 0, 5, 19, 32, 31, 10, 21, 30}

	// Load input into buffer1
	for i := 0; i < 210; i++ {
		inWord := blockWords[(i%64)>>2]
		inByte := byte((inWord >> ((3 - (i % 4)) << 3)) & 0xff)
		buffer1[i] = inByte
	}

	// Scrambling
	for i := 0; i < 840; i++ {
		x := buffer1[uint32(i-155)%210]
		y := buffer1[uint32(i-57)%210]
		z := buffer1[uint32(i-13)%210]
		w := buffer1[uint32(i)%210]
		buffer1[i%210] = byte((uint32(rol8(y, 5)) + (uint32(rol8(z, 3)) ^ uint32(w)) - uint32(rol8(x, 7))) & 0xff)
	}

	// Garble
	garble(buffer0[:], buffer1[:], buffer2[:], buffer3[:], buffer4[:])

	// Fill output with 0xE1
	for i := 0; i < 16; i++ {
		keyOut[i] = 0xE1
	}

	// Apply buffer3
	for i := 0; i < 11; i++ {
		if i == 3 {
			keyOut[i] = 0x3d
		} else {
			keyOut[i] = byte((uint32(keyOut[i]) + uint32(buffer3[i0Index[i]*4])) & 0xff)
		}
	}

	// Apply buffer0
	for i := 0; i < 20; i++ {
		keyOut[i%16] ^= buffer0[i]
	}

	// Apply buffer2
	for i := 0; i < 35; i++ {
		keyOut[i%16] ^= buffer2[i]
	}

	// Apply buffer1
	for i := 0; i < 210; i++ {
		keyOut[i%16] ^= buffer1[i]
	}

	// Reverse scramble
	for j := 0; j < 16; j++ {
		for i := 0; i < 16; i++ {
			x := keyOut[uint32(i-7)%16]
			y := keyOut[i%16]
			z := keyOut[uint32(i-37)%16]
			w := keyOut[uint32(i-177)%16]
			keyOut[i] = rol8(x, 1) ^ y ^ rol8(z, 6) ^ rol8(w, 5)
		}
	}
}

// --- Garble (hand_garble.c) ---

func garble(buffer0, buffer1, buffer2, buffer3, buffer4 []byte) {
	var tmp, tmp2, tmp3 uint32
	var A, B, C, D, E, M, J, G, F, H, K, R, S, T, U, V, W, X, Y, Z uint32

	b0 := func(i int) uint32 { return uint32(buffer0[i]) }
	b1 := func(i int) uint32 { return uint32(buffer1[i]) }
	b2 := func(i int) uint32 { return uint32(buffer2[i]) }
	b4 := func(i int) uint32 { return uint32(buffer4[i]) }

	buffer2[12] = byte(0x14 + (((b1(64) & 92) | ((b1(99) / 3) & 35)) & b4(int(rol8x(buffer4[b1(206)%21], 4)%21))))
	buffer1[4] = byte((b1(99) / 5) * (b1(99) / 5) * 2)
	buffer2[34] = 0xb8
	buffer1[153] ^= byte(b2(int(b1(203)%35)) * b2(int(b1(203)%35)) * b1(190))
	buffer0[3] -= byte(((b4(int(b1(205)%21)) >> 1) & 80) | 0x40)
	buffer0[16] = 0x93
	buffer0[13] = 0x62
	buffer1[33] -= byte(b4(int(b1(36)%21)) & 0xf6)

	tmp2 = b2(int(b1(67) % 35))
	buffer2[12] = 0x07

	tmp = b0(int(b1(181) % 20))
	buffer1[2] -= byte(3136 & 0xff)

	buffer0[19] = byte(b4(int(b1(58) % 21)))

	buffer3[0] = byte(92 - b2(int(b1(32)%35)))
	buffer3[4] = byte(b2(int(b1(15)%35)) + 0x9e)
	buffer1[34] += byte(b4(int((b2(int(b1(15)%35))+0x9e)&0xff)%21) / 5)
	buffer0[19] += byte(0xfffffee6 - ((b0(int(uint32(buffer3[4])%20)) >> 1) & 102))

	// buffer1[15]
	shiftAmt := b4(int(b1(190)%21)) & 7
	shifted := (b1(72) >> shiftAmt) ^ (b1(72) << ((7 - (b4(int(b1(190)%21)) - 1)) & 7))
	buffer1[15] = byte((3 * (shifted - (3 * b4(int(b1(126)%21))))) ^ b1(15))

	buffer0[15] ^= byte(b2(int(b1(181)%35)) * b2(int(b1(181)%35)) * b2(int(b1(181)%35)))
	buffer2[4] ^= byte(b1(202) / 3)

	A = 92 - b0(int(uint32(buffer3[0])%20))
	E = (A & 0xc6) | (^b1(105) & 0xc6) | (A & (^b1(105)))
	buffer2[1] += byte(E * E * E)

	buffer0[19] ^= byte(((224 | (b4(int(b1(92)%21)) & 27)) * b2(int(b1(41)%35))) / 3)
	buffer1[140] += byte(weirdRor8(92, int(b1(5)&7)))

	buffer2[12] += byte(((((^b1(4)) ^ b2(int(b1(12)%35))) | b1(182)) & 192) | (((^b1(4)) ^ b2(int(b1(12)%35))) & b1(182)))
	buffer1[36] += 125

	buffer1[124] = byte(rol8x(byte(((74&b1(138))|((74|b1(138))&b0(15)))&b0(int(b1(43)%20)))|byte(((74&b1(138))|((74|b1(138))&b0(15))|b0(int(b1(43)%20)))&95), 4))

	buffer3[8] = byte((((b0(int(uint32(buffer3[4])%20)) & 95) & ((b4(int(b1(68)%21)) & 46) << 1)) | 16) ^ 92)

	A = b1(177) + b4(int(b1(79)%21))
	D = (((A >> 1) | ((3 * b1(148)) / 5)) & b2(1)) | ((A >> 1) & ((3 * b1(148)) / 5))
	buffer3[12] = byte(-34 - int32(D))

	A = 8 - (b2(22) & 7)
	B = b1(33) >> (A & 7)
	C = b1(33) << (b2(22) & 7)
	buffer2[16] += byte(((b2(int(uint32(buffer3[0])%35)) & 159) | b0(int(uint32(buffer3[4])%20)) | 8) - ((B ^ C) | 128))

	buffer0[14] ^= byte(b2(int(uint32(buffer3[12]) % 35)))

	// Monster
	A = weirdRol8(buffer4[b0(int(b1(201)%20))%21], int((b2(int(b1(112)%35))<<1)&7))
	D = (b0(int(b1(208)%20)) & 131) | (b0(int(b1(164)%20)) & 124)
	buffer1[19] += byte((A & (D / 5)) | ((A | (D / 5)) & 37))

	buffer2[8] = byte(weirdRor8(140, int(((b4(int(b1(45)%21))+92)*(b4(int(b1(45)%21))+92))&7)))
	buffer1[190] = 56
	buffer2[8] ^= buffer3[0]

	buffer1[53] = byte(^((b0(int(b1(83)%20)) | 204) / 5))
	buffer0[13] += byte(b0(int(b1(41) % 20)))
	buffer0[10] = byte(((b2(int(uint32(buffer3[0])%35)) & b1(2)) | ((b2(int(uint32(buffer3[0])%35)) | b1(2)) & uint32(buffer3[12]))) / 15)

	A = (((56 | (b4(int(b1(2)%21)) & 68)) | b2(int(uint32(buffer3[8])%35))) & 42) | (((b4(int(b1(2)%21)) & 68) | 56) & b2(int(uint32(buffer3[8])%35)))
	buffer3[16] = byte((A * A) + 110)
	buffer3[20] = byte(202 - uint32(buffer3[16]))
	buffer3[24] = buffer1[151]
	buffer2[13] ^= byte(b4(int(uint32(buffer3[0]) % 21)))

	B = ((b2(int(b1(179)%35)) - 38) & 177) | (uint32(buffer3[12]) & 177)
	C = (b2(int(b1(179)%35)) - 38) & uint32(buffer3[12])
	buffer3[28] = byte(30 + ((B | C) * (B | C)))
	buffer3[32] = byte(uint32(buffer3[28]) + 62)

	// eek
	A = ((uint32(buffer3[20]) + (uint32(buffer3[0]) & 74)) | ^b4(int(uint32(buffer3[0])%21))) & 121
	B = (uint32(buffer3[20]) + (uint32(buffer3[0]) & 74)) & ^b4(int(uint32(buffer3[0])%21))
	tmp3 = A | B
	C = ((((A | B) ^ 0xffffffa6) | uint32(buffer3[0])) & 4) | (((A | B) ^ 0xffffffa6) & uint32(buffer3[0]))
	buffer1[47] = byte((b2(int(b1(89)%35)) + C) ^ b1(47))

	buffer3[36] = byte(((uint32(rol8(byte((tmp&179)+68), 2)) & b0(3)) | (tmp2 & ^b0(3))) - 15)
	buffer1[123] ^= 221

	A = (b4(int(uint32(buffer3[0])%21)) / 3) - b2(int(uint32(buffer3[4])%35))
	C = (((uint32(buffer3[0]) & 163) + 92) & 246) | (uint32(buffer3[0]) & 92)
	E = ((C | uint32(buffer3[24])) & 54) | (C & uint32(buffer3[24]))
	buffer3[40] = byte(A - E)

	buffer3[44] = byte(tmp3 ^ 81 ^ (((uint32(buffer3[0]) >> 1) & 101) + 26))
	buffer3[48] = byte(b2(int(uint32(buffer3[4])%35)) & 27)
	buffer3[52] = 27
	buffer3[56] = 199

	// caffeine
	buffer3[64] = byte(uint32(buffer3[4]) + (((((((uint32(buffer3[40]) | uint32(buffer3[24])) & 177) | (uint32(buffer3[40]) & uint32(buffer3[24]))) & (((b4(int(uint32(buffer3[0])%20)) & 177) | 176) | ((b4(int(uint32(buffer3[0]) % 21))) & ^uint32(3)))) | ((((uint32(buffer3[40]) & uint32(buffer3[24])) | ((uint32(buffer3[40]) | uint32(buffer3[24])) & 177)) & 199) | ((((b4(int(uint32(buffer3[0])%21)) & 1) + 176) | (b4(int(uint32(buffer3[0])%21)) &^ uint32(3))) & uint32(buffer3[56])))) & (^uint32(buffer3[52]))) | uint32(buffer3[48])))

	buffer2[33] ^= buffer1[26]
	buffer1[106] ^= byte(uint32(buffer3[20]) ^ 133)

	buffer2[30] = byte(((uint32(buffer3[64]) / 3) - (275 | (uint32(buffer3[0]) & 247))) ^ b0(int(b1(122)%20)))
	buffer1[22] = byte((b2(int(b1(90)%35)) & 95) | 68)

	A = (b4(int(uint32(buffer3[36])%21)) & 184) | (b2(int(uint32(buffer3[44])%35)) & ^uint32(184))
	buffer2[18] += byte((A * A * A) >> 1)

	buffer2[5] -= byte(b4(int(b1(92) % 21)))

	A = (((b1(41) & ^uint32(24)) | (b2(int(b1(183)%35)) & 24)) & (uint32(buffer3[16]) + 53)) | (uint32(buffer3[20]) & b2(int(uint32(buffer3[20])%35)))
	B = (b1(17) & (^uint32(buffer3[44]))) | (b0(int(b1(59)%20)) & uint32(buffer3[44]))
	buffer2[18] ^= byte(A * B)

	A = weirdRor8(buffer1[11], int(b2(int(b1(28)%35))&7)) & 7
	B = (((b0(int(b1(93)%20)) & ^b0(14)) | (b0(14) & 150)) & ^uint32(28)) | (b1(7) & 28)
	buffer2[22] = byte(((((B | weirdRol8(buffer2[uint32(buffer3[0])%35], int(A))) & b2(33)) | (B & weirdRol8(buffer2[uint32(buffer3[0])%35], int(A)))) + 74) & 0xff)

	A = b4(int((b0(int(b1(39)%20)) ^ 217) % 21))
	buffer0[15] -= byte(((((uint32(buffer3[20]) | uint32(buffer3[0])) & 214) | (uint32(buffer3[20]) & uint32(buffer3[0]))) & A) | ((((uint32(buffer3[20]) | uint32(buffer3[0])) & 214) | (uint32(buffer3[20]) & uint32(buffer3[0])) | A) & uint32(buffer3[32])))

	// Save T
	B = (((b2(int(b1(57)%35)) & b0(int(uint32(buffer3[64])%20))) | ((b0(int(uint32(buffer3[64])%20)) | b2(int(b1(57)%35))) & 95) | (uint32(buffer3[64]) & 45) | 82) & 32)
	C = ((b2(int(b1(57)%35)) & b0(int(uint32(buffer3[64])%20))) | ((b2(int(b1(57)%35)) | b0(int(uint32(buffer3[64])%20))) & 95)) & ((uint32(buffer3[64]) & 45) | 82)
	D = (((uint32(buffer3[0]) / 3) - (uint32(buffer3[64]) | b1(22))) ^ (uint32(buffer3[28]) + 62) ^ (B | C))
	T = b0(int((D & 0xff) % 20))

	buffer3[68] = byte((b0(int(b1(99)%20)) * b0(int(b1(99)%20)) * b0(int(b1(99)%20)) * b0(int(b1(99)%20))) | b2(int(uint32(buffer3[64])%35)))

	U = b0(int(b1(50) % 20))
	W = b2(int(b1(138) % 35))
	X = b4(int(b1(39) % 21))
	Y = b0(int(b1(4) % 20))
	Z = b4(int(b1(202) % 21))
	V = b0(int(b1(151) % 20))
	S = b2(int(b1(14) % 35))
	R = b0(int(b1(145) % 20))

	A = (b2(int(uint32(buffer3[68])%35)) & b0(int(b1(209)%20))) | ((b2(int(uint32(buffer3[68])%35)) | b0(int(b1(209)%20))) & 24)
	B = weirdRol8(buffer4[b1(127)%21], int(b2(int(uint32(buffer3[68])%35))&7))
	C = (A & b0(10)) | (B & ^b0(10))
	D = 7 ^ (b4(int(b2(int(uint32(buffer3[36])%35))%21)) << 1)
	buffer3[72] = byte((C & 71) | (D & ^uint32(71)))

	buffer2[2] += byte(((((b0(int(uint32(buffer3[20])%20)) << 1) & 159) | (b4(int(b1(190)%21)) & ^uint32(159))) & ((((b4(int(uint32(buffer3[64])%21)) & 110) | (b0(int(b1(25)%20)) & ^uint32(110))) & ^uint32(150)) | (b1(25) & 150))))
	buffer2[14] -= byte(((b2(int(uint32(buffer3[20])%35)) & (uint32(buffer3[72]) ^ b2(int(b1(100)%35)))) & ^uint32(34)) | (b1(97) & 34))
	buffer0[17] = 115

	buffer1[23] ^= byte(((((((b4(int(b1(17)%21)) | b0(int(uint32(buffer3[20])%20))) & uint32(buffer3[72])) | (b4(int(b1(17)%21)) & b0(int(uint32(buffer3[20])%20)))) & (b1(50) / 3)) |
		((((b4(int(b1(17)%21)) | b0(int(uint32(buffer3[20])%20))) & uint32(buffer3[72])) | (b4(int(b1(17)%21)) & b0(int(uint32(buffer3[20])%20))) | (b1(50) / 3)) & 246)) << 1))

	buffer0[13] = byte(((((((b0(int(uint32(buffer3[40])%20)) | b1(10)) & 82) | (b0(int(uint32(buffer3[40])%20)) & b1(10))) & 209) |
		((b0(int(b1(39)%20)) << 1) & 46)) >> 1))

	buffer2[33] -= byte(b1(113) & 9)
	buffer2[28] -= byte(((((2 | (b1(110) & 222)) >> 1) & ^uint32(223)) | (uint32(buffer3[20]) & 223)))

	J = weirdRol8(byte(V|Z), int(U&7))
	A = (b2(16) & T) | (W & (^b2(16)))
	B = (b1(33) & 17) | (X & ^uint32(17))
	E = ((Y | ((A + B) / 5)) & 147) | (Y & ((A + B) / 5))
	M = (uint32(buffer3[40]) & b4(int((uint32(buffer3[8])+J+E)&0xff)%21)) |
		((uint32(buffer3[40]) | b4(int((uint32(buffer3[8])+J+E)&0xff)%21)) & b2(23))

	buffer0[15] = byte((((b4(int(uint32(buffer3[20])%21)) - 48) & (^b1(184))) | ((b4(int(uint32(buffer3[20])%21)) - 48) & 189) | (189 & ^b1(184))) & (M * M * M))

	buffer2[22] += buffer1[183]
	buffer3[76] = byte((3 * b4(int(b1(1)%21))) ^ uint32(buffer3[0]))

	A = b2(int((uint32(buffer3[8]) + (J + E)) & 0xff % 35))
	F = (((b4(int(b1(178)%21)) & A) | ((b4(int(b1(178)%21)) | A) & 209)) * b0(int(b1(13)%20))) * (b4(int(b1(26)%21)) >> 1)
	G = (F+0x733ffff9)*198 - (((F+0x733ffff9)*396 + 212) & 212) + 85
	buffer3[80] = byte(uint32(buffer3[36]) + (G ^ 148) + ((G ^ 107) << 1) - 127)

	buffer3[84] = byte((b2(int(uint32(buffer3[64])%35)))&245 | (b2(int(uint32(buffer3[20])%35)) & 10))

	A = b0(int(uint32(buffer3[68])%20)) | 81
	buffer2[18] -= byte(((A * A * A) & ^uint32(buffer0[15])) | ((uint32(buffer3[80]) / 15) & uint32(buffer0[15])))

	buffer3[88] = byte(uint32(buffer3[8]) + J + E - b0(int(b1(160)%20)) + (b4(int(b0(int((uint32(buffer3[8])+J+E)&255)%20))%21) / 3))

	B = ((R ^ uint32(buffer3[72])) & ^uint32(198)) | ((S * S) & 198)
	F = (b4(int(b1(69)%21)) & b1(172)) | ((b4(int(b1(69)%21)) | b1(172)) & ((uint32(buffer3[12]) - B) + 77))
	buffer0[16] = byte(147 - ((uint32(buffer3[72]) & ((F & 251) | 1)) | (((F & 250) | uint32(buffer3[72])) & 198)))

	C = (b4(int(b1(168)%21)) & b0(int(b1(29)%20)) & 7) | ((b4(int(b1(168)%21)) | b0(int(b1(29)%20))) & 6)
	F = (b4(int(b1(155)%21)) & b1(105)) | ((b4(int(b1(155)%21)) | b1(105)) & 141)
	buffer0[3] -= byte(b4(int(weirdRol32(byte(F), C) % 21)))

	buffer1[5] = byte(weirdRor8(buffer0[12], int((b0(int(b1(61)%20))/5)&7)) ^ ((^b2(int(uint32(buffer3[84])%35)) & 0xffffffff) / 5))

	buffer1[198] += buffer1[3]

	A = 162 | b2(int(uint32(buffer3[64])%35))
	buffer1[164] += byte((A * A) / 5)

	G = weirdRor8(139, int(uint32(buffer3[80])&7))
	C = ((b4(int(uint32(buffer3[64])%21)) * b4(int(uint32(buffer3[64])%21)) * b4(int(uint32(buffer3[64])%21))) & 95) | (b0(int(uint32(buffer3[40])%20)) & ^uint32(95))
	buffer3[92] = byte((G & 12) | (b0(int(uint32(buffer3[20])%20)) & 12) | (G & b0(int(uint32(buffer3[20])%20))) | C)

	buffer2[12] += byte(((b1(103) & 32) | (uint32(buffer3[92]) & (b1(103) | 60)) | 16) / 3)
	buffer3[96] = buffer1[143]
	buffer3[100] = 27

	buffer3[104] = byte((((uint32(buffer3[40]) & ^uint32(buffer2[8])) | (b1(35) & uint32(buffer2[8]))) & uint32(buffer3[64])) ^ 119)
	buffer3[108] = byte(238 & ((((uint32(buffer3[40]) & ^uint32(buffer2[8])) | (b1(35) & uint32(buffer2[8]))) & uint32(buffer3[64])) << 1))
	buffer3[112] = byte((^uint32(buffer3[64]) & (uint32(buffer3[84]) / 3)) ^ 49)
	buffer3[116] = byte(98 & ((^uint32(buffer3[64]) & (uint32(buffer3[84]) / 3)) << 1))

	// finale
	A = (b1(35) & uint32(buffer2[8])) | (uint32(buffer3[40]) & ^uint32(buffer2[8]))
	B = (A & uint32(buffer3[64])) | ((uint32(buffer3[84]) / 3) & ^uint32(buffer3[64]))
	buffer1[143] = byte(uint32(buffer3[96]) - ((B & (86 + ((b1(172) & 64) >> 1))) | (((((b1(172) & 65) >> 1) ^ 86) | ((^uint32(buffer3[64]) & (uint32(buffer3[84]) / 3)) | (((uint32(buffer3[40]) & ^uint32(buffer2[8])) | (b1(35) & uint32(buffer2[8]))) & uint32(buffer3[64])))) & uint32(buffer3[100]))))

	buffer2[29] = 162

	A = (((b4(int(uint32(buffer3[88])%21)) & 160) | (b0(int(b1(125)%20)) & 95)) >> 1)
	B = b2(int(b1(149)%35)) ^ (b1(43) * b1(43))
	buffer0[15] += byte((B & A) | ((A | B) & 115))

	buffer3[120] = byte(uint32(buffer3[64]) - b0(int(uint32(buffer3[40])%20)))
	buffer1[95] = byte(b4(int(uint32(buffer3[20]) % 21)))

	A = weirdRor8(buffer2[uint32(buffer3[80])%35], int((b2(int(b1(17)%35))*b2(int(b1(17)%35))*b2(int(b1(17)%35)))&7))
	buffer0[7] -= byte(A * A)

	buffer2[8] = byte(uint32(buffer2[8]) - b1(184) + (b4(int(b1(202)%21)) * b4(int(b1(202)%21)) * b4(int(b1(202)%21))))
	buffer0[16] = byte((b2(int(b1(102)%35)) << 1) & 132)

	buffer3[124] = byte((b4(int(uint32(buffer3[40])%21)) >> 1) ^ uint32(buffer3[68]))

	buffer0[7] -= byte(b0(int(b1(191)%20)) - (((b4(int(b1(80)%21)) << 1) & ^uint32(177)) | (b4(int(b4(int(uint32(buffer3[88])%21))%21)) & 177)))
	buffer0[6] = byte(b0(int(b1(119) % 20)))

	A = (b4(int(b1(190)%21)) & ^uint32(209)) | (b1(118) & 209)
	B = b0(int(uint32(buffer3[120])%20)) * b0(int(uint32(buffer3[120])%20))
	buffer0[12] = byte((b0(int(uint32(buffer3[84])%20)) ^ (b2(int(b1(71)%35)) + b2(int(b1(15)%35)))) & ((A & B) | ((A | B) & 27)))

	B = (b1(32) & b2(int(uint32(buffer3[88])%35))) | ((b1(32) | b2(int(uint32(buffer3[88])%35))) & 23)
	D = (((b4(int(b1(57)%21)) * 231) & 169) | (B & 86))
	F = (((b0(int(b1(82)%20)) & ^uint32(29)) | (b4(int(uint32(buffer3[124])%21)) & 29)) & 190) | (b4(int(D/5)%21) & ^uint32(190))
	H = b0(int(uint32(buffer3[40])%20)) * b0(int(uint32(buffer3[40])%20)) * b0(int(uint32(buffer3[40])%20))
	K = (H & b1(82)) | (H & 92) | (b1(82) & 92)
	buffer3[128] = byte(((F & K) | ((F | K) & 192)) ^ (D / 5))

	buffer2[25] ^= byte(((b0(int(uint32(buffer3[120])%20)) << 1) * b1(5)) - (weirdRol8(byte(uint32(buffer3[76])), int(b4(int(uint32(buffer3[124])%21))&7)) & (uint32(buffer3[20]) + 110)))

	_, _, _, _, _, _, _ = M, J, G, H, K, R, S // suppress unused
	_, _, _, _, _, _, _ = T, U, V, W, X, Y, Z
	_ = tmp
	_ = tmp2
	_ = tmp3
}

// --- Session key generation ---

func generateSessionKey(oldSap []byte, messageIn []byte, sessionKey []byte) {
	var decryptedMessage [128]byte
	var newSap [320]byte

	decryptMessage(messageIn, decryptedMessage[:])

	copy(newSap[0x000:], staticSource1[:])
	copy(newSap[0x011:], decryptedMessage[:0x80])
	copy(newSap[0x091:], oldSap[0x80:0x100])
	copy(newSap[0x111:], staticSource2[:])
	copy(sessionKey, initialSessionKey[:])

	var md5Out [16]byte
	for round := 0; round < 5; round++ {
		base := newSap[round*64:]
		modifiedMD5(base, sessionKey, md5Out[:])
		sapHash(base, sessionKey)

		// Add MD5 result to session key
		for i := 0; i < 4; i++ {
			skw := binary.LittleEndian.Uint32(sessionKey[i*4:])
			mdw := binary.LittleEndian.Uint32(md5Out[i*4:])
			binary.LittleEndian.PutUint32(sessionKey[i*4:], skw+mdw)
		}
	}

	// Byte-swap each 4-byte word
	for i := 0; i < 16; i += 4 {
		sessionKey[i], sessionKey[i+3] = sessionKey[i+3], sessionKey[i]
		sessionKey[i+1], sessionKey[i+2] = sessionKey[i+2], sessionKey[i+1]
	}

	// XOR with 121
	for i := 0; i < 16; i++ {
		sessionKey[i] ^= 121
	}
}

// --- Main decrypt function ---

// PlayfairDecryptExported is an exported wrapper for testing.
func PlayfairDecryptExported(m3 []byte, ekey []byte) [16]byte {
	return playfairDecrypt(m3, ekey)
}

func playfairDecrypt(m3 []byte, ekey []byte) [16]byte {
	return playfairDecryptWithSap(m3, ekey, defaultSap[:])
}

func playfairDecryptWithSap(m3 []byte, ekey []byte, sap []byte) [16]byte {
	chunk1 := ekey[16:32]
	chunk2 := ekey[56:72]

	var blockIn [16]byte
	var sapKey [16]byte
	var keySchedule [11][4]uint32
	var keyOut [16]byte

	generateSessionKey(sap, m3, sapKey[:])
	generateKeySchedule(sapKey[:], &keySchedule)

	zXor(chunk2, blockIn[:], 1)
	cycle(blockIn[:], &keySchedule)

	for i := 0; i < 16; i++ {
		keyOut[i] = blockIn[i] ^ chunk1[i]
	}
	xXor(keyOut[:], keyOut[:], 1)
	zXor(keyOut[:], keyOut[:], 1)

	return keyOut
}
