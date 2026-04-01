// pcapdump: Parse and decrypt AirPlay mirror data channel frames from a raw TCP dump.
//
// Usage:
//  1. Extract raw sender bytes:  tshark -r capture.pcapng -Y "tcp.stream==2 && tcp.srcport==55132 && tcp.len>0" -T fields -e tcp.payload | tr -d ':' | xxd -r -p > raw.bin
//  2. Run:  go run ./cmd/pcapdump -in raw.bin -key 7c38ab2578518687dcf85904 2bd5e77a -scid 2562744207480275294 -out /tmp/iphone_frames.txt
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"strings"
)

func main() {
	inFile := flag.String("in", "/tmp/data_channel_raw.bin", "Raw TCP stream binary file")
	outFile := flag.String("out", "/tmp/iphone_frames.txt", "Output text file for decoded frames")
	keyHex := flag.String("key", "7c38ab2578518687dcf859042bd5e77a", "16-byte AES key hex (after ecdh hash)")
	scid := flag.Uint64("scid", 2562744207480275294, "streamConnectionID")
	flag.Parse()

	data, err := os.ReadFile(*inFile)
	if err != nil {
		log.Fatalf("read input: %v", err)
	}

	// Derive video AES-CTR key and IV (same as UxPlay mirror_buffer_init_aes)
	aesKey, _ := hex.DecodeString(*keyHex)
	if len(aesKey) != 16 {
		log.Fatalf("key must be 16 bytes, got %d", len(aesKey))
	}

	keyStr := fmt.Sprintf("AirPlayStreamKey%d", *scid)
	ivStr := fmt.Sprintf("AirPlayStreamIV%d", *scid)

	h := sha512.New()
	h.Write([]byte(keyStr))
	h.Write(aesKey)
	cipherKey := h.Sum(nil)[:16]

	h.Reset()
	h.Write([]byte(ivStr))
	h.Write(aesKey)
	cipherIV := h.Sum(nil)[:16]

	out, err := os.Create(*outFile)
	if err != nil {
		log.Fatalf("create output: %v", err)
	}
	defer out.Close()

	fmt.Fprintf(out, "=== AirPlay Mirror Data Channel Decoder ===\n")
	fmt.Fprintf(out, "Input:    %s (%d bytes)\n", *inFile, len(data))
	fmt.Fprintf(out, "aesKey:   %x\n", aesKey)
	fmt.Fprintf(out, "scid:     %d\n", *scid)
	fmt.Fprintf(out, "cipherKey:%x\n", cipherKey)
	fmt.Fprintf(out, "cipherIV: %x\n\n", cipherIV)

	// Create AES-CTR cipher (continuous across encrypted frames, with block-alignment)
	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		log.Fatalf("aes: %v", err)
	}

	// Mirror cipher state: matches airplay.go's mirrorCipher / UxPlay's mirror_buffer_decrypt.
	// blockOffset tracks CTR position within a 16-byte block (always 0 after padded block).
	// nextCryptCount tracks how many og bytes are available for the next frame's prefix.
	stream := cipher.NewCTR(block, cipherIV)
	blockOffset := 0
	nextCryptCount := 0
	og := make([]byte, 16)

	decryptFrame := func(payload []byte) []byte {
		out := make([]byte, len(payload))
		pos := 0

		// Step 1: XOR prefix bytes using cached keystream from og
		if nextCryptCount > 0 {
			n := nextCryptCount
			if n > len(payload) {
				n = len(payload)
			}
			ogStart := 16 - nextCryptCount
			for i := 0; i < n; i++ {
				out[i] = payload[i] ^ og[ogStart+i]
			}
			pos = n
		}

		// Step 2: Advance CTR to next 16-byte boundary
		if blockOffset > 0 {
			waste := make([]byte, 16-blockOffset)
			stream.XORKeyStream(waste, waste)
			blockOffset = 0
		}

		remaining := len(payload) - pos
		fullBlocks := (remaining / 16) * 16
		trailing := remaining % 16

		// Step 3: decrypt full 16-byte blocks
		if fullBlocks > 0 {
			stream.XORKeyStream(out[pos:pos+fullBlocks], payload[pos:pos+fullBlocks])
			pos += fullBlocks
		}

		// Step 4: handle trailing partial block
		nextCryptCount = 0
		if trailing > 0 {
			padded := make([]byte, 16)
			copy(padded, payload[pos:pos+trailing])
			stream.XORKeyStream(padded[:], padded[:])
			copy(out[pos:], padded[:trailing])
			copy(og, padded[:])
			nextCryptCount = 16 - trailing
			blockOffset = 0 // full padded block was consumed
		}

		return out
	}

	offset := 0
	frameNum := 0
	for offset+128 <= len(data) {
		header := data[offset : offset+128]
		payloadSize := int(binary.LittleEndian.Uint32(header[0:4]))
		payloadType := header[4]
		payloadSubtype := header[5]
		payloadOpt0 := header[6]
		payloadOpt1 := header[7]
		ntpTimestamp := binary.LittleEndian.Uint64(header[8:16])

		// Parse float32 dimensions from header
		w1 := math.Float32frombits(binary.LittleEndian.Uint32(header[16:20]))
		h1 := math.Float32frombits(binary.LittleEndian.Uint32(header[20:24]))
		w2 := math.Float32frombits(binary.LittleEndian.Uint32(header[40:44]))
		h2 := math.Float32frombits(binary.LittleEndian.Uint32(header[44:48]))

		if payloadSize < 0 || payloadSize > 10*1024*1024 {
			fmt.Fprintf(out, "\n!!! Invalid payload size %d at offset 0x%x, stopping\n", payloadSize, offset)
			break
		}

		if offset+128+payloadSize > len(data) {
			fmt.Fprintf(out, "\n!!! Truncated: need %d payload bytes at offset 0x%x, only %d left\n",
				payloadSize, offset+128, len(data)-offset-128)
			break
		}

		payload := data[offset+128 : offset+128+payloadSize]

		typeStr := "UNKNOWN"
		switch payloadType {
		case 0x00:
			if payloadSubtype == 0x10 {
				typeStr = "VCL-IDR(encrypted)"
			} else {
				typeStr = "VCL(encrypted)"
			}
		case 0x01:
			typeStr = "SPS+PPS(codec)"
		case 0x02:
			typeStr = "heartbeat"
		case 0x05:
			typeStr = "streaming-report"
		}

		fmt.Fprintf(out, "--- Frame %d @ offset 0x%06x ---\n", frameNum, offset)
		fmt.Fprintf(out, "  payloadSize: %d\n", payloadSize)
		fmt.Fprintf(out, "  type: 0x%02x 0x%02x (%s)\n", payloadType, payloadSubtype, typeStr)
		fmt.Fprintf(out, "  option: 0x%02x 0x%02x\n", payloadOpt0, payloadOpt1)
		fmt.Fprintf(out, "  ntpTimestamp: %d (0x%016x)\n", ntpTimestamp, ntpTimestamp)
		fmt.Fprintf(out, "  dimensions: %.0fx%.0f / %.0fx%.0f\n", w1, h1, w2, h2)
		fmt.Fprintf(out, "  header[0:16]: %s\n", hexLine(header[:16]))
		fmt.Fprintf(out, "  header[16:48]: %s\n", hexLine(header[16:48]))

		if payloadSize > 0 {
			dispLen := payloadSize
			if dispLen > 64 {
				dispLen = 64
			}
			fmt.Fprintf(out, "  raw payload[0:%d]: %s\n", dispLen, hexLine(payload[:dispLen]))
		}

		// Decrypt encrypted frames
		if payloadType == 0x00 && payloadSize > 0 {
			decrypted := decryptFrame(payload)
			dispLen := len(decrypted)
			if dispLen > 128 {
				dispLen = 128
			}
			fmt.Fprintf(out, "  decrypted[0:%d]: %s\n", dispLen, hexLine(decrypted[:dispLen]))

			// Parse AVCC NALs from decrypted payload
			parseAVCC(out, decrypted)
		} else if payloadType == 0x01 && payloadSize > 0 {
			// SPS+PPS codec packet — unencrypted, parse avcC
			parseCodecPacket(out, payload)
		}

		fmt.Fprintln(out)
		offset += 128 + payloadSize
		frameNum++
	}

	fmt.Fprintf(out, "\n=== Total frames: %d, final offset: 0x%x / %d ===\n", frameNum, offset, len(data))
	log.Printf("Wrote %d frames to %s", frameNum, *outFile)
}

func parseCodecPacket(out *os.File, payload []byte) {
	if len(payload) < 8 {
		return
	}
	fmt.Fprintf(out, "  avcC header: version=%d profile=%02x compat=%02x level=%02x lenSize=%d\n",
		payload[0], payload[1], payload[2], payload[3], (payload[4]&0x03)+1)
	numSPS := int(payload[5] & 0x1f)
	fmt.Fprintf(out, "  numSPS=%d\n", numSPS)
	pos := 6
	for i := 0; i < numSPS && pos+2 <= len(payload); i++ {
		spsLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
		pos += 2
		if pos+spsLen <= len(payload) {
			sps := payload[pos : pos+spsLen]
			fmt.Fprintf(out, "  SPS[%d] len=%d: %s\n", i, spsLen, hexLine(sps))
			if len(sps) > 0 {
				fmt.Fprintf(out, "    NAL type=%d\n", sps[0]&0x1f)
			}
			pos += spsLen
		}
	}
	if pos < len(payload) {
		numPPS := int(payload[pos])
		pos++
		fmt.Fprintf(out, "  numPPS=%d\n", numPPS)
		for i := 0; i < numPPS && pos+2 <= len(payload); i++ {
			ppsLen := int(binary.BigEndian.Uint16(payload[pos : pos+2]))
			pos += 2
			if pos+ppsLen <= len(payload) {
				pps := payload[pos : pos+ppsLen]
				fmt.Fprintf(out, "  PPS[%d] len=%d: %s\n", i, ppsLen, hexLine(pps))
				pos += ppsLen
			}
		}
	}
	if pos < len(payload) {
		fmt.Fprintf(out, "  trailer (%d bytes): %s\n", len(payload)-pos, hexLine(payload[pos:]))
	}
}

func parseAVCC(out *os.File, decrypted []byte) {
	pos := 0
	naluIdx := 0
	for pos+4 <= len(decrypted) {
		naluLen := int(binary.BigEndian.Uint32(decrypted[pos : pos+4]))
		pos += 4
		if naluLen <= 0 || pos+naluLen > len(decrypted) {
			if naluLen != 0 {
				fmt.Fprintf(out, "  NALU[%d]: invalid len=%d at pos=%d (remaining=%d)\n",
					naluIdx, naluLen, pos-4, len(decrypted)-pos)
			}
			break
		}
		nalType := decrypted[pos] & 0x1f
		refIdc := (decrypted[pos] >> 5) & 0x3
		nalTypeStr := nalTypeName(nalType)
		dispLen := naluLen
		if dispLen > 32 {
			dispLen = 32
		}
		fmt.Fprintf(out, "  NALU[%d]: type=%d(%s) ref_idc=%d len=%d data=%s\n",
			naluIdx, nalType, nalTypeStr, refIdc, naluLen, hexLine(decrypted[pos:pos+dispLen]))
		pos += naluLen
		naluIdx++
	}
	// Report any trailing bytes after last NALU
	if pos < len(decrypted) {
		trailing := decrypted[pos:]
		dispLen := len(trailing)
		if dispLen > 64 {
			dispLen = 64
		}
		fmt.Fprintf(out, "  TRAILING DATA after NALUs: %d bytes: %s\n", len(trailing), hexLine(trailing[:dispLen]))
	}
}

func nalTypeName(t byte) string {
	switch t {
	case 1:
		return "non-IDR"
	case 2:
		return "part-A"
	case 3:
		return "part-B"
	case 4:
		return "part-C"
	case 5:
		return "IDR"
	case 6:
		return "SEI"
	case 7:
		return "SPS"
	case 8:
		return "PPS"
	case 9:
		return "AUD"
	default:
		return "?"
	}
}

func hexLine(data []byte) string {
	var sb strings.Builder
	for i, b := range data {
		if i > 0 && i%16 == 0 {
			sb.WriteString("\n                    ")
		} else if i > 0 {
			sb.WriteByte(' ')
		}
		fmt.Fprintf(&sb, "%02x", b)
	}
	return sb.String()
}
