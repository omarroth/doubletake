//go:build cgo && fdk_aac

package airplay

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestFDKAACELDEncodesRawFrame(t *testing.T) {
	if !aacELDEncoderAvailable {
		t.Fatal("FDK build did not advertise its AAC-ELD encoder")
	}
	encoder, err := newELDEncoder()
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()

	output := make([]byte, 8192)
	n, err := encoder.Encode(make([]byte, 480*2*2), output)
	if err != nil {
		t.Fatal(err)
	}
	if n <= 0 || n > 1023 {
		t.Fatalf("encoded AAC-ELD length = %d", n)
	}
	if bytes.HasPrefix(output[:n], []byte{0xff, 0xf1}) || bytes.HasPrefix(output[:n], []byte{0xff, 0xf9}) {
		t.Fatalf("AAC-ELD output unexpectedly contains an ADTS header: %x", output[:min(n, 8)])
	}
}

func TestFDKAACELDUsesNegotiatedRedundancyFormats(t *testing.T) {
	legacyStream, legacyPackets := streamAudioPacketsForCodecTest(t, "AES", nil, 4, AudioCodecAACELD, false)
	assertAudioPacketSequences(t, legacyPackets, []uint16{1, 1, 2, 1, 2, 3, 2, 3, 4})
	originals := make(map[uint16][]byte)
	for _, packet := range legacyPackets {
		seq := binary.BigEndian.Uint16(packet[2:4])
		if packet[1] != audioDataPayloadType {
			t.Fatalf("legacy AAC packet PT = %d, want %d", packet[1], audioDataPayloadType)
		}
		if original := originals[seq]; original != nil && !bytes.Equal(original, packet) {
			t.Fatalf("legacy AAC sequence %d changed across its redundant burst", seq)
		}
		originals[seq] = packet
		if !bytes.Equal(legacyStream.audioPacketForRetransmit(seq), packet) {
			t.Fatalf("legacy AAC retransmit history differs for sequence %d", seq)
		}
	}

	rfcStream, rfcPackets := streamAudioPacketsForCodecTest(t, "ChaCha", nil, 4, AudioCodecAACELD, true)
	assertAudioPacketSequences(t, rfcPackets, []uint16{1, 2, 3, 4})
	blocks := make([][][]byte, len(rfcPackets))
	offsets := make([][]uint16, len(rfcPackets))
	for index, packet := range rfcPackets {
		if packet[1] != audioREDPayloadType {
			t.Fatalf("RFC AAC packet PT = %d, want %d", packet[1], audioREDPayloadType)
		}
		plain := decodeAudioPacketPayloadForTest(t, rfcStream, "ChaCha", packet)
		var err error
		offsets[index], blocks[index], err = parseAudioREDPayloadForTest(plain)
		if err != nil {
			t.Fatalf("packet %d RED payload: %v", index+1, err)
		}
		retransmit := rfcStream.audioPacketForRetransmit(uint16(index + 1))
		if len(retransmit) < 12 || retransmit[1] != audioDataPayloadType {
			t.Fatalf("packet %d retransmit is not PT96", index+1)
		}
		if got := binary.LittleEndian.Uint64(packet[len(packet)-audioChaChaNonceSize:]); got != uint64(index*2) {
			t.Fatalf("packet %d RED nonce = %d, want %d", index+1, got, index*2)
		}
		if got := binary.LittleEndian.Uint64(retransmit[len(retransmit)-audioChaChaNonceSize:]); got != uint64(index*2+1) {
			t.Fatalf("packet %d retransmit nonce = %d, want %d", index+1, got, index*2+1)
		}
		if got := decodeAudioPacketPayloadForTest(t, rfcStream, "ChaCha", retransmit); !bytes.Equal(got, blocks[index][len(blocks[index])-1]) {
			t.Fatalf("packet %d retransmit differs from its RED primary", index+1)
		}
	}
	if fmt.Sprint(offsets[0]) != "[0]" || fmt.Sprint(offsets[1]) != "[480 0]" ||
		fmt.Sprint(offsets[2]) != "[960 480 0]" {
		t.Fatalf("RFC AAC offsets = %v", offsets[:3])
	}
	if !bytes.Equal(blocks[2][0], blocks[0][0]) || !bytes.Equal(blocks[2][1], blocks[1][len(blocks[1])-1]) {
		t.Fatal("RFC AAC history payload order does not match prior primary frames")
	}
	if rfcStream.chachaNonce != 8 {
		t.Fatalf("RFC AAC nonce counter = %d, want 8", rfcStream.chachaNonce)
	}
}

func parseAudioREDPayloadForTest(payload []byte) ([]uint16, [][]byte, error) {
	var offsets []uint16
	var lengths []int
	position := 0
	for {
		if position >= len(payload) {
			return nil, nil, fmt.Errorf("missing primary header")
		}
		header := payload[position]
		if header&0x7f != audioDataPayloadType {
			return nil, nil, fmt.Errorf("payload type = %d", header&0x7f)
		}
		if header&0x80 == 0 {
			position++
			break
		}
		if position+4 > len(payload) {
			return nil, nil, fmt.Errorf("truncated redundant header")
		}
		offsets = append(offsets, uint16(payload[position+1])<<6|uint16(payload[position+2]>>2))
		lengths = append(lengths, int(payload[position+2]&0x03)<<8|int(payload[position+3]))
		position += 4
	}
	blocks := make([][]byte, 0, len(lengths)+1)
	for _, length := range lengths {
		if position+length > len(payload) {
			return nil, nil, fmt.Errorf("redundant block exceeds payload")
		}
		blocks = append(blocks, append([]byte(nil), payload[position:position+length]...))
		position += length
	}
	offsets = append(offsets, 0)
	blocks = append(blocks, append([]byte(nil), payload[position:]...))
	return offsets, blocks, nil
}
