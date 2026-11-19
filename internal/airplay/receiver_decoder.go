package airplay

import (
	"encoding/binary"
	"fmt"
)

type receiverDecodedSample struct {
	// Data is valid during the synchronous Sample callback only.
	Data          []byte
	PTS           int64
	Width, Height int
	Stride        int
}

type receiverDecoder interface {
	Push([]byte, int64) error
	Close() error
}

type receiverDecodeCallbacks struct {
	Sample func(receiverDecodedSample)
	Error  func(error)
}

func receiverALACCookie() []byte {
	// ALACSpecificConfig: 352 samples, 16-bit stereo, 44.1 kHz. This is the
	// negotiated screen format, not configuration copied from the encoder.
	return []byte{
		0, 0, 0, 36, 'a', 'l', 'a', 'c', 0, 0, 0, 0,
		0, 0, 1, 96, 0, 16, 40, 10, 14, 2, 0, 0,
		0, 0, 64, 4, 0, 21, 136, 128, 0, 0, 172, 68,
	}
}

func receiverVideoConfiguration(data []byte) (string, []byte, error) {
	if len(data) >= 94 && string(data[4:8]) == "hvc1" && string(data[90:94]) == "hvcC" {
		if int(binary.BigEndian.Uint32(data[:4])) != len(data) || int(binary.BigEndian.Uint32(data[86:90])) != len(data)-86 || len(data[94:]) < 23 || data[94] != 1 || data[115]&3 != 3 {
			return "", nil, fmt.Errorf("truncated hvcC configuration")
		}
		return "hevc", append([]byte(nil), data[94:]...), nil
	}
	if len(data) < 7 || data[0] != 1 || data[4]&3 != 3 {
		return "", nil, fmt.Errorf("unsupported video configuration")
	}
	pos := 6
	count := int(data[5] & 31)
	for group := 0; group < 2; group++ {
		if count == 0 {
			return "", nil, fmt.Errorf("avcC omitted SPS or PPS")
		}
		for n := 0; n < count; n++ {
			if pos+2 > len(data) {
				return "", nil, fmt.Errorf("truncated avcC length")
			}
			size := int(data[pos])<<8 | int(data[pos+1])
			pos += 2
			if size == 0 || size > len(data)-pos {
				return "", nil, fmt.Errorf("invalid avcC parameter set")
			}
			pos += size
		}
		if group == 0 {
			if pos >= len(data) {
				return "", nil, fmt.Errorf("missing avcC PPS count")
			}
			count = int(data[pos])
			pos++
		}
	}
	// AirPlay appends its own four-byte trailer to the decoder record.
	return "h264", append([]byte(nil), data[:pos]...), nil
}
