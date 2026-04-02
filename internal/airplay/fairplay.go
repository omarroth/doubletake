package airplay

import (
	"context"
	"os"
)

func (c *AirPlayClient) FairPlaySetup(ctx context.Context) error {
	// Use the pure Go implementation by default.
	// Set FAIRPLAY_EMULATE=1 to force ARM64 emulation (requires "emulate" build tag
	// + unicorn + AirPlaySender binary).
	if os.Getenv("FAIRPLAY_EMULATE") != "" {
		return c.fairPlaySetupEmulated(ctx)
	}
	return c.FairPlaySetupNative(ctx)
}

// buildEkey constructs a 72-byte ekey with the FPLY header format.
// The chunk data is zeros — the actual AES key is determined by what
// playfair_decrypt produces from this ekey + m3.
//
// Format (72 bytes):
//
//	[0:4]   "FPLY"
//	[4:8]   01 02 01 00
//	[8:12]  00 00 00 3c  (0x3c = 60 = remaining bytes)
//	[12:16] 00 00 00 00  (padding)
//	[16:32] chunk1 (16 bytes)
//	[32:56] padding (24 bytes, zeros)
//	[56:72] chunk2 (16 bytes)
func buildEkey() [72]byte {
	var ekey [72]byte
	copy(ekey[0:4], []byte("FPLY"))
	ekey[4] = 0x01
	ekey[5] = 0x02
	ekey[6] = 0x01
	ekey[7] = 0x00
	ekey[8] = 0x00
	ekey[9] = 0x00
	ekey[10] = 0x00
	ekey[11] = 0x3c
	// bytes 12-71 are zeros (chunk1, padding, chunk2 all zero)
	return ekey
}

// fplyWrap adds FPLY framing header to raw SAP data.
// If the data already starts with "FPLY", it's returned as-is.
func fplyWrap(data []byte, msgType byte) []byte {
	if len(data) >= 4 && string(data[:4]) == "FPLY" {
		return data
	}
	header := make([]byte, 12+len(data))
	copy(header[0:4], []byte("FPLY"))
	header[4] = 0x03
	header[5] = 0x01
	header[6] = msgType
	header[7] = 0x00
	header[8] = byte(len(data) >> 24)
	header[9] = byte(len(data) >> 16)
	header[10] = byte(len(data) >> 8)
	header[11] = byte(len(data))
	copy(header[12:], data)
	return header
}

// fplyUnwrap strips the FPLY framing header and returns the payload.
// If the data doesn't have FPLY framing, it's returned as-is.
func fplyUnwrap(data []byte) []byte {
	if len(data) >= 12 && string(data[:4]) == "FPLY" {
		return data[12:]
	}
	return data
}
