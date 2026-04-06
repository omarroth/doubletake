package airplay

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"

	"doubletake/internal/fpemu"
)

// fairPlayM1 is the fixed m1 blob that matches the snapshot state.
var fairPlayM1 = mustDecodeHexFP("46504c590301010000000004020003bb")

func mustDecodeHexFP(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// FairPlaySetup performs the complete FairPlay SAP handshake using the
// standalone ARM64 interpreter.
func (c *AirPlayClient) FairPlaySetup(ctx context.Context) error {
	dbg("[FP] starting FairPlay SAP handshake...")

	// Phase 1: Send m1, receive m2
	m1 := make([]byte, len(fairPlayM1))
	copy(m1, fairPlayM1)

	dbg("[FP] posting m1 (%d bytes) to /fp-setup", len(m1))
	m2, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup phase 1 (m1): %w", err)
	}

	if len(m2) < 12 {
		return fmt.Errorf("m2 response too short: %d bytes", len(m2))
	}
	dbg("[FP] received m2 (%d bytes)", len(m2))

	// Phase 2: Compute m3 via standalone interpreter, send to server
	m3raw, err := fpemu.FPSAPExchangeM3(m2)
	if err != nil {
		return fmt.Errorf("FPSAPExchange: %w", err)
	}

	// Ensure FPLY framing
	m3 := m3raw
	if len(m3) < 4 || string(m3[:4]) != "FPLY" {
		m3 = fplyWrap(m3raw, 0x03)
	}

	dbg("[FP] posting m3 (%d bytes) to /fp-setup", len(m3))
	m4, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup phase 2 (m3): %w", err)
	}

	if len(m4) < 12 {
		return fmt.Errorf("m4 response too short: %d bytes", len(m4))
	}
	dbg("[FP] received m4 (%d bytes)", len(m4))

	m4Payload := fplyUnwrap(m4)
	if len(m4Payload) >= 16 {
		c.fpKey = make([]byte, 16)
		copy(c.fpKey, m4Payload[:16])
	}

	// Generate and store IV for stream encryption
	var iv [16]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return fmt.Errorf("generate stream IV: %w", err)
	}
	c.fpIV = iv[:]

	// Save m3 for ekey derivation.
	c.fpM3 = make([]byte, len(m3))
	copy(c.fpM3, m3)

	// Derive encryption key.
	ekey := buildEkey()
	aesKey := playfairDecrypt(c.fpM3, ekey[:])
	c.FpEkey = ekey[:]
	c.fpAesKey = make([]byte, 16)
	copy(c.fpAesKey, aesKey[:])

	// Hash with pair-verify shared secret if available.
	finalKey := aesKey[:]
	if c.PairKeys != nil && len(c.PairKeys.SharedSecret) > 0 {
		h := sha512.New()
		h.Write(aesKey[:])
		h.Write(c.PairKeys.SharedSecret)
		finalKey = h.Sum(nil)[:16]
	}

	c.fpKey = finalKey

	dbg("[FP] FairPlay SAP handshake complete!")
	dbg("[FP] session key: %x", c.fpKey)
	dbg("[FP] stream IV:  %x", iv[:])

	return nil
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

// deriveStreamKeys derives AES stream encryption keys from the pair-verify shared secret.
func (c *AirPlayClient) deriveStreamKeys() error {
	if c.encWriteKey == nil {
		key := make([]byte, 16)
		iv := make([]byte, 16)
		if _, err := rand.Read(key); err != nil {
			return err
		}
		if _, err := rand.Read(iv); err != nil {
			return err
		}
		c.streamKey = key
		c.streamIV = iv
		return nil
	}

	c.streamKey = make([]byte, 16)
	c.streamIV = make([]byte, 16)
	copy(c.streamKey, c.encWriteKey)
	copy(c.streamIV, c.encReadKey)

	return nil
}
