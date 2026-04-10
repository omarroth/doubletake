package airplay

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"

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
	dbg("[FP] m2 first 32: %02x", m2[:min(32, len(m2))])

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

	dbg("[FP] m3 (%d bytes) first 32: %02x", len(m3), m3[:min(32, len(m3))])

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
	dbg("[FP] m4 payload (%d bytes): %02x", len(m4Payload), m4Payload)

	// Generate and store IV for stream encryption
	var iv [16]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return fmt.Errorf("generate stream IV: %w", err)
	}
	c.fpIV = iv[:]

	// Save m3 for ekey derivation.
	c.fpM3 = make([]byte, len(m3))
	copy(c.fpM3, m3)

	// Build ekey and derive audio encryption key.
	// Both sender and receiver call playfairDecrypt(m3, ekey) with the same
	// inputs (m3 sent during FP handshake, ekey sent in SETUP body).
	ekey := buildEkey()
	c.FpEkey = ekey[:]
	dbg("[FP] ekey chunk1 [16:32]: %02x", ekey[16:32])
	dbg("[FP] ekey chunk2 [56:72]: %02x", ekey[56:72])

	fpAesKey := playfairDecrypt(c.fpM3, ekey[:])
	c.fpAesKey = fpAesKey[:]
	dbg("[FP] playfairDecrypt fpAesKey: %02x", fpAesKey[:])
	dbg("[FP] m3 first 32 bytes: %02x", c.fpM3[:min(32, len(c.fpM3))])

	// Also try the emulator's FPDecryptKey (version=4) which uses the actual
	// Apple FP binary with session state from the m2 exchange. If the emulator
	// produces a different key, the session-specific state matters.
	emuDecrypted, emuOut, emuRet, emuRc, emuErr := emu.FPDecryptKey(sapCtx, ekey[:])
	if emuErr != nil {
		dbg("[FP] FPDecryptKey error: %v", emuErr)
	} else {
		dbg("[FP] FPDecryptKey ret=%d rc=%d outLen=%d", emuRet, emuRc, len(emuOut))
		if len(emuDecrypted) >= 72 {
			dbg("[FP] FPDecryptKey decrypted ekey first 16: %02x", emuDecrypted[:16])
			dbg("[FP] FPDecryptKey decrypted ekey [16:32]: %02x", emuDecrypted[16:32])
			dbg("[FP] FPDecryptKey decrypted ekey [56:72]: %02x", emuDecrypted[56:72])
			// The AES key might be at a specific offset in the decrypted ekey
			dbg("[FP] FPDecryptKey full decrypted: %02x", emuDecrypted)
		}
		if len(emuOut) > 0 {
			dbg("[FP] FPDecryptKey output buffer: %02x", emuOut)
		}
	}

	// Hash with pair-verify shared secret (ECDH X25519) if available.
	// The receiver does: SHA-512(fairplay_decrypt(ekey) || ecdh_secret)[:16]
	finalKey := c.fpAesKey
	if os.Getenv("FP_NO_HASH") != "" {
		dbg("[FP] FP_NO_HASH=1: using raw fpAesKey (no SharedSecret hash)")
	} else if c.PairKeys != nil && len(c.PairKeys.SharedSecret) > 0 {
		h := sha512.New()
		h.Write(c.fpAesKey)
		h.Write(c.PairKeys.SharedSecret)
		finalKey = h.Sum(nil)[:16]
		dbg("[FP] hashed with SharedSecret (%d bytes)", len(c.PairKeys.SharedSecret))
	}

	c.fpKey = finalKey

	dbg("[FP] FairPlay SAP handshake complete!")
	dbg("[FP] fpAesKey (raw): %02x", c.fpAesKey)
	dbg("[FP] fpKey (hashed): %02x", c.fpKey)
	dbg("[FP] stream IV:      %02x", iv[:])

	return nil
}

// buildEkey constructs a 72-byte ekey with the FPLY header format.
// The chunk data is randomized per session so that playfairDecrypt produces
// a unique AES key for each session. Both sender and receiver compute the
// same key from the same (m3, ekey) inputs.
//
// Format (72 bytes):
//
//	[0:4]   "FPLY"
//	[4:8]   01 02 01 00
//	[8:12]  00 00 00 3c  (0x3c = 60 = remaining bytes)
//	[12:16] 00 00 00 00  (padding)
//	[16:32] chunk1 (16 bytes, random)
//	[32:56] padding (24 bytes, zeros)
//	[56:72] chunk2 (16 bytes, random)
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
	// Fill chunk1 [16:32] and chunk2 [56:72] with random data
	rand.Read(ekey[16:32])
	rand.Read(ekey[56:72])
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
