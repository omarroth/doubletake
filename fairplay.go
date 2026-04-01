package main

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"

	"airplay/fpemu"
	"airplay/playfair"
)

const airplaySenderPath = "original-ios/15A372__iPhone10,5/root/System/Library/PrivateFrameworks/AirPlaySender.framework/AirPlaySender"

func (c *AirPlayClient) fairPlaySetup(ctx context.Context) error {
	binaryPath := os.Getenv("AIRPLAY_SENDER_PATH")
	if binaryPath == "" {
		binaryPath = airplaySenderPath
	}

	log.Printf("[FP] loading AirPlaySender binary: %s", binaryPath)
	emu, err := fpemu.New(binaryPath)
	if err != nil {
		return fmt.Errorf("init fpemu: %w", err)
	}
	defer emu.Close()

	// Initialize FairPlay SAP context
	// hwInfo: 4-byte IDLength (=20) + 20-byte device ID
	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)
	rand.Read(hwInfo[4:])
	sapCtx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		return fmt.Errorf("FPSAPInit: %w", err)
	}
	log.Printf("[FP] SAP context: 0x%x", sapCtx)

	// Phase 1: generate m1 (empty input)
	m1Raw, rc1, err := emu.FPSAPExchange(3, hwInfo, sapCtx, nil)
	if err != nil {
		return fmt.Errorf("phase1: %w", err)
	}
	log.Printf("[FP] m1: %d bytes, rc=%d", len(m1Raw), rc1)

	m1 := fplyWrap(m1Raw, 1)
	m2, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m1: %w", err)
	}
	log.Printf("[FP] m2: %d bytes", len(m2))

	// Phase 2: process m2, generate m3
	// The iOS binary handles FPLY framing internally, pass the full FPLY-wrapped m2
	m3Raw, rc2, err := emu.FPSAPExchange(3, hwInfo, sapCtx, m2)
	if err != nil {
		return fmt.Errorf("phase2: %w", err)
	}
	log.Printf("[FP] m3: %d bytes, rc=%d", len(m3Raw), rc2)

	m3 := fplyWrap(m3Raw, 3)
	m4, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m3: %w", err)
	}
	log.Printf("[FP] m4: %d bytes", len(m4))

	m4Payload := fplyUnwrap(m4)
	if len(m4Payload) >= 16 {
		c.fpKey = make([]byte, 16)
		copy(c.fpKey, m4Payload[:16])
	}

	c.fpIV = make([]byte, 16)
	rand.Read(c.fpIV)

	// Save FPLY-wrapped m3 for ekey construction.
	// The receiver also stores this m3 during fp-setup and uses it with
	// fairplay_decrypt(m3, ekey) to recover the AES key.
	c.fpM3 = make([]byte, len(m3))
	copy(c.fpM3, m3)

	// Construct ekey: 72-byte FPLY-wrapped encrypted key.
	// Instead of trying to encrypt fpKey into ekey (which requires playfair_encrypt),
	// we construct ekey with known chunk data and compute what the receiver will
	// derive via playfair_decrypt(m3, ekey). Then we use that derived key as our
	// video encryption key. Both sides compute the same key.
	ekey := buildEkey()
	aesKey := playfair.Decrypt(c.fpM3, ekey[:])
	c.fpEkey = ekey[:]

	// If pair-verify produced a shared secret (ecdh_secret), the receiver
	// hashes the fairplay-decrypted key with it: SHA-512(aeskey + ecdh_secret)[:16].
	// UxPlay does this in raop_handlers.h; we must match.
	finalKey := aesKey[:]
	if c.pairKeys != nil && len(c.pairKeys.SharedSecret) > 0 {
		h := sha512.New()
		h.Write(aesKey[:])
		h.Write(c.pairKeys.SharedSecret)
		finalKey = h.Sum(nil)[:16]
		log.Printf("[FP]   raw aesKey:   %s", hex.EncodeToString(aesKey[:]))
		log.Printf("[FP]   ecdh_secret:  %s", hex.EncodeToString(c.pairKeys.SharedSecret))
		log.Printf("[FP]   hashed key:   %s", hex.EncodeToString(finalKey))
	}

	// Override fpKey with the key the receiver will actually derive.
	// This ensures sender and receiver SHA-512-derive the same AES-CTR key.
	c.fpKey = finalKey

	log.Printf("[FP] FairPlay handshake complete!")
	log.Printf("[FP]   m4 payload:  %s", hex.EncodeToString(m4Payload))
	log.Printf("[FP]   ekey:        %s", hex.EncodeToString(c.fpEkey))
	log.Printf("[FP]   aesKey:      %s", hex.EncodeToString(c.fpKey))
	log.Printf("[FP]   iv:          %s", hex.EncodeToString(c.fpIV))
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
