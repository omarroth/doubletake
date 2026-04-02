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
	"unsafe"

	"airplay/fpemu"
)

/*
#cgo LDFLAGS: -lm
#include "playfair.h"
*/
import "C"

const airplaySenderPath = "thirdparty/apple/AirPlaySender.framework/AirPlaySender"

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

	// Phase 3: process m4 to finalize the SAP shared secret.
	// The receiver's m4 contains the final DH confirmation. Without processing
	// it, the SAP context may not have the correct shared secret for key derivation.
	m5Raw, rc3, err := emu.FPSAPExchange(3, hwInfo, sapCtx, m4)
	if err != nil {
		log.Printf("[FP] phase3: %v (may be expected for some implementations)", err)
	} else {
		log.Printf("[FP] m5: %d bytes, rc=%d", len(m5Raw), rc3)
	}

	m4Payload := fplyUnwrap(m4)
	if len(m4Payload) >= 16 {
		c.fpKey = make([]byte, 16)
		copy(c.fpKey, m4Payload[:16])
	}

	// Dump SAP context memory to find shared key material.
	// After the 3-phase handshake, the SAP context contains a shared secret
	// that both sides use for HKDF-based key derivation (ChaCha20-Poly1305).
	sapDump := emu.ReadMem(sapCtx, 512)
	log.Printf("[FP] SAP context @0x%x dump (512 bytes):", sapCtx)
	for off := 0; off < len(sapDump); off += 32 {
		end := off + 32
		if end > len(sapDump) {
			end = len(sapDump)
		}
		log.Printf("[FP]   +0x%03x: %s", off, hex.EncodeToString(sapDump[off:end]))
	}

	// Also dump any pointers in the first 64 bytes that point to heap
	for off := 0; off < 64; off += 8 {
		ptr := binary.LittleEndian.Uint64(sapDump[off : off+8])
		if ptr >= 0x80000000 && ptr < 0x84000000 { // heap range
			ptrData := emu.ReadMem(ptr, 256)
			log.Printf("[FP]   SAP+0x%02x → heap 0x%x:", off, ptr)
			for po := 0; po < len(ptrData); po += 32 {
				pe := po + 32
				if pe > len(ptrData) {
					pe = len(ptrData)
				}
				log.Printf("[FP]     +0x%03x: %s", po, hex.EncodeToString(ptrData[po:pe]))
			}
		}
	}

	// Dump heap to find FP SAP shared secret material.
	// The SAP context itself may be at an auto-mapped address, but the actual
	// key material is on the heap. Scan for non-zero 32-byte aligned blocks.
	heapAddr, heapData := emu.HeapDump()
	log.Printf("[FP] heap dump: base=0x%x used=%d bytes", heapAddr, len(heapData))
	for off := 0; off < len(heapData); off += 32 {
		end := off + 32
		if end > len(heapData) {
			end = len(heapData)
		}
		chunk := heapData[off:end]
		// Only log non-zero chunks
		allZero := true
		for _, b := range chunk {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			log.Printf("[FP]   heap+0x%04x (0x%08x): %s", off, heapAddr+uint64(off), hex.EncodeToString(chunk))
		}
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
	aesKey := playfairDecrypt(c.fpM3, ekey[:])
	c.fpEkey = ekey[:]

	// Save the raw 16-byte aesKey before any hashing. AppleTV uses this
	// as the IKM for HKDF-SHA512 to derive ChaCha20-Poly1305 keys.
	c.fpAesKey = make([]byte, 16)
	copy(c.fpAesKey, aesKey[:])

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

// playfairDecrypt calls the playfair_decrypt C function.
// m3 is the full 164-byte FairPlay message 3 (including FPLY header).
// ekey is the 72-byte encrypted key from the SETUP plist.
// Returns the 16-byte decrypted AES key.
func playfairDecrypt(m3 []byte, ekey []byte) [16]byte {
	var key [16]byte
	C.playfair_decrypt(
		(*C.uchar)(unsafe.Pointer(&m3[0])),
		(*C.uchar)(unsafe.Pointer(&ekey[0])),
		(*C.uchar)(unsafe.Pointer(&key[0])),
	)
	return key
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
