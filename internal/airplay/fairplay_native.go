// Pure Go FairPlay SAP handshake using the built-in ARM64 interpreter.
//
// This uses the fpemu package with a pure Go ARM64 interpreter to execute
// the FairPlay SAP exchange from an iOS AirPlaySender binary. No CGo or
// external emulator required.

package airplay

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"

	"airplay/internal/fpemu"
)

const defaultSenderPath = "thirdparty/apple/AirPlaySender.framework/AirPlaySender"

func (c *AirPlayClient) FairPlaySetupNative(ctx context.Context) error {
	dbg("[FP-native] starting pure-Go FairPlay SAP handshake")

	binaryPath := os.Getenv("AIRPLAY_SENDER_PATH")
	if binaryPath == "" {
		binaryPath = defaultSenderPath
	}

	emu, err := fpemu.New(binaryPath)
	if err != nil {
		return fmt.Errorf("init fpemu: %w", err)
	}
	defer emu.Close()

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)
	rand.Read(hwInfo[4:])
	sapCtx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		return fmt.Errorf("FPSAPInit: %w", err)
	}
	dbg("[FP-native] SAP context: 0x%x", sapCtx)

	// Phase 1: compute and send m1.
	m1Raw, rc1, err := emu.FPSAPExchange(3, hwInfo, sapCtx, nil)
	if err != nil {
		return fmt.Errorf("phase1: %w", err)
	}
	dbg("[FP-native] m1 raw: %d bytes, rc=%d", len(m1Raw), rc1)

	m1 := fplyWrap(m1Raw, 1)
	dbg("[FP-native] m1: %d bytes", len(m1))
	m2, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m1: %w", err)
	}
	dbg("[FP-native] m2: %d bytes, hex=%s", len(m2), hex.EncodeToString(m2))

	// Phase 2: compute m3 from real m2 and send.
	m3Raw, rc2, err := emu.FPSAPExchange(3, hwInfo, sapCtx, m2)
	if err != nil {
		return fmt.Errorf("phase2: %w", err)
	}
	dbg("[FP-native] m3 raw: %d bytes, rc=%d", len(m3Raw), rc2)

	m3 := fplyWrap(m3Raw, 3)
	dbg("[FP-native] m3: %d bytes", len(m3))
	m4, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m3: %w", err)
	}
	dbg("[FP-native] m4: %d bytes", len(m4))

	// Extract key material from m4.
	m4Payload := fplyUnwrap(m4)
	if len(m4Payload) >= 16 {
		c.fpKey = make([]byte, 16)
		copy(c.fpKey, m4Payload[:16])
	}

	c.fpIV = make([]byte, 16)
	rand.Read(c.fpIV)

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
		dbg("[FP-native]   raw aesKey:   %s", hex.EncodeToString(aesKey[:]))
		dbg("[FP-native]   ecdh_secret:  %s", hex.EncodeToString(c.PairKeys.SharedSecret))
		dbg("[FP-native]   hashed key:   %s", hex.EncodeToString(finalKey))
	}

	c.fpKey = finalKey

	dbg("[FP-native] FairPlay handshake complete!")
	dbg("[FP-native]   ekey:   %s", hex.EncodeToString(c.FpEkey))
	dbg("[FP-native]   aesKey: %s", hex.EncodeToString(c.fpKey))
	dbg("[FP-native]   iv:     %s", hex.EncodeToString(c.fpIV))
	return nil
}
