package airplay

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"doubletake/internal/fpemu"
)

// FairPlaySetupSnapshot performs the FairPlay SAP handshake using the embedded
// memory snapshot. This is the default path — it requires no external binary.
func (c *AirPlayClient) FairPlaySetupSnapshot(ctx context.Context) error {
	dbg("[FP-snap] starting snapshot-based FairPlay SAP handshake")

	sapCtx, err := fpemu.SnapshotCtx()
	if err != nil {
		return fmt.Errorf("snapshot ctx: %w", err)
	}
	dbg("[FP-snap] SAP context: 0x%x", sapCtx)

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	// Phase 1: send hardcoded m1.
	// The snapshot is taken after FPSAPInit + m1 generation, so m1 is always
	// the same. The server doesn't validate randomness in m1.
	m1, _ := hex.DecodeString("46504c590301010000000004020003bb")
	dbg("[FP-snap] m1: %d bytes", len(m1))

	m2, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m1: %w", err)
	}
	dbg("[FP-snap] m2: %d bytes, hex=%s", len(m2), hex.EncodeToString(m2))

	// Phase 2: compute dynamic signature from m2 and build m3 in pure Go.
	sig, err := fpemu.SignatureFromM2(hwInfo, m2)
	if err != nil {
		return fmt.Errorf("phase2: %w", err)
	}
	m3 := fpemu.BuildM3FromSignature(sig)
	dbg("[FP-snap] m3: %d bytes", len(m3))
	m4, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m3: %w", err)
	}
	dbg("[FP-snap] m4: %d bytes", len(m4))

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
		dbg("[FP-snap]   raw aesKey:   %s", hex.EncodeToString(aesKey[:]))
		dbg("[FP-snap]   ecdh_secret:  %s", hex.EncodeToString(c.PairKeys.SharedSecret))
		dbg("[FP-snap]   hashed key:   %s", hex.EncodeToString(finalKey))
	}

	c.fpKey = finalKey

	dbg("[FP-snap] FairPlay handshake complete!")
	dbg("[FP-snap]   ekey:   %s", hex.EncodeToString(c.FpEkey))
	dbg("[FP-snap]   aesKey: %s", hex.EncodeToString(c.fpKey))
	dbg("[FP-snap]   iv:     %s", hex.EncodeToString(c.fpIV))
	return nil
}
