package airplay

import (
	"context"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"errors"
	"fmt"
)

var ErrFairPlayUnsupported = errors.New("receiver does not support FairPlay SAP")

// The in-tree FPSAP implementation implements the encryption type used by
// Apple's current screen-mirroring path. Do not guess another selector after a
// receiver rejection: different selectors require different SAP/key handling.
const fairPlayEncryptionType = "32"

func mustDecodeHexFP(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// FairPlaySetup performs the complete FairPlay SAP handshake.
func (c *AirPlayClient) FairPlaySetup(ctx context.Context) error {
	if c.info != nil && !c.info.SupportsFairPlaySAP() {
		return fmt.Errorf("%w: FPSAP feature bit is not advertised (features=0x%x)", ErrFairPlayUnsupported, c.info.Features)
	}

	dbg("[FP] starting FairPlay SAP handshake...")

	// Keep one opaque FPSAP context for m1, m3, and encrypted-key creation for
	// the lifetime of this authentication attempt.
	fpsap, err := newFPSAPSession(rand.Reader)
	if err != nil {
		return fmt.Errorf("initialize FPSAP session: %w", err)
	}

	// Phase 1: Send m1, receive m2
	m1 := fpsap.message1()

	dbg("[FP] posting m1 (%d bytes) to /fp-setup", len(m1))
	m2, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": fairPlayEncryptionType})
	if err != nil {
		var statusErr *HTTPStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == 404 {
			return fmt.Errorf("%w: /fp-setup returned 404", ErrFairPlayUnsupported)
		}
		return fmt.Errorf("fp-setup phase 1 (m1): %w", err)
	}

	dbg("[FP] received m2 (%d bytes)", len(m2))
	dbg("[FP] m2 first 32: %02x", m2[:min(32, len(m2))])

	// Phase 2: Compute m3 and send it to the receiver.
	m3, err := fpsap.exchangeM3(m2)
	if err != nil {
		return fmt.Errorf("FPSAPExchange: %w", err)
	}

	dbg("[FP] m3 (%d bytes) first 32: %02x", len(m3), m3[:min(32, len(m3))])

	dbg("[FP] posting m3 (%d bytes) to /fp-setup", len(m3))
	m4, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": fairPlayEncryptionType})
	if err != nil {
		var statusErr *HTTPStatusError
		if errors.As(err, &statusErr) && statusErr.StatusCode == 404 {
			return fmt.Errorf("%w: /fp-setup returned 404 during phase 2", ErrFairPlayUnsupported)
		}
		return fmt.Errorf("fp-setup phase 2 (m3): %w", err)
	}

	if err := fpsap.confirmM4(m4); err != nil {
		return fmt.Errorf("FPSAP m4: %w", err)
	}
	dbg("[FP] received m4 (%d bytes)", len(m4))
	dbg("[FP] m4 payload (%d bytes): %02x", len(m4)-12, m4[12:])

	// Generate and store IV for stream encryption
	var iv [16]byte
	if _, err := rand.Read(iv[:]); err != nil {
		return fmt.Errorf("generate stream IV: %w", err)
	}
	c.fpIV = iv[:]

	// Save m3 for ekey derivation.
	c.fpM3 = make([]byte, len(m3))
	copy(c.fpM3, m3)

	// Generate the raw audio key and wrap it in the FairPlay ekey record. The
	// receiver performs the inverse operation using the state established by m3.
	var fpAesKey [16]byte
	if _, err := rand.Read(fpAesKey[:]); err != nil {
		return fmt.Errorf("generate FairPlay audio key: %w", err)
	}
	ekey, err := fpsap.wrapKey(fpAesKey, rand.Reader)
	if err != nil {
		return fmt.Errorf("wrap FairPlay audio key: %w", err)
	}
	c.FpEkey = ekey[:]
	dbg("[FP] ekey chunk1 [16:32]: %02x", ekey[16:32])
	dbg("[FP] ekey key length [32:36]: %d", 16)
	dbg("[FP] ekey chunk2 [56:72]: %02x", ekey[56:72])

	c.fpAesKey = fpAesKey[:]
	dbg("[FP] wrapped fpAesKey: %02x", fpAesKey[:])
	dbg("[FP] m3 first 32 bytes: %02x", c.fpM3[:min(32, len(c.fpM3))])

	mixPairVerifyKey := c.PairKeys != nil && c.PairKeys.MixFairPlayKey
	finalKey := deriveStreamMasterKey(c.fpAesKey, sharedSecret(c.PairKeys), mixPairVerifyKey)
	if mixPairVerifyKey && len(sharedSecret(c.PairKeys)) > 0 {
		dbg("[FP] mixed with pair-verify SharedSecret (%d bytes)", len(sharedSecret(c.PairKeys)))
	} else {
		dbg("[FP] using raw fpAesKey (legacy receiver or no SharedSecret)")
	}

	c.fpKey = finalKey

	dbg("[FP] FairPlay SAP handshake complete!")
	dbg("[FP] fpAesKey (raw): %02x", c.fpAesKey)
	dbg("[FP] fpKey (hashed): %02x", c.fpKey)
	dbg("[FP] stream IV:      %02x", iv[:])

	return nil
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

// sharedSecret returns the pair-verify X25519 secret, or nil.
func sharedSecret(keys *PairKeys) []byte {
	if keys == nil {
		return nil
	}
	return keys.SharedSecret
}

// deriveStreamMasterKey returns the key the receiver will decrypt the stream
// with, given the raw FairPlay key that ekey wraps.
//
// A HAP-paired receiver mixes the pair-verify secret in:
//
//	SHA-512(fairplay_decrypt(ekey) || ecdh_secret)[:16]
//
// The PairKeys flag records the pair-verify mode which actually completed. HAP
// always selects the mixture; raw pair-verify selects it by sending
// X-Apple-PD. That keeps FairPlay derivation tied to negotiated protocol state
// instead of a receiver name or model.
func deriveStreamMasterKey(rawKey, secret []byte, mixPairVerifySecret bool) []byte {
	if !mixPairVerifySecret || len(secret) == 0 {
		return rawKey
	}
	h := sha512.New()
	h.Write(rawKey)
	h.Write(secret)
	return h.Sum(nil)[:16]
}
