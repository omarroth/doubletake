package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// FairPlay SAP (Secure Association Protocol) setup for AirPlay screen mirroring.
// Establishes the AES key used to encrypt the video stream data.
//
// The protocol uses X25519 key agreement to derive a shared secret, then
// derives AES-128-CTR keys for stream encryption.

const (
	fpSetupMessageType1 = 1 // Client hello
	fpSetupMessageType2 = 2 // Key exchange
	fpSetupMessageType3 = 3 // Verification
)

// fpMessage is the header for FairPlay setup messages.
type fpMessage struct {
	Signature [4]byte // "FPLY"
	Major     byte    // Protocol major version
	Minor     byte    // Protocol minor version
	Phase     byte    // Message phase (1, 2, or 3)
}

func (c *AirPlayClient) fairPlaySetup(ctx context.Context) error {
	// Generate stream encryption key upfront (used regardless of FP outcome).
	// With HKP, we can derive stream keys from the pair-verify shared secret.
	if c.streamKey == nil {
		if err := c.deriveStreamKeys(); err != nil {
			return fmt.Errorf("derive stream keys: %w", err)
		}
	}

	// Phase 1: Client hello - initiate the FairPlay handshake.
	// Send our capabilities and receive server nonce.
	phase1Req := buildFPMessage(fpSetupMessageType1, nil)
	phase1Resp, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", phase1Req)
	if err != nil {
		return fmt.Errorf("fp-setup phase 1: %w", err)
	}

	if len(phase1Resp) < 7 {
		return fmt.Errorf("fp-setup phase 1: response too short (%d bytes)", len(phase1Resp))
	}

	// Extract server nonce from phase 1 response
	serverNonce := phase1Resp[7:]

	// Phase 2: Key exchange using X25519.
	// Generate ephemeral key pair for ECDH.
	var fpPrivate [32]byte
	if _, err := rand.Read(fpPrivate[:]); err != nil {
		return fmt.Errorf("generate fp key: %w", err)
	}

	fpPublic, err := curve25519.X25519(fpPrivate[:], curve25519.Basepoint)
	if err != nil {
		return fmt.Errorf("fp x25519 base: %w", err)
	}

	// Build phase 2 payload: our X25519 public key + nonce response
	phase2Payload := make([]byte, 0, 32+len(serverNonce))
	phase2Payload = append(phase2Payload, fpPublic...)
	phase2Payload = append(phase2Payload, serverNonce...)

	phase2Req := buildFPMessage(fpSetupMessageType2, phase2Payload)
	phase2Resp, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", phase2Req)
	if err != nil {
		return fmt.Errorf("fp-setup phase 2: %w", err)
	}

	if len(phase2Resp) < 39 { // 7 header + 32 server pubkey
		return fmt.Errorf("fp-setup phase 2: response too short (%d bytes)", len(phase2Resp))
	}

	// Extract server's X25519 public key
	serverPubKey := phase2Resp[7:39]

	// Compute shared secret
	sharedSecret, err := curve25519.X25519(fpPrivate[:], serverPubKey)
	if err != nil {
		return fmt.Errorf("fp x25519 shared: %w", err)
	}

	// Derive AES keys from shared secret using SHA-512
	keyMaterial := sha512.Sum512(sharedSecret)
	c.fpKey = keyMaterial[:16]  // AES-128 encryption key
	c.fpIV = keyMaterial[16:32] // AES-CTR IV

	// Phase 3: Verification - prove we derived the correct key.
	// Encrypt a verification token using the derived key.
	verifyToken := make([]byte, 16)
	if _, err := rand.Read(verifyToken); err != nil {
		return fmt.Errorf("generate verify token: %w", err)
	}

	block, err := aes.NewCipher(c.fpKey)
	if err != nil {
		return fmt.Errorf("aes cipher: %w", err)
	}
	stream := cipher.NewCTR(block, c.fpIV)
	encryptedToken := make([]byte, len(verifyToken))
	stream.XORKeyStream(encryptedToken, verifyToken)

	// Include any additional data from phase 2 response for verification
	var extraData []byte
	if len(phase2Resp) > 39 {
		extraData = phase2Resp[39:]
	}

	phase3Payload := make([]byte, 0, len(encryptedToken)+len(extraData))
	phase3Payload = append(phase3Payload, encryptedToken...)
	phase3Payload = append(phase3Payload, extraData...)

	phase3Req := buildFPMessage(fpSetupMessageType3, phase3Payload)
	_, err = c.httpRequest("POST", "/fp-setup", "application/octet-stream", phase3Req)
	if err != nil {
		return fmt.Errorf("fp-setup phase 3: %w", err)
	}

	return nil
}

// deriveStreamKeys derives AES stream encryption keys from the pair-verify shared secret.
// This is used when FairPlay setup is skipped (HomeKit Pairing provides sufficient auth).
func (c *AirPlayClient) deriveStreamKeys() error {
	if c.encWriteKey == nil {
		// Generate random stream key if no pair-verify keys available
		key, iv, err := generateStreamKey()
		if err != nil {
			return err
		}
		c.streamKey = key
		c.streamIV = iv
		return nil
	}

	// Derive from pair-verify encryption key using HKDF
	derived := hkdfSHA512(c.encWriteKey, []byte("AirPlayStream-Salt"), []byte("AirPlayStream-Key"), 32)
	c.streamKey = derived[:16]
	c.streamIV = derived[16:32]
	return nil
}

func buildFPMessage(phase byte, payload []byte) []byte {
	msg := make([]byte, 7+len(payload))
	copy(msg[0:4], []byte("FPLY"))
	msg[4] = 0x03 // Major version 3
	msg[5] = 0x01 // Minor version 1
	msg[6] = phase
	copy(msg[7:], payload)
	return msg
}
