package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"airplay/fpemu"
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
	hwInfo := make([]byte, 24)
	rand.Read(hwInfo)
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
	m2Payload := fplyUnwrap(m2)
	m3Raw, rc2, err := emu.FPSAPExchange(3, hwInfo, sapCtx, m2Payload)
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

	log.Printf("[FP] FairPlay handshake complete! key=%x iv=%x", c.fpKey, c.fpIV)
	return nil
}
