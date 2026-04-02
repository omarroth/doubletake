package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/t0rr3sp3dr0/sapsigner/impl/emu/mescal/definitions"
	"github.com/t0rr3sp3dr0/sapsigner/impl/emu/mescal/emulator"
	"github.com/t0rr3sp3dr0/sapsigner/impl/emu/mescal/guid"
	"github.com/t0rr3sp3dr0/sapsigner/impl/emu/mescal/library"
)

// FairPlaySAPExchanger wraps the official FairPlay SAP implementation via sapsigner's emulator.
// This allows us to perform authentic FairPlay handshakes for AirPlay without hardware keys.
type FairPlaySAPExchanger struct {
	emu    *emulator.Emulator
	hwInfo *definitions.FairPlayHwInfo
	ctxRef *definitions.FPSAPContextOpaqueRef
}

// NewFairPlaySAPExchanger initializes the FairPlay SAP emulator with device HWID.
func NewFairPlaySAPExchanger(ctx context.Context) (*FairPlaySAPExchanger, error) {
	// Try loading from local extracted pkg first, fall back to network fetch
	localDir := os.Getenv("FAIRPLAY_PKG_DIR")
	if localDir == "" {
		localDir = "thirdparty/apple/OSXUpd10.9.1.pkg"
	}

	artifacts, err := library.FetchLocal(localDir)
	if err != nil {
		log.Printf("[FP] local artifacts not found (%v), fetching from network...", err)
		artifacts, err = library.Fetch(ctx)
		if err != nil {
			return nil, fmt.Errorf("fetch artifacts: %w", err)
		}
	} else {
		log.Printf("[FP] loaded artifacts from local directory: %s", localDir)
	}

	// Create library objects for each required framework
	corefpicxsO, err := library.NewCoreFPICXSObject(artifacts["CoreFP.icxs"])
	if err != nil {
		return nil, fmt.Errorf("new CoreFP.icxs: %w", err)
	}

	corefpO, err := library.NewCoreFPObject(artifacts["CoreFP"])
	if err != nil {
		return nil, fmt.Errorf("new CoreFP: %w", err)
	}

	commercecoreO, err := library.NewCommerceCoreObject(artifacts["CommerceCore"])
	if err != nil {
		return nil, fmt.Errorf("new CommerceCore: %w", err)
	}

	commercekitO, err := library.NewCommerceKitObject(artifacts["CommerceKit"])
	if err != nil {
		return nil, fmt.Errorf("new CommerceKit: %w", err)
	}

	storeagentO, err := library.NewStoreAgentObject(artifacts["storeagent"])
	if err != nil {
		return nil, fmt.Errorf("new storeagent: %w", err)
	}

	// Create the CPU emulator instance
	emu, err := emulator.NewEmulator(corefpicxsO, corefpO, commercecoreO, commercekitO, storeagentO)
	if err != nil {
		return nil, fmt.Errorf("create emulator: %w", err)
	}

	// Get or generate device HWID (UDID)
	id, err := guid.Get()
	if err != nil {
		log.Printf("[FP] warning: could not get system GUID, using random ID: %v", err)
		id = make([]byte, 20)
		if _, err := rand.Read(id); err != nil {
			return nil, fmt.Errorf("generate random ID: %w", err)
		}
	}

	// Set up hardware info for FairPlay context
	var hwInfo definitions.FairPlayHwInfo
	hwInfo.SetId(id)
	log.Printf("[FP] device ID (UDID): %x", hwInfo.GetId())

	// Initialize FairPlay SAP context (cp2g1b9ro = FairPlaySAPInit)
	ctxRef, err := emu.FairPlaySAPInit(&hwInfo)
	if err != nil {
		return nil, fmt.Errorf("FairPlaySAPInit: %w", err)
	}
	log.Printf("[FP] SAP context initialized")

	return &FairPlaySAPExchanger{
		emu:    emu,
		hwInfo: &hwInfo,
		ctxRef: ctxRef,
	}, nil
}

// GeneratePhase1Message creates the initial FairPlay SAP handshake message (m1).
// This message is sent as a POST to /fp-setup on the AirPlay receiver.
// airplayExchangeVersion is the FairPlay SAP exchange version used by AirPlay.
// AirPlay uses version 3, not 200 (Regular) or 210 (Prime) used by iTunes Store.
// This is confirmed by decompiled AirPlaySender.c: _Mib5yocT(3, ...)
var airplayExchangeVersion = func() *definitions.FairPlaySAPExchangeVersion {
	v := &definitions.FairPlaySAPExchangeVersion{}
	v.SetVal(3)
	return v
}()

func (f *FairPlaySAPExchanger) GeneratePhase1Message() ([]byte, error) {
	xVer := airplayExchangeVersion

	log.Printf("[FP] generating phase 1 message (m1) with version=%d...", xVer.GetVal())

	// First FairPlaySAPExchange call with empty input generates m1
	// returnCode=1 means "send this to server and give me their response"
	m1, returnCode, err := f.emu.FairPlaySAPExchange(xVer, f.hwInfo, f.ctxRef, nil)
	if err != nil {
		return nil, fmt.Errorf("FairPlaySAPExchange phase1: %w", err)
	}

	if returnCode != 1 {
		return nil, fmt.Errorf("unexpected return code from FairPlaySAPExchange: %d (expected 1)", returnCode)
	}

	log.Printf("[FP] phase 1 generated: %d bytes, returnCode=%d", len(m1), returnCode)
	return m1, nil
}

// ProcessPhase2Message processes the receiver's response (m2) and generates our response (m3).
// Returns the m3 message to send back to the receiver.
func (f *FairPlaySAPExchanger) ProcessPhase2Message(m2 []byte) ([]byte, error) {
	xVer := airplayExchangeVersion

	log.Printf("[FP] processing phase 2 message (m2)... %d bytes", len(m2))

	// Second FairPlaySAPExchange call with m2 generates m3
	// returnCode=0 means "handshake complete"
	m3, returnCode, err := f.emu.FairPlaySAPExchange(xVer, f.hwInfo, f.ctxRef, m2)
	if err != nil {
		return nil, fmt.Errorf("FairPlaySAPExchange phase2: %w", err)
	}

	if returnCode != 0 {
		return nil, fmt.Errorf("unexpected return code from FairPlaySAPExchange: %d (expected 0)", returnCode)
	}

	log.Printf("[FP] phase 2 processed: m3 generated %d bytes, returnCode=%d", len(m3), returnCode)
	return m3, nil
}

// SignStreamKey signs a stream key (used to protect video frame data).
// This may be called to generate additional authenticated key material.
func (f *FairPlaySAPExchanger) SignStreamKey(streamKey []byte) ([]byte, error) {
	log.Printf("[FP] signing stream key (%d bytes)...", len(streamKey))

	signed, err := f.emu.FairPlaySAPSign(f.ctxRef, streamKey)
	if err != nil {
		return nil, fmt.Errorf("FairPlaySAPSign: %w", err)
	}

	log.Printf("[FP] stream key signed: %d bytes", len(signed))
	return signed, nil
}

// Close cleans up the emulator and SAP context.
func (f *FairPlaySAPExchanger) Close() error {
	if f.ctxRef != nil {
		if err := f.emu.FairPlaySAPTeardown(f.ctxRef); err != nil {
			log.Printf("[FP] warning: FairPlaySAPTeardown failed: %v", err)
		}
	}
	if f.emu != nil {
		if err := f.emu.Close(); err != nil {
			log.Printf("[FP] warning: emulator close failed: %v", err)
		}
	}
	return nil
}

// AirPlayFairPlayHandshake performs the complete AirPlay FairPlay SAP handshake with a receiver.
// It handles the /fp-setup protocol: POST m1 -> GET m2 -> POST m3 -> GET m4
//
// Wire format (FPLY framing):
//
//	Bytes 0-3: "FPLY" magic (0x46504c59)
//	Byte 4: Major version (0x03)
//	Byte 5: Minor version (0x01)
//	Byte 6: Message type (1=m1, 2=m2, 3=m3, 4=m4)
//	Byte 7: Reserved (0x00)
//	Bytes 8-11: Payload length (big-endian)
//	Bytes 12+: Payload
func (c *AirPlayClient) AirPlayFairPlayHandshake(ctx context.Context) error {
	log.Printf("[FP] starting AirPlay FairPlay SAP handshake...")

	sap, err := NewFairPlaySAPExchanger(ctx)
	if err != nil {
		return fmt.Errorf("init SAP exchanger: %w", err)
	}
	defer sap.Close()

	// Phase 1: Generate m1 raw data from SAP exchange
	m1Raw, err := sap.GeneratePhase1Message()
	if err != nil {
		return err
	}

	// Wrap in FPLY framing if the exchange didn't already include it
	m1 := fplyWrap(m1Raw, 1)
	log.Printf("[FP] posting m1 (%d bytes, raw=%d) to /fp-setup — first 20: %x",
		len(m1), len(m1Raw), m1[:min(20, len(m1))])

	m2, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup phase 1: %w", err)
	}

	if len(m2) < 4 {
		return fmt.Errorf("m2 response too short: %d bytes", len(m2))
	}

	log.Printf("[FP] received m2 (%d bytes) — first 20: %x", len(m2), m2[:min(20, len(m2))])

	// Strip FPLY framing from m2 before passing to SAP exchange
	m2Payload := fplyUnwrap(m2)

	// Phase 2: Process m2 and generate m3
	m3Raw, err := sap.ProcessPhase2Message(m2Payload)
	if err != nil {
		return err
	}

	// Wrap in FPLY framing
	m3 := fplyWrap(m3Raw, 3)
	log.Printf("[FP] posting m3 (%d bytes, raw=%d) to /fp-setup — first 20: %x",
		len(m3), len(m3Raw), m3[:min(20, len(m3))])

	m4, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup phase 2: %w", err)
	}

	if len(m4) < 4 {
		return fmt.Errorf("m4 response too short: %d bytes", len(m4))
	}

	log.Printf("[FP] received m4 (%d bytes) — first 20: %x", len(m4), m4[:min(20, len(m4))])

	// Strip FPLY framing from m4
	m4Payload := fplyUnwrap(m4)

	log.Printf("[FP] FairPlay SAP handshake complete!")
	log.Printf("[FP] m4 payload: %d bytes — %x", len(m4Payload), m4Payload)

	// Extract session key from m4 payload
	// The m4 payload contains the encrypted key material
	if len(m4Payload) >= 20 {
		// First 20 bytes of m4 payload are typically the signed response
		c.fpKey = make([]byte, 16)
		copy(c.fpKey, m4Payload[:16])
	} else if len(m4Payload) > 0 {
		c.fpKey = make([]byte, len(m4Payload))
		copy(c.fpKey, m4Payload)
	}

	// Generate IV for stream encryption
	c.fpIV = make([]byte, 16)
	if _, err := rand.Read(c.fpIV); err != nil {
		return fmt.Errorf("generate IV: %w", err)
	}

	log.Printf("[FP] session key (%d bytes): %x", len(c.fpKey), c.fpKey)
	log.Printf("[FP] stream IV: %x", c.fpIV)

	return nil
}

// fplyWrap adds FPLY framing header to raw SAP data.
// If the data already starts with "FPLY", it's returned as-is.
func fplyWrap(data []byte, msgType byte) []byte {
	if len(data) >= 4 && string(data[:4]) == "FPLY" {
		// Already FPLY-wrapped
		return data
	}
	header := make([]byte, 12+len(data))
	copy(header[0:4], []byte("FPLY"))
	header[4] = 0x03 // Major version
	header[5] = 0x01 // Minor version
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

// NOTE: This wrapper intentionally does NOT include the Wine/AirParrotNative harness approach.
// Instead, it leverages sapsigner's emulation of the official Apple FairPlay implementation,
// which is more authentic and doesn't require Windows/Wine/DLLs.
//
// Key differences from Wine approach:
// 1. No process spawning or stdin/stdout communication
// 2. Direct CPU emulation of Apple's official binaries
// 3. Support for any Linux/macOS system (no Windows toolchain required)
// 4. More reliable since it's using the exact Apple code
//
// The handshake messages (m1/m2/m3/m4) have the following protocol:
//   m1 (16 bytes + header): Client hello, type=1
//   m2 (142 bytes): Server response, type=2
//   m3 (164 bytes): Client key exchange, type=3
//   m4 (32+ bytes): Server echo, type=4
//
// The FairPlay SAP protocol (Secure Association Protocol) uses a 2-round handshake to:
// - Authenticate both endpoints
// - Establish a shared session key for stream encryption
// - Verify device identity using the UDID
