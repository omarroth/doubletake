//go:build emulate

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

const airplaySenderPath = "thirdparty/apple/AirPlaySender.framework/AirPlaySender"

func (c *AirPlayClient) fairPlaySetupEmulated(ctx context.Context) error {
	binaryPath := os.Getenv("AIRPLAY_SENDER_PATH")
	if binaryPath == "" {
		binaryPath = airplaySenderPath
	}

	dbg("[FP-emu] loading AirPlaySender binary: %s", binaryPath)
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
	dbg("[FP-emu] SAP context: 0x%x", sapCtx)

	m1Raw, rc1, err := emu.FPSAPExchange(3, hwInfo, sapCtx, nil)
	if err != nil {
		return fmt.Errorf("phase1: %w", err)
	}
	dbg("[FP-emu] m1 raw: %d bytes, rc=%d, hex=%s", len(m1Raw), rc1, hex.EncodeToString(m1Raw))

	m1 := fplyWrap(m1Raw, 1)
	dbg("[FP-emu] m1 wrapped: %s", hex.EncodeToString(m1))
	m2, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m1,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m1: %w", err)
	}
	dbg("[FP-emu] m2: %d bytes, hex=%s", len(m2), hex.EncodeToString(m2))

	m3Raw, rc2, err := emu.FPSAPExchange(3, hwInfo, sapCtx, m2)
	if err != nil {
		return fmt.Errorf("phase2: %w", err)
	}
	dbg("[FP-emu] m3 raw: %d bytes, rc=%d, hex=%s", len(m3Raw), rc2, hex.EncodeToString(m3Raw))

	m3 := fplyWrap(m3Raw, 3)
	dbg("[FP-emu] m3 wrapped: %s", hex.EncodeToString(m3))
	m4, err := c.httpRequest("POST", "/fp-setup", "application/octet-stream", m3,
		map[string]string{"X-Apple-ET": "32"})
	if err != nil {
		return fmt.Errorf("fp-setup m3: %w", err)
	}
	dbg("[FP-emu] m4: %d bytes, hex=%s", len(m4), hex.EncodeToString(m4))

	m5Raw, rc3, err := emu.FPSAPExchange(3, hwInfo, sapCtx, m4)
	if err != nil {
		dbg("[FP-emu] phase3: %v (may be expected for some implementations)", err)
	} else {
		dbg("[FP-emu] m5: %d bytes, rc=%d", len(m5Raw), rc3)
	}

	m4Payload := fplyUnwrap(m4)
	if len(m4Payload) >= 16 {
		c.fpKey = make([]byte, 16)
		copy(c.fpKey, m4Payload[:16])
	}

	sapDump := emu.ReadMem(sapCtx, 512)
	dbg("[FP-emu] SAP context @0x%x dump (512 bytes):", sapCtx)
	for off := 0; off < len(sapDump); off += 32 {
		end := off + 32
		if end > len(sapDump) {
			end = len(sapDump)
		}
		dbg("[FP-emu]   +0x%03x: %s", off, hex.EncodeToString(sapDump[off:end]))
	}

	for off := 0; off < 64; off += 8 {
		ptr := binary.LittleEndian.Uint64(sapDump[off : off+8])
		if ptr >= 0x80000000 && ptr < 0x84000000 {
			ptrData := emu.ReadMem(ptr, 256)
			dbg("[FP-emu]   SAP+0x%02x → heap 0x%x:", off, ptr)
			for po := 0; po < len(ptrData); po += 32 {
				pe := po + 32
				if pe > len(ptrData) {
					pe = len(ptrData)
				}
				dbg("[FP-emu]     +0x%03x: %s", po, hex.EncodeToString(ptrData[po:pe]))
			}
		}
	}

	heapAddr, heapData := emu.HeapDump()
	dbg("[FP-emu] heap dump: base=0x%x used=%d bytes", heapAddr, len(heapData))
	for off := 0; off < len(heapData); off += 32 {
		end := off + 32
		if end > len(heapData) {
			end = len(heapData)
		}
		chunk := heapData[off:end]
		allZero := true
		for _, b := range chunk {
			if b != 0 {
				allZero = false
				break
			}
		}
		if !allZero {
			dbg("[FP-emu]   heap+0x%04x (0x%08x): %s", off, heapAddr+uint64(off), hex.EncodeToString(chunk))
		}
	}

	c.fpIV = make([]byte, 16)
	rand.Read(c.fpIV)

	c.fpM3 = make([]byte, len(m3))
	copy(c.fpM3, m3)

	ekey := buildEkey()
	aesKey := playfairDecrypt(c.fpM3, ekey[:])
	c.FpEkey = ekey[:]

	c.fpAesKey = make([]byte, 16)
	copy(c.fpAesKey, aesKey[:])

	finalKey := aesKey[:]
	if c.PairKeys != nil && len(c.PairKeys.SharedSecret) > 0 {
		h := sha512.New()
		h.Write(aesKey[:])
		h.Write(c.PairKeys.SharedSecret)
		finalKey = h.Sum(nil)[:16]
		dbg("[FP-emu]   raw aesKey:   %s", hex.EncodeToString(aesKey[:]))
		dbg("[FP-emu]   ecdh_secret:  %s", hex.EncodeToString(c.PairKeys.SharedSecret))
		dbg("[FP-emu]   hashed key:   %s", hex.EncodeToString(finalKey))
	}

	c.fpKey = finalKey

	dbg("[FP-emu] FairPlay handshake complete!")
	dbg("[FP-emu]   m4 payload:  %s", hex.EncodeToString(m4Payload))
	dbg("[FP-emu]   ekey:        %s", hex.EncodeToString(c.FpEkey))
	dbg("[FP-emu]   aesKey:      %s", hex.EncodeToString(c.fpKey))
	dbg("[FP-emu]   iv:          %s", hex.EncodeToString(c.fpIV))
	return nil
}
