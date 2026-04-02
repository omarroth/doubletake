//go:build emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"log"
	"os"
	"testing"
)

func TestFPSAPInit(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	os.Setenv("FPEMU_TRACE", "1")
	emu, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	emu.SetTracing(false) // disable for phase 1
	defer emu.Close()

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		t.Fatalf("FPSAPInit: %v", err)
	}
	log.Printf("SAP context: 0x%x", ctx)

	m1, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatalf("FPSAPExchange phase1: %v", err)
	}
	t.Logf("m1: %d bytes, rc=%d, hex=%s", len(m1), rc, hex.EncodeToString(m1))

	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	// Only enable tracing for phase 2
	os.Setenv("FPEMU_TRACE", "1")
	emu.SetTracing(true)

	m3, rc2, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatalf("FPSAPExchange phase 2: %v", err)
	}
	t.Logf("m3: %d bytes, rc=%d, hex=%s", len(m3), rc2, hex.EncodeToString(m3))
}
