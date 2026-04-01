package fpemu

import (
	"log"
	"os"
	"testing"
)

func TestFPSAPInit(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../original-ios/15A372__iPhone10,5/root/System/Library/PrivateFrameworks/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	emu, err := New(path)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer emu.Close()

	hwInfo := make([]byte, 24)
	hwInfo[0] = 0x42

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		t.Fatalf("FPSAPInit: %v", err)
	}
	log.Printf("SAP context: 0x%x", ctx)

	m1, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatalf("FPSAPExchange phase1: %v", err)
	}
	log.Printf("m1: %d bytes, rc=%d", len(m1), rc)
	if len(m1) == 0 {
		t.Fatal("m1 is empty")
	}
	n := len(m1)
	if n > 20 {
		n = 20
	}
	t.Logf("m1 first bytes: %x", m1[:n])
}
