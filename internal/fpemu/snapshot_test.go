//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"os"
	"testing"
)

func TestSnapshotExchange(t *testing.T) {
	emu, err := NewFromSnapshot()
	if err != nil {
		t.Fatalf("NewFromSnapshot: %v", err)
	}
	defer emu.Close()

	ctx, err := SnapshotCtx()
	if err != nil {
		t.Fatalf("SnapshotCtx: %v", err)
	}

	hwInfo := make([]byte, 24)
	binary.LittleEndian.PutUint32(hwInfo, 20)

	// Zero m2
	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	m3, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatalf("FPSAPExchange: %v", err)
	}
	t.Logf("m3: %d bytes, rc=%d", len(m3), rc)
	t.Logf("m3 hex: %s", hex.EncodeToString(m3))

	// Strip FPLY header
	payload := m3
	if len(m3) > 12 && string(m3[:4]) == "FPLY" {
		payload = m3[12:]
	}
	if len(payload) != 152 {
		t.Fatalf("unexpected payload length: %d", len(payload))
	}

	// Verify static bytes
	expectedStatic := "038f1a9c991ea22c511e45ba97f1af8dfb0f86f550c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c712202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b69101b849fd93a02860d1a0dff5cd4414aa"
	gotStatic := hex.EncodeToString(payload[:132])
	if gotStatic != expectedStatic {
		t.Fatalf("static bytes mismatch:\n  got:  %s\n  want: %s", gotStatic, expectedStatic)
	}

	// Verify signature for zero m2
	expectedSig := "6f627565f3e77f5b5ede91beee7baf92e4241e0b"
	gotSig := hex.EncodeToString(payload[132:])
	if gotSig != expectedSig {
		t.Fatalf("signature mismatch:\n  got:  %s\n  want: %s", gotSig, expectedSig)
	}
	t.Log("snapshot exchange: static bytes and signature match!")
}

func TestSnapshotOracleComparison(t *testing.T) {
	binaryPath := os.Getenv("AIRPLAY_SENDER_PATH")
	if binaryPath == "" {
		binaryPath = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(binaryPath); err != nil {
		t.Skipf("binary not found for oracle comparison: %s", binaryPath)
	}

	challenges := [][128]byte{
		{}, // all zeros
		func() [128]byte { var c [128]byte; c[0] = 0xFF; return c }(),
		func() [128]byte {
			var c [128]byte
			for i := range c {
				c[i] = byte(i)
			}
			return c
		}(),
		func() [128]byte {
			var c [128]byte
			for i := range c {
				c[i] = 0xFF
			}
			return c
		}(),
		func() [128]byte { var c [128]byte; c[42] = 0x42; return c }(),
	}

	for i, challenge := range challenges {
		// Build m2
		m2 := make([]byte, 142)
		copy(m2[0:4], []byte("FPLY"))
		m2[4] = 0x03
		m2[5] = 0x01
		m2[6] = 0x02
		binary.BigEndian.PutUint32(m2[8:12], 130)
		m2[12] = 0x02
		m2[13] = 0x03
		copy(m2[14:], challenge[:])

		// Oracle: binary-based emulator
		oracleEmu, err := New(binaryPath)
		if err != nil {
			t.Fatalf("oracle New: %v", err)
		}
		hwInfo := make([]byte, 24)
		binary.LittleEndian.PutUint32(hwInfo, 20)
		oracleCtx, err := oracleEmu.FPSAPInit(hwInfo)
		if err != nil {
			oracleEmu.Close()
			t.Fatalf("oracle FPSAPInit: %v", err)
		}
		_, _, err = oracleEmu.FPSAPExchange(3, hwInfo, oracleCtx, nil)
		if err != nil {
			oracleEmu.Close()
			t.Fatalf("oracle phase1: %v", err)
		}
		oracleM3, _, err := oracleEmu.FPSAPExchange(3, hwInfo, oracleCtx, m2)
		oracleEmu.Close()
		if err != nil {
			t.Fatalf("oracle phase2: %v", err)
		}

		// Snapshot-based emulator
		snapEmu, err := NewFromSnapshot()
		if err != nil {
			t.Fatalf("snapshot New: %v", err)
		}
		snapCtx, err := SnapshotCtx()
		if err != nil {
			t.Fatalf("SnapshotCtx: %v", err)
		}
		snapM3, _, err := snapEmu.FPSAPExchange(3, hwInfo, snapCtx, m2)
		snapEmu.Close()
		if err != nil {
			t.Fatalf("snapshot exchange: %v", err)
		}

		oracleHex := hex.EncodeToString(oracleM3)
		snapHex := hex.EncodeToString(snapM3)
		if oracleHex != snapHex {
			t.Errorf("challenge %d: MISMATCH\n  oracle:   %s\n  snapshot: %s", i, oracleHex, snapHex)
		} else {
			t.Logf("challenge %d: match (%d bytes)", i, len(oracleM3))
		}
	}
}
