//go:build !emulate

package fpemu

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

func TestGoEmuFPSAPInit(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
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
	binary.LittleEndian.PutUint32(hwInfo, 20)

	ctx, err := emu.FPSAPInit(hwInfo)
	if err != nil {
		t.Fatalf("FPSAPInit: %v", err)
	}
	t.Logf("SAP context: 0x%x", ctx)

	m1, rc, err := emu.FPSAPExchange(3, hwInfo, ctx, nil)
	if err != nil {
		t.Fatalf("FPSAPExchange phase 1: %v", err)
	}
	t.Logf("m1: %d bytes, rc=%d, hex=%s", len(m1), rc, hex.EncodeToString(m1))

	expectedM1 := "46504c590301010000000004020003bb"
	if hex.EncodeToString(m1) != expectedM1 {
		if hex.EncodeToString(m1) != "020003bb" {
			t.Fatalf("m1 mismatch: got %s", hex.EncodeToString(m1))
		}
	}

	m2 := make([]byte, 142)
	copy(m2[0:4], []byte("FPLY"))
	m2[4] = 0x03
	m2[5] = 0x01
	m2[6] = 0x02
	binary.BigEndian.PutUint32(m2[8:12], 130)
	m2[12] = 0x02
	m2[13] = 0x03

	// Install trace for phase 2 — only TEXT segment instructions
	type traceEntry struct {
		pc         uint64
		x0, x1, x2 uint64
	}
	var goTrace []traceEntry
	type checkpoint struct {
		textN              int
		pc                 uint64
		x0, x1, x2, x3, sp uint64
	}
	var goCheckpoints []checkpoint
	textInstCount := 0
	// Capture full register dump at first visit to specific PCs
	type regDump struct {
		x  [31]uint64
		sp uint64
	}
	regDumps := make(map[uint64]regDump) // PC -> first-visit register dump
	watchPCs := map[uint64]bool{
		0x1a12cf784: true, // matches (~6213)
		0x1a12cf744: true, // ~6262
		0x1a12cf78c: true, // ~6412
		0x1a12d6d48: true, // ~6562 (transition)
		0x1a12d6e10: true, // ~6612
		0x1a12d6ed8: true, // ~6662
		0x1a12d6f9c: true, // DIVERGES (~6712)
	}
	var vregFile *os.File
	defer func() {
		if vregFile != nil {
			vregFile.Close()
		}
	}()
	emu.cpu.Trace = func(pc uint64, inst uint32) {
		// Only trace TEXT segment instructions for comparison
		if pc >= 0x1a1210000 && pc < 0x1a1316000 {
			textInstCount++
			if len(goTrace) < 200000 {
				goTrace = append(goTrace, traceEntry{pc, emu.cpu.X[0], emu.cpu.X[1], emu.cpu.X[2]})
			}
			if textInstCount%1000 == 0 {
				goCheckpoints = append(goCheckpoints, checkpoint{
					textInstCount, pc,
					emu.cpu.X[0], emu.cpu.X[1], emu.cpu.X[2], emu.cpu.X[3], emu.cpu.SP,
				})
			}
			// Detailed V-register trace in the divergent block
			if pc >= 0x1a12d6d48 && pc <= 0x1a12d6e14 {
				if vregFile == nil {
					vregFile, _ = os.Create("/tmp/fp_goemu_vreg_trace.txt")
				}
				if vregFile != nil {
					fmt.Fprintf(vregFile, "PC=0x%x inst=0x%08x SP=0x%x X9=0x%x X10=0x%x X16=0x%x\n",
						pc, inst, emu.cpu.SP, emu.cpu.X[9], emu.cpu.X[10], emu.cpu.X[16])
					for v := 0; v < 5; v++ {
						fmt.Fprintf(vregFile, "  V%d = {0x%016x, 0x%016x}\n", v, emu.cpu.Vreg[v][0], emu.cpu.Vreg[v][1])
					}
					// Dump memory at X9 when we're at the first LDR Q0 instruction
					if pc == 0x1a12d6d64 {
						x9 := emu.cpu.X[9]
						fmt.Fprintf(vregFile, "  MEMDUMP at X9=0x%x: ", x9)
						for i := 0; i < 64; i++ {
							fmt.Fprintf(vregFile, "%02x", emu.mem.Read8(x9+uint64(i)))
						}
						fmt.Fprintf(vregFile, "\n")
					}
					// Dump stack at LDP W9, W16, [SP, #0] to compare SIMD output
					if pc == 0x1a12d6e04 {
						sp := emu.cpu.SP
						fmt.Fprintf(vregFile, "  STACKDUMP at SP=0x%x: ", sp)
						for i := 0; i < 64; i++ {
							fmt.Fprintf(vregFile, "%02x", emu.mem.Read8(sp+uint64(i)))
						}
						fmt.Fprintf(vregFile, "\n")
					}
				}
			}
			if watchPCs[pc] {
				if _, exists := regDumps[pc]; !exists {
					var d regDump
					d.x = emu.cpu.X
					d.sp = emu.cpu.SP
					regDumps[pc] = d
				}
			}
		}
	}

	m3, rc2, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
	if err != nil {
		t.Fatalf("FPSAPExchange phase 2: %v", err)
	}
	emu.cpu.Trace = nil
	t.Logf("m3: %d bytes, rc=%d, hex=%s", len(m3), rc2, hex.EncodeToString(m3))
	t.Logf("goemu executed %d total instructions, %d TEXT instructions traced, %d checkpoints", emu.cpu.InstCount(), textInstCount, len(goCheckpoints))

	// Print register dumps at watch PCs
	for pc, d := range regDumps {
		t.Logf("REGDUMP PC=0x%x SP=0x%x", pc, d.sp)
		for i := 0; i < 31; i++ {
			t.Logf("  X%d=0x%x", i, d.x[i])
		}
	}

	// Compare checkpoints with Unicorn reference
	ucCpFile, cpErr := os.Open("/tmp/fp_unicorn_checkpoints.txt")
	if cpErr != nil {
		t.Logf("no unicorn checkpoints: %v", cpErr)
	} else {
		defer ucCpFile.Close()
		scanner := bufio.NewScanner(ucCpFile)
		ucIdx := 0
		for scanner.Scan() {
			var textN int
			var pc, x0, x1, x2, x3, sp uint64
			fmt.Sscanf(scanner.Text(), "text#%d pc=0x%x x0=0x%x x1=0x%x x2=0x%x x3=0x%x sp=0x%x",
				&textN, &pc, &x0, &x1, &x2, &x3, &sp)
			// Find matching goemu checkpoint by textN
			for _, gcp := range goCheckpoints {
				if gcp.textN == textN {
					if gcp.pc != pc || gcp.x0 != x0 || gcp.x1 != x1 || gcp.x2 != x2 || gcp.x3 != x3 || gcp.sp != sp {
						t.Logf("CHECKPOINT DIVERGENCE at text#%d:", textN)
						t.Logf("  unicorn: pc=0x%x x0=0x%x x1=0x%x x2=0x%x x3=0x%x sp=0x%x", pc, x0, x1, x2, x3, sp)
						t.Logf("  goemu:   pc=0x%x x0=0x%x x1=0x%x x2=0x%x x3=0x%x sp=0x%x", gcp.pc, gcp.x0, gcp.x1, gcp.x2, gcp.x3, gcp.sp)
						// Show previous checkpoint
						if ucIdx > 0 {
							t.Logf("  (previous checkpoint text#%d matched)", textN-1000)
						}
						break
					}
					break
				}
			}
			ucIdx++
		}
		if ucIdx > 0 {
			t.Logf("compared %d Unicorn checkpoints", ucIdx)
		}
	}

	// Load Unicorn trace for comparison
	// Also write goemu trace to file for manual comparison
	{
		f, err := os.Create("/tmp/fp_goemu_trace.txt")
		if err == nil {
			for i, ge := range goTrace {
				fmt.Fprintf(f, "%d 0x%x x0=0x%x x1=0x%x x2=0x%x\n", i, ge.pc, ge.x0, ge.x1, ge.x2)
			}
			f.Close()
			t.Logf("wrote %d goemu trace entries to /tmp/fp_goemu_trace.txt", len(goTrace))
		}
	}
	ucFile, err := os.Open("/tmp/fp_unicorn_trace.txt")
	if err != nil {
		t.Logf("no unicorn trace available: %v", err)
	} else {
		defer ucFile.Close()
		scanner := bufio.NewScanner(ucFile)
		i := 0
		for scanner.Scan() && i < len(goTrace) {
			var idx int
			var pc, x0, x1, x2 uint64
			fmt.Sscanf(scanner.Text(), "%d 0x%x x0=0x%x x1=0x%x x2=0x%x", &idx, &pc, &x0, &x1, &x2)
			ge := goTrace[i]
			if ge.pc != pc || ge.x0 != x0 || ge.x1 != x1 || ge.x2 != x2 {
				// Show context: 5 lines before divergence
				start := i - 5
				if start < 0 {
					start = 0
				}
				for j := start; j < i; j++ {
					t.Logf("  [%d] goemu: PC=0x%x x0=0x%x x1=0x%x x2=0x%x", j, goTrace[j].pc, goTrace[j].x0, goTrace[j].x1, goTrace[j].x2)
				}
				t.Logf("DIVERGENCE at instruction %d:", i)
				t.Logf("  unicorn: PC=0x%x x0=0x%x x1=0x%x x2=0x%x", pc, x0, x1, x2)
				t.Logf("  goemu:   PC=0x%x x0=0x%x x1=0x%x x2=0x%x", ge.pc, ge.x0, ge.x1, ge.x2)
				// Show next few from each
				for j := 1; j <= 5 && i+j < len(goTrace); j++ {
					nge := goTrace[i+j]
					t.Logf("  goemu+%d: PC=0x%x x0=0x%x x1=0x%x x2=0x%x", j, nge.pc, nge.x0, nge.x1, nge.x2)
				}
				// Also show the instruction at the point of divergence
				if i > 0 {
					prevInst := emu.mem.Read32(goTrace[i-1].pc)
					t.Logf("  instruction before divergence: PC=0x%x inst=0x%08x", goTrace[i-1].pc, prevInst)
				}
				break
			}
			i++
		}
		if i == len(goTrace) {
			t.Logf("first %d instructions match Unicorn trace!", i)
		}
	}

	// Strip FPLY header if present
	m3Payload := m3
	if len(m3) > 12 && string(m3[:4]) == "FPLY" {
		m3Payload = m3[12:]
	}

	if len(m3Payload) != 152 {
		t.Fatalf("m3 payload length: got %d, want 152", len(m3Payload))
	}

	expectedStatic := "038f1a9c991ea22c511e45ba97f1af8dfb0f86f550c54486fe6b3ab233da431ef8e5fc1156dba321fffeabb1b392b09d227e88c712202866eb7bbf310015aa1d19a5df36d5dfd8d3ca1639b376eaece946edfe8b7a66cd302d04aac3c1251714019bd5f2d49b543e11eed1646291ec8efd96b69101b849fd93a02860d1a0dff5cd4414aa"
	gotStatic := hex.EncodeToString(m3Payload[:132])
	if gotStatic != expectedStatic {
		for i := 0; i < 132; i++ {
			exp, _ := hex.DecodeString(expectedStatic[i*2 : i*2+2])
			if m3Payload[i] != exp[0] {
				t.Logf("first difference at payload byte %d: got 0x%02x, want 0x%02x", i, m3Payload[i], exp[0])
				break
			}
		}
		t.Fatalf("m3 static bytes mismatch:\n  got:  %s\n  want: %s", gotStatic, expectedStatic)
	}
	t.Logf("m3 static bytes match!")
}
