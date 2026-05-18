package fairplay

import (
	"fmt"
	"strings"
	"testing"
)

func TestWBHashCheckpointCopyXorLoopsStatic(t *testing.T) {
	tests := []struct {
		name string
		data [128]byte
	}{
		{name: "all-zeros"},
		{name: "all-0xFF", data: filledPayload(0xff)},
		{name: "capturedM2", data: capturedPayload()},
		{name: "0x42-at-0", data: payloadWithByte(0, 0x42)},
		{name: "0x42-at-63", data: payloadWithByte(63, 0x42)},
		{name: "0x42-at-64", data: payloadWithByte(64, 0x42)},
		{name: "0x42-at-127", data: payloadWithByte(127, 0x42)},
	}

	checkpoints := []struct {
		name string
		pc   uint64
		regs []int
	}{
		{name: "copy-xor-window", pc: wbHashCopyXorWindowLoopPC, regs: []int{8, 9, 10, 11, 12, 19, 26}},
		{name: "copy-xor-vector", pc: wbHashCopyXorVectorLoopPC, regs: []int{8, 14, 15, 16, 19, 26}},
		{name: "copy-xor-nibble", pc: 0x1a12b9984, regs: []int{8, 9, 10, 11, 12, 19, 20, 26}},
		{name: "copy-xor-tail", pc: wbHashCopyXorTailLoopPC, regs: []int{8, 9, 10, 14, 19, 21, 26}},
		{name: "xor16-next-block", pc: 0x1a12c2090, regs: []int{9, 10, 13, 16, 24}},
		{name: "prepare-lookup-round", pc: wbHashXor16ContinuePC, regs: []int{8, 10, 21}},
		{name: "lookup-layer", pc: 0x1a12c2764, regs: []int{3, 5, 6, 7, 8, 9, 10, 11, 12, 15, 20, 21, 24, 26, 30}},
		{name: "lookup-return", pc: wbHashLookupReturnPC, regs: []int{9, 11, 24, 27}},
		{name: "pointer-dispatch", pc: 0x1a12c28d8, regs: []int{24, 28, 29}},
		{name: "commit-output-status", pc: wbHashDispatchTablePC, regs: []int{19, 20, 24, 27}},
	}

	var baseline map[string][]string
	for _, tc := range tests {
		traces := make(map[string][]string)
		_, err := wbHashWithCheckpointHook(tc.data, func(pc uint64, regs *[31]uint64) {
			for _, checkpoint := range checkpoints {
				if pc == checkpoint.pc {
					traces[checkpoint.name] = append(traces[checkpoint.name], wbHashCheckpointFingerprint(regs, checkpoint.regs))
				}
			}
		})
		if err != nil {
			t.Fatalf("WBHash failed for %s: %v", tc.name, err)
		}

		if baseline == nil {
			baseline = traces
			continue
		}
		for _, checkpoint := range checkpoints {
			compareWBHashCheckpointTrace(t, tc.name, checkpoint.name, baseline[checkpoint.name], traces[checkpoint.name])
		}
	}
}

func TestWBHashCheckpointPointerTableBaseStatic(t *testing.T) {
	tests := []struct {
		name string
		data [128]byte
	}{
		{name: "all-zeros"},
		{name: "all-0xFF", data: filledPayload(0xff)},
		{name: "capturedM2", data: capturedPayload()},
		{name: "0x42-at-0", data: payloadWithByte(0, 0x42)},
		{name: "0x42-at-63", data: payloadWithByte(63, 0x42)},
		{name: "0x42-at-64", data: payloadWithByte(64, 0x42)},
		{name: "0x42-at-127", data: payloadWithByte(127, 0x42)},
	}

	for _, tc := range tests {
		visits := 0
		_, err := wbHashWithCheckpointHook(tc.data, func(pc uint64, regs *[31]uint64) {
			if pc != 0x1a12c345c {
				return
			}
			visits++
			if regs[27] != wbHashDispatchBase {
				t.Errorf("%s checkpoint 0x1a12c345c x27 = 0x%x, want 0x%x", tc.name, regs[27], wbHashDispatchBase)
			}
		})
		if err != nil {
			t.Fatalf("WBHash failed for %s: %v", tc.name, err)
		}
		if visits == 0 {
			t.Fatalf("%s did not visit checkpoint 0x1a12c345c", tc.name)
		}
	}
}

func TestWBHashCheckpointSmallCodeTableIndexStatic(t *testing.T) {
	for _, tc := range wbHashProofPayloadsForTest() {
		t.Run(tc.name, func(t *testing.T) {
			visits := 0
			_, err := wbHashWithCheckpointHook(tc.data, func(pc uint64, regs *[31]uint64) {
				if pc != 0x1a12bffd4 {
					return
				}
				visits++
				if regs[25] != 0x2 {
					t.Errorf("checkpoint 0x1a12bffd4 x25 = 0x%x, want 0x2", regs[25])
				}
			})
			if err != nil {
				t.Fatalf("WBHash failed: %v", err)
			}
			if visits == 0 {
				t.Fatal("did not visit checkpoint 0x1a12bffd4")
			}
		})
	}
}

func wbHashCheckpointFingerprint(regs *[31]uint64, regIndexes []int) string {
	var builder strings.Builder
	for _, regIndex := range regIndexes {
		fmt.Fprintf(&builder, "x%d=0x%016x;", regIndex, regs[regIndex])
	}
	return builder.String()
}

func compareWBHashCheckpointTrace(t *testing.T, payloadName, checkpointName string, want, got []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s checkpoint %s visit count = %d, want %d", payloadName, checkpointName, len(got), len(want))
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("%s checkpoint %s visit %d = %s, want %s", payloadName, checkpointName, index, got[index], want[index])
		}
	}
}
