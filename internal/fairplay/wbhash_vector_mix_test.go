package fairplay

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"sort"
	"testing"
)

// The "vector mix" block is the pair of NEON-heavy inner loops at:
//   Loop A: PCs 0x1a12c2a90 (setup) → 0x1a12c2b10 (body) → 0x1a12c2c20 (exit)
//   Loop B: PCs 0x1a12c2cc0 (setup) → 0x1a12c2da8 (body) → 0x1a12c2ebc (exit)
//
// They are a candidate for native-Go lifting, but the SIMD encodings are not
// yet fully decoded. Before any rewrite, this harness pins down the exact
// register / NEON / stack state at the three boundary PCs so a future native
// implementation can be validated bit-for-bit against the emulator output.
//
// The test does two things:
//   1. Determinism check: hash WBHash twice for each payload, assert that the
//      sequence of snapshots is identical run-to-run. (If this ever fails,
//      something has introduced nondeterminism into the emulator.)
//   2. Golden fingerprint check: SHA-256 of all snapshots for capturedM2 is
//      pinned to a constant. Any future change that alters the input or
//      output state of the vector-mix block will trip this.
//
// Use UPDATE_VECTOR_MIX_GOLDEN=1 go test ... to refresh the fingerprint when
// an intentional change is made.

var wbVectorMixBoundaryPCs = []uint64{
	0x1a12c2a90, // Loop A setup entry
	0x1a12c2c20, // Loop A exit / Loop B selector entry
	0x1a12c2ebc, // Loop B exit
}

// vectorMixSnapshot is the full observable state at one boundary PC.
type vectorMixSnapshot struct {
	pc       uint64
	regs     [31]uint64
	vregs    [32][2]uint64
	sp       uint64
	stackHex string // bytes from sp+0x80 .. sp+0x200 (384 bytes), hex-encoded
}

const (
	vectorMixStackLo = 0x80
	vectorMixStackHi = 0x200
)

func captureVectorMixSnapshots(t *testing.T, payload [128]byte) []vectorMixSnapshot {
	t.Helper()
	want := make(map[uint64]bool, len(wbVectorMixBoundaryPCs))
	for _, pc := range wbVectorMixBoundaryPCs {
		want[pc] = true
	}
	var out []vectorMixSnapshot
	_, err := wbHashWithFullCheckpointHook(payload, func(pc uint64, s *fpState) {
		if !want[pc] {
			return
		}
		snap := vectorMixSnapshot{
			pc:    pc,
			regs:  s.cpu.x,
			vregs: s.cpu.vreg,
			sp:    s.cpu.sp,
		}
		buf := make([]byte, vectorMixStackHi-vectorMixStackLo)
		for i := range buf {
			buf[i] = s.mem.read8Raw(s.cpu.sp + uint64(vectorMixStackLo) + uint64(i))
		}
		snap.stackHex = hex.EncodeToString(buf)
		out = append(out, snap)
	})
	if err != nil {
		t.Fatalf("WBHash failed: %v", err)
	}
	return out
}

func vectorMixSnapshotsEqual(a, b []vectorMixSnapshot) (int, bool) {
	if len(a) != len(b) {
		return -1, false
	}
	for i := range a {
		if a[i].pc != b[i].pc ||
			a[i].sp != b[i].sp ||
			a[i].regs != b[i].regs ||
			a[i].vregs != b[i].vregs ||
			a[i].stackHex != b[i].stackHex {
			return i, false
		}
	}
	return -1, true
}

func TestWBHashVectorMixSnapshotsDeterministic(t *testing.T) {
	for _, tc := range wbHashProofPayloadsForTest() {
		t.Run(tc.name, func(t *testing.T) {
			first := captureVectorMixSnapshots(t, tc.data)
			if len(first) == 0 {
				t.Fatalf("no vector-mix boundary PCs visited for %s", tc.name)
			}
			second := captureVectorMixSnapshots(t, tc.data)
			if idx, ok := vectorMixSnapshotsEqual(first, second); !ok {
				if idx < 0 {
					t.Fatalf("%s: snapshot count diverged: %d vs %d",
						tc.name, len(first), len(second))
				}
				t.Fatalf("%s: snapshot %d diverged between runs at pc=0x%x",
					tc.name, idx, first[idx].pc)
			}
		})
	}
}

func TestWBHashVectorMixBoundariesVisited(t *testing.T) {
	for _, tc := range wbHashProofPayloadsForTest() {
		t.Run(tc.name, func(t *testing.T) {
			snaps := captureVectorMixSnapshots(t, tc.data)
			counts := make(map[uint64]int, len(wbVectorMixBoundaryPCs))
			for _, s := range snaps {
				counts[s.pc]++
			}
			for _, pc := range wbVectorMixBoundaryPCs {
				if counts[pc] == 0 {
					t.Errorf("%s: boundary PC 0x%x not visited", tc.name, pc)
				}
			}
		})
	}
}

// vectorMixFingerprint reduces a snapshot sequence to a stable 32-byte hash.
// Order: pc, sp, regs (LE u64), vregs (LE u64 pairs), stack bytes.
func vectorMixFingerprint(snaps []vectorMixSnapshot) [32]byte {
	h := sha256.New()
	var buf [8]byte
	binary.LittleEndian.PutUint32(buf[:4], uint32(len(snaps)))
	h.Write(buf[:4])
	for _, s := range snaps {
		binary.LittleEndian.PutUint64(buf[:], s.pc)
		h.Write(buf[:])
		binary.LittleEndian.PutUint64(buf[:], s.sp)
		h.Write(buf[:])
		for _, r := range s.regs {
			binary.LittleEndian.PutUint64(buf[:], r)
			h.Write(buf[:])
		}
		for _, v := range s.vregs {
			binary.LittleEndian.PutUint64(buf[:], v[0])
			h.Write(buf[:])
			binary.LittleEndian.PutUint64(buf[:], v[1])
			h.Write(buf[:])
		}
		stack, _ := hex.DecodeString(s.stackHex)
		h.Write(stack)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// wbVectorMixGoldenFingerprints pins the snapshot stream for each test
// payload. Populated by running with UPDATE_VECTOR_MIX_GOLDEN=1 and pasting
// the printed map. Empty until first capture.
var wbVectorMixGoldenFingerprints = map[string]string{
	"0x42-at-0":   "b4f9e56eea13e70b4b58cc1e420ea736570e83390927416bd30e67b59456e69c",
	"0x42-at-127": "72431b99836374e360385810d019e2c13026ab8c57bdec981d7cb520b96c6fb5",
	"0x42-at-63":  "b3fd5aaa8a2955b3299132916b13a633c3061375676404b4e21bb915ccddc101",
	"0x42-at-64":  "8166cb67aaa1d0ca754294ce1a6620a41e71a82f8fbfba6432d3a59327574ff0",
	"all-0xFF":    "13d8748669402e1e7c1d6d7fbac57a37508156431035ba995900429c4bac674d",
	"all-zeros":   "33ed69e84d3838a8864c898188475a7342f497252144cc9fea26706e8807598a",
	"capturedM2":  "e1e12a07eca169614bd1250097061521594e354ba1ef18ef479fa9fd75f8c5d5",
}

func TestWBHashVectorMixGoldenFingerprint(t *testing.T) {
	updates := map[string]string{}
	for _, tc := range wbHashProofPayloadsForTest() {
		snaps := captureVectorMixSnapshots(t, tc.data)
		fp := vectorMixFingerprint(snaps)
		got := hex.EncodeToString(fp[:])
		updates[tc.name] = got
		want, ok := wbVectorMixGoldenFingerprints[tc.name]
		if !ok {
			continue
		}
		if got != want {
			t.Errorf("%s: vector-mix fingerprint mismatch\n  got:  %s\n  want: %s",
				tc.name, got, want)
		}
	}
	if len(wbVectorMixGoldenFingerprints) == 0 || t.Failed() {
		// Print a paste-ready map so the developer can populate / refresh
		// the goldens after an intentional change.
		names := make([]string, 0, len(updates))
		for n := range updates {
			names = append(names, n)
		}
		sort.Strings(names)
		t.Logf("vector-mix goldens (paste into wbVectorMixGoldenFingerprints):")
		for _, n := range names {
			t.Logf("    %q: %q,", n, updates[n])
		}
	}
}

