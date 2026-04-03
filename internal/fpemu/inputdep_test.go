//go:build !emulate

package fpemu

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// TestInputDependentState identifies the exact memory locations that differ
// between two different challenge inputs, revealing the minimal "working state".
func TestInputDependentState(t *testing.T) {
	path := os.Getenv("AIRPLAY_SENDER_PATH")
	if path == "" {
		path = "../../thirdparty/apple/AirPlaySender.framework/AirPlaySender"
	}
	if _, err := os.Stat(path); err != nil {
		t.Skipf("binary not found: %s", path)
	}

	// Run 3 computations with different inputs
	type run struct {
		challenge [128]byte
		sig       [20]byte
		stack     map[uint64]byte // stack page after
		heap      map[uint64]byte // heap page after
	}

	doRun := func(challenge [128]byte) run {
		emu, err := New(path)
		if err != nil {
			t.Fatal(err)
		}
		defer emu.Close()

		hwInfo := make([]byte, 24)
		binary.LittleEndian.PutUint32(hwInfo, 20)
		ctx, err := emu.FPSAPInit(hwInfo)
		if err != nil {
			t.Fatal(err)
		}
		_, _, err = emu.FPSAPExchange(3, hwInfo, ctx, nil)
		if err != nil {
			t.Fatal(err)
		}

		m2 := make([]byte, 142)
		copy(m2[0:4], []byte("FPLY"))
		m2[4] = 0x03
		m2[5] = 0x01
		m2[6] = 0x02
		binary.BigEndian.PutUint32(m2[8:12], 130)
		m2[12] = 0x02
		m2[13] = 0x03
		copy(m2[14:], challenge[:])

		m3, _, err := emu.FPSAPExchange(3, hwInfo, ctx, m2)
		if err != nil {
			t.Fatal(err)
		}

		var r run
		r.challenge = challenge
		payload := m3
		if len(m3) > 12 && string(m3[:4]) == "FPLY" {
			payload = m3[12:]
		}
		copy(r.sig[:], payload[132:])

		// Snapshot stack and heap
		r.stack = map[uint64]byte{}
		r.heap = map[uint64]byte{}
		for pageAddr, data := range emu.Mem().Pages() {
			if pageAddr >= 0x707fe000 && pageAddr <= 0x707fe000 {
				for i, b := range data {
					r.stack[pageAddr+uint64(i)] = b
				}
			}
			if pageAddr >= 0x80017000 && pageAddr <= 0x80017000 {
				for i, b := range data {
					r.heap[pageAddr+uint64(i)] = b
				}
			}
		}

		return r
	}

	var c0, c1, c2 [128]byte
	// c0 = all zeros
	for i := range c1 {
		c1[i] = byte(i)
	}
	for i := range c2 {
		c2[i] = byte(0xFF - i)
	}

	r0 := doRun(c0)
	r1 := doRun(c1)
	r2 := doRun(c2)

	t.Logf("sig0: %s", hex.EncodeToString(r0.sig[:]))
	t.Logf("sig1: %s", hex.EncodeToString(r1.sig[:]))
	t.Logf("sig2: %s", hex.EncodeToString(r2.sig[:]))

	// Find input-dependent stack bytes (differ between r0 and r1)
	diffStack := []uint64{}
	for addr, v0 := range r0.stack {
		if v1, ok := r1.stack[addr]; ok && v0 != v1 {
			diffStack = append(diffStack, addr)
		}
	}
	// Sort addresses
	sortAddrs(diffStack)

	t.Logf("\nInput-dependent stack bytes: %d", len(diffStack))
	if len(diffStack) > 0 {
		t.Logf("  Range: 0x%x - 0x%x", diffStack[0], diffStack[len(diffStack)-1])
		spRef := uint64(0x707fee50) // SP from earlier tests
		t.Logf("  SP = 0x%x", spRef)

		// Group into contiguous ranges
		type addrRange struct {
			start, end uint64
		}
		var ranges []addrRange
		rangeStart := diffStack[0]
		prev := diffStack[0]
		for _, a := range diffStack[1:] {
			if a != prev+1 {
				ranges = append(ranges, addrRange{rangeStart, prev})
				rangeStart = a
			}
			prev = a
		}
		ranges = append(ranges, addrRange{rangeStart, prev})

		t.Logf("  Contiguous ranges: %d", len(ranges))
		for _, r := range ranges {
			size := r.end - r.start + 1
			spOff := int64(r.start) - int64(spRef)
			t.Logf("    0x%x - 0x%x (%d bytes, SP%+d)", r.start, r.end, size, spOff)

			// Show the values for first 8 bytes of each range
			show := int(size)
			if show > 32 {
				show = 32
			}
			vals := make([]string, show)
			for i := 0; i < show; i++ {
				addr := r.start + uint64(i)
				v0 := r0.stack[addr]
				v1 := r1.stack[addr]
				v2 := r2.stack[addr]
				vals[i] = fmt.Sprintf("%02x/%02x/%02x", v0, v1, v2)
			}
			t.Logf("      vals: %v", vals)
		}
	}

	// Input-dependent heap bytes
	diffHeap := []uint64{}
	for addr, v0 := range r0.heap {
		if v1, ok := r1.heap[addr]; ok && v0 != v1 {
			diffHeap = append(diffHeap, addr)
		}
	}
	sortAddrs(diffHeap)

	t.Logf("\nInput-dependent heap bytes: %d", len(diffHeap))
	if len(diffHeap) > 0 {
		t.Logf("  Range: 0x%x - 0x%x", diffHeap[0], diffHeap[len(diffHeap)-1])

		// Group
		type addrRange struct {
			start, end uint64
		}
		var ranges []addrRange
		rangeStart := diffHeap[0]
		prev := diffHeap[0]
		for _, a := range diffHeap[1:] {
			if a != prev+1 {
				ranges = append(ranges, addrRange{rangeStart, prev})
				rangeStart = a
			}
			prev = a
		}
		ranges = append(ranges, addrRange{rangeStart, prev})

		for _, r := range ranges {
			size := r.end - r.start + 1
			t.Logf("    0x%x - 0x%x (%d bytes)", r.start, r.end, size)
			show := int(size)
			if show > 32 {
				show = 32
			}
			vals := make([]string, show)
			for i := 0; i < show; i++ {
				addr := r.start + uint64(i)
				v0 := r0.heap[addr]
				v1 := r1.heap[addr]
				v2 := r2.heap[addr]
				vals[i] = fmt.Sprintf("%02x/%02x/%02x", v0, v1, v2)
			}
			t.Logf("      vals: %v", vals)
		}
	}

	_ = fmt.Sprintf
}

func sortAddrs(addrs []uint64) {
	for i := 1; i < len(addrs); i++ {
		for j := i; j > 0 && addrs[j-1] > addrs[j]; j-- {
			addrs[j-1], addrs[j] = addrs[j], addrs[j-1]
		}
	}
}
