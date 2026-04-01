package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/blacktop/go-macho"
)

type memRange struct {
	start, end uint64
}

func main() {
	data, err := os.ReadFile("original-ios/15A372__iPhone10,5/root/System/Library/PrivateFrameworks/AirPlaySender.framework/AirPlaySender")
	if err != nil {
		panic(err)
	}
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		panic(err)
	}

	var loaded []memRange
	for _, seg := range f.Segments() {
		if seg.Name == "__LINKEDIT" || seg.Memsz == 0 {
			continue
		}
		loaded = append(loaded, memRange{seg.Addr, seg.Addr + seg.Memsz})
	}

	isLocal := func(addr uint64) bool {
		for _, r := range loaded {
			if addr >= r.start && addr < r.end {
				return true
			}
		}
		return false
	}

	targets := make(map[uint64]int)
	for _, sec := range f.Sections {
		if sec.Seg != "__DATA_CONST" && sec.Seg != "__DATA" && sec.Seg != "__DATA_DIRTY" {
			continue
		}
		end := uint64(sec.Offset) + sec.Size
		if end > uint64(len(data)) {
			continue
		}
		secData := data[sec.Offset:end]
		for off := 0; off+8 <= len(secData); off += 8 {
			val := binary.LittleEndian.Uint64(secData[off : off+8])
			if val == 0 {
				continue
			}
			for _, bias := range []uint64{0, 3} {
				target := val - bias
				if target >= 0x180000000 && target < 0x1E0000000 && !isLocal(target) {
					targets[target]++
				}
			}
		}
	}

	addrs := make([]uint64, 0, len(targets))
	for a := range targets {
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i] < addrs[j] })
	fmt.Printf("Found %d unique shared cache targets:\n", len(addrs))
	for _, a := range addrs {
		fmt.Printf("  0x%x (refs=%d)\n", a, targets[a])
	}
}
