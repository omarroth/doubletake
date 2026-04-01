package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/blacktop/go-macho"
)

func main() {
	data, _ := os.ReadFile("original-ios/15A372__iPhone10,5/root/System/Library/PrivateFrameworks/AirPlaySender.framework/AirPlaySender")
	f, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, sec := range f.Sections {
		fmt.Printf("  %s.%s: addr=0x%x size=0x%x offset=0x%x type=%d\n",
			sec.Seg, sec.Name, sec.Addr, sec.Size, sec.Offset, sec.Type)
	}

	fmt.Printf("\nIndirect symbols: %d\n", len(f.Dysymtab.IndirectSyms))

	for _, sec := range f.Sections {
		if sec.Name != "__got" && sec.Name != "__la_symbol_ptr" && sec.Name != "__stubs" && sec.Name != "__stub_helper" {
			continue
		}
		fmt.Printf("\n=== %s.%s ===\n", sec.Seg, sec.Name)
		fmt.Printf("  addr=0x%x size=0x%x offset=0x%x\n", sec.Addr, sec.Size, sec.Offset)
		fmt.Printf("  reserved1=%d reserved2=%d\n", sec.Reserved1, sec.Reserved2)
		nEntries := int(sec.Size) / 8
		if sec.Name == "__stubs" && sec.Reserved2 > 0 {
			nEntries = int(sec.Size) / int(sec.Reserved2)
		}
		fmt.Printf("  entries=%d\n", nEntries)
		for i := 0; i < nEntries && i < 20; i++ {
			isymIdx := int(sec.Reserved1) + i
			if isymIdx >= len(f.Dysymtab.IndirectSyms) {
				continue
			}
			symIdx := f.Dysymtab.IndirectSyms[isymIdx]
			if symIdx >= uint32(len(f.Symtab.Syms)) {
				continue
			}
			sym := f.Symtab.Syms[symIdx]
			if sec.Name == "__got" || sec.Name == "__la_symbol_ptr" {
				gotAddr := sec.Addr + uint64(i)*8
				fileOff := sec.Offset + uint32(i)*8
				gotVal := binary.LittleEndian.Uint64(data[fileOff : fileOff+8])
				fmt.Printf("  [%d] %s got=0x%x val=0x%x\n", i, sym.Name, gotAddr, gotVal)
			} else {
				stubAddr := sec.Addr + uint64(i)*uint64(sec.Reserved2)
				fmt.Printf("  [%d] %s stub=0x%x\n", i, sym.Name, stubAddr)
			}
		}
	}

	fmt.Println("\n=== FP-related GOT entries ===")
	for _, sec := range f.Sections {
		if sec.Name != "__got" && sec.Name != "__la_symbol_ptr" {
			continue
		}
		nEntries := int(sec.Size) / 8
		for i := 0; i < nEntries; i++ {
			isymIdx := int(sec.Reserved1) + i
			if isymIdx >= len(f.Dysymtab.IndirectSyms) {
				continue
			}
			symIdx := f.Dysymtab.IndirectSyms[isymIdx]
			if symIdx >= uint32(len(f.Symtab.Syms)) {
				continue
			}
			name := f.Symtab.Syms[symIdx].Name
			if strings.Contains(name, "AES") || strings.Contains(name, "SHA") ||
				strings.Contains(name, "malloc") || strings.Contains(name, "free") ||
				strings.Contains(name, "calloc") || strings.Contains(name, "memcpy") ||
				strings.Contains(name, "memset") || strings.Contains(name, "memcmp") ||
				strings.Contains(name, "bzero") || strings.Contains(name, "Dk7hjUuq") ||
				strings.Contains(name, "arc4random") || strings.Contains(name, "pthread") ||
				strings.Contains(name, "FigSimple") || strings.Contains(name, "FigThread") {
				gotAddr := sec.Addr + uint64(i)*8
				fmt.Printf("  %s: got=0x%x sec=%s\n", name, gotAddr, sec.Name)
			}
		}
	}
}
