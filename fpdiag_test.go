package main

import (
"encoding/hex"
"fmt"
"testing"

"airplay/playfair"
)

func TestFPPlaintextStructure(t *testing.T) {
m3aBytes, _ := hex.DecodeString(message3KnownHexA)
m3bBytes, _ := hex.DecodeString(message3KnownHexB)

var m3a164, m3b164 [164]byte
copy(m3a164[:], m3aBytes)
copy(m3b164[:], m3bBytes)
m3aplain := playfair.DecryptMessage(m3a164)
m3bplain := playfair.DecryptMessage(m3b164)

fmt.Printf("m3A plain full (%d bytes):\n", len(m3aplain))
for i := 0; i < 128; i += 16 {
end := i + 16
if end > 128 { end = 128 }
fmt.Printf("  [%3d] %02x\n", i, m3aplain[i:end])
}

fmt.Printf("\nm3B plain full (%d bytes):\n", len(m3bplain))
for i := 0; i < 128; i += 16 {
end := i + 16
if end > 128 { end = 128 }
fmt.Printf("  [%3d] %02x\n", i, m3bplain[i:end])
}

// Also check m2 plaintexts
m2aBytes, _ := hex.DecodeString(message2KnownHexA)
m2bBytes, _ := hex.DecodeString(message2KnownHexB)
var m2a164, m2b164 [164]byte
m2a164[12] = 0x02
copy(m2a164[16:144], m2aBytes[14:142])
m2b164[12] = 0x02
copy(m2b164[16:144], m2bBytes[14:142])
m2aplain := playfair.DecryptMessage(m2a164)
m2bplain := playfair.DecryptMessage(m2b164)

fmt.Printf("\nm2A plain full (%d bytes):\n", len(m2aplain))
for i := 0; i < 128; i += 16 {
end := i + 16
if end > 128 { end = 128 }
fmt.Printf("  [%3d] %02x\n", i, m2aplain[i:end])
}

fmt.Printf("\nm2B plain full (%d bytes):\n", len(m2bplain))
for i := 0; i < 128; i += 16 {
end := i + 16
if end > 128 { end = 128 }
fmt.Printf("  [%3d] %02x\n", i, m2bplain[i:end])
}
}
