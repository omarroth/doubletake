package main

import (
"encoding/hex"
"fmt"
"testing"

"airplay/playfair"
)

func TestDecryptChallengeResponses(t *testing.T) {
// Known m2 (server->client) and m3 (client->server) pairs from AirMyPC captures
m2aBytes, _ := hex.DecodeString(message2KnownHexA)
m3aBytes, _ := hex.DecodeString(message3KnownHexA)
m2bBytes, _ := hex.DecodeString(message2KnownHexB)
m3bBytes, _ := hex.DecodeString(message3KnownHexB)

// Decrypt m2 bodies (server challenge)
var m2a164 [164]byte
m2a164[12] = m2aBytes[12] // mode byte
copy(m2a164[16:144], m2aBytes[14:142])
m2aplain := playfair.DecryptMessage(m2a164)

var m2b164 [164]byte
m2b164[12] = m2bBytes[12]
copy(m2b164[16:144], m2bBytes[14:142])
m2bplain := playfair.DecryptMessage(m2b164)

// Decrypt m3 bodies (client challenge response)
var m3a164, m3b164 [164]byte
copy(m3a164[:], m3aBytes)
copy(m3b164[:], m3bBytes)
m3aplain := playfair.DecryptMessage(m3a164)
m3bplain := playfair.DecryptMessage(m3b164)

fmt.Println("=== m2A (server challenge) plaintext ===")
for i := 0; i < 128; i += 16 {
ascii := ""
for j := i; j < i+16 && j < 128; j++ {
if m2aplain[j] >= 0x20 && m2aplain[j] < 0x7f {
ascii += string(m2aplain[j])
} else {
ascii += "."
}
}
fmt.Printf("  [%3d] %02x  %s\n", i, m2aplain[i:i+16], ascii)
}

fmt.Println("\n=== m3A (client response) plaintext ===")
for i := 0; i < 128; i += 16 {
ascii := ""
for j := i; j < i+16 && j < 128; j++ {
if m3aplain[j] >= 0x20 && m3aplain[j] < 0x7f {
ascii += string(m3aplain[j])
} else {
ascii += "."
}
}
fmt.Printf("  [%3d] %02x  %s\n", i, m3aplain[i:i+16], ascii)
}

fmt.Println("\n=== m2B (server challenge) plaintext ===")
for i := 0; i < 128; i += 16 {
ascii := ""
for j := i; j < i+16 && j < 128; j++ {
if m2bplain[j] >= 0x20 && m2bplain[j] < 0x7f {
ascii += string(m2bplain[j])
} else {
ascii += "."
}
}
fmt.Printf("  [%3d] %02x  %s\n", i, m2bplain[i:i+16], ascii)
}

fmt.Println("\n=== m3B (client response) plaintext ===")
for i := 0; i < 128; i += 16 {
ascii := ""
for j := i; j < i+16 && j < 128; j++ {
if m3bplain[j] >= 0x20 && m3bplain[j] < 0x7f {
ascii += string(m3bplain[j])
} else {
ascii += "."
}
}
fmt.Printf("  [%3d] %02x  %s\n", i, m3bplain[i:i+16], ascii)
}

// Also show the 20-byte "tags" (encrypted AES key?)
fmt.Printf("\n=== 20-byte tags (encrypted AES key?) ===\n")
fmt.Printf("m3A tag: %02x\n", m3aBytes[144:164])
fmt.Printf("m3B tag: %02x\n", m3bBytes[144:164])

// Check: do both m2 and m3 share common bytes?
fmt.Println("\n=== Byte comparison m2A vs m3A ===")
matches := 0
for i := 0; i < 128; i++ {
if m2aplain[i] == m3aplain[i] {
matches++
}
}
fmt.Printf("m2A vs m3A same bytes: %d/128\n", matches)

matches = 0
for i := 0; i < 128; i++ {
if m2bplain[i] == m3bplain[i] {
matches++
}
}
fmt.Printf("m2B vs m3B same bytes: %d/128\n", matches)

// Are the m3 plaintexts the same across sessions? (would indicate static content)
matches = 0
for i := 0; i < 128; i++ {
if m3aplain[i] == m3bplain[i] {
matches++
}
}
fmt.Printf("m3A vs m3B same bytes: %d/128 (same across sessions?)\n", matches)
}
