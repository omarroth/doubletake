package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"testing"

	"airplay/playfair"
)

func TestFPAnalysis(t *testing.T) {
	// Known pair A
	m2aBytes, _ := hex.DecodeString(message2KnownHexA)
	m3aBytes, _ := hex.DecodeString(message3KnownHexA)

	// Known pair B
	m2bBytes, _ := hex.DecodeString(message2KnownHexB)
	m3bBytes, _ := hex.DecodeString(message3KnownHexB)

	// Decrypt all bodies
	var m3a164, m3b164 [164]byte
	copy(m3a164[:], m3aBytes)
	copy(m3b164[:], m3bBytes)
	m3aplain := playfair.DecryptMessage(m3a164)
	m3bplain := playfair.DecryptMessage(m3b164)

	var m2a164, m2b164 [164]byte
	m2a164[12] = 0x02
	copy(m2a164[16:144], m2aBytes[14:142])
	m2b164[12] = 0x02
	copy(m2b164[16:144], m2bBytes[14:142])
	m2aplain := playfair.DecryptMessage(m2a164)
	m2bplain := playfair.DecryptMessage(m2b164)

	fmt.Printf("m2A plain: %02x\n", m2aplain[:32])
	fmt.Printf("m3A plain: %02x\n", m3aplain[:32])
	fmt.Printf("m2B plain: %02x\n", m2bplain[:32])
	fmt.Printf("m3B plain: %02x\n", m3bplain[:32])

	// Check XOR hypothesis: is (m2_plain XOR m3_plain) constant across sessions?
	var diffA, diffB [128]byte
	for i := 0; i < 128; i++ {
		diffA[i] = m2aplain[i] ^ m3aplain[i]
		diffB[i] = m2bplain[i] ^ m3bplain[i]
	}
	diffMatch := 0
	for i := 0; i < 128; i++ {
		if diffA[i] == diffB[i] {
			diffMatch++
		}
	}
	fmt.Printf("\ndiffA = m2A XOR m3A: %02x\n", diffA[:32])
	fmt.Printf("diffB = m2B XOR m3B: %02x\n", diffB[:32])
	fmt.Printf("diffA == diffB: %d/128 bytes match\n", diffMatch)

	// Verify encryptMessage roundtrip for both pairs
	encA := playfair.EncryptMessage(m3a164, m3aplain)
	encB := playfair.EncryptMessage(m3b164, m3bplain)
	matchA, matchB := 0, 0
	for i := 0; i < 128; i++ {
		if encA[16+i] == m3aBytes[16+i] {
			matchA++
		}
		if encB[16+i] == m3bBytes[16+i] {
			matchB++
		}
	}
	fmt.Printf("\nEncrypt roundtrip A: %d/128, B: %d/128\n", matchA, matchB)

	// Tag analysis: try various hash computations
	tagA := m3aBytes[144:164]
	tagB := m3bBytes[144:164]
	fmt.Printf("\n=== Tag analysis ===\n")
	fmt.Printf("m3A tag:  %02x\n", tagA)
	fmt.Printf("m3B tag:  %02x\n", tagB)

	bytesMatch := func(a, b []byte) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}

	// SHA-1 of m3 body (128 bytes)
	h := sha1.Sum(m3aBytes[16:144])
	fmt.Printf("SHA1(m3A body):     %02x match=%v\n", h[:], bytesMatch(h[:], tagA))

	// SHA-1 of m3 bytes 0-143 (header + prefix + body)
	h = sha1.Sum(m3aBytes[:144])
	fmt.Printf("SHA1(m3A[0:144]):   %02x match=%v\n", h[:], bytesMatch(h[:], tagA))

	// SHA-1 of m3 plaintext
	h = sha1.Sum(m3aplain[:])
	fmt.Printf("SHA1(m3A plain):    %02x match=%v\n", h[:], bytesMatch(h[:], tagA))

	// SHA-1 of m2 body + m3 body combined
	combined := append(m2aBytes[14:142], m3aBytes[16:144]...)
	h = sha1.Sum(combined)
	fmt.Printf("SHA1(m2A||m3A):     %02x match=%v\n", h[:], bytesMatch(h[:], tagA))

	// SHA-1 of m2 plain + m3 plain combined
	combined2 := append(m2aplain[:], m3aplain[:]...)
	h = sha1.Sum(combined2)
	fmt.Printf("SHA1(m2Ap||m3Ap):   %02x match=%v\n", h[:], bytesMatch(h[:], tagA))

	// SHA-1 of m3 body + mode bytes
	combined3 := append(m3aBytes[12:16], m3aBytes[16:144]...)
	h = sha1.Sum(combined3)
	fmt.Printf("SHA1(prefix||body): %02x match=%v\n", h[:], bytesMatch(h[:], tagA))

	// Check if tag appears to be related to UxPlay static m2 for mode 2
	uxplayM2mode2, _ := hex.DecodeString("46504c5903010200000000820202c169a352eeed35b18cdd9c58d64f16c1519a89eb5317bd0d4336cd68f638ff9d016a5b52b7fa9216b2b65482c784441181a121a2c7fed83db7119e9182aad7d18c7063e2a457555910af9e0efc76347d16404380" +
		"7f581ee4fbe42ca9dedc1b5eb2a3aa3d2ecd59e7eee70b3629f22afd161d877353ddb99adc8e07006e56f850ce")
	var ux164 [164]byte
	ux164[12] = 0x02
	copy(ux164[16:144], uxplayM2mode2[14:142])
	uxplain := playfair.DecryptMessage(ux164)
	fmt.Printf("\nUxPlay m2 mode2 plain: %02x\n", uxplain[:32])

	// Check if m3A plain == UxPlay plain (same static challenge?)
	uxMatch := 0
	for i := 0; i < 128; i++ {
		if m3aplain[i] == uxplain[i] {
			uxMatch++
		}
	}
	fmt.Printf("m3A plain matches UxPlay plain: %d/128\n", uxMatch)

	// === Session key and HMAC-SHA1 tag analysis ===
	fmt.Printf("\n=== Session key + HMAC tag analysis ===\n")

	// Build SAP for pair A: default_sap bytes 0-127 + m2A plaintext at 128-255
	sapBase := playfair.DefaultSAP()
	fmt.Printf("default_sap[0x80:0x90]: %02x\n", sapBase[0x80:0x90])
	fmt.Printf("default_sap[0x7c:0x80]: %02x\n", sapBase[0x7c:0x80])

	// Build correct SAP for pair A using m2A plaintext
	var sapA [256]byte
	copy(sapA[:128], sapBase[:128])
	copy(sapA[128:], m2aplain[:])

	// Generate session key with pair A's SAP + m3A
	keyA := playfair.GenerateSessionKey(sapA, m3a164)
	fmt.Printf("sessionKeyA (with m2A SAP): %02x\n", keyA)

	// Also try with default SAP (UxPlay's m2)
	keyAdefault := playfair.GenerateSessionKey(sapBase, m3a164)
	fmt.Printf("sessionKeyA (with UxPlay SAP): %02x\n", keyAdefault)

	// Test HMAC-SHA1 with session key
	for _, testCase := range []struct {
		name string
		key  [16]byte
		data []byte
	}{
		{"HMAC(keyA, m3A_body)", keyA, m3aBytes[16:144]},
		{"HMAC(keyA, m3A[0:144])", keyA, m3aBytes[:144]},
		{"HMAC(keyA, m3A_plain)", keyA, m3aplain[:]},
		{"HMAC(keyA, m3A[12:144])", keyA, m3aBytes[12:144]},
		{"HMAC(keyAdef, m3A_body)", keyAdefault, m3aBytes[16:144]},
		{"HMAC(keyAdef, m3A[0:144])", keyAdefault, m3aBytes[:144]},
	} {
		mac := hmac.New(sha1.New, testCase.key[:])
		mac.Write(testCase.data)
		h := mac.Sum(nil)
		fmt.Printf("%s: %02x match=%v\n", testCase.name, h, bytesMatch(h, tagA))
	}

	// Test Encrypt/Decrypt roundtrip with session key
	keyForCrypto := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	ekeyA := playfair.Encrypt(m3a164, keyForCrypto)
	recoveredA := playfair.Decrypt(m3a164, ekeyA)
	fmt.Printf("\nEncrypt/Decrypt roundtrip (uses default_sap): key matches=%v\n", recoveredA == keyForCrypto)

	// Verify pair B session key
	var sapB [256]byte
	copy(sapB[:128], sapBase[:128])
	copy(sapB[128:], m2bplain[:])
	keyB := playfair.GenerateSessionKey(sapB, m3b164)
	fmt.Printf("\nsessionKeyB (with m2B SAP): %02x\n", keyB)
	for _, testCase := range []struct {
		name string
		key  [16]byte
		data []byte
	}{
		{"HMAC(keyB, m3B_body)", keyB, m3bBytes[16:144]},
		{"HMAC(keyB, m3B[0:144])", keyB, m3bBytes[:144]},
		{"HMAC(keyB, m3B_plain)", keyB, m3bplain[:]},
	} {
		mac := hmac.New(sha1.New, testCase.key[:])
		mac.Write(testCase.data)
		h := mac.Sum(nil)
		fmt.Printf("%s: %02x match=%v\n", testCase.name, h, bytesMatch(h, tagB))
	}
}

func TestFPEncryptRoundtrip(t *testing.T) {
	m3aBytes, _ := hex.DecodeString(message3KnownHexA)
	var m3a [164]byte
	copy(m3a[:], m3aBytes)

	plain := playfair.DecryptMessage(m3a)
	enc := playfair.EncryptMessage(m3a, plain)

	for i := 0; i < 128; i++ {
		if enc[16+i] != m3aBytes[16+i] {
			t.Fatalf("body mismatch at byte %d: got %02x want %02x", i, enc[16+i], m3aBytes[16+i])
		}
	}
}
