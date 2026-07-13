package airplay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

func TestAnalyzePlayfairMessageAES(t *testing.T) {
	for mode := byte(0); mode < 4; mode++ {
		message := make([]byte, 144)
		message[12] = mode
		for i := 16; i < len(message); i++ {
			message[i] = byte(i*37 + int(mode))
		}
		var want [128]byte
		decryptMessage(message, want[:])

		block, err := aes.NewCipher(sapKeyMaterial[:])
		if err != nil {
			t.Fatal(err)
		}
		got := append([]byte(nil), message[16:]...)
		cipher.NewCBCDecrypter(block, messageIv[mode][:]).CryptBlocks(got, got)
		t.Logf("mode %d standard=%v playfair=%s aes=%s", mode, bytes.Equal(got, want[:]), hex.EncodeToString(want[:16]), hex.EncodeToString(got[:16]))
	}
}
