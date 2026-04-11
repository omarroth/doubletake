package airplay

import (
	"bytes"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestUseAudioFECDefaults(t *testing.T) {
	t.Setenv("AUDIO_NO_FEC", "")
	t.Setenv("AUDIO_FORCE_FEC", "")

	if !useAudioFEC(false) {
		t.Fatal("expected legacy/plaintext sessions to keep FEC by default")
	}
	if useAudioFEC(true) {
		t.Fatal("expected modern encrypted sessions to disable FEC by default")
	}
}

func TestUseAudioFECOverrides(t *testing.T) {
	t.Setenv("AUDIO_NO_FEC", "")
	t.Setenv("AUDIO_FORCE_FEC", "1")
	if !useAudioFEC(true) {
		t.Fatal("expected AUDIO_FORCE_FEC=1 to enable FEC for encrypted sessions")
	}

	t.Setenv("AUDIO_FORCE_FEC", "")
	t.Setenv("AUDIO_NO_FEC", "1")
	if useAudioFEC(false) {
		t.Fatal("expected AUDIO_NO_FEC=1 to disable FEC for legacy sessions")
	}
}

func TestAudioCodecFormatIndex(t *testing.T) {
	if got := AudioCodecALAC.AudioFormatIndex(); got != 0x12 {
		t.Fatalf("ALAC audioFormatIndex = %#x, want 0x12", got)
	}
	if got := AudioCodecAACELD.AudioFormatIndex(); got != 0x18 {
		t.Fatalf("AAC-ELD audioFormatIndex = %#x, want 0x18", got)
	}
}

func TestAudioLatencySamplesForCodec(t *testing.T) {
	tests := []struct {
		name     string
		ct       byte
		override uint32
		want     uint32
	}{
		{name: "default ALAC", ct: byte(AudioCodecALAC), want: 3750},
		{name: "default AAC-ELD", ct: byte(AudioCodecAACELD), want: 7497},
		{name: "override wins", ct: byte(AudioCodecALAC), override: 11025, want: 11025},
		{name: "unknown codec falls back", ct: 99, want: 7497},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := audioLatencySamplesForCodec(tt.ct, tt.override); got != tt.want {
				t.Fatalf("audioLatencySamplesForCodec(%d, %d) = %d, want %d", tt.ct, tt.override, got, tt.want)
			}
		})
	}
}

func TestAudioChaCha64AEADRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x11}, audioChaChaNonceSize)
	aad := []byte{0x90, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab}
	plaintext := []byte("doubletake mirrored audio")

	aead, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %x, want %x", opened, plaintext)
	}
	if len(sealed) != len(plaintext)+aead.Overhead() {
		t.Fatalf("sealed len = %d, want %d", len(sealed), len(plaintext)+aead.Overhead())
	}
}

func TestAudioChaCha64AEADRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x7b}, audioChaChaNonceSize)
	aad := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("auth must fail when the packet changes")

	aead, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	sealed[len(sealed)-1] ^= 0x80
	if _, err := aead.Open(nil, nonce, sealed, aad); err == nil {
		t.Fatal("expected tampered packet to fail authentication")
	}
}

func TestAudioChaCha64AEADEquivalentToZeroPrefixedIETF(t *testing.T) {
	key := bytes.Repeat([]byte{0x35}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x12}, audioChaChaNonceSize)
	aad := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	plaintext := []byte("original 64-bit nonce variant")

	custom, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}
	customSealed := custom.Seal(nil, nonce, plaintext, aad)

	ietf, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New returned error: %v", err)
	}
	ietfNonce := make([]byte, chacha20poly1305.NonceSize)
	copy(ietfNonce[4:], nonce)
	ietfSealed := ietf.Seal(nil, ietfNonce, plaintext, aad)

	if !bytes.Equal(customSealed, ietfSealed) {
		t.Fatal("expected the 64-bit nonce construction to match the zero-prefixed IETF form while the counter stays within 32 bits")
	}
}

func TestAudioChaChaAADUsesRTPNetworkOrder(t *testing.T) {
	as := &AudioStream{
		ssrc:          0x11223344,
		chachaAADMode: audioChaChaAADTimestampSSRC,
	}
	header := []byte{0x80, 0x60, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x11, 0x22, 0x33, 0x44}

	aad := as.audioChaChaAAD(header, 0x12345678)
	want := []byte{0x12, 0x34, 0x56, 0x78, 0x11, 0x22, 0x33, 0x44}
	if !bytes.Equal(aad, want) {
		t.Fatalf("AAD = %x, want %x", aad, want)
	}
}
