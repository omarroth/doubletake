package airplay

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

// The stream master key is either the raw FairPlay key or its SHA-512 mixture
// with the pair-verify secret, according to the mode requested during pairing.
// This is independent of the control channel framing and encryption.
func TestDeriveStreamMasterKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0xa5}, 16)
	secret := bytes.Repeat([]byte{0x5a}, 32)

	h := sha512.New()
	h.Write(raw)
	h.Write(secret)
	mixed := h.Sum(nil)[:16]

	for _, tc := range []struct {
		name      string
		secret    []byte
		mixSecret bool
		want      []byte
	}{
		// The case issue #17 was about: rawPairVerify leaves a shared secret
		// behind, but the receiver only ever saw ekey, which wraps the raw key.
		{"mix not requested, secret present", secret, false, raw},
		{"mix not requested, no secret", nil, false, raw},
		{"mix requested", secret, true, mixed},
		{"mix requested but no secret", nil, true, raw},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveStreamMasterKey(raw, tc.secret, tc.mixSecret)
			if !bytes.Equal(got, tc.want) {
				t.Fatalf("got %x, want %x", got, tc.want)
			}
		})
	}
}

// The two branches must not coincide, or the test above proves nothing.
func TestDeriveStreamMasterKeyBranchesDiffer(t *testing.T) {
	raw := bytes.Repeat([]byte{0xa5}, 16)
	secret := bytes.Repeat([]byte{0x5a}, 32)
	if bytes.Equal(
		deriveStreamMasterKey(raw, secret, false),
		deriveStreamMasterKey(raw, secret, true),
	) {
		t.Fatal("unmixed and mixed derivations produce the same key")
	}
}
