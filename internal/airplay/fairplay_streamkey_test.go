package airplay

import (
	"bytes"
	"crypto/sha512"
	"testing"
)

// The stream master key must be the raw FairPlay key on a legacy receiver and
// the SHA-512 mixture on a HAP-paired one. The discriminator is whether the
// channel is HAP-encrypted, not whether a shared secret happens to exist --
// rawPairVerify stores one even though it leaves the channel unencrypted.
func TestDeriveStreamMasterKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0xa5}, 16)
	secret := bytes.Repeat([]byte{0x5a}, 32)

	h := sha512.New()
	h.Write(raw)
	h.Write(secret)
	mixed := h.Sum(nil)[:16]

	for _, tc := range []struct {
		name         string
		secret       []byte
		hapEncrypted bool
		want         []byte
	}{
		// The case issue #17 was about: rawPairVerify leaves a shared secret
		// behind, but the receiver only ever saw ekey, which wraps the raw key.
		{"legacy pairing, secret present", secret, false, raw},
		{"legacy pairing, no secret", nil, false, raw},
		{"HAP pairing", secret, true, mixed},
		{"HAP flagged but no secret", nil, true, raw},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveStreamMasterKey(raw, tc.secret, tc.hapEncrypted)
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
		t.Fatal("legacy and HAP derivations produce the same key")
	}
}

// rawPairVerify must keep leaving the channel unencrypted, since that flag is
// what now selects the derivation. If it ever sets c.encrypted, legacy
// receivers silently regress to the mixed key and the picture goes black again.
func TestRawPairVerifyDoesNotEnableHAPEncryption(t *testing.T) {
	if !bytes.Contains(readSource(t, "pairing.go"), []byte("c.PairKeys.SharedSecret = shared")) {
		t.Skip("pairing.go no longer stores a shared secret in the expected form")
	}
	src := readSource(t, "pairing.go")
	start := bytes.Index(src, []byte("func (c *AirPlayClient) rawPairVerify"))
	if start < 0 {
		t.Skip("rawPairVerify not found")
	}
	body := src[start:]
	if end := bytes.Index(body, []byte("\nfunc ")); end > 0 {
		body = body[:end]
	}
	if bytes.Contains(body, []byte("c.encrypted = true")) {
		t.Error("rawPairVerify now enables HAP encryption; deriveStreamMasterKey " +
			"would switch legacy receivers to the mixed key (see issue #17)")
	}
}
