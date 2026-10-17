package airplay

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
)

// ReceiverIdentity is a receiver's long-term pairing identity: its pairing
// identifier and Ed25519 public key, learned and proven during pair-setup.
//
// It is what lets a later pair-verify prove that the receiver on the other end
// is the one this machine paired with. Without it, pair-verify accepts any
// X25519 key from any device that answers at the receiver's address -- a LAN
// impersonator of an already-paired receiver gets the encrypted control channel,
// and the screen with it, without ever proving who it is.
type ReceiverIdentity struct {
	// ID is the receiver's HAP pairing identifier. It is empty for raw AirPlay
	// pairings, which carry no identifier.
	ID string
	// PublicKey is the receiver's long-term Ed25519 public key.
	PublicKey ed25519.PublicKey
}

// valid reports whether the identity can verify a signature.
func (r *ReceiverIdentity) valid() bool {
	return r != nil && len(r.PublicKey) == ed25519.PublicKeySize
}

func (r *ReceiverIdentity) clone() *ReceiverIdentity {
	if r == nil {
		return nil
	}
	return &ReceiverIdentity{ID: r.ID, PublicKey: append(ed25519.PublicKey(nil), r.PublicKey...)}
}

// ErrReceiverNotAuthenticated means a receiver failed to prove it is the one
// this machine paired with -- or there was nothing to check it against.
//
// It is a distinct error because the caller's duty on seeing it differs from
// every other pairing failure: it must not fall back to another pairing mode.
// Falling back to transient pairing, which authenticates nobody, would hand the
// stream to exactly the device that just failed to prove its identity.
var ErrReceiverNotAuthenticated = errors.New("receiver did not prove its pairing identity")

// verifyReceiverSignature checks that the receiver identified by want signed
// message, and that it named itself as want.
func verifyReceiverSignature(want *ReceiverIdentity, identifier, message, signature []byte) error {
	if !want.valid() {
		return fmt.Errorf("%w: no saved receiver key to verify against", ErrReceiverNotAuthenticated)
	}
	if want.ID != "" && !bytes.Equal(identifier, []byte(want.ID)) {
		return fmt.Errorf("%w: it identified itself as %q, not the paired %q",
			ErrReceiverNotAuthenticated, identifier, want.ID)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(want.PublicKey, message, signature) {
		return fmt.Errorf("%w: its signature does not match the paired receiver's key",
			ErrReceiverNotAuthenticated)
	}
	return nil
}
