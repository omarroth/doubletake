package airplay

import "errors"

// SavedPairingStep is what to do next with a receiver this machine holds a
// saved pairing for.
type SavedPairingStep int

const (
	// SavedPairingVerified: the receiver proved it is the one paired with.
	SavedPairingVerified SavedPairingStep = iota
	// SavedPairingPairWithCode: pair again with a PIN or password -- never
	// transiently. Only the real receiver can show its PIN on its own screen,
	// so this cannot hand the stream to an impersonator.
	SavedPairingPairWithCode
	// SavedPairingPairAsNew: pair as with a receiver never seen before. Only
	// for a raw pairing saved before receiver identities were recorded: raw
	// pair-setup takes no code, so pairing again is no weaker than the first
	// time was.
	SavedPairingPairAsNew
	// SavedPairingRefuse: do not cast, and do not pair in any other way.
	SavedPairingRefuse
)

// AfterSavedPairing decides what follows a saved pairing, calling verify --
// restore the pairing and run pair-verify -- only when there is a receiver
// identity to verify against.
//
// The rule it exists to keep: once this machine has paired with a receiver,
// nothing falls back to transient pairing for it. Transient pairing
// authenticates nobody, and whether a receiver "needs no code" is read from
// /info, which the device at the address writes itself. Falling back after a
// failed verify -- as the callers used to -- let an impersonator fail on
// purpose, claim to need no code, and receive the stream.
func AfterSavedPairing(saved *SavedCredentials, info *ReceiverInfo, verify func() error) SavedPairingStep {
	raw := saved.UsesRawPairing(info)
	if !saved.HasReceiverIdentity() {
		// Nothing to authenticate it against; pair again to record one.
		if raw {
			return SavedPairingPairAsNew
		}
		return SavedPairingPairWithCode
	}
	err := verify()
	switch {
	case err == nil:
		return SavedPairingVerified
	case errors.Is(err, ErrReceiverNotAuthenticated):
		// The device answering is not the paired receiver, or will not prove
		// it. No other mode may stand in for that proof.
		return SavedPairingRefuse
	case raw:
		// A raw receiver cannot be paired with again any more securely than
		// by trusting whatever answers, so its saved pairing is not replaced
		// behind the user's back.
		return SavedPairingRefuse
	default:
		// The receiver answered as itself but would not accept this machine
		// -- typically it has forgotten it.
		return SavedPairingPairWithCode
	}
}
