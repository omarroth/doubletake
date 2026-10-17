package airplay

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"testing"
)

func TestAfterSavedPairingNeverFallsBackToTransient(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	receiverKey := ed25519.NewKeyFromSeed(pinSetupReceiverSeed).Public().(ed25519.PublicKey)
	saved := func(protocol PairingProtocol, withIdentity bool) *SavedCredentials {
		c := &SavedCredentials{
			PairingID:       "pair-id",
			Ed25519Public:   key.Public().(ed25519.PublicKey),
			Ed25519Seed:     key.Seed(),
			PairingProtocol: protocol,
		}
		if withIdentity {
			c.ReceiverPublicKey = receiverKey
			if protocol == PairingProtocolHAP {
				c.ReceiverID = pinSetupReceiverID
			}
		}
		return c
	}
	notAuthenticated := fmt.Errorf("wrapped: %w", ErrReceiverNotAuthenticated)
	forgotten := errors.New("pair-verify V4 error: 2")

	for _, test := range []struct {
		name         string
		saved        *SavedCredentials
		verifyErr    error
		want         SavedPairingStep
		wantVerified bool
	}{
		{"HAP, receiver proves itself", saved(PairingProtocolHAP, true), nil, SavedPairingVerified, true},
		{"HAP, impostor", saved(PairingProtocolHAP, true), notAuthenticated, SavedPairingRefuse, true},
		{"HAP, receiver forgot this machine", saved(PairingProtocolHAP, true), forgotten, SavedPairingPairWithCode, true},
		{"HAP saved before identities", saved(PairingProtocolHAP, false), nil, SavedPairingPairWithCode, false},
		{"raw, receiver proves itself", saved(PairingProtocolRaw, true), nil, SavedPairingVerified, true},
		{"raw, impostor", saved(PairingProtocolRaw, true), notAuthenticated, SavedPairingRefuse, true},
		{"raw, other failure", saved(PairingProtocolRaw, true), forgotten, SavedPairingRefuse, true},
		{"raw saved before identities", saved(PairingProtocolRaw, false), nil, SavedPairingPairAsNew, false},
		// Older than pairing_protocol: /info would decide whether it is raw,
		// and /info is the impersonator's. It counts as code-paired.
		{"no protocol recorded", saved(PairingProtocolUnknown, false), nil, SavedPairingPairWithCode, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			verified := false
			got := AfterSavedPairing(test.saved, func() error {
				verified = true
				return test.verifyErr
			})
			if got != test.want {
				t.Errorf("step = %d, want %d", got, test.want)
			}
			if verified != test.wantVerified {
				t.Errorf("verify called = %t, want %t", verified, test.wantVerified)
			}
		})
	}
}
