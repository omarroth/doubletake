package airplay

import (
	"encoding/json"
	"fmt"

	"github.com/zalando/go-keyring"
)

const keyringService = "doubletake"

// keyringBackend stores credentials in the system keyring via the
// freedesktop.org Secret Service API (GNOME Keyring, KDE Wallet, KeePassXC, etc.).
type keyringBackend struct{}

// NewKeyringBackend creates a CredentialBackend that uses the system keyring.
func NewKeyringBackend() (CredentialBackend, error) {
	// Verify the keyring is reachable by doing a no-op lookup.
	_, err := keyring.Get(keyringService, "__probe__")
	if err != nil && err != keyring.ErrNotFound {
		return nil, fmt.Errorf("system keyring not available: %w", err)
	}
	return &keyringBackend{}, nil
}

func (kb *keyringBackend) Lookup(deviceID string) (*SavedCredentials, error) {
	data, err := keyring.Get(keyringService, deviceID)
	if err != nil {
		if err == keyring.ErrNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("keyring lookup %s: %w", deviceID, err)
	}
	var creds SavedCredentials
	if err := json.Unmarshal([]byte(data), &creds); err != nil {
		return nil, fmt.Errorf("keyring unmarshal %s: %w", deviceID, err)
	}
	return &creds, nil
}

func (kb *keyringBackend) Save(deviceID string, creds *SavedCredentials) error {
	data, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("keyring marshal %s: %w", deviceID, err)
	}
	if err := keyring.Set(keyringService, deviceID, string(data)); err != nil {
		return fmt.Errorf("keyring save %s: %w", deviceID, err)
	}
	return nil
}
