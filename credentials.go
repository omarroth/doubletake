package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
)

// SavedCredentials holds the persistent pairing credentials.
type SavedCredentials struct {
	PairingID     string `json:"pairing_id"`
	Ed25519Public []byte `json:"ed25519_public"`
	Ed25519Seed   []byte `json:"ed25519_seed"` // 32-byte seed (private key is derived from this)
}

const defaultCredentialsFile = "airplay-credentials.json"

// SaveCredentials writes pairing credentials to disk.
func SaveCredentials(path string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	creds := SavedCredentials{
		PairingID:     pairingID,
		Ed25519Public: []byte(pub),
		Ed25519Seed:   priv.Seed(),
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	return nil
}

// LoadCredentials reads pairing credentials from disk.
// Returns nil, nil if the file doesn't exist.
func LoadCredentials(path string) (*SavedCredentials, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read credentials: %w", err)
	}
	var creds SavedCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}
	return &creds, nil
}

// Ed25519Keys reconstructs the key pair from saved credentials.
func (c *SavedCredentials) Ed25519Keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	priv := ed25519.NewKeyFromSeed(c.Ed25519Seed)
	return ed25519.PublicKey(c.Ed25519Public), priv
}
