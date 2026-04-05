package airplay

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// SavedCredentials holds the persistent pairing credentials for a single device.
type SavedCredentials struct {
	PairingID     string `json:"pairing_id"`
	Ed25519Public []byte `json:"ed25519_public"`
	Ed25519Seed   []byte `json:"ed25519_seed"` // 32-byte seed (private key is derived from this)
}

// DefaultCredentialsPath returns ~/.config/doubletake/credentials.json.
func DefaultCredentialsPath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "doubletake", "credentials.json")
}

// Ed25519Keys reconstructs the key pair from saved credentials.
func (c *SavedCredentials) Ed25519Keys() (ed25519.PublicKey, ed25519.PrivateKey) {
	if len(c.Ed25519Seed) != ed25519.SeedSize {
		return nil, nil
	}
	priv := ed25519.NewKeyFromSeed(c.Ed25519Seed)
	return ed25519.PublicKey(c.Ed25519Public), priv
}

// CredentialStore manages per-device pairing credentials keyed by DeviceID.
type CredentialStore struct {
	mu      sync.Mutex
	path    string
	devices map[string]*SavedCredentials // DeviceID -> credentials
}

// NewCredentialStore creates or loads a credential store at the given path.
func NewCredentialStore(path string) (*CredentialStore, error) {
	cs := &CredentialStore{
		path:    path,
		devices: make(map[string]*SavedCredentials),
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cs, nil
		}
		return nil, fmt.Errorf("read credential store: %w", err)
	}
	if err := json.Unmarshal(data, &cs.devices); err != nil {
		return nil, fmt.Errorf("unmarshal credential store: %w", err)
	}
	return cs, nil
}

// Lookup returns saved credentials for a device, or nil if not found.
func (cs *CredentialStore) Lookup(deviceID string) *SavedCredentials {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return cs.devices[deviceID]
}

// Len returns the number of stored credential entries.
func (cs *CredentialStore) Len() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.devices)
}

// Save stores credentials for a device and persists to disk.
func (cs *CredentialStore) Save(deviceID string, pairingID string, pub ed25519.PublicKey, priv ed25519.PrivateKey) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	cs.devices[deviceID] = &SavedCredentials{
		PairingID:     pairingID,
		Ed25519Public: []byte(pub),
		Ed25519Seed:   priv.Seed(),
	}
	return cs.persist()
}

func (cs *CredentialStore) persist() error {
	dir := filepath.Dir(cs.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create credential dir: %w", err)
	}
	data, err := json.MarshalIndent(cs.devices, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal credential store: %w", err)
	}
	if err := os.WriteFile(cs.path, data, 0600); err != nil {
		return fmt.Errorf("write credential store: %w", err)
	}
	return nil
}
