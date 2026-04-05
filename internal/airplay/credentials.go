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

const DefaultCredentialsFile = "airplay-credentials.json"

// DefaultCredentialStorePath returns ~/.config/doubletake/credentials.json.
func DefaultCredentialStorePath() string {
	dir := os.Getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "doubletake", "credentials.json")
}

// SaveCredentials writes pairing credentials to disk (legacy single-device format).
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

// LoadCredentials reads pairing credentials from disk (legacy single-device format).
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
	// Try multi-device format first
	if err := json.Unmarshal(data, &cs.devices); err != nil {
		// Fall back to legacy single-device format
		var single SavedCredentials
		if err2 := json.Unmarshal(data, &single); err2 != nil {
			return nil, fmt.Errorf("unmarshal credential store: %w", err)
		}
		// Store under empty key — will be re-keyed on first successful connect
		if single.PairingID != "" {
			cs.devices[""] = &single
		}
	}
	return cs, nil
}

// Lookup returns saved credentials for a device, or nil if not found.
func (cs *CredentialStore) Lookup(deviceID string) *SavedCredentials {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	if creds := cs.devices[deviceID]; creds != nil {
		return creds
	}
	// Check legacy empty-key entry
	return cs.devices[""]
}

// Len returns the number of stored credential entries.
func (cs *CredentialStore) Len() int {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	return len(cs.devices)
}

// Import adds a credential entry without persisting (used for legacy migration at startup).
func (cs *CredentialStore) Import(deviceID string, creds *SavedCredentials) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	cs.devices[deviceID] = creds
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
	// Remove legacy empty-key entry if we now have a proper key
	if deviceID != "" {
		delete(cs.devices, "")
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
