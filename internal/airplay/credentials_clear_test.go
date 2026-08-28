package airplay

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

func TestCredentialStoreClearRestoreTokenPreservesPairingAndOtherDevices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.SavePairing("device-1", "pair-1", pub, priv, PairingProtocolHAP); err != nil {
		t.Fatalf("SavePairing: %v", err)
	}
	if err := store.SaveRestoreToken("device-1", "restore-1"); err != nil {
		t.Fatalf("SaveRestoreToken device-1: %v", err)
	}
	if err := store.SaveRestoreToken("device-2", "restore-2"); err != nil {
		t.Fatalf("SaveRestoreToken device-2: %v", err)
	}

	if err := store.ClearRestoreToken("device-1"); err != nil {
		t.Fatalf("ClearRestoreToken: %v", err)
	}

	reloaded, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("reload credential store: %v", err)
	}
	cleared := reloaded.Lookup("device-1")
	if cleared == nil || !cleared.HasPairingCredentials() {
		t.Fatal("clearing the restore token removed pairing credentials")
	}
	if cleared.PairingID != "pair-1" || cleared.PairingProtocol != PairingProtocolHAP {
		t.Fatalf("pairing metadata changed: %+v", cleared)
	}
	if cleared.RestoreToken != "" {
		t.Fatalf("restore token = %q, want empty", cleared.RestoreToken)
	}
	other := reloaded.Lookup("device-2")
	if other == nil || other.RestoreToken != "restore-2" {
		t.Fatalf("other device changed: %+v", other)
	}
}

type recordingCredentialBackend struct {
	devices map[string]*SavedCredentials
	saves   []string
}

func (b *recordingCredentialBackend) Lookup(deviceID string) (*SavedCredentials, error) {
	return b.devices[deviceID], nil
}

func (b *recordingCredentialBackend) Save(deviceID string, creds *SavedCredentials) error {
	b.devices[deviceID] = creds
	b.saves = append(b.saves, deviceID)
	return nil
}

func TestCredentialStoreClearRestoreTokenRollsBackFileBackendAfterPersistFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	if err := store.SaveRestoreToken("device-1", "restore-1"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}

	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("block mkdir"), 0600); err != nil {
		t.Fatalf("create blocked parent: %v", err)
	}
	backend := store.backend.(*fileBackend)
	backend.path = filepath.Join(blockedParent, "credentials.json")

	if err := store.ClearRestoreToken("device-1"); err == nil {
		t.Fatal("ClearRestoreToken unexpectedly succeeded with an invalid credential path")
	}
	creds := store.Lookup("device-1")
	if creds == nil || creds.RestoreToken != "restore-1" {
		t.Fatalf("failed persistence changed in-memory credentials: %+v", creds)
	}
}

func TestCredentialStoreClearRestoreTokenUsesBackendWithoutDeletingEntry(t *testing.T) {
	backend := &recordingCredentialBackend{devices: map[string]*SavedCredentials{
		"device-1": {PairingID: "pair-1", RestoreToken: "restore-1"},
	}}
	store := NewCredentialStoreWithBackend(backend)

	if err := store.ClearRestoreToken("device-1"); err != nil {
		t.Fatalf("ClearRestoreToken: %v", err)
	}

	if len(backend.saves) != 1 || backend.saves[0] != "device-1" {
		t.Fatalf("backend saves = %v, want [device-1]", backend.saves)
	}
	creds := backend.devices["device-1"]
	if creds == nil || creds.PairingID != "pair-1" || creds.RestoreToken != "" {
		t.Fatalf("backend credentials after clear = %+v", creds)
	}
}

func TestRestoreTokenResetRollbackMergesConcurrentCredentialChanges(t *testing.T) {
	backend := &recordingCredentialBackend{devices: map[string]*SavedCredentials{
		"device-1": {PairingID: "pair-1", RestoreToken: "restore-1"},
	}}
	store := NewCredentialStoreWithBackend(backend)

	reset, err := store.BeginRestoreTokenReset("device-1")
	if err != nil {
		t.Fatalf("BeginRestoreTokenReset: %v", err)
	}
	backend.devices["device-1"] = &SavedCredentials{
		PairingID:    "pair-2",
		RestoreToken: "",
	}

	if err := reset.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	creds := backend.devices["device-1"]
	if creds.PairingID != "pair-2" || creds.RestoreToken != "restore-1" {
		t.Fatalf("credentials after rollback = %+v", creds)
	}
}

func TestRestoreTokenResetRollbackDoesNotOverwriteConcurrentToken(t *testing.T) {
	backend := &recordingCredentialBackend{devices: map[string]*SavedCredentials{
		"device-1": {RestoreToken: "restore-1"},
	}}
	store := NewCredentialStoreWithBackend(backend)

	reset, err := store.BeginRestoreTokenReset("device-1")
	if err != nil {
		t.Fatalf("BeginRestoreTokenReset: %v", err)
	}
	backend.devices["device-1"] = &SavedCredentials{RestoreToken: "restore-2"}

	if err := reset.Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got := backend.devices["device-1"].RestoreToken; got != "restore-2" {
		t.Fatalf("restore token after rollback = %q, want concurrent token", got)
	}
}
