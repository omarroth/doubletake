package airplay

import (
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func TestCredentialStoreSaveRestoreTokenPreservesPairingCredentials(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}

	pub1, priv1, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.Save("device-1", "pair-1", pub1, priv1); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := store.SaveRestoreToken("device-1", "restore-1"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}

	pub2, priv2, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.Save("device-1", "pair-2", pub2, priv2); err != nil {
		t.Fatalf("Save second pairing: %v", err)
	}

	creds := store.Lookup("device-1")
	if creds == nil {
		t.Fatal("Lookup returned nil")
	}
	if !creds.HasPairingCredentials() {
		t.Fatal("expected pairing credentials to remain usable")
	}
	if creds.PairingID != "pair-2" {
		t.Fatalf("PairingID = %q, want %q", creds.PairingID, "pair-2")
	}
	if creds.RestoreToken != "restore-1" {
		t.Fatalf("RestoreToken = %q, want %q", creds.RestoreToken, "restore-1")
	}

	gotPub, gotPriv := creds.Ed25519Keys()
	if gotPriv == nil {
		t.Fatal("Ed25519Keys returned nil private key")
	}
	if string(gotPub) != string(pub2) {
		t.Fatal("stored public key did not match latest saved key")
	}
	if string(gotPriv.Seed()) != string(priv2.Seed()) {
		t.Fatal("stored private seed did not match latest saved key")
	}
}

func TestCredentialStoreSaveRestoreTokenCreatesTokenOnlyEntry(t *testing.T) {
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}

	if err := store.SaveRestoreToken("device-2", "restore-only"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}

	creds := store.Lookup("device-2")
	if creds == nil {
		t.Fatal("Lookup returned nil")
	}
	if creds.HasPairingCredentials() {
		t.Fatal("expected token-only entry to have no pairing credentials")
	}
	if creds.RestoreToken != "restore-only" {
		t.Fatalf("RestoreToken = %q, want %q", creds.RestoreToken, "restore-only")
	}
}
