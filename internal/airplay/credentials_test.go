package airplay

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"os"
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

func TestCredentialStorePersistsNegotiatedPairingProtocol(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	receiverPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	receiver := &ReceiverIdentity{PublicKey: receiverPub}
	if err := store.SavePairing("raw-device", "pair-id", pub, priv, PairingProtocolRaw, receiver); err != nil {
		t.Fatalf("SavePairing: %v", err)
	}
	if err := store.SaveRestoreToken("raw-device", "restore-token"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}

	reloaded, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("reload credential store: %v", err)
	}
	creds := reloaded.Lookup("raw-device")
	if creds == nil {
		t.Fatal("reloaded credentials are missing")
	}
	if creds.PairingProtocol != PairingProtocolRaw {
		t.Fatalf("reloaded pairing protocol = %q, want %q", creds.PairingProtocol, PairingProtocolRaw)
	}
	if creds.RestoreToken != "restore-token" {
		t.Fatalf("restore token = %q", creds.RestoreToken)
	}

	client := NewAirPlayClient("127.0.0.1", 7000)
	if err := client.RestorePairingCredentials(creds); err != nil {
		t.Fatalf("RestorePairingCredentials: %v", err)
	}
	if got := client.PairingProtocol(); got != PairingProtocolRaw {
		t.Fatalf("restored protocol = %q, want %q", got, PairingProtocolRaw)
	}
}

func TestLegacyCredentialEntryInfersProtocolFromCapabilities(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("NewCredentialStore: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// Save is the compatibility API used by releases which predate the protocol
	// field. It deliberately leaves the optional JSON member absent.
	if err := store.Save("old-device", "pair-id", pub, priv); err != nil {
		t.Fatalf("Save: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if bytes.Contains(data, []byte("pairing_protocol")) {
		t.Fatalf("legacy credential unexpectedly contains pairing_protocol: %s", data)
	}

	reloaded, err := NewCredentialStore(path)
	if err != nil {
		t.Fatalf("reload credential store: %v", err)
	}
	creds := reloaded.Lookup("old-device")
	if creds == nil {
		t.Fatal("reloaded old-schema credentials are missing")
	}
	if creds.PairingProtocol != PairingProtocolUnknown {
		t.Fatalf("old-schema protocol = %q, want unknown", creds.PairingProtocol)
	}
	for _, test := range []struct {
		name     string
		info     *ReceiverInfo
		protocol PairingProtocol
	}{
		{
			name: "modern HAP capabilities",
			info: &ReceiverInfo{Features: FeatureSystemPairing |
				FeatureTransientPairing | uint64(1<<38)},
			protocol: PairingProtocolHAP,
		},
		{
			name:     "legacy raw capabilities",
			info:     &ReceiverInfo{Features: FeatureLegacyPairing},
			protocol: PairingProtocolRaw,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := NewAirPlayClient("127.0.0.1", 7000)
			client.info = test.info
			if err := client.RestorePairingCredentials(creds); err != nil {
				t.Fatalf("RestorePairingCredentials: %v", err)
			}
			if got := client.PairingProtocol(); got != test.protocol {
				t.Fatalf("restored protocol = %q, want %q", got, test.protocol)
			}
		})
	}
}

func TestRestorePairingCredentialsRejectsUnknownProtocol(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	client := NewAirPlayClient("127.0.0.1", 7000)
	err = client.RestorePairingCredentials(&SavedCredentials{
		PairingID:       "pair-id",
		Ed25519Public:   pub,
		Ed25519Seed:     priv.Seed(),
		PairingProtocol: PairingProtocol("future-protocol"),
	})
	if err == nil {
		t.Fatal("RestorePairingCredentials accepted an unknown protocol")
	}
	if client.PairKeys != nil || client.PairingProtocol() != PairingProtocolUnknown {
		t.Fatal("failed restore partially mutated the client")
	}
}
