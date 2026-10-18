package airplay

import "testing"

// Exercise authentication independently of each profile's media capabilities.
// In particular, raw-only video fixtures cannot display HAP-encrypted video,
// but must still verify fresh and reconnected controller identities correctly.
func TestReceiverPairingAndReconnectMatrix(t *testing.T) {
	for _, profile := range []ReceiverProfile{
		ReceiverProfileModern, ReceiverProfileRoku, ReceiverProfileLG,
		ReceiverProfileAppleTV3, ReceiverProfileUxPlay, ReceiverProfileAirServer,
	} {
		for _, auth := range []ReceiverAuthMode{
			ReceiverAuthNone, ReceiverAuthPIN, ReceiverAuthPassword,
			ReceiverAuthDigest, ReceiverAuthCombined,
		} {
			t.Run(string(profile)+"/"+string(auth), func(t *testing.T) {
				// These presets deliberately model no code-based pairing protocol
				// for AirServer, and no Digest-only password semantics under the
				// modern fixture's SRP-password modes. Exercise supported modes;
				// changing their fixture policy would not validate real firmware.
				if profile == ReceiverProfileAirServer && auth != ReceiverAuthNone && auth != ReceiverAuthDigest ||
					profile == ReceiverProfileModern && (auth == ReceiverAuthPassword || auth == ReceiverAuthCombined) {
					t.Skip("authentication combination is not modeled by this receiver preset")
				}
				code := "4827"
				if auth == ReceiverAuthNone {
					code = ""
				}
				server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
					Profile: profile, Auth: auth, Code: code,
					Model: "UnrelatedModel", Manufacturer: "Independent Vendor",
				})
				client.SetPassword(code)
				pairingCode := code
				if auth == ReceiverAuthDigest {
					pairingCode = ""
				}
				if err := client.Pair(ctx, pairingCode); err != nil {
					t.Fatalf("fresh pairing: %v", err)
				}
				if err := client.reconnectMirrorControl(ctx); err != nil {
					t.Fatalf("reconnected pairing: %v", err)
				}
				if stats := server.Stats(); stats.Connections != 2 || stats.PairVerify != 4 {
					t.Fatalf("pairing stats = %+v, want two fully verified connections", stats)
				}
			})
		}
	}
}
