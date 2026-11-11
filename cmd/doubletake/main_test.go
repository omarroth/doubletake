package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"doubletake/internal/airplay"
)

func TestDiscoverDevicesUntilFoundRetriesEmptyScans(t *testing.T) {
	calls := 0
	want := []airplay.AirPlayDevice{{Name: "Living Room", IP: "192.0.2.10"}}
	got, err := discoverDevicesUntilFound(t.Context(), time.Second, 0, func(context.Context) ([]airplay.AirPlayDevice, error) {
		calls++
		if calls < 3 {
			return nil, nil
		}
		return want, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 3 || len(got) != 1 || got[0].Name != want[0].Name || got[0].IP != want[0].IP {
		t.Fatalf("discovery calls=%d devices=%+v, want 3 and %+v", calls, got, want)
	}
}

func TestDiscoverDevicesUntilFoundRetriesCompletedWindowError(t *testing.T) {
	calls := 0
	got, err := discoverDevicesUntilFound(t.Context(), time.Second, 0, func(context.Context) ([]airplay.AirPlayDevice, error) {
		calls++
		if calls == 1 {
			return nil, fmt.Errorf("browse window: %w", context.DeadlineExceeded)
		}
		return []airplay.AirPlayDevice{{Name: "Office"}}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(got) != 1 || got[0].Name != "Office" {
		t.Fatalf("discovery calls=%d devices=%+v, want a retry and Office", calls, got)
	}
}

func TestDiscoverDevicesUntilFoundHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	_, err := discoverDevicesUntilFound(ctx, time.Second, time.Second, func(context.Context) ([]airplay.AirPlayDevice, error) {
		calls++
		return nil, nil
	})
	if !errors.Is(err, context.Canceled) || calls != 0 {
		t.Fatalf("discovery error=%v calls=%d, want context cancellation before browse", err, calls)
	}
}

func TestDiscoverDevicesUntilFoundReturnsFatalError(t *testing.T) {
	want := errors.New("browse failed")
	_, err := discoverDevicesUntilFound(t.Context(), time.Second, 0, func(context.Context) ([]airplay.AirPlayDevice, error) {
		return nil, want
	})
	if !errors.Is(err, want) {
		t.Fatalf("discovery error=%v, want %v", err, want)
	}
}

func TestParsePortRange(t *testing.T) {
	for _, test := range []struct {
		name       string
		value      string
		wantMin    int
		wantMax    int
		wantErrSub string
	}{
		{name: "ephemeral"},
		{name: "valid", value: "60000-60010", wantMin: 60000, wantMax: 60010},
		{name: "whitespace", value: " 60000 - 60002 ", wantMin: 60000, wantMax: 60002},
		{name: "malformed", value: "60000", wantErrSub: "expected MIN-MAX"},
		{name: "minimum invalid", value: "zero-60010", wantErrSub: "min:"},
		{name: "maximum invalid", value: "60000-many", wantErrSub: "max:"},
		{name: "zero", value: "0-2", wantErrSub: "out of bounds"},
		{name: "maximum too high", value: "65534-65536", wantErrSub: "out of bounds"},
		{name: "reversed", value: "60010-60000", wantErrSub: "out of bounds"},
		{name: "too small", value: "60000-60001", wantErrSub: "too small"},
	} {
		t.Run(test.name, func(t *testing.T) {
			gotMin, gotMax, err := parsePortRange(test.value)
			if test.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("parsePortRange(%q) error = %v, want substring %q", test.value, err, test.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePortRange(%q): %v", test.value, err)
			}
			if gotMin != test.wantMin || gotMax != test.wantMax {
				t.Fatalf("parsePortRange(%q) = %d-%d, want %d-%d", test.value, gotMin, gotMax, test.wantMin, test.wantMax)
			}
		})
	}
}

func TestParseVideoTarget(t *testing.T) {
	for _, test := range []struct {
		name       string
		value      string
		want       videoTarget
		wantErrSub string
	}{
		{name: "maximum", value: "max"},
		{name: "maximum with refresh", value: "max@60", want: videoTarget{refreshRate: 60}},
		{name: "resolution", value: "1920x1080", want: videoTarget{width: 1920, height: 1080}},
		{name: "upper-case separator", value: " 1280X720@30 ", want: videoTarget{width: 1280, height: 720, refreshRate: 30}},
		{name: "empty", wantErrSub: "expected max"},
		{name: "missing height", value: "1920", wantErrSub: "expected max"},
		{name: "extra dimension", value: "1920x1080x60", wantErrSub: "expected max"},
		{name: "zero width", value: "0x1080", wantErrSub: "2 to 9999"},
		{name: "too large", value: "10000x1080", wantErrSub: "2 to 9999"},
		{name: "empty refresh", value: "1920x1080@", wantErrSub: "refresh rate"},
		{name: "zero refresh", value: "1920x1080@0", wantErrSub: "refresh rate"},
		{name: "large refresh", value: "1920x1080@256", wantErrSub: "refresh rate"},
		{name: "extra refresh", value: "1920x1080@60@30", wantErrSub: "expected max"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseVideoTarget(test.value)
			if test.wantErrSub != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
					t.Fatalf("parseVideoTarget(%q) error = %v, want substring %q", test.value, err, test.wantErrSub)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseVideoTarget(%q): %v", test.value, err)
			}
			if got != test.want {
				t.Fatalf("parseVideoTarget(%q) = %+v, want %+v", test.value, got, test.want)
			}
		})
	}
}

func TestReadCredentialPreservesPasswordAndEmptyInput(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("password with spaces\n\n"))
	if got := readCredential(reader, ""); got != "password with spaces" {
		t.Fatalf("password = %q, want %q", got, "password with spaces")
	}
	if got := readCredential(reader, ""); got != "" {
		t.Fatalf("blank password choice = %q, want empty", got)
	}
}

func TestPairingCredentialPrompt(t *testing.T) {
	for _, test := range []struct {
		name       string
		expectPIN  bool
		displayErr error
		want       string
	}{
		{name: "advertised PIN displayed", expectPIN: true, want: "Enter the PIN shown on the receiver: "},
		{name: "advertised PIN display failed", expectPIN: true, displayErr: errors.New("display failed"), want: "Enter the receiver's configured password or pairing PIN: "},
		{name: "unknown mode accepted display request", want: "Enter the receiver's configured password or pairing PIN: "},
		{name: "unknown mode rejected display request", displayErr: errors.New("not supported"), want: "Enter the receiver's configured password or pairing PIN: "},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := pairingCredentialPrompt(test.expectPIN, test.displayErr); got != test.want {
				t.Fatalf("prompt = %q, want %q", got, test.want)
			}
		})
	}
}

func TestPasswordRequiresPairing(t *testing.T) {
	const (
		passwordFlag = uint64(1 << 7)
		pinFlag      = uint64(1 << 9)
	)
	modernFeatures := airplay.FeatureSystemPairing | airplay.FeatureTransientPairing | uint64(1<<38) | uint64(1<<46)
	thirdPartyModernFeatures := modernFeatures | uint64(1<<51)
	legacyFeatures := airplay.FeatureLegacyPairing | uint64(1<<51)

	for _, test := range []struct {
		name string
		info *airplay.ReceiverInfo
		want bool
	}{
		{name: "missing info"},
		{name: "legacy configured password", info: &airplay.ReceiverInfo{Features: legacyFeatures, StatusFlags: passwordFlag}, want: true},
		{name: "modern configured password can pair transiently", info: &airplay.ReceiverInfo{Features: modernFeatures, StatusFlags: passwordFlag}},
		{name: "third-party configured password starts with authenticated legacy probe", info: &airplay.ReceiverInfo{Features: thirdPartyModernFeatures, StatusFlags: passwordFlag}, want: true},
		{name: "modern password suppresses PIN but remains Digest only", info: &airplay.ReceiverInfo{Features: modernFeatures, StatusFlags: passwordFlag | pinFlag}},
		{name: "legacy password wins over PIN", info: &airplay.ReceiverInfo{Features: legacyFeatures, StatusFlags: passwordFlag | pinFlag}, want: true},
		{name: "legacy receiver without password", info: &airplay.ReceiverInfo{Features: legacyFeatures}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := passwordRequiresPairing(test.info); got != test.want {
				t.Fatalf("passwordRequiresPairing() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestForcePairDoesNotUseModernDigestPasswordAsSRPPIN(t *testing.T) {
	const passwordFlag = uint64(1 << 7)
	modernFeatures := airplay.FeatureSystemPairing | airplay.FeatureTransientPairing | uint64(1<<38) | uint64(1<<46)
	thirdPartyModernFeatures := modernFeatures | uint64(1<<51)
	legacyFeatures := airplay.FeatureLegacyPairing | uint64(1<<51)

	if !forcePairUsesTransient(&airplay.ReceiverInfo{Features: modernFeatures, StatusFlags: passwordFlag}) {
		t.Fatal("modern fixed-password receiver would reuse its Digest password as an SRP PIN")
	}
	if forcePairUsesTransient(&airplay.ReceiverInfo{Features: legacyFeatures, StatusFlags: passwordFlag}) {
		t.Fatal("legacy fixed-password receiver lost its authenticated SRP pairing path")
	}
	if forcePairUsesTransient(&airplay.ReceiverInfo{Features: thirdPartyModernFeatures, StatusFlags: passwordFlag}) {
		t.Fatal("third-party fixed-password receiver lost its authenticated SRP probe")
	}
	if forcePairUsesTransient(&airplay.ReceiverInfo{Features: modernFeatures}) {
		t.Fatal("unprotected modern receiver unexpectedly bypassed explicit full pairing")
	}
}

func TestRestoreSavedPairingRestoresRawProtocol(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	client := airplay.NewAirPlayClient("127.0.0.1", 7000)
	err = restoreSavedPairing(client, &airplay.SavedCredentials{
		PairingID:       "pair-id",
		Ed25519Public:   pub,
		Ed25519Seed:     priv.Seed(),
		PairingProtocol: airplay.PairingProtocolRaw,
	})
	if err != nil {
		t.Fatalf("restoreSavedPairing: %v", err)
	}
	if got := client.PairingProtocol(); got != airplay.PairingProtocolRaw {
		t.Fatalf("restored protocol = %q, want raw", got)
	}
}
