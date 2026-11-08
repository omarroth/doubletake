package airplay

import (
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScreenLatenciesForConnectionHint(t *testing.T) {
	SetTargetLatency(0)
	t.Cleanup(func() {
		SetTargetLatency(0)
	})

	tests := []struct {
		name  string
		hint  connectionLatencyHint
		video time.Duration
		audio time.Duration
	}{
		{name: "low", hint: connectionLatencyLow, video: 40 * time.Millisecond, audio: 50 * time.Millisecond},
		{name: "normal", hint: connectionLatencyNormal, video: 75 * time.Millisecond, audio: 85 * time.Millisecond},
		{name: "high", hint: connectionLatencyHigh, video: 100 * time.Millisecond, audio: 170 * time.Millisecond},
		{name: "unknown is normal", hint: connectionLatencyHint(99), video: 75 * time.Millisecond, audio: 85 * time.Millisecond},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := screenLatenciesForHint(test.hint)
			if got.video != test.video || got.audio != test.audio {
				t.Fatalf("latencies = video %v audio %v, want video %v audio %v", got.video, got.audio, test.video, test.audio)
			}
		})
	}
}

func TestTargetLatencyOverrideAppliesJointLead(t *testing.T) {
	SetTargetLatency(120 * time.Millisecond)
	t.Cleanup(func() {
		SetTargetLatency(0)
	})

	for _, hint := range []connectionLatencyHint{connectionLatencyLow, connectionLatencyNormal, connectionLatencyHigh} {
		got := screenLatenciesForHint(hint)
		if got.video != 120*time.Millisecond || got.audio != 120*time.Millisecond {
			t.Fatalf("hint %d override = video %v audio %v, want 120ms/120ms", hint, got.video, got.audio)
		}
	}
	if got := TargetLatency(); got != 120*time.Millisecond {
		t.Fatalf("TargetLatency = %v, want 120ms", got)
	}
	if !HasExplicitTargetLatency() {
		t.Fatal("explicit target latency was not reported")
	}
	if got, want := targetLatencySamples44k1(), samplesFor44k1(120*time.Millisecond); got != want {
		t.Fatalf("audio latency = %d samples, want %d", got, want)
	}
}

func TestTargetLatencyAutomaticAndClamp(t *testing.T) {
	SetTargetLatency(0)
	if HasExplicitTargetLatency() {
		t.Fatal("automatic latency policy was reported as explicit")
	}
	t.Cleanup(func() {
		SetTargetLatency(0)
	})

	SetTargetLatency(time.Millisecond)
	if got := screenLatenciesForHint(connectionLatencyNormal); got.video != 5*time.Millisecond || got.audio != 5*time.Millisecond {
		t.Fatalf("minimum override = video %v audio %v, want 5ms/5ms", got.video, got.audio)
	}

	SetTargetLatency(3 * time.Second)
	if got := screenLatenciesForHint(connectionLatencyNormal); got.video != 2*time.Second || got.audio != 2*time.Second {
		t.Fatalf("maximum override = video %v audio %v, want 2s/2s", got.video, got.audio)
	}

	SetTargetLatency(0)
	if got := screenLatenciesForHint(connectionLatencyNormal); got.video != 75*time.Millisecond || got.audio != 85*time.Millisecond {
		t.Fatalf("automatic policy = video %v audio %v, want 75ms/85ms", got.video, got.audio)
	}
}

func TestSamplesFor44k1TruncatesFractionalSamples(t *testing.T) {
	if got := samplesFor44k1(85 * time.Millisecond); got != 3748 {
		t.Fatalf("85ms = %d samples, want truncation to 3748", got)
	}
}

func TestMinimumVideoLeadPreservesAutomaticAudioVideoDelta(t *testing.T) {
	targets := screenLatencyTargets{
		video: defaultVideoLatencyNormal,
		audio: defaultAudioLatencyNormal,
	}
	if got := targets.withMinimumVideoLead(50 * time.Millisecond); got != targets {
		t.Fatalf("unneeded minimum changed targets to %#v", got)
	}
	got := targets.withMinimumVideoLead(150 * time.Millisecond)
	if got.video != 150*time.Millisecond || got.audio != 160*time.Millisecond {
		t.Fatalf("calibrated targets = video %v audio %v, want 150ms/160ms", got.video, got.audio)
	}
}

func TestConnectionLatencyHintFollowsLocalInterface(t *testing.T) {
	classPath := t.TempDir()
	if err := os.MkdirAll(filepath.Join(classPath, "wlan0", "wireless"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(classPath, "wlan1", "phy80211"), 0o755); err != nil {
		t.Fatal(err)
	}

	interfaces := []localNetworkInterface{
		{name: "eth0", addrs: []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.10"), Mask: net.CIDRMask(24, 32)}}},
		{name: "wlan0", addrs: []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.20"), Mask: net.CIDRMask(24, 32)}}},
		{name: "wlan1", addrs: []net.Addr{&net.IPAddr{IP: net.ParseIP("2001:db8::20")}}},
	}

	tests := []struct {
		name      string
		ip        net.IP
		wantHint  connectionLatencyHint
		wantIface string
	}{
		{name: "wired", ip: net.ParseIP("192.0.2.10"), wantHint: connectionLatencyNormal, wantIface: "eth0"},
		{name: "wireless marker", ip: net.ParseIP("192.0.2.20"), wantHint: connectionLatencyHigh, wantIface: "wlan0"},
		{name: "phy marker", ip: net.ParseIP("2001:db8::20"), wantHint: connectionLatencyHigh, wantIface: "wlan1"},
		{name: "unknown", ip: net.ParseIP("192.0.2.30"), wantHint: connectionLatencyNormal, wantIface: ""},
		{name: "nil", ip: nil, wantHint: connectionLatencyNormal, wantIface: ""},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotHint, gotIface := connectionLatencyHintForLocalIP(test.ip, interfaces, classPath)
			if gotHint != test.wantHint || gotIface != test.wantIface {
				t.Fatalf("hint/interface = %s/%q, want %s/%q",
					connectionLatencyHintName(gotHint), gotIface,
					connectionLatencyHintName(test.wantHint), test.wantIface)
			}
		})
	}
}

func TestConnectionLatencyHintName(t *testing.T) {
	tests := map[connectionLatencyHint]string{
		connectionLatencyLow:     "low",
		connectionLatencyNormal:  "normal",
		connectionLatencyHigh:    "high",
		connectionLatencyHint(9): "normal",
	}
	for hint, want := range tests {
		if got := connectionLatencyHintName(hint); got != want {
			t.Fatalf("hint %d name = %q, want %q", hint, got, want)
		}
	}
}

func TestDynamicAudioLatencyProfilesMatchReferenceVariants(t *testing.T) {
	tests := []struct {
		name    string
		initial time.Duration
		want    []time.Duration
	}{
		{name: "low", initial: 50 * time.Millisecond, want: []time.Duration{50, 46, 40, 36, 30}},
		{name: "normal", initial: 85 * time.Millisecond, want: []time.Duration{85, 81, 75, 71, 65}},
		{name: "high", initial: 170 * time.Millisecond, want: []time.Duration{170, 166, 160, 156, 150}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tiers, ok := dynamicAudioLatencyTiers(samplesFor44k1(test.initial))
			if !ok || len(tiers) != len(test.want) {
				t.Fatalf("profile = %v, %t, want %d tiers", tiers, ok, len(test.want))
			}
			for index, milliseconds := range test.want {
				want := samplesFor44k1(milliseconds * time.Millisecond)
				if tiers[index] != want {
					t.Fatalf("tier %d = %v, want %v", index, audioLatencyDuration(tiers[index]), milliseconds*time.Millisecond)
				}
			}
		})
	}
	if tiers, ok := dynamicAudioLatencyTiers(samplesFor44k1(200 * time.Millisecond)); ok || tiers != nil {
		t.Fatalf("200ms profile = %v, %t, want unsupported", tiers, ok)
	}
}
