package airplay

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/grandcat/zeroconf"
)

func TestConsumeAirPlayEntriesCancellationDoesNotWaitForChannelClose(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	entries := make(chan *zeroconf.ServiceEntry)
	done := make(chan error, 1)
	go func() {
		done <- consumeAirPlayEntries(ctx, entries, nil)
	}()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("consumeAirPlayEntries() error = %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("consumeAirPlayEntries() waited for the result channel to close after cancellation")
	}
}

func TestConsumeAirPlayEntriesReportsParsedDevices(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entries := make(chan *zeroconf.ServiceEntry, 1)
	entry := zeroconf.NewServiceEntry("Living\\ Room", "_airplay._tcp", "local.")
	entry.Port = 7000
	entry.AddrIPv4 = []net.IP{net.ParseIP("192.0.2.10")}
	entry.Text = []string{"deviceid=AA:BB:CC:DD:EE:FF", "model=AppleTV14,1"}
	entries <- entry

	devices := make(chan AirPlayDevice, 1)
	done := make(chan error, 1)
	go func() {
		done <- consumeAirPlayEntries(ctx, entries, func(device AirPlayDevice) {
			devices <- device
		})
	}()

	select {
	case device := <-devices:
		if device.Name != "Living Room" || device.IP != "192.0.2.10" || device.Model != "AppleTV14,1" {
			t.Fatalf("reported device = %+v", device)
		}
		cancel()
	case <-time.After(time.Second):
		t.Fatal("consumeAirPlayEntries() did not report the parsed device")
	}
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("consumeAirPlayEntries() error = %v, want context cancellation", err)
	}
}

func TestIsAirPlayMDNSInterface(t *testing.T) {
	tests := []struct {
		name    string
		iface   net.Interface
		hasIPv4 bool
		hasIPv6 bool
		want    bool
	}{
		{
			name:    "ethernet with usable ipv4",
			iface:   testInterface("enp0s31f6", net.FlagUp|net.FlagBroadcast|net.FlagMulticast),
			hasIPv4: true,
			want:    true,
		},
		{
			name:    "wifi with usable ipv6",
			iface:   testInterface("wlan0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast),
			hasIPv6: true,
			want:    true,
		},
		{
			name:    "down interface",
			iface:   testInterface("eth0", net.FlagBroadcast|net.FlagMulticast),
			hasIPv4: true,
			want:    false,
		},
		{
			name:    "loopback interface",
			iface:   testInterface("lo", net.FlagUp|net.FlagLoopback|net.FlagMulticast),
			hasIPv4: true,
			want:    false,
		},
		{
			name:    "point to point tunnel",
			iface:   testInterface("ppp0", net.FlagUp|net.FlagPointToPoint|net.FlagMulticast),
			hasIPv4: true,
			want:    false,
		},
		{
			name:    "bluetooth pan interface",
			iface:   testInterface("bnep0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast),
			hasIPv4: true,
			want:    false,
		},
		{
			name:    "bluetooth interface",
			iface:   testInterface("bt0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast),
			hasIPv4: true,
			want:    false,
		},
		{
			name:    "docker bridge interface",
			iface:   testInterface("docker0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast),
			hasIPv4: true,
			want:    false,
		},
		{
			name:  "no usable addresses",
			iface: testInterface("eth0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast),
			want:  false,
		},
		{
			name:    "no multicast support",
			iface:   testInterface("eth0", net.FlagUp|net.FlagBroadcast),
			hasIPv4: true,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAirPlayMDNSInterface(tt.iface, tt.hasIPv4, tt.hasIPv6); got != tt.want {
				t.Fatalf("isAirPlayMDNSInterface() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMDNSAddressFamilies(t *testing.T) {
	tests := []struct {
		name     string
		addrs    []net.Addr
		wantIPv4 bool
		wantIPv6 bool
	}{
		{
			name:     "private ipv4 is usable",
			addrs:    []net.Addr{testIPNet("192.168.1.25")},
			wantIPv4: true,
		},
		{
			name:     "unique local ipv6 is usable",
			addrs:    []net.Addr{testIPNet("fd00::25")},
			wantIPv6: true,
		},
		{
			name:  "link local addresses are ignored",
			addrs: []net.Addr{testIPNet("169.254.1.2"), testIPNet("fe80::1")},
		},
		{
			name:  "loopback and unspecified addresses are ignored",
			addrs: []net.Addr{testIPNet("127.0.0.1"), testIPNet("::"), testIPNet("0.0.0.0")},
		},
		{
			name:     "mixed addresses keep usable families",
			addrs:    []net.Addr{testIPNet("fe80::1"), testIPNet("10.0.0.5"), testIPNet("fd12::5")},
			wantIPv4: true,
			wantIPv6: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotIPv4, gotIPv6 := mdnsAddressFamilies(tt.addrs)
			if gotIPv4 != tt.wantIPv4 || gotIPv6 != tt.wantIPv6 {
				t.Fatalf("mdnsAddressFamilies() = (%v, %v), want (%v, %v)", gotIPv4, gotIPv6, tt.wantIPv4, tt.wantIPv6)
			}
		})
	}
}

func TestMDNSTrafficMatchesEligibleInterfaceAddressFamilies(t *testing.T) {
	ifaces := []struct {
		iface   net.Interface
		hasIPv4 bool
		hasIPv6 bool
	}{
		{iface: testInterface("eth0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast), hasIPv4: true},
		{iface: testInterface("wlan0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast), hasIPv6: true},
		{iface: testInterface("bnep0", net.FlagUp|net.FlagBroadcast|net.FlagMulticast), hasIPv4: true},
	}

	var traffic zeroconf.IPType
	for _, candidate := range ifaces {
		if !isAirPlayMDNSInterface(candidate.iface, candidate.hasIPv4, candidate.hasIPv6) {
			continue
		}
		if candidate.hasIPv4 {
			traffic |= zeroconf.IPv4
		}
		if candidate.hasIPv6 {
			traffic |= zeroconf.IPv6
		}
	}

	if traffic != zeroconf.IPv4AndIPv6 {
		t.Fatalf("traffic = %v, want %v", traffic, zeroconf.IPv4AndIPv6)
	}
}

func TestUnescapeDNSName(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "escaped punctuation",
			in:   "Living\\ Room\\ \\(2\\)",
			want: "Living Room (2)",
		},
		{
			name: "utf8 apostrophe encoded as decimal bytes",
			in:   "Emily\\226\\128\\153s MacBook Pro",
			want: "Emily’s MacBook Pro",
		},
		{
			name: "simple ascii apostrophe remains literal",
			in:   "Emily\\'s MacBook Pro",
			want: "Emily's MacBook Pro",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := unescapeDNSName(tt.in); got != tt.want {
				t.Fatalf("unescapeDNSName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestParseFeaturesUsesLowThenHighWireOrder(t *testing.T) {
	if got, want := parseFeatures("0x89ABCDEF,0x01234567"), uint64(0x0123456789abcdef); got != want {
		t.Fatalf("parseFeatures() = 0x%x, want 0x%x", got, want)
	}
	if got, want := parseFeatures("0x1e5a7ffff7"), uint64(0x1e5a7ffff7); got != want {
		t.Fatalf("single-word parseFeatures() = 0x%x, want 0x%x", got, want)
	}
	if got := parseFeatures("not-a-feature-mask"); got != 0 {
		t.Fatalf("invalid parseFeatures() = 0x%x, want 0", got)
	}
}

func TestParseServiceEntryPreservesCapabilityAdvertisement(t *testing.T) {
	entry := zeroconf.NewServiceEntry("Living\\ Room\\ TV", "_airplay._tcp", "local.")
	entry.Port = 7000
	entry.AddrIPv4 = []net.IP{net.ParseIP("192.168.1.124")}
	entry.Text = []string{
		"deviceid=46:7F:F0:39:E3:D8",
		"fex=1d9/St5/Fzw4oY7cDg",
		"features=0x4A7FDFD5,0x3C177FDE",
		"flags=0x18644",
		"model=AppleTV14,1",
		"protovers=1.1",
		"pi=92a5af57-631f-4453-8eb2-d90aa0558dea",
		"psi=447FF039-E3D8-4828-A804-3A60F64DBFCA",
		"pk=9d6c6f7b96fd15faad5b840fca30d2399daae390a7855ce7cd85fff2c604af0e",
		"srcvers=980.77.2",
		"osvers=27.0",
		"vv=1",
	}

	device := parseServiceEntry(entry)
	if device == nil {
		t.Fatal("parseServiceEntry returned nil")
	}
	if device.Name != "Living Room TV" || device.IP != "192.168.1.124" || device.Port != 7000 {
		t.Fatalf("address fields = %+v", device)
	}
	if device.Model != "AppleTV14,1" || device.DeviceID != "46:7F:F0:39:E3:D8" {
		t.Fatalf("identity fields = %+v", device)
	}
	if device.SourceVersion != "980.77.2" || device.ProtocolVersion != "1.1" || device.VV != 1 {
		t.Fatalf("version fields = %+v", device)
	}
	if device.PI != "92a5af57-631f-4453-8eb2-d90aa0558dea" || device.PSI != "447FF039-E3D8-4828-A804-3A60F64DBFCA" {
		t.Fatalf("pairing identifiers = %+v", device)
	}
	if device.Features != 0x3c177fde4a7fdfd5 || device.Flags != 0x18644 {
		t.Fatalf("legacy features/status = (0x%x, 0x%x)", device.Features, device.Flags)
	}
	if device.FEX != "1d9/St5/Fzw4oY7cDg" || device.FeaturesEx.Low64() != device.Features {
		t.Fatalf("extended features = %q/%x", device.FEX, []byte(device.FeaturesEx))
	}
	if !device.HasFeature(99) {
		t.Fatal("extended feature bit 99 was not preserved")
	}
	if device.RawTXT["osvers"] != "27.0" || device.RawTXT["fex"] != device.FEX {
		t.Fatalf("raw TXT = %#v", device.RawTXT)
	}
}

func TestFeatureSetSupportsBitsBeyondLegacyMask(t *testing.T) {
	features, err := decodeFeatureSet("AAAAAAAAAAAI") // bit 67 in little-endian wire order
	if err != nil {
		t.Fatal(err)
	}
	if features.Has(66) || !features.Has(67) {
		t.Fatalf("decoded feature bits = %x", []byte(features))
	}
}

func testInterface(name string, flags net.Flags) net.Interface {
	return net.Interface{Name: name, Flags: flags}
}

func testIPNet(ip string) *net.IPNet {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		panic("invalid test IP: " + ip)
	}
	bits := 128
	if parsed.To4() != nil {
		bits = 32
	}
	return &net.IPNet{
		IP:   parsed,
		Mask: net.CIDRMask(bits, bits),
	}
}

func TestSupportsFairPlaySAP(t *testing.T) {
	rokuFeatures := uint64(0x38bcf46007f8ad0)
	if (&ReceiverInfo{Features: rokuFeatures}).SupportsFairPlaySAP() {
		t.Fatalf("Roku feature mask unexpectedly advertises FPSAP")
	}
	if (&AirPlayDevice{Features: rokuFeatures}).SupportsFairPlaySAP() {
		t.Fatalf("Roku discovery feature mask unexpectedly advertises FPSAP")
	}

	withFairPlay := rokuFeatures | FeatureFPSAP25
	if !(&ReceiverInfo{Features: withFairPlay}).SupportsFairPlaySAP() {
		t.Fatalf("ReceiverInfo with FPSAP bit did not advertise FairPlay SAP")
	}
	if !(&AirPlayDevice{Features: withFairPlay}).SupportsFairPlaySAP() {
		t.Fatalf("AirPlayDevice with FPSAP bit did not advertise FairPlay SAP")
	}
}

func TestSupportsScreenUsesMirroringFeatureNotRotation(t *testing.T) {
	if !(&AirPlayDevice{Features: FeatureScreen}).SupportsScreen() {
		t.Fatal("screen-mirroring feature was not recognized")
	}
	if (&AirPlayDevice{Features: FeatureScreenRotate}).SupportsScreen() {
		t.Fatal("screen-rotation-only feature was mistaken for screen mirroring")
	}
}

func TestSupportsTransientPairingUsesModernFeatureBits(t *testing.T) {
	for _, bit := range []uint64{FeatureSystemPairing, FeatureTransientPairing} {
		if !(&ReceiverInfo{Features: bit}).SupportsTransientPairing() {
			t.Fatalf("ReceiverInfo feature bit 0x%x did not advertise transient pairing", bit)
		}
		if !(&AirPlayDevice{Features: bit}).SupportsTransientPairing() {
			t.Fatalf("AirPlayDevice feature bit 0x%x did not advertise transient pairing", bit)
		}
	}

	// Bit 19 was previously (and incorrectly) treated as transient pairing.
	if (&ReceiverInfo{Features: 1 << 19}).SupportsTransientPairing() {
		t.Fatal("legacy bit 19 unexpectedly advertises transient pairing")
	}
	if (*ReceiverInfo)(nil).SupportsTransientPairing() {
		t.Fatal("nil ReceiverInfo advertises transient pairing")
	}
}

func TestCoreUtilsPairingCapabilityIsIndependentOfThirdPartyBits(t *testing.T) {
	const rokuFeatures = uint64(0x38bcf46007f8ad0)

	tests := []struct {
		name     string
		features uint64
		want     bool
	}{
		{name: "system pairing", features: FeatureSystemPairing, want: true},
		{name: "transient pairing", features: FeatureTransientPairing, want: true},
		{name: "CoreUtils pairing", features: 1 << 38, want: true},
		{name: "HomeKit access control", features: 1 << 46, want: true},
		{name: "legacy pairing", features: 1 << 27},
		{name: "Roku-advertised capabilities", features: rokuFeatures, want: true},
		{name: "third-party bit 26 with modern bits", features: 1<<26 | FeatureSystemPairing | FeatureTransientPairing, want: true},
		{name: "third-party bit 51 with modern bits", features: 1<<51 | FeatureSystemPairing | FeatureTransientPairing, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := (&ReceiverInfo{Features: tt.features}).supportsCoreUtilsPairing(); got != tt.want {
				t.Fatalf("supportsCoreUtilsPairing() = %v, want %v", got, tt.want)
			}
			wantLegacyProbe := tt.features&featureThirdPartyReceiverMask != 0 || !tt.want
			if got := (&ReceiverInfo{Features: tt.features}).PrefersLegacyPairing(); got != wantLegacyProbe {
				t.Fatalf("PrefersLegacyPairing() = %v, want %v", got, wantLegacyProbe)
			}
		})
	}

	if (*ReceiverInfo)(nil).supportsCoreUtilsPairing() {
		t.Fatal("nil ReceiverInfo supports CoreUtils pairing")
	}
}
