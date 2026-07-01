package airplay

import (
	"net"
	"testing"

	"github.com/grandcat/zeroconf"
)

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
