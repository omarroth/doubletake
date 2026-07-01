package airplay

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/grandcat/zeroconf"
)

// AirPlayDevice represents a discovered AirPlay receiver.
type AirPlayDevice struct {
	Name     string
	Model    string
	IP       string
	Port     int
	DeviceID string
	Features uint64
	PK       string // hex-encoded Ed25519 public key
	Flags    uint64
}

// DiscoverAirPlayDevices browses the local network for AirPlay receivers.
func DiscoverAirPlayDevices(ctx context.Context) ([]AirPlayDevice, error) {
	ifaces, traffic, err := airPlayMDNSInterfaces()
	if err != nil {
		return nil, fmt.Errorf("mDNS interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return nil, nil
	}

	resolver, err := zeroconf.NewResolver(
		zeroconf.SelectIfaces(ifaces),
		zeroconf.SelectIPTraffic(traffic),
	)
	if err != nil {
		return nil, fmt.Errorf("zeroconf resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry, 16)
	var devices []AirPlayDevice

	done := make(chan struct{})
	go func() {
		defer close(done)
		for entry := range entries {
			dev := parseServiceEntry(entry)
			if dev != nil {
				devices = append(devices, *dev)
			}
		}
	}()

	if err := resolver.Browse(ctx, "_airplay._tcp", "local.", entries); err != nil {
		return nil, fmt.Errorf("browse: %w", err)
	}

	<-ctx.Done()
	<-done
	return devices, nil
}

func airPlayMDNSInterfaces() ([]net.Interface, zeroconf.IPType, error) {
	systemIfaces, err := net.Interfaces()
	if err != nil {
		return nil, 0, err
	}

	ifaces := make([]net.Interface, 0, len(systemIfaces))
	var traffic zeroconf.IPType
	for _, iface := range systemIfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		hasIPv4, hasIPv6 := mdnsAddressFamilies(addrs)
		if !isAirPlayMDNSInterface(iface, hasIPv4, hasIPv6) {
			continue
		}

		ifaces = append(ifaces, iface)
		if hasIPv4 {
			traffic |= zeroconf.IPv4
		}
		if hasIPv6 {
			traffic |= zeroconf.IPv6
		}
	}

	return ifaces, traffic, nil
}

func isAirPlayMDNSInterface(iface net.Interface, hasIPv4, hasIPv6 bool) bool {
	if iface.Flags&net.FlagUp == 0 {
		return false
	}
	if iface.Flags&net.FlagMulticast == 0 {
		return false
	}
	if iface.Flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
		return false
	}
	if isNonLANInterfaceName(iface.Name) {
		return false
	}
	return hasIPv4 || hasIPv6
}

func isNonLANInterfaceName(name string) bool {
	name = strings.ToLower(name)
	prefixes := [...]string{
		"bnep", "bluetooth", "bt", "pan",
		"br-", "cilium", "cni", "docker", "flannel", "kube", "podman", "veth", "virbr",
		"tailscale", "tap", "tun", "utun", "wg", "zt",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func mdnsAddressFamilies(addrs []net.Addr) (hasIPv4, hasIPv6 bool) {
	for _, addr := range addrs {
		ip := ipFromAddr(addr)
		if ip == nil || !isUsableMDNSAddress(ip) {
			continue
		}
		if ip.To4() != nil {
			hasIPv4 = true
		} else {
			hasIPv6 = true
		}
	}
	return hasIPv4, hasIPv6
}

func ipFromAddr(addr net.Addr) net.IP {
	switch addr := addr.(type) {
	case *net.IPNet:
		return addr.IP
	case *net.IPAddr:
		return addr.IP
	default:
		return nil
	}
}

func isUsableMDNSAddress(ip net.IP) bool {
	return ip != nil &&
		!ip.IsUnspecified() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsMulticast()
}

func parseServiceEntry(entry *zeroconf.ServiceEntry) *AirPlayDevice {
	if len(entry.AddrIPv4) == 0 && len(entry.AddrIPv6) == 0 {
		return nil
	}

	dev := &AirPlayDevice{
		Name: unescapeDNSName(entry.Instance),
		Port: entry.Port,
	}

	if len(entry.AddrIPv4) > 0 {
		dev.IP = entry.AddrIPv4[0].String()
	} else if len(entry.AddrIPv6) > 0 {
		dev.IP = entry.AddrIPv6[0].String()
	}

	txt := parseTXT(entry.Text)
	dev.Model = txt["model"]
	dev.DeviceID = txt["deviceid"]
	dev.PK = txt["pk"]

	if f := txt["features"]; f != "" {
		dev.Features = parseFeatures(f)
	}
	if f := txt["flags"]; f != "" {
		fmt.Sscanf(f, "0x%x", &dev.Flags)
	}

	return dev
}

func parseTXT(records []string) map[string]string {
	m := make(map[string]string, len(records))
	for _, r := range records {
		k, v, _ := strings.Cut(r, "=")
		m[k] = v
	}
	return m
}

// unescapeDNSName removes DNS-SD backslash escapes from an mDNS instance name.
// e.g. "Living\ Room\ \(2\)" -> "Living Room (2)"
func unescapeDNSName(s string) string {
	buf := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			if i+3 < len(s) && isASCIIDigit(s[i+1]) && isASCIIDigit(s[i+2]) && isASCIIDigit(s[i+3]) {
				v, err := strconv.Atoi(s[i+1 : i+4])
				if err == nil && v >= 0 && v <= 255 {
					buf = append(buf, byte(v))
					i += 3
					continue
				}
			}

			i++
		} else {
			buf = append(buf, s[i])
			continue
		}

		buf = append(buf, s[i])
	}
	return string(buf)
}

func isASCIIDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

// parseFeatures parses the AirPlay features string "0xHIGH,0xLOW" into a 64-bit value.
func parseFeatures(s string) uint64 {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		var v uint64
		fmt.Sscanf(s, "0x%x", &v)
		return v
	}
	var lo, hi uint64
	fmt.Sscanf(parts[0], "0x%x", &lo)
	fmt.Sscanf(parts[1], "0x%x", &hi)
	return hi<<32 | lo
}

// Feature bit constants for AirPlay receivers.
const (
	FeatureScreen           uint64 = 1 << 8
	FeatureAudio            uint64 = 1 << 10
	FeatureFPSAP25          uint64 = 1 << 14
	FeatureHomeKitPairing   uint64 = 1 << 17
	FeatureTransientPairing uint64 = 1 << 19
	FeatureUDPMirroring     uint64 = 1 << 49
)

func (d *AirPlayDevice) SupportsScreen() bool {
	return d.Features&FeatureScreen != 0
}

func (d *AirPlayDevice) SupportsTransientPairing() bool {
	return d.Features&FeatureTransientPairing != 0
}

func (d *AirPlayDevice) SupportsFairPlaySAP() bool {
	return d.Features&FeatureFPSAP25 != 0
}

func (i *ReceiverInfo) SupportsFairPlaySAP() bool {
	return i != nil && i.Features&FeatureFPSAP25 != 0
}

// playoutLatencyFloor returns the minimum playout lead this receiver needs.
// Modern Apple receivers advertise FairPlay SAP and have robust audio jitter
// buffers, so they can play at very low latency (floor 0). Receivers without it
// (Roku and other third-party AirPlay implementations) need a conservative lead
// or they drop audio they can no longer schedule.
func (i *ReceiverInfo) playoutLatencyFloor() time.Duration {
	if i != nil && i.SupportsFairPlaySAP() {
		return 0
	}
	return conservativePlayoutLatency
}
