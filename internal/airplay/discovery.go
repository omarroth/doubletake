package airplay

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/grandcat/zeroconf"
)

var errNoAirPlayMDNSInterfaces = errors.New("no multicast-capable LAN interface is available")

// AirPlayDevice represents a discovered AirPlay receiver.
type AirPlayDevice struct {
	Name            string
	Model           string
	IP              string
	Port            int
	DeviceID        string
	Features        uint64
	FeaturesEx      FeatureSet
	FEX             string
	PK              string // hex-encoded Ed25519 public key
	Flags           uint64
	SourceVersion   string
	ProtocolVersion string
	VV              uint64
	PI              string
	PSI             string
	RawTXT          map[string]string
}

// FeatureSet is AirPlay's arbitrary-length, little-endian feature bit vector.
// mDNS publishes it as base64 in fex; /info publishes the same representation
// as featuresEx.
type FeatureSet []byte

// Has reports whether the numbered AirPlay feature bit is set.
func (f FeatureSet) Has(bit uint) bool {
	byteIndex := bit / 8
	return byteIndex < uint(len(f)) && f[byteIndex]&(1<<uint(bit%8)) != 0
}

// Low64 returns the legacy 64-bit prefix of the feature vector.
func (f FeatureSet) Low64() uint64 {
	var low [8]byte
	copy(low[:], f)
	return binary.LittleEndian.Uint64(low[:])
}

func (f FeatureSet) clone() FeatureSet {
	return append(FeatureSet(nil), f...)
}

// UnmarshalPlist accepts both the base64 string used by current Apple
// receivers and data values used by some third-party implementations.
func (f *FeatureSet) UnmarshalPlist(unmarshal func(interface{}) error) error {
	var encoded string
	if err := unmarshal(&encoded); err == nil {
		decoded, err := decodeFeatureSet(encoded)
		if err != nil {
			return err
		}
		*f = decoded
		return nil
	}

	var data []byte
	if err := unmarshal(&data); err != nil {
		return err
	}
	*f = append((*f)[:0], data...)
	return nil
}

// DiscoverAirPlayDevices browses the local network for AirPlay receivers.
func DiscoverAirPlayDevices(ctx context.Context) ([]AirPlayDevice, error) {
	var devices []AirPlayDevice
	err := BrowseAirPlayDevices(ctx, func(device AirPlayDevice) {
		devices = append(devices, device)
	})
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, errNoAirPlayMDNSInterfaces) {
		return devices, nil
	}
	return devices, err
}

// BrowseAirPlayDevices reports receivers discovered by a single long-lived
// mDNS browse. Cancellation returns promptly without waiting for zeroconf's
// result channel to close; its resolver observes the same context and performs
// socket cleanup asynchronously.
func BrowseAirPlayDevices(ctx context.Context, onDevice func(AirPlayDevice)) error {
	ifaces, traffic, err := airPlayMDNSInterfaces()
	if err != nil {
		return fmt.Errorf("mDNS interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return errNoAirPlayMDNSInterfaces
	}

	resolver, err := zeroconf.NewResolver(
		zeroconf.SelectIfaces(ifaces),
		zeroconf.SelectIPTraffic(traffic),
	)
	if err != nil {
		return fmt.Errorf("zeroconf resolver: %w", err)
	}

	entries := make(chan *zeroconf.ServiceEntry, 16)
	if err := resolver.Browse(ctx, "_airplay._tcp", "local.", entries); err != nil {
		return fmt.Errorf("browse: %w", err)
	}

	return consumeAirPlayEntries(ctx, entries, onDevice)
}

func consumeAirPlayEntries(ctx context.Context, entries <-chan *zeroconf.ServiceEntry, onDevice func(AirPlayDevice)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, ok := <-entries:
			if !ok {
				if err := ctx.Err(); err != nil {
					return err
				}
				return fmt.Errorf("mDNS browse stopped unexpectedly")
			}
			if device := parseServiceEntry(entry); device != nil && onDevice != nil {
				onDevice(*device)
			}
		}
	}
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

	populateDeviceFromTXT(dev, parseTXT(entry.Text))

	return dev
}

func populateDeviceFromTXT(dev *AirPlayDevice, txt map[string]string) {
	dev.RawTXT = cloneTXT(txt)
	dev.Model = txt["model"]
	dev.DeviceID = txt["deviceid"]
	dev.PK = txt["pk"]
	dev.FEX = txt["fex"]
	dev.SourceVersion = txt["srcvers"]
	dev.ProtocolVersion = txt["protovers"]
	dev.PI = txt["pi"]
	dev.PSI = txt["psi"]

	if dev.FEX != "" {
		dev.FeaturesEx, _ = decodeFeatureSet(dev.FEX)
	}
	if f := txt["features"]; f != "" {
		dev.Features = parseFeatures(f)
	} else {
		dev.Features = dev.FeaturesEx.Low64()
	}
	if f := txt["flags"]; f != "" {
		dev.Flags, _ = strconv.ParseUint(f, 0, 64)
	}
	if vv := txt["vv"]; vv != "" {
		dev.VV, _ = strconv.ParseUint(vv, 0, 64)
	}
}

func cloneTXT(txt map[string]string) map[string]string {
	if txt == nil {
		return nil
	}
	clone := make(map[string]string, len(txt))
	for key, value := range txt {
		clone[key] = value
	}
	return clone
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

// parseFeatures parses AirPlay's legacy "0xLOW32,0xHIGH32" wire value.
func parseFeatures(s string) uint64 {
	parts := strings.Split(s, ",")
	if len(parts) != 2 {
		v, _ := strconv.ParseUint(strings.TrimSpace(s), 0, 64)
		return v
	}
	lo, err := strconv.ParseUint(strings.TrimSpace(parts[0]), 0, 32)
	if err != nil {
		return 0
	}
	hi, err := strconv.ParseUint(strings.TrimSpace(parts[1]), 0, 32)
	if err != nil {
		return 0
	}
	return hi<<32 | lo
}

func decodeFeatureSet(s string) (FeatureSet, error) {
	s = strings.TrimSpace(s)
	decoded, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(s)
	}
	if err != nil {
		return nil, fmt.Errorf("decode AirPlay extended features: %w", err)
	}
	return FeatureSet(decoded), nil
}

// Feature bit constants for AirPlay receivers.
const (
	FeatureScreen         uint64 = 1 << 7
	FeatureScreenRotate   uint64 = 1 << 8
	FeatureAudio          uint64 = 1 << 10
	FeatureFPSAP25        uint64 = 1 << 14
	FeatureHomeKitPairing uint64 = 1 << 17
	FeatureLegacyPairing  uint64 = 1 << 27
	// Feature 28 selects a 1920x1080 display when the receiver omits displays[];
	// without it, the legacy default is 1280x720.
	featureDefaultDisplay1080p uint64 = 1 << 28
	FeatureSystemPairing       uint64 = 1 << 43
	FeatureTransientPairing    uint64 = 1 << 48
	FeatureUDPMirroring        uint64 = 1 << 49

	// Apple's endpoint description derives these as independent properties.
	// Third-party identity chooses only the first bounded pairing probe; it does
	// not cancel an advertised CoreUtils capability or determine the result.
	featureThirdPartyReceiverMask = uint64(1<<26 | 1<<51)
	featureCoreUtilsPairingMask   = uint64(1<<38 | 1<<43 | 1<<46 | 1<<48)
)

func (d *AirPlayDevice) SupportsScreen() bool {
	return d.HasFeature(7)
}

// HasFeature reports whether a legacy or extended advertised feature is set.
func (d *AirPlayDevice) HasFeature(bit uint) bool {
	if d == nil {
		return false
	}
	if bit < 64 {
		return d.Features&(uint64(1)<<bit) != 0
	}
	return d.FeaturesEx.Has(bit)
}

// HasFeature reports whether a legacy or extended /info feature is set.
func (i *ReceiverInfo) HasFeature(bit uint) bool {
	if i == nil {
		return false
	}
	if bit < 64 {
		return i.Features&(uint64(1)<<bit) != 0
	}
	return i.FeaturesEx.Has(bit)
}

func (d *AirPlayDevice) SupportsTransientPairing() bool {
	return d != nil && supportsTransientPairing(d.Features)
}

func (i *ReceiverInfo) SupportsTransientPairing() bool {
	return i != nil && (i.HasFeature(43) || i.HasFeature(48))
}

func supportsTransientPairing(features uint64) bool {
	return features&(FeatureTransientPairing|FeatureSystemPairing) != 0
}

// SupportsLegacyPairing reports the original HKP pairing feature (bit 27).
func (d *AirPlayDevice) SupportsLegacyPairing() bool {
	return d != nil && d.HasFeature(27)
}

// SupportsLegacyPairing reports the original HKP pairing feature (bit 27).
func (i *ReceiverInfo) SupportsLegacyPairing() bool {
	return i != nil && i.HasFeature(27)
}

// supportsCoreUtilsPairing reports Apple's independent
// SupportsCoreUtilsPairingAndEncryption endpoint property. A receiver's
// first-/third-party classification is deliberately not part of this decision.
// A peer which advertises this capability but rejects HAP is handled by the
// bounded wire-format fallback in pairing.go.
func (i *ReceiverInfo) supportsCoreUtilsPairing() bool {
	if i == nil {
		return false
	}
	return i.Features&featureCoreUtilsPairingMask != 0
}

func (i *ReceiverInfo) isThirdPartyReceiver() bool {
	return i != nil && i.Features&featureThirdPartyReceiverMask != 0
}

// PrefersLegacyPairing reports whether the initial wire-format probe should use
// the original HKP type 3 flow. The successfully negotiated protocol is stored
// separately and takes precedence on later connections.
func (i *ReceiverInfo) PrefersLegacyPairing() bool {
	return i != nil && (!i.supportsCoreUtilsPairing() || i.isThirdPartyReceiver())
}

func (d *AirPlayDevice) SupportsFairPlaySAP() bool {
	return d != nil && d.HasFeature(14)
}

func (i *ReceiverInfo) SupportsFairPlaySAP() bool {
	return i != nil && i.HasFeature(14)
}
