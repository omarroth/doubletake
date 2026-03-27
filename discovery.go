package main

import (
	"context"
	"fmt"
	"strings"

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
	resolver, err := zeroconf.NewResolver(nil)
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

func parseServiceEntry(entry *zeroconf.ServiceEntry) *AirPlayDevice {
	if len(entry.AddrIPv4) == 0 && len(entry.AddrIPv6) == 0 {
		return nil
	}

	dev := &AirPlayDevice{
		Name: entry.Instance,
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
	FeatureScreen          uint64 = 1 << 8
	FeatureAudio           uint64 = 1 << 10
	FeatureFPSAP25         uint64 = 1 << 14
	FeatureHomeKitPairing  uint64 = 1 << 17
	FeatureTransientPairing uint64 = 1 << 19
	FeatureUDPMirroring    uint64 = 1 << 49
)

func (d *AirPlayDevice) SupportsScreen() bool {
	return d.Features&FeatureScreen != 0
}

func (d *AirPlayDevice) SupportsTransientPairing() bool {
	return d.Features&FeatureTransientPairing != 0
}
