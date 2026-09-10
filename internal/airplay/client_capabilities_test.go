package airplay

import (
	"bytes"
	"math"
	"testing"

	"howett.net/plist"
)

func TestReceiverInfoDecodesExtendedCapabilities(t *testing.T) {
	txt := encodeTXTWire([]string{
		"features=0x4A7FDFD5,0x3C177FDE",
		"fex=1d9/St5/Fzw4oY7cDg",
		"srcvers=980.77.2",
	})
	payload, err := plist.Marshal(map[string]interface{}{
		"features":   uint64(0x3c177fde4a7fdfd5),
		"featuresEx": "1d9/St5/Fzw4oY7cDg",
		"txtAirPlay": txt,
		"supportedFormats": map[string]interface{}{
			"audioStream":           int64(21235712),
			"bufferStream":          int64(-1),
			"lowLatencyAudioStream": int64(0),
			"screenStream":          int64(21235712),
		},
		"supportedAudioFormatsExtended": map[string]interface{}{
			"bufferStream": []uint64{21, 22, 23, 71},
		},
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}

	var info ReceiverInfo
	if _, err := plist.Unmarshal(payload, &info); err != nil {
		t.Fatal(err)
	}
	if info.FeaturesEx.Low64() != info.Features || !info.FeaturesEx.Has(99) {
		t.Fatalf("features/featuresEx = 0x%x/%x", info.Features, []byte(info.FeaturesEx))
	}
	if !bytes.Equal(info.TXTAirPlay, txt) {
		t.Fatalf("txtAirPlay = %x, want %x", info.TXTAirPlay, txt)
	}
	if uint64(info.SupportedFormats.BufferStream) != math.MaxUint64 {
		t.Fatalf("signed bufferStream mask = 0x%x", uint64(info.SupportedFormats.BufferStream))
	}
	if !info.SupportsAudioFormat("screenStream", 0x40000) ||
		!info.SupportsAudioFormat("screenStream", 0x1000000) ||
		info.SupportsAudioFormat("screenStream", 1<<5) ||
		info.SupportsAudioFormat("unknown", 0x40000) {
		t.Fatalf("screenStream format mask = 0x%x", uint64(info.SupportedFormats.ScreenStream))
	}
	gotExtended := info.SupportedAudioFormatsExtended["bufferStream"]
	if len(gotExtended) != 4 || gotExtended[3] != 71 {
		t.Fatalf("supportedAudioFormatsExtended = %#v", info.SupportedAudioFormatsExtended)
	}
}

func TestFeatureSetAcceptsPlistData(t *testing.T) {
	payload, err := plist.Marshal(map[string]interface{}{
		"featuresEx": []byte{0x80, 0, 0, 0, 0, 0, 0, 0, 0x08},
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	var info ReceiverInfo
	if _, err := plist.Unmarshal(payload, &info); err != nil {
		t.Fatal(err)
	}
	if !info.FeaturesEx.Has(7) || !info.FeaturesEx.Has(67) {
		t.Fatalf("data featuresEx = %x", []byte(info.FeaturesEx))
	}
}

func TestAdvertisementMergePrecedence(t *testing.T) {
	embeddedTXT := encodeTXTWire([]string{
		"deviceid=AA:BB:CC:DD:EE:FF",
		"fex=1d9/St5/Fzw4oY7cDg",
		"features=0x4A7FDFD5,0x3C177FDE",
		"flags=0x18644",
		"model=Embedded Model",
		"protovers=1.1",
		"pi=embedded-pi",
		"pk=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"srcvers=embedded-version",
		"vv=1",
	})
	mdns := &AirPlayDevice{
		Name:            "mDNS Name",
		Model:           "mDNS Model",
		DeviceID:        "11:22:33:44:55:66",
		Features:        FeatureScreen | FeatureLegacyPairing,
		FeaturesEx:      FeatureSet{0, 0, 0, 0, 0, 0, 0, 0, 1},
		Flags:           0x80,
		SourceVersion:   "mDNS-version",
		ProtocolVersion: "mDNS-protocol",
		VV:              2,
		PI:              "mdns-pi",
		PSI:             "mdns-psi",
		RawTXT: map[string]string{
			"deviceid": "11:22:33:44:55:66", "features": "0x08000080,0",
			"fex": "AAAAAAAAAAAB", "flags": "0x80", "model": "mDNS Model",
			"protovers": "mDNS-protocol", "srcvers": "mDNS-version", "vv": "2",
			"pi": "mdns-pi", "psi": "mdns-psi",
		},
	}
	info := ReceiverInfo{
		Name:          "Explicit Name",
		SourceVersion: "", // Explicitly empty still wins.
		Features:      0,  // Explicit zero still wins for low feature bits.
		StatusFlags:   0,  // Explicit zero still wins.
		TXTAirPlay:    embeddedTXT,
		Server:        "AirTunes/server-fallback",
	}
	fullInfo := map[string]interface{}{
		"name":          "Explicit Name",
		"sourceVersion": "",
		"features":      uint64(0),
		"statusFlags":   uint64(0),
		"txtAirPlay":    embeddedTXT,
	}

	mergeAdvertisementIntoReceiverInfo(&info, fullInfo, mdns)
	if info.Name != "Explicit Name" || info.SourceVersion != "" || info.Features != 0 || info.StatusFlags != 0 {
		t.Fatalf("explicit /info fields were overwritten: %+v", info)
	}
	if info.Model != "Embedded Model" || info.DeviceID != "AA:BB:CC:DD:EE:FF" || info.ProtocolVersion != "1.1" || info.VV != 1 || info.PI != "embedded-pi" {
		t.Fatalf("embedded TXT did not precede mDNS: %+v", info)
	}
	if info.PSI != "mdns-psi" {
		t.Fatalf("mDNS omission fallback PSI = %q", info.PSI)
	}
	if len(info.PK) != 32 || info.PK[0] != 0 || info.PK[31] != 31 {
		t.Fatalf("embedded TXT public key = %x", []byte(info.PK))
	}
	if info.HasFeature(7) || info.HasFeature(28) {
		t.Fatal("lower-precedence extended features overrode explicit low64 features")
	}
	if !info.HasFeature(99) {
		t.Fatal("embedded TXT did not contribute extended feature bit 99")
	}
}

func TestAdvertisementFillsMissingInfoAndServerIsLastFallback(t *testing.T) {
	mdns := AirPlayDevice{
		Name:            "Discovered TV",
		Model:           "Capability Model",
		DeviceID:        "00:11:22:33:44:55",
		Features:        FeatureScreen | FeatureLegacyPairing,
		Flags:           0x80,
		SourceVersion:   "advertised-version",
		ProtocolVersion: "1.1",
		VV:              2,
		PI:              "pi",
		PSI:             "psi",
	}
	info := ReceiverInfo{Server: "AirTunes/999.1"}
	mergeAdvertisementIntoReceiverInfo(&info, nil, &mdns)
	if info.Name != mdns.Name || info.Model != mdns.Model || info.DeviceID != mdns.DeviceID ||
		info.SourceVersion != mdns.SourceVersion || info.ProtocolVersion != mdns.ProtocolVersion ||
		info.Features != mdns.Features || info.StatusFlags != mdns.Flags || info.VV != mdns.VV {
		t.Fatalf("mDNS fallback = %+v", info)
	}

	serverOnly := ReceiverInfo{Server: "AirTunes/999.1"}
	mergeAdvertisementIntoReceiverInfo(&serverOnly, nil, nil)
	if serverOnly.SourceVersion != "999.1" {
		t.Fatalf("Server source-version fallback = %q", serverOnly.SourceVersion)
	}
	nonAirTunes := ReceiverInfo{Server: "doubletake-test-receiver/1"}
	mergeAdvertisementIntoReceiverInfo(&nonAirTunes, nil, nil)
	if nonAirTunes.SourceVersion != "" {
		t.Fatalf("non-AirTunes Server became sourceVersion %q", nonAirTunes.SourceVersion)
	}
}

func TestTopLevelFeaturesExPrecedesEmbeddedLegacyFeatures(t *testing.T) {
	features, err := decodeFeatureSet("1d9/St5/Fzw4oY7cDg")
	if err != nil {
		t.Fatal(err)
	}
	info := ReceiverInfo{
		FeaturesEx: features,
		TXTAirPlay: encodeTXTWire([]string{"features=0x0,0x0"}),
	}
	mergeAdvertisementIntoReceiverInfo(&info, map[string]interface{}{
		"featuresEx": "1d9/St5/Fzw4oY7cDg",
		"txtAirPlay": info.TXTAirPlay,
	}, nil)
	if info.Features != features.Low64() || !info.HasFeature(7) {
		t.Fatalf("top-level featuresEx lost to embedded features: 0x%x", info.Features)
	}
}

func TestNewAirPlayClientForDeviceCopiesAdvertisement(t *testing.T) {
	device := AirPlayDevice{
		IP:         "192.0.2.10",
		Port:       7000,
		FeaturesEx: FeatureSet{1, 2, 3},
		RawTXT:     map[string]string{"srcvers": "1.2.3"},
	}
	client := NewAirPlayClientForDevice(device)
	device.FeaturesEx[0] = 9
	device.RawTXT["srcvers"] = "changed"
	if client.host != "192.0.2.10" || client.port != 7000 || client.advertisement.FeaturesEx[0] != 1 || client.advertisement.RawTXT["srcvers"] != "1.2.3" {
		t.Fatalf("seeded client = %+v", client.advertisement)
	}
}

func TestApplyReceiverInfoUpdatePreservesOmittedCapabilities(t *testing.T) {
	client := NewAirPlayClient("192.0.2.10", 7000)
	client.info = &ReceiverInfo{
		Name:          "Receiver",
		DeviceID:      "00:11:22:33:44:55",
		SourceVersion: "980.77.2",
		Server:        "AirTunes/980.77.2",
		Features:      FeatureScreen,
		FeaturesEx:    FeatureSet{0x80, 0x01},
		StatusFlags:   statusFlagPasswordRequired,
		PK:            plistData{1, 2, 3},
		TXTAirPlay:    []byte{4, 5, 6},
		SupportedFormats: StreamFormats{
			ScreenStream: FormatMask(0x1440800),
		},
		SupportedAudioFormatsExtended: map[string][]uint64{
			"bufferStream": {21, 22, 23},
		},
		Displays: []DisplayInfo{{
			WidthPixels:     1280,
			HeightPixels:    720,
			WidthPixelsMax:  1280,
			HeightPixelsMax: 720,
		}},
	}
	previous := client.info

	updated, err := client.applyReceiverInfoUpdate(map[string]interface{}{
		"displays": []interface{}{map[string]interface{}{
			"widthPixels":     int64(1920),
			"heightPixels":    int64(1080),
			"widthPixelsMax":  int64(3840),
			"heightPixelsMax": int64(2160),
		}},
	}, "AirTunes/981.1")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "Receiver" || updated.DeviceID != "00:11:22:33:44:55" ||
		updated.SourceVersion != "980.77.2" || updated.Features != FeatureScreen ||
		updated.StatusFlags != statusFlagPasswordRequired {
		t.Fatalf("partial update lost prior capabilities: %+v", updated)
	}
	if updated.Server != "AirTunes/981.1" {
		t.Fatalf("updated Server = %q", updated.Server)
	}
	if !bytes.Equal(updated.FeaturesEx, FeatureSet{0x80, 0x01}) {
		t.Fatalf("updated FeaturesEx = %x", []byte(updated.FeaturesEx))
	}
	if got := uint64(updated.SupportedFormats.ScreenStream); got != 0x1440800 {
		t.Fatalf("updated screenStream formats = 0x%x", got)
	}
	if got := updated.SupportedAudioFormatsExtended["bufferStream"]; len(got) != 3 || got[2] != 23 {
		t.Fatalf("updated extended formats = %#v", got)
	}
	if width, height := updated.DisplaySize(); width != 1920 || height != 1080 {
		t.Fatalf("updated nominal display = %dx%d, want 1920x1080", width, height)
	}
	if width, height := updated.MaxVideoSize(); width != 3840 || height != 2160 {
		t.Fatalf("updated maximum display = %dx%d, want 3840x2160", width, height)
	}

	// The new active snapshot must not alias mutable fields in the old one.
	updated.FeaturesEx[0] = 0
	updated.PK[0] = 0
	updated.TXTAirPlay[0] = 0
	updated.SupportedAudioFormatsExtended["bufferStream"][0] = 0
	if previous.FeaturesEx[0] != 0x80 || previous.PK[0] != 1 || previous.TXTAirPlay[0] != 4 ||
		previous.SupportedAudioFormatsExtended["bufferStream"][0] != 21 {
		t.Fatal("partial update aliased mutable fields in the previous snapshot")
	}
}

func TestApplyReceiverInfoUpdateDerivesLegacyFeaturesFromFeaturesEx(t *testing.T) {
	client := NewAirPlayClient("192.0.2.10", 7000)
	client.info = &ReceiverInfo{Features: 1}
	features := make(FeatureSet, 8)
	features[featureRFC2198Redundancy/8] = 1 << (featureRFC2198Redundancy % 8)

	updated, err := client.applyReceiverInfoUpdate(map[string]interface{}{
		"featuresEx": []byte(features),
	}, "")
	if err != nil {
		t.Fatal(err)
	}
	if updated.Features != features.Low64() || !updated.HasFeature(featureRFC2198Redundancy) {
		t.Fatalf("updated features = 0x%x/%x", updated.Features, []byte(updated.FeaturesEx))
	}
}

func TestExplicitSupportedFormatsSuppressLegacyFeatureFallback(t *testing.T) {
	info := receiverWithFeatures(featureAudioFormatAACELD44100Stereo)
	info.hasSupportedFormats = true
	if info.SupportsAudioFormat("screenStream", screenAudioFormatAACELD44100Stereo) {
		t.Fatal("explicit empty supportedFormats was replaced by feature-derived formats")
	}
}

func encodeTXTWire(records []string) []byte {
	var wire []byte
	for _, record := range records {
		wire = append(wire, byte(len(record)))
		wire = append(wire, record...)
	}
	return wire
}
