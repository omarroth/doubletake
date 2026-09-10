package airplay

import (
	"errors"
	"reflect"
	"testing"
)

func receiverWithFeatures(bits ...uint) ReceiverInfo {
	var features uint64
	for _, bit := range bits {
		features |= uint64(1) << bit
	}
	return ReceiverInfo{Features: features}
}

func mustCompatibility(t *testing.T, info *ReceiverInfo, encrypted bool) receiverCompatibility {
	t.Helper()
	policy, err := compatibilityForReceiver(info, encrypted, true)
	if err != nil {
		t.Fatalf("compatibilityForReceiver: %v", err)
	}
	return policy
}

func TestReceiverCompatibilityUsesIndependentCapabilities(t *testing.T) {
	info := receiverWithFeatures(
		43, // system pairing
		featurePTP,
		featureAudioStreamConnectionSetup,
	)
	info.SourceVersion = "354.54.6"
	info.SupportedFormats = StreamFormats{ScreenStream: FormatMask(screenAudioFormatALAC)}

	got := mustCompatibility(t, &info, true)
	if got.timing != timingProtocolPTP || !got.permitsLocalPTPClock() {
		t.Fatalf("PTP policy = timing %q fallback=%t, want PTP with clock-header fallback", got.timing, got.permitsLocalPTPClock())
	}
	if got.audioSecurity != audioSecurityChaCha || got.audioConnections != audioLayoutStreamConnections {
		t.Fatalf("audio policy = security %d/layout %d, want ChaCha/streamConnections", got.audioSecurity, got.audioConnections)
	}
	if got.audioCodec != AudioCodecALAC {
		t.Fatalf("audio codec = %d, want ALAC", got.audioCodec)
	}
	if got.fairPlayRoots != fairPlayDescriptorOnly {
		t.Fatalf("FairPlay roots = %d, want descriptor-only", got.fairPlayRoots)
	}
	if got.sourceVersion() != modernAirPlaySourceVersion {
		t.Fatalf("sender sourceVersion = %q, want %q", got.sourceVersion(), modernAirPlaySourceVersion)
	}
}

func TestFeature59OnlyControlsInitialAudioDescriptorLayout(t *testing.T) {
	withFeature := receiverWithFeatures(featureAudioStreamConnectionSetup)
	withoutFeature := receiverWithFeatures()

	for _, test := range []struct {
		name       string
		info       *ReceiverInfo
		encrypted  bool
		wantLayout audioConnectionLayout
		wantRoots  fairPlayRootPlacement
	}{
		{
			name: "encrypted feature 59",
			info: &withFeature, encrypted: true,
			wantLayout: audioLayoutStreamConnections, wantRoots: fairPlayDescriptorOnly,
		},
		{
			name:       "plaintext feature 59",
			info:       &withFeature,
			wantLayout: audioLayoutStreamConnections, wantRoots: fairPlayAllRoots,
		},
		{
			name: "encrypted without feature 59",
			info: &withoutFeature, encrypted: true,
			wantLayout: audioLayoutControlPort, wantRoots: fairPlayDescriptorOnly,
		},
		{
			name:       "unknown receiver",
			wantLayout: audioLayoutControlPort, wantRoots: fairPlayAllRoots,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := mustCompatibility(t, test.info, test.encrypted)
			if got.audioConnections != test.wantLayout || got.fairPlayRoots != test.wantRoots {
				t.Fatalf("policy = layout %d/roots %d, want %d/%d", got.audioConnections, got.fairPlayRoots, test.wantLayout, test.wantRoots)
			}
		})
	}
}

func TestPTPRequiresCapabilityVersionAndEncryption(t *testing.T) {
	ptp := receiverWithFeatures(featurePTP)
	ptp.SourceVersion = "354.54.6"
	ptp.hasPTPInfo = false
	ptpInfoOnly := receiverWithFeatures()
	ptpInfoOnly.SourceVersion = "980.71.1"
	ptpInfoOnly.hasPTPInfo = true

	for _, test := range []struct {
		name      string
		info      ReceiverInfo
		encrypted bool
		want      string
	}{
		{name: "all predicates", info: ptp, encrypted: true, want: timingProtocolPTP},
		{name: "plaintext", info: ptp, want: timingProtocolNTP},
		{name: "PTPInfo without feature", info: ptpInfoOnly, encrypted: true, want: timingProtocolNTP},
		{name: "feature below version floor", info: func() ReceiverInfo {
			i := ptp
			i.SourceVersion = "354.54.5"
			return i
		}(), encrypted: true, want: timingProtocolNTP},
		{name: "377.40 interoperability exception", info: func() ReceiverInfo {
			i := ptp
			i.SourceVersion = "377.40.12"
			return i
		}(), encrypted: true, want: timingProtocolNTP},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := mustCompatibility(t, &test.info, test.encrypted)
			if got.timing != test.want {
				t.Fatalf("timing = %q, want %q", got.timing, test.want)
			}
			if got.permitsLocalPTPClock() != (test.want == timingProtocolPTP) {
				t.Fatalf("permitsLocalPTPClock = %t for timing %q", got.permitsLocalPTPClock(), got.timing)
			}
		})
	}
}

func TestSupportsPTPSourceVersion(t *testing.T) {
	for _, test := range []struct {
		version string
		want    bool
	}{
		{version: "354.54.5"},
		{version: "354.54.6", want: true},
		{version: "354.55", want: true},
		{version: "355.0", want: true},
		{version: "377.39.99", want: true},
		{version: "377.40"},
		{version: "377.40.0"},
		{version: "377.40.999"},
		{version: "377.41", want: true},
		{version: "980.71.1", want: true},
		{version: ""},
		{version: "354"},
		{version: "354.54.beta"},
		{version: "354.54.6.1"},
	} {
		t.Run(test.version, func(t *testing.T) {
			if got := supportsPTPSourceVersion(test.version); got != test.want {
				t.Fatalf("supportsPTPSourceVersion(%q) = %t, want %t", test.version, got, test.want)
			}
		})
	}
}

func TestScreenAudioCodecUsesAdvertisedFormatMask(t *testing.T) {
	for _, test := range []struct {
		name         string
		mask         uint64
		allowAACELD  bool
		want         AudioCodec
		wantError    error
		wantAnyError bool
	}{
		{name: "missing mask", want: AudioCodecALAC},
		{name: "ALAC", mask: screenAudioFormatALAC, want: AudioCodecALAC},
		{name: "AAC ELD preferred", mask: screenAudioFormatALAC | screenAudioFormatAACELD44100Stereo, allowAACELD: true, want: AudioCodecAACELD},
		{name: "ALAC fallback without AAC encoder", mask: screenAudioFormatALAC | screenAudioFormatAACELD44100Stereo, want: AudioCodecALAC},
		{name: "AAC ELD only", mask: screenAudioFormatAACELD44100Stereo, allowAACELD: true, want: AudioCodecAACELD},
		{name: "AAC ELD unavailable", mask: screenAudioFormatAACELD44100Stereo, wantError: ErrAACELDUnavailable},
		{name: "unsupported advertised mask", mask: 0x800000, wantAnyError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := &ReceiverInfo{SupportedFormats: StreamFormats{ScreenStream: FormatMask(test.mask)}}
			got, err := screenAudioCodec(info, test.allowAACELD)
			if test.wantError != nil {
				if !errors.Is(err, test.wantError) {
					t.Fatalf("screenAudioCodec error = %v, want %v", err, test.wantError)
				}
				return
			}
			if test.wantAnyError {
				if err == nil {
					t.Fatal("screenAudioCodec succeeded, want error")
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("screenAudioCodec = %d, %v, want %d, nil", got, err, test.want)
			}
		})
	}
}

func TestScreenAudioCodecSynthesizesLegacyFormatsFromFeatures(t *testing.T) {
	for _, test := range []struct {
		name     string
		features []uint
		want     AudioCodec
		wantErr  bool
	}{
		{name: "AAC ELD precedes ALAC", features: []uint{featureAudioFormatAACELD44100Stereo, featureAudioFormatALAC44100Stereo}, want: AudioCodecAACELD},
		{name: "AAC ELD", features: []uint{featureAudioFormatAACELD44100Stereo}, want: AudioCodecAACELD},
		{name: "ALAC", features: []uint{featureAudioFormatALAC44100Stereo}, want: AudioCodecALAC},
		{name: "unsupported AAC LC", features: []uint{featureAudioFormatAACLC44100Stereo}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := receiverWithFeatures(test.features...)
			got, err := screenAudioCodec(&info, true)
			if (err != nil) != test.wantErr {
				t.Fatalf("screenAudioCodec error = %v, want error=%t", err, test.wantErr)
			}
			if err == nil && got != test.want {
				t.Fatalf("screenAudioCodec = %d, want %d", got, test.want)
			}
		})
	}

	info := receiverWithFeatures(featureAudioFormatAACELD44100Stereo)
	info.SupportedFormats.ScreenStream = FormatMask(screenAudioFormatALAC)
	if got, err := screenAudioCodec(&info, true); err != nil || got != AudioCodecALAC {
		t.Fatalf("explicit supportedFormats override = %d, %v, want ALAC", got, err)
	}
}

func TestVideoOnlyCompatibilityKeepsAdvertisedAACELDWithoutLocalEncoder(t *testing.T) {
	info := &ReceiverInfo{SupportedFormats: StreamFormats{ScreenStream: FormatMask(screenAudioFormatAACELD44100Stereo)}}
	policy, err := compatibilityForReceiver(info, false, false)
	if err != nil || policy.audioCodec != AudioCodecAACELD {
		t.Fatalf("video-only compatibility = codec %d, %v, want AAC-ELD", policy.audioCodec, err)
	}
}

func TestRFC2198RedundancyRequiresAdvertisedFeature(t *testing.T) {
	without := receiverWithFeatures()
	without.SupportedFormats.ScreenStream = FormatMask(screenAudioFormatALAC)
	with := receiverWithFeatures(featureRFC2198Redundancy)
	with.SupportedFormats.ScreenStream = FormatMask(screenAudioFormatALAC)
	if mustCompatibility(t, &without, false).audioRFC2198 {
		t.Fatal("RFC 2198 enabled without feature 61")
	}
	if !mustCompatibility(t, &with, false).audioRFC2198 {
		t.Fatal("RFC 2198 disabled with feature 61")
	}
}

func TestUnsupportedScreenAudioFormatDoesNotBlockVideoOnlySession(t *testing.T) {
	info := &ReceiverInfo{SupportedFormats: StreamFormats{ScreenStream: 0x800000}}
	policy, err := compatibilityForReceiver(info, false, false)
	if err != nil {
		t.Fatalf("video-only compatibility: %v", err)
	}
	if policy.audioCodec != AudioCodecALAC {
		t.Fatalf("inert video-only audio descriptor codec = %d, want ALAC", policy.audioCodec)
	}
}

func TestAudioSecurityUsesNegotiatedEncryption(t *testing.T) {
	legacyFeature := receiverWithFeatures()
	if got := mustCompatibility(t, &legacyFeature, false).audioSecurity; got != audioSecurityLegacyAES {
		t.Fatalf("plaintext audio security = %d, want legacy AES", got)
	}
	if got := mustCompatibility(t, &legacyFeature, true).audioSecurity; got != audioSecurityChaCha {
		t.Fatalf("encrypted audio security = %d, want ChaCha", got)
	}
}

func TestIdentityDoesNotChangeCompatibilityPolicy(t *testing.T) {
	base := receiverWithFeatures(featurePTP, featureAudioStreamConnectionSetup)
	base.SourceVersion = "980.71.1"
	want := mustCompatibility(t, &base, true)

	for _, identity := range []ReceiverInfo{
		{Name: "receiver one", Model: "model one", Manufacturer: "vendor one"},
		{Name: "receiver two", Model: "model two", Manufacturer: "vendor two"},
	} {
		info := base
		info.Name = identity.Name
		info.Model = identity.Model
		info.Manufacturer = identity.Manufacturer
		if got := mustCompatibility(t, &info, true); !reflect.DeepEqual(got, want) {
			t.Fatalf("identity changed compatibility policy: got %+v, want %+v", got, want)
		}
	}
}

func TestHybridAudioDescriptorLayouts(t *testing.T) {
	key := make([]byte, 32)
	legacy := map[string]interface{}{}
	addScreenAudioStreamFields(legacy, key, 6001, audioLayoutControlPort)
	if got := plistInt(legacy["controlPort"]); got != 6001 {
		t.Fatalf("legacy controlPort = %d, want 6001", got)
	}
	if got, _ := legacy["shk"].([]byte); len(got) != len(key) {
		t.Fatalf("legacy shk length = %d, want %d", len(got), len(key))
	}
	if _, ok := legacy["streamConnections"]; ok {
		t.Fatal("legacy audio unexpectedly contains streamConnections")
	}

	modern := map[string]interface{}{"controlPort": int64(1)}
	addScreenAudioStreamFields(modern, key, 6002, audioLayoutStreamConnections)
	if _, ok := modern["controlPort"]; ok {
		t.Fatal("modern audio retained controlPort")
	}
	connections, _ := modern["streamConnections"].(map[string]interface{})
	if len(connections) == 0 {
		t.Fatal("modern audio omitted streamConnections")
	}

	plaintext := map[string]interface{}{}
	addScreenAudioStreamFields(plaintext, nil, 6003, audioLayoutStreamConnections)
	if _, ok := plaintext["shk"]; ok {
		t.Fatal("plaintext streamConnections descriptor unexpectedly contains shk")
	}
	plaintextConnections, _ := plaintext["streamConnections"].(map[string]interface{})
	rtp, _ := plaintextConnections["streamConnectionTypeRTP"].(map[string]interface{})
	if encrypted, ok := rtp["streamConnectionKeyUseStreamEncryptionKey"].(bool); !ok || encrypted {
		t.Fatalf("plaintext streamConnections encryption flag = %#v, want false", rtp["streamConnectionKeyUseStreamEncryptionKey"])
	}
}
