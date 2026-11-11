package airplay

import (
	"context"
	"strings"
	"testing"
)

func TestReceiverVideoCanvasUsesMaximumOnlyForCapabilityGatedHEVC(t *testing.T) {
	info := &ReceiverInfo{
		Features: uint64(1) << featureScreenMultiCodec,
		Displays: []DisplayInfo{{
			WidthPixels: 1280, HeightPixels: 720,
			WidthPixelsMax: 3840, HeightPixelsMax: 2160,
		}},
	}
	if width, height, err := info.videoCanvas(VideoCodecH264); err != nil || width != 1280 || height != 720 {
		t.Fatalf("H.264 canvas = %dx%d err=%v, want nominal 1280x720", width, height, err)
	}
	if width, height, err := info.videoCanvas(VideoCodecHEVC); err != nil || width != 3840 || height != 2160 {
		t.Fatalf("HEVC canvas = %dx%d err=%v, want maximum 3840x2160", width, height, err)
	}
	info.Features &^= uint64(1) << featureScreenMultiCodec
	if _, _, err := info.videoCanvas(VideoCodecHEVC); err == nil {
		t.Fatal("HEVC canvas accepted without feature 42")
	}
}

func TestAutomaticVideoSelectionUsesHighestAvailableCanvas(t *testing.T) {
	tests := []struct {
		name                   string
		info                   *ReceiverInfo
		automaticHEVCAvailable bool
		wantCodec              VideoCodec
		wantWidth, wantHeight  int
	}{
		{name: "multi-codec high resolution", automaticHEVCAvailable: true, wantCodec: VideoCodecHEVC, wantWidth: 3840, wantHeight: 2160, info: &ReceiverInfo{
			Features: uint64(1) << featureScreenMultiCodec,
			Displays: []DisplayInfo{{WidthPixels: 1280, HeightPixels: 720, WidthPixelsMax: 3840, HeightPixelsMax: 2160}},
		}},
		{name: "local HEVC unavailable", wantCodec: VideoCodecH264, wantWidth: 1280, wantHeight: 720, info: &ReceiverInfo{
			Features: uint64(1) << featureScreenMultiCodec,
			Displays: []DisplayInfo{{WidthPixels: 1280, HeightPixels: 720, WidthPixelsMax: 3840, HeightPixelsMax: 2160}},
		}},
		{name: "legacy receiver", automaticHEVCAvailable: true, wantCodec: VideoCodecH264, wantWidth: 1280, wantHeight: 720, info: &ReceiverInfo{
			Displays: []DisplayInfo{{WidthPixels: 1280, HeightPixels: 720}},
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selection, err := test.info.selectVideo(VideoCodecAuto, test.automaticHEVCAvailable)
			if err != nil {
				t.Fatal(err)
			}
			if selection.codec != test.wantCodec || selection.width != test.wantWidth || selection.height != test.wantHeight {
				t.Fatalf("selection = %s %dx%d, want %s %dx%d", selection.codec, selection.width, selection.height, test.wantCodec, test.wantWidth, test.wantHeight)
			}
		})
	}
}

func TestAutomaticVideoSelectionHonorsTargetCanvas(t *testing.T) {
	info := &ReceiverInfo{
		Features: uint64(1) << featureScreenMultiCodec,
		Displays: []DisplayInfo{{
			WidthPixels: 1280, HeightPixels: 720,
			WidthPixelsMax: 3840, HeightPixelsMax: 2160,
		}},
	}
	for _, test := range []struct {
		name                  string
		width, height         int
		wantCodec             VideoCodec
		wantWidth, wantHeight int
	}{
		{name: "ordinary target stays H264", width: 1280, height: 720, wantCodec: VideoCodecH264, wantWidth: 1280, wantHeight: 720},
		{name: "larger target selects HEVC", width: 2560, height: 1440, wantCodec: VideoCodecHEVC, wantWidth: 2560, wantHeight: 1440},
		{name: "oversize target fits receiver maximum", width: 5000, height: 3000, wantCodec: VideoCodecHEVC, wantWidth: 3600, wantHeight: 2160},
		{name: "odd target normalizes for 4:2:0", width: 1279, height: 719, wantCodec: VideoCodecH264, wantWidth: 1278, wantHeight: 718},
	} {
		t.Run(test.name, func(t *testing.T) {
			selection, err := info.selectVideoTarget(VideoCodecAuto, true, test.width, test.height)
			if err != nil {
				t.Fatal(err)
			}
			if selection.codec != test.wantCodec || selection.width != test.wantWidth || selection.height != test.wantHeight {
				t.Fatalf("selection = %s %dx%d, want %s %dx%d", selection.codec, selection.width, selection.height, test.wantCodec, test.wantWidth, test.wantHeight)
			}
		})
	}
	if _, err := info.selectVideoTarget(VideoCodecAuto, true, 1920, 0); err == nil {
		t.Fatal("accepted an incomplete target canvas")
	}
}

func TestExplicitHEVCSelectionCapsMaximumPreservingAspect(t *testing.T) {
	info := &ReceiverInfo{
		Features: uint64(1) << featureScreenMultiCodec,
		Displays: []DisplayInfo{{
			WidthPixels: 1920, HeightPixels: 1080,
			WidthPixelsMax: 7680, HeightPixelsMax: 2160,
		}},
	}
	forced, err := info.selectVideo(VideoCodecHEVC, false)
	if err != nil {
		t.Fatal(err)
	}
	if forced.width != 3840 || forced.height != 1080 {
		t.Fatalf("forced HEVC canvas = %dx%d, want capped 3840x1080", forced.width, forced.height)
	}
}

func TestExplicitVideoCodecOverridesAutomaticPolicy(t *testing.T) {
	info := &ReceiverInfo{
		Features: uint64(1) << featureScreenMultiCodec,
		Displays: []DisplayInfo{{
			WidthPixels: 1280, HeightPixels: 720,
			WidthPixelsMax: 3840, HeightPixelsMax: 2160,
		}},
	}
	h264, err := info.selectVideo(VideoCodecH264, true)
	if err != nil {
		t.Fatal(err)
	}
	if h264.codec != VideoCodecH264 || h264.width != 1280 || h264.height != 720 {
		t.Fatalf("explicit H.264 = %s %dx%d", h264.codec, h264.width, h264.height)
	}

	hevc, err := info.selectVideo(VideoCodecHEVC, false)
	if err != nil {
		t.Fatal(err)
	}
	if hevc.codec != VideoCodecHEVC || hevc.width != 3840 || hevc.height != 2160 {
		t.Fatalf("explicit HEVC = %s %dx%d", hevc.codec, hevc.width, hevc.height)
	}
}

func TestValidateVideoCodecAcceptsAuto(t *testing.T) {
	for _, codec := range []string{"", "auto", "h264", "hevc"} {
		if err := ValidateVideoCodec(codec); err != nil {
			t.Errorf("ValidateVideoCodec(%q): %v", codec, err)
		}
	}
	if err := ValidateVideoCodec("vp9"); err == nil || !strings.Contains(err.Error(), "auto, h264, or hevc") {
		t.Fatalf("ValidateVideoCodec(vp9) error = %v", err)
	}
}

func TestLegacyMirrorPreparationAPIRejectsAutomaticCodec(t *testing.T) {
	client := &AirPlayClient{}
	if _, err := client.SetupMirror(context.Background(), StreamConfig{VideoCodec: VideoCodecAuto}); err == nil || !strings.Contains(err.Error(), "VideoCodecPreparation") {
		t.Fatalf("SetupMirror(auto) error = %v", err)
	}
	if _, err := client.SetupMirrorWithVideoPreparation(context.Background(), StreamConfig{VideoCodec: VideoCodecAuto}, func(int, int) error { return nil }); err == nil || !strings.Contains(err.Error(), "VideoCodecPreparation") {
		t.Fatalf("legacy preparation(auto) error = %v", err)
	}
}

func TestH264UsesAdvertisedMaximumWithin1080p(t *testing.T) {
	for _, test := range []struct {
		name         string
		maxW, maxH   int
		wantW, wantH int
	}{
		{"1080p maximum", 1920, 1080, 1920, 1080},
		{"intermediate maximum", 1600, 900, 1600, 900},
		{"missing maximum", 0, 0, 1280, 720},
		{"incomplete maximum", 1920, 0, 1280, 720},
		{"smaller maximum", 640, 360, 1280, 720},
		{"high resolution needs separate codec gate", 3840, 2160, 1280, 720},
		{"oversized width", 1921, 1080, 1280, 720},
	} {
		t.Run(test.name, func(t *testing.T) {
			info := &ReceiverInfo{Model: "IndependentModel", Displays: []DisplayInfo{{
				WidthPixels: 1280, HeightPixels: 720,
				WidthPixelsMax: plistNumber(test.maxW), HeightPixelsMax: plistNumber(test.maxH),
			}}}
			for _, codec := range []VideoCodec{VideoCodecAuto, VideoCodecH264} {
				selection, err := info.selectVideo(codec, false)
				if err != nil || selection.codec != VideoCodecH264 || selection.width != test.wantW || selection.height != test.wantH {
					t.Fatalf("selection(%s) = %+v, err=%v, want H.264 %dx%d", codec, selection, err, test.wantW, test.wantH)
				}
			}
			if w, h, err := info.videoCanvas(VideoCodecH264); err != nil || w != test.wantW || h != test.wantH {
				t.Fatalf("canvas = %dx%d err=%v, want %dx%d", w, h, err, test.wantW, test.wantH)
			}
		})
	}
}
