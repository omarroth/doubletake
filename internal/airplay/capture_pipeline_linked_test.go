//go:build gstreamer_cgo && cgo && linux

package airplay

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestLinkedPipelineArgumentsNameControllableElements(t *testing.T) {
	got, err := linkedPipelineArguments([]string{
		"--quiet", "videotestsrc", "!", "x264enc", "bitrate=1000", "!",
		"h264parse", "!", "fdsink", "fd=1", "sync=false", "async=false",
	}, "x264enc")
	if err != nil {
		t.Fatal(err)
	}
	pipeline := strings.Join(got, " ")
	if !strings.Contains(pipeline, "x264enc name="+linkedEncoderName+" bitrate=1000") {
		t.Fatalf("encoder was not named in %q", pipeline)
	}
	if !strings.HasSuffix(pipeline, "appsink name="+linkedOutputName+" sync=false async=false max-buffers=8 drop=false") {
		t.Fatalf("fdsink was not replaced in %q", pipeline)
	}
	if strings.Contains(pipeline, "fd=1") || strings.Contains(pipeline, "--quiet") {
		t.Fatalf("gst-launch-only arguments remain in %q", pipeline)
	}
}

func TestLinkedEncoderBitrateUnitsCoverSelectedBackends(t *testing.T) {
	tests := []struct {
		encoder string
		value   uint64
		v4l2    bool
	}{
		{"x264enc", 2500, false},
		{"x265enc", 2500, false},
		{"vulkanh264enc", 2500, false},
		{"nvh264enc", 2500, false},
		{"nvh265enc", 2500, false},
		{"vah264enc", 2500, false},
		{"openh264enc", 2_500_000, false},
		{"v4l2h264enc", 2_500_000, true},
	}
	for _, test := range tests {
		value, v4l2, err := linkedEncoderBitrateValue(test.encoder, 2500)
		if err != nil {
			t.Fatalf("%s: %v", test.encoder, err)
		}
		if value != test.value || v4l2 != test.v4l2 {
			t.Errorf("%s setting = (%d, %t), want (%d, %t)", test.encoder, value, v4l2, test.value, test.v4l2)
		}
	}
}

func TestLinkedTestCaptureChangesBitrateAndRequestsKeyFrame(t *testing.T) {
	if !hasGstElement("x264enc") || !supportsTimestampedVideoOutput(VideoCodecH264) {
		t.Skip("GStreamer H.264 timestamp pipeline is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	capture, err := StartTestCapture(ctx, CaptureConfig{
		FPS: 10, Bitrate: 1000, HWAccel: "none", VideoCodec: VideoCodecH264,
		MaxWidth: 320, MaxHeight: 180,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()
	if !capture.SupportsRuntimeVideoControl() {
		t.Fatal("linked capture did not advertise runtime video control")
	}

	if err := capture.SetBitrateKbps(700); err != nil {
		t.Fatalf("change live x264 bitrate: %v", err)
	}
	if got := capture.Format().BitrateKbps; got != 700 {
		t.Fatalf("reported bitrate = %d kbps, want 700", got)
	}
	if err := capture.SetFrameRate(5); err != nil {
		t.Fatalf("change live pipeline frame rate: %v", err)
	}
	if got := capture.Format().FPS; got != 5 {
		t.Fatalf("reported frame rate = %d, want 5", got)
	}
	if err := capture.RequestKeyFrame(); err != nil {
		t.Fatalf("request live x264 key frame: %v", err)
	}

	for frame := 0; frame < 20; frame++ {
		unit, err := capture.ReadVideoAccessUnit()
		if err != nil {
			t.Fatal(err)
		}
		for _, wrapped := range splitAnnexBAccessUnit(unit.AnnexB) {
			raw := stripStartCode(wrapped)
			if len(raw) != 0 && raw[0]&0x1f == 5 {
				return
			}
		}
	}
	t.Fatal("encoder did not produce an IDR after force-key-unit request")
}
