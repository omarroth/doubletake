//go:build no_gstreamer && cgo && (darwin || windows)

package airplay

import (
	"context"
	"testing"
	"time"
)

func TestNativeDesktopPattern(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	capture, err := StartTestCapture(ctx, CaptureConfig{
		VideoCodec: VideoCodecH264, FPS: 15, Bitrate: 800,
		MaxWidth: 320, MaxHeight: 192,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()
	if got := capture.Format(); got.Width != 320 || got.Height != 192 || got.Codec != VideoCodecH264 {
		t.Fatalf("native capture format = %+v", got)
	}
	var previous time.Time
	for i := 0; i < 8; i++ {
		unit, err := capture.ReadVideoAccessUnit()
		if err != nil {
			t.Fatal(err)
		}
		if len(unit.AnnexB) == 0 || !unit.PTS.After(previous) || time.Since(unit.PTS) < -20*time.Millisecond {
			t.Fatalf("invalid native frame %d at %v", i, unit.PTS)
		}
		previous = unit.PTS
	}
	if err := capture.SetFrameRate(8); err != nil {
		t.Fatal(err)
	}
	if got := capture.Format().FPS; got != 8 {
		t.Fatalf("native capture rate = %d", got)
	}
	cancel()
	capture.Stop()
}
