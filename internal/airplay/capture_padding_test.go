package airplay

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestVAPlainRawPaddingUsesNegotiatedPixels(t *testing.T) {
	encoder := encoderResult{parts: gstStage{"nvh264enc"}, rawFormat: "NV12"}
	pipeline := buildVAPostprocPlainRawWaylandVideoPipeline(3, 42, 30, encoder, 256, 144, false)
	joined := strings.Join(pipeline, " ")
	if !strings.Contains(joined, "vapostproc disable-passthrough=true add-borders=false video-direction=auto ! video/x-raw,format=NV12 ! videoscale add-borders=true ! video/x-raw,width=256,height=144,pixel-aspect-ratio=1/1") {
		t.Fatalf("VA must preserve source geometry until software fits and fills borders: %s", joined)
	}
	for _, element := range []string{"videotestsrc", "videoscale"} {
		if !hasGstElement(element) {
			t.Skipf("GStreamer %s unavailable", element)
		}
	}
	// Test the actual padding stages on plain frames, as delivered by the VA
	// download boundary. This does not require or claim to exercise a VA driver.
	for _, size := range [][2]int{{192, 128}, {128, 192}, {256, 144}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			args := []string{"--quiet", "videotestsrc", "num-buffers=1", "pattern=white", "!", fmt.Sprintf("video/x-raw,format=NV12,width=%d,height=%d,pixel-aspect-ratio=1/1,colorimetry=bt709", size[0], size[1])}
			for i, arg := range pipeline {
				if arg == "videoscale" {
					args = append(args, pipeline[i-1:i+4]...)
					break
				}
			}
			args = appendGstStage(args, gstStage{"fdsink", "fd=1", "sync=false"})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "gst-launch-1.0", args...)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			got, err := cmd.Output()
			if err != nil {
				t.Fatalf("padding: %v: %s", err, stderr.String())
			}
			if len(got) != 256*144*3/2 {
				t.Fatalf("padded frame has %d bytes", len(got))
			}
			if center := got[72*256+128]; center != 235 {
				t.Fatalf("white content was altered: luma %d", center)
			}
			wantCorner := byte(16)
			if size == [2]int{256, 144} {
				wantCorner = 235
			}
			for _, offset := range []int{0, 255, 143 * 256, 144*256 - 1} {
				if got[offset] != wantCorner {
					t.Errorf("corner luma=%d, want %d", got[offset], wantCorner)
				}
			}
			// Black NV12 must have neutral chroma. All-zero chroma is green.
			for _, chroma := range got[256*144:] {
				if chroma != 128 {
					t.Fatalf("padding contains non-neutral chroma %d", chroma)
				}
			}
		})
	}
}
