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

func gstreamerVersionAtLeast(t *testing.T, wantMajor, wantMinor int) bool {
	t.Helper()
	out, err := exec.Command("gst-launch-1.0", "--version").Output()
	if err != nil {
		t.Fatalf("get GStreamer version: %v", err)
	}
	var major, minor int
	if _, err := fmt.Sscanf(string(out), "gst-launch-1.0 version %d.%d", &major, &minor); err != nil {
		t.Fatalf("parse GStreamer version %q: %v", strings.TrimSpace(string(out)), err)
	}
	return major > wantMajor || major == wantMajor && minor >= wantMinor
}

func TestWaylandOrientationAppliedBeforeCanvas(t *testing.T) {
	encoder := encoderResult{parts: gstStage{"openh264enc"}, rawFormat: "I420", codec: VideoCodecH264}
	software := strings.Join(buildSystemWaylandVideoPipeline(3, 42, 30, encoder, 1920, 1080, true), " ")
	flip := strings.Index(software, "videoflip video-direction=auto")
	scale := strings.Index(software, "videoscale")
	if flip < 0 || flip > scale {
		t.Fatalf("orientation must precede scaling: %s", software)
	}
	for _, pipeline := range [][]string{
		buildVAWaylandVideoPipeline(3, 42, 30, encoder, 1920, 1080, true),
		buildVAPostprocPlainRawWaylandVideoPipeline(3, 42, 30, encoder, 1920, 1080, true),
	} {
		joined := strings.Join(pipeline, " ")
		if !strings.Contains(joined, "video-direction=auto !") {
			t.Fatalf("VA orientation must be applied during import: %s", joined)
		}
		if strings.Contains(joined, "videoflip") {
			t.Fatalf("VA path unexpectedly maps frames for CPU rotation: %s", joined)
		}
	}
}

func TestWaylandOrientationPixels(t *testing.T) {
	for _, element := range []string{"rawvideoparse", "taginject", "videoflip"} {
		if !hasGstElement(element) {
			t.Skipf("GStreamer %s unavailable", element)
		}
	}
	// Distinct pixels in a nonsquare image expose swapped axes and reflection
	// direction errors; dimensions remain multiples of four to avoid row padding.
	const width, height = 8, 4
	pixels := make([]byte, width*height)
	for i := range pixels {
		pixels[i] = byte(i + 1)
	}
	tests := []struct {
		tag    string
		swap   bool
		source func(x, y int) (int, int)
	}{
		{"rotate-0", false, func(x, y int) (int, int) { return x, y }},
		{"rotate-90", true, func(x, y int) (int, int) { return y, height - 1 - x }},
		{"rotate-180", false, func(x, y int) (int, int) { return width - 1 - x, height - 1 - y }},
		{"rotate-270", true, func(x, y int) (int, int) { return width - 1 - y, x }},
		{"flip-rotate-0", false, func(x, y int) (int, int) { return width - 1 - x, y }},
		{"flip-rotate-90", true, func(x, y int) (int, int) { return width - 1 - y, height - 1 - x }},
		{"flip-rotate-180", false, func(x, y int) (int, int) { return x, height - 1 - y }},
		{"flip-rotate-270", true, func(x, y int) (int, int) { return y, x }},
	}
	for _, test := range tests {
		t.Run(test.tag, func(t *testing.T) {
			if (test.tag == "flip-rotate-90" || test.tag == "flip-rotate-270") && !gstreamerVersionAtLeast(t, 1, 20) {
				// GStreamer 1.16 uses the opposite names for these two diagonal
				// transforms. Its contemporary PipeWire plugin does not publish
				// orientation tags, so retain the portable pipeline and exercise
				// the standardized mapping where that integration is available.
				t.Skip("legacy GStreamer diagonal orientation-tag mapping")
			}
			w, h := width, height
			if test.swap {
				w, h = h, w
			}
			args := []string{"--quiet", "fdsrc", "fd=0", "!", "rawvideoparse", "format=gray8", "width=8", "height=4", "framerate=1/1",
				"!", "taginject", "tags=image-orientation=" + test.tag}
			// Use the exact stage selected by the production software pipeline.
			production := buildSystemWaylandVideoPipeline(3, 42, 30, encoderResult{rawFormat: "I420"}, 0, 0, false)
			for i, arg := range production {
				if arg == "videoflip" {
					args = appendGstStage(args, gstStage(production[i:i+2]))
					break
				}
			}
			args = appendGstStage(args, gstStage{"video/x-raw,format=GRAY8"})
			args = appendGstStage(args, gstStage{"fdsink", "fd=1", "sync=false"})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, "gst-launch-1.0", args...)
			cmd.Stdin = bytes.NewReader(pixels)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			got, err := cmd.Output()
			if err != nil {
				t.Fatalf("rotation pipeline: %v: %s", err, stderr.String())
			}
			want := make([]byte, len(pixels))
			for y := range h {
				for x := range w {
					sx, sy := test.source(x, y)
					want[y*w+x] = pixels[sy*width+sx]
				}
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("transformed pixels = %v, want %v", got, want)
			}
		})
	}
}
