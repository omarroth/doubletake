//go:build !cgo || !(linux || darwin || windows) || no_gstreamer

package airplay

import "testing"

func TestStaticBuildReportsNoInProcessGStreamer(t *testing.T) {
	if HasInProcessGStreamer() {
		t.Fatal("static build unexpectedly reported in-process GStreamer support")
	}
}
