//go:build !gstreamer_cgo || !cgo || !linux

package airplay

import "testing"

func TestStaticBuildReportsNoInProcessGStreamer(t *testing.T) {
	if HasInProcessGStreamer() {
		t.Fatal("static build unexpectedly reported in-process GStreamer support")
	}
}
