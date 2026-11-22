//go:build !cgo || !(linux || darwin || windows)

package airplay

import "testing"

func TestStaticBuildReportsNoInProcessGStreamer(t *testing.T) {
	if HasInProcessGStreamer() {
		t.Fatal("static build unexpectedly reported in-process GStreamer support")
	}
}
