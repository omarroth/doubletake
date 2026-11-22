//go:build !cgo || !(linux || darwin || windows) || no_gstreamer

package airplay

import "fmt"

func receiverDecoderAvailable() bool { return false }
func newReceiverMediaDecoder(string, []byte, receiverDecodeCallbacks) (receiverDecoder, error) {
	return nil, fmt.Errorf("headless playback requires cgo and GStreamer; use make doubletake-test-receiver")
}
