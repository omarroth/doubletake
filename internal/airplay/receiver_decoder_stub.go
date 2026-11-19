//go:build !gstreamer_cgo || !cgo || !linux

package airplay

import "fmt"

func receiverDecoderAvailable() bool { return false }
func receiverHasDecoder(string) bool { return false }
func newReceiverMediaDecoder(string, []byte, receiverDecodeCallbacks) (receiverDecoder, error) {
	return nil, fmt.Errorf("headless playback requires a gstreamer_cgo build; use make doubletake-test-receiver")
}
