//go:build !cgo || !fdk_aac

package airplay

import "fmt"

func newReceiverELDDecoder(receiverDecodeCallbacks) (receiverDecoder, error) {
	return nil, fmt.Errorf("AAC-ELD playback requires an fdk_aac build and FDK-AAC runtime decoder")
}
