//go:build !cgo || !fdk_aac

package airplay

import "fmt"

const aacELDEncoderAvailable = false

// eldEncoder keeps codec negotiation available in builds without fdk_aac.
// Default sender builds include the encoder bridge; pure Go builds, including
// the static controller, use this stub.
type eldEncoder struct{}

func newELDEncoder() (*eldEncoder, error) {
	return nil, fmt.Errorf("%w (install libfdk-aac development files and build with -tags fdk_aac)", ErrAACELDUnavailable)
}

func (*eldEncoder) Encode([]byte, []byte) (int, error) {
	return 0, ErrAACELDUnavailable
}

func (*eldEncoder) Close() {}
