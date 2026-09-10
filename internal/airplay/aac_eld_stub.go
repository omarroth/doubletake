//go:build !cgo || !fdk_aac

package airplay

import "fmt"

const aacELDEncoderAvailable = false

// eldEncoder is present in every build so codec negotiation remains portable.
// The actual encoder is deliberately opt-in: libfdk-aac is not available on
// every supported distribution and doubletake's release binaries are static.
type eldEncoder struct{}

func newELDEncoder() (*eldEncoder, error) {
	return nil, fmt.Errorf("%w (install libfdk-aac development files and build with -tags fdk_aac)", ErrAACELDUnavailable)
}

func (*eldEncoder) Encode([]byte, []byte) (int, error) {
	return 0, ErrAACELDUnavailable
}

func (*eldEncoder) Close() {}
