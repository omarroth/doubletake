//go:build !cgo || !fdk_aac

package airplay

import (
	"errors"
	"testing"
)

func TestAACELDStubReportsUnavailable(t *testing.T) {
	if aacELDEncoderAvailable {
		t.Fatal("stub build advertised an AAC-ELD encoder")
	}
	if _, err := newELDEncoder(); !errors.Is(err, ErrAACELDUnavailable) {
		t.Fatalf("newELDEncoder error = %v, want ErrAACELDUnavailable", err)
	}
}
