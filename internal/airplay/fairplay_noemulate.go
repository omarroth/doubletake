//go:build !emulate

package airplay

import (
	"context"
	"fmt"
)

func (c *AirPlayClient) fairPlaySetupEmulated(ctx context.Context) error {
	return fmt.Errorf("ARM64 emulation not available (build without -tags emulate); unset FAIRPLAY_EMULATE to use the native Go implementation")
}
