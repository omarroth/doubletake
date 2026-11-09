//go:build !gstreamer_cgo || !cgo || !linux

package airplay

import (
	"context"
	"os"
)

func launchLinkedGStreamerPipeline(context.Context, []string, encoderResult, []*os.File) (*runningGStreamerPipeline, bool, error) {
	return nil, false, nil
}
