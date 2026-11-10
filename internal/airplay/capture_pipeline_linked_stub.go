//go:build !gstreamer_cgo || !cgo || !linux

package airplay

import (
	"context"
	"os"
)

// HasInProcessGStreamer reports whether this binary owns its video pipeline.
// Static fallback builds launch gst-launch-1.0 and cannot adjust it at runtime.
func HasInProcessGStreamer() bool { return false }

func launchLinkedGStreamerPipeline(context.Context, []string, encoderResult, []*os.File) (*runningGStreamerPipeline, bool, error) {
	return nil, false, nil
}
