//go:build !gstreamer_cgo || !cgo || !linux

package airplay

import (
	"context"
	"errors"
	"os"
)

// HasInProcessGStreamer reports whether this binary owns its video pipeline.
// Static fallback builds launch gst-launch-1.0 and cannot adjust it at runtime.
func HasInProcessGStreamer() bool { return false }

func launchLinkedGStreamerPipeline(context.Context, []string, encoderResult, []*os.File) (*runningGStreamerPipeline, bool, error) {
	return nil, false, nil
}

func launchLinkedMediaGraph(context.Context, []string, encoderResult, *os.File, *os.File, *os.File, *os.File) (*runningGStreamerPipeline, error) {
	return nil, errors.New("linked GStreamer playback unavailable")
}
