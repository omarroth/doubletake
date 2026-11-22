//go:build !cgo || !(linux || darwin || windows)

package airplay

import (
	"context"
	"errors"
	"io"
	"os"
)

var errGStreamerUnavailable = errors.New("media capture requires cgo and the GStreamer development libraries")

func HasInProcessGStreamer() bool                      { return false }
func hasGstElement(string) bool                        { return false }
func hasGstProperty(string, string) bool               { return false }
func probeGstPipeline(context.Context, []string) error { return errGStreamerUnavailable }
func launchGStreamerPipeline(context.Context, []string, encoderResult, *os.File) (*runningGStreamerPipeline, error) {
	return nil, errGStreamerUnavailable
}
func launchLinkedMediaGraph(context.Context, string, encoderResult, []string, []string) (*runningGStreamerPipeline, io.ReadCloser, error) {
	return nil, nil, errGStreamerUnavailable
}

func launchAudioPipeline(context.Context, []string, bool) (*runningGStreamerPipeline, error) {
	return nil, errGStreamerUnavailable
}
