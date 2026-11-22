package airplay

import "io"

type captureRuntimeController interface {
	setBitrateKbps(int) error
	setFrameRate(int) error
	requestKeyFrame() error
	stop()
}

type runningGStreamerPipeline struct {
	stdout     io.ReadCloser
	waitResult <-chan error
	runtime    captureRuntimeController
}
