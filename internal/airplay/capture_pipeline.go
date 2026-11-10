package airplay

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
)

// captureRuntimeController is implemented by an in-process GStreamer pipeline.
// gst-launch deliberately has no equivalent control channel: once launched, its
// element properties cannot be changed by the parent process.
type captureRuntimeController interface {
	setBitrateKbps(int) error
	setFrameRate(int) error
	requestKeyFrame() error
	stop()
}

type runningGStreamerPipeline struct {
	cmd        *exec.Cmd
	stdout     io.ReadCloser
	waitResult <-chan error
	stderr     *captureStderrTail
	runtime    captureRuntimeController
}

// launchGStreamerPipeline selects the build-time capture backend. The default
// binary links libgstreamer and owns the graph in-process. The static fallback
// retains the gst-launch child process.
func launchGStreamerPipeline(ctx context.Context, args []string, encoder encoderResult, extraFiles []*os.File) (*runningGStreamerPipeline, error) {
	if pipeline, handled, err := launchLinkedGStreamerPipeline(ctx, args, encoder, extraFiles); handled {
		if err != nil {
			return nil, fmt.Errorf("start linked GStreamer pipeline: %w", err)
		}
		return pipeline, nil
	}

	cmd := exec.CommandContext(ctx, "gst-launch-1.0", args...)
	cmd.ExtraFiles = extraFiles
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdout.Close()
		return nil, fmt.Errorf("gst stderr pipe: %w", err)
	}
	waitResult, err := startGStreamerCommand(cmd)
	if err != nil {
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, fmt.Errorf("start gst-launch-1.0: %w", err)
	}
	stderrTail := newCaptureStderrTail()
	go logStderr("GST", stderr, stderrTail)
	return &runningGStreamerPipeline{
		cmd: cmd, stdout: stdout, waitResult: waitResult, stderr: stderrTail,
	}, nil
}
