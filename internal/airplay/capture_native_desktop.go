package airplay

import (
	"context"
	"fmt"
	"runtime"
	"strconv"
)

func nativeDesktopSource(platform string, cursor bool) gstStage {
	switch platform {
	case "darwin":
		return gstStage{"avfvideosrc", "capture-screen=true", "capture-screen-cursor=" + strconv.FormatBool(cursor)}
	case "windows":
		return gstStage{"d3d11screencapturesrc", "show-cursor=" + strconv.FormatBool(cursor)}
	default:
		return nil
	}
}

func startNativeDesktopCapture(startup, lifetime context.Context, cfg CaptureConfig, encoder encoderResult, timestamped bool) (*ScreenCapture, error) {
	ctx, cancel := context.WithCancel(lifetime)
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	stages := []gstStage{{"videorate", "drop-only=true", "max-rate=" + strconv.Itoa(fps)}, lowLatencyVideoQueueStage()}
	args := buildGstVideoPipeline(nativeDesktopSource(runtime.GOOS, cfg.ShowCursor), stages, nil, encoder, cfg.MaxWidth, cfg.MaxHeight, timestamped)
	pipeline, err := launchGStreamerPipeline(ctx, args, encoder, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	capture := &ScreenCapture{
		stdout: pipeline.stdout, cancel: cancel, runtime: pipeline.runtime,
		waitCh: make(chan struct{}), format: captureFormat(cfg, encoder),
	}
	capture.enableAutomaticVideoRateControl(cfg)
	if timestamped {
		capture.frames = newRTPVideoAccessUnitReader(pipeline.stdout, encoder.codec)
	}
	go func() {
		capture.waitErr = <-pipeline.waitResult
		close(capture.waitCh)
	}()
	probeCtx, stopProbe := context.WithTimeout(startup, captureStartupProbeTimeout(fps))
	defer stopProbe()
	if err := probeVideoCaptureStartup(probeCtx, capture, encoder.codec, timestamped); err != nil {
		capture.Stop()
		return nil, fmt.Errorf("desktop capture: %w", capture.withPipelineError(err))
	}
	return capture, nil
}
