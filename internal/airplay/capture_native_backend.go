package airplay

import (
	"context"
	"fmt"
	"runtime"
)

// A native build registers the capture paths supported by its operating system.
var openNativeVideo func(startup, lifetime context.Context, cfg CaptureConfig, test bool) (*ScreenCapture, error)

func prepareNativeVideo(ctx context.Context, cfg CaptureConfig, test bool) (*CapturePreparation, error) {
	if openNativeVideo == nil {
		return nil, fmt.Errorf("desktop video on this platform requires a GStreamer build")
	}
	if cfg.X11WindowID != 0 || cfg.X11WindowName != "" {
		return nil, fmt.Errorf("X11 window options require the X11 capture backend")
	}
	if cfg.HWAccel != "" && cfg.HWAccel != "auto" && cfg.HWAccel != "none" {
		return nil, fmt.Errorf("this native capture backend accepts -hwaccel auto or none")
	}
	if runtime.GOOS == "windows" && cfg.VideoCodec == VideoCodecHEVC {
		return nil, fmt.Errorf("native Windows capture supports H.264")
	}
	kind := capturePreparationNativeDesktop
	if test {
		kind = capturePreparationTest
	}
	return &CapturePreparation{ctx: ctx, cfg: cfg, kind: kind, timestampedOutput: true}, nil
}
