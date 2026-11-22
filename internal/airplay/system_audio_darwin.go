//go:build cgo && !no_gstreamer

package airplay

/*
#cgo CFLAGS: -fobjc-arc
#cgo LDFLAGS: -framework Foundation -framework ScreenCaptureKit -framework CoreMedia -framework CoreGraphics -framework AudioToolbox
void *dt_system_audio_start(void *pipeline);
void dt_system_audio_stop(void *capture);
*/
import "C"

import (
	"errors"
	"unsafe"
)

func startSystemAudio(pipeline unsafe.Pointer) (func(), error) {
	capture := C.dt_system_audio_start(pipeline)
	if capture == nil {
		return nil, errors.New("system audio requires ScreenCaptureKit on macOS 13 or later")
	}
	return func() { C.dt_system_audio_stop(capture) }, nil
}
