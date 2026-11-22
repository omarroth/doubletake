//go:build cgo && (linux || windows) && !no_gstreamer

package airplay

import (
	"errors"
	"unsafe"
)

func startSystemAudio(unsafe.Pointer) (func(), error) {
	return nil, errors.New("ScreenCaptureKit requires macOS")
}
