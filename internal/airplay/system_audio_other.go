//go:build cgo && (linux || windows)

package airplay

import (
	"errors"
	"unsafe"
)

func startSystemAudio(unsafe.Pointer) (func(), error) {
	return nil, errors.New("ScreenCaptureKit requires macOS")
}
