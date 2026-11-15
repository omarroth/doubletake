//go:build cgo && fdk_aac

package airplay

/*
#cgo linux LDFLAGS: -ldl
#cgo !linux pkg-config: fdk-aac
#include "aac_eld_fdk_loader.h"
*/
import "C"

import (
	"fmt"
	"unsafe"
)

var aacELDEncoderAvailable = C.doubletake_eld_available() != 0

type eldEncoder struct {
	enc      C.HANDLE_AACENCODER
	frameLen int
}

func newELDEncoder() (*eldEncoder, error) {
	if !aacELDEncoderAvailable {
		return nil, fmt.Errorf("%w (install an FDK-AAC runtime library with AAC-ELD support)", ErrAACELDUnavailable)
	}
	var enc C.HANDLE_AACENCODER
	if result := C.doubletake_eld_open(&enc); result != C.AACENC_OK {
		if enc != nil {
			C.doubletake_eld_close(&enc)
		}
		return nil, fmt.Errorf("open AAC-ELD encoder: FDK error %d", int(result))
	}
	var frameLen C.UINT
	if result := C.doubletake_eld_frame_length(enc, &frameLen); result != C.AACENC_OK {
		C.doubletake_eld_close(&enc)
		return nil, fmt.Errorf("read AAC-ELD encoder info: FDK error %d", int(result))
	}
	if frameLen != 480 {
		C.doubletake_eld_close(&enc)
		return nil, fmt.Errorf("AAC-ELD encoder selected %d samples per frame, want 480", uint32(frameLen))
	}
	return &eldEncoder{enc: enc, frameLen: int(frameLen)}, nil
}

func (e *eldEncoder) Encode(pcm, out []byte) (int, error) {
	wantPCM := e.frameLen * 2 * 2 // samples * stereo * S16LE
	if len(pcm) != wantPCM {
		return 0, fmt.Errorf("AAC-ELD PCM frame is %d bytes, want %d", len(pcm), wantPCM)
	}
	if len(out) == 0 {
		return 0, fmt.Errorf("AAC-ELD output buffer is empty")
	}
	var encoded C.INT
	result := C.doubletake_eld_encode(
		e.enc,
		(*C.INT_PCM)(unsafe.Pointer(&pcm[0])),
		C.INT(e.frameLen*2),
		(*C.UCHAR)(unsafe.Pointer(&out[0])),
		C.INT(len(out)),
		&encoded,
	)
	if result != C.AACENC_OK {
		return 0, fmt.Errorf("encode AAC-ELD: FDK error %d", int(result))
	}
	if encoded < 0 || int(encoded) > len(out) {
		return 0, fmt.Errorf("AAC-ELD encoder returned invalid size %d", int(encoded))
	}
	return int(encoded), nil
}

func (e *eldEncoder) Close() {
	if e != nil && e.enc != nil {
		C.doubletake_eld_close(&e.enc)
		e.enc = nil
	}
}
