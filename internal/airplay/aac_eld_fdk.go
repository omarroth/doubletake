//go:build cgo && fdk_aac

package airplay

/*
#cgo pkg-config: fdk-aac
#include <fdk-aac/aacenc_lib.h>

static AACENC_ERROR doubletake_eld_open(HANDLE_AACENCODER *enc) {
	AACENC_ERROR err;
	if ((err = aacEncOpen(enc, 0, 2)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_AOT, 39)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_SAMPLERATE, 44100)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_CHANNELMODE, MODE_2)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_CHANNELORDER, 1)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_BITRATE, 256000)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_TRANSMUX, TT_MP4_RAW)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_SBR_MODE, 0)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_GRANULE_LENGTH, 480)) != AACENC_OK) return err;
	return aacEncEncode(*enc, NULL, NULL, NULL, NULL);
}

static AACENC_ERROR doubletake_eld_frame_length(HANDLE_AACENCODER enc, UINT *frameLength) {
	AACENC_InfoStruct info;
	AACENC_ERROR err = aacEncInfo(enc, &info);
	if (err == AACENC_OK) *frameLength = info.frameLength;
	return err;
}

static AACENC_ERROR doubletake_eld_encode(HANDLE_AACENCODER enc, INT_PCM *pcm,
	INT nSamples, UCHAR *out, INT outSize, INT *nOut) {
	AACENC_BufDesc inDesc = {0}, outDesc = {0};
	AACENC_InArgs inArgs = {0};
	AACENC_OutArgs outArgs = {0};
	void *inBufs[1] = {pcm}, *outBufs[1] = {out};
	INT inIds[1] = {IN_AUDIO_DATA}, outIds[1] = {OUT_BITSTREAM_DATA};
	INT inSizes[1] = {nSamples * (INT)sizeof(INT_PCM)}, outSizes[1] = {outSize};
	INT inElSizes[1] = {(INT)sizeof(INT_PCM)}, outElSizes[1] = {1};
	inDesc.numBufs = outDesc.numBufs = 1;
	inDesc.bufs = inBufs;
	inDesc.bufferIdentifiers = inIds;
	inDesc.bufSizes = inSizes;
	inDesc.bufElSizes = inElSizes;
	outDesc.bufs = outBufs;
	outDesc.bufferIdentifiers = outIds;
	outDesc.bufSizes = outSizes;
	outDesc.bufElSizes = outElSizes;
	inArgs.numInSamples = nSamples;
	AACENC_ERROR err = aacEncEncode(enc, &inDesc, &outDesc, &inArgs, &outArgs);
	*nOut = outArgs.numOutBytes;
	return err;
}
*/
import "C"

import (
	"fmt"
	"unsafe"
)

const aacELDEncoderAvailable = true

type eldEncoder struct {
	enc      C.HANDLE_AACENCODER
	frameLen int
}

func newELDEncoder() (*eldEncoder, error) {
	var enc C.HANDLE_AACENCODER
	if result := C.doubletake_eld_open(&enc); result != C.AACENC_OK {
		if enc != nil {
			C.aacEncClose(&enc)
		}
		return nil, fmt.Errorf("open AAC-ELD encoder: FDK error %d", int(result))
	}
	var frameLen C.UINT
	if result := C.doubletake_eld_frame_length(enc, &frameLen); result != C.AACENC_OK {
		C.aacEncClose(&enc)
		return nil, fmt.Errorf("read AAC-ELD encoder info: FDK error %d", int(result))
	}
	if frameLen != 480 {
		C.aacEncClose(&enc)
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
		C.aacEncClose(&e.enc)
		e.enc = nil
	}
}
