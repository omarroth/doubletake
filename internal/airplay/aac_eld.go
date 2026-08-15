package airplay

/*
#cgo pkg-config: fdk-aac
#include <fdk-aac/aacenc_lib.h>

static AACENC_ERROR eld_open(HANDLE_AACENCODER *enc) {
	AACENC_ERROR err;
	if ((err = aacEncOpen(enc, 0, 2)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_AOT, 39)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_SAMPLERATE, 44100)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_CHANNELMODE, 2)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_CHANNELORDER, 1)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_BITRATE, 128000)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_TRANSMUX, 0)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_SBR_MODE, 0)) != AACENC_OK) return err;
	if ((err = aacEncoder_SetParam(*enc, AACENC_GRANULE_LENGTH, 480)) != AACENC_OK) return err;
	return aacEncEncode(*enc, NULL, NULL, NULL, NULL);
}

static AACENC_ERROR eld_frame_length(HANDLE_AACENCODER enc, UINT *frameLength) {
	AACENC_InfoStruct info;
	AACENC_ERROR err = aacEncInfo(enc, &info);
	if (err == AACENC_OK) *frameLength = info.frameLength;
	return err;
}

static AACENC_ERROR eld_encode(HANDLE_AACENCODER enc, INT_PCM *pcm, INT nSamples, UCHAR *out, INT outSize, INT *nOut) {
	AACENC_BufDesc inDesc = {0}, outDesc = {0};
	AACENC_InArgs inArgs = {0};
	AACENC_OutArgs outArgs = {0};
	void *inBufs[1] = {pcm}, *outBufs[1] = {out};
	INT inIds[1] = {IN_AUDIO_DATA}, outIds[1] = {OUT_BITSTREAM_DATA};
	INT inSizes[1] = {nSamples * (INT)sizeof(INT_PCM)}, outSizes[1] = {outSize};
	INT inElSizes[1] = {(INT)sizeof(INT_PCM)}, outElSizes[1] = {1};
	inDesc.numBufs = outDesc.numBufs = 1;
	inDesc.bufs = inBufs; inDesc.bufferIdentifiers = inIds; inDesc.bufSizes = inSizes; inDesc.bufElSizes = inElSizes;
	outDesc.bufs = outBufs; outDesc.bufferIdentifiers = outIds; outDesc.bufSizes = outSizes; outDesc.bufElSizes = outElSizes;
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

type eldEncoder struct {
	enc      C.HANDLE_AACENCODER
	frameLen int
	outBuf   []byte
}

func newELDEncoder(_, _, _ int) (*eldEncoder, error) {
	var enc C.HANDLE_AACENCODER
	if err := C.eld_open(&enc); err != C.AACENC_OK {
		if enc != nil {
			C.aacEncClose(&enc)
		}
		return nil, fmt.Errorf("open AAC-ELD encoder: %d", int(err))
	}
	var frameLen C.UINT
	if err := C.eld_frame_length(enc, &frameLen); err != C.AACENC_OK {
		C.aacEncClose(&enc)
		return nil, fmt.Errorf("read AAC-ELD encoder info: %d", int(err))
	}
	return &eldEncoder{enc: enc, frameLen: int(frameLen), outBuf: make([]byte, 2048)}, nil
}

func (e *eldEncoder) Encode(pcm, out []byte) (int, error) {
	var n C.INT
	err := C.eld_encode(e.enc, (*C.INT_PCM)(unsafe.Pointer(&pcm[0])), C.INT(e.frameLen*2),
		(*C.UCHAR)(unsafe.Pointer(&e.outBuf[0])), C.INT(len(e.outBuf)), &n)
	if err != C.AACENC_OK {
		return 0, fmt.Errorf("encode AAC-ELD: %d", int(err))
	}
	if int(n) > len(out) {
		return 0, fmt.Errorf("AAC-ELD frame exceeds buffer")
	}
	copy(out, e.outBuf[:n])
	return int(n), nil
}

func (e *eldEncoder) Close() {
	if e != nil && e.enc != nil {
		C.aacEncClose(&e.enc)
		e.enc = nil
	}
}
