//go:build cgo && fdk_aac

package airplay

/*
#cgo linux LDFLAGS: -ldl
#cgo !linux pkg-config: fdk-aac
#include <fdk-aac/aacdecoder_lib.h>
#ifdef __linux__
#include <dlfcn.h>
#endif

typedef struct {
    __typeof__(aacDecoder_Open) *open;
    __typeof__(aacDecoder_ConfigRaw) *config;
    __typeof__(aacDecoder_Fill) *fill;
    __typeof__(aacDecoder_DecodeFrame) *decode;
    __typeof__(aacDecoder_GetStreamInfo) *info;
    __typeof__(aacDecoder_Close) *close;
} DTReceiverAACAPI;
#ifdef __linux__
static DTReceiverAACAPI dt_receiver_aac;
static int dt_receiver_aac_load(void) {
    const char *names[]={"libfdk-aac.so.2","libfdk-aac.so.1",NULL};
    for (int i=0; names[i]; i++) {
        void *library=dlopen(names[i],RTLD_NOW|RTLD_LOCAL);
        if (!library) continue;
        DTReceiverAACAPI api={0};
        api.open=(__typeof__(api.open))dlsym(library,"aacDecoder_Open");
        api.config=(__typeof__(api.config))dlsym(library,"aacDecoder_ConfigRaw");
        api.fill=(__typeof__(api.fill))dlsym(library,"aacDecoder_Fill");
        api.decode=(__typeof__(api.decode))dlsym(library,"aacDecoder_DecodeFrame");
        api.info=(__typeof__(api.info))dlsym(library,"aacDecoder_GetStreamInfo");
        api.close=(__typeof__(api.close))dlsym(library,"aacDecoder_Close");
        if (api.open&&api.config&&api.fill&&api.decode&&api.info&&api.close) { dt_receiver_aac=api; return 1; }
        dlclose(library);
    }
    return 0;
}
#else
static DTReceiverAACAPI dt_receiver_aac={aacDecoder_Open,aacDecoder_ConfigRaw,aacDecoder_Fill,aacDecoder_DecodeFrame,aacDecoder_GetStreamInfo,aacDecoder_Close};
static int dt_receiver_aac_load(void) { return 1; }
#endif
static HANDLE_AACDECODER dt_receiver_eld_open(void) {
    HANDLE_AACDECODER decoder=dt_receiver_aac.open(TT_MP4_RAW,1);
    if (!decoder) return NULL;
    // AudioSpecificConfig: AOT 39, 44100 Hz, stereo, 480-sample ELD, no SBR.
    UCHAR asc[]={0xf8,0xe8,0x50,0x00}; UCHAR *config=asc; UINT size=sizeof(asc);
    if (dt_receiver_aac.config(decoder,&config,&size)!=AAC_DEC_OK) { dt_receiver_aac.close(decoder); return NULL; }
    return decoder;
}
static int dt_receiver_eld_decode(HANDLE_AACDECODER decoder,UCHAR *data,UINT size,INT_PCM *pcm,INT capacity) {
    UINT valid=size;
    if (dt_receiver_aac.fill(decoder,&data,&size,&valid)!=AAC_DEC_OK || valid!=0) return -1;
    AAC_DECODER_ERROR result=dt_receiver_aac.decode(decoder,pcm,capacity,0);
    if (result!=AAC_DEC_OK) return -(int)result-1;
    CStreamInfo *info=dt_receiver_aac.info(decoder);
    if (!info || info->sampleRate!=44100 || info->frameSize!=480 || info->numChannels!=2) return -2;
    return info->frameSize*info->numChannels;
}
static void dt_receiver_eld_close(HANDLE_AACDECODER decoder) { dt_receiver_aac.close(decoder); }
*/
import "C"

import (
	"encoding/binary"
	"fmt"
	"sync"
	"unsafe"
)

var receiverELDLibrary struct {
	sync.Once
	available bool
}

type receiverELDDecoder struct {
	mu        sync.Mutex
	decoder   C.HANDLE_AACDECODER
	callbacks receiverDecodeCallbacks
}

func newReceiverELDDecoder(callbacks receiverDecodeCallbacks) (receiverDecoder, error) {
	receiverELDLibrary.Do(func() { receiverELDLibrary.available = C.dt_receiver_aac_load() != 0 })
	if !receiverELDLibrary.available {
		return nil, fmt.Errorf("AAC-ELD playback requires the FDK-AAC runtime decoder")
	}
	decoder := C.dt_receiver_eld_open()
	if decoder == nil {
		return nil, fmt.Errorf("configure 480-sample AAC-ELD receiver decoder")
	}
	return &receiverELDDecoder{decoder: decoder, callbacks: callbacks}, nil
}

func (d *receiverELDDecoder) Push(frame []byte, pts int64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.decoder == nil || len(frame) == 0 || len(frame) > 8192 {
		return fmt.Errorf("invalid AAC-ELD decoder frame")
	}
	var samples [960]C.INT_PCM
	count := int(C.dt_receiver_eld_decode(d.decoder, (*C.UCHAR)(unsafe.Pointer(&frame[0])), C.UINT(len(frame)), &samples[0], C.INT(len(samples))))
	if count != 960 {
		return fmt.Errorf("AAC-ELD decode failed: %d", count)
	}
	pcm := make([]byte, len(samples)*2)
	for i, value := range samples {
		binary.LittleEndian.PutUint16(pcm[i*2:], uint16(int16(value)))
	}
	d.callbacks.Sample(receiverDecodedSample{Data: pcm, PTS: pts})
	return nil
}

func (d *receiverELDDecoder) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.decoder != nil {
		C.dt_receiver_eld_close(d.decoder)
		d.decoder = nil
	}
	return nil
}
