#ifndef DOUBLETAKE_AAC_ELD_FDK_WINDOWS_H
#define DOUBLETAKE_AAC_ELD_FDK_WINDOWS_H

#include <windows.h>
#include <stdint.h>

// Subset of the public FDK-AAC encoder ABI (aacenc_lib.h and FDK_audio.h).
// The runtime is optional, so building on Windows does not need its SDK.
typedef int16_t INT_PCM;
typedef struct AACENCODER *HANDLE_AACENCODER;
typedef unsigned int AACENC_ERROR;
typedef unsigned int AACENC_PARAM;

enum {
    AACENC_OK = 0,
    AACENC_INIT_ERROR = 0x0040,
    AACENC_AOT = 0x0100,
    AACENC_BITRATE = 0x0101,
    AACENC_SAMPLERATE = 0x0103,
    AACENC_SBR_MODE = 0x0104,
    AACENC_GRANULE_LENGTH = 0x0105,
    AACENC_CHANNELMODE = 0x0106,
    AACENC_CHANNELORDER = 0x0107,
    AACENC_TRANSMUX = 0x0300,
    MODE_2 = 2,
    TT_MP4_RAW = 0,
    IN_AUDIO_DATA = 0,
    OUT_BITSTREAM_DATA = 3,
};

typedef struct {
    INT numBufs;
    void **bufs;
    INT *bufferIdentifiers;
    INT *bufSizes;
    INT *bufElSizes;
} AACENC_BufDesc;

typedef struct {
    INT numInSamples;
    INT numAncBytes;
} AACENC_InArgs;

// These are the fields the sender reads. The loader supplies padded storage for
// the remaining fields written by the library.
typedef struct {
    UINT maxOutBufBytes;
    UINT maxAncBytes;
    UINT inBufFillLevel;
    UINT inputChannels;
    UINT frameLength;
} AACENC_InfoStruct;

typedef struct {
    INT numOutBytes;
} AACENC_OutArgs;

AACENC_ERROR aacEncOpen(HANDLE_AACENCODER *, UINT, UINT);
AACENC_ERROR aacEncoder_SetParam(HANDLE_AACENCODER, AACENC_PARAM, UINT);
AACENC_ERROR aacEncInfo(HANDLE_AACENCODER, AACENC_InfoStruct *);
AACENC_ERROR aacEncEncode(HANDLE_AACENCODER, const AACENC_BufDesc *,
    const AACENC_BufDesc *, const AACENC_InArgs *, AACENC_OutArgs *);
AACENC_ERROR aacEncClose(HANDLE_AACENCODER *);

#endif
