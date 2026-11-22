#ifndef DOUBLETAKE_AAC_ELD_FDK_LOADER_H
#define DOUBLETAKE_AAC_ELD_FDK_LOADER_H

#ifdef _WIN32
#include "aac_eld_fdk_windows.h"
#else
#include <fdk-aac/aacenc_lib.h>
#endif
#include <stddef.h>
#include <string.h>
#ifdef __linux__
#include <dlfcn.h>
#endif

typedef struct {
    __typeof__(aacEncOpen) *open;
    __typeof__(aacEncoder_SetParam) *set_param;
    __typeof__(aacEncInfo) *info;
    __typeof__(aacEncEncode) *encode;
    __typeof__(aacEncClose) *close;
} DTAACAPI;

#if defined(__linux__) || defined(_WIN32)
static DTAACAPI dt_aac;
#else
static DTAACAPI dt_aac = {aacEncOpen, aacEncoder_SetParam, aacEncInfo, aacEncEncode, aacEncClose};
#endif

// FDK ABI 2 added nDelayCore to InfoStruct and bitResState to OutArgs.
// The encoder entry points, parameter values, input structures, and the output
// fields we consume are shared with ABI 1. Reserve space for either layout;
// never let a newer library overwrite an older SDK's shorter stack objects.
typedef union {
    AACENC_InfoStruct value;
    unsigned char storage[512];
} DTAACInfo;
typedef union {
    AACENC_OutArgs value;
    unsigned char storage[64];
} DTAACOutput;
_Static_assert(offsetof(AACENC_InfoStruct, frameLength) == 4 * sizeof(UINT), "unsupported FDK info layout");
_Static_assert(offsetof(AACENC_OutArgs, numOutBytes) == 0, "unsupported FDK output layout");
_Static_assert(sizeof(AACENC_InfoStruct) <= 512, "FDK info storage is too small");
_Static_assert(sizeof(AACENC_OutArgs) <= 64, "FDK output storage is too small");

static AACENC_ERROR doubletake_eld_open(HANDLE_AACENCODER *enc) {
    if (dt_aac.open == NULL) return AACENC_INIT_ERROR;
    AACENC_ERROR err;
    if ((err = dt_aac.open(enc, 0, 2)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_AOT, 39)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_SAMPLERATE, 44100)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_CHANNELMODE, MODE_2)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_CHANNELORDER, 1)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_BITRATE, 256000)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_TRANSMUX, TT_MP4_RAW)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_SBR_MODE, 0)) != AACENC_OK) return err;
    if ((err = dt_aac.set_param(*enc, AACENC_GRANULE_LENGTH, 480)) != AACENC_OK) return err;
    return dt_aac.encode(*enc, NULL, NULL, NULL, NULL);
}

static AACENC_ERROR doubletake_eld_close(HANDLE_AACENCODER *enc) {
    return dt_aac.close(enc);
}

static AACENC_ERROR doubletake_eld_frame_length(HANDLE_AACENCODER enc, UINT *frame_length) {
    DTAACInfo info = {0};
    AACENC_ERROR err = dt_aac.info(enc, &info.value);
    if (err == AACENC_OK) *frame_length = info.value.frameLength;
    return err;
}

static int doubletake_eld_probe(void) {
    HANDLE_AACENCODER enc = NULL;
    UINT frame_length = 0;
    AACENC_ERROR err = doubletake_eld_open(&enc);
    if (err == AACENC_OK) err = doubletake_eld_frame_length(enc, &frame_length);
    if (enc != NULL) doubletake_eld_close(&enc);
    return err == AACENC_OK && frame_length == 480;
}

#if defined(__linux__) || defined(_WIN32)
#ifdef _WIN32
typedef HMODULE DTAACLibrary;
#define DT_AAC_SYMBOL GetProcAddress
#else
typedef void *DTAACLibrary;
#define DT_AAC_SYMBOL dlsym
#endif

static int doubletake_eld_load(DTAACLibrary library) {
    dt_aac.open = (__typeof__(dt_aac.open))DT_AAC_SYMBOL(library, "aacEncOpen");
    dt_aac.set_param = (__typeof__(dt_aac.set_param))DT_AAC_SYMBOL(library, "aacEncoder_SetParam");
    dt_aac.info = (__typeof__(dt_aac.info))DT_AAC_SYMBOL(library, "aacEncInfo");
    dt_aac.encode = (__typeof__(dt_aac.encode))DT_AAC_SYMBOL(library, "aacEncEncode");
    dt_aac.close = (__typeof__(dt_aac.close))DT_AAC_SYMBOL(library, "aacEncClose");
    if (dt_aac.open && dt_aac.set_param && dt_aac.info && dt_aac.encode &&
        dt_aac.close && doubletake_eld_probe()) return 1;
    memset(&dt_aac, 0, sizeof(dt_aac));
    return 0;
}
#undef DT_AAC_SYMBOL
#endif

// Called once by Go package initialization. A compatible library stays loaded
// for the lifetime of the process so encoder instances can use its symbols.
static int doubletake_eld_available(void) {
#if defined(_WIN32)
    HMODULE library = LoadLibraryExW(L"libfdk-aac-2.dll", NULL,
        LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!library) return 0;
    if (doubletake_eld_load(library)) return 1;
    FreeLibrary(library);
    return 0;
#elif defined(__linux__)
    const char *names[] = {"libfdk-aac.so.2", "libfdk-aac.so.1"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        void *library = dlopen(names[i], RTLD_NOW | RTLD_LOCAL);
        if (!library) continue;
        if (doubletake_eld_load(library)) return 1;
        dlclose(library);
    }
    return 0;
#else
    return doubletake_eld_probe();
#endif
}

static AACENC_ERROR doubletake_eld_encode(HANDLE_AACENCODER enc, INT_PCM *pcm,
    INT n_samples, UCHAR *out, INT out_size, INT *n_out) {
    AACENC_BufDesc in_desc = {0}, out_desc = {0};
    AACENC_InArgs in_args = {0};
    DTAACOutput out_args = {0};
    void *in_bufs[1] = {pcm}, *out_bufs[1] = {out};
    INT in_ids[1] = {IN_AUDIO_DATA}, out_ids[1] = {OUT_BITSTREAM_DATA};
    INT in_sizes[1] = {n_samples * (INT)sizeof(INT_PCM)}, out_sizes[1] = {out_size};
    INT in_element_sizes[1] = {(INT)sizeof(INT_PCM)}, out_element_sizes[1] = {1};
    in_desc.numBufs = out_desc.numBufs = 1;
    in_desc.bufs = in_bufs;
    in_desc.bufferIdentifiers = in_ids;
    in_desc.bufSizes = in_sizes;
    in_desc.bufElSizes = in_element_sizes;
    out_desc.bufs = out_bufs;
    out_desc.bufferIdentifiers = out_ids;
    out_desc.bufSizes = out_sizes;
    out_desc.bufElSizes = out_element_sizes;
    in_args.numInSamples = n_samples;
    AACENC_ERROR err = dt_aac.encode(enc, &in_desc, &out_desc, &in_args, &out_args.value);
    *n_out = out_args.value.numOutBytes;
    return err;
}

#endif
