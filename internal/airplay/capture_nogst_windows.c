//go:build cgo && no_gstreamer

#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <mfapi.h>
#include <mferror.h>
#include <mfidl.h>
#include <mftransform.h>
#include <icodecapi.h>
#include <wmcodecdsp.h>
#include <codecapi.h>
#include <oleauto.h>
#include <stdint.h>
#include <stdlib.h>

static const GUID dt_AVEncCommonMeanBitRate = {STATIC_CODECAPI_AVEncCommonMeanBitRate};
static const GUID dt_AVEncVideoForceKeyFrame = {STATIC_CODECAPI_AVEncVideoForceKeyFrame};
static const GUID dt_AVLowLatencyMode = {STATIC_CODECAPI_AVLowLatencyMode};
static const GUID dt_AVEncCommonRateControlMode = {STATIC_CODECAPI_AVEncCommonRateControlMode};
static const GUID dt_AVEncMPVGOPSize = {STATIC_CODECAPI_AVEncMPVGOPSize};
static const GUID dt_AVEncMPVDefaultBPictureCount = {STATIC_CODECAPI_AVEncMPVDefaultBPictureCount};

typedef struct DTWinVideo {
    IMFTransform *encoder;
    ICodecAPI *controls;
    BOOL mf_started;
    BOOL test;
    BOOL cursor;
    int width, height, fps;
    HDC screen, target;
    HBITMAP bitmap;
    HGDIOBJ previous;
    BYTE *rgb;
    BYTE *encoded;
    size_t capacity;
    BYTE *configuration;
    UINT32 configuration_size;
} DTWinVideo;

static HRESULT dt_win_set(DTWinVideo *video, const GUID *key, UINT32 value) {
    if (!video->controls) return E_NOINTERFACE;
    VARIANT setting = {0};
    V_VT(&setting) = VT_UI4;
    V_UI4(&setting) = value;
    return ICodecAPI_SetValue(video->controls, key, &setting);
}

int32_t dt_win_bitrate(DTWinVideo *video, int bits) {
    return dt_win_set(video, &dt_AVEncCommonMeanBitRate, (UINT32)bits);
}

int32_t dt_win_keyframe(DTWinVideo *video) {
    return dt_win_set(video, &dt_AVEncVideoForceKeyFrame, 1);
}

void dt_win_video_close(DTWinVideo *video) {
    if (!video) return;
    if (video->previous) SelectObject(video->target, video->previous);
    if (video->bitmap) DeleteObject(video->bitmap);
    if (video->target) DeleteDC(video->target);
    if (video->screen) ReleaseDC(NULL, video->screen);
    if (video->controls) ICodecAPI_Release(video->controls);
    if (video->encoder) {
        IMFTransform_ProcessMessage(video->encoder, MFT_MESSAGE_NOTIFY_END_STREAMING, 0);
        IMFTransform_Release(video->encoder);
    }
    if (video->mf_started) MFShutdown();
    CoUninitialize();
    free(video->encoded);
    if (video->configuration) CoTaskMemFree(video->configuration);
    free(video);
}

static HRESULT dt_win_media_type(DTWinVideo *video, BOOL output, int bitrate) {
    IMFMediaType *type = NULL;
    HRESULT hr = MFCreateMediaType(&type);
    if (FAILED(hr)) return hr;
    hr = IMFMediaType_SetGUID(type, &MF_MT_MAJOR_TYPE, &MFMediaType_Video);
    if (SUCCEEDED(hr)) hr = IMFMediaType_SetGUID(type, &MF_MT_SUBTYPE, output ? &MFVideoFormat_H264 : &MFVideoFormat_NV12);
    if (SUCCEEDED(hr)) hr = IMFMediaType_SetUINT64(type, &MF_MT_FRAME_SIZE, ((UINT64)video->width << 32) | (UINT32)video->height);
    if (SUCCEEDED(hr)) hr = IMFMediaType_SetUINT64(type, &MF_MT_FRAME_RATE, ((UINT64)video->fps << 32) | 1);
    if (SUCCEEDED(hr)) hr = IMFMediaType_SetUINT64(type, &MF_MT_PIXEL_ASPECT_RATIO, (1ULL << 32) | 1);
    if (SUCCEEDED(hr)) hr = IMFMediaType_SetUINT32(type, &MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive);
    if (output) {
        if (SUCCEEDED(hr)) hr = IMFMediaType_SetUINT32(type, &MF_MT_MPEG2_PROFILE, eAVEncH264VProfile_Main);
        if (SUCCEEDED(hr)) hr = IMFMediaType_SetUINT32(type, &MF_MT_AVG_BITRATE, bitrate);
        if (SUCCEEDED(hr)) hr = IMFTransform_SetOutputType(video->encoder, 0, type, 0);
    } else if (SUCCEEDED(hr)) {
        hr = IMFTransform_SetInputType(video->encoder, 0, type, 0);
    }
    IMFMediaType_Release(type);
    return hr;
}

DTWinVideo *dt_win_video_open(int width, int height, int fps, int bitrate,
        int test, int cursor, int gop, int32_t *status) {
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        *status = hr;
        return NULL;
    }
    DTWinVideo *video = calloc(1, sizeof(*video));
    if (!video) {
        CoUninitialize();
        *status = E_OUTOFMEMORY;
        return NULL;
    }
    video->width = width;
    video->height = height;
    video->fps = fps;
    video->test = test;
    video->cursor = cursor;
    hr = MFStartup(MF_VERSION, MFSTARTUP_LITE);
    if (FAILED(hr)) goto fail;
    video->mf_started = TRUE;
    hr = CoCreateInstance(&CLSID_CMSH264EncoderMFT, NULL, CLSCTX_INPROC_SERVER,
        &IID_IMFTransform, (void **)&video->encoder);
    if (FAILED(hr)) goto fail;
    IMFTransform_QueryInterface(video->encoder, &IID_ICodecAPI, (void **)&video->controls);
    if (video->controls) {
        VARIANT low_latency = {0};
        V_VT(&low_latency) = VT_BOOL;
        V_BOOL(&low_latency) = VARIANT_TRUE;
        ICodecAPI_SetValue(video->controls, &dt_AVLowLatencyMode, &low_latency);
        dt_win_set(video, &dt_AVEncCommonRateControlMode, eAVEncCommonRateControlMode_CBR);
        dt_win_set(video, &dt_AVEncMPVGOPSize, gop);
        dt_win_set(video, &dt_AVEncMPVDefaultBPictureCount, 0);
    }
    hr = dt_win_media_type(video, TRUE, bitrate);
    if (SUCCEEDED(hr)) hr = dt_win_media_type(video, FALSE, bitrate);
    if (SUCCEEDED(hr)) hr = IMFTransform_ProcessMessage(video->encoder, MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
    if (SUCCEEDED(hr)) hr = IMFTransform_ProcessMessage(video->encoder, MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
    if (FAILED(hr)) goto fail;

    if (!test) {
        SetProcessDPIAware();
        video->screen = GetDC(NULL);
        if (!video->screen) {
            hr = E_FAIL;
            goto fail;
        }
        video->target = CreateCompatibleDC(video->screen);
        BITMAPINFO info = {0};
        info.bmiHeader.biSize = sizeof(info.bmiHeader);
        info.bmiHeader.biWidth = width;
        info.bmiHeader.biHeight = -height;
        info.bmiHeader.biPlanes = 1;
        info.bmiHeader.biBitCount = 32;
        info.bmiHeader.biCompression = BI_RGB;
        video->bitmap = CreateDIBSection(video->screen, &info, DIB_RGB_COLORS, (void **)&video->rgb, NULL, 0);
        if (!video->target || !video->bitmap) {
            hr = E_OUTOFMEMORY;
            goto fail;
        }
        video->previous = SelectObject(video->target, video->bitmap);
        SetStretchBltMode(video->target, HALFTONE);
    }
    return video;

fail:
    *status = hr;
    dt_win_video_close(video);
    return NULL;
}

static BOOL dt_win_screen(DTWinVideo *video) {
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    if (sw <= 0 || sh <= 0) return FALSE;
    int w = video->width, h = video->height;
    if (w * sh > h * sw) w = h * sw / sh;
    else h = w * sh / sw;
    int x = (video->width - w) / 2, y = (video->height - h) / 2;
    if (x || y) PatBlt(video->target, 0, 0, video->width, video->height, BLACKNESS);
    // CAPTUREBLT can disturb the local pointer on virtual display drivers.
    // Copy the desktop normally and draw the cursor only into our own bitmap.
    if (!StretchBlt(video->target, x, y, w, h, video->screen, 0, 0, sw, sh, SRCCOPY)) return FALSE;
    CURSORINFO cursor = { .cbSize = sizeof(cursor) };
    if (video->cursor && GetCursorInfo(&cursor) && (cursor.flags & CURSOR_SHOWING) &&
        cursor.ptScreenPos.x >= 0 && cursor.ptScreenPos.x < sw && cursor.ptScreenPos.y >= 0 && cursor.ptScreenPos.y < sh) {
        ICONINFO icon;
        if (GetIconInfo(cursor.hCursor, &icon)) {
            DrawIconEx(video->target, x + cursor.ptScreenPos.x * w / sw - (int)icon.xHotspot,
                y + cursor.ptScreenPos.y * h / sh - (int)icon.yHotspot, cursor.hCursor,
                0, 0, 0, NULL, DI_NORMAL);
            if (icon.hbmMask) DeleteObject(icon.hbmMask);
            if (icon.hbmColor) DeleteObject(icon.hbmColor);
        }
    }
    GdiFlush();
    return TRUE;
}

// Convert the desktop DIB to studio-range BT.601 NV12.
static void dt_win_nv12(DTWinVideo *video, BYTE *nv12) {
    int w = video->width, h = video->height;
    BYTE *uv = nv12 + w * h;
    for (int y = 0; y < h; y += 2) {
        for (int x = 0; x < w; x += 2) {
            int r = 0, g = 0, b = 0;
            for (int row = 0; row < 2; row++) {
                for (int col = 0; col < 2; col++) {
                    int pixel = (y + row) * w + x + col;
                    const BYTE *bgra = video->rgb + 4 * pixel;
                    nv12[pixel] = 16 + ((66 * bgra[2] + 129 * bgra[1] + 25 * bgra[0] + 128) >> 8);
                    r += bgra[2]; g += bgra[1]; b += bgra[0];
                }
            }
            uv[x + y / 2 * w] = 128 + ((-38 * r - 74 * g + 112 * b + 512) >> 10);
            uv[x + y / 2 * w + 1] = 128 + ((112 * r - 94 * g - 18 * b + 512) >> 10);
        }
    }
}

int32_t dt_win_video_input(DTWinVideo *video, int64_t pts, int64_t duration, int number) {
    int pixels = video->width * video->height;
    DWORD bytes = pixels * 3 / 2;
    IMFSample *sample = NULL;
    IMFMediaBuffer *buffer = NULL;
    BYTE *data = NULL;
    HRESULT hr = MFCreateSample(&sample);
    if (SUCCEEDED(hr)) hr = MFCreateMemoryBuffer(bytes, &buffer);
    if (SUCCEEDED(hr)) hr = IMFMediaBuffer_Lock(buffer, &data, NULL, NULL);
    if (SUCCEEDED(hr)) {
        if (video->test) {
            for (int y = 0; y < video->height; y++) {
                for (int x = 0; x < video->width; x++)
                    data[y * video->width + x] = ((x / 32 + y / 32 + number / 2) & 1) ? 188 : 54;
            }
            memset(data + pixels, 128, pixels / 2);
        } else if (dt_win_screen(video)) {
            dt_win_nv12(video, data);
        } else {
            hr = E_FAIL;
        }
        IMFMediaBuffer_Unlock(buffer);
    }
    if (SUCCEEDED(hr)) hr = IMFMediaBuffer_SetCurrentLength(buffer, bytes);
    if (SUCCEEDED(hr)) hr = IMFSample_AddBuffer(sample, buffer);
    if (SUCCEEDED(hr)) hr = IMFSample_SetSampleTime(sample, pts);
    if (SUCCEEDED(hr)) hr = IMFSample_SetSampleDuration(sample, duration);
    if (SUCCEEDED(hr)) hr = IMFTransform_ProcessInput(video->encoder, 0, sample, 0);
    if (buffer) IMFMediaBuffer_Release(buffer);
    if (sample) IMFSample_Release(sample);
    return hr;
}

int32_t dt_win_video_output(DTWinVideo *video, const void **data, uint32_t *size, int64_t *pts,
        const void **config, uint32_t *config_size) {
    MFT_OUTPUT_STREAM_INFO info;
    HRESULT hr = IMFTransform_GetOutputStreamInfo(video->encoder, 0, &info);
    if (FAILED(hr)) return hr;
    DWORD status = 0, bytes = 0;
    IMFMediaBuffer *buffer = NULL;
    IMFSample *original = NULL;
    MFT_OUTPUT_DATA_BUFFER output = {0};
    if (!(info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES)) {
        hr = MFCreateSample(&original);
        if (SUCCEEDED(hr)) hr = MFCreateMemoryBuffer(info.cbSize ? info.cbSize : (DWORD)(video->width * video->height * 2), &buffer);
        if (SUCCEEDED(hr)) hr = IMFSample_AddBuffer(original, buffer);
        if (buffer) IMFMediaBuffer_Release(buffer);
        buffer = NULL;
        output.pSample = original;
    }
    if (SUCCEEDED(hr)) hr = IMFTransform_ProcessOutput(video->encoder, 0, 1, &output, &status);
    if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT) hr = S_FALSE;
    if (hr == S_OK && output.pSample) {
        hr = IMFSample_GetSampleTime(output.pSample, pts);
        if (SUCCEEDED(hr)) hr = IMFSample_ConvertToContiguousBuffer(output.pSample, &buffer);
        BYTE *sample = NULL;
        if (SUCCEEDED(hr)) hr = IMFMediaBuffer_Lock(buffer, &sample, NULL, &bytes);
        if (SUCCEEDED(hr)) {
            if (bytes > video->capacity) {
                BYTE *replacement = realloc(video->encoded, bytes);
                if (!replacement) hr = E_OUTOFMEMORY;
                else {
                    video->encoded = replacement;
                    video->capacity = bytes;
                }
            }
            if (SUCCEEDED(hr) && bytes) {
                memcpy(video->encoded, sample, bytes);
                *data = video->encoded;
                *size = bytes;
            }
            IMFMediaBuffer_Unlock(buffer);
        }
    }
    if (output.pEvents) IMFCollection_Release(output.pEvents);
    if (buffer) IMFMediaBuffer_Release(buffer);
    if (output.pSample && output.pSample != original) IMFSample_Release(output.pSample);
    if (original) IMFSample_Release(original);
    if (hr == MF_E_TRANSFORM_STREAM_CHANGE) {
        IMFMediaType *type = NULL;
        hr = IMFTransform_GetOutputAvailableType(video->encoder, 0, 0, &type);
        if (SUCCEEDED(hr)) hr = IMFTransform_SetOutputType(video->encoder, 0, type, 0);
        if (type) IMFMediaType_Release(type);
        if (SUCCEEDED(hr)) return 2; // retry output using the newly negotiated type
    }
    if (*size && !video->configuration) {
        IMFMediaType *type = NULL;
        if (SUCCEEDED(IMFTransform_GetOutputCurrentType(video->encoder, 0, &type))) {
            IMFMediaType_GetAllocatedBlob(type, &MF_MT_MPEG_SEQUENCE_HEADER, &video->configuration, &video->configuration_size);
            IMFMediaType_Release(type);
        }
    }
    *config = video->configuration;
    *config_size = video->configuration_size;
    return hr;
}

void dt_win_dimensions(int *width, int *height) {
    SetProcessDPIAware();
    *width = GetSystemMetrics(SM_CXSCREEN);
    *height = GetSystemMetrics(SM_CYSCREEN);
}
