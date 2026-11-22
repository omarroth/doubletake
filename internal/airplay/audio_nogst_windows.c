//go:build cgo && no_gstreamer

#define COBJMACROS
#include <windows.h>
#include <initguid.h>
#include <mmdeviceapi.h>
#include <audioclient.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct DTLoopback {
    IAudioClient *client;
    IAudioCaptureClient *reader;
    HANDLE ready;
    BYTE *samples;
    size_t capacity;
} DTLoopback;

void dt_loopback_close(DTLoopback *capture) {
    if (!capture) return;
    if (capture->client) IAudioClient_Stop(capture->client);
    if (capture->reader) IAudioCaptureClient_Release(capture->reader);
    if (capture->client) IAudioClient_Release(capture->client);
    if (capture->ready) CloseHandle(capture->ready);
    free(capture->samples);
    free(capture);
    CoUninitialize();
}

static HRESULT dt_loopback_device(IMMDeviceEnumerator *enumerator, IMMDevice **device, const char **stage) {
    static const ERole roles[] = { eConsole, eMultimedia };
    const HRESULT not_found = HRESULT_FROM_WIN32(ERROR_NOT_FOUND);
    *stage = "look up the default Windows playback output";
    for (size_t i = 0; i < sizeof(roles) / sizeof(roles[0]); i++) {
        HRESULT hr = IMMDeviceEnumerator_GetDefaultAudioEndpoint(enumerator, eRender, roles[i], device);
        if (hr != not_found) return hr;
    }

    // A new or redirected Windows session can have an active render device
    // before either default role is populated. Pick it only if unambiguous.
    *stage = "enumerate active Windows playback outputs";
    IMMDeviceCollection *outputs = NULL;
    HRESULT hr = IMMDeviceEnumerator_EnumAudioEndpoints(enumerator, eRender, DEVICE_STATE_ACTIVE, &outputs);
    if (FAILED(hr)) return hr;
    UINT count = 0;
    hr = IMMDeviceCollection_GetCount(outputs, &count);
    if (SUCCEEDED(hr)) {
        if (count == 1) {
            *stage = "select the active Windows playback output";
            hr = IMMDeviceCollection_Item(outputs, 0, device);
        } else {
            *stage = count == 0
                ? "no active Windows playback output; enable an output in Settings > System > Sound"
                : "no default Windows playback output; select an output in Settings > System > Sound";
            hr = not_found;
        }
    }
    IMMDeviceCollection_Release(outputs);
    return hr;
}

DTLoopback *dt_loopback_open(int32_t *status, const char **stage) {
    *stage = "initialize Windows COM";
    HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    if (FAILED(hr)) {
        *status = hr;
        return NULL;
    }
    *stage = "allocate loopback capture";
    DTLoopback *capture = calloc(1, sizeof(*capture));
    if (!capture) {
        CoUninitialize();
        *status = E_OUTOFMEMORY;
        return NULL;
    }
    IMMDeviceEnumerator *enumerator = NULL;
    IMMDevice *device = NULL;
    *stage = "open the Windows audio device enumerator";
    hr = CoCreateInstance(&CLSID_MMDeviceEnumerator, NULL, CLSCTX_ALL, &IID_IMMDeviceEnumerator, (void **)&enumerator);
    if (SUCCEEDED(hr)) hr = dt_loopback_device(enumerator, &device, stage);
    if (SUCCEEDED(hr)) {
        *stage = "activate the Windows playback output";
        hr = IMMDevice_Activate(device, &IID_IAudioClient, CLSCTX_ALL, NULL, (void **)&capture->client);
    }
    if (device) IMMDevice_Release(device);
    if (enumerator) IMMDeviceEnumerator_Release(enumerator);
    if (FAILED(hr)) goto fail;

    WAVEFORMATEX format = { WAVE_FORMAT_PCM, 2, 44100, 44100 * 4, 4, 16, 0 };
    DWORD flags = AUDCLNT_STREAMFLAGS_LOOPBACK | AUDCLNT_STREAMFLAGS_EVENTCALLBACK |
        AUDCLNT_STREAMFLAGS_AUTOCONVERTPCM | AUDCLNT_STREAMFLAGS_SRC_DEFAULT_QUALITY;
    *stage = "initialize stereo 44.1 kHz loopback on the Windows playback output";
    hr = IAudioClient_Initialize(capture->client, AUDCLNT_SHAREMODE_SHARED, flags, 0, 0, &format, NULL);
    if (FAILED(hr)) goto fail;
    *stage = "create the WASAPI capture event";
    capture->ready = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!capture->ready) {
        hr = HRESULT_FROM_WIN32(GetLastError());
        goto fail;
    }
    *stage = "register the WASAPI capture event";
    hr = IAudioClient_SetEventHandle(capture->client, capture->ready);
    if (FAILED(hr)) goto fail;
    *stage = "get the WASAPI capture service";
    hr = IAudioClient_GetService(capture->client, &IID_IAudioCaptureClient, (void **)&capture->reader);
    if (FAILED(hr)) goto fail;
    *stage = "start WASAPI capture on the Windows playback output";
    hr = IAudioClient_Start(capture->client);
    if (FAILED(hr)) goto fail;
    return capture;

fail:
    *status = hr;
    dt_loopback_close(capture);
    return NULL;
}

// GetBuffer returns an absolute performance-counter timestamp in units of
// 100 ns for the first frame. Return its age only if the timestamp is valid.
int32_t dt_loopback_pull(DTLoopback *capture, const void **bytes, int *size,
        int64_t *age, int *timestamp_valid, int *discontinuity) {
    UINT32 frames = 0;
    HRESULT hr = IAudioCaptureClient_GetNextPacketSize(capture->reader, &frames);
    if (FAILED(hr)) return hr;
    if (!frames) {
        WaitForSingleObject(capture->ready, 10);
        hr = IAudioCaptureClient_GetNextPacketSize(capture->reader, &frames);
        if (FAILED(hr) || !frames) return hr;
    }
    DWORD flags = 0;
    UINT64 qpc = 0;
    BYTE *data = NULL;
    hr = IAudioCaptureClient_GetBuffer(capture->reader, &data, &frames, &flags, NULL, &qpc);
    if (hr == AUDCLNT_E_BUFFER_ERROR) {
        // The buffer was unavailable this pass. Continue on the next event.
        WaitForSingleObject(capture->ready, 10);
        return S_FALSE;
    }
    if (FAILED(hr) || !frames) return hr;
    size_t length = (size_t)frames * 4;
    if (length > capture->capacity) {
        BYTE *new_samples = realloc(capture->samples, length);
        if (!new_samples) {
            IAudioCaptureClient_ReleaseBuffer(capture->reader, frames);
            return E_OUTOFMEMORY;
        }
        capture->samples = new_samples;
        capture->capacity = length;
    }
    if (flags & AUDCLNT_BUFFERFLAGS_SILENT) memset(capture->samples, 0, length);
    else memcpy(capture->samples, data, length);
    *bytes = capture->samples;
    *size = (int)length;
    *discontinuity = (flags & AUDCLNT_BUFFERFLAGS_DATA_DISCONTINUITY) != 0;
    LARGE_INTEGER now, frequency;
    if (!(flags & AUDCLNT_BUFFERFLAGS_TIMESTAMP_ERROR) && qpc &&
        QueryPerformanceCounter(&now) && QueryPerformanceFrequency(&frequency)) {
        int64_t ticks = (now.QuadPart / frequency.QuadPart) * 10000000LL +
            (now.QuadPart % frequency.QuadPart) * 10000000LL / frequency.QuadPart;
        *age = ticks - (int64_t)qpc;
        *timestamp_valid = 1;
    }
    return IAudioCaptureClient_ReleaseBuffer(capture->reader, frames);
}
