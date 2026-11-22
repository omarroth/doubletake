//go:build cgo && !no_gstreamer

#import <Foundation/Foundation.h>
#import <AudioToolbox/AudioToolbox.h>
#import <CoreGraphics/CoreGraphics.h>
#import <CoreMedia/CoreMedia.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#include <gst/app/gstappsrc.h>
#include <string.h>

#include "capture_info_darwin.h"

API_AVAILABLE(macos(13.0))
@interface DTSystemAudio : NSObject <SCStreamOutput, SCStreamDelegate> {
    GstAppSrc *_source;
    SCStream *_stream;
    dispatch_queue_t _samples;
    BOOL _stopped;
}
- (instancetype)initWithSource:(GstAppSrc *)source;
- (void)start;
- (void)stop;
@end

@implementation DTSystemAudio
- (instancetype)initWithSource:(GstAppSrc *)source {
    self = [super init];
    if (self) {
        _source = gst_object_ref(source);
        _samples = dispatch_queue_create("doubletake.system-audio", DISPATCH_QUEUE_SERIAL);
    }
    return self;
}

- (void)dealloc {
    gst_object_unref(_source);
}

- (void)fail:(NSString *)message {
    @synchronized (self) {
        if (_stopped) return;
        GST_ELEMENT_ERROR(_source, RESOURCE, FAILED, ("ScreenCaptureKit: %s", message.UTF8String), (NULL));
    }
}

- (void)start {
    [SCShareableContent getShareableContentExcludingDesktopWindows:NO onScreenWindowsOnly:YES
        completionHandler:^(SCShareableContent *content, NSError *error) {
        if (error) {
            [self fail:error.localizedDescription];
            return;
        }
        SCDisplay *display = content.displays.firstObject;
        for (SCDisplay *candidate in content.displays) {
            if (candidate.displayID == CGMainDisplayID()) {
                display = candidate;
                break;
            }
        }
        if (!display) {
            [self fail:@"no shareable display in this desktop session"];
            return;
        }
        @synchronized (self) {
            if (self->_stopped) return;
            SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:display excludingWindows:@[]];
            SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
            config.capturesAudio = YES;
            config.sampleRate = 48000;
            config.channelCount = 2;
            SCStream *stream = [[SCStream alloc] initWithFilter:filter configuration:config delegate:self];
            NSError *attachError = nil;
            if (![stream addStreamOutput:self type:SCStreamOutputTypeAudio sampleHandlerQueue:self->_samples error:&attachError]) {
                [self fail:attachError.localizedDescription ?: @"could not register audio output"];
                return;
            }
            self->_stream = stream;
            [stream startCaptureWithCompletionHandler:^(NSError *startError) {
                if (startError) [self fail:startError.localizedDescription];
            }];
        }
    }];
}

- (void)stop {
    SCStream *stream;
    @synchronized (self) {
        _stopped = YES;
        stream = _stream;
        _stream = nil;
    }
    [stream stopCaptureWithCompletionHandler:^(NSError *error) { (void)error; }];
}

- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error {
    [self fail:error.localizedDescription];
}

- (void)stream:(SCStream *)stream didOutputSampleBuffer:(CMSampleBufferRef)sample ofType:(SCStreamOutputType)type {
    if (type != SCStreamOutputTypeAudio || !CMSampleBufferDataIsReady(sample)) return;
    // Keep the capture callback nonblocking and bound pending audio to 125 ms.
    if (gst_app_src_get_current_level_bytes(_source) >= 48000 * 2 * sizeof(float) / 8) return;
    CMItemCount frames = CMSampleBufferGetNumSamples(sample);
    if (frames <= 0) return;
    const AudioStreamBasicDescription *format = CMAudioFormatDescriptionGetStreamBasicDescription(CMSampleBufferGetFormatDescription(sample));
    if (!format || format->mSampleRate != 48000 || format->mChannelsPerFrame != 2 ||
        format->mFormatID != kAudioFormatLinearPCM || !(format->mFormatFlags & kAudioFormatFlagIsFloat) ||
        format->mBitsPerChannel != 32) {
        [self fail:@"unexpected system audio format"];
        return;
    }
    struct { UInt32 count; AudioBuffer buffers[2]; } storage = {0};
    AudioBufferList *audio = (AudioBufferList *)&storage;
    CMBlockBufferRef block = NULL;
    OSStatus status = CMSampleBufferGetAudioBufferListWithRetainedBlockBuffer(sample, NULL, audio, sizeof(storage),
        NULL, NULL, kCMSampleBufferFlag_AudioBufferList_Assure16ByteAlignment, &block);
    if (status != noErr) {
        if (block) CFRelease(block);
        [self fail:@"could not read system audio samples"];
        return;
    }

    size_t bytes = (size_t)frames * sizeof(float);
    GstBuffer *buffer = gst_buffer_new_allocate(NULL, bytes * 2, NULL);
    GstMapInfo mapped;
    BOOL valid = NO;
    if (buffer && gst_buffer_map(buffer, &mapped, GST_MAP_WRITE)) {
        AudioBuffer first = audio->mBuffers[0];
        if (audio->mNumberBuffers == 1 && first.mData && first.mDataByteSize >= bytes * 2) {
            memcpy(mapped.data, first.mData, bytes * 2);
            valid = YES;
        } else if (audio->mNumberBuffers == 2) {
            AudioBuffer second = audio->mBuffers[1];
            if (first.mData && second.mData && first.mDataByteSize >= bytes && second.mDataByteSize >= bytes) {
                const float *left = first.mData, *right = second.mData;
                float *out = (float *)mapped.data;
                for (CMItemCount i = 0; i < frames; i++) {
                    out[2 * i] = left[i];
                    out[2 * i + 1] = right[i];
                }
                valid = YES;
            }
        }
        gst_buffer_unmap(buffer, &mapped);
    }
    if (block) CFRelease(block);
    if (!valid) {
        if (buffer) gst_buffer_unref(buffer);
        [self fail:@"could not interleave system audio samples"];
        return;
    }
    GST_BUFFER_DURATION(buffer) = gst_util_uint64_scale(frames, GST_SECOND, 48000);
    gst_app_src_push_buffer(_source, buffer);
}
@end

void *dt_system_audio_start(void *pipeline) {
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            GstElement *source = gst_bin_get_by_name(GST_BIN(pipeline), "doubletake-system-audio");
            if (source == NULL) return NULL;
            DTSystemAudio *capture = [[DTSystemAudio alloc] initWithSource:GST_APP_SRC(source)];
            gst_object_unref(source);
            [capture start];
            return (__bridge_retained void *)capture;
        }
    }
    return NULL;
}

void dt_system_audio_stop(void *capture) {
    if (@available(macOS 13.0, *)) {
        @autoreleasepool {
            DTSystemAudio *audio = (__bridge_transfer DTSystemAudio *)capture;
            [audio stop];
        }
    }
}
