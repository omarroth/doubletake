//go:build cgo && no_gstreamer

#import <AVFoundation/AVFoundation.h>
#import <CoreGraphics/CoreGraphics.h>
#import <ScreenCaptureKit/ScreenCaptureKit.h>
#import <VideoToolbox/VideoToolbox.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include "capture_info_darwin.h"

@interface DTMacPacket : NSObject
@property (nonatomic, strong) NSData *data;
@property (nonatomic) CMTime pts;
@end
@implementation DTMacPacket
@end

API_AVAILABLE(macos(13.0))
@interface DTMacCapture : NSObject <SCStreamDelegate, SCStreamOutput> {
    NSCondition *_ready;
    NSMutableArray<DTMacPacket *> *_packets;
    dispatch_queue_t _captureQueue;
    dispatch_source_t _timer;
    SCStream *_stream;
    VTCompressionSessionRef _encoder;
    CVPixelBufferRef _lastImage;
    AVAudioConverter *_converter;
    NSString *_error;
    CMTime _lastSubmitted;
    CMTime _audioPTS;
    int _audioOffset;
    int _fps;
    BOOL _stopped;
    BOOL _firstKeyFrame;
    BOOL _forceKeyFrame;
}
@property (readonly) int width;
@property (readonly) int height;
@property (readonly) BOOL hardware;
@property (readonly) BOOL audio;
- (instancetype)initAudio:(BOOL)audio;
- (OSStatus)configureEncoder:(CMVideoCodecType)codec width:(int)width height:(int)height
    fps:(int)fps bitrate:(int)bitrate useHardware:(BOOL)useHardware;
- (void)startDisplay:(BOOL)cursor;
- (void)startPattern;
- (void)startIdleTimer;
- (void)shutdown;
- (void)fail:(NSString *)error;
- (DTMacPacket *)take:(NSString **)error;
- (OSStatus)setBitrate:(int)bitrate;
- (void)setFPS:(int)fps;
- (void)requestKeyFrame;
- (void)encoded:(CMSampleBufferRef)sample status:(OSStatus)status;
@end

static int64_t DTTimeNS(CMTime time) {
    if (!CMTIME_IS_NUMERIC(time)) return 0;
    return CMTimeConvertScale(time, 1000000000, kCMTimeRoundingMethod_Default).value;
}

static void DTOnEncoded(void *context, void *frame, OSStatus status,
        VTEncodeInfoFlags flags, CMSampleBufferRef sample) {
    (void)frame;
    (void)flags;
    @autoreleasepool {
        [(__bridge DTMacCapture *)context encoded:sample status:status];
    }
}

@implementation DTMacCapture
- (instancetype)initAudio:(BOOL)audio {
    if ((self = [super init])) {
        _audio = audio;
        _ready = [[NSCondition alloc] init];
        _packets = [[NSMutableArray alloc] init];
        _captureQueue = dispatch_queue_create("doubletake.capture", DISPATCH_QUEUE_SERIAL);
        _audioPTS = kCMTimeInvalid;
        _lastSubmitted = kCMTimeInvalid;
    }
    return self;
}

- (OSStatus)configureEncoder:(CMVideoCodecType)codec width:(int)width height:(int)height
        fps:(int)fps bitrate:(int)bitrate useHardware:(BOOL)useHardware {
    _width = width;
    _height = height;
    _fps = fps;
    _forceKeyFrame = YES;
    NSDictionary *spec = @{(__bridge NSString *)kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder: @(useHardware)};
    NSDictionary *pixels = @{
        (__bridge NSString *)kCVPixelBufferPixelFormatTypeKey: @(kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange),
        (__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{},
    };
    OSStatus err = VTCompressionSessionCreate(NULL, width, height, codec,
        (__bridge CFDictionaryRef)spec, (__bridge CFDictionaryRef)pixels, NULL,
        DTOnEncoded, (__bridge void *)self, &_encoder);
    if (err != noErr) return err;
    NSDictionary *props = @{
        (__bridge NSString *)kVTCompressionPropertyKey_RealTime: @YES,
        (__bridge NSString *)kVTCompressionPropertyKey_AllowFrameReordering: @NO,
        (__bridge NSString *)kVTCompressionPropertyKey_ExpectedFrameRate: @(fps),
        (__bridge NSString *)kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration: @0.5,
        (__bridge NSString *)kVTCompressionPropertyKey_AverageBitRate: @(bitrate),
        (__bridge NSString *)kVTCompressionPropertyKey_ProfileLevel: (__bridge NSString *)(codec == kCMVideoCodecType_HEVC
            ? kVTProfileLevel_HEVC_Main_AutoLevel : kVTProfileLevel_H264_Main_AutoLevel),
    };
    err = VTSessionSetProperties(_encoder, (__bridge CFDictionaryRef)props);
    if (err != noErr) return err;
    err = VTCompressionSessionPrepareToEncodeFrames(_encoder);
    if (err != noErr) return err;
    CFTypeRef value = NULL;
    if (VTSessionCopyProperty(_encoder, kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder, NULL, &value) == noErr && value) {
        _hardware = CFEqual(value, kCFBooleanTrue);
        CFRelease(value);
    }
    return noErr;
}

- (void)startDisplay:(BOOL)cursor {
    [SCShareableContent getShareableContentExcludingDesktopWindows:NO onScreenWindowsOnly:YES
        completionHandler:^(SCShareableContent *content, NSError *error) {
        if (error) {
            [self fail:error.localizedDescription];
            return;
        }
        SCDisplay *display = nil;
        for (SCDisplay *candidate in content.displays) {
            if (candidate.displayID == CGMainDisplayID()) {
                display = candidate;
                break;
            }
        }
        if (!display) {
            [self fail:@"the main display is unavailable"];
            return;
        }

        SCContentFilter *filter = [[SCContentFilter alloc] initWithDisplay:display excludingWindows:@[]];
        SCStreamConfiguration *config = [[SCStreamConfiguration alloc] init];
        config.showsCursor = cursor;
        if (self.audio) {
            config.capturesAudio = YES;
            config.sampleRate = 48000;
            config.channelCount = 2;
        } else {
            config.width = self.width;
            config.height = self.height;
            config.pixelFormat = kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange;
            config.queueDepth = 3;
            [self->_ready lock];
            int fps = self->_fps;
            [self->_ready unlock];
            config.minimumFrameInterval = CMTimeMake(1, fps);
        }
        SCStream *stream = [[SCStream alloc] initWithFilter:filter configuration:config delegate:self];
        NSError *attachError = nil;
        if (![stream addStreamOutput:self type:(self.audio ? SCStreamOutputTypeAudio : SCStreamOutputTypeScreen)
            sampleHandlerQueue:self->_captureQueue error:&attachError]) {
            [self fail:attachError.localizedDescription ?: @"could not register capture output"];
            return;
        }
        [self->_ready lock];
        if (!self->_stopped && !self->_error) {
            self->_stream = stream;
            if (!self.audio) [self startIdleTimer];
            [stream startCaptureWithCompletionHandler:^(NSError *startError) {
                if (startError) [self fail:startError.localizedDescription];
            }];
        }
        [self->_ready unlock];
    }];
}

- (void)submit:(CVPixelBufferRef)image time:(CMTime)pts {
    [_ready lock];
    BOOL stopped = _stopped || _error;
    CMTime minimum = CMTimeMake(9, _fps * 10);
    if (stopped || (CMTIME_IS_NUMERIC(_lastSubmitted) && CMTimeCompare(CMTimeSubtract(pts, _lastSubmitted), minimum) < 0)) {
        [_ready unlock];
        return;
    }
    _lastSubmitted = pts;
    BOOL force = _forceKeyFrame;
    _forceKeyFrame = NO;
    [_ready unlock];
    NSDictionary *options = force ? @{(__bridge NSString *)kVTEncodeFrameOptionKey_ForceKeyFrame: @YES} : nil;
    OSStatus err = VTCompressionSessionEncodeFrame(_encoder, image, pts, kCMTimeInvalid,
        (__bridge CFDictionaryRef)options, NULL, NULL);
    if (err != noErr) [self fail:[NSString stringWithFormat:@"VideoToolbox submission failed (%d)", (int)err]];
}

- (void)startPattern {
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _captureQueue);
    dispatch_source_set_timer(_timer, DISPATCH_TIME_NOW, NSEC_PER_SEC / _fps, 500000);
    __weak DTMacCapture *owner = self;
    __block uint64_t frame = 0;
    dispatch_source_set_event_handler(_timer, ^{
        DTMacCapture *self = owner;
        if (!self) return;
        CVPixelBufferRef image = NULL;
        CVPixelBufferPoolRef pool = VTCompressionSessionGetPixelBufferPool(self->_encoder);
        if (!pool || CVPixelBufferPoolCreatePixelBuffer(NULL, pool, &image) != kCVReturnSuccess) {
            [self fail:@"could not allocate the synthetic video frame"];
            return;
        }
        CVPixelBufferLockBaseAddress(image, 0);
        uint8_t *luma = CVPixelBufferGetBaseAddressOfPlane(image, 0);
        size_t stride = CVPixelBufferGetBytesPerRowOfPlane(image, 0);
        for (int y = 0; y < self.height; y++) {
            for (int x = 0; x < self.width; x++)
                luma[y * stride + x] = ((x / 32 + y / 32 + frame / 2) & 1) ? 188 : 54;
        }
        memset(CVPixelBufferGetBaseAddressOfPlane(image, 1), 128,
            CVPixelBufferGetBytesPerRowOfPlane(image, 1) * CVPixelBufferGetHeightOfPlane(image, 1));
        CVPixelBufferUnlockBaseAddress(image, 0);
        frame++;
        [self submit:image time:CMClockGetTime(CMClockGetHostTimeClock())];
        CVPixelBufferRelease(image);
    });
    dispatch_activate(_timer);
}

// An unchanged desktop may stop producing image buffers. Retain one
// surface so a new receiver can still get an IDR on a static desktop.
- (void)startIdleTimer {
    _timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, _captureQueue);
    dispatch_source_set_timer(_timer, dispatch_time(DISPATCH_TIME_NOW, 100 * NSEC_PER_MSEC),
        100 * NSEC_PER_MSEC, 5 * NSEC_PER_MSEC);
    __weak DTMacCapture *owner = self;
    dispatch_source_set_event_handler(_timer, ^{
        DTMacCapture *self = owner;
        if (!self || !self->_lastImage) return;
        CMTime now = CMClockGetTime(CMClockGetHostTimeClock());
        [self->_ready lock];
        BOOL due = self->_forceKeyFrame || DTTimeNS(CMTimeSubtract(now, self->_lastSubmitted)) >= 500000000;
        if (due) self->_forceKeyFrame = YES;
        [self->_ready unlock];
        if (due) [self submit:self->_lastImage time:now];
    });
    dispatch_activate(_timer);
}

// Leave bounded headroom for the encoder. Backpressure drops uncoded screen
// frames in ScreenCaptureKit instead of breaking the encoded frame chain.
- (void)publish:(NSData *)data time:(CMTime)pts {
    DTMacPacket *packet = [[DTMacPacket alloc] init];
    packet.data = data;
    packet.pts = pts;
    [_ready lock];
    while (!_stopped && !_error && _packets.count >= (_audio ? 24 : 8)) {
        if (_audio) {
            [_packets removeObjectAtIndex:0];
            break;
        }
        [_ready wait];
    }
    if (!_stopped && !_error) {
        [_packets addObject:packet];
        [_ready broadcast];
    }
    [_ready unlock];
}

- (DTMacPacket *)take:(NSString **)error {
    [_ready lock];
    while (!_stopped && !_error && _packets.count == 0) [_ready wait];
    DTMacPacket *packet = _packets.firstObject;
    if (packet) [_packets removeObjectAtIndex:0];
    else *error = _error;
    [_ready broadcast];
    [_ready unlock];
    return packet;
}

- (void)encoded:(CMSampleBufferRef)sample status:(OSStatus)status {
    if (status != noErr) {
        [self fail:[NSString stringWithFormat:@"VideoToolbox encoding failed (%d)", (int)status]];
        return;
    }
    if (!sample || !CMSampleBufferDataIsReady(sample)) return;
    CMFormatDescriptionRef format = CMSampleBufferGetFormatDescription(sample);
    BOOL hevc = CMFormatDescriptionGetMediaSubType(format) == kCMVideoCodecType_HEVC;
    CFArrayRef attachments = CMSampleBufferGetSampleAttachmentsArray(sample, false);
    CFDictionaryRef flags = attachments && CFArrayGetCount(attachments) ? CFArrayGetValueAtIndex(attachments, 0) : NULL;
    BOOL key = !flags || !CFDictionaryContainsKey(flags, kCMSampleAttachmentKey_NotSync);
    [_ready lock];
    BOOL ready = _firstKeyFrame || key;
    _firstKeyFrame = ready;
    [_ready unlock];
    if (!ready) return;

    NSMutableData *annex = [NSMutableData data];
    static const uint8_t start[] = {0, 0, 0, 1};
    size_t count = 0;
    int header = 0;
    OSStatus err = hevc
        ? CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(format, 0, NULL, NULL, &count, &header)
        : CMVideoFormatDescriptionGetH264ParameterSetAtIndex(format, 0, NULL, NULL, &count, &header);
    if (err != noErr || header < 1 || header > 4) {
        [self fail:@"VideoToolbox did not provide valid codec configuration"];
        return;
    }
    if (key) {
        for (size_t i = 0; i < count; i++) {
            const uint8_t *param = NULL;
            size_t length = 0;
            err = hevc
                ? CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(format, i, &param, &length, NULL, NULL)
                : CMVideoFormatDescriptionGetH264ParameterSetAtIndex(format, i, &param, &length, NULL, NULL);
            if (err != noErr) {
                [self fail:@"could not read VideoToolbox parameter sets"];
                return;
            }
            [annex appendBytes:start length:sizeof(start)];
            [annex appendBytes:param length:length];
        }
    }
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sample);
    if (!block) return;
    size_t size = CMBlockBufferGetDataLength(block);
    NSMutableData *encoded = [NSMutableData dataWithLength:size];
    if (CMBlockBufferCopyDataBytes(block, 0, size, encoded.mutableBytes) != noErr) {
        [self fail:@"could not read VideoToolbox frame"];
        return;
    }
    const uint8_t *bytes = encoded.bytes;
    for (size_t offset = 0; offset < size;) {
        uint32_t n = 0;
        if (size - offset >= header) {
            for (int i = 0; i < header; i++) n = (n << 8) | bytes[offset++];
        }
        if (!n || n > size - offset) {
            [self fail:@"VideoToolbox returned an invalid NAL length"];
            return;
        }
        [annex appendBytes:start length:sizeof(start)];
        [annex appendBytes:bytes + offset length:n];
        offset += n;
    }
    [self publish:annex time:CMSampleBufferGetPresentationTimeStamp(sample)];
}

- (void)audioSample:(CMSampleBufferRef)sample time:(CMTime)pts {
    const AudioStreamBasicDescription *fmt = CMAudioFormatDescriptionGetStreamBasicDescription(CMSampleBufferGetFormatDescription(sample));
    CMItemCount frames = CMSampleBufferGetNumSamples(sample);
    if (!fmt || fmt->mFormatID != kAudioFormatLinearPCM || fmt->mChannelsPerFrame != 2 ||
        frames <= 0 || frames > 48000 || fmt->mSampleRate <= 0) {
        [self fail:@"ScreenCaptureKit returned an invalid audio format"];
        return;
    }
    AVAudioFormat *inputFormat = [[AVAudioFormat alloc] initWithStreamDescription:fmt];
    if (!_converter || ![inputFormat isEqual:_converter.inputFormat]) {
        AVAudioFormat *outputFormat = [[AVAudioFormat alloc] initWithCommonFormat:AVAudioPCMFormatInt16
            sampleRate:44100 channels:2 interleaved:YES];
        _converter = [[AVAudioConverter alloc] initFromFormat:inputFormat toFormat:outputFormat];
        _converter.primeMethod = AVAudioConverterPrimeMethod_None;
        _audioPTS = kCMTimeInvalid;
    }
    if (!_converter) {
        [self fail:@"could not create the system audio converter"];
        return;
    }
    AVAudioPCMBuffer *input = [[AVAudioPCMBuffer alloc] initWithPCMFormat:inputFormat frameCapacity:(AVAudioFrameCount)frames];
    if (!input) {
        [self fail:@"could not allocate ScreenCaptureKit audio buffer"];
        return;
    }
    input.frameLength = (AVAudioFrameCount)frames;
    if (CMSampleBufferCopyPCMDataIntoAudioBufferList(sample, 0, (int32_t)frames, input.mutableAudioBufferList) != noErr) {
        [self fail:@"could not read ScreenCaptureKit audio"];
        return;
    }
    CMTime expected = CMTimeAdd(_audioPTS, CMTimeMake(_audioOffset, 44100));
    if (!CMTIME_IS_NUMERIC(expected) || llabs(DTTimeNS(CMTimeSubtract(pts, expected))) > 30000000) {
        [_converter reset];
        _audioPTS = pts;
        _audioOffset = 0;
        expected = pts;
    }
    AVAudioFrameCount capacity = (AVAudioFrameCount)ceil(frames * 44100.0 / fmt->mSampleRate) + 32;
    AVAudioPCMBuffer *output = [[AVAudioPCMBuffer alloc] initWithPCMFormat:_converter.outputFormat frameCapacity:capacity];
    if (!output) {
        [self fail:@"could not allocate system audio conversion buffer"];
        return;
    }
    __block BOOL supplied = NO;
    NSError *error = nil;
    AVAudioConverterOutputStatus status = [_converter convertToBuffer:output error:&error
        withInputFromBlock:^AVAudioBuffer *(AVAudioPacketCount requested, AVAudioConverterInputStatus *inputStatus) {
        (void)requested;
        *inputStatus = supplied ? AVAudioConverterInputStatus_NoDataNow : AVAudioConverterInputStatus_HaveData;
        if (supplied) return nil;
        supplied = YES;
        return input;
    }];
    if (status == AVAudioConverterOutputStatus_Error) {
        [self fail:error.localizedDescription ?: @"system audio conversion failed"];
        return;
    }
    if (output.frameLength) {
        [self publish:[NSData dataWithBytes:output.int16ChannelData[0] length:output.frameLength * 4] time:expected];
        _audioOffset += output.frameLength;
        if (_audioOffset > 44100 * 60) {
            _audioPTS = CMTimeAdd(_audioPTS, CMTimeMake(_audioOffset, 44100));
            _audioOffset = 0;
        }
    }
}

- (void)stream:(SCStream *)stream didOutputSampleBuffer:(CMSampleBufferRef)sample ofType:(SCStreamOutputType)type {
    [_ready lock];
    BOOL stopped = _stopped || _error;
    [_ready unlock];
    if (stopped || !CMSampleBufferDataIsReady(sample)) return;
    CMTime pts = CMSampleBufferGetPresentationTimeStamp(sample);
    if (stream.synchronizationClock) pts = CMSyncConvertTime(pts, stream.synchronizationClock, CMClockGetHostTimeClock());
    if (!CMTIME_IS_NUMERIC(pts)) return;
    if (type == SCStreamOutputTypeAudio) {
        [self audioSample:sample time:pts];
    } else if (type == SCStreamOutputTypeScreen) {
        CVPixelBufferRef image = CMSampleBufferGetImageBuffer(sample);
        if (image) {
            if (_lastImage) CVPixelBufferRelease(_lastImage);
            _lastImage = CVPixelBufferRetain(image);
            [self submit:image time:pts];
        }
    }
}

- (void)stream:(SCStream *)stream didStopWithError:(NSError *)error {
    (void)stream;
    [self fail:error.localizedDescription];
}

- (void)fail:(NSString *)error {
    [_ready lock];
    if (!_stopped && !_error) _error = error ?: @"capture failed";
    [_ready broadcast];
    [_ready unlock];
}

- (OSStatus)setBitrate:(int)bitrate {
    return VTSessionSetProperty(_encoder, kVTCompressionPropertyKey_AverageBitRate, (__bridge CFNumberRef)@(bitrate));
}
- (void)setFPS:(int)fps {
    [_ready lock];
    _fps = fps;
    [_ready unlock];
}
- (void)requestKeyFrame {
    [_ready lock];
    _forceKeyFrame = YES;
    [_ready unlock];
}

- (void)shutdown {
    [_ready lock];
    _stopped = YES;
    SCStream *stream = _stream;
    _stream = nil;
    [_packets removeAllObjects];
    [_ready broadcast];
    [_ready unlock];
    if (_timer) {
        dispatch_source_cancel(_timer);
        _timer = nil;
    }
    if (stream) [stream stopCaptureWithCompletionHandler:nil];
    dispatch_sync(_captureQueue, ^{
        if (_lastImage) {
            CVPixelBufferRelease(_lastImage);
            _lastImage = NULL;
        }
    });
    if (_encoder) {
        VTCompressionSessionInvalidate(_encoder);
        CFRelease(_encoder);
        _encoder = NULL;
    }
}
@end

void *dt_mac_open(int audio, int test, int width, int height, int fps, int bitrate,
        int hevc, int hardware, int cursor, int *using_hardware, char **message) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            DTMacCapture *capture = [[DTMacCapture alloc] initAudio:audio];
            if (!audio) {
                OSStatus err = [capture configureEncoder:(hevc ? kCMVideoCodecType_HEVC : kCMVideoCodecType_H264)
                    width:width height:height fps:fps bitrate:bitrate useHardware:hardware];
                if (err != noErr) {
                    [capture shutdown];
                    *message = strdup([[NSString stringWithFormat:@"could not start VideoToolbox encoder (%d)", (int)err] UTF8String]);
                    return NULL;
                }
                *using_hardware = capture.hardware;
            }
            if (test) [capture startPattern];
            else [capture startDisplay:cursor];
            return (__bridge_retained void *)capture;
        }
        *message = strdup("native capture requires macOS 13 or later");
        return NULL;
    }
}

int dt_mac_pull(void *handle, void **data, size_t *length, int64_t *age, char **message) {
    @autoreleasepool {
        if (@available(macOS 13.0, *)) {
            NSString *error = nil;
            DTMacPacket *packet = [(__bridge DTMacCapture *)handle take:&error];
            if (error) {
                *message = strdup(error.UTF8String);
                return -1;
            }
            if (packet) {
                *length = packet.data.length;
                *data = malloc(*length);
                if (!*data) {
                    *message = strdup("could not allocate capture buffer");
                    return -1;
                }
                memcpy(*data, packet.data.bytes, *length);
                *age = DTTimeNS(CMTimeSubtract(CMClockGetTime(CMClockGetHostTimeClock()), packet.pts));
                return 1;
            }
        }
        return 0;
    }
}

void dt_mac_retain(void *handle) { CFRetain(handle); }
void dt_mac_release(void *handle) { CFRelease(handle); }
void dt_mac_shutdown(void *handle) { if (@available(macOS 13.0, *)) [(__bridge DTMacCapture *)handle shutdown]; }
int dt_mac_bitrate(void *handle, int bitrate) {
    if (@available(macOS 13.0, *)) return [(__bridge DTMacCapture *)handle setBitrate:bitrate];
    return -1;
}
void dt_mac_fps(void *handle, int fps) {
    if (@available(macOS 13.0, *)) [(__bridge DTMacCapture *)handle setFPS:fps];
}
void dt_mac_keyframe(void *handle) {
    if (@available(macOS 13.0, *)) [(__bridge DTMacCapture *)handle requestKeyFrame];
}

int dt_mac_dimensions(int *width, int *height) {
    CGDirectDisplayID display = CGMainDisplayID();
    *width = (int)CGDisplayPixelsWide(display);
    *height = (int)CGDisplayPixelsHigh(display);
    return *width > 0 && *height > 0;
}
