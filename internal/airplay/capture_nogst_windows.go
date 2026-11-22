//go:build cgo && no_gstreamer

package airplay

/*
#cgo LDFLAGS: -lmfplat -luser32 -lgdi32
#include <stdint.h>
typedef struct DTWinVideo DTWinVideo;
void dt_win_dimensions(int *width, int *height);
DTWinVideo *dt_win_video_open(int width, int height, int fps, int bitrate,
	int test, int cursor, int gop, int32_t *status);
void dt_win_video_close(DTWinVideo *video);
int32_t dt_win_video_input(DTWinVideo *video, int64_t pts, int64_t duration, int number);
int32_t dt_win_video_output(DTWinVideo *video, const void **data, uint32_t *size, int64_t *pts,
	const void **config, uint32_t *config_size);
int32_t dt_win_bitrate(DTWinVideo *video, int bits);
int32_t dt_win_keyframe(DTWinVideo *video);
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"time"
	"unsafe"
)

func init() { openNativeVideo = startWindowsVideo }

func winBool(v bool) C.int {
	if v {
		return 1
	}
	return 0
}

type windowsVideoControl struct {
	apply func(*C.DTWinVideo, *int, *time.Ticker) error
	done  chan error
}

type windowsVideo struct {
	ctx        context.Context
	cancel     context.CancelFunc
	control    chan windowsVideoControl
	frames     chan VideoAccessUnit
	done       chan struct{}
	err        error
	rawPTSBase int64
	haveRawPTS bool
	parameters [2][]byte // SPS and PPS for receivers that attach after the first IDR
}

func startWindowsVideo(startup, lifetime context.Context, cfg CaptureConfig, test bool) (*ScreenCapture, error) {
	if cfg.FPS <= 0 {
		cfg.FPS = 30
	}
	if cfg.FPS > 240 {
		return nil, fmt.Errorf("native capture supports up to 240 fps")
	}
	if cfg.MaxWidth <= 0 || cfg.MaxHeight <= 0 {
		w, h := C.int(testCaptureWidth), C.int(testCaptureHeight)
		if !test {
			C.dt_win_dimensions(&w, &h)
		}
		cfg.MaxWidth, cfg.MaxHeight = int(w), int(h)
	}
	cfg.MaxWidth, cfg.MaxHeight = cfg.MaxWidth&^1, cfg.MaxHeight&^1
	if cfg.MaxWidth < 16 || cfg.MaxHeight < 16 || cfg.MaxWidth > 4096 || cfg.MaxHeight > 4096 {
		return nil, fmt.Errorf("unsupported Media Foundation dimensions %dx%d", cfg.MaxWidth, cfg.MaxHeight)
	}
	bitrate := captureBitrateKbps(cfg)
	if bitrate <= 0 || bitrate > (1<<31-1)/1000 {
		return nil, fmt.Errorf("bitrate is outside the Media Foundation range")
	}
	ctx, cancel := context.WithCancel(lifetime)
	source := &windowsVideo{
		ctx: ctx, cancel: cancel, control: make(chan windowsVideoControl),
		frames: make(chan VideoAccessUnit, 8), done: make(chan struct{}),
	}
	started := make(chan error, 1)
	go source.run(cfg, test, bitrate, started)
	probe, done := context.WithTimeout(startup, captureStartupProbeTimeout(cfg.FPS))
	defer done()
	select {
	case err := <-started:
		if err != nil {
			cancel()
			return nil, err
		}
	case <-probe.Done():
		cancel()
		return nil, probe.Err()
	}
	enc := encoderResult{name: "Media Foundation H.264", bitrateKbps: bitrate, codec: cfg.VideoCodec}
	capture := &ScreenCapture{frames: source, runtime: source, cancel: cancel, waitCh: make(chan struct{}), format: captureFormat(cfg, enc)}
	capture.enableAutomaticVideoRateControl(cfg)
	go func() {
		<-source.done
		capture.waitErr = source.err
		close(capture.waitCh)
	}()
	if err := probeVideoCaptureStartup(probe, capture, cfg.VideoCodec, true); err != nil {
		capture.Stop()
		return nil, fmt.Errorf("native Windows video startup: %w", err)
	}
	return capture, nil
}

func (s *windowsVideo) run(cfg CaptureConfig, test bool, bitrate int, started chan<- error) {
	defer close(s.done)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	fps := cfg.FPS
	var status C.int32_t
	encoder := C.dt_win_video_open(C.int(cfg.MaxWidth), C.int(cfg.MaxHeight), C.int(fps), C.int(bitrate*1000),
		winBool(test), winBool(cfg.ShowCursor), C.int(keyframeIntervalFrames(fps)), &status)
	if encoder == nil {
		started <- fmt.Errorf("start Media Foundation H.264 encoder: HRESULT 0x%08x", uint32(status))
		return
	}
	defer C.dt_win_video_close(encoder)
	started <- nil

	var origin time.Time
	tick := time.NewTicker(time.Second / time.Duration(fps))
	defer tick.Stop()
	number := 0
	for {
		select {
		case <-s.ctx.Done():
			return
		case request := <-s.control:
			request.done <- request.apply(encoder, &fps, tick)
		case <-tick.C:
			if len(s.frames) == cap(s.frames) {
				continue // skip raw capture while the receiver is backpressured
			}
			if origin.IsZero() {
				origin = time.Now()
			}
			duration := time.Second / time.Duration(fps)
			if number%keyframeIntervalFrames(fps) == 0 {
				_ = C.dt_win_keyframe(encoder)
			}
			status := C.dt_win_video_input(encoder, C.int64_t(time.Since(origin)/100),
				C.int64_t(duration/100), C.int(number))
			if status < 0 {
				s.err = fmt.Errorf("capture or submit Windows video: HRESULT 0x%08x", uint32(status))
				return
			}
			number++
			if err := s.drain(encoder, origin, &fps, tick); err != nil {
				s.err = err
				return
			}
		}
	}
}

func (s *windowsVideo) drain(encoder *C.DTWinVideo, origin time.Time, fps *int, tick *time.Ticker) error {
	for changes := 0; ; {
		var data, configuration unsafe.Pointer
		var length, configLength C.uint32_t
		var pts C.int64_t
		status := C.dt_win_video_output(encoder, &data, &length, &pts, &configuration, &configLength)
		if status < 0 {
			return fmt.Errorf("read Media Foundation H.264: HRESULT 0x%08x", uint32(status))
		}
		if status == 2 && changes < 2 {
			changes++
			continue
		}
		if status == 1 {
			return nil
		}
		if length == 0 || length > maxVideoAccessUnitBytes || configLength > maxVideoAccessUnitBytes-length {
			return fmt.Errorf("invalid Media Foundation H.264 access unit size %d", length)
		}
		frame := C.GoBytes(data, C.int(length))
		idr, sps, pps := false, false, false
		for _, nal := range splitAnnexBAccessUnit(frame) {
			switch raw := stripStartCode(nal); {
			case len(raw) == 0:
			case raw[0]&0x1f == 5:
				idr = true
			case raw[0]&0x1f == 7:
				sps = true
				s.parameters[0] = append(s.parameters[0][:0], nal...)
			case raw[0]&0x1f == 8:
				pps = true
				s.parameters[1] = append(s.parameters[1][:0], nal...)
			}
		}
		if idr && (!sps || !pps) {
			if len(s.parameters[0]) != 0 && len(s.parameters[1]) != 0 {
				prefix := make([]byte, 0, len(frame)+len(s.parameters[0])+len(s.parameters[1]))
				for _, parameter := range s.parameters {
					prefix = append(prefix, parameter...)
				}
				frame = append(prefix, frame...)
			} else if configLength != 0 {
				frame = append(C.GoBytes(configuration, C.int(configLength)), frame...)
			}
		}
		// Match the first encoded picture to the capture clock. An
		// encoder may return sample times in its own nonzero epoch.
		if !s.haveRawPTS {
			s.rawPTSBase, s.haveRawPTS = int64(pts), true
		}
		unit := VideoAccessUnit{AnnexB: frame, PTS: origin.Add(time.Duration(int64(pts)-s.rawPTSBase) * 100)}
		delivered := false
		for !delivered {
			select {
			case <-s.ctx.Done():
				return nil
			case request := <-s.control:
				request.done <- request.apply(encoder, fps, tick)
			case s.frames <- unit:
				delivered = true
			}
		}
	}
}

func (s *windowsVideo) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	select {
	case frame := <-s.frames:
		return frame, nil
	case <-s.done:
		if s.err != nil {
			return VideoAccessUnit{}, s.err
		}
		return VideoAccessUnit{}, io.EOF
	}
}

func (s *windowsVideo) request(apply func(*C.DTWinVideo, *int, *time.Ticker) error) error {
	request := windowsVideoControl{apply: apply, done: make(chan error, 1)}
	select {
	case s.control <- request:
		return <-request.done
	case <-s.done:
		return io.ErrClosedPipe
	}
}

func (s *windowsVideo) setBitrateKbps(kbps int) error {
	if kbps <= 0 || kbps > (1<<31-1)/1000 {
		return fmt.Errorf("bitrate is outside the Media Foundation range")
	}
	return s.request(func(handle *C.DTWinVideo, _ *int, _ *time.Ticker) error {
		if status := C.dt_win_bitrate(handle, C.int(kbps*1000)); status < 0 {
			return fmt.Errorf("Media Foundation bitrate update failed (HRESULT 0x%08x)", uint32(status))
		}
		return nil
	})
}

func (s *windowsVideo) setFrameRate(fps int) error {
	if fps <= 0 || fps > 240 {
		return fmt.Errorf("frame rate is outside the native capture range")
	}
	return s.request(func(_ *C.DTWinVideo, current *int, tick *time.Ticker) error {
		*current = fps
		tick.Reset(time.Second / time.Duration(fps))
		return nil
	})
}

func (s *windowsVideo) requestKeyFrame() error {
	return s.request(func(handle *C.DTWinVideo, _ *int, _ *time.Ticker) error {
		if status := C.dt_win_keyframe(handle); status < 0 {
			return fmt.Errorf("Media Foundation key-frame request failed (HRESULT 0x%08x)", uint32(status))
		}
		return nil
	})
}

func (s *windowsVideo) stop() { s.cancel() }
