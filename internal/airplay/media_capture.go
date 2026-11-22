package airplay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ErrMediaPlaybackRequiresGStreamer is returned when media playback is
// requested from a sender built without GStreamer.
var ErrMediaPlaybackRequiresGStreamer = errors.New("file, HTTP and stdin playback require a GStreamer-enabled doubletake sender")

// ResolveMediaSource accepts an HTTP(S) URL or resolves a local file in the
// caller's working directory. Foreground stdin is handled by the caller.
func ResolveMediaSource(source string) (string, error) {
	if source == "" || source == "-" {
		return "", fmt.Errorf("a local media file or HTTP(S) URL is required")
	}
	path := source
	if strings.Contains(source, "://") {
		location, err := url.Parse(source)
		if err != nil {
			return "", errors.New("invalid media URL")
		}
		switch location.Scheme {
		case "http", "https":
			if location.Hostname() == "" {
				return "", errors.New("media URL requires a host")
			}
			return location.String(), nil
		case "file":
			path = mediaFilePath(location.Path)
			if location.Host != "" && !strings.EqualFold(location.Host, "localhost") ||
				!filepath.IsAbs(path) || location.RawQuery != "" || location.Fragment != "" {
				return "", errors.New("file URI must refer to an absolute local path")
			}
		default:
			return "", fmt.Errorf("unsupported media URL scheme %q (use http, https, or file)", location.Scheme)
		}
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("resolve video file: %w", err)
	}
	info, err := os.Stat(absolute)
	if err != nil {
		return "", fmt.Errorf("video file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("video source %q must be a regular file", path)
	}
	return absolute, nil
}

func remoteMediaSource(source string) bool {
	return strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://")
}

func mediaSourceURI(source string) string {
	if source == "-" {
		return "fd://0"
	}
	if remoteMediaSource(source) {
		return source
	}
	return (&url.URL{Scheme: "file", Path: mediaURIPath(source)}).String()
}

// StartMediaCapture starts decoding after the receiver has negotiated its
// canvas and audio codec. A video-only session does not create an audio graph.
func (s *MirrorSession) StartMediaCapture(p *CapturePreparation, width, height int, codec VideoCodec) (*ScreenCapture, error) {
	if s.noAudio || !s.HasAudio() {
		return p.StartWithCodec(width, height, codec)
	}
	return p.startWithContextAndCodec(nil, width, height, codec, s)
}

func startPreparedMediaCapture(ctx context.Context, cfg CaptureConfig, encoder encoderResult, session *MirrorSession) (*ScreenCapture, error) {
	ctx, cancel := context.WithCancel(ctx)
	source := gstStage{"fdsrc", "fd=0"}
	fps := cfg.FPS
	if fps <= 0 {
		fps = 30
	}
	// Select a decoded video pad. The receiver's existing encoding path
	// applies its negotiated canvas and rate to the decoded pictures.
	stages := []gstStage{
		{"decodebin"}, {"capsfilter", "caps=video/x-raw"},
		{"videorate", "drop-only=true", "max-rate=" + strconv.Itoa(fps)},
	}
	if cfg.MediaSource != "-" {
		source = gstStage{"uridecodebin", "uri=" + strconv.Quote(mediaSourceURI(cfg.MediaSource))}
		stages = stages[1:]
	}
	args := buildGstVideoPipeline(source, stages, nil, encoder, cfg.MaxWidth, cfg.MaxHeight, true)
	var audio *mediaAudioPlayback
	var pipeline *runningGStreamerPipeline
	var err error
	var timeline *mediaPlaybackTimeline
	if session == nil {
		pipeline, err = launchGStreamerPipeline(ctx, args, encoder, nil)
	} else {
		timeline = &mediaPlaybackTimeline{ctx: ctx}
		pipeline, audio, err = launchMediaAV(ctx, cfg, encoder, fps, timeline, session)
	}
	if err != nil {
		cancel()
		return nil, err
	}
	capture := &ScreenCapture{
		stdout: pipeline.stdout, cancel: cancel,
		runtime: pipeline.runtime, waitCh: make(chan struct{}), finite: true,
		format: captureFormat(cfg, encoder), mediaAudio: audio,
		frames: &pacedMediaVideo{
			ctx: ctx, reader: newRTPVideoAccessUnitReader(pipeline.stdout, encoder.codec), timeline: timeline,
		},
	}
	capture.enableAutomaticVideoRateControl(cfg)
	if audio != nil {
		audio.capture.waitCh = capture.waitCh
	}
	go func() {
		capture.waitErr = <-pipeline.waitResult
		close(capture.waitCh)
	}()
	return capture, nil
}

// Preroll and decoding may run ahead of playback. Pace the encoded pictures
// against one local monotonic origin while retaining their presentation spacing.
type pacedMediaVideo struct {
	ctx      context.Context
	reader   videoAccessUnitReader
	first    time.Time
	start    time.Time
	timeline *mediaPlaybackTimeline
}

func (v *pacedMediaVideo) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	unit, err := v.reader.ReadVideoAccessUnit()
	if err != nil {
		return unit, err
	}
	if v.timeline != nil {
		unit.PTS = v.timeline.localPTS(unit.PTS)
	} else {
		if v.first.IsZero() {
			v.first, v.start = unit.PTS, time.Now()
		}
		unit.PTS = v.start.Add(unit.PTS.Sub(v.first))
	}
	if err := waitForMediaPTS(v.ctx, unit.PTS); err != nil {
		return VideoAccessUnit{}, err
	}
	return unit, nil
}

func waitForMediaPTS(ctx context.Context, pts time.Time) error {
	if delay := time.Until(pts); delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-timer.C:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Both RTP branches use the same fixed ONVIF offset, so a decoded PTS is
// the pipeline running time relative to this epoch. Preserve track offsets.
var mediaPTSEpoch = time.Unix(0, 0)

type mediaPlaybackTimeline struct {
	ctx   context.Context
	once  sync.Once
	start time.Time
}

func (p *mediaPlaybackTimeline) localPTS(pts time.Time) time.Time {
	p.once.Do(func() { p.start = time.Now().Add(50 * time.Millisecond) })
	return p.start.Add(pts.Sub(mediaPTSEpoch))
}

type mediaAudioPlayback struct {
	capture  *AudioCapture
	timeline *mediaPlaybackTimeline
	reader   *rtpL16PCMFrameReader
	lead     func() time.Duration
	lastEnd  time.Time
	present  atomic.Bool
}

func (a *mediaAudioPlayback) ReadPCMFrame(dst []byte) (time.Time, error) {
	position, err := a.ReadPCMFramePosition(dst)
	return position.PTS, err
}

func (a *mediaAudioPlayback) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	position, err := a.reader.ReadPCMFramePosition(dst)
	if err != nil {
		if errors.Is(err, io.EOF) && !a.lastEnd.IsZero() {
			if waitErr := waitForMediaPTS(a.timeline.ctx, a.lastEnd.Add(a.lead())); waitErr != nil {
				return position, waitErr
			}
		}
		return position, err
	}
	a.present.Store(true)
	position.PTS = a.timeline.localPTS(position.PTS)
	a.lastEnd = position.PTS.Add(audioSamplesDuration(uint64(len(dst) / audioBytesPerSampleFrame)))
	return position, waitForMediaPTS(a.timeline.ctx, position.PTS)
}

func playbackSinkProperty(name string, args []string) string {
	for i, token := range args {
		if token == "ntp-offset=-1" {
			args[i] = "ntp-offset=" + strconv.FormatInt(secondsFrom1900To1970*int64(time.Second), 10)
		}
	}
	return name + "=" + strings.Join(args, " ")
}

func launchMediaAV(ctx context.Context, cfg CaptureConfig, encoder encoderResult, fps int, timeline *mediaPlaybackTimeline, session *MirrorSession) (*runningGStreamerPipeline, *mediaAudioPlayback, error) {
	codec := session.AudioCodec()
	audioCapture := &AudioCapture{codec: codec, finite: true}
	if codec == AudioCodecAACELD {
		var err error
		audioCapture.eld, err = newELDEncoder()
		if err != nil {
			return nil, nil, err
		}
	}

	uri := mediaSourceURI(cfg.MediaSource)
	videoArgs := buildGstVideoPipeline(
		gstStage{"videorate", "drop-only=true", "max-rate=" + strconv.Itoa(fps)},
		nil, nil, encoder, cfg.MaxWidth, cfg.MaxHeight, true)[1:]
	_, spf, _, _, _, _ := codec.Info()
	audioArgs := appendTimestampedPCMOutput(appendPCMConversion([]string{"queue"}, true), spf)
	// playbin manages the optional audio pad and signals EOS for all tracks,
	// including files with no audio or whose tracks end at different times.
	pipeline, pcm, err := launchLinkedMediaGraph(ctx, uri, encoder, videoArgs, audioArgs)
	if err != nil {
		if audioCapture.eld != nil {
			audioCapture.eld.Close()
		}
		return nil, nil, err
	}
	audioCapture.pcmPipe = pcm
	reader := newRTPL16PCMFrameReaderWithNow(pcm, time.Now)
	reader.padFinal = true
	audio := &mediaAudioPlayback{capture: audioCapture, timeline: timeline, reader: reader, lead: func() time.Duration {
		return audioLatencyDuration(session.AudioStream().currentLatencySamples())
	}}
	audioCapture.pcmFrames = audio
	return pipeline, audio, nil
}

func mediaGraphArgs(uri string, videoArgs, audioArgs []string) []string {
	return []string{"playbin", "flags=video+audio", "uri=" + uri,
		playbackSinkProperty("video-sink", videoArgs), playbackSinkProperty("audio-sink", audioArgs)}
}

// HasMediaAudio reports whether the source has delivered an audio track.
func (sc *ScreenCapture) HasMediaAudio() bool {
	return sc != nil && sc.mediaAudio != nil && sc.mediaAudio.present.Load()
}

// StreamMedia sends a finite input and keeps the stream alive until both
// tracks finish. A file without audio simply ends the audio reader at EOF.
func (s *MirrorSession) StreamMedia(ctx context.Context, capture *ScreenCapture) error {
	if capture.mediaAudio == nil {
		return s.StreamFrames(ctx, capture, 0)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 2)
	go func() { done <- s.StreamFrames(ctx, capture, 0) }()
	go func() {
		err := s.StreamAudio(ctx, capture.mediaAudio.capture, s.AudioStream())
		if errors.Is(err, io.EOF) {
			err = nil
		}
		done <- err
	}()
	var result error
	for range 2 {
		if err := <-done; err != nil && result == nil {
			result = err
			cancel()
			capture.Stop()
		}
	}
	if result != nil {
		select {
		case <-capture.waitCh:
			if capture.waitErr != nil && !errors.Is(result, capture.waitErr) {
				result = fmt.Errorf("%w: %w", result, capture.waitErr)
			}
		default:
		}
	}
	return result
}
