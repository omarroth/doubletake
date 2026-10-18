package airplay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
)

var errSharedAudioBacklog = errors.New("shared audio receiver backlog exceeded")

type audioEncodedFrameReader interface {
	readEncodedFrame([]byte) (int, audioPCMFramePosition, error)
}

type encodedAudioFrame struct {
	payload  []byte // immutable: encryption and RTP framing happen per receiver
	position audioPCMFramePosition
}

type sharedAudioSink struct {
	mu     sync.Mutex
	cond   *sync.Cond
	queue  []encodedAudioFrame
	limit  int
	closed bool
	err    error
	done   chan struct{}
}

func newSharedAudioSink(codec AudioCodec) *sharedAudioSink {
	_, spf, _, _, _, _ := codec.Info()
	s := &sharedAudioSink{limit: int(audioCaptureStallBuffer/audioSamplesDuration(uint64(spf))) + 1, done: make(chan struct{})}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func (s *sharedAudioSink) push(frame encodedAudioFrame) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if len(s.queue) >= s.limit {
		s.queue = nil
		s.finishLocked(errSharedAudioBacklog)
		return
	}
	s.queue = append(s.queue, frame)
	s.cond.Signal()
}

func (s *sharedAudioSink) finishLocked(err error) {
	if s.closed {
		return
	}
	s.closed, s.err = true, err
	close(s.done)
	s.cond.Broadcast()
}

func (s *sharedAudioSink) finish(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.finishLocked(err)
}

func (s *sharedAudioSink) abort() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.queue = nil
		s.finishLocked(io.EOF)
	}
}

func (s *sharedAudioSink) readEncodedFrame(dst []byte) (int, audioPCMFramePosition, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.queue) == 0 && !s.closed {
		s.cond.Wait()
	}
	if len(s.queue) == 0 {
		return 0, audioPCMFramePosition{}, s.err
	}
	frame := s.queue[0]
	if len(dst) < len(frame.payload) {
		return 0, audioPCMFramePosition{}, io.ErrShortBuffer
	}
	s.queue[0] = encodedAudioFrame{}
	s.queue = s.queue[1:]
	return copy(dst, frame.payload), frame.position, nil
}

type sharedAudioCodec struct {
	mu       sync.Mutex // serializes encoding and encoder destruction
	codec    AudioCodec
	alac     alacEncoder
	eld      *eldEncoder
	pcm      []byte
	position audioPCMFramePosition
	nextRTP  uint32
	haveRTP  bool
	closed   bool
	sinks    map[*sharedAudioSink]struct{} // protected by SharedAudioCapture.mu
}

func newSharedAudioCodec(codec AudioCodec) (*sharedAudioCodec, error) {
	g := &sharedAudioCodec{codec: codec, sinks: make(map[*sharedAudioSink]struct{})}
	switch codec {
	case AudioCodecALAC:
	case AudioCodecAACELD:
		var err error
		g.eld, err = newELDEncoder()
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported shared audio codec %d", codec)
	}
	return g, nil
}

func (g *sharedAudioCodec) close() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.closed && g.eld != nil {
		g.eld.Close()
	}
	g.closed = true
}

func (g *sharedAudioCodec) encode(pcm []byte, position audioPCMFramePosition) ([]encodedAudioFrame, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil, nil
	}
	if !g.haveRTP || position.SourceRTP != g.nextRTP {
		// A discontinuity must not concatenate samples from opposite sides of a
		// gap into one codec frame. Preserve the new sample position for RTP reset.
		g.pcm = nil
	}
	g.haveRTP = true
	g.nextRTP = position.SourceRTP + uint32(len(pcm)/audioBytesPerSampleFrame)
	buffered := len(g.pcm) / audioBytesPerSampleFrame
	g.position = position
	g.position.SourceRTP -= uint32(buffered)
	g.position.PTS = position.PTS.Add(-audioSamplesDuration(uint64(buffered)))
	g.pcm = append(g.pcm, pcm...)
	_, spf, _, _, _, _ := g.codec.Info()
	frameBytes := int(spf) * audioBytesPerSampleFrame
	var frames []encodedAudioFrame
	for len(g.pcm) >= frameBytes {
		out := make([]byte, 8192)
		var n int
		var err error
		if g.eld != nil {
			n, err = g.eld.Encode(g.pcm[:frameBytes], out)
		} else {
			n = g.alac.Encode(out, g.pcm[:frameBytes])
		}
		if err != nil {
			return nil, err
		}
		if n > 0 {
			frames = append(frames, encodedAudioFrame{payload: out[:n], position: g.position})
		}
		g.pcm = g.pcm[frameBytes:]
		g.position.PTS = g.position.PTS.Add(audioSamplesDuration(uint64(spf)))
		g.position.SourceRTP += uint32(spf)
	}
	return frames, nil
}

type sharedAudioGeneration struct {
	source   *AudioCapture
	codecs   map[AudioCodec]*sharedAudioCodec
	users    int
	done     chan struct{}
	testTone bool
	route    AudioSource
}

// SharedAudioCapture owns one timestamped PCM source and one encoder for each
// negotiated codec. Receiver queues, RTP epochs, security, retransmission and
// clock conversion remain independent. Its zero value is ready to use.
type SharedAudioCapture struct {
	mu     sync.Mutex
	active *sharedAudioGeneration
	closed bool
	start  func(context.Context, bool, AudioCodec, AudioSource) (*AudioCapture, error)
}

// SharedAudioStats describes active capture/encoding resources, not receiver
// rendering or clock-lock measurements.
type SharedAudioStats struct {
	Sources   int `json:"sources"`
	Encoders  int `json:"encoders"`
	Receivers int `json:"receivers"`
}

func (h *SharedAudioCapture) Stats() SharedAudioStats {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active == nil {
		return SharedAudioStats{}
	}
	return SharedAudioStats{Sources: 1, Encoders: len(h.active.codecs), Receivers: h.active.users}
}

// PreferredCodec reuses an active encoder when possible. Negotiation must still
// check the new receiver's format mask; this is a preference, not an override.
func (h *SharedAudioCapture) PreferredCodec() AudioCodec {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active != nil {
		if h.active.codecs[AudioCodecALAC] != nil {
			return AudioCodecALAC
		}
		if h.active.codecs[AudioCodecAACELD] != nil {
			return AudioCodecAACELD
		}
	}
	return AudioCodecALAC
}

func (h *SharedAudioCapture) Acquire(ctx context.Context, testTone bool, codec AudioCodec, route AudioSource) (*AudioCapture, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if h.closed {
		return nil, fmt.Errorf("shared audio capture is closed")
	}
	if err := ValidateAudioSource(string(route)); err != nil {
		return nil, err
	}
	if route == "" {
		route = AudioSourceOutput
	}
	gen := h.active
	if gen != nil && (gen.route != route || gen.testTone != testTone) {
		return nil, fmt.Errorf("shared audio source configuration changed")
	}
	var group *sharedAudioCodec
	if gen != nil {
		group = gen.codecs[codec]
	}
	if group == nil {
		var err error
		group, err = newSharedAudioCodec(codec)
		if err != nil {
			return nil, err
		}
	}
	if gen == nil {
		start := h.start
		if start == nil {
			if !supportsTimestampedAudioOutput() {
				group.close()
				return nil, fmt.Errorf("shared audio requires GStreamer RTP/ONVIF audio timestamps")
			}
			start = StartAudioCaptureWithSource
		}
		// This lifetime belongs to all consumers, not to the first receiver.
		source, err := start(context.Background(), testTone, AudioCodecALAC, route)
		if err != nil {
			group.close()
			return nil, err
		}
		gen = &sharedAudioGeneration{source: source, codecs: make(map[AudioCodec]*sharedAudioCodec), done: make(chan struct{}), testTone: testTone, route: route}
		h.active = gen
		go h.run(gen)
	}
	gen.codecs[codec] = group
	sink := newSharedAudioSink(codec)
	group.sinks[sink] = struct{}{}
	gen.users++
	capture := &AudioCapture{codec: codec, encodedFrames: sink}
	capture.stopShared = func() {
		sink.abort()
		h.mu.Lock()
		delete(group.sinks, sink)
		gen.users--
		if len(group.sinks) == 0 {
			delete(gen.codecs, codec)
			group.close()
		}
		last := gen.users == 0
		if last && h.active == gen {
			h.active = nil
		}
		h.mu.Unlock()
		if last {
			gen.source.Stop()
			<-gen.done
		}
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-sink.done:
		}
		capture.Stop()
	}()
	return capture, nil
}

func (h *SharedAudioCapture) run(gen *sharedAudioGeneration) {
	terminal := error(io.EOF)
	defer func() {
		h.mu.Lock()
		if h.active == gen {
			h.active = nil
		}
		for _, g := range gen.codecs {
			for s := range g.sinks {
				s.finish(terminal)
			}
			g.close()
		}
		h.mu.Unlock()
		gen.source.Stop()
		close(gen.done)
	}()
	pcm := make([]byte, 352*audioBytesPerSampleFrame)
	for {
		position, err := gen.source.readPCMFramePosition(pcm)
		if err != nil {
			terminal = err
			return
		}
		if position.PTS.IsZero() || !position.HasSourceRTP {
			terminal = fmt.Errorf("shared PCM source lost its timestamp/sample clock")
			return
		}
		h.mu.Lock()
		groups := make([]*sharedAudioCodec, 0, len(gen.codecs))
		for _, g := range gen.codecs {
			groups = append(groups, g)
		}
		h.mu.Unlock()
		for _, g := range groups {
			frames, err := g.encode(pcm, position)
			h.mu.Lock()
			for s := range g.sinks {
				if err != nil {
					s.finish(fmt.Errorf("shared audio encode: %w", err))
					continue
				}
				for _, frame := range frames {
					s.push(frame)
				}
			}
			h.mu.Unlock()
		}
	}
}

func (h *SharedAudioCapture) Close() {
	h.mu.Lock()
	h.closed = true
	gen := h.active
	if gen != nil {
		for _, g := range gen.codecs {
			for s := range g.sinks {
				s.abort()
			}
		}
	}
	h.mu.Unlock()
	if gen != nil {
		gen.source.Stop()
		<-gen.done
	}
}
