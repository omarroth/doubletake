package airplay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"
)

type sharedPCMInput struct {
	frames chan audioPCMFramePosition
	done   chan struct{}
	wait   chan struct{}
	once   sync.Once
}

func (r *sharedPCMInput) ReadPCMFrame(dst []byte) (time.Time, error) {
	p, e := r.ReadPCMFramePosition(dst)
	return p.PTS, e
}
func (r *sharedPCMInput) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	select {
	case p, ok := <-r.frames:
		if !ok {
			return audioPCMFramePosition{}, io.EOF
		}
		for i := range dst {
			dst[i] = byte(int(p.SourceRTP) + i)
		}
		return p, nil
	case <-r.done:
		return audioPCMFramePosition{}, io.EOF
	}
}
func (r *sharedPCMInput) Read([]byte) (int, error) { panic("raw reads not expected") }
func (r *sharedPCMInput) Close() error {
	r.once.Do(func() { close(r.done); close(r.wait) })
	return nil
}

func newSharedAudioTestHub(t *testing.T) (*SharedAudioCapture, **sharedPCMInput, *int) {
	t.Helper()
	var input *sharedPCMInput
	starts := 0
	h := &SharedAudioCapture{start: func(context.Context, bool, AudioCodec, AudioSource) (*AudioCapture, error) {
		starts++
		input = &sharedPCMInput{frames: make(chan audioPCMFramePosition), done: make(chan struct{}), wait: make(chan struct{})}
		return &AudioCapture{codec: AudioCodecALAC, pcmFrames: input, pcmPipe: input, waitCh: input.wait}, nil
	}}
	t.Cleanup(h.Close)
	return h, &input, &starts
}

func acquireSharedTestCapture(t *testing.T, h *SharedAudioCapture) *AudioCapture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	c, err := h.Acquire(ctx, true, AudioCodecALAC, AudioSourceOutput)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	return c
}

func TestSharedAudioEncodesOnePayloadForMultipleReceivers(t *testing.T) {
	h, input, starts := newSharedAudioTestHub(t)
	a, b := acquireSharedTestCapture(t, h), acquireSharedTestCapture(t, h)
	base := time.Now()
	for i := range 8 {
		want := audioPCMFramePosition{PTS: base.Add(audioSamplesDuration(uint64(i * 352))), SourceRTP: uint32(i * 352), HasSourceRTP: true}
		(*input).frames <- want
		first, second := make([]byte, 8192), make([]byte, 8192)
		n, p, err := a.readFramePosition(first)
		if err != nil {
			t.Fatal(err)
		}
		m, q, err := b.readFramePosition(second)
		if err != nil {
			t.Fatal(err)
		}
		if n != m || !bytes.Equal(first[:n], second[:m]) || p != want || q != want {
			t.Fatalf("receivers did not get identical encoded source frames: n=%d/%d p=%+v/%+v", n, m, p, q)
		}
	}
	h.mu.Lock()
	encoders := len(h.active.codecs)
	h.mu.Unlock()
	if *starts != 1 || encoders != 1 {
		t.Fatalf("source starts=%d encoders=%d, want 1/1", *starts, encoders)
	}
	a.Stop()
	select {
	case <-(*input).done:
		t.Fatal("first disconnect stopped shared source")
	default:
	}
	(*input).frames <- audioPCMFramePosition{PTS: base.Add(time.Second), SourceRTP: 44100, HasSourceRTP: true}
	if _, _, err := b.readFramePosition(make([]byte, 8192)); err != nil {
		t.Fatal(err)
	}
	b.Stop()
	select {
	case <-(*input).done:
	default:
		t.Fatal("last disconnect did not stop source")
	}
	acquireSharedTestCapture(t, h)
	if *starts != 2 {
		t.Fatal("new stream did not restart a fresh shared source")
	}
}

func TestSharedAudioSlowReceiverCannotStallPeers(t *testing.T) {
	h, input, _ := newSharedAudioTestHub(t)
	slow, fast := acquireSharedTestCapture(t, h), acquireSharedTestCapture(t, h)
	base := time.Now()
	for i := range 100 {
		(*input).frames <- audioPCMFramePosition{PTS: base.Add(audioSamplesDuration(uint64(i * 352))), SourceRTP: uint32(i * 352), HasSourceRTP: true}
		if _, _, err := fast.readFramePosition(make([]byte, 8192)); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := slow.readFramePosition(make([]byte, 8192)); !errors.Is(err, errSharedAudioBacklog) {
		t.Fatalf("slow receiver = %v, want backlog error", err)
	}
	select {
	case <-(*input).done:
		t.Fatal("slow receiver failure stopped healthy peer")
	default:
	}
}

func TestSharedAudioSourceEOFDrainsAllReceivers(t *testing.T) {
	h, input, _ := newSharedAudioTestHub(t)
	a, b := acquireSharedTestCapture(t, h), acquireSharedTestCapture(t, h)
	for i := range 3 {
		(*input).frames <- audioPCMFramePosition{PTS: time.Now(), SourceRTP: uint32(i * 352), HasSourceRTP: true}
	}
	close((*input).frames)
	for _, c := range []*AudioCapture{a, b} {
		for range 3 {
			if _, _, err := c.readFramePosition(make([]byte, 8192)); err != nil {
				t.Fatal(err)
			}
		}
		if _, _, err := c.readFramePosition(make([]byte, 8192)); !errors.Is(err, io.EOF) {
			t.Fatalf("source completion = %v", err)
		}
	}
}

func TestSharedAudioCancellationReleasesBlockedRead(t *testing.T) {
	h, _, _ := newSharedAudioTestHub(t)
	ctx, cancel := context.WithCancel(context.Background())
	c, err := h.Acquire(ctx, true, AudioCodecALAC, AudioSourceOutput)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := c.readFramePosition(make([]byte, 8192)); done <- err }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not release shared reader")
	}
	c.Stop()
}

func TestSharedAudioMixedCodecsPreserveSampleTimeline(t *testing.T) {
	if !aacELDEncoderAvailable {
		t.Skip("requires fdk_aac")
	}
	alac, err := newSharedAudioCodec(AudioCodecALAC)
	if err != nil {
		t.Fatal(err)
	}
	defer alac.close()
	eld, err := newSharedAudioCodec(AudioCodecAACELD)
	if err != nil {
		t.Fatal(err)
	}
	defer eld.close()
	base := time.Now()
	for _, g := range []*sharedAudioCodec{alac, eld} {
		var frames []encodedAudioFrame
		for i := range 30 {
			position := audioPCMFramePosition{PTS: base.Add(audioSamplesDuration(uint64(i * 352))), SourceRTP: uint32(i * 352), HasSourceRTP: true}
			encoded, err := g.encode(make([]byte, 352*4), position)
			if err != nil {
				t.Fatal(err)
			}
			frames = append(frames, encoded...)
		}
		_, spf, _, _, _, _ := g.codec.Info()
		if len(frames) != 10560/int(spf) {
			t.Fatalf("codec %d encoded %d frames", g.codec, len(frames))
		}
		for i, f := range frames {
			wantRTP := uint32(int64(i) * spf)
			wantPTS := base.Add(audioSamplesDuration(uint64(wantRTP)))
			if f.position.SourceRTP != wantRTP || f.position.PTS.Sub(wantPTS).Abs() > time.Nanosecond {
				t.Fatalf("codec %d frame %d position=%+v want RTP=%d PTS=%v", g.codec, i, f.position, wantRTP, wantPTS)
			}
		}
	}
}

func TestSharedAudioDiscontinuityDoesNotSplicePartialFrames(t *testing.T) {
	if !aacELDEncoderAvailable {
		t.Skip("requires fdk_aac")
	}
	g, err := newSharedAudioCodec(AudioCodecAACELD)
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	base := time.Now()
	for _, rtp := range []uint32{0, 2000, 2352} {
		frames, err := g.encode(make([]byte, 352*4), audioPCMFramePosition{PTS: base.Add(audioSamplesDuration(uint64(rtp))), SourceRTP: rtp, HasSourceRTP: true})
		if err != nil {
			t.Fatal(err)
		}
		if rtp == 2352 && (len(frames) != 1 || frames[0].position.SourceRTP != 2000) {
			t.Fatalf("discontinuous samples spliced into %+v", frames)
		}
	}
}
