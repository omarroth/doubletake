package airplay

import (
	"errors"
	"io"
	"sync"
	"time"
)

const (
	// A video socket can legitimately spend up to two seconds in Write. At the
	// maximum supported 12 Mbit/s bitrate that is about 3 MB of encoded video.
	// Eight MiB leaves ample room for keyframe bursts and scheduler jitter while
	// still putting a firm per-receiver bound on queued payload data.
	broadcastSinkQueueBytes = 8 << 20

	// The byte limit is normally reached first. This second bound prevents a
	// pathological source that returns tiny reads from consuming unbounded slice
	// metadata; it is deliberately generous for normal H.264 buffer cadence.
	broadcastSinkQueueChunks = 4096

	// Encoded frames are detached from the portal-owned raw-buffer pool. Keep
	// enough of them to absorb a receiver's ordinary two-second socket-write
	// stall without terminating the session; the independent byte limit still
	// bounds memory and a persistently stalled peer is removed.
	broadcastSinkQueueDuration = 2 * time.Second

	// Source shutdown normally races with consumers draining their last few
	// buffers. Do not let a receiver that stopped reading keep Run alive forever.
	broadcastSinkDrainTimeout = 2 * time.Second
)

var (
	errBroadcastSinkBacklog = errors.New("broadcast sink backlog limit exceeded")
	errBroadcastSinkMode    = errors.New("backpressured broadcast sink requires an otherwise unused capture")
)

// BroadcastCapture reads from a single ScreenCapture and fans the raw byte
// stream out to multiple registered sinks. Each sink has an independent,
// bounded queue, so a stalled receiver cannot stop capture or its peers.
//
// Usage:
//
//	bc := NewBroadcastCapture(underlying)
//	go bc.Run()          // pumps bytes from the underlying capture
//	sink1 := bc.AddSink()
//	sink2 := bc.AddSink()
//	go session1.StreamFrames(ctx, sink1.AsCapture(), 0)
//	go session2.StreamFrames(ctx, sink2.AsCapture(), 0)
type BroadcastCapture struct {
	src    *ScreenCapture
	frames bool
	// frameDuration is the configured source cadence, not the difference between
	// adjacent PTS values. A leaky upstream queue can legitimately create large
	// PTS gaps while only one encoded picture is pending.
	frameDuration time.Duration
	mu            sync.Mutex
	done          chan struct{}
	err           error // set before done is closed
	stopped       bool
	exclusive     bool // one backpressured sink owns this capture for its lifetime
	// sequence is reserved before each source Read. A late sink starts at the
	// following sequence, which gives attachment an exact cutover even when a
	// source read has completed but has not yet been fanned out.
	sequence uint64
	drainTimeout time.Duration

	sinks []*BroadcastSink
}

// BroadcastSink is a reader end of a BroadcastCapture. It satisfies the same
// Read interface as ScreenCapture and can be wrapped into a ScreenCapture-like
// value via AsCapture().
type BroadcastSink struct {
	owner *BroadcastCapture

	mu   sync.Mutex
	cond *sync.Cond

	queue       [][]byte
	frameQueue  []VideoAccessUnit
	headOffset  int
	queuedBytes int
	// queuedFrameDuration is a nominal sample-duration sum. It deliberately does
	// not use the PTS span: source-frame dropping makes that span discontinuous.
	queuedFrameDuration time.Duration
	frameDuration       time.Duration

	maxQueuedBytes  int
	maxQueuedChunks int
	// This encoded system-memory queue is independent of Apple's upstream raw
	// frame queue. It counts nominal sample durations so PTS gaps caused by raw
	// frame dropping do not spuriously detach a healthy receiver.
	maxFrameQueueDuration time.Duration
	backpressure          bool
	blockedProducers      int // number waiting for queue handoff; guarded by mu

	inputClosed   bool // the source ended; drain queue, then return EOF
	closed        bool // explicitly removed; discard queue and return EOF
	doneClosed    bool
	done          chan struct{}
	startSequence uint64
}

func newBroadcastSinkWithPolicy(owner *BroadcastCapture, backpressure bool) *BroadcastSink {
	frameDuration := time.Second / 30
	if owner != nil && owner.frameDuration > 0 {
		frameDuration = owner.frameDuration
	}
	s := &BroadcastSink{
		owner:                 owner,
		maxQueuedBytes:        broadcastSinkQueueBytes,
		maxQueuedChunks:       broadcastSinkQueueChunks,
		maxFrameQueueDuration: broadcastSinkQueueDuration,
		backpressure:          backpressure,
		frameDuration:         frameDuration,
		done:                  make(chan struct{}),
	}
	s.cond = sync.NewCond(&s.mu)
	return s
}

func newBroadcastSink(owner *BroadcastCapture) *BroadcastSink {
	return newBroadcastSinkWithPolicy(owner, false)
}

// NewBroadcastCapture wraps src. Sinks may be added before or while Run is
// active; running without sinks simply drains the encoder until a session is
// ready to consume frames.
func NewBroadcastCapture(src *ScreenCapture) *BroadcastCapture {
	return NewBroadcastCaptureWithFrameRate(src, 30)
}

// NewBroadcastCaptureWithFrameRate wraps src and supplies the nominal sample
// duration used to bound asynchronous fan-out queues. PTS remains the media
// timestamp; frame rate is used only for queue-duration accounting.
func NewBroadcastCaptureWithFrameRate(src *ScreenCapture, fps int) *BroadcastCapture {
	if fps <= 0 {
		fps = 30
	}
	return &BroadcastCapture{
		src:           src,
		frames:        src != nil && src.frames != nil,
		frameDuration: time.Second / time.Duration(fps),
		done:          make(chan struct{}),
		drainTimeout:  broadcastSinkDrainTimeout,
	}
}

// AddSink registers a shared fan-out reader before or while Run is active. A
// capture reserved by AddBackpressuredSink rejects later shared readers by
// returning an already-finished sink, preserving the no-cross-target-stall
// invariant even if a caller accidentally mixes the two modes.
func (bc *BroadcastCapture) AddSink() *BroadcastSink {
	s := newBroadcastSinkWithPolicy(bc, false)
	bc.mu.Lock()
	if bc.stopped || bc.exclusive {
		bc.mu.Unlock()
		s.finish()
		return s
	}
	s.startSequence = bc.sequence + 1
	bc.sinks = append(bc.sinks, s)
	bc.mu.Unlock()
	return s
}

// AddBackpressuredSink registers a sink for a single-destination caller. It
// permits only one pending chunk or access unit, propagating a stalled network
// writer back into the capture pipeline's leaky raw-frame queue. Shared daemon
// fan-out must use AddSink so one receiver can never block another. Registration
// fails if any sink has already claimed the capture.
func (bc *BroadcastCapture) AddBackpressuredSink() (*BroadcastSink, error) {
	s := newBroadcastSinkWithPolicy(bc, true)
	bc.mu.Lock()
	if bc.stopped {
		bc.mu.Unlock()
		s.finish()
		return s, nil
	}
	if bc.exclusive || len(bc.sinks) != 0 {
		bc.mu.Unlock()
		s.abort()
		return nil, errBroadcastSinkMode
	}
	bc.exclusive = true
	s.startSequence = bc.sequence + 1
	bc.sinks = append(bc.sinks, s)
	bc.mu.Unlock()
	return s, nil
}

// RemoveSink closes and removes a sink so it no longer receives data. Any
// blocked Read is released immediately. It is safe to call concurrently with
// Run or more than once.
func (bc *BroadcastCapture) RemoveSink(s *BroadcastSink) {
	if s == nil {
		return
	}
	s.abort()

	bc.mu.Lock()
	defer bc.mu.Unlock()
	for i, current := range bc.sinks {
		if current == s {
			bc.sinks = append(bc.sinks[:i], bc.sinks[i+1:]...)
			return
		}
	}
}

// Run pumps data from the underlying ScreenCapture to all registered sinks.
// It returns when the capture ends and every active sink has consumed the data
// already queued for it, or after the bounded drain grace period. The caller
// should run this in a dedicated goroutine; an empty sink list is intentionally
// not terminal.
func (bc *BroadcastCapture) Run() error {
	if bc.frames {
		return bc.runFrames()
	}
	buf := make([]byte, 256*1024)
	for {
		// Reserve this read's sequence before blocking in the source. A sink added
		// at any point after this reservation must begin with the next read, not
		// with bytes that may have been captured before its session was ready.
		bc.mu.Lock()
		bc.sequence++
		sequence := bc.sequence
		bc.mu.Unlock()

		n, readErr := bc.src.Read(buf)
		if n > 0 {
			bc.mu.Lock()
			sinks := make([]*BroadcastSink, 0, len(bc.sinks))
			for _, sink := range bc.sinks {
				if sink.startSequence <= sequence {
					sinks = append(sinks, sink)
				}
			}
			bc.mu.Unlock()

			if len(sinks) > 0 {
				// The payload is immutable after this point and can therefore be
				// shared by all sink queues instead of copied once per receiver.
				chunk := append([]byte(nil), buf[:n]...)
				for _, s := range sinks {
					if err := s.enqueue(chunk); err != nil {
						// A receiver that accumulates more than the bounded
						// backlog is detached without delaying healthy peers.
						bc.RemoveSink(s)
					}
				}
			}
		}
		if readErr != nil {
			bc.finish(readErr)
			return readErr
		}
	}
}

// runFrames preserves access-unit boundaries and capture PTS while sharing one
// encoder between receivers. Reserving the sequence before the blocking read
// gives late sinks the same clean next-frame cutover as the byte path.
func (bc *BroadcastCapture) runFrames() error {
	for {
		bc.mu.Lock()
		bc.sequence++
		sequence := bc.sequence
		bc.mu.Unlock()

		frame, readErr := bc.src.ReadVideoAccessUnit()
		if len(frame.AnnexB) > 0 {
			bc.mu.Lock()
			sinks := make([]*BroadcastSink, 0, len(bc.sinks))
			for _, sink := range bc.sinks {
				if sink.startSequence <= sequence {
					sinks = append(sinks, sink)
				}
			}
			bc.mu.Unlock()

			for _, sink := range sinks {
				if err := sink.enqueueFrame(frame); err != nil {
					bc.RemoveSink(sink)
				}
			}
		}
		if readErr != nil {
			bc.finish(readErr)
			return readErr
		}
	}
}

// finish stops accepting sinks, lets existing sinks drain, and only then
// publishes BroadcastCapture completion.
func (bc *BroadcastCapture) finish(err error) {
	bc.mu.Lock()
	bc.err = err
	bc.stopped = true
	sinks := append([]*BroadcastSink(nil), bc.sinks...)
	bc.sinks = nil
	bc.mu.Unlock()

	for _, s := range sinks {
		s.finish()
	}
	timer := time.NewTimer(bc.drainTimeout)
	defer timer.Stop()
	for i, s := range sinks {
		select {
		case <-s.done:
		case <-timer.C:
			// The grace period is shared by every sink, so shutdown is bounded
			// regardless of receiver count. Aborting an already-drained sink is
			// harmless and avoids a second bookkeeping pass.
			for _, pending := range sinks[i:] {
				pending.abort()
			}
			close(bc.done)
			return
		}
	}
	close(bc.done)
}

// Done returns a channel that is closed after Run has finished and all queued
// sink data has either been consumed, explicitly discarded by closing the
// sink, or discarded when the bounded drain grace period expires.
func (bc *BroadcastCapture) Done() <-chan struct{} {
	return bc.done
}

// Err returns the error that caused Run to exit (nil if still running).
func (bc *BroadcastCapture) Err() error {
	select {
	case <-bc.done:
		return bc.err
	default:
		return nil
	}
}

// Source returns the underlying ScreenCapture.
func (bc *BroadcastCapture) Source() *ScreenCapture {
	return bc.src
}

// --- BroadcastSink ---

// enqueue appends immutable capture data. Shared sinks never wait for the
// receiver and are detached on overflow; an explicitly backpressured sink waits
// for its one pending chunk to be consumed.
func (s *BroadcastSink) enqueue(p []byte) error {
	if len(p) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.closed || s.inputClosed {
			return io.ErrClosedPipe
		}
		if s.backpressure && len(s.queue) > 0 {
			s.blockedProducers++
			s.cond.Wait()
			s.blockedProducers--
			continue
		}
		if len(s.queue) >= s.maxQueuedChunks || len(p) > s.maxQueuedBytes-s.queuedBytes {
			return errBroadcastSinkBacklog
		}
		break
	}
	s.queue = append(s.queue, p)
	s.queuedBytes += len(p)
	s.cond.Signal()
	return nil
}

func (s *BroadcastSink) frameQueueExceedsLimitsLocked(frame VideoAccessUnit) bool {
	if len(s.frameQueue) >= s.maxQueuedChunks || len(frame.AnnexB) > s.maxQueuedBytes-s.queuedBytes {
		return true
	}
	return len(s.frameQueue) > 0 && s.maxFrameQueueDuration > 0 &&
		s.queuedFrameDuration+s.frameDuration > s.maxFrameQueueDuration
}

// enqueueFrame appends an immutable complete access unit without copying it.
// The same backing bytes can safely be referenced by every receiver queue.
// An explicitly single-destination sink waits once one AU is pending, rather
// than accumulating encoded references which cannot safely be dropped. Shared
// fan-out is nonblocking and detaches only the sink which exceeds Doubletake's
// nominal-duration relay budget. This policy is distinct from Apple's upstream
// source-frame dropping behavior.
func (s *BroadcastSink) enqueueFrame(frame VideoAccessUnit) error {
	if len(frame.AnnexB) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		if s.closed || s.inputClosed {
			return io.ErrClosedPipe
		}
		if len(s.frameQueue) == 0 && len(frame.AnnexB) > s.maxQueuedBytes {
			return errBroadcastSinkBacklog
		}
		if s.backpressure && len(s.frameQueue) > 0 {
			s.blockedProducers++
			s.cond.Wait()
			s.blockedProducers--
			continue
		}
		if s.frameQueueExceedsLimitsLocked(frame) {
			return errBroadcastSinkBacklog
		}
		break
	}
	s.frameQueue = append(s.frameQueue, frame)
	s.queuedBytes += len(frame.AnnexB)
	s.queuedFrameDuration += s.frameDuration
	s.cond.Signal()
	return nil
}

func (s *BroadcastSink) queueEmptyLocked() bool {
	return len(s.queue) == 0 && len(s.frameQueue) == 0
}

// finish marks source EOF without discarding data already queued.
func (s *BroadcastSink) finish() {
	s.mu.Lock()
	if !s.closed && !s.inputClosed {
		s.inputClosed = true
		if s.queueEmptyLocked() {
			s.closeDoneLocked()
		}
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

// abort discards queued data and releases a blocked reader immediately.
func (s *BroadcastSink) abort() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.inputClosed = true
		for i := range s.queue {
			s.queue[i] = nil
		}
		s.queue = nil
		for i := range s.frameQueue {
			s.frameQueue[i].AnnexB = nil
		}
		s.frameQueue = nil
		s.headOffset = 0
		s.queuedBytes = 0
		s.queuedFrameDuration = 0
		s.closeDoneLocked()
		s.cond.Broadcast()
	}
	s.mu.Unlock()
}

func (s *BroadcastSink) closeDoneLocked() {
	if !s.doneClosed {
		s.doneClosed = true
		close(s.done)
	}
}

// Read implements io.Reader. It blocks until data arrives, the source ends, or
// the sink is explicitly closed.
func (s *BroadcastSink) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.queue) == 0 && !s.inputClosed && !s.closed {
		s.cond.Wait()
	}
	if s.closed {
		return 0, io.EOF
	}
	if len(s.queue) == 0 {
		s.closeDoneLocked()
		return 0, io.EOF
	}

	chunk := s.queue[0]
	n := copy(p, chunk[s.headOffset:])
	s.headOffset += n
	s.queuedBytes -= n
	if s.headOffset == len(chunk) {
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.headOffset = 0
		s.cond.Broadcast()
		if len(s.queue) == 0 {
			s.queue = nil
			if s.inputClosed {
				s.closeDoneLocked()
				return n, nil
			}
		}
	}
	return n, nil
}

// ReadVideoAccessUnit returns the next complete timestamped frame. It blocks
// until a frame arrives, the source ends, or this sink is removed.
func (s *BroadcastSink) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.frameQueue) == 0 && !s.inputClosed && !s.closed {
		s.cond.Wait()
	}
	if s.closed {
		return VideoAccessUnit{}, io.EOF
	}
	if len(s.frameQueue) == 0 {
		s.closeDoneLocked()
		return VideoAccessUnit{}, io.EOF
	}

	frame := s.frameQueue[0]
	s.frameQueue[0].AnnexB = nil
	s.frameQueue = s.frameQueue[1:]
	s.queuedBytes -= len(frame.AnnexB)
	s.queuedFrameDuration -= s.frameDuration
	if s.queuedFrameDuration < 0 {
		s.queuedFrameDuration = 0
	}
	// Wake a single-destination producer waiting to hand off the next complete
	// AU. Broadcast is intentional because Close/finish share this condition.
	s.cond.Broadcast()
	if len(s.frameQueue) == 0 {
		s.frameQueue = nil
		if s.inputClosed && len(s.queue) == 0 {
			s.closeDoneLocked()
			return frame, nil
		}
	}
	return frame, nil
}

type broadcastSinkReadCloser struct {
	sink *BroadcastSink
}

func (r broadcastSinkReadCloser) Read(p []byte) (int, error) {
	return r.sink.Read(p)
}

func (r broadcastSinkReadCloser) Close() error {
	r.sink.Close()
	return nil
}

// AsCapture wraps this sink in a synthetic ScreenCapture so it can be passed
// directly to MirrorSession.StreamFrames.
func (s *BroadcastSink) AsCapture() *ScreenCapture {
	capture := &ScreenCapture{
		stdout: broadcastSinkReadCloser{sink: s},
		waitCh: s.done,
	}
	if s.owner != nil && s.owner.frames {
		capture.frames = s
	}
	return capture
}

// Close closes this sink, discarding queued data and signalling EOF to its
// reader.
func (s *BroadcastSink) Close() {
	if s.owner != nil {
		s.owner.RemoveSink(s)
		return
	}
	s.abort()
}
