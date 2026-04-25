package airplay

import (
	"io"
	"sync"
)

// BroadcastCapture reads from a single ScreenCapture and fans the raw byte
// stream out to multiple registered sinks. Each sink is a pipe-based reader
// that can be passed to MirrorSession.StreamFrames just like a ScreenCapture.
//
// Usage:
//
//	bc := NewBroadcastCapture(underlying)
//	sink1 := bc.AddSink()
//	sink2 := bc.AddSink()
//	go bc.Run()          // pumps bytes from the underlying capture
//	go session1.StreamFrames(ctx, sink1.AsCapture(), 0)
//	go session2.StreamFrames(ctx, sink2.AsCapture(), 0)
type BroadcastCapture struct {
	src  *ScreenCapture
	mu   sync.Mutex
	done chan struct{}
	err  error // set once Run() exits

	sinks []*BroadcastSink
}

// BroadcastSink is a reader end of a BroadcastCapture. It satisfies the same
// Read interface as ScreenCapture and can be wrapped into a ScreenCapture-like
// value via AsCapture().
type BroadcastSink struct {
	pr     *io.PipeReader
	pw     *io.PipeWriter
	closed bool
	mu     sync.Mutex
}

// NewBroadcastCapture wraps src. Call AddSink before calling Run.
func NewBroadcastCapture(src *ScreenCapture) *BroadcastCapture {
	return &BroadcastCapture{
		src:  src,
		done: make(chan struct{}),
	}
}

// AddSink registers a new fan-out reader. Must be called before Run.
func (bc *BroadcastCapture) AddSink() *BroadcastSink {
	pr, pw := io.Pipe()
	s := &BroadcastSink{pr: pr, pw: pw}
	bc.mu.Lock()
	bc.sinks = append(bc.sinks, s)
	bc.mu.Unlock()
	return s
}

// RemoveSink closes and removes a sink so it no longer receives data.
// Safe to call concurrently with Run.
func (bc *BroadcastCapture) RemoveSink(s *BroadcastSink) {
	s.close()
	bc.mu.Lock()
	defer bc.mu.Unlock()
	for i, ss := range bc.sinks {
		if ss == s {
			bc.sinks = append(bc.sinks[:i], bc.sinks[i+1:]...)
			return
		}
	}
}

// Run pumps data from the underlying ScreenCapture to all registered sinks.
// It returns when the capture ends or all sinks are removed. The caller
// should run this in a dedicated goroutine.
func (bc *BroadcastCapture) Run() error {
	buf := make([]byte, 256*1024)
	defer func() {
		bc.mu.Lock()
		sinks := make([]*BroadcastSink, len(bc.sinks))
		copy(sinks, bc.sinks)
		bc.mu.Unlock()
		for _, s := range sinks {
			s.close()
		}
		close(bc.done)
	}()

	for {
		n, err := bc.src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			bc.mu.Lock()
			sinks := make([]*BroadcastSink, len(bc.sinks))
			copy(sinks, bc.sinks)
			bc.mu.Unlock()

			if len(sinks) == 0 {
				// No active sinks; keep draining to avoid blocking capture.
				if err != nil {
					return err
				}
				continue
			}

			for _, s := range sinks {
				if writeErr := s.write(chunk); writeErr != nil {
					// Sink is closed or broken; remove it.
					bc.RemoveSink(s)
				}
			}
		}
		if err != nil {
			bc.err = err
			return err
		}
	}
}

// Done returns a channel that is closed when Run has finished.
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

func (s *BroadcastSink) write(p []byte) error {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return io.ErrClosedPipe
	}
	_, err := s.pw.Write(p)
	return err
}

func (s *BroadcastSink) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	s.pr.CloseWithError(io.EOF)
	s.pw.CloseWithError(io.EOF)
}

// Read implements io.Reader — reads broadcast data. Blocks until data arrives
// or the broadcast ends.
func (s *BroadcastSink) Read(p []byte) (int, error) {
	return s.pr.Read(p)
}

// AsCapture wraps this sink in a synthetic ScreenCapture so it can be passed
// directly to MirrorSession.StreamFrames.
func (s *BroadcastSink) AsCapture() *ScreenCapture {
	return &ScreenCapture{
		stdout: s.pr,
		waitCh: make(chan struct{}), // never closed; EOF comes from pipe
	}
}

// Close closes this sink, signalling EOF to its reader.
func (s *BroadcastSink) Close() {
	s.close()
}
