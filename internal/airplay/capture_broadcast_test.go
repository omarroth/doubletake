package airplay

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"testing"
	"time"
)

type sliceVideoAccessUnitReader struct {
	frames []VideoAccessUnit
	index  int
}

type channelVideoAccessUnitReader struct {
	frames <-chan VideoAccessUnit
}

func waitForBroadcastSinkState(t *testing.T, sink *BroadcastSink, predicate func(*BroadcastSink) bool, description string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		sink.mu.Lock()
		ready := predicate(sink)
		sink.mu.Unlock()
		if ready {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for broadcast sink state: %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForBlockedBroadcastProducer(t *testing.T, sink *BroadcastSink) {
	t.Helper()
	waitForBroadcastSinkState(t, sink, func(s *BroadcastSink) bool {
		return s.blockedProducers > 0
	}, "producer blocked on single-target handoff")
}

func (r *channelVideoAccessUnitReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	frame, ok := <-r.frames
	if !ok {
		return VideoAccessUnit{}, io.EOF
	}
	return frame, nil
}

func (r *sliceVideoAccessUnitReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	if r.index == len(r.frames) {
		return VideoAccessUnit{}, io.EOF
	}
	frame := r.frames[r.index]
	r.index++
	return frame, nil
}

func TestBroadcastCapturePreservesTimestampedAccessUnits(t *testing.T) {
	firstPTS := time.Now().Add(-200 * time.Millisecond)
	frames := []VideoAccessUnit{
		{AnnexB: []byte{0, 0, 0, 1, 0x65, 1}, PTS: firstPTS},
		{AnnexB: []byte{0, 0, 0, 1, 0x61, 2}, PTS: firstPTS.Add(time.Second / 30)},
	}
	capture := &ScreenCapture{
		frames: &sliceVideoAccessUnitReader{frames: frames},
		waitCh: make(chan struct{}),
	}
	broadcast := NewBroadcastCapture(capture)
	firstSink := broadcast.AddSink().AsCapture()
	secondSink := broadcast.AddSink().AsCapture()
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()

	for i, want := range frames {
		for sinkIndex, sink := range []*ScreenCapture{firstSink, secondSink} {
			got, err := sink.ReadVideoAccessUnit()
			if err != nil {
				t.Fatalf("sink %d frame %d: %v", sinkIndex, i, err)
			}
			if !bytes.Equal(got.AnnexB, want.AnnexB) || got.PTS != want.PTS {
				t.Fatalf("sink %d frame %d = {%x %v}, want {%x %v}", sinkIndex, i, got.AnnexB, got.PTS, want.AnnexB, want.PTS)
			}
		}
	}
	for sinkIndex, sink := range []*ScreenCapture{firstSink, secondSink} {
		if frame, err := sink.ReadVideoAccessUnit(); len(frame.AnnexB) != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("sink %d read after final frame = (%x, %v), want empty EOF", sinkIndex, frame.AnnexB, err)
		}
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("broadcast run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timestamped broadcast did not finish after both sinks drained")
	}
}

func TestBroadcastSinkBackpressuresWithOnePendingAccessUnit(t *testing.T) {
	sink := newBroadcastSinkWithPolicy(nil, true)
	base := time.Now()
	first := VideoAccessUnit{AnnexB: []byte{1}, PTS: base}
	second := VideoAccessUnit{AnnexB: []byte{2}, PTS: base.Add(time.Second / 30)}
	if err := sink.enqueueFrame(first); err != nil {
		t.Fatalf("enqueue first frame: %v", err)
	}

	enqueued := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		enqueued <- sink.enqueueFrame(second)
	}()
	<-started
	waitForBlockedBroadcastProducer(t, sink)
	got, err := sink.ReadVideoAccessUnit()
	if err != nil || !bytes.Equal(got.AnnexB, first.AnnexB) {
		t.Fatalf("read first frame = (%x, %v), want (%x, nil)", got.AnnexB, err, first.AnnexB)
	}
	select {
	case err := <-enqueued:
		if err != nil {
			t.Fatalf("enqueue second frame after handoff: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("dequeue did not release the backpressured producer")
	}
	got, err = sink.ReadVideoAccessUnit()
	if err != nil || !bytes.Equal(got.AnnexB, second.AnnexB) {
		t.Fatalf("read second frame = (%x, %v), want (%x, nil)", got.AnnexB, err, second.AnnexB)
	}
}

func TestBroadcastSinkBackpressuresWithOnePendingByteChunk(t *testing.T) {
	sink := newBroadcastSinkWithPolicy(nil, true)
	first := []byte("first")
	second := []byte("second")
	if err := sink.enqueue(first); err != nil {
		t.Fatalf("enqueue first chunk: %v", err)
	}
	enqueued := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		enqueued <- sink.enqueue(second)
	}()
	<-started
	waitForBlockedBroadcastProducer(t, sink)
	buf := make([]byte, len(first))
	if n, err := io.ReadFull(sink, buf); err != nil || n != len(first) || !bytes.Equal(buf, first) {
		t.Fatalf("read first chunk = (%q, %d, %v), want (%q, %d, nil)", buf, n, err, first, len(first))
	}
	select {
	case err := <-enqueued:
		if err != nil {
			t.Fatalf("enqueue second chunk after handoff: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("byte dequeue did not release the backpressured producer")
	}
}

func TestBroadcastSinkCloseUnblocksBackpressuredFrame(t *testing.T) {
	sink := newBroadcastSinkWithPolicy(nil, true)
	base := time.Now()
	if err := sink.enqueueFrame(VideoAccessUnit{AnnexB: []byte{1}, PTS: base}); err != nil {
		t.Fatalf("enqueue first frame: %v", err)
	}
	enqueued := make(chan error, 1)
	go func() {
		enqueued <- sink.enqueueFrame(VideoAccessUnit{AnnexB: []byte{2}, PTS: base.Add(time.Second / 30)})
	}()
	waitForBlockedBroadcastProducer(t, sink)
	sink.Close()
	select {
	case err := <-enqueued:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("blocked enqueue after Close = %v, want closed pipe", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not release the backpressured producer")
	}
}

func TestBroadcastSinkNonblockingFrameQueueUsesNominalDuration(t *testing.T) {
	sink := newBroadcastSink(nil)
	base := time.Now()
	// A large or backward PTS gap can be caused by the upstream leaky queue; it
	// must not turn one queued picture into an artificial duration overflow.
	for i := 0; i < 60; i++ {
		offset := time.Duration(i%2) * time.Second
		frame := VideoAccessUnit{AnnexB: []byte{byte(i + 1)}, PTS: base.Add(offset)}
		if err := sink.enqueueFrame(frame); err != nil {
			t.Fatalf("enqueue frame %d at %v: %v", i, offset, err)
		}
	}
	overflow := VideoAccessUnit{AnnexB: []byte{0xff}, PTS: base.Add(-time.Second)}
	if err := sink.enqueueFrame(overflow); !errors.Is(err, errBroadcastSinkBacklog) {
		t.Fatalf("enqueue frame after 2s nominal 30fps queue = %v, want backlog error", err)
	}
}

func TestBroadcastSinkNominalDurationUsesConfiguredFrameRate(t *testing.T) {
	for _, test := range []struct {
		fps             int
		acceptedFrames  int
		rejectedOrdinal int
	}{
		{fps: 20, acceptedFrames: 40, rejectedOrdinal: 41},
		{fps: 60, acceptedFrames: 120, rejectedOrdinal: 121},
	} {
		t.Run(fmt.Sprintf("%dfps", test.fps), func(t *testing.T) {
			broadcast := NewBroadcastCaptureWithFrameRate(nil, test.fps)
			sink := broadcast.AddSink()
			defer sink.Close()
			for i := 0; i < test.acceptedFrames; i++ {
				if err := sink.enqueueFrame(VideoAccessUnit{AnnexB: []byte{byte(i + 1)}}); err != nil {
					t.Fatalf("enqueue nominal frame %d: %v", i+1, err)
				}
			}
			if err := sink.enqueueFrame(VideoAccessUnit{AnnexB: []byte{0xff}}); !errors.Is(err, errBroadcastSinkBacklog) {
				t.Fatalf("enqueue nominal frame %d = %v, want backlog error", test.rejectedOrdinal, err)
			}
		})
	}
}

func TestBackpressuredSinkRegistrationIsExclusive(t *testing.T) {
	sharedBroadcast := NewBroadcastCapture(nil)
	shared := sharedBroadcast.AddSink()
	if sink, err := sharedBroadcast.AddBackpressuredSink(); sink != nil || !errors.Is(err, errBroadcastSinkMode) {
		t.Fatalf("backpressured sink after shared sink = (%v, %v), want mode error", sink, err)
	}
	shared.Close()

	exclusiveBroadcast := NewBroadcastCapture(nil)
	exclusive, err := exclusiveBroadcast.AddBackpressuredSink()
	if err != nil {
		t.Fatalf("add first backpressured sink: %v", err)
	}
	defer exclusive.Close()
	if sink, err := exclusiveBroadcast.AddBackpressuredSink(); sink != nil || !errors.Is(err, errBroadcastSinkMode) {
		t.Fatalf("second backpressured sink = (%v, %v), want mode error", sink, err)
	}
	lateShared := exclusiveBroadcast.AddSink()
	defer lateShared.Close()
	if _, err := lateShared.ReadVideoAccessUnit(); !errors.Is(err, io.EOF) {
		t.Fatalf("shared sink after exclusive reservation = %v, want EOF", err)
	}
}

func TestBackpressuredTimestampedBroadcastHandoff(t *testing.T) {
	frames := make(chan VideoAccessUnit)
	capture := &ScreenCapture{
		frames: &channelVideoAccessUnitReader{frames: frames},
		waitCh: make(chan struct{}),
	}
	broadcast := NewBroadcastCaptureWithFrameRate(capture, 30)
	sink, err := broadcast.AddBackpressuredSink()
	if err != nil {
		t.Fatalf("add backpressured sink: %v", err)
	}
	defer sink.Close()
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()

	base := time.Now()
	first := VideoAccessUnit{AnnexB: []byte{1}, PTS: base}
	second := VideoAccessUnit{AnnexB: []byte{2}, PTS: base.Add(time.Second / 30)}
	frames <- first
	waitForBroadcastSinkState(t, sink, func(s *BroadcastSink) bool {
		return len(s.frameQueue) == 1
	}, "first timestamped AU queued")
	frames <- second
	waitForBlockedBroadcastProducer(t, sink)

	got, err := sink.ReadVideoAccessUnit()
	if err != nil || !bytes.Equal(got.AnnexB, first.AnnexB) {
		t.Fatalf("read first timestamped AU = (%x, %v), want (%x, nil)", got.AnnexB, err, first.AnnexB)
	}
	waitForBroadcastSinkState(t, sink, func(s *BroadcastSink) bool {
		return len(s.frameQueue) == 1 && bytes.Equal(s.frameQueue[0].AnnexB, second.AnnexB)
	}, "second timestamped AU handed off")
	close(frames)
	got, err = sink.ReadVideoAccessUnit()
	if err != nil || !bytes.Equal(got.AnnexB, second.AnnexB) {
		t.Fatalf("read second timestamped AU = (%x, %v), want (%x, nil)", got.AnnexB, err, second.AnnexB)
	}
	if _, err := sink.ReadVideoAccessUnit(); !errors.Is(err, io.EOF) {
		t.Fatalf("read after final timestamped AU = %v, want EOF", err)
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("timestamped broadcast run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timestamped broadcast did not finish")
	}
}

func TestBackpressuredByteBroadcastHandoff(t *testing.T) {
	sourceReader, sourceWriter := io.Pipe()
	capture := &ScreenCapture{stdout: sourceReader, waitCh: make(chan struct{})}
	broadcast := NewBroadcastCapture(capture)
	sink, err := broadcast.AddBackpressuredSink()
	if err != nil {
		t.Fatalf("add backpressured sink: %v", err)
	}
	defer sink.Close()
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()

	first := []byte("first")
	second := []byte("second")
	if _, err := sourceWriter.Write(first); err != nil {
		t.Fatalf("write first source chunk: %v", err)
	}
	waitForBroadcastSinkState(t, sink, func(s *BroadcastSink) bool {
		return len(s.queue) == 1
	}, "first byte chunk queued")
	secondWrite := make(chan error, 1)
	go func() {
		_, writeErr := sourceWriter.Write(second)
		secondWrite <- writeErr
	}()
	waitForBlockedBroadcastProducer(t, sink)

	buf := make([]byte, len(second))
	if n, err := io.ReadFull(sink, buf[:len(first)]); err != nil || n != len(first) || !bytes.Equal(buf[:len(first)], first) {
		t.Fatalf("read first byte chunk = (%q, %d, %v), want (%q, %d, nil)", buf[:len(first)], n, err, first, len(first))
	}
	select {
	case err := <-secondWrite:
		if err != nil {
			t.Fatalf("write second source chunk: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("second source write remained blocked after handoff")
	}
	if err := sourceWriter.Close(); err != nil {
		t.Fatalf("close source writer: %v", err)
	}
	if n, err := io.ReadFull(sink, buf); err != nil || n != len(second) || !bytes.Equal(buf, second) {
		t.Fatalf("read second byte chunk = (%q, %d, %v), want (%q, %d, nil)", buf, n, err, second, len(second))
	}
	if n, err := sink.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("read after final byte chunk = (%d, %v), want (0, EOF)", n, err)
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("byte broadcast run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("byte broadcast did not finish")
	}
}

func TestLoneSharedTimestampedSinkDoesNotBackpressureCapture(t *testing.T) {
	base := time.Now()
	frames := make([]VideoAccessUnit, 62)
	for i := range frames {
		frames[i] = VideoAccessUnit{
			AnnexB: []byte{byte(i + 1)},
			PTS:    base.Add(time.Duration(i) * time.Second / 30),
		}
	}
	capture := &ScreenCapture{
		frames: &sliceVideoAccessUnitReader{frames: frames},
		waitCh: make(chan struct{}),
	}
	broadcast := NewBroadcastCapture(capture)
	slow := broadcast.AddSink()
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()

	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("shared broadcast run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		// Avoid leaking the pump if a regression makes a shared sink wait like the
		// direct single-target policy.
		slow.Close()
		<-runDone
		t.Fatal("a lone shared sink backpressured the timestamped source")
	}
	if n, err := slow.ReadVideoAccessUnit(); len(n.AnnexB) != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("overflowed shared sink read = (%x, %v), want empty EOF", n.AnnexB, err)
	}
}

func TestSharedTimestampedSinkToleratesTransientNetworkStall(t *testing.T) {
	sink := newBroadcastSinkWithPolicy(nil, false)
	base := time.Now()
	for i := 0; i < 15; i++ {
		frame := VideoAccessUnit{
			AnnexB: []byte{byte(i + 1)},
			PTS:    base.Add(time.Duration(i) * time.Second / 30),
		}
		if err := sink.enqueueFrame(frame); err != nil {
			t.Fatalf("enqueue frame %d during 500ms network stall: %v", i, err)
		}
	}
}

func TestTimestampedSlowSinkDoesNotStallHealthyPeer(t *testing.T) {
	frames := make(chan VideoAccessUnit)
	capture := &ScreenCapture{
		frames: &channelVideoAccessUnitReader{frames: frames},
		waitCh: make(chan struct{}),
	}
	broadcast := NewBroadcastCapture(capture)
	slow := broadcast.AddSink()
	healthy := broadcast.AddSink()
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()

	healthyFrames := make(chan VideoAccessUnit, 8)
	healthyDone := make(chan error, 1)
	go func() {
		for {
			frame, err := healthy.ReadVideoAccessUnit()
			if len(frame.AnnexB) > 0 {
				healthyFrames <- frame
			}
			if err != nil {
				healthyDone <- err
				return
			}
		}
	}()

	base := time.Now()
	for i := 0; i < 62; i++ {
		want := VideoAccessUnit{
			AnnexB: []byte{byte(i + 1)},
			PTS:    base.Add(time.Duration(i) * time.Second / 30),
		}
		frames <- want
		select {
		case got := <-healthyFrames:
			if !bytes.Equal(got.AnnexB, want.AnnexB) || !got.PTS.Equal(want.PTS) {
				t.Fatalf("healthy frame %d = {%x %v}, want {%x %v}", i, got.AnnexB, got.PTS, want.AnnexB, want.PTS)
			}
		case <-time.After(time.Second):
			t.Fatalf("healthy sink stalled at frame %d", i)
		}
	}
	close(frames)
	select {
	case err := <-healthyDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("healthy sink ended with %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("healthy sink did not finish")
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("broadcast run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("broadcast did not finish")
	}
	if n, err := slow.ReadVideoAccessUnit(); len(n.AnnexB) != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("overflowed slow sink read = (%x, %v), want empty EOF", n.AnnexB, err)
	}
}

func TestBroadcastCaptureCanAttachSinkAfterRunStarts(t *testing.T) {
	sourceReader, sourceWriter := io.Pipe()
	capture := &ScreenCapture{stdout: sourceReader, waitCh: make(chan struct{})}
	broadcast := NewBroadcastCapture(capture)
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()

	// The encoder must keep draining while a receiver is still negotiating
	// SETUP, without an unconsumed sink blocking established targets.
	drained := make(chan error, 1)
	go func() {
		_, err := sourceWriter.Write([]byte("before setup"))
		drained <- err
	}()
	select {
	case err := <-drained:
		if err != nil {
			t.Fatalf("drain before sink: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("broadcast stopped draining while no sink was attached")
	}

	sink := broadcast.AddSink()
	defer sink.Close()
	// A source Read may already be in flight when the sink attaches. Complete
	// that boundary read, then use the following chunk as the deterministic
	// post-attachment marker. The boundary itself may fall on either side.
	boundary := []byte("attachment boundary")
	if _, err := sourceWriter.Write(boundary); err != nil {
		t.Fatalf("write attachment boundary: %v", err)
	}
	want := []byte("after setup")
	readDone := make(chan []byte, 1)
	markerSeen := make(chan struct{})
	go func() {
		var got []byte
		buf := make([]byte, 64)
		seen := false
		for {
			n, err := sink.Read(buf)
			if n > 0 {
				got = append(got, buf[:n]...)
				if !seen && bytes.Contains(got, want) {
					seen = true
					close(markerSeen)
				}
			}
			if err != nil {
				readDone <- got
				return
			}
		}
	}()
	if _, err := sourceWriter.Write(want); err != nil {
		t.Fatalf("write after sink attachment: %v", err)
	}
	select {
	case <-markerSeen:
	case <-time.After(time.Second):
		t.Fatal("late-attached sink did not receive capture data")
	}
	_ = sourceWriter.Close()
	select {
	case err := <-runDone:
		if err != nil && err != io.EOF {
			t.Fatalf("broadcast run: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("broadcast did not stop at source EOF")
	}
	select {
	case got := <-readDone:
		if bytes.Contains(got, []byte("before setup")) {
			t.Fatalf("late-attached sink received stale pre-SETUP capture: %q", got)
		}
		if !bytes.Contains(got, want) {
			t.Fatalf("late-attached sink data = %q, want post-SETUP marker %q", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("late-attached sink did not close at source EOF")
	}
}

type fixedChunkReadCloser struct {
	data      []byte
	chunkSize int
	offset    int
	eof       chan struct{}
	eofSent   bool
}

func (r *fixedChunkReadCloser) Read(p []byte) (int, error) {
	if r.offset == len(r.data) {
		if !r.eofSent {
			r.eofSent = true
			close(r.eof)
		}
		return 0, io.EOF
	}
	n := min(len(p), min(r.chunkSize, len(r.data)-r.offset))
	copy(p, r.data[r.offset:r.offset+n])
	r.offset += n
	return n, nil
}

func (*fixedChunkReadCloser) Close() error { return nil }

func TestBroadcastCaptureBuffersSchedulerBurstAndDrainsBeforeDone(t *testing.T) {
	// Delay the consumer until every source read has completed. This creates a
	// deterministic scheduler burst that fits within the default chunk limit;
	// a healthy receiver must remain attached and receive it in order.
	want := make([]byte, broadcastSinkQueueChunks/2)
	for i := range want {
		want[i] = byte(i)
	}
	source := &fixedChunkReadCloser{
		data:      want,
		chunkSize: 1,
		eof:       make(chan struct{}),
	}
	capture := &ScreenCapture{stdout: source, waitCh: make(chan struct{})}
	broadcast := NewBroadcastCapture(capture)
	sink := broadcast.AddSink()
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()

	select {
	case <-source.eof:
	case <-time.After(time.Second):
		t.Fatal("broadcast did not consume scheduler burst")
	}
	select {
	case <-broadcast.Done():
		t.Fatal("broadcast completed before its sink drained queued data")
	default:
	}

	got, err := io.ReadAll(sink)
	if err != nil {
		t.Fatalf("read queued burst: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("queued burst mismatch: got %d bytes, want %d", len(got), len(want))
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("broadcast run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("broadcast did not finish after sink drained")
	}
	select {
	case <-broadcast.Done():
	default:
		t.Fatal("Done remained open after queued data drained")
	}
}

func TestBroadcastCaptureSlowSinkDoesNotStallHealthySink(t *testing.T) {
	sourceReader, sourceWriter := io.Pipe()
	capture := &ScreenCapture{stdout: sourceReader, waitCh: make(chan struct{})}
	broadcast := NewBroadcastCapture(capture)
	slow := broadcast.AddSink()
	// Keep this test small while exercising the same production overflow path.
	slow.mu.Lock()
	slow.maxQueuedBytes = 128
	slow.maxQueuedChunks = 2
	slow.mu.Unlock()
	healthy := broadcast.AddSink()

	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()
	healthyDone := make(chan struct {
		data []byte
		err  error
	}, 1)
	go func() {
		data, err := io.ReadAll(healthy)
		healthyDone <- struct {
			data []byte
			err  error
		}{data: data, err: err}
	}()

	want := make([]byte, 0, 64*32)
	writeDone := make(chan error, 1)
	go func() {
		for i := 0; i < 32; i++ {
			chunk := bytes.Repeat([]byte{byte(i)}, 64)
			want = append(want, chunk...)
			if _, err := sourceWriter.Write(chunk); err != nil {
				writeDone <- err
				return
			}
		}
		writeDone <- nil
	}()
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("write source: %v", err)
		}
	case <-time.After(time.Second):
		slow.Close()
		_ = sourceWriter.Close()
		t.Fatal("slow sink stalled the source")
	}
	_ = sourceWriter.Close()

	select {
	case result := <-healthyDone:
		if result.err != nil {
			t.Fatalf("healthy sink read: %v", result.err)
		}
		if !bytes.Equal(result.data, want) {
			t.Fatalf("healthy sink got %d bytes, want %d", len(result.data), len(want))
		}
	case <-time.After(time.Second):
		t.Fatal("healthy sink did not finish")
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("broadcast run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("broadcast did not finish")
	}

	buf := make([]byte, 1)
	if n, err := slow.Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("overflowed sink read = (%d, %v), want (0, EOF)", n, err)
	}
}

func TestBroadcastCaptureRemoveOrCloseUnblocksFanout(t *testing.T) {
	for _, tc := range []struct {
		name   string
		remove func(*BroadcastCapture, *BroadcastSink)
	}{
		{name: "RemoveSink", remove: func(b *BroadcastCapture, s *BroadcastSink) { b.RemoveSink(s) }},
		{name: "Close", remove: func(_ *BroadcastCapture, s *BroadcastSink) { s.Close() }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sourceReader, sourceWriter := io.Pipe()
			capture := &ScreenCapture{stdout: sourceReader, waitCh: make(chan struct{})}
			broadcast := NewBroadcastCapture(capture)
			sink := broadcast.AddSink()
			runDone := make(chan error, 1)
			go func() { runDone <- broadcast.Run() }()

			firstDone := make(chan error, 1)
			go func() {
				_, err := sourceWriter.Write([]byte("first"))
				firstDone <- err
			}()
			select {
			case err := <-firstDone:
				if err != nil {
					t.Fatalf("first source write: %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("first source write did not reach fanout")
			}

			secondDone := make(chan error, 1)
			go func() {
				_, err := sourceWriter.Write([]byte("second"))
				secondDone <- err
			}()
			tc.remove(broadcast, sink)
			select {
			case err := <-secondDone:
				if err != nil {
					t.Fatalf("source remained blocked after removal: %v", err)
				}
			case <-time.After(time.Second):
				_ = sourceWriter.Close()
				t.Fatal("removing sink did not promptly unblock fanout")
			}

			_ = sourceWriter.Close()
			select {
			case err := <-runDone:
				if !errors.Is(err, io.EOF) {
					t.Fatalf("broadcast run = %v, want EOF", err)
				}
			case <-time.After(time.Second):
				t.Fatal("broadcast did not finish")
			}
		})
	}
}

func TestBroadcastSinkCloseUnblocksRead(t *testing.T) {
	sink := newBroadcastSink(nil)
	readDone := make(chan error, 1)
	go func() {
		_, err := sink.Read(make([]byte, 1))
		readDone <- err
	}()
	sink.Close()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("read after Close = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not unblock Read")
	}
}

func TestBroadcastSinkCaptureStopReturnsPromptly(t *testing.T) {
	sink := newBroadcastSink(nil)
	capture := sink.AsCapture()
	stopped := make(chan struct{})
	go func() {
		capture.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("stopping a sink capture remained blocked")
	}
}

func TestBroadcastCaptureSourceEOFHasBoundedDrain(t *testing.T) {
	capture := &ScreenCapture{
		stdout: io.NopCloser(bytes.NewReader([]byte("unconsumed"))),
		waitCh: make(chan struct{}),
	}
	broadcast := NewBroadcastCapture(capture)
	broadcast.drainTimeout = 10 * time.Millisecond
	sink := broadcast.AddSink()

	started := time.Now()
	if err := broadcast.Run(); !errors.Is(err, io.EOF) {
		t.Fatalf("broadcast run = %v, want EOF", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("source EOF took %v with an unconsumed sink", elapsed)
	}
	select {
	case <-broadcast.Done():
	default:
		t.Fatal("Done remained open after bounded drain period")
	}
	if n, err := sink.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("timed-out sink read = (%d, %v), want (0, EOF)", n, err)
	}
}

func TestBroadcastCaptureClosesSinkAddedAfterSourceStops(t *testing.T) {
	capture := &ScreenCapture{
		stdout: io.NopCloser(bytes.NewReader(nil)),
		waitCh: make(chan struct{}),
	}
	broadcast := NewBroadcastCapture(capture)
	if err := broadcast.Run(); err != io.EOF {
		t.Fatalf("broadcast run = %v, want EOF", err)
	}

	sink := broadcast.AddSink()
	defer sink.Close()
	readDone := make(chan error, 1)
	go func() {
		_, err := sink.Read(make([]byte, 1))
		readDone <- err
	}()
	select {
	case err := <-readDone:
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("late sink read = %v, want a closed stream", err)
		}
	case <-time.After(time.Second):
		t.Fatal("sink added after capture stop remained open")
	}
}
