package airplay

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

func TestBroadcastSinkDrainedBurstRestoresBudget(t *testing.T) {
	sink := newBroadcastSink(nil)
	defer sink.Close()
	for burst := 0; burst < 3; burst++ {
		for i := 0; i < 7; i++ {
			if err := sink.enqueueFrame(VideoAccessUnit{AnnexB: []byte{byte(i)}}); err != nil {
				t.Fatalf("burst %d frame %d: %v", burst, i, err)
			}
		}
		for i := 0; i < 7; i++ {
			frame, err := sink.ReadVideoAccessUnit()
			if err != nil || !bytes.Equal(frame.AnnexB, []byte{byte(i)}) {
				t.Fatalf("burst %d read %d = (%x, %v)", burst, i, frame.AnnexB, err)
			}
		}
	}
}

func TestTimestampedBroadcastBuffersBurstAndDrains(t *testing.T) {
	// Hold the reader until source EOF, forcing a scheduler burst rather than
	// relying on relative goroutine timing. Six 30fps AUs fit the relay budget.
	frames := make([]VideoAccessUnit, 6)
	for i := range frames {
		frames[i] = VideoAccessUnit{AnnexB: []byte{byte(i + 1)}, PTS: time.Unix(int64(i), 0)}
	}
	broadcast := NewBroadcastCapture(&ScreenCapture{frames: &sliceVideoAccessUnitReader{frames: frames}})
	sink := broadcast.AddSink()
	defer sink.Close()
	runDone := make(chan error, 1)
	go func() { runDone <- broadcast.Run() }()
	waitForBroadcastSinkState(t, sink, func(s *BroadcastSink) bool { return s.inputClosed }, "source EOF")
	select {
	case <-broadcast.Done():
		t.Fatal("broadcast completed before burst drained")
	default:
	}
	for i, want := range frames {
		got, err := sink.ReadVideoAccessUnit()
		if err != nil || !bytes.Equal(got.AnnexB, want.AnnexB) || got.PTS != want.PTS {
			t.Fatalf("burst frame %d = %+v, %v; want %+v", i, got, err, want)
		}
	}
	if _, err := sink.ReadVideoAccessUnit(); !errors.Is(err, io.EOF) {
		t.Fatalf("drained burst = %v, want EOF", err)
	}
	select {
	case err := <-runDone:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("Run = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("broadcast did not finish after drain")
	}
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.queuedBytes != 0 || sink.queuedFrameDuration != 0 || len(sink.frameQueue) != 0 {
		t.Fatal("drain did not release queue accounting")
	}
}
