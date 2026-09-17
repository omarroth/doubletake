package airplay

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestBroadcastTerminalReadsRaceWithCleanup(t *testing.T) {
	for _, overflow := range []bool{false, true} {
		broadcast := NewBroadcastCapture(&ScreenCapture{frames: &sliceVideoAccessUnitReader{}})
		sink := broadcast.AddSink()
		sink.maxQueuedBytes = 1
		capture := sink.AsCapture()
		results := make(chan error, 2)
		go func() { _, err := capture.Read(make([]byte, 1)); results <- err }()
		go func() { _, err := capture.ReadVideoAccessUnit(); results <- err }()
		want := io.EOF
		if overflow {
			want = errBroadcastSinkBacklog
			if err := sink.enqueueFrame(VideoAccessUnit{AnnexB: []byte{1, 2}}); !errors.Is(err, want) {
				t.Fatal(err)
			}
		}
		var cleanup sync.WaitGroup
		for _, closeSink := range []func(){sink.Close, sink.finish, func() { broadcast.RemoveSink(sink) }} {
			cleanup.Add(1)
			go func() { defer cleanup.Done(); closeSink() }()
		}
		cleanup.Wait()
		for i := 0; i < 2; i++ {
			select {
			case err := <-results:
				if !errors.Is(err, want) {
					t.Fatalf("overflow=%v read error = %v, want %v", overflow, err, want)
				}
			case <-time.After(time.Second):
				t.Fatal("terminal state did not unblock reader")
			}
		}
	}
}

func TestBroadcastBacklogSurvivesCaptureAndStreamFrames(t *testing.T) {
	for _, timestamped := range []bool{false, true} {
		name := "bytes"
		if timestamped {
			name = "access-units"
		}
		t.Run(name, func(t *testing.T) {
			source := &ScreenCapture{stdout: io.NopCloser(bytes.NewReader([]byte{1, 2}))}
			if timestamped {
				source.frames = &sliceVideoAccessUnitReader{frames: []VideoAccessUnit{{AnnexB: []byte{1, 2}}}}
			}
			broadcast := NewBroadcastCapture(source)
			sink := broadcast.AddSink()
			sink.maxQueuedBytes = 1
			capture := sink.AsCapture()
			if err := broadcast.Run(); !errors.Is(err, io.EOF) {
				t.Fatalf("Run = %v, want source EOF", err)
			}
			// Cleanup must not replace the original failure with EOF.
			sink.Close()
			capture.Stop()
			if n, err := capture.Read(make([]byte, 1)); n != 0 || !errors.Is(err, errBroadcastSinkBacklog) {
				t.Fatalf("capture Read = (%d, %v), want backlog", n, err)
			}
			if timestamped {
				if frame, err := capture.ReadVideoAccessUnit(); len(frame.AnnexB) != 0 || !errors.Is(err, errBroadcastSinkBacklog) {
					t.Fatalf("capture AU = (%+v, %v), want backlog", frame, err)
				}
			}
			codecs := []VideoCodec{VideoCodecH264}
			if timestamped { // HEVC does not support the legacy byte capture path.
				codecs = append(codecs, VideoCodecHEVC)
			}
			for _, codec := range codecs {
				session := &MirrorSession{videoCodec: codec}
				err := session.StreamFrames(context.Background(), capture, 0)
				if !errors.Is(err, errBroadcastSinkBacklog) || strings.Contains(err.Error(), "process exited") {
					t.Fatalf("%s StreamFrames = %v, want backlog (not capture exit)", codec, err)
				}
			}
		})
	}
}

func TestBroadcastOverflowIsTerminalBeforeRemoval(t *testing.T) {
	for _, mode := range []string{"bytes", "chunks", "frame-bytes", "frame-chunks", "duration"} {
		t.Run(mode, func(t *testing.T) {
			sink := newBroadcastSink(nil)
			defer sink.Close()
			switch mode {
			case "bytes", "frame-bytes":
				sink.maxQueuedBytes = 1
			case "chunks", "frame-chunks":
				sink.maxQueuedChunks = 1
			case "duration":
				sink.maxFrameQueueDuration = sink.frameDuration
			}
			enqueue := func() error { return sink.enqueue([]byte{1}) }
			if strings.HasPrefix(mode, "frame-") || mode == "duration" {
				enqueue = func() error { return sink.enqueueFrame(VideoAccessUnit{AnnexB: []byte{1}}) }
			}
			if err := enqueue(); err != nil {
				t.Fatal(err)
			}
			if err := enqueue(); !errors.Is(err, errBroadcastSinkBacklog) {
				t.Fatalf("overflow = %v, want backlog", err)
			}
			// Overflow must publish the failure atomically, not wait for Run to
			// remove the sink (which can race with Close, finish or a reader).
			select {
			case <-sink.done:
			default:
				t.Fatal("overflow did not terminate the sink before removal")
			}
			if n, err := sink.Read(make([]byte, 1)); n != 0 || !errors.Is(err, errBroadcastSinkBacklog) {
				t.Fatalf("Read before removal = (%d, %v), want backlog", n, err)
			}
			sink.finish()
			sink.Close()
			if n, err := sink.Read(make([]byte, 1)); n != 0 || !errors.Is(err, errBroadcastSinkBacklog) {
				t.Fatalf("Read = (%d, %v), want backlog", n, err)
			}
			if frame, err := sink.ReadVideoAccessUnit(); len(frame.AnnexB) != 0 || !errors.Is(err, errBroadcastSinkBacklog) {
				t.Fatalf("AU = (%+v, %v), want backlog", frame, err)
			}
			if err := enqueue(); !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("enqueue after terminal overflow = %v, want closed pipe", err)
			}
		})
	}
}
