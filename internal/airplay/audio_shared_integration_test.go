package airplay

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestSharedAudioOutputIntegration(t *testing.T) {
	server := os.Getenv("DOUBLETAKE_TEST_PULSE_SERVER")
	if server == "" {
		t.Skip("requires an explicitly supplied private sound server")
	}
	t.Setenv("PULSE_SERVER", server)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	h := &SharedAudioCapture{}
	defer h.Close()
	a, err := h.Acquire(ctx, false, AudioCodecALAC, AudioSourceOutput)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Stop()
	b, err := h.Acquire(ctx, false, AudioCodecALAC, AudioSourceOutput)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Stop()
	if stats := h.Stats(); stats != (SharedAudioStats{Sources: 1, Encoders: 1, Receivers: 2}) {
		t.Fatalf("actual capture sharing=%+v", stats)
	}
	sharedAudioOutput.mu.Lock()
	name := sharedAudioOutput.name
	sharedAudioOutput.mu.Unlock()
	tone := exec.CommandContext(ctx, "gst-launch-1.0", "--quiet", "audiotestsrc", "is-live=true", "volume=0.8", "!", "audioconvert", "!", "audioresample", "!", "pulsesink", "device="+name, "buffer-time=100000", "latency-time=10000")
	if err := tone.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { tone.Process.Kill(); tone.Wait() }()
	left, right := make([]byte, 8192), make([]byte, 8192)
	for i := range 80 {
		n, p, err := a.readFramePosition(left)
		if err != nil {
			t.Fatal(err)
		}
		m, q, err := b.readFramePosition(right)
		if err != nil {
			t.Fatal(err)
		}
		if n != m || !bytes.Equal(left[:n], right[:m]) || p != q || p.PTS.IsZero() {
			t.Fatalf("sound server delivered different content/positions at frame %d", i)
		}
	}
	a.Stop()
	if stats := h.Stats(); stats.Receivers != 1 || stats.Sources != 1 {
		t.Fatalf("first disconnect disturbed shared capture: %+v", stats)
	}
	if _, p, err := b.readFramePosition(right); err != nil || p.PTS.IsZero() {
		t.Fatalf("surviving capture: %v %+v", err, p)
	}
	b.Stop()
	if stats := h.Stats(); stats != (SharedAudioStats{}) {
		t.Fatalf("last disconnect leaked capture: %+v", stats)
	}
}
