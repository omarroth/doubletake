//go:build no_gstreamer

package airplay

import (
	"context"
	"encoding/binary"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestNativeLinuxPulseMonitor(t *testing.T) {
	server := os.Getenv("DOUBLETAKE_TEST_PULSE_SERVER")
	if server == "" {
		t.Skip("requires a private PulseAudio or pipewire-pulse test server")
	}
	t.Setenv("PULSE_SERVER", server)
	t.Setenv("PULSE_SINK", "doubletake_native_fixture")
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	module, err := runPulseCommand(ctx, "load-module", "module-null-sink", "sink_name=doubletake_native_fixture", "channels=2", "rate=44100")
	if err != nil {
		t.Fatal(err)
	}
	defer runPulseCommand(context.Background(), "unload-module", strings.TrimSpace(string(module)))

	capture, err := StartAudioCaptureWithSource(ctx, false, AudioCodecALAC, AudioSourceMonitor)
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()

	player := exec.CommandContext(ctx, "gst-launch-1.0", "-q", "audiotestsrc", "is-live=true", "volume=0.05", "!",
		"audioconvert", "!", "pulsesink", "device=doubletake_native_fixture")
	if err := player.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = player.Process.Kill()
		_ = player.Wait()
	}()

	previous := time.Time{}
	pcm := make([]byte, 352*audioBytesPerSampleFrame)
	heardTone := false
	for !heardTone {
		position, err := capture.readPCMFramePosition(pcm)
		if err != nil {
			t.Fatal(err)
		}
		if !position.PTS.After(previous) {
			t.Fatalf("capture timestamps reversed: %v then %v", previous, position.PTS)
		}
		previous = position.PTS
		for offset := 0; offset < len(pcm); offset += audioBytesPerSample {
			if int16(binary.LittleEndian.Uint16(pcm[offset:])) > 500 {
				heardTone = true
				break
			}
		}
	}

	receiver, err := NewReceiverServer(ReceiverConfig{ListenAddress: "127.0.0.1:0", Profile: ReceiverProfileRAOP})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	go receiver.Serve(ctx)
	session, err := OpenRAOP(ctx, receiver.RAOPDevice(), AudioOnlyConfig{PlayoutLatency: 250 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	playback, stop := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- session.Stream(playback, capture) }()
	defer func() {
		stop()
		capture.Stop()
		<-done
	}()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for receiver.Stats().AudioPackets < 20 {
		select {
		case <-tick.C:
		case <-ctx.Done():
			t.Fatalf("received %d RAOP packets, want at least 20", receiver.Stats().AudioPackets)
		}
	}
}
