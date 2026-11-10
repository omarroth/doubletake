package airplay

import (
	"context"
	"encoding/binary"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Run only against an explicitly supplied private server: ordinary go test must
// never create outputs on, record from, or change the user's sound server.
func TestDedicatedAudioOutputIntegration(t *testing.T) {
	server := os.Getenv("DOUBLETAKE_TEST_PULSE_SERVER")
	if server == "" {
		t.Skip("requires DOUBLETAKE_TEST_PULSE_SERVER pointing to a private test server")
	}
	t.Setenv("PULSE_SERVER", server)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	run := func(args ...string) string {
		t.Helper()
		out, err := runPulseCommand(ctx, args...)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}
	localModule := run("load-module", "module-null-sink", "sink_name=local_test_output")
	defer runPulseCommand(context.Background(), "unload-module", localModule)
	run("set-default-sink", "local_test_output")
	firstCtx, cancelFirst := context.WithCancel(ctx)
	first, err := StartAudioCapture(firstCtx, false, AudioCodecALAC)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Stop()
	second, err := StartAudioCapture(ctx, false, AudioCodecALAC)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Stop()
	name := sharedAudioOutput.name
	if got := run("get-default-sink"); got != "local_test_output" {
		t.Fatalf("creation changed default output to %s", got)
	}
	if !strings.Contains(run("list", "short", "sinks"), name) {
		t.Fatal("dedicated output missing")
	}
	// Play exclusively to doubletake. Nothing is routed to a physical output.
	tone := exec.CommandContext(ctx, "gst-launch-1.0", "--quiet", "audiotestsrc", "is-live=true", "wave=sine", "volume=0.8",
		"!", "audioconvert", "!", "audioresample", "!", "pulsesink", "device="+name, "buffer-time=100000", "latency-time=10000")
	if err := tone.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { tone.Process.Kill(); tone.Wait() }()
	levels := make(chan float64, 512)
	readErrors := make(chan error, 1)
	go func() {
		pcm := make([]byte, 352*4)
		for {
			pts, err := first.pcmFrames.ReadPCMFrame(pcm)
			if err != nil {
				readErrors <- err
				return
			}
			if pts.IsZero() {
				readErrors <- context.DeadlineExceeded
				return
			}
			squared := float64(0)
			for i := 0; i < len(pcm); i += 2 {
				sample := float64(int16(binary.LittleEndian.Uint16(pcm[i:])))
				squared += sample * sample
			}
			select {
			case levels <- math.Sqrt(squared / float64(len(pcm)/2)):
			case <-ctx.Done():
				return
			}
		}
	}()
	measure := func() float64 {
		t.Helper()
		// Drain continuously while the sound-server ring and source queue settle.
		settle := time.NewTimer(600 * time.Millisecond)
		defer settle.Stop()
		for {
			select {
			case <-levels:
			case err := <-readErrors:
				t.Fatalf("capture: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-settle.C:
				goto settled
			}
		}
	settled:
		sum := float64(0)
		for range 20 {
			select {
			case level := <-levels:
				sum += level
			case err := <-readErrors:
				t.Fatalf("capture: %v", err)
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			}
		}
		return sum / 20
	}
	// PulseAudio can initially return silence while the playback stream primes.
	// Wait for two stable tone windows before comparing gain changes.
	full := measure()
	for range 5 {
		next := measure()
		stable := next > 1000 && math.Abs(next-full) < next*0.02
		full = next
		if stable {
			break
		}
	}
	if full < 1000 {
		t.Fatalf("routed tone is silent: RMS %.1f", full)
	}
	run("set-sink-volume", name, "50%")
	half := measure()
	t.Logf("full / 50%% PCM RMS: %.1f / %.1f", full, half)
	if ratio := half / full; ratio < 0.08 || ratio > 0.18 {
		t.Fatalf("50%% volume RMS ratio %.3f, expected Pulse's cubic gain near 0.125", ratio)
	}
	run("set-sink-mute", name, "1")
	muted := measure()
	if muted > 1 {
		t.Fatalf("muted output is audible: RMS %.1f", muted)
	}
	run("set-sink-mute", name, "0")
	run("set-sink-volume", name, "100%")
	unmuted := measure()
	if unmuted < full*0.9 {
		t.Fatalf("unmuting did not restore sound: %.1f vs %.1f", unmuted, full)
	}
	t.Logf("PCM RMS: full=%.1f 50%%=%.1f muted=%.1f restored=%.1f", full, half, muted, unmuted)
	// A stable sink identity lets module-device-restore retain the user's level
	// after doubletake removes and recreates the output.
	run("set-sink-volume", name, "37%")
	cancelFirst()
	first.Stop()
	if !strings.Contains(run("list", "short", "sinks"), name) {
		t.Fatal("stopping one capture removed shared output")
	}
	second.Stop()
	if strings.Contains(run("list", "short", "sinks"), name) {
		t.Fatal("last capture leaked its output")
	}
	if got := run("get-default-sink"); got != "local_test_output" {
		t.Fatalf("cleanup changed default output: %s", got)
	}
	if !aacELDEncoderAvailable {
		// Encoder construction happens after source selection. A build missing
		// the optional codec must roll back the output it just acquired.
		if failed, err := StartAudioCapture(ctx, false, AudioCodecAACELD); err == nil {
			failed.Stop()
			t.Fatal("unavailable AAC-ELD encoder unexpectedly started")
		}
		if strings.Contains(run("list", "short", "sinks"), stableAudioOutputName) {
			t.Fatal("encoder startup failure leaked its output")
		}
	}
	// Cleanup must also happen on context cancellation without an explicit Stop.
	restartCtx, stopRestart := context.WithCancel(ctx)
	restart, err := StartAudioCapture(restartCtx, false, AudioCodecALAC)
	if err != nil {
		t.Fatal(err)
	}
	defer restart.Stop()
	if restored := run("get-sink-volume", sharedAudioOutput.name); !strings.Contains(restored, "37%") {
		t.Fatalf("recreated output did not restore its volume: %s", restored)
	}
	run("set-sink-volume", sharedAudioOutput.name, "100%")
	stopRestart()
	select {
	case <-restart.waitCh:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if strings.Contains(run("list", "short", "sinks"), stableAudioOutputName) {
		t.Fatal("canceled capture leaked its output")
	}
}

func TestDedicatedAudioOutputContinuityIntegration(t *testing.T) {
	server := os.Getenv("DOUBLETAKE_TEST_PULSE_SERVER")
	if server == "" {
		t.Skip("requires DOUBLETAKE_TEST_PULSE_SERVER pointing to a private test server")
	}
	t.Setenv("PULSE_SERVER", server)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	capture, err := StartAudioCapture(ctx, false, AudioCodecALAC)
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()

	tone := exec.CommandContext(ctx, "gst-launch-1.0", "--quiet",
		"audiotestsrc", "is-live=true", "wave=sine", "volume=0.1", "samplesperbuffer=352",
		"!", "audioconvert", "!", "audioresample",
		"!", "pulsesink", "device="+sharedAudioOutput.name, "buffer-time=100000", "latency-time=10000")
	if err := tone.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { tone.Process.Kill(); tone.Wait() }()

	reader, ok := capture.pcmFrames.(*rtpL16PCMFrameReader)
	if !ok {
		t.Fatalf("capture reader = %T, want timestamped RTP/L16", capture.pcmFrames)
	}
	pcm := make([]byte, 352*audioBytesPerSampleFrame)
	var previous audioPCMFramePosition
	previousRead := time.Time{}
	minReadGap, maxReadGap := time.Duration(1<<63-1), time.Duration(0)
	minPTSDelta, maxPTSDelta := time.Duration(1<<63-1), time.Duration(0)
	minSourceAge, maxSourceAge := time.Duration(1<<63-1), time.Duration(0)
	burstReads := 0
	for frame := range 750 {
		position, err := capture.readPCMFramePosition(pcm)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		sourceAge := now.Sub(position.PTS)
		if sourceAge < minSourceAge {
			minSourceAge = sourceAge
		}
		maxSourceAge = max(maxSourceAge, sourceAge)
		if frame > 0 {
			if delta := position.SourceRTP - previous.SourceRTP; delta != 352 {
				t.Fatalf("frame %d source RTP advanced by %d samples", frame, delta)
			}
			gap := now.Sub(previousRead)
			if gap < minReadGap {
				minReadGap = gap
			}
			maxReadGap = max(maxReadGap, gap)
			ptsDelta := position.PTS.Sub(previous.PTS)
			if ptsDelta < minPTSDelta {
				minPTSDelta = ptsDelta
			}
			maxPTSDelta = max(maxPTSDelta, ptsDelta)
			if gap < time.Millisecond {
				burstReads++
			}
		}
		previous, previousRead = position, now
	}
	if reader.discontinuities != 0 {
		t.Fatalf("capture reported %d discontinuities", reader.discontinuities)
	}
	t.Logf("750 frames: source age %v..%v, read gaps %v..%v, PTS deltas %v..%v, sub-millisecond batch reads %d",
		minSourceAge, maxSourceAge, minReadGap, maxReadGap, minPTSDelta, maxPTSDelta, burstReads)
}
