//go:build cgo && (linux || darwin || windows)

package airplay

import (
	"context"
	"errors"
	"net"
	"os/exec"
	"testing"
	"time"
)

func TestAirPlay2RealtimeAudioHeadless(t *testing.T) {
	if exec.Command("gst-inspect-1.0", "rtponviftimestamp").Run() != nil {
		t.Skip("requires GStreamer ONVIF timestamps")
	}
	if exec.Command("gst-inspect-1.0", "avdec_alac").Run() != nil && exec.Command("gst-inspect-1.0", "alacdec").Run() != nil {
		t.Skip("requires GStreamer ALAC decoding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	receiver, err := NewReceiverServer(ReceiverConfig{
		ListenAddress: "127.0.0.1:0", RealtimeAudio: true, DecodeMedia: true, AudioDropEvery: 13,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	go receiver.Serve(ctx)
	address := receiver.Addr().(*net.TCPAddr)
	device := AirPlayDevice{
		IP: address.IP.String(), Port: address.Port,
		DeviceID: receiver.cfg.DeviceID, Features: receiver.profile.features,
	}
	if !device.UsesAudioOnly() {
		t.Fatal("realtime media endpoint must be selected as audio-only")
	}
	session, err := OpenAudioOnly(ctx, device, AudioOnlyConfig{}, nil, device.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if err := session.matchOutputVolume(-10); err != nil {
		t.Fatal(err)
	}
	var source SharedAudioCapture
	audioCtx, stopAudio := context.WithCancel(ctx)
	defer stopAudio()
	capture, err := source.Acquire(audioCtx, true, AudioCodecALAC, AudioSourceMonitor)
	if err != nil {
		t.Fatal(err)
	}
	defer capture.Stop()
	done := make(chan error, 1)
	go func() { done <- session.Stream(audioCtx, capture) }()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		stats := receiver.Stats()
		if stats.Playback.AudioPlayedSamples >= 12*352 && stats.Playback.AudioRecovered > 0 && stats.FeedbackRequests > 0 {
			if stats.PairSetup != 2 || stats.PairVerify != 0 || stats.SetupRequests != 2 ||
				stats.EventConnections != 1 || stats.VideoConnections != 0 || stats.ParameterRequests != 1 ||
				stats.Playback.AudioPeak == 0 || stats.Playback.AudioCryptoErrors != 0 || stats.Playback.DecodeErrors != 0 {
				t.Fatalf("invalid realtime audio playback: %+v", stats)
			}
			stopAudio()
			if err := <-done; !errors.Is(err, context.Canceled) {
				t.Fatalf("stream ended with %v", err)
			}
			return
		}
		select {
		case err := <-done:
			t.Fatalf("stream exited before playback: %v", err)
		case <-ctx.Done():
			t.Fatalf("no realtime playback: %+v", stats)
		case <-ticker.C:
		}
	}
}
