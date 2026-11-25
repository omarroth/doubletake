//go:build cgo && (linux || darwin || windows) && !no_gstreamer

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
	t.Run("NTP", func(t *testing.T) { testAirPlay2RealtimeAudioHeadless(t, false) })
	t.Run("NTP after PTP bind failure", func(t *testing.T) { testAirPlay2RealtimeAudioHeadless(t, true) })
}

func testAirPlay2RealtimeAudioHeadless(t *testing.T, failPTPBind bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	receiverConfig := ReceiverConfig{
		ListenAddress: "127.0.0.1:0", RealtimeAudio: true, DecodeMedia: true, AudioDropEvery: 13,
	}
	var audioConfig AudioOnlyConfig
	ptpBindAttempts := 0
	if failPTPBind {
		receiverConfig.AcceptNTPFallback = true
		receiverConfig.realtimePTPStart = func(uint64) error { return errors.New("unexpected SETPEERS") }
		audioConfig.ptpPool = &ptpClockPool{bind: func() (*net.UDPConn, *net.UDPConn, error) {
			ptpBindAttempts++
			return nil, nil, errors.New("test PTP port bind failure")
		}}
	}
	receiver, err := NewReceiverServer(receiverConfig)
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
	session, err := OpenAudioOnly(ctx, device, audioConfig, nil, device.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if !session.airPlay2 || session.playback.timingProtocol != timingProtocolNTP {
		t.Fatalf("expected AirPlay 2 with NTP, got AirPlay 2=%t timing=%q", session.airPlay2, session.playback.timingProtocol)
	}
	if failPTPBind && ptpBindAttempts != 1 {
		t.Fatalf("expected one PTP bind attempt, got %d", ptpBindAttempts)
	}
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
				stats.TimingReplies < 3 || stats.Playback.AudioPeak == 0 ||
				stats.Playback.AudioCryptoErrors != 0 || stats.Playback.DecodeErrors != 0 {
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

func TestAirPlay2AudioUsesConfiguredDigestPassword(t *testing.T) {
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		RealtimeAudio: true, Auth: ReceiverAuthDigest, Code: "fixture-password",
	})
	device, ok := client.AudioOnlyEndpoint()
	if !ok || device.Port != server.Addr().(*net.TCPAddr).Port || !device.SupportsAirPlay2Audio() {
		t.Fatal("/info did not identify the audio-only endpoint")
	}
	if _, err := OpenAudioOnly(ctx, device, AudioOnlyConfig{}, nil, device.DeviceID); !errors.Is(err, ErrCredentialsRequired) {
		t.Fatalf("AirPlay 2 without password = %v, want Digest challenge", err)
	}
	session, err := OpenAudioOnly(ctx, device, AudioOnlyConfig{Password: "fixture-password"}, nil, device.DeviceID)
	if err != nil {
		t.Fatalf("AirPlay 2 with configured password: %v", err)
	}
	defer session.Close()
	if !session.airPlay2 || server.Stats().PairVerify != 0 {
		t.Fatal("configured password did not use transient AirPlay 2 audio pairing")
	}
}
