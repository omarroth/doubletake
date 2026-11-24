//go:build cgo && fdk_aac

package daemon

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"doubletake/internal/airplay"
)

func TestDaemonReusesCodecBeforeAddingRequiredEncoder(t *testing.T) {
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		if err := exec.Command("gst-inspect-1.0", "x264enc").Run(); err != nil {
			t.Skip("requires headless GStreamer capture")
		}
	}
	encoder := "openh264"
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		encoder = "none"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	d, err := New(Config{CredFile: filepath.Join(t.TempDir(), "creds.json"), FPS: 10, Bitrate: 500, HWAccel: encoder, TestMode: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	// A dual-format receiver starts the group with ELD, matching foreground
	// negotiation. An ELD-only receiver reuses it, and a later ALAC-only
	// receiver needs a second encoder sharing the same source.
	// A fourth, legacy HAP/AES receiver must reuse those sources too.
	var receivers []*airplay.ReceiverServer
	for i, profile := range []airplay.ReceiverProfile{airplay.ReceiverProfileModern, airplay.ReceiverProfileAirServer, airplay.ReceiverProfileUxPlay, airplay.ReceiverProfileAppleTV3} {
		server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{ListenAddress: fmt.Sprintf("127.0.0.%d:0", i+1), Profile: profile, DisplayWidth: 320, DisplayHeight: 180, DecodeMedia: airplay.HasInProcessGStreamer(), Logger: log.New(io.Discard, "", 0)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx) }()
		t.Cleanup(func() { server.Close(); <-done })
		receivers = append(receivers, server)
		addr := server.Addr().(*net.TCPAddr)
		if resp := d.handleConnect(Request{Target: addr.IP.String(), Port: addr.Port}); !resp.OK {
			t.Fatal(resp.Error)
		}
		for {
			status := d.handleStatus()
			if status.Error != "" {
				t.Fatal(status.Error)
			}
			stats := server.Stats()
			if stats.VideoCryptoErrors != 0 {
				t.Fatalf("%s rejected video encryption: %+v", profile, stats)
			}
			if stats.Playback.DecodeErrors > 0 || stats.Playback.TimestampErrors > 0 || stats.Playback.AudioLost > 0 {
				t.Fatalf("%s failed full-loop playback: %+v", profile, stats.Playback)
			}
			videoReady := stats.VideoPackets > 0
			if profile != airplay.ReceiverProfileAirServer {
				videoReady = stats.VideoDecrypted > 0
			}
			if airplay.HasInProcessGStreamer() {
				videoReady = stats.Playback.VideoPlayed > 0 && stats.Playback.AudioPlayedSamples > 1024
			}
			if stats.AudioPackets > 5 && videoReady {
				encoders := 1
				if i >= 2 {
					encoders = 2
				}
				if status.SharedAudio.Sources != 1 || status.SharedAudio.Encoders != encoders || status.SharedAudio.Receivers != i+1 || status.VideoEncoders != 1 {
					t.Fatalf("after receiver %d: %+v", i+1, status)
				}
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal(ctx.Err())
			case <-time.After(5 * time.Millisecond):
			}
		}
	}
	if airplay.HasInProcessGStreamer() {
		// Compare the same decoded picture across the distinct receiver clocks.
		// Different last-frame hashes alone can be a one-frame polling race.
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			first := receivers[0].Stats().Playback
			minimum, maximum := first.LastVideoDeadline, first.LastVideoDeadline
			matched := first.LastVideoHash != 0
			for _, receiver := range receivers[1:] {
				current := receiver.Stats().Playback
				matched = matched && current.LastVideoHash == first.LastVideoHash
				minimum = min(minimum, current.LastVideoDeadline)
				maximum = max(maximum, current.LastVideoDeadline)
			}
			if matched {
				if time.Duration(maximum-minimum) > 50*time.Millisecond {
					t.Fatalf("shared picture presentation differs across receivers by %s", time.Duration(maximum-minimum))
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("receivers did not present a common decoded picture")
	}
}
