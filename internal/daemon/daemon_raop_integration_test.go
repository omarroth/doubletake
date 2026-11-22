//go:build cgo && gstreamer_cgo

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

func TestDaemonRAOPSharedAudioPlayout(t *testing.T) {
	testSharedAudioPlayout(t, false, false)
}

func TestDaemonRAOPAndMirrorSharedAudioPlayout(t *testing.T) {
	if err := exec.Command("gst-inspect-1.0", "openh264enc").Run(); err != nil {
		t.Skip("requires the OpenH264 encoder")
	}
	airplay.SetTargetLatency(airplay.DefaultRAOPPlayoutLatency)
	t.Cleanup(func() { airplay.SetTargetLatency(0) })
	testSharedAudioPlayout(t, true, false)
}

func TestDaemonNoVideoStreamsAudioToDisplayRAOPEndpoint(t *testing.T) {
	testSharedAudioPlayout(t, false, true)
}

func testSharedAudioPlayout(t *testing.T, mirror, noVideo bool) {
	t.Helper()
	if err := exec.Command("gst-inspect-1.0", "rtponviftimestamp").Run(); err != nil {
		t.Skip("requires GStreamer ONVIF audio timestamps")
	}
	if err := exec.Command("gst-inspect-1.0", "alacdec").Run(); err != nil {
		if err := exec.Command("gst-inspect-1.0", "avdec_alac").Run(); err != nil {
			t.Skip("requires a GStreamer ALAC decoder")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	type playout struct {
		hash                uint64
		deadline, presented time.Time
	}
	events := [2]chan playout{make(chan playout, 2048), make(chan playout, 2048)}
	var receivers [2]*airplay.ReceiverServer
	devices := make([]airplay.AirPlayDevice, len(receivers))
	for i := range receivers {
		index := i
		cfg := airplay.ReceiverConfig{
			ListenAddress: fmt.Sprintf("127.0.0.%d:0", i+1),
			Profile:       airplay.ReceiverProfileRAOP, DecodeMedia: true,
			Logger: log.New(io.Discard, "", 0), AudioDropEvery: 13,
			AudioProbe: func(hash uint64, deadline, presented time.Time) {
				select {
				case events[index] <- playout{hash: hash, deadline: deadline, presented: presented}:
				default:
				}
			},
		}
		if i == 1 {
			if mirror {
				cfg.Profile = airplay.ReceiverProfileUxPlay
				cfg.DeviceID = "02:00:00:00:00:02"
				cfg.DisplayWidth, cfg.DisplayHeight = 320, 180
			} else {
				cfg.Auth, cfg.Code = airplay.ReceiverAuthDigest, "fixture-password"
				cfg.RAOPAuthSetup = true
			}
		}
		server, err := airplay.NewReceiverServer(cfg)
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		go server.Serve(ctx)
		receivers[i] = server
		if i == 1 && mirror {
			addr := server.Addr().(*net.TCPAddr)
			devices[i] = airplay.AirPlayDevice{IP: addr.IP.String(), Port: addr.Port, DeviceID: cfg.DeviceID}
		} else {
			devices[i] = server.RAOPDevice()
		}
		if i == 1 && !mirror {
			// A dual-advertised speaker uses the RAOP service port.
			devices[i].RAOPOnly = false
			devices[i].Port = 7000
			devices[i].Features = airplay.FeatureTransientPairing
			if noVideo {
				devices[i].Features |= airplay.FeatureScreen
			}
		}
	}
	// Deliberately do not run background mDNS or start a desktop session.
	d, err := New(Config{
		CredFile: filepath.Join(t.TempDir(), "credentials.json"), TestMode: true, NoVideo: noVideo, FPS: 10, Bitrate: 500, HWAccel: "openh264",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	d.devices = devices

	wait := func(label string, condition func() bool) {
		t.Helper()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for !condition() {
			select {
			case <-ctx.Done():
				t.Fatalf("%s: %v, daemon=%+v, room1=%+v, room2=%+v",
					label, ctx.Err(), d.handleStatus(), receivers[0].Stats(), receivers[1].Stats())
			case <-ticker.C:
			}
		}
	}

	connect := func(index int, code string) {
		t.Helper()
		device := devices[index]
		reply := d.handleConnect(Request{Target: device.IP, DeviceID: device.DeviceID, Pin: code})
		if !reply.OK {
			t.Fatalf("connect receiver %d: %+v", index, reply)
		}
	}
	connect(0, "")
	wait("first receiver started", func() bool { return receivers[0].Stats().AudioPackets > 10 })
	if mirror {
		connect(1, "")
	} else {
		connect(1, "")
		wait("second receiver requests Digest password", func() bool {
			status := d.handleStatus()
			return status.NeedsCredential && status.CredentialKind == CredentialKindPassword
		})
		connect(1, "fixture-password")
	}

	wait("both receivers played with successful retransmits", func() bool {
		for _, server := range receivers {
			a := server.Stats().Playback
			if a.AudioPlayedSamples < 50*352 || a.AudioRecovered == 0 {
				return false
			}
		}
		return true
	})

	status := d.handleStatus()
	wantVideoEncoders := 0
	if mirror {
		wantVideoEncoders = 1
	}
	if status.SharedAudio.Sources != 1 || status.SharedAudio.Encoders != 1 || status.VideoEncoders != wantVideoEncoders || len(status.Streams) != 2 {
		t.Fatalf("capture/encoder sharing: %+v", status)
	}
	for i, entry := range status.Streams {
		audioOnly := i == 0 || !mirror
		if entry.AudioOnly != audioOnly || !entry.HasAudio || audioOnly && entry.AudioLeadMS != 2000 || entry.State != StateStreaming {
			t.Fatalf("unexpected stream status: %+v", entry)
		}
	}
	for i, server := range receivers {
		stats := server.Stats()
		playback := stats.Playback
		if (i == 0 || !mirror) && (stats.TimingReplies != 3 || stats.VideoPackets != 0) ||
			i == 1 && mirror && playback.VideoPlayed == 0 ||
			playback.AudioPeak == 0 || playback.AudioMissingSamples != 0 || playback.AudioLost != 0 ||
			playback.DecodeErrors != 0 || playback.TimestampErrors != 0 || playback.QueueOverruns != 0 {
			t.Fatalf("invalid headless audio playback: %+v", stats)
		}
	}

	firstRoom := make(map[uint64]playout)
	for range len(events[0]) {
		event := <-events[0]
		firstRoom[event.hash] = event
	}
	overlap := 0
	var maxDeadlineSkew, maxPlayoutSkew time.Duration
	for range len(events[1]) {
		event := <-events[1]
		if first, ok := firstRoom[event.hash]; ok {
			overlap++
			maxDeadlineSkew = max(maxDeadlineSkew, event.deadline.Sub(first.deadline).Abs())
			maxPlayoutSkew = max(maxPlayoutSkew, event.presented.Sub(first.presented).Abs())
		}
	}
	t.Logf("compared %d identical PCM frames: max deadline skew %v, max simulated playout skew %v",
		overlap, maxDeadlineSkew, maxPlayoutSkew)
	if overlap < 20 || maxDeadlineSkew > 2*time.Millisecond || maxPlayoutSkew > 35*time.Millisecond {
		t.Fatalf("expected at least 20 common frames aligned across both rooms")
	}
	if !mirror {
		firstBefore := receivers[0].Stats().ParameterRequests
		secondBefore := receivers[1].Stats().ParameterRequests
		if firstBefore != 2 || secondBefore != 2 {
			t.Fatal("both speakers must initialize playback with their current volume")
		}
		if response := d.handleSetMute(Request{Target: devices[1].IP}, true); !response.OK {
			t.Fatalf("mute: %+v", response)
		}
		if response := d.handleSetMute(Request{Target: devices[1].IP}, false); !response.OK {
			t.Fatalf("unmute: %+v", response)
		}
		if receivers[0].Stats().ParameterRequests != firstBefore || receivers[1].Stats().ParameterRequests != secondBefore+3 {
			t.Fatal("targeted mute must read, mute and restore only the second room")
		}
	}

	req := Request{Cmd: "volume", Target: devices[1].IP}
	checkVolume := func(want float64) {
		t.Helper()
		resp := d.handleRequest(Request{Cmd: "volume", Target: req.Target})
		if !resp.OK || resp.VolumeDB == nil || *resp.VolumeDB != want {
			t.Fatalf("receiver volume: got %+v, want %v dB", resp, want)
		}
	}
	firstBefore := receivers[0].Stats().ParameterRequests
	level := -12.5
	req.VolumeDB = &level
	if reply := d.handleRequest(req); !reply.OK {
		t.Fatal(reply.Error)
	}
	checkVolume(level)
	if reply := d.handleSetMute(req, true); !reply.OK {
		t.Fatal(reply.Error)
	}
	level = -18
	if reply := d.handleRequest(req); !reply.OK {
		t.Fatal(reply.Error)
	}
	checkVolume(-144)
	if reply := d.handleSetMute(req, false); !reply.OK {
		t.Fatal(reply.Error)
	}
	checkVolume(level)
	if got := receivers[0].Stats().ParameterRequests; got != firstBefore {
		t.Fatal("volume controls reached the other room")
	}

	if response := d.handleDisconnect(Request{Target: devices[0].IP}); !response.OK {
		t.Fatalf("disconnect first room: %+v", response)
	}
	played := receivers[1].Stats().Playback.AudioPlayedSamples
	wait("remaining room keeps playing on the same source", func() bool {
		return receivers[1].Stats().Playback.AudioPlayedSamples > played && d.handleStatus().SharedAudio.Sources == 1
	})
	if response := d.handleDisconnect(Request{}); !response.OK {
		t.Fatalf("disconnect all: %+v", response)
	}
	wait("released audio capture and both sessions", func() bool {
		status := d.handleStatus()
		return status.SharedAudio.Sources == 0 && len(status.Streams) == 0 &&
			receivers[0].Stats().TeardownRequests == 1 && receivers[1].Stats().TeardownRequests == 1
	})
}
