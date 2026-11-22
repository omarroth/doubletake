//go:build cgo && (linux || darwin || windows)

package daemon

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"doubletake/internal/airplay"
)

func TestDaemonPlayMediaSource(t *testing.T) {
	t.Run("video only", func(t *testing.T) { testDaemonPlayMedia(t, false, false) })
	t.Run("with audio tail", func(t *testing.T) { testDaemonPlayMedia(t, true, false) })
	t.Run("HTTP with audio", func(t *testing.T) { testDaemonPlayMedia(t, true, true) })
}

func testDaemonPlayMedia(t *testing.T, withAudio, overHTTP bool) {
	t.Helper()
	for _, element := range []string{"vp8enc", "vp8dec", "matroskamux", "matroskademux", "openh264enc", "rtponviftimestamp"} {
		if err := exec.Command("gst-inspect-1.0", element).Run(); err != nil {
			t.Skipf("requires GStreamer %s", element)
		}
	}
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	clip := filepath.Join(dir, "test.mkv")
	args := []string{"-q", "matroskamux", "name=mux", "!", "filesink", "location=" + filepath.ToSlash(clip),
		"videotestsrc", "num-buffers=20",
		"!", "video/x-raw,width=320,height=180,framerate=10/1", "!", "vp8enc",
		"!", "queue", "!", "mux."}
	if withAudio {
		for _, element := range []string{"vorbisenc", "vorbisdec", "rtpL16pay"} {
			if err := exec.Command("gst-inspect-1.0", element).Run(); err != nil {
				t.Skipf("requires GStreamer %s", element)
			}
		}
		args = append(args, "audiotestsrc", "num-buffers=441", "samplesperbuffer=240", "volume=0.02",
			"timestamp-offset=120000000",
			"!", "audio/x-raw,rate=44100", "!", "audioconvert", "!", "vorbisenc", "!", "queue", "!", "mux.")
	}
	cmd := exec.CommandContext(ctx, "gst-launch-1.0", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("make test clip: %v\n%s", err, output)
	}
	name := `clip ! "quoted".mkv`
	if runtime.GOOS == "windows" {
		name = "clip ! café.mkv"
	}
	file := filepath.Join(dir, name)
	if err := os.Rename(clip, file); err != nil {
		t.Fatal(err)
	}
	source := file
	if overHTTP {
		if err := exec.Command("gst-inspect-1.0", "souphttpsrc").Run(); err != nil {
			t.Skip("requires GStreamer souphttpsrc")
		}
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/clip.mkv" || r.URL.Query().Get("quality") != "test=1" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "video/x-matroska")
			http.ServeFile(w, r, file)
		}))
		defer server.Close()
		source = server.URL + "/clip.mkv?quality=test%3D1"
	}

	decode := airplay.HasInProcessGStreamer() && (exec.Command("gst-inspect-1.0", "avdec_h264").Run() == nil ||
		exec.Command("gst-inspect-1.0", "openh264dec").Run() == nil)
	if withAudio && exec.Command("gst-inspect-1.0", "avdec_alac").Run() != nil && exec.Command("gst-inspect-1.0", "alacdec").Run() != nil {
		decode = false
	}
	firstAudio := make(chan time.Time, 1)
	var firstAudioSeen bool
	receiver, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress: "127.0.0.1:0", Profile: airplay.ReceiverProfileRoku, DecodeMedia: decode,
		AudioProbe: func(_ uint64, deadline, _ time.Time) {
			if !firstAudioSeen {
				firstAudioSeen = true
				firstAudio <- deadline
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	go receiver.Serve(ctx)
	addr := receiver.Addr().(*net.TCPAddr)
	socket := shortTestSocketPath(t)
	d, err := New(Config{
		SocketPath: socket, CredBackend: "file", CredFile: filepath.Join(dir, "credentials.json"),
		FPS: 10, TargetWidth: 320, TargetHeight: 180, Bitrate: 500, HWAccel: "openh264",
	})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		d.Shutdown()
		if err := <-done; err != nil {
			t.Errorf("daemon stopped: %v", err)
		}
	})
	waitForDaemonSocket(t, socket)

	req := Request{Cmd: "play", Target: addr.IP.String(), Port: addr.Port, MediaSource: source}
	if resp := sendDaemonSocketRequest(t, socket, req); !resp.OK {
		t.Fatal(resp.Error)
	}
	waitForDaemonSocketStatus(t, socket, 6*time.Second, func(resp Response) bool {
		return len(resp.Streams) == 1 && resp.Streams[0].State == StateStreaming &&
			resp.Streams[0].MediaSource == source && resp.Streams[0].HasAudio == withAudio
	})
	waitForDaemonSocketStatus(t, socket, 6*time.Second, func(resp Response) bool {
		return len(resp.Streams) == 0 && receiver.Stats().TeardownRequests > 0
	})
	stats := receiver.Stats()
	if stats.VideoPackets < 20 || stats.VideoWidth != 320 || stats.VideoHeight != 180 ||
		(stats.AudioPackets != 0) != withAudio || stats.VideoCryptoErrors != 0 {
		t.Fatalf("unexpected playback packets or canvas: %+v", stats)
	}
	if decode && (stats.Playback.VideoPlayed != 20 || stats.Playback.DecodeErrors != 0 || stats.Playback.TimestampErrors != 0) {
		t.Fatalf("expected all 20 pictures presented: %+v", stats.Playback)
	}
	if decode && withAudio && (stats.Playback.AudioPlayedSamples < 100000 || stats.Playback.AudioPeak == 0 ||
		stats.Playback.AudioCryptoErrors != 0 || stats.Playback.AudioMissingSamples != 0) {
		t.Fatalf("expected decoded audio through the end of the longer track: %+v", stats.Playback)
	}
	if decode && withAudio {
		select {
		case audioStart := <-firstAudio:
			videoStart := time.Unix(0, stats.Playback.LastVideoDeadline).Add(-1900 * time.Millisecond)
			if offset := audioStart.Sub(videoStart); (offset - 120*time.Millisecond).Abs() > 35*time.Millisecond {
				t.Fatalf("audio starts %v after video, want the clip's 120 ms offset", offset)
			}
		default:
			t.Fatal("no audio playout deadline")
		}
	}
	status := sendDaemonSocketRequest(t, socket, Request{Cmd: "status"})
	if status.Error != "" {
		t.Fatal(status.Error)
	}
}
