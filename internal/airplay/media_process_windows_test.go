package airplay

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsMediaAudioPipe(t *testing.T) {
	for _, element := range []string{"vp8enc", "vp8dec", "matroskamux", "matroskademux", "playbin", "fdsink", "filesink"} {
		if !hasGstElement(element) {
			t.Skipf("requires GStreamer %s", element)
		}
	}
	for _, audio := range []bool{true, false} {
		name := "with audio"
		if !audio {
			name = "video only"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			file := filepath.Join(t.TempDir(), "clip ! café.mkv")
			fixture := filepath.Join(filepath.Dir(file), "fixture.mkv")
			args := []string{"-q", "matroskamux", "name=mux", "!", "filesink", "location=" + filepath.ToSlash(fixture),
				"videotestsrc", "num-buffers=5", "!", "video/x-raw,width=160,height=90", "!", "vp8enc", "!", "queue", "!", "mux."}
			if audio {
				args = append(args, "audiotestsrc", "num-buffers=10", "!", "audio/x-raw,format=S16LE", "!", "queue", "!", "mux.")
			}
			if output, err := exec.CommandContext(ctx, "gst-launch-1.0", args...).CombinedOutput(); err != nil {
				t.Fatalf("make test clip: %v\n%s", err, output)
			}
			if err := os.Rename(fixture, file); err != nil {
				t.Fatal(err)
			}
			uri := mediaSourceURI(file)
			if resolved, err := ResolveMediaSource(uri); err != nil || resolved != file {
				t.Fatalf("resolve %q: got %q, %v", uri, resolved, err)
			}
			sink := []string{"queue", "!", "fdsink", "fd=1", "sync=false", "async=false"}
			pipeline, pcm, err := launchMediaGraphProcess(ctx, uri, sink, append([]string(nil), sink...))
			if err != nil {
				t.Fatal(err)
			}
			defer pcm.Close()
			defer pipeline.stdout.Close()
			pcmDone := make(chan error, 1)
			go func() {
				count, err := io.Copy(io.Discard, pcm)
				if err == nil && (count > 0) != audio {
					pcmDone <- fmt.Errorf("audio bytes: %d, expected audio: %t", count, audio)
					return
				}
				pcmDone <- err
			}()
			video, videoErr := io.Copy(io.Discard, pipeline.stdout)
			if err := <-pipeline.waitResult; err != nil {
				t.Fatalf("GStreamer after %d video bytes: %v: %s", video, err, pipeline.stderr.String())
			}
			if videoErr != nil || video == 0 {
				t.Fatalf("video bytes: %d, %v", video, videoErr)
			}
			if err := <-pcmDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
