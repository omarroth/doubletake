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
		t.Skip("requires headless GStreamer capture")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	d, err := New(Config{CredFile: filepath.Join(t.TempDir(), "creds.json"), FPS: 10, Bitrate: 500, HWAccel: "openh264", TestMode: true})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Shutdown()
	// An ELD-only receiver starts the codec group. A dual-format receiver
	// reuses ELD; a later ALAC-only receiver needs a second encoder, one source.
	for i, profile := range []airplay.ReceiverProfile{airplay.ReceiverProfileAirServer, airplay.ReceiverProfileModern, airplay.ReceiverProfileUxPlay} {
		server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{ListenAddress: fmt.Sprintf("127.0.0.%d:0", i+1), Profile: profile, DisplayWidth: 1920, DisplayHeight: 1080, Logger: log.New(io.Discard, "", 0)})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx) }()
		t.Cleanup(func() { server.Close(); <-done })
		addr := server.Addr().(*net.TCPAddr)
		if resp := d.handleConnect(Request{Target: addr.IP.String(), Port: addr.Port}); !resp.OK {
			t.Fatal(resp.Error)
		}
		for {
			status := d.handleStatus()
			if status.Error != "" {
				t.Fatal(status.Error)
			}
			if server.Stats().AudioPackets > 5 {
				encoders := 1
				if i == 2 {
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
}
