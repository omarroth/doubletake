package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"doubletake/internal/airplay"
)

func TestRunRejectsSecondDaemonWithoutRemovingLiveSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "doubletake.sock")
	lockFile, err := acquireInstanceLock(socketPath)
	if err != nil {
		t.Fatalf("acquire first daemon lock: %v", err)
	}

	// The first daemon's live socket is represented by a marker here. Run must
	// reject the second instance before it removes anything at the socket path.
	const marker = "owned by first daemon"
	if err := os.WriteFile(socketPath, []byte(marker), 0600); err != nil {
		releaseInstanceLock(lockFile)
		t.Fatalf("create socket marker: %v", err)
	}

	d := &Daemon{cfg: Config{SocketPath: socketPath}}
	err = d.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already running") {
		releaseInstanceLock(lockFile)
		t.Fatalf("second Daemon.Run error = %v, want already-running error", err)
	}
	contents, readErr := os.ReadFile(socketPath)
	if readErr != nil {
		releaseInstanceLock(lockFile)
		t.Fatalf("first daemon socket marker was removed: %v", readErr)
	}
	if string(contents) != marker {
		releaseInstanceLock(lockFile)
		t.Fatalf("socket marker = %q, want %q", contents, marker)
	}

	releaseInstanceLock(lockFile)
	reacquired, err := acquireInstanceLock(socketPath)
	if err != nil {
		t.Fatalf("lock was not released with first daemon: %v", err)
	}
	releaseInstanceLock(reacquired)
}

func TestRunRejectsLiveDaemonThatPredatesInstanceLock(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "doubletake.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen as old daemon: %v", err)
	}
	defer listener.Close()

	d := &Daemon{cfg: Config{SocketPath: socketPath}}
	err = d.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("Daemon.Run error = %v, want already-running error", err)
	}
	if _, statErr := os.Lstat(socketPath); statErr != nil {
		t.Fatalf("live old-daemon socket was removed: %v", statErr)
	}
}

func TestNewRejectsUnknownHWAccel(t *testing.T) {
	daemon, err := New(Config{HWAccel: "bogus"})
	if err == nil {
		if daemon != nil {
			t.Fatal("New returned a daemon for an unknown hwaccel value")
		}
		t.Fatal("New accepted an unknown hwaccel value")
	}
	if !strings.Contains(err.Error(), `unknown encoder "bogus"`) {
		t.Fatalf("New error = %q", err)
	}
}

func TestNewDefaultsVideoCodecToAuto(t *testing.T) {
	d, err := New(Config{CredFile: filepath.Join(t.TempDir(), "credentials.json")})
	if err != nil {
		t.Fatal(err)
	}
	if d.cfg.VideoCodec != airplay.VideoCodecAuto {
		t.Fatalf("default video codec = %s, want auto", d.cfg.VideoCodec)
	}
}

func TestMirrorStreamConfigIncludesDaemonPortRange(t *testing.T) {
	d := &Daemon{cfg: Config{
		FPS:       60,
		Bitrate:   8000,
		PortMin:   60000,
		PortMax:   60010,
		NoEncrypt: true,
		DirectKey: true,
		NoAudio:   true,
	}}

	want := airplay.StreamConfig{
		PreferredAudioCodec: airplay.AudioCodecALAC,
		FPS:                 60,
		Bitrate:             8000,
		PortMin:             60000,
		PortMax:             60010,
		NoEncrypt:           true,
		DirectKey:           true,
		NoAudio:             true,
	}
	if got := d.mirrorStreamConfig(); got != want {
		t.Fatalf("mirror stream config = %+v, want %+v", got, want)
	}
}

func TestValidatePortRange(t *testing.T) {
	for _, test := range []struct {
		name       string
		portMin    int
		portMax    int
		wantErrSub string
	}{
		{name: "ephemeral"},
		{name: "three ports", portMin: 60000, portMax: 60002},
		{name: "larger range", portMin: 60000, portMax: 60010},
		{name: "minimum missing", portMax: 60010, wantErrSub: "out of bounds"},
		{name: "maximum missing", portMin: 60000, wantErrSub: "out of bounds"},
		{name: "reversed", portMin: 60010, portMax: 60000, wantErrSub: "out of bounds"},
		{name: "maximum too high", portMin: 60000, portMax: 65536, wantErrSub: "out of bounds"},
		{name: "too small", portMin: 60000, portMax: 60001, wantErrSub: "too small"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validatePortRange(test.portMin, test.portMax)
			if test.wantErrSub == "" {
				if err != nil {
					t.Fatalf("validatePortRange(%d, %d): %v", test.portMin, test.portMax, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrSub) {
				t.Fatalf("validatePortRange(%d, %d) error = %v, want substring %q", test.portMin, test.portMax, err, test.wantErrSub)
			}
		})
	}
}
