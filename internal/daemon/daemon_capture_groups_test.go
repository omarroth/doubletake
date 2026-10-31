package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"doubletake/internal/airplay"
)

func TestNormalizedVideoCaptureKeyUsesEncodedEvenCanvas(t *testing.T) {
	for _, test := range []struct {
		name       string
		width      int
		height     int
		wantWidth  int
		wantHeight int
	}{
		{name: "1080p", width: 1920, height: 1080, wantWidth: 1920, wantHeight: 1080},
		{name: "odd dimensions", width: 1921, height: 1081, wantWidth: 1920, wantHeight: 1080},
		{name: "missing width", height: 720},
		{name: "missing height", width: 1280},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := normalizedVideoCaptureKey(test.width, test.height)
			if got.maxWidth != test.wantWidth || got.maxHeight != test.wantHeight {
				t.Fatalf("capture key = %dx%d, want %dx%d", got.maxWidth, got.maxHeight, test.wantWidth, test.wantHeight)
			}
		})
	}
}

func TestNormalizedVideoCaptureKeySeparatesResolvedCodecs(t *testing.T) {
	h264 := normalizedVideoCaptureKey(1920, 1080, airplay.VideoCodecH264)
	hevc := normalizedVideoCaptureKey(1920, 1080, airplay.VideoCodecHEVC)
	if h264 == hevc {
		t.Fatalf("H.264 and HEVC capture keys unexpectedly match: %+v", h264)
	}
	if h264.codec != airplay.VideoCodecH264 || hevc.codec != airplay.VideoCodecHEVC {
		t.Fatalf("capture key codecs = %s/%s", h264.codec, hevc.codec)
	}
}

func TestRemovingStreamStopsOnlyItsResolutionGroup(t *testing.T) {
	for _, first := range []videoCaptureKey{
		{maxWidth: 1920, maxHeight: 1080},
		{maxWidth: 1280, maxHeight: 720},
	} {
		second := videoCaptureKey{maxWidth: 1280, maxHeight: 720}
		if first == second {
			second = videoCaptureKey{maxWidth: 1920, maxHeight: 1080}
		}
		t.Run(captureKeyName(first)+" first", func(t *testing.T) {
			firstGroup := &videoCaptureGroup{key: first}
			secondGroup := &videoCaptureGroup{key: second}
			firstCtx, cancelFirst := context.WithCancel(context.Background())
			secondCtx, cancelSecond := context.WithCancel(context.Background())
			t.Cleanup(cancelFirst)
			t.Cleanup(cancelSecond)

			d := &Daemon{
				streams: map[string]*activeStream{
					"first":  {deviceIP: "first", captureGroup: firstGroup, cancelFn: cancelFirst},
					"second": {deviceIP: "second", captureGroup: secondGroup, cancelFn: cancelSecond},
				},
				captureGroups: map[videoCaptureKey]*videoCaptureGroup{
					first:  firstGroup,
					second: secondGroup,
				},
			}

			cleanup := d.detachStreamLocked("first")
			cleanup.run()
			if _, ok := d.captureGroups[first]; ok {
				t.Fatalf("removed stream left its %s capture group", captureKeyName(first))
			}
			if d.captureGroups[second] != secondGroup || d.streams["second"] == nil {
				t.Fatalf("removing %s disturbed active %s group", captureKeyName(first), captureKeyName(second))
			}
			select {
			case <-firstCtx.Done():
			default:
				t.Fatal("removed stream context was not cancelled")
			}
			select {
			case <-secondCtx.Done():
				t.Fatal("other resolution stream was cancelled")
			default:
			}
		})
	}
}

func TestCaptureGroupLivesUntilItsLastSharedStreamLeaves(t *testing.T) {
	key := videoCaptureKey{maxWidth: 1280, maxHeight: 720}
	group := &videoCaptureGroup{key: key}
	d := &Daemon{
		streams: map[string]*activeStream{
			"one": {deviceIP: "one", captureGroup: group},
			"two": {deviceIP: "two", captureGroup: group},
		},
		captureGroups: map[videoCaptureKey]*videoCaptureGroup{key: group},
	}

	cleanup := d.detachStreamLocked("one")
	cleanup.run()
	if d.captureGroups[key] != group {
		t.Fatal("shared capture group stopped while one stream remained")
	}
	cleanup = d.detachStreamLocked("two")
	cleanup.run()
	if len(d.captureGroups) != 0 {
		t.Fatalf("last shared stream left %d capture groups", len(d.captureGroups))
	}
}

func captureKeyName(key videoCaptureKey) string {
	return fmt.Sprintf("%dx%d", key.maxWidth, key.maxHeight)
}

func TestDisconnectAndShutdownCleanupRunWithoutDaemonMutex(t *testing.T) {
	for _, test := range []struct {
		name   string
		invoke func(*Daemon)
	}{
		{
			name: "targeted disconnect",
			invoke: func(d *Daemon) {
				d.handleDisconnect(Request{Cmd: "disconnect", Target: "target"})
			},
		},
		{
			name: "disconnect all",
			invoke: func(d *Daemon) {
				d.handleDisconnect(Request{Cmd: "disconnect"})
			},
		},
		{
			name: "shutdown",
			invoke: func(d *Daemon) {
				d.Shutdown()
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			entry := &activeStream{
				deviceIP: "target",
				cancelFn: func() {
					close(started)
					<-release
				},
			}
			d := &Daemon{
				cfg:           Config{SocketPath: filepath.Join(t.TempDir(), "daemon.sock")},
				streams:       map[string]*activeStream{"target": entry},
				captureGroups: make(map[videoCaptureKey]*videoCaptureGroup),
			}

			done := make(chan struct{})
			go func() {
				test.invoke(d)
				close(done)
			}()

			waitForCleanupBlock(t, started, release, done)
			assertDaemonMutexAvailable(t, d, release, done, func() {
				if len(d.streams) != 0 {
					t.Errorf("cleanup started before stream was detached: %+v", d.streams)
				}
			})
		})
	}
}

func TestCaptureFailureCleanupRunsWithoutDaemonMutex(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	key := videoCaptureKey{maxWidth: 1920, maxHeight: 1080}
	group := &videoCaptureGroup{key: key}
	entry := &activeStream{
		deviceIP:     "target",
		captureGroup: group,
		cancelFn: func() {
			close(started)
			<-release
		},
	}
	d := &Daemon{
		streams:       map[string]*activeStream{"target": entry},
		captureGroups: map[videoCaptureKey]*videoCaptureGroup{key: group},
	}

	done := make(chan struct{})
	go func() {
		d.finishCaptureGroup(group, nil, errors.New("capture stopped"))
		close(done)
	}()

	waitForCleanupBlock(t, started, release, done)
	assertDaemonMutexAvailable(t, d, release, done, func() {
		if len(d.streams) != 0 || len(d.captureGroups) != 0 {
			t.Errorf("capture failure cleanup was not detached: streams=%+v groups=%+v", d.streams, d.captureGroups)
		}
		if d.lastError == "" {
			t.Error("capture failure did not publish its error before cleanup")
		}
	})
}

func TestShutdownWaitsForConcurrentDetachedCleanup(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	d := &Daemon{
		cfg: Config{SocketPath: filepath.Join(t.TempDir(), "daemon.sock")},
		streams: map[string]*activeStream{
			"target": {
				deviceIP: "target",
				cancelFn: func() {
					close(started)
					<-release
				},
			},
		},
		captureGroups: make(map[videoCaptureKey]*videoCaptureGroup),
	}

	disconnectDone := make(chan struct{})
	go func() {
		d.handleDisconnect(Request{Cmd: "disconnect", Target: "target"})
		close(disconnectDone)
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("disconnect cleanup did not start")
	}

	shutdownDone := make(chan struct{})
	go func() {
		d.Shutdown()
		close(shutdownDone)
	}()
	select {
	case <-shutdownDone:
		close(release)
		<-disconnectDone
		t.Fatal("Shutdown returned before detached cleanup completed")
	case <-time.After(25 * time.Millisecond):
	}

	close(release)
	select {
	case <-disconnectDone:
	case <-time.After(time.Second):
		t.Fatal("disconnect cleanup did not finish")
	}
	select {
	case <-shutdownDone:
	case <-time.After(time.Second):
		t.Fatal("Shutdown did not finish after detached cleanup")
	}
}

func waitForCleanupBlock(t *testing.T, started, release, done chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("cleanup did not reach the deliberately blocking operation")
	}
}

func assertDaemonMutexAvailable(t *testing.T, d *Daemon, release, done chan struct{}, check func()) {
	t.Helper()
	locked := make(chan struct{})
	go func() {
		d.mu.Lock()
		check()
		d.mu.Unlock()
		close(locked)
	}()

	select {
	case <-locked:
		close(release)
		<-done
	case <-time.After(time.Second):
		close(release)
		<-done
		t.Fatal("daemon mutex remained locked during blocking cleanup")
	}
}

func TestStatusReportsSourceForEachStreamsCaptureGroup(t *testing.T) {
	monitorGroup := &videoCaptureGroup{source: &airplay.SourceInfo{Type: 1, Width: 3840, Height: 2160, HasPosition: true}}
	windowGroup := &videoCaptureGroup{source: &airplay.SourceInfo{Type: 2, Width: 1280, Height: 720}}
	d := &Daemon{streams: map[string]*activeStream{
		"192.0.2.20": {deviceIP: "192.0.2.20", device: "Window TV", state: StateStreaming, captureGroup: windowGroup},
		"192.0.2.10": {deviceIP: "192.0.2.10", device: "Monitor TV", state: StateStreaming, captureGroup: monitorGroup},
	}}

	status := d.handleStatus()
	if len(status.Streams) != 2 {
		t.Fatalf("status streams = %+v, want both streams", status.Streams)
	}
	want := map[string]airplay.SourceInfo{
		"192.0.2.10": *monitorGroup.source,
		"192.0.2.20": *windowGroup.source,
	}
	for _, stream := range status.Streams {
		if stream.Source == nil {
			t.Fatalf("stream %s reported no source: %+v", stream.DeviceIP, stream)
		}
		if *stream.Source != want[stream.DeviceIP] {
			t.Fatalf("stream %s reported source %+v, want %+v", stream.DeviceIP, *stream.Source, want[stream.DeviceIP])
		}
	}

	// The status reply is a wire format, so pin the keys a caller parses.
	raw, err := json.Marshal(*status.Streams[0].Source)
	if err != nil {
		t.Fatalf("marshal source: %v", err)
	}
	if got, want := string(raw), `{"type":1,"width":3840,"height":2160,"x":0,"y":0,"has_position":true}`; got != want {
		t.Fatalf("source JSON = %s, want %s", got, want)
	}
}

func TestStatusOmitsCaptureSourceWhenPortalReportedNone(t *testing.T) {
	d := &Daemon{streams: map[string]*activeStream{
		"192.0.2.10": {deviceIP: "192.0.2.10", device: "TV", state: StateStreaming, captureGroup: &videoCaptureGroup{}},
	}}

	stream := d.handleStatus().Streams[0]
	if stream.Source != nil {
		t.Fatalf("unknown source reported as %+v", *stream.Source)
	}
	raw, err := json.Marshal(stream)
	if err != nil {
		t.Fatalf("marshal stream: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal stream: %v", err)
	}
	if _, present := fields["source"]; present {
		t.Fatalf("unknown source is present in JSON: %s", raw)
	}
}
