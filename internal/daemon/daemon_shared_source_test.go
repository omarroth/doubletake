package daemon

import (
	"context"
	"testing"

	"doubletake/internal/airplay"
)

func TestDaemonReleasesSelectedSourceOnlyAfterLastStream(t *testing.T) {
	root := &airplay.CapturePreparation{}
	d := &Daemon{videoSource: root, streams: map[string]*activeStream{"one": {}, "two": {}}, captureGroups: make(map[videoCaptureKey]*videoCaptureGroup)}
	first := d.detachStreamLocked("one")
	first.run()
	if d.videoSource != root {
		t.Fatal("first disconnect dropped selected source")
	}
	fork, err := root.Fork(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	fork.Close()
	last := d.detachStreamLocked("two")
	last.run()
	if d.videoSource != nil {
		t.Fatal("last disconnect retained selected source")
	}
	if fork, err := root.Fork(context.Background(), ""); err == nil {
		fork.Close()
		t.Fatal("last disconnect leaked root capture preparation")
	}
}
