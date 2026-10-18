package airplay

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
)

type leasedPortalFixture struct {
	mu            sync.Mutex
	opens, closes int
	fail          bool
}

func (p *leasedPortalFixture) Close() error { p.mu.Lock(); defer p.mu.Unlock(); p.closes++; return nil }
func (p *leasedPortalFixture) openPipeWireRemote(context.Context) (*os.File, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closes != 0 || p.fail {
		return nil, fmt.Errorf("portal unavailable")
	}
	p.opens++
	return os.Open(os.DevNull)
}

func TestCaptureSourceLeasesOutliveFirstReceiver(t *testing.T) {
	portal := &leasedPortalFixture{}
	rootFD, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	root := &CapturePreparation{kind: capturePreparationWayland, cfg: CaptureConfig{VideoCodec: VideoCodecAuto}, portal: portal, pwFd: rootFD, pwNodeID: 42, streamSize: [2]int{1280, 720}}
	a, err := root.Fork(context.Background(), VideoCodecAuto)
	if err != nil {
		t.Fatal(err)
	}
	b, err := root.Fork(context.Background(), VideoCodecH264)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	defer b.Close()
	root.Close()
	if _, err := rootFD.Stat(); err == nil {
		t.Fatal("root remote FD leaked")
	}
	if portal.closes != 0 || portal.opens != 2 {
		t.Fatalf("portal lifecycle=%+v", portal)
	}
	if a.pwFd == b.pwFd || a.pwNodeID != 42 || b.streamSize != [2]int{1280, 720} {
		t.Fatal("forks did not share selected node with separate remote FDs")
	}
	a.Close()
	if portal.closes != 0 {
		t.Fatal("first receiver closed another group's source")
	}
	b.Close()
	if portal.closes != 1 {
		t.Fatalf("last lease closed portal %d times", portal.closes)
	}
	if _, err := root.Fork(context.Background(), VideoCodecAuto); err == nil {
		t.Fatal("closed source accepted new encoder")
	}
}

func TestCaptureSourceFailedForkDoesNotLeakLease(t *testing.T) {
	portal := &leasedPortalFixture{fail: true}
	root := &CapturePreparation{kind: capturePreparationWayland, portal: portal}
	if _, err := root.Fork(context.Background(), ""); err == nil {
		t.Fatal("failed remote open succeeded")
	}
	root.Close()
	if portal.closes != 1 {
		t.Fatal("failed fork retained portal lease")
	}
}

func TestCaptureSourceConcurrentForkAndRelease(t *testing.T) {
	portal := &leasedPortalFixture{}
	root := &CapturePreparation{kind: capturePreparationWayland, portal: portal}
	var workers sync.WaitGroup
	for range 20 {
		workers.Go(func() {
			fork, err := root.Fork(context.Background(), "")
			if err == nil {
				fork.Close()
			}
		})
	}
	workers.Go(root.Close)
	workers.Wait()
	if portal.closes != 1 {
		t.Fatalf("concurrent release closed portal %d times", portal.closes)
	}
}
