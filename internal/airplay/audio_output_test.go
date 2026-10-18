package airplay

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type fakePulseOutput struct {
	module, name   string
	loads, unloads int
	loadErr        error
	loadReply      string
	calls          []string
}

func (p *fakePulseOutput) run(_ context.Context, args ...string) ([]byte, error) {
	p.calls = append(p.calls, strings.Join(args, " "))
	switch args[0] {
	case "load-module":
		p.loads++
		p.name = strings.TrimPrefix(args[2], "sink_name=")
		p.module = "42"
		if p.loadErr != nil || p.loadReply != "" {
			return []byte(p.loadReply), p.loadErr
		}
		return []byte("42\n"), nil
	case "list":
		return []byte(fmt.Sprintf("%s\tmodule-null-sink\tsink_name=%s rate=44100\t0\n", p.module, p.name)), nil
	case "unload-module":
		p.unloads++
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected pactl command %v", args)
}

func TestAudioOutputSharedUntilLastCapture(t *testing.T) {
	pulse := &fakePulseOutput{}
	manager := audioOutputManager{run: pulse.run}
	monitor, release, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, releaseSecond, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if monitor != second || !strings.HasPrefix(monitor, "doubletake_") || !strings.HasSuffix(monitor, ".monitor") {
		t.Fatalf("captures did not share a dedicated monitor: %q / %q", monitor, second)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(release)
	}
	workers.Wait()
	if pulse.unloads != 0 || manager.users != 1 {
		t.Fatal("output removed while a capture remained")
	}
	releaseSecond()
	if pulse.loads != 1 || pulse.unloads != 1 || manager.users != 0 {
		t.Fatalf("lifecycle = %+v", pulse)
	}
	third, releaseThird, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer releaseThird()
	if third == monitor {
		t.Fatal("output generation reused its old name")
	}
	for _, call := range pulse.calls {
		if strings.HasPrefix(call, "set-default") || strings.HasPrefix(call, "move-") {
			t.Fatalf("changed user routing: %s", call)
		}
	}
}

func TestAudioOutputDoesNotUnloadReusedModuleID(t *testing.T) {
	pulse := &fakePulseOutput{}
	manager := audioOutputManager{run: pulse.run}
	_, release, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pulse.name = "unrelated_output"
	release()
	if pulse.unloads != 0 {
		t.Fatal("unloaded unrelated module after server restart")
	}
}

func TestAudioOutputFailedLoadCleansOnlyOwnGeneration(t *testing.T) {
	for _, reply := range []string{"", "not an ID"} {
		t.Run(reply, func(t *testing.T) {
			pulse := &fakePulseOutput{loadReply: reply}
			if reply == "" {
				pulse.loadErr = context.DeadlineExceeded
			}
			manager := audioOutputManager{run: pulse.run}
			if _, _, err := manager.acquire(context.Background()); err == nil {
				t.Fatal("failed load succeeded")
			}
			if pulse.unloads != 1 || manager.users != 0 {
				t.Fatalf("incomplete load leaked output: %+v", pulse)
			}
		})
	}
}

func TestAudioOutputCanceledAcquireDoesNotCreateSink(t *testing.T) {
	pulse := &fakePulseOutput{}
	manager := audioOutputManager{run: pulse.run}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := manager.acquire(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("acquire = %v", err)
	}
	if pulse.loads != 0 {
		t.Fatal("canceled capture created an output")
	}
}
