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
	module, name, generation string
	existingSink             string
	loads, unloads           int
	loadErr                  error
	loadReply                string
	collideStable            bool
	calls                    []string
}

func (p *fakePulseOutput) run(_ context.Context, args ...string) ([]byte, error) {
	p.calls = append(p.calls, strings.Join(args, " "))
	switch args[0] {
	case "load-module":
		p.loads++
		p.name = strings.TrimPrefix(args[2], "sink_name=")
		for _, field := range strings.Fields(strings.Join(args, " ")) {
			if strings.HasPrefix(field, "doubletake.generation=") {
				p.generation = strings.Trim(strings.TrimPrefix(field, "doubletake.generation="), "'\"")
			}
		}
		if p.collideStable && p.loads == 1 && p.name == stableAudioOutputName {
			p.existingSink = stableAudioOutputName
			p.module = "77"
			p.generation = "owned-by-another-process"
			return nil, errors.New("sink name already exists")
		}
		p.module = "42"
		if p.loadErr != nil || p.loadReply != "" {
			return []byte(p.loadReply), p.loadErr
		}
		return []byte("42\n"), nil
	case "list":
		if args[2] == "sinks" {
			if p.existingSink == "" {
				return nil, nil
			}
			return []byte(fmt.Sprintf("1\t%s\tPipeWire\ts16le 2ch 44100Hz\tSUSPENDED\n", p.existingSink)), nil
		}
		return []byte(fmt.Sprintf("%s\tmodule-null-sink\tsink_name=%s rate=44100 sink_properties='doubletake.generation=%s'\t0\n",
			p.module, p.name, p.generation)), nil
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
	if monitor != "doubletake.monitor" || monitor != second {
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
	if third != monitor {
		t.Fatalf("stable output changed from %q to %q", monitor, third)
	}
	for _, call := range pulse.calls {
		if strings.HasPrefix(call, "set-default") || strings.HasPrefix(call, "move-") {
			t.Fatalf("changed user routing: %s", call)
		}
	}
}

func TestAudioOutputUsesGeneratedFallbackWhenStableNameExists(t *testing.T) {
	pulse := &fakePulseOutput{existingSink: stableAudioOutputName}
	manager := audioOutputManager{run: pulse.run}
	monitor, release, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if !strings.HasPrefix(monitor, "doubletake_") || !strings.HasSuffix(monitor, ".monitor") {
		t.Fatalf("colliding stable sink produced monitor %q", monitor)
	}
}

func TestAudioOutputRetriesGeneratedNameAfterStableNameRace(t *testing.T) {
	pulse := &fakePulseOutput{collideStable: true}
	manager := audioOutputManager{run: pulse.run}
	monitor, release, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(monitor, "doubletake_") || !strings.HasSuffix(monitor, ".monitor") {
		t.Fatalf("colliding stable sink produced monitor %q", monitor)
	}
	if pulse.loads != 2 || pulse.unloads != 0 {
		t.Fatalf("race handling loaded/unloaded %d/%d modules", pulse.loads, pulse.unloads)
	}
	release()
	if pulse.unloads != 1 {
		t.Fatal("generated fallback was not removed")
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

func TestAudioOutputDoesNotUnloadReusedGeneration(t *testing.T) {
	pulse := &fakePulseOutput{}
	manager := audioOutputManager{run: pulse.run}
	_, release, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pulse.generation = "owned-by-another-process"
	release()
	if pulse.unloads != 0 {
		t.Fatal("unloaded another process's output after module reuse")
	}
}

func TestPulseModuleLineArgumentMatchingHonorsQuotedProperty(t *testing.T) {
	fields := strings.Fields("sink_name=doubletake sink_properties='device.description=doubletake doubletake.generation=abc123'")
	if !pulseModuleLineHasArgument(fields, "sink_name=doubletake") ||
		!pulseModuleLineHasArgument(fields, "doubletake.generation=abc123") {
		t.Fatalf("did not match quoted module arguments: %v", fields)
	}
	if pulseModuleLineHasArgument(fields, "doubletake.generation=other") {
		t.Fatal("matched an unrelated generation")
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
