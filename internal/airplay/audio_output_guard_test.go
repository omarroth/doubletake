package airplay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	if handled, err := RunAudioOutputGuard(os.Args[1:]); handled {
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	os.Exit(m.Run())
}

func TestAudioOutputGuardWaitsForOwnerEOF(t *testing.T) {
	pulse := &fakePulseOutput{}
	input, owner := io.Pipe()
	response, output := io.Pipe()
	defer owner.Close()
	defer response.Close()
	done := make(chan error, 1)
	go func() {
		defer output.Close()
		done <- runAudioOutputGuard(input, output, pulse.run)
	}()
	if err := json.NewEncoder(owner).Encode(audioOutputGuardRequest{Name: stableAudioOutputName, Generation: "abc123"}); err != nil {
		t.Fatal(err)
	}
	var reply audioOutputGuardResponse
	if err := json.NewDecoder(response).Decode(&reply); err != nil {
		t.Fatal(err)
	}
	if reply.Module != "42" || reply.Error != "" || pulse.unloads != 0 {
		t.Fatalf("output not retained while owner was alive: %+v, unloads=%d", reply, pulse.unloads)
	}
	owner.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if pulse.unloads != 1 {
		t.Fatalf("owner EOF unloaded %d outputs, want 1", pulse.unloads)
	}
}

type failedAudioOutputReply struct{}

func (failedAudioOutputReply) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestAudioOutputGuardLostStartupReplyCleansSink(t *testing.T) {
	pulse := &fakePulseOutput{}
	var input bytes.Buffer
	if err := json.NewEncoder(&input).Encode(audioOutputGuardRequest{Name: stableAudioOutputName, Generation: "abc123"}); err != nil {
		t.Fatal(err)
	}
	if err := runAudioOutputGuard(&input, failedAudioOutputReply{}, pulse.run); err == nil {
		t.Fatal("lost startup reply succeeded")
	}
	if pulse.loads != 1 || pulse.unloads != 1 {
		t.Fatalf("lost startup reply loaded/unloaded %d/%d modules", pulse.loads, pulse.unloads)
	}
}

func TestAudioOutputGuardRetriesTransientCleanupFailure(t *testing.T) {
	pulse := &fakePulseOutput{}
	checks := 0
	run := func(ctx context.Context, args ...string) ([]byte, error) {
		if args[0] == "list" {
			checks++
			if checks == 1 {
				return nil, context.DeadlineExceeded
			}
		}
		return pulse.run(ctx, args...)
	}
	var input, output bytes.Buffer
	if err := json.NewEncoder(&input).Encode(audioOutputGuardRequest{Name: stableAudioOutputName, Generation: "abc123"}); err != nil {
		t.Fatal(err)
	}
	if err := runAudioOutputGuard(&input, &output, run); err != nil {
		t.Fatal(err)
	}
	if checks != 2 || pulse.unloads != 1 {
		t.Fatalf("cleanup checked %d times, unloaded %d outputs", checks, pulse.unloads)
	}
}

func TestAudioOutputGuardSharedUntilLastCapture(t *testing.T) {
	pulse := &fakePulseOutput{}
	starts, stops := 0, 0
	manager := audioOutputManager{run: pulse.run, guard: func(context.Context, string, string) (string, func(), error) {
		starts++
		return "42", func() { stops++ }, nil
	}}
	_, first, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := manager.acquire(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first()
	if starts != 1 || stops != 0 {
		t.Fatalf("guard started/stopped %d/%d times while a capture remained", starts, stops)
	}
	second()
	second()
	if stops != 1 || pulse.unloads != 0 {
		t.Fatalf("guard stopped %d times, parent unloaded %d times", stops, pulse.unloads)
	}
}
