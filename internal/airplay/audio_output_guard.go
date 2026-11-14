package airplay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const audioOutputGuardArgument = "--internal-audio-output-guard"

type audioOutputGuardRequest struct {
	Name       string
	Generation string
}

type audioOutputGuardResponse struct {
	Module string
	Error  string
}

// RunAudioOutputGuard handles the private child-process entry point. Call it
// before parsing CLI flags. The child owns the sound-server module and watches
// a pipe held only by its parent, so even a native crash closes that pipe and
// removes the output. It must survive terminal signals sent to both processes.
func RunAudioOutputGuard(args []string) (bool, error) {
	if len(args) != 1 || args[0] != audioOutputGuardArgument {
		return false, nil
	}
	signal.Ignore(os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGPIPE)
	return true, runAudioOutputGuard(os.Stdin, os.Stdout, runPulseCommand)
}

func runAudioOutputGuard(input io.Reader, output io.Writer, run pulseCommand) (result error) {
	// Keep the decoder's buffered bytes when subsequently waiting for EOF.
	decoder := json.NewDecoder(input)
	var request audioOutputGuardRequest
	if err := decoder.Decode(&request); err != nil {
		return fmt.Errorf("read audio output request: %w", err)
	}
	if request.Generation == "" || (request.Name != stableAudioOutputName &&
		request.Name != stableAudioOutputName+"_"+request.Generation) {
		return fmt.Errorf("invalid audio output identity")
	}
	manager := audioOutputManager{run: run}
	module, err := manager.create(context.Background(), request.Name, request.Generation)
	if err != nil {
		_ = json.NewEncoder(output).Encode(audioOutputGuardResponse{Error: err.Error()})
		return err
	}
	defer func() {
		for attempt := 0; attempt < 3; attempt++ {
			err := manager.remove(request.Name, module, request.Generation)
			if err == nil {
				return
			}
			if attempt == 2 {
				result = errors.Join(result, err)
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	if err := json.NewEncoder(output).Encode(audioOutputGuardResponse{Module: module}); err != nil {
		return fmt.Errorf("report audio output: %w", err)
	}
	_, err = io.Copy(io.Discard, io.MultiReader(decoder.Buffered(), input))
	return err
}

func startAudioOutputGuard(ctx context.Context, name, generation string) (string, func(), error) {
	executable, err := os.Executable()
	if err != nil {
		return "", nil, err
	}
	input, keepAlive, err := os.Pipe()
	if err != nil {
		return "", nil, err
	}
	defer input.Close()
	response, ready, err := os.Pipe()
	if err != nil {
		keepAlive.Close()
		return "", nil, err
	}
	defer ready.Close()
	// Do not attach the child to ctx or give it a parent-death signal: it needs
	// to finish cleanup after cancellation or the main process disappearing.
	cmd := exec.Command(executable, audioOutputGuardArgument)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, ready, os.Stderr
	if err := cmd.Start(); err != nil {
		keepAlive.Close()
		response.Close()
		return "", nil, fmt.Errorf("start audio output guard: %w", err)
	}
	// The parent must not retain the child's copies of either pipe endpoint.
	input.Close()
	ready.Close()
	done := make(chan struct{})
	go func() {
		if err := cmd.Wait(); err != nil {
			log.Printf("[AUDIO] output guard: %v", err)
		}
		close(done)
	}()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() { keepAlive.Close() })
		<-done
	}
	if err := json.NewEncoder(keepAlive).Encode(audioOutputGuardRequest{Name: name, Generation: generation}); err != nil {
		response.Close()
		stop()
		return "", nil, err
	}
	type result struct {
		response audioOutputGuardResponse
		err      error
	}
	resultCh := make(chan result, 1)
	go func() {
		defer response.Close()
		var reply audioOutputGuardResponse
		err := json.NewDecoder(response).Decode(&reply)
		resultCh <- result{reply, err}
	}()
	select {
	case <-ctx.Done():
		stop()
		return "", nil, ctx.Err()
	case result := <-resultCh:
		if err := ctx.Err(); err != nil {
			stop()
			return "", nil, err
		}
		if result.err == nil && result.response.Error != "" {
			result.err = fmt.Errorf("%s", result.response.Error)
		}
		if result.err == nil {
			if _, err := strconv.ParseUint(strings.TrimSpace(result.response.Module), 10, 32); err != nil {
				result.err = fmt.Errorf("invalid guarded module ID %q", result.response.Module)
			}
		}
		if result.err != nil {
			stop()
			return "", nil, fmt.Errorf("create guarded audio output: %w", result.err)
		}
		return result.response.Module, stop, nil
	}
}
