package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const cliHelperEnvironment = "DOUBLETAKE_CTL_TEST_HELPER"

type controlFixtureResult struct {
	request map[string]json.RawMessage
	err     error
}

func TestResetRestoreTokenCLI(t *testing.T) {
	listener, results := startControlFixture(t)
	socketPath := listener.Addr().String()

	code, stdout, stderr := runCLIProcess(t,
		"-socket", socketPath,
		"reset-restore-token", "192.0.2.10",
	)
	if code != 0 {
		t.Fatalf("reset-restore-token exit code = %d, want 0; stdout=%q stderr=%q", code, stdout, stderr)
	}

	result := awaitControlFixture(t, results)
	if result.err != nil {
		t.Fatalf("control fixture: %v", result.err)
	}
	if len(result.request) != 2 {
		t.Fatalf("request fields = %v, want exactly cmd and target", result.request)
	}
	assertJSONStringField(t, result.request, "cmd", "reset-restore-token")
	assertJSONStringField(t, result.request, "target", "192.0.2.10")

	if err := listener.Close(); err != nil {
		t.Fatalf("close control fixture: %v", err)
	}
}

func TestResetRestoreTokenCLIRejectsInvalidArityWithoutContactingDaemon(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
	}{
		{name: "missing target", args: []string{"reset-restore-token"}},
		{name: "extra target", args: []string{"reset-restore-token", "192.0.2.10", "192.0.2.11"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			listener, results := startControlFixture(t)
			args := append([]string{"-socket", listener.Addr().String()}, test.args...)

			code, stdout, stderr := runCLIProcess(t, args...)
			if code == 0 {
				t.Fatalf("invalid reset exit code = 0, want nonzero; stdout=%q stderr=%q", stdout, stderr)
			}
			if err := listener.Close(); err != nil {
				t.Fatalf("close control fixture: %v", err)
			}

			result := awaitControlFixture(t, results)
			if result.err == nil {
				t.Fatalf("invalid reset contacted daemon with request %v", result.request)
			}
			if !errors.Is(result.err, net.ErrClosed) {
				t.Fatalf("control fixture stopped with %v, want listener close", result.err)
			}
		})
	}
}

func TestDoubletakeCtlHelperProcess(t *testing.T) {
	if os.Getenv(cliHelperEnvironment) != "1" {
		return
	}
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		os.Exit(2)
	}
	os.Args = append([]string{"doubletake-ctl"}, os.Args[separator+1:]...)
	main()
}

func startControlFixture(t *testing.T) (net.Listener, <-chan controlFixtureResult) {
	t.Helper()
	listener, err := net.Listen("unix", filepath.Join(t.TempDir(), "doubletake.sock"))
	if err != nil {
		t.Fatalf("listen on control socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	results := make(chan controlFixtureResult, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			results <- controlFixtureResult{err: err}
			return
		}
		defer conn.Close()

		var request map[string]json.RawMessage
		if err := json.NewDecoder(conn).Decode(&request); err != nil {
			results <- controlFixtureResult{err: err}
			return
		}
		if err := json.NewEncoder(conn).Encode(map[string]any{"ok": true, "state": "connecting"}); err != nil {
			results <- controlFixtureResult{err: err}
			return
		}
		results <- controlFixtureResult{request: request}
	}()
	return listener, results
}

func runCLIProcess(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	commandArgs := []string{"-test.run=^TestDoubletakeCtlHelperProcess$", "--"}
	commandArgs = append(commandArgs, args...)
	cmd := exec.CommandContext(ctx, os.Args[0], commandArgs...)
	cmd.Env = append(os.Environ(), cliHelperEnvironment+"=1")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("CLI process did not complete: %v", ctx.Err())
	}
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run CLI process: %v", err)
	}
	return exitErr.ExitCode(), stdout.String(), stderr.String()
}

func awaitControlFixture(t *testing.T, results <-chan controlFixtureResult) controlFixtureResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	select {
	case result := <-results:
		return result
	case <-ctx.Done():
		t.Fatalf("control fixture did not finish: %v", ctx.Err())
		return controlFixtureResult{}
	}
}

func assertJSONStringField(t *testing.T, request map[string]json.RawMessage, field, want string) {
	t.Helper()
	raw, ok := request[field]
	if !ok {
		t.Fatalf("request is missing %q: %v", field, request)
	}
	var got string
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("decode request field %q: %v", field, err)
	}
	if got != want {
		t.Fatalf("request field %q = %q, want %q", field, got, want)
	}
}
