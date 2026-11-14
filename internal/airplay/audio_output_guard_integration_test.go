//go:build linux

package airplay

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This subprocess deliberately never releases its output. Exiting or killing
// it must still remove the sink, including when the entire terminal receives
// a shutdown signal. Two owners also exercise the independent-process case.
func TestAudioOutputOwnerExitIntegration(t *testing.T) {
	if os.Getenv("DOUBLETAKE_TEST_AUDIO_OUTPUT_OWNER") == "1" {
		monitor, _, err := sharedAudioOutput.acquire(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintln(os.Stdout, monitor)
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	server := os.Getenv("DOUBLETAKE_TEST_PULSE_SERVER")
	if server == "" {
		t.Skip("requires DOUBLETAKE_TEST_PULSE_SERVER pointing to a private test server")
	}
	t.Setenv("PULSE_SERVER", server)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	type owner struct {
		cmd   *exec.Cmd
		input io.WriteCloser
		name  string
	}
	start := func(t *testing.T) owner {
		t.Helper()
		cmd := exec.CommandContext(ctx, executable, "-test.run=^TestAudioOutputOwnerExitIntegration$")
		cmd.Env = append(os.Environ(), "DOUBLETAKE_TEST_AUDIO_OUTPUT_OWNER=1")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Stderr = os.Stderr
		input, err := cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := cmd.StdoutPipe()
		if err != nil {
			input.Close()
			t.Fatal(err)
		}
		if err := cmd.Start(); err != nil {
			input.Close()
			output.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() {
			input.Close()
			cmd.Process.Kill()
			cmd.Wait()
		})
		monitor, err := bufio.NewReader(output).ReadString('\n')
		if err != nil {
			t.Fatalf("owner did not create output: %v", err)
		}
		return owner{cmd: cmd, input: input, name: strings.TrimSuffix(strings.TrimSpace(monitor), ".monitor")}
	}
	hasSink := func(t *testing.T, name string) bool {
		t.Helper()
		out, err := runPulseCommand(ctx, "list", "short", "sinks")
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(out), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] == name {
				return true
			}
		}
		return false
	}
	for _, exit := range []string{"normal exit", "killed owner", "terminal SIGTERM", "terminal SIGINT", "terminal SIGHUP"} {
		t.Run(exit, func(t *testing.T) {
			first, second := start(t), start(t)
			if first.name != stableAudioOutputName || first.name == second.name {
				t.Fatalf("outputs were stale or shared across owners: %q / %q", first.name, second.name)
			}
			switch exit {
			case "normal exit":
				first.input.Close()
			case "killed owner":
				if err := first.cmd.Process.Kill(); err != nil {
					t.Fatal(err)
				}
			case "terminal SIGTERM", "terminal SIGINT", "terminal SIGHUP":
				signal := map[string]syscall.Signal{
					"terminal SIGTERM": syscall.SIGTERM,
					"terminal SIGINT":  syscall.SIGINT,
					"terminal SIGHUP":  syscall.SIGHUP,
				}[exit]
				if err := syscall.Kill(-first.cmd.Process.Pid, signal); err != nil {
					t.Fatal(err)
				}
			}
			if err := first.cmd.Wait(); err != nil && exit == "normal exit" {
				t.Fatal(err)
			}
			deadline := time.Now().Add(8 * time.Second)
			for hasSink(t, first.name) && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if hasSink(t, first.name) {
				t.Fatal("exited owner leaked its audio output")
			}
			if !hasSink(t, second.name) {
				t.Fatal("cleanup removed the other owner's output")
			}
			second.input.Close()
			if err := second.cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			for hasSink(t, second.name) && time.Now().Before(deadline) {
				time.Sleep(20 * time.Millisecond)
			}
			if hasSink(t, second.name) {
				t.Fatal("second owner leaked its audio output")
			}
		})
	}
}
