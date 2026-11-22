package airplay

import (
	"os/exec"
	"syscall"
	"testing"
)

func TestStartGStreamerCommandSetsParentDeathSignal(t *testing.T) {
	cmd := exec.Command("true")
	waitResult, err := startGStreamerCommand(cmd)
	if err != nil {
		t.Fatalf("startGStreamerCommand: %v", err)
	}
	if cmd.SysProcAttr == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("Pdeathsig = %v, want SIGKILL", cmd.SysProcAttr)
	}
	if err := <-waitResult; err != nil {
		t.Fatalf("wait for supervised command: %v", err)
	}
}
