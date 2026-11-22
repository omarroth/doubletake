package airplay

import (
	"os/exec"
	"runtime"
	"syscall"
)

func configureCaptureProcess(cmd *exec.Cmd) func() {
	runtime.LockOSThread()
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return runtime.UnlockOSThread
}
