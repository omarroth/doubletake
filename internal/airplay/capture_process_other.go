//go:build !linux

package airplay

import "os/exec"

func configureCaptureProcess(*exec.Cmd) func() { return func() {} }
