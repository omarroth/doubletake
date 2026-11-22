package airplay

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func startMacOSAudio(ctx context.Context) (*os.File, <-chan error, error) {
	executable, err := os.Executable()
	if err != nil {
		return nil, nil, err
	}
	helper := filepath.Join(filepath.Dir(executable), "doubletake-macos-audio")
	if _, err := os.Stat(helper); err != nil {
		return nil, nil, fmt.Errorf("macOS audio helper: %w (build with make macos-audio-helper, or use -no-audio)", err)
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		return nil, nil, err
	}
	defer writer.Close()
	cmd := exec.CommandContext(ctx, helper)
	cmd.Stdout, cmd.Stderr = writer, os.Stderr
	if err := cmd.Start(); err != nil {
		_ = reader.Close()
		return nil, nil, fmt.Errorf("start macOS audio capture: %w", err)
	}
	wait := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		var exit *exec.ExitError
		if ctx.Err() != nil && errors.As(err, &exit) && exit.ExitCode() < 0 {
			err = nil
		}
		if err != nil {
			err = fmt.Errorf("macOS audio capture: %w", err)
		}
		wait <- err
	}()
	return reader, wait, nil
}
