//go:build cgo

package airplay

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func linkedPortalArguments(args []string, portal *os.File) ([]string, func(), error) {
	// Keep this descriptor valid while pipewiresrc can open or reconnect.
	// The plugin duplicates it when opening its PipeWire connection.
	fd, err := unix.FcntlInt(portal.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("duplicate PipeWire descriptor: %w", err)
	}
	return replacePipelineFD(args, 3, fd), func() { _ = unix.Close(fd) }, nil
}
