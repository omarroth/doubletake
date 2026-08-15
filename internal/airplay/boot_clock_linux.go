//go:build linux

package airplay

import (
	"time"

	"golang.org/x/sys/unix"
)

func bootRelativeNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err == nil {
		return time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
	}
	return time.Since(appStartTime)
}
