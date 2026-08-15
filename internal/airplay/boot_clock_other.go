//go:build !linux

package airplay

import "time"

func bootRelativeNow() time.Duration {
	return time.Since(appStartTime)
}
