// Package version identifies the source used to build a binary.
package version

import (
	"fmt"
	"runtime/debug"
)

// Release builds set these through the linker. Direct go builds fall back to
// the VCS information recorded by the Go toolchain.
var (
	Version = "devel"
	Commit  = ""
)

func String() string {
	commit := Commit
	if commit == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range info.Settings {
				if setting.Key == "vcs.revision" {
					commit = setting.Value
				}
			}
		}
	}
	if commit == "" {
		return Version
	}
	if len(commit) > 12 {
		commit = commit[:12]
	}
	return fmt.Sprintf("%s (%s)", Version, commit)
}
