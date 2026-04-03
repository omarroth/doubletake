package fpemu

import "log"

// DebugMode controls verbose logging. Set by the caller (e.g. main).
var DebugMode bool

func dbg(format string, args ...interface{}) {
	if DebugMode {
		log.Printf(format, args...)
	}
}
