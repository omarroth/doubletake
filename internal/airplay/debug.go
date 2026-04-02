package airplay

import "log"

// DebugMode controls verbose logging. Set via -debug flag.
var DebugMode bool

// dbg logs a message only when debug mode is enabled.
func dbg(format string, args ...interface{}) {
	if DebugMode {
		log.Printf(format, args...)
	}
}
