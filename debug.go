package main

import "log"

// debugMode controls verbose logging. Set via -debug flag.
var debugMode bool

// dbg logs a message only when debug mode is enabled.
func dbg(format string, args ...interface{}) {
	if debugMode {
		log.Printf(format, args...)
	}
}
