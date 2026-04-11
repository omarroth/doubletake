package airplay

import (
	"flag"
	"testing"
)

var appleTVHost = flag.String("apple-tv", "", "Apple TV IP for hardware-backed integration tests")

func requireAppleTV(t *testing.T) string {
	t.Helper()
	if *appleTVHost == "" {
		t.Skip("set -apple-tv=<ip> via go test -args to run hardware-backed integration tests")
	}
	return *appleTVHost
}
