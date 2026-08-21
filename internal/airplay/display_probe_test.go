package airplay

import "testing"

// x11Endpoint follows Xlib's rule for turning a DISPLAY value into something
// dialable: an empty or "unix" host means the local socket, anything else is
// TCP on 6000+N. The screen suffix and an optional protocol prefix are not
// part of the endpoint.
func TestX11Endpoint(t *testing.T) {
	for _, test := range []struct {
		display     string
		wantNetwork string
		wantAddress string
	}{
		{display: ":0", wantNetwork: "unix", wantAddress: "/tmp/.X11-unix/X0"},
		{display: ":99", wantNetwork: "unix", wantAddress: "/tmp/.X11-unix/X99"},
		// The screen suffix selects a screen on the same server, so it must
		// not change which socket is dialled.
		{display: ":0.0", wantNetwork: "unix", wantAddress: "/tmp/.X11-unix/X0"},
		{display: ":99.1", wantNetwork: "unix", wantAddress: "/tmp/.X11-unix/X99"},
		{display: "unix:0", wantNetwork: "unix", wantAddress: "/tmp/.X11-unix/X0"},
		// A protocol prefix is stripped before the host is read; "local"
		// leaves an empty host, which is still the unix socket.
		{display: "local/unix:2", wantNetwork: "unix", wantAddress: "/tmp/.X11-unix/X2"},
		{display: "host:0", wantNetwork: "tcp", wantAddress: "host:6000"},
		{display: "host:12.0", wantNetwork: "tcp", wantAddress: "host:6012"},
		{display: "192.168.1.5:1", wantNetwork: "tcp", wantAddress: "192.168.1.5:6001"},
		// An IPv6 literal keeps its brackets through JoinHostPort, and the
		// display number is taken from the LAST colon.
		{display: "[::1]:0", wantNetwork: "tcp", wantAddress: "[::1]:6000"},
	} {
		t.Run(test.display, func(t *testing.T) {
			network, address, err := x11Endpoint(test.display)
			if err != nil {
				t.Fatalf("x11Endpoint(%q) returned %v, want %s %s", test.display, err, test.wantNetwork, test.wantAddress)
			}
			if network != test.wantNetwork || address != test.wantAddress {
				t.Fatalf("x11Endpoint(%q) = %s %s, want %s %s", test.display, network, address, test.wantNetwork, test.wantAddress)
			}
		})
	}
}

// A DISPLAY that cannot be resolved must be reported rather than guessed at,
// since guessing is what lets a stale variable start a capture against
// nothing.
func TestX11EndpointRejectsUnusableDisplay(t *testing.T) {
	for _, display := range []string{
		"",
		"0",         // no colon at all
		":",         // no display number
		":abc",      // display number is not a number
		"host:",     // host but no number
		"host:xy.0", // screen suffix present, number still unusable
	} {
		t.Run(display, func(t *testing.T) {
			network, address, err := x11Endpoint(display)
			if err == nil {
				t.Fatalf("x11Endpoint(%q) = %s %s, want an error", display, network, address)
			}
		})
	}
}
