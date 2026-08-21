package airplay

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// displayProbeTimeout bounds the reachability check so an unresponsive
// compositor cannot stall startup.
const displayProbeTimeout = 2 * time.Second

// probeX11Display reports whether DISPLAY points at a reachable X server.
//
// A display variable that is merely set is not enough. When a desktop session
// ends, the X (or Xwayland) socket is removed while DISPLAY survives in every
// process that outlived the session. A lingering systemd user service is the
// common case: it keeps the DISPLAY and XAUTHORITY it inherited at login, so
// after logout it still advertises a display that no longer exists. Capture
// then starts against nothing, GStreamer produces no frames, and the receiver
// shows a black screen with no error reported anywhere.
//
// This only checks that the display endpoint accepts a connection. It does not
// validate authentication: a reachable server that rejects the cookie still
// fails later in GStreamer, with GStreamer's own message.
func probeX11Display(display string) error {
	network, address, err := x11Endpoint(display)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout(network, address, displayProbeTimeout)
	if err != nil {
		return fmt.Errorf("DISPLAY=%q is set but the X server at %s is not reachable: %w "+
			"(a process that outlives its login session keeps a stale DISPLAY)", display, address, err)
	}
	return conn.Close()
}

// probeWaylandDisplay reports whether WAYLAND_DISPLAY points at a reachable
// compositor. It has the same stale-variable failure mode as probeX11Display.
func probeWaylandDisplay(display string) error {
	address := display
	if !filepath.IsAbs(address) {
		runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
		if runtimeDir == "" {
			return fmt.Errorf("WAYLAND_DISPLAY=%q is set but XDG_RUNTIME_DIR is empty, "+
				"so the compositor socket cannot be located", display)
		}
		address = filepath.Join(runtimeDir, address)
	}
	conn, err := net.DialTimeout("unix", address, displayProbeTimeout)
	if err != nil {
		return fmt.Errorf("WAYLAND_DISPLAY=%q is set but the compositor socket %s is not reachable: %w "+
			"(a process that outlives its login session keeps a stale WAYLAND_DISPLAY)", display, address, err)
	}
	return conn.Close()
}

// x11Endpoint resolves a DISPLAY value to a dialable endpoint, following the
// same unix-socket-or-TCP rule as Xlib.
func x11Endpoint(display string) (network, address string, err error) {
	spec := display
	if slash := strings.Index(spec, "/"); slash >= 0 {
		spec = spec[slash+1:] // drop an optional protocol prefix
	}
	colon := strings.LastIndex(spec, ":")
	if colon < 0 {
		return "", "", fmt.Errorf("DISPLAY=%q is not a valid display name", display)
	}
	host := spec[:colon]
	number := spec[colon+1:]
	if dot := strings.Index(number, "."); dot >= 0 {
		number = number[:dot] // drop the screen suffix
	}
	n, convErr := strconv.Atoi(number)
	if convErr != nil {
		return "", "", fmt.Errorf("DISPLAY=%q has no usable display number", display)
	}
	if host == "" || host == "unix" {
		return "unix", fmt.Sprintf("/tmp/.X11-unix/X%d", n), nil
	}
	// An IPv6 literal may already be bracketed in DISPLAY. JoinHostPort adds
	// its own brackets to any host containing a colon, so leaving these on
	// produces an undialable "[[::1]]:6000".
	if len(host) > 1 && host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	return "tcp", net.JoinHostPort(host, strconv.Itoa(6000+n)), nil
}
