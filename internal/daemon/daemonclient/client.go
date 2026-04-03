package daemonclient

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"doubletake/internal/daemon"
)

// Client communicates with a running doubletake-daemon over its Unix socket.
type Client struct {
	SocketPath string
}

// New creates a client that connects to the daemon at the given socket path.
func New(socketPath string) *Client {
	return &Client{SocketPath: socketPath}
}

// NewDefault creates a client using the default socket path.
func NewDefault() *Client {
	return &Client{SocketPath: daemon.DefaultSocketPath()}
}

// Status returns the daemon's current state.
func (c *Client) Status() (*daemon.Response, error) {
	return c.send(daemon.Request{Cmd: "status"})
}

// Discover triggers device discovery and returns found devices.
func (c *Client) Discover() (*daemon.Response, error) {
	return c.send(daemon.Request{Cmd: "discover"})
}

// Devices returns the cached list of discovered devices.
func (c *Client) Devices() (*daemon.Response, error) {
	return c.send(daemon.Request{Cmd: "devices"})
}

// Connect starts mirroring to the specified target (or first discovered device if empty).
func (c *Client) Connect(target string, port int, pin string) (*daemon.Response, error) {
	return c.send(daemon.Request{Cmd: "connect", Target: target, Port: port, Pin: pin})
}

// Disconnect stops the current mirroring session.
func (c *Client) Disconnect() (*daemon.Response, error) {
	return c.send(daemon.Request{Cmd: "disconnect"})
}

func (c *Client) send(req daemon.Request) (*daemon.Response, error) {
	conn, err := net.DialTimeout("unix", c.SocketPath, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connect to daemon: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}

	var resp daemon.Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	return &resp, nil
}
