package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"doubletake/internal/airplay"
	"doubletake/internal/fpemu"
)

// State represents the daemon's current lifecycle state.
type State string

const (
	StateIdle        State = "idle"
	StateDiscovering State = "discovering"
	StateConnecting  State = "connecting"
	StateStreaming   State = "streaming"
)

// Request is a command sent to the daemon over the control socket.
type Request struct {
	Cmd    string `json:"cmd"`
	Target string `json:"target,omitempty"`
	Port   int    `json:"port,omitempty"`
	Pin    string `json:"pin,omitempty"`
}

// Response is returned to the caller for every request.
type Response struct {
	OK       bool         `json:"ok"`
	State    State        `json:"state"`
	Device   string       `json:"device,omitempty"`
	DeviceIP string       `json:"device_ip,omitempty"`
	Error    string       `json:"error,omitempty"`
	Devices  []DeviceInfo `json:"devices,omitempty"`
}

// DeviceInfo is a simplified view of a discovered AirPlay device.
type DeviceInfo struct {
	Name  string `json:"name"`
	Model string `json:"model"`
	IP    string `json:"ip"`
	Port  int    `json:"port"`
}

// Config holds daemon configuration.
type Config struct {
	SocketPath string
	CredFile   string
	Width      int
	Height     int
	FPS        int
	Bitrate    int
	HWAccel    string
	Debug      bool
	TestMode   bool
	NoEncrypt  bool
	DirectKey  bool
	NoAudio    bool
}

// DefaultSocketPath returns the default socket path using XDG_RUNTIME_DIR.
func DefaultSocketPath() string {
	dir := os.Getenv("XDG_RUNTIME_DIR")
	if dir == "" {
		dir = "/tmp"
	}
	return filepath.Join(dir, "doubletake.sock")
}

// Daemon manages a long-running doubletake service.
type Daemon struct {
	cfg         Config
	mu          sync.Mutex
	state       State
	discovering bool // true while discover is in-flight, independent of state
	devices     []airplay.AirPlayDevice
	client      *airplay.AirPlayClient
	session     *airplay.MirrorSession
	capture     *airplay.ScreenCapture
	device      string // name of connected device
	deviceIP    string // IP of connected device
	cancelFn    context.CancelFunc
	listener    net.Listener
}

// New creates a new Daemon with the given configuration.
func New(cfg Config) *Daemon {
	return &Daemon{
		cfg:   cfg,
		state: StateIdle,
	}
}

// Run starts the daemon control socket and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	airplay.DebugMode = d.cfg.Debug
	fpemu.DebugMode = d.cfg.Debug

	// Clean up stale socket
	if err := os.Remove(d.cfg.SocketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	ln, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", d.cfg.SocketPath, err)
	}
	d.listener = ln
	// Owner-only permissions
	if err := os.Chmod(d.cfg.SocketPath, 0700); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	log.Printf("[daemon] listening on %s", d.cfg.SocketPath)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			log.Printf("[daemon] accept error: %v", err)
			continue
		}
		go d.handleConn(conn)
	}
}

// Shutdown stops any active session and cleans up the socket.
func (d *Daemon) Shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.stopLocked()
	if d.listener != nil {
		d.listener.Close()
	}
	os.Remove(d.cfg.SocketPath)
}

func (d *Daemon) handleConn(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	dec := json.NewDecoder(conn)
	enc := json.NewEncoder(conn)

	var req Request
	if err := dec.Decode(&req); err != nil {
		enc.Encode(Response{OK: false, Error: "invalid request: " + err.Error()})
		return
	}

	resp := d.handleRequest(req)
	enc.Encode(resp)
}

func (d *Daemon) handleRequest(req Request) Response {
	switch req.Cmd {
	case "status":
		return d.handleStatus()
	case "discover":
		return d.handleDiscover()
	case "devices":
		return d.handleDevices()
	case "connect":
		return d.handleConnect(req)
	case "disconnect":
		return d.handleDisconnect()
	default:
		return Response{OK: false, Error: "unknown command: " + req.Cmd}
	}
}

func (d *Daemon) handleStatus() Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{
		OK:       true,
		State:    d.state,
		Device:   d.device,
		DeviceIP: d.deviceIP,
	}
}

func (d *Daemon) handleDiscover() Response {
	d.mu.Lock()
	if d.discovering {
		st := d.state
		d.mu.Unlock()
		return Response{OK: false, State: st, Error: "discovery already in progress"}
	}
	d.discovering = true
	d.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	devices, err := airplay.DiscoverAirPlayDevices(ctx)

	d.mu.Lock()
	defer d.mu.Unlock()
	d.discovering = false

	if err != nil {
		return Response{OK: false, State: d.state, Error: "discovery failed: " + err.Error()}
	}

	d.devices = devices
	return Response{
		OK:      true,
		State:   d.state,
		Devices: toDeviceInfos(devices),
	}
}

func (d *Daemon) handleDevices() Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{
		OK:      true,
		State:   d.state,
		Devices: toDeviceInfos(d.devices),
	}
}

func (d *Daemon) handleConnect(req Request) Response {
	d.mu.Lock()
	if d.state == StateStreaming || d.state == StateConnecting {
		d.mu.Unlock()
		return Response{OK: false, State: d.state, Error: "already connected or connecting"}
	}
	d.state = StateConnecting
	d.mu.Unlock()

	target := req.Target
	port := req.Port
	if port == 0 {
		port = 7000
	}

	// If no target specified, discover and use first device
	if target == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		devices, err := airplay.DiscoverAirPlayDevices(ctx)
		cancel()
		if err != nil || len(devices) == 0 {
			d.mu.Lock()
			d.state = StateIdle
			d.mu.Unlock()
			return Response{OK: false, State: StateIdle, Error: "no devices found"}
		}
		d.mu.Lock()
		d.devices = devices
		d.mu.Unlock()
		target = devices[0].IP
		port = devices[0].Port
	}

	// Launch connection in background goroutine
	connCtx, cancel := context.WithCancel(context.Background())

	d.mu.Lock()
	d.cancelFn = cancel
	d.mu.Unlock()

	go d.connectAndStream(connCtx, target, port, req.Pin)

	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{OK: true, State: d.state, Device: target}
}

func (d *Daemon) connectAndStream(ctx context.Context, target string, port int, pin string) {
	setErr := func(msg string) {
		log.Printf("[daemon] %s", msg)
		d.mu.Lock()
		d.state = StateIdle
		d.device = ""
		d.deviceIP = ""
		d.client = nil
		d.session = nil
		d.capture = nil
		d.cancelFn = nil
		d.mu.Unlock()
	}

	client := airplay.NewAirPlayClient(target, port)
	if err := client.Connect(ctx); err != nil {
		setErr(fmt.Sprintf("connect to %s:%d failed: %v", target, port, err))
		return
	}

	info, err := client.GetInfo()
	if err != nil {
		client.Close()
		setErr(fmt.Sprintf("get info failed: %v", err))
		return
	}

	d.mu.Lock()
	d.device = info.Name
	d.deviceIP = target
	d.mu.Unlock()

	log.Printf("[daemon] connected to %s (model: %s)", info.Name, info.Model)

	// Try saved credentials first
	savedCreds, _ := airplay.LoadCredentials(d.cfg.CredFile)
	if savedCreds != nil {
		pub, priv := savedCreds.Ed25519Keys()
		client.PairingID = savedCreds.PairingID
		client.PairKeys = &airplay.PairKeys{
			Ed25519Public:  pub,
			Ed25519Private: priv,
		}
		if err := client.PairVerify(ctx); err != nil {
			log.Printf("[daemon] pair-verify failed, falling back: %v", err)
			client.Close()
			client = airplay.NewAirPlayClient(target, port)
			if err := client.Connect(ctx); err != nil {
				setErr(fmt.Sprintf("reconnect failed: %v", err))
				return
			}
			if _, err := client.GetInfo(); err != nil {
				setErr(fmt.Sprintf("get info after reconnect failed: %v", err))
				return
			}
			if err := client.Pair(ctx, pin); err != nil {
				setErr(fmt.Sprintf("pairing failed: %v", err))
				return
			}
		}
	} else {
		if err := client.Pair(ctx, pin); err != nil {
			setErr(fmt.Sprintf("pairing failed: %v", err))
			return
		}
	}

	// FairPlay setup
	if err := client.FairPlaySetup(ctx); err != nil {
		log.Printf("[daemon] FairPlay setup failed: %v", err)
		client.Close()
		setErr(fmt.Sprintf("FairPlay setup failed: %v", err))
		return
	}

	streamCfg := airplay.StreamConfig{
		Width:     d.cfg.Width,
		Height:    d.cfg.Height,
		FPS:       d.cfg.FPS,
		Bitrate:   d.cfg.Bitrate,
		NoEncrypt: d.cfg.NoEncrypt,
		DirectKey: d.cfg.DirectKey,
		NoAudio:   d.cfg.NoAudio,
	}
	session, err := client.SetupMirror(ctx, streamCfg)
	if err != nil {
		client.Close()
		setErr(fmt.Sprintf("mirror setup failed: %v", err))
		return
	}

	capCfg := airplay.CaptureConfig{
		Width:   d.cfg.Width,
		Height:  d.cfg.Height,
		FPS:     d.cfg.FPS,
		Bitrate: d.cfg.Bitrate,
		HWAccel: d.cfg.HWAccel,
	}
	var capture *airplay.ScreenCapture
	if d.cfg.TestMode {
		capture, err = airplay.StartTestCapture(ctx, capCfg)
	} else {
		capture, err = airplay.StartCapture(ctx, capCfg)
	}
	if err != nil {
		session.Close()
		client.Close()
		setErr(fmt.Sprintf("capture failed: %v", err))
		return
	}

	d.mu.Lock()
	d.state = StateStreaming
	d.client = client
	d.session = session
	d.capture = capture
	d.mu.Unlock()

	log.Printf("[daemon] streaming to %s", d.device)

	err = session.StreamFrames(ctx, capture, 0)
	if err != nil && ctx.Err() == nil {
		log.Printf("[daemon] stream error: %v", err)
	}

	// Cleanup
	capture.Stop()
	session.Close()
	client.Close()

	d.mu.Lock()
	d.state = StateIdle
	d.device = ""
	d.deviceIP = ""
	d.client = nil
	d.session = nil
	d.capture = nil
	d.cancelFn = nil
	d.mu.Unlock()

	log.Printf("[daemon] stream ended")
}

func (d *Daemon) handleDisconnect() Response {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.state == StateIdle {
		return Response{OK: true, State: StateIdle}
	}

	d.stopLocked()
	return Response{OK: true, State: StateIdle}
}

// stopLocked stops the current session. Must be called with d.mu held.
func (d *Daemon) stopLocked() {
	if d.cancelFn != nil {
		d.cancelFn()
		d.cancelFn = nil
	}
	if d.capture != nil {
		d.capture.Stop()
		d.capture = nil
	}
	if d.session != nil {
		d.session.Close()
		d.session = nil
	}
	if d.client != nil {
		d.client.Close()
		d.client = nil
	}
	d.state = StateIdle
	d.device = ""
	d.deviceIP = ""
}

func toDeviceInfos(devices []airplay.AirPlayDevice) []DeviceInfo {
	infos := make([]DeviceInfo, len(devices))
	for i, d := range devices {
		infos[i] = DeviceInfo{
			Name:  d.Name,
			Model: d.Model,
			IP:    d.IP,
			Port:  d.Port,
		}
	}
	return infos
}
