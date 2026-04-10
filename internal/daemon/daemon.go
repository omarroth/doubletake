package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"doubletake/internal/airplay"
)

// State represents the daemon's current lifecycle state.
type State string

const (
	StateIdle        State = "idle"
	StateDiscovering State = "discovering"
	StateConnecting  State = "connecting"
	StateStreaming   State = "streaming"
	StatePINRequired State = "pin_required"
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
	NeedsPIN bool         `json:"needs_pin,omitempty"`
	Error    string       `json:"error,omitempty"`
	Devices  []DeviceInfo `json:"devices,omitempty"`
}

// DeviceInfo is a simplified view of a discovered AirPlay device.
type DeviceInfo struct {
	Name     string `json:"name"`
	Model    string `json:"model"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	DeviceID string `json:"device_id"`
}

// Config holds daemon configuration.
type Config struct {
	SocketPath  string
	CredFile    string
	CredBackend string
	Width       int
	Height      int
	FPS         int
	Bitrate     int
	HWAccel     string
	Debug       bool
	TestMode    bool
	NoEncrypt   bool
	DirectKey   bool
	NoAudio     bool
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
	cfg            Config
	mu             sync.Mutex
	state          State
	devices        []airplay.AirPlayDevice
	deviceLastSeen map[string]time.Time // keyed by IP
	credStore      *airplay.CredentialStore
	client         *airplay.AirPlayClient
	session        *airplay.MirrorSession
	capture        *airplay.ScreenCapture
	device         string // name of connected device
	deviceIP       string // IP of connected device
	deviceIDStr    string // DeviceID of connected/pending device
	pendingTarget  string // target IP waiting for PIN
	pendingPort    int    // port waiting for PIN
	cancelFn       context.CancelFunc
	discoverCancel context.CancelFunc
	listener       net.Listener
}

// New creates a new Daemon with the given configuration.
func New(cfg Config) (*Daemon, error) {
	var cs *airplay.CredentialStore
	switch cfg.CredBackend {
	case "keyring":
		kb, err := airplay.NewKeyringBackend()
		if err != nil {
			return nil, fmt.Errorf("keyring backend: %w", err)
		}
		cs = airplay.NewCredentialStoreWithBackend(kb)
	default:
		credPath := cfg.CredFile
		if credPath == "" {
			credPath = airplay.DefaultCredentialsPath()
		}
		var err error
		cs, err = airplay.NewCredentialStore(credPath)
		if err != nil {
			return nil, fmt.Errorf("load credentials: %w", err)
		}
	}

	return &Daemon{
		cfg:            cfg,
		state:          StateIdle,
		deviceLastSeen: make(map[string]time.Time),
		credStore:      cs,
	}, nil
}

// Run starts the daemon control socket and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	airplay.DebugMode = d.cfg.Debug

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

	// Start continuous mDNS discovery in the background
	discoverCtx, discoverCancel := context.WithCancel(ctx)
	d.discoverCancel = discoverCancel
	go d.backgroundDiscover(discoverCtx)

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
	if d.discoverCancel != nil {
		d.discoverCancel()
		d.discoverCancel = nil
	}
	d.stopLocked()
	if d.listener != nil {
		d.listener.Close()
	}
	os.Remove(d.cfg.SocketPath)
}

// backgroundDiscover continuously browses mDNS for AirPlay devices.
// Each scan runs for 5 seconds. Devices not seen for >30 seconds are removed.
func (d *Daemon) backgroundDiscover(ctx context.Context) {
	const (
		scanDuration = 5 * time.Second
		deviceTTL    = 30 * time.Second
	)
	log.Printf("[daemon] starting continuous mDNS discovery")
	for {
		browseCtx, cancel := context.WithTimeout(ctx, scanDuration)
		found, err := airplay.DiscoverAirPlayDevices(browseCtx)
		cancel()

		if ctx.Err() != nil {
			return
		}

		now := time.Now()
		d.mu.Lock()
		if err == nil {
			// Build a map of currently known devices by IP for quick lookup
			known := make(map[string]airplay.AirPlayDevice, len(d.devices))
			for _, dev := range d.devices {
				known[dev.IP] = dev
			}

			// Update last-seen timestamps and merge new devices
			for _, dev := range found {
				d.deviceLastSeen[dev.IP] = now
				known[dev.IP] = dev // add or update
			}

			// Rebuild device list, dropping anything older than TTL
			devices := make([]airplay.AirPlayDevice, 0, len(known))
			for ip, dev := range known {
				if now.Sub(d.deviceLastSeen[ip]) <= deviceTTL {
					devices = append(devices, dev)
				} else {
					delete(d.deviceLastSeen, ip)
				}
			}
			d.devices = devices
			sort.Slice(d.devices, func(i, j int) bool {
				return d.devices[i].IP < d.devices[j].IP
			})
		} else {
			log.Printf("[daemon] mDNS browse error: %v", err)
		}
		d.mu.Unlock()

		// Next scan starts immediately (no extra wait — the 5s scan is the cadence)
		if ctx.Err() != nil {
			return
		}
	}
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
		NeedsPIN: d.state == StatePINRequired,
	}
}

func (d *Daemon) handleDiscover() Response {
	// Return the continuously-updated device list
	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{
		OK:      true,
		State:   d.state,
		Devices: toDeviceInfos(d.devices),
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

	// If we're waiting for a PIN and one was provided, resume
	if d.state == StatePINRequired && req.Pin != "" {
		target := d.pendingTarget
		port := d.pendingPort
		d.state = StateConnecting
		d.mu.Unlock()

		connCtx, cancel := context.WithCancel(context.Background())
		d.mu.Lock()
		d.cancelFn = cancel
		d.mu.Unlock()

		go d.connectAndStream(connCtx, target, port, req.Pin)

		d.mu.Lock()
		defer d.mu.Unlock()
		return Response{OK: true, State: d.state, Device: target}
	}

	if d.state == StateStreaming || d.state == StateConnecting || d.state == StatePINRequired {
		st := d.state
		d.mu.Unlock()
		return Response{OK: false, State: st, Error: "already connected or connecting"}
	}
	d.state = StateConnecting
	d.mu.Unlock()

	target := req.Target
	port := req.Port

	// If no target specified, use first cached device
	if target == "" {
		d.mu.Lock()
		if len(d.devices) == 0 {
			d.state = StateIdle
			d.mu.Unlock()
			return Response{OK: false, State: StateIdle, Error: "no devices found"}
		}
		target = d.devices[0].IP
		port = d.devices[0].Port
		d.mu.Unlock()
	}

	// Look up the discovered port for this target if not explicitly provided.
	if port == 0 {
		d.mu.Lock()
		for _, dev := range d.devices {
			if dev.IP == target {
				port = dev.Port
				break
			}
		}
		d.mu.Unlock()
	}
	if port == 0 {
		port = 7000
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
		d.deviceIDStr = ""
		d.pendingTarget = ""
		d.pendingPort = 0
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

	deviceID := info.DeviceID
	savedCreds := d.credStore.Lookup(deviceID)
	screenCastRestoreToken := ""
	if savedCreds != nil {
		screenCastRestoreToken = savedCreds.RestoreToken
	}
	d.mu.Lock()
	d.device = info.Name
	d.deviceIP = target
	d.deviceIDStr = deviceID
	d.mu.Unlock()

	log.Printf("[daemon] connected to %s (model: %s, deviceID: %s)", info.Name, info.Model, deviceID)

	// If a PIN was provided, skip credential lookup and go straight to PIN pairing.
	// The PIN was displayed during the previous connection attempt; trying pair-verify
	// or transient pairing first would reset the device's pairing state and invalidate it.
	paired := false
	if pin != "" {
		if err := client.Pair(ctx, pin); err != nil {
			setErr(fmt.Sprintf("pairing failed: %v", err))
			return
		}
		paired = true
		// Save the new credentials
		if client.PairKeys != nil {
			if err := d.credStore.Save(deviceID, client.PairingID,
				client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private); err != nil {
				log.Printf("[daemon] warning: failed to save credentials: %v", err)
			} else {
				log.Printf("[daemon] credentials saved for %s (deviceID: %s)", info.Name, deviceID)
			}
		}
	}

	// Try saved credentials by DeviceID
	if !paired {
		if savedCreds != nil && savedCreds.HasPairingCredentials() {
			pub, priv := savedCreds.Ed25519Keys()
			client.PairingID = savedCreds.PairingID
			client.PairKeys = &airplay.PairKeys{
				Ed25519Public:  pub,
				Ed25519Private: priv,
			}
			if err := client.PairVerify(ctx); err != nil {
				log.Printf("[daemon] pair-verify with saved creds failed: %v, trying transient pairing", err)
				// Reconnect for fresh pairing attempt
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
				// Try transient (no-PIN) pairing as fallback
				if err := client.Pair(ctx, ""); err != nil {
					log.Printf("[daemon] transient pairing also failed: %v", err)
				} else {
					paired = true
					log.Printf("[daemon] transient pairing succeeded for %s", info.Name)
				}
			} else {
				paired = true
				log.Printf("[daemon] pair-verify succeeded for %s", info.Name)
			}
		} else if savedCreds != nil {
			log.Printf("[daemon] saved credentials have no usable pair-verify keys, skipping")
		}
	}

	// If still not paired, try transient pairing (no saved creds)
	if !paired {
		if err := client.Pair(ctx, ""); err != nil {
			log.Printf("[daemon] transient pairing failed: %v", err)
			// Last resort: ask for PIN
			if err := client.StartPINDisplay(); err != nil {
				log.Printf("[daemon] start PIN display failed: %v", err)
			}
			client.Close()
			d.mu.Lock()
			d.state = StatePINRequired
			d.pendingTarget = target
			d.pendingPort = port
			d.cancelFn = nil
			d.mu.Unlock()
			log.Printf("[daemon] PIN required for %s — waiting for user input", info.Name)
			return
		}
		paired = true
		log.Printf("[daemon] transient pairing succeeded for %s", info.Name)
	}

	// FairPlay setup
	if err := client.FairPlaySetup(ctx); err != nil {
		if os.Getenv("ALLOW_FAIRPLAY_FALLBACK") != "" {
			log.Printf("[daemon] FairPlay setup failed (fallback enabled): %v", err)
		} else {
			log.Printf("[daemon] FairPlay setup failed: %v", err)
			client.Close()
			setErr(fmt.Sprintf("FairPlay setup failed: %v", err))
			return
		}
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
		Width:        d.cfg.Width,
		Height:       d.cfg.Height,
		FPS:          d.cfg.FPS,
		Bitrate:      d.cfg.Bitrate,
		HWAccel:      d.cfg.HWAccel,
		RestoreToken: screenCastRestoreToken,
	}
	if deviceID != "" {
		capCfg.SaveRestoreToken = func(token string) error {
			return d.credStore.SaveRestoreToken(deviceID, token)
		}
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
	d.deviceIDStr = ""
	d.pendingTarget = ""
	d.pendingPort = 0
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
	d.deviceIDStr = ""
	d.pendingTarget = ""
	d.pendingPort = 0
}

func toDeviceInfos(devices []airplay.AirPlayDevice) []DeviceInfo {
	infos := make([]DeviceInfo, len(devices))
	for i, d := range devices {
		infos[i] = DeviceInfo{
			Name:     d.Name,
			Model:    d.Model,
			IP:       d.IP,
			Port:     d.Port,
			DeviceID: d.DeviceID,
		}
	}
	return infos
}
