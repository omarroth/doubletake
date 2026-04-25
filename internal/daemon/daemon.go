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

// StreamInfo describes one active (or connecting) mirror stream.
type StreamInfo struct {
	Device     string `json:"device"`
	DeviceIP   string `json:"device_ip"`
	State      State  `json:"state"`
	HasAudio   bool   `json:"has_audio"`
	AudioMuted bool   `json:"audio_muted"`
}

// Response is returned to the caller for every request.
type Response struct {
	OK         bool         `json:"ok"`
	State      State        `json:"state"`
	Device     string       `json:"device,omitempty"`
	DeviceIP   string       `json:"device_ip,omitempty"`
	HasAudio   bool         `json:"has_audio"`
	AudioMuted bool         `json:"audio_muted"`
	NeedsPIN   bool         `json:"needs_pin,omitempty"`
	Error      string       `json:"error,omitempty"`
	Devices    []DeviceInfo `json:"devices,omitempty"`
	Streams    []StreamInfo `json:"streams,omitempty"`
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

// activeStream tracks the state of a single mirroring session to one receiver.
type activeStream struct {
	device     string // friendly name
	deviceIP   string
	deviceID   string
	state      State
	audioMuted bool
	session    *airplay.MirrorSession
	client     *airplay.AirPlayClient
	sink       *airplay.BroadcastSink // fan-out video sink (nil when no broadcast)
	cancelFn   context.CancelFunc
}

// Daemon manages a long-running doubletake service.
type Daemon struct {
	cfg            Config
	mu             sync.Mutex
	devices        []airplay.AirPlayDevice
	deviceLastSeen map[string]time.Time // keyed by IP
	credStore      *airplay.CredentialStore

	// Multi-stream state
	streams       map[string]*activeStream  // keyed by target IP
	broadcast     *airplay.BroadcastCapture // shared video fan-out; nil when no streams active
	capture       *airplay.ScreenCapture    // underlying screen capture
	captureCancel context.CancelFunc        // cancellation for shared capture context

	// PIN-waiting state (at most one device waits for a PIN at a time)
	pendingTarget string
	pendingPort   int

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
		deviceLastSeen: make(map[string]time.Time),
		streams:        make(map[string]*activeStream),
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

// Shutdown stops any active sessions and cleans up the socket.
func (d *Daemon) Shutdown() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.discoverCancel != nil {
		d.discoverCancel()
		d.discoverCancel = nil
	}
	d.stopAllLocked()
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
		return d.handleDisconnect(req)
	case "mute":
		return d.handleSetMute(req, true)
	case "unmute":
		return d.handleSetMute(req, false)
	default:
		return Response{OK: false, Error: "unknown command: " + req.Cmd}
	}
}

// overallState returns the aggregate daemon state based on active streams.
// Must be called with d.mu held.
func (d *Daemon) overallStateLocked() State {
	if d.pendingTarget != "" {
		return StatePINRequired
	}
	hasStreaming := false
	hasConnecting := false
	for _, s := range d.streams {
		switch s.state {
		case StateStreaming:
			hasStreaming = true
		case StateConnecting:
			hasConnecting = true
		}
	}
	if hasStreaming {
		return StateStreaming
	}
	if hasConnecting {
		return StateConnecting
	}
	return StateIdle
}

func (d *Daemon) handleStatus() Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.statusResponseLocked(true, "")
}

func (d *Daemon) statusResponseLocked(ok bool, errMsg string) Response {
	streams := make([]StreamInfo, 0, len(d.streams))
	for _, s := range d.streams {
		streams = append(streams, StreamInfo{
			Device:     s.device,
			DeviceIP:   s.deviceIP,
			State:      s.state,
			HasAudio:   s.session != nil && s.session.HasAudio(),
			AudioMuted: s.audioMuted,
		})
	}
	// Sort for deterministic output
	sort.Slice(streams, func(i, j int) bool {
		return streams[i].DeviceIP < streams[j].DeviceIP
	})

	overall := d.overallStateLocked()

	// Populate legacy single-stream fields using the first streaming entry for
	// backwards-compatibility with existing clients.
	var device, deviceIP string
	var hasAudio, audioMuted bool
	for _, s := range streams {
		if s.State == StateStreaming {
			device = s.Device
			deviceIP = s.DeviceIP
			hasAudio = s.HasAudio
			audioMuted = s.AudioMuted
			break
		}
	}

	return Response{
		OK:         ok,
		State:      overall,
		Device:     device,
		DeviceIP:   deviceIP,
		HasAudio:   hasAudio,
		AudioMuted: audioMuted,
		NeedsPIN:   overall == StatePINRequired,
		Error:      errMsg,
		Streams:    streams,
	}
}

func (d *Daemon) handleDiscover() Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{
		OK:      true,
		State:   d.overallStateLocked(),
		Devices: toDeviceInfos(d.devices),
	}
}

func (d *Daemon) handleDevices() Response {
	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{
		OK:      true,
		State:   d.overallStateLocked(),
		Devices: toDeviceInfos(d.devices),
	}
}

func (d *Daemon) handleConnect(req Request) Response {
	d.mu.Lock()

	// If we're waiting for a PIN and one was provided, resume that pending stream.
	if d.pendingTarget != "" && req.Pin != "" {
		target := d.pendingTarget
		port := d.pendingPort
		d.pendingTarget = ""
		d.pendingPort = 0

		// Register a connecting entry so state is visible
		d.streams[target] = &activeStream{
			deviceIP: target,
			state:    StateConnecting,
		}
		d.mu.Unlock()

		connCtx, cancel := context.WithCancel(context.Background())
		d.mu.Lock()
		d.streams[target].cancelFn = cancel
		d.mu.Unlock()

		go d.connectAndStream(connCtx, target, port, req.Pin)

		d.mu.Lock()
		defer d.mu.Unlock()
		return Response{OK: true, State: d.overallStateLocked(), Device: target}
	}

	// Reject a duplicate connection to the same target.
	target := req.Target
	if target != "" {
		if existing, ok := d.streams[target]; ok {
			st := existing.state
			d.mu.Unlock()
			return Response{OK: false, State: st, Error: "already connected or connecting to " + target}
		}
	}

	// If no target specified, use first cached device not already streaming.
	port := req.Port
	if target == "" {
		target, port = d.pickFreeDeviceLocked(port)
		if target == "" {
			d.mu.Unlock()
			return Response{OK: false, State: d.overallStateLocked(), Error: "no available devices found"}
		}
	}

	// Look up the discovered port for this target if not explicitly provided.
	if port == 0 {
		for _, dev := range d.devices {
			if dev.IP == target {
				port = dev.Port
				break
			}
		}
	}
	if port == 0 {
		port = 7000
	}

	// Register a connecting placeholder.
	entry := &activeStream{
		deviceIP: target,
		state:    StateConnecting,
	}
	d.streams[target] = entry
	d.mu.Unlock()

	connCtx, cancel := context.WithCancel(context.Background())
	d.mu.Lock()
	entry.cancelFn = cancel
	d.mu.Unlock()

	go d.connectAndStream(connCtx, target, port, req.Pin)

	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{OK: true, State: d.overallStateLocked(), Device: target}
}

// pickFreeDeviceLocked returns the first discovered device not already in d.streams.
// Must be called with d.mu held.
func (d *Daemon) pickFreeDeviceLocked(preferredPort int) (string, int) {
	for _, dev := range d.devices {
		if _, inUse := d.streams[dev.IP]; !inUse {
			p := dev.Port
			if preferredPort != 0 {
				p = preferredPort
			}
			return dev.IP, p
		}
	}
	return "", 0
}

func (d *Daemon) connectAndStream(ctx context.Context, target string, port int, pin string) {
	// removeStream cleans up this stream's entry and tears down the shared broadcast
	// if no other streams remain.
	removeStream := func(msg string) {
		if msg != "" {
			log.Printf("[daemon] %s", msg)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		d.removeStreamLocked(target)
	}

	client := airplay.NewAirPlayClient(target, port)
	if err := client.Connect(ctx); err != nil {
		removeStream(fmt.Sprintf("connect to %s:%d failed: %v", target, port, err))
		return
	}

	info, err := client.GetInfo()
	if err != nil {
		client.Close()
		removeStream(fmt.Sprintf("get info failed: %v", err))
		return
	}

	deviceID := info.DeviceID
	savedCreds := d.credStore.Lookup(deviceID)
	screenCastRestoreToken := ""
	if savedCreds != nil {
		screenCastRestoreToken = savedCreds.RestoreToken
	}
	d.mu.Lock()
	if entry, ok := d.streams[target]; ok {
		entry.device = info.Name
		entry.deviceID = deviceID
	}
	d.mu.Unlock()

	log.Printf("[daemon] connected to %s (model: %s, deviceID: %s)", info.Name, info.Model, deviceID)

	// Pairing
	paired := false
	if pin != "" {
		if err := client.Pair(ctx, pin); err != nil {
			client.Close()
			removeStream(fmt.Sprintf("pairing failed: %v", err))
			return
		}
		paired = true
		if client.PairKeys != nil {
			if err := d.credStore.Save(deviceID, client.PairingID,
				client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private); err != nil {
				log.Printf("[daemon] warning: failed to save credentials: %v", err)
			} else {
				log.Printf("[daemon] credentials saved for %s (deviceID: %s)", info.Name, deviceID)
			}
		}
	}

	if !paired && savedCreds != nil && savedCreds.HasPairingCredentials() {
		pub, priv := savedCreds.Ed25519Keys()
		client.PairingID = savedCreds.PairingID
		client.PairKeys = &airplay.PairKeys{
			Ed25519Public:  pub,
			Ed25519Private: priv,
		}
		if err := client.PairVerify(ctx); err != nil {
			log.Printf("[daemon] pair-verify with saved creds failed: %v, trying transient pairing", err)
			client.Close()
			client = airplay.NewAirPlayClient(target, port)
			if err := client.Connect(ctx); err != nil {
				removeStream(fmt.Sprintf("reconnect failed: %v", err))
				return
			}
			if _, err := client.GetInfo(); err != nil {
				removeStream(fmt.Sprintf("get info after reconnect failed: %v", err))
				return
			}
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
	} else if !paired && savedCreds != nil {
		log.Printf("[daemon] saved credentials have no usable pair-verify keys, skipping")
	}

	if !paired {
		if err := client.Pair(ctx, ""); err != nil {
			log.Printf("[daemon] transient pairing failed: %v", err)
			if err := client.StartPINDisplay(); err != nil {
				log.Printf("[daemon] start PIN display failed: %v", err)
			}
			client.Close()
			d.mu.Lock()
			// Remove the connecting placeholder and record the pending PIN state.
			delete(d.streams, target)
			d.pendingTarget = target
			d.pendingPort = port
			d.mu.Unlock()
			log.Printf("[daemon] PIN required for %s — waiting for user input", info.Name)
			return
		}
		paired = true
		log.Printf("[daemon] transient pairing succeeded for %s", info.Name)
	}
	_ = paired

	// FairPlay setup
	if err := client.FairPlaySetup(ctx); err != nil {
		client.Close()
		removeStream(fmt.Sprintf("FairPlay setup failed: %v", err))
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
		removeStream(fmt.Sprintf("mirror setup failed: %v", err))
		return
	}

	// Obtain or reuse the shared screen capture + broadcast fan-out.
	sink, err := d.getOrStartBroadcastLocked(screenCastRestoreToken, deviceID)
	if err != nil {
		session.Close()
		client.Close()
		removeStream(fmt.Sprintf("capture failed: %v", err))
		return
	}

	d.mu.Lock()
	entry, ok := d.streams[target]
	if !ok {
		// Stream was cancelled while we were setting up
		d.mu.Unlock()
		sink.Close()
		session.Close()
		client.Close()
		d.mu.Lock()
		d.maybeStopBroadcastLocked()
		d.mu.Unlock()
		return
	}
	entry.state = StateStreaming
	entry.session = session
	entry.client = client
	entry.sink = sink
	entry.audioMuted = false
	d.mu.Unlock()

	log.Printf("[daemon] streaming to %s (%s)", info.Name, target)

	// Start audio for this stream independently.
	if !d.cfg.NoAudio && session.HasAudio() {
		audioCapture, audioErr := airplay.StartAudioCapture(ctx, d.cfg.TestMode)
		if audioErr != nil {
			log.Printf("[daemon] audio capture failed: %v (continuing without audio)", audioErr)
		} else {
			defer audioCapture.Stop()
			go func() {
				if aerr := session.StreamAudio(ctx, audioCapture, session.AudioStream()); aerr != nil && ctx.Err() == nil {
					log.Printf("[daemon] audio streaming error: %v", aerr)
				}
			}()
			log.Printf("[daemon] audio capture started for %s", target)
		}
	}

	streamErr := session.StreamFrames(ctx, sink.AsCapture(), 0)
	if streamErr != nil && ctx.Err() == nil {
		log.Printf("[daemon] stream error for %s: %v", target, streamErr)
	}

	// Cleanup this stream.
	sink.Close()
	session.Close()
	client.Close()

	d.mu.Lock()
	d.removeStreamLocked(target)
	d.mu.Unlock()

	log.Printf("[daemon] stream ended for %s", target)
}

// getOrStartBroadcastLocked ensures a shared BroadcastCapture is running and
// returns a new sink registered with it. If no capture is running, it starts one.
// Must NOT be called with d.mu held.
func (d *Daemon) getOrStartBroadcastLocked(restoreToken, deviceID string) (*airplay.BroadcastSink, error) {
	d.mu.Lock()
	bc := d.broadcast
	d.mu.Unlock()

	if bc != nil {
		// Capture already running — add a new sink.
		sink := bc.AddSink()
		return sink, nil
	}

	// Start a fresh screen capture.
	capCfg := airplay.CaptureConfig{
		Width:        d.cfg.Width,
		Height:       d.cfg.Height,
		FPS:          d.cfg.FPS,
		Bitrate:      d.cfg.Bitrate,
		HWAccel:      d.cfg.HWAccel,
		RestoreToken: restoreToken,
	}
	if deviceID != "" {
		capCfg.SaveRestoreToken = func(token string) error {
			return d.credStore.SaveRestoreToken(deviceID, token)
		}
	}

	var (
		capture *airplay.ScreenCapture
		err     error
	)
	captureCtx, captureCancel := context.WithCancel(context.Background())
	if d.cfg.TestMode {
		capture, err = airplay.StartTestCapture(captureCtx, capCfg)
	} else {
		capture, err = airplay.StartCapture(captureCtx, capCfg)
	}
	if err != nil {
		captureCancel()
		return nil, err
	}

	newBC := airplay.NewBroadcastCapture(capture)
	sink := newBC.AddSink()

	d.mu.Lock()
	// Double-check: another goroutine might have started capture concurrently.
	if d.broadcast != nil {
		d.mu.Unlock()
		// Discard the one we just started and use the existing one.
		captureCancel()
		capture.Stop()
		return d.broadcast.AddSink(), nil
	}
	d.broadcast = newBC
	d.capture = capture
	d.captureCancel = captureCancel
	d.mu.Unlock()

	go func() {
		if runErr := newBC.Run(); runErr != nil && runErr.Error() != "EOF" {
			log.Printf("[daemon] broadcast capture error: %v", runErr)
		}
		// When the capture ends, stop all active streams.
		d.mu.Lock()
		d.stopAllLocked()
		d.mu.Unlock()
	}()

	return sink, nil
}

// removeStreamLocked removes a single stream entry and tears down the shared
// capture if no other streams are left. Must be called with d.mu held.
func (d *Daemon) removeStreamLocked(target string) {
	entry, ok := d.streams[target]
	if !ok {
		return
	}
	if entry.cancelFn != nil {
		entry.cancelFn()
	}
	delete(d.streams, target)
	d.maybeStopBroadcastLocked()
}

// maybeStopBroadcastLocked stops the shared capture if no active streams remain.
// Must be called with d.mu held.
func (d *Daemon) maybeStopBroadcastLocked() {
	if len(d.streams) > 0 {
		return
	}
	if d.captureCancel != nil {
		d.captureCancel()
		d.captureCancel = nil
	}
	if d.capture != nil {
		d.capture.Stop()
		d.capture = nil
	}
	d.broadcast = nil
}

func (d *Daemon) handleDisconnect(req Request) Response {
	d.mu.Lock()
	defer d.mu.Unlock()

	// If a target is specified, disconnect only that stream.
	if req.Target != "" {
		entry, ok := d.streams[req.Target]
		if !ok {
			return Response{OK: false, State: d.overallStateLocked(), Error: "no active stream to " + req.Target}
		}
		if entry.cancelFn != nil {
			entry.cancelFn()
		}
		if entry.sink != nil {
			entry.sink.Close()
		}
		if entry.session != nil {
			entry.session.Close()
		}
		if entry.client != nil {
			entry.client.Close()
		}
		delete(d.streams, req.Target)
		d.maybeStopBroadcastLocked()
		return Response{OK: true, State: d.overallStateLocked()}
	}

	// Also clear any pending PIN state.
	d.pendingTarget = ""
	d.pendingPort = 0

	// Disconnect all.
	d.stopAllLocked()
	return Response{OK: true, State: StateIdle}
}

func (d *Daemon) handleSetMute(req Request, muted bool) Response {
	d.mu.Lock()

	var targets []*activeStream
	if req.Target != "" {
		entry, ok := d.streams[req.Target]
		if !ok {
			d.mu.Unlock()
			return Response{OK: false, State: d.overallStateLocked(), Error: "no active stream to " + req.Target}
		}
		targets = []*activeStream{entry}
	} else {
		for _, s := range d.streams {
			if s.state == StateStreaming {
				targets = append(targets, s)
			}
		}
	}

	if len(targets) == 0 {
		resp := d.statusResponseLocked(false, "not currently streaming")
		d.mu.Unlock()
		return resp
	}

	sessions := make([]*airplay.MirrorSession, 0, len(targets))
	for _, t := range targets {
		if t.session != nil && (d.cfg.NoAudio || t.session.HasAudio()) {
			sessions = append(sessions, t.session)
		}
	}
	d.mu.Unlock()

	var lastErr error
	for _, s := range sessions {
		if err := s.SetAudioMuted(muted); err != nil {
			lastErr = err
		}
	}
	if lastErr != nil {
		d.mu.Lock()
		defer d.mu.Unlock()
		return d.statusResponseLocked(false, "failed to update audio mute state: "+lastErr.Error())
	}

	d.mu.Lock()
	for _, t := range targets {
		t.audioMuted = muted
	}
	defer d.mu.Unlock()
	return d.statusResponseLocked(true, "")
}

// stopAllLocked stops all active streams and tears down the capture.
// Must be called with d.mu held.
func (d *Daemon) stopAllLocked() {
	for target, entry := range d.streams {
		if entry.cancelFn != nil {
			entry.cancelFn()
		}
		if entry.sink != nil {
			entry.sink.Close()
		}
		if entry.session != nil {
			entry.session.Close()
		}
		if entry.client != nil {
			entry.client.Close()
		}
		delete(d.streams, target)
	}
	if d.capture != nil {
		d.capture.Stop()
		d.capture = nil
	}
	if d.captureCancel != nil {
		d.captureCancel()
		d.captureCancel = nil
	}
	d.broadcast = nil
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
