package daemon

import (
	"context"
	"encoding/json"
	"errors"
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

// CredentialKind tells a control client which single authentication value the
// receiver is waiting for. StatePINRequired is retained as the wire-compatible
// waiting state; new clients should use CredentialKind to choose their prompt.
type CredentialKind string

const (
	CredentialKindPIN      CredentialKind = "pin"
	CredentialKindPassword CredentialKind = "password"
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
	Device         string         `json:"device"`
	DeviceIP       string         `json:"device_ip"`
	State          State          `json:"state"`
	HasAudio       bool           `json:"has_audio"`
	AudioMuted     bool           `json:"audio_muted"`
	CredentialKind CredentialKind `json:"credential_kind,omitempty"`
}

// Response is returned to the caller for every request.
type Response struct {
	OK         bool   `json:"ok"`
	State      State  `json:"state"`
	Device     string `json:"device,omitempty"`
	DeviceIP   string `json:"device_ip,omitempty"`
	HasAudio   bool   `json:"has_audio"`
	AudioMuted bool   `json:"audio_muted"`
	// NeedsPIN is retained for older clients and is true only for an on-screen
	// PIN. NeedsCredential and CredentialKind distinguish configured passwords.
	NeedsPIN        bool           `json:"needs_pin,omitempty"`
	NeedsCredential bool           `json:"needs_credential,omitempty"`
	CredentialKind  CredentialKind `json:"credential_kind,omitempty"`
	Error           string         `json:"error,omitempty"`
	Devices         []DeviceInfo   `json:"devices,omitempty"`
	Streams         []StreamInfo   `json:"streams,omitempty"`
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
	FPS         int
	Bitrate     int
	PortMin     int // inclusive local UDP port bound; zero with PortMax means ephemeral
	PortMax     int // inclusive local UDP port bound; zero with PortMin means ephemeral
	HWAccel     string
	Debug       bool
	TestMode    bool
	NoEncrypt   bool
	DirectKey   bool
	NoAudio     bool
	ShowCursor  bool
	Code        string // default pairing/Digest credential; request Pin overrides it
}

func (d *Daemon) mirrorStreamConfig() airplay.StreamConfig {
	return airplay.StreamConfig{
		FPS:       d.cfg.FPS,
		Bitrate:   d.cfg.Bitrate,
		NoEncrypt: d.cfg.NoEncrypt,
		DirectKey: d.cfg.DirectKey,
		NoAudio:   d.cfg.NoAudio,
		PortMin:   d.cfg.PortMin,
		PortMax:   d.cfg.PortMax,
	}
}

func validatePortRange(portMin, portMax int) error {
	if portMin == 0 && portMax == 0 {
		return nil
	}
	if portMin < 1 || portMax > 65535 || portMin > portMax {
		return fmt.Errorf("range %d-%d out of bounds (1-65535, min<=max)", portMin, portMax)
	}
	if portMax-portMin+1 < 3 {
		return fmt.Errorf("range %d-%d too small; need 3 consecutive UDP ports", portMin, portMax)
	}
	return nil
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
	device         string // friendly name
	deviceIP       string
	deviceID       string
	state          State
	audioMuted     bool
	session        *airplay.MirrorSession
	client         *airplay.AirPlayClient
	sink           *airplay.BroadcastSink // fan-out video sink (nil when no broadcast)
	cancelFn       context.CancelFunc
	credentialCh   chan string
	credentialKind CredentialKind
}

// Daemon manages a long-running doubletake service.
type Daemon struct {
	cfg            Config
	mu             sync.Mutex
	devices        []airplay.AirPlayDevice
	deviceLastSeen map[string]time.Time // keyed by IP
	credStore      *airplay.CredentialStore

	// Multi-stream state
	streams         map[string]*activeStream  // keyed by target IP
	broadcast       *airplay.BroadcastCapture // shared video fan-out; nil when no streams active
	capture         *airplay.ScreenCapture    // underlying screen capture
	captureCancel   context.CancelFunc        // cancellation for starting/running shared capture
	captureStartMu  sync.Mutex                // serializes creation of the shared capture
	lastError       string                    // most recent asynchronous stream failure
	lastErrorTarget string                    // target associated with lastError; empty for capture-wide errors

	discoverCancel context.CancelFunc
	listener       net.Listener
}

// New creates a new Daemon with the given configuration.
func New(cfg Config) (*Daemon, error) {
	if err := airplay.ValidateHWAccel(cfg.HWAccel); err != nil {
		return nil, fmt.Errorf("hwaccel: %w", err)
	}
	if err := validatePortRange(cfg.PortMin, cfg.PortMax); err != nil {
		return nil, fmt.Errorf("port range: %w", err)
	}
	if cfg.HWAccel == "" {
		cfg.HWAccel = "auto"
	}
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
	hasStreaming := false
	hasConnecting := false
	for _, s := range d.streams {
		switch s.state {
		case StatePINRequired:
			return StatePINRequired
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
	if errMsg == "" {
		errMsg = d.lastError
	}
	streams := make([]StreamInfo, 0, len(d.streams))
	for _, s := range d.streams {
		streams = append(streams, StreamInfo{
			Device:         s.device,
			DeviceIP:       s.deviceIP,
			State:          s.state,
			HasAudio:       s.session != nil && s.session.HasAudio(),
			AudioMuted:     s.audioMuted,
			CredentialKind: waitingCredentialKind(s),
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
	var credentialKind CredentialKind
	for _, s := range streams {
		if s.State == StateStreaming {
			device = s.Device
			deviceIP = s.DeviceIP
			hasAudio = s.HasAudio
			audioMuted = s.AudioMuted
			break
		}
	}
	// The top-level fields can describe only one prompt. Select the first pending
	// stream from the already sorted list for deterministic legacy behavior; all
	// prompts remain available in Streams for multi-target control clients.
	for _, stream := range streams {
		if stream.State == StatePINRequired {
			device = stream.Device
			deviceIP = stream.DeviceIP
			credentialKind = stream.CredentialKind
			break
		}
	}

	return Response{
		OK:              ok,
		State:           overall,
		Device:          device,
		DeviceIP:        deviceIP,
		HasAudio:        hasAudio,
		AudioMuted:      audioMuted,
		NeedsPIN:        credentialKind == CredentialKindPIN,
		NeedsCredential: credentialKind != "",
		CredentialKind:  credentialKind,
		Error:           errMsg,
		Streams:         streams,
	}
}

func waitingCredentialKind(stream *activeStream) CredentialKind {
	if stream == nil || stream.state != StatePINRequired {
		return ""
	}
	if stream.credentialKind != "" {
		return stream.credentialKind
	}
	// Entries created by older clients/tests predate CredentialKind and used the
	// waiting state exclusively for an on-screen PIN.
	return CredentialKindPIN
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

	// Resume a pending authentication session without replacing its AirPlay
	// client. A target is required only when more than one receiver is waiting;
	// targetless submissions remain compatible with older control clients.
	if req.Pin != "" {
		target := req.Target
		if target == "" {
			pending := d.pendingCredentialTargetsLocked()
			switch len(pending) {
			case 0:
				state := d.overallStateLocked()
				d.mu.Unlock()
				return Response{OK: false, State: state, Error: "no device is waiting for a credential"}
			case 1:
				target = pending[0]
			default:
				state := d.overallStateLocked()
				d.mu.Unlock()
				return Response{OK: false, State: state, Error: "multiple devices are waiting for credentials; specify a target"}
			}
		}

		if entry, ok := d.streams[target]; ok {
			if entry.state != StatePINRequired || entry.credentialCh == nil {
				state := d.overallStateLocked()
				d.mu.Unlock()
				return Response{OK: false, State: state, Error: "credential prompt is not ready for " + target}
			}
			entry.state = StateConnecting
			entry.credentialKind = ""
			d.clearLastErrorForTargetLocked(target)
			// credentialCh is buffered and each pending session can be claimed only once.
			entry.credentialCh <- req.Pin
			state := d.overallStateLocked()
			d.mu.Unlock()
			return Response{OK: true, State: state, Device: target, DeviceIP: target}
		}
		// No existing entry means this is a new targeted connection with a
		// credential supplied up front; continue into normal connection setup.
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
			state := d.overallStateLocked()
			d.mu.Unlock()
			return Response{OK: false, State: state, Error: "no available devices found"}
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

	// Create the context before publishing the entry so a concurrent disconnect
	// can always cancel the connection goroutine.
	connCtx, cancel := context.WithCancel(context.Background())
	entry := &activeStream{
		deviceIP:     target,
		state:        StateConnecting,
		cancelFn:     cancel,
		credentialCh: make(chan string, 1),
	}
	d.clearLastErrorForTargetLocked(target)
	d.streams[target] = entry
	d.mu.Unlock()

	go d.connectAndStream(connCtx, entry, target, port, req.Pin)

	d.mu.Lock()
	defer d.mu.Unlock()
	return Response{OK: true, State: d.overallStateLocked(), Device: target}
}

// pendingCredentialTargetsLocked returns pending target IPs in stable order.
// Must be called with d.mu held.
func (d *Daemon) pendingCredentialTargetsLocked() []string {
	targets := make([]string, 0)
	for target, stream := range d.streams {
		if stream.state == StatePINRequired && stream.credentialCh != nil {
			targets = append(targets, target)
		}
	}
	sort.Strings(targets)
	return targets
}

// clearLastErrorForTargetLocked acknowledges an error only when retrying the
// receiver that produced it. Starting another target must not hide a concurrent
// connection failure before a control client has a chance to report it.
// Must be called with d.mu held.
func (d *Daemon) clearLastErrorForTargetLocked(target string) {
	if d.lastErrorTarget == "" || d.lastErrorTarget == target {
		d.lastError = ""
		d.lastErrorTarget = ""
	}
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

func (d *Daemon) connectAndStream(ctx context.Context, entry *activeStream, target string, port int, suppliedCredential string) {
	// removeStream cleans up this stream's entry and tears down the shared broadcast
	// if no other streams remain.
	removeStream := func(msg string) {
		failure := msg
		if failure != "" {
			failure = fmt.Sprintf("%s: %s", target, failure)
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		// A user-requested disconnect removes the entry before closing its client.
		// Ignore the resulting read/handshake error from that obsolete goroutine.
		if d.streams[target] != entry {
			return
		}
		if failure != "" {
			log.Printf("[daemon] %s", failure)
			d.lastError = failure
			d.lastErrorTarget = target
		}
		d.removeStreamLocked(target)
	}

	// A receiver-configured password and an on-screen pairing PIN travel through
	// the same user-facing field. Pair-setup consumes it first; HTTP Digest may
	// then require the same value during SETUP. Retain it across reconnects.
	credential := d.cfg.Code
	if suppliedCredential != "" {
		credential = suppliedCredential
	}
	connectClient := func() (*airplay.AirPlayClient, *airplay.ReceiverInfo, error) {
		next := airplay.NewAirPlayClient(target, port)
		next.SetPassword(credential)
		if err := next.Connect(ctx); err != nil {
			return nil, nil, err
		}

		// Publish the connected client immediately so disconnect/shutdown can
		// interrupt GetInfo, pairing, or a pending credential wait.
		d.mu.Lock()
		if d.streams[target] != entry {
			d.mu.Unlock()
			_ = next.Close()
			return nil, nil, context.Canceled
		}
		entry.client = next
		d.mu.Unlock()

		nextInfo, err := next.GetInfo()
		if err != nil {
			_ = next.Close()
			return nil, nil, err
		}

		d.mu.Lock()
		if d.streams[target] != entry {
			d.mu.Unlock()
			_ = next.Close()
			return nil, nil, context.Canceled
		}
		entry.device = nextInfo.Name
		entry.deviceID = nextInfo.DeviceID
		d.mu.Unlock()
		return next, nextInfo, nil
	}

	client, info, err := connectClient()
	if err != nil {
		removeStream(fmt.Sprintf("connect to %s:%d failed: %v", target, port, err))
		return
	}

	deviceID := info.DeviceID
	savedCreds := d.credStore.Lookup(deviceID)
	screenCastRestoreToken := ""
	if savedCreds != nil {
		screenCastRestoreToken = savedCreds.RestoreToken
	}

	reconnect := func() error {
		_ = client.Close()
		next, nextInfo, err := connectClient()
		if err != nil {
			return err
		}
		client = next
		info = nextInfo
		deviceID = info.DeviceID
		return nil
	}

	log.Printf("[daemon] connected to %s (model: %s, deviceID: %s)", info.Name, info.Model, deviceID)

	pairWithCredentialValue := func(value string) error {
		credential = value
		if err := client.Pair(ctx, value); err != nil {
			return err
		}
		if client.PairKeys != nil {
			if err := d.credStore.Save(deviceID, client.PairingID,
				client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private); err != nil {
				log.Printf("[daemon] warning: failed to save credentials: %v", err)
			} else {
				log.Printf("[daemon] credentials saved for %s (deviceID: %s)", info.Name, deviceID)
			}
		}
		return nil
	}

	waitForCredential := func(kind CredentialKind) (string, error) {
		d.mu.Lock()
		if d.streams[target] != entry {
			d.mu.Unlock()
			return "", context.Canceled
		}
		entry.credentialKind = kind
		d.mu.Unlock()

		// Do not expose the PIN prompt until the receiver has accepted the request
		// to display one. Password mode deliberately never touches this endpoint.
		if kind == CredentialKindPIN {
			if err := client.StartPINDisplay(); err != nil {
				d.mu.Lock()
				if d.streams[target] == entry {
					entry.credentialKind = ""
				}
				d.mu.Unlock()
				return "", fmt.Errorf("start PIN display: %w", err)
			}
		}

		d.mu.Lock()
		if d.streams[target] != entry {
			d.mu.Unlock()
			return "", context.Canceled
		}
		entry.state = StatePINRequired
		d.mu.Unlock()

		log.Printf("[daemon] %s required for %s — waiting for user input", kind, info.Name)
		select {
		case value := <-entry.credentialCh:
			return value, nil
		case <-ctx.Done():
			d.mu.Lock()
			if d.streams[target] == entry {
				entry.credentialKind = ""
			}
			d.mu.Unlock()
			return "", ctx.Err()
		}
	}

	// Pairing
	paired := false
	if savedCreds != nil && savedCreds.HasPairingCredentials() {
		pub, priv := savedCreds.Ed25519Keys()
		client.PairingID = savedCreds.PairingID
		client.PairKeys = &airplay.PairKeys{
			Ed25519Public:  pub,
			Ed25519Private: priv,
		}
		if err := client.PairVerify(ctx); err != nil {
			log.Printf("[daemon] pair-verify with saved creds failed: %v", err)
			if err := reconnect(); err != nil {
				removeStream(fmt.Sprintf("reconnect failed: %v", err))
				return
			}
		} else {
			paired = true
			log.Printf("[daemon] pair-verify succeeded for %s", info.Name)
		}
	} else if savedCreds != nil {
		log.Printf("[daemon] saved credentials have no usable pair-verify keys, skipping")
	}

	if !paired {
		pairWithCredential := func(kind CredentialKind) error {
			if credential == "" {
				value, err := waitForCredential(kind)
				if err != nil {
					return fmt.Errorf("wait for %s: %w", kind, err)
				}
				credential = value
				client.SetPassword(credential)
			}
			if err := pairWithCredentialValue(credential); err != nil {
				return fmt.Errorf("%s pairing: %w", kind, err)
			}
			return nil
		}

		// Legacy third-party password receivers require full SRP pairing. Trying a
		// transient exchange first can leave the receiver rejecting the immediate
		// password retry. A PIN bit also requires full pairing; password still wins
		// when both modes are advertised.
		passwordNeedsPairing := info.RequiresPassword() &&
			(info.RequiresPINPairing() || info.PrefersLegacyPairing())
		if passwordNeedsPairing {
			if err := pairWithCredential(CredentialKindPassword); err != nil {
				_ = client.Close()
				removeStream(err.Error())
				return
			}
		} else if info.RequiresPINPairing() {
			if err := pairWithCredential(CredentialKindPIN); err != nil {
				_ = client.Close()
				removeStream(err.Error())
				return
			}
		} else if err := client.Pair(ctx, ""); err != nil {
			log.Printf("[daemon] transient pairing failed: %v", err)
			// A failed setup may leave pairing state attached to this socket. Start
			// and finish the credential exchange together on a fresh connection.
			if err := reconnect(); err != nil {
				removeStream(fmt.Sprintf("reconnect for credential pairing failed: %v", err))
				return
			}
			kind := CredentialKindPIN
			if info.RequiresPassword() {
				kind = CredentialKindPassword
			}
			if err := pairWithCredential(kind); err != nil {
				_ = client.Close()
				removeStream(err.Error())
				return
			}
		} else {
			log.Printf("[daemon] transient pairing succeeded for %s", info.Name)
		}
	}

	// A configured playback password is independent from pair-verify. A saved or
	// transient pairing may succeed without it, but SETUP will later issue a
	// Digest challenge. Obtain the password once now and retain it for that retry.
	if info.RequiresPassword() && credential == "" {
		value, err := waitForCredential(CredentialKindPassword)
		if err != nil {
			_ = client.Close()
			removeStream(fmt.Sprintf("wait for password: %v", err))
			return
		}
		credential = value
		client.SetPassword(credential)
	}

	// FairPlay setup
	if err := client.FairPlaySetup(ctx); err != nil {
		if !errors.Is(err, airplay.ErrFairPlayUnsupported) {
			client.Close()
			removeStream(fmt.Sprintf("FairPlay setup failed: %v", err))
			return
		}
		log.Printf("[daemon] FairPlay SAP unsupported (%v); continuing with pair-verify DataStream setup", err)
	}

	streamCfg := airplay.StreamConfig{
		FPS:       d.cfg.FPS,
		Bitrate:   d.cfg.Bitrate,
		NoEncrypt: d.cfg.NoEncrypt,
		DirectKey: d.cfg.DirectKey,
		NoAudio:   d.cfg.NoAudio,
	}

	// Start capture before SetupMirror. Modern receivers start a deadline for
	// the first video data during setup, while the Wayland screencast portal may
	// wait indefinitely for user selection.
	capMaxW, capMaxH := info.DisplaySize()
	sink, err := d.getOrStartBroadcastLocked(screenCastRestoreToken, deviceID, capMaxW, capMaxH)
	if err != nil {
		client.Close()
		removeStream(fmt.Sprintf("capture failed: %v", err))
		return
	}

	session, err := client.SetupMirror(ctx, streamCfg)
	if err != nil {
		sink.Close()
		client.Close()
		removeStream(fmt.Sprintf("mirror setup failed: %v", err))
		return
	}

	d.mu.Lock()
	current, ok := d.streams[target]
	if !ok || current != entry {
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
	current.state = StateStreaming
	current.session = session
	current.client = client
	current.sink = sink
	current.audioMuted = false
	d.mu.Unlock()

	log.Printf("[daemon] streaming to %s (%s)", info.Name, target)

	// Start audio for this stream independently.
	if !d.cfg.NoAudio && session.HasAudio() {
		audioCapture, audioErr := airplay.StartAudioCapture(ctx, d.cfg.TestMode, session.AudioCodec())
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
	if d.streams[target] == entry {
		d.removeStreamLocked(target)
	}
	d.mu.Unlock()

	log.Printf("[daemon] stream ended for %s", target)
}

// getOrStartBroadcastLocked ensures a shared BroadcastCapture is running and
// returns a new sink registered with it. If no capture is running, it starts one.
// Must NOT be called with d.mu held.
// maxW/maxH clamp the encoded size for the receiver that starts the capture;
// sinks that join later share it.
func (d *Daemon) getOrStartBroadcastLocked(restoreToken, deviceID string, maxW, maxH int) (*airplay.BroadcastSink, error) {
	// Two targets may finish authentication together. Serialize the nil check and
	// capture startup so Wayland opens only one portal and X11 starts one encoder.
	d.captureStartMu.Lock()
	defer d.captureStartMu.Unlock()

	d.mu.Lock()
	bc := d.broadcast
	d.mu.Unlock()

	if bc != nil {
		// Capture already running — add a new sink.
		sink := bc.AddSink()
		return sink, nil
	}

	// Publish the startup cancellation before entering the display portal or
	// launching GStreamer. A concurrent disconnect-all can then interrupt a
	// capture that has not returned from StartCapture yet.
	captureCtx, captureCancel := context.WithCancel(context.Background())
	d.mu.Lock()
	if len(d.streams) == 0 {
		d.mu.Unlock()
		captureCancel()
		return nil, context.Canceled
	}
	d.captureCancel = captureCancel
	d.mu.Unlock()

	// Start a fresh screen capture.
	capCfg := airplay.CaptureConfig{
		FPS:          d.cfg.FPS,
		Bitrate:      d.cfg.Bitrate,
		HWAccel:      d.cfg.HWAccel,
		MaxWidth:     maxW,
		MaxHeight:    maxH,
		ShowCursor:   d.cfg.ShowCursor,
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
	if d.cfg.TestMode {
		capture, err = airplay.StartTestCapture(captureCtx, capCfg)
	} else {
		capture, err = airplay.StartCapture(captureCtx, capCfg)
	}
	if err != nil {
		captureCancel()
		d.mu.Lock()
		// captureStartMu prevents another startup from replacing this cancel
		// function before this attempt has finished.
		if d.broadcast == nil && d.capture == nil {
			d.captureCancel = nil
		}
		d.mu.Unlock()
		return nil, err
	}

	newBC := airplay.NewBroadcastCapture(capture)
	sink := newBC.AddSink()

	d.mu.Lock()
	if len(d.streams) == 0 || d.captureCancel == nil {
		d.mu.Unlock()
		captureCancel()
		capture.Stop()
		return nil, context.Canceled
	}
	d.broadcast = newBC
	d.capture = capture
	d.captureCancel = captureCancel
	d.mu.Unlock()

	go func() {
		runErr := newBC.Run()
		unexpected := runErr != nil && runErr.Error() != "EOF"
		d.mu.Lock()
		// A stopped capture can finish after a replacement connection has already
		// been queued. Its cleanup must not tear down that newer generation.
		if d.broadcast != newBC {
			d.mu.Unlock()
			return
		}
		if unexpected {
			log.Printf("[daemon] broadcast capture error: %v", runErr)
		}
		// When the active capture ends, stop all streams consuming it.
		// Shutdown also closes the capture and can produce a benign read error.
		// Only retain failures that ended streams which were still active.
		if unexpected && len(d.streams) > 0 {
			d.lastError = "shared capture failed: " + runErr.Error()
			d.lastErrorTarget = ""
		}
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
		if entry.sink != nil {
			entry.sink.Close()
		}
		if entry.session != nil {
			entry.session.Close()
		}
		if entry.client != nil {
			entry.client.Close()
		}
		d.removeStreamLocked(req.Target)
		return Response{OK: true, State: d.overallStateLocked()}
	}

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
			state := d.overallStateLocked()
			d.mu.Unlock()
			return Response{OK: false, State: state, Error: "no active stream to " + req.Target}
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
