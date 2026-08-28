package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
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
	VideoCodec  airplay.VideoCodec
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
		FPS:        d.cfg.FPS,
		Bitrate:    d.cfg.Bitrate,
		VideoCodec: d.cfg.VideoCodec,
		NoEncrypt:  d.cfg.NoEncrypt,
		DirectKey:  d.cfg.DirectKey,
		NoAudio:    d.cfg.NoAudio,
		PortMin:    d.cfg.PortMin,
		PortMax:    d.cfg.PortMax,
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

// acquireInstanceLock prevents two daemons from owning different listeners at
// the same socket path. A Unix socket alone is not sufficient for this: unlinking
// its pathname does not stop the process that is already listening on it.
func acquireInstanceLock(socketPath string) (*os.File, error) {
	lockPath := socketPath + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open daemon lock %s: %w", lockPath, err)
	}
	if err := lockFile.Chmod(0600); err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("chmod daemon lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lockFile.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, fmt.Errorf("another doubletake daemon is already running for %s", socketPath)
		}
		return nil, fmt.Errorf("lock daemon instance %s: %w", lockPath, err)
	}
	return lockFile, nil
}

func releaseInstanceLock(lockFile *os.File) {
	if lockFile == nil {
		return
	}
	_ = syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	_ = lockFile.Close()
}

// removeStaleSocket only unlinks a socket after confirming that no daemon is
// listening. The probe keeps a newly upgraded daemon from replacing the live
// socket of an older doubletake version that predates the instance lock.
func removeStaleSocket(socketPath string) error {
	info, err := os.Lstat(socketPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("control socket path %s exists and is not a Unix socket", socketPath)
	}

	conn, dialErr := net.DialTimeout("unix", socketPath, 250*time.Millisecond)
	if dialErr == nil {
		conn.Close()
		return fmt.Errorf("another doubletake daemon is already running for %s", socketPath)
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) && !os.IsNotExist(dialErr) {
		return fmt.Errorf("probe existing control socket: %w", dialErr)
	}
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}
	return nil
}

// activeStream tracks the state of a single mirroring session to one receiver.
type activeStream struct {
	device         string // friendly name
	deviceIP       string
	deviceID       string
	port           int
	state          State
	audioMuted     bool
	session        *airplay.MirrorSession
	client         *airplay.AirPlayClient
	sink           *airplay.BroadcastSink // fan-out video sink (nil when no broadcast)
	captureGroup   *videoCaptureGroup     // encoder group selected from the resolved nominal canvas
	cancelFn       context.CancelFunc
	credentialCh   chan string
	credentialKind CredentialKind
}

// videoCaptureKey identifies captures which can safely share one encoded
// stream. Capture settings are daemon-wide, so only the receiver's nominal
// canvas and codec vary between concurrent targets.
type videoCaptureKey struct {
	maxWidth  int
	maxHeight int
	codec     airplay.VideoCodec
}

// videoCaptureGroup owns one capture/encoder and its byte-stream fan-out. A
// receiver can join only the group matching its resolved nominal canvas, so a
// lower-resolution receiver never inherits a larger first target's encoding.
type videoCaptureGroup struct {
	key              videoCaptureKey
	broadcast        *airplay.BroadcastCapture
	capture          *airplay.ScreenCapture
	minimumVideoLead time.Duration
	cancel           context.CancelFunc
	resetReservedBy  *activeStream
}

var errCaptureGroupResetReserved = errors.New("capture group is reserved for restore-token reset")

// daemonCleanup owns resources detached from the daemon's state maps. Building
// a cleanup plan while holding d.mu makes the state change atomic; running it
// afterwards keeps cancellation, pipe closure, RTSP teardown, socket closure,
// and process shutdown from blocking unrelated daemon requests.
type daemonCleanup struct {
	cancels  []context.CancelFunc
	sinks    []*airplay.BroadcastSink
	sessions []*airplay.MirrorSession
	clients  []*airplay.AirPlayClient
	captures []*airplay.ScreenCapture
}

func (cleanup *daemonCleanup) addStream(entry *activeStream) {
	if entry.cancelFn != nil {
		cleanup.cancels = append(cleanup.cancels, entry.cancelFn)
		entry.cancelFn = nil
	}
	if entry.sink != nil {
		cleanup.sinks = append(cleanup.sinks, entry.sink)
		entry.sink = nil
	}
	if entry.session != nil {
		cleanup.sessions = append(cleanup.sessions, entry.session)
		entry.session = nil
	}
	if entry.client != nil {
		cleanup.clients = append(cleanup.clients, entry.client)
		entry.client = nil
	}
	if entry.captureGroup != nil && entry.captureGroup.resetReservedBy == entry {
		entry.captureGroup.resetReservedBy = nil
	}
	entry.captureGroup = nil
}

func (cleanup *daemonCleanup) addCaptureGroup(group *videoCaptureGroup) {
	if group.cancel != nil {
		cleanup.cancels = append(cleanup.cancels, group.cancel)
		group.cancel = nil
	}
	if group.capture != nil {
		cleanup.captures = append(cleanup.captures, group.capture)
		group.capture = nil
	}
	group.broadcast = nil
	group.resetReservedBy = nil
}

// run may block and therefore must never be called with d.mu held. Cancel all
// producers and close all fan-out pipes before waiting for protocol or capture
// teardown, so independent stream workers can start unwinding promptly.
func (cleanup *daemonCleanup) run() {
	for _, cancel := range cleanup.cancels {
		cancel()
	}
	for _, sink := range cleanup.sinks {
		sink.Close()
	}
	for _, session := range cleanup.sessions {
		_ = session.Close()
	}
	for _, client := range cleanup.clients {
		_ = client.Close()
	}
	for _, capture := range cleanup.captures {
		capture.Stop()
	}
}

// Daemon manages a long-running doubletake service.
type Daemon struct {
	cfg            Config
	mu             sync.Mutex
	devices        []airplay.AirPlayDevice
	deviceLastSeen map[string]time.Time // keyed by IP
	credStore      *airplay.CredentialStore

	// Multi-stream state
	streams         map[string]*activeStream               // keyed by target IP
	captureGroups   map[videoCaptureKey]*videoCaptureGroup // one encoder/fan-out per advertised canvas
	capturePortalMu sync.Mutex                             // serializes interactive Wayland portal access
	captureStartMu  sync.Mutex                             // serializes exact-size group publication/encoder startup
	lastError       string                                 // most recent asynchronous stream failure
	lastErrorTarget string                                 // target associated with lastError; empty for capture-wide errors

	discoverCancel context.CancelFunc
	listener       net.Listener
	streamWorkers  sync.WaitGroup // stream, capture, and externally detached cleanup workers
	shuttingDown   bool
}

// New creates a new Daemon with the given configuration.
func New(cfg Config) (*Daemon, error) {
	if err := airplay.ValidateHWAccel(cfg.HWAccel); err != nil {
		return nil, fmt.Errorf("hwaccel: %w", err)
	}
	if err := airplay.ValidateVideoCodec(string(cfg.VideoCodec)); err != nil {
		return nil, fmt.Errorf("video codec: %w", err)
	}
	if cfg.VideoCodec == "" {
		cfg.VideoCodec = airplay.VideoCodecAuto
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
		captureGroups:  make(map[videoCaptureKey]*videoCaptureGroup),
		credStore:      cs,
	}, nil
}

// Run starts the daemon control socket and blocks until ctx is cancelled.
func (d *Daemon) Run(ctx context.Context) error {
	airplay.SetDebugMode(d.cfg.Debug)

	// Acquire an advisory lock before removing a stale socket. Without this, a
	// second daemon can unlink the first daemon's live listener and bind a new
	// socket at the same pathname, leaving both daemons and their captures alive.
	instanceLock, err := acquireInstanceLock(d.cfg.SocketPath)
	if err != nil {
		return err
	}
	defer releaseInstanceLock(instanceLock)

	if err := removeStaleSocket(d.cfg.SocketPath); err != nil {
		return err
	}

	ln, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("listen %s: %w", d.cfg.SocketPath, err)
	}
	// Owner-only permissions
	if err := os.Chmod(d.cfg.SocketPath, 0700); err != nil {
		ln.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Start continuous mDNS discovery in the background
	discoverCtx, discoverCancel := context.WithCancel(ctx)
	d.mu.Lock()
	if d.shuttingDown {
		d.mu.Unlock()
		discoverCancel()
		_ = ln.Close()
		return nil
	}
	d.listener = ln
	d.discoverCancel = discoverCancel
	d.mu.Unlock()

	log.Printf("[daemon] listening on %s", d.cfg.SocketPath)
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
			d.mu.Lock()
			shuttingDown := d.shuttingDown
			d.mu.Unlock()
			if shuttingDown {
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
	d.shuttingDown = true
	discoverCancel := d.discoverCancel
	d.discoverCancel = nil
	listener := d.listener
	d.listener = nil
	cleanup := d.detachAllLocked()
	d.mu.Unlock()

	if discoverCancel != nil {
		discoverCancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	cleanup.run()

	// Network handshakes, capture callbacks, and a concurrent control request's
	// detached cleanup may still be unwinding. Do not let them run into the next
	// test or process lifecycle.
	d.streamWorkers.Wait()
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
		}
		d.mu.Unlock()
		if err != nil {
			log.Printf("[daemon] mDNS browse error: %v", err)
		}

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
	case "reset-restore-token":
		return d.handleResetRestoreToken(req)
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

func requiredPairingCredentialKind(info *airplay.ReceiverInfo) CredentialKind {
	switch info.RequiredPairingCredential() {
	case airplay.PairingCredentialPIN:
		return CredentialKindPIN
	case airplay.PairingCredentialPassword:
		return CredentialKindPassword
	default:
		return ""
	}
}

func restoreSavedPairing(client *airplay.AirPlayClient, saved *airplay.SavedCredentials) error {
	return client.RestorePairingCredentials(saved)
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
	if d.shuttingDown {
		d.mu.Unlock()
		return Response{OK: false, State: StateIdle, Error: "daemon is shutting down"}
	}

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
		port:         port,
		state:        StateConnecting,
		cancelFn:     cancel,
		credentialCh: make(chan string, 1),
	}
	d.clearLastErrorForTargetLocked(target)
	d.streams[target] = entry
	// Add while holding d.mu, before Shutdown can mark the daemon closed and
	// begin waiting. This is the WaitGroup's required Add-before-Wait ordering.
	d.streamWorkers.Add(1)
	d.mu.Unlock()

	go func() {
		defer d.streamWorkers.Done()
		d.connectAndStream(connCtx, entry, target, port, req.Pin)
	}()

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
	// removeStream cleans up this stream's entry and tears down its capture group
	// if no other streams use that group.
	removeStream := func(msg string) {
		failure := msg
		if failure != "" {
			failure = fmt.Sprintf("%s: %s", target, failure)
		}
		d.mu.Lock()
		// A user-requested disconnect removes the entry before closing its client.
		// Ignore the resulting read/handshake error from that obsolete goroutine.
		if d.streams[target] != entry {
			d.mu.Unlock()
			return
		}
		if failure != "" {
			d.lastError = failure
			d.lastErrorTarget = target
		}
		cleanup := d.detachStreamLocked(target)
		d.mu.Unlock()

		if failure != "" {
			log.Printf("[daemon] %s", failure)
		}
		cleanup.run()
	}

	// A receiver-configured password and an on-screen pairing PIN travel through
	// the same user-facing field. Pair-setup consumes it first; HTTP Digest may
	// then require the same value during SETUP. Retain it across reconnects.
	credential := d.cfg.Code
	if suppliedCredential != "" {
		credential = suppliedCredential
	}
	connectClient := func() (*airplay.AirPlayClient, *airplay.ReceiverInfo, error) {
		var next *airplay.AirPlayClient
		d.mu.Lock()
		for _, device := range d.devices {
			if device.IP == target {
				device.Port = port
				next = airplay.NewAirPlayClientForDevice(device)
				break
			}
		}
		d.mu.Unlock()
		if next == nil {
			next = airplay.NewAirPlayClient(target, port)
		}
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
			return nil, nil, err
		}

		d.mu.Lock()
		if d.streams[target] != entry {
			d.mu.Unlock()
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
			if err := d.credStore.SavePairing(deviceID, client.PairingID,
				client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private,
				client.PairingProtocol()); err != nil {
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
		verifyErr := restoreSavedPairing(client, savedCreds)
		if verifyErr == nil {
			verifyErr = client.PairVerify(ctx)
		}
		if verifyErr != nil {
			log.Printf("[daemon] pair-verify with saved creds failed: %v", verifyErr)
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

		// Resolve the password/PIN status bits against the pairing generation.
		// Legacy password receivers consume the password in SRP. Modern receivers
		// keep it solely for Digest and still perform transient HAP pairing, even
		// when the receiver also publishes the on-screen PIN bit.
		switch requiredPairingCredentialKind(info) {
		case CredentialKindPassword:
			if err := pairWithCredential(CredentialKindPassword); err != nil {
				removeStream(err.Error())
				return
			}
		case CredentialKindPIN:
			if err := pairWithCredential(CredentialKindPIN); err != nil {
				removeStream(err.Error())
				return
			}
		default:
			if err := client.Pair(ctx, ""); err != nil {
				log.Printf("[daemon] transient pairing failed: %v", err)
				// A modern fixed password is an HTTP Digest credential, not an SRP
				// secret. Do not turn a transient failure into an invalid full setup.
				if info.RequiresPassword() {
					removeStream(fmt.Sprintf("transient pairing failed for password-protected receiver: %v", err))
					return
				}
				// A failed setup may leave pairing state attached to this socket. Start
				// and finish the explicit PIN exchange on a fresh connection.
				if err := reconnect(); err != nil {
					removeStream(fmt.Sprintf("reconnect for credential pairing failed: %v", err))
					return
				}
				if err := pairWithCredential(CredentialKindPIN); err != nil {
					removeStream(err.Error())
					return
				}
			} else {
				log.Printf("[daemon] transient pairing succeeded for %s", info.Name)
			}
		}
	}

	// A configured playback password is independent from pair-verify. A saved or
	// transient pairing may succeed without it, but SETUP will later issue a
	// Digest challenge. Obtain the password once now and retain it for that retry.
	if info.RequiresPassword() && credential == "" {
		value, err := waitForCredential(CredentialKindPassword)
		if err != nil {
			removeStream(fmt.Sprintf("wait for password: %v", err))
			return
		}
		credential = value
		client.SetPassword(credential)
	}

	// FairPlay setup
	if err := client.FairPlaySetup(ctx); err != nil {
		if !errors.Is(err, airplay.ErrFairPlayUnsupported) {
			removeStream(fmt.Sprintf("FairPlay setup failed: %v", err))
			return
		}
		log.Printf("[daemon] FairPlay SAP unsupported (%v); continuing with pair-verify DataStream setup", err)
	}

	// Complete the potentially interactive portal request before SETUP, but do
	// not start an encoder until control SETUP exposes session-time display info.
	// This preserves the receiver deadline while avoiding the provisional 720p
	// fallback used by receivers whose public /info omits displays.
	capturePreparation, err := d.prepareVideoCapture(ctx, screenCastRestoreToken, deviceID)
	if err != nil {
		removeStream(fmt.Sprintf("prepare capture failed: %v", err))
		return
	}
	defer capturePreparation.Close()
	streamCfg := d.mirrorStreamConfig()
	streamCfg.AutomaticHEVCAvailable = capturePreparation.AutomaticHEVCAvailable()
	streamCfg.MeasuredVideoLatency = capturePreparation.MeasuredVideoLatency()
	streamCfg.MinimumVideoLead = capturePreparation.MinimumVideoLead()
	var broadcast *airplay.BroadcastCapture
	selectedCaptureKey := videoCaptureKey{maxWidth: -1, maxHeight: -1}
	prepareVideo := func(width, height int, codec airplay.VideoCodec) (airplay.VideoPreparationResult, error) {
		key := normalizedVideoCaptureKey(width, height, codec)
		if broadcast != nil {
			if key.codec == selectedCaptureKey.codec {
				if key.maxWidth != selectedCaptureKey.maxWidth || key.maxHeight != selectedCaptureKey.maxHeight {
					log.Printf("[daemon] receiver updated the %s canvas to %dx%d after capture started; keeping %dx%d for this session",
						key.codec, key.maxWidth, key.maxHeight, selectedCaptureKey.maxWidth, selectedCaptureKey.maxHeight)
				}
				d.mu.Lock()
				lead := time.Duration(0)
				if entry.captureGroup != nil {
					lead = entry.captureGroup.minimumVideoLead
				}
				d.mu.Unlock()
				return airplay.VideoPreparationResult{MinimumVideoLead: lead}, nil
			}
			return airplay.VideoPreparationResult{}, fmt.Errorf("receiver changed video from %s %dx%d to %s %dx%d during setup",
				selectedCaptureKey.codec, selectedCaptureKey.maxWidth, selectedCaptureKey.maxHeight,
				key.codec, key.maxWidth, key.maxHeight)
		}
		resolved, minimumVideoLead, startErr := d.getOrStartPreparedCaptureGroup(ctx, entry, capturePreparation, width, height, codec)
		if startErr != nil {
			return airplay.VideoPreparationResult{}, startErr
		}
		broadcast = resolved
		selectedCaptureKey = key
		return airplay.VideoPreparationResult{MinimumVideoLead: minimumVideoLead}, nil
	}

	session, err := client.SetupMirrorWithCalibratedVideoPreparation(ctx, streamCfg, prepareVideo)
	err = retryMirrorSetupAfterDigestChallenge(
		err,
		func() (string, error) { return waitForCredential(CredentialKindPassword) },
		func(value string) {
			credential = value
			client.SetPassword(value)
		},
		func() error {
			if selectedCaptureKey.codec != "" {
				streamCfg.VideoCodec = selectedCaptureKey.codec
			}
			var setupErr error
			session, setupErr = client.SetupMirrorWithCalibratedVideoPreparation(ctx, streamCfg, prepareVideo)
			return setupErr
		},
	)
	if err != nil {
		removeStream(fmt.Sprintf("mirror setup failed: %v", err))
		return
	}
	if broadcast == nil {
		_ = session.Close()
		removeStream("mirror setup completed without preparing video capture")
		return
	}

	d.mu.Lock()
	current, ok := d.streams[target]
	if !ok || current != entry {
		// Stream was cancelled while we were setting up
		d.mu.Unlock()
		_ = session.Close()
		d.mu.Lock()
		cleanup := d.detachCaptureGroupIfUnusedLocked(entry.captureGroup)
		d.mu.Unlock()
		cleanup.run()
		return
	}
	// Attach only after SETUP succeeds. This avoids buffering encoded data for a
	// receiver which is still pairing, prompting, or negotiating its media ports.
	sink := broadcast.AddSink()
	current.state = StateStreaming
	current.session = session
	current.client = client
	current.sink = sink
	current.audioMuted = false
	d.mu.Unlock()

	log.Printf("[daemon] streaming to %s (%s) at %dx%d using %s",
		info.Name, target, selectedCaptureKey.maxWidth, selectedCaptureKey.maxHeight, selectedCaptureKey.codec)
	videoDone := make(chan error, 1)
	go func() {
		videoDone <- session.StreamFrames(ctx, sink.AsCapture(), 0)
	}()

	// Start audio for this stream independently, but retain a completion channel
	// so the stream worker does not outlive daemon shutdown.
	var audioCapture *airplay.AudioCapture
	var audioDone chan error
	if !d.cfg.NoAudio && session.HasAudio() {
		var audioErr error
		audioCapture, audioErr = airplay.StartAudioCapture(ctx, d.cfg.TestMode, session.AudioCodec())
		if audioErr != nil {
			log.Printf("[daemon] audio capture failed: %v (continuing without audio)", audioErr)
		} else {
			audioDone = make(chan error, 1)
			go func() {
				aerr := session.StreamAudio(ctx, audioCapture, session.AudioStream())
				if aerr != nil && ctx.Err() == nil {
					log.Printf("[daemon] audio streaming error: %v", aerr)
				}
				audioDone <- aerr
			}()
			log.Printf("[daemon] audio capture started for %s", target)
		}
	}

	streamErr := <-videoDone
	if streamErr != nil && ctx.Err() == nil {
		log.Printf("[daemon] stream error for %s: %v", target, streamErr)
	}

	// Atomically remove the stream before any potentially blocking teardown.
	// A concurrent disconnect or shutdown which won the detach race owns those
	// resources instead, and the idempotent local audio cleanup can still finish.
	d.mu.Lock()
	cleanup := daemonCleanup{}
	if d.streams[target] == entry {
		cleanup = d.detachStreamLocked(target)
	}
	d.mu.Unlock()
	cleanup.run()

	if audioCapture != nil {
		audioCapture.Stop()
	}
	if audioDone != nil {
		<-audioDone
	}

	log.Printf("[daemon] stream ended for %s", target)
}

// retryMirrorSetupAfterDigestChallenge handles receivers which reveal a
// configured playback password only when SETUP is attempted. It deliberately
// retries once on the existing paired/FairPlay connection: a rejected Digest
// request has not created receiver-side media state, and reconnecting would
// discard both the cached challenge and the completed handshakes.
func retryMirrorSetupAfterDigestChallenge(
	setupErr error,
	waitForPassword func() (string, error),
	setPassword func(string),
	retrySetup func() error,
) error {
	if !errors.Is(setupErr, airplay.ErrCredentialsRequired) {
		return setupErr
	}

	password, err := waitForPassword()
	if err != nil {
		return fmt.Errorf("wait for password: %w", err)
	}
	setPassword(password)

	return retrySetup()
}

// normalizedVideoCaptureKey matches the even canvas which the capture pipeline
// will actually encode. Invalid or incomplete dimensions share the unconstrained
// group instead of accidentally constraining one axis only.
func normalizedVideoCaptureKey(maxW, maxH int, codecs ...airplay.VideoCodec) videoCaptureKey {
	codec := airplay.VideoCodecH264
	if len(codecs) > 0 && codecs[0] != "" {
		codec = codecs[0]
	}
	if maxW <= 0 || maxH <= 0 {
		return videoCaptureKey{codec: codec}
	}
	return videoCaptureKey{maxWidth: maxW &^ 1, maxHeight: maxH &^ 1, codec: codec}
}

// prepareVideoCapture completes interactive capture authorization before the
// receiver session begins, but leaves GStreamer unstarted until control SETUP
// reveals the session-time display canvas. Portal serialization is deliberately
// separate from captureStartMu: a different user prompt must not block an
// already-negotiated receiver from starting its encoder before its deadline.
func (d *Daemon) prepareVideoCapture(ctx context.Context, restoreToken, deviceID string) (*airplay.CapturePreparation, error) {
	d.capturePortalMu.Lock()
	defer d.capturePortalMu.Unlock()

	cfg := airplay.CaptureConfig{
		FPS:          d.cfg.FPS,
		Bitrate:      d.cfg.Bitrate,
		HWAccel:      d.cfg.HWAccel,
		VideoCodec:   d.cfg.VideoCodec,
		ShowCursor:   d.cfg.ShowCursor,
		RestoreToken: restoreToken,
	}
	if deviceID != "" {
		cfg.SaveRestoreToken = func(token string) error {
			return d.credStore.SaveRestoreToken(deviceID, token)
		}
	}
	if d.cfg.TestMode {
		return airplay.PrepareTestCapture(ctx, cfg)
	}
	return airplay.PrepareCapture(ctx, cfg)
}

// getOrStartPreparedCaptureGroup consumes an already-authorized capture source
// only when no encoder exists for the resolved nominal canvas. Otherwise the
// stream joins the existing group and the unused preparation is released.
// Must NOT be called with d.mu held.
func (d *Daemon) getOrStartPreparedCaptureGroup(ctx context.Context, entry *activeStream, preparation *airplay.CapturePreparation, width, height int, codec airplay.VideoCodec) (*airplay.BroadcastCapture, time.Duration, error) {
	d.captureStartMu.Lock()
	defer d.captureStartMu.Unlock()

	key := normalizedVideoCaptureKey(width, height, codec)
	d.mu.Lock()
	if d.streams[entry.deviceIP] != entry {
		d.mu.Unlock()
		return nil, 0, context.Canceled
	}
	if d.captureGroups == nil {
		d.captureGroups = make(map[videoCaptureKey]*videoCaptureGroup)
	}
	if _, err := d.migrateRestoreTokenResetReservationLocked(entry, key); err != nil {
		d.mu.Unlock()
		return nil, 0, err
	}
	group := d.captureGroups[key]
	var captureCtx context.Context
	var captureCancel context.CancelFunc
	if group != nil {
		if group.resetReservedBy != nil && group.resetReservedBy != entry {
			d.mu.Unlock()
			return nil, 0, fmt.Errorf("%w: %dx%d", errCaptureGroupResetReserved, key.maxWidth, key.maxHeight)
		}
		if group.resetReservedBy == entry && group.broadcast == nil && group.capture == nil && group.cancel == nil {
			captureCtx, captureCancel = context.WithCancel(context.Background())
			group.cancel = captureCancel
			group.resetReservedBy = nil
		} else {
			entry.captureGroup = group
			broadcast := group.broadcast
			d.mu.Unlock()
			preparation.Close()
			if broadcast == nil {
				return nil, 0, fmt.Errorf("capture group %dx%d has no broadcast", key.maxWidth, key.maxHeight)
			}
			return broadcast, group.minimumVideoLead, nil
		}
	} else {
		captureCtx, captureCancel = context.WithCancel(context.Background())
		group = &videoCaptureGroup{key: key, cancel: captureCancel}
		d.captureGroups[key] = group
		entry.captureGroup = group
	}
	entry.captureGroup = group
	d.mu.Unlock()

	capture, err := preparation.StartWithContextAndCodec(captureCtx, key.maxWidth, key.maxHeight, key.codec)
	if err != nil {
		captureCancel()
		d.mu.Lock()
		if d.captureGroups[key] == group {
			delete(d.captureGroups, key)
		}
		if entry.captureGroup == group {
			entry.captureGroup = nil
		}
		d.mu.Unlock()
		return nil, 0, err
	}

	minimumVideoLead := time.Duration(0)
	if key.codec == airplay.VideoCodecHEVC && !airplay.HasExplicitTargetLatency() {
		minimumVideoLead, err = airplay.MeasureVideoCaptureLatency(ctx, capture, d.cfg.FPS)
		if err != nil {
			captureCancel()
			capture.Stop()
			d.mu.Lock()
			if d.captureGroups[key] == group {
				delete(d.captureGroups, key)
			}
			if entry.captureGroup == group {
				entry.captureGroup = nil
			}
			d.mu.Unlock()
			return nil, 0, fmt.Errorf("measure production HEVC timing: %w", err)
		}
		log.Printf("[daemon] production HEVC timing for %dx%d requires at least %v video lead", key.maxWidth, key.maxHeight, minimumVideoLead)
	}

	broadcast := airplay.NewBroadcastCaptureWithFrameRate(capture, d.cfg.FPS)
	d.mu.Lock()
	if d.captureGroups[key] != group || d.streams[entry.deviceIP] != entry || entry.captureGroup != group {
		d.mu.Unlock()
		captureCancel()
		capture.Stop()
		return nil, 0, context.Canceled
	}
	group.broadcast = broadcast
	group.capture = capture
	group.minimumVideoLead = minimumVideoLead
	d.streamWorkers.Add(1)
	d.mu.Unlock()

	go func() {
		defer d.streamWorkers.Done()
		d.finishCaptureGroup(group, broadcast, broadcast.Run())
	}()
	return broadcast, minimumVideoLead, nil
}

// getOrStartCaptureGroup returns the capture group matching this stream's
// requested encoded canvas. It deliberately does not add a sink: callers
// attach only after SETUP succeeds, when they can immediately consume it without
// stalling established streams. Must NOT be called with d.mu held.
func (d *Daemon) getOrStartCaptureGroup(entry *activeStream, restoreToken, deviceID string, maxW, maxH int, codecs ...airplay.VideoCodec) (*airplay.BroadcastCapture, error) {
	// Serialize capture startup so two targets cannot race the group map and so
	// Wayland portal requests are presented one at a time.
	d.captureStartMu.Lock()
	defer d.captureStartMu.Unlock()

	codec := d.cfg.VideoCodec
	if len(codecs) > 0 {
		codec = codecs[0]
	}
	if codec == "" {
		codec = airplay.VideoCodecH264
	}
	if codec == airplay.VideoCodecAuto {
		if len(codecs) > 0 {
			return nil, fmt.Errorf("automatic video codec must be resolved before capture startup")
		}
		// This legacy helper has no receiver snapshot from which to resolve auto;
		// retain its historical H.264 behavior. The production setup path passes
		// a concrete per-session codec to getOrStartPreparedCaptureGroup instead.
		codec = airplay.VideoCodecH264
	}
	key := normalizedVideoCaptureKey(maxW, maxH, codec)
	d.mu.Lock()
	if d.streams[entry.deviceIP] != entry {
		d.mu.Unlock()
		return nil, context.Canceled
	}
	if d.captureGroups == nil {
		d.captureGroups = make(map[videoCaptureKey]*videoCaptureGroup)
	}
	if _, err := d.migrateRestoreTokenResetReservationLocked(entry, key); err != nil {
		d.mu.Unlock()
		return nil, err
	}
	group := d.captureGroups[key]
	var captureCtx context.Context
	var captureCancel context.CancelFunc
	if group != nil {
		if group.resetReservedBy != nil && group.resetReservedBy != entry {
			d.mu.Unlock()
			return nil, fmt.Errorf("%w: %dx%d", errCaptureGroupResetReserved, key.maxWidth, key.maxHeight)
		}
		if group.resetReservedBy == entry && group.broadcast == nil && group.capture == nil && group.cancel == nil {
			captureCtx, captureCancel = context.WithCancel(context.Background())
			group.cancel = captureCancel
			group.resetReservedBy = nil
		} else {
			entry.captureGroup = group
			broadcast := group.broadcast
			d.mu.Unlock()
			if broadcast == nil {
				return nil, fmt.Errorf("capture group %dx%d has no broadcast", key.maxWidth, key.maxHeight)
			}
			return broadcast, nil
		}
	} else {
		captureCtx, captureCancel = context.WithCancel(context.Background())
		group = &videoCaptureGroup{key: key, cancel: captureCancel}
		d.captureGroups[key] = group
		entry.captureGroup = group
	}
	entry.captureGroup = group
	d.mu.Unlock()

	capCfg := airplay.CaptureConfig{
		FPS:          d.cfg.FPS,
		Bitrate:      d.cfg.Bitrate,
		HWAccel:      d.cfg.HWAccel,
		VideoCodec:   codec,
		MaxWidth:     key.maxWidth,
		MaxHeight:    key.maxHeight,
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
		if d.captureGroups[key] == group {
			delete(d.captureGroups, key)
		}
		if entry.captureGroup == group {
			entry.captureGroup = nil
		}
		d.mu.Unlock()
		return nil, err
	}

	newBC := airplay.NewBroadcastCaptureWithFrameRate(capture, d.cfg.FPS)
	d.mu.Lock()
	if d.captureGroups[key] != group || d.streams[entry.deviceIP] != entry || entry.captureGroup != group {
		d.mu.Unlock()
		captureCancel()
		capture.Stop()
		return nil, context.Canceled
	}
	group.broadcast = newBC
	group.capture = capture
	// Add while holding d.mu so Shutdown cannot begin waiting between publishing
	// the capture and registering its completion worker.
	d.streamWorkers.Add(1)
	d.mu.Unlock()

	go func() {
		defer d.streamWorkers.Done()
		d.finishCaptureGroup(group, newBC, newBC.Run())
	}()

	return newBC, nil
}

// migrateRestoreTokenResetReservationLocked moves an owner-only reset claim
// when the receiver negotiates a different canvas after reconnecting. It never
// joins an occupied destination: reset replacement remains exclusive.
func (d *Daemon) migrateRestoreTokenResetReservationLocked(entry *activeStream, key videoCaptureKey) (*videoCaptureGroup, error) {
	reservation := entry.captureGroup
	if reservation == nil || reservation.resetReservedBy != entry ||
		reservation.broadcast != nil || reservation.capture != nil || reservation.cancel != nil {
		return nil, nil
	}
	if reservation.key == key {
		return reservation, nil
	}
	if d.captureGroups[reservation.key] != reservation {
		return nil, context.Canceled
	}
	if d.captureGroups[key] != nil {
		return nil, fmt.Errorf("%w: replacement canvas %dx%d is already active", errCaptureGroupResetReserved, key.maxWidth, key.maxHeight)
	}
	delete(d.captureGroups, reservation.key)
	reservation.key = key
	d.captureGroups[key] = reservation
	return reservation, nil
}

// detachStreamLocked removes a single stream and transfers ownership of its
// resources, plus an unused final capture group, to a cleanup plan. The caller
// must unlock d.mu before running the plan.
func (d *Daemon) detachStreamLocked(target string) daemonCleanup {
	cleanup := daemonCleanup{}
	entry, ok := d.streams[target]
	if !ok {
		return cleanup
	}
	group := entry.captureGroup
	delete(d.streams, target)
	cleanup.addStream(entry)
	cleanup.merge(d.detachCaptureGroupIfUnusedLocked(group))
	return cleanup
}

// captureGroupInUseLocked reports whether a connecting or streaming receiver
// still owns a reference to group. Must be called with d.mu held.
func (d *Daemon) captureGroupInUseLocked(group *videoCaptureGroup) bool {
	if group == nil {
		return false
	}
	for _, entry := range d.streams {
		if entry.captureGroup == group {
			return true
		}
	}
	return false
}

func (cleanup *daemonCleanup) merge(other daemonCleanup) {
	cleanup.cancels = append(cleanup.cancels, other.cancels...)
	cleanup.sinks = append(cleanup.sinks, other.sinks...)
	cleanup.sessions = append(cleanup.sessions, other.sessions...)
	cleanup.clients = append(cleanup.clients, other.clients...)
	cleanup.captures = append(cleanup.captures, other.captures...)
}

func (cleanup *daemonCleanup) empty() bool {
	return len(cleanup.cancels) == 0 && len(cleanup.sinks) == 0 &&
		len(cleanup.sessions) == 0 && len(cleanup.clients) == 0 &&
		len(cleanup.captures) == 0
}

// detachCaptureGroupIfUnusedLocked transfers an encoder group to a cleanup plan
// when its final receiver leaves. The caller must run the plan after unlocking.
func (d *Daemon) detachCaptureGroupIfUnusedLocked(group *videoCaptureGroup) daemonCleanup {
	if group == nil || d.captureGroupInUseLocked(group) {
		return daemonCleanup{}
	}
	return d.detachCaptureGroupLocked(group)
}

// detachCaptureGroupLocked removes one capture generation before transferring
// its resources. Deleting first makes the BroadcastCapture completion callback
// recognize an intentional stop and leave any replacement generation alone.
func (d *Daemon) detachCaptureGroupLocked(group *videoCaptureGroup) daemonCleanup {
	cleanup := daemonCleanup{}
	if group == nil {
		return cleanup
	}
	if d.captureGroups[group.key] != group {
		return cleanup
	}
	delete(d.captureGroups, group.key)
	cleanup.addCaptureGroup(group)
	return cleanup
}

// detachCaptureGroupStreamsLocked removes only streams backed by group and
// transfers all associated resources. The caller must run cleanup after unlock.
func (d *Daemon) detachCaptureGroupStreamsLocked(group *videoCaptureGroup) daemonCleanup {
	cleanup := daemonCleanup{}
	for target, entry := range d.streams {
		if entry.captureGroup != group {
			continue
		}
		delete(d.streams, target)
		cleanup.addStream(entry)
	}
	cleanup.merge(d.detachCaptureGroupLocked(group))
	return cleanup
}

// finishCaptureGroup handles both EOF and failures from BroadcastCapture.Run.
// State is detached under d.mu and all cancellation and I/O happens afterwards.
func (d *Daemon) finishCaptureGroup(group *videoCaptureGroup, broadcast *airplay.BroadcastCapture, runErr error) {
	unexpected := runErr != nil && !errors.Is(runErr, io.EOF)
	d.mu.Lock()
	// An intentionally stopped group can finish after another capture with the
	// same dimensions has already started. Never tear down that replacement.
	if d.captureGroups[group.key] != group || group.broadcast != broadcast {
		d.mu.Unlock()
		return
	}
	inUse := d.captureGroupInUseLocked(group)
	if unexpected && inUse {
		d.lastError = fmt.Sprintf("%dx%d capture failed: %v", group.key.maxWidth, group.key.maxHeight, runErr)
		d.lastErrorTarget = ""
	}
	// A capture failure affects only receivers consuming this encoded canvas;
	// other resolution groups continue streaming.
	cleanup := d.detachCaptureGroupStreamsLocked(group)
	d.mu.Unlock()

	if unexpected {
		log.Printf("[daemon] %dx%d capture error: %v", group.key.maxWidth, group.key.maxHeight, runErr)
	}
	cleanup.run()
}

func (d *Daemon) handleDisconnect(req Request) Response {
	d.mu.Lock()

	// If a target is specified, disconnect only that stream.
	if req.Target != "" {
		_, ok := d.streams[req.Target]
		if !ok {
			response := Response{OK: false, State: d.overallStateLocked(), Error: "no active stream to " + req.Target}
			d.mu.Unlock()
			return response
		}
		cleanup := d.detachStreamLocked(req.Target)
		response := Response{OK: true, State: d.overallStateLocked()}
		// Shutdown waits for every cleanup which was detached before it marked the
		// daemon closed. Register while holding d.mu to preserve Add-before-Wait.
		tracked := !cleanup.empty()
		if tracked {
			d.streamWorkers.Add(1)
		}
		d.mu.Unlock()
		cleanup.run()
		if tracked {
			d.streamWorkers.Done()
		}
		return response
	}

	// Disconnect all.
	cleanup := d.detachAllLocked()
	tracked := !cleanup.empty()
	if tracked {
		d.streamWorkers.Add(1)
	}
	d.mu.Unlock()
	cleanup.run()
	if tracked {
		d.streamWorkers.Done()
	}
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

// detachAllLocked removes every active stream and capture group atomically and
// returns their resources for cleanup after d.mu is released.
func (d *Daemon) detachAllLocked() daemonCleanup {
	cleanup := daemonCleanup{}
	for target, entry := range d.streams {
		delete(d.streams, target)
		cleanup.addStream(entry)
	}
	// Entries no longer reference their groups, so every published group can be
	// detached without repeatedly scanning d.streams.
	for _, group := range d.captureGroups {
		cleanup.addCaptureGroup(group)
	}
	clear(d.captureGroups)
	return cleanup
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
