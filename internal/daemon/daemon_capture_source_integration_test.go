package daemon

// Regression coverage for the capture-source propagation chain:
//
//	xdg-desktop-portal Start reply -> airplay.PrepareCapture
//	    -> Daemon.getOrStartPreparedCaptureGroup -> Daemon.handleStatus
//
// The tests below drive the real production code with a fake portal owned by a
// private dbus-daemon (DBUS_SESSION_BUS_ADDRESS is pointed at it with t.Setenv,
// so the developer's desktop portal is never contacted) and a real GStreamer
// encoder boundary. Only the two external processes are substituted:
//
//   - gst-launch-1.0 is a test-only wrapper that replaces the unavailable
//     PipeWire source element with a real videotestsrc node, leaving the real
//     scaling, encoding, RTP, and ONVIF staging suffix untouched. The wrapper
//     runs the real gst-launch-1.0 resolved before PATH is changed.
//   - gst-inspect-1.0 reports vapostproc as unavailable so the capture plan is
//     the deterministic system-memory production pipeline on hosts with or
//     without a working VA driver. Every other element query is delegated to
//     the real gst-inspect-1.0.
//
// These substitutions sit at the process boundary, not inside production code:
// there are no test hooks, interfaces, or constructors in non-test files.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"doubletake/internal/airplay"
)

// Literal xdg-desktop-portal identifiers. They mirror the production
// constants in internal/airplay/capture.go, which is a different package.
const (
	fakeCapturePortalBusName         = "org.freedesktop.portal.Desktop"
	fakeCapturePortalObjectPath      = dbus.ObjectPath("/org/freedesktop/portal/desktop")
	fakeCapturePortalRequestPrefix   = "/org/freedesktop/portal/desktop/request"
	fakeCapturePortalSessionPrefix   = "/org/freedesktop/portal/desktop/session"
	fakeCapturePortalScreenCastIface = "org.freedesktop.portal.ScreenCast"
	fakeCapturePortalRequestIface    = "org.freedesktop.portal.Request"
	fakeCapturePortalSessionIface    = "org.freedesktop.portal.Session"
	fakeCapturePortalPropertiesIface = "org.freedesktop.DBus.Properties"
)

// fakeCapturePortalPoint gives the Start reply's size and position properties
// their real D-Bus signature, (ii), instead of an array of variants.
type fakeCapturePortalPoint struct {
	X int32
	Y int32
}

// fakeCapturePortalStream is one entry of the Start reply's a(ua{sv}) streams
// array. Encoding a Go struct keeps the node ID as u and the properties as
// a{sv}, matching the portal specification.
type fakeCapturePortalStream struct {
	NodeID     uint32
	Properties map[string]dbus.Variant
}

type fakeCapturePortalStart struct {
	Streams []fakeCapturePortalStream
}

// fakeCapturePortal is a private-session-bus xdg-desktop-portal ScreenCast
// backend. It serves one scripted Start reply per preparation, in order.
type fakeCapturePortal struct {
	conn *dbus.Conn
	pwFD int

	mu         sync.Mutex
	starts     []fakeCapturePortalStart
	startCount int
}

type fakeCapturePortalSession struct{}

func (s *fakeCapturePortalSession) Close() *dbus.Error {
	return nil
}

// Get supplies ScreenCast version 4 so SelectSources exercises the same
// persistent-session options a modern desktop portal receives.
func (p *fakeCapturePortal) Get(interfaceName, propertyName string) (dbus.Variant, *dbus.Error) {
	if interfaceName == fakeCapturePortalScreenCastIface && propertyName == "version" {
		return dbus.MakeVariant(uint32(4)), nil
	}
	return dbus.Variant{}, dbus.MakeFailedError(fmt.Errorf("unknown property %s.%s", interfaceName, propertyName))
}

func (p *fakeCapturePortal) CreateSession(sender dbus.Sender, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	handleToken, ok := options["handle_token"].Value().(string)
	if !ok {
		return "", dbus.MakeFailedError(fmt.Errorf("CreateSession without handle_token"))
	}
	sessionToken, ok := options["session_handle_token"].Value().(string)
	if !ok {
		return "", dbus.MakeFailedError(fmt.Errorf("CreateSession without session_handle_token"))
	}
	requestPath := fakeCapturePortalPath(fakeCapturePortalRequestPrefix, string(sender), handleToken)
	sessionPath := fakeCapturePortalPath(fakeCapturePortalSessionPrefix, string(sender), sessionToken)

	// Export before replying so the client can immediately call Close on an
	// abandoned preparation.
	if err := p.conn.Export(&fakeCapturePortalSession{}, sessionPath, fakeCapturePortalSessionIface); err != nil {
		return "", dbus.MakeFailedError(fmt.Errorf("export portal session: %w", err))
	}

	return requestPath, p.respond(requestPath, map[string]dbus.Variant{
		"session_handle": dbus.MakeVariant(sessionPath),
	})
}

func (p *fakeCapturePortal) SelectSources(sender dbus.Sender, session dbus.ObjectPath, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	handleToken, ok := options["handle_token"].Value().(string)
	if !ok {
		return "", dbus.MakeFailedError(fmt.Errorf("SelectSources without handle_token"))
	}
	requestPath := fakeCapturePortalPath(fakeCapturePortalRequestPrefix, string(sender), handleToken)
	return requestPath, p.respond(requestPath, map[string]dbus.Variant{})
}

func (p *fakeCapturePortal) Start(sender dbus.Sender, session dbus.ObjectPath, parentWindow string, options map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	handleToken, ok := options["handle_token"].Value().(string)
	if !ok {
		return "", dbus.MakeFailedError(fmt.Errorf("Start without handle_token"))
	}
	requestPath := fakeCapturePortalPath(fakeCapturePortalRequestPrefix, string(sender), handleToken)

	p.mu.Lock()
	if p.startCount >= len(p.starts) {
		unexpected := p.startCount + 1
		p.mu.Unlock()
		return "", dbus.MakeFailedError(fmt.Errorf("unscripted Start call %d", unexpected))
	}
	reply := p.starts[p.startCount]
	p.startCount++
	p.mu.Unlock()

	// dbus.MakeVariant infers a(ua{sv}) from the []fakeCapturePortalStream
	// type, and (ii) from fakeCapturePortalPoint, so the wire shape is the one
	// a real portal sends rather than an easier-to-parse look-alike.
	result := map[string]dbus.Variant{
		"streams": dbus.MakeVariant(reply.Streams),
	}
	return requestPath, p.respond(requestPath, result)
}

func (p *fakeCapturePortal) OpenPipeWireRemote(session dbus.ObjectPath, options map[string]dbus.Variant) (dbus.UnixFD, *dbus.Error) {
	return dbus.UnixFD(p.pwFD), nil
}

func (p *fakeCapturePortal) respond(requestPath dbus.ObjectPath, result map[string]dbus.Variant) *dbus.Error {
	if err := p.conn.Emit(requestPath, fakeCapturePortalRequestIface+".Response", uint32(0), result); err != nil {
		return dbus.MakeFailedError(fmt.Errorf("emit portal response: %w", err))
	}
	return nil
}

func (p *fakeCapturePortal) startReplies() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.startCount
}

func fakeCapturePortalPath(prefix, sender, token string) dbus.ObjectPath {
	name := strings.ReplaceAll(strings.TrimPrefix(sender, ":"), ".", "_")
	return dbus.ObjectPath(prefix + "/" + name + "/" + token)
}

func fakeCapturePortalStreamFromMetadata(nodeID, sourceType uint32, width, height int, x, y int32) fakeCapturePortalStream {
	return fakeCapturePortalStream{
		NodeID: nodeID,
		Properties: map[string]dbus.Variant{
			"source_type": dbus.MakeVariant(sourceType),
			"size":        dbus.MakeVariant(fakeCapturePortalPoint{X: int32(width), Y: int32(height)}),
			"position":    dbus.MakeVariant(fakeCapturePortalPoint{X: x, Y: y}),
		},
	}
}

// requireCaptureSourceIntegrationDeps skips the tests before any process is
// started when the external integration dependencies are unavailable.
func requireCaptureSourceIntegrationDeps(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("dbus-daemon"); err != nil {
		t.Skip("dbus-daemon is required for the private portal integration test")
	}
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil {
		t.Skip("gst-launch-1.0 is required for the headless capture integration test")
	}
	gstInspect, err := exec.LookPath("gst-inspect-1.0")
	if err != nil {
		t.Skip("gst-inspect-1.0 is required for the headless capture integration test")
	}
	for _, element := range []string{
		"openh264enc", "h264parse", "rtph264pay", "rtponviftimestamp", "rtpstreampay", "videotestsrc",
	} {
		if err := exec.Command(gstInspect, element).Run(); err != nil {
			t.Skipf("GStreamer element %s is required for the headless capture integration test", element)
		}
	}
}

// startFakeCapturePortal runs a private dbus-daemon, owns the portal bus name
// on it, and points DBUS_SESSION_BUS_ADDRESS at it for the remainder of the
// test. The real session bus is never used.
func startFakeCapturePortal(t *testing.T, starts ...fakeCapturePortalStart) *fakeCapturePortal {
	t.Helper()
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--nopidfile", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start private dbus-daemon: %v", err)
	}
	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()
	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(syscall.SIGTERM)
			}
			select {
			case <-waitCh:
			case <-time.After(2 * time.Second):
				if cmd.Process != nil {
					_ = cmd.Process.Kill()
				}
				<-waitCh
			}
		})
	}
	t.Cleanup(stop)

	type addressResult struct {
		value string
		err   error
	}
	ready := make(chan addressResult, 1)
	go func() {
		line, readErr := bufio.NewReader(stdout).ReadString('\n')
		ready <- addressResult{value: strings.TrimSpace(line), err: readErr}
	}()
	var address string
	select {
	case result := <-ready:
		if result.err != nil {
			stop()
			t.Fatalf("read private bus address: %v (%s)", result.err, stderr.String())
		}
		address = result.value
	case <-time.After(3 * time.Second):
		stop()
		t.Fatalf("private dbus-daemon did not become ready (%s)", stderr.String())
	}
	if address == "" {
		stop()
		t.Fatal("private dbus-daemon returned an empty address")
	}
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", address)

	service, err := dbus.Connect(address)
	if err != nil {
		stop()
		t.Fatalf("connect fake portal to private bus: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	reply, err := service.RequestName(fakeCapturePortalBusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		t.Fatalf("own fake portal bus name: %v", err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("fake portal bus name reply = %d, want primary owner", reply)
	}
	if !service.SupportsUnixFDs() {
		t.Skip("private bus does not support Unix file descriptor passing")
	}

	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = devNull.Close() })

	portal := &fakeCapturePortal{conn: service, pwFD: int(devNull.Fd()), starts: starts}
	if err := service.Export(portal, fakeCapturePortalObjectPath, fakeCapturePortalPropertiesIface); err != nil {
		t.Fatalf("export portal properties: %v", err)
	}
	if err := service.Export(portal, fakeCapturePortalObjectPath, fakeCapturePortalScreenCastIface); err != nil {
		t.Fatalf("export fake ScreenCast portal: %v", err)
	}
	return portal
}

// installFakeCaptureGstWrappers substitutes only the PipeWire source element
// and the VA capability probe. The encoder, payloader, and ONVIF staging run
// for real.
func installFakeCaptureGstWrappers(t *testing.T) {
	t.Helper()
	gstLaunch, err := exec.LookPath("gst-launch-1.0")
	if err != nil {
		t.Skip("gst-launch-1.0 is required for the headless capture integration test")
	}
	gstInspect, err := exec.LookPath("gst-inspect-1.0")
	if err != nil {
		t.Skip("gst-inspect-1.0 is required for the headless capture integration test")
	}
	dir := t.TempDir()
	writeCaptureSourceExecutable(t, filepath.Join(dir, "gst-launch-1.0"), fmt.Sprintf(`#!/usr/bin/env bash
set -u
real_launch=%s
args=("$@")
out=()
index=0
replaced=0
while [ "$index" -lt "${#args[@]}" ]; do
    current="${args[$index]}"
    if [ "$replaced" -eq 0 ] && [ "$current" = "pipewiresrc" ]; then
        index=$((index + 1))
        while [ "$index" -lt "${#args[@]}" ] && [ "${args[$index]}" != "!" ]; do
            index=$((index + 1))
        done
        out+=("videotestsrc" "pattern=18" "is-live=true" "do-timestamp=true")
        replaced=1
        continue
    fi
    out+=("$current")
    index=$((index + 1))
done
if [ "$replaced" -ne 1 ]; then
    echo "capture-source test wrapper: pipeline carried no pipewiresrc element" >&2
    exit 64
fi
exec "$real_launch" "${out[@]}"
`, fakeCaptureShellQuote(gstLaunch)))
	writeCaptureSourceExecutable(t, filepath.Join(dir, "gst-inspect-1.0"), fmt.Sprintf(`#!/usr/bin/env bash
set -u
# Force the production system-memory Wayland plan so the test does not depend
# on a working VA driver on the host; every other probe is the real element.
if [ "$#" -ge 1 ] && [ "$1" = "vapostproc" ]; then
    exit 1
fi
exec %s "$@"
`, fakeCaptureShellQuote(gstInspect)))
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// startFakeWaylandSocket satisfies PrepareCapture's compositor preflight. It
// is not a compositor; the capture source comes from the wrapper's
// videotestsrc.
func startFakeWaylandSocket(t *testing.T) {
	t.Helper()
	// A short path keeps the Unix socket below the kernel's ~108-byte limit;
	// t.TempDir includes the already long test name.
	runtimeDir, err := os.MkdirTemp("", "dt-capture-wl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	listener, err := net.Listen("unix", filepath.Join(runtimeDir, "wl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDir)
	t.Setenv("WAYLAND_DISPLAY", "wl")
}

func newCaptureSourceIntegrationDaemon(t *testing.T) *Daemon {
	t.Helper()
	d, err := New(Config{
		SocketPath:  filepath.Join(t.TempDir(), "doubletake-capture-source.sock"),
		CredBackend: "file",
		CredFile:    filepath.Join(t.TempDir(), "credentials.json"),
		FPS:         10,
		Bitrate:     500,
		HWAccel:     "openh264",
		VideoCodec:  airplay.VideoCodecH264,
		NoAudio:     true,
	})
	if err != nil {
		t.Fatalf("create capture-source daemon: %v", err)
	}
	t.Cleanup(d.Shutdown)
	return d
}

func addCaptureSourceIntegrationStream(t *testing.T, d *Daemon, deviceIP string) *activeStream {
	t.Helper()
	entry := &activeStream{deviceIP: deviceIP, device: "capture-source receiver " + deviceIP, state: StateConnecting}
	d.mu.Lock()
	d.streams[deviceIP] = entry
	d.mu.Unlock()
	return entry
}

// startCaptureSourceIntegrationGroup prepares capture through the real portal
// path and starts the encoder group through the same production helper the
// mirror setup callback uses.
func startCaptureSourceIntegrationGroup(t *testing.T, d *Daemon, entry *activeStream, width, height int) {
	t.Helper()
	preparation, err := d.prepareVideoCapture(context.Background(), "", entry.deviceID)
	if err != nil {
		t.Fatalf("prepare capture for %s: %v", entry.deviceIP, err)
	}
	if _, _, err := d.getOrStartPreparedCaptureGroup(context.Background(), entry, preparation, width, height, airplay.VideoCodecH264); err != nil {
		preparation.Close()
		t.Fatalf("start %dx%d capture group for %s: %v", width, height, entry.deviceIP, err)
	}
	// Ownership moved to the capture; this only matches the production
	// capturePreparation defer and must not release the running session.
	preparation.Close()
	d.mu.Lock()
	entry.state = StateStreaming
	d.mu.Unlock()
}

type captureSourceIntegrationWant struct {
	Type        uint32
	Width       int
	Height      int
	X           int
	Y           int
	HasPosition bool
}

func assertCaptureSourceIntegrationStatus(t *testing.T, d *Daemon, deviceIP string, want captureSourceIntegrationWant) {
	t.Helper()
	status := d.handleStatus()
	var stream *StreamInfo
	for index := range status.Streams {
		if status.Streams[index].DeviceIP == deviceIP {
			stream = &status.Streams[index]
			break
		}
	}
	if stream == nil {
		t.Fatalf("status has no stream for %s: %+v", deviceIP, status.Streams)
	}
	if stream.Source == nil {
		t.Fatalf("stream %s reported no source, want %+v", deviceIP, want)
	}
	got := captureSourceIntegrationWant{
		Type:        stream.Source.Type,
		Width:       stream.Source.Width,
		Height:      stream.Source.Height,
		X:           stream.Source.X,
		Y:           stream.Source.Y,
		HasPosition: stream.Source.HasPosition,
	}
	if got != want {
		t.Fatalf("stream %s source = %+v, want %+v", deviceIP, got, want)
	}

	// Pin the control-socket representation too: handleStatus feeds the same
	// StreamInfo values the JSON status reply carries.
	raw, err := json.Marshal(*stream)
	if err != nil {
		t.Fatalf("marshal stream %s: %v", deviceIP, err)
	}
	var wire struct {
		Source *struct {
			Type        uint32 `json:"type"`
			Width       int    `json:"width"`
			Height      int    `json:"height"`
			X           *int   `json:"x"`
			Y           *int   `json:"y"`
			HasPosition *bool  `json:"has_position"`
		} `json:"source"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal stream %s: %v", deviceIP, err)
	}
	if wire.Source == nil {
		t.Fatalf("stream %s JSON omitted the source: %s", deviceIP, raw)
	}
	if wire.Source.Type != want.Type || wire.Source.Width != want.Width || wire.Source.Height != want.Height {
		t.Fatalf("stream %s JSON source = %s, want type/width/height %d/%d/%d", deviceIP, raw, want.Type, want.Width, want.Height)
	}
	if wire.Source.X == nil || wire.Source.Y == nil || *wire.Source.X != want.X || *wire.Source.Y != want.Y {
		t.Fatalf("stream %s JSON source coordinates = %s, want (%d,%d)", deviceIP, raw, want.X, want.Y)
	}
	if wire.Source.HasPosition == nil || *wire.Source.HasPosition != want.HasPosition {
		t.Fatalf("stream %s JSON source = %s, want explicit has_position=%t", deviceIP, raw, want.HasPosition)
	}
}

func assertCaptureSourceIntegrationAbsent(t *testing.T, d *Daemon, deviceIP string) {
	t.Helper()
	status := d.handleStatus()
	var stream *StreamInfo
	for index := range status.Streams {
		if status.Streams[index].DeviceIP == deviceIP {
			stream = &status.Streams[index]
			break
		}
	}
	if stream == nil {
		t.Fatalf("status has no stream for %s: %+v", deviceIP, status.Streams)
	}
	if stream.Source != nil {
		t.Fatalf("stream %s reported unverifiable source %+v, want none", deviceIP, *stream.Source)
	}
	raw, err := json.Marshal(*stream)
	if err != nil {
		t.Fatalf("marshal stream %s: %v", deviceIP, err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal stream %s: %v", deviceIP, err)
	}
	if _, present := fields["source"]; present {
		t.Fatalf("stream %s JSON includes an unknown source: %s", deviceIP, raw)
	}
}

func captureSourceIntegrationGroupCount(t *testing.T, d *Daemon) int {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.captureGroups)
}

func assertCaptureSourceIntegrationStartCount(t *testing.T, portal *fakeCapturePortal, want int) {
	t.Helper()
	if got := portal.startReplies(); got != want {
		t.Fatalf("portal served %d Start requests, want %d (each preparation must reach the portal)", got, want)
	}
}

func writeCaptureSourceExecutable(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o755); err != nil {
		t.Fatalf("write executable %s: %v", path, err)
	}
}

func fakeCaptureShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}

// TestDaemonCaptureSourceIntegrationReportsEachGroupPortalMetadata proves that
// two streams backed by different canvases each report the metadata of their
// own portal Start reply.
func TestDaemonCaptureSourceIntegrationReportsEachGroupPortalMetadata(t *testing.T) {
	requireCaptureSourceIntegrationDeps(t)
	portal := startFakeCapturePortal(t,
		fakeCapturePortalStart{Streams: []fakeCapturePortalStream{
			fakeCapturePortalStreamFromMetadata(41, 1, 2560, 1440, -2560, 0),
		}},
		fakeCapturePortalStart{Streams: []fakeCapturePortalStream{
			{NodeID: 42, Properties: map[string]dbus.Variant{
				"source_type": dbus.MakeVariant(uint32(2)),
				"size":        dbus.MakeVariant(fakeCapturePortalPoint{X: 1280, Y: 720}),
				// Window position is optional; unknown must survive to status.
			}},
		}},
	)
	installFakeCaptureGstWrappers(t)
	startFakeWaylandSocket(t)
	d := newCaptureSourceIntegrationDaemon(t)

	monitor := addCaptureSourceIntegrationStream(t, d, "192.0.2.10")
	window := addCaptureSourceIntegrationStream(t, d, "192.0.2.20")
	startCaptureSourceIntegrationGroup(t, d, monitor, 640, 480)
	startCaptureSourceIntegrationGroup(t, d, window, 1280, 720)

	assertCaptureSourceIntegrationStartCount(t, portal, 2)
	if got := captureSourceIntegrationGroupCount(t, d); got != 2 {
		t.Fatalf("capture groups = %d, want 2 distinct canvases", got)
	}
	assertCaptureSourceIntegrationStatus(t, d, "192.0.2.10",
		captureSourceIntegrationWant{Type: 1, Width: 2560, Height: 1440, X: -2560, Y: 0, HasPosition: true})
	assertCaptureSourceIntegrationStatus(t, d, "192.0.2.20",
		captureSourceIntegrationWant{Type: 2, Width: 1280, Height: 720, HasPosition: false})
}

// TestDaemonCaptureSourceIntegrationSharedGroupKeepsOriginalSource proves that
// a second stream joining an existing capture group keeps reporting the source
// the group was started with. The second preparation is discarded, so its
// different portal metadata must not overwrite the shared group.
func TestDaemonCaptureSourceIntegrationSharedGroupKeepsOriginalSource(t *testing.T) {
	requireCaptureSourceIntegrationDeps(t)
	portal := startFakeCapturePortal(t,
		fakeCapturePortalStart{Streams: []fakeCapturePortalStream{
			fakeCapturePortalStreamFromMetadata(51, 1, 1920, 1080, 0, 0),
		}},
		fakeCapturePortalStart{Streams: []fakeCapturePortalStream{
			fakeCapturePortalStreamFromMetadata(52, 2, 3840, 2160, 1920, 1080),
		}},
	)
	installFakeCaptureGstWrappers(t)
	startFakeWaylandSocket(t)
	d := newCaptureSourceIntegrationDaemon(t)

	origin := addCaptureSourceIntegrationStream(t, d, "192.0.2.30")
	joiner := addCaptureSourceIntegrationStream(t, d, "192.0.2.31")
	startCaptureSourceIntegrationGroup(t, d, origin, 640, 480)
	startCaptureSourceIntegrationGroup(t, d, joiner, 640, 480)

	assertCaptureSourceIntegrationStartCount(t, portal, 2)
	if got := captureSourceIntegrationGroupCount(t, d); got != 1 {
		t.Fatalf("capture groups = %d, want one shared canvas", got)
	}
	monitor := captureSourceIntegrationWant{Type: 1, Width: 1920, Height: 1080, X: 0, Y: 0, HasPosition: true}
	assertCaptureSourceIntegrationStatus(t, d, "192.0.2.30", monitor)
	assertCaptureSourceIntegrationStatus(t, d, "192.0.2.31", monitor)
}

// TestDaemonCaptureSourceIntegrationUnknownPortalMetadataReportsNoSource
// proves that a Start reply without usable identity metadata produces no
// source rather than a fabricated or zero-valued one. The malformed case also
// covers a portal whose properties are present but have the wrong D-Bus types.
func TestDaemonCaptureSourceIntegrationUnknownPortalMetadataReportsNoSource(t *testing.T) {
	requireCaptureSourceIntegrationDeps(t)
	portal := startFakeCapturePortal(t,
		fakeCapturePortalStart{Streams: []fakeCapturePortalStream{
			{NodeID: 61, Properties: map[string]dbus.Variant{}},
		}},
		fakeCapturePortalStart{Streams: []fakeCapturePortalStream{
			{
				NodeID: 62,
				Properties: map[string]dbus.Variant{
					"source_type": dbus.MakeVariant("monitor"),
					"size":        dbus.MakeVariant([]int32{1920}),
					"position":    dbus.MakeVariant(int32(0)),
				},
			},
		}},
	)
	installFakeCaptureGstWrappers(t)
	startFakeWaylandSocket(t)
	d := newCaptureSourceIntegrationDaemon(t)

	empty := addCaptureSourceIntegrationStream(t, d, "192.0.2.40")
	malformed := addCaptureSourceIntegrationStream(t, d, "192.0.2.41")
	startCaptureSourceIntegrationGroup(t, d, empty, 640, 480)
	startCaptureSourceIntegrationGroup(t, d, malformed, 1280, 720)

	assertCaptureSourceIntegrationStartCount(t, portal, 2)
	if got := captureSourceIntegrationGroupCount(t, d); got != 2 {
		t.Fatalf("capture groups = %d, want 2 distinct canvases", got)
	}
	assertCaptureSourceIntegrationAbsent(t, d, "192.0.2.40")
	assertCaptureSourceIntegrationAbsent(t, d, "192.0.2.41")
}
