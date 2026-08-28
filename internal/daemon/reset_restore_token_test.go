package daemon

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"doubletake/internal/airplay"
)

func TestResetRestoreTokenRejectsMissingUnknownAndNonStreamingTargetsWithoutMutation(t *testing.T) {
	for _, test := range []struct {
		name   string
		target string
		state  State
	}{
		{name: "missing target"},
		{name: "unknown target", target: "192.0.2.99"},
		{name: "connecting target", target: "192.0.2.10", state: StateConnecting},
		{name: "credential-waiting target", target: "192.0.2.10", state: StatePINRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			d, err := New(Config{CredFile: filepath.Join(t.TempDir(), "credentials.json")})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if err := d.credStore.SaveRestoreToken("device-1", "restore-1"); err != nil {
				t.Fatalf("SaveRestoreToken: %v", err)
			}
			entry := &activeStream{deviceIP: "192.0.2.10", deviceID: "device-1", state: test.state}
			if test.state != "" {
				d.streams[entry.deviceIP] = entry
			}

			response := d.handleRequest(Request{Cmd: "reset-restore-token", Target: test.target})

			if response.OK {
				t.Fatalf("reset unexpectedly succeeded: %+v", response)
			}
			if d.streams[entry.deviceIP] != entry && test.state != "" {
				t.Fatal("rejected reset detached the target")
			}
			creds := d.credStore.Lookup("device-1")
			if creds == nil || creds.RestoreToken != "restore-1" {
				t.Fatalf("rejected reset mutated credentials: %+v", creds)
			}
		})
	}
}

func TestResetRestoreTokenRejectsSharedCaptureGroupWithoutMutation(t *testing.T) {
	d, err := New(Config{CredFile: filepath.Join(t.TempDir(), "credentials.json")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := d.credStore.SaveRestoreToken("device-1", "restore-1"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}
	group := &videoCaptureGroup{key: normalizedVideoCaptureKey(1920, 1080)}
	target := &activeStream{deviceIP: "192.0.2.10", deviceID: "device-1", state: StateStreaming, captureGroup: group}
	peer := &activeStream{deviceIP: "192.0.2.11", deviceID: "device-2", state: StateStreaming, captureGroup: group}
	d.streams[target.deviceIP] = target
	d.streams[peer.deviceIP] = peer
	d.captureGroups[group.key] = group

	response := d.handleRequest(Request{Cmd: "reset-restore-token", Target: target.deviceIP})

	if response.OK || !strings.Contains(response.Error, "shared capture group") {
		t.Fatalf("shared-group reset response = %+v", response)
	}
	if d.streams[target.deviceIP] != target || d.streams[peer.deviceIP] != peer || d.captureGroups[group.key] != group {
		t.Fatal("shared-group rejection changed active stream state")
	}
	creds := d.credStore.Lookup("device-1")
	if creds == nil || creds.RestoreToken != "restore-1" {
		t.Fatalf("shared-group rejection mutated credentials: %+v", creds)
	}
}

func TestResetRestoreTokenKeepsDaemonResponsiveDuringCredentialSave(t *testing.T) {
	saveStarted := make(chan struct{})
	saveRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseSave := func() { releaseOnce.Do(func() { close(saveRelease) }) }
	backend := &controlledCredentialBackend{
		credentials: &airplay.SavedCredentials{RestoreToken: "restore-1"},
		saveStarted: saveStarted,
		saveRelease: saveRelease,
		saveErr:     errors.New("save failed"),
	}
	d, _, _, _ := newResetTestDaemon(t, backend)
	defer d.Shutdown()
	defer releaseSave()

	resetResponse := make(chan Response, 1)
	go func() {
		resetResponse <- d.handleResetRestoreToken(Request{Cmd: "reset-restore-token", Target: resetTestTarget})
	}()
	waitForResetSignal(t, saveStarted, "credential save did not start")

	statusResponse := make(chan Response, 1)
	go func() {
		statusResponse <- d.handleStatus()
	}()
	select {
	case response := <-statusResponse:
		if response.State != StateStreaming {
			t.Fatalf("status during credential save = %+v, want original stream", response)
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked behind credential backend I/O")
	}

	releaseSave()
	response := waitForResetResponse(t, resetResponse)
	if response.OK || !strings.Contains(response.Error, "save failed") {
		t.Fatalf("reset response = %+v, want credential save failure", response)
	}
}

func TestResetRestoreTokenCredentialFailureIsAtomic(t *testing.T) {
	for _, test := range []struct {
		name      string
		lookupErr error
		saveErr   error
	}{
		{name: "lookup failure", lookupErr: errors.New("lookup failed")},
		{name: "save failure", saveErr: errors.New("save failed")},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &controlledCredentialBackend{
				credentials: &airplay.SavedCredentials{PairingID: "pair-1", RestoreToken: "restore-1"},
				lookupErr:   test.lookupErr,
				saveErr:     test.saveErr,
			}
			d, entry, group, streamCtx := newResetTestDaemon(t, backend)
			defer d.Shutdown()
			d.lastError = "existing stream error"
			d.lastErrorTarget = resetTestTarget

			response := d.handleResetRestoreToken(Request{Cmd: "reset-restore-token", Target: resetTestTarget})

			if response.OK {
				t.Fatalf("reset unexpectedly succeeded: %+v", response)
			}
			d.mu.Lock()
			streamPreserved := d.streams[resetTestTarget] == entry
			groupPreserved := d.captureGroups[group.key] == group && entry.captureGroup == group
			errorPreserved := d.lastError == "existing stream error" && d.lastErrorTarget == resetTestTarget
			d.mu.Unlock()
			if !streamPreserved || !groupPreserved {
				t.Fatalf("credential failure changed stream state: stream=%t group=%t", streamPreserved, groupPreserved)
			}
			if !errorPreserved {
				t.Fatalf("credential failure changed last error: %q for %q", d.lastError, d.lastErrorTarget)
			}
			select {
			case <-streamCtx.Done():
				t.Fatal("credential failure canceled the original stream")
			default:
			}
			creds := d.credStore.Lookup("device-1")
			if creds == nil || creds.RestoreToken != "restore-1" {
				t.Fatalf("credential failure changed restore token: %+v", creds)
			}

			peer := &activeStream{deviceIP: "192.0.2.11", state: StateConnecting}
			d.mu.Lock()
			d.streams[peer.deviceIP] = peer
			d.mu.Unlock()
			broadcast, _, err := d.getOrStartPreparedCaptureGroup(context.Background(), peer, nil, 1920, 1080, airplay.VideoCodecH264)
			if err != nil || broadcast != group.broadcast {
				t.Fatalf("capture reservation remained after failed reset: broadcast=%p err=%v", broadcast, err)
			}
			d.mu.Lock()
			delete(d.streams, peer.deviceIP)
			peer.captureGroup = nil
			d.mu.Unlock()
		})
	}
}

func TestResetRestoreTokenReservationExcludesCaptureGroupJoin(t *testing.T) {
	saveStarted := make(chan struct{})
	saveRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseSave := func() { releaseOnce.Do(func() { close(saveRelease) }) }
	backend := &controlledCredentialBackend{
		credentials: &airplay.SavedCredentials{RestoreToken: "restore-1"},
		saveStarted: saveStarted,
		saveRelease: saveRelease,
		saveErr:     errors.New("save failed"),
	}
	d, _, _, _ := newResetTestDaemon(t, backend)
	defer d.Shutdown()
	defer releaseSave()
	peer := &activeStream{deviceIP: "192.0.2.11", state: StateConnecting}
	d.streams[peer.deviceIP] = peer

	resetResponse := make(chan Response, 1)
	go func() {
		resetResponse <- d.handleResetRestoreToken(Request{Cmd: "reset-restore-token", Target: resetTestTarget})
	}()
	waitForResetSignal(t, saveStarted, "credential save did not start")

	type joinResult struct {
		err error
	}
	joinResults := make(chan joinResult, 1)
	go func() {
		_, _, err := d.getOrStartPreparedCaptureGroup(context.Background(), peer, nil, 1920, 1080, airplay.VideoCodecH264)
		joinResults <- joinResult{err: err}
	}()
	var result joinResult
	select {
	case result = <-joinResults:
	case <-time.After(time.Second):
		t.Fatal("peer capture join blocked behind credential backend I/O")
	}
	if result.err == nil || !strings.Contains(result.err.Error(), "reserved for restore-token reset") {
		t.Fatalf("peer capture join error = %v, want reset reservation rejection", result.err)
	}
	d.mu.Lock()
	joined := peer.captureGroup != nil
	delete(d.streams, peer.deviceIP)
	d.mu.Unlock()
	if joined {
		t.Fatal("peer joined capture group while restore-token reset was reserved")
	}

	releaseSave()
	response := waitForResetResponse(t, resetResponse)
	if response.OK || !strings.Contains(response.Error, "save failed") {
		t.Fatalf("reset response = %+v, want credential save failure", response)
	}
}

func TestResetRestoreTokenReservationSurvivesPhysicalCaptureCleanup(t *testing.T) {
	backend := &controlledCredentialBackend{
		credentials: &airplay.SavedCredentials{RestoreToken: "restore-1"},
	}
	d, entry, oldGroup, _ := newResetTestDaemon(t, backend)
	cleanupStarted := make(chan struct{})
	cleanupRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseCleanup := func() { releaseOnce.Do(func() { close(cleanupRelease) }) }
	originalCancel := entry.cancelFn
	entry.cancelFn = func() {
		close(cleanupStarted)
		<-cleanupRelease
		originalCancel()
	}
	peer := &activeStream{deviceIP: "192.0.2.11", state: StateConnecting}
	d.streams[peer.deviceIP] = peer
	defer d.Shutdown()
	defer releaseCleanup()

	resetResponse := make(chan Response, 1)
	go func() {
		resetResponse <- d.handleResetRestoreToken(Request{Cmd: "reset-restore-token", Target: resetTestTarget})
	}()
	waitForResetSignal(t, cleanupStarted, "old capture cleanup did not start")

	d.mu.Lock()
	replacement := d.streams[resetTestTarget]
	reservation := d.captureGroups[oldGroup.key]
	reserved := reservation != nil && reservation != oldGroup &&
		reservation.resetReservedBy == replacement &&
		replacement.captureGroup == reservation
	d.mu.Unlock()
	if !reserved {
		t.Fatal("replacement did not retain an exclusive capture-key reservation during cleanup")
	}

	_, _, joinErr := d.getOrStartPreparedCaptureGroup(
		context.Background(), peer, nil, 1920, 1080, airplay.VideoCodecH264,
	)
	if joinErr == nil || !strings.Contains(joinErr.Error(), "reserved for restore-token reset") {
		t.Fatalf("capture join during cleanup = %v, want reset reservation rejection", joinErr)
	}
	d.mu.Lock()
	delete(d.streams, peer.deviceIP)
	d.mu.Unlock()

	releaseCleanup()
	if response := waitForResetResponse(t, resetResponse); !response.OK {
		t.Fatalf("reset response = %+v", response)
	}
}

func TestResetRestoreTokenReservationMakesShutdownWait(t *testing.T) {
	saveStarted := make(chan struct{})
	saveRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseSave := func() { releaseOnce.Do(func() { close(saveRelease) }) }
	backend := &controlledCredentialBackend{
		credentials: &airplay.SavedCredentials{RestoreToken: "restore-1"},
		saveStarted: saveStarted,
		saveRelease: saveRelease,
	}
	d, entry, _, _ := newResetTestDaemon(t, backend)
	defer releaseSave()

	cancelEvents := make(chan struct{}, 2)
	originalCancel := entry.cancelFn
	entry.cancelFn = func() {
		originalCancel()
		cancelEvents <- struct{}{}
	}
	resetResponse := make(chan Response, 1)
	resetDone := make(chan struct{})
	go func() {
		resetResponse <- d.handleResetRestoreToken(Request{Cmd: "reset-restore-token", Target: resetTestTarget})
		close(resetDone)
	}()
	defer func() {
		releaseSave()
		waitForResetSignal(t, resetDone, "reset did not finish during cleanup")
	}()
	waitForResetSignal(t, saveStarted, "credential save did not start")
	select {
	case <-cancelEvents:
		// The old implementation canceled before credential I/O. Drain that event
		// so only shutdown detachment can satisfy the wait below.
	default:
	}

	shutdownDone := make(chan struct{})
	go func() {
		d.Shutdown()
		close(shutdownDone)
	}()
	waitForResetSignal(t, cancelEvents, "shutdown did not detach the reserved stream")
	select {
	case <-shutdownDone:
		t.Fatal("Shutdown returned while credential I/O was still blocked")
	case <-time.After(100 * time.Millisecond):
	}

	releaseSave()
	response := waitForResetResponse(t, resetResponse)
	if response.OK || !strings.Contains(response.Error, "shutting down") || response.State != StateIdle {
		t.Fatalf("reset response during shutdown = %+v", response)
	}
	if credentials := d.credStore.Lookup("device-1"); credentials == nil || credentials.RestoreToken != "restore-1" {
		t.Fatalf("shutdown cancellation lost restore token: %+v", credentials)
	}
	waitForResetSignal(t, shutdownDone, "Shutdown did not finish after reset released its reservation")
}

func TestResetRestoreTokenConcurrentDisconnectReportsCancellationAndOverallState(t *testing.T) {
	backend := &controlledCredentialBackend{
		credentials: &airplay.SavedCredentials{RestoreToken: "restore-1"},
	}
	d, entry, _, _ := newResetTestDaemon(t, backend)
	cleanupStarted := make(chan struct{})
	cleanupRelease := make(chan struct{})
	var releaseOnce sync.Once
	releaseCleanup := func() { releaseOnce.Do(func() { close(cleanupRelease) }) }
	originalCancel := entry.cancelFn
	entry.cancelFn = func() {
		close(cleanupStarted)
		<-cleanupRelease
		originalCancel()
	}
	independentGroup := &videoCaptureGroup{key: normalizedVideoCaptureKey(1280, 720)}
	independent := &activeStream{
		deviceIP:     "192.0.2.20",
		deviceID:     "device-2",
		port:         7000,
		state:        StateStreaming,
		captureGroup: independentGroup,
	}
	d.streams[independent.deviceIP] = independent
	d.captureGroups[independentGroup.key] = independentGroup
	defer d.Shutdown()
	defer releaseCleanup()

	resetResponse := make(chan Response, 1)
	go func() {
		resetResponse <- d.handleResetRestoreToken(Request{Cmd: "reset-restore-token", Target: resetTestTarget})
	}()
	waitForResetSignal(t, cleanupStarted, "old stream cleanup did not start")

	disconnect := d.handleDisconnect(Request{Cmd: "disconnect", Target: resetTestTarget})
	if !disconnect.OK || disconnect.State != StateStreaming {
		t.Fatalf("concurrent disconnect response = %+v, want independent stream preserved", disconnect)
	}
	releaseCleanup()
	response := waitForResetResponse(t, resetResponse)
	if response.OK || !strings.Contains(response.Error, "canceled") {
		t.Fatalf("reset response = %+v, want concurrent cancellation", response)
	}
	if strings.Contains(response.Error, "shutting down") || response.State != StateStreaming {
		t.Fatalf("reset misreported concurrent disconnect: %+v", response)
	}
	if credentials := d.credStore.Lookup("device-1"); credentials == nil || credentials.RestoreToken != "restore-1" {
		t.Fatalf("disconnect cancellation lost restore token: %+v", credentials)
	}
}

func TestCanceledResetReportsRollbackPersistenceFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		lookupErrAt int
		saveErrAt   int
	}{
		{name: "rollback lookup", lookupErrAt: 2},
		{name: "rollback save", saveErrAt: 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &controlledCredentialBackend{
				credentials: &airplay.SavedCredentials{RestoreToken: "restore-1"},
				lookupErrAt: test.lookupErrAt,
				saveErrAt:   test.saveErrAt,
			}
			d, entry, _, _ := newResetTestDaemon(t, backend)
			cleanupStarted := make(chan struct{})
			cleanupRelease := make(chan struct{})
			originalCancel := entry.cancelFn
			entry.cancelFn = func() {
				close(cleanupStarted)
				<-cleanupRelease
				originalCancel()
			}
			defer d.Shutdown()

			resetResponse := make(chan Response, 1)
			go func() {
				resetResponse <- d.handleResetRestoreToken(Request{Cmd: "reset-restore-token", Target: resetTestTarget})
			}()
			waitForResetSignal(t, cleanupStarted, "cleanup did not start")
			if response := d.handleDisconnect(Request{Cmd: "disconnect", Target: resetTestTarget}); !response.OK {
				t.Fatalf("disconnect response = %+v", response)
			}
			close(cleanupRelease)

			response := waitForResetResponse(t, resetResponse)
			if response.OK || !strings.Contains(response.Error, "rollback failed") {
				t.Fatalf("reset response = %+v, want explicit rollback failure", response)
			}
		})
	}
}

func TestRestoreTokenResetReservationMigratesChangedCanvasExclusively(t *testing.T) {
	d, entry, reservation, _ := newResetTestDaemon(t, &controlledCredentialBackend{})
	oldKey := reservation.key
	newKey := normalizedVideoCaptureKey(1280, 720, airplay.VideoCodecH264)
	reservation.broadcast = nil
	reservation.resetReservedBy = entry

	d.mu.Lock()
	migrated, err := d.migrateRestoreTokenResetReservationLocked(entry, newKey)
	oldReleased := d.captureGroups[oldKey] == nil
	newOwned := d.captureGroups[newKey] == reservation
	d.mu.Unlock()
	if err != nil || migrated != reservation || !oldReleased || !newOwned {
		t.Fatalf("migration = %p, %v, oldReleased=%t newOwned=%t", migrated, err, oldReleased, newOwned)
	}

	occupiedKey := normalizedVideoCaptureKey(3840, 2160, airplay.VideoCodecH264)
	occupied := &videoCaptureGroup{key: occupiedKey}
	d.mu.Lock()
	d.captureGroups[occupiedKey] = occupied
	_, err = d.migrateRestoreTokenResetReservationLocked(entry, occupiedKey)
	stillOwned := d.captureGroups[newKey] == reservation && entry.captureGroup == reservation
	d.mu.Unlock()
	if err == nil || !errors.Is(err, errCaptureGroupResetReserved) || !stillOwned {
		t.Fatalf("occupied migration = %v, stillOwned=%t", err, stillOwned)
	}

	d.mu.Lock()
	cleanup := d.detachStreamLocked(resetTestTarget)
	reservationReleased := d.captureGroups[newKey] == nil
	d.mu.Unlock()
	cleanup.run()
	if !reservationReleased {
		t.Fatal("disconnect left migrated reservation behind")
	}
}

func TestResetRestoreTokenClearsExclusiveTargetAndReconnectsActualPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr == nil {
			accepted <- conn
		}
	}()

	d, err := New(Config{CredFile: filepath.Join(t.TempDir(), "credentials.json")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Shutdown()
	if err := d.credStore.SaveRestoreToken("device-1", "restore-1"); err != nil {
		t.Fatalf("SaveRestoreToken: %v", err)
	}
	address := listener.Addr().(*net.TCPAddr)
	group := &videoCaptureGroup{key: normalizedVideoCaptureKey(1920, 1080)}
	oldContext, cancelOld := context.WithCancel(context.Background())
	old := &activeStream{
		deviceIP:     address.IP.String(),
		deviceID:     "device-1",
		state:        StateStreaming,
		port:         address.Port,
		captureGroup: group,
		cancelFn:     cancelOld,
	}
	independentGroup := &videoCaptureGroup{key: normalizedVideoCaptureKey(1280, 720)}
	independent := &activeStream{
		deviceIP:     "192.0.2.20",
		deviceID:     "device-2",
		state:        StateStreaming,
		captureGroup: independentGroup,
	}
	d.streams[old.deviceIP] = old
	d.streams[independent.deviceIP] = independent
	d.captureGroups[group.key] = group
	d.captureGroups[independentGroup.key] = independentGroup

	response := d.handleRequest(Request{Cmd: "reset-restore-token", Target: old.deviceIP})

	if !response.OK {
		t.Fatalf("reset response = %+v", response)
	}
	creds := d.credStore.Lookup("device-1")
	if creds == nil || creds.RestoreToken != "" {
		t.Fatalf("restore token was not cleared: %+v", creds)
	}
	select {
	case <-oldContext.Done():
	default:
		t.Fatal("old stream cleanup did not finish before reset returned")
	}
	d.mu.Lock()
	replacement := d.streams[old.deviceIP]
	replacementGroup := d.captureGroups[group.key]
	oldGroupStillPresent := replacementGroup == group
	independentPreserved := d.streams[independent.deviceIP] == independent &&
		d.captureGroups[independentGroup.key] == independentGroup
	d.mu.Unlock()
	if replacement == nil || replacement == old || replacement.port != address.Port {
		t.Fatalf("replacement stream = %+v, want new entry on port %d", replacement, address.Port)
	}
	if oldGroupStillPresent {
		t.Fatal("exclusive old capture group remained active")
	}
	if replacementGroup != nil && replacement.captureGroup != replacementGroup {
		t.Fatal("replacement did not own the reserved capture generation")
	}
	if !independentPreserved {
		t.Fatal("reset changed an independent stream or capture group")
	}
	select {
	case conn := <-accepted:
		defer conn.Close()
	case <-time.After(3 * time.Second):
		t.Fatal("reset did not reconnect to the target's actual port")
	}
}

const resetTestTarget = "192.0.2.10"

type controlledCredentialBackend struct {
	credentials *airplay.SavedCredentials
	lookupErr   error
	saveErr     error
	saveStarted chan struct{}
	saveRelease <-chan struct{}
	saveOnce    sync.Once
	lookupCalls int
	saveCalls   int
	lookupErrAt int
	saveErrAt   int
}

func (b *controlledCredentialBackend) Lookup(string) (*airplay.SavedCredentials, error) {
	b.lookupCalls++
	if b.lookupErrAt > 0 && b.lookupCalls == b.lookupErrAt {
		return nil, errors.New("injected lookup failure")
	}
	if b.lookupErr != nil {
		err := b.lookupErr
		b.lookupErr = nil
		return nil, err
	}
	if b.credentials == nil {
		return nil, nil
	}
	credentials := *b.credentials
	return &credentials, nil
}

func (b *controlledCredentialBackend) Save(_ string, credentials *airplay.SavedCredentials) error {
	if b.saveStarted != nil {
		b.saveOnce.Do(func() { close(b.saveStarted) })
	}
	if b.saveRelease != nil {
		<-b.saveRelease
	}
	b.saveCalls++
	if b.saveErrAt > 0 && b.saveCalls == b.saveErrAt {
		return errors.New("injected save failure")
	}
	if b.saveErr != nil {
		return b.saveErr
	}
	updated := *credentials
	b.credentials = &updated
	return nil
}

func newResetTestDaemon(t *testing.T, backend airplay.CredentialBackend) (*Daemon, *activeStream, *videoCaptureGroup, context.Context) {
	t.Helper()
	d, err := New(Config{
		SocketPath: filepath.Join(t.TempDir(), "doubletake.sock"),
		CredFile:   filepath.Join(t.TempDir(), "credentials.json"),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	d.credStore = airplay.NewCredentialStoreWithBackend(backend)
	group := &videoCaptureGroup{
		key:       normalizedVideoCaptureKey(1920, 1080),
		broadcast: airplay.NewBroadcastCapture(nil),
	}
	streamCtx, cancel := context.WithCancel(context.Background())
	entry := &activeStream{
		deviceIP:     resetTestTarget,
		deviceID:     "device-1",
		port:         7000,
		state:        StateStreaming,
		captureGroup: group,
		cancelFn:     cancel,
	}
	d.streams[resetTestTarget] = entry
	d.captureGroups[group.key] = group
	return d, entry, group, streamCtx
}

func waitForResetSignal(t *testing.T, signal <-chan struct{}, failure string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(time.Second):
		t.Fatal(failure)
	}
}

func waitForResetResponse(t *testing.T, responses <-chan Response) Response {
	t.Helper()
	select {
	case response := <-responses:
		return response
	case <-time.After(time.Second):
		t.Fatal("reset did not return")
		return Response{}
	}
}
