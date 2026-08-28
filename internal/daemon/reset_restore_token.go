package daemon

import (
	"context"

	"doubletake/internal/airplay"
)

func (d *Daemon) handleResetRestoreToken(req Request) Response {
	d.mu.Lock()
	if req.Target == "" {
		response := Response{OK: false, State: d.overallStateLocked(), Error: "reset-restore-token requires a target IP"}
		d.mu.Unlock()
		return response
	}
	if d.shuttingDown {
		d.mu.Unlock()
		return Response{OK: false, State: StateIdle, Error: "daemon is shutting down"}
	}
	entry, ok := d.streams[req.Target]
	if !ok {
		response := Response{OK: false, State: d.overallStateLocked(), Error: "no active stream to " + req.Target}
		d.mu.Unlock()
		return response
	}
	if entry.state != StateStreaming {
		response := Response{OK: false, State: d.overallStateLocked(), Error: "restore token can be reset only for a fully streaming target: " + req.Target}
		d.mu.Unlock()
		return response
	}
	group := entry.captureGroup
	if group == nil || d.captureGroups[group.key] != group {
		response := Response{OK: false, State: d.overallStateLocked(), Error: "active target has no owned capture group: " + req.Target}
		d.mu.Unlock()
		return response
	}
	if group.resetReservedBy != nil {
		response := Response{OK: false, State: d.overallStateLocked(), Error: "restore token reset is already in progress for " + req.Target}
		d.mu.Unlock()
		return response
	}
	for target, other := range d.streams {
		if target != req.Target && other.captureGroup == group {
			response := Response{OK: false, State: d.overallStateLocked(), Error: "target uses a shared capture group; disconnect its peers before resetting the restore token"}
			d.mu.Unlock()
			return response
		}
	}
	if entry.deviceIP != req.Target || entry.deviceID == "" || entry.port == 0 {
		response := Response{OK: false, State: d.overallStateLocked(), Error: "active target is missing receiver identity or port: " + req.Target}
		d.mu.Unlock()
		return response
	}

	target := entry.deviceIP
	deviceID := entry.deviceID
	port := entry.port
	group.resetReservedBy = entry
	// Register the reset before releasing d.mu. Shutdown may detach the original
	// stream while credential I/O is in progress, but it cannot finish Wait until
	// this request either abandons the reservation or starts the replacement.
	d.streamWorkers.Add(1)
	d.mu.Unlock()

	credentialReset, clearErr := d.credStore.BeginRestoreTokenReset(deviceID)

	d.mu.Lock()
	reservationCurrent := d.restoreTokenResetReservationCurrentLocked(target, deviceID, port, entry, group)
	state := d.overallStateLocked()
	if d.shuttingDown {
		if group.resetReservedBy == entry {
			group.resetReservedBy = nil
		}
		d.mu.Unlock()
		rollbackErr := rollbackRestoreTokenReset(credentialReset, clearErr)
		d.streamWorkers.Done()
		return Response{OK: false, State: state, Error: resetFailure("daemon is shutting down", rollbackErr)}
	}
	if !reservationCurrent {
		if group.resetReservedBy == entry {
			group.resetReservedBy = nil
		}
		d.mu.Unlock()
		rollbackErr := rollbackRestoreTokenReset(credentialReset, clearErr)
		d.streamWorkers.Done()
		return Response{OK: false, State: state, Error: resetFailure("restore token reset was canceled for "+target, rollbackErr)}
	}
	if clearErr != nil {
		group.resetReservedBy = nil
		d.mu.Unlock()
		d.streamWorkers.Done()
		return Response{OK: false, State: state, Error: "clear restore token: " + clearErr.Error()}
	}

	connCtx, cancel := context.WithCancel(context.Background())
	replacement := &activeStream{
		deviceIP:     target,
		deviceID:     deviceID,
		port:         port,
		state:        StateConnecting,
		cancelFn:     cancel,
		credentialCh: make(chan string, 1),
	}
	// Replace the old generation with an owner-only claim before releasing the
	// daemon lock. Peers cannot create or join this key while physical cleanup
	// runs; the designated replacement later converts the claim into a capture.
	group.resetReservedBy = nil
	cleanup := d.detachStreamLocked(target)
	reservation := &videoCaptureGroup{
		key:             group.key,
		resetReservedBy: replacement,
	}
	replacement.captureGroup = reservation
	d.captureGroups[group.key] = reservation
	d.streams[target] = replacement
	d.mu.Unlock()

	cleanup.run()

	// Cleanup can block, so disconnect or shutdown may remove the replacement
	// reservation before its worker starts. Only detach the exact generation we
	// published and report the daemon's actual aggregate state.
	d.mu.Lock()
	replacementCurrent := d.streams[target] == replacement
	shuttingDown := d.shuttingDown
	if shuttingDown || !replacementCurrent {
		abandoned := daemonCleanup{}
		if replacementCurrent {
			abandoned = d.detachStreamLocked(target)
		}
		state = d.overallStateLocked()
		d.mu.Unlock()
		abandoned.run()
		cancel()
		rollbackErr := credentialReset.Rollback()
		d.streamWorkers.Done()
		if shuttingDown {
			return Response{OK: false, State: state, Error: resetFailure("daemon is shutting down", rollbackErr)}
		}
		return Response{OK: false, State: state, Error: resetFailure("restore token reset was canceled for "+target, rollbackErr)}
	}
	d.clearLastErrorForTargetLocked(target)
	state = d.overallStateLocked()
	d.mu.Unlock()

	credentialReset.Commit()
	go func() {
		defer d.streamWorkers.Done()
		d.connectAndStream(connCtx, replacement, target, port, "")
	}()
	return Response{OK: true, State: state, Device: target, DeviceIP: target}
}

func rollbackRestoreTokenReset(reset *airplay.RestoreTokenReset, clearErr error) error {
	if clearErr != nil {
		return nil
	}
	return reset.Rollback()
}

func resetFailure(message string, rollbackErr error) string {
	if rollbackErr == nil {
		return message
	}
	return message + "; restore token rollback failed: " + rollbackErr.Error()
}

// restoreTokenResetReservationCurrentLocked reports whether the exact stream
// and exclusive capture generation reserved before credential I/O are still
// current. Must be called with d.mu held.
func (d *Daemon) restoreTokenResetReservationCurrentLocked(target, deviceID string, port int, entry *activeStream, group *videoCaptureGroup) bool {
	if d.streams[target] != entry || entry.state != StateStreaming ||
		entry.deviceIP != target || entry.deviceID != deviceID || entry.port != port ||
		entry.captureGroup != group || d.captureGroups[group.key] != group ||
		group.resetReservedBy != entry {
		return false
	}
	for otherTarget, other := range d.streams {
		if otherTarget != target && other.captureGroup == group {
			return false
		}
	}
	return true
}
