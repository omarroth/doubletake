package airplay

import (
	"context"
	"fmt"
	"os"
	"sync"
)

type sharedPortal struct {
	mu     sync.Mutex
	portal pipeWirePortalSession
	users  int
}

type portalLease struct {
	owner *sharedPortal
	once  sync.Once
}

func (l *portalLease) Close() error {
	var err error
	l.once.Do(func() {
		l.owner.mu.Lock()
		defer l.owner.mu.Unlock()
		l.owner.users--
		if l.owner.users == 0 {
			err = l.owner.portal.Close()
		}
	})
	return err
}

func (l *portalLease) openPipeWireRemote(ctx context.Context) (*os.File, error) {
	l.owner.mu.Lock()
	defer l.owner.mu.Unlock()
	if l.owner.users == 0 {
		return nil, fmt.Errorf("shared capture portal is closed")
	}
	return l.owner.portal.openPipeWireRemote(ctx)
}

// Fork authorizes another encoder against the same selected capture source.
// Each Wayland fork has its own remote FD and a lease on the original portal,
// so stopping one resolution group cannot close another group's screen source.
// The original preparation remains unconsumed and acts as the source owner.
func (p *CapturePreparation) Fork(ctx context.Context, codec VideoCodec) (*CapturePreparation, error) {
	if p == nil {
		return nil, fmt.Errorf("capture source is nil")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.used {
		return nil, fmt.Errorf("capture source is closed or consumed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cfg := p.cfg
	if codec != "" && codec != cfg.VideoCodec {
		// Daemon auto fallback may pin H.264, which the original auto preflight
		// already validated. Other codec changes require a fresh preflight.
		if cfg.VideoCodec != VideoCodecAuto || codec != VideoCodecH264 {
			return nil, fmt.Errorf("capture source prepared for %s, cannot fork %s", cfg.VideoCodec, codec)
		}
		cfg.VideoCodec = codec
	}
	clone := &CapturePreparation{
		ctx: ctx, cfg: cfg, kind: p.kind, timestampedOutput: p.timestampedOutput,
		automaticHEVCAvail: p.automaticHEVCAvail, measuredVideoLatency: p.measuredVideoLatency,
		pwNodeID: p.pwNodeID, streamSize: p.streamSize,
	}
	if cfg.VideoCodec == VideoCodecH264 {
		clone.measuredVideoLatency = 0
	}
	if p.portal != nil {
		lease, ok := p.portal.(*portalLease)
		if !ok {
			lease = &portalLease{owner: &sharedPortal{portal: p.portal, users: 1}}
			p.portal = lease
		}
		lease.owner.mu.Lock()
		lease.owner.users++
		lease.owner.mu.Unlock()
		clone.portal = &portalLease{owner: lease.owner}
		fd, err := clone.portal.openPipeWireRemote(ctx)
		if err != nil {
			clone.portal.Close()
			return nil, fmt.Errorf("open shared PipeWire source: %w", err)
		}
		clone.pwFd = fd
	}
	return clone, nil
}
