//go:build !linux

package airplay

import (
	"net"
	"time"
)

// Slow socket writes still feed the portable controller. Platform socket
// telemetry can be added here without changing the stream or capture layers.
type videoTransportSampler struct{}

func newVideoTransportSampler(net.Conn) *videoTransportSampler { return nil }

func (*videoTransportSampler) sample(time.Time) (videoTransportMetrics, bool) {
	return videoTransportMetrics{}, false
}
