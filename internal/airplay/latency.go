package airplay

import (
	"math"
	"sync/atomic"
	"time"
)

const defaultTargetLatency = 100 * time.Millisecond

var targetLatencyNS atomic.Int64

func init() {
	targetLatencyNS.Store(int64(defaultTargetLatency))
}

// SetTargetLatency sets the desired end-to-end playout latency target.
// Values are clamped to a sane operational range.
func SetTargetLatency(d time.Duration) {
	if d < 5*time.Millisecond {
		d = 5 * time.Millisecond
	}
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	targetLatencyNS.Store(int64(d))
}

// TargetLatency returns the configured playout latency target.
func TargetLatency() time.Duration {
	d := time.Duration(targetLatencyNS.Load())
	if d <= 0 {
		return defaultTargetLatency
	}
	return d
}

func targetLatencySamples44k1() uint32 {
	d := TargetLatency()
	samples := int64(math.Round(float64(d) * 44100.0 / float64(time.Second)))
	if samples < 1 {
		samples = 1
	}
	if samples > math.MaxUint32 {
		samples = math.MaxUint32
	}
	return uint32(samples)
}
