package airplay

import (
	"math"
	"sync/atomic"
	"time"
)

const defaultTargetLatency = 1 * time.Millisecond

// conservativePlayoutLatency is the playout lead required by receivers that lack
// a robust audio jitter buffer (third-party AirPlay implementations such as
// Roku, which do not advertise FairPlay SAP). The control-port sync anchor
// reports that the newest audio frame plays this far in the future, which is
// also the buffer lead the receiver has to schedule each packet before its play
// time. With too little lead these receivers drop audio they can no longer
// schedule. Modern Apple receivers buffer aggressively and do not need this, so
// it is applied per-receiver (see ReceiverInfo.playoutLatencyFloor), not
// globally — audio and video share whatever latency is chosen so they stay in
// sync.
const conservativePlayoutLatency = 500 * time.Millisecond

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
	return samplesFor44k1(TargetLatency())
}

func samplesFor44k1(d time.Duration) uint32 {
	samples := int64(math.Round(float64(d) * 44100.0 / float64(time.Second)))
	if samples < 1 {
		samples = 1
	}
	if samples > math.MaxUint32 {
		samples = math.MaxUint32
	}
	return uint32(samples)
}
