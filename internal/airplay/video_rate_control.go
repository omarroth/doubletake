package airplay

import (
	"log"
	"sync"
	"time"
)

const (
	// Apple's screen sender assigns 75 percent of the current network bandwidth
	// estimate to video, then clamps that budget to a 1--40 Mbit/s range. Keep
	// doubletake's resolution-derived bitrate as the upper bound: it is both a
	// quality setting and a guard against needlessly saturating a local network.
	videoBandwidthAllocationNumerator   = 3
	videoBandwidthAllocationDenominator = 4
	appleMinimumVideoBitrateKbps        = 1000

	videoTelemetryInterval = 500 * time.Millisecond
	videoTelemetryMaxAge   = 2 * time.Second
	videoRecoveryHold      = 2 * time.Second
	videoFPSHysteresis     = 5 * time.Second
	videoSlowWrite         = 25 * time.Millisecond
	videoQueueDelayLimit   = 10 * time.Millisecond
	videoQueueDelaySamples = 3
)

// videoTransportMetrics is deliberately independent of Linux's tcp_info.
// Other operating systems can populate the same observations from their own
// socket APIs without changing capture or rate-control policy.
type videoTransportMetrics struct {
	At                      time.Time
	DeliveryRateBps         uint64
	PacingRateBps           uint64
	CongestionWindowRateBps uint64
	BytesAcked              uint64
	BytesRetransmitted      uint64
	NotSentBytes            uint32
	RoundTripTime           time.Duration
	RoundTripVariation      time.Duration
	MinimumRoundTripTime    time.Duration
	WriteDuration           time.Duration
	transportSampled        bool
}

func (sample videoTransportMetrics) hasTransportSample() bool {
	// Tests and future platform samplers may construct useful partial metrics.
	// The explicit bit distinguishes a valid all-zero kernel sample from the
	// portable write-only observation used when socket telemetry is unavailable.
	return sample.transportSampled || sample.DeliveryRateBps != 0 || sample.PacingRateBps != 0 ||
		sample.CongestionWindowRateBps != 0 || sample.BytesAcked != 0 ||
		sample.BytesRetransmitted != 0 || sample.NotSentBytes != 0 ||
		sample.RoundTripTime != 0 || sample.MinimumRoundTripTime != 0
}

type videoReceiverRateState struct {
	lastSeen           time.Time
	availableBps       uint64
	bytesAcked         uint64
	bytesRetransmitted uint64
	notSentBytes       uint32
	queuePressure      int
	minimumRTT         time.Duration
	queueDelay         time.Duration
	delayPressure      int
	hasCounters        bool
	congested          bool
}

type videoRateController struct {
	mu sync.Mutex

	runtime captureRuntimeController
	publish func(videoRateState)

	maxBitrateKbps int
	maxFPS         int
	bitrateKbps    int
	fps            int

	receivers map[uint64]*videoReceiverRateState
	nextID    uint64

	recoverySince     time.Time
	lastBitrateChange time.Time
	fpsCandidate      int
	fpsCandidateSince time.Time

	bitrateControlFailed bool
	fpsControlFailed     bool
}

type videoRateState struct {
	bitrateKbps            int
	fps                    int
	estimatedBandwidthKbps int
	receivers              int
}

func newVideoRateController(runtime captureRuntimeController, bitrateKbps, fps int, publish func(videoRateState)) *videoRateController {
	if runtime == nil || bitrateKbps <= 0 || fps <= 0 {
		return nil
	}
	c := &videoRateController{
		runtime:        runtime,
		publish:        publish,
		maxBitrateKbps: bitrateKbps,
		maxFPS:         fps,
		bitrateKbps:    bitrateKbps,
		fps:            fps,
		receivers:      make(map[uint64]*videoReceiverRateState),
	}
	c.publishLocked(0)
	return c
}

func (c *videoRateController) attachReceiver() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	c.receivers[c.nextID] = &videoReceiverRateState{}
	c.publishLocked(c.weakestBandwidthLocked(time.Now()))
	return c.nextID
}

func (c *videoRateController) detachReceiver(id uint64) {
	if c == nil || id == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.receivers, id)
	c.recalculateLocked(time.Now())
}

func (c *videoRateController) observe(id uint64, sample videoTransportMetrics) {
	if c == nil || id == 0 {
		return
	}
	if sample.At.IsZero() {
		sample.At = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	receiver := c.receivers[id]
	if receiver == nil {
		return
	}
	receiver.lastSeen = sample.At
	var reason string
	receiver.congested, reason = c.sampleIsCongestedLocked(receiver, sample)
	estimate := c.estimateAvailableBandwidthLocked(sample)
	if estimate != 0 {
		receiver.availableBps = estimate
	} else if receiver.congested && receiver.availableBps == 0 {
		// Slow writes remain useful on platforms without a socket bandwidth API.
		// Seed an estimate whose 75-percent allocation equals the current rate;
		// the congestion backoff below will then lower it once.
		receiver.availableBps = saturatingRatio(
			uint64(c.bitrateKbps*1000),
			videoBandwidthAllocationDenominator,
			videoBandwidthAllocationNumerator,
		)
	}
	dbg("[RATE] receiver=%d available=%d kbps delivery=%d kbps pacing=%d kbps cwnd=%d kbps rtt=%v rttvar=%v queue-delay=%v notsent=%d write=%v congested=%t reason=%s",
		id, receiver.availableBps/1000, sample.DeliveryRateBps/1000, sample.PacingRateBps/1000,
		sample.CongestionWindowRateBps/1000, sample.RoundTripTime, sample.RoundTripVariation, receiver.queueDelay,
		sample.NotSentBytes, sample.WriteDuration, receiver.congested, reason)
	if sample.hasTransportSample() {
		receiver.bytesAcked = sample.BytesAcked
		receiver.bytesRetransmitted = sample.BytesRetransmitted
		receiver.notSentBytes = sample.NotSentBytes
		receiver.hasCounters = true
	}
	c.recalculateLocked(sample.At)
}

func (c *videoRateController) estimateAvailableBandwidthLocked(sample videoTransportMetrics) uint64 {
	// TCP delivery rate is commonly application-limited for a screen stream.
	// Restore the same 4/3 headroom that Apple's later 3/4 allocation removes,
	// otherwise every observation would recursively lower its own offered load.
	delivery := sample.DeliveryRateBps
	if delivery != 0 {
		delivery = saturatingRatio(delivery, videoBandwidthAllocationDenominator, videoBandwidthAllocationNumerator)
	}
	capacity := sample.CongestionWindowRateBps
	if sample.PacingRateBps != 0 && (capacity == 0 || sample.PacingRateBps < capacity) {
		capacity = sample.PacingRateBps
	}
	if delivery == 0 {
		return capacity
	}
	// Kernel congestion-window and pacing estimates can be extremely large on
	// a quiet LAN. Permit useful recovery headroom but never let them claim more
	// than twice the recently delivered rate.
	deliveryCeiling := saturatingMultiply(delivery, 2)
	if capacity > deliveryCeiling {
		capacity = deliveryCeiling
	}
	if capacity > delivery {
		return capacity
	}
	return delivery
}

func (c *videoRateController) sampleIsCongestedLocked(receiver *videoReceiverRateState, sample videoTransportMetrics) (bool, string) {
	if sample.WriteDuration >= videoSlowWrite {
		return true, "slow-write"
	}
	if !sample.hasTransportSample() {
		return false, "none"
	}
	// Apple's rate controller records one-way relative delay so it can react to
	// queue growth before packets are lost. TCP_INFO does not expose receiver
	// OWRD, but RTT growth above the connection minimum is the same receiver-
	// neutral signal with the reverse-path component folded in. Require three
	// consecutive observations above ten milliseconds to ignore an isolated
	// wireless or scheduler spike.
	receiver.queueDelay = 0
	if sample.RoundTripTime > 0 {
		minimumRTT := sample.MinimumRoundTripTime
		if minimumRTT <= 0 {
			minimumRTT = sample.RoundTripTime
		}
		if receiver.minimumRTT == 0 || minimumRTT < receiver.minimumRTT {
			receiver.minimumRTT = minimumRTT
		}
		if sample.RoundTripTime > receiver.minimumRTT {
			receiver.queueDelay = sample.RoundTripTime - receiver.minimumRTT
		}
		if receiver.queueDelay > videoQueueDelayLimit {
			receiver.delayPressure++
		} else {
			receiver.delayPressure = 0
		}
		if receiver.delayPressure >= videoQueueDelaySamples {
			return true, "queue-delay"
		}
	} else {
		receiver.delayPressure = 0
	}
	if receiver.hasCounters && sample.BytesRetransmitted > receiver.bytesRetransmitted {
		retransmitted := sample.BytesRetransmitted - receiver.bytesRetransmitted
		acknowledged := uint64(0)
		if sample.BytesAcked > receiver.bytesAcked {
			acknowledged = sample.BytesAcked - receiver.bytesAcked
		}
		// One retransmitted segment on an otherwise healthy TCP path is noise.
		// Treat retransmission as congestion only when at least 4 KiB and roughly
		// five percent of newly acknowledged data had to be sent again.
		threshold := acknowledged / 20
		if threshold < 4<<10 {
			threshold = 4 << 10
		}
		if retransmitted >= threshold {
			return true, "retransmission"
		}
	}
	// A small send buffer is normally occupied by a few frames. Require a queue
	// materially larger than that buffer, which is nondecreasing for three
	// observations, before treating it as persistent pressure.
	fps := c.fps
	if fps <= 0 {
		fps = 30
	}
	queuedLimit := uint64(c.bitrateKbps*1000/8/fps) * 6
	if queuedLimit < 128<<10 {
		queuedLimit = 128 << 10
	}
	if uint64(sample.NotSentBytes) >= queuedLimit && sample.NotSentBytes >= receiver.notSentBytes {
		receiver.queuePressure++
	} else {
		receiver.queuePressure = 0
	}
	if receiver.queuePressure >= 3 {
		return true, "send-queue"
	}
	return false, "none"
}

func (c *videoRateController) recalculateLocked(now time.Time) {
	available := c.weakestBandwidthLocked(now)
	if available == 0 {
		c.recoverySince = time.Time{}
		c.resetFPSCandidateLocked()
		c.publishLocked(0)
		return
	}

	allocatedKbps := saturatingRatio(available, videoBandwidthAllocationNumerator, videoBandwidthAllocationDenominator) / 1000
	desired := c.maxBitrateKbps
	if allocatedKbps < uint64(desired) {
		desired = int(allocatedKbps)
	}
	minimum := appleMinimumVideoBitrateKbps
	if c.maxBitrateKbps < minimum {
		minimum = c.maxBitrateKbps
	}
	if desired < minimum {
		desired = minimum
	}
	if desired > c.maxBitrateKbps {
		desired = c.maxBitrateKbps
	}
	congested := c.anyCongestedLocked(now)
	if congested {
		// Backpressure or retransmission is more current than a delivery-rate
		// sample. Back off once even if the kernel estimate has not caught up.
		backoff := c.bitrateKbps * 3 / 4
		if backoff < minimum {
			backoff = minimum
		}
		if desired > backoff {
			desired = backoff
		}
	}

	switch {
	case desired < c.bitrateKbps:
		c.recoverySince = time.Time{}
		c.applyBitrateLocked(desired, now)
	case desired > c.bitrateKbps && !congested:
		if c.recoverySince.IsZero() {
			c.recoverySince = now
		} else if now.Sub(c.recoverySince) >= videoRecoveryHold && now.Sub(c.lastBitrateChange) >= videoRecoveryHold {
			step := c.bitrateKbps / 4
			if step < 250 {
				step = 250
			}
			if desired > c.bitrateKbps+step {
				desired = c.bitrateKbps + step
			}
			c.applyBitrateLocked(desired, now)
			c.recoverySince = now
		}
	default:
		if congested {
			c.recoverySince = time.Time{}
		}
	}

	c.updateFPSLocked(appleVideoFrameRate(available, c.maxFPS), now)
	c.publishLocked(available)
}

func (c *videoRateController) weakestBandwidthLocked(now time.Time) uint64 {
	var weakest uint64
	for _, receiver := range c.receivers {
		if receiver.availableBps == 0 || receiver.lastSeen.IsZero() || now.Sub(receiver.lastSeen) > videoTelemetryMaxAge {
			continue
		}
		if weakest == 0 || receiver.availableBps < weakest {
			weakest = receiver.availableBps
		}
	}
	return weakest
}

func (c *videoRateController) anyCongestedLocked(now time.Time) bool {
	for _, receiver := range c.receivers {
		if receiver.congested && !receiver.lastSeen.IsZero() && now.Sub(receiver.lastSeen) <= videoTelemetryMaxAge {
			return true
		}
	}
	return false
}

func (c *videoRateController) applyBitrateLocked(bitrate int, now time.Time) {
	if c.bitrateControlFailed || bitrate == c.bitrateKbps {
		return
	}
	if err := c.runtime.setBitrateKbps(bitrate); err != nil {
		c.bitrateControlFailed = true
		log.Printf("[CAPTURE] disabling automatic video bitrate changes for this encoder: %v", err)
		return
	}
	log.Printf("[CAPTURE] network controller changed video bitrate from %d to %d kbps", c.bitrateKbps, bitrate)
	c.bitrateKbps = bitrate
	c.lastBitrateChange = now
}

func appleVideoFrameRate(availableBps uint64, maximum int) int {
	fps := 60
	switch {
	case availableBps < 500_000:
		fps = 10
	case availableBps < 1_000_000:
		fps = 20
	case availableBps < 4_000_000:
		fps = 30
	}
	if fps > maximum {
		fps = maximum
	}
	return fps
}

func (c *videoRateController) updateFPSLocked(target int, now time.Time) {
	if c.fpsControlFailed || target <= 0 || target == c.fps {
		c.resetFPSCandidateLocked()
		return
	}
	if target != c.fpsCandidate {
		c.fpsCandidate = target
		c.fpsCandidateSince = now
		return
	}
	if now.Sub(c.fpsCandidateSince) < videoFPSHysteresis {
		return
	}
	next := adjacentVideoFrameRate(c.fps, target, c.maxFPS)
	if err := c.runtime.setFrameRate(next); err != nil {
		c.fpsControlFailed = true
		log.Printf("[CAPTURE] disabling automatic video frame-rate changes for this pipeline: %v", err)
		return
	}
	log.Printf("[CAPTURE] network controller changed video frame rate from %d to %d fps", c.fps, next)
	c.fps = next
	c.fpsCandidateSince = now
}

func adjacentVideoFrameRate(current, target, maximum int) int {
	levels := []int{10, 20, 30, 60}
	if target > maximum {
		target = maximum
	}
	if target < current {
		for i := len(levels) - 1; i >= 0; i-- {
			if levels[i] < current {
				if levels[i] < target {
					return target
				}
				return levels[i]
			}
		}
		return target
	}
	for _, level := range levels {
		if level > current {
			if level > target || level > maximum {
				return target
			}
			return level
		}
	}
	return target
}

func (c *videoRateController) resetFPSCandidateLocked() {
	c.fpsCandidate = 0
	c.fpsCandidateSince = time.Time{}
}

func (c *videoRateController) publishLocked(availableBps uint64) {
	if c.publish == nil {
		return
	}
	c.publish(videoRateState{
		bitrateKbps:            c.bitrateKbps,
		fps:                    c.fps,
		estimatedBandwidthKbps: int(availableBps / 1000),
		receivers:              len(c.receivers),
	})
}

func saturatingRatio(value, numerator, denominator uint64) uint64 {
	if denominator == 0 {
		return ^uint64(0)
	}
	quotient, remainder := value/denominator, value%denominator
	whole := saturatingMultiply(quotient, numerator)
	if whole == ^uint64(0) {
		return whole
	}
	if remainder != 0 && numerator > ^uint64(0)/remainder {
		return ^uint64(0)
	}
	fraction := remainder * numerator / denominator
	if fraction > ^uint64(0)-whole {
		return ^uint64(0)
	}
	return whole + fraction
}

func saturatingMultiply(a, b uint64) uint64 {
	if a != 0 && b > ^uint64(0)/a {
		return ^uint64(0)
	}
	return a * b
}
