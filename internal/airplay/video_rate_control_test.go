package airplay

import (
	"reflect"
	"testing"
	"time"
)

type fakeCaptureRuntimeController struct {
	bitrates []int
	frames   []int
	keys     int
}

func (f *fakeCaptureRuntimeController) setBitrateKbps(value int) error {
	f.bitrates = append(f.bitrates, value)
	return nil
}

func (f *fakeCaptureRuntimeController) setFrameRate(value int) error {
	f.frames = append(f.frames, value)
	return nil
}

func (f *fakeCaptureRuntimeController) requestKeyFrame() error {
	f.keys++
	return nil
}

func (*fakeCaptureRuntimeController) stop() {}

func TestVideoRateControllerUsesAppleScreenBandwidthAllocation(t *testing.T) {
	runtime := &fakeCaptureRuntimeController{}
	var state videoRateState
	controller := newVideoRateController(runtime, 12_000, 60, func(current videoRateState) { state = current })
	receiver := controller.attachReceiver()
	now := time.Now()
	controller.observe(receiver, videoTransportMetrics{
		At: now, CongestionWindowRateBps: 8_000_000,
	})
	if !reflect.DeepEqual(runtime.bitrates, []int{6000}) {
		t.Fatalf("bitrate changes = %v, want 75%% of 8 Mbit/s", runtime.bitrates)
	}
	if state.bitrateKbps != 6000 || state.estimatedBandwidthKbps != 8000 || state.receivers != 1 {
		t.Fatalf("published state = %+v", state)
	}

	controller.observe(receiver, videoTransportMetrics{
		At: now.Add(time.Second), CongestionWindowRateBps: 500_000,
	})
	if got := runtime.bitrates[len(runtime.bitrates)-1]; got != appleMinimumVideoBitrateKbps {
		t.Fatalf("minimum bitrate = %d, want %d", got, appleMinimumVideoBitrateKbps)
	}
	controller.observe(receiver, videoTransportMetrics{
		At: now.Add(time.Second + videoFPSHysteresis), CongestionWindowRateBps: 500_000,
	})
	if !reflect.DeepEqual(runtime.frames, []int{30}) {
		t.Fatalf("frame-rate changes = %v, want one tier from 60 to 30", runtime.frames)
	}
}

func TestVideoRateControllerUsesWeakestSharedReceiverAndRecovers(t *testing.T) {
	runtime := &fakeCaptureRuntimeController{}
	controller := newVideoRateController(runtime, 9000, 30, nil)
	fast := controller.attachReceiver()
	slow := controller.attachReceiver()
	now := time.Now()
	controller.observe(fast, videoTransportMetrics{At: now, CongestionWindowRateBps: 8_000_000})
	controller.observe(slow, videoTransportMetrics{At: now, CongestionWindowRateBps: 2_000_000})
	if got := runtime.bitrates[len(runtime.bitrates)-1]; got != 1500 {
		t.Fatalf("shared bitrate = %d, want weakest path allocation 1500", got)
	}

	controller.detachReceiver(slow)
	controller.observe(fast, videoTransportMetrics{
		At: now.Add(videoRecoveryHold + time.Second), CongestionWindowRateBps: 8_000_000,
	})
	if got := runtime.bitrates[len(runtime.bitrates)-1]; got != 1875 {
		t.Fatalf("first bounded recovery bitrate = %d, want 1875", got)
	}
}

func TestVideoRateControllerBacksOffOnRetransmission(t *testing.T) {
	runtime := &fakeCaptureRuntimeController{}
	controller := newVideoRateController(runtime, 6000, 30, nil)
	receiver := controller.attachReceiver()
	now := time.Now()
	controller.observe(receiver, videoTransportMetrics{
		At: now, CongestionWindowRateBps: 8_000_000, BytesAcked: 10_000, BytesRetransmitted: 10,
	})
	controller.observe(receiver, videoTransportMetrics{
		At: now.Add(videoTelemetryInterval), CongestionWindowRateBps: 8_000_000,
		BytesAcked: 60_000, BytesRetransmitted: 5010,
	})
	if !reflect.DeepEqual(runtime.bitrates, []int{4500}) {
		t.Fatalf("bitrate changes = %v, want a single 25%% congestion backoff", runtime.bitrates)
	}
}

func TestVideoRateControllerIgnoresNormalSmallSendBufferOccupancy(t *testing.T) {
	runtime := &fakeCaptureRuntimeController{}
	controller := newVideoRateController(runtime, 4147, 30, nil)
	receiver := controller.attachReceiver()
	now := time.Now()
	for sample := 0; sample < 4; sample++ {
		controller.observe(receiver, videoTransportMetrics{
			At:                      now.Add(time.Duration(sample) * videoTelemetryInterval),
			CongestionWindowRateBps: 100_000_000,
			BytesAcked:              uint64(sample+1) * 50_000,
			BytesRetransmitted:      uint64(sample),
			NotSentBytes:            64 << 10,
		})
	}
	if len(runtime.bitrates) != 0 {
		t.Fatalf("normal 64 KiB send-buffer occupancy changed bitrate: %v", runtime.bitrates)
	}
}

func TestVideoRateControllerBacksOffOnPersistentGrowingQueue(t *testing.T) {
	runtime := &fakeCaptureRuntimeController{}
	controller := newVideoRateController(runtime, 6000, 30, nil)
	receiver := controller.attachReceiver()
	now := time.Now()
	for sample, queued := range []uint32{180 << 10, 190 << 10, 200 << 10} {
		controller.observe(receiver, videoTransportMetrics{
			At:                      now.Add(time.Duration(sample) * videoTelemetryInterval),
			CongestionWindowRateBps: 8_000_000,
			NotSentBytes:            queued,
		})
	}
	if !reflect.DeepEqual(runtime.bitrates, []int{4500}) {
		t.Fatalf("bitrate changes = %v, want persistent-queue backoff", runtime.bitrates)
	}
}

func TestAppleVideoFrameRateTiers(t *testing.T) {
	tests := []struct {
		bandwidth uint64
		maximum   int
		want      int
	}{
		{499_999, 60, 10},
		{500_000, 60, 20},
		{999_999, 60, 20},
		{1_000_000, 60, 30},
		{3_999_999, 60, 30},
		{4_000_000, 60, 60},
		{4_000_000, 30, 30},
	}
	for _, test := range tests {
		if got := appleVideoFrameRate(test.bandwidth, test.maximum); got != test.want {
			t.Errorf("appleVideoFrameRate(%d, %d) = %d, want %d", test.bandwidth, test.maximum, got, test.want)
		}
	}
}

func TestSaturatingRatio(t *testing.T) {
	if got := saturatingRatio(8_000_000, 3, 4); got != 6_000_000 {
		t.Fatalf("ordinary ratio = %d, want 6000000", got)
	}
	if got := saturatingRatio(^uint64(0), 4, 3); got != ^uint64(0) {
		t.Fatalf("overflowing ratio = %d, want uint64 max", got)
	}
}

func TestAutomaticVideoRateControlHonorsExplicitBitrate(t *testing.T) {
	runtime := &fakeCaptureRuntimeController{}
	explicit := &ScreenCapture{runtime: runtime, format: CaptureFormat{FPS: 30, BitrateKbps: 4000}}
	explicit.enableAutomaticVideoRateControl(CaptureConfig{FPS: 30, Bitrate: 4000})
	if explicit.rate != nil || explicit.Format().Adaptive {
		t.Fatal("an explicit bitrate must remain a fixed encoder override")
	}

	automatic := &ScreenCapture{runtime: runtime, format: CaptureFormat{FPS: 30, BitrateKbps: 4000}}
	automatic.enableAutomaticVideoRateControl(CaptureConfig{FPS: 30})
	if automatic.rate == nil || !automatic.Format().Adaptive {
		t.Fatal("automatic linked capture did not enable rate control")
	}
}
