package airplay

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

func TestSendFrameWritesNTPTimeAndZeroTimeline(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()

	session := &MirrorSession{dataConn: sender}
	payload := []byte{1, 2, 3, 4}
	const timestamp = uint64(0x123456789abcdef0)

	errCh := make(chan error, 1)
	go func() {
		errCh <- session.sendFrame(payload, true, timestamp, 0)
	}()

	packet := make([]byte, 128+len(payload))
	if _, err := io.ReadFull(receiver, packet); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send frame: %v", err)
	}
	if got := binary.LittleEndian.Uint64(packet[8:16]); got != timestamp {
		t.Fatalf("timestamp = 0x%016x, want 0x%016x", got, timestamp)
	}
	if got := binary.LittleEndian.Uint64(packet[40:48]); got != 0 {
		t.Fatalf("NTP timeline = 0x%016x, want 0", got)
	}
}

func TestSendFrameWritesPTPTimeline(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()

	const timeline = uint64(0x48e15caa8da00008)
	session := &MirrorSession{dataConn: sender}
	errCh := make(chan error, 1)
	go func() {
		errCh <- session.sendFrame([]byte{1}, false, 2, timeline)
	}()

	packet := make([]byte, 129)
	if _, err := io.ReadFull(receiver, packet); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	if err := <-errCh; err != nil {
		t.Fatalf("send frame: %v", err)
	}
	if got := binary.LittleEndian.Uint64(packet[40:48]); got != timeline {
		t.Fatalf("PTP timeline = 0x%016x, want 0x%016x", got, timeline)
	}
}

func TestMediaClockConfiguresFromSetupResponse(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	response := map[string]interface{}{
		"timingPeerInfo": map[string]interface{}{"ClockID": timeline},
	}
	headers := map[string]string{
		"x-apple-requestreceivedtimestamp": "136989894",
		"x-apple-processingtime":           "106",
	}
	receivedAt := time.Now()
	clock := &mediaClock{}
	if err := clock.configureFromSetup(response, headers, receivedAt); err != nil {
		t.Fatal(err)
	}

	if got := clock.timelineID; got != timeline {
		t.Fatalf("timeline = 0x%016x, want 0x%016x", got, timeline)
	}
	wantTimestamp := compactTimestamp(136990000 * time.Millisecond)
	if clock.anchorTimestamp != wantTimestamp {
		t.Fatalf("anchor timestamp = 0x%016x, want 0x%016x", clock.anchorTimestamp, wantTimestamp)
	}
	if !clock.anchorLocal.Equal(receivedAt) {
		t.Fatalf("anchor local time = %v, want %v", clock.anchorLocal, receivedAt)
	}
}

func TestMediaClockRequiresReceiverClockIdentity(t *testing.T) {
	clock := &mediaClock{}
	err := clock.configureFromSetup(nil, map[string]string{
		"x-apple-requestreceivedtimestamp": "1",
	}, time.Now())
	if err == nil {
		t.Fatal("configureFromSetup succeeded without timingPeerInfo.ClockID")
	}
}

func TestMediaClockRequiresReceiverProcessingTime(t *testing.T) {
	clock := &mediaClock{}
	err := clock.configureFromSetup(map[string]interface{}{
		"timingPeerInfo": map[string]interface{}{"ClockID": uint64(1)},
	}, map[string]string{
		"x-apple-requestreceivedtimestamp": "1",
	}, time.Now())
	if err == nil {
		t.Fatal("configureFromSetup succeeded without X-Apple-ProcessingTime")
	}
}

func TestMediaClockReanchorsWithoutChangingTimeline(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	clock := &mediaClock{
		anchorLocal:     time.Unix(1, 0),
		anchorTimestamp: compactTimestamp(time.Second),
		timelineID:      timeline,
	}
	receivedAt := time.Unix(2, 0)
	if err := clock.reanchor(map[string]string{
		"x-apple-requestreceivedtimestamp": "2000",
		"x-apple-processingtime":           "5",
	}, receivedAt); err != nil {
		t.Fatal(err)
	}
	if got, want := clock.anchorTimestamp, compactTimestamp(2005*time.Millisecond); got != want {
		t.Fatalf("anchor timestamp = 0x%016x, want 0x%016x", got, want)
	}
	if !clock.anchorLocal.Equal(receivedAt) {
		t.Fatalf("anchor local time = %v, want %v", clock.anchorLocal, receivedAt)
	}
	if clock.timelineID != timeline {
		t.Fatalf("timeline changed to 0x%016x", clock.timelineID)
	}
}

func TestFrameTimeStaysMonotonicAcrossBackwardReanchor(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	now := time.Now()
	clock := &mediaClock{
		anchorLocal:     now,
		anchorTimestamp: compactTimestamp(60 * time.Second),
		timelineID:      timeline,
	}
	session := &MirrorSession{mediaClock: clock, timestampBias: 5 * time.Millisecond}

	first, firstTimeline := session.frameTimeNow()
	if err := clock.reanchor(map[string]string{
		"x-apple-requestreceivedtimestamp": "1000",
		"x-apple-processingtime":           "0",
	}, now); err != nil {
		t.Fatal(err)
	}
	second, secondTimeline := session.frameTimeNow()

	if firstTimeline != timeline || secondTimeline != timeline {
		t.Fatalf("timelines = 0x%016x, 0x%016x; want 0x%016x", firstTimeline, secondTimeline, timeline)
	}
	if second != first+1 {
		t.Fatalf("timestamp after backward reanchor = 0x%016x, want 0x%016x", second, first+1)
	}
}

func TestMirrorSessionCloseStopsWorkersAndIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sender, receiver := net.Pipe()
	defer receiver.Close()

	session := &MirrorSession{
		dataConn:       sender,
		cancel:         cancel,
		firstFrameSent: make(chan struct{}),
	}
	workerExited := make(chan struct{})
	session.startWorker(func() {
		defer close(workerExited)
		session.dataHeartbeatLoop(ctx)
	})

	closeResult := make(chan error, 1)
	go func() { closeResult <- session.Close() }()
	select {
	case err := <-closeResult:
		if err != nil {
			t.Fatalf("first Close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close did not stop session workers")
	}
	select {
	case <-workerExited:
	default:
		t.Fatal("worker had not exited when Close returned")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestPlistUint64RejectsFloatingPointClockIdentity(t *testing.T) {
	const timeline = uint64(0xf8e15caa8da00008)
	if got := plistUint64(timeline); got != timeline {
		t.Fatalf("integer ClockID = 0x%016x, want 0x%016x", got, timeline)
	}
	if got := plistUint64(float64(timeline)); got != 0 {
		t.Fatalf("floating-point ClockID = 0x%016x, want rejection", got)
	}
}

func TestTimingProtocolForSession(t *testing.T) {
	if got := timingProtocolForSession(false); got != timingProtocolNTP {
		t.Fatalf("legacy timing protocol = %q, want %q", got, timingProtocolNTP)
	}
	if got := timingProtocolForSession(true); got != timingProtocolPTP {
		t.Fatalf("modern timing protocol = %q, want %q", got, timingProtocolPTP)
	}
}

func TestTimingProtocolForClientUsesAdvertisedPTP(t *testing.T) {
	legacy := &AirPlayClient{info: &ReceiverInfo{}}
	if got := timingProtocolForClient(legacy, false); got != timingProtocolNTP {
		t.Fatalf("legacy without PTPInfo = %q, want NTP", got)
	}
	ptpTV := &AirPlayClient{info: &ReceiverInfo{hasPTPInfo: true}}
	if got := timingProtocolForClient(ptpTV, false); got != timingProtocolPTP {
		t.Fatalf("third-party with PTPInfo = %q, want PTP", got)
	}
	if got := timingProtocolForClient(&AirPlayClient{info: &ReceiverInfo{hasPTPInfo: true}}, true); got != timingProtocolPTP {
		t.Fatalf("modern + PTPInfo = %q, want PTP", got)
	}
}

func TestModernSessionSetupRequiresFirstPartyProfile(t *testing.T) {
	const rokuFeatures = uint64(0x38bcf46007f8ad0)

	tests := []struct {
		name      string
		encrypted bool
		features  uint64
		want      bool
	}{
		{name: "modern Apple", encrypted: true, features: FeatureSystemPairing, want: true},
		{name: "modern Apple plaintext", features: FeatureSystemPairing},
		{name: "encrypted Roku", encrypted: true, features: rokuFeatures},
		{name: "encrypted legacy receiver", encrypted: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &AirPlayClient{
				encrypted: tt.encrypted,
				info:      &ReceiverInfo{Features: tt.features},
			}
			if got := client.usesModernSessionSetup(); got != tt.want {
				t.Fatalf("usesModernSessionSetup() = %v, want %v", got, tt.want)
			}
		})
	}
}
