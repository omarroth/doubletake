package airplay

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestFrameTimeAtPreservesPTPSourcePTS(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	anchorLocal := time.Now().Add(-time.Second)
	clock := &mediaClock{
		anchorLocal:     anchorLocal,
		anchorTimestamp: compactTimestamp(10 * time.Second),
		timelineID:      timeline,
	}
	session := &MirrorSession{mediaClock: clock, timestampBias: 500 * time.Millisecond}
	capturedAt := anchorLocal.Add(800 * time.Millisecond)
	got, gotTimeline, timely := session.frameTimeAtNow(capturedAt, anchorLocal.Add(time.Second))
	if !timely {
		t.Fatal("fresh capture PTS was rejected")
	}
	want := compactTimestamp(11*time.Second + 300*time.Millisecond)
	if got != want {
		t.Fatalf("timestamp = 0x%016x, want 0x%016x", got, want)
	}
	if gotTimeline != timeline {
		t.Fatalf("timeline = 0x%016x, want 0x%016x", gotTimeline, timeline)
	}
}

func TestFrameTimeAtPreservesLateSourcePTS(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	now := time.Unix(1700000000, 0)
	clock := &mediaClock{
		anchorLocal:     now.Add(-time.Second),
		anchorTimestamp: compactTimestamp(10 * time.Second),
		timelineID:      timeline,
	}
	session := &MirrorSession{mediaClock: clock, timestampBias: 100 * time.Millisecond}
	got, gotTimeline, mapped := session.frameTimeAtNow(now.Add(-500*time.Millisecond), now)
	if !mapped {
		t.Fatal("late capture PTS was rejected")
	}
	want := compactTimestamp(10*time.Second + 600*time.Millisecond)
	if got != want || gotTimeline != timeline {
		t.Fatalf("late timestamp = (0x%016x, 0x%016x), want (0x%016x, 0x%016x)", got, gotTimeline, want, timeline)
	}
	if !session.latePTSReported {
		t.Fatal("late capture PTS was not reported")
	}
}

func TestFrameTimeAtFallsBackForZeroSourcePTS(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	now := time.Unix(1700000000, 0)
	want := compactTimestamp(11*time.Second + 100*time.Millisecond)
	clock := &mediaClock{
		anchorLocal:     now.Add(-time.Second),
		anchorTimestamp: compactTimestamp(10 * time.Second),
		timelineID:      timeline,
	}
	session := &MirrorSession{mediaClock: clock, timestampBias: 100 * time.Millisecond}
	got, gotTimeline, timely := session.frameTimeAtNow(time.Time{}, now)
	if !timely {
		t.Fatal("zero source PTS did not use output-time fallback")
	}
	if got != want || gotTimeline != timeline {
		t.Fatalf("fallback = (0x%016x, 0x%016x), want (0x%016x, 0x%016x)", got, gotTimeline, want, timeline)
	}
}

func TestFrameTimeAtRejectsImplausibleNonzeroPTS(t *testing.T) {
	now := time.Unix(1700000000, 0)
	for _, test := range []struct {
		name string
		pts  time.Time
	}{
		{name: "future", pts: now.Add(2 * time.Second)},
		{name: "old", pts: now.Add(-31 * time.Second)},
	} {
		t.Run(test.name, func(t *testing.T) {
			session := &MirrorSession{timestampBias: 100 * time.Millisecond}
			got, gotTimeline, timely := session.frameTimeAtNow(test.pts, now)
			if timely || got != 0 || gotTimeline != 0 {
				t.Fatalf("invalid nonzero PTS returned (0x%016x, 0x%016x, %t), want rejection", got, gotTimeline, timely)
			}
		})
	}
}

func TestStreamFramesUsesAccessUnitPTSWithoutLookahead(t *testing.T) {
	now := time.Unix(1700000000, 0)
	firstPTS := now.Add(-300 * time.Millisecond)
	frames := []VideoAccessUnit{
		{AnnexB: joinAnnexBNALs(
			[]byte{0x67, 0x42, 0x00, 0x1f, 0xf8, 0x0a, 0x00, 0xb7, 0x20},
			[]byte{0x68, 0xce, 0x06, 0xe2},
			[]byte{0x65, 0x80, 0x01},
		), PTS: firstPTS},
		{AnnexB: joinAnnexBNALs([]byte{0x61, 0x80, 0x02}), PTS: firstPTS.Add(100 * time.Millisecond)},
	}
	capture := &ScreenCapture{
		frames: &sliceVideoAccessUnitReader{frames: frames},
		waitCh: make(chan struct{}),
	}
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()
	session := &MirrorSession{
		dataConn:       sender,
		firstFrameSent: make(chan struct{}),
		timestampBias:  500 * time.Millisecond,
		frameClockNow:  func() time.Time { return now },
		mediaClock: &mediaClock{
			anchorLocal:     now.Add(-time.Second),
			anchorTimestamp: compactTimestamp(10 * time.Second),
			timelineID:      1,
		},
	}
	errCh := make(chan error, 1)
	go func() { errCh <- session.StreamFrames(context.Background(), capture, 0) }()

	readPacket := func() []byte {
		t.Helper()
		header := make([]byte, 128)
		if _, err := io.ReadFull(receiver, header); err != nil {
			t.Fatal(err)
		}
		payload := make([]byte, binary.LittleEndian.Uint32(header[:4]))
		if _, err := io.ReadFull(receiver, payload); err != nil {
			t.Fatal(err)
		}
		return append(header, payload...)
	}
	codec := readPacket()
	if codec[4] != 1 {
		t.Fatalf("first packet type = %d, want codec", codec[4])
	}
	first := readPacket()
	second := readPacket()
	firstTimestamp := binary.LittleEndian.Uint64(first[8:16])
	secondTimestamp := binary.LittleEndian.Uint64(second[8:16])
	gotDelta := time.Duration(((secondTimestamp - firstTimestamp) * uint64(time.Second)) >> 32)
	if difference := gotDelta - 100*time.Millisecond; difference < -2*time.Millisecond || difference > 2*time.Millisecond {
		t.Fatalf("frame timestamp delta = %v, want 100ms", gotDelta)
	}
	if !bytes.Equal(first[132:], []byte{0x65, 0x80, 0x01}) {
		t.Fatalf("first VCL payload = %x", first[128:])
	}
	if err := <-errCh; err == nil || !strings.Contains(err.Error(), "unexpectedly") {
		t.Fatalf("StreamFrames error = %v, want capture EOF", err)
	}
}

func TestStreamFramesForwardsLateReferenceChain(t *testing.T) {
	base := time.Unix(1700000000, 0)
	frames := []VideoAccessUnit{
		{AnnexB: joinAnnexBNALs(
			[]byte{0x67, 0x42, 0x00, 0x1f, 0xf8, 0x0a, 0x00, 0xb7, 0x20},
			[]byte{0x68, 0xce, 0x06, 0xe2},
			[]byte{0x65, 0x80, 0x01},
		), PTS: base},
		{AnnexB: joinAnnexBNALs([]byte{0x61, 0x80, 0x02}), PTS: base.Add(33 * time.Millisecond)},
		{AnnexB: joinAnnexBNALs([]byte{0x61, 0x80, 0x03}), PTS: base.Add(66 * time.Millisecond)},
		{AnnexB: joinAnnexBNALs([]byte{0x65, 0x80, 0x04}), PTS: base.Add(99 * time.Millisecond)},
		{AnnexB: joinAnnexBNALs([]byte{0x61, 0x80, 0x05}), PTS: base.Add(132 * time.Millisecond)},
	}
	capture := &ScreenCapture{
		frames: &sliceVideoAccessUnitReader{frames: frames},
		waitCh: make(chan struct{}),
	}
	sender, receiver := net.Pipe()
	var output bytes.Buffer
	copyDone := make(chan error, 1)
	go func() {
		_, err := io.Copy(&output, receiver)
		copyDone <- err
	}()

	nowValues := []time.Time{
		base.Add(50 * time.Millisecond),
		base.Add(110 * time.Millisecond), // The second AU has missed its 75 ms deadline.
		base.Add(120 * time.Millisecond),
		base.Add(130 * time.Millisecond),
		base.Add(140 * time.Millisecond),
	}
	nowIndex := 0
	session := &MirrorSession{
		dataConn:       sender,
		firstFrameSent: make(chan struct{}),
		timestampBias:  75 * time.Millisecond,
		frameClockNow: func() time.Time {
			if nowIndex >= len(nowValues) {
				t.Fatalf("frame clock read %d exceeds %d access units", nowIndex+1, len(nowValues))
			}
			now := nowValues[nowIndex]
			nowIndex++
			return now
		},
		mediaClock: &mediaClock{
			anchorLocal:     base,
			anchorTimestamp: compactTimestamp(10 * time.Second),
			timelineID:      1,
		},
	}
	err := session.StreamFrames(context.Background(), capture, 0)
	_ = sender.Close()
	if copyErr := <-copyDone; copyErr != nil {
		t.Fatalf("copy packets: %v", copyErr)
	}
	_ = receiver.Close()
	if err == nil || !strings.Contains(err.Error(), "unexpectedly") {
		t.Fatalf("StreamFrames error = %v, want capture EOF", err)
	}
	if !session.latePTSReported {
		t.Fatal("late access unit was not detected")
	}

	packets := splitMirrorPackets(t, output.Bytes())
	if len(packets) != 6 {
		t.Fatalf("sent %d packets, want codec plus all five VCL access units", len(packets))
	}
	if packets[0].header[4] != 1 {
		t.Fatalf("packet 0 type = %d, want codec", packets[0].header[4])
	}
	wantNALs := [][]byte{
		{0x65, 0x80, 0x01},
		{0x61, 0x80, 0x02},
		{0x61, 0x80, 0x03},
		{0x65, 0x80, 0x04},
		{0x61, 0x80, 0x05},
	}
	for index, wantNAL := range wantNALs {
		packet := packets[index+1]
		if packet.header[4] != 0 {
			t.Fatalf("packet %d type = %d, want VCL", index+1, packet.header[4])
		}
		if got := firstAVCCNAL(t, packet.payload); !bytes.Equal(got, wantNAL) {
			t.Fatalf("packet %d NAL = %x, want %x", index+1, got, wantNAL)
		}
		if index > 0 {
			previous := binary.LittleEndian.Uint64(packets[index].header[8:16])
			current := binary.LittleEndian.Uint64(packet.header[8:16])
			delta := time.Duration(((current - previous) * uint64(time.Second)) >> 32)
			if difference := delta - 33*time.Millisecond; difference < -2*time.Millisecond || difference > 2*time.Millisecond {
				t.Fatalf("packet %d timestamp delta = %v, want 33ms", index+1, delta)
			}
		}
	}
	wantFlags := []byte{0x10, 0, 0, 0x10, 0}
	for index, want := range wantFlags {
		if got := packets[index+1].header[5]; got != want {
			t.Fatalf("VCL packet %d keyframe flag = %02x, want %02x", index+1, got, want)
		}
	}
}

type mirrorPacket struct {
	header  []byte
	payload []byte
}

func splitMirrorPackets(t *testing.T, stream []byte) []mirrorPacket {
	t.Helper()
	var packets []mirrorPacket
	for len(stream) != 0 {
		if len(stream) < 128 {
			t.Fatalf("truncated mirror header: %d bytes", len(stream))
		}
		payloadSize := int(binary.LittleEndian.Uint32(stream[:4]))
		if payloadSize > len(stream)-128 {
			t.Fatalf("truncated mirror payload: have %d, want %d", len(stream)-128, payloadSize)
		}
		packets = append(packets, mirrorPacket{
			header:  append([]byte(nil), stream[:128]...),
			payload: append([]byte(nil), stream[128:128+payloadSize]...),
		})
		stream = stream[128+payloadSize:]
	}
	return packets
}

func firstAVCCNAL(t *testing.T, payload []byte) []byte {
	t.Helper()
	if len(payload) < 4 {
		t.Fatalf("AVCC payload is only %d bytes", len(payload))
	}
	nalSize := int(binary.BigEndian.Uint32(payload[:4]))
	if nalSize <= 0 || nalSize > len(payload)-4 {
		t.Fatalf("invalid AVCC NAL size %d for %d-byte payload", nalSize, len(payload))
	}
	return payload[4 : 4+nalSize]
}

func joinAnnexBNALs(nals ...[]byte) []byte {
	var out []byte
	for _, nal := range nals {
		out = append(out, 0, 0, 0, 1)
		out = append(out, nal...)
	}
	return out
}

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
	if err := clock.configureFromLocalClock(); err == nil {
		t.Fatal("local PTP fallback succeeded without a receiver ClockID")
	}
}

func TestThirdPartyPTPLocalClockFallbackKeepsPTPAudioAndVideoTimeline(t *testing.T) {
	const timeline = uint64(0x4454424c54414b45)
	clock := &mediaClock{}
	response := map[string]interface{}{
		"timingPeerInfo": map[string]interface{}{"ClockID": timeline},
	}
	if err := clock.configureFromSetup(response, nil, time.Now()); err == nil {
		t.Fatal("configureFromSetup succeeded without Apple clock headers")
	}
	if clock.timelineID != timeline {
		t.Fatalf("retained timeline = 0x%016x, want 0x%016x", clock.timelineID, timeline)
	}
	if err := clock.configureFromLocalClock(); err != nil {
		t.Fatalf("configure local PTP fallback: %v", err)
	}

	session := &MirrorSession{
		mediaClock:     clock,
		timingProtocol: timingProtocolPTP,
		timestampBias:  5 * time.Millisecond,
	}
	audioTimestamp, audioTimeline := session.audioClockNow()
	if audioTimeline != timeline {
		t.Fatalf("audio timeline = 0x%016x, want 0x%016x", audioTimeline, timeline)
	}
	packet := captureAudioSyncPacket(t, &AudioStream{}, session.timingProtocol, audioTimestamp, audioTimeline, false)
	if len(packet) != 28 || packet[1] != audioSyncPayloadTypePTP {
		t.Fatalf("audio sync packet = len %d type 0x%02x, want PTP len 28 type 0x%02x",
			len(packet), packet[1], audioSyncPayloadTypePTP)
	}
	if got := binary.BigEndian.Uint64(packet[20:28]); got != timeline {
		t.Fatalf("audio packet timeline = 0x%016x, want 0x%016x", got, timeline)
	}

	if _, videoTimeline := session.frameTimeNow(); videoTimeline != timeline {
		t.Fatalf("video timeline = 0x%016x, want 0x%016x", videoTimeline, timeline)
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

func TestMediaClockTimingPeerUpdatePreservesContinuity(t *testing.T) {
	const (
		oldTimeline = uint64(0x0102030405060708)
		newTimeline = uint64(0x48e15caa8da00008)
	)
	anchorLocal := time.Unix(10, 0)
	clock := &mediaClock{
		anchorLocal:     anchorLocal,
		anchorTimestamp: compactTimestamp(20 * time.Second),
		timelineID:      oldTimeline,
	}
	receivedAt := anchorLocal.Add(1500 * time.Millisecond)
	if err := clock.updateTimingPeerInfo(map[string]interface{}{"ClockID": newTimeline}, receivedAt); err != nil {
		t.Fatal(err)
	}

	if clock.timelineID != newTimeline {
		t.Fatalf("timeline = 0x%016x, want 0x%016x", clock.timelineID, newTimeline)
	}
	if !clock.anchorLocal.Equal(receivedAt) {
		t.Fatalf("anchor local time = %v, want %v", clock.anchorLocal, receivedAt)
	}
	if got, want := clock.anchorTimestamp, compactTimestamp(21500*time.Millisecond); got != want {
		t.Fatalf("anchor timestamp = 0x%016x, want 0x%016x", got, want)
	}
}

func TestMediaClockTimingPeerUpdateInitializesAsyncClock(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	clock := &mediaClock{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	waitErr := make(chan error, 1)
	go func() {
		waitErr <- clock.waitUntilReady(ctx, time.Second)
	}()

	receivedAt := time.Now()
	if err := clock.updateTimingPeerInfo(map[string]interface{}{"ClockID": timeline}, receivedAt); err != nil {
		t.Fatal(err)
	}
	if err := <-waitErr; err != nil {
		t.Fatalf("wait for asynchronous clock: %v", err)
	}
	if timestamp, gotTimeline, ok := clock.now(0); !ok || timestamp == 0 || gotTimeline != timeline {
		t.Fatalf("asynchronous clock = timestamp 0x%016x timeline 0x%016x ok=%t, want nonzero timestamp on 0x%016x",
			timestamp, gotTimeline, ok, timeline)
	}
}

func TestMediaClockTimingPeerUpdateRequiresClockIdentity(t *testing.T) {
	clock := &mediaClock{timelineID: 1}
	if err := clock.updateTimingPeerInfo(nil, time.Now()); err == nil {
		t.Fatal("timing peer update without ClockID succeeded")
	}
	if clock.timelineID != 1 {
		t.Fatalf("invalid update changed timeline to 0x%016x", clock.timelineID)
	}
}

func TestAudioAndVideoClocksStayContinuousAcrossBackwardReanchor(t *testing.T) {
	const timeline = uint64(0x48e15caa8da00008)
	now := time.Now()
	clock := &mediaClock{
		anchorLocal:     now,
		anchorTimestamp: compactTimestamp(60 * time.Second),
		timelineID:      timeline,
	}
	session := &MirrorSession{mediaClock: clock, timestampBias: 5 * time.Millisecond}

	firstAudio, firstAudioTimeline := session.audioClockNow()
	firstVideo, firstVideoTimeline := session.frameTimeNow()
	if err := clock.reanchor(map[string]string{
		"x-apple-requestreceivedtimestamp": "1000",
		"x-apple-processingtime":           "0",
	}, now); err != nil {
		t.Fatal(err)
	}
	secondAudio, secondAudioTimeline := session.audioClockNow()
	secondVideo, secondVideoTimeline := session.frameTimeNow()

	if firstAudioTimeline != timeline || secondAudioTimeline != timeline ||
		firstVideoTimeline != timeline || secondVideoTimeline != timeline {
		t.Fatalf("audio timelines = 0x%016x, 0x%016x; video timelines = 0x%016x, 0x%016x; want 0x%016x",
			firstAudioTimeline, secondAudioTimeline, firstVideoTimeline, secondVideoTimeline, timeline)
	}
	if secondAudio < firstAudio {
		t.Fatalf("audio clock moved backwards: 0x%016x -> 0x%016x", firstAudio, secondAudio)
	}
	if secondVideo <= firstVideo {
		t.Fatalf("video clock did not advance: 0x%016x -> 0x%016x", firstVideo, secondVideo)
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

func TestNTPTimingPacketClassificationRejectsResponses(t *testing.T) {
	request := make([]byte, 32)
	request[0], request[1] = 0x80, 0xd2
	if !isNTPTimingRequest(request) {
		t.Fatal("valid 0xd2 timing request was rejected")
	}

	response := append([]byte(nil), request...)
	response[1] = 0xd3
	if isNTPTimingRequest(response) {
		t.Fatal("0xd3 timing response was accepted as a request")
	}
	if isNTPTimingRequest(request[:31]) {
		t.Fatal("short timing packet was accepted")
	}
	request[0] = 0
	if isNTPTimingRequest(request) {
		t.Fatal("timing packet with an invalid marker was accepted")
	}
}

type recordingPacketConn struct {
	packets [][]byte
	addrs   []net.Addr
}

func (c *recordingPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	panic("ReadFrom is not used by this test")
}

func (c *recordingPacketConn) WriteTo(packet []byte, addr net.Addr) (int, error) {
	c.packets = append(c.packets, append([]byte(nil), packet...))
	c.addrs = append(c.addrs, addr)
	return len(packet), nil
}

func (c *recordingPacketConn) Close() error                     { return nil }
func (c *recordingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *recordingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingPacketConn) SetWriteDeadline(time.Time) error { return nil }

func TestSendNTPTimingProbesUsesReceiverPort(t *testing.T) {
	conn := &recordingPacketConn{}
	sendNTPTimingProbes(context.Background(), conn, "192.0.2.10", 7010)

	if len(conn.packets) != 3 {
		t.Fatalf("sent %d timing probes, want 3", len(conn.packets))
	}
	for index, packet := range conn.packets {
		if !isNTPTimingRequest(packet) {
			t.Fatalf("probe %d is not a timing request: %x", index, packet)
		}
		if got, want := binary.BigEndian.Uint16(packet[2:4]), uint16(index+1); got != want {
			t.Fatalf("probe %d sequence = %d, want %d", index, got, want)
		}
		if got := binary.BigEndian.Uint64(packet[24:32]) >> 32; got < secondsFrom1900To1970 {
			t.Fatalf("probe %d timestamp seconds = %d, want NTP epoch or later", index, got)
		}
		addr, ok := conn.addrs[index].(*net.UDPAddr)
		if !ok || addr.Port != 7010 || !addr.IP.Equal(net.ParseIP("192.0.2.10")) {
			t.Fatalf("probe %d address = %v, want 192.0.2.10:7010", index, conn.addrs[index])
		}
	}
}
