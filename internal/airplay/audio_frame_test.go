package airplay

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAudioCapturePipelineUsesTimestampedFramingWhenAvailable(t *testing.T) {
	args := strings.Join(audioCapturePipelineArgs([]string{"audiotestsrc"}, AudioCodecALAC, true), " ")
	for _, want := range []string{
		"format=S16BE",
		"audiobuffersplit output-buffer-duration=352/44100 strict-buffer-size=true",
		"queue max-size-buffers=0 max-size-bytes=0 max-size-time=250000000 leaky=no",
		"rtpL16pay pt=96 mtu=60000 timestamp-offset=0 seqnum-offset=0 perfect-rtptime=true",
		"rtponviftimestamp ntp-offset=-1 set-e-bit=false set-t-bit=false",
		"rtpstreampay",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("timestamped pipeline %q does not contain %q", args, want)
		}
	}
	if !strings.Contains(args, "max-ptime=7981860") {
		t.Fatalf("timestamped ALAC pipeline %q does not use the codec-frame packet duration", args)
	}

	raw := strings.Join(audioCapturePipelineArgs([]string{"audiotestsrc"}, AudioCodecALAC, false), " ")
	if !strings.Contains(raw, "format=S16LE") {
		t.Fatalf("raw fallback pipeline %q does not retain S16LE", raw)
	}
	if !strings.Contains(raw, "queue max-size-buffers=2 max-size-bytes=0 max-size-time=0 leaky=downstream") {
		t.Fatalf("raw fallback pipeline %q does not retain its bounded no-PTS drop policy", raw)
	}
	for _, unwanted := range []string{"audiobuffersplit", "rtpL16pay", "rtponviftimestamp", "rtpstreampay"} {
		if strings.Contains(raw, unwanted) {
			t.Fatalf("raw fallback pipeline %q unexpectedly contains %q", raw, unwanted)
		}
	}
}

func TestAudioTestToneUsesSafeExplicitAmplitude(t *testing.T) {
	joined := strings.Join(audioTestToneSourceArgs(352), " ")
	for _, want := range []string{
		"audiotestsrc", "wave=sine", "freq=440", "volume=0.01",
		"is-live=true", "samplesperbuffer=352",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("test-tone source %q does not contain %q", joined, want)
		}
	}
	if strings.Count(joined, "volume=") != 1 {
		t.Fatalf("test-tone source %q must set exactly one volume", joined)
	}
}

func TestPulseMonitorSourceSeparatesStallBufferFromFragment(t *testing.T) {
	args := strings.Join(pulseMonitorSourceArgs("test.monitor", AudioCodecALAC), " ")
	for _, want := range []string{
		"pulsesrc",
		"device=test.monitor",
		"buffer-time=250000",
		"latency-time=7982",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("Pulse monitor source %q does not contain %q", args, want)
		}
	}
	if got := audioCaptureFragmentTime(AudioCodecAACELD); got != 10885*time.Microsecond {
		t.Fatalf("AAC-ELD capture fragment = %v, want 10.885ms", got)
	}
}

func TestAudioMonitorSourceSelection(t *testing.T) {
	for _, test := range []struct {
		name        string
		hasPulse    bool
		monitor     string
		hasPipeWire bool
		wantSource  string
		wantArgs    []string
	}{
		{
			name: "Pulse monitor preferred when both plugins exist", hasPulse: true,
			monitor: "test.monitor", hasPipeWire: true, wantSource: "pulse",
			wantArgs: []string{"pulsesrc", "device=test.monitor", "buffer-time=250000", "latency-time=7982"},
		},
		{
			name: "native Pulse monitor", hasPulse: true,
			monitor: "test.monitor", wantSource: "pulse",
			wantArgs: []string{"pulsesrc", "device=test.monitor", "buffer-time=250000", "latency-time=7982"},
		},
		{
			name: "PipeWire fallback without Pulse plugin", hasPipeWire: true, wantSource: "pipewire",
			wantArgs: []string{"pipewiresrc", "client-name=doubletake"},
		},
		{
			name: "PipeWire fallback without detected monitor", hasPulse: true,
			hasPipeWire: true, wantSource: "pipewire",
			wantArgs: []string{"pipewiresrc", "client-name=doubletake"},
		},
		{name: "no source plugin", wantSource: ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, source := selectAudioMonitorSource(test.hasPulse, test.monitor, test.hasPipeWire, AudioCodecALAC)
			if source != test.wantSource {
				t.Fatalf("source = %q, want %q", source, test.wantSource)
			}
			if got := strings.Join(args, " "); got != strings.Join(test.wantArgs, " ") {
				t.Fatalf("args = %q, want %q", got, strings.Join(test.wantArgs, " "))
			}
		})
	}
}

func TestAudioCaptureTestToneCarriesSourcePTSWithoutHardware(t *testing.T) {
	if _, err := exec.LookPath("gst-launch-1.0"); err != nil || !supportsTimestampedAudioOutput() || !hasGstElement("audiotestsrc") {
		t.Skip("timestamped GStreamer test elements are unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	capture, err := StartAudioCapture(ctx, true, AudioCodecALAC)
	if err != nil {
		t.Fatalf("start timestamped test-tone capture: %v", err)
	}
	defer capture.Stop()

	buf := make([]byte, 8192)
	n, position, err := capture.readFramePosition(buf)
	if err != nil {
		t.Fatalf("read timestamped test-tone frame: %v", err)
	}
	if n == 0 || position.PTS.IsZero() || !position.HasSourceRTP {
		t.Fatalf("test-tone frame = %d bytes position=%#v, want encoded bytes, source PTS, and source RTP", n, position)
	}
	if age := time.Since(position.PTS); age < -time.Second || age > 2*time.Second {
		t.Fatalf("test-tone source PTS age = %v, want a current capture time", age)
	}
	reader, ok := capture.pcmFrames.(*rtpL16PCMFrameReader)
	if !ok {
		t.Fatalf("timestamped capture reader = %T, want RTP/L16 reader", capture.pcmFrames)
	}
	if reader.reportPackets != 1 || reader.reportSamples != 352 {
		t.Fatalf("first codec frame used %d RTP packets and %d samples, want one 352-sample source callback",
			reader.reportPackets, reader.reportSamples)
	}
	_, second, err := capture.readFramePosition(buf)
	if err != nil {
		t.Fatalf("read second timestamped test-tone frame: %v", err)
	}
	if delta := second.SourceRTP - position.SourceRTP; delta != 352 {
		t.Fatalf("test-tone source RTP delta = %d, want one ALAC frame (352 samples)", delta)
	}
}

func TestRTPL16PCMFrameReaderPreservesPTSAndCodecBoundaries(t *testing.T) {
	base := time.Unix(1787356800, 123456789).UTC()
	firstBE, firstLE := testL16Samples(200, 0x1000)
	secondBE, secondLE := testL16Samples(300, 0x2000)
	thirdBE, thirdLE := testL16Samples(204, 0x3000)
	stream := bytes.Join([][]byte{
		testFramedL16Packet(10, 1000, base, firstBE),
		testFramedL16Packet(11, 1200, base.Add(audioSamplesDuration(200)), secondBE),
		testFramedL16Packet(12, 1500, base.Add(audioSamplesDuration(500)), thirdBE),
	}, nil)
	reader := newRTPL16PCMFrameReaderWithNow(bytes.NewReader(stream), func() time.Time { return base.Add(time.Second) })

	pcm := make([]byte, 352*audioBytesPerSampleFrame)
	firstPTS, err := reader.ReadPCMFrame(pcm)
	if err != nil {
		t.Fatal(err)
	}
	wantPCM := append(append(append([]byte{}, firstLE...), secondLE...), thirdLE...)
	if !bytes.Equal(pcm, wantPCM[:len(pcm)]) {
		t.Fatal("first assembled PCM frame does not contain the expected byte-swapped L16 samples")
	}
	wantFirstPTS := timeFromNTP(testNTPFromTime(base))
	if !firstPTS.Equal(wantFirstPTS) {
		t.Fatalf("first PTS = %v, want %v", firstPTS, wantFirstPTS)
	}

	secondPTS, err := reader.ReadPCMFrame(pcm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pcm, wantPCM[len(pcm):2*len(pcm)]) {
		t.Fatal("second assembled PCM frame does not cross RTP packet boundaries correctly")
	}
	wantSecondPTS := wantFirstPTS.Add(audioSamplesDuration(352))
	if !secondPTS.Equal(wantSecondPTS) {
		t.Fatalf("second PTS = %v, want %v", secondPTS, wantSecondPTS)
	}
}

func TestRTPL16PCMFrameReaderPreservesSamplePositionAndRebasesPTS(t *testing.T) {
	base := time.Unix(1787356850, 0).UTC()
	firstBE, _ := testL16Samples(200, 0x1000)
	secondBE, _ := testL16Samples(200, 0x2000)
	// Model a source clock whose presentation-time correlation moved by 2ms.
	// RTP remains the authoritative count of captured samples.
	secondPTS := base.Add(audioSamplesDuration(200)).Add(2 * time.Millisecond)
	stream := bytes.Join([][]byte{
		testFramedL16Packet(10, 9000, base, firstBE),
		testFramedL16Packet(11, 9200, secondPTS, secondBE),
	}, nil)
	reader := newRTPL16PCMFrameReaderWithNow(bytes.NewReader(stream), func() time.Time { return base.Add(time.Second) })
	pcm := make([]byte, 352*audioBytesPerSampleFrame)
	position, err := reader.ReadPCMFramePosition(pcm)
	if err != nil {
		t.Fatal(err)
	}
	if !position.HasSourceRTP || position.SourceRTP != 9000 {
		t.Fatalf("source position = %#v, want RTP 9000", position)
	}
	// The newest packet correlation is projected back to the first sample of
	// this codec frame, retaining the source clock's observed 2ms phase change.
	wantPTS := timeFromNTP(testNTPFromTime(secondPTS)).Add(-audioSamplesDuration(200))
	if !position.PTS.Equal(wantPTS) {
		t.Fatalf("frame PTS = %v, want rebased %v", position.PTS, wantPTS)
	}
}

func TestRTPL16PCMFrameReaderDropsPartialFrameAtDiscontinuity(t *testing.T) {
	base := time.Unix(1787356900, 0).UTC()
	partialBE, _ := testL16Samples(100, 0x1000)
	completeBE, completeLE := testL16Samples(352, 0x4000)
	secondPTS := base.Add(100 * time.Millisecond)
	stream := bytes.Join([][]byte{
		testFramedL16Packet(1, 1000, base, partialBE),
		// Both sequence and RTP time jump. The 100 buffered samples must not be
		// concatenated with samples from this new source timeline.
		testFramedL16Packet(3, 6000, secondPTS, completeBE),
	}, nil)
	reader := newRTPL16PCMFrameReaderWithNow(bytes.NewReader(stream), func() time.Time { return base.Add(time.Second) })
	pcm := make([]byte, len(completeLE))
	pts, err := reader.ReadPCMFrame(pcm)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pcm, completeLE) {
		t.Fatal("partial PCM preceding a capture discontinuity leaked into the next codec frame")
	}
	wantPTS := timeFromNTP(testNTPFromTime(secondPTS))
	if !pts.Equal(wantPTS) {
		t.Fatalf("PTS after discontinuity = %v, want %v", pts, wantPTS)
	}
	if reader.discontinuities != 1 {
		t.Fatalf("discontinuities = %d, want 1", reader.discontinuities)
	}
}

func TestAudioRTPClockPreservesSourceGapsAndReanchorsBackwardClock(t *testing.T) {
	epoch := uint32(0xfffffff0)
	base := time.Unix(1787357000, 0)
	clock := newAudioRTPClock(epoch)
	first, reset := clock.mapFrame(base, 352)
	if first != epoch || reset {
		t.Fatalf("first map = rtp %#x reset=%t, want %#x false", first, reset, epoch)
	}

	secondPTS := base.Add(audioSamplesDuration(352))
	second, reset := clock.mapFrame(secondPTS, 352)
	if want := epoch + 352; second != want || reset {
		t.Fatalf("second map = rtp %#x reset=%t, want %#x false", second, reset, want)
	}

	gapPTS := base.Add(audioSamplesDuration(352 + 352 + 4410))
	afterGap, reset := clock.mapFrame(gapPTS, 352)
	if want := epoch + 352 + 352 + 4410; afterGap != want || reset {
		t.Fatalf("gap map = rtp %#x reset=%t, want %#x false", afterGap, reset, want)
	}

	backwardPTS := base.Add(-time.Second)
	afterReset, reset := clock.mapFrame(backwardPTS, 352)
	if want := afterGap + 352; afterReset != want || !reset {
		t.Fatalf("backward map = rtp %#x reset=%t, want %#x true", afterReset, reset, want)
	}
	if at, ok := clock.rtpAt(backwardPTS.Add(time.Second)); !ok || at != afterReset+audioSampleRate {
		t.Fatalf("rtpAt after reset = %#x ok=%t, want %#x true", at, ok, afterReset+audioSampleRate)
	}
}

func TestAudioRTPClockUsesCapturedSampleClockWithoutLongTermWallDrift(t *testing.T) {
	epoch := uint32(0x12345678)
	base := time.Unix(1787357050, 0)
	clock := newAudioRTPClock(epoch)
	firstPosition := audioPCMFramePosition{PTS: base, SourceRTP: 1000, HasSourceRTP: true}
	first, reset := clock.mapFramePosition(firstPosition, 352)
	if first != epoch || reset {
		t.Fatalf("first map = %#x reset=%t, want %#x false", first, reset, epoch)
	}

	// After ten minutes, model an audio clock running 200ppm faster than the
	// host/video clock. A wall-duration-derived RTP value would be about 5292
	// samples short; the captured source position remains exact.
	const elapsedSamples = uint32(10 * 60 * audioSampleRate)
	nominalWall := 10 * time.Minute
	elapsedWall := time.Duration(float64(nominalWall) / 1.0002)
	lastPosition := audioPCMFramePosition{
		PTS:          base.Add(elapsedWall),
		SourceRTP:    firstPosition.SourceRTP + elapsedSamples,
		HasSourceRTP: true,
	}
	last, reset := clock.mapFramePosition(lastPosition, 352)
	if want := epoch + elapsedSamples; last != want || reset {
		t.Fatalf("ten-minute map = %#x reset=%t, want exact sample position %#x false", last, reset, want)
	}
	if wallDerived := epoch + uint32(durationToAudioSamples(elapsedWall)); wallDerived == last {
		t.Fatal("test clock did not create a measurable wall/sample-rate difference")
	}
	announceAt := lastPosition.PTS.Add(137 * time.Millisecond)
	announcedRTP, ok := clock.rtpAt(announceAt)
	wantAnnouncedRTP := last + uint32(durationToAudioSamples(137*time.Millisecond))
	if !ok || announcedRTP != wantAnnouncedRTP {
		t.Fatalf("current interpolation = rtp %#x ok=%t, want %#x true",
			announcedRTP, ok, wantAnnouncedRTP)
	}
}

func TestAudioRTPClockPreservesCapturedGapsAndResetsBackwardSampleClock(t *testing.T) {
	epoch := uint32(0x40000000)
	base := time.Unix(1787357060, 0)
	clock := newAudioRTPClock(epoch)
	position := audioPCMFramePosition{PTS: base, SourceRTP: 5000, HasSourceRTP: true}
	first, _ := clock.mapFramePosition(position, 352)

	position.PTS = position.PTS.Add(audioSamplesDuration(352 + 4410))
	position.SourceRTP += 352 + 4410
	afterGap, reset := clock.mapFramePosition(position, 352)
	if want := first + 352 + 4410; afterGap != want || reset {
		t.Fatalf("gap map = %#x reset=%t, want %#x false", afterGap, reset, want)
	}

	position.PTS = position.PTS.Add(audioSamplesDuration(352))
	position.SourceRTP = 100 // capture RTP epoch restarted
	afterReset, reset := clock.mapFramePosition(position, 352)
	if want := afterGap + 352; afterReset != want || !reset {
		t.Fatalf("reset map = %#x reset=%t, want continuous outgoing %#x true", afterReset, reset, want)
	}
}

func TestAudioClockAtNTPFallbackIncludesNTP1900Epoch(t *testing.T) {
	session := &MirrorSession{}
	sourcePTS := time.Now().Add(-250 * time.Millisecond)
	timestamp, timeline := session.audioClockAt(sourcePTS)
	if timeline != 0 {
		t.Fatalf("NTP fallback timeline = %#x, want 0", timeline)
	}
	if seconds := timestamp >> 32; seconds < secondsFrom1900To1970 {
		t.Fatalf("NTP fallback seconds = %d, missing 1900 epoch", seconds)
	}
	now := ntpBootTimestamp()
	delta := now - timestamp
	if delta < compactTimestamp(200*time.Millisecond) || delta > compactTimestamp(350*time.Millisecond) {
		t.Fatalf("NTP source-time delta = %#x, want approximately 250ms", delta)
	}
}

func TestSendSyncPacketAtUsesExplicitSourceRTPForPlayhead(t *testing.T) {
	stream := &AudioStream{rtpTime: 123, latencySamples: 1000}
	conn := &recordingPacketConn{}
	stream.ctrlConn = conn
	stream.ctrlAddr = &netUDPAddrForAudioTest
	if err := stream.sendSyncPacketAt(timingProtocolNTP, 0x83aa7e8012345678, 0, 7000, false); err != nil {
		t.Fatal(err)
	}
	packet := conn.packets[0]
	if got := binary.BigEndian.Uint32(packet[4:8]); got != 6000 {
		t.Fatalf("playback RTP = %d, want 6000", got)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != 7000 {
		t.Fatalf("next RTP = %d, want unadjusted source position 7000", got)
	}
}

func TestAudioFrameStalenessRequiresPositivePlayoutLead(t *testing.T) {
	now := time.Unix(1787357100, 0)
	const latency = uint32(4410) // 100 ms at 44.1 kHz
	if audioFrameIsStale(now.Add(-90*time.Millisecond), now, latency, minimumAudioSendLead) {
		t.Fatal("frame with 10ms remaining lead was classified stale")
	}
	if !audioFrameIsStale(now.Add(-100*time.Millisecond), now, latency, minimumAudioSendLead) {
		t.Fatal("frame with no remaining lead was not classified stale")
	}
	if audioFrameIsStale(time.Time{}, now, latency, minimumAudioSendLead) {
		t.Fatal("raw fallback frame with no PTS was classified stale")
	}
	if !audioFrameIsStale(now.Add(-90*time.Millisecond), now, latency, 13*time.Millisecond) {
		t.Fatal("frame without enough lead for pacing was not classified stale")
	}
}

type stalePCMFrameReader struct {
	pts time.Time
}

func (r stalePCMFrameReader) ReadPCMFrame(dst []byte) (time.Time, error) {
	clear(dst)
	return r.pts, nil
}

func TestStreamAudioBoundsInitialTimestampCatchup(t *testing.T) {
	firstVideoFrame := make(chan struct{})
	close(firstVideoFrame)
	session := &MirrorSession{firstFrameSent: firstVideoFrame, timingProtocol: timingProtocolNTP}
	stream := &AudioStream{
		ctrlConn:       &recordingPacketConn{},
		ctrlAddr:       &netUDPAddrForAudioTest,
		spf:            352,
		ct:             byte(AudioCodecALAC),
		latencySamples: 4410,
	}
	capture := &AudioCapture{
		pcmFrames: stalePCMFrameReader{pts: time.Now().Add(-time.Second)},
		waitCh:    make(chan struct{}),
		codec:     AudioCodecALAC,
	}
	err := session.StreamAudio(context.Background(), capture, stream)
	if err == nil || !strings.Contains(err.Error(), "discarding 128 stale frames") {
		t.Fatalf("StreamAudio error = %v, want bounded 128-frame catch-up failure", err)
	}
}

// recordingPacketConn only needs a non-nil address; WriteTo records the packet.
var netUDPAddrForAudioTest = net.UDPAddr{}

func testL16Samples(samples int, seed uint16) (bigEndian, littleEndian []byte) {
	bigEndian = make([]byte, samples*audioBytesPerSampleFrame)
	littleEndian = make([]byte, len(bigEndian))
	for sample := 0; sample < samples; sample++ {
		for channel := 0; channel < audioChannels; channel++ {
			value := seed + uint16(sample*audioChannels+channel)
			offset := (sample*audioChannels + channel) * audioBytesPerSample
			binary.BigEndian.PutUint16(bigEndian[offset:offset+2], value)
			binary.LittleEndian.PutUint16(littleEndian[offset:offset+2], value)
		}
	}
	return bigEndian, littleEndian
}

func testFramedL16Packet(sequence uint16, rtpTimestamp uint32, pts time.Time, payload []byte) []byte {
	packet := make([]byte, 28+len(payload))
	packet[0] = 0x90 // RTP v2 + extension
	packet[1] = audioCapturePayloadType
	binary.BigEndian.PutUint16(packet[2:4], sequence)
	binary.BigEndian.PutUint32(packet[4:8], rtpTimestamp)
	binary.BigEndian.PutUint32(packet[8:12], 0x11223344)
	binary.BigEndian.PutUint16(packet[12:14], audioONVIFRTPHeaderProfile)
	binary.BigEndian.PutUint16(packet[14:16], 3)
	binary.BigEndian.PutUint64(packet[16:24], testNTPFromTime(pts))
	copy(packet[28:], payload)

	framed := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(packet)))
	copy(framed[2:], packet)
	return framed
}

func testNTPFromTime(value time.Time) uint64 {
	seconds := uint64(value.Unix() + secondsFrom1900To1970)
	fraction := (uint64(value.Nanosecond()) << 32) / uint64(time.Second)
	return seconds<<32 | fraction
}
