package airplay

import (
	"bytes"
	"context"
	"encoding/binary"
	"math"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"howett.net/plist"
)

func testSerializedGlitchHistogram(samples ...interface{}) map[string]interface{} {
	return map[string]interface{}{
		"BucketCount":  uint64(len(samples)),
		"MinValue":     float64(-2147483648),
		"MaxValue":     float64(2147483647),
		"RealMinValue": float64(-2147483648),
		"RealMaxValue": float64(2147483647),
		"BucketWidth":  float64(0),
		"BucketRanges": []interface{}{float64(-2147483648), float64(10), float64(25)},
		"Samples":      samples,
	}
}

func testMediaDataMessage(messageType, command string, replyToken uint64, payload []byte) []byte {
	message := make([]byte, mediaDataControlHeaderSize+len(payload))
	binary.BigEndian.PutUint32(message[0:4], uint32(len(message)))
	copy(message[4:8], messageType)
	copy(message[16:20], command)
	binary.BigEndian.PutUint64(message[20:28], replyToken)
	copy(message[mediaDataControlHeaderSize:], payload)
	return message
}

func TestParseAudioPerformanceReportUsesReferenceGlitchWeights(t *testing.T) {
	report, ok, err := parseAudioPerformanceReport(map[string]interface{}{
		"ProtocolVersion":             uint64(1),
		"SessionDurationSec":          uint64(5),
		"RenderDeadlineMinMs":         int64(8),
		"LiveAdaptiveGlitchHistogram": testSerializedGlitchHistogram(uint64(2), uint64(3), uint64(4)),
	})
	if err != nil || !ok {
		t.Fatalf("parseAudioPerformanceReport = %#v, %t, %v", report, ok, err)
	}
	if math.Abs(report.weightedGlitches-4.7) > 0.0001 {
		t.Fatalf("weighted glitches = %v, want 4.7", report.weightedGlitches)
	}
	if report.durationSecs != 5 || report.renderDeadlineMinMS != 8 {
		t.Fatalf("report = %#v, want duration=5 deadline=8", report)
	}
}

func TestAudioPerformanceReportRequiresMinimumDurationAndLiveHistogram(t *testing.T) {
	short := map[string]interface{}{
		"ProtocolVersion":             uint64(1),
		"SessionDurationSec":          uint64(4),
		"RenderDeadlineMinMs":         int64(8),
		"LiveAdaptiveGlitchHistogram": testSerializedGlitchHistogram(uint64(0), uint64(0), uint64(0)),
	}
	if _, ok, err := parseAudioPerformanceReport(short); err != nil || ok {
		t.Fatalf("short report = ok %t, err %v; want ignored", ok, err)
	}

	nonLive := map[string]interface{}{
		"ProtocolVersion":           uint64(1),
		"SessionDurationSec":        uint64(5),
		"RenderDeadlineMinMs":       int64(8),
		"NonStartupGlitchHistogram": testSerializedGlitchHistogram(uint64(0), uint64(0), uint64(0)),
	}
	if _, ok, err := parseAudioPerformanceReport(nonLive); err != nil || ok {
		t.Fatalf("non-live report = ok %t, err %v; want ignored", ok, err)
	}
}

func TestAudioDynamicLatencyNormalizesGlitchesToPromotionWindow(t *testing.T) {
	tiers, _ := dynamicAudioLatencyTiers(samplesFor44k1(defaultAudioLatencyNormal))
	audio := &AudioStream{
		latencySamples:  tiers[1],
		adaptiveLatency: true,
		latencyTiers:    tiers,
		latencyTier:     1,
	}

	// A 120-second report with 0.3 weighted glitches represents 0.15 glitches
	// in the manager's 60-second window, below the >0.2 one-tier demotion limit.
	if audio.applyPerformanceReport(audioPerformanceReport{
		durationSecs:        120,
		renderDeadlineMinMS: 0,
		weightedGlitches:    0.3,
	}) {
		t.Fatal("normalized sub-threshold glitches changed the latency tier")
	}
	if got := audio.currentLatencySamples(); got != tiers[1] {
		t.Fatalf("latency after normalized report = %v, want %v", audioLatencyDuration(got), audioLatencyDuration(tiers[1]))
	}
}

func TestMediaDataControlEncryptedRoundTripAndReportApplication(t *testing.T) {
	const seed = uint64(18446744073709551600)
	secret := []byte("0123456789abcdef0123456789abcdef")
	senderConn, receiverConn := net.Pipe()
	defer receiverConn.Close()

	sender, err := newMediaDataControlChannel(senderConn, secret, seed)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("DataStream-Salt18446744073709551600")
	receiverReadKey := hkdfSHA512(secret, salt, []byte("DataStream-Output-Encryption-Key"), chacha20poly1305.KeySize)
	receiverWriteKey := hkdfSHA512(secret, salt, []byte("DataStream-Input-Encryption-Key"), chacha20poly1305.KeySize)
	receiverReadCipher, _ := chacha20poly1305.New(receiverReadKey)
	receiverWriteCipher, _ := chacha20poly1305.New(receiverWriteKey)
	receiver := &eventChannel{conn: receiverConn, readCipher: receiverReadCipher, writeCipher: receiverWriteCipher}

	tiers, _ := dynamicAudioLatencyTiers(samplesFor44k1(defaultAudioLatencyNormal))
	audio := &AudioStream{
		latencySamples:  tiers[0],
		adaptiveLatency: true,
		latencyTiers:    tiers,
		latencyChanged:  make(chan struct{}, 1),
	}
	reportBody, err := plist.Marshal(map[string]interface{}{
		"ProtocolVersion":             uint64(1),
		"SessionDurationSec":          uint64(60),
		"RenderDeadlineMinMs":         int64(5),
		"LiveAdaptiveGlitchHistogram": testSerializedGlitchHistogram(uint64(0), uint64(0), uint64(0)),
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveMediaDataControl(ctx, sender, audio) }()

	request := testMediaDataMessage("sync", "raup", 42, reportBody)
	binary.BigEndian.PutUint64(request[8:16], 99)
	if _, err := receiver.Write(request); err != nil {
		t.Fatalf("write receiver report: %v", err)
	}
	reply, err := readMediaDataControlMessage(receiver)
	if err != nil {
		t.Fatalf("read sender reply: %v", err)
	}
	if got, command, opaque := string(reply.messageType[:]), string(reply.command[:]), binary.BigEndian.Uint64(reply.header[8:16]); got != "rply" || command != "raup" || opaque != 99 || reply.replyToken != 42 || reply.status != 0 {
		t.Fatalf("reply = type %q command %q opaque %d token %d status %d", got, command, opaque, reply.replyToken, reply.status)
	}
	if got := audio.currentLatencySamples(); got != tiers[1] {
		t.Fatalf("latency after report = %v, want %v", audioLatencyDuration(got), audioLatencyDuration(tiers[1]))
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serveMediaDataControl: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveMediaDataControl did not stop after cancellation")
	}
}

func TestReadMediaDataControlMessageRejectsInvalidLength(t *testing.T) {
	header := make([]byte, mediaDataControlHeaderSize)
	binary.BigEndian.PutUint32(header[:4], mediaDataControlHeaderSize-1)
	if _, err := readMediaDataControlMessage(bytes.NewReader(header)); err == nil {
		t.Fatal("undersized message accepted")
	}
}
