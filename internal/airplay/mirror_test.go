package airplay

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestStreamFramesStopsWhenReceiverClosesDataChannel(t *testing.T) {
	sender, receiver := net.Pipe()
	reader := &blockingVideoReader{closed: make(chan struct{}), waitCh: make(chan struct{})}
	capture := &ScreenCapture{stdout: reader, frames: reader, waitCh: reader.waitCh}
	session := &MirrorSession{
		dataConn:       sender,
		firstFrameSent: make(chan struct{}),
		streamDone:     make(chan struct{}),
	}
	go session.monitorDataConnection(sender)

	result := make(chan error, 1)
	go func() {
		result <- session.StreamFrames(context.Background(), capture, 0)
	}()
	if err := receiver.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "video data channel closed") {
			t.Fatalf("StreamFrames error = %v, want receiver disconnect", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StreamFrames remained blocked after receiver disconnected")
	}
	_ = sender.Close()
}

func TestCodecFrameUsesEncodedRasterForAllRects(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()

	session := &MirrorSession{
		dataConn:    sender,
		videoWidth:  1280,
		videoHeight: 800,
	}
	done := make(chan error, 1)
	go func() { done <- session.sendCodecFrame([]byte{1, 2, 3}, 0) }()

	packet := make([]byte, 131)
	if _, err := io.ReadFull(receiver, packet); err != nil {
		t.Fatalf("read codec frame: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("send codec frame: %v", err)
	}
	floatAt := func(offset int) float32 {
		return math.Float32frombits(binary.LittleEndian.Uint32(packet[offset : offset+4]))
	}
	for _, offset := range []int{16, 40, 56} {
		if got := floatAt(offset); got != 1280 {
			t.Errorf("width at offset %d = %v, want encoded width 1280", offset, got)
		}
	}
	for _, offset := range []int{20, 44, 60} {
		if got := floatAt(offset); got != 800 {
			t.Errorf("height at offset %d = %v, want encoded height 800", offset, got)
		}
	}
	for _, offset := range []int{32, 36, 48, 52} {
		if got := floatAt(offset); got != 0 {
			t.Errorf("rectangle origin at offset %d = %v, want 0", offset, got)
		}
	}
}

func TestCodecFrameUsesHEVCFormatOption(t *testing.T) {
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()
	session := &MirrorSession{dataConn: sender, videoCodec: VideoCodecHEVC}
	done := make(chan error, 1)
	go func() { done <- session.sendCodecFrame([]byte{1}, 0) }()
	packet := make([]byte, 129)
	if _, err := io.ReadFull(receiver, packet); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if packet[6] != 0x1e || packet[7] != 0x01 {
		t.Fatalf("HEVC codec option = %02x %02x, want 1e 01", packet[6], packet[7])
	}
}

func TestIsFirstSlice(t *testing.T) {
	// NAL header 0x61 (type 1), slice header starts with bit 1 → first_mb_in_slice=0
	if !isFirstSlice([]byte{0x61, 0x80}) {
		t.Fatal("expected first slice (first_mb_in_slice=0)")
	}
	// NAL header 0x61, slice header starts with bit 0 → first_mb_in_slice > 0
	if isFirstSlice([]byte{0x61, 0x40}) {
		t.Fatal("expected non-first slice (first_mb_in_slice > 0)")
	}
	// Too short
	if isFirstSlice([]byte{0x61}) {
		t.Fatal("expected false for single-byte NAL")
	}
}

func TestSPSDimensions(t *testing.T) {
	// Baseline-profile SPS (profile_idc=66, level 31) encoding 1280x720,
	// frame_mbs_only=1, no cropping. Hand-encoded RBSP.
	sps := []byte{0x67, 0x42, 0x00, 0x1F, 0xF8, 0x0A, 0x00, 0xB7, 0x20}
	w, h, ok := spsDimensions(sps)
	if !ok {
		t.Fatal("expected SPS to parse")
	}
	if w != 1280 || h != 720 {
		t.Fatalf("expected 1280x720, got %dx%d", w, h)
	}

	// Non-SPS NAL (type 1) must be rejected.
	if _, _, ok := spsDimensions([]byte{0x61, 0x80, 0x00, 0x00}); ok {
		t.Fatal("expected non-SPS NAL to be rejected")
	}
	// Truncated SPS must be rejected.
	if _, _, ok := spsDimensions([]byte{0x67, 0x42}); ok {
		t.Fatal("expected truncated SPS to be rejected")
	}
}

func TestCodecConfigCadence(t *testing.T) {
	sps := []byte{0x67, 0x42, 0x00, 0x1f}
	pps := []byte{0x68, 0xce, 0x06, 0xe2}
	if !codecConfigNeedsSend(false, sps, pps, nil, nil) {
		t.Fatal("first decoder configuration was suppressed")
	}
	if codecConfigNeedsSend(true, sps, pps, append([]byte(nil), sps...), append([]byte(nil), pps...)) {
		t.Fatal("identical decoder configuration was repeated")
	}
	changedSPS := append([]byte(nil), sps...)
	changedSPS[len(changedSPS)-1]++
	if !codecConfigNeedsSend(true, changedSPS, pps, sps, pps) {
		t.Fatal("changed SPS was not advertised")
	}
	changedPPS := append([]byte(nil), pps...)
	changedPPS[len(changedPPS)-1]++
	if !codecConfigNeedsSend(true, sps, changedPPS, sps, pps) {
		t.Fatal("changed PPS was not advertised")
	}
}

func TestPlistStreamPortsLegacy(t *testing.T) {
	stream := map[string]interface{}{
		"dataPort":    uint64(6100),
		"controlPort": uint64(6101),
	}

	dataPort, controlPort := plistStreamPorts(stream)
	if dataPort != 6100 || controlPort != 6101 {
		t.Fatalf("expected legacy ports 6100/6101, got %d/%d", dataPort, controlPort)
	}
}

func TestPlistStreamPortsStreamConnections(t *testing.T) {
	stream := map[string]interface{}{
		"dataPort":    uint64(6100),
		"controlPort": uint64(6101),
		"streamConnections": map[string]interface{}{
			"streamConnectionTypeRTP": map[string]interface{}{
				"streamConnectionKeyPort": uint64(7100),
			},
			"streamConnectionTypeRTCP": map[string]interface{}{
				"streamConnectionKeyPort": uint64(7101),
			},
		},
	}

	dataPort, controlPort := plistStreamPorts(stream)
	if dataPort != 7100 || controlPort != 7101 {
		t.Fatalf("expected streamConnections ports 7100/7101, got %d/%d", dataPort, controlPort)
	}
}

func TestPlistMediaDataControlPort(t *testing.T) {
	stream := map[string]interface{}{
		"streamConnections": map[string]interface{}{
			"streamConnectionTypeMediaDataControl": map[string]interface{}{
				"streamConnectionKeyPort": uint64(7200),
			},
		},
	}
	if got := plistMediaDataControlPort(stream); got != 7200 {
		t.Fatalf("MediaDataControl port = %d, want 7200", got)
	}
	if got := plistMediaDataControlPort(map[string]interface{}{}); got != 0 {
		t.Fatalf("missing MediaDataControl port = %d, want 0", got)
	}
}

func TestGenerateAudioChaChaKey(t *testing.T) {
	want := bytes.Repeat([]byte{0x5a}, chacha20poly1305.KeySize)

	key, err := generateAudioChaChaKey(bytes.NewReader(want))
	if err != nil {
		t.Fatalf("generateAudioChaChaKey returned error: %v", err)
	}
	if !bytes.Equal(key, want) {
		t.Fatalf("generated key = %x, want %x", key, want)
	}
}

func TestGenerateAudioChaChaKeyShortRead(t *testing.T) {
	if _, err := generateAudioChaChaKey(bytes.NewReader(make([]byte, 8))); err == nil {
		t.Fatal("expected short reader to fail")
	}
}
