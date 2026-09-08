package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestUseAudioFECDefaults(t *testing.T) {
	if !useAudioFEC(AudioCodecALAC, false) {
		t.Fatal("expected legacy/plaintext sessions to keep FEC by default")
	}
	if useAudioFEC(AudioCodecALAC, true) {
		t.Fatal("expected modern encrypted sessions to disable FEC by default")
	}
	if useAudioFEC(AudioCodecAACELD, false) {
		t.Fatal("AAC-ELD must not use ALAC-style redundant retransmits")
	}
}

func TestStreamAudioUsesNegotiatedRecentFrameRedundancy(t *testing.T) {
	for _, security := range []string{"plaintext", "AES", "ChaCha"} {
		t.Run(security, func(t *testing.T) {
			stream, packets := streamAudioPacketsForTest(t, security, nil, 12)
			var wantSequences []uint16
			for seq := uint16(1); seq <= 12; seq++ {
				first := seq
				if security != "ChaCha" {
					first = 1
					if seq > 2 {
						first = seq - 2
					}
				}
				for redundant := first; redundant <= seq; redundant++ {
					wantSequences = append(wantSequences, redundant)
				}
			}
			assertAudioPacketSequences(t, packets, wantSequences)

			// Repeated packets and requested retransmissions must retain the exact
			// encoded/encrypted datagram, including its original sample position.
			originals := make(map[uint16][]byte)
			for _, packet := range packets {
				seq := binary.BigEndian.Uint16(packet[2:4])
				if original := originals[seq]; original != nil && !bytes.Equal(packet, original) {
					t.Fatalf("redundant sequence %d differs from its original datagram", seq)
				}
				originals[seq] = packet
				if !bytes.Equal(stream.audioPacketForRetransmit(seq), packet) {
					t.Fatalf("requested retransmit history differs for sequence %d", seq)
				}
			}
			for seq := uint16(2); seq <= 12; seq++ {
				rtp := binary.BigEndian.Uint32(originals[seq][4:8])
				previous := binary.BigEndian.Uint32(originals[seq-1][4:8])
				if rtp-previous != 352 {
					t.Fatalf("sequence %d RTP delta = %d, want 352", seq, rtp-previous)
				}
			}
		})
	}
}

func TestStreamAudioRedundancyPreservesCaptureGapsAndResets(t *testing.T) {
	base := time.Now()
	positions := []audioPCMFramePosition{
		{PTS: base, SourceRTP: 1000, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(352)), SourceRTP: 1352, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(704)), SourceRTP: 1704, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(5466)), SourceRTP: 6466, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(5818)), SourceRTP: 6818, HasSourceRTP: true},
		// A source reset reanchors outgoing RTP to the previous frame's end.
		{PTS: base.Add(audioSamplesDuration(6170)), SourceRTP: 0, HasSourceRTP: true},
	}
	_, packets := streamAudioPacketsForTest(t, "AES", &positionedPCMFramesForTest{positions: positions}, len(positions))
	assertAudioPacketSequences(t, packets, []uint16{1, 1, 2, 1, 2, 3, 2, 3, 4, 3, 4, 5, 4, 5, 6})
	firstRTP := binary.BigEndian.Uint32(packets[0][4:8])
	wantOffsets := []uint32{0, 352, 704, 5466, 5818, 6170}
	for _, packet := range packets {
		seq := binary.BigEndian.Uint16(packet[2:4])
		offset := binary.BigEndian.Uint32(packet[4:8]) - firstRTP
		if want := wantOffsets[seq-1]; offset != want {
			t.Fatalf("sequence %d RTP offset = %d, want original source offset %d", seq, offset, want)
		}
	}
}

type positionedPCMFramesForTest struct {
	positions []audioPCMFramePosition
}

func (r *positionedPCMFramesForTest) ReadPCMFrame(dst []byte) (time.Time, error) {
	position, err := r.ReadPCMFramePosition(dst)
	return position.PTS, err
}

func (r *positionedPCMFramesForTest) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	if len(r.positions) == 0 {
		return audioPCMFramePosition{}, io.EOF
	}
	position := r.positions[0]
	r.positions = r.positions[1:]
	clear(dst)
	return position, nil
}

func streamAudioPacketsForTest(t *testing.T, security string, frames audioPCMFrameReader, count int) (*AudioStream, [][]byte) {
	t.Helper()
	ctrlConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctrlConn.Close() })
	ctrlPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctrlPeer.Close() })
	dataConn := &recordingPacketConn{}
	stream := &AudioStream{
		conn: dataConn, ctrlConn: ctrlConn, remoteAddr: &netUDPAddrForAudioTest,
		ctrlAddr: ctrlPeer.LocalAddr().(*net.UDPAddr), spf: 352,
		// This fixture tests packet order, independent of scheduler latency.
		ct: byte(AudioCodecALAC), latencySamples: audioSampleRate,
	}
	switch security {
	case "AES":
		stream.cipher, err = aes.NewCipher(bytes.Repeat([]byte{0x42}, 16))
		stream.aesIV = bytes.Repeat([]byte{0x24}, 16)
	case "ChaCha":
		stream.chachaCipher, err = newAudioChaCha64AEAD(bytes.Repeat([]byte{0x42}, 32))
		stream.chachaNonceMode = defaultAudioChaChaNonceMode()
		stream.chachaAADMode = defaultAudioChaChaAADMode()
	}
	if err != nil {
		t.Fatal(err)
	}
	pcm := make([]byte, count*352*audioBytesPerSampleFrame)
	for i := range pcm {
		pcm[i] = byte(i)
	}
	capture := &AudioCapture{
		pcmPipe: io.NopCloser(bytes.NewReader(pcm)), pcmFrames: frames,
		waitCh: make(chan struct{}), codec: AudioCodecALAC,
	}
	firstVideo := make(chan struct{})
	close(firstVideo)
	session := &MirrorSession{firstFrameSent: firstVideo, timingProtocol: timingProtocolNTP}
	if err := session.StreamAudio(context.Background(), capture, stream); !errors.Is(err, io.EOF) {
		t.Fatalf("StreamAudio = %v, want EOF after %d source frames", err, count)
	}
	return stream, dataConn.packets
}

func assertAudioPacketSequences(t *testing.T, packets [][]byte, want []uint16) {
	t.Helper()
	got := make([]uint16, len(packets))
	for i, packet := range packets {
		got[i] = binary.BigEndian.Uint16(packet[2:4])
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("audio wire sequences = %v, want %v", got, want)
	}
}

func TestAudioCodecInfoKeepsScreenLatencyMinimumAtZero(t *testing.T) {
	_, _, _, latencyMin, latencyMax, latencySamples := AudioCodecALAC.Info()
	if latencyMin != 0 {
		t.Fatalf("latencyMin = %d, want 0", latencyMin)
	}
	if latencyMax != int64(latencySamples) {
		t.Fatalf("latencyMax = %d, want %d", latencyMax, latencySamples)
	}
}

func TestAACELDCodecInfoMatchesAirPlayCompressionType(t *testing.T) {
	ct, spf, format, latencyMin, latencyMax, latencySamples := AudioCodecAACELD.Info()
	if ct != 8 || spf != 480 || format != 0x1000000 {
		t.Fatalf("AAC-ELD info = ct=%d spf=%d format=0x%x, want ct=8 spf=480 format=0x1000000", ct, spf, format)
	}
	if latencyMin != 0 || latencyMax != int64(latencySamples) {
		t.Fatalf("AAC-ELD latency = min=%d max=%d samples=%d", latencyMin, latencyMax, latencySamples)
	}
}

func TestAudioLatencySamplesForCodec(t *testing.T) {
	defaultLatency := targetLatencySamples44k1()
	tests := []struct {
		name     string
		ct       byte
		override uint32
		want     uint32
	}{
		{name: "default ALAC", ct: byte(AudioCodecALAC), want: defaultLatency},
		{name: "AAC ELD", ct: byte(AudioCodecAACELD), want: defaultLatency},
		{name: "override wins", ct: byte(AudioCodecALAC), override: 11025, want: 11025},
		{name: "unknown codec falls back", ct: 99, want: defaultLatency},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := audioLatencySamplesForCodec(tt.ct, tt.override); got != tt.want {
				t.Fatalf("audioLatencySamplesForCodec(%d, %d) = %d, want %d", tt.ct, tt.override, got, tt.want)
			}
		})
	}
}

func TestStreamAudioJoinsOwnedWorkersOnReadFailure(t *testing.T) {
	ctrlConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		t.Fatalf("listen peer socket: %v", err)
	}
	defer peer.Close()

	firstFrame := make(chan struct{})
	close(firstFrame)
	session := &MirrorSession{
		firstFrameSent: firstFrame,
		timingProtocol: timingProtocolNTP,
	}
	stream := &AudioStream{
		ctrlConn:       ctrlConn,
		ctrlAddr:       peer.LocalAddr().(*net.UDPAddr),
		spf:            352,
		latencySamples: targetLatencySamples44k1(),
	}
	capture := &AudioCapture{
		pcmPipe: io.NopCloser(bytes.NewReader(nil)),
		waitCh:  make(chan struct{}),
		codec:   AudioCodecALAC,
	}

	done := make(chan error, 1)
	go func() { done <- session.StreamAudio(context.Background(), capture, stream) }()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("StreamAudio error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StreamAudio did not join its control and timing workers")
	}

	if _, err := ctrlConn.WriteTo([]byte{1}, peer.LocalAddr()); err == nil {
		t.Fatal("StreamAudio returned without closing its owned control socket")
	}
}

type gatedPCMReader struct {
	reads  chan struct{}
	frames chan []byte
	done   chan struct{}
	once   sync.Once
}

func newGatedPCMReader() *gatedPCMReader {
	return &gatedPCMReader{
		reads:  make(chan struct{}, 8),
		frames: make(chan []byte),
		done:   make(chan struct{}),
	}
}

func (r *gatedPCMReader) Read(p []byte) (int, error) {
	select {
	case r.reads <- struct{}{}:
	default:
	}
	select {
	case frame := <-r.frames:
		return copy(p, frame), nil
	case <-r.done:
		return 0, io.EOF
	}
}

func (r *gatedPCMReader) Close() error {
	r.once.Do(func() { close(r.done) })
	return nil
}

func TestStreamAudioAnchorsClockOnlyAfterFirstCapturedFrame(t *testing.T) {
	ctrlConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	ctrlPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		t.Fatalf("listen control peer: %v", err)
	}
	defer ctrlPeer.Close()

	dataConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		t.Fatalf("listen data socket: %v", err)
	}
	dataPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		dataConn.Close()
		t.Fatalf("listen data peer: %v", err)
	}
	defer dataPeer.Close()

	firstVideoFrame := make(chan struct{})
	session := &MirrorSession{
		firstFrameSent: firstVideoFrame,
		timingProtocol: timingProtocolNTP,
	}
	stream := &AudioStream{
		conn:            dataConn,
		ctrlConn:        ctrlConn,
		remoteAddr:      dataPeer.LocalAddr().(*net.UDPAddr),
		ctrlAddr:        ctrlPeer.LocalAddr().(*net.UDPAddr),
		spf:             352,
		ct:              byte(AudioCodecALAC),
		latencySamples:  targetLatencySamples44k1(),
		securityMode:    audioSecurityLegacyAES,
		chachaNonceMode: defaultAudioChaChaNonceMode(),
		chachaAADMode:   defaultAudioChaChaAADMode(),
	}
	pcmReader := newGatedPCMReader()
	capture := &AudioCapture{
		pcmPipe: pcmReader,
		waitCh:  make(chan struct{}),
		codec:   AudioCodecALAC,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- session.StreamAudio(ctx, capture, stream) }()
	waitForPCMRead := func(label string) {
		t.Helper()
		select {
		case <-pcmReader.reads:
		case <-time.After(time.Second):
			t.Fatalf("audio capture did not request %s PCM frame", label)
		}
	}
	const pcmFrameBytes = 352 * 2 * 2
	pcmFrame := make([]byte, pcmFrameBytes)
	waitForPCMRead("pre-roll")

	// Starting the process and observing the first video frame are not enough to
	// define an audio clock anchor. No TimeAnnounce may leave until a real sample
	// is available to associate with the initial RTP timestamp.
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, _, err := ctrlPeer.ReadFrom(buf); err == nil {
		t.Fatal("initial TimeAnnounce was sent before the first captured audio frame")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read before first frame: %v", err)
	}

	pcmReader.frames <- pcmFrame
	waitForPCMRead("last pre-roll")
	close(firstVideoFrame)
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ctrlPeer.ReadFrom(buf); err == nil {
		t.Fatal("initial TimeAnnounce was sent before a post-video audio frame was ready")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read before fresh frame: %v", err)
	}

	// The prewarmer may already be blocked in one final read when video becomes
	// ready. Release that read, then withhold the next frame and verify that the
	// clock still has not been anchored.
	pcmReader.frames <- pcmFrame
	waitForPCMRead("first current")
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ctrlPeer.ReadFrom(buf); err == nil {
		t.Fatal("initial TimeAnnounce was sent while only pre-roll audio was available")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read before held current frame: %v", err)
	}

	pcmReader.frames <- pcmFrame
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := ctrlPeer.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read initial TimeAnnounce: %v", err)
	}
	if n != 20 || buf[0] != 0x90 || buf[1] != audioSyncPayloadTypeNTP {
		t.Fatalf("initial TimeAnnounce = len %d header %02x, want len 20 header 90d4", n, buf[:min(n, 2)])
	}
	if err := dataPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dataPeer.ReadFrom(buf); err != nil {
		t.Fatalf("read first RTP audio packet: %v", err)
	}

	cancel()
	_ = pcmReader.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamAudio error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StreamAudio did not stop")
	}
}

func TestRandomRTPTime(t *testing.T) {
	got, err := randomRTPTime(bytes.NewReader([]byte{0x12, 0x34, 0x56, 0x78}))
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x12345678 {
		t.Fatalf("RTP timestamp = %#x, want 0x12345678", got)
	}
}

func TestSendSyncPacketUsesNTPFormatWithoutTimeline(t *testing.T) {
	const (
		networkTime = uint64(0x83aa7e8012345678)
		rtpTime     = uint32(5000)
	)
	packet := captureAudioSyncPacket(t, &AudioStream{
		rtpTime:        rtpTime,
		latencySamples: 1000,
	}, timingProtocolNTP, networkTime, 0, true)

	if len(packet) != 20 {
		t.Fatalf("NTP sync packet length = %d, want 20", len(packet))
	}
	if packet[0] != 0x90 || packet[1] != audioSyncPayloadTypeNTP {
		t.Fatalf("NTP sync header = %02x%02x, want 90d4", packet[0], packet[1])
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != 4000 {
		t.Fatalf("NTP playback RTP = %d, want 4000", got)
	}
	if got := binary.BigEndian.Uint64(packet[8:16]); got != networkTime {
		t.Fatalf("NTP timestamp = 0x%016x, want 0x%016x", got, networkTime)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != rtpTime {
		t.Fatalf("NTP receive RTP = %d, want %d", got, rtpTime)
	}
}

func TestSendSyncPacketUsesNegotiatedProtocolInsteadOfTimelinePresence(t *testing.T) {
	packet := captureAudioSyncPacket(t, &AudioStream{}, timingProtocolNTP, 1, 0x1122334455667788, false)
	if len(packet) != 20 || packet[1] != audioSyncPayloadTypeNTP {
		t.Fatalf("explicit NTP sync packet = len %d type 0x%02x, want len 20 type 0x%02x",
			len(packet), packet[1], audioSyncPayloadTypeNTP)
	}

	stream := &AudioStream{ctrlConn: &recordingPacketConn{}, ctrlAddr: &net.UDPAddr{}}
	if err := stream.sendSyncPacket(timingProtocolPTP, 1, 0, false); err == nil {
		t.Fatal("PTP sync succeeded without a receiver timeline ID")
	}
}

func TestSendSyncPacketUsesPTPTimeAnnounceWithTimeline(t *testing.T) {
	const (
		networkTime = uint64(0x0000000180000000) // 1.5 seconds in seconds.32
		timelineID  = uint64(0x48e15caa8da00008)
		rtpTime     = uint32(5000)
	)
	packet := captureAudioSyncPacket(t, &AudioStream{
		rtpTime:        rtpTime,
		latencySamples: 1000,
	}, timingProtocolPTP, networkTime, timelineID, false)

	if len(packet) != 28 {
		t.Fatalf("PTP sync packet length = %d, want 28", len(packet))
	}
	if packet[0] != 0x80 || packet[1] != audioSyncPayloadTypePTP {
		t.Fatalf("PTP sync header = %02x%02x, want 80d7", packet[0], packet[1])
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != 4000 {
		t.Fatalf("PTP network-time RTP = %d, want 4000", got)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != rtpTime {
		t.Fatalf("PTP apply RTP = %d, want %d", got, rtpTime)
	}
	if got := binary.BigEndian.Uint64(packet[8:16]); got != 1500000000 {
		t.Fatalf("PTP timestamp = %d ns, want 1500000000", got)
	}
	if got := binary.BigEndian.Uint64(packet[20:28]); got != timelineID {
		t.Fatalf("PTP timeline = 0x%016x, want 0x%016x", got, timelineID)
	}
}

func TestSendSyncPacketWrapsLatencyAdjustedRTP(t *testing.T) {
	rtpTime := uint32(1000)
	latency := uint32(4410)
	packet := captureAudioSyncPacket(t, &AudioStream{
		rtpTime:        rtpTime,
		latencySamples: latency,
	}, timingProtocolPTP, 1, 2, true)

	if got, want := binary.BigEndian.Uint32(packet[4:8]), rtpTime-latency; got != want {
		t.Fatalf("wrapped network-time RTP = %#x, want %#x", got, want)
	}
}

func captureAudioSyncPacket(t *testing.T, stream *AudioStream, timingProtocol string, networkTime, timelineID uint64, isFirst bool) []byte {
	t.Helper()
	conn := &recordingPacketConn{}
	stream.ctrlConn = conn
	stream.ctrlAddr = &net.UDPAddr{}
	if err := stream.sendSyncPacket(timingProtocol, networkTime, timelineID, isFirst); err != nil {
		t.Fatal(err)
	}
	if len(conn.packets) != 1 {
		t.Fatalf("sent %d sync packets, want 1", len(conn.packets))
	}
	return conn.packets[0]
}

func TestAudioChaCha64AEADRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x11}, audioChaChaNonceSize)
	aad := []byte{0x90, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab}
	plaintext := []byte("doubletake mirrored audio")

	aead, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %x, want %x", opened, plaintext)
	}
	if len(sealed) != len(plaintext)+aead.Overhead() {
		t.Fatalf("sealed len = %d, want %d", len(sealed), len(plaintext)+aead.Overhead())
	}
}

func TestAudioChaCha64AEADRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x7b}, audioChaChaNonceSize)
	aad := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("auth must fail when the packet changes")

	aead, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	sealed[len(sealed)-1] ^= 0x80
	if _, err := aead.Open(nil, nonce, sealed, aad); err == nil {
		t.Fatal("expected tampered packet to fail authentication")
	}
}

func TestAudioChaCha64AEADEquivalentToZeroPrefixedIETF(t *testing.T) {
	key := bytes.Repeat([]byte{0x35}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x12}, audioChaChaNonceSize)
	aad := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	plaintext := []byte("original 64-bit nonce variant")

	custom, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}
	customSealed := custom.Seal(nil, nonce, plaintext, aad)

	ietf, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New returned error: %v", err)
	}
	ietfNonce := make([]byte, chacha20poly1305.NonceSize)
	copy(ietfNonce[4:], nonce)
	ietfSealed := ietf.Seal(nil, ietfNonce, plaintext, aad)

	if !bytes.Equal(customSealed, ietfSealed) {
		t.Fatal("expected the 64-bit nonce construction to match the zero-prefixed IETF form while the counter stays within 32 bits")
	}
}

func TestAudioChaChaAADUsesRTPNetworkOrder(t *testing.T) {
	as := &AudioStream{
		ssrc:          0x11223344,
		chachaAADMode: audioChaChaAADTimestampSSRC,
	}
	header := []byte{0x80, 0x60, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x11, 0x22, 0x33, 0x44}

	aad := as.audioChaChaAAD(header, 0x12345678)
	want := []byte{0x12, 0x34, 0x56, 0x78, 0x11, 0x22, 0x33, 0x44}
	if !bytes.Equal(aad, want) {
		t.Fatalf("AAD = %x, want %x", aad, want)
	}
}

func TestParseAudioRetransmitRequest(t *testing.T) {
	packet := []byte{0x80, 0xd5, 0x12, 0x34, 0xff, 0xfe, 0x00, 0x02}
	request, ok := parseAudioRetransmitRequest(packet)
	if !ok {
		t.Fatal("valid audio retransmit request was rejected")
	}
	if request.requestSeq != 0x1234 || request.firstSeq != 0xfffe || request.count != 2 {
		t.Fatalf("request = %#v, want id 0x1234, first 0xfffe, count 2", request)
	}

	for _, test := range []struct {
		name   string
		packet []byte
	}{
		{name: "short", packet: packet[:7]},
		{name: "long", packet: append(append([]byte(nil), packet...), 0)},
		{name: "wrong version", packet: []byte{0x40, 0xd5, 0, 1, 0, 2, 0, 1}},
		{name: "wrong payload type", packet: []byte{0x80, 0xd4, 0, 1, 0, 2, 0, 1}},
		{name: "zero count", packet: []byte{0x80, 0xd5, 0, 1, 0, 2, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := parseAudioRetransmitRequest(test.packet); ok {
				t.Fatalf("malformed request %x was accepted", test.packet)
			}
		})
	}
}

func TestAudioRetransmitReturnsExactChaChaDatagramOnControlSocket(t *testing.T) {
	aead, err := newAudioChaCha64AEAD(bytes.Repeat([]byte{0x5a}, chacha20poly1305.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	dataConn := &recordingPacketConn{}
	ctrlConn := &recordingPacketConn{}
	stream := &AudioStream{
		conn:            dataConn,
		ctrlConn:        ctrlConn,
		remoteAddr:      &netUDPAddrForAudioTest,
		chachaCipher:    aead,
		chachaNonceMode: audioChaChaNonceCounter,
		chachaAADMode:   audioChaChaAADTimestampSSRC,
	}
	const (
		sequence = uint16(0xfffe)
		rtpTime  = uint32(0x12345678)
	)
	if err := stream.sendAudioPacketWithSeq([]byte("recover this encrypted audio frame"), rtpTime, sequence); err != nil {
		t.Fatal(err)
	}
	if len(dataConn.packets) != 1 {
		t.Fatalf("sent %d original packets, want 1", len(dataConn.packets))
	}
	original := append([]byte(nil), dataConn.packets[0]...)

	request := []byte{0x80, 0xd5, 0x00, 0x2a, 0xff, 0xfe, 0x00, 0x01}
	requester := &net.UDPAddr{IP: net.ParseIP("192.0.2.25"), Port: 7001}
	handled, resent, err := stream.handleAudioControlPacket(request, requester)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || resent != 1 {
		t.Fatalf("handled=%t resent=%d, want true, 1", handled, resent)
	}
	if len(ctrlConn.packets) != 1 {
		t.Fatalf("sent %d control responses, want 1", len(ctrlConn.packets))
	}
	want := append([]byte{0x80, 0xd6, 0x00, 0x2a}, original...)
	if !bytes.Equal(ctrlConn.packets[0], want) {
		t.Fatalf("retransmit response = %x, want exact wrapped datagram %x", ctrlConn.packets[0], want)
	}
	if ctrlConn.addrs[0] != requester {
		t.Fatalf("retransmit destination = %v, want request source %v", ctrlConn.addrs[0], requester)
	}
	if !bytes.Equal(dataConn.packets[0], original) {
		t.Fatal("serving the retransmit mutated the original encrypted datagram")
	}
}

func TestAudioRetransmitUsesFutileResponseForExpiredPacket(t *testing.T) {
	ctrlConn := &recordingPacketConn{}
	stream := &AudioStream{ctrlConn: ctrlConn}
	request := []byte{0x80, 0xd5, 0x00, 0x07, 0x45, 0x67, 0x00, 0x03}
	handled, resent, err := stream.handleAudioControlPacket(request, &netUDPAddrForAudioTest)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || resent != 0 {
		t.Fatalf("handled=%t resent=%d, want true, 0", handled, resent)
	}
	want := []byte{0x80, 0xd6, 0x00, 0x07, 0x45, 0x67, 0x00, 0x00}
	if len(ctrlConn.packets) != 1 || !bytes.Equal(ctrlConn.packets[0], want) {
		t.Fatalf("futile response = %x, want %x", ctrlConn.packets, want)
	}
}

func TestAudioRetransmitRangeWrapsAndStopsAtFirstExpiredPacket(t *testing.T) {
	ctrlConn := &recordingPacketConn{}
	stream := &AudioStream{ctrlConn: ctrlConn}
	stream.rememberAudioPacket(0xffff, []byte{0x80, 0x60, 0xff, 0xff, 0xaa})
	request := []byte{0x80, 0xd5, 0x00, 0x01, 0xff, 0xff, 0x00, 0x02}
	handled, resent, err := stream.handleAudioControlPacket(request, &netUDPAddrForAudioTest)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || resent != 1 {
		t.Fatalf("handled=%t resent=%d, want true, 1", handled, resent)
	}
	wantPackets := [][]byte{
		{0x80, 0xd6, 0x00, 0x01, 0x80, 0x60, 0xff, 0xff, 0xaa},
		{0x80, 0xd6, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
	}
	if len(ctrlConn.packets) != len(wantPackets) {
		t.Fatalf("sent %d responses, want %d", len(ctrlConn.packets), len(wantPackets))
	}
	for index, want := range wantPackets {
		if !bytes.Equal(ctrlConn.packets[index], want) {
			t.Fatalf("response %d = %x, want %x", index, ctrlConn.packets[index], want)
		}
	}
}

func TestAudioRetransmitHistoryIsBoundedAndSequenceAware(t *testing.T) {
	stream := &AudioStream{}
	const oldSequence = uint16(17)
	newSequence := oldSequence + audioRetransmitHistoryPackets
	stream.rememberAudioPacket(oldSequence, []byte("old"))
	stream.rememberAudioPacket(newSequence, []byte("new"))

	if packet := stream.audioPacketForRetransmit(oldSequence); packet != nil {
		t.Fatalf("evicted sequence returned %q", packet)
	}
	if packet := stream.audioPacketForRetransmit(newSequence); !bytes.Equal(packet, []byte("new")) {
		t.Fatalf("new sequence returned %q, want new", packet)
	}
}

func TestAudioRetransmitHistoryConcurrentReplacement(t *testing.T) {
	stream := &AudioStream{}
	const firstSequence = uint16(29)
	secondSequence := firstSequence + audioRetransmitHistoryPackets
	sequences := [...]uint16{firstSequence, secondSequence}
	start := make(chan struct{})
	errCh := make(chan string, 1)
	report := func(message string) {
		select {
		case errCh <- message:
		default:
		}
	}

	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for index := 0; index < 2000; index++ {
			seq := sequences[index%len(sequences)]
			packet := make([]byte, 2)
			binary.BigEndian.PutUint16(packet, seq)
			stream.rememberAudioPacket(seq, packet)
		}
	}()
	for reader := 0; reader < 4; reader++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for index := 0; index < 2000; index++ {
				seq := sequences[index%len(sequences)]
				packet := stream.audioPacketForRetransmit(seq)
				if packet != nil && (len(packet) != 2 || binary.BigEndian.Uint16(packet) != seq) {
					report(fmt.Sprintf("sequence %d returned mismatched packet %x", seq, packet))
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
	select {
	case message := <-errCh:
		t.Fatal(message)
	default:
	}
}

func TestAudioControlPeerUsesNegotiatedReceiverIP(t *testing.T) {
	stream := &AudioStream{ctrlAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7000}}
	if !stream.audioControlPacketFromReceiver(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9000}) {
		t.Fatal("matching receiver IP was rejected because its source port differed")
	}
	if stream.audioControlPacketFromReceiver(&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 7000}) {
		t.Fatal("unexpected control peer IP was accepted")
	}
}

func TestAudioSendBurstLimiterOnlyDelaysCatchupBurst(t *testing.T) {
	base := time.Unix(1787616000, 0)
	var limiter audioSendBurstLimiter
	for packet := 0; packet < maximumAudioPacketsPerBurst; packet++ {
		if delay := limiter.reserveDelay(base); delay != 0 {
			t.Fatalf("packet %d delay = %v, want 0", packet+1, delay)
		}
	}
	if delay := limiter.reserveDelay(base); delay != audioSendBurstWindow {
		t.Fatalf("first excess packet delay = %v, want %v", delay, audioSendBurstWindow)
	}
	if delay := limiter.reserveDelay(base.Add(2 * time.Millisecond)); delay != 3*time.Millisecond {
		t.Fatalf("partway through window delay = %v, want 3ms", delay)
	}
	if delay := limiter.reserveDelay(base.Add(audioSendBurstWindow)); delay != 0 {
		t.Fatalf("packet at next window delay = %v, want 0", delay)
	}

	// Ordinary codec frames arrive about 8ms (ALAC) or 11ms (AAC-ELD) apart,
	// outside the limiter window, and must never accumulate artificial delay.
	limiter = audioSendBurstLimiter{}
	for frame := 0; frame < 100; frame++ {
		now := base.Add(time.Duration(frame) * 8 * time.Millisecond)
		if delay := limiter.reserveDelay(now); delay != 0 {
			t.Fatalf("normally paced frame %d delay = %v, want 0", frame, delay)
		}
	}
}
