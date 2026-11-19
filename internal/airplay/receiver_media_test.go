package airplay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"howett.net/plist"
)

func TestReceiverMediaSessionDrainsAndCounts(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	session := newTestReceiverMediaSession(t, receiverMediaConfig{
		BindIP:            "127.0.0.1",
		EventEncrypted:    true,
		EventSharedSecret: secret,
	})
	endpoints := session.Endpoints()
	for name, port := range map[string]int{
		"event":      endpoints.EventPort,
		"video":      endpoints.VideoPort,
		"audio RTP":  endpoints.AudioRTPPort,
		"audio RTCP": endpoints.AudioRTCPPort,
		"timing":     endpoints.TimingPort,
	} {
		if port <= 0 {
			t.Fatalf("%s port = %d, want an ephemeral port", name, port)
		}
	}

	eventConn := acknowledgeReceiverEventCommand(t, endpoints.EventPort, true, secret)
	defer eventConn.Close()

	videoConn := dialReceiverMediaTCP(t, endpoints.VideoPort)
	writeReceiverMirrorPacket(t, videoConn, 0x01, 0x00, []byte{1, 2, 3})
	writeReceiverMirrorPacket(t, videoConn, 0x00, 0x10, []byte{4, 5, 6, 7})
	writeReceiverMirrorPacket(t, videoConn, 0x02, 0x00, nil)
	if err := videoConn.Close(); err != nil {
		t.Fatalf("close video connection: %v", err)
	}

	sendReceiverMediaUDP(t, endpoints.AudioRTPPort, []byte{1, 2, 3, 4})
	sendReceiverMediaUDP(t, endpoints.AudioRTPPort, []byte{5, 6})
	sendReceiverMediaUDP(t, endpoints.AudioRTCPPort, []byte{7, 8, 9})

	wantVideoBytes := uint64(3*receiverMirrorHeaderSize + 7)
	waitForReceiverMediaStats(t, session, func(stats receiverMediaStats) bool {
		return stats.EventResponses == 1 &&
			stats.VideoPackets == 3 &&
			stats.AudioRTPPackets == 2 &&
			stats.AudioRTCPPackets == 1
	})
	stats := session.Snapshot()
	if stats.EventConnections != 1 || stats.EventRequests != 1 || stats.EventResponses != 1 || stats.EventErrors != 0 {
		t.Fatalf("event stats = %+v", stats)
	}
	if stats.VideoConnections != 1 || stats.VideoPackets != 3 || stats.VideoCodecFrames != 1 ||
		stats.VideoFrames != 1 || stats.VideoKeyFrames != 1 || stats.VideoHeartbeats != 1 ||
		stats.VideoMalformed != 0 || stats.VideoBytes != wantVideoBytes || stats.VideoPayloadBytes != 7 {
		t.Fatalf("video stats = %+v, want wire bytes %d", stats, wantVideoBytes)
	}
	if stats.AudioRTPPackets != 2 || stats.AudioRTPBytes != 6 || stats.AudioRTCPPackets != 1 || stats.AudioRTCPBytes != 3 {
		t.Fatalf("audio stats = %+v", stats)
	}
}

func TestReceiverMediaSessionSendsPlaintextEventCommand(t *testing.T) {
	session := newTestReceiverMediaSession(t, receiverMediaConfig{BindIP: "127.0.0.1"})
	conn := acknowledgeReceiverEventCommand(t, session.Endpoints().EventPort, false, nil)
	defer conn.Close()
	waitForReceiverMediaStats(t, session, func(stats receiverMediaStats) bool {
		return stats.EventResponses == 1
	})
	stats := session.Snapshot()
	if stats.EventConnections != 1 || stats.EventRequests != 1 || stats.EventResponses != 1 || stats.EventErrors != 0 {
		t.Fatalf("plaintext event stats = %+v", stats)
	}
}

func TestReceiverMediaSessionRejectsMismatchedEventResponse(t *testing.T) {
	session := newTestReceiverMediaSession(t, receiverMediaConfig{BindIP: "127.0.0.1"})
	conn, channel, request := readReceiverEventCommand(t, session.Endpoints().EventPort, false, nil)
	defer conn.Close()
	response := fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: %s0\r\nContent-Length: 0\r\n\r\n", request.headers["cseq"])
	if _, err := channel.Write([]byte(response)); err != nil {
		t.Fatalf("write mismatched event response: %v", err)
	}
	waitForReceiverMediaStats(t, session, func(stats receiverMediaStats) bool {
		return stats.EventErrors == 1
	})
	stats := session.Snapshot()
	if stats.EventRequests != 1 || stats.EventResponses != 0 {
		t.Fatalf("mismatched event response stats = %+v", stats)
	}
}

func TestReceiverMediaSessionRejectsOversizeVideoAndAcceptsNextConnection(t *testing.T) {
	session := newTestReceiverMediaSession(t, receiverMediaConfig{
		BindIP:          "127.0.0.1",
		MaxVideoPayload: 4,
	})
	port := session.Endpoints().VideoPort

	malformed := dialReceiverMediaTCP(t, port)
	var header [receiverMirrorHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:4], 5)
	if _, err := malformed.Write(header[:]); err != nil {
		t.Fatalf("write oversized header: %v", err)
	}
	_ = malformed.Close()
	waitForReceiverMediaStats(t, session, func(stats receiverMediaStats) bool {
		return stats.VideoMalformed == 1
	})

	valid := dialReceiverMediaTCP(t, port)
	writeReceiverMirrorPacket(t, valid, 0x00, 0, []byte{1, 2, 3, 4})
	_ = valid.Close()
	waitForReceiverMediaStats(t, session, func(stats receiverMediaStats) bool {
		return stats.VideoConnections == 2 && stats.VideoFrames == 1
	})

	stats := session.Snapshot()
	if stats.VideoPackets != 1 || stats.VideoMalformed != 1 {
		t.Fatalf("video stats after reconnect = %+v", stats)
	}
}

func TestReceiverMediaSessionDecryptsAndValidatesLegacyVideo(t *testing.T) {
	key := bytes.Repeat([]byte{0x31}, 16)
	iv := bytes.Repeat([]byte{0x72}, 16)
	session, senderConn := newPipeReceiverMediaSession(t, key, iv)

	senderCipher, err := newMirrorCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	idr := receiverTestAVCC([]byte{0x65, 0x80})
	writeReceiverMirrorPacket(t, senderConn, 0x00, 0x10, senderCipher.EncryptFrame(idr))
	// Plaintext packets do not advance the legacy VCL cipher between frames.
	writeReceiverMirrorPacket(t, senderConn, 0x02, 0, nil)
	writeReceiverMirrorPacket(t, senderConn, 0x01, 0, []byte{1, 2, 3})
	lengths := []int{1, 1, 1, 11, 12, 15, 16, 17, 31, 32, 33}
	for _, length := range lengths {
		nonIDR := receiverTestAVCC(bytes.Repeat([]byte{0x61}, length))
		writeReceiverMirrorPacket(t, senderConn, 0x00, 0, senderCipher.EncryptFrame(nonIDR))
	}
	if err := senderConn.Close(); err != nil {
		t.Fatal(err)
	}
	waitReceiverPipeSession(t, session)

	stats := session.Snapshot()
	wantFrames := uint64(1 + len(lengths))
	if stats.VideoFrames != wantFrames || stats.VideoKeyFrames != 1 || stats.VideoHeartbeats != 1 || stats.VideoCodecFrames != 1 ||
		stats.VideoDecrypted != wantFrames || stats.VideoCryptoErrors != 0 || stats.VideoMalformed != 0 {
		t.Fatalf("legacy video stats = %+v", stats)
	}
}

func TestReceiverMediaSessionRejectsCorruptLegacyVideo(t *testing.T) {
	key := bytes.Repeat([]byte{0x14}, 16)
	iv := bytes.Repeat([]byte{0x25}, 16)
	session, senderConn := newPipeReceiverMediaSession(t, key, iv)
	senderCipher, err := newMirrorCipher(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := senderCipher.EncryptFrame(receiverTestAVCC([]byte{0x65, 0x80}))
	ciphertext[0] ^= 0x80 // Corrupt the decrypted AVCC length deterministically.
	writeReceiverMirrorPacket(t, senderConn, 0x00, 0x10, ciphertext)
	_ = senderConn.Close()
	waitReceiverPipeSession(t, session)

	stats := session.Snapshot()
	if stats.VideoFrames != 1 || stats.VideoDecrypted != 0 || stats.VideoCryptoErrors != 1 || stats.VideoMalformed != 1 {
		t.Fatalf("corrupt legacy video stats = %+v", stats)
	}
}

func TestValidateReceiverAVCCFrame(t *testing.T) {
	for _, test := range []struct {
		name     string
		payload  []byte
		keyframe bool
		wantErr  bool
	}{
		{name: "IDR", payload: receiverTestAVCC([]byte{0x65, 0x80}), keyframe: true},
		{name: "multiple non-IDR slices", payload: receiverTestAVCC([]byte{0x61}, []byte{0x42, 0x01})},
		{name: "SEI with IDR", payload: receiverTestAVCC([]byte{0x06, 0x80}, []byte{0x65, 0x80}), keyframe: true},
		{name: "AUD and filler with picture", payload: receiverTestAVCC([]byte{0x09}, []byte{0x61}, []byte{0x0c, 0xff})},
		{name: "metadata without picture", payload: receiverTestAVCC([]byte{0x06, 0x80}), wantErr: true},
		{name: "empty", wantErr: true},
		{name: "truncated length", payload: []byte{0, 0, 0}, wantErr: true},
		{name: "zero length", payload: []byte{0, 0, 0, 0}, wantErr: true},
		{name: "oversize NAL", payload: []byte{0, 0, 0, 2, 0x61}, wantErr: true},
		{name: "forbidden bit", payload: receiverTestAVCC([]byte{0xe5}), keyframe: true, wantErr: true},
		{name: "non-VCL", payload: receiverTestAVCC([]byte{0x67}), wantErr: true},
		{name: "IDR without flag", payload: receiverTestAVCC([]byte{0x65}), wantErr: true},
		{name: "flag without IDR", payload: receiverTestAVCC([]byte{0x61}), keyframe: true, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateReceiverAVCCFrame(test.payload, test.keyframe)
			if (err != nil) != test.wantErr {
				t.Fatalf("validateReceiverAVCCFrame() error = %v, wantErr %t", err, test.wantErr)
			}
		})
	}
}

func TestReceiverMediaSessionProbesLegacyTiming(t *testing.T) {
	session := newTestReceiverMediaSession(t, receiverMediaConfig{BindIP: "127.0.0.1"})

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen sender timing: %v", err)
	}
	defer sender.Close()

	const probeCount = 3
	serverErr := make(chan error, 1)
	go func() {
		var request [32]byte
		for sequence := 1; sequence <= probeCount; sequence++ {
			if err := sender.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				serverErr <- err
				return
			}
			n, from, err := sender.ReadFromUDP(request[:])
			if err != nil {
				serverErr <- err
				return
			}
			if n != len(request) || request[0] != 0x80 || request[1] != 0xd2 {
				serverErr <- fmt.Errorf("probe %d = %d bytes type %02x%02x", sequence, n, request[0], request[1])
				return
			}
			if from.Port != session.Endpoints().TimingPort {
				serverErr <- fmt.Errorf("probe source port = %d, want %d", from.Port, session.Endpoints().TimingPort)
				return
			}

			reply := request
			reply[0], reply[1] = 0x80, 0xd3
			copy(reply[8:16], request[24:32])
			now := ntpBootTimestamp()
			binary.BigEndian.PutUint64(reply[16:24], now)
			binary.BigEndian.PutUint64(reply[24:32], now)
			if _, err := sender.WriteToUDP(reply[:], from); err != nil {
				serverErr <- err
				return
			}
		}
		serverErr <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := session.ProbeLegacyTiming(ctx, sender.LocalAddr().(*net.UDPAddr), probeCount); err != nil {
		t.Fatalf("probe legacy timing: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("sender timing responder: %v", err)
	}
	stats := session.Snapshot()
	if stats.TimingProbes != probeCount || stats.TimingReplies != probeCount || stats.TimingErrors != 0 {
		t.Fatalf("timing stats = %+v", stats)
	}
}

func TestReceiverMediaSessionAnswersSenderInitiatedTiming(t *testing.T) {
	session := newTestReceiverMediaSession(t, receiverMediaConfig{
		BindIP:          "127.0.0.1",
		TimingResponder: true,
	})
	endpoint := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: session.Endpoints().TimingPort}
	sender, err := net.DialUDP("udp4", nil, endpoint)
	if err != nil {
		t.Fatalf("dial receiver timing: %v", err)
	}
	defer sender.Close()
	if err := sender.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set timing deadline: %v", err)
	}

	for sequence := uint16(1); sequence <= 3; sequence++ {
		var request [32]byte
		request[0], request[1] = 0x80, 0xd2
		binary.BigEndian.PutUint16(request[2:4], sequence)
		transmit := ntpBootTimestamp()
		binary.BigEndian.PutUint64(request[24:32], transmit)
		if _, err := sender.Write(request[:]); err != nil {
			t.Fatalf("write timing probe %d: %v", sequence, err)
		}
		var reply [32]byte
		if _, err := io.ReadFull(sender, reply[:]); err != nil {
			t.Fatalf("read timing reply %d: %v", sequence, err)
		}
		if reply[0] != 0x80 || reply[1] != 0xd3 {
			t.Fatalf("timing reply %d type = %02x%02x, want 80d3", sequence, reply[0], reply[1])
		}
		if reference := binary.BigEndian.Uint64(reply[8:16]); reference != transmit {
			t.Fatalf("timing reply %d reference = 0x%016x, want 0x%016x", sequence, reference, transmit)
		}
	}

	waitForReceiverMediaStats(t, session, func(stats receiverMediaStats) bool {
		return stats.TimingProbes == 3 && stats.TimingReplies == 3
	})
	stats := session.Snapshot()
	if stats.TimingErrors != 0 {
		t.Fatalf("sender-initiated timing stats = %+v", stats)
	}
}

func TestReceiverMediaTimingResponderIgnoresReplies(t *testing.T) {
	session := newTestReceiverMediaSession(t, receiverMediaConfig{
		BindIP:          "127.0.0.1",
		TimingResponder: true,
	})
	sender, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP: net.ParseIP("127.0.0.1"), Port: session.Endpoints().TimingPort,
	})
	if err != nil {
		t.Fatalf("dial receiver timing: %v", err)
	}
	defer sender.Close()
	if err := sender.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("set timing deadline: %v", err)
	}
	reply := make([]byte, 32)
	reply[0], reply[1] = 0x80, 0xd3
	if _, err := sender.Write(reply); err != nil {
		t.Fatalf("write unsolicited timing reply: %v", err)
	}
	var unexpected [32]byte
	if _, err := sender.Read(unexpected[:]); err == nil {
		t.Fatal("receiver answered a timing reply and would create a loop")
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read after unsolicited timing reply: %v", err)
	}
	stats := session.Snapshot()
	if stats.TimingProbes != 0 || stats.TimingReplies != 0 || stats.TimingErrors != 0 {
		t.Fatalf("unsolicited timing reply changed counters: %+v", stats)
	}
}

func TestReceiverMediaSessionParentCancellationClosesActiveConnections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	session, err := newReceiverMediaSession(ctx, receiverMediaConfig{})
	if err != nil {
		t.Fatalf("create receiver media session: %v", err)
	}
	conn := dialReceiverMediaTCP(t, session.Endpoints().VideoPort)
	defer conn.Close()

	cancel()
	done := make(chan struct{})
	go func() {
		_ = session.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receiver media Close did not unblock active connection")
	}
	if err := session.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestReceiverMediaSessionValidatesConfiguration(t *testing.T) {
	for _, test := range []struct {
		name string
		ctx  context.Context
		cfg  receiverMediaConfig
	}{
		{name: "nil context", cfg: receiverMediaConfig{}},
		{name: "invalid IP", ctx: context.Background(), cfg: receiverMediaConfig{BindIP: "localhost"}},
		{name: "encrypted without secret", ctx: context.Background(), cfg: receiverMediaConfig{EventEncrypted: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			session, err := newReceiverMediaSession(test.ctx, test.cfg)
			if err == nil {
				_ = session.Close()
				t.Fatal("expected configuration error")
			}
		})
	}
}

func newTestReceiverMediaSession(t *testing.T, cfg receiverMediaConfig) *receiverMediaSession {
	t.Helper()
	session, err := newReceiverMediaSession(context.Background(), cfg)
	if err != nil {
		t.Fatalf("create receiver media session: %v", err)
	}
	t.Cleanup(func() {
		if err := session.Close(); err != nil {
			t.Errorf("close receiver media session: %v", err)
		}
	})
	return session
}

func newPipeReceiverMediaSession(t *testing.T, key, iv []byte) (*receiverMediaSession, net.Conn) {
	t.Helper()
	return newPipeReceiverMediaSessionWithCrypto(t, func(s *receiverMediaSession) error {
		return s.configureLegacyVideo(key, iv)
	})
}

func newPipeReceiverMediaSessionWithCrypto(t *testing.T, configure func(*receiverMediaSession) error) (*receiverMediaSession, net.Conn) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	session := &receiverMediaSession{
		ctx: ctx, connections: make(map[net.Conn]struct{}),
		maxVideoPayload: defaultReceiverMaxVideoPayload,
	}
	if err := configure(session); err != nil {
		t.Fatalf("configure video cipher: %v", err)
	}
	receiverConn, senderConn := net.Pipe()
	session.connections[receiverConn] = struct{}{}
	session.wg.Add(1)
	go session.drainVideo(receiverConn)
	return session, senderConn
}

func waitReceiverPipeSession(t *testing.T, session *receiverMediaSession) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		session.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("receiver video worker did not stop")
	}
}

func receiverTestAVCC(nals ...[]byte) []byte {
	var payload []byte
	for _, nal := range nals {
		var length [4]byte
		binary.BigEndian.PutUint32(length[:], uint32(len(nal)))
		payload = append(payload, length[:]...)
		payload = append(payload, nal...)
	}
	return payload
}

func dialReceiverMediaTCP(t *testing.T, port int) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", fmt.Sprint(port)), time.Second)
	if err != nil {
		t.Fatalf("dial receiver media port %d: %v", port, err)
	}
	return conn
}

func acknowledgeReceiverEventCommand(t *testing.T, port int, encrypted bool, secret []byte) net.Conn {
	t.Helper()
	conn, channel, request := readReceiverEventCommand(t, port, encrypted, secret)
	response := fmt.Sprintf("RTSP/1.0 200 OK\r\nCSeq: %s\r\nContent-Length: 0\r\n\r\n", request.headers["cseq"])
	if _, err := channel.Write([]byte(response)); err != nil {
		conn.Close()
		t.Fatalf("write event response: %v", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		conn.Close()
		t.Fatalf("clear event deadline: %v", err)
	}
	return conn
}

func readReceiverEventCommand(t *testing.T, port int, encrypted bool, secret []byte) (net.Conn, *eventChannel, rtspTestRequest) {
	t.Helper()
	conn := dialReceiverMediaTCP(t, port)
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		conn.Close()
		t.Fatalf("set event deadline: %v", err)
	}
	channel, err := newEventChannel(conn, encrypted, secret)
	if err != nil {
		conn.Close()
		t.Fatalf("create sender event channel: %v", err)
	}
	request, err := readRTSPTestRequest(bufio.NewReader(channel))
	if err != nil {
		conn.Close()
		t.Fatalf("read receiver event command: %v", err)
	}
	if request.method != "POST" || request.uri != "/command" {
		conn.Close()
		t.Fatalf("event command = %s %s, want POST /command", request.method, request.uri)
	}
	if request.headers["cseq"] != fmt.Sprint(receiverEventCommandCSeq) {
		conn.Close()
		t.Fatalf("event command CSeq = %q, want %d", request.headers["cseq"], receiverEventCommandCSeq)
	}
	if request.headers["content-type"] != "application/x-apple-binary-plist" {
		conn.Close()
		t.Fatalf("event command Content-Type = %q", request.headers["content-type"])
	}
	var command map[string]any
	if _, err := plist.Unmarshal(request.body, &command); err != nil {
		conn.Close()
		t.Fatalf("decode event command plist: %v", err)
	}
	if command["type"] != "forceKeyFrame" {
		conn.Close()
		t.Fatalf("event command plist = %#v", command)
	}
	return conn, channel, request
}

func sendReceiverMediaUDP(t *testing.T, port int, payload []byte) {
	t.Helper()
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		t.Fatalf("dial receiver UDP port %d: %v", port, err)
	}
	defer conn.Close()
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write receiver UDP port %d: %v", port, err)
	}
}

func writeReceiverMirrorPacket(t *testing.T, conn net.Conn, packetType, flags byte, payload []byte) {
	t.Helper()
	var header [receiverMirrorHeaderSize]byte
	binary.LittleEndian.PutUint32(header[0:4], uint32(len(payload)))
	header[4], header[5] = packetType, flags
	if err := writeAll(conn, header[:]); err != nil {
		t.Fatalf("write mirror header: %v", err)
	}
	if err := writeAll(conn, payload); err != nil {
		t.Fatalf("write mirror payload: %v", err)
	}
}

func waitForReceiverMediaStats(t *testing.T, session *receiverMediaSession, ready func(receiverMediaStats) bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		stats := session.Snapshot()
		if ready(stats) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for receiver media stats; last snapshot: %+v", stats)
		}
		time.Sleep(time.Millisecond)
	}
}
