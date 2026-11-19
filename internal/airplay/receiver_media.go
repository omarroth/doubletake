package airplay

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"howett.net/plist"
)

const (
	receiverMirrorHeaderSize       = 128
	defaultReceiverMaxVideoPayload = 32 * 1024 * 1024
	receiverTimingReplyTimeout     = time.Second
	receiverEventCommandCSeq       = 1
)

// receiverMediaConfig configures the media-side listeners advertised by a
// receiver RTSP server. BindIP must be an IPv4 or IPv6 literal. An empty value
// uses IPv4 loopback so tests never accidentally expose listeners on the LAN.
type receiverMediaConfig struct {
	BindIP            string
	EventEncrypted    bool
	EventSharedSecret []byte
	TimingResponder   bool
	MaxVideoPayload   uint32
	Playback          *receiverPlaybackConfig
}

// receiverMediaEndpoints are the receiver-owned ports returned in SETUP
// responses. All listeners bind to the IP supplied in receiverMediaConfig.
type receiverMediaEndpoints struct {
	EventPort     int
	VideoPort     int
	AudioRTPPort  int
	AudioRTCPPort int
	TimingPort    int
}

// receiverMediaStats is a point-in-time copy of the traffic observed by a
// receiverMediaSession. EventRequests are receiver-to-sender commands and
// EventResponses are their sender acknowledgements. VideoBytes includes each
// packet's 128-byte header; VideoPayloadBytes counts only bytes after headers.
type receiverMediaStats struct {
	EventConnections uint64
	EventRequests    uint64
	EventResponses   uint64
	EventErrors      uint64

	VideoConnections  uint64
	VideoBytes        uint64
	VideoPayloadBytes uint64
	VideoPackets      uint64
	VideoCodecFrames  uint64
	VideoFrames       uint64
	VideoKeyFrames    uint64
	VideoHeartbeats   uint64
	VideoDecrypted    uint64
	VideoCryptoErrors uint64
	VideoMalformed    uint64
	VideoWidth        uint64
	VideoHeight       uint64

	AudioRTPPackets  uint64
	AudioRTPBytes    uint64
	AudioRTCPPackets uint64
	AudioRTCPBytes   uint64
	AudioPackets     uint64
	AudioBytes       uint64

	TimingProbes  uint64
	TimingReplies uint64
	TimingErrors  uint64
	Playback      ReceiverPlaybackStats
}

// add accumulates another media snapshot. The receiver server uses this to
// combine closed sessions with snapshots of sessions that are still active.
func (s *receiverMediaStats) add(other receiverMediaStats) {
	s.EventConnections += other.EventConnections
	s.EventRequests += other.EventRequests
	s.EventResponses += other.EventResponses
	s.EventErrors += other.EventErrors
	s.VideoConnections += other.VideoConnections
	s.VideoBytes += other.VideoBytes
	s.VideoPayloadBytes += other.VideoPayloadBytes
	s.VideoPackets += other.VideoPackets
	s.VideoCodecFrames += other.VideoCodecFrames
	s.VideoFrames += other.VideoFrames
	s.VideoKeyFrames += other.VideoKeyFrames
	s.VideoHeartbeats += other.VideoHeartbeats
	s.VideoDecrypted += other.VideoDecrypted
	s.VideoCryptoErrors += other.VideoCryptoErrors
	s.VideoMalformed += other.VideoMalformed
	if other.VideoWidth > s.VideoWidth {
		s.VideoWidth = other.VideoWidth
	}
	if other.VideoHeight > s.VideoHeight {
		s.VideoHeight = other.VideoHeight
	}
	s.AudioRTPPackets += other.AudioRTPPackets
	s.AudioRTPBytes += other.AudioRTPBytes
	s.AudioRTCPPackets += other.AudioRTCPPackets
	s.AudioRTCPBytes += other.AudioRTCPBytes
	s.AudioPackets += other.AudioPackets
	s.AudioBytes += other.AudioBytes
	s.TimingProbes += other.TimingProbes
	s.TimingReplies += other.TimingReplies
	s.TimingErrors += other.TimingErrors
	s.Playback.add(other.Playback)
}

type receiverMediaCounters struct {
	eventConnections atomic.Uint64
	eventRequests    atomic.Uint64
	eventResponses   atomic.Uint64
	eventErrors      atomic.Uint64

	videoConnections  atomic.Uint64
	videoBytes        atomic.Uint64
	videoPayloadBytes atomic.Uint64
	videoPackets      atomic.Uint64
	videoCodecFrames  atomic.Uint64
	videoFrames       atomic.Uint64
	videoKeyFrames    atomic.Uint64
	videoHeartbeats   atomic.Uint64
	videoDecrypted    atomic.Uint64
	videoCryptoErrors atomic.Uint64
	videoMalformed    atomic.Uint64
	videoWidth        atomic.Uint64
	videoHeight       atomic.Uint64

	audioRTPPackets  atomic.Uint64
	audioRTPBytes    atomic.Uint64
	audioRTCPPackets atomic.Uint64
	audioRTCPBytes   atomic.Uint64

	timingProbes  atomic.Uint64
	timingReplies atomic.Uint64
	timingErrors  atomic.Uint64
}

// receiverMediaSession owns the media listeners used by one receiver session.
// It validates and accounts for traffic, optionally decoding it for headless
// presentation checks.
// Configured video cryptors independently check legacy AES access units or
// modern ChaCha authentication rather than counting opaque ciphertext as valid.
type receiverMediaSession struct {
	ctx    context.Context
	cancel context.CancelFunc

	eventListener net.Listener
	videoListener net.Listener
	audioRTPConn  *net.UDPConn
	audioRTCPConn *net.UDPConn
	timingConn    *net.UDPConn

	endpoints       receiverMediaEndpoints
	eventEncrypted  bool
	eventSecret     []byte
	maxVideoPayload uint32
	videoCryptoMu   sync.RWMutex
	legacyVideoKey  [16]byte
	legacyVideoIV   [16]byte
	legacyVideoSet  bool
	videoAEAD       cipher.AEAD
	playback        *receiverPlayback

	connectionsMu sync.Mutex
	connections   map[net.Conn]struct{}
	timingMu      sync.Mutex
	wg            sync.WaitGroup
	closeOnce     sync.Once
	counters      receiverMediaCounters
}

// newReceiverMediaSession binds all receiver-side media endpoints to ephemeral
// ports and starts their drain loops. Cancelling parent has the same effect as
// calling Close.
func newReceiverMediaSession(parent context.Context, cfg receiverMediaConfig) (*receiverMediaSession, error) {
	if parent == nil {
		return nil, fmt.Errorf("receiver media parent context is nil")
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	if cfg.EventEncrypted && len(cfg.EventSharedSecret) == 0 {
		return nil, fmt.Errorf("encrypted receiver event channel has no shared secret")
	}

	bindIP := cfg.BindIP
	if bindIP == "" {
		bindIP = "127.0.0.1"
	}
	ip := net.ParseIP(bindIP)
	if ip == nil {
		return nil, fmt.Errorf("invalid receiver media bind IP %q", bindIP)
	}

	tcpNetwork, udpNetwork := "tcp6", "udp6"
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
		tcpNetwork, udpNetwork = "tcp4", "udp4"
	}

	listenTCP := func() (net.Listener, error) {
		return net.Listen(tcpNetwork, net.JoinHostPort(ip.String(), "0"))
	}
	listenUDP := func() (*net.UDPConn, error) {
		return net.ListenUDP(udpNetwork, &net.UDPAddr{IP: ip, Port: 0})
	}

	eventListener, err := listenTCP()
	if err != nil {
		return nil, fmt.Errorf("listen receiver event channel: %w", err)
	}
	closeOnError := []io.Closer{eventListener}
	cleanup := func() {
		for _, closer := range closeOnError {
			_ = closer.Close()
		}
	}

	videoListener, err := listenTCP()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("listen receiver video channel: %w", err)
	}
	closeOnError = append(closeOnError, videoListener)
	audioRTPConn, err := listenUDP()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("listen receiver audio RTP: %w", err)
	}
	closeOnError = append(closeOnError, audioRTPConn)
	audioRTCPConn, err := listenUDP()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("listen receiver audio RTCP: %w", err)
	}
	closeOnError = append(closeOnError, audioRTCPConn)
	timingConn, err := listenUDP()
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("listen receiver legacy timing: %w", err)
	}
	closeOnError = append(closeOnError, timingConn)

	maxVideoPayload := cfg.MaxVideoPayload
	if maxVideoPayload == 0 {
		maxVideoPayload = defaultReceiverMaxVideoPayload
	}
	ctx, cancel := context.WithCancel(parent)
	s := &receiverMediaSession{
		ctx:             ctx,
		cancel:          cancel,
		eventListener:   eventListener,
		videoListener:   videoListener,
		audioRTPConn:    audioRTPConn,
		audioRTCPConn:   audioRTCPConn,
		timingConn:      timingConn,
		eventEncrypted:  cfg.EventEncrypted,
		eventSecret:     append([]byte(nil), cfg.EventSharedSecret...),
		maxVideoPayload: maxVideoPayload,
		connections:     make(map[net.Conn]struct{}),
		endpoints: receiverMediaEndpoints{
			EventPort:     eventListener.Addr().(*net.TCPAddr).Port,
			VideoPort:     videoListener.Addr().(*net.TCPAddr).Port,
			AudioRTPPort:  audioRTPConn.LocalAddr().(*net.UDPAddr).Port,
			AudioRTCPPort: audioRTCPConn.LocalAddr().(*net.UDPAddr).Port,
			TimingPort:    timingConn.LocalAddr().(*net.UDPAddr).Port,
		},
	}
	if cfg.Playback != nil {
		s.playback, err = newReceiverPlayback(*cfg.Playback)
		if err != nil {
			cancel()
			cleanup()
			return nil, err
		}
	}

	workers := 4
	if cfg.TimingResponder {
		workers++
	}
	s.wg.Add(workers)
	go s.acceptEvents()
	go s.acceptVideo()
	go s.drainUDP(audioRTPConn, &s.counters.audioRTPPackets, &s.counters.audioRTPBytes)
	go s.drainUDP(audioRTCPConn, &s.counters.audioRTCPPackets, &s.counters.audioRTCPBytes)
	if cfg.TimingResponder {
		go s.respondLegacyTiming()
	}
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	return s, nil
}

func (s *receiverMediaSession) Endpoints() receiverMediaEndpoints {
	if s == nil {
		return receiverMediaEndpoints{}
	}
	return s.endpoints
}

func (s *receiverMediaSession) Snapshot() receiverMediaStats {
	if s == nil {
		return receiverMediaStats{}
	}
	c := &s.counters
	audioRTPPackets := c.audioRTPPackets.Load()
	audioRTPBytes := c.audioRTPBytes.Load()
	audioRTCPPackets := c.audioRTCPPackets.Load()
	audioRTCPBytes := c.audioRTCPBytes.Load()
	snapshot := receiverMediaStats{
		EventConnections:  c.eventConnections.Load(),
		EventRequests:     c.eventRequests.Load(),
		EventResponses:    c.eventResponses.Load(),
		EventErrors:       c.eventErrors.Load(),
		VideoConnections:  c.videoConnections.Load(),
		VideoBytes:        c.videoBytes.Load(),
		VideoPayloadBytes: c.videoPayloadBytes.Load(),
		VideoPackets:      c.videoPackets.Load(),
		VideoCodecFrames:  c.videoCodecFrames.Load(),
		VideoFrames:       c.videoFrames.Load(),
		VideoKeyFrames:    c.videoKeyFrames.Load(),
		VideoHeartbeats:   c.videoHeartbeats.Load(),
		VideoDecrypted:    c.videoDecrypted.Load(),
		VideoCryptoErrors: c.videoCryptoErrors.Load(),
		VideoMalformed:    c.videoMalformed.Load(),
		VideoWidth:        c.videoWidth.Load(),
		VideoHeight:       c.videoHeight.Load(),
		AudioRTPPackets:   audioRTPPackets,
		AudioRTPBytes:     audioRTPBytes,
		AudioRTCPPackets:  audioRTCPPackets,
		AudioRTCPBytes:    audioRTCPBytes,
		AudioPackets:      audioRTPPackets + audioRTCPPackets,
		AudioBytes:        audioRTPBytes + audioRTCPBytes,
		TimingProbes:      c.timingProbes.Load(),
		TimingReplies:     c.timingReplies.Load(),
		TimingErrors:      c.timingErrors.Load(),
	}
	if s.playback != nil {
		snapshot.Playback = s.playback.snapshot()
	}
	return snapshot
}

func (s *receiverMediaSession) acceptEvents() {
	defer s.wg.Done()
	for {
		conn, err := s.eventListener.Accept()
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				dbg("[RECEIVER-EVENT] accept failed: %v", err)
			}
			return
		}
		if !s.trackConnection(conn) {
			_ = conn.Close()
			return
		}
		s.counters.eventConnections.Add(1)
		s.wg.Add(1)
		go s.serveEventConnection(conn)
	}
}

func (s *receiverMediaSession) serveEventConnection(conn net.Conn) {
	defer s.wg.Done()
	defer s.untrackConnection(conn)
	defer conn.Close()

	channel, err := newReceiverEventChannel(conn, s.eventEncrypted, s.eventSecret)
	if err != nil {
		s.counters.eventErrors.Add(1)
		dbg("[RECEIVER-EVENT] initialize channel: %v", err)
		return
	}
	request, err := receiverForceKeyFrameRequest(receiverEventCommandCSeq)
	if err != nil {
		s.counters.eventErrors.Add(1)
		dbg("[RECEIVER-EVENT] encode force-key-frame request: %v", err)
		return
	}
	if _, err := channel.Write(request); err != nil {
		if !receiverMediaClosed(s.ctx, err) {
			s.counters.eventErrors.Add(1)
			dbg("[RECEIVER-EVENT] write force-key-frame request: %v", err)
		}
		return
	}
	s.counters.eventRequests.Add(1)

	reader := bufio.NewReaderSize(channel, 4096)
	if err := readReceiverEventResponse(reader, receiverEventCommandCSeq); err != nil {
		if !receiverMediaClosed(s.ctx, err) {
			s.counters.eventErrors.Add(1)
			dbg("[RECEIVER-EVENT] read force-key-frame response: %v", err)
		}
		return
	}
	s.counters.eventResponses.Add(1)

	// Keep the persistent event connection open until the sender or session
	// closes it. Drain any future traffic without retaining unbounded data.
	if _, err := io.Copy(io.Discard, reader); err != nil && !receiverMediaClosed(s.ctx, err) {
		s.counters.eventErrors.Add(1)
		dbg("[RECEIVER-EVENT] drain channel: %v", err)
	}
}

func receiverForceKeyFrameRequest(cseq uint64) ([]byte, error) {
	body, err := plist.Marshal(map[string]any{"type": "forceKeyFrame"}, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}
	header := fmt.Sprintf("POST /command RTSP/1.0\r\nCSeq: %d\r\nContent-Type: application/x-apple-binary-plist\r\nContent-Length: %d\r\n\r\n", cseq, len(body))
	return append([]byte(header), body...), nil
}

// readReceiverEventResponse validates one bounded RTSP acknowledgement from
// the sender and consumes its optional response body.
func readReceiverEventResponse(reader *bufio.Reader, wantCSeq uint64) error {
	statusLine, used, err := readEventLine(reader, eventHeaderSizeLimit)
	if err != nil {
		return err
	}
	parts := strings.Fields(statusLine)
	if len(parts) < 2 || parts[0] != "RTSP/1.0" {
		return fmt.Errorf("invalid event response line %q", statusLine)
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status != 200 {
		return fmt.Errorf("event response status is %q, want 200", parts[1])
	}

	var cseq uint64
	contentLength := 0
	hasCSeq, hasContentLength := false, false
	for {
		line, size, err := readEventLine(reader, eventHeaderSizeLimit-used)
		if err != nil {
			return err
		}
		used += size
		if line == "" {
			break
		}
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			return fmt.Errorf("invalid event response header %q", line)
		}
		name = strings.ToLower(strings.TrimSpace(name))
		value = strings.TrimSpace(value)
		switch name {
		case "cseq":
			if hasCSeq {
				return fmt.Errorf("duplicate event response CSeq")
			}
			cseq, err = strconv.ParseUint(value, 10, 64)
			if err != nil {
				return fmt.Errorf("invalid event response CSeq %q", value)
			}
			hasCSeq = true
		case "content-length":
			if hasContentLength {
				return fmt.Errorf("duplicate event response Content-Length")
			}
			contentLength, err = strconv.Atoi(value)
			if err != nil || contentLength < 0 || contentLength > eventBodySizeLimit {
				return fmt.Errorf("invalid event response Content-Length %q", value)
			}
			hasContentLength = true
		}
	}
	if !hasCSeq {
		return fmt.Errorf("event response omitted CSeq")
	}
	if cseq != wantCSeq {
		return fmt.Errorf("event response CSeq is %d, want %d", cseq, wantCSeq)
	}
	if _, err := io.CopyN(io.Discard, reader, int64(contentLength)); err != nil {
		return fmt.Errorf("read event response body: %w", err)
	}
	return nil
}

// newReceiverEventChannel reverses the sender-side event key direction. The
// receiver reads bytes written with Events-Read and writes bytes the sender
// reads with Events-Write.
func newReceiverEventChannel(conn net.Conn, encrypted bool, sharedSecret []byte) (*eventChannel, error) {
	if conn == nil {
		return nil, fmt.Errorf("receiver event connection is nil")
	}
	channel := &eventChannel{conn: conn}
	if !encrypted {
		return channel, nil
	}
	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("encrypted receiver event channel has no shared secret")
	}

	readKey := hkdfSHA512(sharedSecret, []byte("Events-Salt"), []byte("Events-Read-Encryption-Key"), chacha20poly1305.KeySize)
	writeKey := hkdfSHA512(sharedSecret, []byte("Events-Salt"), []byte("Events-Write-Encryption-Key"), chacha20poly1305.KeySize)
	newCipher := func(key []byte) (cipher.AEAD, error) {
		return chacha20poly1305.New(key)
	}
	var err error
	channel.readCipher, err = newCipher(readKey)
	if err != nil {
		return nil, fmt.Errorf("create receiver event read cipher: %w", err)
	}
	channel.writeCipher, err = newCipher(writeKey)
	if err != nil {
		return nil, fmt.Errorf("create receiver event write cipher: %w", err)
	}
	return channel, nil
}

func (s *receiverMediaSession) acceptVideo() {
	defer s.wg.Done()
	for {
		conn, err := s.videoListener.Accept()
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				dbg("[RECEIVER-VIDEO] accept failed: %v", err)
			}
			return
		}
		if !s.trackConnection(conn) {
			_ = conn.Close()
			return
		}
		s.counters.videoConnections.Add(1)
		s.wg.Add(1)
		go s.drainVideo(conn)
	}
}

func (s *receiverMediaSession) drainVideo(conn net.Conn) {
	defer s.wg.Done()
	defer s.untrackConnection(conn)
	defer conn.Close()

	videoCipher, videoAEAD, err := s.newVideoCiphers()
	if err != nil {
		s.counters.videoCryptoErrors.Add(1)
		dbg("[RECEIVER-VIDEO] initialize cipher: %v", err)
		return
	}

	header := make([]byte, receiverMirrorHeaderSize)
	var videoNonce uint64
	for {
		if _, err := io.ReadFull(conn, header); err != nil {
			if errors.Is(err, io.ErrUnexpectedEOF) {
				s.counters.videoMalformed.Add(1)
			}
			if !receiverMediaClosed(s.ctx, err) {
				dbg("[RECEIVER-VIDEO] read header: %v", err)
			}
			return
		}
		s.counters.videoBytes.Add(receiverMirrorHeaderSize)

		payloadSize := binary.LittleEndian.Uint32(header[0:4])
		if payloadSize > s.maxVideoPayload {
			s.counters.videoMalformed.Add(1)
			dbg("[RECEIVER-VIDEO] payload %d exceeds limit %d", payloadSize, s.maxVideoPayload)
			return
		}
		var payload []byte
		if payloadSize > 0 {
			if s.playback != nil || (videoCipher != nil || videoAEAD != nil) && header[4] == 0x00 {
				payload = make([]byte, payloadSize)
				n, err := io.ReadFull(conn, payload)
				s.counters.videoBytes.Add(uint64(n))
				s.counters.videoPayloadBytes.Add(uint64(n))
				if err != nil {
					if !receiverMediaClosed(s.ctx, err) {
						s.counters.videoMalformed.Add(1)
						dbg("[RECEIVER-VIDEO] read payload: %v", err)
					}
					return
				}
			} else {
				n, err := io.CopyN(io.Discard, conn, int64(payloadSize))
				s.counters.videoBytes.Add(uint64(n))
				s.counters.videoPayloadBytes.Add(uint64(n))
				if err != nil {
					if !receiverMediaClosed(s.ctx, err) {
						s.counters.videoMalformed.Add(1)
						dbg("[RECEIVER-VIDEO] read payload: %v", err)
					}
					return
				}
			}
		}

		s.counters.videoPackets.Add(1)
		switch header[4] {
		case 0x00:
			s.counters.videoFrames.Add(1)
			keyframe := header[5]&0x10 != 0
			if keyframe {
				s.counters.videoKeyFrames.Add(1)
			}
			if videoCipher != nil {
				plain := make([]byte, len(payload))
				videoCipher.XORKeyStream(plain, payload)
				if err := validateReceiverAVCCFrame(plain, keyframe); err != nil {
					s.counters.videoCryptoErrors.Add(1)
					s.counters.videoMalformed.Add(1)
					dbg("[RECEIVER-VIDEO] legacy frame decryption failed validation: %v", err)
					return
				}
				s.counters.videoDecrypted.Add(1)
				payload = plain
			}
			if videoAEAD != nil {
				var nonce [12]byte
				binary.LittleEndian.PutUint64(nonce[4:], videoNonce)
				plain, err := videoAEAD.Open(payload[:0], nonce[:], payload, header)
				if err != nil {
					s.counters.videoCryptoErrors.Add(1)
					s.counters.videoMalformed.Add(1)
					dbg("[RECEIVER-VIDEO] frame authentication failed: %v", err)
					return
				}
				videoNonce++
				s.counters.videoDecrypted.Add(1)
				payload = plain
			}
			if s.playback != nil {
				if err := s.playback.videoFrame(payload, binary.LittleEndian.Uint64(header[8:16]), binary.LittleEndian.Uint64(header[40:48])); err != nil {
					s.playback.fail(err)
					return
				}
			}
		case 0x01:
			s.counters.videoCodecFrames.Add(1)
			if s.playback != nil {
				if err := s.playback.configureVideo(payload); err != nil {
					return
				}
			}
			width := math.Float32frombits(binary.LittleEndian.Uint32(header[16:20]))
			height := math.Float32frombits(binary.LittleEndian.Uint32(header[20:24]))
			if width > 0 && height > 0 && width <= 16384 && height <= 16384 {
				storeReceiverMaximum(&s.counters.videoWidth, uint64(width))
				storeReceiverMaximum(&s.counters.videoHeight, uint64(height))
			}
		case 0x02:
			s.counters.videoHeartbeats.Add(1)
		}
	}
}

func storeReceiverMaximum(counter *atomic.Uint64, value uint64) {
	for current := counter.Load(); value > current; current = counter.Load() {
		if counter.CompareAndSwap(current, value) {
			return
		}
	}
}

// configureLegacyVideo installs a receiver-side AES-CTR key. A fresh stream is
// created for each accepted TCP connection; only encrypted VCL packets advance
// it because codec configuration and heartbeat packets are plaintext.
func (s *receiverMediaSession) configureLegacyVideo(key, iv []byte) error {
	if len(key) != 16 || len(iv) != 16 {
		return fmt.Errorf("legacy video cipher requires a 16-byte key and IV")
	}
	s.videoCryptoMu.Lock()
	copy(s.legacyVideoKey[:], key)
	copy(s.legacyVideoIV[:], iv)
	s.legacyVideoSet = true
	s.videoAEAD = nil
	s.videoCryptoMu.Unlock()
	return nil
}

func (s *receiverMediaSession) configureChaChaVideo(key []byte) error {
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return fmt.Errorf("create receiver video AEAD: %w", err)
	}
	s.videoCryptoMu.Lock()
	s.videoAEAD = aead
	s.legacyVideoSet = false
	s.videoCryptoMu.Unlock()
	return nil
}

func (s *receiverMediaSession) newVideoCiphers() (cipher.Stream, cipher.AEAD, error) {
	s.videoCryptoMu.RLock()
	configured := s.legacyVideoSet
	key, iv := s.legacyVideoKey, s.legacyVideoIV
	aead := s.videoAEAD
	s.videoCryptoMu.RUnlock()
	if !configured {
		return nil, aead, nil
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}
	// Use Go's continuous CTR stream instead of the sender's frame cipher.
	// This independently checks that partial-block keystream survives frames.
	return cipher.NewCTR(block, iv[:]), nil, nil
}

// validateReceiverAVCCFrame validates the decrypted VCL access unit. Legacy
// AES-CTR has no per-frame tag, so authenticated FairPlay key setup plus this
// strict AVCC/NAL check is what makes wrong-key or corrupted frames observable
// in the diagnostic receiver instead of counting opaque ciphertext as success.
func validateReceiverAVCCFrame(payload []byte, keyframe bool) error {
	if len(payload) == 0 {
		return fmt.Errorf("empty AVCC access unit")
	}
	sawIDR := false
	nalCount := 0
	for len(payload) > 0 {
		if len(payload) < 4 {
			return fmt.Errorf("truncated AVCC NAL length")
		}
		nalLength := uint64(binary.BigEndian.Uint32(payload[:4]))
		payload = payload[4:]
		if nalLength == 0 || nalLength > uint64(len(payload)) {
			return fmt.Errorf("invalid AVCC NAL length %d with %d bytes remaining", nalLength, len(payload))
		}
		nal := payload[:int(nalLength)]
		payload = payload[int(nalLength):]
		if nal[0]&0x80 != 0 {
			return fmt.Errorf("H.264 forbidden_zero_bit is set")
		}
		nalType := nal[0] & 0x1f
		if nalType == 6 || nalType == 9 || nalType == 12 {
			// SEI, AUD and filler can accompany a coded picture. They neither
			// establish its presence nor change the IDR flag.
			continue
		}
		if nalType < 1 || nalType > 5 {
			return fmt.Errorf("unexpected picture NAL type %d", nalType)
		}
		if nalType == 5 {
			sawIDR = true
		}
		nalCount++
	}
	if keyframe != sawIDR {
		return fmt.Errorf("keyframe flag is %t but decrypted access unit IDR is %t", keyframe, sawIDR)
	}
	if nalCount == 0 {
		return fmt.Errorf("AVCC access unit contains no coded picture")
	}
	return nil
}

func (s *receiverMediaSession) drainUDP(conn *net.UDPConn, packets, bytes *atomic.Uint64) {
	defer s.wg.Done()
	buffer := make([]byte, 64*1024)
	for {
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				dbg("[RECEIVER-AUDIO] read failed: %v", err)
			}
			return
		}
		packets.Add(1)
		bytes.Add(uint64(n))
		if s.playback != nil {
			if conn == s.audioRTPConn {
				s.playback.audioPacket(buffer[:n], false)
			} else {
				s.playback.audioControl(buffer[:n])
			}
		}
	}
}

// respondLegacyTiming implements the inverse NTP role used by AirServer-style
// receivers. The receiver advertises TimingPort and waits for the sender to
// initiate three 0xd2 probes instead of probing the sender's timingPort.
func (s *receiverMediaSession) respondLegacyTiming() {
	defer s.wg.Done()
	var request [32]byte
	for {
		n, from, err := s.timingConn.ReadFromUDP(request[:])
		if err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.counters.timingErrors.Add(1)
				dbg("[RECEIVER-TIMING] read failed: %v", err)
			}
			return
		}
		if n != len(request) || request[0] != 0x80 || request[1] != 0xd2 {
			// A 0xd3 packet is a response to a receiver-originated probe. Ignore it
			// rather than replying and creating a timing response loop.
			if n >= 2 && request[0] == 0x80 && request[1] == 0xd3 {
				continue
			}
			s.counters.timingErrors.Add(1)
			continue
		}
		s.counters.timingProbes.Add(1)

		reply := request
		reply[0], reply[1] = 0x80, 0xd3
		copy(reply[8:16], request[24:32])
		now := ntpBootTimestamp()
		binary.BigEndian.PutUint64(reply[16:24], now)
		binary.BigEndian.PutUint64(reply[24:32], now)
		if _, err := s.timingConn.WriteToUDP(reply[:], from); err != nil {
			if s.ctx.Err() == nil && !errors.Is(err, net.ErrClosed) {
				s.counters.timingErrors.Add(1)
				dbg("[RECEIVER-TIMING] reply failed: %v", err)
			}
			return
		}
		s.counters.timingReplies.Add(1)
	}
}

// ProbeLegacyTiming sends count AirPlay 32-byte NTP probes from TimingPort to
// the timing port advertised by a legacy sender, validating each reply before
// proceeding to the next probe.
func (s *receiverMediaSession) ProbeLegacyTiming(ctx context.Context, sender *net.UDPAddr, count int) (err error) {
	if s == nil {
		return fmt.Errorf("receiver media session is nil")
	}
	if ctx == nil {
		return fmt.Errorf("legacy timing context is nil")
	}
	if sender == nil || sender.IP == nil || sender.Port < 1 || sender.Port > 65535 {
		return fmt.Errorf("invalid sender timing address %v", sender)
	}
	if count < 1 {
		return fmt.Errorf("legacy timing probe count must be positive")
	}

	s.timingMu.Lock()
	defer s.timingMu.Unlock()
	defer func() {
		_ = s.timingConn.SetDeadline(time.Time{})
		if err != nil {
			s.counters.timingErrors.Add(1)
		}
	}()

	for sequence := 1; sequence <= count; sequence++ {
		if err := contextError(ctx, s.ctx); err != nil {
			return err
		}

		request := make([]byte, 32)
		request[0], request[1] = 0x80, 0xd2
		binary.BigEndian.PutUint16(request[2:4], uint16(sequence))
		transmit := ntpBootTimestamp()
		binary.BigEndian.PutUint64(request[24:32], transmit)

		deadline := time.Now().Add(receiverTimingReplyTimeout)
		if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
			deadline = ctxDeadline
		}
		if err := s.timingConn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set legacy timing deadline: %w", err)
		}
		if _, err := s.timingConn.WriteToUDP(request, sender); err != nil {
			if contextErr := contextError(ctx, s.ctx); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf("send legacy timing probe %d: %w", sequence, err)
		}
		s.counters.timingProbes.Add(1)

		var reply [32]byte
		n, from, err := s.timingConn.ReadFromUDP(reply[:])
		if err != nil {
			if contextErr := contextError(ctx, s.ctx); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf("read legacy timing reply %d: %w", sequence, err)
		}
		if !from.IP.Equal(sender.IP) || from.Port != sender.Port {
			return fmt.Errorf("legacy timing reply %d came from %s, want %s", sequence, from, sender)
		}
		if n != len(reply) {
			return fmt.Errorf("legacy timing reply %d is %d bytes, want %d", sequence, n, len(reply))
		}
		if reply[0] != 0x80 || reply[1] != 0xd3 {
			return fmt.Errorf("legacy timing reply %d type is %02x%02x, want 80d3", sequence, reply[0], reply[1])
		}
		if reference := binary.BigEndian.Uint64(reply[8:16]); reference != transmit {
			return fmt.Errorf("legacy timing reply %d reference is 0x%016x, want 0x%016x", sequence, reference, transmit)
		}
		if s.playback != nil && s.playback.cfg.Timing != timingProtocolPTP {
			// Four-timestamp NTP offset, independent of packet receive jitter.
			t1 := receiverCompactDuration(transmit - (uint64(secondsFrom1900To1970) << 32))
			t2 := receiverCompactDuration(binary.BigEndian.Uint64(reply[16:24]) - (uint64(secondsFrom1900To1970) << 32))
			t3 := receiverCompactDuration(binary.BigEndian.Uint64(reply[24:32]) - (uint64(secondsFrom1900To1970) << 32))
			t4 := bootRelativeNow()
			s.playback.ntpOffset.Store(int64(((t2 - t1) + (t3 - t4)) / 2))
		}
		s.counters.timingReplies.Add(1)
	}
	return nil
}

func contextError(contexts ...context.Context) error {
	for _, ctx := range contexts {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

func (s *receiverMediaSession) trackConnection(conn net.Conn) bool {
	s.connectionsMu.Lock()
	defer s.connectionsMu.Unlock()
	if s.ctx.Err() != nil {
		return false
	}
	s.connections[conn] = struct{}{}
	return true
}

func (s *receiverMediaSession) untrackConnection(conn net.Conn) {
	s.connectionsMu.Lock()
	delete(s.connections, conn)
	s.connectionsMu.Unlock()
}

func receiverMediaClosed(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF)
}

// Close stops all listeners and active connections, then waits for every media
// worker to exit. It is safe to call concurrently and more than once.
func (s *receiverMediaSession) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		s.cancel()
		_ = s.eventListener.Close()
		_ = s.videoListener.Close()
		_ = s.audioRTPConn.Close()
		_ = s.audioRTCPConn.Close()
		_ = s.timingConn.Close()

		s.connectionsMu.Lock()
		for conn := range s.connections {
			_ = conn.Close()
		}
		s.connectionsMu.Unlock()
		s.wg.Wait()
		if s.playback != nil {
			s.playback.Close()
		}
	})
	return nil
}
