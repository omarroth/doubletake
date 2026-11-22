package airplay

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// DefaultRAOPPlayoutLatency is the media-audio lead. Screen mirroring has a
// separate low-latency budget.
const DefaultRAOPPlayoutLatency = 2 * time.Second

// AudioOnlyConfig controls a direct audio session.
type AudioOnlyConfig struct {
	Password         string
	PortMin, PortMax int
	PlayoutLatency   time.Duration // zero uses the application override or media-audio default
	ptpPool          *ptpClockPool
}

// AudioOnlySession holds the control and media channels for direct audio.
type AudioOnlySession struct {
	client   *AirPlayClient
	stream   *AudioStream
	timing   net.PacketConn
	event    net.Conn
	airPlay2 bool
	uri      string
	headers  map[string]string
	playback audioPlayback

	stopTiming     context.CancelFunc
	releaseClock   func()
	timingDone     <-chan struct{}
	closeOnce      sync.Once
	closeErr       error
	mu             sync.Mutex
	restore        *float64
	matchedVolume  float64
	volumeMatched  bool
	canMatchVolume bool
	rtspTimeout    time.Duration
}

// OpenRAOP negotiates ALAC and the advertised classic UDP transport.
func OpenRAOP(ctx context.Context, device AirPlayDevice, cfg AudioOnlyConfig) (*AudioOnlySession, error) {
	ctx, cancelSetup := context.WithTimeout(ctx, 15*time.Second)
	defer cancelSetup()
	if device.RAOP == nil {
		return nil, errors.New("receiver has no advertised RAOP endpoint")
	}
	txt := device.RAOP.TXT
	codecs := txt["cn"]
	if codecs != "" && !raopTXTContains(codecs, "1") {
		return nil, fmt.Errorf("RAOP receiver does not advertise Apple Lossless (cn=%q)", codecs)
	}
	if transport := txt["tp"]; transport != "" && !raopTXTContains(transport, "UDP") {
		return nil, fmt.Errorf("RAOP receiver does not advertise UDP transport (tp=%q)", transport)
	}
	encryption := txt["et"]
	var rsaAudio bool
	requireEncryption := txt["ek"] == "1"
	switch {
	case !requireEncryption && raopTXTContains(encryption, "0"):
	case raopTXTContains(encryption, "1") || requireEncryption && encryption == "":
		rsaAudio = true
	default:
		return nil, fmt.Errorf("RAOP receiver does not advertise clear or RSA audio (et=%q)", encryption)
	}
	if cfg.PlayoutLatency <= 0 {
		cfg.PlayoutLatency = time.Duration(targetLatencyNS.Load())
	}
	latency := cfg.PlayoutLatency
	if latency <= 0 {
		latency = DefaultRAOPPlayoutLatency
	}
	samples := durationToAudioSamples(latency)
	if samples <= 0 || samples > 1<<31-1 {
		return nil, fmt.Errorf("invalid RAOP playout lead %v", latency)
	}

	host := device.RAOP.IP
	client := NewAirPlayClient(host, device.RAOP.Port)
	client.SetPassword(cfg.Password)
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	stopSetup := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopSetup()
	owned := false
	defer func() {
		if !owned {
			_ = client.Close()
		}
	}()

	var random [18]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	sessionID := binary.BigEndian.Uint32(random[:4])
	initialRTP := binary.BigEndian.Uint32(random[4:8])
	initialSeq := binary.BigEndian.Uint16(random[8:10])
	instance := fmt.Sprintf("%X", random[10:])
	headers := map[string]string{"Client-Instance": instance, "DACP-ID": instance}
	local := client.conn.LocalAddr().(*net.TCPAddr).IP
	remote := client.conn.RemoteAddr().(*net.TCPAddr).IP
	addressFamily := "IP4"
	if local.To4() == nil {
		addressFamily = "IP6"
	}
	hostName := remote.String()
	if remote.To4() == nil {
		hostName = "[" + hostName + "]"
	}
	uri := fmt.Sprintf("rtsp://%s/%d", hostName, sessionID)
	_, options, err := client.rtspRequest("OPTIONS", "*", "", nil, headers)
	if err != nil {
		return nil, fmt.Errorf("RAOP OPTIONS: %w", err)
	}
	if raopTXTContains(encryption, "4") && raopTXTContains(options["public"], "POST") {
		// et=4 advertises the preliminary auth-setup exchange, independent
		// of the media encryption declared in SDP.
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		request := append([]byte{1}, key.PublicKey().Bytes()...)
		if _, _, err := client.rtspRequest("POST", "/auth-setup", "application/octet-stream", request, headers); err != nil {
			return nil, fmt.Errorf("RAOP auth-setup: %w", err)
		}
	}
	ct, spf, _, _, _, _ := AudioCodecALAC.Info()
	sdp := fmt.Sprintf("v=0\r\no=iTunes %d 0 IN %s %s\r\ns=iTunes\r\nc=IN %s %s\r\nt=0 0\r\n"+
		"m=audio 0 RTP/AVP 96\r\na=rtpmap:96 AppleLossless\r\na=fmtp:96 %d 0 16 40 10 14 2 255 0 0 %d\r\n",
		sessionID, addressFamily, local, addressFamily, remote, spf, audioSampleRate)
	var aesKey, aesIV []byte
	if rsaAudio {
		keyMaterial := make([]byte, 32)
		if _, err := rand.Read(keyMaterial); err != nil {
			return nil, err
		}
		aesKey, aesIV = keyMaterial[:16], keyMaterial[16:]
		wrapped, err := wrapRAOPAESKey(aesKey)
		if err != nil {
			return nil, err
		}
		sdp += "a=rsaaeskey:" + base64.RawStdEncoding.EncodeToString(wrapped) + "\r\n" +
			"a=aesiv:" + base64.RawStdEncoding.EncodeToString(aesIV) + "\r\n"
	}
	if _, _, err := client.rtspRequest("ANNOUNCE", uri, "application/sdp", []byte(sdp), headers); err != nil {
		return nil, fmt.Errorf("RAOP ANNOUNCE: %w", err)
	}
	ports, err := allocateConsecutiveUDPPortsInRange(3, cfg.PortMin, cfg.PortMax)
	if err != nil {
		return nil, fmt.Errorf("allocate RAOP UDP ports: %w", err)
	}
	timing, control, data := ports[0], ports[1], ports[2]
	timingCtx, stopTiming := context.WithCancel(context.Background())
	timingDone := make(chan struct{})
	nowNTP := func() uint64 { return wallNTPTimestamp(time.Now()) }
	go func() {
		defer close(timingDone)
		respondToNTPTiming(timingCtx, timing, nowNTP, remote)
	}()
	defer func() {
		if !owned {
			stopTiming()
			for _, port := range ports {
				_ = port.Close()
			}
			<-timingDone
		}
	}()

	transport := fmt.Sprintf("RTP/AVP/UDP;unicast;interleaved=0-1;mode=record;control_port=%d;timing_port=%d",
		control.LocalAddr().(*net.UDPAddr).Port, timing.LocalAddr().(*net.UDPAddr).Port)
	_, reply, err := client.rtspRequest("SETUP", uri, "", nil, withHeader(headers, "Transport", transport))
	if err != nil {
		return nil, fmt.Errorf("RAOP SETUP: %w", err)
	}
	session, _, _ := strings.Cut(reply["session"], ";")
	session = strings.TrimSpace(session)
	if session == "" {
		return nil, errors.New("RAOP SETUP omitted the session identifier")
	}
	headers["Session"] = session
	// Once the receiver reserves media resources, release them even when the
	// subsequent RECORD fails. Closing control also releases the session on EOF.
	defer func() {
		if !owned && ctx.Err() == nil {
			timer := time.AfterFunc(time.Second, func() { _ = client.Close() })
			defer timer.Stop()
			_, _, _ = client.rtspRequest("TEARDOWN", uri, "", nil, headers)
		}
	}()
	remoteData, remoteControl, remoteTiming, err := parseRAOPTransport(reply["transport"])
	if err != nil {
		return nil, err
	}
	if remoteTiming != 0 {
		go sendNTPTimingProbesWithClock(timingCtx, timing, client.sessionPeerHost(), remoteTiming, nowNTP)
	}
	record := withHeader(headers, "Range", "npt=0-")
	record["RTP-Info"] = fmt.Sprintf("seq=%d;rtptime=%d", initialSeq, initialRTP)
	_, reply, err = client.rtspRequest("RECORD", uri, "", nil, record)
	if err != nil {
		return nil, fmt.Errorf("RAOP RECORD: %w", err)
	}
	if minimum, err := strconv.ParseUint(reply["audio-latency"], 10, 31); err == nil && int64(minimum) > samples {
		if cfg.PlayoutLatency > 0 {
			return nil, fmt.Errorf("RAOP receiver needs at least %v of playout lead (requested %v)",
				audioLatencyDuration(uint32(minimum)), cfg.PlayoutLatency)
		}
		samples = int64(minimum)
	}

	canSetVolume := raopTXTContains(options["public"], "SET_PARAMETER")
	if canSetVolume {
		if err := initializeRAOPVolume(client, uri, headers, raopTXTContains(options["public"], "GET_PARAMETER")); err != nil {
			return nil, err
		}
	}

	stream, err := client.setupAudioStream(remoteData, remoteControl, aesKey, aesIV, nil,
		mediaSecurityLegacyAES, byte(ct), uint32(samples), false, nil, control, data)
	if err != nil {
		return nil, err
	}
	stream.ssrc = sessionID
	stream.markFirstPacket = true
	stream.announceFlags = 7
	if !stopSetup() {
		return nil, ctx.Err()
	}
	owned = true
	return &AudioOnlySession{
		client: client, stream: stream, timing: timing, uri: uri, headers: headers,
		stopTiming: stopTiming, timingDone: timingDone, rtspTimeout: 2 * time.Second, canMatchVolume: canSetVolume,
		playback: audioPlayback{
			now: time.Now, timingProtocol: timingProtocolNTP,
			clockAt: func(t time.Time) (uint64, uint64) {
				if t.IsZero() {
					t = time.Now()
				}
				return wallNTPTimestamp(t), 0
			},
			initialRTP: initialRTP, initialSeq: initialSeq, singleSend: true,
		},
	}, nil
}

// Send the current volume after RECORD, before the first media packet.
// A receiver reporting the mute sentinel keeps that setting.
func initializeRAOPVolume(client *AirPlayClient, uri string, headers map[string]string, canReadVolume bool) error {
	volume, source := airPlayDefaultVolumeDB, "fallback"
	if canReadVolume {
		body, _, err := client.rtspRequest("GET_PARAMETER", uri, "text/parameters", []byte("volume\r\n"), headers)
		if err != nil {
			var status *HTTPStatusError
			if !errors.As(err, &status) || status.StatusCode == 401 {
				return fmt.Errorf("read RAOP initial volume: %w", err)
			}
		} else if current, err := parseReceiverVolume(body); err == nil {
			volume = normalizeOutgoingVolume(current)
			if volume == current {
				source = "receiver"
			}
		}
	}
	dbg("[RAOP] initializing playback volume at %.1f dB (%s)", volume, source)
	if _, _, err := client.rtspRequest("SET_PARAMETER", uri, "text/parameters", audioVolumeBody(volume), headers); err != nil {
		var status *HTTPStatusError
		if errors.As(err, &status) && (status.StatusCode == 405 || status.StatusCode == 451 || status.StatusCode == 501) {
			dbg("[RAOP] receiver declined initial volume: %v", err)
			return nil
		}
		return fmt.Errorf("set RAOP initial volume: %w", err)
	}
	return nil
}

func wallNTPTimestamp(t time.Time) uint64 {
	return uint64(t.Unix()+secondsFrom1900To1970)<<32 | (uint64(t.Nanosecond())<<32)/uint64(time.Second)
}

func raopTXTContains(list, value string) bool {
	for _, entry := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(entry), value) {
			return true
		}
	}
	return false
}

func parseRAOPTransport(header string) (data, control, timing int, err error) {
	protocol, fields, _ := strings.Cut(header, ";")
	if !strings.EqualFold(strings.TrimSpace(protocol), "RTP/AVP/UDP") {
		return 0, 0, 0, fmt.Errorf("unsupported RAOP transport %q", protocol)
	}
	for _, field := range strings.Split(fields, ";") {
		key, value, _ := strings.Cut(field, "=")
		port, _ := strconv.ParseUint(strings.TrimSpace(value), 10, 16)
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "server_port":
			data = int(port)
		case "control_port":
			control = int(port)
		case "timing_port":
			timing = int(port)
		}
	}
	if data == 0 || control == 0 {
		return 0, 0, 0, fmt.Errorf("RAOP SETUP omitted valid UDP ports (data=%d control=%d)", data, control)
	}
	return data, control, timing, nil
}

func wrapRAOPAESKey(key []byte) ([]byte, error) {
	// AirTunes interoperability public key. Each session generates its own
	// AES key and IV.
	const modulus = "59dE8qLieItsH1WgjrcFRKj6eUWqi+bGLOX1HL3U3GhC/j0Qg90u3sG/1CUtwC5vOYvfDmFI6oSFXi5ELabWJmT2dKHzBJKa3k9ok+8t9ucRqMd6DZHJ2YCCLlDRKSKv6kDqnw4UwPdpOMXziC/AMj3Z/lUVX1G7WSHCAWKf1zNS1eLvqr+boEjXuBOitnZ/bDzPHrTOZz0Dew0uowxf/+sG+NCK3eQJVxqcaJ/vEHKIVd2M+5qL71yJQ+87X6oV3eaYvt3zWZYD6z5vYTcrtij2VZ9Zmni/UAaHqn9JdsBWLUEpVviYnhimNVvYFZeCXg/IdTQ+x4IRdiXNv5hEew=="
	n, err := base64.StdEncoding.DecodeString(modulus)
	if err != nil {
		return nil, err
	}
	wrapped, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: 65537}, key, nil)
	if err != nil {
		return nil, fmt.Errorf("wrap RAOP AES key: %w", err)
	}
	return wrapped, nil
}

// PlayoutLatency reports the negotiated capture-to-playout lead.
func (s *AudioOnlySession) PlayoutLatency() time.Duration {
	return audioLatencyDuration(s.stream.currentLatencySamples())
}

// Stream consumes one ALAC tap. Joining another session on the same timestamped
// capture keeps both mappings aligned at capture PTS plus the common lead.
func (s *AudioOnlySession) Stream(ctx context.Context, capture *AudioCapture) error {
	if capture.codec != AudioCodecALAC {
		return errors.New("direct audio requires an ALAC audio capture")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopCapture := context.AfterFunc(ctx, capture.Stop)
	defer stopCapture()
	var volumeTicks <-chan time.Time
	updateVolume := func() {
		if volume, ok := capture.outputVolume.read(ctx); ok {
			if err := s.matchOutputVolume(volume); err != nil && ctx.Err() == nil {
				dbg("[AUDIO] matching receiver volume: %v", err)
			}
		}
	}
	if s.canMatchVolume && capture.outputVolume != nil {
		updateVolume()
		volumeTicker := time.NewTicker(volumeSampleInterval)
		defer volumeTicker.Stop()
		volumeTicks = volumeTicker.C
	}
	mediaDone := make(chan error, 1)
	go func() { mediaDone <- s.stream.play(ctx, capture, s.playback) }()
	interval := 20 * time.Second
	if s.airPlay2 {
		interval = 2 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case err := <-mediaDone:
			return err
		case <-ctx.Done():
			capture.Stop()
			<-mediaDone
			return ctx.Err()
		case <-volumeTicks:
			updateVolume()
		case <-ticker.C:
			method, uri := "OPTIONS", "*"
			if s.airPlay2 {
				method, uri = "POST", "/feedback"
			}
			if _, err := s.request(method, uri, "", nil); err != nil {
				cancel()
				capture.Stop()
				<-mediaDone
				return fmt.Errorf("audio session keepalive: %w", err)
			}
		}
	}
}

func (s *AudioOnlySession) request(method, uri, contentType string, body []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.requestLocked(method, uri, contentType, body)
}

func (s *AudioOnlySession) requestLocked(method, uri, contentType string, body []byte) ([]byte, error) {
	timer := time.AfterFunc(s.rtspTimeout, func() { _ = s.client.Close() })
	defer timer.Stop()
	response, _, err := s.client.rtspRequest(method, uri, contentType, body, s.headers)
	return response, err
}

func (s *AudioOnlySession) matchOutputVolume(volume float64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.volumeMatched && volume == s.matchedVolume {
		return nil
	}
	if s.restore != nil {
		// A daemon mute remains active even when the local volume changes.
		*s.restore = volume
	} else if _, err := s.requestLocked("SET_PARAMETER", s.uri, "text/parameters", audioVolumeBody(volume)); err != nil {
		return err
	}
	s.matchedVolume, s.volumeMatched = volume, true
	dbg("[AUDIO] matched receiver volume to local output at %.1f dB", volume)
	return nil
}

func (s *AudioOnlySession) SetAudioMuted(muted bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if muted {
		if s.restore != nil {
			return nil
		}
		body, err := s.requestLocked("GET_PARAMETER", s.uri, "text/parameters", []byte("volume\r\n"))
		if err != nil {
			return fmt.Errorf("read RAOP volume: %w", err)
		}
		previous, err := parseReceiverVolume(body)
		if err != nil {
			return err
		}
		if _, err := s.requestLocked("SET_PARAMETER", s.uri, "text/parameters", audioVolumeBody(airPlayMutedVolumeDB)); err != nil {
			return err
		}
		s.restore = &previous
		return nil
	}
	if s.restore == nil {
		return nil
	}
	if _, err := s.requestLocked("SET_PARAMETER", s.uri, "text/parameters", audioVolumeBody(*s.restore)); err != nil {
		return err
	}
	s.restore = nil
	return nil
}

func (s *AudioOnlySession) Close() error {
	s.closeOnce.Do(func() {
		s.stopTiming()
		_ = s.timing.Close()
		<-s.timingDone
		if s.event != nil {
			_ = s.event.Close()
		}
		s.stream.Close()
		_, s.closeErr = s.request("TEARDOWN", s.uri, "", nil)
		_ = s.client.Close()
		if s.releaseClock != nil {
			s.releaseClock()
		}
	})
	return s.closeErr
}
