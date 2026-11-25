package airplay

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"howett.net/plist"
)

const featureUnifiedMedia uint = 38

var errAudioPTPUnavailable = errors.New("AirPlay 2 media PTP clock unavailable")

// OpenAirPlay2Audio opens encrypted realtime audio (stream type 96) on
// the receiver's advertised network clock.
func OpenAirPlay2Audio(ctx context.Context, device AirPlayDevice, cfg AudioOnlyConfig, store *CredentialStore, expectedID string) (*AudioOnlySession, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	client := NewAirPlayClientForDevice(device)
	client.SetPassword(cfg.Password)
	if err := client.Connect(ctx); err != nil {
		return nil, err
	}
	stopSetup := context.AfterFunc(ctx, func() { _ = client.Close() })
	defer stopSetup()
	ready := false
	defer func() {
		if !ready {
			_ = client.Close()
		}
	}()

	info, err := client.GetInfo()
	if err != nil {
		return nil, fmt.Errorf("AirPlay 2 audio /info: %w", err)
	}
	if expectedID == "" {
		expectedID = device.DeviceID
	}
	var saved *SavedCredentials
	if store != nil {
		saved, err = store.LookupReceiver(expectedID, info.DeviceID)
		if err != nil {
			return nil, err
		}
	}
	if saved.HasPairingCredentials() {
		if err := client.RestorePairingCredentials(saved); err != nil {
			return nil, err
		}
		if client.PairingProtocol() != PairingProtocolHAP {
			return nil, errors.New("AirPlay 2 audio requires HAP pairing credentials")
		}
		client.pairType = pairingTypeLegacy
		err = client.PairVerify(ctx)
	} else {
		// A configured playback password can be a Digest credential. Only
		// requirements for persistent pair-setup rule out this transient path.
		if !info.SupportsTransientPairing() || info.RequiredPairingCredential() != PairingCredentialNone {
			return nil, errors.New("AirPlay 2 audio receiver requires persistent media pairing")
		}
		err = client.pairAudioTransient(ctx)
	}
	if err != nil {
		return nil, fmt.Errorf("AirPlay 2 audio pairing: %w", err)
	}
	if !client.encrypted {
		return nil, errors.New("AirPlay 2 audio requires encrypted control")
	}

	local := client.conn.LocalAddr().(*net.TCPAddr)
	peer := client.conn.RemoteAddr().(*net.TCPAddr)
	timingProtocol, clockAt := timingProtocolNTP, wallAudioClock
	var clock *sharedPTPClock
	var releaseClock func()
	if info.HasFeature(featurePTP) && supportsPTPSourceVersion(info.SourceVersion) {
		pool := cfg.ptpPool
		if pool == nil {
			pool = &directAudioPTP
		}
		clock, releaseClock, err = pool.acquire(peer.AddrPort().Addr().Unmap())
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errAudioPTPUnavailable, err)
		}
		defer func() {
			if !ready {
				releaseClock()
			}
		}()
		timingProtocol, clockAt = timingProtocolPTP, clock.mediaTimeAt
	}

	ports, err := allocateConsecutiveUDPPortsInRange(3, cfg.PortMin, cfg.PortMax)
	if err != nil {
		return nil, err
	}
	timing, control, data := ports[0], ports[1], ports[2]
	timingCtx, stopTiming := context.WithCancel(context.Background())
	timingDone := make(chan struct{})
	var event net.Conn
	nowNTP := func() uint64 { return wallNTPTimestamp(time.Now()) }
	if clock == nil {
		go func() {
			defer close(timingDone)
			respondToNTPTiming(timingCtx, timing, nowNTP, peer.IP)
		}()
	} else {
		_ = timing.Close()
		close(timingDone)
	}
	defer func() {
		if !ready {
			stopTiming()
			for _, port := range ports {
				_ = port.Close()
			}
			<-timingDone
			if event != nil {
				_ = event.Close()
			}
		}
	}()

	var entropy [42]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return nil, err
	}
	sessionID := binary.BigEndian.Uint32(entropy[:4]) | 1
	initialRTP := binary.BigEndian.Uint32(entropy[4:8])
	initialSeq := binary.BigEndian.Uint16(entropy[8:10])
	streamKey := entropy[10:]
	sessionUUID := generateUUID()
	uri := fmt.Sprintf("rtsp://%s/%d", net.JoinHostPort(local.IP.String(), fmt.Sprint(local.Port)), sessionID)
	request := map[string]any{
		"deviceID": uuidToMAC(client.PairingID), "sessionUUID": sessionUUID,
		"timingProtocol": timingProtocol,
	}
	if clock == nil {
		request["timingPort"] = timing.LocalAddr().(*net.UDPAddr).Port
	} else {
		senderID := uuidToMAC(clock.groupID)
		timingPeer := map[string]any{
			"ID": clock.groupID, "DeviceType": 0, "ClockID": clock.clockID,
			"Addresses": []string{local.IP.String()}, "SupportsClockPortMatchingOverride": false,
		}
		request["deviceID"], request["macAddress"] = senderID, senderID
		request["name"], request["groupUUID"] = pairingClientName(), clock.groupID
		request["groupContainsGroupLeader"] = false
		request["timingPeerInfo"] = timingPeer
		request["timingPeerList"] = []any{timingPeer}
	}
	session, err := client.setupDirectAudio(uri, request)
	if err != nil {
		return nil, fmt.Errorf("AirPlay 2 audio session SETUP: %w", err)
	}
	defer func() {
		if !ready && ctx.Err() == nil {
			timer := time.AfterFunc(time.Second, func() { _ = client.Close() })
			defer timer.Stop()
			_, _, _ = client.rtspRequest("TEARDOWN", uri, "", nil, nil)
		}
	}()
	if timingPort := plistInt(session["timingPort"]); clock == nil && timingPort > 0 && timingPort <= 65535 {
		go sendNTPTimingProbesWithClock(timingCtx, timing, client.sessionPeerHost(), timingPort, nowNTP)
	}
	if eventPort := plistInt(session["eventPort"]); eventPort > 0 && eventPort <= 65535 {
		event, err = client.connectEventChannel(timingCtx, eventPort, nil)
		if err != nil {
			return nil, err
		}
	}
	if _, _, err := client.rtspRequest("RECORD", uri, "", nil, nil); err != nil {
		return nil, fmt.Errorf("AirPlay 2 audio RECORD: %w", err)
	}

	lead := cfg.PlayoutLatency
	if lead == 0 && HasExplicitTargetLatency() {
		lead = SharedPlayoutLatency()
	}
	if lead <= 0 {
		lead = DefaultRAOPPlayoutLatency
	}
	samples := durationToAudioSamples(lead)
	if samples <= 0 || samples > 1<<31-1 {
		return nil, fmt.Errorf("invalid realtime audio lead %v", lead)
	}
	ct, spf, format, _, _, _ := AudioCodecALAC.Info()
	descriptor := map[string]any{
		"type": 96, "ct": ct, "spf": spf, "sr": audioSampleRate, "audioFormat": format,
		"audioMode": "default", "isMedia": true, "shk": streamKey, "streamConnectionID": sessionID,
		"controlPort": control.LocalAddr().(*net.UDPAddr).Port, "dataPort": data.LocalAddr().(*net.UDPAddr).Port,
		"latencyMin": min(int(samples), audioSampleRate/4), "latencyMax": samples,
		"supportsDynamicStreamID": false,
	}
	replies, err := client.setupDirectAudio(uri, map[string]any{"streams": []any{descriptor}})
	if err != nil {
		return nil, fmt.Errorf("AirPlay 2 audio stream SETUP: %w", err)
	}
	streams, _ := replies["streams"].([]any)
	if len(streams) != 1 {
		return nil, errors.New("AirPlay 2 audio SETUP omitted the realtime stream")
	}
	result, _ := streams[0].(map[string]any)
	if plistInt(result["type"]) != 96 {
		return nil, errors.New("AirPlay 2 audio SETUP returned an unexpected stream type")
	}
	dataPort, controlPort := plistStreamPorts(result)
	if dataPort <= 0 || dataPort > 65535 || controlPort <= 0 || controlPort > 65535 {
		return nil, errors.New("AirPlay 2 audio SETUP returned invalid UDP ports")
	}
	minimum, maximum := plistInt(result["latencyMin"]), plistInt(result["latencyMax"])
	if minimum < 0 || maximum < 0 || int64(minimum) > samples || maximum != 0 && int64(maximum) < samples {
		return nil, fmt.Errorf("AirPlay 2 audio cannot use a %v lead (receiver window %d..%d samples)", lead, minimum, maximum)
	}
	stream, err := client.setupAudioStream(dataPort, controlPort, nil, nil, streamKey, mediaSecurityChaCha,
		byte(ct), uint32(samples), false, nil, control, data)
	if err != nil {
		return nil, err
	}
	stream.ssrc = sessionID
	stream.announceFlags = 7
	stream.directPlayout = true
	stream.markFirstPacket = true
	if clock != nil {
		stream.ssrc = 0
		stream.announceFlags = 6
		body, err := plist.Marshal([]string{peer.IP.String(), local.IP.String()}, plist.BinaryFormat)
		if err != nil {
			return nil, err
		}
		if _, _, err := client.rtspRequest("SETPEERS", uri, "application/x-apple-binary-plist", body, nil); err != nil {
			return nil, fmt.Errorf("AirPlay 2 audio SETPEERS: %w", err)
		}
		lockCtx, cancelLock := context.WithTimeout(ctx, 6*time.Second)
		defer cancelLock()
		if err := clock.WaitPeerReady(lockCtx, peer.AddrPort().Addr().Unmap()); err != nil {
			return nil, err
		}
	}
	dbg("[AUDIO] AirPlay 2 realtime media negotiated with %s timing", timingProtocol)
	if !stopSetup() {
		return nil, ctx.Err()
	}
	ready = true
	return &AudioOnlySession{
		client: client, stream: stream, timing: timing, event: event, uri: uri, airPlay2: true, releaseClock: releaseClock,
		stopTiming: stopTiming, timingDone: timingDone, rtspTimeout: 2 * time.Second, canMatchVolume: true,
		playback: audioPlayback{
			now: time.Now, timingProtocol: timingProtocol, clockAt: clockAt,
			initialRTP: initialRTP, initialSeq: initialSeq, singleSend: true,
		},
	}, nil
}

func (c *AirPlayClient) setupDirectAudio(uri string, request map[string]any) (map[string]any, error) {
	body, err := plist.Marshal(request, plist.BinaryFormat)
	if err != nil {
		return nil, err
	}
	body, _, err = c.rtspRequest("SETUP", uri, "application/x-apple-binary-plist", body, nil)
	if err != nil {
		return nil, err
	}
	var response map[string]any
	_, err = plist.Unmarshal(body, &response)
	return response, err
}

func wallAudioClock(t time.Time) (uint64, uint64) {
	if t.IsZero() {
		t = time.Now()
	}
	return wallNTPTimestamp(t), 0
}

// SupportsAirPlay2Audio identifies an advertised AirPlay media endpoint
// with HomeKit or CoreUtils pairing support.
func (d AirPlayDevice) SupportsAirPlay2Audio() bool {
	return !d.RAOPOnly && d.HasFeature(featureUnifiedMedia) && (d.HasFeature(46) || d.HasFeature(48))
}

func (d AirPlayDevice) AudioOnlyPort() int {
	if d.SupportsAirPlay2Audio() {
		return d.Port
	}
	if d.RAOP != nil {
		return d.RAOP.Port
	}
	return 0
}

func (d AirPlayDevice) UsesAudioOnly() bool {
	return d.SupportsAirPlay2Audio() && !d.SupportsScreen() || d.UsesClassicRAOP()
}

// AudioOnlyEndpoint identifies a realtime AirPlay 2 speaker from a connected
// receiver's /info response, including when it was addressed without discovery.
func (c *AirPlayClient) AudioOnlyEndpoint() (AirPlayDevice, bool) {
	if c.info == nil {
		return AirPlayDevice{}, false
	}
	device := AirPlayDevice{
		IP:            c.sessionPeerHost(),
		Port:          c.port,
		Name:          c.info.Name,
		DeviceID:      c.info.DeviceID,
		Features:      c.info.Features,
		FeaturesEx:    c.info.FeaturesEx,
		Flags:         c.info.StatusFlags,
		SourceVersion: c.info.SourceVersion,
	}
	return device, device.SupportsAirPlay2Audio() && !device.SupportsScreen()
}

func OpenAudioOnly(ctx context.Context, device AirPlayDevice, cfg AudioOnlyConfig, store *CredentialStore, expectedID string) (*AudioOnlySession, error) {
	if device.SupportsAirPlay2Audio() {
		session, err := OpenAirPlay2Audio(ctx, device, cfg, store, expectedID)
		if !errors.Is(err, errAudioPTPUnavailable) || device.RAOP == nil {
			return session, err
		}
		// A local bind failure can use the separately advertised classic
		// endpoint. Pairing, negotiation, and synchronization failures do
		// not trigger a protocol downgrade.
		log.Printf("[AUDIO] %v; trying advertised classic RAOP endpoint", err)
	}
	if device.RAOP == nil {
		return nil, errors.New("receiver does not advertise a supported audio-only endpoint")
	}
	if store == nil {
		return nil, errors.New("classic RAOP requires a credential store to check saved identities")
	}
	if err := store.CheckRAOPReceiver(expectedID, device.DeviceID, device.RAOP.DeviceID); err != nil {
		return nil, err
	}
	return OpenRAOP(ctx, device, cfg)
}
