package airplay

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

// RAOPDevice returns the classic fixture's equivalent mDNS advertisement,
// so tests can inject it into discovery without sending multicast packets.
func (s *ReceiverServer) RAOPDevice() AirPlayDevice {
	address := s.Addr().(*net.TCPAddr)
	txt := map[string]string{"cn": "1", "et": "0", "tp": "UDP"}
	if s.digest.enabled() {
		txt["pw"] = "true"
	}
	if s.cfg.RAOPAuthSetup {
		txt["et"] = "0,4"
	}
	return AirPlayDevice{
		Name: s.cfg.Name, Model: s.cfg.Model, DeviceID: s.cfg.DeviceID,
		IP: address.IP.String(), Port: address.Port, RAOPOnly: true,
		RAOP: &RAOPAdvertisement{IP: address.IP.String(), Port: address.Port, TXT: txt},
	}
}

func (c *receiverConnection) dispatchClassicAudio(request receiverRequest) receiverResponse {
	const id = "raop-test-session"
	s := c.server
	if !c.authorize(request) {
		s.stats.digestChallenges.Add(1)
		return receiverResponse{status: 401, headers: map[string]string{"WWW-Authenticate": s.digest.challengeHeader()}}
	}
	switch request.method {
	case "OPTIONS":
		methods := "OPTIONS, ANNOUNCE, SETUP, RECORD, GET_PARAMETER, SET_PARAMETER, TEARDOWN"
		if s.cfg.RAOPAuthSetup {
			methods += ", POST"
		}
		return receiverResponse{status: 200, headers: map[string]string{"Public": methods}}
	case "POST":
		if !s.cfg.RAOPAuthSetup || request.uri != "/auth-setup" || len(request.body) != 33 || request.body[0] != 1 {
			return receiverError(400, fmt.Errorf("invalid classic auth-setup request"))
		}
		c.raopAuthSetup = true
		return receiverOK(nil, "")
	case "ANNOUNCE":
		if c.sessionState != receiverSessionInitial || s.cfg.RAOPAuthSetup && !c.raopAuthSetup {
			return c.invalidSessionState(request.method)
		}
		sdp := string(request.body)
		if request.headers["content-type"] != "application/sdp" ||
			!strings.Contains(sdp, "a=rtpmap:96 AppleLossless\r\n") ||
			!strings.Contains(sdp, "a=fmtp:96 352 0 16 40 10 14 2 255 0 0 44100\r\n") ||
			strings.Contains(sdp, "a=rsaaeskey:") {
			return receiverError(415, fmt.Errorf("fixture requires clear 44.1 kHz stereo ALAC"))
		}
		c.raopAnnounced = true
		c.raopVolume = -20
		return receiverOK(nil, "")
	case "SETUP":
		s.stats.setupRequests.Add(1)
		if !c.raopAnnounced || c.sessionState != receiverSessionInitial {
			return c.invalidSessionState(request.method)
		}
		protocol, fields, _ := strings.Cut(request.headers["transport"], ";")
		controlPort, timingPort := 0, 0
		for _, field := range strings.Split(fields, ";") {
			key, value, _ := strings.Cut(field, "=")
			port, _ := strconv.ParseUint(value, 10, 16)
			switch key {
			case "control_port":
				controlPort = int(port)
			case "timing_port":
				timingPort = int(port)
			}
		}
		if protocol != "RTP/AVP/UDP" || controlPort == 0 || timingPort == 0 {
			return receiverError(415, fmt.Errorf("fixture requires UDP timing and control ports"))
		}

		c.timingProtocol = timingProtocolNTP
		if err := c.ensureMedia(); err != nil {
			return receiverError(500, err)
		}
		if c.media.playback != nil {
			if err := c.media.playback.configureAudio(AudioCodecALAC, nil, nil, nil, c.audioResend(controlPort)); err != nil {
				return receiverError(500, err)
			}
		}
		if !s.cfg.RAOPSenderTiming {
			remote := c.conn.RemoteAddr().(*net.TCPAddr)
			ctx, cancel := context.WithTimeout(s.ctx, 2*time.Second)
			defer cancel()
			if err := c.media.ProbeLegacyTiming(ctx, &net.UDPAddr{IP: remote.IP, Zone: remote.Zone, Port: timingPort}, 3); err != nil {
				return receiverError(500, err)
			}
		}
		c.sessionState = receiverSessionAudioPrepared
		ports := c.media.Endpoints()
		transport := fmt.Sprintf("RTP/AVP/UDP;unicast;server_port=%d;control_port=%d", ports.AudioRTPPort, ports.AudioRTCPPort)
		if s.cfg.RAOPSenderTiming {
			transport += fmt.Sprintf(";timing_port=%d", ports.TimingPort)
		}
		return receiverResponse{status: 200, headers: map[string]string{
			"Session":   id + ";timeout=60",
			"Transport": transport,
		}}
	case "RECORD":
		s.stats.recordRequests.Add(1)
		var seq uint16
		var timestamp uint32
		_, originErr := fmt.Sscanf(request.headers["rtp-info"], "seq=%d;rtptime=%d", &seq, &timestamp)
		if c.sessionState != receiverSessionAudioPrepared || request.headers["session"] != id || originErr != nil {
			return c.invalidSessionState(request.method)
		}
		c.sessionState = receiverSessionReady
		return receiverResponse{status: 200, headers: map[string]string{"Audio-Latency": "11025"}}
	case "GET_PARAMETER", "SET_PARAMETER":
		if c.sessionState != receiverSessionReady || request.headers["session"] != id {
			return c.invalidSessionState(request.method)
		}
		s.stats.parameterRequests.Add(1)
		if request.method == "GET_PARAMETER" {
			return receiverOK(audioVolumeBody(c.raopVolume), "text/parameters")
		}
		volume, err := parseReceiverVolume(request.body)
		if err != nil {
			return receiverError(400, err)
		}
		c.raopVolume = volume
		return receiverOK(nil, "")
	case "TEARDOWN":
		s.stats.teardownRequests.Add(1)
		if c.media == nil || request.headers["session"] != id {
			return c.invalidSessionState(request.method)
		}
		c.closeMedia()
		c.sessionState = receiverSessionTornDown
		return receiverOK(nil, "")
	default:
		return receiverResponse{status: 404}
	}
}
