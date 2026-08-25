package airplay

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

type rtspTestRequest struct {
	method  string
	uri     string
	body    []byte
	headers map[string]string
}

func TestMirrorSetupRequestUsesProtocolSpecificTimingFields(t *testing.T) {
	for _, test := range []struct {
		name           string
		protocol       string
		sourceVersion  string
		wantTimingPort bool
		wantTimingPeer bool
	}{
		{name: "legacy NTP", protocol: timingProtocolNTP, sourceVersion: legacyAirPlaySourceVersion, wantTimingPort: true},
		{name: "modern PTP", protocol: timingProtocolPTP, sourceVersion: modernAirPlaySourceVersion, wantTimingPeer: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := (mirrorSetupRequest{
				deviceID:          "00:11:22:33:44:55",
				sessionUUID:       "session",
				sourceVersion:     test.sourceVersion,
				timingProtocol:    test.protocol,
				timingPort:        6000,
				timingPeerID:      "peer-id",
				timingPeerAddress: "192.0.2.1",
				name:              "sender",
			}).sessionPlist()

			if got := request["timingProtocol"]; got != test.protocol {
				t.Fatalf("timingProtocol = %v, want %q", got, test.protocol)
			}
			if got := request["sourceVersion"]; got != test.sourceVersion {
				t.Fatalf("sourceVersion = %v, want %q", got, test.sourceVersion)
			}
			_, hasTimingPort := request["timingPort"]
			if hasTimingPort != test.wantTimingPort {
				t.Fatalf("timingPort presence = %t, want %t", hasTimingPort, test.wantTimingPort)
			}
			peer, hasTimingPeer := request["timingPeerInfo"].(map[string]interface{})
			if hasTimingPeer != test.wantTimingPeer {
				t.Fatalf("timingPeerInfo presence = %t, want %t", hasTimingPeer, test.wantTimingPeer)
			}
			list, hasTimingPeerList := request["timingPeerList"].([]interface{})
			if hasTimingPeerList != test.wantTimingPeer {
				t.Fatalf("timingPeerList presence = %t, want %t", hasTimingPeerList, test.wantTimingPeer)
			}
			if test.wantTimingPeer {
				if peer["ID"] != "peer-id" || plistInt(peer["DeviceType"]) != 0 {
					t.Fatalf("timingPeerInfo = %#v", peer)
				}
				if supported, _ := peer["SupportsClockPortMatchingOverride"].(bool); !supported {
					t.Fatal("timing peer omitted clock-port matching support")
				}
				addresses, _ := peer["Addresses"].([]interface{})
				if len(addresses) != 1 || addresses[0] != "192.0.2.1" {
					t.Fatalf("timing peer addresses = %#v", addresses)
				}
				if len(list) != 1 {
					t.Fatalf("timingPeerList = %#v, want one peer", list)
				}
			}
		})
	}
}

func TestSetupShapeRejected(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "bad request", err: fmt.Errorf("audio SETUP: %w", &HTTPStatusError{StatusCode: 400}), want: true},
		{name: "invalid state", err: &HTTPStatusError{StatusCode: 455}, want: true},
		{name: "digest challenge", err: &HTTPStatusError{StatusCode: 401}},
		{name: "transport error", err: io.EOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := setupShapeRejected(test.err); got != test.want {
				t.Fatalf("setupShapeRejected(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestSetupOrderRejectedOnlyForProtocolResponses(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "bad request", err: &HTTPStatusError{StatusCode: 400}, want: true},
		{name: "method not allowed", err: &HTTPStatusError{StatusCode: 405}, want: true},
		{name: "invalid state", err: fmt.Errorf("control SETUP: %w", &HTTPStatusError{StatusCode: 455}), want: true},
		{name: "server failure", err: &HTTPStatusError{StatusCode: 500}},
		{name: "digest challenge", err: &HTTPStatusError{StatusCode: 401}},
		{name: "transport error", err: io.EOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := setupOrderRejected(test.err); got != test.want {
				t.Fatalf("setupOrderRejected(%v) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}

func TestModernControlSetupPlistHasNoStreams(t *testing.T) {
	request := roundTripPlistMap(t, (mirrorSetupRequest{
		deviceID:          "00:11:22:33:44:55",
		sessionUUID:       "session",
		sourceVersion:     modernAirPlaySourceVersion,
		timingProtocol:    timingProtocolPTP,
		timingPeerID:      "peer-id",
		timingPeerAddress: "192.0.2.1",
		name:              "sender",
	}).controlPlist())

	if update, ok := request["updateSessionRequest"].(bool); !ok || update {
		t.Fatalf("updateSessionRequest = %#v, want explicit false", request["updateSessionRequest"])
	}
	if _, ok := request["streams"]; ok {
		t.Fatalf("control SETUP unexpectedly contains streams: %#v", request["streams"])
	}
	if request["sessionUUID"] != "session" || request["timingProtocol"] != timingProtocolPTP {
		t.Fatalf("control session fields = %#v", request)
	}
	if _, ok := request["timingPeerInfo"].(map[string]interface{}); !ok {
		t.Fatalf("control SETUP omitted timingPeerInfo: %#v", request)
	}
	if _, ok := request["timingPort"]; ok {
		t.Fatalf("PTP control SETUP unexpectedly contains timingPort: %#v", request["timingPort"])
	}
}

func TestModernStreamSetupPlistsContainOnlyStreams(t *testing.T) {
	for _, streamType := range []int64{96, 110} {
		t.Run(strconv.FormatInt(streamType, 10), func(t *testing.T) {
			request := roundTripPlistMap(t, streamOnlyPlist(map[string]interface{}{
				"type": streamType,
			}))
			if len(request) != 1 {
				t.Fatalf("stream SETUP keys = %#v, want only streams", request)
			}
			streams, ok := request["streams"].([]interface{})
			if !ok || len(streams) != 1 {
				t.Fatalf("streams = %#v, want one stream", request["streams"])
			}
			stream, ok := streams[0].(map[string]interface{})
			if !ok || plistInt(stream["type"]) != int(streamType) {
				t.Fatalf("stream = %#v, want type %d", streams[0], streamType)
			}
		})
	}
}

func TestSetupMirrorDigestRetryReusesStartedVideoPreparation(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen RTSP: %v", err)
	}
	defer listener.Close()

	responseBody, err := plist.Marshal(map[string]interface{}{
		"skipRecord": false,
		"info": map[string]interface{}{
			"displays": []interface{}{map[string]interface{}{
				"widthPixels":     int64(1920),
				"heightPixels":    int64(1080),
				"widthPixelsMax":  int64(3840),
				"heightPixelsMax": int64(2160),
			}},
		},
	}, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal control response: %v", err)
	}

	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)

		for attempt := 0; attempt < 2; attempt++ {
			control, err := readRTSPTestRequest(reader)
			if err != nil {
				serverErr <- fmt.Errorf("read control SETUP %d: %w", attempt+1, err)
				return
			}
			if control.method != "SETUP" {
				serverErr <- fmt.Errorf("request before Digest attempt %d = %s, want control SETUP", attempt+1, control.method)
				return
			}
			if attempt == 1 && !strings.HasPrefix(control.headers["authorization"], "Digest ") {
				serverErr <- fmt.Errorf("retried control SETUP omitted cached Digest authorization")
				return
			}
			if err := writeRTSPTestResponse(conn, 200, nil, responseBody); err != nil {
				serverErr <- err
				return
			}

			record, err := readRTSPTestRequest(reader)
			if err != nil {
				serverErr <- fmt.Errorf("read RECORD %d: %w", attempt+1, err)
				return
			}
			if record.method != "RECORD" {
				serverErr <- fmt.Errorf("request after control SETUP %d = %s, want RECORD", attempt+1, record.method)
				return
			}
			if attempt == 0 {
				if err := writeRTSPTestResponse(conn, 401, map[string]string{
					"WWW-Authenticate": `Digest realm="airplay", nonce="late-challenge"`,
				}, nil); err != nil {
					serverErr <- err
					return
				}
				continue
			}
			if !strings.HasPrefix(record.headers["authorization"], "Digest ") {
				serverErr <- fmt.Errorf("retried RECORD omitted cached Digest authorization")
				return
			}
			// Stop after proving that the second negotiation crossed the video
			// preparation boundary. A full media fixture is unnecessary here.
			if err := writeRTSPTestResponse(conn, 500, nil, nil); err != nil {
				serverErr <- err
				return
			}
			serverErr <- nil
			return
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := NewAirPlayClient("127.0.0.1", listener.Addr().(*net.TCPAddr).Port)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	client.info = &ReceiverInfo{SupportedFormats: StreamFormats{ScreenStream: 0x800000}}

	callbackCalls := 0
	encoderStarts := 0
	startedWidth, startedHeight := 0, 0
	prepareVideo := func(width, height int) error {
		callbackCalls++
		if encoderStarts != 0 {
			if width != startedWidth || height != startedHeight {
				return fmt.Errorf("receiver changed canvas from %dx%d to %dx%d", startedWidth, startedHeight, width, height)
			}
			return nil
		}
		encoderStarts++
		startedWidth, startedHeight = width, height
		return nil
	}

	if _, err := client.SetupMirrorWithVideoPreparation(ctx, StreamConfig{NoAudio: true}, prepareVideo); !errors.Is(err, ErrCredentialsRequired) {
		t.Fatalf("first setup error = %v, want ErrCredentialsRequired", err)
	}
	client.SetPassword("configured password")
	if _, err := client.SetupMirrorWithVideoPreparation(ctx, StreamConfig{NoAudio: true}, prepareVideo); err == nil {
		t.Fatal("second setup unexpectedly completed past the scripted stop")
	} else {
		var statusErr *HTTPStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != 500 {
			t.Fatalf("second setup error = %v, want scripted HTTP 500", err)
		}
	}
	if callbackCalls != 2 {
		t.Fatalf("video preparation callbacks = %d, want one per setup attempt", callbackCalls)
	}
	if encoderStarts != 1 {
		t.Fatalf("encoder starts = %d, want one shared start across Digest retry", encoderStarts)
	}
	if startedWidth != 1920 || startedHeight != 1080 {
		t.Fatalf("started canvas = %dx%d, want 1920x1080", startedWidth, startedHeight)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func roundTripPlistMap(t *testing.T, value map[string]interface{}) map[string]interface{} {
	t.Helper()
	body, err := plist.Marshal(value, plist.BinaryFormat)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]interface{}
	if _, err := plist.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestModernAudioStreamFields(t *testing.T) {
	stream := map[string]interface{}{"controlPort": int64(1234)}
	key := make([]byte, 32)
	addModernScreenAudioStreamFields(stream, key, 6001)

	if _, ok := stream["controlPort"]; ok {
		t.Fatal("modern screen audio retained legacy top-level controlPort")
	}
	if got, ok := stream["isMedia"].(bool); !ok || got {
		t.Fatal("modern screen audio stream must use isMedia=false")
	}
	if got, _ := stream["supportsDynamicStreamID"].(bool); !got {
		t.Fatal("modern audio stream omitted supportsDynamicStreamID=true")
	}
	if got, _ := stream["shk"].([]byte); len(got) != len(key) {
		t.Fatalf("modern audio key length = %d, want %d", len(got), len(key))
	}
	connections, _ := stream["streamConnections"].(map[string]interface{})
	rtcp, _ := connections["streamConnectionTypeRTCP"].(map[string]interface{})
	if got := plistInt(rtcp["streamConnectionKeyPort"]); got != 6001 {
		t.Fatalf("modern RTCP port = %d, want 6001", got)
	}
}

func TestAudioVolumeBody(t *testing.T) {
	for _, test := range []struct {
		muted bool
		want  string
	}{
		{want: "volume: 0.000000\r\n"},
		{muted: true, want: "volume: -144.000000\r\n"},
	} {
		if got := string(audioVolumeBody(test.muted)); got != test.want {
			t.Errorf("audioVolumeBody(%t) = %q, want %q", test.muted, got, test.want)
		}
	}
}

func TestSetupMirrorNoAudioStillNegotiatesAudioSession(t *testing.T) {
	SetTargetLatency(0)
	t.Cleanup(func() {
		SetTargetLatency(0)
	})

	for _, test := range []struct {
		name       string
		skipRecord bool
	}{
		{name: "record", skipRecord: false},
		{name: "skip record", skipRecord: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			testSetupMirrorAudioSessionNegotiation(t, audioSessionCase{skipRecord: test.skipRecord, noAudio: true})
		})
	}
}

// A session that DOES carry audio must still set the receiver's volume, so the
// -no-audio guard narrows that behaviour rather than removing it.
func TestSetupMirrorWithAudioSetsReceiverVolume(t *testing.T) {
	for _, test := range []struct {
		name       string
		skipRecord bool
	}{
		{name: "record", skipRecord: false},
		{name: "skip record", skipRecord: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			testSetupMirrorAudioSessionNegotiation(t, audioSessionCase{skipRecord: test.skipRecord, noAudio: false})
		})
	}
}

// A no-audio session must not be able to write the receiver's volume through
// the daemon's mute control either: unmuting sends 0 dB, which is full scale.
func TestSetAudioMutedRefusesWhenSessionHasNoAudio(t *testing.T) {
	for _, muted := range []bool{true, false} {
		session := &MirrorSession{client: &AirPlayClient{}, sessionURI: "rtsp://example/session", noAudio: true}
		err := session.SetAudioMuted(muted)
		if err == nil {
			t.Fatalf("SetAudioMuted(%v) = nil, want a refusal for a no-audio session", muted)
		}
		// Assert the REASON, not merely that something failed: without the
		// guard this call still errors (no connection), so an error alone
		// would pass on the unfixed code.
		if !strings.Contains(err.Error(), "audio disabled") {
			t.Fatalf("SetAudioMuted(%v) error = %q, want a refusal naming the disabled audio", muted, err)
		}
	}
}

type audioSessionCase struct {
	skipRecord bool
	noAudio    bool
}

func testSetupMirrorAudioSessionNegotiation(t *testing.T, test audioSessionCase) {
	skipRecord, noAudio := test.skipRecord, test.noAudio
	eventListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen event channel: %v", err)
	}
	defer eventListener.Close()

	eventResult := make(chan error, 1)
	go func() {
		conn, err := eventListener.Accept()
		if err != nil {
			eventResult <- err
			return
		}
		defer conn.Close()
		body, err := plist.Marshal(map[string]interface{}{
			"type": "forceKeyFrame",
		}, plist.BinaryFormat)
		if err != nil {
			eventResult <- err
			return
		}
		if _, err := conn.Write(eventTestRequest(17, body)); err != nil {
			eventResult <- err
			return
		}
		response, err := readRTSPTestRequest(bufio.NewReader(conn))
		if err != nil {
			eventResult <- fmt.Errorf("read event response: %w", err)
			return
		}
		if response.method != "RTSP/1.0" || response.uri != "200" {
			eventResult <- fmt.Errorf("unexpected event response line: %s %s", response.method, response.uri)
			return
		}
		if got := response.headers["cseq"]; got != "17" {
			eventResult <- fmt.Errorf("event response CSeq = %q, want 17", got)
			return
		}
		eventResult <- nil
	}()

	dataListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen video data: %v", err)
	}
	defer dataListener.Close()

	dataAccepted := make(chan net.Conn, 1)
	go func() {
		conn, err := dataListener.Accept()
		if err != nil {
			close(dataAccepted)
			return
		}
		dataAccepted <- conn
	}()

	rtspListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen rtsp: %v", err)
	}
	defer rtspListener.Close()

	requests := make(chan rtspTestRequest, 10)
	feedbackReceived := make(chan struct{}, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := rtspListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		timingPort := 0
		controlSetups := 0
		for {
			req, err := readRTSPTestRequest(reader)
			if err != nil {
				if err == io.EOF || strings.Contains(err.Error(), "closed") {
					serverErr <- nil
					return
				}
				serverErr <- err
				return
			}
			requests <- req

			waitForEvent := false
			switch req.method {
			case "SETUP":
				var setup map[string]interface{}
				if _, err := plist.Unmarshal(req.body, &setup); err != nil {
					serverErr <- fmt.Errorf("decode setup plist: %w", err)
					return
				}
				streams, _ := setup["streams"].([]interface{})
				if len(streams) == 0 {
					controlSetups++
					if controlSetups > 1 {
						serverErr <- fmt.Errorf("received %d control SETUP attempts, want one", controlSetups)
						return
					}
					if mirroring, _ := setup["isScreenMirroringSession"].(bool); !mirroring {
						serverErr <- fmt.Errorf("control-first probe omitted session fields")
						return
					}
					if update, ok := setup["updateSessionRequest"].(bool); !ok || update {
						serverErr <- fmt.Errorf("control-first probe omitted updateSessionRequest=false")
						return
					}
					combined, _ := setup["combinedGetInfoWithControlSetup"].(bool)
					if !combined {
						serverErr <- fmt.Errorf("first control SETUP omitted combined GetInfo request")
						return
					}
					// Explicitly reject the artifact-preferred control-first shape so
					// this test also exercises the one-way media-first negotiation.
					if err := writeRTSPTestResponse(conn, 400, nil, nil); err != nil {
						serverErr <- err
						return
					}
					continue
				}
				if len(streams) != 1 {
					serverErr <- fmt.Errorf("expected one stream in setup, got %d", len(streams))
					return
				}
				stream, _ := streams[0].(map[string]interface{})
				streamType := plistInt(stream["type"])
				var respBody []byte
				switch streamType {
				case 96:
					if got, _ := setup["sourceVersion"].(string); got != legacyAirPlaySourceVersion {
						serverErr <- fmt.Errorf("audio sourceVersion = %q, want %q", got, legacyAirPlaySourceVersion)
						return
					}
					if got, _ := setup["timingProtocol"].(string); got != timingProtocolNTP {
						serverErr <- fmt.Errorf("expected timingProtocol NTP in audio setup, got %q", got)
						return
					}
					if mirroring, _ := setup["isScreenMirroringSession"].(bool); !mirroring {
						serverErr <- fmt.Errorf("expected isScreenMirroringSession in initial setup")
						return
					}
					timingPort = plistInt(setup["timingPort"])
					if timingPort <= 0 {
						serverErr <- fmt.Errorf("expected positive timingPort in audio setup, got %d", timingPort)
						return
					}
					if err := probeNTPTiming(timingPort); err != nil {
						serverErr <- err
						return
					}
					if got := plistInt(stream["controlPort"]); got <= 0 {
						serverErr <- fmt.Errorf("expected positive controlPort in audio setup, got %d", got)
						return
					}
					if got := plistInt(stream["latencyMin"]); got != 0 {
						serverErr <- fmt.Errorf("audio latencyMin = %d, want 0", got)
						return
					}
					if got, want := plistInt(stream["latencyMax"]), int(samplesFor44k1(defaultAudioLatencyNormal)); got != want {
						serverErr <- fmt.Errorf("audio latencyMax = %d, want %d", got, want)
						return
					}
					respBody, err = plist.Marshal(map[string]interface{}{
						"eventPort":  int64(eventListener.Addr().(*net.TCPAddr).Port),
						"skipRecord": skipRecord,
						"streams": []interface{}{
							map[string]interface{}{
								"type":        int64(96),
								"dataPort":    int64(6100),
								"controlPort": int64(6101),
							},
						},
					}, plist.BinaryFormat)
					waitForEvent = true
				case 110:
					if got := plistInt(stream["latencyMs"]); got != int(defaultVideoLatencyNormal/time.Millisecond) {
						serverErr <- fmt.Errorf("video latencyMs = %d, want %d", got, defaultVideoLatencyNormal/time.Millisecond)
						return
					}
					if got, _ := setup["timingProtocol"].(string); got != timingProtocolNTP {
						serverErr <- fmt.Errorf("expected timingProtocol NTP in video setup, got %q", got)
						return
					}
					if got := plistInt(setup["timingPort"]); got != timingPort {
						serverErr <- fmt.Errorf("video timingPort = %d, want audio timingPort %d", got, timingPort)
						return
					}
					respBody, err = plist.Marshal(map[string]interface{}{
						"streams": []interface{}{
							map[string]interface{}{
								"type":     int64(110),
								"dataPort": int64(dataListener.Addr().(*net.TCPAddr).Port),
							},
						},
					}, plist.BinaryFormat)
				default:
					serverErr <- fmt.Errorf("unexpected setup stream type %d", streamType)
					return
				}
				if err != nil {
					serverErr <- fmt.Errorf("marshal setup response: %w", err)
					return
				}
				if err := writeRTSPTestResponse(conn, 200, nil, respBody); err != nil {
					serverErr <- err
					return
				}
				if waitForEvent {
					select {
					case err := <-eventResult:
						if err != nil {
							serverErr <- err
							return
						}
					case <-time.After(time.Second):
						serverErr <- fmt.Errorf("event command was not acknowledged before video SETUP")
						return
					}
				}
			case "RECORD":
				if err := writeRTSPTestResponse(conn, 200, map[string]string{
					"Audio-Latency": "11025",
				}, nil); err != nil {
					serverErr <- err
					return
				}
			case "SET_PARAMETER":
				if string(req.body) != "volume: 0.000000\r\n" {
					serverErr <- fmt.Errorf("unexpected SET_PARAMETER body %q", string(req.body))
					return
				}
				if err := writeRTSPTestResponse(conn, 200, nil, nil); err != nil {
					serverErr <- err
					return
				}
			case "POST":
				if req.uri != "/feedback" {
					serverErr <- fmt.Errorf("unexpected POST URI %s", req.uri)
					return
				}
				if err := writeRTSPTestResponse(conn, 200, nil, nil); err != nil {
					serverErr <- err
					return
				}
				feedbackReceived <- struct{}{}
			case "TEARDOWN":
				if err := writeRTSPTestResponse(conn, 200, nil, nil); err != nil {
					serverErr <- err
					return
				}
				serverErr <- nil
				return
			default:
				serverErr <- fmt.Errorf("unexpected RTSP method %s", req.method)
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	client := NewAirPlayClient("127.0.0.1", rtspListener.Addr().(*net.TCPAddr).Port)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer client.Close()
	// -no-audio is also the escape hatch for receivers that advertise no screen
	// audio codec we can encode. Timing and video setup must remain usable.
	client.info = &ReceiverInfo{SupportedFormats: StreamFormats{ScreenStream: 0x800000}}

	session, err := client.SetupMirror(ctx, StreamConfig{FPS: 30, NoAudio: noAudio})
	if err != nil {
		t.Fatalf("SetupMirror(noAudio=%v): %v", noAudio, err)
	}
	if !session.HasAudio() {
		t.Fatalf("noAudio=%v: expected the negotiated audio stream state to survive setup", noAudio)
	}
	if session.timestampBias != defaultVideoLatencyNormal {
		t.Fatalf("session timestamp bias = %v, want %v", session.timestampBias, defaultVideoLatencyNormal)
	}
	if got, want := session.audioStream.latencySamples, samplesFor44k1(defaultAudioLatencyNormal); got != want {
		t.Fatalf("TimeAnnounce lead = %d samples, want %d", got, want)
	}

	select {
	case conn := <-dataAccepted:
		if conn != nil {
			defer conn.Close()
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for video data connection")
	}

	// /feedback starts as soon as SETUP completes, before Wayland's portal UI has
	// necessarily delivered a first frame. It is the only RTSP control keepalive;
	// another serialized request could starve it if the receiver ignores that
	// request.
	select {
	case <-feedbackReceived:
	case <-ctx.Done():
		t.Fatal("timed out waiting for immediate /feedback")
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	wantMethods := []string{"SETUP", "SETUP", "SETUP"}
	recordIndex := -1
	if !skipRecord {
		recordIndex = len(wantMethods)
		wantMethods = append(wantMethods, "RECORD")
	}
	// The two volume SET_PARAMETERs are sent only when the session carries
	// audio: `volume: 0.000000` is 0 dB — full scale — so a video-only
	// session would force the receiver to maximum.
	if !noAudio {
		wantMethods = append(wantMethods, "SET_PARAMETER", "SET_PARAMETER")
	}
	wantMethods = append(wantMethods, "POST", "TEARDOWN")
	got := make([]rtspTestRequest, 0, len(wantMethods))
	for range wantMethods {
		select {
		case req := <-requests:
			got = append(got, req)
		case <-ctx.Done():
			t.Fatal("timed out collecting RTSP requests")
		}
	}
	for index, want := range wantMethods {
		if got[index].method != want {
			t.Fatalf("request %d = %s, want %s", index, got[index].method, want)
		}
	}
	const audioIndex = 1
	const videoIndex = 2
	if got[0].uri != got[audioIndex].uri {
		t.Fatal("control-first probe should use the audio session URI")
	}
	if got[audioIndex].uri == got[videoIndex].uri {
		t.Fatal("video SETUP should use a distinct URI from the audio control session")
	}
	for index := videoIndex + 1; index < len(got); index++ {
		if got[index].method == "POST" {
			if got[index].uri != "/feedback" {
				t.Fatalf("feedback URI = %s, want /feedback", got[index].uri)
			}
			continue
		}
		if got[index].uri != got[audioIndex].uri {
			t.Fatalf("request %d URI = %s, want audio session URI %s", index, got[index].uri, got[audioIndex].uri)
		}
	}
	if recordIndex >= 0 {
		for header, want := range map[string]string{
			"range":    "npt=0-",
			"rtp-info": "seq=0;rtptime=0",
		} {
			if gotValue := got[recordIndex].headers[header]; gotValue != want {
				t.Fatalf("RECORD %s = %q, want %q", header, gotValue, want)
			}
		}
	}

	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func probeNTPTiming(port int) error {
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	if err != nil {
		return fmt.Errorf("dial timing port: %w", err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}

	request := make([]byte, 32)
	request[0], request[1] = 0x80, 0xd2
	const transmit = uint64(secondsFrom1900To1970)<<32 | 0x12345678
	binary.BigEndian.PutUint64(request[24:32], transmit)
	if _, err := conn.Write(request); err != nil {
		return fmt.Errorf("write timing probe: %w", err)
	}

	reply := make([]byte, 32)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("read timing response: %w", err)
	}
	if reply[0] != 0x80 || reply[1] != 0xd3 {
		return fmt.Errorf("timing response type = %02x%02x, want 80d3", reply[0], reply[1])
	}
	if got := binary.BigEndian.Uint64(reply[8:16]); got != transmit {
		return fmt.Errorf("timing reference = 0x%016x, want 0x%016x", got, transmit)
	}
	for _, offset := range []int{16, 24} {
		if seconds := binary.BigEndian.Uint64(reply[offset:offset+8]) >> 32; seconds < secondsFrom1900To1970 {
			return fmt.Errorf("timing timestamp at %d has seconds %d, want NTP epoch or later", offset, seconds)
		}
	}
	return nil
}

func readRTSPTestRequest(reader *bufio.Reader) (rtspTestRequest, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return rtspTestRequest{}, err
	}
	line = strings.TrimSpace(line)
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return rtspTestRequest{}, fmt.Errorf("malformed request line %q", line)
	}

	headers := make(map[string]string)
	contentLength := 0
	for {
		headerLine, err := reader.ReadString('\n')
		if err != nil {
			return rtspTestRequest{}, err
		}
		headerLine = strings.TrimSpace(headerLine)
		if headerLine == "" {
			break
		}
		name, value, found := strings.Cut(headerLine, ":")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		headers[strings.ToLower(name)] = value
		if strings.EqualFold(name, "Content-Length") {
			contentLength, err = strconv.Atoi(value)
			if err != nil {
				return rtspTestRequest{}, fmt.Errorf("invalid content length %q: %w", value, err)
			}
		}
	}

	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return rtspTestRequest{}, err
	}

	return rtspTestRequest{
		method:  parts[0],
		uri:     parts[1],
		body:    body,
		headers: headers,
	}, nil
}

func writeRTSPTestResponse(conn net.Conn, status int, headers map[string]string, body []byte) error {
	if headers == nil {
		headers = make(map[string]string)
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "RTSP/1.0 %d %s\r\n", status, rtspStatusText(status))
	for key, value := range headers {
		fmt.Fprintf(&builder, "%s: %s\r\n", key, value)
	}
	fmt.Fprintf(&builder, "Content-Length: %d\r\n\r\n", len(body))
	if _, err := conn.Write([]byte(builder.String())); err != nil {
		return err
	}
	if len(body) > 0 {
		_, err := conn.Write(body)
		return err
	}
	return nil
}

func rtspStatusText(status int) string {
	switch status {
	case 200:
		return "OK"
	case 455:
		return "Method Not Valid in This State"
	default:
		return "Status"
	}
}
