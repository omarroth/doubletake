package airplay

import (
	"bytes"
	"context"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"howett.net/plist"
)

func TestReceiverServerEndToEndProfiles(t *testing.T) {
	for _, test := range []struct {
		name          string
		profile       ReceiverProfile
		wantEncrypted bool
		wantSetups    uint64
		wantFairPlay  uint64
		wantTiming    uint64
		wantEvents    uint64
	}{
		{name: "modern Apple HAP accepts control-first PTP", profile: ReceiverProfileModern, wantEncrypted: true, wantSetups: 3, wantFairPlay: 2, wantEvents: 1},
		{name: "Roku raw negotiates media-first receiver-initiated NTP", profile: ReceiverProfileRoku, wantSetups: 3, wantTiming: 3, wantEvents: 1},
		{name: "LG HAP negotiates media-first PTP", profile: ReceiverProfileLG, wantEncrypted: true, wantSetups: 3, wantEvents: 1},
		{name: "AppleTV3 raw negotiates media-first receiver-initiated NTP", profile: ReceiverProfileAppleTV3, wantSetups: 3, wantFairPlay: 2, wantTiming: 3, wantEvents: 1},
		{name: "UxPlay legacy negotiates media-first without eventPort", profile: ReceiverProfileUxPlay, wantSetups: 3, wantFairPlay: 2, wantTiming: 3},
		{name: "AirServer raw control-first with descriptor retry", profile: ReceiverProfileAirServer, wantSetups: 4, wantFairPlay: 2, wantTiming: 3, wantEvents: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			name := "renamed-" + string(test.profile)
			model := "UnrelatedModel-" + string(test.profile)
			manufacturer := "Independent Vendor " + string(test.profile)
			server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
				Profile:      test.profile,
				Auth:         ReceiverAuthNone,
				Name:         name,
				Model:        model,
				Manufacturer: manufacturer,
			})
			if client.info.Name != name || client.info.Model != model || client.info.Manufacturer != manufacturer {
				t.Fatalf("receiver identity = %q/%q/%q, want randomized %q/%q/%q",
					client.info.Name, client.info.Model, client.info.Manufacturer, name, model, manufacturer)
			}

			if err := client.Pair(ctx, ""); err != nil {
				t.Fatalf("pair: %v", err)
			}
			if client.encrypted != test.wantEncrypted {
				t.Fatalf("encrypted control = %t, want %t", client.encrypted, test.wantEncrypted)
			}
			if client.info.SupportsFairPlaySAP() {
				if err := client.FairPlaySetup(ctx); err != nil {
					t.Fatalf("FairPlay setup: %v", err)
				}
			}

			session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
			if err != nil {
				t.Fatalf("setup mirror: %v", err)
			}
			if test.profile == ReceiverProfileUxPlay && session.eventConn != nil {
				t.Fatal("UxPlay-compatible session unexpectedly opened an unadvertised event channel")
			}
			// Media accepts and sender-initiated AirServer timing probes run in
			// separate goroutines. Let those observable side effects settle before
			// closing the session and folding its counters into the server totals.
			deadline := time.Now().Add(time.Second)
			stats := server.Stats()
			for (stats.EventConnections != test.wantEvents || stats.VideoConnections != 1 ||
				stats.TimingProbes < test.wantTiming || stats.TimingReplies < test.wantTiming) && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
				stats = server.Stats()
			}
			if err := session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close mirror session: %v", err)
			}
			stats = server.Stats()
			if stats.SetupRequests != test.wantSetups {
				t.Fatalf("SETUP requests = %d, want %d", stats.SetupRequests, test.wantSetups)
			}
			if stats.RecordRequests != 1 || stats.FeedbackRequests < 1 || stats.TeardownRequests != 1 {
				t.Fatalf("control stats = %+v", stats)
			}
			if stats.FairPlayRequests != test.wantFairPlay {
				t.Fatalf("FairPlay requests = %d, want %d", stats.FairPlayRequests, test.wantFairPlay)
			}
			if stats.EventConnections != test.wantEvents || stats.VideoConnections != 1 {
				t.Fatalf("media connections = %+v", stats)
			}
			if stats.TimingProbes != test.wantTiming || stats.TimingReplies != test.wantTiming {
				t.Fatalf("timing stats = %+v, want %d probes/replies", stats, test.wantTiming)
			}
			server.mediaMu.Lock()
			activeMedia := len(server.activeMedia)
			server.mediaMu.Unlock()
			if activeMedia != 0 {
				t.Fatalf("active media sessions after Close = %d, want 0", activeMedia)
			}
		})
	}
}

func TestReceiverServerDecryptsLegacyFairPlayVideo(t *testing.T) {
	for _, profile := range []ReceiverProfile{ReceiverProfileAppleTV3, ReceiverProfileUxPlay} {
		t.Run(string(profile), func(t *testing.T) {
			server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: profile})
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatalf("pair: %v", err)
			}
			if err := client.FairPlaySetup(ctx); err != nil {
				t.Fatalf("FairPlay setup: %v", err)
			}
			session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
			if err != nil {
				t.Fatalf("setup mirror: %v", err)
			}
			if session.streamCipher == nil {
				t.Fatal("legacy FairPlay session did not configure its AES-CTR cipher")
			}

			frame := session.streamCipher(receiverTestAVCC([]byte{0x65, 0x80}))
			timestamp, timeline := session.frameTimeNow()
			if err := session.sendFrame(frame, true, timestamp, timeline); err != nil {
				t.Fatalf("send encrypted legacy frame: %v", err)
			}

			deadline := time.Now().Add(time.Second)
			stats := server.Stats()
			for stats.VideoDecrypted == 0 && stats.VideoCryptoErrors == 0 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
				stats = server.Stats()
			}
			if stats.VideoDecrypted != 1 || stats.VideoCryptoErrors != 0 {
				t.Fatalf("legacy video crypto stats = %+v, want one decrypted frame and no errors", stats)
			}
			if err := session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				t.Fatalf("close mirror session: %v", err)
			}
		})
	}
}

func TestReceiverProfilePresets(t *testing.T) {
	tests := []struct {
		profile                  ReceiverProfile
		model                    string
		sourceVersion            string
		features                 uint64
		pairing                  receiverPairingProfile
		order                    receiverSetupOrder
		timing                   string
		ntpInitiator             receiverNTPInitiator
		ptpInfo                  bool
		ptpClockIdentity         bool
		ptpClockHeaders          bool
		audioConnectionsWithHAP  bool
		audioResponseConnections bool
		audioCodec               AudioCodec
		supportedScreenFormats   uint64
		audioSHKWithHAP          bool
		fairPlayRoot             bool
		legacyVideoKey           receiverLegacyVideoKeyMode
		omitEventPort            bool
		displayWidth             int
		displayHeight            int
		displayMaxWidth          int
		displayMaxHeight         int
		displayRequiresSession   bool
	}{
		{ReceiverProfileModern, "AppleTV14,1", modernAirPlaySourceVersion, 0x3c177fde4a7fdfd5, receiverPairingModern,
			receiverSetupSessionFirst, timingProtocolPTP, receiverNTPNone, false, true, true, true, true,
			AudioCodecALAC, 0x40000, true, false, receiverLegacyVideoNone, false, 1920, 1080, 3840, 2160, true},
		{ReceiverProfileRoku, "3820R2", "377.40.00", 0x038bcf46007f8ad0, receiverPairingLegacy,
			receiverSetupMediaFirst, timingProtocolNTP, receiverNTPReceiver, true, false, false, true, true,
			AudioCodecALAC, 0x40000, true, false, receiverLegacyVideoNone, false, 1920, 1080, 0, 0, false},
		{ReceiverProfileLG, "75UP75009LC", "377.25.06", 0x038bcb46007f8ad0, receiverPairingLegacyHAP,
			receiverSetupMediaFirst, timingProtocolPTP, receiverNTPNone, true, true, false, false, false,
			AudioCodecALAC, 0x40000, true, false, receiverLegacyVideoNone, false, 1920, 1080, 0, 0, false},
		{ReceiverProfileAppleTV3, "AppleTV3,2", "220.68", 0x1e5a7ffff7, receiverPairingLegacy,
			receiverSetupMediaFirst, timingProtocolNTP, receiverNTPReceiver, false, false, false, false, false,
			AudioCodecALAC, 0x40000, false, true, receiverLegacyVideoRaw, false, 0, 0, 0, 0, false},
		{ReceiverProfileUxPlay, "AppleTV3,2", "220.68", 0x527ffee6, receiverPairingLegacy,
			receiverSetupMediaFirst, timingProtocolNTP, receiverNTPReceiver, false, false, false, false, false,
			AudioCodecALAC, 0x40000, false, true, receiverLegacyVideoMixed, true, 1920, 1080, 0, 0, false},
		{ReceiverProfileAirServer, "AppleTV5,3", "375.3", 0x3c177fde4a7fdfd5, receiverPairingLegacy,
			receiverSetupSessionFirst, timingProtocolNTP, receiverNTPSender, false, false, false, true, false,
			AudioCodecAACELD, 0x1000000, true, true, receiverLegacyVideoNone, false, 0, 0, 0, 0, false},
	}
	for _, test := range tests {
		t.Run(string(test.profile), func(t *testing.T) {
			got, err := receiverProfile(test.profile)
			if err != nil {
				t.Fatalf("receiverProfile: %v", err)
			}
			if got.model != test.model || got.sourceVersion != test.sourceVersion ||
				got.features != test.features || got.pairing != test.pairing ||
				got.setupOrder != test.order || got.timingProtocol != test.timing || got.ntpInitiator != test.ntpInitiator ||
				got.advertisePTPInfo != test.ptpInfo ||
				got.providePTPClockIdentity != test.ptpClockIdentity ||
				got.providePTPClockHeaders != test.ptpClockHeaders ||
				got.audioConnectionsWithHAP != test.audioConnectionsWithHAP ||
				got.audioResponseConnections != test.audioResponseConnections || got.audioCodec != test.audioCodec ||
				got.supportedScreenFormats != test.supportedScreenFormats ||
				got.audioSHKWithHAP != test.audioSHKWithHAP ||
				got.fairPlayRootKeys != test.fairPlayRoot || got.legacyVideoKey != test.legacyVideoKey ||
				got.omitEventPort != test.omitEventPort ||
				got.displayWidth != test.displayWidth ||
				got.displayHeight != test.displayHeight ||
				got.displayMaxWidth != test.displayMaxWidth ||
				got.displayMaxHeight != test.displayMaxHeight ||
				got.displayRequiresSession != test.displayRequiresSession {
				t.Fatalf("profile = %+v", got)
			}
		})
	}

}

func TestReceiverLegacyVideoMasterKeyProfiles(t *testing.T) {
	rawKey := bytes.Repeat([]byte{0xa5}, 16)
	pairSecret := bytes.Repeat([]byte{0x5a}, 32)
	digest := sha512.Sum512(append(append([]byte(nil), rawKey...), pairSecret...))

	raw, err := receiverLegacyVideoMasterKey(receiverLegacyVideoRaw, rawKey, pairSecret)
	if err != nil {
		t.Fatalf("derive AppleTV3 key: %v", err)
	}
	if !bytes.Equal(raw, rawKey) {
		t.Fatalf("AppleTV3 master = %x, want raw key %x", raw, rawKey)
	}
	mixed, err := receiverLegacyVideoMasterKey(receiverLegacyVideoMixed, rawKey, pairSecret)
	if err != nil {
		t.Fatalf("derive UxPlay key: %v", err)
	}
	if !bytes.Equal(mixed, digest[:16]) {
		t.Fatalf("UxPlay master = %x, want SHA-512 mixture %x", mixed, digest[:16])
	}
	if bytes.Equal(raw, mixed) {
		t.Fatal("AppleTV3 raw and UxPlay mixed branches produced the same key")
	}
	if _, err := receiverLegacyVideoMasterKey(receiverLegacyVideoMixed, rawKey, nil); err == nil {
		t.Fatal("UxPlay key derivation accepted a missing pair-verify secret")
	}
}

func TestReceiverSetupResponseEventPortPolicy(t *testing.T) {
	endpoints := receiverMediaEndpoints{EventPort: 49152}

	appleTV3, err := receiverProfile(ReceiverProfileAppleTV3)
	if err != nil {
		t.Fatal(err)
	}
	if got := plistInt(receiverSetupResponse(appleTV3, endpoints)["eventPort"]); got != endpoints.EventPort {
		t.Fatalf("AppleTV3 eventPort = %d, want %d", got, endpoints.EventPort)
	}

	uxplay, err := receiverProfile(ReceiverProfileUxPlay)
	if err != nil {
		t.Fatal(err)
	}
	response := receiverSetupResponse(uxplay, endpoints)
	if _, present := response["eventPort"]; present {
		t.Fatalf("UxPlay response advertised eventPort: %+v", response)
	}
	if skipRecord, ok := response["skipRecord"].(bool); !ok || skipRecord {
		t.Fatalf("UxPlay skipRecord = %#v, want false", response["skipRecord"])
	}
}

func TestReceiverServerCombinedControlSetupReturnsSessionInfo(t *testing.T) {
	for _, test := range []struct {
		name        string
		requestInfo bool
	}{
		{name: "ordinary control SETUP"},
		{name: "combined control SETUP", requestInfo: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileModern})
			if len(client.info.Displays) != 0 {
				t.Fatalf("pre-session /info displays = %#v, want omitted", client.info.Displays)
			}
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatalf("pair: %v", err)
			}
			if err := client.FairPlaySetup(ctx); err != nil {
				t.Fatalf("FairPlay setup: %v", err)
			}

			peer := map[string]any{
				"ID":                                "sender-clock",
				"DeviceType":                        int64(0),
				"Addresses":                         []any{"127.0.0.1"},
				"SupportsClockPortMatchingOverride": true,
			}
			request := map[string]any{
				"isScreenMirroringSession": true,
				"sessionUUID":              "combined-info-test",
				"timingProtocol":           timingProtocolPTP,
				"timingPeerInfo":           peer,
				"timingPeerList":           []any{peer},
			}
			if test.requestInfo {
				request["combinedGetInfoWithControlSetup"] = true
			}
			body, err := plist.Marshal(request, plist.BinaryFormat)
			if err != nil {
				t.Fatalf("marshal control SETUP: %v", err)
			}
			responseBody, _, err := client.rtspRequest(
				"SETUP", "/combined-info-test", "application/x-apple-binary-plist", body, nil,
			)
			if err != nil {
				t.Fatalf("control SETUP: %v", err)
			}
			var response map[string]any
			if _, err := plist.Unmarshal(responseBody, &response); err != nil {
				t.Fatalf("decode control SETUP response: %v", err)
			}
			info, hasInfo := response["info"].(map[string]any)
			if hasInfo != test.requestInfo {
				t.Fatalf("response info presence = %t, want %t: %#v", hasInfo, test.requestInfo, response)
			}
			if !test.requestInfo {
				if _, ok := response["eventPort"]; !ok {
					t.Fatalf("ordinary SETUP response lost its eventPort fallback shape: %#v", response)
				}
				return
			}

			displays, ok := info["displays"].([]any)
			if !ok || len(displays) != 1 {
				t.Fatalf("session info displays = %#v, want one display", info["displays"])
			}
			display, ok := displays[0].(map[string]any)
			if !ok {
				t.Fatalf("session display = %#v, want dictionary", displays[0])
			}
			if gotW, gotH := plistInt(display["widthPixels"]), plistInt(display["heightPixels"]); gotW != 1920 || gotH != 1080 {
				t.Fatalf("session display nominal size = %dx%d, want 1920x1080", gotW, gotH)
			}
			if gotW, gotH := plistInt(display["widthPixelsMax"]), plistInt(display["heightPixelsMax"]); gotW != 3840 || gotH != 2160 {
				t.Fatalf("session display maximum size = %dx%d, want 3840x2160", gotW, gotH)
			}
			if got := info["sourceVersion"]; got != modernAirPlaySourceVersion {
				t.Fatalf("session info sourceVersion = %#v, want %q", got, modernAirPlaySourceVersion)
			}
		})
	}
}

func TestSetupMirrorPreparesVideoFromSessionDisplayInfo(t *testing.T) {
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileModern})
	if width, height := client.info.MirrorSize(); width != 1280 || height != 720 {
		t.Fatalf("pre-session mirror size = %dx%d, want provisional 1280x720", width, height)
	}
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	if err := client.FairPlaySetup(ctx); err != nil {
		t.Fatalf("FairPlay setup: %v", err)
	}

	callbackCount := 0
	session, err := client.SetupMirrorWithVideoPreparation(ctx, StreamConfig{NoAudio: true}, func(width, height int) error {
		callbackCount++
		if width != 1920 || height != 1080 {
			return fmt.Errorf("resolved mirror size = %dx%d, want 1920x1080", width, height)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	defer session.Close()
	if callbackCount != 1 {
		t.Fatalf("video preparation callbacks = %d, want 1", callbackCount)
	}
	if width, height := client.info.DisplaySize(); width != 1920 || height != 1080 {
		t.Fatalf("session display size = %dx%d, want 1920x1080", width, height)
	}
	if width, height := client.info.MaxVideoSize(); width != 3840 || height != 2160 {
		t.Fatalf("session maximum = %dx%d, want 3840x2160", width, height)
	}
}

func TestSetupMirrorAutomaticallySelectsHEVCFromSessionDisplayInfo(t *testing.T) {
	SetTargetLatency(0)
	t.Cleanup(func() { SetTargetLatency(0) })
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileModern})
	if width, height := client.info.MaxVideoSize(); width != 1280 || height != 720 {
		t.Fatalf("pre-session maximum = %dx%d, want provisional 1280x720", width, height)
	}
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	if err := client.FairPlaySetup(ctx); err != nil {
		t.Fatalf("FairPlay setup: %v", err)
	}

	callbackCount := 0
	session, err := client.SetupMirrorWithVideoCodecPreparation(ctx, StreamConfig{
		VideoCodec:             VideoCodecAuto,
		AutomaticHEVCAvailable: true,
		MeasuredVideoLatency:   150 * time.Millisecond,
	}, func(width, height int, codec VideoCodec) error {
		callbackCount++
		if codec != VideoCodecHEVC || width != 3840 || height != 2160 {
			return fmt.Errorf("automatic selection = %s %dx%d, want HEVC 3840x2160", codec, width, height)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	defer session.Close()
	if callbackCount != 1 {
		t.Fatalf("video preparation callbacks = %d, want 1", callbackCount)
	}
	if session.videoCodec != VideoCodecHEVC {
		t.Fatalf("session codec = %s, want HEVC", session.videoCodec)
	}
	if session.timestampBias != 150*time.Millisecond {
		t.Fatalf("session video lead = %v, want calibrated 150ms", session.timestampBias)
	}
	if session.audioStream == nil || session.audioStream.latencySamples != samplesFor44k1(160*time.Millisecond) {
		t.Fatalf("session audio lead = %#v, want calibrated 160ms (%d samples)", session.audioStream, samplesFor44k1(160*time.Millisecond))
	}
}

func TestLiveHEVCCaptureLeadIsCommittedBeforeMediaSetup(t *testing.T) {
	tests := []struct {
		name          string
		preflight     time.Duration
		live          time.Duration
		override      time.Duration
		wantVideoLead time.Duration
		wantAudioLead time.Duration
	}{
		{
			name: "live measurement raises preflight", preflight: 150 * time.Millisecond, live: 175 * time.Millisecond,
			wantVideoLead: 175 * time.Millisecond, wantAudioLead: 185 * time.Millisecond,
		},
		{
			name: "live measurement cannot lower preflight", preflight: 150 * time.Millisecond, live: 120 * time.Millisecond,
			wantVideoLead: 150 * time.Millisecond, wantAudioLead: 160 * time.Millisecond,
		},
		{
			name: "explicit joint target wins", preflight: 150 * time.Millisecond, live: 200 * time.Millisecond, override: 100 * time.Millisecond,
			wantVideoLead: 100 * time.Millisecond, wantAudioLead: 100 * time.Millisecond,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetTargetLatency(test.override)
			t.Cleanup(func() { SetTargetLatency(0) })
			_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileModern})
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatalf("pair: %v", err)
			}
			if err := client.FairPlaySetup(ctx); err != nil {
				t.Fatalf("FairPlay setup: %v", err)
			}
			session, err := client.SetupMirrorWithCalibratedVideoPreparation(ctx, StreamConfig{
				VideoCodec:             VideoCodecAuto,
				AutomaticHEVCAvailable: true,
				MeasuredVideoLatency:   test.preflight,
			}, func(_, _ int, codec VideoCodec) (VideoPreparationResult, error) {
				if codec != VideoCodecHEVC {
					return VideoPreparationResult{}, fmt.Errorf("selected codec = %s, want HEVC", codec)
				}
				return VideoPreparationResult{MinimumVideoLead: test.live}, nil
			})
			if err != nil {
				t.Fatalf("setup mirror: %v", err)
			}
			defer session.Close()
			if session.timestampBias != test.wantVideoLead {
				t.Fatalf("video lead = %v, want %v", session.timestampBias, test.wantVideoLead)
			}
			wantSamples := samplesFor44k1(test.wantAudioLead)
			if session.audioStream == nil || session.audioStream.latencySamples != wantSamples {
				t.Fatalf("audio lead = %#v, want %d samples", session.audioStream, wantSamples)
			}
		})
	}
}

func TestMeasuredHEVCLatencyIsScopedAndExplicitOverrideWins(t *testing.T) {
	tests := []struct {
		name          string
		requested     VideoCodec
		override      time.Duration
		wantCodec     VideoCodec
		wantVideoLead time.Duration
		wantAudioLead time.Duration
	}{
		{
			name: "H264 ignores HEVC measurement", requested: VideoCodecH264,
			wantCodec: VideoCodecH264, wantVideoLead: 75 * time.Millisecond, wantAudioLead: 85 * time.Millisecond,
		},
		{
			name: "joint override wins", requested: VideoCodecAuto, override: 100 * time.Millisecond,
			wantCodec: VideoCodecHEVC, wantVideoLead: 100 * time.Millisecond, wantAudioLead: 100 * time.Millisecond,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetTargetLatency(test.override)
			t.Cleanup(func() { SetTargetLatency(0) })
			_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileModern})
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatalf("pair: %v", err)
			}
			if err := client.FairPlaySetup(ctx); err != nil {
				t.Fatalf("FairPlay setup: %v", err)
			}
			session, err := client.SetupMirrorWithVideoCodecPreparation(ctx, StreamConfig{
				VideoCodec:             test.requested,
				AutomaticHEVCAvailable: true,
				MeasuredVideoLatency:   150 * time.Millisecond,
			}, func(_, _ int, codec VideoCodec) error {
				if codec != test.wantCodec {
					return fmt.Errorf("selected codec = %s, want %s", codec, test.wantCodec)
				}
				return nil
			})
			if err != nil {
				t.Fatalf("setup mirror: %v", err)
			}
			defer session.Close()
			if session.timestampBias != test.wantVideoLead {
				t.Fatalf("video lead = %v, want %v", session.timestampBias, test.wantVideoLead)
			}
			wantSamples := samplesFor44k1(test.wantAudioLead)
			if session.audioStream == nil || session.audioStream.latencySamples != wantSamples {
				t.Fatalf("audio lead = %#v, want %d samples", session.audioStream, wantSamples)
			}
		})
	}
}

func TestMediaFirstAutoFallsBackBeforeCreatingLatencyMismatch(t *testing.T) {
	SetTargetLatency(0)
	t.Cleanup(func() { SetTargetLatency(0) })
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku, DisplayWidth: 3840, DisplayHeight: 2160,
	})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	session, err := client.SetupMirrorWithVideoCodecPreparation(ctx, StreamConfig{
		VideoCodec:             VideoCodecAuto,
		AutomaticHEVCAvailable: true,
		MeasuredVideoLatency:   150 * time.Millisecond,
	}, func(_, _ int, codec VideoCodec) error {
		if codec != VideoCodecH264 {
			return fmt.Errorf("media-first codec = %s, want coherent H.264 fallback", codec)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	defer session.Close()
	if session.videoCodec != VideoCodecH264 || session.timestampBias != defaultVideoLatencyNormal {
		t.Fatalf("media-first session = codec %s lead %v, want H.264/%v", session.videoCodec, session.timestampBias, defaultVideoLatencyNormal)
	}
	if session.audioStream == nil || session.audioStream.latencySamples != samplesFor44k1(defaultAudioLatencyNormal) {
		t.Fatalf("media-first audio lead = %#v, want %d samples", session.audioStream, samplesFor44k1(defaultAudioLatencyNormal))
	}
}

func TestMediaFirstRelayLeadPreservesAutomaticHEVC(t *testing.T) {
	SetTargetLatency(0)
	t.Cleanup(func() { SetTargetLatency(0) })
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku, DisplayWidth: 3840, DisplayHeight: 2160,
	})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	session, err := client.SetupMirrorWithVideoCodecPreparation(ctx, StreamConfig{
		VideoCodec:             VideoCodecAuto,
		AutomaticHEVCAvailable: true,
		MinimumVideoLead:       250 * time.Millisecond,
	}, func(_, _ int, codec VideoCodec) error {
		if codec != VideoCodecHEVC {
			return fmt.Errorf("media-first relay codec = %s, want HEVC", codec)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	defer session.Close()
	if session.videoCodec != VideoCodecHEVC || session.timestampBias != 250*time.Millisecond {
		t.Fatalf("media-first relay session = codec %s lead %v, want HEVC/250ms", session.videoCodec, session.timestampBias)
	}
	if session.audioStream == nil || session.audioStream.latencySamples != samplesFor44k1(260*time.Millisecond) {
		t.Fatalf("media-first relay audio lead = %#v, want %d samples", session.audioStream, samplesFor44k1(260*time.Millisecond))
	}
}

func TestMediaFirstCalibratedAutoFallsBackBeforeLiveMeasurement(t *testing.T) {
	SetTargetLatency(0)
	t.Cleanup(func() { SetTargetLatency(0) })
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku, DisplayWidth: 3840, DisplayHeight: 2160,
	})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	var preparedCodec VideoCodec
	session, err := client.SetupMirrorWithCalibratedVideoPreparation(ctx, StreamConfig{
		VideoCodec:             VideoCodecAuto,
		AutomaticHEVCAvailable: true,
	}, func(_, _ int, codec VideoCodec) (VideoPreparationResult, error) {
		preparedCodec = codec
		if codec == VideoCodecHEVC {
			return VideoPreparationResult{MinimumVideoLead: 175 * time.Millisecond}, nil
		}
		return VideoPreparationResult{}, nil
	})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	defer session.Close()
	if preparedCodec != VideoCodecH264 || session.videoCodec != VideoCodecH264 {
		t.Fatalf("media-first calibrated codec = prepared %s/session %s, want H.264", preparedCodec, session.videoCodec)
	}
	if session.timestampBias != defaultVideoLatencyNormal || session.audioStream == nil ||
		session.audioStream.latencySamples != samplesFor44k1(defaultAudioLatencyNormal) {
		t.Fatalf("media-first calibrated leads = video %v audio %#v, want nominal coherent policy", session.timestampBias, session.audioStream)
	}
}

func TestMediaFirstForcedHEVCRejectsLateLiveLead(t *testing.T) {
	SetTargetLatency(0)
	t.Cleanup(func() { SetTargetLatency(0) })
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku, DisplayWidth: 3840, DisplayHeight: 2160,
	})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	_, err := client.SetupMirrorWithCalibratedVideoPreparation(ctx, StreamConfig{
		VideoCodec: VideoCodecHEVC,
	}, func(_, _ int, codec VideoCodec) (VideoPreparationResult, error) {
		if codec != VideoCodecHEVC {
			return VideoPreparationResult{}, fmt.Errorf("prepared codec = %s, want HEVC", codec)
		}
		return VideoPreparationResult{MinimumVideoLead: 175 * time.Millisecond}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "media-first audio SETUP already committed") {
		t.Fatalf("forced media-first HEVC setup = %v, want coherent late-lead rejection", err)
	}
}

func TestSetupMirrorRefreshesSessionInfoWhenCombinedResponseOmitsIt(t *testing.T) {
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile:          ReceiverProfileModern,
		OmitCombinedInfo: true,
	})
	// Model a receiver which publishes a usable but provisional canvas before
	// its media session exists. Its nonzero size must not suppress the
	// post-control refresh.
	client.info.Displays = []DisplayInfo{{
		WidthPixels:     1280,
		HeightPixels:    720,
		WidthPixelsMax:  1280,
		HeightPixelsMax: 720,
	}}
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	if err := client.FairPlaySetup(ctx); err != nil {
		t.Fatalf("FairPlay setup: %v", err)
	}

	callbackCount := 0
	session, err := client.SetupMirrorWithVideoPreparation(ctx, StreamConfig{NoAudio: true}, func(width, height int) error {
		callbackCount++
		if width != 1920 || height != 1080 {
			return fmt.Errorf("refreshed mirror size = %dx%d, want 1920x1080", width, height)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	defer session.Close()
	if callbackCount != 1 {
		t.Fatalf("video preparation callbacks = %d, want 1", callbackCount)
	}
	if got := server.Stats().InfoRequests; got != 2 {
		t.Fatalf("GET /info requests = %d, want initial plus one post-session refresh", got)
	}
	if width, height := client.info.MaxVideoSize(); width != 3840 || height != 2160 {
		t.Fatalf("refreshed maximum = %dx%d, want 3840x2160", width, height)
	}
}

func TestReceiverServerAdvertisesCapabilityAxes(t *testing.T) {
	for _, test := range []struct {
		profile          ReceiverProfile
		sourceVersion    string
		wantPTPFeature   bool
		wantConnections  bool
		wantLegacyPair   bool
		wantPTPInfo      bool
		wantDisplay      bool
		supportedFormats uint64
	}{
		{profile: ReceiverProfileModern, sourceVersion: modernAirPlaySourceVersion, wantPTPFeature: true, wantConnections: true, wantLegacyPair: true, supportedFormats: 0x40000},
		{profile: ReceiverProfileRoku, sourceVersion: "377.40.00", wantPTPFeature: true, wantPTPInfo: true, wantDisplay: true, supportedFormats: 0x40000},
		{profile: ReceiverProfileLG, sourceVersion: "377.25.06", wantPTPFeature: true, wantPTPInfo: true, wantDisplay: true, supportedFormats: 0x40000},
		{profile: ReceiverProfileAppleTV3, sourceVersion: "220.68", wantLegacyPair: true, supportedFormats: 0x40000},
		{profile: ReceiverProfileUxPlay, sourceVersion: "220.68", wantDisplay: true, supportedFormats: 0x40000},
		{profile: ReceiverProfileAirServer, sourceVersion: "375.3", wantPTPFeature: true, wantConnections: true, wantLegacyPair: true, supportedFormats: 0x1000000},
	} {
		t.Run(string(test.profile), func(t *testing.T) {
			server, client, _ := newReceiverServerTestPair(t, ReceiverConfig{Profile: test.profile})
			if client.info.SourceVersion != test.sourceVersion {
				t.Fatalf("sourceVersion = %q, want %q", client.info.SourceVersion, test.sourceVersion)
			}
			if client.info.Features != server.profile.features {
				t.Fatalf("features = 0x%x, want profile bits 0x%x", client.info.Features, server.profile.features)
			}
			if client.info.HasFeature(featurePTP) != test.wantPTPFeature {
				t.Fatalf("feature 41 = %t, want %t", client.info.HasFeature(featurePTP), test.wantPTPFeature)
			}
			if client.info.HasFeature(featureAudioStreamConnectionSetup) != test.wantConnections {
				t.Fatalf("feature 59 = %t, want %t", client.info.HasFeature(featureAudioStreamConnectionSetup), test.wantConnections)
			}
			if client.info.SupportsLegacyPairing() != test.wantLegacyPair {
				t.Fatalf("feature 27 = %t, want %t", client.info.SupportsLegacyPairing(), test.wantLegacyPair)
			}
			if got := uint64(client.info.SupportedFormats.ScreenStream); got != test.supportedFormats {
				t.Fatalf("supportedFormats.screenStream = 0x%x, want 0x%x", got, test.supportedFormats)
			}
			if client.info.hasPTPInfo != test.wantPTPInfo {
				t.Fatalf("hasPTPInfo = %t, want %t", client.info.hasPTPInfo, test.wantPTPInfo)
			}
			if (len(client.info.Displays) > 0) != test.wantDisplay {
				t.Fatalf("display count = %d, want display=%t", len(client.info.Displays), test.wantDisplay)
			}
		})
	}
}

func TestReceiverServerCombinedCodePairsAndAnswersDigest(t *testing.T) {
	const code = "password with spaces"
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku,
		Auth:    ReceiverAuthCombined,
		Code:    code,
	})

	if !client.info.RequiresPassword() {
		t.Fatal("combined receiver did not advertise a configured password")
	}
	if client.info.RequiresPINPairing() {
		t.Fatal("combined password receiver unexpectedly advertised an on-screen PIN")
	}
	if err := client.Pair(ctx, code); err != nil {
		t.Fatalf("pair with combined code: %v", err)
	}
	if !client.encrypted {
		t.Fatal("code pairing did not establish encrypted HAP control")
	}
	session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
	if err != nil {
		t.Fatalf("Digest-protected setup: %v", err)
	}
	if err := session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close mirror session: %v", err)
	}

	stats := server.Stats()
	if stats.DigestChallenges != 1 {
		t.Fatalf("Digest challenges = %d, want exactly 1", stats.DigestChallenges)
	}
	// The profile deliberately omits feature 59 while requiring encrypted
	// streamConnections, exercising the sender's bounded descriptor negotiation:
	// controlPort is rejected once, then the alternate shape succeeds.
	if stats.PINStarts != 0 || stats.PairSetup != 3 || stats.PairVerify != 2 || stats.SetupRequests != 4 {
		t.Fatalf("combined auth stats = %+v", stats)
	}
	if got := server.stats.audioControlPort.Load(); got != 1 {
		t.Fatalf("controlPort audio descriptors = %d, want one initial capability-selected attempt", got)
	}
	if got := server.stats.audioConnections.Load(); got != 1 {
		t.Fatalf("streamConnections audio descriptors = %d, want one bounded alternate-layout retry", got)
	}
}

func TestReceiverServerHiddenDigestRequirementCanRetrySetup(t *testing.T) {
	const code = "legacy playback password"
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile:            ReceiverProfileRoku,
		Auth:               ReceiverAuthDigest,
		Code:               code,
		HidePasswordStatus: true,
	})

	if client.info.RequiresPassword() {
		t.Fatal("receiver advertised the deliberately hidden password requirement")
	}
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("transient pair: %v", err)
	}

	// A legacy receiver may reveal its configured playback password only when
	// SETUP is attempted. Nothing should be accepted before the caller obtains
	// that credential, and the error must be distinguishable from other setup
	// failures so an interactive caller can prompt once.
	if _, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true}); !errors.Is(err, ErrCredentialsRequired) {
		t.Fatalf("first setup error = %v, want ErrCredentialsRequired", err)
	}
	stats := server.Stats()
	if stats.DigestChallenges != 1 || stats.SetupRequests != 0 {
		t.Fatalf("first setup stats = %+v, want one challenge and no accepted SETUP", stats)
	}

	// Keep the paired connection and answer its cached challenge. SetupMirror
	// starts a fresh negotiation, whose absolute RTSP URI differs from the
	// challenged attempt; the client must recompute the Digest for that URI.
	client.SetPassword(code)
	session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
	if err != nil {
		t.Fatalf("retry setup with password: %v", err)
	}
	if err := session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close mirror session: %v", err)
	}

	stats = server.Stats()
	if stats.Connections != 1 {
		t.Fatalf("connections = %d, want same paired connection", stats.Connections)
	}
	if stats.DigestChallenges != 1 {
		t.Fatalf("Digest challenges = %d, want cached challenge reused without another 401", stats.DigestChallenges)
	}
	if stats.SetupRequests != 3 || stats.RecordRequests != 1 || stats.TeardownRequests != 1 {
		t.Fatalf("successful legacy session stats = %+v", stats)
	}
}

func TestReceiverServerRequiresPairVerifyBeforeSessionRequests(t *testing.T) {
	_, client, _ := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku,
		Auth:    ReceiverAuthNone,
	})

	for _, request := range []struct {
		name   string
		method string
		uri    string
		body   []byte
	}{
		{name: "SETUP", method: "SETUP", uri: "/session", body: receiverTestSetupBody(t, 96)},
		{name: "RECORD", method: "RECORD", uri: "/session"},
		{name: "SET_PARAMETER", method: "SET_PARAMETER", uri: "/session", body: []byte("volume: 0\r\n")},
		{name: "feedback", method: "POST", uri: "/feedback"},
		{name: "TEARDOWN", method: "TEARDOWN", uri: "/session"},
		{name: "FairPlay", method: "POST", uri: "/fp-setup", body: newFPSAPRecord(1, len(fpsapM1Payload))},
	} {
		t.Run(request.name, func(t *testing.T) {
			err := receiverTestRTSPRequest(client, request.method, request.uri, request.body)
			requireReceiverStatus(t, err, 455)
		})
	}
}

func TestReceiverServerEnforcesModernSessionOrder(t *testing.T) {
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileModern,
		Auth:    ReceiverAuthNone,
	})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	if err := client.FairPlaySetup(ctx); err != nil {
		t.Fatalf("FairPlay setup: %v", err)
	}

	requireReceiverStatus(t, receiverTestRTSPRequest(client, "SETUP", "/audio", receiverTestSetupBody(t, 96)), 455)
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "RECORD", "/session", nil), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SETUP", "/session", receiverTestSetupBody(t)))
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "SETUP", "/audio", receiverTestSetupBody(t, 96)), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "RECORD", "/session", nil))
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "SETUP", "/video", receiverTestSetupBody(t, 110)), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SETUP", "/audio", receiverTestSetupBody(t, 96)))
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "POST", "/feedback", nil), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SETUP", "/video", receiverTestSetupBody(t, 110)))
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SET_PARAMETER", "/session", []byte("volume: 0\r\n")))
	requireReceiverOK(t, receiverTestRTSPRequest(client, "POST", "/feedback", nil))
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "RECORD", "/session", nil), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "TEARDOWN", "/session", nil))
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "TEARDOWN", "/session", nil), 455)
}

func TestReceiverServerRequiresFairPlayBeforeModernSetup(t *testing.T) {
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileModern,
		Auth:    ReceiverAuthNone,
	})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "SETUP", "/session", receiverTestSetupBody(t)), 455)
	if err := client.FairPlaySetup(ctx); err != nil {
		t.Fatalf("FairPlay setup: %v", err)
	}
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SETUP", "/session", receiverTestSetupBody(t)))
	if got := server.Stats().FairPlayRequests; got != 2 {
		t.Fatalf("FairPlay requests = %d, want 2", got)
	}
}

func TestReceiverServerEnforcesRokuSessionOrder(t *testing.T) {
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku,
		Auth:    ReceiverAuthNone,
	})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}

	requireReceiverStatus(t, receiverTestRTSPRequest(client, "SETUP", "/session", receiverTestSetupBody(t)), 455)
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "SETUP", "/video", receiverTestSetupBody(t, 110)), 455)
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "RECORD", "/session", nil), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SETUP", "/audio", receiverTestSetupBody(t, 96)))
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "RECORD", "/session", nil), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SETUP", "/video", receiverTestSetupBody(t, 110)))
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "SET_PARAMETER", "/session", []byte("volume: 0\r\n")), 455)
	requireReceiverStatus(t, receiverTestRTSPRequest(client, "POST", "/feedback", nil), 455)
	requireReceiverOK(t, receiverTestRTSPRequest(client, "RECORD", "/session", nil))
	requireReceiverOK(t, receiverTestRTSPRequest(client, "SET_PARAMETER", "/session", []byte("volume: 0\r\n")))
	requireReceiverOK(t, receiverTestRTSPRequest(client, "POST", "/feedback", nil))
	requireReceiverOK(t, receiverTestRTSPRequest(client, "TEARDOWN", "/session", nil))
}

func TestReceiverServerPINAndDigestModes(t *testing.T) {
	t.Run("on-screen PIN", func(t *testing.T) {
		const code = "4827"
		server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
			Profile: ReceiverProfileModern,
			Auth:    ReceiverAuthPIN,
			Code:    code,
		})
		if !client.info.RequiresPINPairing() {
			t.Fatal("PIN receiver did not advertise PIN-required status")
		}
		if client.info.RequiresPassword() {
			t.Fatal("PIN receiver unexpectedly advertised a configured password")
		}
		if err := client.StartPINDisplay(); err != nil {
			t.Fatalf("start PIN display: %v", err)
		}
		if err := client.Pair(ctx, code); err != nil {
			t.Fatalf("PIN pair: %v", err)
		}
		stats := server.Stats()
		if stats.PINStarts != 1 || stats.PairSetup != 3 || stats.PairVerify != 2 {
			t.Fatalf("PIN stats = %+v", stats)
		}
	})

	t.Run("Digest after raw transient pairing", func(t *testing.T) {
		const code = "digest-only"
		server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
			Profile: ReceiverProfileRoku,
			Auth:    ReceiverAuthDigest,
			Code:    code,
		})
		client.SetPassword(code)
		if !client.info.RequiresPassword() {
			t.Fatal("Digest receiver did not advertise a configured password")
		}
		if err := client.Pair(ctx, ""); err != nil {
			t.Fatalf("transient pair: %v", err)
		}
		if client.encrypted {
			t.Fatal("raw Roku pairing unexpectedly encrypted the control channel")
		}
		session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
		if err != nil {
			t.Fatalf("Digest-protected setup: %v", err)
		}
		if err := session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Fatalf("close mirror session: %v", err)
		}
		if got := server.Stats().DigestChallenges; got != 1 {
			t.Fatalf("Digest challenges = %d, want 1", got)
		}
	})
}

func TestReceiverServerRejectsWrongPairingCode(t *testing.T) {
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile: ReceiverProfileRoku,
		Auth:    ReceiverAuthPassword,
		Code:    "correct",
	})
	if err := client.Pair(ctx, "wrong"); err == nil {
		t.Fatal("pairing accepted the wrong configured password")
	}
}

func TestReceiverServerConfigValidation(t *testing.T) {
	for _, test := range []struct {
		name string
		cfg  ReceiverConfig
	}{
		{name: "unknown profile", cfg: ReceiverConfig{ListenAddress: "127.0.0.1:0", Profile: "other"}},
		{name: "unknown auth", cfg: ReceiverConfig{ListenAddress: "127.0.0.1:0", Auth: "other"}},
		{name: "missing code", cfg: ReceiverConfig{ListenAddress: "127.0.0.1:0", Auth: ReceiverAuthPIN}},
		{name: "unused code", cfg: ReceiverConfig{ListenAddress: "127.0.0.1:0", Auth: ReceiverAuthNone, Code: "1234"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, err := NewReceiverServer(test.cfg)
			if err == nil {
				_ = server.Close()
				t.Fatal("expected configuration error")
			}
		})
	}
}

func newReceiverServerTestPair(t *testing.T, cfg ReceiverConfig) (*ReceiverServer, *AirPlayClient, context.Context) {
	t.Helper()
	cfg.ListenAddress = "127.0.0.1:0"
	cfg.Logger = log.New(io.Discard, "", 0)
	server, err := NewReceiverServer(cfg)
	if err != nil {
		t.Fatalf("new receiver server: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("serve receiver: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("receiver Serve did not stop")
		}
	})

	host, portText, err := net.SplitHostPort(server.Addr().String())
	if err != nil {
		t.Fatalf("split receiver address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse receiver port: %v", err)
	}
	client := NewAirPlayClient(host, port)
	if err := client.Connect(ctx); err != nil {
		t.Fatalf("connect receiver: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if _, err := client.GetInfo(); err != nil {
		t.Fatalf("get receiver info: %v", err)
	}
	return server, client, ctx
}

func receiverTestSetupBody(t *testing.T, streamTypes ...int64) []byte {
	t.Helper()
	setup := make(map[string]any)
	if len(streamTypes) > 0 {
		streams := make([]any, len(streamTypes))
		for i, streamType := range streamTypes {
			streams[i] = map[string]any{"type": streamType}
		}
		setup["streams"] = streams
	}
	body, err := plist.Marshal(setup, plist.BinaryFormat)
	if err != nil {
		t.Fatalf("marshal test SETUP: %v", err)
	}
	return body
}

func receiverTestRTSPRequest(client *AirPlayClient, method, uri string, body []byte) error {
	contentType := ""
	if len(body) > 0 {
		contentType = "application/x-apple-binary-plist"
	}
	_, _, err := client.rtspRequest(method, uri, contentType, body, nil)
	return err
}

func requireReceiverOK(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("receiver request failed: %v", err)
	}
}

func requireReceiverStatus(t *testing.T, err error, want int) {
	t.Helper()
	var statusErr *HTTPStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != want {
		t.Fatalf("receiver request error = %v, want HTTP %d", err, want)
	}
}
