//go:build gstreamer_cgo && cgo && linux

package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"fmt"
	"math"
	"testing"
	"time"
)

func TestReceiverHeadlessPlaybackProfiles(t *testing.T) {
	if !hasGstElement("x264enc") || !receiverHasDecoder("avdec_h264") || !receiverHasDecoder("avdec_alac") {
		t.Skip("requires x264 and GStreamer libav decoders")
	}
	for _, test := range []struct {
		name               string
		profile            ReceiverProfile
		alac               bool
		drop               int
		ntp, hevc, rawOnly bool
		auth               ReceiverAuthMode
		reconnect          bool
	}{
		{name: "modern", profile: ReceiverProfileModern},
		{name: "modern-alac", profile: ReceiverProfileModern, alac: true},
		{name: "modern-saved-pin", profile: ReceiverProfileModern, alac: true, auth: ReceiverAuthPIN, reconnect: true},
		{name: "modern-ntp-early-record", profile: ReceiverProfileModern, alac: true, ntp: true},
		{name: "modern-hevc", profile: ReceiverProfileModern, alac: true, hevc: true},
		{name: "roku", profile: ReceiverProfileRoku},
		{name: "lg", profile: ReceiverProfileLG, alac: true},
		{name: "appletv3", profile: ReceiverProfileAppleTV3},
		{name: "appletv3-alac", profile: ReceiverProfileAppleTV3, alac: true},
		{name: "appletv3-saved-pin", profile: ReceiverProfileAppleTV3, auth: ReceiverAuthPIN, reconnect: true},
		{name: "uxplay", profile: ReceiverProfileUxPlay, alac: true},
		{name: "raw-only-legacy-capabilities", profile: ReceiverProfileUxPlay, alac: true, rawOnly: true},
		{name: "airserver", profile: ReceiverProfileAirServer},
		{name: "airserver-digest", profile: ReceiverProfileAirServer, auth: ReceiverAuthDigest},
		{name: "modern-red-recovery", profile: ReceiverProfileModern, alac: true, drop: 12},
		{name: "uxplay-retransmit-recovery", profile: ReceiverProfileUxPlay, alac: true, drop: 12},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.profile == ReceiverProfileAirServer && !aacELDEncoderAvailable {
				t.Skip("AAC-ELD-only fixture requires FDK-AAC")
			}
			codec := VideoCodecH264
			if test.hevc {
				if !hasGstElement("x265enc") || (!receiverHasDecoder("avdec_h265") && !receiverHasDecoder("libde265dec")) {
					t.Skip("HEVC encoder/decoder unavailable")
				}
				codec = VideoCodecHEVC
			}
			code := ""
			if test.auth != "" {
				code = "4827"
			}
			server, client, parent := newReceiverServerTestPair(t, ReceiverConfig{
				Profile: test.profile, DecodeMedia: true, AudioDropEvery: test.drop, DisplayWidth: 320, DisplayHeight: 180,
				Name: "Independent playback endpoint", Model: "UnrelatedModel", Manufacturer: "Independent Vendor",
				AcceptNTPFallback: test.profile == ReceiverProfileLG,
				ForceNTP:          test.ntp, AcceptEarlyRecord: test.ntp,
				Auth: test.auth, Code: code,
			}, func(server *ReceiverServer) {
				if test.rawOnly {
					server.profile.features = 0x1e5a7ffff7
					server.profile.pairing = receiverPairingRawOnly
				}
			})
			ctx, cancel := context.WithCancel(parent)
			defer cancel()
			client.SetPassword(code)
			pin := code
			if test.auth == ReceiverAuthDigest {
				pin = ""
			}
			if err := client.Pair(ctx, pin); err != nil {
				t.Fatal(err)
			}
			if test.reconnect {
				if err := client.reconnectMirrorControl(ctx); err != nil {
					t.Fatal(err)
				}
			}
			if client.info.SupportsFairPlaySAP() {
				if err := client.FairPlaySetup(ctx); err != nil {
					t.Fatal(err)
				}
			}
			// Leave CPU-decoder startup room in CI; this verifies negotiated
			// presentation timestamps rather than benchmarking plugin cold start.
			cfg := StreamConfig{TargetWidth: 320, TargetHeight: 180, VideoCodec: codec, PlayoutLatency: 500 * time.Millisecond}
			if test.alac {
				cfg.PreferredAudioCodec = AudioCodecALAC
			}
			session, err := client.SetupMirror(ctx, cfg)
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			capture, err := StartTestCapture(ctx, CaptureConfig{FPS: 10, Bitrate: 500, HWAccel: "none", VideoCodec: codec, MaxWidth: 320, MaxHeight: 180})
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Stop()
			audio, err := StartAudioCaptureWithSource(ctx, true, session.AudioCodec(), AudioSourceOutput)
			if err != nil {
				t.Fatal(err)
			}
			defer audio.Stop()
			done := make(chan error, 2)
			go func() { done <- session.StreamFrames(ctx, capture, 0) }()
			go func() { done <- session.StreamAudio(ctx, audio, session.AudioStream()) }()
			defer func() {
				cancel()
				capture.Stop()
				audio.Stop()
				for i := 0; i < 2; i++ {
					select {
					case <-done:
					case <-time.After(3 * time.Second):
						t.Error("headless stream did not stop")
					}
				}
			}()
			deadline := time.Now().Add(6 * time.Second)
			for time.Now().Before(deadline) {
				stats := server.Stats()
				p := stats.Playback
				if p.DecodeErrors > 0 || p.AudioCryptoErrors > 0 || stats.VideoCryptoErrors > 0 || p.TimestampErrors > 0 {
					t.Fatalf("headless playback failed: %+v; video crypto=%d", p, stats.VideoCryptoErrors)
				}
				if p.VideoPlayed >= 8 && p.AudioPlayedSamples >= 22050 {
					if p.VideoWidth != 320 || p.VideoHeight != 180 || p.VideoChanges < 2 {
						t.Fatalf("decoded video content: %+v", p)
					}
					rms := math.Sqrt(p.AudioSquares / float64(2*p.AudioSamples))
					if p.AudioPeak < 100 || p.AudioPeak > 1000 || rms < 50 || rms > 500 {
						t.Fatalf("decoded test tone has incorrect levels: peak=%d rms=%f", p.AudioPeak, rms)
					}
					if p.AudioLost != 0 || p.AudioMissingSamples != 0 || p.QueueOverruns != 0 {
						t.Fatalf("headless stream lost media: %+v", p)
					}
					if p.MaxAVSkew > 250*time.Millisecond {
						t.Fatalf("A/V presentation skew=%s: %+v", p.MaxAVSkew, p)
					}
					if test.drop > 0 && (p.AudioDropped == 0 || p.AudioRecovered == 0) {
						t.Fatalf("loss injection did not exercise recovery: %+v", p)
					}
					if test.profile == ReceiverProfileUxPlay && test.drop > 0 && p.AudioResends == 0 {
						t.Fatalf("classic audio did not request retransmission: %+v", p)
					}
					t.Logf("%s: decoded/played video=%d/%d, audio samples=%d/%d, peak=%d rms=%.1f, recovered=%d, A/V skew=%s", test.profile, p.VideoDecoded, p.VideoPlayed, p.AudioSamples, p.AudioPlayedSamples, p.AudioPeak, rms, p.AudioRecovered, p.MaxAVSkew)
					return
				}
				select {
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				case <-time.After(10 * time.Millisecond):
				}
			}
			t.Fatal(fmt.Sprintf("headless playback did not reach expected media: %+v", server.Stats()))
		})
	}
}

func TestReceiverHeadlessALACIsLosslessAcrossReorderAndWrap(t *testing.T) {
	if !receiverHasDecoder("avdec_alac") {
		t.Skip("requires GStreamer ALAC decoder")
	}
	for _, mode := range []string{"plaintext", "AES", "ChaCha"} {
		t.Run(mode, func(t *testing.T) {
			p, err := newReceiverPlayback(receiverPlaybackConfig{Timing: timingProtocolNTP})
			if err != nil {
				t.Fatal(err)
			}
			defer p.Close()
			key := bytes.Repeat([]byte{0x37}, 16)
			iv := bytes.Repeat([]byte{0x52}, 16)
			chacha := bytes.Repeat([]byte{0x83}, 32)
			as := &AudioStream{chachaAADMode: defaultAudioChaChaAADMode()}
			switch mode {
			case "AES":
				as.cipher, err = aes.NewCipher(key)
				as.aesIV = iv
			case "ChaCha":
				as.chachaCipher, err = newAudioChaCha64AEAD(chacha)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode != "AES" {
				key = nil
				iv = nil
			}
			if mode != "ChaCha" {
				chacha = nil
			}
			if err := p.configureAudio(AudioCodecALAC, key, iv, chacha, nil); err != nil {
				t.Fatal(err)
			}
			origin := uint32(0xffffff00)
			var packets [][]byte
			var expected uint64
			encoder := &alacEncoder{}
			for i := 0; i < 5; i++ {
				pcm := testALACPCM()
				pcm[0] = byte(i + 1)
				expected = receiverChecksum(expected, pcm)
				encoded := make([]byte, 4096)
				n := encoder.Encode(encoded, pcm)
				packet, _ := as.buildAudioPacketLocked(encoded[:n], origin+uint32(i*352), uint16(65534+i), 96, nil)
				packets = append(packets, packet)
			}
			p.audioPacket(packets[2], false)
			if p.snapshot().AudioDecoded != 0 {
				t.Fatal("audio decoded before a TimeAnnounce anchor")
			}
			var announce [20]byte
			announce[0], announce[1] = 0x90, 0xd4
			binary.BigEndian.PutUint32(announce[4:8], origin)
			binary.BigEndian.PutUint64(announce[8:16], ntpBootTimestamp()+compactTimestamp(200*time.Millisecond))
			p.audioControl(announce[:])
			for _, index := range []int{0, 0, 1, 3, 4, 2} {
				p.audioPacket(packets[index], false)
			}
			deadline := time.Now().Add(2 * time.Second)
			for time.Now().Before(deadline) {
				stats := p.snapshot()
				if stats.DecodeErrors > 0 || stats.TimestampErrors > 0 {
					t.Fatalf("lossless decode failed: %+v", stats)
				}
				if stats.AudioPlayedSamples == 5*352 {
					if stats.AudioChecksum != expected || stats.AudioSamples != 5*352 || stats.AudioDuplicates != 2 || stats.AudioLost != 0 {
						t.Fatalf("PCM changed, duplicated, or reordered: %+v; checksum=%x", stats, expected)
					}
					return
				}
				time.Sleep(5 * time.Millisecond)
			}
			t.Fatalf("ALAC playback did not complete: %+v", p.snapshot())
		})
	}
}

func TestReceiverHeadlessRejectsInvalidAudioAuthentication(t *testing.T) {
	p, err := newReceiverPlayback(receiverPlaybackConfig{Timing: timingProtocolNTP})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	key := bytes.Repeat([]byte{0x83}, 32)
	if err := p.configureAudio(AudioCodecALAC, nil, nil, key, nil); err != nil {
		t.Fatal(err)
	}
	aead, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	as := &AudioStream{chachaCipher: aead, chachaAADMode: defaultAudioChaChaAADMode()}
	packet, _ := as.buildAudioPacketLocked([]byte{1, 2, 3}, 0, 1, 96, nil)
	packet[4] ^= 1 // Timestamp bytes belong to the authenticated data.
	p.audioPacket(packet, false)
	stats := p.snapshot()
	if stats.AudioCryptoErrors != 1 || stats.AudioDecoded != 0 {
		t.Fatalf("accepted altered audio: %+v", stats)
	}
}

func TestReceiverHeadlessRejectsUndecodableAudio(t *testing.T) {
	p, err := newReceiverPlayback(receiverPlaybackConfig{Timing: timingProtocolNTP, AudioJitter: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.configureAudio(AudioCodecALAC, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var announce [20]byte
	announce[0], announce[1] = 0x90, 0xd4
	binary.BigEndian.PutUint64(announce[8:16], ntpBootTimestamp())
	p.audioControl(announce[:])
	as := &AudioStream{}
	packet, _ := as.buildAudioPacketLocked([]byte{0xff, 0xff, 0xff, 0xff}, 0, 1, 96, nil)
	p.audioPacket(packet, false)
	_ = p.audio.decoder.Close()
	stats := p.snapshot()
	if stats.DecodeErrors == 0 || stats.AudioDecoded != 0 {
		t.Fatalf("opaque audio counted as successful decoding: %+v", stats)
	}
}

func TestReceiverHeadlessEmptyDecoderClosesCleanly(t *testing.T) {
	p, err := newReceiverPlayback(receiverPlaybackConfig{Timing: timingProtocolNTP})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.configureAudio(AudioCodecALAC, nil, nil, nil, nil); err != nil {
		p.Close()
		t.Fatal(err)
	}
	p.Close()
	if stats := p.snapshot(); stats.DecodeErrors != 0 || stats.AudioDecoded != 0 {
		t.Fatalf("unused audio decoder created a failure: %+v", stats)
	}
}

func TestReceiverHeadlessDetectsPresentationSkewAndBadTimeline(t *testing.T) {
	p, err := newReceiverPlayback(receiverPlaybackConfig{Timing: timingProtocolPTP, Timeline: 73})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.videoFrame([]byte{1}, 1, 99); err == nil {
		t.Fatal("accepted a different PTP timeline")
	}
	base := bootRelativeNow() + 20*time.Millisecond
	p.decodedVideo(receiverDecodedSample{Data: []byte{1, 2}, PTS: int64(base), Width: 2, Height: 1})
	p.decodedAudio(receiverDecodedSample{Data: make([]byte, 352*4), PTS: int64(base + 80*time.Millisecond)})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stats := p.snapshot()
		if stats.AudioPlayedSamples == 352 {
			if stats.TimestampErrors != 1 || stats.MaxAVSkew < 80*time.Millisecond {
				t.Fatalf("timing errors were hidden: %+v", stats)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed samples were not presented")
}

func TestReceiverHeadlessDetectsSourceAudioGapWithoutRequestingLostPackets(t *testing.T) {
	p, err := newReceiverPlayback(receiverPlaybackConfig{Timing: timingProtocolNTP, AudioJitter: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var resends int
	if err := p.configureAudio(AudioCodecALAC, nil, nil, nil, func(uint16, uint16) error { resends++; return nil }); err != nil {
		t.Fatal(err)
	}
	var announce [20]byte
	announce[0], announce[1] = 0x90, 0xd4
	binary.BigEndian.PutUint64(announce[8:16], ntpBootTimestamp()+compactTimestamp(200*time.Millisecond))
	p.audioControl(announce[:])
	encoded := make([]byte, 4096)
	n := (&alacEncoder{}).Encode(encoded, testALACPCM())
	as := &AudioStream{}
	for i, rtp := range []uint32{0, 704} {
		packet, _ := as.buildAudioPacketLocked(encoded[:n], rtp, uint16(i+1), 96, nil)
		p.audioPacket(packet, false)
	}
	stats := p.snapshot()
	if stats.AudioMissingSamples != 352 || stats.AudioLost != 0 || resends != 0 {
		t.Fatalf("source gap was confused with network loss: %+v; requests=%d", stats, resends)
	}
}

func TestReceiverHeadlessReportsUnrecoverableAudioLoss(t *testing.T) {
	p, err := newReceiverPlayback(receiverPlaybackConfig{Timing: timingProtocolNTP, AudioJitter: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err := p.configureAudio(AudioCodecALAC, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	var announce [20]byte
	announce[0], announce[1] = 0x90, 0xd4
	binary.BigEndian.PutUint64(announce[8:16], ntpBootTimestamp()+compactTimestamp(100*time.Millisecond))
	p.audioControl(announce[:])
	encoded := make([]byte, 4096)
	n := (&alacEncoder{}).Encode(encoded, testALACPCM())
	as := &AudioStream{}
	for _, index := range []int{0, 2} {
		packet, _ := as.buildAudioPacketLocked(encoded[:n], uint32(index*352), uint16(index+1), 96, nil)
		p.audioPacket(packet, false)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stats := p.snapshot()
		if stats.AudioPlayedSamples == 704 {
			if stats.AudioLost != 1 || stats.AudioMissingSamples != 352 {
				t.Fatalf("unrecoverable loss was hidden: %+v", stats)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("jitter buffer stalled after missing audio: %+v", p.snapshot())
}
