package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

type multiroomPacketConn struct{ recordingPacketConn }

func (c *multiroomPacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, io.EOF }

func TestMultiroomSharedAudioSchedulesIdenticalContentOnDifferentClocks(t *testing.T) {
	h, input, _ := newSharedAudioTestHub(t)
	a, b := acquireSharedTestCapture(t, h), acquireSharedTestCapture(t, h)
	base := time.Now()
	const count = 8
	videoReady := make(chan struct{})
	close(videoReady)
	lead := 250 * time.Millisecond
	clockOrigin := compactTimestamp(1234 * time.Second)
	sessions := []*MirrorSession{
		{firstFrameSent: videoReady, timingProtocol: timingProtocolNTP, timestampBias: lead},
		{firstFrameSent: videoReady, timingProtocol: timingProtocolPTP, timestampBias: lead,
			mediaClock: &mediaClock{anchorLocal: base, anchorTimestamp: clockOrigin, timelineID: 0x1234}},
	}
	var streams [2]*AudioStream
	var data, control [2]*multiroomPacketConn
	done := make(chan error, 2)
	for i, capture := range []*AudioCapture{a, b} {
		data[i], control[i] = &multiroomPacketConn{}, &multiroomPacketConn{}
		streams[i] = &AudioStream{conn: data[i], ctrlConn: control[i], remoteAddr: &netUDPAddrForAudioTest, ctrlAddr: &netUDPAddrForAudioTest,
			ct: byte(AudioCodecALAC), spf: 352, latencySamples: samplesFor44k1(lead), rfc2198: true}
		var err error
		if i == 0 {
			streams[i].cipher, err = aes.NewCipher(bytes.Repeat([]byte{0x23}, 16))
			streams[i].aesIV = make([]byte, 16)
		} else {
			streams[i].chachaCipher, err = newAudioChaCha64AEAD(bytes.Repeat([]byte{0x42}, 32))
			streams[i].chachaAADMode = defaultAudioChaChaAADMode()
		}
		if err != nil {
			t.Fatal(err)
		}
		go func(i int, capture *AudioCapture) {
			done <- sessions[i].StreamAudio(context.Background(), capture, streams[i])
		}(i, capture)
	}
	for i := range count {
		(*input).frames <- audioPCMFramePosition{PTS: base.Add(audioSamplesDuration(uint64(i * 352))), SourceRTP: uint32(i * 352), HasSourceRTP: true}
	}
	close((*input).frames)
	for range 2 {
		if err := <-done; !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
	}
	if len(data[0].packets) != count || len(data[1].packets) != count {
		t.Fatalf("frame counts=%d/%d", len(data[0].packets), len(data[1].packets))
	}
	for i := range count {
		var primary [2][]byte
		for receiver := range 2 {
			security := []string{"AES", "ChaCha"}[receiver]
			plain := decodeAudioPacketPayloadForTest(t, streams[receiver], security, data[receiver].packets[i])
			_, primary[receiver] = splitAudioREDPayloadForTest(t, plain)
		}
		if !bytes.Equal(primary[0], primary[1]) {
			t.Fatalf("receiver encryption changed shared content at frame %d", i)
		}
	}
	// Resolve each independent RTP epoch through its own TimeAnnounce, then
	// compare the audio presentation instant to video's source-PTS deadline.
	for receiver, s := range sessions {
		if len(control[receiver].packets) == 0 {
			t.Fatal("missing TimeAnnounce")
		}
		syncPacket := control[receiver].packets[0]
		playhead := binary.BigEndian.Uint32(syncPacket[4:8])
		for i, p := range data[receiver].packets {
			frameRTP := binary.BigEndian.Uint32(p[4:8])
			advance := audioSamplesDuration(uint64(uint32(frameRTP - playhead)))
			pts := base.Add(audioSamplesDuration(uint64(i * 352)))
			video, _, ok := s.frameTimeAt(pts)
			if !ok {
				t.Fatal("video mapping failed")
			}
			var got, want time.Duration
			if receiver == 0 {
				ntp := binary.BigEndian.Uint64(syncPacket[8:16]) - (uint64(secondsFrom1900To1970) << 32)
				got = time.Duration(ptpNanoseconds(ntp)) + advance
				want = time.Duration(ptpNanoseconds(video))
			} else {
				got = time.Duration(binary.BigEndian.Uint64(syncPacket[8:16])) + advance
				want = time.Duration(ptpNanoseconds(video))
				if binary.BigEndian.Uint64(syncPacket[20:28]) != 0x1234 {
					t.Fatal("lost PTP clock identity")
				}
			}
			if difference := (got - want).Abs(); difference > time.Millisecond {
				t.Fatalf("receiver %d frame %d audio/video deadline differs by %v", receiver, i, difference)
			}
		}
	}
}

func TestSharedPlayoutNegotiationUsesOneBudget(t *testing.T) {
	for _, profile := range []ReceiverProfile{ReceiverProfileModern, ReceiverProfileRoku} {
		t.Run(string(profile), func(t *testing.T) {
			_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: profile})
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if err := client.FairPlaySetup(ctx); err != nil && !errors.Is(err, ErrFairPlayUnsupported) {
				t.Fatal(err)
			}
			session, err := client.SetupMirror(ctx, StreamConfig{PlayoutLatency: 250 * time.Millisecond, PreferredAudioCodec: AudioCodecALAC})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			if session.timestampBias != 250*time.Millisecond || session.audioStream.latencySamples != 11025 {
				t.Fatalf("negotiated unequal group leads: video=%v audio=%d", session.timestampBias, session.audioStream.latencySamples)
			}
			if session.AudioCodec() != AudioCodecALAC {
				t.Fatal("shared codec preference did not select offered ALAC")
			}
		})
	}
}

func TestSharedPlayoutRejectsCaptureOutsideGroupBudget(t *testing.T) {
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileModern})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := client.FairPlaySetup(ctx); err != nil && !errors.Is(err, ErrFairPlayUnsupported) {
		t.Fatal(err)
	}
	_, err := client.SetupMirrorWithCalibratedVideoPreparation(ctx, StreamConfig{PlayoutLatency: 250 * time.Millisecond}, func(int, int, VideoCodec) (VideoPreparationResult, error) {
		return VideoPreparationResult{MinimumVideoLead: 300 * time.Millisecond}, nil
	})
	if err == nil || !strings.Contains(err.Error(), "shared playout budget") {
		t.Fatalf("slow capture = %v, want refusal instead of a different deadline", err)
	}
	if stats := server.Stats(); stats.RecordRequests != 0 || stats.TeardownRequests != 1 {
		t.Fatalf("failed capture left media state: %+v", stats)
	}
}

func TestSharedAudioCodecPreferenceRetainsELDOnlyReceivers(t *testing.T) {
	if !aacELDEncoderAvailable {
		t.Skip("requires fdk_aac")
	}
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileAirServer})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := client.FairPlaySetup(ctx); err != nil && !errors.Is(err, ErrFairPlayUnsupported) {
		t.Fatal(err)
	}
	session, err := client.SetupMirror(ctx, StreamConfig{PlayoutLatency: 250 * time.Millisecond, PreferredAudioCodec: AudioCodecALAC})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if session.AudioCodec() != AudioCodecAACELD {
		t.Fatal("unadvertised ALAC forced onto an ELD-only receiver")
	}
}
