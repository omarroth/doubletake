package airplay

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"testing"
	"time"
)

func TestReceiverWithoutPTPTimelineFallsBackToNTP(t *testing.T) {
	// Transient pairing must be redone on the new connection; a PIN pairing
	// is re-verified with the long-term keys it already holds.
	for _, test := range []struct {
		name     string
		auth     ReceiverAuthMode
		code     string
		profile  ReceiverProfile
		fairPlay bool
	}{
		{name: "transient pairing", auth: ReceiverAuthNone, profile: ReceiverProfileLG},
		{name: "PIN pairing", auth: ReceiverAuthPIN, code: "1234", profile: ReceiverProfileLG},
		{name: "FairPlay transient pairing", auth: ReceiverAuthNone, profile: ReceiverProfileModern, fairPlay: true},
		{name: "FairPlay PIN pairing", auth: ReceiverAuthPIN, code: "1234", profile: ReceiverProfileModern, fairPlay: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			testReceiverWithoutPTPTimelineFallsBackToNTP(t, test.auth, test.code, test.profile, test.fairPlay)
		})
	}
}

func testReceiverWithoutPTPTimelineFallsBackToNTP(t *testing.T, auth ReceiverAuthMode, code string, profile ReceiverProfile, fairPlay bool) {
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
		Profile:              profile,
		Auth:                 auth,
		Code:                 code,
		OmitPTPClockIdentity: true,
		AcceptNTPFallback:    true,
	})
	if auth == ReceiverAuthPIN {
		// Reusing a client for code pairing must clear its transient history.
		client.pairedTransient = true
	}
	if err := client.Pair(ctx, code); err != nil {
		t.Fatalf("pair: %v", err)
	}
	if fairPlay {
		if err := client.FairPlaySetup(ctx); err != nil {
			t.Fatal(err)
		}
	}
	session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	if session.timingProtocol != timingProtocolNTP || session.mediaClock != nil {
		t.Fatalf("session timing = %q (media clock %t), want NTP without a PTP clock",
			session.timingProtocol, session.mediaClock != nil)
	}
	deadline := time.Now().Add(time.Second)
	stats := server.Stats()
	for (stats.VideoConnections != 1 || stats.TimingReplies == 0) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		stats = server.Stats()
	}
	if err := session.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("close mirror session: %v", err)
	}
	stats = server.Stats()
	// The PTP attempt is torn down on the first connection; NTP runs on a
	// second, re-verified one.
	if stats.Connections != 2 || stats.TeardownRequests != 2 || stats.RecordRequests != 1 {
		t.Fatalf("control stats = %+v, want 2 connections, 2 TEARDOWNs, 1 RECORD", stats)
	}
	if fairPlay && stats.FairPlayRequests != 4 {
		t.Fatalf("FairPlay requests = %d, want two complete handshakes", stats.FairPlayRequests)
	}
	if stats.VideoConnections != 1 || stats.TimingProbes == 0 || stats.TimingReplies == 0 {
		t.Fatalf("media stats = %+v, want one video stream timed over NTP", stats)
	}
}

func TestTimingReconnectRejectsAReplacementReceiver(t *testing.T) {
	for _, changeID := range []bool{false, true} {
		t.Run(map[bool]string{false: "same ID new key", true: "changed ID"}[changeID], func(t *testing.T) {
			server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
				Profile: ReceiverProfileLG, Auth: ReceiverAuthPIN, Code: "1234",
			})
			if err := client.Pair(ctx, "1234"); err != nil {
				t.Fatal(err)
			}
			address, deviceID := server.Addr().String(), client.info.DeviceID
			if err := server.Close(); err != nil {
				t.Fatal(err)
			}
			if changeID {
				deviceID = "another-device"
			}
			impostor, err := NewReceiverServer(ReceiverConfig{
				ListenAddress: address, DeviceID: deviceID, Profile: ReceiverProfileLG,
				Logger: log.New(io.Discard, "", 0),
			})
			if err != nil {
				t.Fatal(err)
			}
			serveCtx, cancel := context.WithCancel(ctx)
			done := make(chan error, 1)
			go func() { done <- impostor.Serve(serveCtx) }()
			t.Cleanup(func() { cancel(); _ = impostor.Close(); <-done })
			if err := client.reconnectMirrorControl(ctx); !errors.Is(err, ErrReceiverNotAuthenticated) {
				t.Fatalf("reconnect = %v, want refusal of replacement receiver", err)
			}
			if stats := impostor.Stats(); stats.PairSetup != 0 || stats.SetupRequests != 0 {
				t.Fatalf("replacement receiver reached pairing or stream setup: %+v", stats)
			}
		})
	}
}
