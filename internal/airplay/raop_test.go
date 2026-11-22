package airplay

import (
	"context"
	"testing"
	"time"
)

func TestRAOPProbesAdvertisedReceiverTimingPort(t *testing.T) {
	receiver, err := NewReceiverServer(ReceiverConfig{
		ListenAddress: "127.0.0.1:0", Profile: ReceiverProfileRAOP, RAOPSenderTiming: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go receiver.Serve(ctx)
	session, err := OpenRAOP(ctx, receiver.RAOPDevice(), AudioOnlyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if receiver.Stats().TimingReplies == 3 {
			return
		}
		select {
		case <-ticker.C:
		case <-ctx.Done():
			t.Fatalf("receiver observed %d timing replies, want 3", receiver.Stats().TimingReplies)
		}
	}
}

func TestRAOPMatchesLocalVolumeAndPreservesDaemonMute(t *testing.T) {
	receiver, err := NewReceiverServer(ReceiverConfig{
		ListenAddress: "127.0.0.1:0", Profile: ReceiverProfileRAOP,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go receiver.Serve(ctx)
	session, err := OpenRAOP(ctx, receiver.RAOPDevice(), AudioOnlyConfig{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	assertVolume := func(want float64) {
		t.Helper()
		body, err := session.request("GET_PARAMETER", session.uri, "text/parameters", []byte("volume\r\n"))
		if err != nil {
			t.Fatal(err)
		}
		got, err := parseReceiverVolume(body)
		if err != nil || got != want {
			t.Fatalf("receiver volume = %v, %v, want %v", got, err, want)
		}
	}
	if err := session.matchOutputVolume(-8); err != nil {
		t.Fatal(err)
	}
	assertVolume(-8)
	if err := session.SetAudioMuted(true); err != nil {
		t.Fatal(err)
	}
	if err := session.matchOutputVolume(-12); err != nil {
		t.Fatal(err)
	}
	assertVolume(airPlayMutedVolumeDB)
	if err := session.SetAudioMuted(false); err != nil {
		t.Fatal(err)
	}
	assertVolume(-12)
	if err := session.matchOutputVolume(airPlayMutedVolumeDB); err != nil {
		t.Fatal(err)
	}
	assertVolume(airPlayMutedVolumeDB)
}
