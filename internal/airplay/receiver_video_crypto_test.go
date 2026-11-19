package airplay

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

// These fixed vectors were generated independently with Python's hashlib/hmac
// and cryptography ChaCha20Poly1305. Secret = bytes(range(32)), stream ID =
// 1234567, salt = DataStream-Salt1234567, info = DataStream-Output-Encryption-Key.
// The 128-byte AAD contains only LE32(payload size) and the IDR flag at byte 5.
const receiverVideoKeyVector = "fdefc241634f4abd824c6bc3993938beee8cc83a565440e9ad679d79923638cf"
const receiverVideoIDRVector = "51fa46d2a91dc83d2ee8e9febeff4aefc85c0ba7f362" // nonce 0, 000000026580
const receiverVideoPVector = "b1750386aba110c060a803f1378705fb39e08c1c93"     // nonce 1, 0000000161

func receiverVideoHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func TestReceiverDataStreamKeyVector(t *testing.T) {
	secret := make([]byte, 32)
	for i := range secret {
		secret[i] = byte(i)
	}
	key, err := receiverDataStreamKey(secret, 1234567)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, receiverVideoHex(t, receiverVideoKeyVector)) {
		t.Fatalf("receiver data-stream key = %x", key)
	}
	if _, err := receiverDataStreamKey(secret[:31], 1234567); err == nil {
		t.Fatal("accepted a truncated pair-verify secret")
	}
}

func TestReceiverMediaSessionAuthenticatesModernVideo(t *testing.T) {
	key := receiverVideoHex(t, receiverVideoKeyVector)
	session, senderConn := newPipeReceiverMediaSessionWithCrypto(t, func(s *receiverMediaSession) error {
		return s.configureChaChaVideo(key)
	})
	writeReceiverMirrorPacket(t, senderConn, 0x00, 0x10, receiverVideoHex(t, receiverVideoIDRVector))
	// Neither plaintext packet type advances the encrypted-picture nonce.
	writeReceiverMirrorPacket(t, senderConn, 0x01, 0, []byte{1, 2, 3})
	writeReceiverMirrorPacket(t, senderConn, 0x02, 0, nil)
	writeReceiverMirrorPacket(t, senderConn, 0x00, 0, receiverVideoHex(t, receiverVideoPVector))
	_ = senderConn.Close()
	waitReceiverPipeSession(t, session)
	stats := session.Snapshot()
	if stats.VideoDecrypted != 2 || stats.VideoCryptoErrors != 0 || stats.VideoMalformed != 0 {
		t.Fatalf("modern video authentication stats = %+v", stats)
	}
}

func TestReceiverMediaSessionRejectsInvalidModernVideo(t *testing.T) {
	for _, test := range []string{"wrong key", "header AAD", "ciphertext", "tag", "truncated tag", "wrong nonce", "replayed frame"} {
		t.Run(test, func(t *testing.T) {
			key := receiverVideoHex(t, receiverVideoKeyVector)
			payload := receiverVideoHex(t, receiverVideoIDRVector)
			flag := byte(0x10)
			if test == "wrong key" {
				key[0] ^= 1
			}
			session, senderConn := newPipeReceiverMediaSessionWithCrypto(t, func(s *receiverMediaSession) error {
				return s.configureChaChaVideo(key)
			})
			var wantDecrypted uint64
			switch test {
			case "header AAD":
				flag = 0
			case "ciphertext":
				payload[0] ^= 1
			case "tag":
				payload[len(payload)-1] ^= 1
			case "truncated tag":
				payload = payload[:len(payload)-1]
			case "wrong nonce":
				payload = receiverVideoHex(t, receiverVideoPVector)
				flag = 0
			case "replayed frame":
				writeReceiverMirrorPacket(t, senderConn, 0x00, flag, payload)
				wantDecrypted = 1
			}
			writeReceiverMirrorPacket(t, senderConn, 0x00, flag, payload)
			_ = senderConn.Close()
			waitReceiverPipeSession(t, session)
			stats := session.Snapshot()
			if stats.VideoDecrypted != wantDecrypted || stats.VideoCryptoErrors != 1 || stats.VideoMalformed != 1 {
				t.Fatalf("invalid modern video stats = %+v", stats)
			}
		})
	}
}

func TestReceiverServerAuthenticatesModernVideo(t *testing.T) {
	server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileModern})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := client.FairPlaySetup(ctx); err != nil {
		t.Fatal(err)
	}
	session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	for _, keyframe := range []bool{true, false} {
		nal := byte(0x61)
		if keyframe {
			nal = 0x65
		}
		timestamp, timeline := session.frameTimeNow()
		if err := session.sendFrame(receiverTestAVCC([]byte{nal, 0x80}), keyframe, timestamp, timeline); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stats := server.Stats()
		if stats.VideoCryptoErrors != 0 {
			t.Fatalf("receiver could not authenticate CoreUtils video: %+v", stats)
		}
		if stats.VideoDecrypted == 2 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("receiver did not authenticate CoreUtils pictures: %+v", server.Stats())
}

func TestReceiverServerRejectsLegacyKeyUnrelatedToFairPlay(t *testing.T) {
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileAppleTV3})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatal(err)
	}
	if err := client.FairPlaySetup(ctx); err != nil {
		t.Fatal(err)
	}
	client.fpKey = append([]byte(nil), client.fpKey...)
	client.fpKey[0] ^= 1
	session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
	if err == nil {
		session.Close()
		t.Fatal("receiver accepted a shorthand key unrelated to authenticated FairPlay material")
	}
	if !strings.Contains(err.Error(), "shk does not match") {
		t.Fatalf("SETUP failed for an unrelated reason: %v", err)
	}
}

func TestReceiverServerRecordPreparationMatrix(t *testing.T) {
	for _, profile := range []ReceiverProfile{ReceiverProfileAppleTV3, ReceiverProfileModern} {
		for _, acceptEarly := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/acceptEarly=%t", profile, acceptEarly), func(t *testing.T) {
				server, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{
					Profile: profile, AcceptEarlyRecord: acceptEarly,
				}, func(server *ReceiverServer) {
					server.profile.setupOrder = receiverSetupSessionFirst
				})
				if err := client.Pair(ctx, ""); err != nil {
					t.Fatal(err)
				}
				if err := client.FairPlaySetup(ctx); err != nil {
					t.Fatal(err)
				}
				session, err := client.SetupMirror(ctx, StreamConfig{})
				if err != nil {
					t.Fatal(err)
				}
				defer session.Close()
				wantRecords, wantEarly := uint64(1), uint64(0)
				if profile == ReceiverProfileModern {
					wantEarly = 1
					if !acceptEarly {
						wantRecords = 2
					}
				}
				stats := server.Stats()
				if stats.RecordRequests != wantRecords || stats.EarlyRecordRequests != wantEarly {
					t.Fatalf("RECORD requests = %d (%d early), want %d (%d early)",
						stats.RecordRequests, stats.EarlyRecordRequests, wantRecords, wantEarly)
				}
			})
		}
	}
}
