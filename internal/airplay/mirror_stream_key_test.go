package airplay

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"howett.net/plist"
)

// recordingConn keeps a copy of everything the client writes, so a test can
// read back the exact requests that crossed a plaintext control channel.
type recordingConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (r *recordingConn) Write(p []byte) (int, error) {
	r.mu.Lock()
	r.written.Write(p)
	r.mu.Unlock()
	return r.Conn.Write(p)
}

func (r *recordingConn) requests(t *testing.T) []rtspTestRequest {
	t.Helper()
	r.mu.Lock()
	data := append([]byte(nil), r.written.Bytes()...)
	r.mu.Unlock()
	reader := bufio.NewReader(bytes.NewReader(data))
	var requests []rtspTestRequest
	for {
		request, err := readRTSPTestRequest(reader)
		if errors.Is(err, io.EOF) {
			return requests
		}
		if err != nil {
			t.Fatalf("parse recorded request: %v", err)
		}
		requests = append(requests, request)
	}
}

func recordControlConnection(client *AirPlayClient) *recordingConn {
	recorder := &recordingConn{Conn: client.conn}
	client.conn = recorder
	return recorder
}

// videoStreamDescriptors returns every type-110 stream a recorded SETUP carried.
func videoStreamDescriptors(t *testing.T, requests []rtspTestRequest) []map[string]any {
	t.Helper()
	return streamDescriptors(t, requests, 110)
}

// streamDescriptors returns every stream of one type a recorded SETUP carried.
func streamDescriptors(t *testing.T, requests []rtspTestRequest, streamType int) []map[string]any {
	t.Helper()
	var streams []map[string]any
	for _, request := range requests {
		if request.method != "SETUP" || len(request.body) == 0 {
			continue
		}
		var setup map[string]any
		if _, err := plist.Unmarshal(request.body, &setup); err != nil {
			t.Fatalf("decode recorded SETUP: %v", err)
		}
		list, _ := setup["streams"].([]any)
		for _, item := range list {
			stream, _ := item.(map[string]any)
			if plistInt(stream["type"]) == streamType {
				streams = append(streams, stream)
			}
		}
	}
	return streams
}

// On a plaintext control channel the video SETUP is readable by anyone on the
// network path, and with shk and streamConnectionID together they could derive
// the AES-CTR video key. Legacy receivers learn the key from ekey instead.
func TestPlaintextControlVideoSetupOmitsStreamKey(t *testing.T) {
	for _, profile := range []ReceiverProfile{ReceiverProfileAppleTV3, ReceiverProfileUxPlay, ReceiverProfileAirServer} {
		t.Run(string(profile), func(t *testing.T) {
			_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: profile})
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatalf("pair: %v", err)
			}
			if client.encrypted {
				t.Fatalf("%s control channel is encrypted; this test needs a plaintext one", profile)
			}
			if err := client.FairPlaySetup(ctx); err != nil {
				t.Fatalf("FairPlay setup: %v", err)
			}
			recorder := recordControlConnection(client)

			session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
			if err != nil {
				t.Fatalf("setup mirror: %v", err)
			}
			defer session.Close()
			if session.streamCipher == nil {
				t.Fatal("plaintext legacy session did not configure its video cipher")
			}

			streams := videoStreamDescriptors(t, recorder.requests(t))
			if len(streams) == 0 {
				t.Fatal("no video SETUP was recorded")
			}
			for _, stream := range streams {
				if _, ok := stream["shk"]; ok {
					t.Fatal("video SETUP on a plaintext control channel carried shk")
				}
				if iv := plistBytes(stream["shiv"]); !bytes.Equal(iv, client.fpIV) {
					t.Fatalf("video shiv = %x, want the FairPlay eiv %x", iv, client.fpIV)
				}
			}
		})
	}
}

// Audio on a plaintext channel is AES-CBC keyed from FairPlay, and its SETUP
// must not carry a key either. A guard: audio never carried one, and this keeps
// it that way.
func TestPlaintextControlAudioSetupOmitsStreamKey(t *testing.T) {
	for _, profile := range []ReceiverProfile{ReceiverProfileAppleTV3, ReceiverProfileUxPlay, ReceiverProfileAirServer} {
		t.Run(string(profile), func(t *testing.T) {
			_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: profile})
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatalf("pair: %v", err)
			}
			if err := client.FairPlaySetup(ctx); err != nil {
				t.Fatalf("FairPlay setup: %v", err)
			}
			recorder := recordControlConnection(client)

			session, err := client.SetupMirror(ctx, StreamConfig{})
			if err != nil && strings.Contains(err.Error(), "encoder is unavailable") {
				t.Skipf("no audio encoder for this profile here: %v", err)
			}
			if err != nil {
				t.Fatalf("setup mirror: %v", err)
			}
			defer session.Close()

			streams := streamDescriptors(t, recorder.requests(t), 96)
			if len(streams) == 0 {
				t.Fatal("no audio SETUP was recorded")
			}
			for _, stream := range streams {
				if _, ok := stream["shk"]; ok {
					t.Fatal("audio SETUP on a plaintext control channel carried shk")
				}
			}
		})
	}
}

func TestReceiverLegacyVideoKeysRejectStreamKeyInTheClear(t *testing.T) {
	masterKey := bytes.Repeat([]byte{0xa5}, 16)
	eiv := bytes.Repeat([]byte{0x3c}, 16)
	const streamConnectionID = int64(0x1234567890)

	cipherKey, cipherIV, err := receiverLegacyVideoKeys(map[string]any{
		"shiv":               eiv,
		"streamConnectionID": streamConnectionID,
	}, masterKey, eiv)
	if err != nil {
		t.Fatalf("derive legacy video keys from ekey: %v", err)
	}
	wantKey, wantIV := deriveVideoKeys(masterKey, streamConnectionID)
	if !bytes.Equal(cipherKey, wantKey) || !bytes.Equal(cipherIV, wantIV) {
		t.Fatalf("legacy video keys = %x/%x, want %x/%x", cipherKey, cipherIV, wantKey, wantIV)
	}

	_, _, err = receiverLegacyVideoKeys(map[string]any{
		"shk":                masterKey,
		"shiv":               eiv,
		"streamConnectionID": streamConnectionID,
	}, masterKey, eiv)
	if err == nil || !strings.Contains(err.Error(), "legacy video sent its stream key in the clear") {
		t.Fatalf("shk in the clear error = %v, want a refusal", err)
	}

	_, _, err = receiverLegacyVideoKeys(map[string]any{
		"shiv":               bytes.Repeat([]byte{0x00}, 16),
		"streamConnectionID": streamConnectionID,
	}, masterKey, eiv)
	if err == nil || !strings.Contains(err.Error(), "shiv") {
		t.Fatalf("mismatched shiv error = %v, want a shiv refusal", err)
	}
}

// shk is still sent wherever the receiver needs it: on an encrypted channel,
// inside the encryption, and to a plaintext receiver without FairPlay, which
// has no other way to learn the key.
func TestVideoStreamKeyIsSentWhereTheReceiverNeedsIt(t *testing.T) {
	fpKey := bytes.Repeat([]byte{0x11}, 16)
	for _, test := range []struct {
		name      string
		encrypted bool
		fpKey     []byte
		want      bool
	}{
		{"HAP with FairPlay", true, fpKey, true},
		{"HAP without FairPlay", true, nil, true},
		{"plaintext with FairPlay", false, fpKey, false},
		{"plaintext without FairPlay", false, nil, true},
	} {
		if got := sendVideoStreamKey(test.encrypted, test.fpKey); got != test.want {
			t.Errorf("%s: sendVideoStreamKey = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestPlaintextControlWithoutFairPlayStillSendsStreamKey(t *testing.T) {
	_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: ReceiverProfileRoku})
	if err := client.Pair(ctx, ""); err != nil {
		t.Fatalf("pair: %v", err)
	}
	if err := client.FairPlaySetup(ctx); err != nil && !errors.Is(err, ErrFairPlayUnsupported) {
		t.Fatalf("FairPlay setup: %v", err)
	}
	if client.encrypted || client.fpKey != nil {
		t.Fatalf("Roku session encrypted=%t fpKey=%x; this test needs plaintext without FairPlay", client.encrypted, client.fpKey)
	}
	recorder := recordControlConnection(client)

	session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
	if err != nil {
		t.Fatalf("setup mirror: %v", err)
	}
	defer session.Close()

	streams := videoStreamDescriptors(t, recorder.requests(t))
	if len(streams) == 0 {
		t.Fatal("no video SETUP was recorded")
	}
	for _, stream := range streams {
		if len(plistBytes(stream["shk"])) == 0 {
			t.Fatal("video SETUP to a plaintext receiver without FairPlay lost its shk")
		}
	}
}
