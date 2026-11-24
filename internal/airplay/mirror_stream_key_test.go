package airplay

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"howett.net/plist"
)

type mirrorSetupRecordingConn struct {
	net.Conn
	mu      sync.Mutex
	written bytes.Buffer
}

func (c *mirrorSetupRecordingConn) Write(data []byte) (int, error) {
	n, err := c.Conn.Write(data)
	c.mu.Lock()
	c.written.Write(data[:n])
	c.mu.Unlock()
	return n, err
}

func TestPlaintextMirrorSetupVideoKey(t *testing.T) {
	for _, test := range []struct {
		profile  ReceiverProfile
		fairPlay bool
	}{
		{profile: ReceiverProfileUxPlay, fairPlay: true},
		{profile: ReceiverProfileRoku},
	} {
		t.Run(string(test.profile), func(t *testing.T) {
			_, client, ctx := newReceiverServerTestPair(t, ReceiverConfig{Profile: test.profile})
			if err := client.Pair(ctx, ""); err != nil {
				t.Fatal(err)
			}
			if err := client.FairPlaySetup(ctx); err != nil && !errors.Is(err, ErrFairPlayUnsupported) {
				t.Fatal(err)
			}
			if client.encrypted || (client.fpKey != nil) != test.fairPlay {
				t.Fatal("test pairing did not establish the intended plaintext session")
			}
			conn := &mirrorSetupRecordingConn{Conn: client.conn}
			client.conn = conn
			session, err := client.SetupMirror(ctx, StreamConfig{NoAudio: true})
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()

			conn.mu.Lock()
			reader := bufio.NewReader(bytes.NewReader(bytes.Clone(conn.written.Bytes())))
			conn.mu.Unlock()
			var rootSent, videoSent bool
			for {
				request, err := readRTSPTestRequest(reader)
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatal(err)
				}
				if request.method != "SETUP" {
					continue
				}
				var setup map[string]any
				if _, err := plist.Unmarshal(request.body, &setup); err != nil {
					t.Fatal(err)
				}
				rootSent = rootSent || len(plistBytes(setup["ekey"])) > 0 && bytes.Equal(plistBytes(setup["eiv"]), client.fpIV)
				streams, _ := setup["streams"].([]any)
				for _, item := range streams {
					stream, _ := item.(map[string]any)
					_, keySent := stream["shk"]
					switch plistInt(stream["type"]) {
					case 96:
						if keySent {
							t.Fatal("plaintext audio SETUP carried shk")
						}
					case 110:
						videoSent = true
						if keySent == test.fairPlay {
							t.Fatalf("plaintext video SETUP carried shk = %t with FairPlay = %t", keySent, test.fairPlay)
						}
						if iv := plistBytes(stream["shiv"]); len(iv) != 16 || test.fairPlay && !bytes.Equal(iv, client.fpIV) {
							t.Fatal("plaintext video SETUP has an invalid shiv")
						}
					}
				}
			}
			if !videoSent || rootSent != test.fairPlay {
				t.Fatalf("video SETUP sent = %t, FairPlay root sent = %t, want true/%t", videoSent, rootSent, test.fairPlay)
			}
		})
	}
}
