package airplay

import (
	"bufio"
	"context"
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

func TestSetupMirrorNoAudioStillNegotiatesAudioSession(t *testing.T) {
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

	requests := make(chan rtspTestRequest, 8)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := rtspListener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
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

			switch req.method {
			case "SETUP":
				var setup map[string]interface{}
				if _, err := plist.Unmarshal(req.body, &setup); err != nil {
					serverErr <- fmt.Errorf("decode setup plist: %w", err)
					return
				}
				streams, _ := setup["streams"].([]interface{})
				if len(streams) != 1 {
					serverErr <- fmt.Errorf("expected one stream in setup, got %d", len(streams))
					return
				}
				stream, _ := streams[0].(map[string]interface{})
				streamType := plistInt(stream["type"])
				var respBody []byte
				switch streamType {
				case 96:
					if got, _ := setup["timingProtocol"].(string); got != "NTP" {
						serverErr <- fmt.Errorf("expected timingProtocol NTP in audio setup, got %q", got)
						return
					}
					if got := plistInt(setup["timingPort"]); got <= 0 {
						serverErr <- fmt.Errorf("expected positive timingPort in audio setup, got %d", got)
						return
					}
					if got := plistInt(stream["controlPort"]); got <= 0 {
						serverErr <- fmt.Errorf("expected positive controlPort in audio setup, got %d", got)
						return
					}
					respBody, err = plist.Marshal(map[string]interface{}{
						"streams": []interface{}{
							map[string]interface{}{
								"type":        int64(96),
								"dataPort":    int64(6100),
								"controlPort": int64(6101),
							},
						},
					}, plist.BinaryFormat)
				case 110:
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
			case "RECORD":
				if err := writeRTSPTestResponse(conn, 200, map[string]string{"Audio-Latency": "11025"}, nil); err != nil {
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

	session, err := client.SetupMirror(ctx, StreamConfig{Width: 1280, Height: 720, FPS: 30, NoAudio: true})
	if err != nil {
		t.Fatalf("SetupMirror(no audio): %v", err)
	}
	if !session.HasAudio() {
		t.Fatal("expected no-audio session setup to keep the negotiated audio stream state")
	}

	select {
	case conn := <-dataAccepted:
		if conn != nil {
			defer conn.Close()
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for video data connection")
	}

	if err := session.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var got []rtspTestRequest
	collectTimeout := time.After(250 * time.Millisecond)
	collecting := true
	for collecting {
		select {
		case req := <-requests:
			got = append(got, req)
		case <-collectTimeout:
			collecting = false
		}
	}

	if len(got) < 2 {
		t.Fatalf("expected full setup sequence, got %d requests", len(got))
	}
	wantMethods := []string{"SETUP", "SETUP", "RECORD", "SET_PARAMETER", "SET_PARAMETER", "TEARDOWN"}
	if len(got) != len(wantMethods) {
		t.Fatalf("got %d RTSP requests, want %d", len(got), len(wantMethods))
	}
	for index, want := range wantMethods {
		if got[index].method != want {
			t.Fatalf("request %d = %s, want %s", index, got[index].method, want)
		}
	}
	if got[0].uri == got[1].uri {
		t.Fatal("video SETUP should use a distinct URI from the audio control session")
	}
	if got[0].uri != got[2].uri || got[0].uri != got[3].uri || got[0].uri != got[4].uri {
		t.Fatal("audio SETUP, RECORD, and volume SET_PARAMETER requests should share the audio URI")
	}
	if got[len(got)-1].uri != got[0].uri {
		t.Fatalf("TEARDOWN URI = %s, want %s", got[len(got)-1].uri, got[0].uri)
	}

	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
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
