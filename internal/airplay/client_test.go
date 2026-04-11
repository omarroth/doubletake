package airplay

import "testing"

func TestParseHTTPHeaderReturnsHeaders(t *testing.T) {
	header := "RTSP/1.0 200 OK\r\nAudio-Latency: 11025\r\nContent-Length: 12\r\nServer: AirTunes/220.68\r\n\r\n"

	statusCode, contentLength, headers := parseHTTPHeader(header)
	if statusCode != 200 {
		t.Fatalf("statusCode = %d, want 200", statusCode)
	}
	if contentLength != 12 {
		t.Fatalf("contentLength = %d, want 12", contentLength)
	}
	if got := headers["audio-latency"]; got != "11025" {
		t.Fatalf("audio-latency header = %q, want 11025", got)
	}
	if got := headers["server"]; got != "AirTunes/220.68" {
		t.Fatalf("server header = %q, want AirTunes/220.68", got)
	}
}
