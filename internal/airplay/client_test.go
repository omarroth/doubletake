package airplay

import (
	"net"
	"testing"
)

func TestParseHTTPHeaderReturnsHeaders(t *testing.T) {
	header := "RTSP/1.0 200 OK\r\nAudio-Latency: 11025\r\nContent-Length: 12\r\nServer: AirTunes/220.68\r\n\r\n"

	statusCode, contentLength, headers, err := parseHTTPHeader(header)
	if err != nil {
		t.Fatalf("parseHTTPHeader: %v", err)
	}
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

type remoteAddrConn struct {
	net.Conn
	remote net.Addr
}

func (c remoteAddrConn) RemoteAddr() net.Addr { return c.remote }

func TestSessionPeerHostUsesRTSPPeerAddress(t *testing.T) {
	nonTCPA, nonTCPB := net.Pipe()
	t.Cleanup(func() {
		_ = nonTCPA.Close()
		_ = nonTCPB.Close()
	})

	tests := []struct {
		name   string
		client *AirPlayClient
		want   string
	}{
		{name: "nil client", want: ""},
		{name: "no connection", client: &AirPlayClient{host: "receiver.local"}, want: "receiver.local"},
		{
			name:   "IPv4 peer",
			client: &AirPlayClient{host: "receiver.local", conn: remoteAddrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7000}}},
			want:   "192.0.2.10",
		},
		{
			name:   "IPv6 peer",
			client: &AirPlayClient{host: "receiver.local", conn: remoteAddrConn{remote: &net.TCPAddr{IP: net.ParseIP("2001:db8::10"), Port: 7000}}},
			want:   "2001:db8::10",
		},
		{
			name:   "link-local peer keeps zone",
			client: &AirPlayClient{host: "receiver.local", conn: remoteAddrConn{remote: &net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 7000, Zone: "eth0"}}},
			want:   "fe80::1%eth0",
		},
		{
			name:   "IPv4 peer ignores invalid zone",
			client: &AirPlayClient{host: "receiver.local", conn: remoteAddrConn{remote: &net.TCPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7000, Zone: "eth0"}}},
			want:   "192.0.2.10",
		},
		{
			name:   "empty TCP address",
			client: &AirPlayClient{host: "receiver.local", conn: remoteAddrConn{remote: &net.TCPAddr{Port: 7000}}},
			want:   "receiver.local",
		},
		{
			name:   "non-TCP connection",
			client: &AirPlayClient{host: "receiver.local", conn: nonTCPA},
			want:   "receiver.local",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.client.sessionPeerHost(); got != test.want {
				t.Fatalf("sessionPeerHost() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestSessionPeerHostPreservesUDPFamilyAndZone(t *testing.T) {
	client := &AirPlayClient{
		host: "receiver.local",
		conn: remoteAddrConn{remote: &net.TCPAddr{
			IP: net.ParseIP("fe80::1"), Port: 7000, Zone: "eth0",
		}},
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(client.sessionPeerHost(), "6001"))
	if err != nil {
		t.Fatalf("ResolveUDPAddr: %v", err)
	}
	if addr.IP.To4() != nil || !addr.IP.Equal(net.ParseIP("fe80::1")) || addr.Zone != "eth0" || addr.Port != 6001 {
		t.Fatalf("resolved %v, want IPv6 fe80::1%%eth0 port 6001", addr)
	}
}
