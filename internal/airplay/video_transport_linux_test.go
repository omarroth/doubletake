//go:build linux

package airplay

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestVideoTransportSamplerReadsTCPInfo(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
		close(accepted)
	}()
	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server := <-accepted
	if server == nil {
		t.Fatal("listener did not accept the test connection")
	}
	defer server.Close()

	payload := make([]byte, 64<<10)
	received := make([]byte, len(payload))
	readDone := make(chan error, 1)
	go func() {
		_, err := io.ReadFull(server, received)
		readDone <- err
	}()
	if _, err := client.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}

	sampler := newVideoTransportSampler(client)
	if sampler == nil {
		t.Fatal("TCP connection did not expose syscall.Conn")
	}
	now := time.Now()
	metrics, ok := sampler.sample(now)
	if !ok {
		t.Fatal("TCP_INFO sampling failed")
	}
	if !metrics.At.Equal(now) {
		t.Fatalf("sample time = %v, want %v", metrics.At, now)
	}
	if metrics.RoundTripTime <= 0 || metrics.MinimumRoundTripTime <= 0 {
		t.Fatalf("TCP_INFO returned invalid RTT metrics: current=%v minimum=%v", metrics.RoundTripTime, metrics.MinimumRoundTripTime)
	}
}
