//go:build linux

package airplay

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type videoTransportSampler struct {
	conn syscall.Conn
}

func newVideoTransportSampler(conn net.Conn) *videoTransportSampler {
	raw, ok := conn.(syscall.Conn)
	if !ok {
		return nil
	}
	return &videoTransportSampler{conn: raw}
}

func (s *videoTransportSampler) sample(at time.Time) (videoTransportMetrics, bool) {
	if s == nil || s.conn == nil {
		return videoTransportMetrics{}, false
	}
	var info *unix.TCPInfo
	raw, err := s.conn.SyscallConn()
	if err != nil {
		return videoTransportMetrics{}, false
	}
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		info, socketErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
	}); err != nil || socketErr != nil || info == nil {
		return videoTransportMetrics{}, false
	}

	delivery := saturatingMultiply(info.Delivery_rate, 8)
	pacing := saturatingMultiply(info.Pacing_rate, 8)
	// Linux represents an unlimited pacing rate as UINT64_MAX.
	if info.Pacing_rate == ^uint64(0) || info.Pacing_rate == 0 {
		pacing = 0
	}
	var congestionWindow uint64
	if info.Rtt != 0 && info.Snd_cwnd != 0 && info.Snd_mss != 0 {
		windowBytes := saturatingMultiply(uint64(info.Snd_cwnd), uint64(info.Snd_mss))
		congestionWindow = saturatingMultiply(windowBytes, 8_000_000) / uint64(info.Rtt)
	}
	return videoTransportMetrics{
		At:                      at,
		DeliveryRateBps:         delivery,
		PacingRateBps:           pacing,
		CongestionWindowRateBps: congestionWindow,
		BytesAcked:              info.Bytes_acked,
		BytesRetransmitted:      info.Bytes_retrans,
		NotSentBytes:            info.Notsent_bytes,
		RoundTripTime:           time.Duration(info.Rtt) * time.Microsecond,
		RoundTripVariation:      time.Duration(info.Rttvar) * time.Microsecond,
		MinimumRoundTripTime:    time.Duration(info.Min_rtt) * time.Microsecond,
		transportSampled:        true,
	}, true
}
