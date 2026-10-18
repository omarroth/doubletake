package airplay

import (
	"math"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

type connectionLatencyHint int8

const (
	connectionLatencyLow    connectionLatencyHint = -1
	connectionLatencyNormal connectionLatencyHint = 0
	connectionLatencyHigh   connectionLatencyHint = 1

	// The ordinary screen path selects separate video and audio leads from the
	// same semantic connection hint.
	defaultVideoLatencyLow    = 40 * time.Millisecond
	defaultVideoLatencyNormal = 75 * time.Millisecond
	defaultVideoLatencyHigh   = 100 * time.Millisecond
	defaultAudioLatencyLow    = 50 * time.Millisecond
	defaultAudioLatencyNormal = 85 * time.Millisecond
	defaultAudioLatencyHigh   = 170 * time.Millisecond
)

type screenLatencyTargets struct {
	video time.Duration
	audio time.Duration
}

type localNetworkInterface struct {
	name  string
	addrs []net.Addr
}

const networkInterfaceClassPath = "/sys/class/net"

// connectionLatencyHintForConnection mirrors the sender's use of the control
// connection interface latency hint. A wireless route uses the high-latency
// screen profile, which leaves enough receiver headroom for normal Wi-Fi jitter.
// Unknown and non-wireless interfaces retain the ordinary profile.
func connectionLatencyHintForConnection(conn net.Conn) (connectionLatencyHint, string) {
	if conn == nil {
		return connectionLatencyNormal, ""
	}
	localAddr, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || localAddr.IP == nil || localAddr.IP.IsUnspecified() {
		return connectionLatencyNormal, ""
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return connectionLatencyNormal, ""
	}
	snapshots := make([]localNetworkInterface, 0, len(interfaces))
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		snapshots = append(snapshots, localNetworkInterface{name: iface.Name, addrs: addrs})
	}
	return connectionLatencyHintForLocalIP(localAddr.IP, snapshots, networkInterfaceClassPath)
}

func connectionLatencyHintForLocalIP(localIP net.IP, interfaces []localNetworkInterface, classPath string) (connectionLatencyHint, string) {
	if localIP == nil {
		return connectionLatencyNormal, ""
	}
	for _, iface := range interfaces {
		for _, addr := range iface.addrs {
			if !networkAddressIP(addr).Equal(localIP) {
				continue
			}
			if networkInterfaceIsWireless(iface.name, classPath) {
				return connectionLatencyHigh, iface.name
			}
			return connectionLatencyNormal, iface.name
		}
	}
	return connectionLatencyNormal, ""
}

func networkAddressIP(addr net.Addr) net.IP {
	switch value := addr.(type) {
	case *net.IPNet:
		return value.IP
	case *net.IPAddr:
		return value.IP
	default:
		return nil
	}
}

func networkInterfaceIsWireless(name, classPath string) bool {
	for _, marker := range []string{"wireless", "phy80211"} {
		if _, err := os.Stat(filepath.Join(classPath, name, marker)); err == nil {
			return true
		}
	}
	return false
}

func connectionLatencyHintName(hint connectionLatencyHint) string {
	switch hint {
	case connectionLatencyLow:
		return "low"
	case connectionLatencyHigh:
		return "high"
	default:
		return "normal"
	}
}

// withMinimumVideoLead gives a locally measured capture pipeline enough room
// while preserving the relative audio/video policy for the connection hint.
// This is sender scheduling compensation, not a receiver or codec-specific
// clock offset.
func (targets screenLatencyTargets) withMinimumVideoLead(minimum time.Duration) screenLatencyTargets {
	if minimum <= targets.video {
		return targets
	}
	delta := minimum - targets.video
	targets.video += delta
	targets.audio += delta
	return targets
}

var targetLatencyNS atomic.Int64

// SetTargetLatency sets the application's explicit joint playout lead. Screen
// and audio overrides are independent, but doubletake historically exposed one
// flag for both; applying the same explicit value preserves that contract. A
// non-positive value restores the automatic policy.
func SetTargetLatency(d time.Duration) {
	if d <= 0 {
		targetLatencyNS.Store(0)
		return
	}
	if d < 5*time.Millisecond {
		d = 5 * time.Millisecond
	}
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	targetLatencyNS.Store(int64(d))
}

// TargetLatency returns the video lead for an ordinary connection. It remains
// the compatibility accessor for callers that only need the video timestamp
// bias; new session setup should use screenLatenciesForHint.
func TargetLatency() time.Duration {
	return screenLatenciesForHint(connectionLatencyNormal).video
}

// HasExplicitTargetLatency reports whether SetTargetLatency currently replaces
// automatic capture calibration with one joint audio/video lead.
func HasExplicitTargetLatency() bool {
	return targetLatencyIsExplicit()
}

func targetLatencyIsExplicit() bool {
	return targetLatencyNS.Load() > 0
}

func screenLatenciesForHint(hint connectionLatencyHint) screenLatencyTargets {
	var targets screenLatencyTargets
	switch hint {
	case connectionLatencyLow:
		targets = screenLatencyTargets{video: defaultVideoLatencyLow, audio: defaultAudioLatencyLow}
	case connectionLatencyHigh:
		targets = screenLatencyTargets{video: defaultVideoLatencyHigh, audio: defaultAudioLatencyHigh}
	default:
		targets = screenLatencyTargets{video: defaultVideoLatencyNormal, audio: defaultAudioLatencyNormal}
	}

	if override := time.Duration(targetLatencyNS.Load()); override > 0 {
		targets.video = override
		targets.audio = override
	}
	return targets
}

func targetLatencySamples44k1() uint32 {
	return samplesFor44k1(screenLatenciesForHint(connectionLatencyNormal).audio)
}

func samplesFor44k1(d time.Duration) uint32 {
	// Convert millisecond latency to the integral SETUP and RTP-timebase value by
	// truncation: 85 ms is 3748.5 samples and is advertised as 3748, not rounded
	// to 3749.
	samples := int64(d/time.Second)*44100 + int64(d%time.Second)*44100/int64(time.Second)
	if samples < 1 {
		samples = 1
	}
	if samples > math.MaxUint32 {
		samples = math.MaxUint32
	}
	return uint32(samples)
}

// SharedPlayoutLatency provides a common budget for all daemon destinations.
// A quarter second absorbs the existing bounded capture/fan-out stall window;
// the explicit joint latency option remains authoritative.
func SharedPlayoutLatency() time.Duration {
	if explicit := time.Duration(targetLatencyNS.Load()); explicit > 0 {
		return explicit
	}
	return audioCaptureStallBuffer
}
