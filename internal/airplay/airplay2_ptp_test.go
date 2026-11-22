//go:build cgo && gstreamer_cgo

package airplay

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestAirPlay2PTPAudioSharesClockAcrossRooms(t *testing.T) {
	if exec.Command("gst-inspect-1.0", "rtponviftimestamp").Run() != nil {
		t.Skip("requires GStreamer ONVIF timestamps")
	}
	if exec.Command("gst-inspect-1.0", "avdec_alac").Run() != nil &&
		exec.Command("gst-inspect-1.0", "alacdec").Run() != nil {
		t.Skip("requires GStreamer ALAC decoding")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Second)
	defer cancel()
	listen := func(host string, port int) *net.UDPConn {
		t.Helper()
		conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host), Port: port})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		return conn
	}
	event, general := listen("127.0.0.1", 0), listen("127.0.0.1", 0)
	eventAddr := event.LocalAddr().(*net.UDPAddr)
	generalAddr := general.LocalAddr().(*net.UDPAddr)
	binds := 0
	pool := &ptpClockPool{
		bind: func() (*net.UDPConn, *net.UDPConn, error) {
			binds++
			return event, general, nil
		},
		peerEventPort: uint16(eventAddr.Port), peerGeneralPort: uint16(generalAddr.Port),
	}
	type audioFrame struct {
		hash     uint64
		deadline time.Time
	}
	type room struct {
		receiver       *ReceiverServer
		session        *AudioOnlySession
		observed       atomic.Uint64
		delayResponses atomic.Uint32
		clockOffset    atomic.Int64
		done           chan error
		frames         chan audioFrame
	}
	rooms := [2]*room{{}, {}}
	var capture SharedAudioCapture
	defer capture.Close()
	for index, host := range []string{"127.0.0.2", "127.0.0.3"} {
		room := rooms[index]
		room.frames = make(chan audioFrame, 1024)
		peerEvent := listen(host, eventAddr.Port)
		peerGeneral := listen(host, generalAddr.Port)
		receiver, err := NewReceiverServer(ReceiverConfig{
			ListenAddress: net.JoinHostPort(host, "0"),
			RealtimeAudio: true, DecodeMedia: true, AudioDropEvery: 13,
			AudioProbe: func(hash uint64, deadline, _ time.Time) {
				select {
				case room.frames <- audioFrame{hash: hash, deadline: deadline}:
				default:
				}
			},
			realtimePTPNow: func() time.Duration {
				return time.Duration(time.Now().UnixNano() + room.clockOffset.Load())
			},
			realtimePTPStart: func(clockID uint64) error {
				room.observed.Store(clockID)
				go func() {
					b := make([]byte, 512)
					requester := uint64(0xabcdef000001) + uint64(index)
					var sequence uint16
					for ctx.Err() == nil {
						_ = peerGeneral.SetReadDeadline(time.Now().Add(time.Second))
						n, from, err := peerGeneral.ReadFromUDP(b)
						if err != nil {
							continue
						}
						if n < 44 || !from.IP.Equal(generalAddr.IP) || from.Port != generalAddr.Port ||
							binary.BigEndian.Uint64(b[20:28]) != clockID {
							continue
						}
						switch b[0] & 15 {
						case 8: // Follow_Up timestamp from the selected clock.
							seconds := uint64(binary.BigEndian.Uint16(b[34:36]))<<32 | uint64(binary.BigEndian.Uint32(b[36:40]))
							nanos := seconds*1_000_000_000 + uint64(binary.BigEndian.Uint32(b[40:44]))
							room.clockOffset.Store(int64(nanos) - time.Now().UnixNano())
							var packet [44]byte
							packet[0], packet[1] = 1, 2 // Delay_Req
							binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
							binary.BigEndian.PutUint64(packet[20:28], requester)
							binary.BigEndian.PutUint16(packet[28:30], 1)
							binary.BigEndian.PutUint16(packet[30:32], sequence)
							sequence++
							_, _ = peerEvent.WriteToUDP(packet[:], eventAddr)
						case 9: // Delay_Resp names the receiver that asked.
							if n >= 54 && binary.BigEndian.Uint64(b[44:52]) == requester {
								room.delayResponses.Add(1)
							}
						}
					}
				}()
				return nil
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		room.receiver = receiver
		defer receiver.Close()
		go receiver.Serve(ctx)
		address := receiver.Addr().(*net.TCPAddr)
		device := AirPlayDevice{
			IP: address.IP.String(), Port: address.Port,
			DeviceID: receiver.cfg.DeviceID, Features: receiver.profile.features,
		}
		session, err := OpenAudioOnly(ctx, device, AudioOnlyConfig{ptpPool: pool}, nil, device.DeviceID)
		if err != nil {
			t.Fatalf("room %d: %v", index+1, err)
		}
		room.session = session
		defer session.Close()
		if session.playback.timingProtocol != timingProtocolPTP {
			t.Fatalf("room %d negotiated %s", index+1, session.playback.timingProtocol)
		}
		tap, err := capture.Acquire(ctx, true, AudioCodecALAC, AudioSourceMonitor)
		if err != nil {
			t.Fatal(err)
		}
		defer tap.Stop()
		room.done = make(chan error, 1)
		go func() { room.done <- session.Stream(ctx, tap) }()
	}
	if first, second := rooms[0].observed.Load(), rooms[1].observed.Load(); first == 0 || first != second || binds != 1 {
		t.Fatalf("receivers did not share one clock (IDs %x and %x, %d binds)", first, second, binds)
	}
	if stats := capture.Stats(); stats.Sources != 1 || stats.Encoders != 1 || stats.Receivers != 2 {
		t.Fatalf("rooms did not share capture: %+v", stats)
	}
	for i, room := range rooms {
		for {
			stats := room.receiver.Stats()
			if stats.Playback.AudioPlayedSamples >= 12*352 && stats.Playback.AudioRecovered > 0 {
				if room.delayResponses.Load() < 3 || stats.VideoConnections != 0 || stats.Playback.AudioPeak == 0 ||
					stats.Playback.DecodeErrors != 0 || stats.Playback.TimestampErrors != 0 ||
					stats.Playback.AudioCryptoErrors != 0 {
					t.Fatalf("room %d invalid playback: %+v", i+1, stats)
				}
				break
			}
			select {
			case err := <-room.done:
				t.Fatalf("room %d stopped early: %v", i+1, err)
			case <-ctx.Done():
				t.Fatalf("room %d did not play: %+v", i+1, stats)
			case <-time.After(20 * time.Millisecond):
			}
		}
	}
	deadlines := [2]map[uint64]time.Time{{}, {}}
	for matched := 0; matched < 8; {
		var index int
		var frame audioFrame
		select {
		case frame = <-rooms[0].frames:
		case frame = <-rooms[1].frames:
			index = 1
		case <-ctx.Done():
			t.Fatalf("matched only %d playout deadlines across rooms", matched)
		}
		deadlines[index][frame.hash] = frame.deadline
		if other, ok := deadlines[1-index][frame.hash]; ok && frame.deadline.Sub(other).Abs() <= 4*time.Millisecond {
			delete(deadlines[0], frame.hash)
			delete(deadlines[1], frame.hash)
			matched++
		}
	}
	cancel()
	for _, room := range rooms {
		<-room.done
		_ = room.session.Close()
	}
	if pool.clock != nil || pool.users != 0 {
		t.Fatal("final session did not release PTP sockets")
	}
}

func TestAirPlay2PTPUnavailableFallsBackToAdvertisedClassicAudio(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	realtime, err := NewReceiverServer(ReceiverConfig{
		ListenAddress: "127.0.0.1:0", RealtimeAudio: true,
		realtimePTPStart: func(uint64) error { return errors.New("unexpected SETPEERS") },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer realtime.Close()
	go realtime.Serve(ctx)
	classic, err := NewReceiverServer(ReceiverConfig{
		ListenAddress: "127.0.0.1:0", Profile: ReceiverProfileRAOP,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer classic.Close()
	go classic.Serve(ctx)
	store, err := NewCredentialStore(filepath.Join(t.TempDir(), "pairings.json"))
	if err != nil {
		t.Fatal(err)
	}
	address := realtime.Addr().(*net.TCPAddr)
	device := AirPlayDevice{
		IP: address.IP.String(), Port: address.Port,
		DeviceID: realtime.cfg.DeviceID, Features: realtime.profile.features,
	}
	cfg := AudioOnlyConfig{
		ptpPool: &ptpClockPool{bind: func() (*net.UDPConn, *net.UDPConn, error) {
			return nil, nil, errors.New("test PTP port bind failure")
		}},
	}
	if session, err := OpenAudioOnly(ctx, device, cfg, store, device.DeviceID); !errors.Is(err, errAudioPTPUnavailable) {
		if session != nil {
			session.Close()
		}
		t.Fatalf("expected the PTP bind error without classic advertisement, got %v", err)
	}
	device.RAOP = classic.RAOPDevice().RAOP
	session, err := OpenAudioOnly(ctx, device, cfg, store, device.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if stats := classic.Stats(); stats.RecordRequests != 1 {
		t.Fatalf("classic receiver did not start playback: %+v", stats)
	}
}
