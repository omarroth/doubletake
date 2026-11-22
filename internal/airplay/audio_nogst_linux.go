//go:build no_gstreamer

package airplay

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jfreymuth/pulse/proto"
)

func init() { openNativeMonitor = openPulseMonitor }

// Connect to the local desktop sound server directly. PipeWire's PulseAudio
// service implements the same protocol.
func openPulseMonitor(ctx context.Context) (nativePCMInput, error) {
	socket := os.Getenv("PULSE_SERVER")
	if socket == "" {
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			dir = fmt.Sprintf("/run/user/%d", os.Getuid())
		}
		socket = filepath.Join(dir, "pulse", "native")
	}
	socket = strings.TrimPrefix(socket, "unix:")
	if !filepath.IsAbs(socket) {
		return nativePCMInput{}, fmt.Errorf("native Linux audio requires a local PulseAudio socket")
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return nativePCMInput{}, fmt.Errorf("connect to desktop audio at %s: %w", socket, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = conn.Close()
		}
	}()
	abortSetup := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer abortSetup()

	blocks := make(chan nativePCMBlock, 24)
	closed := make(chan struct{})
	var nextPTS time.Time
	var client proto.Client
	client.SetTimeout(time.Second)
	client.Callback = func(event interface{}) {
		switch p := event.(type) {
		case *proto.DataPacket:
			if len(p.Data) == 0 || len(p.Data)%audioBytesPerSampleFrame != 0 {
				return
			}
			duration := audioSamplesDuration(uint64(len(p.Data) / audioBytesPerSampleFrame))
			now := time.Now().Add(-duration)
			if gap := now.Sub(nextPTS); nextPTS.IsZero() || gap < -30*time.Millisecond || gap > 30*time.Millisecond {
				nextPTS = now
			}
			block := nativePCMBlock{samples: append([]byte(nil), p.Data...), pts: nextPTS}
			nextPTS = nextPTS.Add(duration)
			select {
			case blocks <- block:
			default:
				select {
				case <-blocks:
				default:
				}
				blocks <- block
			}
		case *proto.RecordStreamKilled:
			_ = conn.Close()
		case *proto.ConnectionClosed:
			close(closed)
		}
	}
	client.Open(conn)

	cookie := make([]byte, 256)
	cookiePath := os.Getenv("PULSE_COOKIE")
	if cookiePath == "" {
		if config, err := os.UserConfigDir(); err == nil {
			cookiePath = filepath.Join(config, "pulse", "cookie")
		}
	}
	if cookiePath != "" {
		if data, err := os.ReadFile(cookiePath); err == nil && len(data) == len(cookie) {
			cookie = data
		}
	}
	var auth proto.AuthReply
	if err := client.Request(&proto.Auth{Version: client.Version(), Cookie: cookie}, &auth); err != nil {
		return nativePCMInput{}, fmt.Errorf("authorize desktop audio: %w", err)
	}
	client.SetVersion(auth.Version)
	properties := proto.PropList{"application.name": proto.PropListString("doubletake")}
	if err := client.Request(&proto.SetClientName{Props: properties}, nil); err != nil {
		return nativePCMInput{}, fmt.Errorf("register desktop audio client: %w", err)
	}
	var server proto.GetServerInfoReply
	if err := client.Request(&proto.GetServerInfo{}, &server); err != nil {
		return nativePCMInput{}, fmt.Errorf("find default desktop audio output: %w", err)
	}
	if sink := os.Getenv("PULSE_SINK"); sink != "" {
		server.DefaultSinkName = sink
	}
	if server.DefaultSinkName == "" || server.DefaultSinkName == "@DEFAULT_SINK@" {
		return nativePCMInput{}, errors.New("sound server has no default output")
	}
	var sink proto.GetSinkInfoReply
	if err := client.Request(&proto.GetSinkInfo{SinkIndex: proto.Undefined, SinkName: server.DefaultSinkName}, &sink); err != nil {
		return nativePCMInput{}, fmt.Errorf("find default output monitor: %w", err)
	}
	if sink.MonitorSourceIndex == proto.Undefined {
		return nativePCMInput{}, errors.New("default audio output has no monitor")
	}

	const fragment = audioSampleRate / 100 * audioBytesPerSampleFrame
	var stream proto.CreateRecordStreamReply
	err = client.Request(&proto.CreateRecordStream{
		SampleSpec:  proto.SampleSpec{Format: proto.FormatInt16LE, Channels: 2, Rate: audioSampleRate},
		ChannelMap:  proto.ChannelMap{proto.ChannelLeft, proto.ChannelRight},
		SourceIndex: sink.MonitorSourceIndex, NoMove: true, DirectOnInputIndex: proto.Undefined,
		BufferMaxLength: 24 * fragment, BufferFragSize: fragment, AdjustLatency: true,
		Properties:     properties,
		ChannelVolumes: proto.ChannelVolumes{0x10000, 0x10000},
	}, &stream)
	if err != nil {
		return nativePCMInput{}, fmt.Errorf("start PulseAudio output monitor: %w", err)
	}
	if stream.Rate != audioSampleRate || stream.Channels != audioChannels || stream.Format != proto.FormatInt16LE {
		return nativePCMInput{}, fmt.Errorf("sound server did not accept stereo 44.1 kHz S16 PCM")
	}

	client.SetTimeout(volumeSampleInterval)
	pipeWire := strings.Contains(strings.ToLower(server.PackageName), "pipewire")
	volume := &capturedOutputVolume{readLevel: func(ctx context.Context) (float64, bool) {
		if ctx.Err() != nil {
			return 0, false
		}
		var current proto.GetSinkInfoReply
		if err := client.Request(&proto.GetSinkInfo{SinkIndex: proto.Undefined, SinkName: sink.SinkName}, &current); err != nil {
			return 0, false
		}
		var gain float64
		for _, level := range current.ChannelVolumes {
			gain = max(gain, level.Linear())
		}
		const hardwareVolumeFlag = 1
		alreadyApplied := current.Flags&hardwareVolumeFlag == 0
		if pipeWire {
			alreadyApplied = strings.TrimRight(string(current.Properties["monitor.channel-volumes"]), "\x00") == "true"
		}
		return matchingOutputDB(20*math.Log10(gain), current.Mute, alreadyApplied), len(current.ChannelVolumes) != 0
	}}
	ok = true
	return nativePCMInput{
		volume: volume,
		read: func() (nativePCMBlock, error) {
			select {
			case block := <-blocks:
				return block, nil
			case <-closed:
				return nativePCMBlock{}, io.ErrUnexpectedEOF
			case <-ctx.Done():
				return nativePCMBlock{}, ctx.Err()
			}
		},
		close: func() { _ = conn.Close() },
	}, nil
}
