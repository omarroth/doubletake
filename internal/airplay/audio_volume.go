package airplay

import (
	"context"
	"encoding/json"
	"math"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const volumeSampleInterval = 500 * time.Millisecond

// Each tap of a shared capture reads the same sink's level. Cache one sound
// server query per interval regardless of the number of receivers.
type capturedOutputVolume struct {
	sink           string
	alreadyApplied bool
	readLevel      func(context.Context) (float64, bool)

	mu          sync.Mutex
	nextSample  time.Time
	volume      float64
	known       bool
	pipeWire    bool
	serverKnown bool
}

func (v *capturedOutputVolume) read(ctx context.Context) (float64, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.alreadyApplied {
		return 0, true
	}
	if time.Now().Before(v.nextSample) {
		return v.volume, v.known
	}
	ctx, cancel := context.WithTimeout(ctx, volumeSampleInterval)
	defer cancel()
	v.volume, v.known = v.sample(ctx)
	v.nextSample = time.Now().Add(volumeSampleInterval)
	return v.volume, v.known
}

func (v *capturedOutputVolume) sample(ctx context.Context) (float64, bool) {
	if v.readLevel != nil {
		return v.readLevel(ctx)
	}
	if !v.serverKnown {
		info, err := runPulseCommand(ctx, "info")
		if err != nil {
			return 0, false
		}
		for _, line := range strings.Split(string(info), "\n") {
			name, found := strings.CutPrefix(line, "Server Name:")
			if found {
				v.pipeWire = strings.Contains(strings.ToLower(name), "pipewire")
				v.serverKnown = true
				break
			}
		}
		if !v.serverKnown {
			return 0, false
		}
	}
	if v.pipeWire {
		data, err := exec.CommandContext(ctx, "pw-dump", "--", v.sink).Output()
		if err != nil {
			return 0, false
		}
		return pipeWireOutputLevel(data, v.sink)
	}
	data, err := runPulseCommand(ctx, "list", "sinks")
	if err != nil {
		return 0, false
	}
	return pulseOutputLevel(string(data), v.sink)
}

func pipeWireOutputLevel(data []byte, sink string) (float64, bool) {
	var nodes []struct {
		Info struct {
			Props  map[string]json.RawMessage
			Params struct {
				Props []struct {
					Mute           bool
					ChannelVolumes []float64
					Params         []json.RawMessage
				}
			}
		}
	}
	if json.Unmarshal(data, &nodes) != nil {
		return 0, false
	}
	for _, node := range nodes {
		var name string
		if json.Unmarshal(node.Info.Props["node.name"], &name) != nil || name != sink {
			continue
		}
		for _, props := range node.Info.Params.Props {
			if len(props.ChannelVolumes) == 0 {
				continue
			}
			monitorAppliesVolume := string(node.Info.Props["monitor.channel-volumes"]) == "true" ||
				string(node.Info.Props["monitor.channel-volumes"]) == `"true"`
			for i := 0; i+1 < len(props.Params); i += 2 {
				if string(props.Params[i]) == `"monitor.channel-volumes"` {
					monitorAppliesVolume = string(props.Params[i+1]) == "true"
					break
				}
			}
			var gain float64
			for _, level := range props.ChannelVolumes {
				gain = math.Max(gain, level)
			}
			return matchingOutputDB(20*math.Log10(gain), props.Mute, monitorAppliesVolume), true
		}
	}
	return 0, false
}

var pulseDBField = regexp.MustCompile(`(-?inf|[+-]?[0-9]+(?:\.[0-9]+)?)\s+dB($|[,\s])`)

func pulseOutputLevel(sinks, sink string) (float64, bool) {
	for _, block := range strings.Split(sinks, "Sink #") {
		var name, flags, volume string
		var muted bool
		for _, line := range strings.Split(block, "\n") {
			key, value, _ := strings.Cut(strings.TrimSpace(line), ":")
			value = strings.TrimSpace(value)
			switch key {
			case "Name":
				name = value
			case "Flags":
				flags = value
			case "Volume":
				volume = value
			case "Mute":
				muted = value == "yes"
			}
		}
		if name != sink {
			continue
		}
		if muted {
			return airPlayMutedVolumeDB, true
		}
		// PulseAudio renders software sink volume into the buffer sent to
		// the monitor. Hardware volume is applied after that buffer.
		if !strings.Contains(" "+flags+" ", " HW_VOLUME_CTRL ") {
			return 0, flags != ""
		}
		db := math.Inf(-1)
		found := false
		for _, field := range pulseDBField.FindAllStringSubmatch(volume, -1) {
			level, err := strconv.ParseFloat(field[1], 64)
			if err == nil {
				db = math.Max(db, level)
				found = true
			}
		}
		return matchingOutputDB(db, false, false), found
	}
	return 0, false
}

func matchingOutputDB(db float64, muted, alreadyApplied bool) float64 {
	switch {
	case muted || math.IsInf(db, -1):
		return airPlayMutedVolumeDB
	case alreadyApplied:
		return 0
	default:
		return math.Round(math.Max(airPlayMinimumVolumeDB, math.Min(db, 0))*10) / 10
	}
}
