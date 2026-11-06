package airplay

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AudioSource selects a local capture route, independently of receiver codecs.
type AudioSource string

const (
	AudioSourceOutput     AudioSource = "output"
	AudioSourceMonitor    AudioSource = "monitor"
	stableAudioOutputName             = "doubletake"
)

func ValidateAudioSource(source string) error {
	if source == "" || AudioSource(source) == AudioSourceOutput || AudioSource(source) == AudioSourceMonitor {
		return nil
	}
	return fmt.Errorf("unknown audio source %q (use output or monitor)", source)
}

type pulseCommand func(context.Context, ...string) ([]byte, error)

func runPulseCommand(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "pactl", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("pactl %s: %w: %s", args[0], err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// All receivers in this process consume the same selectable output, including
// streams using different encoders. Its lifetime ends with the last capture.
type audioOutputManager struct {
	mu         sync.Mutex
	run        pulseCommand
	name       string
	module     string
	generation string
	users      int
}

var sharedAudioOutput = audioOutputManager{run: runPulseCommand}

func (m *audioOutputManager) acquire(ctx context.Context) (string, func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return "", nil, err
	}
	if m.users == 0 {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return "", nil, fmt.Errorf("name audio output: %w", err)
		}
		generation := fmt.Sprintf("%x", suffix)
		name := stableAudioOutputName
		if m.outputExists(ctx, name) {
			// A concurrent process owns the stable sink. Keep both captures
			// independent rather than adopting an output the other process can
			// remove, at the cost of volume restoration for this fallback only.
			name += "_" + generation
		}
		module, err := m.create(ctx, name, generation)
		// Another process can claim the stable name between the check and load.
		// Retry under this process's unique name only when that race is visible.
		if err != nil && name == stableAudioOutputName && m.outputExists(ctx, name) {
			name += "_" + generation
			module, err = m.create(ctx, name, generation)
		}
		if err != nil {
			return "", nil, fmt.Errorf("create doubletake audio output (requires pactl and PulseAudio or pipewire-pulse): %w", err)
		}
		m.name, m.module, m.generation = name, module, generation
		log.Printf("[AUDIO] output doubletake is available; select it in your sound settings to route applications here")
	}
	m.users++
	name := m.name
	var once sync.Once
	release := func() {
		once.Do(func() {
			m.mu.Lock()
			defer m.mu.Unlock()
			m.users--
			if m.users == 0 {
				m.remove(m.name, m.module, m.generation)
				m.name, m.module, m.generation = "", "", ""
			}
		})
	}
	return name + ".monitor", release, nil
}

func (m *audioOutputManager) create(ctx context.Context, name, generation string) (string, error) {
	// module-null-sink is implemented by both PulseAudio and pipewire-pulse.
	// The PipeWire property enables sink volume/mute on its monitor ports;
	// PulseAudio's software null sink already applies these to the mix.
	out, err := m.run(ctx, "load-module", "module-null-sink", "sink_name="+name,
		"format=s16le", "rate=44100", "channels=2", "channel_map=front-left,front-right",
		fmt.Sprintf("sink_properties='device.description=doubletake device.class=sound monitor.channel-volumes=true doubletake.generation=%s'", generation))
	module := strings.TrimSpace(string(out))
	if _, parseErr := strconv.ParseUint(module, 10, 32); err != nil || parseErr != nil {
		// A canceled load may have reached the server without returning its ID.
		// The generation property prevents cleanup from touching a sink owned
		// by another process, including one using the stable name.
		m.remove(name, "", generation)
		if err == nil {
			err = fmt.Errorf("invalid module ID %q", module)
		}
		return "", err
	}
	return module, nil
}

func (m *audioOutputManager) outputExists(ctx context.Context, name string) bool {
	out, err := m.run(ctx, "list", "short", "sinks")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == name {
			return true
		}
	}
	return false
}

func (m *audioOutputManager) remove(name, module, generation string) {
	// The sound server may have restarted and reused a module number. Match its
	// type, complete sink_name and private generation before unloading anything.
	out, err := m.run(context.Background(), "list", "short", "modules")
	if err != nil {
		log.Printf("[AUDIO] could not check output cleanup: %v", err)
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "module-null-sink" || (module != "" && fields[0] != module) {
			continue
		}
		if !pulseModuleLineHasArgument(fields[2:], "sink_name="+name) ||
			!pulseModuleLineHasArgument(fields[2:], "doubletake.generation="+generation) {
			continue
		}
		if _, err := m.run(context.Background(), "unload-module", fields[0]); err != nil {
			log.Printf("[AUDIO] could not remove output %s: %v", name, err)
		}
		return
	}
}

func pulseModuleLineHasArgument(fields []string, want string) bool {
	for _, field := range fields {
		field = strings.Trim(field, "'\"")
		if field == want {
			return true
		}
		if value, ok := strings.CutPrefix(field, "sink_properties="); ok &&
			strings.Trim(value, "'\"") == want {
			return true
		}
	}
	return false
}
