package airplay

import (
	"fmt"
	"testing"
)

func TestPipeWireOutputLevelMatchesOnlyUnappliedGain(t *testing.T) {
	for _, tt := range []struct {
		name          string
		muted         bool
		monitorVolume bool
		channels      string
		want          float64
	}{
		{"unscaled monitor", false, false, "[0.343,0.343]", -9.3},
		{"monitor scales volume", false, true, "[0.343,0.343]", 0},
		{"muted", true, false, "[0.343,0.343]", airPlayMutedVolumeDB},
		{"zero volume", false, false, "[0,0]", airPlayMutedVolumeDB},
		{"quiet volume below receiver range", false, false, "[0.01,0.01]", -30},
		{"volume above unity", false, false, "[2,2]", 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := fmt.Appendf(nil, `[{"info":{"props":{"node.name":"speaker"},
				"params":{"Props":[{"mute":%t,"channelVolumes":%s,
					"params":["monitor.channel-volumes",%t]}]}}}]`, tt.muted, tt.channels, tt.monitorVolume)
			if got, ok := pipeWireOutputLevel(data, "speaker"); !ok || got != tt.want {
				t.Fatalf("gain = %v, known = %t, want %v", got, ok, tt.want)
			}
			if _, ok := pipeWireOutputLevel(data, "other-speaker"); ok {
				t.Fatal("used the level of a sink outside this capture")
			}
		})
	}
}

func TestPulseOutputLevelFollowsHardwareGain(t *testing.T) {
	output := func(flags, mute string) string {
		return fmt.Sprintf(`Sink #4
	Name: speaker
	Mute: %s
	Volume: front-left: 18000 / 27%% / -33.67 dB, front-right: 45875 / 70%% / -9.29 dB
	Flags: %s
Sink #5
	Name: other-speaker
	Mute: yes
	Flags: HW_VOLUME_CTRL DECIBEL_VOLUME
`, mute, flags)
	}
	for _, tt := range []struct {
		flags string
		mute  string
		want  float64
	}{
		{"HARDWARE HW_VOLUME_CTRL DECIBEL_VOLUME", "no", -9.3},
		{"DECIBEL_VOLUME LATENCY", "no", 0},
		{"HARDWARE HW_VOLUME_CTRL", "yes", airPlayMutedVolumeDB},
	} {
		if got, ok := pulseOutputLevel(output(tt.flags, tt.mute), "speaker"); !ok || got != tt.want {
			t.Fatalf("gain = %v, known = %t, want %v", got, ok, tt.want)
		}
	}
}
