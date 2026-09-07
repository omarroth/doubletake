package airplay

import (
	"fmt"
	"strconv"
	"strings"
)

type audioConnectionLayout uint8

const (
	audioLayoutControlPort audioConnectionLayout = iota
	audioLayoutStreamConnections
)

type fairPlayRootPlacement uint8

const (
	fairPlayDescriptorOnly fairPlayRootPlacement = iota
	fairPlayAllRoots
)

type receiverCompatibility struct {
	timing           string
	audioSecurity    audioSecurityMode
	audioConnections audioConnectionLayout
	audioCodec       AudioCodec
	fairPlayRoots    fairPlayRootPlacement
}

const (
	// These bit numbers are AirPlay feature indices used by Apple's sender, not
	// receiver fingerprints. Feature 41 advertises PTP and feature 59 advertises
	// the streamConnections audio descriptor.
	featurePTP                         uint   = 41
	featureAudioStreamConnectionSetup  uint   = 59
	minimumPTPSourceVersionMajor              = 354
	minimumPTPSourceVersionMinor              = 54
	minimumPTPSourceVersionPatch              = 6
	screenAudioFormatALAC              uint64 = 0x00040000
	screenAudioFormatAACELD44100Stereo uint64 = 0x01000000
)

func compatibilityForReceiver(info *ReceiverInfo, encrypted, audioEnabled bool) (receiverCompatibility, error) {
	audioCodec, err := screenAudioCodec(info)
	if err != nil && audioEnabled {
		return receiverCompatibility{}, err
	}
	if err != nil {
		// A video-only session still creates AirPlay's screen-audio descriptor so
		// legacy receivers reach the same ready state, but no audio packets follow.
		// Keep the historical descriptor value as an inert placeholder rather than
		// rejecting a usable video path for an audio mask it will never consume.
		audioCodec = AudioCodecALAC
	}
	policy := receiverCompatibility{
		timing:           timingProtocolNTP,
		audioSecurity:    selectAudioSecurityMode(encrypted),
		audioConnections: audioLayoutControlPort,
		audioCodec:       audioCodec,
		fairPlayRoots:    fairPlayAllRoots,
	}
	if encrypted {
		// An encrypted HAP pair-verify session has a CoreUtils key holder. Stream
		// descriptors carry the key references; legacy root ekey/eiv fields are
		// neither needed nor part of that setup form.
		policy.fairPlayRoots = fairPlayDescriptorOnly
	}

	if info == nil {
		return policy, nil
	}

	// Feature 59 specifies streamConnections. It does not select SETUP order;
	// the sender starts with Apple's control-first sequence and negotiates a
	// legacy media-first sequence only after an explicit protocol rejection.
	if info.HasFeature(featureAudioStreamConnectionSetup) {
		policy.audioConnections = audioLayoutStreamConnections
	}

	// The sender gates PTP on both feature 41 and SourceVersion 354.54.6. PTP is
	// meaningful here only after pair-verify actually encrypted the control
	// channel. SourceVersion 377.40.x is a narrowly observed interoperability
	// exception whose feature 41 advertisement does not yield a working PTP
	// mirroring session.
	if encrypted && info.HasFeature(featurePTP) && supportsPTPSourceVersion(info.SourceVersion) {
		policy.timing = timingProtocolPTP
		// Samsung AU9000 with this AirPlay version advertises PTP but omits
		// timingPeerInfo.ClockID in SETUP. NTP works on the same receiver.
		// Keep the exception limited to the observed model/version pair.
		if info.Model == "UAU9000" && info.SourceVersion == "377.25.06" {
			policy.timing = timingProtocolNTP
		}
	}

	return policy, nil
}

func screenAudioCodec(info *ReceiverInfo) (AudioCodec, error) {
	if info == nil || info.SupportedFormats.ScreenStream == 0 {
		return AudioCodecALAC, nil
	}
	if info.SupportsAudioFormat("screenStream", screenAudioFormatALAC) {
		return AudioCodecALAC, nil
	}
	if info.SupportsAudioFormat("screenStream", screenAudioFormatAACELD44100Stereo) {
		return AudioCodecAACELD, nil
	}
	return 0, fmt.Errorf(
		"receiver advertises unsupported supportedFormats.screenStream mask 0x%x (need ALAC 0x%x or AAC-ELD 0x%x)",
		uint64(info.SupportedFormats.ScreenStream), screenAudioFormatALAC, screenAudioFormatAACELD44100Stereo,
	)
}

func supportsPTPSourceVersion(sourceVersion string) bool {
	major, minor, patch, ok := parseSourceVersion(sourceVersion)
	if !ok || major == 377 && minor == 40 {
		return false
	}
	return compareVersion(
		major, minor, patch,
		minimumPTPSourceVersionMajor,
		minimumPTPSourceVersionMinor,
		minimumPTPSourceVersionPatch,
	) >= 0
}

func parseSourceVersion(sourceVersion string) (major, minor, patch int, ok bool) {
	parts := strings.Split(sourceVersion, ".")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, 0, 0, false
	}
	values := []*int{&major, &minor, &patch}
	for index, part := range parts {
		if part == "" {
			return 0, 0, 0, false
		}
		value, err := strconv.Atoi(part)
		if err != nil || value < 0 {
			return 0, 0, 0, false
		}
		*values[index] = value
	}
	return major, minor, patch, true
}

func compareVersion(aMajor, aMinor, aPatch, bMajor, bMinor, bPatch int) int {
	for _, pair := range [][2]int{
		{aMajor, bMajor},
		{aMinor, bMinor},
		{aPatch, bPatch},
	} {
		if pair[0] < pair[1] {
			return -1
		}
		if pair[0] > pair[1] {
			return 1
		}
	}
	return 0
}

func (p receiverCompatibility) sourceVersion() string {
	if p.audioSecurity == audioSecurityChaCha {
		return modernAirPlaySourceVersion
	}
	return legacyAirPlaySourceVersion
}

func (p receiverCompatibility) permitsLocalPTPClock() bool {
	return p.timing == timingProtocolPTP
}

func (p receiverCompatibility) fairPlayOnControl() bool {
	return p.fairPlayRoots == fairPlayAllRoots
}

func (p receiverCompatibility) fairPlayOnStreams() bool {
	return p.fairPlayRoots == fairPlayAllRoots
}
