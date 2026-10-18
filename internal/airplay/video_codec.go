package airplay

import (
	"fmt"
	"math"
)

// VideoCodec selects the compressed screen codec carried by AirPlay mirroring.
// The empty value remains H.264 for backwards-compatible programmatic use;
// command-line callers may request Auto and provide the local encoder gate in
// StreamConfig after capture preflight.
type VideoCodec string

const (
	VideoCodecAuto VideoCodec = "auto"
	VideoCodecH264 VideoCodec = "h264"
	VideoCodecHEVC VideoCodec = "hevc"
)

const featureScreenMultiCodec uint = 42

func normalizeVideoCodec(codec VideoCodec) VideoCodec {
	if codec == "" {
		return VideoCodecH264
	}
	return codec
}

// ValidateVideoCodec checks a command/config codec value.
func ValidateVideoCodec(codec string) error {
	switch VideoCodec(codec) {
	case "", VideoCodecAuto, VideoCodecH264, VideoCodecHEVC:
		return nil
	default:
		return fmt.Errorf("unknown video codec %q (want auto, h264, or hevc)", codec)
	}
}

func (i *ReceiverInfo) supportsVideoCodec(codec VideoCodec) bool {
	switch normalizeVideoCodec(codec) {
	case VideoCodecH264:
		return true
	case VideoCodecHEVC:
		// Apple's SupportsScreenMultiCodec property is feature index 42.
		return i != nil && i.HasFeature(featureScreenMultiCodec)
	default:
		return false
	}
}

type videoSelection struct {
	codec         VideoCodec
	width, height int
	reason        string
}

// selectVideo chooses one concrete codec and canvas from the final receiver
// snapshot. The ordinary AVC path can use the advertised maximum up to 1080p;
// larger canvases require a separate high-resolution codec path.
func (i *ReceiverInfo) selectVideo(requested VideoCodec, automaticHEVCAvailable bool) (videoSelection, error) {
	_ = automaticHEVCAvailable // Retained for programmatic compatibility.
	if requested == "" {
		requested = VideoCodecH264
	}
	if err := ValidateVideoCodec(string(requested)); err != nil {
		return videoSelection{}, err
	}

	switch requested {
	case VideoCodecH264:
		width, height := i.h264VideoCanvas()
		return videoSelection{codec: VideoCodecH264, width: width, height: height, reason: "explicit H.264"}, nil
	case VideoCodecHEVC:
		width, height, err := i.videoCanvas(VideoCodecHEVC)
		if err != nil {
			return videoSelection{}, err
		}
		return videoSelection{codec: VideoCodecHEVC, width: width, height: height, reason: "explicit HEVC"}, nil
	case VideoCodecAuto:
		width, height := i.h264VideoCanvas()
		return videoSelection{codec: VideoCodecH264, width: width, height: height, reason: "automatic compatibility path"}, nil
	default:
		panic("validated video codec has no selection policy")
	}
}

// h264VideoCanvas follows screenstream_init's default screenEnableMaxDisplaySize
// and screenstream_initDisplayInfo's ordinary 1920x1080 limit. A receiver's
// nominal 720p canvas is not its decoder limit when it advertises a usable
// 1080p maximum. Above that limit Apple's sender requires another local codec
// gate; keep the nominal canvas rather than inferring that gate from a model.
// AirPlaySender.c:188161,188237,191104-191143 (26A5388g).
func (i *ReceiverInfo) h264VideoCanvas() (int, int) {
	width, height := i.MirrorSize()
	maximumW, maximumH := i.MaxVideoSize()
	if width > 0 && height > 0 && maximumW > 0 && maximumH > 0 && maximumW <= 1920 && maximumH <= 1080 {
		return max(width, maximumW), max(height, maximumH)
	}
	return width, height
}

// highResolutionVideoCanvas implements the high-resolution display-size gate.
// A missing maximum falls back to nominal, a malformed
// maximum cannot shrink nominal, and the result is capped aspect-preserving to
// 3840x2160. A maximum of exactly 1920x1080 remains on the ordinary path.
func (i *ReceiverInfo) highResolutionVideoCanvas() (int, int, bool) {
	maximumW, maximumH := i.maximumVideoCanvas()
	if maximumW <= 1920 && maximumH <= 1080 {
		return 0, 0, false
	}
	if maximumW <= 0 || maximumH <= 0 {
		return 0, 0, false
	}
	return maximumW, maximumH, true
}

func (i *ReceiverInfo) maximumVideoCanvas() (int, int) {
	nominalW, nominalH := i.MirrorSize()
	maximumW, maximumH := i.MaxVideoSize()
	if maximumW < nominalW {
		maximumW = nominalW
	}
	if maximumH < nominalH {
		maximumH = nominalH
	}
	if maximumW <= 0 || maximumH <= 0 {
		return 0, 0
	}
	return fitVideoSize(maximumW, maximumH, 3840, 2160)
}

func fitVideoSize(width, height, maximumW, maximumH int) (int, int) {
	if width <= maximumW && height <= maximumH {
		return width, height
	}
	scale := math.Min(float64(maximumW)/float64(width), float64(maximumH)/float64(height))
	return int(math.Round(float64(width) * scale)), int(math.Round(float64(height) * scale))
}

func (i *ReceiverInfo) videoCanvas(codec VideoCodec) (int, int, error) {
	codec = normalizeVideoCodec(codec)
	if !i.supportsVideoCodec(codec) {
		return 0, 0, fmt.Errorf("receiver does not advertise AirPlay feature 42 (SupportsScreenMultiCodec) required for HEVC")
	}
	if codec == VideoCodecHEVC {
		// The high-resolution screen path can exceed the ordinary H.264 limit.
		width, height := i.maximumVideoCanvas()
		return width, height, nil
	}
	width, height := i.h264VideoCanvas()
	return width, height, nil
}
