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

// selectVideo chooses the highest usable concrete codec and canvas from the
// final receiver snapshot.
func (i *ReceiverInfo) selectVideo(requested VideoCodec, automaticHEVCAvailable bool) (videoSelection, error) {
	return i.selectVideoTarget(requested, automaticHEVCAvailable, 0, 0)
}

// selectVideoTarget applies an optional requested canvas to the receiver's
// codec-specific ceiling. A zero target means the highest usable receiver
// mode. Automatic mode uses HEVC only when both endpoints can provide it and
// the selected canvas exceeds the ordinary H.264 path.
func (i *ReceiverInfo) selectVideoTarget(requested VideoCodec, automaticHEVCAvailable bool, targetWidth, targetHeight int) (videoSelection, error) {
	if requested == "" {
		requested = VideoCodecH264
	}
	if err := ValidateVideoCodec(string(requested)); err != nil {
		return videoSelection{}, err
	}
	if (targetWidth == 0) != (targetHeight == 0) || targetWidth < 0 || targetHeight < 0 {
		return videoSelection{}, fmt.Errorf("target video canvas must specify both positive dimensions or neither")
	}
	fitTarget := func(maximumWidth, maximumHeight int) (int, int) {
		if targetWidth == 0 {
			return maximumWidth &^ 1, maximumHeight &^ 1
		}
		width, height := fitVideoSize(targetWidth, targetHeight, maximumWidth, maximumHeight)
		return width &^ 1, height &^ 1
	}

	switch requested {
	case VideoCodecH264:
		width, height := fitTarget(i.h264VideoCanvas())
		return videoSelection{codec: VideoCodecH264, width: width, height: height, reason: "explicit H.264"}, nil
	case VideoCodecHEVC:
		maximumWidth, maximumHeight, err := i.videoCanvas(VideoCodecHEVC)
		if err != nil {
			return videoSelection{}, err
		}
		width, height := fitTarget(maximumWidth, maximumHeight)
		return videoSelection{codec: VideoCodecHEVC, width: width, height: height, reason: "explicit HEVC"}, nil
	case VideoCodecAuto:
		h264Width, h264Height := i.h264VideoCanvas()
		width, height := fitTarget(h264Width, h264Height)
		if automaticHEVCAvailable && i.supportsVideoCodec(VideoCodecHEVC) {
			maximumWidth, maximumHeight, highResolution := i.highResolutionVideoCanvas()
			if highResolution {
				hevcWidth, hevcHeight := fitTarget(maximumWidth, maximumHeight)
				if hevcWidth > width || hevcHeight > height {
					return videoSelection{codec: VideoCodecHEVC, width: hevcWidth, height: hevcHeight, reason: "automatic highest-resolution path"}, nil
				}
			}
		}
		return videoSelection{codec: VideoCodecH264, width: width, height: height, reason: "automatic H.264 path"}, nil
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
