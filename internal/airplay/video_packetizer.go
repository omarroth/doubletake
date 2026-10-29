package airplay

import (
	"encoding/binary"
	"fmt"
)

// mirrorVideoPacketizer separates decoder configuration from complete encoded
// pictures. Access-unit boundaries and timestamps belong to the capture reader;
// the sender must not infer new boundaries from slice headers a second time.
type mirrorVideoPacketizer struct {
	codec         VideoCodec
	current, sent [3][]byte // VPS (HEVC only), SPS, PPS
	primed        bool
}

type mirrorVideoFrame struct {
	payload  []byte
	keyframe bool
	hasVCL   bool
}

func (p *mirrorVideoPacketizer) packetize(annexB []byte) mirrorVideoFrame {
	var frame mirrorVideoFrame
	for _, wrapped := range splitAnnexBAccessUnit(annexB) {
		raw := stripStartCode(wrapped)
		if len(raw) == 0 {
			continue
		}
		parameter := -1
		if p.codec == VideoCodecHEVC {
			typ := hevcNALType(raw)
			switch typ {
			case 32, 33, 34:
				parameter = int(typ - 32)
			case 35: // AUD; the capture reader already delimits access units.
				continue
			}
			frame.hasVCL = frame.hasVCL || typ <= 31
			frame.keyframe = frame.keyframe || typ >= 16 && typ <= 21
		} else {
			typ := raw[0] & 0x1f
			switch typ {
			case 7, 8:
				parameter = int(typ - 6)
			case 9:
				continue
			}
			frame.hasVCL = frame.hasVCL || typ >= 1 && typ <= 5
			frame.keyframe = frame.keyframe || typ == 5
		}
		if parameter >= 0 {
			p.current[parameter] = append(p.current[parameter][:0], raw...)
			continue
		}
		// Preserve the encoder's sample, including SEI, in its original order.
		frame.payload = appendAVCCNAL(frame.payload, raw)
	}
	return frame
}

func appendAVCCNAL(dst, raw []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(raw)))
	return append(dst, raw...)
}

func (p *mirrorVideoPacketizer) ready(frame mirrorVideoFrame) bool {
	return frame.hasVCL && (p.primed || frame.keyframe &&
		len(p.current[1]) != 0 && len(p.current[2]) != 0 &&
		(p.codec != VideoCodecHEVC || len(p.current[0]) != 0))
}

func (p *mirrorVideoPacketizer) needsConfiguration() bool {
	if p.codec == VideoCodecHEVC {
		return hevcCodecConfigNeedsSend(p.primed, p.current, p.sent)
	}
	return codecConfigNeedsSend(p.primed, p.current[1], p.current[2], p.sent[1], p.sent[2])
}

func (p *mirrorVideoPacketizer) configuration() (data []byte, width, height int, err error) {
	if p.codec == VideoCodecHEVC {
		data, err = buildHEVCSampleDescription(p.current[0], p.current[1], p.current[2])
		if err != nil {
			return nil, 0, 0, err
		}
		info, _ := parseHEVCSPS(p.current[1]) // Validated by buildHEVCSampleDescription.
		return data, info.width, info.height, nil
	}
	if len(p.current[1]) == 0 || len(p.current[2]) == 0 {
		return nil, 0, 0, fmt.Errorf("missing H.264 SPS/PPS")
	}
	width, height, _ = spsDimensions(p.current[1])
	return buildAVCCConfig(p.current[1], p.current[2]), width, height, nil
}

func (p *mirrorVideoPacketizer) configured() {
	for i := range p.current {
		p.sent[i] = append(p.sent[i][:0], p.current[i]...)
	}
	p.primed = true
}
