package airplay

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

type hevcSPSInfo struct {
	width, height        int
	profileByte          byte
	compatibility        [4]byte
	constraints          [6]byte
	levelIDC             byte
	maxSubLayersMinus1   byte
	temporalIDNested     byte
	chromaFormatIDC      byte
	bitDepthLumaMinus8   byte
	bitDepthChromaMinus8 byte
}

func hevcNALType(raw []byte) byte {
	if len(raw) < 2 {
		return 63
	}
	return (raw[0] >> 1) & 0x3f
}

func parseHEVCSPS(sps []byte) (hevcSPSInfo, bool) {
	var info hevcSPSInfo
	if len(sps) < 15 || hevcNALType(sps) != 33 {
		return info, false
	}
	rbsp := stripEmulationPrevention(sps[2:])
	if len(rbsp) < 13 {
		return info, false
	}
	info.maxSubLayersMinus1 = (rbsp[0] >> 1) & 7
	info.temporalIDNested = rbsp[0] & 1
	info.profileByte = rbsp[1]
	copy(info.compatibility[:], rbsp[2:6])
	copy(info.constraints[:], rbsp[6:12])
	info.levelIDC = rbsp[12]

	r := &h264BitReader{data: rbsp}
	r.readBits(8)  // sps_video_parameter_set_id, max_sub_layers, nesting
	r.readBits(96) // general_profile_tier_level
	profilePresent := make([]uint, info.maxSubLayersMinus1)
	levelPresent := make([]uint, info.maxSubLayersMinus1)
	for n := range profilePresent {
		profilePresent[n] = r.readBit()
		levelPresent[n] = r.readBit()
	}
	if info.maxSubLayersMinus1 > 0 {
		for n := int(info.maxSubLayersMinus1); n < 8; n++ {
			r.readBits(2)
		}
	}
	for n := range profilePresent {
		if profilePresent[n] != 0 {
			r.readBits(88)
		}
		if levelPresent[n] != 0 {
			r.readBits(8)
		}
	}
	r.readUE() // sps_seq_parameter_set_id
	chroma := r.readUE()
	if chroma > 3 {
		return info, false
	}
	info.chromaFormatIDC = byte(chroma)
	separateColourPlane := uint(0)
	if chroma == 3 {
		separateColourPlane = r.readBit()
	}
	width := r.readUE()
	height := r.readUE()
	var cropLeft, cropRight, cropTop, cropBottom uint
	if r.readBit() != 0 {
		cropLeft, cropRight = r.readUE(), r.readUE()
		cropTop, cropBottom = r.readUE(), r.readUE()
	}
	lumaDepth, chromaDepth := r.readUE(), r.readUE()
	if r.err || width == 0 || height == 0 || lumaDepth > 7 || chromaDepth > 7 {
		return info, false
	}
	subWidthC, subHeightC := uint(1), uint(1)
	if separateColourPlane == 0 {
		switch chroma {
		case 1:
			subWidthC, subHeightC = 2, 2
		case 2:
			subWidthC, subHeightC = 2, 1
		}
	}
	if (cropLeft+cropRight)*subWidthC >= width || (cropTop+cropBottom)*subHeightC >= height {
		return info, false
	}
	info.width = int(width - (cropLeft+cropRight)*subWidthC)
	info.height = int(height - (cropTop+cropBottom)*subHeightC)
	info.bitDepthLumaMinus8 = byte(lumaDepth)
	info.bitDepthChromaMinus8 = byte(chromaDepth)
	return info, true
}

// buildHEVCSampleDescription serializes an hvc1 visual sample entry and hvcC
// decoder configuration from the encoded parameter sets.
func buildHEVCSampleDescription(vps, sps, pps []byte) ([]byte, error) {
	info, ok := parseHEVCSPS(sps)
	if !ok || len(vps) < 2 || hevcNALType(vps) != 32 || len(pps) < 2 || hevcNALType(pps) != 34 {
		return nil, fmt.Errorf("invalid HEVC VPS/SPS/PPS")
	}
	hvcc := make([]byte, 23)
	hvcc[0] = 1
	hvcc[1] = info.profileByte
	copy(hvcc[2:6], info.compatibility[:])
	copy(hvcc[6:12], info.constraints[:])
	hvcc[12] = info.levelIDC
	binary.BigEndian.PutUint16(hvcc[13:15], 0xf000) // reserved + min_spatial_segmentation_idc
	hvcc[15] = 0xfc                                 // reserved + parallelismType unknown
	hvcc[16] = 0xfc | info.chromaFormatIDC
	hvcc[17] = 0xf8 | info.bitDepthLumaMinus8
	hvcc[18] = 0xf8 | info.bitDepthChromaMinus8
	// avgFrameRate remains zero. lengthSizeMinusOne=3 selects four-byte NAL lengths.
	hvcc[21] = ((info.maxSubLayersMinus1 + 1) << 3) | (info.temporalIDNested << 2) | 3
	hvcc[22] = 3
	for _, parameterSet := range []struct {
		typ byte
		nal []byte
	}{{32, vps}, {33, sps}, {34, pps}} {
		hvcc = append(hvcc, 0x80|parameterSet.typ, 0, 1)
		if len(parameterSet.nal) > 0xffff {
			return nil, fmt.Errorf("HEVC parameter set is too large")
		}
		hvcc = binary.BigEndian.AppendUint16(hvcc, uint16(len(parameterSet.nal)))
		hvcc = append(hvcc, parameterSet.nal...)
	}

	const visualSampleEntrySize = 86
	payload := make([]byte, visualSampleEntrySize+8+len(hvcc))
	binary.BigEndian.PutUint32(payload[0:4], uint32(len(payload)))
	copy(payload[4:8], "hvc1")
	binary.BigEndian.PutUint16(payload[14:16], 1) // data_reference_index
	binary.BigEndian.PutUint16(payload[32:34], uint16(info.width))
	binary.BigEndian.PutUint16(payload[34:36], uint16(info.height))
	binary.BigEndian.PutUint32(payload[36:40], 0x00480000) // 72 dpi
	binary.BigEndian.PutUint32(payload[40:44], 0x00480000)
	binary.BigEndian.PutUint16(payload[48:50], 1)      // frame_count
	binary.BigEndian.PutUint16(payload[82:84], 0x0018) // depth
	binary.BigEndian.PutUint16(payload[84:86], 0xffff)
	binary.BigEndian.PutUint32(payload[86:90], uint32(8+len(hvcc)))
	copy(payload[90:94], "hvcC")
	copy(payload[94:], hvcc)
	return payload, nil
}

func hevcCodecConfigNeedsSend(primed bool, current, sent [3][]byte) bool {
	return !primed || !bytes.Equal(current[0], sent[0]) || !bytes.Equal(current[1], sent[1]) || !bytes.Equal(current[2], sent[2])
}
