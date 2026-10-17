package airplay

import (
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	rtpVideoPayloadType       = 96
	onvifRTPHeaderProfile     = 0xabac
	maxVideoAccessUnitBytes   = 16 << 20
	ntpFractionalSecondScale  = uint64(1) << 32
	annexBLongStartCodeLength = 4
)

var annexBLongStartCode = [...]byte{0, 0, 0, 1}

// VideoAccessUnit is one complete encoded H.264 or HEVC picture and its original
// capture presentation time. AnnexB contains complete NAL units separated by
// four-byte Annex-B start codes.
type VideoAccessUnit struct {
	AnnexB []byte
	PTS    time.Time
}

// videoAccessUnitReader is the timestamp-preserving boundary between the
// GStreamer capture process and the AirPlay video sender.
type videoAccessUnitReader interface {
	ReadVideoAccessUnit() (VideoAccessUnit, error)
}

type rtpVideoAccessUnitReader struct {
	reader io.Reader
	now    func() time.Time
	codec  VideoCodec
	packet []byte

	maxAccessUnitBytes int
	haveSequence       bool
	sequence           uint16
	haveSSRC           bool
	ssrc               uint32

	haveAccessUnitTimestamp bool
	rtpTimestamp            uint32
	onvifTimestamp          uint64
	accessUnit              []byte

	fragmentActive     bool
	fragmentIndicator  byte
	fragmentType       byte
	hevcFragmentHeader [2]byte
}

func newRTPVideoAccessUnitReader(reader io.Reader, codecs ...VideoCodec) videoAccessUnitReader {
	codec := VideoCodecH264
	if len(codecs) > 0 {
		codec = normalizeVideoCodec(codecs[0])
	}
	return newRTPVideoAccessUnitReaderForCodecWithNow(reader, codec, time.Now)
}

func newRTPVideoAccessUnitReaderWithNow(reader io.Reader, now func() time.Time) *rtpVideoAccessUnitReader {
	return newRTPVideoAccessUnitReaderForCodecWithNow(reader, VideoCodecH264, now)
}

func newRTPVideoAccessUnitReaderForCodecWithNow(reader io.Reader, codec VideoCodec, now func() time.Time) *rtpVideoAccessUnitReader {
	if now == nil {
		now = time.Now
	}
	return &rtpVideoAccessUnitReader{
		reader:             reader,
		now:                now,
		codec:              normalizeVideoCodec(codec),
		maxAccessUnitBytes: maxVideoAccessUnitBytes,
	}
}

func (r *rtpVideoAccessUnitReader) ReadVideoAccessUnit() (VideoAccessUnit, error) {
	for {
		packet, err := r.readRFC4571Packet()
		if err != nil {
			if err == io.EOF && (len(r.accessUnit) != 0 || r.fragmentActive) {
				return VideoAccessUnit{}, io.ErrUnexpectedEOF
			}
			return VideoAccessUnit{}, err
		}

		header, payload, err := parseTimestampedRTPPacket(packet)
		if err != nil {
			return VideoAccessUnit{}, err
		}
		if err := r.acceptPacketHeader(header); err != nil {
			return VideoAccessUnit{}, err
		}
		var payloadErr error
		if r.codec == VideoCodecHEVC {
			payloadErr = r.acceptHEVCPayload(payload)
		} else {
			payloadErr = r.acceptH264Payload(payload)
		}
		if payloadErr != nil {
			return VideoAccessUnit{}, payloadErr
		}

		if !header.marker {
			continue
		}
		if r.fragmentActive {
			return VideoAccessUnit{}, fmt.Errorf("RTP video: access unit marker arrived before FU-A completed")
		}
		if len(r.accessUnit) == 0 {
			return VideoAccessUnit{}, fmt.Errorf("RTP video: empty access unit")
		}

		wallPTS := timeFromNTP(r.onvifTimestamp)
		now := r.now()
		// Adding the wall-clock difference to a time returned by time.Now keeps
		// its monotonic clock reading. Downstream clock conversion can therefore
		// subtract encoder and pipe delay without becoming sensitive to later
		// wall-clock adjustments.
		pts := now.Add(wallPTS.Sub(now))
		accessUnit := r.accessUnit
		r.accessUnit = nil
		r.haveAccessUnitTimestamp = false
		return VideoAccessUnit{AnnexB: accessUnit, PTS: pts}, nil
	}
}

// acceptHEVCPayload implements the single-NAL, aggregation packet (AP), and
// fragmentation unit (FU) forms from RFC 7798. GStreamer uses AP-disabled
// packetization, but accepting AP makes the capture boundary robust.
func (r *rtpVideoAccessUnitReader) acceptHEVCPayload(payload []byte) error {
	if len(payload) < 2 {
		return fmt.Errorf("RTP video: truncated HEVC payload header")
	}
	nalType := (payload[0] >> 1) & 0x3f
	switch nalType {
	case 48:
		if r.fragmentActive {
			return fmt.Errorf("RTP video: HEVC AP arrived before FU completed")
		}
		return r.acceptHEVCAP(payload)
	case 49:
		return r.acceptHEVCFU(payload)
	case 50:
		return fmt.Errorf("RTP video: HEVC PACI packets are unsupported")
	default:
		if r.fragmentActive {
			return fmt.Errorf("RTP video: complete HEVC NAL arrived before FU completed")
		}
		return r.appendNAL(payload)
	}
}

func (r *rtpVideoAccessUnitReader) acceptHEVCAP(payload []byte) error {
	if len(payload) == 2 {
		return fmt.Errorf("RTP video: empty HEVC aggregation packet")
	}
	for offset := 2; offset < len(payload); {
		if len(payload)-offset < 2 {
			return fmt.Errorf("RTP video: truncated HEVC AP NAL length")
		}
		n := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if n < 2 || n > len(payload)-offset {
			return fmt.Errorf("RTP video: invalid HEVC AP NAL length %d", n)
		}
		if err := r.appendNAL(payload[offset : offset+n]); err != nil {
			return err
		}
		offset += n
	}
	return nil
}

func (r *rtpVideoAccessUnitReader) acceptHEVCFU(payload []byte) error {
	if len(payload) <= 3 {
		return fmt.Errorf("RTP video: truncated HEVC FU")
	}
	fuHeader := payload[2]
	start, end := fuHeader&0x80 != 0, fuHeader&0x40 != 0
	fragmentType := fuHeader & 0x3f
	if fragmentType >= 48 || (start && end) {
		return fmt.Errorf("RTP video: invalid HEVC FU header 0x%02x", fuHeader)
	}
	// Restore the original two-byte HEVC NAL header while retaining the layer
	// and temporal-id fields from the FU payload header.
	reconstructed := [2]byte{(payload[0] & 0x81) | fragmentType<<1, payload[1]}
	if start {
		if r.fragmentActive {
			return fmt.Errorf("RTP video: nested HEVC FU start")
		}
		r.fragmentActive = true
		r.fragmentType = fragmentType
		r.hevcFragmentHeader = reconstructed
		if err := r.appendAccessUnitBytes(annexBLongStartCode[:]); err != nil {
			return err
		}
		if err := r.appendAccessUnitBytes(reconstructed[:]); err != nil {
			return err
		}
		return r.appendAccessUnitBytes(payload[3:])
	}
	if !r.fragmentActive {
		return fmt.Errorf("RTP video: HEVC FU continuation without start")
	}
	if fragmentType != r.fragmentType || reconstructed != r.hevcFragmentHeader {
		return fmt.Errorf("RTP video: HEVC FU header changed within fragmented NAL")
	}
	if err := r.appendAccessUnitBytes(payload[3:]); err != nil {
		return err
	}
	if end {
		r.fragmentActive = false
	}
	return nil
}

func (r *rtpVideoAccessUnitReader) readRFC4571Packet() ([]byte, error) {
	if r.reader == nil {
		return nil, fmt.Errorf("RTP video: nil capture reader")
	}
	var lengthBytes [2]byte
	if _, err := io.ReadFull(r.reader, lengthBytes[:]); err != nil {
		if err == io.ErrUnexpectedEOF {
			return nil, fmt.Errorf("RTP video: truncated RFC4571 length: %w", err)
		}
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if length == 0 {
		return nil, fmt.Errorf("RTP video: zero-length RFC4571 packet")
	}
	if cap(r.packet) < length {
		r.packet = make([]byte, length)
	} else {
		r.packet = r.packet[:length]
	}
	if _, err := io.ReadFull(r.reader, r.packet); err != nil {
		return nil, fmt.Errorf("RTP video: truncated RFC4571 packet: %w", err)
	}
	return r.packet, nil
}

type timestampedRTPHeader struct {
	marker         bool
	sequence       uint16
	timestamp      uint32
	ssrc           uint32
	onvifTimestamp uint64
	// untimed marks a packet without the ONVIF extension. GStreamer before 1.22
	// timestamps only the first packet of each buffer list, so the later FU-A
	// fragments of a large access unit arrive untimed; they inherit the access
	// unit's timestamp in acceptPacketHeader.
	untimed bool
}

func parseTimestampedRTPPacket(packet []byte) (timestampedRTPHeader, []byte, error) {
	var header timestampedRTPHeader
	if len(packet) < 12 {
		return header, nil, fmt.Errorf("RTP video: packet is shorter than the RTP header")
	}
	if packet[0]>>6 != 2 {
		return header, nil, fmt.Errorf("RTP video: unsupported RTP version %d", packet[0]>>6)
	}
	if packet[1]&0x7f != rtpVideoPayloadType {
		return header, nil, fmt.Errorf("RTP video: unexpected payload type %d", packet[1]&0x7f)
	}

	padding := packet[0]&0x20 != 0
	hasExtension := packet[0]&0x10 != 0
	csrcCount := int(packet[0] & 0x0f)
	offset := 12 + 4*csrcCount
	if offset > len(packet) {
		return header, nil, fmt.Errorf("RTP video: truncated CSRC list")
	}
	var onvifTimestamp uint64
	if hasExtension {
		if len(packet)-offset < 4 {
			return header, nil, fmt.Errorf("RTP video: truncated header extension")
		}
		profile := binary.BigEndian.Uint16(packet[offset : offset+2])
		if profile != onvifRTPHeaderProfile {
			return header, nil, fmt.Errorf("RTP video: unexpected header extension profile 0x%04x", profile)
		}
		extensionWords := int(binary.BigEndian.Uint16(packet[offset+2 : offset+4]))
		extensionBytes := extensionWords * 4
		offset += 4
		if extensionWords < 3 {
			return header, nil, fmt.Errorf("RTP video: ONVIF extension is %d bytes, want at least 12", extensionBytes)
		}
		if extensionBytes > len(packet)-offset {
			return header, nil, fmt.Errorf("RTP video: truncated ONVIF extension")
		}
		onvifTimestamp = binary.BigEndian.Uint64(packet[offset : offset+8])
		if onvifTimestamp == 0 {
			return header, nil, fmt.Errorf("RTP video: zero ONVIF timestamp")
		}
		offset += extensionBytes
	}

	payloadEnd := len(packet)
	if padding {
		paddingBytes := int(packet[len(packet)-1])
		if paddingBytes == 0 || paddingBytes > payloadEnd-offset {
			return header, nil, fmt.Errorf("RTP video: invalid padding length %d", paddingBytes)
		}
		payloadEnd -= paddingBytes
	}
	if payloadEnd <= offset {
		return header, nil, fmt.Errorf("RTP video: packet has no H.264 payload")
	}

	header = timestampedRTPHeader{
		marker:         packet[1]&0x80 != 0,
		sequence:       binary.BigEndian.Uint16(packet[2:4]),
		timestamp:      binary.BigEndian.Uint32(packet[4:8]),
		ssrc:           binary.BigEndian.Uint32(packet[8:12]),
		onvifTimestamp: onvifTimestamp,
		untimed:        !hasExtension,
	}
	return header, packet[offset:payloadEnd], nil
}

func (r *rtpVideoAccessUnitReader) acceptPacketHeader(header timestampedRTPHeader) error {
	if r.haveSequence && header.sequence != r.sequence+1 {
		return fmt.Errorf("RTP video: sequence discontinuity: got %d after %d", header.sequence, r.sequence)
	}
	r.haveSequence = true
	r.sequence = header.sequence

	if r.haveSSRC && header.ssrc != r.ssrc {
		return fmt.Errorf("RTP video: SSRC changed from 0x%08x to 0x%08x", r.ssrc, header.ssrc)
	}
	r.haveSSRC = true
	r.ssrc = header.ssrc

	if header.untimed {
		if !r.haveAccessUnitTimestamp || header.timestamp != r.rtpTimestamp {
			return fmt.Errorf("RTP video: ONVIF timestamp extension is absent")
		}
		return nil
	}
	if !r.haveAccessUnitTimestamp {
		r.haveAccessUnitTimestamp = true
		r.rtpTimestamp = header.timestamp
		r.onvifTimestamp = header.onvifTimestamp
		return nil
	}
	if header.timestamp != r.rtpTimestamp {
		return fmt.Errorf("RTP video: timestamp changed before access unit marker")
	}
	if header.onvifTimestamp != r.onvifTimestamp {
		return fmt.Errorf("RTP video: ONVIF timestamp changed before access unit marker")
	}
	return nil
}

func (r *rtpVideoAccessUnitReader) acceptH264Payload(payload []byte) error {
	nalType := payload[0] & 0x1f
	switch {
	case nalType >= 1 && nalType <= 23:
		if r.fragmentActive {
			return fmt.Errorf("RTP video: complete NAL arrived before FU-A completed")
		}
		return r.appendNAL(payload)
	case nalType == 24:
		if r.fragmentActive {
			return fmt.Errorf("RTP video: STAP-A arrived before FU-A completed")
		}
		return r.acceptSTAPA(payload)
	case nalType == 28:
		return r.acceptFUA(payload)
	default:
		return fmt.Errorf("RTP video: unsupported H.264 packetization type %d", nalType)
	}
}

func (r *rtpVideoAccessUnitReader) acceptSTAPA(payload []byte) error {
	if len(payload) == 1 {
		return fmt.Errorf("RTP video: empty STAP-A")
	}
	for offset := 1; offset < len(payload); {
		if len(payload)-offset < 2 {
			return fmt.Errorf("RTP video: truncated STAP-A NAL length")
		}
		nalLength := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		if nalLength == 0 || nalLength > len(payload)-offset {
			return fmt.Errorf("RTP video: invalid STAP-A NAL length %d", nalLength)
		}
		nal := payload[offset : offset+nalLength]
		containedType := nal[0] & 0x1f
		if containedType == 0 || containedType >= 24 {
			return fmt.Errorf("RTP video: invalid STAP-A contained NAL type %d", containedType)
		}
		if err := r.appendNAL(nal); err != nil {
			return err
		}
		offset += nalLength
	}
	return nil
}

func (r *rtpVideoAccessUnitReader) acceptFUA(payload []byte) error {
	if len(payload) <= 2 {
		return fmt.Errorf("RTP video: truncated FU-A")
	}
	indicator := payload[0] & 0xe0
	header := payload[1]
	start := header&0x80 != 0
	end := header&0x40 != 0
	reserved := header&0x20 != 0
	fragmentType := header & 0x1f
	if reserved || fragmentType == 0 || fragmentType >= 24 {
		return fmt.Errorf("RTP video: invalid FU-A header 0x%02x", header)
	}
	if start && end {
		return fmt.Errorf("RTP video: FU-A start and end bits are both set")
	}

	if start {
		if r.fragmentActive {
			return fmt.Errorf("RTP video: nested FU-A start")
		}
		r.fragmentActive = true
		r.fragmentIndicator = indicator
		r.fragmentType = fragmentType
		if err := r.appendAccessUnitBytes(annexBLongStartCode[:]); err != nil {
			return err
		}
		if err := r.appendAccessUnitBytes([]byte{indicator | fragmentType}); err != nil {
			return err
		}
		return r.appendAccessUnitBytes(payload[2:])
	}

	if !r.fragmentActive {
		return fmt.Errorf("RTP video: FU-A continuation without start")
	}
	if indicator != r.fragmentIndicator || fragmentType != r.fragmentType {
		return fmt.Errorf("RTP video: FU-A header changed within fragmented NAL")
	}
	if err := r.appendAccessUnitBytes(payload[2:]); err != nil {
		return err
	}
	if end {
		r.fragmentActive = false
	}
	return nil
}

func (r *rtpVideoAccessUnitReader) appendNAL(nal []byte) error {
	if len(nal) == 0 {
		return fmt.Errorf("RTP video: empty NAL")
	}
	if err := r.appendAccessUnitBytes(annexBLongStartCode[:]); err != nil {
		return err
	}
	return r.appendAccessUnitBytes(nal)
}

func (r *rtpVideoAccessUnitReader) appendAccessUnitBytes(data []byte) error {
	limit := r.maxAccessUnitBytes
	if limit <= 0 {
		limit = maxVideoAccessUnitBytes
	}
	if len(data) > limit-len(r.accessUnit) {
		return fmt.Errorf("RTP video: access unit exceeds %d bytes", limit)
	}
	r.accessUnit = append(r.accessUnit, data...)
	return nil
}

func timeFromNTP(timestamp uint64) time.Time {
	seconds := int64(timestamp>>32) - secondsFrom1900To1970
	fraction := timestamp & (ntpFractionalSecondScale - 1)
	nanoseconds := int64((fraction * uint64(time.Second)) >> 32)
	return time.Unix(seconds, nanoseconds).UTC()
}
