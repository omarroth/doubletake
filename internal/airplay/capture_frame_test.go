package airplay

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

const testVideoSSRC = uint32(0x12345678)

type testRTPPacket struct {
	sequence  uint16
	timestamp uint32
	ntp       uint64
	marker    bool
	payload   []byte
}

func TestRTPVideoAccessUnitReaderPreservesPTSAndNALs(t *testing.T) {
	wallPTS := time.Unix(1787276227, 500_000_000).UTC()
	now := time.Now()
	stream := joinTestRTPPackets(
		testRTPPacket{10, 9000, ntpFromTime(wallPTS), false, []byte{0x67, 0x42, 0xc0}},
		testRTPPacket{11, 9000, ntpFromTime(wallPTS), false, []byte{0x68, 0xce, 0x3c}},
		testRTPPacket{12, 9000, ntpFromTime(wallPTS), true, []byte{0x65, 0xaa, 0xbb}},
	)
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), func() time.Time { return now })

	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	wantData := []byte{
		0, 0, 0, 1, 0x67, 0x42, 0xc0,
		0, 0, 0, 1, 0x68, 0xce, 0x3c,
		0, 0, 0, 1, 0x65, 0xaa, 0xbb,
	}
	if !bytes.Equal(unit.AnnexB, wantData) {
		t.Fatalf("Annex-B access unit = %x, want %x", unit.AnnexB, wantData)
	}
	wantPTS := now.Add(wallPTS.Sub(now))
	if unit.PTS != wantPTS {
		t.Fatalf("PTS = %#v, want monotonic-preserving %#v", unit.PTS, wantPTS)
	}
	if !unit.PTS.Equal(wallPTS) {
		t.Fatalf("PTS wall time = %v, want %v", unit.PTS, wallPTS)
	}

	if _, err := reader.ReadVideoAccessUnit(); err != io.EOF {
		t.Fatalf("second read error = %v, want EOF", err)
	}
}

func TestRTPVideoAccessUnitReaderReassemblesFUA(t *testing.T) {
	pts := time.Unix(1787276300, 0)
	stream := joinTestRTPPackets(
		testRTPPacket{20, 12000, ntpFromTime(pts), false, []byte{0x7c, 0x85, 0x11, 0x22}},
		testRTPPacket{21, 12000, ntpFromTime(pts), false, []byte{0x7c, 0x05, 0x33, 0x44}},
		testRTPPacket{22, 12000, ntpFromTime(pts), true, []byte{0x7c, 0x45, 0x55}},
	)
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33, 0x44, 0x55}
	if !bytes.Equal(unit.AnnexB, want) {
		t.Fatalf("reassembled FU-A = %x, want %x", unit.AnnexB, want)
	}
}

func TestRTPVideoAccessUnitReaderReassemblesHEVCFU(t *testing.T) {
	pts := time.Unix(1787276300, 0)
	stream := joinTestRTPPackets(
		testRTPPacket{20, 12000, ntpFromTime(pts), false, []byte{0x62, 0x01, 0x93, 0x11, 0x22}},
		testRTPPacket{21, 12000, ntpFromTime(pts), false, []byte{0x62, 0x01, 0x13, 0x33, 0x44}},
		testRTPPacket{22, 12000, ntpFromTime(pts), true, []byte{0x62, 0x01, 0x53, 0x55}},
	)
	reader := newRTPVideoAccessUnitReaderForCodecWithNow(bytes.NewReader(stream), VideoCodecHEVC, time.Now)
	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1, 0x26, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55}
	if !bytes.Equal(unit.AnnexB, want) {
		t.Fatalf("reassembled HEVC FU = %x, want %x", unit.AnnexB, want)
	}
}

func TestRTPVideoAccessUnitReaderAcceptsHEVCAP(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	ap := []byte{0x60, 0x01, 0, 3, 0x40, 0x01, 0xaa, 0, 4, 0x42, 0x01, 0xbb, 0xcc}
	stream := joinTestRTPPackets(testRTPPacket{1, 1, pts, true, ap})
	reader := newRTPVideoAccessUnitReaderForCodecWithNow(bytes.NewReader(stream), VideoCodecHEVC, time.Now)
	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1, 0x40, 0x01, 0xaa, 0, 0, 0, 1, 0x42, 0x01, 0xbb, 0xcc}
	if !bytes.Equal(unit.AnnexB, want) {
		t.Fatalf("HEVC AP access unit = %x, want %x", unit.AnnexB, want)
	}
}

func TestRTPVideoAccessUnitReaderAcceptsSTAPA(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stap := []byte{0x78, 0, 2, 0x67, 0x01, 0, 3, 0x68, 0x02, 0x03}
	stream := joinTestRTPPackets(testRTPPacket{1, 1, pts, true, stap})
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0, 0, 0, 1, 0x67, 0x01, 0, 0, 0, 1, 0x68, 0x02, 0x03}
	if !bytes.Equal(unit.AnnexB, want) {
		t.Fatalf("STAP-A access unit = %x, want %x", unit.AnnexB, want)
	}
}

func TestRTPVideoAccessUnitReaderReadsArbitrarilyChunkedStream(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stream := joinTestRTPPackets(testRTPPacket{1, 1, pts, true, []byte{0x65, 1, 2, 3}})
	reader := newRTPVideoAccessUnitReaderWithNow(&oneByteReader{reader: bytes.NewReader(stream)}, time.Now)
	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 0, 0, 1, 0x65, 1, 2, 3}; !bytes.Equal(unit.AnnexB, want) {
		t.Fatalf("access unit = %x, want %x", unit.AnnexB, want)
	}
}

func TestRTPVideoAccessUnitReaderReturnsConsecutiveAccessUnits(t *testing.T) {
	firstPTS := time.Unix(1787276300, 0)
	secondPTS := firstPTS.Add(time.Second / 30)
	stream := joinTestRTPPackets(
		testRTPPacket{1, 1000, ntpFromTime(firstPTS), true, []byte{0x65, 1}},
		testRTPPacket{2, 4000, ntpFromTime(secondPTS), true, []byte{0x41, 2}},
	)
	now := time.Now()
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), func() time.Time { return now })
	first, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	second, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	if !first.PTS.Equal(firstPTS) || !second.PTS.Equal(timeFromNTP(ntpFromTime(secondPTS))) {
		t.Fatalf("PTS values = %v, %v; want %v, %v", first.PTS, second.PTS, firstPTS, secondPTS)
	}
	if bytes.Equal(first.AnnexB, second.AnnexB) {
		t.Fatalf("consecutive access units unexpectedly share content: %x", first.AnnexB)
	}
}

func TestRTPVideoAccessUnitReaderRejectsSequenceDiscontinuity(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stream := joinTestRTPPackets(
		testRTPPacket{100, 1, pts, false, []byte{0x67, 1}},
		testRTPPacket{102, 1, pts, true, []byte{0x65, 2}},
	)
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	_, err := reader.ReadVideoAccessUnit()
	if err == nil || !strings.Contains(err.Error(), "sequence discontinuity") {
		t.Fatalf("error = %v, want sequence discontinuity", err)
	}
}

func TestRTPVideoAccessUnitReaderRejectsTimestampChangeWithinAU(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stream := joinTestRTPPackets(
		testRTPPacket{1, 10, pts, false, []byte{0x67, 1}},
		testRTPPacket{2, 11, pts, true, []byte{0x65, 2}},
	)
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	_, err := reader.ReadVideoAccessUnit()
	if err == nil || !strings.Contains(err.Error(), "timestamp changed") {
		t.Fatalf("error = %v, want timestamp change", err)
	}
}

func TestRTPVideoAccessUnitReaderRejectsONVIFTimestampChangeWithinAU(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stream := joinTestRTPPackets(
		testRTPPacket{1, 10, pts, false, []byte{0x67, 1}},
		testRTPPacket{2, 10, pts + 1, true, []byte{0x65, 2}},
	)
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	_, err := reader.ReadVideoAccessUnit()
	if err == nil || !strings.Contains(err.Error(), "ONVIF timestamp changed") {
		t.Fatalf("error = %v, want ONVIF timestamp change", err)
	}
}

func TestRTPVideoAccessUnitReaderRejectsSSRCChange(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	first := testRTPPacketBytes(testRTPPacket{1, 10, pts, false, []byte{0x67, 1}})
	second := testRTPPacketBytes(testRTPPacket{2, 10, pts, true, []byte{0x65, 2}})
	second[10] ^= 1 // RFC4571 prefix (2) plus the first SSRC byte (8).
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(append(first, second...)), time.Now)
	_, err := reader.ReadVideoAccessUnit()
	if err == nil || !strings.Contains(err.Error(), "SSRC changed") {
		t.Fatalf("error = %v, want SSRC change", err)
	}
}

func TestRTPVideoAccessUnitReaderRejectsMalformedPackets(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	valid := testRTPPacketBytes(testRTPPacket{1, 1, pts, true, []byte{0x65, 1}})
	tests := []struct {
		name string
		data []byte
		want string
	}{
		{name: "truncated RFC length", data: []byte{0}, want: "truncated RFC4571 length"},
		{name: "zero RFC length", data: []byte{0, 0}, want: "zero-length RFC4571"},
		{name: "truncated RFC packet", data: []byte{0, 20, 0x90}, want: "truncated RFC4571 packet"},
		{name: "short RTP", data: frameRFC4571([]byte{0x90, 0x60}), want: "shorter than the RTP header"},
		{name: "wrong RTP version", data: mutateTestPacket(valid, 2, 0x50), want: "unsupported RTP version"},
		{name: "wrong payload type", data: mutateTestPacket(valid, 3, 0x61), want: "unexpected payload type"},
		{name: "missing extension", data: mutateTestPacket(valid, 2, 0x80), want: "timestamp extension is absent"},
		{name: "truncated CSRC list", data: mutateTestPacket(valid, 2, 0x9f), want: "truncated CSRC list"},
		{name: "wrong extension profile", data: mutateTestPacket(valid, 14, 0xbe), want: "unexpected header extension profile"},
		{name: "short ONVIF extension", data: mutateTestPacket(valid, 17, 2), want: "want at least 12"},
		{name: "truncated ONVIF extension", data: mutateTestPacket(valid, 17, 4), want: "truncated ONVIF extension"},
		{name: "zero ONVIF timestamp", data: zeroTestPacketRange(valid, 18, 26), want: "zero ONVIF timestamp"},
		{name: "empty H264 payload", data: testRTPPacketBytes(testRTPPacket{1, 1, pts, true, nil}), want: "no H.264 payload"},
		{name: "invalid padding", data: invalidlyPaddedTestPacket(valid), want: "invalid padding length"},
		{name: "unsupported packetization", data: testRTPPacketBytes(testRTPPacket{1, 1, pts, true, []byte{0x79, 1}}), want: "unsupported H.264 packetization"},
		{name: "truncated FU-A", data: testRTPPacketBytes(testRTPPacket{1, 1, pts, true, []byte{0x7c, 0x85}}), want: "truncated FU-A"},
		{name: "FU marker before end", data: testRTPPacketBytes(testRTPPacket{1, 1, pts, true, []byte{0x7c, 0x85, 1}}), want: "marker arrived before FU-A completed"},
		{name: "truncated STAP-A", data: testRTPPacketBytes(testRTPPacket{1, 1, pts, true, []byte{0x78, 0, 3, 0x67}}), want: "invalid STAP-A NAL length"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(tt.data), time.Now)
			_, err := reader.ReadVideoAccessUnit()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want substring %q", err, tt.want)
			}
		})
	}
}

func TestRTPVideoAccessUnitReaderReportsTruncatedAccessUnit(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stream := joinTestRTPPackets(testRTPPacket{1, 1, pts, false, []byte{0x65, 1}})
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	_, err := reader.ReadVideoAccessUnit()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want unexpected EOF", err)
	}
}

func TestRTPVideoAccessUnitReaderBoundsAccessUnitSize(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stream := joinTestRTPPackets(testRTPPacket{1, 1, pts, true, []byte{0x65, 1, 2, 3, 4}})
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	reader.maxAccessUnitBytes = annexBLongStartCodeLength + 4
	_, err := reader.ReadVideoAccessUnit()
	if err == nil || !strings.Contains(err.Error(), "access unit exceeds") {
		t.Fatalf("error = %v, want access unit limit", err)
	}
}

func TestRTPVideoAccessUnitReaderAllowsSequenceWrap(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	stream := joinTestRTPPackets(
		testRTPPacket{0xffff, 1, pts, false, []byte{0x67, 1}},
		testRTPPacket{0, 1, pts, true, []byte{0x65, 2}},
	)
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	if _, err := reader.ReadVideoAccessUnit(); err != nil {
		t.Fatal(err)
	}
}

type oneByteReader struct {
	reader io.Reader
}

func (r *oneByteReader) Read(p []byte) (int, error) {
	if len(p) > 1 {
		p = p[:1]
	}
	return r.reader.Read(p)
}

func joinTestRTPPackets(packets ...testRTPPacket) []byte {
	var stream []byte
	for _, packet := range packets {
		stream = append(stream, testRTPPacketBytes(packet)...)
	}
	return stream
}

func testRTPPacketBytes(packet testRTPPacket) []byte {
	rtp := make([]byte, 28+len(packet.payload))
	rtp[0] = 0x90 // RTP v2 with a header extension.
	rtp[1] = rtpVideoPayloadType
	if packet.marker {
		rtp[1] |= 0x80
	}
	binary.BigEndian.PutUint16(rtp[2:4], packet.sequence)
	binary.BigEndian.PutUint32(rtp[4:8], packet.timestamp)
	binary.BigEndian.PutUint32(rtp[8:12], testVideoSSRC)
	binary.BigEndian.PutUint16(rtp[12:14], onvifRTPHeaderProfile)
	binary.BigEndian.PutUint16(rtp[14:16], 3)
	binary.BigEndian.PutUint64(rtp[16:24], packet.ntp)
	binary.BigEndian.PutUint32(rtp[24:28], 0xa0000000)
	copy(rtp[28:], packet.payload)
	return frameRFC4571(rtp)
}

func frameRFC4571(packet []byte) []byte {
	framed := make([]byte, 2+len(packet))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(packet)))
	copy(framed[2:], packet)
	return framed
}

func mutateTestPacket(packet []byte, offset int, value byte) []byte {
	mutated := append([]byte(nil), packet...)
	mutated[offset] = value
	return mutated
}

func zeroTestPacketRange(packet []byte, start, end int) []byte {
	mutated := append([]byte(nil), packet...)
	for index := start; index < end; index++ {
		mutated[index] = 0
	}
	return mutated
}

func invalidlyPaddedTestPacket(packet []byte) []byte {
	mutated := append([]byte(nil), packet...)
	mutated[2] |= 0x20
	mutated[len(mutated)-1] = 0xff
	return mutated
}

func ntpFromTime(value time.Time) uint64 {
	seconds := uint64(value.Unix() + secondsFrom1900To1970)
	fraction := (uint64(value.Nanosecond()) << 32) / uint64(time.Second)
	return seconds<<32 | fraction
}

// testUntimedRTPPacketBytes builds a packet without the ONVIF extension, as
// GStreamer before 1.22 emits for every buffer-list entry after the first.
func testUntimedRTPPacketBytes(packet testRTPPacket) []byte {
	rtp := make([]byte, 12+len(packet.payload))
	rtp[0] = 0x80
	rtp[1] = rtpVideoPayloadType
	if packet.marker {
		rtp[1] |= 0x80
	}
	binary.BigEndian.PutUint16(rtp[2:4], packet.sequence)
	binary.BigEndian.PutUint32(rtp[4:8], packet.timestamp)
	binary.BigEndian.PutUint32(rtp[8:12], testVideoSSRC)
	copy(rtp[12:], packet.payload)
	return frameRFC4571(rtp)
}

func TestRTPVideoAccessUnitReaderAcceptsUntimedContinuationPackets(t *testing.T) {
	wallPTS := time.Unix(1787276400, 0).UTC()
	now := time.Now()
	var stream []byte
	stream = append(stream, testRTPPacketBytes(testRTPPacket{20, 9000, ntpFromTime(wallPTS), false, []byte{0x7c, 0x85, 1, 2}})...)
	stream = append(stream, testUntimedRTPPacketBytes(testRTPPacket{21, 9000, 0, true, []byte{0x7c, 0x45, 3, 4}})...)
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), func() time.Time { return now })

	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{0, 0, 0, 1, 0x65, 1, 2, 3, 4}; !bytes.Equal(unit.AnnexB, want) {
		t.Fatalf("Annex-B access unit = %x, want %x", unit.AnnexB, want)
	}
	if !unit.PTS.Equal(wallPTS) {
		t.Fatalf("PTS wall time = %v, want %v", unit.PTS, wallPTS)
	}
}

func TestRTPVideoAccessUnitReaderRejectsUntimedAccessUnitStart(t *testing.T) {
	stream := testUntimedRTPPacketBytes(testRTPPacket{20, 9000, 0, true, []byte{0x65, 1}})
	reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
	if _, err := reader.ReadVideoAccessUnit(); err == nil || !strings.Contains(err.Error(), "extension is absent") {
		t.Fatalf("error = %v, want missing extension", err)
	}
}

func TestRTPVideoAccessUnitReaderUntimedPacketBoundaries(t *testing.T) {
	pts := ntpFromTime(time.Unix(1787276300, 0))
	for _, test := range []struct {
		name    string
		first   testRTPPacket
		second  testRTPPacket
		wantErr string
	}{
		{"new timestamp", testRTPPacket{1, 90, pts, false, []byte{0x65, 1}}, testRTPPacket{2, 180, 0, true, []byte{0x61, 2}}, "extension is absent"},
		{"sequence gap", testRTPPacket{1, 90, pts, false, []byte{0x65, 1}}, testRTPPacket{3, 90, 0, true, []byte{0x61, 2}}, "sequence discontinuity"},
		{"new access unit reusing timestamp", testRTPPacket{1, 90, pts, true, []byte{0x65, 1}}, testRTPPacket{2, 90, 0, true, []byte{0x61, 2}}, "extension is absent"},
	} {
		t.Run(test.name, func(t *testing.T) {
			stream := append(testRTPPacketBytes(test.first), testUntimedRTPPacketBytes(test.second)...)
			reader := newRTPVideoAccessUnitReaderWithNow(bytes.NewReader(stream), time.Now)
			if test.first.marker {
				if _, err := reader.ReadVideoAccessUnit(); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := reader.ReadVideoAccessUnit(); err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestRTPVideoAccessUnitReaderUntimedHEVCContinuation(t *testing.T) {
	pts := time.Unix(1787276300, 0)
	stream := append(testRTPPacketBytes(testRTPPacket{1, 90, ntpFromTime(pts), false, []byte{0x62, 1, 0x93, 0x11}}),
		testUntimedRTPPacketBytes(testRTPPacket{2, 90, 0, true, []byte{0x62, 1, 0x53, 0x22}})...)
	reader := newRTPVideoAccessUnitReaderForCodecWithNow(bytes.NewReader(stream), VideoCodecHEVC, time.Now)
	unit, err := reader.ReadVideoAccessUnit()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(unit.AnnexB, []byte{0, 0, 0, 1, 0x26, 1, 0x11, 0x22}) || !unit.PTS.Equal(pts) {
		t.Fatalf("HEVC unit = %+v, want reassembled IDR with original PTS", unit)
	}
}
