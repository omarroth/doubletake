package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"io"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestVideoPacketizerPreservesSEIAndSlices(t *testing.T) {
	for _, codec := range []VideoCodec{VideoCodecH264, VideoCodecHEVC} {
		t.Run(string(codec), func(t *testing.T) {
			p := mirrorVideoPacketizer{codec: codec}
			var config, sample [][]byte
			if codec == VideoCodecH264 {
				config = [][]byte{{0x67, 0x42}, {0x68, 0xce}, {9, 0xf0}}
				sample = [][]byte{{6, 5, 1, 0xaa, 0x80}, {0x65, 0x80}, {0x65, 0x40}}
			} else {
				config = [][]byte{{32 << 1, 1}, {33 << 1, 1}, {34 << 1, 1}, {35 << 1, 1}}
				sample = [][]byte{{39 << 1, 1, 5, 1, 0xaa, 0x80}, {19 << 1, 1, 0x80}, {19 << 1, 1, 0x40}, {40 << 1, 1, 5, 1, 0xbb, 0x80}}
			}
			if frame := p.packetize(joinAnnexBNALs(config...)); p.ready(frame) {
				t.Fatal("parameter sets alone were treated as a picture")
			}
			frame := p.packetize(joinAnnexBNALs(sample...))
			if !p.ready(frame) || !frame.keyframe {
				t.Fatal("configured random-access picture was suppressed")
			}
			var want []byte
			for _, nal := range sample {
				want = append(want, receiverTestAVCC(nal)...)
			}
			if !bytes.Equal(frame.payload, want) {
				t.Fatalf("sample = %x, want SEI and all slices in order: %x", frame.payload, want)
			}
		})
	}
}

func TestStreamFramesPreservesSEIAcrossPrimingAndReconfiguration(t *testing.T) {
	sps := []byte{0x67, 0x42, 0, 0x1f, 0xf8, 0x0a, 0, 0xb7, 0x20}
	pps := []byte{0x68, 0xce, 6, 0xe2}
	changed := append([]byte(nil), pps...)
	changed[len(changed)-1]++
	sei := func(value byte) []byte { return []byte{6, 5, 1, value, 0x80} }
	samples := [][][]byte{
		{sei(1), {0x65, 0x80, 1}, {0x65, 0x40, 2}},
		{sei(2), {0x61, 0x80, 3}},
		{sei(3), {0x65, 0x80, 4}},
	}
	nals := [][][]byte{
		{sps, pps}, {sei(0), {0x61, 0x80, 0}},
		append([][]byte{{9, 0xf0}}, samples[0]...),
		append([][]byte{{9, 0xf0}}, samples[1]...),
		append([][]byte{{9, 0xf0}, sps, changed}, samples[2]...),
	}
	for _, raw := range []bool{false, true} {
		t.Run(map[bool]string{false: "timestamped", true: "raw"}[raw], func(t *testing.T) {
			capture := &ScreenCapture{waitCh: make(chan struct{})}
			var units []VideoAccessUnit
			var stream []byte
			for i, unit := range nals {
				encoded := joinAnnexBNALs(unit...)
				units = append(units, VideoAccessUnit{AnnexB: encoded, PTS: time.Unix(1700000000, 0).Add(time.Duration(i) * time.Second / 30)})
				stream = append(stream, encoded...)
			}
			if raw {
				capture.stdout = io.NopCloser(bytes.NewReader(stream))
			} else {
				capture.frames = &sliceVideoAccessUnitReader{frames: units}
			}
			packets := collectVideoPackets(t, capture, VideoCodecH264, nil)
			if len(packets) != 5 || packets[0].header[4] != 1 || packets[3].header[4] != 1 {
				t.Fatalf("got %d packets, want initial codec, two pictures, changed codec, final picture", len(packets))
			}
			for i, index := range []int{1, 2, 4} {
				var want []byte
				for _, nal := range samples[i] {
					want = append(want, receiverTestAVCC(nal)...)
				}
				if !bytes.Equal(packets[index].payload, want) {
					t.Fatalf("picture %d = %x, want %x", i, packets[index].payload, want)
				}
			}
		})
	}
}

func collectVideoPackets(t *testing.T, capture *ScreenCapture, codec VideoCodec, encrypt func([]byte) []byte) []mirrorPacket {
	t.Helper()
	sender, receiver := net.Pipe()
	defer sender.Close()
	defer receiver.Close()
	var output bytes.Buffer
	done := make(chan error, 1)
	go func() { _, err := io.Copy(&output, receiver); done <- err }()
	now := time.Unix(1700000000, 0)
	if reader, ok := capture.frames.(*sliceVideoAccessUnitReader); ok && len(reader.frames) != 0 {
		now = reader.frames[len(reader.frames)-1].PTS
	}
	session := &MirrorSession{
		dataConn: sender, videoCodec: codec, firstFrameSent: make(chan struct{}),
		streamCipher: encrypt, timestampBias: time.Second,
		frameClockNow: func() time.Time { return now },
	}
	err := session.StreamFrames(context.Background(), capture, 0)
	_ = sender.Close()
	if copyErr := <-done; copyErr != nil {
		t.Fatal(copyErr)
	}
	if err == nil || !strings.Contains(err.Error(), "unexpectedly (EOF)") {
		t.Fatalf("stream error = %v, want capture EOF", err)
	}
	return splitMirrorPackets(t, output.Bytes())
}

func TestStreamFramesEncodedVideoRoundTrip(t *testing.T) {
	if _, err := exec.LookPath("ffmpeg"); err != nil {
		t.Skip("FFmpeg is unavailable for the decoder round trip")
	}
	for _, codec := range []VideoCodec{VideoCodecH264, VideoCodecHEVC} {
		t.Run(string(codec), func(t *testing.T) {
			encoder := "x264enc"
			if codec == VideoCodecHEVC {
				encoder = "x265enc"
			}
			if !hasGstElement(encoder) || !supportsTimestampedVideoOutput(codec) {
				t.Skip("GStreamer encoder or timestamped output unavailable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			capture, err := StartTestCapture(ctx, CaptureConfig{FPS: 30, Bitrate: 1000, HWAccel: "none", VideoCodec: codec, MaxWidth: 320, MaxHeight: 180})
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Stop()
			var units []VideoAccessUnit
			for range 3 {
				unit, err := capture.ReadVideoAccessUnit()
				if err != nil {
					t.Fatal(err)
				}
				units = append(units, unit)
			}
			key, iv := bytes.Repeat([]byte{0x31}, 16), bytes.Repeat([]byte{0x72}, 16)
			encryptor, err := newMirrorCipher(key, iv)
			if err != nil {
				t.Fatal(err)
			}
			packets := collectVideoPackets(t, &ScreenCapture{frames: &sliceVideoAccessUnitReader{frames: units}, waitCh: make(chan struct{})}, codec, encryptor.EncryptFrame)
			if len(packets) != 4 || packets[0].header[4] != 1 {
				t.Fatalf("got %d packets, want codec plus three pictures", len(packets))
			}
			block, _ := aes.NewCipher(key)
			decrypt := cipher.NewCTR(block, iv)
			var elementary []byte
			// Recover the elementary-stream configuration from the actual encoder.
			for _, wrapped := range splitAnnexBAccessUnit(units[0].AnnexB) {
				raw := stripStartCode(wrapped)
				typ := raw[0] & 0x1f
				parameter := typ == 7 || typ == 8
				if codec == VideoCodecHEVC {
					typ = hevcNALType(raw)
					parameter = typ >= 32 && typ <= 34
				}
				if parameter {
					elementary = append(elementary, joinAnnexBNALs(raw)...)
				}
			}
			for _, packet := range packets[1:] {
				decrypt.XORKeyStream(packet.payload, packet.payload)
				for data := packet.payload; len(data) != 0; {
					if len(data) < 4 {
						t.Fatal("truncated transmitted NAL length")
					}
					n := int(binary.BigEndian.Uint32(data[:4]))
					if n == 0 || n > len(data)-4 {
						t.Fatal("invalid transmitted NAL length")
					}
					elementary = append(elementary, joinAnnexBNALs(data[4:4+n])...)
					data = data[4+n:]
				}
			}
			format := "h264"
			if codec == VideoCodecHEVC {
				format = "hevc"
			}
			decoder := exec.CommandContext(ctx, "ffmpeg", "-v", "error", "-xerror", "-f", format, "-i", "pipe:0", "-f", "null", "-")
			decoder.Stdin = bytes.NewReader(elementary)
			if output, err := decoder.CombinedOutput(); err != nil {
				t.Fatalf("decode transmitted %s: %v\n%s", codec, err, output)
			}
		})
	}
}
