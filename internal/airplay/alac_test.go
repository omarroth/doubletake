package airplay

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestALACVerbatimEncoding(t *testing.T) {
	// Generate a 440 Hz sine wave frame: 352 samples, stereo, 16-bit, 44100 Hz
	const spf = 352
	const channels = 2
	const sampleRate = 44100
	const freq = 440.0

	pcm := make([]byte, spf*channels*2)
	for i := 0; i < spf; i++ {
		sample := int16(math.Sin(2*math.Pi*freq*float64(i)/sampleRate) * 16000)
		// S16LE format
		for ch := 0; ch < channels; ch++ {
			off := (i*channels + ch) * 2
			pcm[off] = byte(sample)
			pcm[off+1] = byte(sample >> 8)
		}
	}

	// Encode
	out := make([]byte, 4096)
	n := encodeALACVerbatim(out, pcm, spf, channels, 16)
	out = out[:n]

	t.Logf("ALAC frame: %d bytes", n)
	t.Logf("First 16 bytes (hex): %s", hex.EncodeToString(out[:min(16, n)]))

	// Verify header bits
	// Byte 0: 001 0000 0 = 0x20 (TYPE_CPE=1, elemTag=0, unused starts)
	if out[0] != 0x20 {
		t.Errorf("byte 0: got 0x%02x, want 0x20", out[0])
	}
	// Byte 1: 00000000 (unused continuation)
	if out[1] != 0x00 {
		t.Errorf("byte 1: got 0x%02x, want 0x00", out[1])
	}
	if n >= 7 {
		wantPrefix := "200012000002c0"
		gotPrefix := hex.EncodeToString(out[:7])
		if gotPrefix != wantPrefix {
			t.Errorf("header prefix: got %s, want %s", gotPrefix, wantPrefix)
		}
	}

	// Expected frame size includes the explicit 32-bit sample count.
	expectedSize := (23 + 32 + spf*channels*16 + 3 + 7) / 8 // round up
	t.Logf("Expected size: %d bytes", expectedSize)
	if n != expectedSize {
		t.Errorf("frame size: got %d, want %d", n, expectedSize)
	}

	// Verify that encoded data has non-zero samples (sine wave, not silence)
	// Sample data starts at bit 55 (byte 6, bit 7)
	// Just check that bytes 7-20 aren't all zero
	allZero := true
	for i := 7; i < min(20, n); i++ {
		if out[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("sample data appears to be all zeros (silence)")
	}

	// Test with all-zero PCM (silence) to verify encoding still works
	silentPCM := make([]byte, spf*channels*2)
	silentOut := make([]byte, 4096)
	sn := encodeALACVerbatim(silentOut, silentPCM, spf, channels, 16)
	t.Logf("Silent frame: %d bytes, first 16: %s", sn, hex.EncodeToString(silentOut[:min(16, sn)]))
}

func TestALACCompressedEncoding(t *testing.T) {
	pcm := testALACPCM()
	out := make([]byte, 4096)
	n := (&alacEncoder{}).Encode(out, pcm)
	out = out[:n]

	if n >= 1024 {
		t.Fatalf("compressed ALAC frame is %d bytes; RFC 2198 can only describe blocks up to 1023 bytes", n)
	}
	// A modern encrypted packet has 36 bytes of RTP, AEAD, and nonce overhead.
	// Keep enough room for the current frame, one redundant frame, and the
	// five-byte RFC 2198 header inside the 1472-byte UDP payload limit.
	if got, limit := 2*n+5, maximumAudioRTPDatagramBytes-36; got > limit {
		t.Fatalf("current plus one redundant ALAC frame uses %d bytes, payload limit is %d", got, limit)
	}
	if out[0] != 0x20 {
		t.Fatalf("first byte = 0x%02x, want stereo channel-pair element", out[0])
	}
	// The element flags begin after the 3-bit tag, 4-bit instance, and
	// 12 reserved bits. The packet carries an explicit sample count and is
	// compressed without shifted bytes.
	flags := (uint16(out[2])<<8 | uint16(out[3])) >> 9 & 0xf
	if flags != 8 {
		t.Fatalf("element flags = 0x%x, want explicit-size compressed frame", flags)
	}
	if got, want := hex.EncodeToString(out[:7]), "200010000002c0"; got != want {
		t.Fatalf("compressed header prefix = %s, want %s", got, want)
	}
	reader := h264BitReader{data: out}
	if got := reader.readBits(3); got != 1 {
		t.Fatalf("element tag = %d, want stereo channel pair", got)
	}
	reader.readBits(4 + 12 + 4 + 32)
	if got := reader.readBits(8); got != alacStereoShift {
		t.Fatalf("stereo transform shift = %d, want %d", got, alacStereoShift)
	}
	if got := reader.readBits(8); got > 1<<alacStereoShift {
		t.Fatalf("stereo transform weight = %d, want 0..%d", got, 1<<alacStereoShift)
	}
	for channel := 0; channel < alacStereoChannels; channel++ {
		if got := reader.readBits(8); got != alacPredictionShift {
			t.Fatalf("channel %d predictor mode/shift = 0x%x, want 0x%x", channel, got, alacPredictionShift)
		}
		order := int(reader.readBits(8) & 0x1f)
		if order < alacPredictionMinOrder || order > alacPredictionMaxOrder {
			t.Fatalf("channel %d predictor order = %d, want %d..%d",
				channel, order, alacPredictionMinOrder, alacPredictionMaxOrder)
		}
		coefficients := alacPredictionCoefficients(order)
		for coefficientIndex, want := range coefficients[:order] {
			if got := int16(reader.readBits(16)); got != want {
				t.Fatalf("channel %d coefficient %d = %d, want %d", channel, coefficientIndex, got, want)
			}
		}
	}
	if reader.err {
		t.Fatal("compressed predictor header is truncated")
	}
	t.Logf("compressed 352-sample stereo ALAC frame: %d bytes", n)
}

func TestALACCompressedEncodingAllocatesNoPerFrameMemory(t *testing.T) {
	pcm := testALACPCM()
	out := make([]byte, 4096)
	encoder := &alacEncoder{}
	if allocations := testing.AllocsPerRun(100, func() {
		encoder.Encode(out, pcm)
	}); allocations != 0 {
		t.Fatalf("ALAC frame encoding allocated %.1f objects, want 0", allocations)
	}
}

func TestALACEntropyBitCountMatchesWriter(t *testing.T) {
	patterns := map[string][]byte{
		"music":     testALACPCM(),
		"transient": testALACTransientPCM(),
		"silence":   make([]byte, alacScreenFrameSamples*audioBytesPerSampleFrame),
		"noise":     testALACNoisePCM(),
	}
	for name, pcm := range patterns {
		t.Run(name, func(t *testing.T) {
			for channel := 0; channel < alacStereoChannels; channel++ {
				samples := make([]int32, alacScreenFrameSamples)
				for sampleIndex := range samples {
					offset := sampleIndex*audioBytesPerSampleFrame + channel*audioBytesPerSample
					samples[sampleIndex] = int32(int16(binary.LittleEndian.Uint16(pcm[offset:])))
				}
				residuals := make([]int32, alacScreenFrameSamples)
				encoded := make([]byte, 4096)
				for order := alacPredictionMinOrder; order <= alacPredictionMaxOrder; order++ {
					alacPredictResiduals(samples, residuals, order)
					var writer bitWriter
					writer.init(encoded)
					writeALACEntropyBlock(&writer, residuals, alacCodedChannelBits)
					writtenBits := writer.pos*8 + writer.bitPos
					if countedBits := alacEntropyBitCount(residuals, alacCodedChannelBits); countedBits != writtenBits {
						t.Fatalf("channel %d order %d entropy size = %d bits, writer produced %d",
							channel, order, countedBits, writtenBits)
					}
				}
			}
		})
	}
}

func TestALACCompressedFrameDecodesLosslessly(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable for independent ALAC decode")
	}

	patterns := map[string][]byte{
		"music":     testALACPCM(),
		"transient": testALACTransientPCM(),
		"silence":   make([]byte, alacScreenFrameSamples*audioBytesPerSampleFrame),
		"noise":     testALACNoisePCM(),
	}
	for name, pcm := range patterns {
		t.Run(name, func(t *testing.T) {
			encoded := make([]byte, 4096)
			n := (&alacEncoder{}).Encode(encoded, pcm)
			encoded = encoded[:n]

			temporary := t.TempDir()
			cafPath := filepath.Join(temporary, "frame.caf")
			pcmPath := filepath.Join(temporary, "decoded.pcm")
			if err := os.WriteFile(cafPath, singleFrameALACCAF(encoded), 0o600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(ffmpeg, "-v", "error", "-y", "-i", cafPath,
				"-f", "s16le", "-acodec", "pcm_s16le", pcmPath)
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatalf("ffmpeg rejected ALAC: %v\n%s", err, output)
			}
			decoded, err := os.ReadFile(pcmPath)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(decoded, pcm) {
				t.Fatalf("decoded PCM differs: got %d bytes, want %d", len(decoded), len(pcm))
			}
		})
	}
}

func TestALACAdaptivePredictionKeepsTransientFramesRFC2198Compatible(t *testing.T) {
	pcm := testALACTransientPCM()
	encoded := make([]byte, 4096)
	n := (&alacEncoder{}).Encode(encoded, pcm)
	if n > 0x3ff {
		t.Fatalf("transient ALAC frame is %d bytes; RFC 2198 can describe at most 1023", n)
	}
}

func TestALACCompressedStreamDecodesLosslesslyAcrossSilence(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable for independent ALAC decode")
	}

	const frameCount = 12
	pcm := make([]byte, frameCount*alacScreenFrameSamples*audioBytesPerSampleFrame)
	for sampleIndex := 0; sampleIndex < frameCount*alacScreenFrameSamples; sampleIndex++ {
		// Exercise the transitions seen in live capture: whole silent packets,
		// signal starting and stopping at packet boundaries, and zero runs inside
		// otherwise active packets.
		var left, right int16
		switch {
		case sampleIndex < 2*alacScreenFrameSamples:
		case sampleIndex < 7*alacScreenFrameSamples:
			left = int16(math.Sin(2*math.Pi*440*float64(sampleIndex)/44100) * 16000)
			right = int16(math.Sin(2*math.Pi*659.25*float64(sampleIndex)/44100) * 12000)
		case sampleIndex < 9*alacScreenFrameSamples:
			if sampleIndex%64 >= 24 {
				left = int16((sampleIndex*7919)%60001 - 30000)
				right = -left
			}
		}
		offset := sampleIndex * audioBytesPerSampleFrame
		binary.LittleEndian.PutUint16(pcm[offset:], uint16(left))
		binary.LittleEndian.PutUint16(pcm[offset+2:], uint16(right))
	}

	encoder := &alacEncoder{}
	frames := make([][]byte, frameCount)
	for frameIndex := range frames {
		start := frameIndex * alacScreenFrameSamples * audioBytesPerSampleFrame
		encoded := make([]byte, 4096)
		n := encoder.Encode(encoded, pcm[start:start+alacScreenFrameSamples*audioBytesPerSampleFrame])
		frames[frameIndex] = append([]byte(nil), encoded[:n]...)
	}

	temporary := t.TempDir()
	cafPath := filepath.Join(temporary, "stream.caf")
	pcmPath := filepath.Join(temporary, "decoded.pcm")
	if err := os.WriteFile(cafPath, multiFrameALACCAF(frames), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(ffmpeg, "-v", "error", "-y", "-i", cafPath,
		"-f", "s16le", "-acodec", "pcm_s16le", pcmPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg rejected ALAC stream: %v\n%s", err, output)
	}
	decoded, err := os.ReadFile(pcmPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, pcm) {
		t.Fatalf("decoded PCM differs across silence transitions: got %d bytes, want %d", len(decoded), len(pcm))
	}
}

func TestALACLongMixedSignalStreamDecodesLosslessly(t *testing.T) {
	ffmpeg, err := exec.LookPath("ffmpeg")
	if err != nil {
		t.Skip("ffmpeg is unavailable for independent ALAC decode")
	}

	const frameCount = 512
	pcm := make([]byte, frameCount*alacScreenFrameSamples*audioBytesPerSampleFrame)
	state := uint32(0x6d2b79f5)
	var walkLeft, walkRight int32
	for sampleIndex := 0; sampleIndex < frameCount*alacScreenFrameSamples; sampleIndex++ {
		frameIndex := sampleIndex / alacScreenFrameSamples
		frameSample := sampleIndex % alacScreenFrameSamples
		var left, right int16
		switch frameIndex % 12 {
		case 0, 1:
			// Whole silent frames exercise start/stop boundaries.
		case 2, 3, 4:
			left = int16(math.Sin(2*math.Pi*440*float64(sampleIndex)/44100) * 28000)
			right = int16(math.Sin(2*math.Pi*659.25*float64(sampleIndex)/44100) * 22000)
		case 5:
			// Full-scale transitions and isolated impulses stress predictor resets.
			if frameSample%64 < 32 {
				left, right = 32767, -32768
			}
			if frameSample == 176 {
				left, right = -32768, 32767
			}
		case 6, 7, 8:
			// Correlated random walks resemble broad-band program material while
			// repeatedly changing the adaptive predictor's preferred order.
			state = state*1664525 + 1013904223
			walkLeft += int32(int8(state>>24)) * 17
			if walkLeft < -30000 {
				walkLeft = -30000
			} else if walkLeft > 30000 {
				walkLeft = 30000
			}
			state = state*1664525 + 1013904223
			walkRight += int32(int8(state>>24)) * 13
			if walkRight < -30000 {
				walkRight = -30000
			} else if walkRight > 30000 {
				walkRight = 30000
			}
			left = int16(walkLeft)
			right = int16((walkLeft + walkRight) / 2)
		default:
			// Incompressible input selects the verbatim path.
			state = state*1664525 + 1013904223
			left = int16(state >> 16)
			state = state*1664525 + 1013904223
			right = int16(state >> 16)
		}
		offset := sampleIndex * audioBytesPerSampleFrame
		binary.LittleEndian.PutUint16(pcm[offset:], uint16(left))
		binary.LittleEndian.PutUint16(pcm[offset+2:], uint16(right))
	}

	encoder := &alacEncoder{}
	frames := make([][]byte, frameCount)
	frameBytes := alacScreenFrameSamples * audioBytesPerSampleFrame
	for frameIndex := range frames {
		encoded := make([]byte, 4096)
		start := frameIndex * frameBytes
		n := encoder.Encode(encoded, pcm[start:start+frameBytes])
		frames[frameIndex] = append([]byte(nil), encoded[:n]...)
	}

	temporary := t.TempDir()
	cafPath := filepath.Join(temporary, "mixed.caf")
	pcmPath := filepath.Join(temporary, "decoded.pcm")
	if err := os.WriteFile(cafPath, multiFrameALACCAF(frames), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(ffmpeg, "-v", "error", "-y", "-i", cafPath,
		"-f", "s16le", "-acodec", "pcm_s16le", pcmPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("ffmpeg rejected long ALAC stream: %v\n%s", err, output)
	}
	decoded, err := os.ReadFile(pcmPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decoded, pcm) {
		t.Fatalf("long mixed-signal PCM differs: got %d bytes, want %d", len(decoded), len(pcm))
	}
}

func TestAudioCaptureUsesCompressedALAC(t *testing.T) {
	pcm := testALACPCM()
	capture := &AudioCapture{
		pcmPipe: io.NopCloser(bytes.NewReader(pcm)),
		waitCh:  make(chan struct{}),
		codec:   AudioCodecALAC,
	}
	encoded := make([]byte, 8192)
	n, _, err := capture.readFramePosition(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if n >= 1024 {
		t.Fatalf("encoded length = %d, want a compressed ALAC packet", n)
	}
}

func testALACPCM() []byte {
	const sampleRate = 44100
	pcm := make([]byte, alacScreenFrameSamples*audioBytesPerSampleFrame)
	for sampleIndex := 0; sampleIndex < alacScreenFrameSamples; sampleIndex++ {
		left := int16(math.Sin(2*math.Pi*440*float64(sampleIndex)/sampleRate) * 16000)
		right := int16(math.Sin(2*math.Pi*659.25*float64(sampleIndex)/sampleRate) * 12000)
		offset := sampleIndex * audioBytesPerSampleFrame
		binary.LittleEndian.PutUint16(pcm[offset:], uint16(left))
		binary.LittleEndian.PutUint16(pcm[offset+2:], uint16(right))
	}
	return pcm
}

func testALACNoisePCM() []byte {
	pcm := make([]byte, alacScreenFrameSamples*audioBytesPerSampleFrame)
	state := uint32(0x4d595df4)
	for offset := 0; offset < len(pcm); offset += 2 {
		state = state*1664525 + 1013904223
		binary.LittleEndian.PutUint16(pcm[offset:], uint16(state>>16))
	}
	return pcm
}

func testALACTransientPCM() []byte {
	pcm := make([]byte, alacScreenFrameSamples*audioBytesPerSampleFrame)
	for sampleIndex := 0; sampleIndex < alacScreenFrameSamples; sampleIndex++ {
		left, right := int16(-20000), int16(10000)
		if sampleIndex%20 < 10 {
			left, right = 20000, -10000
		}
		offset := sampleIndex * audioBytesPerSampleFrame
		binary.LittleEndian.PutUint16(pcm[offset:], uint16(left))
		binary.LittleEndian.PutUint16(pcm[offset+2:], uint16(right))
	}
	return pcm
}

func singleFrameALACCAF(frame []byte) []byte {
	return multiFrameALACCAF([][]byte{frame})
}

func multiFrameALACCAF(frames [][]byte) []byte {
	// CAF metadata for the negotiated 44.1 kHz, stereo, 16-bit screen-audio
	// format. Its configured frame length and each packet are both 352 samples.
	prefix, err := hex.DecodeString(
		"6361666600010000" +
			"64657363000000000000002040e5888000000000616c61630000000000000000000010000000000200000000" +
			"6368616e000000000000000c006500020000000000000000" +
			"6b756b6900000000000000300000000c66726d61616c616300000024616c616300000000000001600010280a0e02000000004004001588800000ac44")
	if err != nil {
		panic(err)
	}

	var caf bytes.Buffer
	caf.Write(prefix)
	caf.WriteString("data")
	dataLength := 4
	packetTableLength := 24
	for _, frame := range frames {
		dataLength += len(frame)
		packetTableLength += len(cafVariableInteger(uint64(len(frame))))
	}
	_ = binary.Write(&caf, binary.BigEndian, uint64(dataLength))
	_ = binary.Write(&caf, binary.BigEndian, uint32(0))
	for _, frame := range frames {
		caf.Write(frame)
	}

	caf.WriteString("pakt")
	_ = binary.Write(&caf, binary.BigEndian, uint64(packetTableLength))
	_ = binary.Write(&caf, binary.BigEndian, uint64(len(frames)))
	_ = binary.Write(&caf, binary.BigEndian, uint64(len(frames)*alacScreenFrameSamples))
	_ = binary.Write(&caf, binary.BigEndian, uint32(0))
	_ = binary.Write(&caf, binary.BigEndian, uint32(0))
	for _, frame := range frames {
		caf.Write(cafVariableInteger(uint64(len(frame))))
	}
	return caf.Bytes()
}

func cafVariableInteger(value uint64) []byte {
	var reversed [10]byte
	count := 0
	for {
		reversed[count] = byte(value & 0x7f)
		count++
		value >>= 7
		if value == 0 {
			break
		}
	}
	encoded := make([]byte, count)
	for index := 0; index < count; index++ {
		encoded[index] = reversed[count-1-index]
		if index+1 < count {
			encoded[index] |= 0x80
		}
	}
	return encoded
}
