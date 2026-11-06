package airplay

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

func TestUseAudioRedundancyDefaults(t *testing.T) {
	if !useAudioRedundancy(AudioCodecALAC) {
		t.Fatal("expected ALAC screen sessions to use recent-packet redundancy")
	}
	if !useAudioRedundancy(AudioCodecAACELD) {
		t.Fatal("expected AAC-ELD screen sessions to use recent-packet redundancy")
	}
}

func TestComposeAudioREDPayload(t *testing.T) {
	previous := []audioREDFrame{
		{payload: []byte{1, 2}, rtpTime: 1000},
		{payload: []byte{3, 4, 5}, rtpTime: 1480},
	}
	got := composeAudioREDPayload([]byte{6}, 1960, previous, 64)
	want := []byte{
		0xe0, 0x0f, 0x00, 0x02, // PT=96, offset=960, length=2
		0xe0, 0x07, 0x80, 0x03, // PT=96, offset=480, length=3
		0x60,
		1, 2, 3, 4, 5, 6,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RED payload = %x, want %x", got, want)
	}

	got = composeAudioREDPayload([]byte{6}, 1960, previous, 9)
	want = []byte{0xe0, 0x07, 0x80, 0x03, 0x60, 3, 4, 5, 6}
	if !bytes.Equal(got, want) {
		t.Fatalf("capacity-limited RED payload = %x, want %x", got, want)
	}

	tooLarge := []audioREDFrame{
		{payload: []byte{1}, rtpTime: 1000},
		{payload: make([]byte, 1024), rtpTime: 1480},
	}
	got = composeAudioREDPayload([]byte{6}, 1960, tooLarge, 2048)
	if !bytes.Equal(got, []byte{0x60, 6}) {
		t.Fatalf("oversized RED history was retained: %x", got[:min(len(got), 16)])
	}

	// A complete history can exceed the receiver's fixed RTP packet buffer even
	// though each RFC 2198 block is independently representable. Preserve the
	// newest recovery frame that fits rather than creating a fragmented packet.
	primary := bytes.Repeat([]byte{3}, 700)
	previous = []audioREDFrame{
		{payload: bytes.Repeat([]byte{1}, 700), rtpTime: 1000},
		{payload: bytes.Repeat([]byte{2}, 700), rtpTime: 1480},
	}
	got = composeAudioREDPayload(primary, 1960, previous, maximumAudioRTPDatagramBytes-12-16-audioChaChaNonceSize)
	if headerLength, err := audioREDHeaderLength(got); err != nil {
		t.Fatal(err)
	} else if redundant := (headerLength - 1) / 4; redundant != 1 {
		t.Fatalf("MTU-limited RED payload retained %d history frames, want 1", redundant)
	}
	if wireLength := 12 + len(got) + 16 + audioChaChaNonceSize; wireLength > maximumAudioRTPDatagramBytes {
		t.Fatalf("MTU-limited RED datagram = %d bytes, maximum %d", wireLength, maximumAudioRTPDatagramBytes)
	}
}

func TestStreamAudioUsesNegotiatedRecentFrameRedundancy(t *testing.T) {
	for _, security := range []string{"plaintext", "AES", "ChaCha"} {
		t.Run(security, func(t *testing.T) {
			stream, packets := streamAudioPacketsForTest(t, security, nil, 12)
			var wantSequences []uint16
			for seq := uint16(1); seq <= 12; seq++ {
				for age := uint16(0); age <= 2 && age < seq; age++ {
					wantSequences = append(wantSequences, seq-age)
				}
			}
			assertAudioPacketSequences(t, packets, wantSequences)

			// Repeated packets and requested retransmissions must retain the exact
			// encoded/encrypted datagram, including its original sample position.
			originals := make(map[uint16][]byte)
			for _, packet := range packets {
				seq := binary.BigEndian.Uint16(packet[2:4])
				if original := originals[seq]; original != nil && !bytes.Equal(packet, original) {
					t.Fatalf("redundant sequence %d differs from its original datagram", seq)
				}
				if originals[seq] == nil {
					plain := decodeAudioPacketPayloadForTest(t, stream, security, packet)
					if len(plain) == 0 || len(plain) >= 1416 {
						t.Fatalf("legacy sequence %d ALAC length = %d, want a compressed frame", seq, len(plain))
					}
				}
				originals[seq] = packet
				if !bytes.Equal(stream.audioPacketForRetransmit(seq), packet) {
					t.Fatalf("requested retransmit history differs for sequence %d", seq)
				}
			}
			for seq := uint16(2); seq <= 12; seq++ {
				rtp := binary.BigEndian.Uint32(originals[seq][4:8])
				previous := binary.BigEndian.Uint32(originals[seq-1][4:8])
				if rtp-previous != 352 {
					t.Fatalf("sequence %d RTP delta = %d, want 352", seq, rtp-previous)
				}
			}
		})
	}
}

func TestEncryptedAudioRedundancyRecoversTwoLostBursts(t *testing.T) {
	const frames = 12
	stream, packets := streamAudioPacketsForTest(t, "ChaCha", nil, frames)
	// Lose both startup bursts: [1] and [2,1]. The next burst must recover
	// both frames, without a retransmission round trip or a new nonce.
	if len(packets) < 6 {
		t.Fatalf("only %d packets sent", len(packets))
	}
	recovered := make(map[uint16][]byte)
	for _, packet := range packets[3:] {
		seq := binary.BigEndian.Uint16(packet[2:4])
		tail := packet[len(packet)-8:]
		if got := binary.LittleEndian.Uint64(tail); got != uint64(seq-1) {
			t.Fatalf("sequence %d nonce = %d, want original nonce %d", seq, got, seq-1)
		}
		plain, err := stream.chachaCipher.Open(nil, tail, packet[12:len(packet)-8], packet[4:12])
		if err != nil {
			t.Fatalf("authenticate recovered sequence %d: %v", seq, err)
		}
		if previous := recovered[seq]; previous != nil && !bytes.Equal(previous, plain) {
			t.Fatalf("sequence %d changed its decoded payload", seq)
		}
		recovered[seq] = plain
	}
	for seq := uint16(1); seq <= frames; seq++ {
		if recovered[seq] == nil {
			t.Fatalf("sequence %d was not recovered after two lost bursts", seq)
		}
	}
	if stream.chachaNonce != frames {
		t.Fatalf("nonce counter = %d, want one increment per source frame (%d)", stream.chachaNonce, frames)
	}
}

func TestStreamAudioUsesRFC2198ForAdvertisedReceiver(t *testing.T) {
	const frames = 6
	for _, security := range []string{"plaintext", "AES", "ChaCha"} {
		t.Run(security, func(t *testing.T) {
			stream, packets := streamAudioPacketsForTest(t, security, nil, frames, true)
			if len(packets) != frames {
				t.Fatalf("RFC 2198 datagrams = %d, want %d", len(packets), frames)
			}
			previousPrimary := make([][]byte, 0, audioRedundancyCount)
			for index, packet := range packets {
				seq := uint16(index + 1)
				if packet[1] != audioREDPayloadType || binary.BigEndian.Uint16(packet[2:4]) != seq {
					t.Fatalf("packet %d header = %02x/%d, want PT=%d seq=%d", index, packet[1], binary.BigEndian.Uint16(packet[2:4]), audioREDPayloadType, seq)
				}
				if len(packet) > maximumAudioRTPDatagramBytes {
					t.Fatalf("packet %d length = %d, maximum %d", index, len(packet), maximumAudioRTPDatagramBytes)
				}
				plain := decodeAudioPacketPayloadForTest(t, stream, security, packet)
				redundant, primary := splitAudioREDPayloadForTest(t, plain)
				if len(primary) == 0 || len(primary) > 1023 {
					t.Fatalf("packet %d primary ALAC length = %d, want 1..1023", index, len(primary))
				}
				wantRedundant := 0
				used := 1 + len(primary)
				for historyIndex := len(previousPrimary) - 1; historyIndex >= 0 && wantRedundant < audioRedundancyCount; historyIndex-- {
					block := previousPrimary[historyIndex]
					if len(block) > 0x3ff || used+4+len(block) > stream.maximumPlainAudioPayloadBytes() {
						break
					}
					wantRedundant++
					used += 4 + len(block)
				}
				if len(redundant) != wantRedundant {
					t.Fatalf("packet %d carries %d redundant frames, want %d", index, len(redundant), wantRedundant)
				}
				wantHistory := previousPrimary[len(previousPrimary)-wantRedundant:]
				for historyIndex := range wantHistory {
					if !bytes.Equal(redundant[historyIndex], wantHistory[historyIndex]) {
						t.Fatalf("packet %d redundant block %d differs from prior primary", index, historyIndex)
					}
				}
				retransmit := stream.audioPacketForRetransmit(seq)
				if len(retransmit) < 12 || retransmit[1] != audioDataPayloadType {
					t.Fatalf("sequence %d retransmit packet is not PT96: %x", seq, retransmit[:min(len(retransmit), 12)])
				}
				if got := decodeAudioPacketPayloadForTest(t, stream, security, retransmit); !bytes.Equal(got, primary) {
					t.Fatalf("sequence %d retransmit primary differs from RED primary", seq)
				}
				if len(previousPrimary) == audioRedundancyCount {
					copy(previousPrimary, previousPrimary[1:])
					previousPrimary = previousPrimary[:audioRedundancyCount-1]
				}
				previousPrimary = append(previousPrimary, append([]byte(nil), primary...))
				if security == "ChaCha" {
					redNonce := binary.LittleEndian.Uint64(packet[len(packet)-audioChaChaNonceSize:])
					primaryNonce := binary.LittleEndian.Uint64(retransmit[len(retransmit)-audioChaChaNonceSize:])
					if redNonce != uint64(index*2) || primaryNonce != uint64(index*2+1) {
						t.Fatalf("sequence %d RED/primary nonces = %d/%d, want %d/%d", seq, redNonce, primaryNonce, index*2, index*2+1)
					}
				}
			}
			if security == "ChaCha" && stream.chachaNonce != frames*2 {
				t.Fatalf("nonce counter = %d, want %d", stream.chachaNonce, frames*2)
			}
		})
	}
}

func splitAudioREDPayloadForTest(t *testing.T, payload []byte) ([][]byte, []byte) {
	t.Helper()
	type blockHeader struct {
		length int
	}
	var headers []blockHeader
	offset := 0
	for {
		if offset >= len(payload) || payload[offset]&0x7f != audioDataPayloadType {
			t.Fatalf("invalid RFC 2198 header at offset %d: %x", offset, payload[:min(len(payload), offset+4)])
		}
		if payload[offset]&0x80 == 0 {
			offset++
			break
		}
		if offset+4 > len(payload) {
			t.Fatalf("truncated RFC 2198 header: %x", payload)
		}
		headers = append(headers, blockHeader{length: int(payload[offset+2]&3)<<8 | int(payload[offset+3])})
		offset += 4
	}
	blocks := make([][]byte, 0, len(headers))
	for _, header := range headers {
		if offset+header.length > len(payload) {
			t.Fatalf("RFC 2198 block length %d exceeds %d-byte payload", header.length, len(payload)-offset)
		}
		blocks = append(blocks, payload[offset:offset+header.length])
		offset += header.length
	}
	return blocks, payload[offset:]
}

func TestCompoundRFC2198LeavesHeadersClearAndEncryptsCodecDataAsOneRegion(t *testing.T) {
	for _, security := range []string{"plaintext", "AES", "ChaCha"} {
		t.Run(security, func(t *testing.T) {
			conn := &recordingPacketConn{}
			control := &recordingPacketConn{}
			stream := &AudioStream{conn: conn, ctrlConn: control, remoteAddr: &netUDPAddrForAudioTest}
			var err error
			switch security {
			case "AES":
				stream.cipher, err = aes.NewCipher(bytes.Repeat([]byte{0x42}, 16))
				stream.aesIV = bytes.Repeat([]byte{0x24}, 16)
			case "ChaCha":
				stream.chachaCipher, err = newAudioChaCha64AEAD(bytes.Repeat([]byte{0x42}, 32))
				stream.chachaNonceMode = defaultAudioChaChaNonceMode()
				stream.chachaAADMode = defaultAudioChaChaAADMode()
			}
			if err != nil {
				t.Fatal(err)
			}
			plain := composeAudioREDPayload([]byte("current"), 1960, []audioREDFrame{
				{payload: []byte("older"), rtpTime: 1000},
				{payload: []byte("newer"), rtpTime: 1480},
			}, stream.maximumPlainAudioPayloadBytes())
			primary := []byte("current")
			if err := stream.sendAudioREDPacket(plain, primary, 1960, 3); err != nil {
				t.Fatal(err)
			}
			if len(conn.packets) != 1 {
				t.Fatalf("sent %d packets, want one", len(conn.packets))
			}
			packet := conn.packets[0]
			if packet[1] != audioREDPayloadType || binary.BigEndian.Uint16(packet[2:4]) != 3 || binary.BigEndian.Uint32(packet[4:8]) != 1960 {
				t.Fatalf("RTP header = %x", packet[:12])
			}
			if got := decodeAudioPacketPayloadForTest(t, stream, security, packet); !bytes.Equal(got, plain) {
				t.Fatalf("decoded RED payload = %x, want %x", got, plain)
			}
			clearPrefix, err := audioREDHeaderLength(plain)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(packet[12:12+clearPrefix], plain[:clearPrefix]) {
				t.Fatalf("wire RED header = %x, want clear header %x", packet[12:12+clearPrefix], plain[:clearPrefix])
			}
			retransmit := stream.audioPacketForRetransmit(3)
			if len(retransmit) < 12 || retransmit[1] != audioDataPayloadType {
				t.Fatalf("retransmit header = %x, want PT96", retransmit[:min(len(retransmit), 12)])
			}
			if got := decodeAudioPacketPayloadForTest(t, stream, security, retransmit); !bytes.Equal(got, primary) {
				t.Fatalf("retransmit primary = %x, want %x", got, primary)
			}
			request := []byte{0x80, audioRetransmitRequestPayloadType, 0, 7, 0, 3, 0, 1}
			handled, resent, err := stream.handleAudioControlPacket(request, &net.UDPAddr{})
			if err != nil || !handled || resent != 1 || len(control.packets) != 1 {
				t.Fatalf("NACK result = handled %t resent %d packets %d error %v", handled, resent, len(control.packets), err)
			}
			response := control.packets[0]
			if len(response) != 4+len(retransmit) || response[1] != audioRetransmitResponsePayloadType || !bytes.Equal(response[4:], retransmit) {
				t.Fatalf("NACK response did not wrap the stored PT96 packet: %x", response[:min(len(response), 20)])
			}
			if security == "ChaCha" {
				redNonce := binary.LittleEndian.Uint64(packet[len(packet)-audioChaChaNonceSize:])
				primaryNonce := binary.LittleEndian.Uint64(retransmit[len(retransmit)-audioChaChaNonceSize:])
				if redNonce == primaryNonce || stream.chachaNonce != 2 {
					t.Fatalf("RED/primary nonces = %d/%d with counter %d, want distinct values and counter 2", redNonce, primaryNonce, stream.chachaNonce)
				}
			}
		})
	}
}

func TestStreamAudioRedundancyPreservesCaptureGapsAndResets(t *testing.T) {
	base := time.Now()
	positions := []audioPCMFramePosition{
		{PTS: base, SourceRTP: 1000, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(352)), SourceRTP: 1352, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(704)), SourceRTP: 1704, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(5466)), SourceRTP: 6466, HasSourceRTP: true},
		{PTS: base.Add(audioSamplesDuration(5818)), SourceRTP: 6818, HasSourceRTP: true},
		// A source reset reanchors outgoing RTP to the previous frame's end.
		{PTS: base.Add(audioSamplesDuration(6170)), SourceRTP: 0, HasSourceRTP: true},
	}
	_, packets := streamAudioPacketsForTest(t, "AES", &positionedPCMFramesForTest{positions: positions}, len(positions))
	assertAudioPacketSequences(t, packets, []uint16{1, 2, 1, 3, 2, 1, 4, 3, 2, 5, 4, 3, 6, 5, 4})
	firstRTP := binary.BigEndian.Uint32(packets[0][4:8])
	wantOffsets := []uint32{0, 352, 704, 5466, 5818, 6170}
	for _, packet := range packets {
		seq := binary.BigEndian.Uint16(packet[2:4])
		offset := binary.BigEndian.Uint32(packet[4:8]) - firstRTP
		if want := wantOffsets[seq-1]; offset != want {
			t.Fatalf("sequence %d RTP offset = %d, want original source offset %d", seq, offset, want)
		}
	}
}

type positionedPCMFramesForTest struct {
	positions []audioPCMFramePosition
}

func (r *positionedPCMFramesForTest) ReadPCMFrame(dst []byte) (time.Time, error) {
	position, err := r.ReadPCMFramePosition(dst)
	return position.PTS, err
}

func (r *positionedPCMFramesForTest) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	if len(r.positions) == 0 {
		return audioPCMFramePosition{}, io.EOF
	}
	position := r.positions[0]
	r.positions = r.positions[1:]
	clear(dst)
	return position, nil
}

type steadyTimestampedPCMFramesForTest struct {
	now       func() time.Time
	remaining int
	sourceRTP uint32
	spf       uint32
	age       time.Duration
}

func (r *steadyTimestampedPCMFramesForTest) ReadPCMFrame(dst []byte) (time.Time, error) {
	position, err := r.ReadPCMFramePosition(dst)
	return position.PTS, err
}

func (r *steadyTimestampedPCMFramesForTest) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	if r.remaining == 0 {
		return audioPCMFramePosition{}, io.EOF
	}
	now := time.Now
	if r.now != nil {
		now = r.now
	}
	position := audioPCMFramePosition{
		PTS:          now().Add(-r.age).Add(audioSamplesDuration(uint64(r.sourceRTP))),
		SourceRTP:    r.sourceRTP,
		HasSourceRTP: true,
	}
	r.sourceRTP += r.spf
	r.remaining--
	clear(dst)
	return position, nil
}

func TestStreamAudioKeepsTimestampedFramesWithPositivePlayoutLead(t *testing.T) {
	const frames = 6
	// Freeze the fixture's host clock: encoding/scheduler time is unrelated to
	// this test's ten milliseconds of positive source playout lead.
	instant := time.Now()
	reader := &steadyTimestampedPCMFramesForTest{
		now:       func() time.Time { return instant },
		remaining: frames,
		spf:       352,
		age:       75 * time.Millisecond,
	}
	started := time.Now()
	_, packets := streamAudioPacketsForCodecTest(
		t, "plaintext", reader, frames, AudioCodecALAC, false,
		samplesFor44k1(85*time.Millisecond),
	)
	if elapsed := time.Since(started); elapsed < 3*audioSamplesDuration(352) {
		t.Fatalf("timestamped callback batch was sent without cadence pacing in %v", elapsed)
	}
	assertAudioPacketSequences(t, packets, []uint16{1, 2, 1, 3, 2, 1, 4, 3, 2, 5, 4, 3, 6, 5, 4})
}

func streamAudioPacketsForTest(t *testing.T, security string, frames audioPCMFrameReader, count int, rfc2198 ...bool) (*AudioStream, [][]byte) {
	return streamAudioPacketsForCodecTest(t, security, frames, count, AudioCodecALAC, len(rfc2198) > 0 && rfc2198[0])
}

func streamAudioPacketsForCodecTest(t *testing.T, security string, frames audioPCMFrameReader, count int, codec AudioCodec, rfc2198 bool, latencyOverride ...uint32) (*AudioStream, [][]byte) {
	t.Helper()
	ctrlConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctrlConn.Close() })
	ctrlPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ctrlPeer.Close() })
	dataConn := &recordingPacketConn{}
	latencySamples := uint32(audioSampleRate)
	if len(latencyOverride) > 0 {
		latencySamples = latencyOverride[0]
	}
	stream := &AudioStream{
		conn: dataConn, ctrlConn: ctrlConn, remoteAddr: &netUDPAddrForAudioTest,
		ctrlAddr: ctrlPeer.LocalAddr().(*net.UDPAddr),
		// This fixture tests packet order, independent of scheduler latency.
		ct: byte(codec), latencySamples: latencySamples, rfc2198: rfc2198,
	}
	_, codecSPF, _, _, _, _ := codec.Info()
	stream.spf = uint16(codecSPF)
	switch security {
	case "AES":
		stream.cipher, err = aes.NewCipher(bytes.Repeat([]byte{0x42}, 16))
		stream.aesIV = bytes.Repeat([]byte{0x24}, 16)
	case "ChaCha":
		stream.chachaCipher, err = newAudioChaCha64AEAD(bytes.Repeat([]byte{0x42}, 32))
		stream.chachaNonceMode = defaultAudioChaChaNonceMode()
		stream.chachaAADMode = defaultAudioChaChaAADMode()
	}
	if err != nil {
		t.Fatal(err)
	}
	pcm := make([]byte, count*int(codecSPF)*audioBytesPerSampleFrame)
	for i := range pcm {
		pcm[i] = byte(i)
	}
	capture := &AudioCapture{
		pcmPipe: io.NopCloser(bytes.NewReader(pcm)), pcmFrames: frames,
		waitCh: make(chan struct{}), codec: codec,
	}
	if codec == AudioCodecAACELD {
		capture.eld, err = newELDEncoder()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(capture.eld.Close)
	}
	firstVideo := make(chan struct{})
	close(firstVideo)
	session := &MirrorSession{firstFrameSent: firstVideo, timingProtocol: timingProtocolNTP}
	if r, ok := frames.(*steadyTimestampedPCMFramesForTest); ok && r.now != nil {
		session.frameClockNow = r.now
	}
	if err := session.StreamAudio(context.Background(), capture, stream); !errors.Is(err, io.EOF) {
		t.Fatalf("StreamAudio = %v, want EOF after %d source frames", err, count)
	}
	return stream, dataConn.packets
}

func decodeAudioPacketPayloadForTest(t *testing.T, stream *AudioStream, security string, packet []byte) []byte {
	t.Helper()
	payload := packet[12:]
	clearPrefix := 0
	if packet[1]&0x7f == audioREDPayloadType {
		var err error
		clearPrefix, err = audioREDHeaderLength(payload)
		if err != nil {
			t.Fatalf("parse clear RED header: %v", err)
		}
	}
	switch security {
	case "AES":
		plain := append([]byte(nil), payload...)
		protected := plain[clearPrefix:]
		length := len(protected) / stream.cipher.BlockSize() * stream.cipher.BlockSize()
		cipher.NewCBCDecrypter(stream.cipher, stream.aesIV).CryptBlocks(protected[:length], protected[:length])
		return plain
	case "ChaCha":
		if len(payload)-clearPrefix < audioChaChaNonceSize {
			t.Fatalf("ChaCha payload is only %d bytes", len(payload))
		}
		nonce := payload[len(payload)-audioChaChaNonceSize:]
		plain, err := stream.chachaCipher.Open(nil, nonce, payload[clearPrefix:len(payload)-audioChaChaNonceSize], packet[4:12])
		if err != nil {
			t.Fatalf("authenticate sequence %d: %v", binary.BigEndian.Uint16(packet[2:4]), err)
		}
		return append(append([]byte(nil), payload[:clearPrefix]...), plain...)
	default:
		return payload
	}
}

func assertAudioPacketSequences(t *testing.T, packets [][]byte, want []uint16) {
	t.Helper()
	got := make([]uint16, len(packets))
	for i, packet := range packets {
		got[i] = binary.BigEndian.Uint16(packet[2:4])
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("audio wire sequences = %v, want %v", got, want)
	}
}

func TestAudioCodecInfoKeepsScreenLatencyMinimumAtZero(t *testing.T) {
	_, _, _, latencyMin, latencyMax, latencySamples := AudioCodecALAC.Info()
	if latencyMin != 0 {
		t.Fatalf("latencyMin = %d, want 0", latencyMin)
	}
	if latencyMax != int64(latencySamples) {
		t.Fatalf("latencyMax = %d, want %d", latencyMax, latencySamples)
	}
}

func TestAACELDCodecInfoMatchesAirPlayCompressionType(t *testing.T) {
	ct, spf, format, latencyMin, latencyMax, latencySamples := AudioCodecAACELD.Info()
	if ct != 8 || spf != 480 || format != 0x1000000 {
		t.Fatalf("AAC-ELD info = ct=%d spf=%d format=0x%x, want ct=8 spf=480 format=0x1000000", ct, spf, format)
	}
	if latencyMin != 0 || latencyMax != int64(latencySamples) {
		t.Fatalf("AAC-ELD latency = min=%d max=%d samples=%d", latencyMin, latencyMax, latencySamples)
	}
}

func TestAudioLatencySamplesForCodec(t *testing.T) {
	defaultLatency := targetLatencySamples44k1()
	tests := []struct {
		name     string
		ct       byte
		override uint32
		want     uint32
	}{
		{name: "default ALAC", ct: byte(AudioCodecALAC), want: defaultLatency},
		{name: "AAC ELD", ct: byte(AudioCodecAACELD), want: defaultLatency},
		{name: "override wins", ct: byte(AudioCodecALAC), override: 11025, want: 11025},
		{name: "unknown codec falls back", ct: 99, want: defaultLatency},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := audioLatencySamplesForCodec(tt.ct, tt.override); got != tt.want {
				t.Fatalf("audioLatencySamplesForCodec(%d, %d) = %d, want %d", tt.ct, tt.override, got, tt.want)
			}
		})
	}
}

func TestStreamAudioJoinsOwnedWorkersOnReadFailure(t *testing.T) {
	ctrlConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	peer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		t.Fatalf("listen peer socket: %v", err)
	}
	defer peer.Close()

	firstFrame := make(chan struct{})
	close(firstFrame)
	session := &MirrorSession{
		firstFrameSent: firstFrame,
		timingProtocol: timingProtocolNTP,
	}
	stream := &AudioStream{
		ctrlConn:       ctrlConn,
		ctrlAddr:       peer.LocalAddr().(*net.UDPAddr),
		spf:            352,
		latencySamples: targetLatencySamples44k1(),
	}
	capture := &AudioCapture{
		pcmPipe: io.NopCloser(bytes.NewReader(nil)),
		waitCh:  make(chan struct{}),
		codec:   AudioCodecALAC,
	}

	done := make(chan error, 1)
	go func() { done <- session.StreamAudio(context.Background(), capture, stream) }()
	select {
	case err := <-done:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("StreamAudio error = %v, want EOF", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StreamAudio did not join its control and timing workers")
	}

	if _, err := ctrlConn.WriteTo([]byte{1}, peer.LocalAddr()); err == nil {
		t.Fatal("StreamAudio returned without closing its owned control socket")
	}
}

type gatedPCMReader struct {
	reads  chan struct{}
	frames chan []byte
	done   chan struct{}
	once   sync.Once
}

func newGatedPCMReader() *gatedPCMReader {
	return &gatedPCMReader{
		reads:  make(chan struct{}, 8),
		frames: make(chan []byte),
		done:   make(chan struct{}),
	}
}

func (r *gatedPCMReader) Read(p []byte) (int, error) {
	select {
	case r.reads <- struct{}{}:
	default:
	}
	select {
	case frame := <-r.frames:
		return copy(p, frame), nil
	case <-r.done:
		return 0, io.EOF
	}
}

func (r *gatedPCMReader) Close() error {
	r.once.Do(func() { close(r.done) })
	return nil
}

func TestStreamAudioAnchorsClockOnlyAfterFirstCapturedFrame(t *testing.T) {
	ctrlConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen control socket: %v", err)
	}
	ctrlPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		t.Fatalf("listen control peer: %v", err)
	}
	defer ctrlPeer.Close()

	dataConn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		t.Fatalf("listen data socket: %v", err)
	}
	dataPeer, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		ctrlConn.Close()
		dataConn.Close()
		t.Fatalf("listen data peer: %v", err)
	}
	defer dataPeer.Close()

	firstVideoFrame := make(chan struct{})
	session := &MirrorSession{
		firstFrameSent: firstVideoFrame,
		timingProtocol: timingProtocolNTP,
	}
	stream := &AudioStream{
		conn:            dataConn,
		ctrlConn:        ctrlConn,
		remoteAddr:      dataPeer.LocalAddr().(*net.UDPAddr),
		ctrlAddr:        ctrlPeer.LocalAddr().(*net.UDPAddr),
		spf:             352,
		ct:              byte(AudioCodecALAC),
		latencySamples:  targetLatencySamples44k1(),
		securityMode:    audioSecurityLegacyAES,
		chachaNonceMode: defaultAudioChaChaNonceMode(),
		chachaAADMode:   defaultAudioChaChaAADMode(),
	}
	pcmReader := newGatedPCMReader()
	capture := &AudioCapture{
		pcmPipe: pcmReader,
		waitCh:  make(chan struct{}),
		codec:   AudioCodecALAC,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- session.StreamAudio(ctx, capture, stream) }()
	waitForPCMRead := func(label string) {
		t.Helper()
		select {
		case <-pcmReader.reads:
		case <-time.After(time.Second):
			t.Fatalf("audio capture did not request %s PCM frame", label)
		}
	}
	const pcmFrameBytes = 352 * 2 * 2
	pcmFrame := make([]byte, pcmFrameBytes)
	waitForPCMRead("pre-roll")

	// Starting the process and observing the first video frame are not enough to
	// define an audio clock anchor. No TimeAnnounce may leave until a real sample
	// is available to associate with the initial RTP timestamp.
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2048)
	if _, _, err := ctrlPeer.ReadFrom(buf); err == nil {
		t.Fatal("initial TimeAnnounce was sent before the first captured audio frame")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read before first frame: %v", err)
	}

	pcmReader.frames <- pcmFrame
	waitForPCMRead("last pre-roll")
	close(firstVideoFrame)
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ctrlPeer.ReadFrom(buf); err == nil {
		t.Fatal("initial TimeAnnounce was sent before a post-video audio frame was ready")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read before fresh frame: %v", err)
	}

	// The prewarmer may already be blocked in one final read when video becomes
	// ready. Release that read, then withhold the next frame and verify that the
	// clock still has not been anchored.
	pcmReader.frames <- pcmFrame
	waitForPCMRead("first current")
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ctrlPeer.ReadFrom(buf); err == nil {
		t.Fatal("initial TimeAnnounce was sent while only pre-roll audio was available")
	} else if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Fatalf("read before held current frame: %v", err)
	}

	pcmReader.frames <- pcmFrame
	if err := ctrlPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := ctrlPeer.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read initial TimeAnnounce: %v", err)
	}
	if n != 20 || buf[0] != 0x90 || buf[1] != audioSyncPayloadTypeNTP {
		t.Fatalf("initial TimeAnnounce = len %d header %02x, want len 20 header 90d4", n, buf[:min(n, 2)])
	}
	if err := dataPeer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := dataPeer.ReadFrom(buf); err != nil {
		t.Fatalf("read first RTP audio packet: %v", err)
	}

	cancel()
	_ = pcmReader.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("StreamAudio error = %v, want cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("StreamAudio did not stop")
	}
}

func TestRandomRTPTime(t *testing.T) {
	got, err := randomRTPTime(bytes.NewReader([]byte{0x12, 0x34, 0x56, 0x78}))
	if err != nil {
		t.Fatal(err)
	}
	if got != 0x12345678 {
		t.Fatalf("RTP timestamp = %#x, want 0x12345678", got)
	}
}

func TestSendSyncPacketUsesNTPFormatWithoutTimeline(t *testing.T) {
	const (
		networkTime = uint64(0x83aa7e8012345678)
		rtpTime     = uint32(5000)
	)
	packet := captureAudioSyncPacket(t, &AudioStream{
		rtpTime:        rtpTime,
		latencySamples: 1000,
	}, timingProtocolNTP, networkTime, 0, true)

	if len(packet) != 20 {
		t.Fatalf("NTP sync packet length = %d, want 20", len(packet))
	}
	if packet[0] != 0x90 || packet[1] != audioSyncPayloadTypeNTP {
		t.Fatalf("NTP sync header = %02x%02x, want 90d4", packet[0], packet[1])
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != 4000 {
		t.Fatalf("NTP playback RTP = %d, want 4000", got)
	}
	if got := binary.BigEndian.Uint64(packet[8:16]); got != networkTime {
		t.Fatalf("NTP timestamp = 0x%016x, want 0x%016x", got, networkTime)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != rtpTime {
		t.Fatalf("NTP next RTP = %d, want %d", got, rtpTime)
	}
}

func TestSendSyncPacketUsesNegotiatedProtocolInsteadOfTimelinePresence(t *testing.T) {
	packet := captureAudioSyncPacket(t, &AudioStream{}, timingProtocolNTP, 1, 0x1122334455667788, false)
	if len(packet) != 20 || packet[1] != audioSyncPayloadTypeNTP {
		t.Fatalf("explicit NTP sync packet = len %d type 0x%02x, want len 20 type 0x%02x",
			len(packet), packet[1], audioSyncPayloadTypeNTP)
	}

	stream := &AudioStream{ctrlConn: &recordingPacketConn{}, ctrlAddr: &net.UDPAddr{}}
	if err := stream.sendSyncPacket(timingProtocolPTP, 1, 0, false); err == nil {
		t.Fatal("PTP sync succeeded without a receiver timeline ID")
	}
}

func TestSendSyncPacketUsesPTPTimeAnnounceWithTimeline(t *testing.T) {
	const (
		networkTime = uint64(0x0000000180000000) // 1.5 seconds in seconds.32
		timelineID  = uint64(0x48e15caa8da00008)
		rtpTime     = uint32(5000)
	)
	packet := captureAudioSyncPacket(t, &AudioStream{
		rtpTime:        rtpTime,
		latencySamples: 1000,
	}, timingProtocolPTP, networkTime, timelineID, false)

	if len(packet) != 28 {
		t.Fatalf("PTP sync packet length = %d, want 28", len(packet))
	}
	if packet[0] != 0x80 || packet[1] != audioSyncPayloadTypePTP {
		t.Fatalf("PTP sync header = %02x%02x, want 80d7", packet[0], packet[1])
	}
	if got := binary.BigEndian.Uint32(packet[4:8]); got != 4000 {
		t.Fatalf("PTP network-time RTP = %d, want 4000", got)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != 4000 {
		t.Fatalf("PTP apply RTP = %d, want 4000", got)
	}
	if got := binary.BigEndian.Uint64(packet[8:16]); got != 1500000000 {
		t.Fatalf("PTP timestamp = %d ns, want 1500000000", got)
	}
	if got := binary.BigEndian.Uint64(packet[20:28]); got != timelineID {
		t.Fatalf("PTP timeline = 0x%016x, want 0x%016x", got, timelineID)
	}
}

func TestSendSyncPacketWrapsLatencyAdjustedRTP(t *testing.T) {
	rtpTime := uint32(1000)
	latency := uint32(4410)
	packet := captureAudioSyncPacket(t, &AudioStream{
		rtpTime:        rtpTime,
		latencySamples: latency,
	}, timingProtocolPTP, 1, 2, true)

	want := rtpTime - latency
	if got := binary.BigEndian.Uint32(packet[4:8]); got != want {
		t.Fatalf("wrapped network-time RTP = %#x, want %#x", got, want)
	}
	if got := binary.BigEndian.Uint32(packet[16:20]); got != want {
		t.Fatalf("wrapped apply RTP = %#x, want %#x", got, want)
	}
}

func captureAudioSyncPacket(t *testing.T, stream *AudioStream, timingProtocol string, networkTime, timelineID uint64, isFirst bool) []byte {
	t.Helper()
	conn := &recordingPacketConn{}
	stream.ctrlConn = conn
	stream.ctrlAddr = &net.UDPAddr{}
	if err := stream.sendSyncPacket(timingProtocol, networkTime, timelineID, isFirst); err != nil {
		t.Fatal(err)
	}
	if len(conn.packets) != 1 {
		t.Fatalf("sent %d sync packets, want 1", len(conn.packets))
	}
	return conn.packets[0]
}

func TestAudioChaCha64AEADRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x11}, audioChaChaNonceSize)
	aad := []byte{0x90, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab}
	plaintext := []byte("doubletake mirrored audio")

	aead, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil {
		t.Fatalf("Open returned error: %v", err)
	}
	if !bytes.Equal(opened, plaintext) {
		t.Fatalf("opened plaintext = %x, want %x", opened, plaintext)
	}
	if len(sealed) != len(plaintext)+aead.Overhead() {
		t.Fatalf("sealed len = %d, want %d", len(sealed), len(plaintext)+aead.Overhead())
	}
}

func TestAudioChaCha64AEADRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x7b}, audioChaChaNonceSize)
	aad := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	plaintext := []byte("auth must fail when the packet changes")

	aead, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}

	sealed := aead.Seal(nil, nonce, plaintext, aad)
	sealed[len(sealed)-1] ^= 0x80
	if _, err := aead.Open(nil, nonce, sealed, aad); err == nil {
		t.Fatal("expected tampered packet to fail authentication")
	}
}

func TestAudioChaCha64AEADEquivalentToZeroPrefixedIETF(t *testing.T) {
	key := bytes.Repeat([]byte{0x35}, chacha20poly1305.KeySize)
	nonce := bytes.Repeat([]byte{0x12}, audioChaChaNonceSize)
	aad := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11}
	plaintext := []byte("original 64-bit nonce variant")

	custom, err := newAudioChaCha64AEAD(key)
	if err != nil {
		t.Fatalf("newAudioChaCha64AEAD returned error: %v", err)
	}
	customSealed := custom.Seal(nil, nonce, plaintext, aad)

	ietf, err := chacha20poly1305.New(key)
	if err != nil {
		t.Fatalf("chacha20poly1305.New returned error: %v", err)
	}
	ietfNonce := make([]byte, chacha20poly1305.NonceSize)
	copy(ietfNonce[4:], nonce)
	ietfSealed := ietf.Seal(nil, ietfNonce, plaintext, aad)

	if !bytes.Equal(customSealed, ietfSealed) {
		t.Fatal("expected the 64-bit nonce construction to match the zero-prefixed IETF form while the counter stays within 32 bits")
	}
}

func TestAudioChaChaAADUsesRTPNetworkOrder(t *testing.T) {
	as := &AudioStream{
		ssrc:          0x11223344,
		chachaAADMode: audioChaChaAADTimestampSSRC,
	}
	header := []byte{0x80, 0x60, 0x00, 0x01, 0x12, 0x34, 0x56, 0x78, 0x11, 0x22, 0x33, 0x44}

	aad := as.audioChaChaAAD(header, 0x12345678)
	want := []byte{0x12, 0x34, 0x56, 0x78, 0x11, 0x22, 0x33, 0x44}
	if !bytes.Equal(aad, want) {
		t.Fatalf("AAD = %x, want %x", aad, want)
	}
}

func TestParseAudioRetransmitRequest(t *testing.T) {
	packet := []byte{0x80, 0xd5, 0x12, 0x34, 0xff, 0xfe, 0x00, 0x02}
	request, ok := parseAudioRetransmitRequest(packet)
	if !ok {
		t.Fatal("valid audio retransmit request was rejected")
	}
	if request.requestSeq != 0x1234 || request.firstSeq != 0xfffe || request.count != 2 {
		t.Fatalf("request = %#v, want id 0x1234, first 0xfffe, count 2", request)
	}

	for _, test := range []struct {
		name   string
		packet []byte
	}{
		{name: "short", packet: packet[:7]},
		{name: "long", packet: append(append([]byte(nil), packet...), 0)},
		{name: "wrong version", packet: []byte{0x40, 0xd5, 0, 1, 0, 2, 0, 1}},
		{name: "wrong payload type", packet: []byte{0x80, 0xd4, 0, 1, 0, 2, 0, 1}},
		{name: "zero count", packet: []byte{0x80, 0xd5, 0, 1, 0, 2, 0, 0}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, ok := parseAudioRetransmitRequest(test.packet); ok {
				t.Fatalf("malformed request %x was accepted", test.packet)
			}
		})
	}
}

func TestAudioRetransmitReturnsExactChaChaDatagramOnControlSocket(t *testing.T) {
	aead, err := newAudioChaCha64AEAD(bytes.Repeat([]byte{0x5a}, chacha20poly1305.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	dataConn := &recordingPacketConn{}
	ctrlConn := &recordingPacketConn{}
	stream := &AudioStream{
		conn:            dataConn,
		ctrlConn:        ctrlConn,
		remoteAddr:      &netUDPAddrForAudioTest,
		chachaCipher:    aead,
		chachaNonceMode: audioChaChaNonceCounter,
		chachaAADMode:   audioChaChaAADTimestampSSRC,
	}
	const (
		sequence = uint16(0xfffe)
		rtpTime  = uint32(0x12345678)
	)
	if err := stream.sendAudioPacketWithSeq([]byte("recover this encrypted audio frame"), rtpTime, sequence); err != nil {
		t.Fatal(err)
	}
	if len(dataConn.packets) != 1 {
		t.Fatalf("sent %d original packets, want 1", len(dataConn.packets))
	}
	original := append([]byte(nil), dataConn.packets[0]...)

	request := []byte{0x80, 0xd5, 0x00, 0x2a, 0xff, 0xfe, 0x00, 0x01}
	requester := &net.UDPAddr{IP: net.ParseIP("192.0.2.25"), Port: 7001}
	handled, resent, err := stream.handleAudioControlPacket(request, requester)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || resent != 1 {
		t.Fatalf("handled=%t resent=%d, want true, 1", handled, resent)
	}
	if len(ctrlConn.packets) != 1 {
		t.Fatalf("sent %d control responses, want 1", len(ctrlConn.packets))
	}
	want := append([]byte{0x80, 0xd6, 0x00, 0x2a}, original...)
	if !bytes.Equal(ctrlConn.packets[0], want) {
		t.Fatalf("retransmit response = %x, want exact wrapped datagram %x", ctrlConn.packets[0], want)
	}
	if ctrlConn.addrs[0] != requester {
		t.Fatalf("retransmit destination = %v, want request source %v", ctrlConn.addrs[0], requester)
	}
	if !bytes.Equal(dataConn.packets[0], original) {
		t.Fatal("serving the retransmit mutated the original encrypted datagram")
	}
}

func TestAudioRetransmitUsesFutileResponseForExpiredPacket(t *testing.T) {
	ctrlConn := &recordingPacketConn{}
	stream := &AudioStream{ctrlConn: ctrlConn}
	request := []byte{0x80, 0xd5, 0x00, 0x07, 0x45, 0x67, 0x00, 0x03}
	handled, resent, err := stream.handleAudioControlPacket(request, &netUDPAddrForAudioTest)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || resent != 0 {
		t.Fatalf("handled=%t resent=%d, want true, 0", handled, resent)
	}
	want := []byte{0x80, 0xd6, 0x00, 0x07, 0x45, 0x67, 0x00, 0x00}
	if len(ctrlConn.packets) != 1 || !bytes.Equal(ctrlConn.packets[0], want) {
		t.Fatalf("futile response = %x, want %x", ctrlConn.packets, want)
	}
}

func TestAudioRetransmitRangeWrapsAndStopsAtFirstExpiredPacket(t *testing.T) {
	ctrlConn := &recordingPacketConn{}
	stream := &AudioStream{ctrlConn: ctrlConn}
	stream.rememberAudioPacket(0xffff, []byte{0x80, 0x60, 0xff, 0xff, 0xaa})
	request := []byte{0x80, 0xd5, 0x00, 0x01, 0xff, 0xff, 0x00, 0x02}
	handled, resent, err := stream.handleAudioControlPacket(request, &netUDPAddrForAudioTest)
	if err != nil {
		t.Fatal(err)
	}
	if !handled || resent != 1 {
		t.Fatalf("handled=%t resent=%d, want true, 1", handled, resent)
	}
	wantPackets := [][]byte{
		{0x80, 0xd6, 0x00, 0x01, 0x80, 0x60, 0xff, 0xff, 0xaa},
		{0x80, 0xd6, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00},
	}
	if len(ctrlConn.packets) != len(wantPackets) {
		t.Fatalf("sent %d responses, want %d", len(ctrlConn.packets), len(wantPackets))
	}
	for index, want := range wantPackets {
		if !bytes.Equal(ctrlConn.packets[index], want) {
			t.Fatalf("response %d = %x, want %x", index, ctrlConn.packets[index], want)
		}
	}
}

func TestAudioRetransmitHistoryIsBoundedAndSequenceAware(t *testing.T) {
	stream := &AudioStream{}
	const oldSequence = uint16(17)
	newSequence := oldSequence + audioRetransmitHistoryPackets
	stream.rememberAudioPacket(oldSequence, []byte("old"))
	stream.rememberAudioPacket(newSequence, []byte("new"))

	if packet := stream.audioPacketForRetransmit(oldSequence); packet != nil {
		t.Fatalf("evicted sequence returned %q", packet)
	}
	if packet := stream.audioPacketForRetransmit(newSequence); !bytes.Equal(packet, []byte("new")) {
		t.Fatalf("new sequence returned %q, want new", packet)
	}
}

func TestAudioRetransmitHistoryConcurrentReplacement(t *testing.T) {
	stream := &AudioStream{}
	const firstSequence = uint16(29)
	secondSequence := firstSequence + audioRetransmitHistoryPackets
	sequences := [...]uint16{firstSequence, secondSequence}
	start := make(chan struct{})
	errCh := make(chan string, 1)
	report := func(message string) {
		select {
		case errCh <- message:
		default:
		}
	}

	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		<-start
		for index := 0; index < 2000; index++ {
			seq := sequences[index%len(sequences)]
			packet := make([]byte, 2)
			binary.BigEndian.PutUint16(packet, seq)
			stream.rememberAudioPacket(seq, packet)
		}
	}()
	for reader := 0; reader < 4; reader++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			for index := 0; index < 2000; index++ {
				seq := sequences[index%len(sequences)]
				packet := stream.audioPacketForRetransmit(seq)
				if packet != nil && (len(packet) != 2 || binary.BigEndian.Uint16(packet) != seq) {
					report(fmt.Sprintf("sequence %d returned mismatched packet %x", seq, packet))
					return
				}
			}
		}()
	}
	close(start)
	workers.Wait()
	select {
	case message := <-errCh:
		t.Fatal(message)
	default:
	}
}

func TestAudioControlPeerUsesNegotiatedReceiverIP(t *testing.T) {
	stream := &AudioStream{ctrlAddr: &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 7000}}
	if !stream.audioControlPacketFromReceiver(&net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9000}) {
		t.Fatal("matching receiver IP was rejected because its source port differed")
	}
	if stream.audioControlPacketFromReceiver(&net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 7000}) {
		t.Fatal("unexpected control peer IP was accepted")
	}
}

func TestAudioSendBurstLimiterOnlyDelaysCatchupBurst(t *testing.T) {
	base := time.Unix(1787616000, 0)
	var limiter audioSendBurstLimiter
	for packet := 0; packet < maximumAudioPacketsPerBurst; packet++ {
		if delay := limiter.reserveDelay(base); delay != 0 {
			t.Fatalf("packet %d delay = %v, want 0", packet+1, delay)
		}
	}
	if delay := limiter.reserveDelay(base); delay != audioSendBurstWindow {
		t.Fatalf("first excess packet delay = %v, want %v", delay, audioSendBurstWindow)
	}
	if delay := limiter.reserveDelay(base.Add(2 * time.Millisecond)); delay != 3*time.Millisecond {
		t.Fatalf("partway through window delay = %v, want 3ms", delay)
	}
	if delay := limiter.reserveDelay(base.Add(audioSendBurstWindow)); delay != 0 {
		t.Fatalf("packet at next window delay = %v, want 0", delay)
	}

	// Ordinary codec frames arrive about 8ms (ALAC) or 11ms (AAC-ELD) apart,
	// outside the limiter window, and must never accumulate artificial delay.
	limiter = audioSendBurstLimiter{}
	for frame := 0; frame < 100; frame++ {
		now := base.Add(time.Duration(frame) * 8 * time.Millisecond)
		if delay := limiter.reserveDelay(now); delay != 0 {
			t.Fatalf("normally paced frame %d delay = %v, want 0", frame, delay)
		}
	}
}

func TestAudioFramePacerSmoothsCaptureBlocksAtRTPCadence(t *testing.T) {
	base := time.Unix(1787616000, 0)
	const (
		firstRTP = uint32(1000)
		spf      = uint32(352)
	)
	frameDuration := audioSamplesDuration(uint64(spf))
	arrivals := make([]time.Duration, 18)
	for frame := range arrivals {
		// Model six codec frames released by one PipeWire callback every 48 ms.
		arrivals[frame] = time.Duration(frame/6) * 6 * frameDuration
	}
	pacer := audioFramePacer{bufferFrames: maximumAudioPacingFrames}
	lastSend := base
	for frame, arrival := range arrivals {
		now := base.Add(arrival)
		if now.Before(lastSend) {
			now = lastSend
		}
		delay := pacer.reserveDelay(now, firstRTP+uint32(frame)*spf, spf, time.Time{})
		sentAt := now.Add(delay)
		want := base.Add(audioSamplesDuration(uint64(spf) * maximumAudioPacingFrames)).
			Add(audioSamplesDuration(uint64(frame) * uint64(spf)))
		if !sentAt.Equal(want) {
			t.Fatalf("frame %d sent at %v, want %v (delay %v)", frame, sentAt.Sub(base), want.Sub(base), delay)
		}
		lastSend = sentAt
	}
}

func TestAudioFramePacerHandlesRTPWrap(t *testing.T) {
	base := time.Unix(1787616000, 0)
	const spf = uint32(352)
	firstRTP := ^uint32(0) - 100
	frameDuration := audioSamplesDuration(uint64(spf))
	pacer := audioFramePacer{bufferFrames: maximumAudioPacingFrames}
	wantDelay := audioSamplesDuration(uint64(spf) * maximumAudioPacingFrames)
	if delay := pacer.reserveDelay(base, firstRTP, spf, time.Time{}); delay != wantDelay {
		t.Fatalf("first frame delay = %v, want %v", delay, wantDelay)
	}
	if delay := pacer.reserveDelay(base.Add(frameDuration), firstRTP+spf, spf, time.Time{}); delay != wantDelay {
		t.Fatalf("wrapped frame delay = %v, want %v", delay, wantDelay)
	}
}

func TestAudioFramePacerReturnsToSourceCadenceAfterLateRelease(t *testing.T) {
	base := time.Unix(1787616000, 0)
	const (
		firstRTP = uint32(1000)
		spf      = uint32(352)
	)
	frameDuration := audioSamplesDuration(uint64(spf))
	pacer := audioFramePacer{bufferFrames: maximumAudioPacingFrames}
	firstDelay := pacer.reserveDelay(base, firstRTP, spf, time.Time{})
	firstTarget := base.Add(firstDelay)

	lateRelease := firstTarget.Add(5 * time.Millisecond)
	want := frameDuration - 5*time.Millisecond
	if delay := pacer.reserveDelay(lateRelease, firstRTP+spf, spf, time.Time{}); delay != want {
		t.Fatalf("post-stall delay = %v, want %v to recover the source cadence", delay, want)
	}
}

func TestAudioFramePacerPreservesDeliveryLead(t *testing.T) {
	base := time.Unix(1787616000, 0)
	const spf = uint32(352)
	pacer := audioFramePacer{bufferFrames: maximumAudioPacingFrames}
	deadline := base.Add(3 * time.Millisecond)
	if delay := pacer.reserveDelay(base, 1000, spf, deadline); delay != 3*time.Millisecond {
		t.Fatalf("deadline-limited pacing delay = %v, want 3ms", delay)
	}
}

func TestAudioPacingFramesRespectLatencyBudget(t *testing.T) {
	for _, test := range []struct {
		name    string
		latency time.Duration
		spf     uint32
		want    uint32
	}{
		{name: "high ALAC", latency: defaultAudioLatencyHigh, spf: 352, want: 4},
		{name: "normal ALAC", latency: defaultAudioLatencyNormal, spf: 352, want: 4},
		{name: "low ALAC", latency: defaultAudioLatencyLow, spf: 352, want: 0},
		{name: "normal AAC-ELD", latency: defaultAudioLatencyNormal, spf: 480, want: 3},
		{name: "minimum override", latency: 5 * time.Millisecond, spf: 352, want: 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			latencySamples := samplesFor44k1(test.latency)
			if got := audioPacingFramesForLatency(latencySamples, test.spf); got != test.want {
				t.Fatalf("pacing frames = %d, want %d", got, test.want)
			}
		})
	}
}
