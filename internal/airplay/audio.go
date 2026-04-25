package airplay

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	aeadchacha20poly1305 "github.com/aead/chacha20poly1305"
)

// AudioCodec identifies the codec used for audio streaming.
type AudioCodec int

type audioSecurityMode int
type audioChaChaNonceMode int
type audioChaChaAADMode int

const (
	AudioCodecALAC AudioCodec = 2 // ct=2, spf=352, audioFormat=0x40000

	audioSecurityLegacyAES audioSecurityMode = iota
	audioSecurityChaCha

	audioChaChaNonceCounter audioChaChaNonceMode = iota
	audioChaChaNonceSeq
	audioChaChaNonceSeqZeroBased
	audioChaChaNonceRTP

	audioChaChaAADNone audioChaChaAADMode = iota
	audioChaChaAADRTPHeader
	audioChaChaAADTimestampSSRC

	audioChaChaNonceSize = 8
)

func newAudioChaCha64AEAD(key []byte) (cipher.AEAD, error) {
	return aeadchacha20poly1305.NewCipher(key)
}

func useAudioFEC(modernEncrypted bool) bool {
	return !modernEncrypted
}

func defaultAudioChaChaNonceMode() audioChaChaNonceMode {
	return audioChaChaNonceCounter
}

func defaultAudioChaChaAADMode() audioChaChaAADMode {
	return audioChaChaAADTimestampSSRC
}

func (c AudioCodec) AudioFormatIndex() int64 {
	return 0x12
}

// AudioCodecInfo returns SETUP parameters for the supported mirrored-audio codec.
func (c AudioCodec) Info() (ct int64, spf int64, audioFormat int64, latencyMin int64, latencyMax int64, latencySamples uint32) {
	latency := targetLatencySamples44k1()
	latencyI64 := int64(latency)
	return 2, 352, 0x40000, latencyI64, latencyI64, latency
}

func audioLatencySamplesForCodec(ct byte, override uint32) uint32 {
	if override > 0 {
		return override
	}
	_ = ct
	return targetLatencySamples44k1()
}

// AudioCapture manages audio capture via GStreamer and local ALAC encoding.
type AudioCapture struct {
	gstCmd  *exec.Cmd
	pcmPipe io.ReadCloser
	cancel  context.CancelFunc
	waitCh  chan struct{}
	waitErr error
	stopped bool
}

// StartAudioCapture launches a pipeline that captures system audio (monitor source)
// and feeds raw PCM into the built-in ALAC encoder.
func StartAudioCapture(ctx context.Context, testTone bool) (*AudioCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

	// Detect audio source
	var srcArgs []string
	if testTone {
		srcArgs = []string{"audiotestsrc", "wave=sine", "freq=440", "is-live=true",
			"samplesperbuffer=352"}
		dbg("[AUDIO] using test tone (440 Hz sine wave, live, spf=352)")
	} else if exec.Command("gst-inspect-1.0", "pulsesrc").Run() == nil {
		monitor := detectPulseMonitor()
		if monitor == "" {
			cancel()
			return nil, fmt.Errorf("no PulseAudio monitor source found")
		}
		srcArgs = []string{"pulsesrc", fmt.Sprintf("device=%s", monitor)}
		dbg("[AUDIO] using pulsesrc device=%s", monitor)
	} else if exec.Command("gst-inspect-1.0", "pipewiresrc").Run() == nil {
		srcArgs = []string{"pipewiresrc"}
		dbg("[AUDIO] using pipewiresrc")
	} else {
		cancel()
		return nil, fmt.Errorf("no audio source available (need pulsesrc or pipewiresrc)")
	}

	ac := &AudioCapture{
		cancel: cancel,
		waitCh: make(chan struct{}),
	}

	gstArgs := []string{"--quiet"}
	gstArgs = append(gstArgs, srcArgs...)
	gstArgs = append(gstArgs,
		"!", "audioconvert",
		"!", "audioresample",
		"!", "audio/x-raw,rate=44100,channels=2,format=S16LE",
		"!", "queue", "max-size-buffers=2", "max-size-bytes=0", "max-size-time=0", "leaky=downstream",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	)
	dbg("[AUDIO] ALAC verbatim pipeline: gst-launch-1.0 %s", strings.Join(gstArgs, " "))

	gstCmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)
	gstStdout, err := gstCmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	gstStderr, _ := gstCmd.StderrPipe()

	if err := gstCmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start ALAC gst pipeline: %w", err)
	}
	go logStderr("AUDIO-GST", gstStderr)

	ac.gstCmd = gstCmd
	ac.pcmPipe = gstStdout
	go func() {
		ac.waitErr = gstCmd.Wait()
		close(ac.waitCh)
	}()

	return ac, nil
}

// ReadFrame reads a single ALAC-encoded audio frame.
func (ac *AudioCapture) ReadFrame(buf []byte) (int, error) {
	select {
	case <-ac.waitCh:
		if ac.waitErr != nil {
			return 0, fmt.Errorf("audio capture exited: %w", ac.waitErr)
		}
		return 0, io.EOF
	default:
	}

	const spf = 352
	const channels = 2
	const bytesPerSample = 2
	pcmSize := spf * channels * bytesPerSample // 1408 bytes
	pcm := make([]byte, pcmSize)
	if _, err := io.ReadFull(ac.pcmPipe, pcm); err != nil {
		return 0, err
	}
	n := encodeALACVerbatim(buf, pcm, spf, channels, 16)
	return n, nil
}

func (ac *AudioCapture) Stop() {
	if ac.stopped {
		return
	}
	ac.stopped = true
	if ac.cancel != nil {
		ac.cancel()
	}
	if ac.pcmPipe != nil {
		ac.pcmPipe.Close()
	}
	if ac.gstCmd != nil && ac.gstCmd.Process != nil {
		ac.gstCmd.Process.Kill()
	}
	select {
	case <-ac.waitCh:
	case <-time.After(2 * time.Second):
		if ac.gstCmd != nil && ac.gstCmd.Process != nil {
			ac.gstCmd.Process.Kill()
		}
		<-ac.waitCh
	}
}

// encodeALACVerbatim produces a verbatim (uncompressed) ALAC frame from
// interleaved S16LE PCM data. This is the simplest ALAC encoding mode —
// the frame contains raw samples with a minimal bit-level header.
//
// ALAC verbatim frame format (stereo, 16-bit):
//
//	tag(3)            = 1 (TYPE_CPE for stereo)
//	elementInstance(4)= 0
//	unused(12)        = 0
//	hasSize(1)        = 1 (include 32-bit sample count)
//	extraBytes(2)     = 0 (16-bit, no shift)
//	verbatim(1)       = 1
//	numSamples(32)    = frameSize
//	for each sample:
//	    left(16)      = big-endian signed 16-bit
//	    right(16)     = big-endian signed 16-bit
//	endTag(3)         = 7 (TYPE_END)
func encodeALACVerbatim(out, pcm []byte, frameSize, channels, bitDepth int) int {
	// Bit-level writer using a byte buffer
	var bw bitWriter
	bw.init(out)

	// Element header
	if channels == 2 {
		bw.write(1, 3) // TYPE_CPE (channel pair element)
	} else {
		bw.write(0, 3) // TYPE_SCE (single channel element)
	}
	bw.write(0, 4)  // elementInstanceTag
	bw.write(0, 12) // unused

	bw.write(1, 1) // hasSize = 1
	bw.write(0, 2) // extraBytes = 0 (16-bit)
	bw.write(1, 1) // verbatim = 1

	bw.write(uint32(frameSize), 32) // numSamples

	// Write raw samples: S16LE PCM → big-endian 16-bit
	for i := 0; i < frameSize*channels; i++ {
		off := i * 2
		// Read S16LE sample
		sample := uint16(pcm[off]) | uint16(pcm[off+1])<<8
		bw.write(uint32(sample), uint32(bitDepth))
	}

	// End tag
	bw.write(7, 3) // TYPE_END

	return bw.flush()
}

// bitWriter writes bits MSB-first into a byte buffer.
type bitWriter struct {
	buf    []byte
	pos    int    // byte position
	bitBuf uint32 // accumulated bits
	bitPos int    // number of bits in bitBuf (0-32)
}

func (w *bitWriter) init(buf []byte) {
	w.buf = buf
	w.pos = 0
	w.bitBuf = 0
	w.bitPos = 0
}

func (w *bitWriter) write(val uint32, nbits uint32) {
	// Write nbits (MSB first) from val
	for nbits > 0 {
		space := uint32(8 - w.bitPos)
		if nbits <= space {
			w.bitBuf |= (val & ((1 << nbits) - 1)) << (space - nbits)
			w.bitPos += int(nbits)
			if w.bitPos == 8 {
				w.buf[w.pos] = byte(w.bitBuf)
				w.pos++
				w.bitBuf = 0
				w.bitPos = 0
			}
			return
		}
		// Fill remaining space in current byte
		shift := nbits - space
		w.bitBuf |= (val >> shift) & ((1 << space) - 1)
		w.buf[w.pos] = byte(w.bitBuf)
		w.pos++
		w.bitBuf = 0
		w.bitPos = 0
		nbits = shift
		val &= (1 << shift) - 1
	}
}

func (w *bitWriter) flush() int {
	if w.bitPos > 0 {
		w.buf[w.pos] = byte(w.bitBuf)
		w.pos++
	}
	return w.pos
}

// detectPulseMonitor finds the default PulseAudio sink's monitor source name.
func detectPulseMonitor() string {
	out, err := exec.Command("pactl", "get-default-sink").Output()
	if err != nil {
		dbg("[AUDIO] pactl get-default-sink failed: %v", err)
		return ""
	}
	sinkName := strings.TrimSpace(string(out))
	if sinkName == "" {
		return ""
	}
	return sinkName + ".monitor"
}

// AudioStream manages the RTP audio channel to the AirPlay receiver.
type AudioStream struct {
	conn            net.PacketConn // local UDP socket for sending audio
	ctrlConn        net.PacketConn // control port for sync/resend
	remoteAddr      *net.UDPAddr   // receiver's audio data address
	ctrlAddr        *net.UDPAddr   // receiver's audio control address
	rtpTime         uint32
	ssrc            uint32
	cipher          cipher.Block // AES-128 for audio encryption (nil = no encryption)
	aesIV           []byte       // 16-byte IV for AES-CBC
	chachaCipher    cipher.AEAD  // ChaCha20-Poly1305 for modern Apple receivers
	securityMode    audioSecurityMode
	chachaNonce     uint64
	chachaNonceMode audioChaChaNonceMode
	chachaAADMode   audioChaChaAADMode
	ct              byte   // compression type: 2=ALAC
	spf             uint16 // samples per frame
	latencySamples  uint32 // audio latency in samples (for sync packets)
	mu              sync.Mutex
}

// setupAudioStream creates the audio RTP stream state.
// Real AirPlay senders use TWO separate UDP sockets for audio:
//   - ctrlConn: the declared controlPort socket → sends sync/control to receiver's controlPort
//   - dataConn: a separate socket at controlPort+1 → sends audio data to receiver's dataPort
//
// Both pcaps show senders allocate 3 consecutive ports: timing(N), control(N+1), data(N+2).
// The Apple TV classifies incoming traffic by source port.
func (s *MirrorSession) setupAudioStream(dataPort, controlPort int, aesKey, aesIV, chachaKey []byte, securityMode audioSecurityMode, ct byte, latencyOverride uint32, ctrlConn, dataConn net.PacketConn) (*AudioStream, error) {
	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.client.host, fmt.Sprintf("%d", dataPort)))
	if err != nil {
		return nil, fmt.Errorf("resolve audio remote: %w", err)
	}

	ctrlAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.client.host, fmt.Sprintf("%d", controlPort)))
	if err != nil {
		return nil, fmt.Errorf("resolve audio control remote: %w", err)
	}

	dataLocalPort := dataConn.LocalAddr().(*net.UDPAddr).Port
	ctrlLocalPort := ctrlConn.LocalAddr().(*net.UDPAddr).Port

	var block cipher.Block
	if len(aesKey) == 16 {
		block, err = aes.NewCipher(aesKey)
		if err != nil {
			dataConn.Close()
			return nil, fmt.Errorf("aes cipher: %w", err)
		}
	}

	var aead cipher.AEAD
	if securityMode == audioSecurityChaCha {
		aead, err = newAudioChaCha64AEAD(chachaKey)
		if err != nil {
			dataConn.Close()
			return nil, fmt.Errorf("audio chacha cipher: %w", err)
		}
	}

	spf := uint16(352)
	latencySamples := audioLatencySamplesForCodec(ct, latencyOverride)

	// Apple senders use SSRC=0 for mirroring audio RTP.

	as := &AudioStream{
		conn:            dataConn, // separate socket for audio data
		ctrlConn:        ctrlConn, // declared control port for sync
		remoteAddr:      remoteAddr,
		ctrlAddr:        ctrlAddr,
		rtpTime:         0,
		ssrc:            0,
		cipher:          block,
		aesIV:           aesIV,
		chachaCipher:    aead,
		securityMode:    securityMode,
		chachaNonceMode: defaultAudioChaChaNonceMode(),
		chachaAADMode:   defaultAudioChaChaAADMode(),
		ct:              ct,
		spf:             spf,
		latencySamples:  latencySamples,
	}

	securityName := "none"
	switch {
	case aead != nil:
		securityName = "chacha20-poly1305-64x64"
	case block != nil:
		securityName = "aes-128-cbc"
	}

	dbg("[AUDIO] stream setup: dataPort=%d controlPort=%d ct=%d spf=%d ssrc=0x%08x security=%s",
		dataPort, controlPort, ct, spf, as.ssrc, securityName)
	if aead != nil {
		dbg("[AUDIO] chacha config: nonce=%s aad=%s",
			as.chachaNonceMode.String(), as.chachaAADMode.String())
	}
	if latencyOverride > 0 {
		dbg("[AUDIO] receiver audio latency override: %d samples", latencySamples)
	}
	dbg("[AUDIO] local ports: data=%d (→remote %d) ctrl=%d (→remote %d)",
		dataLocalPort, dataPort, ctrlLocalPort, controlPort)

	return as, nil
}

func (m audioChaChaNonceMode) String() string {
	switch m {
	case audioChaChaNonceSeq:
		return "seq"
	case audioChaChaNonceSeqZeroBased:
		return "seq0"
	case audioChaChaNonceRTP:
		return "rtp"
	default:
		return "counter"
	}
}

func (m audioChaChaAADMode) String() string {
	switch m {
	case audioChaChaAADRTPHeader:
		return "rtp-header"
	case audioChaChaAADTimestampSSRC:
		return "timestamp-ssrc"
	default:
		return "none"
	}
}

func (as *AudioStream) nextAudioChaChaNonce(seq uint16, rtpTime uint32, reuse *uint64) (uint64, [audioChaChaNonceSize]byte) {
	var value uint64
	if reuse != nil {
		value = *reuse
	} else {
		switch as.chachaNonceMode {
		case audioChaChaNonceSeq:
			value = uint64(seq)
		case audioChaChaNonceSeqZeroBased:
			if seq > 0 {
				value = uint64(seq - 1)
			}
		case audioChaChaNonceRTP:
			value = uint64(rtpTime)
		default:
			value = as.chachaNonce
			as.chachaNonce++
		}
	}
	var nonce [audioChaChaNonceSize]byte
	binary.LittleEndian.PutUint64(nonce[:], value)
	return value, nonce
}

func (as *AudioStream) audioChaChaAAD(header []byte, rtpTime uint32) []byte {
	switch as.chachaAADMode {
	case audioChaChaAADRTPHeader:
		return header
	case audioChaChaAADTimestampSSRC:
		// The receiver reconstructs the AAD from the RTP timestamp and SSRC bytes
		// in network order, so use the on-wire header bytes directly.
		aad := make([]byte, 8)
		copy(aad, header[4:12])
		return aad
	default:
		return nil
	}
}

// sendAudioPacketWithSeq sends a single RTP audio packet with explicit seq and RTP timestamp.
// The caller manages sequence numbers (frame-based, not packet-based).
// payload is the raw encoded frame data.
func (as *AudioStream) sendAudioPacketWithSeq(payload []byte, rtpTime uint32, seq uint16) error {
	_, err := as.sendAudioPacketWithSeqAndNonce(payload, rtpTime, seq, nil)
	return err
}

func (as *AudioStream) sendAudioPacketWithSeqAndNonce(payload []byte, rtpTime uint32, seq uint16, reuseNonce *uint64) (uint64, error) {
	as.mu.Lock()
	defer as.mu.Unlock()

	// RTP header: 12 bytes
	header := make([]byte, 12)
	header[0] = 0x80
	header[1] = 0x60 // M=0, PT=96 (Apple senders never set marker bit)
	binary.BigEndian.PutUint16(header[2:4], seq)
	binary.BigEndian.PutUint32(header[4:8], rtpTime)
	binary.BigEndian.PutUint32(header[8:12], as.ssrc)

	// Encrypt payload according to the negotiated audio security mode.
	packetPayload := payload
	usedNonce := uint64(0)
	if as.chachaCipher != nil {
		var nonce [audioChaChaNonceSize]byte
		usedNonce, nonce = as.nextAudioChaChaNonce(seq, rtpTime, reuseNonce)
		aad := as.audioChaChaAAD(header, rtpTime)
		sealed := as.chachaCipher.Seal(nil, nonce[:], payload, aad)
		packetPayload = make([]byte, len(sealed)+8)
		copy(packetPayload, sealed)
		binary.LittleEndian.PutUint64(packetPayload[len(sealed):], usedNonce)
		if seq <= 3 {
			tagStart := len(sealed) - as.chachaCipher.Overhead()
			if tagStart < 0 {
				tagStart = 0
			}
			dbg("[AUDIO-CHACHA] seq=%d nonce=%d aad=%s plain=%d sealed=%d tag=%02x tail=%02x",
				seq, usedNonce, as.chachaAADMode.String(), len(payload), len(sealed), sealed[tagStart:], packetPayload[len(sealed):])
		}
	} else if as.cipher != nil && as.aesIV != nil {
		packetPayload = aesEncryptAudioPayload(as.cipher, as.aesIV, payload)

		// Self-decrypt check on first packet to verify key/IV correctness
		if seq == 1 {
			blockSize := as.cipher.BlockSize()
			encLen := (len(packetPayload) / blockSize) * blockSize
			if encLen > 0 {
				decrypted := make([]byte, len(packetPayload))
				copy(decrypted, packetPayload)
				dec := cipher.NewCBCDecrypter(as.cipher, as.aesIV)
				dec.CryptBlocks(decrypted[:encLen], decrypted[:encLen])
				match := true
				for i := 0; i < len(payload); i++ {
					if decrypted[i] != payload[i] {
						match = false
						break
					}
				}
				dbg("[AUDIO] *** SELF-DECRYPT CHECK: match=%v", match)
				dbg("[AUDIO] *** plaintext first 16: %02x", payload[:min(16, len(payload))])
				dbg("[AUDIO] *** encrypted first 16: %02x", packetPayload[:min(16, len(packetPayload))])
				dbg("[AUDIO] *** decrypted first 16: %02x", decrypted[:min(16, len(decrypted))])
				dbg("[AUDIO] *** IV: %02x", as.aesIV)
			}
		}
	}

	packet := make([]byte, 12+len(packetPayload))
	copy(packet[:12], header)
	copy(packet[12:], packetPayload)

	_, err := as.conn.WriteTo(packet, as.remoteAddr)
	if err != nil {
		return usedNonce, err
	}

	// Track the latest RTP time for sync packets (only update forward)
	if rtpTime >= as.rtpTime {
		as.rtpTime = rtpTime
	}
	return usedNonce, nil
}

// aesEncryptAudioPayload encrypts audio data using AES-128-CBC.
// Only encrypts full 16-byte blocks; trailing bytes are sent in the clear.
// This matches the AirPlay receiver's decryption behavior.
func aesEncryptAudioPayload(block cipher.Block, iv, data []byte) []byte {
	blockSize := block.BlockSize()
	encLen := (len(data) / blockSize) * blockSize
	if encLen == 0 {
		return data
	}

	out := make([]byte, len(data))
	copy(out, data)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(out[:encLen], out[:encLen])

	return out
}

// sendSyncPacket sends an RTP sync/timing packet on the control port.
// This tells the receiver the current RTP timestamp mapping.
func (as *AudioStream) sendSyncPacket(ntpTime uint64, isFirst bool) error {
	as.mu.Lock()
	rtpNow := as.rtpTime
	latencySamples := as.latencySamples
	as.mu.Unlock()

	// Sync packet: 20 bytes total (8-byte RTP-like header + 12-byte payload)
	// Format observed from real Apple senders:
	//   header: V=2, X=1(first)/0(subsequent), M=1, PT=84, seq=4 (constant)
	//   RTP timestamp = current playback position (sync_rtp)
	//   payload: NTP_hi(4) + NTP_lo(4) + next_rtp(4)
	//   next_rtp = sync_rtp + latencySamples
	packet := make([]byte, 20)
	if isFirst {
		packet[0] = 0x90 // V=2, X=1
	} else {
		packet[0] = 0x80 // V=2, X=0
	}
	packet[1] = 0xd4 // M=1, PT=84
	// seq field is constant 4 in working pcap captures
	binary.BigEndian.PutUint16(packet[2:4], 4)
	// Bytes 4-7: sync_rtp = current playback position
	syncRtp := rtpNow
	if rtpNow >= latencySamples {
		syncRtp = rtpNow - latencySamples
	}
	binary.BigEndian.PutUint32(packet[4:8], syncRtp)
	// Bytes 8-15: NTP timestamp (current wall-clock time)
	binary.BigEndian.PutUint64(packet[8:16], ntpTime)
	// Bytes 16-19: next_rtp = sync_rtp + latencySamples
	binary.BigEndian.PutUint32(packet[16:20], syncRtp+latencySamples)

	_, err := as.ctrlConn.WriteTo(packet, as.ctrlAddr)
	return err
}

func (as *AudioStream) Close() {
	if as.conn != nil && as.conn != as.ctrlConn {
		as.conn.Close()
	}
	if as.ctrlConn != nil {
		as.ctrlConn.Close()
	}
}

// StreamAudio reads ALAC frames from the capture pipeline and sends
// RTP audio packets to the receiver. It also sends periodic sync packets.
func (s *MirrorSession) StreamAudio(ctx context.Context, capture *AudioCapture, audioStream *AudioStream) error {
	spf := uint32(audioStream.spf)

	// Wait for the first video frame before starting audio.
	// The Apple TV processes audio in the context of an active video stream;
	// sending audio before video may cause it to be discarded.
	dbg("[AUDIO] waiting for first video frame before starting audio...")
	select {
	case <-s.firstFrameSent:
		dbg("[AUDIO] first video frame sent, starting audio")
	case <-ctx.Done():
		return ctx.Err()
	}

	// Send initial sync burst — real Apple senders send multiple identical sync
	// packets (observed 7 in pcap) before any audio data, all with X=1 (0x90).
	ntpNow := ntpBootTimestamp()
	for i := 0; i < 7; i++ {
		if err := audioStream.sendSyncPacket(ntpNow, true); err != nil {
			dbg("[AUDIO] initial sync error: %v", err)
		}
	}

	// Start data RTP time at latencySamples so the first real audio packet
	// has rtp >= next_rtp from the sync packet.
	// No empty header packet — real Apple senders go directly to data.
	latencySamples := audioStream.latencySamples
	nextRtp := latencySamples
	// Update rtpTime so sync packets reflect the correct position
	audioStream.mu.Lock()
	audioStream.rtpTime = nextRtp
	audioStream.mu.Unlock()
	dbg("[AUDIO] sent initial sync burst (7 packets), starting audio at rtp=%d", nextRtp)

	// Periodic sync sender — more frequent during initial ramp-up (every 200ms
	// for the first 5 seconds), then every 1 second. Real Apple senders appear
	// to sync roughly every 170ms initially.
	go func() {
		fastTicker := time.NewTicker(200 * time.Millisecond)
		defer fastTicker.Stop()
		slowTimer := time.After(5 * time.Second)
		for {
			select {
			case <-ctx.Done():
				return
			case <-slowTimer:
				// Switch to slow (1s) sync after initial period
				fastTicker.Stop()
				slowTick := time.NewTicker(1 * time.Second)
				defer slowTick.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-slowTick.C:
						nt := ntpBootTimestamp()
						if err := audioStream.sendSyncPacket(nt, false); err != nil {
							dbg("[AUDIO] sync error: %v", err)
						}
					}
				}
			case <-fastTicker.C:
				nt := ntpBootTimestamp()
				if err := audioStream.sendSyncPacket(nt, false); err != nil {
					dbg("[AUDIO] sync error: %v", err)
				}
			}
		}
	}()

	// Listen for control packets (resend requests) in background
	go func() {
		buf := make([]byte, 1024)
		for {
			n, addr, err := audioStream.ctrlConn.ReadFrom(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				dbg("[AUDIO] control read error: %v", err)
				return
			}
			dbg("[AUDIO] control packet from %s: %d bytes: %02x", addr, n, buf[:n])
		}
	}()

	// Redundant audio is kept for legacy/plaintext sessions, but modern
	// ChaCha-encrypted receivers decode more reliably when each frame is sent once.
	useFEC := useAudioFEC(audioStream.chachaCipher != nil)
	if !useFEC {
		dbg("[AUDIO] FEC disabled for ChaCha-encrypted sessions: each frame sent once")
	} else {
		dbg("[AUDIO] FEC enabled: burst-8 + interleaved retransmit")
	}

	const retransmitDepth = 8
	type audioFrame struct {
		payload []byte
		rtpTime uint32
		seq     uint16
		nonce   uint64
	}
	var retransmitBuf [retransmitDepth]audioFrame
	var frameSeq uint16 = 1 // first frame = seq 1
	var frameCount int
	retransmitIdx := 0
	burstDone := false
	frameBuf := make([]byte, 8192)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := capture.ReadFrame(frameBuf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("audio read frame: %w", err)
		}
		if n == 0 {
			continue
		}

		payload := make([]byte, n)
		copy(payload, frameBuf[:n])

		frameCount++

		if !useFEC {
			// Single-send: send each frame once
			if _, err := audioStream.sendAudioPacketWithSeqAndNonce(payload, nextRtp, frameSeq, nil); err != nil {
				return fmt.Errorf("audio send: %w", err)
			}
		} else if !burstDone {
			// Initial burst phase: send frames immediately, fill retransmit buffer
			nonce, err := audioStream.sendAudioPacketWithSeqAndNonce(payload, nextRtp, frameSeq, nil)
			if err != nil {
				return fmt.Errorf("audio send: %w", err)
			}
			retransmitBuf[retransmitIdx] = audioFrame{payload: payload, rtpTime: nextRtp, seq: frameSeq, nonce: nonce}
			retransmitIdx++
			if retransmitIdx >= retransmitDepth {
				burstDone = true
				retransmitIdx = 0
				dbg("[AUDIO] initial burst of %d frames complete", retransmitDepth)
			}
		} else {
			// Steady state: send retransmit of old frame, then new frame
			old := retransmitBuf[retransmitIdx]
			if _, err := audioStream.sendAudioPacketWithSeqAndNonce(old.payload, old.rtpTime, old.seq, &old.nonce); err != nil {
				return fmt.Errorf("audio retransmit: %w", err)
			}

			// Store and send new frame
			nonce, err := audioStream.sendAudioPacketWithSeqAndNonce(payload, nextRtp, frameSeq, nil)
			if err != nil {
				return fmt.Errorf("audio send: %w", err)
			}
			retransmitBuf[retransmitIdx] = audioFrame{payload: payload, rtpTime: nextRtp, seq: frameSeq, nonce: nonce}
			retransmitIdx = (retransmitIdx + 1) % retransmitDepth
		}

		frameSeq++
		nextRtp += spf

		if frameCount <= 10 || frameCount%100 == 0 {
			hexStart := n
			if hexStart > 16 {
				hexStart = 16
			}
			dbg("[AUDIO] sent frame %d: seq=%d payload=%d rtp=%d hex=%02x",
				frameCount, frameSeq-1, n, nextRtp-spf, payload[:hexStart])
		}
	}
}
