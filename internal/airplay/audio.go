package airplay

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
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
	AudioCodecALAC   AudioCodec = 2 // ct=2, spf=352, audioFormat=0x40000
	AudioCodecAACELD AudioCodec = 8 // ct=8, spf=480, audioFormat=0x1000000

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

	audioSyncPayloadTypeNTP = 0xd4
	audioSyncPayloadTypePTP = 0xd7

	// AirPlay receivers report missing audio on the control socket with the
	// classic RTP retransmit request/response payload types. Keep the same
	// bounded 512-packet history used by Apple's sender-side audio queues.
	audioRetransmitRequestPayloadType  = 0xd5
	audioRetransmitResponsePayloadType = 0xd6
	audioRetransmitHistoryPackets      = 512

	// Timestamped capture can absorb a short scheduler stall without losing raw
	// PCM. This queue has no minimum threshold, so it does not add steady-state
	// latency; source PTS still decides whether a recovered frame is timely.
	audioCaptureStallBuffer = 250 * time.Millisecond
)

// ErrAACELDUnavailable means this build does not contain the optional FDK-AAC
// encoder. Video remains usable on receivers which require AAC-ELD audio.
var ErrAACELDUnavailable = errors.New("AAC-ELD encoder is unavailable")

func newAudioChaCha64AEAD(key []byte) (cipher.AEAD, error) {
	return aeadchacha20poly1305.NewCipher(key)
}

func useAudioRedundancy(codec AudioCodec) bool {
	// AirPlaySender's APEndpointCreateAudioStreamOptions selects two recent
	// packets for screen audio independently of its cryptor selection. Repeated
	// packets retain their original nonce and ciphertext; encryption does not
	// remove the need to recover UDP loss before the render deadline.
	return codec == AudioCodecALAC
}

func defaultAudioChaChaNonceMode() audioChaChaNonceMode {
	return audioChaChaNonceCounter
}

func defaultAudioChaChaAADMode() audioChaChaAADMode {
	return audioChaChaAADTimestampSSRC
}

// Info returns SETUP parameters for the supported mirrored-audio codec.
func (c AudioCodec) Info() (ct int64, spf int64, audioFormat int64, latencyMin int64, latencyMax int64, latencySamples uint32) {
	latency := targetLatencySamples44k1()
	if c == AudioCodecAACELD {
		return int64(AudioCodecAACELD), 480, 0x1000000, 0, int64(latency), latency
	}
	return 2, 352, 0x40000, 0, int64(latency), latency
}

func audioLatencySamplesForCodec(ct byte, override uint32) uint32 {
	if override > 0 {
		return override
	}
	_ = ct
	return targetLatencySamples44k1()
}

func randomRTPTime(reader io.Reader) (uint32, error) {
	var value [4]byte
	if _, err := io.ReadFull(reader, value[:]); err != nil {
		return 0, fmt.Errorf("generate RTP timestamp: %w", err)
	}
	return binary.BigEndian.Uint32(value[:]), nil
}

// AudioCapture manages audio capture via GStreamer and local ALAC encoding.
type AudioCapture struct {
	gstCmd    *exec.Cmd
	pcmPipe   io.ReadCloser
	pcmFrames audioPCMFrameReader
	cancel    context.CancelFunc
	waitCh    chan struct{}
	waitErr   error
	stopped   bool
	codec     AudioCodec
	eldMu     sync.Mutex
	eld       *eldEncoder
}

var audioTimestampFallbackWarning sync.Once

func supportsTimestampedAudioOutput() bool {
	for _, element := range []string{"rtpL16pay", "rtponviftimestamp", "rtpstreampay"} {
		if !hasGstElement(element) {
			return false
		}
	}
	return true
}

func audioCapturePipelineArgs(srcArgs []string, codec AudioCodec, timestamped bool) []string {
	_, codecSPF, _, _, _, _ := codec.Info()
	format := "S16LE"
	if timestamped {
		// RTP L16 is network byte order. The framed reader restores S16LE before
		// handing samples to either local AirPlay encoder.
		format = "S16BE"
	}
	args := append([]string{"--quiet"}, srcArgs...)
	args = append(args,
		"!", "audioconvert",
		"!", "audioresample",
		"!", fmt.Sprintf("audio/x-raw,rate=%d,channels=%d,format=%s,layout=interleaved", audioSampleRate, audioChannels, format),
	)
	if timestamped {
		// Preserve complete source samples through short CPU/GPU scheduling stalls.
		// The timestamp-aware Go reader can then discard only codec frames whose
		// negotiated playout deadline has actually passed.
		args = append(args,
			"!", "queue", "max-size-buffers=0", "max-size-bytes=0",
			fmt.Sprintf("max-size-time=%d", audioCaptureStallBuffer), "leaky=no",
		)
		// ceil(SPF / sampleRate) keeps a normal codec frame within one packet,
		// while the Go reader remains correct if GStreamer splits or combines it.
		maxPacketTime := (codecSPF*int64(time.Second) + audioSampleRate - 1) / audioSampleRate
		args = append(args,
			"!", "rtpL16pay", "pt=96", "mtu=60000", "timestamp-offset=0", "seqnum-offset=0",
			// Generate capture RTP from the number of PCM samples, not wall time.
			// The ONVIF extension independently preserves the matching source PTS.
			"perfect-rtptime=true", fmt.Sprintf("max-ptime=%d", maxPacketTime),
			"!", "rtponviftimestamp", "ntp-offset=-1", "set-e-bit=false", "set-t-bit=false",
			"!", "rtpstreampay",
		)
	} else {
		// The compatibility fallback has no source PTS with which to recognize a
		// backlog. Retain its small downstream-leaky queue so a stalled reader
		// cannot turn into permanent audio lag.
		args = append(args,
			"!", "queue", "max-size-buffers=2", "max-size-bytes=0", "max-size-time=0", "leaky=downstream",
		)
	}
	return append(args, "!", "fdsink", "fd=1", "sync=false", "async=false")
}

// StartAudioCapture launches a pipeline that captures system audio (monitor source)
// and feeds raw PCM into the encoder negotiated by SETUP. ALAC is built in;
// AAC-ELD is available in builds made with -tags fdk_aac and libfdk-aac.
func StartAudioCapture(ctx context.Context, testTone bool, codec AudioCodec) (*AudioCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)
	if codec != AudioCodecALAC && codec != AudioCodecAACELD {
		cancel()
		return nil, fmt.Errorf("unsupported audio codec %d", codec)
	}
	_, codecSPF, _, _, _, _ := codec.Info()

	// Detect audio source
	var srcArgs []string
	if testTone {
		srcArgs = []string{"audiotestsrc", "wave=sine", "freq=440", "is-live=true",
			fmt.Sprintf("samplesperbuffer=%d", codecSPF)}
		dbg("[AUDIO] using test tone (440 Hz sine wave, live, spf=%d)", codecSPF)
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
		codec:  codec,
	}
	if codec == AudioCodecAACELD {
		var err error
		ac.eld, err = newELDEncoder()
		if err != nil {
			cancel()
			return nil, err
		}
	}

	timestamped := supportsTimestampedAudioOutput()
	if !timestamped {
		audioTimestampFallbackWarning.Do(func() {
			log.Printf("[AUDIO] warning: GStreamer RTP/ONVIF timestamp elements are unavailable; using read-time audio clock fallback")
		})
	}
	gstArgs := audioCapturePipelineArgs(srcArgs, codec, timestamped)
	dbg("[AUDIO] PCM capture pipeline: gst-launch-1.0 %s", strings.Join(gstArgs, " "))

	gstCmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)
	gstStdout, err := gstCmd.StdoutPipe()
	if err != nil {
		if ac.eld != nil {
			ac.eld.Close()
			ac.eld = nil
		}
		cancel()
		return nil, fmt.Errorf("gst stdout pipe: %w", err)
	}
	gstStderr, _ := gstCmd.StderrPipe()

	waitResult, err := startGStreamerCommand(gstCmd)
	if err != nil {
		if ac.eld != nil {
			ac.eld.Close()
			ac.eld = nil
		}
		cancel()
		return nil, fmt.Errorf("start audio capture pipeline: %w", err)
	}
	go logStderr("AUDIO-GST", gstStderr)

	ac.gstCmd = gstCmd
	ac.pcmPipe = gstStdout
	if timestamped {
		ac.pcmFrames = newRTPL16PCMFrameReader(gstStdout)
	}
	go func() {
		ac.waitErr = <-waitResult
		close(ac.waitCh)
	}()

	return ac, nil
}

// ReadFrame reads one encoded audio frame. Timestamp-aware callers should use
// ReadFrameAt so the sample's capture time remains attached to its RTP epoch.
func (ac *AudioCapture) ReadFrame(buf []byte) (int, error) {
	n, _, err := ac.ReadFrameAt(buf)
	return n, err
}

// ReadFrameAt reads one encoded audio frame and returns the source PTS of its
// first sample. PTS is zero only for the transparent unframed fallback.
func (ac *AudioCapture) ReadFrameAt(buf []byte) (int, time.Time, error) {
	n, position, err := ac.readFramePosition(buf)
	return n, position.PTS, err
}

func (ac *AudioCapture) readFramePosition(buf []byte) (int, audioPCMFramePosition, error) {
	select {
	case <-ac.waitCh:
		if ac.waitErr != nil {
			return 0, audioPCMFramePosition{}, fmt.Errorf("audio capture exited: %w", ac.waitErr)
		}
		return 0, audioPCMFramePosition{}, io.EOF
	default:
	}

	_, codecSPF, _, _, _, _ := ac.codec.Info()
	spf := int(codecSPF)
	const channels = 2
	const bytesPerSample = 2
	pcmSize := spf * channels * bytesPerSample // 1408 bytes
	pcm := make([]byte, pcmSize)
	var position audioPCMFramePosition
	var err error
	if ac.pcmFrames != nil {
		if positioned, ok := ac.pcmFrames.(audioPCMFramePositionReader); ok {
			position, err = positioned.ReadPCMFramePosition(pcm)
		} else {
			position.PTS, err = ac.pcmFrames.ReadPCMFrame(pcm)
		}
	} else {
		_, err = io.ReadFull(ac.pcmPipe, pcm)
	}
	if err != nil {
		return 0, audioPCMFramePosition{}, err
	}
	if ac.codec == AudioCodecAACELD {
		ac.eldMu.Lock()
		defer ac.eldMu.Unlock()
		if ac.eld == nil {
			return 0, audioPCMFramePosition{}, io.EOF
		}
		n, err := ac.eld.Encode(pcm, buf)
		return n, position, err
	}
	n := encodeALACVerbatim(buf, pcm, spf, channels, 16)
	return n, position, nil
}

// DrainStale discards any PCM that buffered in the OS pipe between capture
// start and the first read. The capture pipeline starts producing audio
// immediately, but streaming does not begin until the first video frame is
// sent; during that gap the kernel pipe accumulates a FIFO backlog that would
// otherwise be read in order forever, leaving every frame permanently stale and
// audio lagging video. Draining once just before the read loop starts streaming
// from the freshest sample. It removes whatever backlog actually accumulated —
// no fixed latency value is assumed.
func (ac *AudioCapture) DrainStale() {
	if ac.pcmFrames != nil {
		// RFC4571 is a framed stream; arbitrary byte reads would corrupt it. The
		// timestamp-aware media loop catches up by discarding whole codec frames.
		return
	}
	type deadlineReader interface {
		SetReadDeadline(t time.Time) error
	}
	dr, ok := ac.pcmPipe.(deadlineReader)
	if !ok {
		return
	}
	buf := make([]byte, 32*1024)
	var discarded int
	for {
		// Re-arm a short idle timeout each read: while a backlog exists, reads
		// return buffered data immediately; once the pipe is empty the read
		// blocks and this deadline fires before the next live frame (~8ms)
		// arrives, ending the drain. This is a poll timeout, not a latency.
		if err := dr.SetReadDeadline(time.Now().Add(2 * time.Millisecond)); err != nil {
			break
		}
		n, err := ac.pcmPipe.Read(buf)
		discarded += n
		if err != nil {
			break
		}
	}
	// Restore blocking reads for steady-state streaming.
	_ = dr.SetReadDeadline(time.Time{})
	if discarded > 0 {
		const bytesPerSecond = 44100 * 2 * 2 // 44.1kHz, stereo, S16LE
		dbg("[AUDIO] drained %d bytes (~%.0fms) of startup backlog before streaming",
			discarded, float64(discarded)/bytesPerSecond*1000)
	}
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
	ac.eldMu.Lock()
	if ac.eld != nil {
		ac.eld.Close()
		ac.eld = nil
	}
	ac.eldMu.Unlock()
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

type audioPacketHistoryEntry struct {
	valid  bool
	seq    uint16
	packet []byte
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
	ct              byte   // AirPlay compression type (2=ALAC, 8=AAC-ELD)
	spf             uint16 // samples per frame
	latencySamples  uint32 // audio latency in samples (for sync packets)
	mu              sync.Mutex
	historyMu       sync.RWMutex
	packetHistory   [audioRetransmitHistoryPackets]audioPacketHistoryEntry
}

// AudioCodec returns the codec negotiated for this mirror session.
func (s *MirrorSession) AudioCodec() AudioCodec {
	if s == nil || s.audioStream == nil {
		return AudioCodecALAC
	}
	return AudioCodec(s.audioStream.ct)
}

// setupAudioStream creates the audio RTP stream state.
// Real AirPlay senders use two separate UDP sockets for audio:
//   - ctrlConn: the declared controlPort socket → sends sync/control to receiver's controlPort
//   - dataConn: a separate socket at controlPort+1 → sends audio data to receiver's dataPort
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

	_, codecSPF, _, _, _, _ := AudioCodec(ct).Info()
	spf := uint16(codecSPF)
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
		dbg("[AUDIO] audio latency: %d samples", latencySamples)
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
		// APSTransportMessageGetAudioAADPointer returns the serialized timestamp
		// and SSRC fields directly: eight bytes beginning two bytes into Apple's
		// ten-byte audio-data header (the RTP header without V/PT).
		return header[4:12]
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

	if reuseNonce == nil {
		// Register the immutable message before network dispatch, matching the
		// official sender's prepare/enqueue order and closing the lookup window
		// before a later packet can expose this sequence as missing.
		as.rememberAudioPacket(seq, packet)
	}
	_, err := as.conn.WriteTo(packet, as.remoteAddr)
	if err != nil {
		return usedNonce, err
	}

	// RTP timestamps wrap at 32 bits. A signed modular comparison keeps an old
	// retransmit from moving the clock backwards while still crossing rollover.
	if int32(rtpTime-as.rtpTime) >= 0 {
		as.rtpTime = rtpTime
	}
	return usedNonce, nil
}

func (as *AudioStream) rememberAudioPacket(seq uint16, packet []byte) {
	// sendAudioPacketWithSeqAndNonce fully serializes each fresh allocation before
	// registering it and never mutates it afterward, so the ring can retain that
	// allocation directly. This keeps retransmission byte-identical without a copy.
	index := int(seq) % len(as.packetHistory)
	as.historyMu.Lock()
	as.packetHistory[index] = audioPacketHistoryEntry{valid: true, seq: seq, packet: packet}
	as.historyMu.Unlock()
}

func (as *AudioStream) audioPacketForRetransmit(seq uint16) []byte {
	index := int(seq) % len(as.packetHistory)
	as.historyMu.RLock()
	entry := as.packetHistory[index]
	as.historyMu.RUnlock()
	if !entry.valid || entry.seq != seq {
		return nil
	}
	// Replacing a ring slot never mutates its previous backing allocation. This
	// local slice keeps those immutable bytes alive after releasing the lock.
	return entry.packet
}

type audioRetransmitRequest struct {
	requestSeq uint16
	firstSeq   uint16
	count      uint16
}

func parseAudioRetransmitRequest(packet []byte) (audioRetransmitRequest, bool) {
	if len(packet) != 8 || packet[0] != 0x80 || packet[1] != audioRetransmitRequestPayloadType {
		return audioRetransmitRequest{}, false
	}
	request := audioRetransmitRequest{
		requestSeq: binary.BigEndian.Uint16(packet[2:4]),
		firstSeq:   binary.BigEndian.Uint16(packet[4:6]),
		count:      binary.BigEndian.Uint16(packet[6:8]),
	}
	if request.count == 0 {
		return audioRetransmitRequest{}, false
	}
	return request, true
}

// handleAudioControlPacket answers a receiver retransmit request on the same
// control socket. A successful response is the four-byte 0xd6 wrapper followed
// by the exact original RTP datagram. If history has expired, the eight-byte
// form tells the receiver that retrying this sequence is futile.
func (as *AudioStream) handleAudioControlPacket(packet []byte, addr net.Addr) (handled bool, resent int, err error) {
	request, ok := parseAudioRetransmitRequest(packet)
	if !ok {
		return false, 0, nil
	}

	// At most one more lookup than the bounded history can succeed. This keeps a
	// malformed count from amplifying traffic while still producing the official
	// futile response at the first sequence we cannot serve.
	requestCount := int(request.count)
	if requestCount > len(as.packetHistory)+1 {
		requestCount = len(as.packetHistory) + 1
	}
	for offset := 0; offset < requestCount; offset++ {
		seq := request.firstSeq + uint16(offset)
		original := as.audioPacketForRetransmit(seq)
		if original == nil {
			response := make([]byte, 8)
			response[0] = 0x80
			response[1] = audioRetransmitResponsePayloadType
			binary.BigEndian.PutUint16(response[2:4], request.requestSeq)
			binary.BigEndian.PutUint16(response[4:6], seq)
			if _, writeErr := as.ctrlConn.WriteTo(response, addr); writeErr != nil {
				return true, resent, writeErr
			}
			dbg("[AUDIO] retransmit request id=%d first=%d count=%d: resent=%d, sequence %d expired",
				request.requestSeq, request.firstSeq, request.count, resent, seq)
			return true, resent, nil
		}

		response := make([]byte, 4+len(original))
		response[0] = 0x80
		response[1] = audioRetransmitResponsePayloadType
		binary.BigEndian.PutUint16(response[2:4], request.requestSeq)
		copy(response[4:], original)
		if _, writeErr := as.ctrlConn.WriteTo(response, addr); writeErr != nil {
			return true, resent, writeErr
		}
		resent++
	}

	dbg("[AUDIO] retransmit request id=%d first=%d count=%d: resent=%d",
		request.requestSeq, request.firstSeq, request.count, resent)
	return true, resent, nil
}

func (as *AudioStream) audioControlPacketFromReceiver(addr net.Addr) bool {
	if as.ctrlAddr == nil || len(as.ctrlAddr.IP) == 0 {
		return true
	}
	peer, ok := addr.(*net.UDPAddr)
	return ok && peer.IP.Equal(as.ctrlAddr.IP)
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

// sendSyncPacket sends the last transmitted RTP position. It remains the
// fallback for un-timestamped capture and focused packet-format tests.
func (as *AudioStream) sendSyncPacket(timingProtocol string, networkTime, timelineID uint64, isFirst bool) error {
	as.mu.Lock()
	rtpNow := as.rtpTime
	as.mu.Unlock()
	return as.sendSyncPacketAt(timingProtocol, networkTime, timelineID, rtpNow, isFirst)
}

// sendSyncPacketAt publishes an RTP and network-time pair describing the same
// source-clock instant. Official senders derive both values from one host tick.
func (as *AudioStream) sendSyncPacketAt(timingProtocol string, networkTime, timelineID uint64, rtpNow uint32, isFirst bool) error {
	as.mu.Lock()
	latencySamples := as.latencySamples
	as.mu.Unlock()

	packetSize := 0
	switch timingProtocol {
	case timingProtocolNTP:
		packetSize = 20
	case timingProtocolPTP:
		if timelineID == 0 {
			return fmt.Errorf("PTP TimeAnnounce requires a receiver timeline ID")
		}
		packetSize = 28
	default:
		return fmt.Errorf("unsupported audio timing protocol %q", timingProtocol)
	}
	packet := make([]byte, packetSize)
	if isFirst {
		packet[0] = 0x90 // V=2, X=1
	} else {
		packet[0] = 0x80 // V=2, X=0
	}
	// seq field is constant 4 in working pcap captures
	binary.BigEndian.PutUint16(packet[2:4], 4)

	if timingProtocol == timingProtocolPTP {
		// PTP TimeAnnounce: the first RTP value is the media position at the
		// announced network time; the second is the future RTP position at which
		// the receiver applies the mapping. Apple senders keep those positions one
		// negotiated audio latency apart.
		packet[1] = audioSyncPayloadTypePTP
		syncRTP := rtpNow - latencySamples
		binary.BigEndian.PutUint32(packet[4:8], syncRTP)
		binary.BigEndian.PutUint64(packet[8:16], ptpNanoseconds(networkTime))
		binary.BigEndian.PutUint32(packet[16:20], rtpNow)
		binary.BigEndian.PutUint64(packet[20:28], timelineID)
	} else {
		// Legacy NTP TimeAnnounce: playback RTP, NTP seconds.32, receive RTP.
		packet[1] = audioSyncPayloadTypeNTP
		syncRtp := rtpNow - latencySamples
		binary.BigEndian.PutUint32(packet[4:8], syncRtp)
		binary.BigEndian.PutUint64(packet[8:16], networkTime)
		binary.BigEndian.PutUint32(packet[16:20], rtpNow)
	}

	dbg("[AUDIO-SYNC] first=%t rtp=%d latency=%d network=0x%016x timeline=0x%016x",
		isFirst, rtpNow, latencySamples, networkTime, timelineID)
	_, err := as.ctrlConn.WriteTo(packet, as.ctrlAddr)
	return err
}

func ptpNanoseconds(timestamp uint64) uint64 {
	seconds := timestamp >> 32
	fraction := timestamp & 0xffffffff
	return seconds*uint64(time.Second) + (fraction * uint64(time.Second) >> 32)
}

// audioClockAt converts a source PTS through the same session clock used by
// video. The NTP fallback keeps the monotonic component of the source time and
// adds the protocol's 1900 epoch to the sender's boot-relative clock.
func (s *MirrorSession) audioClockAt(local time.Time) (timestamp, timelineID uint64) {
	if local.IsZero() {
		return s.audioClockNow()
	}
	if s.mediaClock != nil {
		if timestamp, timelineID, ok := s.mediaClock.at(local, 0); ok {
			return timestamp, timelineID
		}
	}
	if presentation, ok := addDurationToBootTime(local.Sub(time.Now())); ok {
		return compactTimestamp(presentation) + (uint64(secondsFrom1900To1970) << 32), 0
	}
	return s.audioClockNow()
}

const (
	minimumAudioSendLead        = 5 * time.Millisecond
	maximumInitialCatchupFrames = 128
	audioSendBurstWindow        = 5 * time.Millisecond
	maximumAudioPacketsPerBurst = 12
)

// audioSendBurstLimiter bounds only catch-up bursts. At normal ALAC/AAC-ELD
// cadence every source frame arrives outside the five-millisecond window, so it
// adds no steady-state delay. Apple's real-time audio sender uses the same
// five-millisecond service cadence and a burst budget whose floor is 12.
type audioSendBurstLimiter struct {
	windowStart time.Time
	packets     int
}

func (limiter *audioSendBurstLimiter) reserveDelay(now time.Time) time.Duration {
	if now.IsZero() {
		return 0
	}
	elapsed := now.Sub(limiter.windowStart)
	if limiter.windowStart.IsZero() || elapsed < 0 || elapsed >= audioSendBurstWindow {
		limiter.windowStart = now
		limiter.packets = 0
	}
	if limiter.packets < maximumAudioPacketsPerBurst {
		limiter.packets++
		return 0
	}
	return audioSendBurstWindow - elapsed
}

func (limiter *audioSendBurstLimiter) wait(ctx context.Context) error {
	for {
		delay := limiter.reserveDelay(time.Now())
		if delay <= 0 {
			return nil
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func audioLatencyDuration(samples uint32) time.Duration {
	return audioSamplesDuration(uint64(samples))
}

func audioFrameIsStale(pts, now time.Time, latencySamples uint32) bool {
	if pts.IsZero() || now.IsZero() {
		return false
	}
	return !pts.Add(audioLatencyDuration(latencySamples)).After(now.Add(minimumAudioSendLead))
}

func (as *AudioStream) Close() {
	if as.conn != nil && as.conn != as.ctrlConn {
		as.conn.Close()
	}
	if as.ctrlConn != nil {
		as.ctrlConn.Close()
	}
}

// StreamAudio reads encoded frames from the capture pipeline and sends
// RTP audio packets to the receiver. It also sends periodic sync packets.
func (s *MirrorSession) StreamAudio(ctx context.Context, capture *AudioCapture, audioStream *AudioStream) error {
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	defer func() {
		// The periodic announce and RTCP reader are owned by this call. Closing the
		// sockets unblocks ReadFrom; cancellation stops the ticker before returning.
		cancel()
		audioStream.Close()
		workers.Wait()
	}()

	spf := uint32(audioStream.spf)

	// Prewarm the capture while waiting for the first presentable video frame.
	// GStreamer starts producing PCM immediately; continuously consuming and
	// discarding complete frames prevents its internal queues and the stdout pipe
	// from preserving old samples throughout video encoder startup or the wait
	// for the next IDR. No audio clock mapping is published during this pre-roll.
	dbg("[AUDIO] prewarming capture while waiting for first video frame...")
	prewarmBuf := make([]byte, 8192)
	prewarmedFrames := 0
	for {
		select {
		case <-s.firstFrameSent:
			dbg("[AUDIO] first video frame sent after discarding %d pre-roll audio frames", prewarmedFrames)
			goto videoReady
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if _, _, err := capture.ReadFrameAt(prewarmBuf); err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("audio prewarm: %w", err)
		}
		prewarmedFrames++
	}

videoReady:

	// Apple starts each audio timeline at a random 32-bit RTP epoch. The
	// latency-adjusted TimeAnnounce value is allowed to wrap below that epoch.
	// No empty header packet is sent before the first real audio frame.
	nextRtp, err := randomRTPTime(rand.Reader)
	if err != nil {
		return err
	}
	// Update rtpTime so the first sync packet reflects the first media position.
	audioStream.mu.Lock()
	audioStream.rtpTime = nextRtp
	audioStream.mu.Unlock()

	// Discard any partial unframed pipe backlog between the final prewarm read and
	// the video-ready signal, then wait until one complete, fresh audio frame is in hand.
	// The RTP/network-clock mapping must be established at this point, not when
	// the capture process was merely started: GStreamer and the sound server can
	// take hundreds of milliseconds to deliver their first sample, which would
	// otherwise make audio lead video by the same amount.
	capture.DrainStale()
	frameBuf := make([]byte, 8192)
	firstFrameSize := 0
	var firstFramePosition audioPCMFramePosition
	catchupFrames := 0
	for firstFrameSize == 0 {
		firstFrameSize, firstFramePosition, err = capture.readFramePosition(frameBuf)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("audio read first frame: %w", err)
		}
		if firstFrameSize > 0 && audioFrameIsStale(firstFramePosition.PTS, time.Now(), audioStream.latencySamples) {
			catchupFrames++
			if catchupFrames >= maximumInitialCatchupFrames {
				age := time.Since(firstFramePosition.PTS)
				return fmt.Errorf("audio capture cannot meet %v playout lead after discarding %d stale frames (source age %v)",
					audioLatencyDuration(audioStream.latencySamples), catchupFrames, age)
			}
			firstFrameSize = 0
		}
	}
	if catchupFrames > 0 {
		dbg("[AUDIO] discarded %d timestamped startup frames to restore positive playout lead", catchupFrames)
	}
	timestampedAudio := !firstFramePosition.PTS.IsZero()
	if firstFramePosition.PTS.IsZero() {
		// Transparent raw fallback: preserve the historical read-time anchor.
		firstFramePosition.PTS = time.Now()
	}
	rtpClock := newAudioRTPClock(nextRtp)
	firstFrameRTP, _ := rtpClock.mapFramePosition(firstFramePosition, spf)
	var announceMu sync.Mutex

	// Establish the initial mapping at the first sample's source PTS. The reset
	// bit is also used if the source clock later jumps backwards and is re-anchored.
	clockNow, timelineID := s.audioClockNow()
	if timestampedAudio {
		clockNow, timelineID = s.audioClockAt(firstFramePosition.PTS)
	}
	if err := audioStream.sendSyncPacketAt(s.timingProtocol, clockNow, timelineID, firstFrameRTP, true); err != nil {
		return fmt.Errorf("audio initial clock mapping: %w", err)
	}
	dbg("[AUDIO] sent initial source clock mapping pts=%v sourceRTP=%d rtp=%d",
		firstFramePosition.PTS, firstFramePosition.SourceRTP, firstFrameRTP)

	// Apple senders refresh TimeAnnounce once per second.
	workers.Add(1)
	go func() {
		defer workers.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !timestampedAudio {
					clockNow, timelineID := s.audioClockNow()
					if err := audioStream.sendSyncPacket(s.timingProtocol, clockNow, timelineID, false); err != nil {
						dbg("[AUDIO] sync error: %v", err)
					}
					continue
				}
				announceMu.Lock()
				rtpNow, announcedAt, ok := rtpClock.latestBoundary()
				if !ok {
					announceMu.Unlock()
					continue
				}
				clockNow, timelineID := s.audioClockAt(announcedAt)
				err := audioStream.sendSyncPacketAt(s.timingProtocol, clockNow, timelineID, rtpNow, false)
				announceMu.Unlock()
				if err != nil {
					dbg("[AUDIO] sync error: %v", err)
				}
			}
		}
	}()

	// Listen for control packets (primarily retransmit requests) in background.
	workers.Add(1)
	go func() {
		defer workers.Done()
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
			if !audioStream.audioControlPacketFromReceiver(addr) {
				dbg("[AUDIO] ignoring control packet from unexpected peer %s", addr)
				continue
			}
			handled, _, handleErr := audioStream.handleAudioControlPacket(buf[:n], addr)
			if handleErr != nil {
				dbg("[AUDIO] retransmit response error for %s: %v", addr, handleErr)
				continue
			}
			if !handled {
				dbg("[AUDIO] control packet from %s: %d bytes: %02x", addr, n, buf[:n])
			}
		}
	}()

	// Redundant audio is kept for legacy/plaintext sessions, but modern
	// ChaCha-encrypted receivers decode more reliably when each frame is sent once.
	useFEC := useAudioRedundancy(AudioCodec(audioStream.ct))
	if !useFEC {
		dbg("[AUDIO] packet redundancy disabled for codec %d: each frame sent once", audioStream.ct)
	} else {
		dbg("[AUDIO] packet redundancy enabled: current frame plus two recent frames")
	}
	var burstLimiter audioSendBurstLimiter
	sendPacket := func(payload []byte, rtpTime uint32, seq uint16, reuseNonce *uint64) (uint64, error) {
		if err := burstLimiter.wait(ctx); err != nil {
			return 0, err
		}
		return audioStream.sendAudioPacketWithSeqAndNonce(payload, rtpTime, seq, reuseNonce)
	}

	// AirPlaySender's APMessageRingCopyNextBurst walks backward from the next
	// unsent packet, includes redundancyCount prior packets, then reverses the
	// array. Match our SETUP redundantAudio=2 with [N-2, N-1, N]; an eight-frame
	// interleave sends unrelated older packets outside that negotiated window.
	const retransmitDepth = 3
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
	useFirstFrame := true
	framePosition := firstFramePosition
	framePTS := firstFramePosition.PTS
	frameRTP := firstFrameRTP
	staleFrames := 0

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n := firstFrameSize
		usingFirstFrame := useFirstFrame
		if usingFirstFrame {
			useFirstFrame = false
		} else {
			n, framePosition, err = capture.readFramePosition(frameBuf)
			if err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return fmt.Errorf("audio read frame: %w", err)
			}
			framePTS = framePosition.PTS
		}
		if n == 0 {
			continue
		}
		if framePTS.IsZero() {
			// Unframed fallback has no source clock. Preserve its historical fixed
			// SPF progression instead of turning read-scheduling jitter into RTP jitter.
			framePTS = firstFramePosition.PTS.Add(audioSamplesDuration(uint64(frameCount) * uint64(spf)))
			framePosition.PTS = framePTS
		}
		if !usingFirstFrame && timestampedAudio && audioFrameIsStale(framePTS, time.Now(), audioStream.latencySamples) {
			staleFrames++
			if staleFrames == 1 || staleFrames%100 == 0 {
				dbg("[AUDIO] dropping stale source frame %v old (latency=%v, dropped=%d)",
					time.Since(framePTS), audioLatencyDuration(audioStream.latencySamples), staleFrames)
			}
			continue
		}
		if staleFrames > 0 {
			dbg("[AUDIO] source caught up after dropping %d stale frames", staleFrames)
			staleFrames = 0
		}
		if frameCount > 0 {
			if timestampedAudio {
				announceMu.Lock()
				var reset bool
				frameRTP, reset = rtpClock.mapFramePosition(framePosition, spf)
				if reset {
					clockNow, timelineID := s.audioClockAt(framePTS)
					err := audioStream.sendSyncPacketAt(s.timingProtocol, clockNow, timelineID, frameRTP, true)
					announceMu.Unlock()
					if err != nil {
						return fmt.Errorf("audio reset clock mapping: %w", err)
					}
					dbg("[AUDIO] reset source clock mapping pts=%v rtp=%d", framePTS, frameRTP)
				} else {
					announceMu.Unlock()
				}
			} else {
				frameRTP += spf
			}
		}

		payload := make([]byte, n)
		copy(payload, frameBuf[:n])

		frameCount++
		if !useFEC {
			// Single-send: send each frame once
			if _, err := sendPacket(payload, frameRTP, frameSeq, nil); err != nil {
				return fmt.Errorf("audio send: %w", err)
			}
		} else {
			retransmitBuf[retransmitIdx] = audioFrame{payload: payload, rtpTime: frameRTP, seq: frameSeq}
			retransmitIdx = (retransmitIdx + 1) % retransmitDepth
			available := min(frameCount, retransmitDepth)
			start := (retransmitIdx - available + retransmitDepth) % retransmitDepth
			for i := 0; i < available; i++ {
				frame := &retransmitBuf[(start+i)%retransmitDepth]
				var reuseNonce *uint64
				if i < available-1 {
					reuseNonce = &frame.nonce
				}
				nonce, err := sendPacket(frame.payload, frame.rtpTime, frame.seq, reuseNonce)
				if err != nil {
					return fmt.Errorf("audio send: %w", err)
				}
				frame.nonce = nonce
			}
		}

		frameSeq++

		if frameCount <= 10 || frameCount%100 == 0 {
			hexStart := n
			if hexStart > 16 {
				hexStart = 16
			}
			dbg("[AUDIO] sent frame %d: seq=%d payload=%d rtp=%d hex=%02x",
				frameCount, frameSeq-1, n, frameRTP, payload[:hexStart])
		}
	}
}
