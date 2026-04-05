package airplay

import (
	"bufio"
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
)

// AudioCapture manages audio capture via GStreamer's PulseAudio/PipeWire source,
// encoding to AAC-ELD (ct=8) and outputting ADTS-framed AAC packets.
type AudioCapture struct {
	cmd     *exec.Cmd
	stdout  io.ReadCloser
	cancel  context.CancelFunc
	waitCh  chan struct{}
	waitErr error
	stopped bool
}

// StartAudioCapture launches a GStreamer pipeline that captures system audio
// (monitor source) and encodes it as AAC-LC at 44100 Hz, outputting raw ADTS frames.
// AirPlay mirroring uses AAC-ELD (ct=8) with 480 samples/frame, but avdec_aac on
// the receiver also handles AAC-LC. We use AAC-LC because fdkaacenc (ELD) is often
// not available. If fdkaacenc is present we prefer it with ELD profile.
func StartAudioCapture(ctx context.Context) (*AudioCapture, error) {
	captureCtx, cancel := context.WithCancel(ctx)

	// Detect audio source: prefer PipeWire (pipewiresrc), fall back to pulsesrc monitor
	var srcArgs []string
	if exec.Command("gst-inspect-1.0", "pipewiresrc").Run() == nil {
		// PipeWire: capture desktop audio via the default sink monitor
		srcArgs = []string{"pipewiresrc"}
		dbg("[AUDIO] using pipewiresrc")
	} else if exec.Command("gst-inspect-1.0", "pulsesrc").Run() == nil {
		// PulseAudio: capture from the default sink's monitor
		monitor := detectPulseMonitor()
		if monitor == "" {
			cancel()
			return nil, fmt.Errorf("no PulseAudio monitor source found")
		}
		srcArgs = []string{"pulsesrc", fmt.Sprintf("device=%s", monitor)}
		dbg("[AUDIO] using pulsesrc device=%s", monitor)
	} else {
		cancel()
		return nil, fmt.Errorf("no audio source available (need pipewiresrc or pulsesrc)")
	}

	// Detect AAC encoder: prefer fdkaacenc (supports ELD), fall back to avenc_aac (LC)
	var encArgs []string
	ct := byte(4) // AAC-LC
	if exec.Command("gst-inspect-1.0", "fdkaacenc").Run() == nil {
		// fdkaacenc with ELD profile — lowest latency, 480 samples/frame
		encArgs = []string{"fdkaacenc", "bitrate=256000"}
		ct = 8 // AAC-ELD
		dbg("[AUDIO] using fdkaacenc (AAC-ELD)")
	} else if exec.Command("gst-inspect-1.0", "avenc_aac").Run() == nil {
		encArgs = []string{"avenc_aac", "bitrate=256000"}
		dbg("[AUDIO] using avenc_aac (AAC-LC)")
	} else if exec.Command("gst-inspect-1.0", "faac").Run() == nil {
		encArgs = []string{"faac", "bitrate=256000"}
		dbg("[AUDIO] using faac (AAC-LC)")
	} else {
		cancel()
		return nil, fmt.Errorf("no AAC encoder available (need fdkaacenc, avenc_aac, or faac)")
	}

	// Build GStreamer pipeline:
	// source ! audioconvert ! audioresample ! audio/x-raw,rate=44100,channels=2
	// ! aac_encoder ! aacparse ! audio/x-aac,stream-format=adts ! fdsink fd=1
	gstArgs := []string{"--quiet"}
	gstArgs = append(gstArgs, srcArgs...)
	gstArgs = append(gstArgs,
		"!", "audioconvert",
		"!", "audioresample",
		"!", "audio/x-raw,rate=44100,channels=2,format=S16LE",
		"!", "queue", "max-size-buffers=2", "max-size-bytes=0", "max-size-time=0", "leaky=downstream",
		"!",
	)
	gstArgs = append(gstArgs, encArgs...)
	gstArgs = append(gstArgs,
		"!", "aacparse",
		"!", "audio/x-aac,stream-format=adts",
		"!", "fdsink", "fd=1", "sync=false", "async=false",
	)

	dbg("[AUDIO] gst-launch-1.0 %s", strings.Join(gstArgs, " "))
	cmd := exec.CommandContext(captureCtx, "gst-launch-1.0", gstArgs...)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("audio gst stdout pipe: %w", err)
	}
	stderr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start audio gst-launch: %w", err)
	}

	go logStderr("AUDIO-GST", stderr)

	ac := &AudioCapture{
		cmd:    cmd,
		stdout: stdout,
		cancel: cancel,
		waitCh: make(chan struct{}),
	}
	go func() {
		ac.waitErr = cmd.Wait()
		close(ac.waitCh)
	}()

	_ = ct // ct is logged above; the actual ct sent to receiver is determined in setupAudioStream
	return ac, nil
}

func (ac *AudioCapture) Read(buf []byte) (int, error) {
	select {
	case <-ac.waitCh:
		if ac.waitErr != nil {
			return 0, fmt.Errorf("audio capture exited: %w", ac.waitErr)
		}
		return 0, io.EOF
	default:
	}
	return ac.stdout.Read(buf)
}

func (ac *AudioCapture) Stop() {
	if ac.stopped || ac.cmd == nil {
		return
	}
	ac.stopped = true
	if ac.cancel != nil {
		ac.cancel()
	}
	if ac.stdout != nil {
		ac.stdout.Close()
	}
	if ac.cmd.Process != nil {
		ac.cmd.Process.Kill()
	}
	select {
	case <-ac.waitCh:
	case <-time.After(2 * time.Second):
		if ac.cmd.Process != nil {
			ac.cmd.Process.Kill()
		}
		<-ac.waitCh
	}
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
	conn       net.PacketConn // local UDP socket for sending audio
	ctrlConn   net.PacketConn // control port for sync/resend
	remoteAddr *net.UDPAddr   // receiver's audio data address
	ctrlAddr   *net.UDPAddr   // receiver's audio control address
	seqnum     uint16
	rtpTime    uint32
	ssrc       uint32
	cipher     cipher.Block // AES-128 for audio encryption (nil = no encryption)
	aesIV      []byte       // 16-byte IV for AES-CBC
	ct         byte         // compression type: 2=ALAC, 8=AAC-ELD, 4=AAC-LC
	spf        uint16       // samples per frame
	mu         sync.Mutex
}

// setupAudioStream creates a UDP socket for audio, connects to the receiver's
// audio data port, and prepares the RTP stream state.
func (s *MirrorSession) setupAudioStream(dataPort, controlPort int, aesKey, aesIV []byte, ct byte) (*AudioStream, error) {
	// Create local UDP socket
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("listen audio UDP: %w", err)
	}

	ctrlConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("listen audio control UDP: %w", err)
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.client.host, fmt.Sprintf("%d", dataPort)))
	if err != nil {
		conn.Close()
		ctrlConn.Close()
		return nil, fmt.Errorf("resolve audio remote: %w", err)
	}

	ctrlAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(s.client.host, fmt.Sprintf("%d", controlPort)))
	if err != nil {
		conn.Close()
		ctrlConn.Close()
		return nil, fmt.Errorf("resolve audio control remote: %w", err)
	}

	var block cipher.Block
	if aesKey != nil && len(aesKey) == 16 {
		block, err = aes.NewCipher(aesKey)
		if err != nil {
			conn.Close()
			ctrlConn.Close()
			return nil, fmt.Errorf("aes cipher: %w", err)
		}
	}

	// Samples per frame depends on codec
	spf := uint16(1024) // AAC-LC default
	if ct == 8 {
		spf = 480 // AAC-ELD
	} else if ct == 2 {
		spf = 352 // ALAC
	}

	as := &AudioStream{
		conn:       conn,
		ctrlConn:   ctrlConn,
		remoteAddr: remoteAddr,
		ctrlAddr:   ctrlAddr,
		seqnum:     0,
		rtpTime:    0,
		ssrc:       0,
		cipher:     block,
		aesIV:      aesIV,
		ct:         ct,
		spf:        spf,
	}

	dbg("[AUDIO] stream setup: dataPort=%d controlPort=%d ct=%d spf=%d encrypted=%v",
		dataPort, controlPort, ct, spf, block != nil)

	return as, nil
}

// sendAudioPacket sends a single RTP audio packet.
// payload is the raw AAC frame data (without ADTS header).
func (as *AudioStream) sendAudioPacket(payload []byte) error {
	as.mu.Lock()
	defer as.mu.Unlock()

	// RTP header: 12 bytes
	// [0]     0x80 (V=2, P=0, X=0, CC=0)
	// [1]     0x60 (PT=96, M=0)
	// [2:3]   sequence number (big-endian)
	// [4:7]   RTP timestamp (big-endian)
	// [8:11]  SSRC (big-endian)
	header := make([]byte, 12)
	header[0] = 0x80
	header[1] = 0x60 // payload type 96
	binary.BigEndian.PutUint16(header[2:4], as.seqnum)
	binary.BigEndian.PutUint32(header[4:8], as.rtpTime)
	binary.BigEndian.PutUint32(header[8:12], as.ssrc)

	// Encrypt payload with AES-128-CBC if cipher is set
	encrypted := payload
	if as.cipher != nil && as.aesIV != nil {
		encrypted = aesEncryptAudioPayload(as.cipher, as.aesIV, payload)
	}

	packet := make([]byte, 12+len(encrypted))
	copy(packet[:12], header)
	copy(packet[12:], encrypted)

	_, err := as.conn.WriteTo(packet, as.remoteAddr)
	if err != nil {
		return err
	}

	as.seqnum++
	as.rtpTime += uint32(as.spf)
	return nil
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
	as.mu.Unlock()

	// Sync packet: 20 bytes
	// [0]     0x90 (first) or 0x80 (subsequent)
	// [1]     0xd4 (type 0x54 | 0x80)
	// [2:3]   0x00 0x07 (extension length)
	// [4:7]   current RTP time (big-endian)
	// [8:15]  NTP timestamp (big-endian)
	// [16:19] next RTP time (big-endian)
	packet := make([]byte, 20)
	if isFirst {
		packet[0] = 0x90
	} else {
		packet[0] = 0x80
	}
	packet[1] = 0xd4
	packet[2] = 0x00
	packet[3] = 0x07
	binary.BigEndian.PutUint32(packet[4:8], rtpNow)
	binary.BigEndian.PutUint64(packet[8:16], ntpTime)
	binary.BigEndian.PutUint32(packet[16:20], rtpNow+uint32(as.spf))

	_, err := as.ctrlConn.WriteTo(packet, as.ctrlAddr)
	return err
}

func (as *AudioStream) Close() {
	if as.conn != nil {
		as.conn.Close()
	}
	if as.ctrlConn != nil {
		as.ctrlConn.Close()
	}
}

// StreamAudio reads ADTS-framed AAC from the capture pipeline and sends
// RTP audio packets to the receiver. It also sends periodic sync packets.
func (s *MirrorSession) StreamAudio(ctx context.Context, capture *AudioCapture, audioStream *AudioStream) error {
	reader := bufio.NewReaderSize(capture, 32*1024)

	// Send initial sync
	ntpNow := ntpBootTimestamp()
	if err := audioStream.sendSyncPacket(ntpNow, true); err != nil {
		dbg("[AUDIO] initial sync error: %v", err)
	}

	// Periodic sync sender
	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
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
			dbg("[AUDIO] control packet from %s: %d bytes", addr, n)
		}
	}()

	var frameCount int

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read ADTS frame: starts with 0xFF 0xF0-0xFF sync word
		// Find sync word
		b, err := reader.ReadByte()
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("audio capture EOF")
			}
			return fmt.Errorf("audio read: %w", err)
		}
		if b != 0xFF {
			continue
		}
		b2, err := reader.ReadByte()
		if err != nil {
			return fmt.Errorf("audio read: %w", err)
		}
		if b2&0xF0 != 0xF0 {
			continue
		}

		// Read rest of ADTS header (7 bytes total, we have 2)
		adtsHeader := make([]byte, 7)
		adtsHeader[0] = 0xFF
		adtsHeader[1] = b2
		if _, err := io.ReadFull(reader, adtsHeader[2:7]); err != nil {
			return fmt.Errorf("audio read adts header: %w", err)
		}

		// Parse frame length from ADTS header
		// Bits: header[3] lower 2 bits, header[4] all 8 bits, header[5] upper 3 bits
		frameLen := (int(adtsHeader[3]&0x03) << 11) | (int(adtsHeader[4]) << 3) | (int(adtsHeader[5]) >> 5)
		if frameLen < 7 || frameLen > 8192 {
			dbg("[AUDIO] invalid ADTS frame length: %d", frameLen)
			continue
		}

		// Read the AAC payload (frame after ADTS header)
		payloadLen := frameLen - 7
		payload := make([]byte, payloadLen)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return fmt.Errorf("audio read payload: %w", err)
		}

		if err := audioStream.sendAudioPacket(payload); err != nil {
			return fmt.Errorf("audio send: %w", err)
		}

		frameCount++
		if frameCount <= 5 {
			dbg("[AUDIO] sent frame %d: adts_len=%d payload=%d rtp_seq=%d",
				frameCount, frameLen, payloadLen, audioStream.seqnum-1)
		}
	}
}
