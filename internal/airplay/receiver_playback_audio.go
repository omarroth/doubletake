package airplay

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"time"

	audioaead "github.com/aead/chacha20poly1305"
)

type receiverAudioFrame struct {
	seq       uint16
	rtp       uint32
	data      []byte
	recovered bool
}

type receiverPlaybackAudio struct {
	decoder                    receiverDecoder
	block                      cipher.Block
	aead                       cipher.AEAD
	iv                         []byte
	spf                        uint32
	frames                     map[uint16]receiverAudioFrame
	next                       uint16
	started, anchored, closing bool
	anchorRTP                  uint32
	anchorPTS                  int64
	gapSince, lastResend       time.Time
	initialAt                  time.Time
	resend                     func(uint16, uint16) error
	lastDrop                   uint64
	haveLastRTP                bool
	lastRTP                    uint32
}

func (p *receiverPlayback) configureAudio(codec AudioCodec, key, iv, chacha []byte, resend func(uint16, uint16) error) error {
	p.audioMu.Lock()
	defer p.audioMu.Unlock()
	if p.audio.decoder != nil {
		return fmt.Errorf("receiver audio already configured")
	}
	a := receiverPlaybackAudio{frames: make(map[uint16]receiverAudioFrame), resend: resend, spf: 352}
	var err error
	if len(chacha) != 0 {
		a.aead, err = audioaead.NewCipher(chacha)
	} else if len(key) != 0 {
		if len(iv) != 16 {
			return fmt.Errorf("legacy audio requires a 16-byte IV")
		}
		a.block, err = aes.NewCipher(key)
		a.iv = append([]byte(nil), iv...)
	}
	if err != nil {
		return err
	}
	callbacks := receiverDecodeCallbacks{Sample: p.decodedAudio, Error: p.fail}
	if codec == AudioCodecAACELD {
		a.spf = 480
		a.decoder, err = newReceiverELDDecoder(callbacks)
	} else if codec == AudioCodecALAC {
		a.decoder, err = newReceiverMediaDecoder("alac", receiverALACCookie(), callbacks)
	} else {
		return fmt.Errorf("unsupported playback audio codec %d", codec)
	}
	if err != nil {
		return err
	}
	p.audio = a
	return nil
}

// receiverREDHeaders parses the clear RFC 2198 prefix independently of the
// sender's packet builder. Each length applies to one encrypted-history block.
func receiverREDHeaders(payload []byte) (prefix int, offsets []uint32, lengths []int, err error) {
	for position := 0; ; position += 4 {
		if position >= len(payload) || payload[position]&0x7f != 96 {
			return 0, nil, nil, fmt.Errorf("invalid audio RED header")
		}
		if payload[position]&0x80 == 0 {
			return position + 1, offsets, lengths, nil
		}
		if position+4 >= len(payload) || len(offsets) >= 32 {
			return 0, nil, nil, fmt.Errorf("truncated or excessive RED history")
		}
		offset := uint32(payload[position+1])<<6 | uint32(payload[position+2]>>2)
		size := int(payload[position+2]&3)<<8 | int(payload[position+3])
		if offset == 0 || size == 0 {
			return 0, nil, nil, fmt.Errorf("empty RED history block")
		}
		offsets = append(offsets, offset)
		lengths = append(lengths, size)
	}
}

func (p *receiverPlayback) audioPacket(packet []byte, retransmitted bool) {
	if len(packet) < 12 || packet[0] != 0x80 || (packet[1] != 96 && packet[1] != 97) {
		p.fail(fmt.Errorf("invalid receiver audio RTP packet"))
		return
	}
	seq := binary.BigEndian.Uint16(packet[2:4])
	rtp := binary.BigEndian.Uint32(packet[4:8])
	if !retransmitted && p.cfg.AudioDropEvery > 0 && int(seq)%p.cfg.AudioDropEvery == 0 {
		p.audioMu.Lock()
		id := uint64(rtp)<<16 | uint64(seq)
		if p.audio.lastDrop != id {
			p.audio.lastDrop = id
			p.statsMu.Lock()
			p.stats.AudioDropped++
			p.statsMu.Unlock()
		}
		p.audioMu.Unlock()
		return
	}
	p.audioMu.Lock()
	defer p.audioMu.Unlock()
	a := &p.audio
	if a.decoder == nil || a.closing {
		return
	}
	payload := packet[12:]
	prefix := 0
	var offsets []uint32
	var lengths []int
	var err error
	if packet[1] == 97 {
		prefix, offsets, lengths, err = receiverREDHeaders(payload)
		if err != nil {
			p.fail(err)
			return
		}
	}
	if a.aead != nil {
		if len(payload) < prefix+24 {
			p.audioCryptoError(fmt.Errorf("truncated encrypted audio"))
			return
		}
		nonce := payload[len(payload)-8:]
		plain, e := a.aead.Open(nil, nonce, payload[prefix:len(payload)-8], packet[4:12])
		if e != nil {
			p.audioCryptoError(e)
			return
		}
		payload = plain
	} else {
		payload = append([]byte(nil), payload[prefix:]...)
		if a.block != nil {
			complete := len(payload) / 16 * 16
			cipher.NewCBCDecrypter(a.block, a.iv).CryptBlocks(payload[:complete], payload[:complete])
		}
	}
	frames := make([]receiverAudioFrame, 0, len(offsets)+1)
	for i, offset := range offsets {
		if offset%a.spf != 0 || lengths[i] > len(payload) {
			p.fail(fmt.Errorf("invalid RED sample offset or block length"))
			return
		}
		frames = append(frames, receiverAudioFrame{seq: seq - uint16(offset/a.spf), rtp: rtp - offset, data: append([]byte(nil), payload[:lengths[i]]...), recovered: true})
		payload = payload[lengths[i]:]
	}
	if len(payload) == 0 {
		p.fail(fmt.Errorf("audio packet omitted primary frame"))
		return
	}
	frames = append(frames, receiverAudioFrame{seq: seq, rtp: rtp, data: append([]byte(nil), payload...), recovered: retransmitted})
	if !a.started {
		a.started = true
		a.next = frames[0].seq
		a.initialAt = time.Now()
	}
	for _, frame := range frames {
		if !a.haveLastRTP && int16(frame.seq-a.next) < 0 && int16(frame.seq-a.next) > -512 {
			a.next = frame.seq
		}
		_, queued := a.frames[frame.seq]
		if int16(frame.seq-a.next) < 0 || queued {
			if frame.seq == seq {
				p.statsMu.Lock()
				p.stats.AudioDuplicates++
				p.statsMu.Unlock()
			}
			continue
		}
		if int16(frame.seq-a.next) > 511 || len(a.frames) >= 512 {
			p.statsMu.Lock()
			p.stats.QueueOverruns++
			p.statsMu.Unlock()
			continue
		}
		a.frames[frame.seq] = frame
	}
	p.flushAudioLocked()
}

func (p *receiverPlayback) audioCryptoError(err error) {
	p.statsMu.Lock()
	p.stats.AudioCryptoErrors++
	p.statsMu.Unlock()
	p.fail(fmt.Errorf("audio decryption: %w", err))
}

func (p *receiverPlayback) audioControl(packet []byte) {
	if len(packet) >= 16 && packet[1] == 0xd6 {
		p.audioPacket(packet[4:], true)
		return
	}
	var pts int64
	if len(packet) == 20 && packet[1] == 0xd4 && p.cfg.Timing == timingProtocolNTP {
		pts = int64(receiverCompactDuration(binary.BigEndian.Uint64(packet[8:16]) - (uint64(secondsFrom1900To1970) << 32)))
	} else if len(packet) == 28 && packet[1] == 0xd7 && p.cfg.Timing == timingProtocolPTP {
		if binary.BigEndian.Uint64(packet[20:28]) != p.cfg.Timeline {
			p.statsMu.Lock()
			p.stats.TimestampErrors++
			p.statsMu.Unlock()
			return
		}
		pts = int64(binary.BigEndian.Uint64(packet[8:16]))
	} else {
		return
	}
	p.audioMu.Lock()
	defer p.audioMu.Unlock()
	p.audio.anchorRTP = binary.BigEndian.Uint32(packet[4:8])
	p.audio.anchorPTS = pts
	p.audio.anchored = true
	p.statsMu.Lock()
	p.stats.SyncPackets++
	p.statsMu.Unlock()
	p.flushAudioLocked()
}

func (p *receiverPlayback) flushAudio() {
	p.audioMu.Lock()
	defer p.audioMu.Unlock()
	p.flushAudioLocked()
}

func (p *receiverPlayback) flushAudioLocked() {
	a := &p.audio
	if a.closing || !a.anchored || !a.started || a.decoder == nil {
		return
	}
	// Keep the initial reorder window too: the first datagram received need
	// not contain the first audio frame in the stream.
	if !a.haveLastRTP && time.Since(a.initialAt) < p.cfg.AudioJitter {
		return
	}
	for len(a.frames) > 0 {
		frame, ok := a.frames[a.next]
		if !ok {
			now := time.Now()
			if a.gapSince.IsZero() {
				a.gapSince = now
			}
			if a.resend != nil && now.Sub(a.lastResend) > 20*time.Millisecond {
				if err := a.resend(a.next, 1); err == nil {
					p.statsMu.Lock()
					p.stats.AudioResends++
					p.statsMu.Unlock()
				}
				a.lastResend = now
			}
			if now.Sub(a.gapSince) < p.cfg.AudioJitter {
				return
			}
			p.statsMu.Lock()
			p.stats.AudioLost++
			p.statsMu.Unlock()
			a.next++
			a.gapSince = time.Time{}
			continue
		}
		delete(a.frames, a.next)
		a.next++
		a.gapSince = time.Time{}
		if a.haveLastRTP && int32(frame.rtp-a.lastRTP) <= 0 {
			p.statsMu.Lock()
			p.stats.TimestampErrors++
			p.statsMu.Unlock()
			continue
		}
		if a.haveLastRTP && uint32(frame.rtp-a.lastRTP) > a.spf {
			p.statsMu.Lock()
			p.stats.AudioMissingSamples += uint64(uint32(frame.rtp-a.lastRTP) - a.spf)
			p.statsMu.Unlock()
		}
		a.lastRTP = frame.rtp
		a.haveLastRTP = true
		pts := a.anchorPTS + int64(int32(frame.rtp-a.anchorRTP))*int64(time.Second)/44100
		if err := a.decoder.Push(frame.data, pts); err != nil {
			p.fail(err)
		}
		if frame.recovered {
			p.statsMu.Lock()
			p.stats.AudioRecovered++
			p.statsMu.Unlock()
		}
	}
}
