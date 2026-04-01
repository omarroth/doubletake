package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"time"
)

// ReplayConfig holds parameters for replaying a captured data channel.
type ReplayConfig struct {
	CaptureFile string // path to raw data channel binary
	AESKeyHex   string // 16-byte AES key hex (after ecdh hash, before SHA-512 derivation)
	SCID        uint64 // streamConnectionID from the original capture
}

// capturedFrame represents one frame from the data channel capture.
type capturedFrame struct {
	header       [128]byte
	payload      []byte // raw (encrypted for VCL, plaintext for codec/heartbeat)
	payloadType  byte
	payloadSize  int
	ntpTimestamp uint64
}

// parseCaptureFrames parses a raw data channel binary into frames.
func parseCaptureFrames(data []byte) ([]capturedFrame, error) {
	var frames []capturedFrame
	offset := 0
	for offset+128 <= len(data) {
		var hdr [128]byte
		copy(hdr[:], data[offset:offset+128])
		payloadSize := int(binary.LittleEndian.Uint32(hdr[0:4]))
		if payloadSize < 0 || payloadSize > 10*1024*1024 {
			return nil, fmt.Errorf("invalid payload size %d at offset 0x%x", payloadSize, offset)
		}
		if offset+128+payloadSize > len(data) {
			return nil, fmt.Errorf("truncated frame at offset 0x%x: need %d, have %d",
				offset, payloadSize, len(data)-offset-128)
		}
		payload := make([]byte, payloadSize)
		copy(payload, data[offset+128:offset+128+payloadSize])

		frames = append(frames, capturedFrame{
			header:       hdr,
			payload:      payload,
			payloadType:  hdr[4],
			payloadSize:  payloadSize,
			ntpTimestamp: binary.LittleEndian.Uint64(hdr[8:16]),
		})
		offset += 128 + payloadSize
	}
	return frames, nil
}

// newCaptureDecrypter creates a mirrorCipher-compatible decrypter for the original capture.
func newCaptureDecrypter(aesKeyHex string, scid uint64) (*mirrorCipher, error) {
	aesKey, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode aes key: %w", err)
	}
	if len(aesKey) != 16 {
		return nil, fmt.Errorf("aes key must be 16 bytes, got %d", len(aesKey))
	}

	cipherKey, cipherIV := deriveVideoKeys(aesKey, int64(scid))
	log.Printf("[REPLAY] original capture cipher key: %02x", cipherKey)
	log.Printf("[REPLAY] original capture cipher IV:  %02x", cipherIV)

	block, err := aes.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	return &mirrorCipher{
		stream: cipher.NewCTR(block, cipherIV),
	}, nil
}

// ReplayFrames reads a captured AirMyPC data channel binary, decrypts VCL payloads
// with the original key, re-encrypts with this session's key, and sends to the receiver.
// Headers are sent exactly as captured (timestamps rebased to current time).
// This isolates whether the issue is our H.264 content vs the protocol/encryption.
func (s *MirrorSession) ReplayFrames(ctx context.Context, cfg ReplayConfig) error {
	data, err := os.ReadFile(cfg.CaptureFile)
	if err != nil {
		return fmt.Errorf("read capture: %w", err)
	}
	log.Printf("[REPLAY] loaded %d bytes from %s", len(data), cfg.CaptureFile)

	frames, err := parseCaptureFrames(data)
	if err != nil {
		return fmt.Errorf("parse capture: %w", err)
	}
	log.Printf("[REPLAY] parsed %d frames", len(frames))

	// Create decrypter for the original capture's encryption
	decrypter, err := newCaptureDecrypter(cfg.AESKeyHex, cfg.SCID)
	if err != nil {
		return fmt.Errorf("create decrypter: %w", err)
	}

	// Count frame types
	var codecCount, vclCount, hbCount, otherCount int
	for _, f := range frames {
		switch f.payloadType {
		case 0x01:
			codecCount++
		case 0x00:
			vclCount++
		case 0x02:
			hbCount++
		default:
			otherCount++
		}
	}
	log.Printf("[REPLAY] frame types: codec=%d VCL=%d heartbeat=%d other=%d",
		codecCount, vclCount, hbCount, otherCount)

	// Compute timestamp rebasing: map original timestamps to current time
	var firstOrigTS uint64
	for _, f := range frames {
		if f.ntpTimestamp > 0 {
			firstOrigTS = f.ntpTimestamp
			break
		}
	}
	baseTS := ntpTimeNow()
	log.Printf("[REPLAY] rebasing timestamps: orig_base=%d -> new_base=%d", firstOrigTS, baseTS)

	frameInterval := time.Second / 30 // ~33ms
	var lastSendTime time.Time
	sentFrames := 0

	for i, f := range frames {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Rebase timestamp
		var newTS uint64
		if f.ntpTimestamp > 0 && firstOrigTS > 0 {
			delta := f.ntpTimestamp - firstOrigTS
			newTS = baseTS + delta
		}

		switch f.payloadType {
		case 0x01: // Codec frame (unencrypted) — send with rebased timestamp
			header := f.header
			binary.LittleEndian.PutUint64(header[8:16], newTS)

			frame := make([]byte, 128+len(f.payload))
			copy(frame[:128], header[:])
			copy(frame[128:], f.payload)

			log.Printf("[REPLAY] sending codec frame %d: payLen=%d ts=%d", i, len(f.payload), newTS)
			log.Printf("[REPLAY] codec header: %02x", header[:16])
			log.Printf("[REPLAY] codec payload: %02x", f.payload)

			s.dataMu.Lock()
			s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writeFull(s.dataConn, frame)
			s.dataMu.Unlock()
			if err != nil {
				return fmt.Errorf("send codec frame %d: %w", i, err)
			}

			// Signal first frame sent (unblocks heartbeat/feedback)
			select {
			case <-s.firstFrameSent:
			default:
				close(s.firstFrameSent)
			}

		case 0x00: // VCL frame (encrypted) — decrypt with original key, re-encrypt with session key
			// Pace frames
			if !lastSendTime.IsZero() {
				elapsed := time.Since(lastSendTime)
				if elapsed < frameInterval {
					time.Sleep(frameInterval - elapsed)
				}
			}
			lastSendTime = time.Now()

			// Decrypt with original capture's cipher
			plaintext := decrypter.EncryptFrame(f.payload) // XOR is symmetric

			if sentFrames < 5 {
				dispLen := len(plaintext)
				if dispLen > 32 {
					dispLen = 32
				}
				log.Printf("[REPLAY] frame %d decrypted[0:%d]: %02x", i, dispLen, plaintext[:dispLen])
			}

			// Re-encrypt with this session's cipher
			var ciphertext []byte
			if s.streamCipher != nil {
				ciphertext = s.streamCipher(plaintext)
			} else {
				ciphertext = plaintext
			}

			// Build frame with rebased timestamp but original header format
			header := f.header
			binary.LittleEndian.PutUint64(header[8:16], newTS)

			frame := make([]byte, 128+len(ciphertext))
			copy(frame[:128], header[:])
			copy(frame[128:], ciphertext)

			if sentFrames < 5 {
				log.Printf("[REPLAY] sending VCL frame %d: payLen=%d ts=%d hdr[4:8]=%02x",
					i, len(ciphertext), newTS, header[4:8])
				log.Printf("[REPLAY] VCL header: %02x", header[:64])
			}

			s.dataMu.Lock()
			s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writeFull(s.dataConn, frame)
			s.dataMu.Unlock()
			if err != nil {
				return fmt.Errorf("send VCL frame %d (sent=%d): %w", i, sentFrames, err)
			}
			sentFrames++

		case 0x02: // Heartbeat — send as-is
			s.dataMu.Lock()
			s.dataConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writeFull(s.dataConn, f.header[:])
			s.dataMu.Unlock()
			if err != nil {
				return fmt.Errorf("send heartbeat frame %d: %w", i, err)
			}

		default:
			log.Printf("[REPLAY] skipping unknown frame type 0x%02x at index %d", f.payloadType, i)
		}
	}

	log.Printf("[REPLAY] done: sent %d VCL frames, %d total frames", sentFrames, len(frames))

	// Keep connection alive for a bit to see if Apple TV stays connected
	log.Printf("[REPLAY] waiting 10s to observe connection stability...")
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(10 * time.Second):
	}

	return nil
}
