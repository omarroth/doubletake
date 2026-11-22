package airplay

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"time"
)

type nativePCMBlock struct {
	samples []byte
	pts     time.Time
}

type nativePCMInput struct {
	read   func() (nativePCMBlock, error)
	close  func()
	volume *capturedOutputVolume
}

var openNativeMonitor func(context.Context) (nativePCMInput, error)

func startNativeAudio(ctx context.Context, cancel context.CancelFunc, test bool, codec AudioCodec, route AudioSource) (*AudioCapture, error) {
	var input nativePCMInput
	switch {
	case test:
		tone := &nativeTestTone{ctx: ctx, origin: time.Now()}
		input = nativePCMInput{read: tone.next}
	case route != AudioSourceMonitor:
		return nil, fmt.Errorf("the selectable audio output requires a GStreamer build")
	case openNativeMonitor == nil:
		return nil, fmt.Errorf("desktop audio on this platform requires a GStreamer build")
	default:
		var err error
		input, err = openNativeMonitor(ctx)
		if err != nil {
			return nil, err
		}
	}

	capture := &AudioCapture{
		codec: codec, cancel: cancel, waitCh: make(chan struct{}),
		pcmFrames: &nativePCMFrames{read: input.read}, outputVolume: input.volume,
	}
	if codec == AudioCodecAACELD {
		var err error
		capture.eld, err = newELDEncoder()
		if err != nil {
			if input.close != nil {
				input.close()
			}
			return nil, err
		}
	} else {
		capture.alac = &alacEncoder{}
	}
	go func() {
		<-ctx.Done()
		if input.close != nil {
			input.close()
		}
		close(capture.waitCh)
	}()
	return capture, nil
}

// Assemble codec frames across native callback boundaries. Preserve each
// block's first-sample time and never splice across a capture discontinuity.
type nativePCMFrames struct {
	read     func() (nativePCMBlock, error)
	block    nativePCMBlock
	consumed int
	position uint32
}

func (r *nativePCMFrames) ReadPCMFrame(dst []byte) (time.Time, error) {
	position, err := r.ReadPCMFramePosition(dst)
	return position.PTS, err
}

func (r *nativePCMFrames) ReadPCMFramePosition(dst []byte) (audioPCMFramePosition, error) {
	if len(dst) == 0 || len(dst)%audioBytesPerSampleFrame != 0 {
		return audioPCMFramePosition{}, fmt.Errorf("native PCM frame size %d is not whole stereo samples", len(dst))
	}
	var start audioPCMFramePosition
	written := 0
	for written < len(dst) {
		if r.consumed == len(r.block.samples) {
			block, err := r.read()
			if err != nil {
				return audioPCMFramePosition{}, err
			}
			if len(block.samples) == 0 || len(block.samples)%audioBytesPerSampleFrame != 0 || block.pts.IsZero() {
				return audioPCMFramePosition{}, fmt.Errorf("invalid native PCM block")
			}
			if !r.block.pts.IsZero() {
				expected := r.block.pts.Add(audioSamplesDuration(uint64(r.consumed / audioBytesPerSampleFrame)))
				if gap := block.pts.Sub(expected); gap < -30*time.Millisecond || gap > 30*time.Millisecond {
					if gap > 0 {
						r.position += uint32(durationToAudioSamples(gap))
					}
					written = 0
				}
			}
			r.block, r.consumed = block, 0
		}
		if written == 0 {
			start = audioPCMFramePosition{
				PTS:       r.block.pts.Add(audioSamplesDuration(uint64(r.consumed / audioBytesPerSampleFrame))),
				SourceRTP: r.position, HasSourceRTP: true,
			}
		}
		n := copy(dst[written:], r.block.samples[r.consumed:])
		r.consumed += n
		r.position += uint32(n / audioBytesPerSampleFrame)
		written += n
	}
	return start, nil
}

type nativeTestTone struct {
	ctx    context.Context
	origin time.Time
	sample uint64
}

func (t *nativeTestTone) next() (nativePCMBlock, error) {
	const blockSamples = audioSampleRate / 100
	pts := t.origin.Add(audioSamplesDuration(t.sample))
	if err := waitForMediaPTS(t.ctx, pts.Add(audioSamplesDuration(blockSamples))); err != nil {
		return nativePCMBlock{}, err
	}
	data := make([]byte, blockSamples*audioBytesPerSampleFrame)
	for offset := 0; offset < len(data); offset += audioBytesPerSampleFrame {
		position := float64(t.sample % audioSampleRate)
		sample := uint16(int16(32767 * 0.01 * math.Sin(2*math.Pi*440*position/audioSampleRate)))
		binary.LittleEndian.PutUint16(data[offset:], sample)
		binary.LittleEndian.PutUint16(data[offset+audioBytesPerSample:], sample)
		t.sample++
	}
	return nativePCMBlock{samples: data, pts: pts}, nil
}
