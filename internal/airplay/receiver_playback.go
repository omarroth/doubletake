package airplay

import (
	"bytes"
	"container/heap"
	"encoding/binary"
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// ReceiverPlaybackStats describes decoded content and simulated presentation.
// Packet receipt is deliberately separate from decoding and presentation.
type ReceiverPlaybackStats struct {
	VideoDecoded, VideoPlayed, VideoChanges                                uint64
	VideoChecksum                                                          uint64
	LastVideoHash                                                          uint64
	LastVideoDeadline                                                      int64
	VideoWidth, VideoHeight                                                int
	AudioDecoded, AudioSamples, AudioPlayedSamples                         uint64
	AudioChecksum                                                          uint64
	AudioPeak                                                              uint32
	AudioSquares                                                           float64
	AudioDuplicates, AudioRecovered, AudioDropped, AudioLost, AudioResends uint64
	AudioMissingSamples                                                    uint64
	AudioCryptoErrors, DecodeErrors, TimestampErrors, QueueOverruns        uint64
	VideoLate, AudioLate                                                   uint64
	MaxLateness, MaxAVSkew                                                 time.Duration
	SyncPackets                                                            uint64
	LastError                                                              string
}

func (s *ReceiverPlaybackStats) add(o ReceiverPlaybackStats) {
	s.VideoDecoded += o.VideoDecoded
	s.VideoPlayed += o.VideoPlayed
	s.VideoChanges += o.VideoChanges
	s.VideoChecksum ^= o.VideoChecksum
	if o.LastVideoDeadline > s.LastVideoDeadline {
		s.LastVideoDeadline = o.LastVideoDeadline
		s.LastVideoHash = o.LastVideoHash
	}
	if o.VideoWidth > s.VideoWidth {
		s.VideoWidth = o.VideoWidth
	}
	if o.VideoHeight > s.VideoHeight {
		s.VideoHeight = o.VideoHeight
	}
	s.AudioDecoded += o.AudioDecoded
	s.AudioSamples += o.AudioSamples
	s.AudioPlayedSamples += o.AudioPlayedSamples
	s.AudioChecksum ^= o.AudioChecksum
	s.AudioSquares += o.AudioSquares
	if o.AudioPeak > s.AudioPeak {
		s.AudioPeak = o.AudioPeak
	}
	s.AudioDuplicates += o.AudioDuplicates
	s.AudioRecovered += o.AudioRecovered
	s.AudioDropped += o.AudioDropped
	s.AudioLost += o.AudioLost
	s.AudioMissingSamples += o.AudioMissingSamples
	s.AudioResends += o.AudioResends
	s.AudioCryptoErrors += o.AudioCryptoErrors
	s.DecodeErrors += o.DecodeErrors
	s.TimestampErrors += o.TimestampErrors
	s.QueueOverruns += o.QueueOverruns
	s.VideoLate += o.VideoLate
	s.AudioLate += o.AudioLate
	s.SyncPackets += o.SyncPackets
	if o.MaxLateness > s.MaxLateness {
		s.MaxLateness = o.MaxLateness
	}
	if o.MaxAVSkew > s.MaxAVSkew {
		s.MaxAVSkew = o.MaxAVSkew
	}
	if s.LastError == "" {
		s.LastError = o.LastError
	}
}

type receiverPlaybackConfig struct {
	NetworkNow     func() time.Duration
	Timing         string
	Timeline       uint64
	AudioDropEvery int
	AudioJitter    time.Duration
	VideoProbe     func(uint32, time.Time)
	AudioProbe     func(uint64, time.Time, time.Time)
}

type receiverPlayback struct {
	cfg           receiverPlaybackConfig
	statsMu       sync.Mutex
	stats         ReceiverPlaybackStats
	videoMu       sync.Mutex
	video         receiverDecoder
	videoConfig   []byte
	lastVideoHash uint64
	lastVideoPTS  int64
	haveVideoPTS  bool
	audioMu       sync.Mutex
	audio         receiverPlaybackAudio
	events        chan receiverPlayoutEvent
	stop, done    chan struct{}
	closeOnce     sync.Once
	ntpOffset     atomic.Int64
}

func newReceiverPlayback(cfg receiverPlaybackConfig) (*receiverPlayback, error) {
	if cfg.NetworkNow == nil {
		cfg.NetworkNow = bootRelativeNow
	}
	if !receiverDecoderAvailable() {
		return nil, fmt.Errorf("headless playback requires make doubletake-test-receiver (gstreamer_cgo)")
	}
	if cfg.AudioDropEvery < 0 || cfg.AudioDropEvery == 1 {
		return nil, fmt.Errorf("audio loss interval must be 0 or at least 2")
	}
	if cfg.AudioJitter == 0 {
		cfg.AudioJitter = 50 * time.Millisecond
	}
	if cfg.AudioJitter < 0 || cfg.AudioJitter > time.Second {
		return nil, fmt.Errorf("audio jitter buffer must be between 0 and 1s")
	}
	p := &receiverPlayback{cfg: cfg, events: make(chan receiverPlayoutEvent, 512), stop: make(chan struct{}), done: make(chan struct{})}
	go p.run()
	return p, nil
}

func receiverChecksum(previous uint64, data []byte) uint64 {
	if previous == 0 {
		previous = 14695981039346656037
	}
	for _, v := range data {
		previous = (previous ^ uint64(v)) * 1099511628211
	}
	return previous
}

func (p *receiverPlayback) fail(err error) {
	if err == nil {
		return
	}
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	p.stats.DecodeErrors++
	if p.stats.LastError == "" {
		p.stats.LastError = err.Error()
	}
}

func (p *receiverPlayback) snapshot() ReceiverPlaybackStats {
	p.statsMu.Lock()
	defer p.statsMu.Unlock()
	return p.stats
}

func (p *receiverPlayback) configureVideo(data []byte) error {
	codec, config, err := receiverVideoConfiguration(data)
	if err != nil {
		p.fail(err)
		return err
	}
	p.videoMu.Lock()
	defer p.videoMu.Unlock()
	if p.video != nil && bytes.Equal(config, p.videoConfig) {
		return nil
	}
	if p.video != nil {
		_ = p.video.Close()
		p.video = nil
	}
	decoder, err := newReceiverMediaDecoder(codec, config, receiverDecodeCallbacks{Sample: p.decodedVideo, Error: p.fail})
	if err != nil {
		p.fail(err)
		return err
	}
	p.video = decoder
	p.videoConfig = config
	return nil
}

func (p *receiverPlayback) videoFrame(data []byte, timestamp, timeline uint64) error {
	if p.cfg.Timing == timingProtocolPTP && timeline != p.cfg.Timeline {
		p.statsMu.Lock()
		p.stats.TimestampErrors++
		p.statsMu.Unlock()
		return fmt.Errorf("video timeline %x differs from negotiated %x", timeline, p.cfg.Timeline)
	}
	p.videoMu.Lock()
	defer p.videoMu.Unlock()
	if p.video == nil {
		return fmt.Errorf("video arrived before decoder configuration")
	}
	return p.video.Push(data, int64(receiverCompactDuration(timestamp)))
}

func receiverCompactDuration(value uint64) time.Duration {
	return time.Duration(value>>32)*time.Second + time.Duration((value&0xffffffff)*uint64(time.Second)>>32)
}

func (p *receiverPlayback) decodedVideo(sample receiverDecodedSample) {
	stride := sample.Stride
	if stride == 0 {
		stride = sample.Width
	}
	if sample.Width <= 0 || sample.Height <= 0 || stride < sample.Width || sample.Height > 16384 || stride > 1<<20 || (sample.Height-1)*stride+sample.Width > len(sample.Data) {
		p.fail(fmt.Errorf("invalid decoded GRAY8 video layout"))
		return
	}
	var checksum uint64
	for row := 0; row < sample.Height; row++ {
		checksum = receiverChecksum(checksum, sample.Data[row*stride:row*stride+sample.Width])
	}
	p.statsMu.Lock()
	if p.haveVideoPTS && sample.PTS <= p.lastVideoPTS {
		p.stats.TimestampErrors++
	}
	p.haveVideoPTS = true
	p.lastVideoPTS = sample.PTS
	if p.stats.VideoDecoded > 0 && checksum != p.lastVideoHash {
		p.stats.VideoChanges++
	}
	p.lastVideoHash = checksum
	p.stats.VideoDecoded++
	for row := 0; row < sample.Height; row++ {
		p.stats.VideoChecksum = receiverChecksum(p.stats.VideoChecksum, sample.Data[row*stride:row*stride+sample.Width])
	}
	p.stats.VideoWidth = sample.Width
	p.stats.VideoHeight = sample.Height
	p.statsMu.Unlock()
	event := receiverPlayoutEvent{video: true, pts: sample.PTS, hash: checksum}
	if p.cfg.VideoProbe != nil {
		event.marker, event.hasMarker = receiverVideoMarker(sample.Data, sample.Width, sample.Height, stride)
	}
	p.schedule(event)
}

// The desktop test draws 26 vertical bars. The first two calibrate the
// luminance threshold after encoding and decoding.
func receiverVideoMarker(data []byte, width, height, stride int) (uint32, bool) {
	const bars = 26
	if width < 2*bars {
		return 0, false
	}
	brightness := func(column int) int {
		x := (2*column + 1) * width / (2 * bars)
		return int(data[(height/2)*stride+x])
	}
	black, white := brightness(0), brightness(1)
	if white-black < 128 {
		return 0, false
	}
	var marker uint32
	for column := 2; column < bars; column++ {
		marker <<= 1
		if brightness(column) > (black+white)/2 {
			marker |= 1
		}
	}
	return marker, true
}

func (p *receiverPlayback) decodedAudio(sample receiverDecodedSample) {
	if len(sample.Data)%4 != 0 {
		p.fail(fmt.Errorf("decoded audio is not stereo S16LE"))
		return
	}
	count := uint64(len(sample.Data) / 4)
	p.statsMu.Lock()
	p.stats.AudioDecoded++
	p.stats.AudioSamples += count
	p.stats.AudioChecksum = receiverChecksum(p.stats.AudioChecksum, sample.Data)
	for i := 0; i < len(sample.Data); i += 2 {
		value := int32(int16(binary.LittleEndian.Uint16(sample.Data[i:])))
		absolute := value
		if absolute < 0 {
			absolute = -absolute
		}
		if uint32(absolute) > p.stats.AudioPeak {
			p.stats.AudioPeak = uint32(absolute)
		}
		p.stats.AudioSquares += float64(value) * float64(value)
	}
	p.statsMu.Unlock()
	event := receiverPlayoutEvent{pts: sample.PTS, samples: count}
	if p.cfg.AudioProbe != nil {
		event.hash = receiverChecksum(0, sample.Data)
	}
	p.schedule(event)
}

type receiverPlayoutEvent struct {
	video     bool
	marker    uint32
	hasMarker bool
	hash      uint64
	pts       int64
	samples   uint64
	deadline  time.Time
}
type receiverPlayoutQueue []receiverPlayoutEvent

func (q receiverPlayoutQueue) Len() int           { return len(q) }
func (q receiverPlayoutQueue) Less(i, j int) bool { return q[i].deadline.Before(q[j].deadline) }
func (q receiverPlayoutQueue) Swap(i, j int)      { q[i], q[j] = q[j], q[i] }
func (q *receiverPlayoutQueue) Push(v any)        { *q = append(*q, v.(receiverPlayoutEvent)) }
func (q *receiverPlayoutQueue) Pop() any {
	old := *q
	v := old[len(old)-1]
	*q = old[:len(old)-1]
	return v
}

func (p *receiverPlayback) schedule(event receiverPlayoutEvent) {
	delta := time.Duration(event.pts) - p.cfg.NetworkNow() - time.Duration(p.ntpOffset.Load())
	if event.pts < 0 || delta < -5*time.Second || delta > 5*time.Second {
		p.statsMu.Lock()
		p.stats.TimestampErrors++
		p.statsMu.Unlock()
		return
	}
	event.deadline = time.Now().Add(delta)
	select {
	case p.events <- event:
	default:
		p.statsMu.Lock()
		p.stats.QueueOverruns++
		p.statsMu.Unlock()
	}
}

func (p *receiverPlayback) run() {
	defer close(p.done)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	var queue receiverPlayoutQueue
	var videoPTS, audioPTS int64
	var haveVideo, haveAudio bool
	for {
		select {
		case <-p.stop:
			return
		case event := <-p.events:
			if len(queue) < 512 {
				heap.Push(&queue, event)
			} else {
				p.statsMu.Lock()
				p.stats.QueueOverruns++
				p.statsMu.Unlock()
			}
		case <-ticker.C:
			p.flushAudio()
		}
		for len(queue) > 0 && !queue[0].deadline.After(time.Now()) {
			event := heap.Pop(&queue).(receiverPlayoutEvent)
			presented := time.Now()
			late := presented.Sub(event.deadline)
			p.statsMu.Lock()
			if event.video {
				p.stats.VideoPlayed++
				p.stats.LastVideoHash = event.hash
				p.stats.LastVideoDeadline = event.deadline.UnixNano()
				videoPTS = event.pts
				haveVideo = true
			} else {
				p.stats.AudioPlayedSamples += event.samples
				audioPTS = event.pts + int64(event.samples)*int64(time.Second)/44100
				haveAudio = true
			}
			if late > 10*time.Millisecond {
				if event.video {
					p.stats.VideoLate++
				} else {
					p.stats.AudioLate++
				}
			}
			if late > p.stats.MaxLateness {
				p.stats.MaxLateness = late
			}
			if haveVideo && haveAudio {
				skew := time.Duration(math.Abs(float64(videoPTS - audioPTS)))
				if skew > p.stats.MaxAVSkew {
					p.stats.MaxAVSkew = skew
				}
			}
			p.statsMu.Unlock()
			if event.hasMarker {
				p.cfg.VideoProbe(event.marker, presented)
			}
			if !event.video && p.cfg.AudioProbe != nil {
				p.cfg.AudioProbe(event.hash, event.deadline, presented)
			}
		}
	}
}

func (p *receiverPlayback) Close() {
	p.closeOnce.Do(func() {
		p.audioMu.Lock()
		p.audio.closing = true
		audio := p.audio.decoder
		p.audioMu.Unlock()
		p.videoMu.Lock()
		if p.video != nil {
			_ = p.video.Close()
		}
		p.videoMu.Unlock()
		if audio != nil {
			_ = audio.Close()
		}
		close(p.stop)
		<-p.done
	})
}
