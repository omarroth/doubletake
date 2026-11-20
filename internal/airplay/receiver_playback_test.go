package airplay

import (
	"testing"
	"time"
)

func TestReceiverVideoMarker(t *testing.T) {
	const width, height, stride = 104, 3, 112
	const timestamp uint32 = 0xa021d3
	pixels := make([]byte, stride*height)
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			column := x / 4
			pixels[y*stride+x] = 16
			if column == 1 || (column >= 2 && (timestamp>>uint(25-column))&1 != 0) {
				pixels[y*stride+x] = 235
			}
		}
	}
	got, ok := receiverVideoMarker(pixels, width, height, stride)
	if !ok || got != timestamp {
		t.Fatalf("decoded marker = %#x, valid=%t, want %#x", got, ok, timestamp)
	}
	clear(pixels)
	if _, ok := receiverVideoMarker(pixels, width, height, stride); ok {
		t.Fatal("accepted a blank picture as a timestamp")
	}
}

func TestReceiverREDHeaderBounds(t *testing.T) {
	for _, payload := range [][]byte{nil, {0x61}, {0xe0}, {0xe0, 0, 0, 1}, {0xe0, 0, 0, 1, 0x60}, {0xe0, 0, 4, 0, 0x60}} {
		if _, _, _, err := receiverREDHeaders(payload); err == nil {
			t.Fatalf("accepted malformed RED headers %x", payload)
		}
	}
	prefix, offsets, lengths, err := receiverREDHeaders([]byte{0xe0, 5, 0x80, 3, 0x60, 1, 2, 3, 4})
	if err != nil || prefix != 5 || len(offsets) != 1 || offsets[0] != 352 || lengths[0] != 3 {
		t.Fatalf("RED history parsed as %d/%v/%v: %v", prefix, offsets, lengths, err)
	}
}

func TestReceiverVideoConfigurationBounds(t *testing.T) {
	for _, payload := range [][]byte{nil, {1}, {1, 0x42, 0, 30, 0xff, 0, 0}, {1, 0x42, 0, 30, 0xff, 0xe1, 0xff, 0xff}} {
		if _, _, err := receiverVideoConfiguration(payload); err == nil {
			t.Fatalf("accepted invalid decoder configuration %x", payload)
		}
	}
	config := []byte{1, 0x42, 0, 30, 0xff, 0xe1, 0, 2, 0x67, 0x80, 1, 0, 2, 0x68, 0x80, 2, 0, 0, 0}
	codec, data, err := receiverVideoConfiguration(config)
	if err != nil || codec != "h264" || len(data) != 15 {
		t.Fatalf("avcC/trailer parsing = %q/%x: %v", codec, data, err)
	}
}

func TestReceiverNetworkTimestampPrecision(t *testing.T) {
	if got := receiverCompactDuration(uint64(37)<<32 | 0x80000000); got != 37500*time.Millisecond {
		t.Fatalf("compact timestamp=%s", got)
	}
	if got := receiverCompactDuration(1); got != 0 {
		t.Fatalf("fraction rounded up: %s", got)
	}
	if got := receiverCompactDuration(uint64(1)<<32 | 0xffffffff); got != 2*time.Second-time.Nanosecond {
		t.Fatalf("fraction overflowed: %s", got)
	}
}

func TestReceiverVideoChecksumsIgnoreStridePadding(t *testing.T) {
	p := &receiverPlayback{cfg: receiverPlaybackConfig{NetworkNow: bootRelativeNow}, events: make(chan receiverPlayoutEvent, 2)}
	pts := int64(bootRelativeNow() + time.Second)
	p.decodedVideo(receiverDecodedSample{Data: []byte{1, 2, 0xff, 0xff, 3, 4}, Width: 2, Height: 2, Stride: 4, PTS: pts})
	p.decodedVideo(receiverDecodedSample{Data: []byte{1, 2, 0x11, 0x22, 3, 4}, Width: 2, Height: 2, Stride: 4, PTS: pts + 1})
	stats := p.snapshot()
	if stats.VideoChanges != 0 || stats.LastError != "" || p.lastVideoHash != receiverChecksum(0, []byte{1, 2, 3, 4}) {
		t.Fatalf("video padding affected content checks: %+v", stats)
	}
}
