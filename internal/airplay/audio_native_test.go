package airplay

import (
	"bytes"
	"testing"
	"time"
)

func TestNativePCMSampleClockIgnoresCallbackJitter(t *testing.T) {
	instant := time.Now()
	var n int
	reader := nativePCMFrames{read: func() (nativePCMBlock, error) {
		block := nativePCMBlock{
			samples: make([]byte, 441*audioBytesPerSampleFrame),
			pts:     instant.Add(time.Duration(n)*10*time.Millisecond + time.Duration(n%2)*3*time.Millisecond),
		}
		n++
		return block, nil
	}}
	pcm := make([]byte, 352*audioBytesPerSampleFrame)
	for i := range 12 {
		frame, err := reader.ReadPCMFramePosition(pcm)
		if err != nil {
			t.Fatal(err)
		}
		if !frame.HasSourceRTP || frame.SourceRTP != uint32(i*352) {
			t.Fatalf("frame %d sample position = %+v", i, frame)
		}
	}
}

func TestNativePCMDoesNotJoinAudioAcrossCaptureDiscontinuity(t *testing.T) {
	start := time.Now()
	const blockSamples = 441
	first := bytes.Repeat([]byte{0x11}, blockSamples*audioBytesPerSampleFrame)
	resumed := bytes.Repeat([]byte{0x22}, blockSamples*audioBytesPerSampleFrame)
	blocks := []nativePCMBlock{
		{samples: first, pts: start},
		{samples: resumed, pts: start.Add(20 * time.Millisecond), discontinuity: true},
		{samples: resumed, pts: start.Add(30 * time.Millisecond)},
	}
	reader := nativePCMFrames{read: func() (nativePCMBlock, error) {
		block := blocks[0]
		blocks = blocks[1:]
		return block, nil
	}}
	pcm := make([]byte, 480*audioBytesPerSampleFrame)
	frame, err := reader.ReadPCMFramePosition(pcm)
	if err != nil {
		t.Fatal(err)
	}
	if !frame.PTS.Equal(start.Add(20*time.Millisecond)) || frame.SourceRTP != 2*blockSamples {
		t.Fatalf("resumed frame starts at %+v, want 20 ms and sample %d", frame, 2*blockSamples)
	}
	if !bytes.Equal(pcm, bytes.Repeat([]byte{0x22}, len(pcm))) {
		t.Fatal("codec frame included samples from before the capture glitch")
	}
}
