package airplay

import (
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
