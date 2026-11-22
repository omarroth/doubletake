//go:build cgo && no_gstreamer

package airplay

/*
#cgo LDFLAGS: -lole32 -luuid
#include <stdint.h>
typedef struct DTLoopback DTLoopback;
DTLoopback *dt_loopback_open(int32_t *status);
int32_t dt_loopback_pull(DTLoopback *capture, const void **bytes, int *size, int64_t *age);
void dt_loopback_close(DTLoopback *capture);
*/
import "C"

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"time"
	"unsafe"
)

func init() { openNativeMonitor = openWindowsMonitor }

func openWindowsMonitor(lifetime context.Context) (nativePCMInput, error) {
	ctx, cancel := context.WithCancel(lifetime)
	started := make(chan error, 1)
	ended := make(chan struct{})
	blocks := make(chan nativePCMBlock, 24)
	var failure error
	go func() {
		defer close(ended)
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		var status C.int32_t
		capture := C.dt_loopback_open(&status)
		if capture == nil {
			started <- fmt.Errorf("start WASAPI loopback: HRESULT 0x%08x", uint32(status))
			return
		}
		defer C.dt_loopback_close(capture)
		started <- nil

		var nextPTS time.Time
		lastPacket := time.Now()
		for ctx.Err() == nil {
			var data unsafe.Pointer
			var size C.int
			var age C.int64_t
			status := C.dt_loopback_pull(capture, &data, &size, &age)
			if status < 0 {
				failure = fmt.Errorf("read WASAPI loopback: HRESULT 0x%08x", uint32(status))
				return
			}

			now := time.Now()
			var block nativePCMBlock
			if size > 0 {
				block = nativePCMBlock{samples: C.GoBytes(data, size), pts: now.Add(-time.Duration(age) * 100)}
				lastPacket = now
			} else {
				// The Windows audio engine may suspend a quiet endpoint.
				// Keep an established stream clock running through silence.
				if now.Sub(lastPacket) < 40*time.Millisecond {
					continue
				}
				pts := nextPTS
				if pts.IsZero() || now.Sub(pts) > 40*time.Millisecond {
					pts = now.Add(-10 * time.Millisecond)
				}
				if now.Before(pts.Add(10 * time.Millisecond)) {
					continue
				}
				block = nativePCMBlock{samples: make([]byte, audioSampleRate/100*audioBytesPerSampleFrame), pts: pts}
			}
			nextPTS = block.pts.Add(audioSamplesDuration(uint64(len(block.samples) / audioBytesPerSampleFrame)))
			select {
			case blocks <- block:
			default:
				select {
				case <-blocks:
				default:
				}
				blocks <- block
			}
		}
	}()
	select {
	case err := <-started:
		if err != nil {
			cancel()
			return nativePCMInput{}, err
		}
	case <-ctx.Done():
		cancel()
		return nativePCMInput{}, ctx.Err()
	}
	return nativePCMInput{
		read: func() (nativePCMBlock, error) {
			select {
			case <-ctx.Done():
				return nativePCMBlock{}, ctx.Err()
			case block := <-blocks:
				return block, nil
			case <-ended:
				if failure == nil {
					return nativePCMBlock{}, io.EOF
				}
				return nativePCMBlock{}, failure
			}
		},
		close: func() {
			cancel()
			<-ended
		},
	}, nil
}
