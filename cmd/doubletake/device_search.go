package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode"

	"doubletake/internal/airplay"
)

const deviceSearchRetryInterval = time.Second

type stableDeviceList struct {
	devices []airplay.AirPlayDevice
	index   map[string]int
}

func (l *stableDeviceList) upsert(device airplay.AirPlayDevice) (index int, added, displayChanged bool) {
	if l.index == nil {
		l.index = make(map[string]int)
	}
	key := deviceSearchKey(device)
	if index, ok := l.index[key]; ok {
		previous := l.devices[index]
		displayChanged = previous.Name != device.Name ||
			previous.Model != device.Model ||
			previous.IP != device.IP ||
			previous.Port != device.Port
		l.devices[index] = device
		return index, false, displayChanged
	}
	index = len(l.devices)
	l.index[key] = index
	l.devices = append(l.devices, device)
	return index, true, true
}

func deviceSearchKey(device airplay.AirPlayDevice) string {
	if id := strings.TrimSpace(device.DeviceID); id != "" {
		return "device:" + strings.ToLower(id)
	}
	if name := strings.TrimSpace(device.Name); name != "" {
		return fmt.Sprintf("service:%s:%d", strings.ToLower(name), device.Port)
	}
	return fmt.Sprintf("address:%s:%d", strings.ToLower(device.IP), device.Port)
}

func canUseDynamicDeviceSearch() bool {
	stdin, stdinErr := os.Stdin.Stat()
	stdout, stdoutErr := os.Stdout.Stat()
	return stdinErr == nil && stdoutErr == nil &&
		stdin.Mode()&os.ModeCharDevice != 0 && stdout.Mode()&os.ModeCharDevice != 0
}

// selectDeviceDynamically keeps normal cooked-terminal input and only uses a
// carriage return to animate one status line. That makes Ctrl+C remain a normal
// signal and avoids tying discovery to Unix terminal-control APIs.
func selectDeviceDynamically(ctx context.Context) (*airplay.AirPlayDevice, error) {
	searchCtx, cancelSearch := context.WithCancel(ctx)
	defer cancelSearch()

	updates := make(chan airplay.AirPlayDevice, 16)
	browseErrors := make(chan error, 1)
	go browseAirPlayContinuously(searchCtx, updates, browseErrors, airplay.BrowseAirPlayDevices)

	ready := make(chan error, 1)
	readDeviceSearchReady(ready)

	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()

	var devices stableDeviceList
	var lastDiscoveryWarning string
	status := newDeviceSearchStatus(os.Stdout)
	defer status.finish()
	fmt.Fprintln(os.Stdout, "available devices:")
	status.draw(0, len(devices.devices))
	frame := 0

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case device := <-updates:
			index, added, changed := devices.upsert(device)
			lastDiscoveryWarning = ""
			if added || changed {
				status.clear()
				printDiscoveredDevice(os.Stdout, index, device, !added)
				status.draw(frame, len(devices.devices))
			}
		case err := <-browseErrors:
			warning := safeTerminalText(err.Error())
			if warning == lastDiscoveryWarning {
				continue
			}
			lastDiscoveryWarning = warning
			status.clear()
			fmt.Fprintf(os.Stdout, "discovery warning: %s; retrying\n", warning)
			status.draw(frame, len(devices.devices))
		case err := <-ready:
			if errors.Is(err, io.EOF) {
				return nil, context.Canceled
			}
			if err != nil {
				return nil, fmt.Errorf("wait for device selection: %w", err)
			}
			if len(devices.devices) == 0 {
				status.clear()
				fmt.Fprintln(os.Stdout, "no receivers are available yet; continuing to search")
				status.draw(frame, 0)
				readDeviceSearchReady(ready)
				continue
			}

			cancelSearch()
			status.clear()
			fmt.Fprintln(os.Stdout)
			return readDeviceSelection(devices.devices)
		case <-ticker.C:
			frame++
			status.draw(frame, len(devices.devices))
		}
	}
}

type airPlayBrowser func(context.Context, func(airplay.AirPlayDevice)) error

func browseAirPlayContinuously(ctx context.Context, updates chan<- airplay.AirPlayDevice, browseErrors chan<- error, browse airPlayBrowser) {
	for {
		err := browse(ctx, func(device airplay.AirPlayDevice) {
			select {
			case updates <- device:
			case <-ctx.Done():
			}
		})
		if ctx.Err() != nil {
			return
		}
		if err == nil {
			err = errors.New("mDNS browse stopped unexpectedly")
		}
		select {
		case browseErrors <- err:
		default:
		}

		timer := time.NewTimer(deviceSearchRetryInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func readDeviceSearchReady(result chan<- error) {
	go func() {
		var input [1]byte
		for {
			n, err := os.Stdin.Read(input[:])
			if n > 0 && (input[0] == '\n' || input[0] == '\r') {
				result <- nil
				return
			}
			if err != nil {
				result <- err
				return
			}
		}
	}()
}

type deviceSearchStatus struct {
	out       io.Writer
	lastWidth int
}

func newDeviceSearchStatus(out io.Writer) *deviceSearchStatus {
	return &deviceSearchStatus{out: out}
}

func (s *deviceSearchStatus) draw(frame, deviceCount int) {
	frames := [...]byte{'|', '/', '-', '\\'}
	var line string
	if deviceCount == 0 {
		line = fmt.Sprintf("searching for AirPlay receivers... %c", frames[frame%len(frames)])
	} else {
		line = fmt.Sprintf("searching, select receiver [1]... %c", frames[frame%len(frames)])
	}
	padding := s.lastWidth - len(line)
	if padding < 0 {
		padding = 0
	}
	fmt.Fprintf(s.out, "\r%s%s", line, strings.Repeat(" ", padding))
	s.lastWidth = len(line)
}

func (s *deviceSearchStatus) clear() {
	if s.lastWidth == 0 {
		return
	}
	fmt.Fprintf(s.out, "\r%s\r", strings.Repeat(" ", s.lastWidth))
	s.lastWidth = 0
}

func (s *deviceSearchStatus) finish() {
	if s.lastWidth == 0 {
		return
	}
	s.clear()
	fmt.Fprintln(s.out)
}

func printDiscoveredDevice(out io.Writer, index int, device airplay.AirPlayDevice, updated bool) {
	name := safeTerminalText(device.Name)
	if name == "" {
		name = safeTerminalText(device.IP)
	}
	model := safeTerminalText(device.Model)
	suffix := ""
	if updated {
		suffix = " (updated)"
	}
	if model == "" {
		fmt.Fprintf(out, "  [%d] %s - %s%s\n", index+1, name, safeTerminalText(device.IP), suffix)
		return
	}
	fmt.Fprintf(out, "  [%d] %s (%s) - %s%s\n", index+1, name, model, safeTerminalText(device.IP), suffix)
}

func safeTerminalText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return '?'
		}
		return r
	}, value)
}
