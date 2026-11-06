package main

import (
	"bufio"
	"bytes"
	"strings"
	"testing"

	"doubletake/internal/airplay"
)

func TestDeviceSearchSelectionReadsOneSelection(t *testing.T) {
	result := make(chan deviceSearchSelection, 1)
	readDeviceSearchSelection(bufio.NewReader(strings.NewReader("2\n1\n")), result)
	selection := <-result
	if selection.err != nil || selection.input != "2" {
		t.Fatalf("selection = %+v, want input 2", selection)
	}
}

func TestDeviceSelectionIndex(t *testing.T) {
	for _, test := range []struct {
		name        string
		input       string
		deviceCount int
		want        int
		wantError   bool
	}{
		{name: "default", deviceCount: 2},
		{name: "explicit", input: "2", deviceCount: 2, want: 1},
		{name: "trimmed", input: " 1 ", deviceCount: 2},
		{name: "no devices", wantError: true},
		{name: "out of range", input: "3", deviceCount: 2, wantError: true},
		{name: "not a number", input: "office", deviceCount: 2, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := deviceSelectionIndex(test.input, test.deviceCount)
			if test.wantError {
				if err == nil {
					t.Fatalf("deviceSelectionIndex() = %d, want an error", got)
				}
				return
			}
			if err != nil || got != test.want {
				t.Fatalf("deviceSelectionIndex() = (%d, %v), want (%d, nil)", got, err, test.want)
			}
		})
	}
}

func TestStableDeviceListPreservesFirstSeenOrderAndUpdatesInPlace(t *testing.T) {
	var list stableDeviceList
	list.upsert(airplay.AirPlayDevice{
		Name:     "Living Room",
		DeviceID: "AA:BB:CC:DD:EE:01",
		IP:       "192.0.2.10",
		Port:     7000,
	})
	list.upsert(airplay.AirPlayDevice{
		Name:     "Office",
		DeviceID: "AA:BB:CC:DD:EE:02",
		IP:       "192.0.2.20",
		Port:     7000,
	})
	list.upsert(airplay.AirPlayDevice{
		Name:     "Living Room TV",
		DeviceID: "aa:bb:cc:dd:ee:01",
		IP:       "192.0.2.11",
		Port:     7000,
	})

	if len(list.devices) != 2 {
		t.Fatalf("device count = %d, want 2", len(list.devices))
	}
	if list.devices[0].Name != "Living Room TV" || list.devices[0].IP != "192.0.2.11" {
		t.Fatalf("first device = %+v, want updated Living Room device", list.devices[0])
	}
	if list.devices[1].Name != "Office" {
		t.Fatalf("second device = %+v, want Office", list.devices[1])
	}
}

func TestStableDeviceListUsesServiceIdentityWithoutDeviceID(t *testing.T) {
	var list stableDeviceList
	list.upsert(airplay.AirPlayDevice{Name: "Kitchen", Model: "old", IP: "192.0.2.30", Port: 7000})
	list.upsert(airplay.AirPlayDevice{Name: "kitchen", Model: "new", IP: "192.0.2.31", Port: 7000})

	if len(list.devices) != 1 || list.devices[0].Model != "new" {
		t.Fatalf("devices = %+v, want one updated service", list.devices)
	}
}

func TestDeviceSearchStatusUsesPortableCarriageReturnOutput(t *testing.T) {
	var output bytes.Buffer
	status := newDeviceSearchStatus(&output)
	status.draw(1, 0)
	status.draw(2, 2)
	status.finish()
	got := output.String()

	for _, want := range []string{
		"\r",
		"searching for AirPlay receivers... /",
		"searching, select receiver [1]... -",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("status output does not contain %q:\n%q", want, got)
		}
	}
	if strings.Contains(got, "\x1b") {
		t.Fatalf("status output uses terminal-specific escape sequences: %q", got)
	}
}

func TestPrintDiscoveredDeviceUsesStableNumberAndSanitizesAdvertisement(t *testing.T) {
	var output bytes.Buffer
	printDiscoveredDevice(&output, 1, airplay.AirPlayDevice{
		Name:  "Office\x1b[31m",
		Model: "AppleTV\n",
		IP:    "192.0.2.20",
	}, true)
	if got, want := output.String(), "  [2] Office?[31m (AppleTV?) - 192.0.2.20 (updated)\n"; got != want {
		t.Fatalf("printed device = %q, want %q", got, want)
	}
}

func TestSafeTerminalTextRemovesControlAndFormatCharacters(t *testing.T) {
	if got, want := safeTerminalText("TV\x1b[31m\n\u202e"), "TV?[31m??"; got != want {
		t.Fatalf("safeTerminalText() = %q, want %q", got, want)
	}
}
