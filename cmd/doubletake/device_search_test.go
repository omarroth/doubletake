package main

import (
	"bytes"
	"strings"
	"testing"

	"doubletake/internal/airplay"
)

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
		"searching for AirPlay receivers... -",
		"Press Enter after a receiver appears",
		"Press Enter to choose",
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
