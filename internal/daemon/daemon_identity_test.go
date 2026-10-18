package daemon

import (
	"context"
	"io"
	"log"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"doubletake/internal/airplay"
)

func TestDaemonRefusesReplacementReceiverBeforeCapture(t *testing.T) {
	for _, scenario := range []string{"same ID new key", "explicit ID mismatch", "discovered ID mismatch"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			startReceiver := func(cfg airplay.ReceiverConfig) *airplay.ReceiverServer {
				cfg.ListenAddress = "127.0.0.1:0"
				cfg.Profile = airplay.ReceiverProfileLG
				cfg.Logger = log.New(io.Discard, "", 0)
				server, err := airplay.NewReceiverServer(cfg)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				go func() { done <- server.Serve(ctx) }()
				t.Cleanup(func() { _ = server.Close(); <-done })
				return server
			}
			const deviceID = "00:11:22:33:44:55"
			real := startReceiver(airplay.ReceiverConfig{DeviceID: deviceID, Auth: airplay.ReceiverAuthPIN, Code: "4827"})
			address := real.Addr().(*net.TCPAddr)
			client := airplay.NewAirPlayClient(address.IP.String(), address.Port)
			defer client.Close()
			if err := client.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			if _, err := client.GetInfo(); err != nil {
				t.Fatal(err)
			}
			if err := client.Pair(ctx, "4827"); err != nil {
				t.Fatal(err)
			}
			d, err := New(Config{CredBackend: "file", CredFile: filepath.Join(t.TempDir(), "credentials.json"), NoAudio: true})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(d.Shutdown)
			if err := d.credStore.SavePairing(deviceID, client.PairingID, client.PairKeys.Ed25519Public,
				client.PairKeys.Ed25519Private, client.PairingProtocol(), client.ReceiverIdentity()); err != nil {
				t.Fatal(err)
			}
			impostorID := deviceID
			if scenario != "same ID new key" {
				impostorID = "another-device"
			}
			impostor := startReceiver(airplay.ReceiverConfig{DeviceID: impostorID})
			address = impostor.Addr().(*net.TCPAddr)
			request := Request{Cmd: "connect", Target: address.IP.String(), Port: address.Port}
			if scenario == "explicit ID mismatch" {
				request.DeviceID = deviceID
			} else if scenario == "discovered ID mismatch" {
				d.devices = []airplay.AirPlayDevice{{IP: address.IP.String(), Port: address.Port, DeviceID: deviceID}}
			}
			if response := d.handleConnect(request); !response.OK {
				t.Fatalf("connect rejected before worker: %+v", response)
			}
			for {
				status := d.handleStatus()
				if status.Error != "" {
					if !strings.Contains(status.Error, "refusing to cast") || len(status.Streams) != 0 {
						t.Fatalf("status = %+v, want authentication refusal before capture", status)
					}
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal("daemon did not refuse the replacement receiver")
				case <-time.After(time.Millisecond):
				}
			}
			if stats := impostor.Stats(); stats.PairSetup != 0 || stats.SetupRequests != 0 || stats.VideoPackets != 0 {
				t.Fatalf("replacement receiver received pairing/media traffic: %+v", stats)
			}
		})
	}
}
