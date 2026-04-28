package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"doubletake/internal/airplay"
	"doubletake/internal/daemon"
)

func main() {
	target := flag.String("target", "", "Apple TV IP address or hostname (skip discovery)")
	port := flag.Int("port", 7000, "AirPlay port")
	pin := flag.String("pin", "", "4-digit PIN for pairing (shown on Apple TV)")
	credFile := flag.String("creds", airplay.DefaultCredentialsPath(), "Path to saved pairing credentials")
	credBackend := flag.String("cred-backend", "file", "Credential storage backend: file or keyring (system keyring via Secret Service)")
	forcePair := flag.Bool("pair", false, "Force new pairing even if credentials exist")
	width := flag.Int("width", 1920, "Stream width")
	height := flag.Int("height", 1080, "Stream height")
	fps := flag.Int("fps", 30, "Frames per second")
	bitrate := flag.Int("bitrate", 0, "Video bitrate in kbps (0 = auto, default tunes for resolution/FPS)")
	targetLatencyMs := flag.Int("target-latency-ms", 100, "Target end-to-end latency in milliseconds (applies to audio and video timing)")
	hwaccel := flag.String("hwaccel", "auto", "Hardware acceleration: auto, nvenc, vaapi, none")
	testMode := flag.Bool("test", false, "Use synthetic video (videotestsrc) instead of screen capture for debugging")
	noEncrypt := flag.Bool("no-encrypt", false, "Disable RTSP header encryption (debugging only; video frames are always encrypted)")
	directKey := flag.Bool("direct-key", false, "Use shk/shiv directly without SHA-512 derivation")
	noAudio := flag.Bool("no-audio", false, "Disable audio streaming")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	daemonize := flag.Bool("daemonize", false, "Run as background daemon with Unix socket control interface")
	socketPath := flag.String("socket", daemon.DefaultSocketPath(), "Unix socket path for daemon control interface")
	flag.Parse()

	airplay.SetTargetLatency(time.Duration(*targetLatencyMs) * time.Millisecond)

	airplay.DebugMode = *debug

	if *daemonize {
		runDaemon(*socketPath, *credFile, *credBackend, *width, *height, *fps, *bitrate, *hwaccel, *debug, *testMode, *noEncrypt, *directKey, *noAudio)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
		// Give goroutines a moment to clean up, then force exit
		go func() {
			time.Sleep(3 * time.Second)
			log.Println("forced exit (timeout)")
			os.Exit(1)
		}()
		// Also force exit on second signal
		<-sigCh
		log.Println("forced exit")
		os.Exit(1)
	}()

	var addr string
	if *target != "" {
		addr = *target
	} else {
		device, err := selectDevice(ctx)
		if err != nil {
			log.Fatalf("discovery failed: %v", err)
		}
		addr = device.IP
		*port = device.Port
		fmt.Printf("selected: %s (%s:%d)\n", device.Name, device.IP, device.Port)
	}

	client := airplay.NewAirPlayClient(addr, *port)
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	info, err := client.GetInfo()
	if err != nil {
		log.Fatalf("get info failed: %v", err)
	}
	log.Printf("connected to: %s (model: %s, initialVolume: %.1f)", info.Name, info.Model, info.InitialVolume)

	// Pairing flow:
	// 1. If --pin provided or --pair forced, do full pair-setup + save credentials
	// 2. If saved credentials exist, load them and do pair-verify only
	// 3. Otherwise, do transient (ephemeral) pairing
	needFullPair := *forcePair || *pin != ""

	credStore, err := newCredentialStore(*credBackend, *credFile)
	if err != nil {
		log.Fatalf("failed to load credentials: %v", err)
	}

	var savedCreds *airplay.SavedCredentials
	if !needFullPair {
		savedCreds = credStore.Lookup(info.DeviceID)
	}

	if needFullPair {
		// Full pair-setup with PIN
		pinVal := *pin
		if pinVal == "" {
			// Trigger PIN display on the TV first, then ask user
			if err := client.StartPINDisplay(); err != nil {
				log.Fatalf("failed to trigger PIN display: %v", err)
			}
			fmt.Print("Enter the PIN shown on Apple TV: ")
			fmt.Scanln(&pinVal)
		}
		if err := client.Pair(ctx, pinVal); err != nil {
			log.Fatalf("pairing failed: %v", err)
		}
		// Save credentials for next time
		if err := credStore.Save(info.DeviceID, client.PairingID, client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private); err != nil {
			log.Printf("warning: failed to save credentials: %v", err)
		} else {
			log.Printf("credentials saved (%s)", *credBackend)
		}
	} else if savedCreds != nil {
		// Use saved credentials — pair-verify
		log.Printf("using saved credentials (%s)", *credBackend)
		pub, priv := savedCreds.Ed25519Keys()
		client.PairingID = savedCreds.PairingID
		client.PairKeys = &airplay.PairKeys{
			Ed25519Public:  pub,
			Ed25519Private: priv,
		}
		if err := client.PairVerify(ctx); err != nil {
			log.Printf("pair-verify with saved creds failed: %v, falling back to transient pairing", err)
			// Reconnect — the failed pair-verify may have closed the connection
			client.Close()
			if err := client.Connect(ctx); err != nil {
				log.Fatalf("reconnect failed: %v", err)
			}
			if _, err := client.GetInfo(); err != nil {
				log.Fatalf("get info after reconnect failed: %v", err)
			}
			if err := client.Pair(ctx, ""); err != nil {
				log.Printf("transient pairing fallback failed: %v, prompting for PIN", err)
				pinVal := promptForPIN(client)
				// Reconnect for fresh PIN pairing attempt
				client.Close()
				client = airplay.NewAirPlayClient(addr, *port)
				if err := client.Connect(ctx); err != nil {
					log.Fatalf("reconnect failed: %v", err)
				}
				if _, err := client.GetInfo(); err != nil {
					log.Fatalf("get info after reconnect failed: %v", err)
				}
				if err := client.Pair(ctx, pinVal); err != nil {
					log.Fatalf("PIN pairing failed: %v", err)
				}
				// Save credentials for next time
				if err := credStore.Save(info.DeviceID, client.PairingID, client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private); err != nil {
					log.Printf("warning: failed to save credentials: %v", err)
				} else {
					log.Printf("credentials saved (%s)", *credBackend)
				}
			}
		}
	} else {
		// Transient pairing (no saved creds, no PIN)
		if err := client.Pair(ctx, ""); err != nil {
			log.Printf("transient pairing failed: %v, prompting for PIN", err)
			pinVal := promptForPIN(client)
			// Reconnect for fresh PIN pairing attempt
			client.Close()
			client = airplay.NewAirPlayClient(addr, *port)
			if err := client.Connect(ctx); err != nil {
				log.Fatalf("reconnect failed: %v", err)
			}
			if _, err := client.GetInfo(); err != nil {
				log.Fatalf("get info after reconnect failed: %v", err)
			}
			if err := client.Pair(ctx, pinVal); err != nil {
				log.Fatalf("PIN pairing failed: %v", err)
			}
			// Save credentials for next time
			if err := credStore.Save(info.DeviceID, client.PairingID, client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private); err != nil {
				log.Printf("warning: failed to save credentials: %v", err)
			} else {
				log.Printf("credentials saved (%s)", *credBackend)
			}
		}
	}
	log.Println("pairing complete")

	// FairPlay setup — establishes fp-setup state and ekey/eiv used for the
	// final encrypted mirror stream. Pair-verify and FairPlay are both needed
	// for Apple TV compatibility in the normal modern flow.
	// Non-Apple devices (e.g. Samsung AirPlay 2 TVs) do not implement /fp-setup;
	// skip FairPlay entirely for receivers that don't advertise the feature.
	if client.FpEkey == nil && info.SupportsFairPlay() {
		if err := client.FairPlaySetup(ctx); err != nil {
			log.Fatalf("FairPlay setup failed: %v", err)
		} else {
			log.Println("FairPlay setup complete")
		}
	} else if !info.SupportsFairPlay() {
		log.Println("device does not support FairPlay, skipping fp-setup")
	}

	streamCfg := airplay.StreamConfig{
		Width:     *width,
		Height:    *height,
		FPS:       *fps,
		Bitrate:   *bitrate,
		NoEncrypt: *noEncrypt,
		DirectKey: *directKey,
		NoAudio:   *noAudio,
	}
	session, err := client.SetupMirror(ctx, streamCfg)
	if err != nil {
		log.Fatalf("mirror setup failed: %v", err)
	}
	defer session.Close()
	log.Printf("mirror session ready (data port: %d)", session.DataPort)

	var capture *airplay.ScreenCapture
	if *testMode {
		if *noAudio {
			log.Println("using synthetic video (videotestsrc) for debugging")
		} else {
			log.Println("using synthetic video (videotestsrc) and audio test tone for debugging")
		}
		var err error
		capture, err = airplay.StartTestCapture(ctx, airplay.CaptureConfig{
			Width:   *width,
			Height:  *height,
			FPS:     *fps,
			Bitrate: *bitrate,
			HWAccel: *hwaccel,
		})
		if err != nil {
			log.Fatalf("test capture failed: %v", err)
		}
	} else {
		captureCfg := airplay.CaptureConfig{
			Width:   *width,
			Height:  *height,
			FPS:     *fps,
			Bitrate: *bitrate,
			HWAccel: *hwaccel,
		}
		var err error
		capture, err = airplay.StartCapture(ctx, captureCfg)
		if err != nil {
			log.Fatalf("screen capture failed: %v", err)
		}
	}
	defer capture.Stop()
	go func() {
		<-ctx.Done()
		capture.Stop()
		session.Close()
	}()
	log.Println("screen capture started")

	// Start audio capture and streaming unless disabled.
	if !*noAudio && session.HasAudio() {
		audioCapture, err := airplay.StartAudioCapture(ctx, *testMode)
		if err != nil {
			log.Printf("warning: audio capture failed: %v (continuing without audio)", err)
		} else {
			defer audioCapture.Stop()
			go func() {
				if err := session.StreamAudio(ctx, audioCapture, session.AudioStream()); err != nil && ctx.Err() == nil {
					log.Printf("audio streaming error: %v", err)
				}
			}()
			log.Println("audio capture started")
		}
	} else if !*noAudio {
		log.Println("audio disabled (receiver did not provide audio ports)")
	}

	if err := session.StreamFrames(ctx, capture, 0*time.Second); err != nil && ctx.Err() == nil {
		log.Fatalf("streaming error: %v", err)
	}
	log.Println("stream ended")
}

func promptForPIN(client *airplay.AirPlayClient) string {
	if err := client.StartPINDisplay(); err != nil {
		log.Printf("warning: failed to trigger PIN display: %v", err)
	}
	fmt.Print("Enter the PIN shown on Apple TV: ")
	var pinVal string
	fmt.Scanln(&pinVal)
	return pinVal
}

func selectDevice(ctx context.Context) (*airplay.AirPlayDevice, error) {
	fmt.Println("searching for Apple TVs...")
	discoverCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	devices, err := airplay.DiscoverAirPlayDevices(discoverCtx)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no Apple TVs found")
	}

	sort.Slice(devices, func(i, j int) bool {
		return compareIPs(devices[i].IP, devices[j].IP) < 0
	})

	fmt.Println("\navailable devices:")
	for i, d := range devices {
		fmt.Printf("  [%d] %s (%s) - %s\n", i+1, d.Name, d.Model, d.IP)
	}

	fmt.Print("\nselect device [1]: ")
	var input string
	fmt.Scanln(&input)
	input = strings.TrimSpace(input)
	if input == "" {
		return &devices[0], nil
	}

	idx, err := strconv.Atoi(input)
	if err != nil || idx < 1 || idx > len(devices) {
		return nil, fmt.Errorf("invalid selection")
	}
	return &devices[idx-1], nil
}

// compareIPs compares two IP address strings numerically.
func compareIPs(a, b string) int {
	ipA := net.ParseIP(a)
	ipB := net.ParseIP(b)
	if ipA == nil && ipB == nil {
		return strings.Compare(a, b)
	}
	if ipA == nil {
		return 1
	}
	if ipB == nil {
		return -1
	}
	aBytes := ipA.To16()
	bBytes := ipB.To16()
	for i := range aBytes {
		if aBytes[i] < bBytes[i] {
			return -1
		}
		if aBytes[i] > bBytes[i] {
			return 1
		}
	}
	return 0
}

func runDaemon(socketPath, credFile, credBackend string, width, height, fps, bitrate int, hwaccel string, debug, testMode, noEncrypt, directKey, noAudio bool) {
	cfg := daemon.Config{
		SocketPath:  socketPath,
		CredFile:    credFile,
		CredBackend: credBackend,
		Width:       width,
		Height:      height,
		FPS:         fps,
		Bitrate:     bitrate,
		HWAccel:     hwaccel,
		Debug:       debug,
		TestMode:    testMode,
		NoEncrypt:   noEncrypt,
		DirectKey:   directKey,
		NoAudio:     noAudio,
	}

	d, err := daemon.New(cfg)
	if err != nil {
		log.Fatalf("[daemon] %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("[daemon] shutting down...")
		cancel()
		d.Shutdown()
		<-sigCh
		log.Println("[daemon] forced exit")
		os.Exit(1)
	}()

	if err := d.Run(ctx); err != nil {
		log.Fatalf("[daemon] %v", err)
	}
}

func newCredentialStore(backend, filePath string) (*airplay.CredentialStore, error) {
	switch backend {
	case "keyring":
		kb, err := airplay.NewKeyringBackend()
		if err != nil {
			return nil, err
		}
		return airplay.NewCredentialStoreWithBackend(kb), nil
	case "file":
		return airplay.NewCredentialStore(filePath)
	default:
		return nil, fmt.Errorf("unknown credential backend %q (use \"file\" or \"keyring\")", backend)
	}
}
