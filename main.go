package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func main() {
	target := flag.String("target", "", "Apple TV IP address or hostname (skip discovery)")
	port := flag.Int("port", 7000, "AirPlay port")
	pin := flag.String("pin", "", "4-digit PIN for pairing (shown on Apple TV)")
	credFile := flag.String("creds", defaultCredentialsFile, "Path to saved pairing credentials")
	forcePair := flag.Bool("pair", false, "Force new pairing even if credentials exist")
	width := flag.Int("width", 1920, "Stream width")
	height := flag.Int("height", 1080, "Stream height")
	fps := flag.Int("fps", 30, "Frames per second")
	hwaccel := flag.String("hwaccel", "auto", "Hardware acceleration: auto, vaapi, none")
	testMode := flag.Bool("test", false, "Use synthetic video (videotestsrc) instead of screen capture for debugging")
	noEncrypt := flag.Bool("no-encrypt", false, "Disable RTSP header encryption (debugging only; video frames are always encrypted)")
	flag.Parse()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
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

	client := NewAirPlayClient(addr, *port)
	if err := client.Connect(ctx); err != nil {
		log.Fatalf("connect failed: %v", err)
	}
	defer client.Close()

	info, err := client.GetInfo()
	if err != nil {
		log.Fatalf("get info failed: %v", err)
	}
	log.Printf("connected to: %s (model: %s)", info.Name, info.Model)

	// Pairing flow:
	// 1. If --pin provided or --pair forced, do full pair-setup + save credentials
	// 2. If saved credentials exist, load them and do pair-verify only
	// 3. Otherwise, do transient (ephemeral) pairing
	needFullPair := *forcePair || *pin != ""
	var savedCreds *SavedCredentials

	if !needFullPair {
		var err error
		savedCreds, err = LoadCredentials(*credFile)
		if err != nil {
			log.Printf("warning: failed to load credentials: %v", err)
		}
	}

	if needFullPair {
		// Full pair-setup with PIN
		pinVal := *pin
		if pinVal == "" {
			// Trigger PIN display and ask user
			fmt.Print("Enter the PIN shown on Apple TV: ")
			fmt.Scanln(&pinVal)
		}
		if err := client.Pair(ctx, pinVal); err != nil {
			log.Fatalf("pairing failed: %v", err)
		}
		// Save credentials for next time
		if err := SaveCredentials(*credFile, client.pairingID, client.pairKeys.Ed25519Public, client.pairKeys.Ed25519Private); err != nil {
			log.Printf("warning: failed to save credentials: %v", err)
		} else {
			log.Printf("credentials saved to %s", *credFile)
		}
	} else if savedCreds != nil {
		// Use saved credentials — pair-verify only (fast path)
		log.Printf("using saved credentials from %s", *credFile)
		pub, priv := savedCreds.Ed25519Keys()
		client.pairingID = savedCreds.PairingID
		client.pairKeys = &PairKeys{
			Ed25519Public:  pub,
			Ed25519Private: priv,
		}
		if err := client.pairVerify(ctx); err != nil {
			log.Printf("pair-verify with saved creds failed: %v", err)
			log.Printf("try re-pairing with: --pair --pin XXXX")
			os.Exit(1)
		}
	} else {
		// Transient pairing (no saved creds, no PIN)
		if err := client.Pair(ctx, ""); err != nil {
			log.Fatalf("pairing failed: %v", err)
		}
	}
	log.Println("pairing complete")

	if err := client.FairPlaySetup(ctx); err != nil {
		log.Printf("fairplay setup skipped (non-fatal with HKP): %v", err)
	} else {
		log.Println("fairplay setup complete")
	}

	streamCfg := StreamConfig{
		Width:     *width,
		Height:    *height,
		FPS:       *fps,
		NoEncrypt: *noEncrypt,
	}
	session, err := client.SetupMirror(ctx, streamCfg)
	if err != nil {
		log.Fatalf("mirror setup failed: %v", err)
	}
	defer session.Close()
	log.Printf("mirror session ready (data port: %d)", session.DataPort)

	var capture *ScreenCapture
	if *testMode {
		log.Println("using synthetic video (videotestsrc) for debugging")
		var err error
		capture, err = StartTestCapture(ctx, CaptureConfig{
			Width:   *width,
			Height:  *height,
			FPS:     *fps,
			HWAccel: *hwaccel,
		})
		if err != nil {
			log.Fatalf("test capture failed: %v", err)
		}
	} else {
		captureCfg := CaptureConfig{
			Width:   *width,
			Height:  *height,
			FPS:     *fps,
			HWAccel: *hwaccel,
		}
		var err error
		capture, err = StartCapture(ctx, captureCfg)
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

	if err := session.StreamFrames(ctx, capture); err != nil && ctx.Err() == nil {
		log.Fatalf("streaming error: %v", err)
	}
	log.Println("stream ended")
}

func selectDevice(ctx context.Context) (*AirPlayDevice, error) {
	fmt.Println("searching for Apple TVs...")
	discoverCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	devices, err := DiscoverAirPlayDevices(discoverCtx)
	if err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no Apple TVs found")
	}

	fmt.Println("\navailable devices:")
	for i, d := range devices {
		fmt.Printf("  [%d] %s (%s) - %s\n", i+1, d.Name, d.Model, d.IP)
	}

	if len(devices) == 1 {
		return &devices[0], nil
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
