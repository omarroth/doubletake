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

	"doubletake/internal/airplay"
	"doubletake/internal/daemon"
)

func main() {
	target := flag.String("target", "", "Apple TV IP address or hostname (skip discovery)")
	port := flag.Int("port", 7000, "AirPlay port")
	pin := flag.String("pin", "", "4-digit PIN for pairing (shown on Apple TV)")
	credFile := flag.String("creds", airplay.DefaultCredentialsPath(), "Path to saved pairing credentials")
	forcePair := flag.Bool("pair", false, "Force new pairing even if credentials exist")
	width := flag.Int("width", 1920, "Stream width")
	height := flag.Int("height", 1080, "Stream height")
	fps := flag.Int("fps", 30, "Frames per second")
	bitrate := flag.Int("bitrate", 0, "Video bitrate in kbps (0 = auto, default tunes for resolution/FPS)")
	hwaccel := flag.String("hwaccel", "auto", "Hardware acceleration: auto, nvenc, vaapi, none")
	testMode := flag.Bool("test", false, "Use synthetic video (videotestsrc) instead of screen capture for debugging")
	noEncrypt := flag.Bool("no-encrypt", false, "Disable RTSP header encryption (debugging only; video frames are always encrypted)")
	directKey := flag.Bool("direct-key", false, "Use shk/shiv directly without SHA-512 derivation")
	audio := flag.Bool("audio", false, "Enable audio streaming (currently non-functional)")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	daemonize := flag.Bool("daemonize", false, "Run as background daemon with Unix socket control interface")
	socketPath := flag.String("socket", daemon.DefaultSocketPath(), "Unix socket path for daemon control interface")
	flag.Parse()

	airplay.DebugMode = *debug

	if *daemonize {
		runDaemon(*socketPath, *credFile, *width, *height, *fps, *bitrate, *hwaccel, *debug, *testMode, *noEncrypt, *directKey, !*audio)
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
		// Force exit on second signal
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
	log.Printf("connected to: %s (model: %s)", info.Name, info.Model)

	// Pairing flow:
	// 1. If --pin provided or --pair forced, do full pair-setup + save credentials
	// 2. If saved credentials exist, load them and do pair-verify only
	// 3. Otherwise, do transient (ephemeral) pairing
	needFullPair := *forcePair || *pin != ""
	var savedCreds *airplay.SavedCredentials

	if !needFullPair {
		var err error
		savedCreds, err = airplay.LoadCredentials(*credFile)
		if err != nil {
			log.Printf("warning: failed to load credentials: %v", err)
		}
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
		if err := airplay.SaveCredentials(*credFile, client.PairingID, client.PairKeys.Ed25519Public, client.PairKeys.Ed25519Private); err != nil {
			log.Printf("warning: failed to save credentials: %v", err)
		} else {
			log.Printf("credentials saved to %s", *credFile)
		}
	} else if savedCreds != nil {
		// Use saved credentials — pair-verify
		log.Printf("using saved credentials from %s", *credFile)
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
				log.Fatalf("transient pairing fallback failed: %v", err)
			}
		}
	} else {
		// Transient pairing (no saved creds, no PIN)
		if err := client.Pair(ctx, ""); err != nil {
			log.Fatalf("pairing failed: %v", err)
		}
	}
	log.Println("pairing complete")

	// FairPlay setup — establishes fp-setup state and ekey/eiv used for the
	// final encrypted mirror stream. Pair-verify and FairPlay are both needed
	// for Apple TV compatibility in the normal modern flow.
	if os.Getenv("SKIP_FAIRPLAY") != "" {
		log.Println("SKIP_FAIRPLAY: skipping FairPlay setup entirely")
	} else if client.FpEkey == nil {
		if err := client.FairPlaySetup(ctx); err != nil {
			if os.Getenv("ALLOW_FAIRPLAY_FALLBACK") != "" {
				log.Printf("FairPlay setup failed (fallback enabled): %v", err)
			} else {
				log.Fatalf("FairPlay setup failed: %v", err)
			}
		} else {
			log.Println("FairPlay setup complete")
		}
	}

	streamCfg := airplay.StreamConfig{
		Width:     *width,
		Height:    *height,
		FPS:       *fps,
		Bitrate:   *bitrate,
		NoEncrypt: *noEncrypt,
		DirectKey: *directKey,
		NoAudio:   !*audio,
	}
	session, err := client.SetupMirror(ctx, streamCfg)
	if err != nil {
		log.Fatalf("mirror setup failed: %v", err)
	}
	defer session.Close()
	log.Printf("mirror session ready (data port: %d)", session.DataPort)

	// Quick heartbeat-only test: don't send any video, just keep session alive
	if os.Getenv("HEARTBEAT_ONLY") != "" {
		log.Println("HEARTBEAT_ONLY mode: no video will be sent, waiting 10s...")
		if os.Getenv("SEND_CODEC") != "" {
			// Send an SPS/PPS codec frame, then wait
			log.Println("sending test codec frame...")
			sps := []byte{0x67, 0x64, 0x00, 0x28, 0xAC, 0x56, 0x20, 0x0D, 0x81, 0x4F, 0xE5, 0x9B, 0x81, 0x01, 0x01, 0x01}
			pps := []byte{0x68, 0xEE, 0x3C, 0xB0}
			// Build avcC
			avcC := make([]byte, 6+2+len(sps)+1+2+len(pps))
			avcC[0] = 0x01
			avcC[1] = sps[1]
			avcC[2] = sps[2]
			avcC[3] = sps[3]
			avcC[4] = 0xff
			avcC[5] = 0xe1
			avcC[6] = byte(len(sps) >> 8)
			avcC[7] = byte(len(sps))
			copy(avcC[8:], sps)
			avcC[8+len(sps)] = 0x01
			avcC[9+len(sps)] = byte(len(pps) >> 8)
			avcC[10+len(sps)] = byte(len(pps))
			copy(avcC[11+len(sps):], pps)
			// Send as codec packet
			session.SendTestCodec(avcC)
		}
		if os.Getenv("SEND_EMPTY_VCL") != "" {
			log.Println("sending empty VCL header (zero payload)...")
			session.SendTestEmptyVCL()
		}
		time.Sleep(10 * time.Second)
		log.Println("heartbeat test complete")
		return
	}

	var capture *airplay.ScreenCapture
	if *testMode {
		log.Println("using synthetic video (videotestsrc) for debugging")
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

	// Start audio capture and streaming if audio is enabled
	if *audio && session.HasAudio() {
		audioCapture, err := airplay.StartAudioCapture(ctx)
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
	} else if *audio {
		log.Println("audio disabled (receiver did not provide audio ports)")
	}

	if err := session.StreamFrames(ctx, capture, 0*time.Second); err != nil && ctx.Err() == nil {
		log.Fatalf("streaming error: %v", err)
	}
	log.Println("stream ended")
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

func runDaemon(socketPath, credFile string, width, height, fps, bitrate int, hwaccel string, debug, testMode, noEncrypt, directKey, noAudio bool) {
	cfg := daemon.Config{
		SocketPath: socketPath,
		CredFile:   credFile,
		Width:      width,
		Height:     height,
		FPS:        fps,
		Bitrate:    bitrate,
		HWAccel:    hwaccel,
		Debug:      debug,
		TestMode:   testMode,
		NoEncrypt:  noEncrypt,
		DirectKey:  directKey,
		NoAudio:    noAudio,
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
