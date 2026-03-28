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
	width := flag.Int("width", 1920, "Stream width")
	height := flag.Int("height", 1080, "Stream height")
	fps := flag.Int("fps", 30, "Frames per second")
	hwaccel := flag.String("hwaccel", "auto", "Hardware acceleration: auto, vaapi, none")
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

	if err := client.Pair(ctx, *pin); err != nil {
		log.Fatalf("pairing failed: %v", err)
	}
	log.Println("pairing complete")

	if err := client.FairPlaySetup(ctx); err != nil {
		log.Printf("fairplay setup skipped (non-fatal with HKP): %v", err)
	} else {
		log.Println("fairplay setup complete")
	}

	streamCfg := StreamConfig{
		Width:  *width,
		Height: *height,
		FPS:    *fps,
	}
	session, err := client.SetupMirror(ctx, streamCfg)
	if err != nil {
		log.Fatalf("mirror setup failed: %v", err)
	}
	defer session.Close()
	log.Printf("mirror session ready (data port: %d)", session.DataPort)

	captureCfg := CaptureConfig{
		Width:   *width,
		Height:  *height,
		FPS:     *fps,
		HWAccel: *hwaccel,
	}
	capture, err := StartCapture(ctx, captureCfg)
	if err != nil {
		log.Fatalf("screen capture failed: %v", err)
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
