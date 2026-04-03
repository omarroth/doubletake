package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"doubletake/internal/airplay"
	"doubletake/internal/daemon"
)

func main() {
	socketPath := flag.String("socket", daemon.DefaultSocketPath(), "Unix socket path for control interface")
	credFile := flag.String("creds", airplay.DefaultCredentialsFile, "Path to saved pairing credentials")
	width := flag.Int("width", 1920, "Stream width")
	height := flag.Int("height", 1080, "Stream height")
	fps := flag.Int("fps", 30, "Frames per second")
	bitrate := flag.Int("bitrate", 10000, "Video bitrate in kbps")
	hwaccel := flag.String("hwaccel", "auto", "Hardware acceleration: auto, nvenc, vaapi, none")
	debug := flag.Bool("debug", false, "Enable verbose debug logging")
	flag.Parse()

	cfg := daemon.Config{
		SocketPath: *socketPath,
		CredFile:   *credFile,
		Width:      *width,
		Height:     *height,
		FPS:        *fps,
		Bitrate:    *bitrate,
		HWAccel:    *hwaccel,
		Debug:      *debug,
	}

	d := daemon.New(cfg)

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
