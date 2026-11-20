package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"doubletake/internal/airplay"
)

const receiverCodeEnvironment = "DOUBLETAKE_RECEIVER_CODE"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	flags := flag.NewFlagSet("doubletake-test-receiver", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	listenAddress := flags.String("listen", "127.0.0.1:7000", "TCP address for the AirPlay control listener")
	profileName := flags.String("profile", "roku", "receiver profile: modern, roku, lg, appletv3, uxplay, airserver, or raop")
	authName := flags.String("auth", "none", "authentication mode: none, pin, password, digest, or combined")
	code := flags.String("code", "", "receiver PIN/password (DOUBLETAKE_RECEIVER_CODE takes precedence)")
	name := flags.String("name", "", "receiver name advertised by /info (profile default when empty)")
	model := flags.String("model", "", "receiver model advertised by /info (profile default when empty)")
	deviceID := flags.String("device-id", "", "receiver device ID advertised by /info (random when empty)")
	debug := flags.Bool("debug", false, "enable verbose receiver protocol logging")
	statsInterval := flags.Duration("stats-interval", 0, "periodic statistics interval (0 disables periodic output)")
	acceptEarlyRecord := flags.Bool("accept-early-record", false, "accept RECORD before media SETUP instead of returning 455")
	decode := flags.Bool("decode", true, "decode audio/video and simulate headless playback (requires linked build)")
	audioDropEvery := flags.Int("audio-drop-every", 0, "drop every Nth primary audio sequence to test recovery (0 disables)")
	audioJitter := flags.Duration("audio-jitter", 50*time.Millisecond, "time allowed for missing audio recovery")
	forceNTP := flags.Bool("ntp", false, "advertise and use NTP independently of the selected profile")
	videoProbe := flags.Bool("video-probe", false, "report simulated presentation latency for the desktop CI timestamp pattern")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "error: unexpected positional arguments: %s\n", strings.Join(flags.Args(), " "))
		flags.Usage()
		return 2
	}
	if *statsInterval < 0 {
		fmt.Fprintln(os.Stderr, "error: -stats-interval must be non-negative (0 disables periodic output)")
		return 2
	}
	if *audioDropEvery < 0 || *audioDropEvery == 1 {
		fmt.Fprintln(os.Stderr, "error: -audio-drop-every must be 0 or at least 2")
		return 2
	}
	if *audioJitter < 0 || *audioJitter > time.Second {
		fmt.Fprintln(os.Stderr, "error: -audio-jitter must be between 0 and 1s")
		return 2
	}
	if *audioDropEvery > 0 && !*decode {
		fmt.Fprintln(os.Stderr, "error: -audio-drop-every requires -decode")
		return 2
	}

	profile, err := parseReceiverProfile(*profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	auth, err := parseReceiverAuth(*authName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	receiverCode := *code
	if environmentCode, present := os.LookupEnv(receiverCodeEnvironment); present {
		receiverCode = environmentCode
	}

	logger := log.New(os.Stderr, "", log.LstdFlags)
	var probe func(uint32, time.Time)
	if *videoProbe {
		probe = func(marker uint32, presented time.Time) {
			latency := (uint32(presented.UnixMilli()) - marker) & 0xffffff
			fmt.Printf("video-probe: marker=%d presented_ms=%d latency_ms=%d\n", marker, presented.UnixMilli(), latency)
		}
	}
	server, err := airplay.NewReceiverServer(airplay.ReceiverConfig{
		ListenAddress:     *listenAddress,
		Profile:           profile,
		Auth:              auth,
		Code:              receiverCode,
		Name:              *name,
		Model:             *model,
		DeviceID:          *deviceID,
		Logger:            logger,
		Debug:             *debug,
		AcceptEarlyRecord: *acceptEarlyRecord,
		DecodeMedia:       *decode,
		AudioDropEvery:    *audioDropEvery,
		AudioJitter:       *audioJitter,
		ForceNTP:          *forceNTP,
		VideoProbe:        probe,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: start receiver: %v\n", err)
		return 1
	}

	ctx, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	fmt.Printf("doubletake test receiver listening on %s (profile=%s auth=%s)\n", server.Addr(), profile, auth)

	statsDone := make(chan struct{})
	if *statsInterval > 0 {
		go reportReceiverStats(ctx, server, *statsInterval, statsDone)
	} else {
		close(statsDone)
	}

	serveErr := server.Serve(ctx)
	stopSignals()
	<-statsDone
	closeErr := server.Close()
	fmt.Printf("final stats: %s\n", receiverStatsSummary(server.Stats()))
	stats := server.Stats()
	if *decode && (stats.VideoCryptoErrors > 0 || stats.Playback.DecodeErrors > 0 || stats.Playback.TimestampErrors > 0 || stats.Playback.AudioLost > 0 || stats.Playback.AudioMissingSamples > 0 || stats.Playback.QueueOverruns > 0) {
		fmt.Fprintf(os.Stderr, "error: headless playback validation failed: %+v\n", stats.Playback)
		return 1
	}

	if serveErr != nil {
		fmt.Fprintf(os.Stderr, "error: receiver failed: %v\n", serveErr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(os.Stderr, "error: close receiver: %v\n", closeErr)
		return 1
	}
	return 0
}

func parseReceiverProfile(value string) (airplay.ReceiverProfile, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case string(airplay.ReceiverProfileRAOP):
		return airplay.ReceiverProfileRAOP, nil
	case string(airplay.ReceiverProfileModern):
		return airplay.ReceiverProfileModern, nil
	case string(airplay.ReceiverProfileRoku):
		return airplay.ReceiverProfileRoku, nil
	case string(airplay.ReceiverProfileLG):
		return airplay.ReceiverProfileLG, nil
	case string(airplay.ReceiverProfileAppleTV3):
		return airplay.ReceiverProfileAppleTV3, nil
	case string(airplay.ReceiverProfileUxPlay):
		return airplay.ReceiverProfileUxPlay, nil
	case string(airplay.ReceiverProfileAirServer), "airtame":
		return airplay.ReceiverProfileAirServer, nil
	default:
		return "", fmt.Errorf("invalid -profile %q (want modern, roku, lg, appletv3, uxplay, airserver, or raop)", value)
	}
}

func parseReceiverAuth(value string) (airplay.ReceiverAuthMode, error) {
	switch normalized := strings.ToLower(strings.TrimSpace(value)); normalized {
	case string(airplay.ReceiverAuthNone):
		return airplay.ReceiverAuthNone, nil
	case string(airplay.ReceiverAuthPIN):
		return airplay.ReceiverAuthPIN, nil
	case string(airplay.ReceiverAuthPassword):
		return airplay.ReceiverAuthPassword, nil
	case string(airplay.ReceiverAuthDigest):
		return airplay.ReceiverAuthDigest, nil
	case string(airplay.ReceiverAuthCombined):
		return airplay.ReceiverAuthCombined, nil
	default:
		return "", fmt.Errorf("invalid -auth %q (want none, pin, password, digest, or combined)", value)
	}
}

func reportReceiverStats(ctx context.Context, server *airplay.ReceiverServer, interval time.Duration, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fmt.Printf("stats: %s\n", receiverStatsSummary(server.Stats()))
		}
	}
}

func receiverStatsSummary(stats airplay.ReceiverStats) string {
	summary := fmt.Sprintf(
		"connections=%d info=%d pairing=%d/%d fairplay=%d setup=%d early_record=%d feedback=%d teardown=%d events=%d video=%d/%dB video_decrypted=%d video_crypto_errors=%d audio=%d/%dB timing=%d/%d digest_challenges=%d",
		stats.Connections,
		stats.InfoRequests,
		stats.PairSetup,
		stats.PairVerify,
		stats.FairPlayRequests,
		stats.SetupRequests,
		stats.EarlyRecordRequests,
		stats.FeedbackRequests,
		stats.TeardownRequests,
		stats.EventConnections,
		stats.VideoPackets,
		stats.VideoBytes,
		stats.VideoDecrypted,
		stats.VideoCryptoErrors,
		stats.AudioPackets,
		stats.AudioBytes,
		stats.TimingProbes,
		stats.TimingReplies,
		stats.DigestChallenges,
	)
	p := stats.Playback
	if p.VideoDecoded > 0 || p.AudioDecoded > 0 || p.DecodeErrors > 0 {
		rms := 0.0
		if p.AudioSamples > 0 {
			rms = math.Sqrt(p.AudioSquares / float64(2*p.AudioSamples))
		}
		summary += fmt.Sprintf(" video_decoded=%d video_played=%d audio_samples=%d audio_played=%d audio_peak=%d audio_rms=%.1f recovered=%d lost=%d missing_samples=%d duplicates=%d decode_errors=%d timestamp_errors=%d av_skew=%s",
			p.VideoDecoded, p.VideoPlayed, p.AudioSamples, p.AudioPlayedSamples, p.AudioPeak, rms, p.AudioRecovered, p.AudioLost, p.AudioMissingSamples, p.AudioDuplicates, p.DecodeErrors, p.TimestampErrors, p.MaxAVSkew)
	}
	return summary
}
