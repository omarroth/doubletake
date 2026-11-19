package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
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
	profileName := flags.String("profile", "roku", "receiver profile: modern, roku, lg, appletv3, uxplay, or airserver")
	authName := flags.String("auth", "none", "authentication mode: none, pin, password, digest, or combined")
	code := flags.String("code", "", "receiver PIN/password (DOUBLETAKE_RECEIVER_CODE takes precedence)")
	name := flags.String("name", "", "receiver name advertised by /info (profile default when empty)")
	model := flags.String("model", "", "receiver model advertised by /info (profile default when empty)")
	deviceID := flags.String("device-id", "", "receiver device ID advertised by /info (random when empty)")
	debug := flags.Bool("debug", false, "enable verbose receiver protocol logging")
	statsInterval := flags.Duration("stats-interval", 0, "periodic statistics interval (0 disables periodic output)")
	acceptEarlyRecord := flags.Bool("accept-early-record", false, "accept RECORD before media SETUP instead of returning 455")
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
		return "", fmt.Errorf("invalid -profile %q (want modern, roku, lg, appletv3, uxplay, or airserver)", value)
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
	return fmt.Sprintf(
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
}
