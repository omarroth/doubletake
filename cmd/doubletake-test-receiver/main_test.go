package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"doubletake/internal/airplay"
)

func TestParseReceiverProfile(t *testing.T) {
	tests := []struct {
		input string
		want  airplay.ReceiverProfile
	}{
		{input: "roku", want: airplay.ReceiverProfileRoku},
		{input: " RoKu\t", want: airplay.ReceiverProfileRoku},
		{input: "modern", want: airplay.ReceiverProfileModern},
		{input: " MODERN ", want: airplay.ReceiverProfileModern},
		{input: "lg", want: airplay.ReceiverProfileLG},
		{input: "appletv3", want: airplay.ReceiverProfileAppleTV3},
		{input: " UxPlay ", want: airplay.ReceiverProfileUxPlay},
		{input: "airserver", want: airplay.ReceiverProfileAirServer},
		{input: " AirTame ", want: airplay.ReceiverProfileAirServer},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := parseReceiverProfile(test.input)
			if err != nil {
				t.Fatalf("parseReceiverProfile(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("parseReceiverProfile(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}

	for _, input := range []string{"", "apple-tv", "modern,roku"} {
		t.Run("invalid_"+input, func(t *testing.T) {
			got, err := parseReceiverProfile(input)
			if err == nil {
				t.Fatalf("parseReceiverProfile(%q) = %q, want an error", input, got)
			}
			if got != "" || !strings.Contains(err.Error(), "invalid -profile") {
				t.Fatalf("parseReceiverProfile(%q) = (%q, %v)", input, got, err)
			}
		})
	}
}

func TestParseReceiverAuth(t *testing.T) {
	tests := []struct {
		input string
		want  airplay.ReceiverAuthMode
	}{
		{input: "none", want: airplay.ReceiverAuthNone},
		{input: " PIN ", want: airplay.ReceiverAuthPIN},
		{input: "password", want: airplay.ReceiverAuthPassword},
		{input: "DiGeSt", want: airplay.ReceiverAuthDigest},
		{input: " combined\t", want: airplay.ReceiverAuthCombined},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			got, err := parseReceiverAuth(test.input)
			if err != nil {
				t.Fatalf("parseReceiverAuth(%q): %v", test.input, err)
			}
			if got != test.want {
				t.Fatalf("parseReceiverAuth(%q) = %q, want %q", test.input, got, test.want)
			}
		})
	}

	for _, input := range []string{"", "basic", "pin,digest"} {
		t.Run("invalid_"+input, func(t *testing.T) {
			got, err := parseReceiverAuth(input)
			if err == nil {
				t.Fatalf("parseReceiverAuth(%q) = %q, want an error", input, got)
			}
			if got != "" || !strings.Contains(err.Error(), "invalid -auth") {
				t.Fatalf("parseReceiverAuth(%q) = (%q, %v)", input, got, err)
			}
		})
	}
}

func TestRunRejectsInvalidArgumentsWithoutStartingReceiver(t *testing.T) {
	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantStderr string
	}{
		{name: "help", args: []string{"-help"}, wantCode: 0, wantStderr: "Usage of doubletake-test-receiver"},
		{name: "unknown flag", args: []string{"-unknown"}, wantCode: 2, wantStderr: "flag provided but not defined"},
		{name: "positional argument", args: []string{"unexpected"}, wantCode: 2, wantStderr: "unexpected positional arguments"},
		{name: "invalid duration", args: []string{"-stats-interval=often"}, wantCode: 2, wantStderr: "invalid value"},
		{name: "negative interval", args: []string{"-stats-interval=-1ms"}, wantCode: 2, wantStderr: "must be non-negative"},
		{name: "invalid profile", args: []string{"-profile=other"}, wantCode: 2, wantStderr: "invalid -profile"},
		{name: "invalid auth", args: []string{"-auth=other"}, wantCode: 2, wantStderr: "invalid -auth"},
		{name: "invalid loss", args: []string{"-audio-drop-every=1"}, wantCode: 2, wantStderr: "must be 0 or at least 2"},
		{name: "invalid jitter", args: []string{"-audio-jitter=-1ms"}, wantCode: 2, wantStderr: "must be between 0 and 1s"},
		{name: "loss without decoder", args: []string{"-decode=false", "-audio-drop-every=2"}, wantCode: 2, wantStderr: "requires -decode"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, stderr := runReceiverCLIWithStderr(t, test.args)
			if code != test.wantCode {
				t.Fatalf("run(%q) = %d, want %d; stderr: %s", test.args, code, test.wantCode, stderr)
			}
			if !strings.Contains(stderr, test.wantStderr) {
				t.Fatalf("run(%q) stderr = %q, want substring %q", test.args, stderr, test.wantStderr)
			}
		})
	}
}

func TestReceiverStatsSummary(t *testing.T) {
	stats := airplay.ReceiverStats{
		Connections:         2,
		InfoRequests:        3,
		PairSetup:           4,
		PairVerify:          5,
		FairPlayRequests:    17,
		DigestChallenges:    6,
		SetupRequests:       7,
		EarlyRecordRequests: 20,
		FeedbackRequests:    8,
		TeardownRequests:    9,
		EventConnections:    10,
		VideoPackets:        11,
		VideoBytes:          12,
		VideoDecrypted:      18,
		VideoCryptoErrors:   19,
		AudioPackets:        13,
		AudioBytes:          14,
		TimingProbes:        15,
		TimingReplies:       16,
	}
	want := "connections=2 info=3 pairing=4/5 fairplay=17 setup=7 early_record=20 feedback=8 teardown=9 " +
		"events=10 video=11/12B video_decrypted=18 video_crypto_errors=19 audio=13/14B timing=15/16 digest_challenges=6"
	if got := receiverStatsSummary(stats); got != want {
		t.Fatalf("receiverStatsSummary() =\n%q\nwant\n%q", got, want)
	}
}

func runReceiverCLIWithStderr(t *testing.T, args []string) (int, string) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	oldStderr := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = oldStderr }()

	code := run(args)
	if err := writer.Close(); err != nil {
		t.Fatalf("close stderr writer: %v", err)
	}
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("close stderr reader: %v", err)
	}
	return code, string(output)
}
