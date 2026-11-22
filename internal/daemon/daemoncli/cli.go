package daemoncli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"doubletake/internal/airplay"
	"doubletake/internal/daemon"
	"doubletake/internal/daemon/daemonclient"
	"doubletake/internal/version"
)

// Run handles daemon-control commands and returns a process exit code.
func Run(name string, argv []string) int {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socketPath := fs.String("socket", daemon.DefaultSocketPath(), "daemon socket path")
	showVersion := fs.Bool("version", false, "Show version and exit")
	fs.Usage = func() { usage(name) }

	if err := fs.Parse(argv); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *showVersion {
		fmt.Printf("%s %s\n", name, version.String())
		return 0
	}

	args := fs.Args()
	if len(args) < 1 {
		usage(name)
		return 1
	}

	client := daemonclient.New(*socketPath)
	cmd := args[0]

	var resp *daemon.Response
	var err error

	switch cmd {
	case "status":
		resp, err = client.Status()
	case "discover":
		resp, err = client.Discover()
	case "devices":
		resp, err = client.Devices()
	case "connect":
		target := ""
		pin := ""
		if len(args) >= 2 {
			target = args[1]
		}
		if len(args) >= 3 {
			pin = args[2]
		}
		resp, err = client.Connect(target, 0, pin)
	case "play":
		if len(args) < 2 || len(args) > 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s play SOURCE [target]\n", name)
			return 1
		}
		source, resolveErr := airplay.ResolveMediaSource(args[1])
		if resolveErr != nil {
			err = resolveErr
			break
		}
		target := ""
		if len(args) == 3 {
			target = args[2]
		}
		resp, err = client.Play(source, target)
	case "pin":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: %s pin <PIN-or-password>\n", name)
			return 1
		}
		resp, err = client.Connect("", 0, args[1])
	case "disconnect":
		if len(args) >= 2 {
			resp, err = client.DisconnectTarget(args[1])
		} else {
			resp, err = client.Disconnect()
		}
	case "mute":
		if len(args) >= 2 {
			resp, err = client.MuteTarget(args[1])
		} else {
			resp, err = client.Mute()
		}
	case "unmute":
		if len(args) >= 2 {
			resp, err = client.UnmuteTarget(args[1])
		} else {
			resp, err = client.Unmute()
		}
	case "volume":
		if len(args) < 2 || len(args) > 3 {
			fmt.Fprintf(os.Stderr, "Usage: %s volume TARGET [DB]\n", name)
			return 1
		}
		var db *float64
		if len(args) == 3 {
			value, parseErr := strconv.ParseFloat(args[2], 64)
			if parseErr != nil {
				err = fmt.Errorf("invalid volume %q", args[2])
				break
			}
			db = &value
		}
		resp, err = client.Volume(args[1], db)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage(name)
		return 1
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(resp)

	if !resp.OK {
		return 1
	}
	return 0
}

func usage(name string) {
	fmt.Fprintf(os.Stderr, "Usage: %s [-socket path] <command> [args]\n\nCommands:\n  status                              Show daemon state and all active streams\n  discover                            Discover AirPlay devices on the network\n  devices                             List cached discovered devices\n  connect [target] [PIN-or-password]   Start streaming (to target IP, or first free device)\n  play SOURCE [target]                 Play media from a file or HTTP(S) URL\n  pin <PIN-or-password>                Submit pairing credentials for a waiting device\n  disconnect [target]                  Stop streaming (all streams, or only the given IP)\n  mute [target]                        Mute receiver audio (all streams, or only the given IP)\n  unmute [target]                      Unmute receiver audio (all streams, or only the given IP)\n  volume TARGET [DB]                   Get or set the receiver playback level in dB\n\nFlags:\n  -socket path                        Override daemon socket path (default: %s)\n  -version                            Show version and exit\n  -help, -h                           Show command-line help\n", name, daemon.DefaultSocketPath())
}
