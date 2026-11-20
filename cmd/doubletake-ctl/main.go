package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"doubletake/internal/daemon"
	"doubletake/internal/daemon/daemonclient"
	"doubletake/internal/version"
)

func main() {
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socketPath := fs.String("socket", daemon.DefaultSocketPath(), "daemon socket path")
	showVersion := fs.Bool("version", false, "Show version and exit")
	fs.Usage = usage

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		os.Exit(2)
	}
	if *showVersion {
		fmt.Printf("doubletake-ctl %s\n", version.String())
		return
	}

	args := fs.Args()
	if len(args) < 1 {
		usage()
		os.Exit(1)
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
	case "pin":
		if len(args) < 2 {
			fmt.Fprintf(os.Stderr, "Usage: doubletake-ctl pin <PIN-or-password>\n")
			os.Exit(1)
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", cmd)
		usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(resp)

	if !resp.OK {
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: doubletake-ctl [-socket path] <command> [args]\n\nCommands:\n  status                              Show daemon state and all active streams\n  discover                            Discover AirPlay devices on the network\n  devices                             List cached discovered devices\n  connect [target] [PIN-or-password]   Start streaming (to target IP, or first free device)\n  pin <PIN-or-password>                Submit pairing credentials for a waiting device\n  disconnect [target]                  Stop streaming (all streams, or only the given IP)\n  mute [target]                        Mute receiver audio (all streams, or only the given IP)\n  unmute [target]                      Unmute receiver audio (all streams, or only the given IP)\n\nFlags:\n  -socket path                        Override daemon socket path (default: %s)\n  -version                            Show version and exit\n  -help, -h                           Show command-line help\n", daemon.DefaultSocketPath())
}
