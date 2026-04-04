package main

import (
	"encoding/json"
	"fmt"
	"os"

	"doubletake/internal/daemon"
	"doubletake/internal/daemon/daemonclient"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	socketPath := os.Getenv("DOUBLETAKE_SOCKET")
	if socketPath == "" {
		socketPath = daemon.DefaultSocketPath()
	}

	client := daemonclient.New(socketPath)
	cmd := os.Args[1]

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
		if len(os.Args) >= 3 {
			target = os.Args[2]
		}
		if len(os.Args) >= 4 {
			pin = os.Args[3]
		}
		resp, err = client.Connect(target, 0, pin)
	case "pin":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "Usage: doubletake-ctl pin <4-digit-PIN>\n")
			os.Exit(1)
		}
		resp, err = client.Connect("", 0, os.Args[2])
	case "disconnect":
		resp, err = client.Disconnect()
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
	fmt.Fprintf(os.Stderr, "Usage: doubletake-ctl <command> [args]\n\nCommands:\n  status              Show daemon state\n  discover            Discover AirPlay devices on the network\n  devices             List cached discovered devices\n  connect [target] [pin]  Start mirroring (to target IP, or first discovered device)\n  pin <4-digit-PIN>   Submit PIN for a device waiting for pairing\n  disconnect          Stop mirroring\n\nEnvironment:\n  DOUBLETAKE_SOCKET   Override daemon socket path (default: $XDG_RUNTIME_DIR/doubletake.sock)\n")
}
