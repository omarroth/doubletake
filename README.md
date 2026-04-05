# doubletake

AirPlay screen mirroring sender for Linux. Streams your desktop to an Apple TV using the AirPlay 2 mirroring protocol.

## Features

- Full AirPlay 2 mirroring protocol (RTSP/HTTP + encrypted video stream)
- FairPlay SAP authentication (snapshot-backed Go ARM64 execution)
- SRP-6a pairing with PIN and persistent credential storage
- Wayland (PipeWire/xdg-desktop-portal) and X11 screen capture
- Hardware-accelerated H.264 encoding (NVENC, VA-API) with software fallback
- ChaCha20-Poly1305 stream encryption
- mDNS device discovery

## Requirements

- Go 1.23+
- GStreamer 1.0 (with plugins-base, plugins-good, plugins-bad, plugins-ugly, libav)
- PipeWire (Wayland) or X11 for screen capture

### Ubuntu/Debian

```sh
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
  gstreamer1.0-plugins-ugly gstreamer1.0-libav
```

## Build

```sh
go build -o doubletake ./cmd/doubletake
```

## Usage

```sh
# Discover Apple TVs on the network and stream
./doubletake

# Connect to a specific Apple TV
./doubletake -target 192.168.1.77

# First-time pairing with PIN (saves credentials for reuse)
./doubletake -target 192.168.1.77 -pair

# Use saved credentials
./doubletake -target 192.168.1.77 -creds airplay-credentials.json

# Adjust stream settings (bitrate 0 = auto)
./doubletake -target 192.168.1.77 -width 1920 -height 1080 -fps 30 -bitrate 0

# Force a lower bitrate on weaker Wi-Fi
./doubletake -target 192.168.1.77 -bitrate 4500

# Hardware encoding
./doubletake -target 192.168.1.77 -hwaccel nvenc   # NVIDIA
./doubletake -target 192.168.1.77 -hwaccel vaapi   # Intel/AMD

# Debug mode (verbose protocol logging)
./doubletake -target 192.168.1.77 -debug
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Apple TV IP (skip mDNS discovery) |
| `-port` | 7000 | AirPlay port |
| `-pin` | | 4-digit PIN for pairing |
| `-creds` | `airplay-credentials.json` | Credentials file path |
| `-pair` | false | Force new pairing |
| `-width` | 1920 | Stream width |
| `-height` | 1080 | Stream height |
| `-fps` | 30 | Frames per second |
| `-bitrate` | 0 | Video bitrate in kbps (`0` = auto) |
| `-hwaccel` | auto | Hardware accel: `auto`, `nvenc`, `vaapi`, `none` |
| `-test` | false | Use synthetic video source |
| `-debug` | false | Verbose debug logging |

## License

This project is for educational and research purposes.
