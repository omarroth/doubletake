# airplay

AirPlay screen mirroring sender for Linux. Streams your desktop to an Apple TV using the AirPlay 2 mirroring protocol.

## Features

- Full AirPlay 2 mirroring protocol (RTSP/HTTP + encrypted video stream)
- FairPlay SAP authentication (DRM handshake via ARM64 binary emulation)
- SRP-6a pairing with PIN and persistent credential storage
- Wayland (PipeWire/xdg-desktop-portal) and X11 screen capture
- Hardware-accelerated H.264 encoding (NVENC, VA-API) with software fallback
- ChaCha20-Poly1305 stream encryption
- mDNS device discovery

## Requirements

- Go 1.23+
- GStreamer 1.0 (with plugins-base, plugins-good, plugins-bad, plugins-ugly, libav)
- Unicorn Engine (`libunicorn-dev`) — for FairPlay ARM64 emulation
- PipeWire (Wayland) or X11 for screen capture

### Ubuntu/Debian

```sh
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
  gstreamer1.0-plugins-ugly gstreamer1.0-libav libunicorn-dev
```

## Build

```sh
go build -o airplay ./cmd/airplay
```

## Usage

```sh
# Discover Apple TVs on the network and stream
./airplay

# Connect to a specific Apple TV
./airplay -target 192.168.1.77

# First-time pairing with PIN (saves credentials for reuse)
./airplay -target 192.168.1.77 -pair

# Use saved credentials
./airplay -target 192.168.1.77 -creds airplay-credentials.json

# Adjust stream settings
./airplay -target 192.168.1.77 -width 1920 -height 1080 -fps 30 -bitrate 10000

# Hardware encoding
./airplay -target 192.168.1.77 -hwaccel nvenc   # NVIDIA
./airplay -target 192.168.1.77 -hwaccel vaapi   # Intel/AMD

# Debug mode (verbose protocol logging)
./airplay -target 192.168.1.77 -debug
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
| `-bitrate` | 10000 | Video bitrate (kbps) |
| `-hwaccel` | auto | Hardware accel: `auto`, `nvenc`, `vaapi`, `none` |
| `-test` | false | Use synthetic video source |
| `-debug` | false | Verbose debug logging |

## Project Structure

```
cmd/
  airplay/       Main binary
  pcapdump/      AirPlay packet capture parser
  checksecs/     Mach-O binary inspector
  scantable/     Mach-O table scanner
internal/
  airplay/       Core protocol implementation
    client.go      RTSP/HTTP client, connection management
    pairing.go     SRP-6a pair-setup, pair-verify, TLV8
    fairplay.go    FairPlay SAP handshake orchestration
    mirror.go      Mirror session, NTP sync, frame streaming
    capture.go     Screen capture (Wayland/X11 via GStreamer)
    playfair.go    FairPlay crypto (pure Go port)
    credentials.go Credential persistence
    discovery.go   mDNS device discovery
  fpemu/         ARM64 emulator for FairPlay binary
thirdparty/
  apple/         Required Apple binaries for FairPlay emulation
```

## License

This project is for educational and research purposes.
