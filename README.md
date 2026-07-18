# doubletake

AirPlay screen mirroring sender for Linux. Streams your desktop to an Apple TV using the AirPlay 2 mirroring protocol.

## Features

- Full AirPlay 2 mirroring protocol (RTSP/HTTP + encrypted video stream)
- FairPlay SAP authentication (clean Go implementation)
- SRP-6a pairing with PIN and persistent credential storage
- Wayland (PipeWire/xdg-desktop-portal) and X11 screen capture
- Hardware-accelerated H.264 encoding (NVENC, VA-API) with software fallback
- ChaCha20-Poly1305 stream encryption
- mDNS device discovery
- Daemon mode with multi-target streaming control (`doubletake-ctl`)
- Configurable latency target (`-target-latency-ms`, default 100ms)
- KDE Plasma widget for quick access (see [plasmoid/](plasmoid/))

## Requirements

- Go 1.23+
- GStreamer 1.0 (with plugins-base, plugins-good, plugins-bad, plugins-ugly, libav)
- PulseAudio utilities (`pactl`; `pulseaudio-utils` on Ubuntu/Debian or the equivalent package on other distributions)
- PipeWire (Wayland) or X11 for screen capture

### Ubuntu/Debian

```sh
sudo apt install libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
  gstreamer1.0-plugins-ugly gstreamer1.0-libav pulseaudio-utils
```

### Arch Linux

```sh
sudo pacman -S gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad \
  gst-plugins-ugly gst-libav libpulse
```

You can also install from the AUR:

- [`doubletake`](https://aur.archlinux.org/packages/doubletake) (stable release package)
- [`doubletake-git`](https://aur.archlinux.org/packages/doubletake-git) (latest from git)
- [`doubletake-bin`](https://aur.archlinux.org/packages/doubletake-bin) (prebuilt binary package)

## Tested Devices

These are devices that have been tested with doubletake. If there are devices not listed here that you have confirmed working or non-functional, please open an issue.

- AppleTV14,1 (4K, 2022 3rd gen) + Homepod (1st gen)
- Mac17,2 (MacBook Pro, M5 14")
- Mac16,10 (Mac mini, M4)
- Roku Streaming Stick 4K (3820R2)
- Samsung TV TU8300 Series 4K UHD
- Hisense 55A6QU
- Xiaomi 4K HDR TV (AFTBR92D74) (currently non-functional, see [#4](https://github.com/omarroth/doubletake/issues/4))

## Build

```sh
make
```

This builds both binaries into `bin/`:

- `bin/doubletake`
- `bin/doubletake-ctl`

## Install

Install binaries and man pages (default prefix: `/usr/local`):

```sh
sudo make install
```

Use a custom prefix if needed:

```sh
make install PREFIX=$HOME/.local
```

Uninstall:

```sh
sudo make uninstall
```

Run tests:

```sh
make test
```

## Firewall

doubletake opens UDP ports (audio timing/control/data — 3 consecutive) and one
TCP port (event channel) and advertises them to the Apple TV during SETUP. The
Apple TV connects back to those ports — until that reverse handshake completes,
the receiver silently stalls and SETUP never returns.

By default the OS assigns ephemeral ports. Use `-port-range MIN-MAX` to confine
them to a small window you can open in your firewall (needs at least 4 ports):

```sh
doubletake -target 192.168.1.77 -port-range 60000-60010
```

Then with UFW:

```sh
sudo ufw allow from any proto udp to any port 60000:60010
sudo ufw allow from any proto tcp to any port 60000:60010
```

For nftables/firewalld, add equivalent rules allowing inbound UDP and TCP from
the Apple TV's address on the chosen range.

## Usage

```sh
# Discover Apple TVs on the network and stream
doubletake

# Disable audio for video-only mirroring
doubletake -no-audio

# Connect to a specific Apple TV
doubletake -target 192.168.1.77

# First-time pairing with PIN (saves credentials for reuse)
doubletake -target 192.168.1.77 -pair

# Use saved credentials
doubletake -target 192.168.1.77 -creds airplay-credentials.json

# Adjust stream settings (bitrate 0 = auto)
doubletake -target 192.168.1.77 -width 1920 -height 1080 -fps 30 -bitrate 0

# Force a lower bitrate on weaker Wi-Fi
doubletake -target 192.168.1.77 -bitrate 4500

# Set a target playout latency (default is 100ms)
doubletake -target 192.168.1.77 -target-latency-ms 100

# Hardware encoding
doubletake -target 192.168.1.77 -hwaccel nvenc   # NVIDIA
doubletake -target 192.168.1.77 -hwaccel vaapi   # Intel/AMD

# Debug mode (verbose protocol logging)
doubletake -target 192.168.1.77 -debug

# Run daemon mode and control from a second shell
doubletake -daemonize
doubletake-ctl status
doubletake-ctl connect 192.168.1.77
doubletake-ctl connect 192.168.1.133
doubletake-ctl disconnect 192.168.1.77
doubletake-ctl disconnect
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Apple TV IP (skip mDNS discovery) |
| `-port` | 7000 | AirPlay port |
| `-pin` | | 4-digit PIN for pairing |
| `-cred-backend` | `file` | Credential backend (`file` or `keyring`) |
| `-creds` | `~/.config/doubletake/credentials.json` | Credentials file path |
| `-pair` | false | Force new pairing |
| `-width` | 1920 | Stream width |
| `-height` | 1080 | Stream height |
| `-fps` | 30 | Frames per second |
| `-bitrate` | 0 | Video bitrate in kbps (`0` = auto) |
| `-target-latency-ms` | 100 | Target end-to-end latency in milliseconds (audio + video timing) |
| `-hwaccel` | auto | Hardware accel: `auto`, `nvenc`, `vaapi`, `none` |
| `-no-encrypt` | false | Disable RTSP header encryption (debugging only) |
| `-direct-key` | false | Use `shk`/`shiv` directly without SHA-512 derivation |
| `-no-audio` | false | Disable audio streaming |
| `-test` | false | Use synthetic video source |
| `-daemonize` | false | Run as background daemon with Unix socket control interface |
| `-socket` | `$XDG_RUNTIME_DIR/doubletake.sock` | Daemon control socket path |
| `-debug` | false | Verbose debug logging |

### Daemon Control (`doubletake-ctl`)

```sh
doubletake-ctl status
doubletake-ctl discover
doubletake-ctl devices
doubletake-ctl connect [target] [pin]
doubletake-ctl pin <4-digit-PIN>
doubletake-ctl disconnect [target]
doubletake-ctl mute [target]
doubletake-ctl unmute [target]
```

- `disconnect` without a target stops all active streams.
- `disconnect <target>` stops only that receiver.
- `mute`/`unmute` can operate globally or per target.

## Disclaimer

The majority of code for this project was written by LLMs. I've read through the code to make sure there's nothing obviously stupid, but if you're in a production or security-sensitive environment and need to use AirPlay (for whatever reason), do not use this project.

Since I assume most of the code for this project was trained from [UxPlay](https://github.com/FDH2/UxPlay) and similar projects, I've provided this project under a similar license. Most of the reverse engineering work has already been done by many other people and this project would not be possible without them.

## License

This project is licensed under the [GNU Lesser General Public License v3.0 or later](LICENSE) (`LGPL-3.0-or-later`). See the LICENSE file for the LGPL terms and [COPYING.GPL](COPYING.GPL) for the incorporated GPLv3 terms.

Releases v0.3.2 and earlier were provided under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`).
