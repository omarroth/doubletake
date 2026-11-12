# doubletake

AirPlay screen mirroring sender for Linux. Streams your desktop to Apple TV and compatible AirPlay receivers.

## Features

- Full AirPlay mirroring protocol (RTSP/HTTP + encrypted video stream)
- FairPlay SAP authentication (clean Go implementation)
- SRP-6a pairing with PIN and persistent credential storage
- Wayland (PipeWire/xdg-desktop-portal) and X11 screen capture
- H.264 encoding with NVENC, VA-API, V4L2 stateful encoders, OpenH264, and x264
- Capability-gated HEVC Main10/high-resolution encoding with NVENC or x265
- ChaCha20-Poly1305 stream encryption
- mDNS device discovery
- Daemon mode with multi-target streaming control (`doubletake-ctl`)
- In-process test receiver for hardware-free pairing and media-flow tests
- Connection-aware screen/audio latency with receiver-reported adaptation and an optional fixed override
- KDE Plasma widget for quick access (see [plasmoid/](plasmoid/))

## Requirements

- Go 1.25+
- GStreamer 1.16+ (with plugins-base, plugins-good, plugins-bad, plugins-ugly, libav)
- PulseAudio utilities (`pactl`; `pulseaudio-utils` on Ubuntu/Debian or the equivalent package on other distributions)
- PipeWire (Wayland) or X11 for screen capture

### Ubuntu/Debian

```sh
sudo apt install build-essential pkg-config \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev \
  gstreamer1.0-plugins-base gstreamer1.0-plugins-good gstreamer1.0-plugins-bad \
  gstreamer1.0-plugins-ugly gstreamer1.0-libav gstreamer1.0-tools \
  gstreamer1.0-pipewire gstreamer1.0-pulseaudio pulseaudio-utils
```

### Arch Linux

```sh
sudo pacman -S --needed base-devel gstreamer gst-plugins-base gst-plugins-good gst-plugins-bad \
  gst-plugins-ugly gst-libav libpulse
```

The `openh264` encoder requires the GStreamer `openh264enc` element, normally
provided by the plugins-bad package. Check availability with
`gst-inspect-1.0 openh264enc`.

For AMD/Intel Wayland capture, also install `gst-plugin-va` on Arch Linux and
check `gst-inspect-1.0 vapostproc`. This supplies the VA DMA-BUF import and
path, including when the video encoder uses a different backend. When downloading
frames for another backend, doubletake fits and pads them with `videoscale` in
system memory to produce initialized black borders. This uses more CPU than VA
scaling and works from actual video dimensions, including rotated captures.
Other distributions may package `vapostproc` separately from their older
`vaapipostproc` plugin.

Hyprland users should use `xdg-desktop-portal-hyprland` 1.5.0 or newer. Version
1.4.1 can permanently stop producing frames after its buffer pool is exhausted;
installing `gst-plugin-va` does not reliably avoid that portal bug. See
[#62](https://github.com/omarroth/doubletake/issues/62).

niri 26.04 offers DMA-BUF-only screencasts that affected versions of
GStreamer's `pipewiresrc` cannot negotiate. Upgrade to a niri release with
shared-memory screencast support and, when necessary, enable niri's
`debug { disable-pipewire-dmabuf }` workaround. Adding caps after `pipewiresrc`
cannot repair a failure that occurs during PipeWire format negotiation. See
[#78](https://github.com/omarroth/doubletake/issues/78).

You can also install from the AUR:

- [`doubletake`](https://aur.archlinux.org/packages/doubletake) (stable release package)
- [`doubletake-git`](https://aur.archlinux.org/packages/doubletake-git) (latest from git)
- [`doubletake-bin`](https://aur.archlinux.org/packages/doubletake-bin) (prebuilt binary package)

## Tested Devices

These are devices that have been tested with doubletake. If there are devices not listed here that you have confirmed working or non-functional, please open an issue.

- AppleTV3,2 (2013 3rd generation)
- AppleTV11,1 (4K, 2021 2nd gen)
- AppleTV14,1 (4K, 2022 3rd gen) + Homepod (1st gen)
- AppleTV14,1 (4K, 2022 3rd gen)
- Mac17,2 (MacBook Pro, M5 14")
- Mac16,10 (Mac mini, M4)
- Roku Streaming Stick 4K (3820R2)
- Roku TV (K844X)
- Samsung TV TU8300 Series 4K UHD
- TCL 55R617 Roku TV (7120X)
- TCL 55Q6C
- Hisense 55H5BR
- Hisense 55A6QU
- Xiaomi 4K HDR TV (AFTBR92D74) (currently non-functional, see [#4](https://github.com/omarroth/doubletake/issues/4))

## Build

```sh
make
```

This builds two binaries into `bin/`:

- `bin/doubletake` dynamically links GStreamer and owns the video pipeline
  in-process. This is the default and supports live quality adaptation.
- `bin/doubletake-ctl` is always static and has no GStreamer dependency.

For developer testing, build the diagnostic receiver explicitly:

```sh
make doubletake-test-receiver
```

This creates `bin/doubletake-test-receiver`. It is excluded from default builds,
installation, and release artifacts. Its manual is available at
`man/man1/doubletake-test-receiver.1`.

### In-process GStreamer backend

Build the streaming binary directly with:

```sh
make doubletake
```

The default build requires the GStreamer core, app, and video development
packages plus a C compiler. It supports live target-bitrate,
frame-rate, and force-key-frame controls. Release builds target GStreamer 1.16
and are linked on Ubuntu 20.04 so their glibc baseline remains compatible with
that distribution and newer Linux systems.

With `-bitrate 0`, the default build enables the automatic network controller.
On Linux it samples each video TCP connection's delivery
rate, pacing rate, congestion window, RTT growth, retransmitted bytes, and
unsent queue; portable socket-write delay remains a fallback signal. Persistent
RTT growth supplies the same early queue-pressure role as the relative-delay
telemetry in Apple's controller. A shared multiroom encoder follows the weakest
current receiver path. Matching Apple's screen policy, 75 percent of estimated
bandwidth is allocated to video, with a 1 Mbit/s floor and doubletake's
resolution/FPS budget as the ceiling. Frame rate moves through 10/20/30/60 fps
tiers after five seconds of stable telemetry. Recovery is deliberately gradual.
Supplying a nonzero `-bitrate` keeps a fixed target and disables these automatic
changes.

The same control adapter covers x264, x265, OpenH264, NVENC, VA, Vulkan/NVENC,
and V4L2 encoders selected by doubletake. V4L2 updates its `video_bitrate`
extra-control; the others update their live `bitrate` property. Availability
still depends on the installed GStreamer plugin and driver exposing a mutable
control. The controller is receiver-neutral: it does not identify receiver
models or apply per-device presets.

## Install

Install binaries and man pages (default prefix: `/usr/local`):

```sh
sudo make install
```

Use a custom prefix if needed:

```sh
make install PREFIX=$HOME/.local SYSTEMDUSERDIR=$HOME/.local/share/systemd/user
```

Installation includes a systemd user unit for daemon mode. Enable it after a
system install with:

```sh
systemctl --user daemon-reload
systemctl --user enable --now doubletake.service
```

Uninstall:

```sh
sudo make uninstall
```

Run tests:

```sh
make test
```

### Audio output

By default, doubletake creates a selectable **doubletake** output while streaming;
route the applications you want to send there. Use `-audio-source monitor` to copy
the default local output instead, or `-no-audio` to disable audio. The selectable
output requires `pactl`, PulseAudio or `pipewire-pulse`, and GStreamer's `pulsesrc`.

### Multiroom playback

Daemon mode uses one timestamped audio capture and one encoder per negotiated
audio codec. New receivers reuse an active codec when they advertise it; otherwise
the daemon prefers lossless ALAC when offered. Receivers requiring another format
get one shared encoder for that format. AAC-ELD remains available in builds that
enable it. Encryption, RTP epochs,
retransmission and network-clock conversion remain independent for each receiver.

Video receivers sharing a codec and canvas use one capture/encoder and encoded
fan-out. Different canvases or codecs retain separate encoders to respect receiver
limits and image quality. They reuse the same selected source and Wayland portal
session. Joining or leaving does not restart capture for the other receivers.

All daemon destinations use a common audio/video playout budget of **250 ms**,
including the first receiver, so later joins do not require shifting an existing
stream's timeline. `-target-latency-ms` sets a different joint budget at daemon
startup. A capture whose measured requirement exceeds that budget is rejected;
increase the budget rather than giving that receiver a different deadline.
The foreground sender starts at the safest value in its connection-aware audio
profile. Receivers that send live-adaptive render reports allow the sender to
lower latency after a clean window and restore headroom after glitches. Normal
performance reports are telemetry only. Other receivers, and an explicit
`-target-latency-ms`, remain fixed.

Capture PTS and audio sample positions determine presentation time, regardless of
when an individual sender drains its queue. Queues are bounded: a stalled audio
consumer loses its subscription instead of blocking the other rooms. Timestamped
capture preserves complete frames through short sender stalls and catches up in
bounded bursts instead of creating RTP gaps; an adaptive stream also returns to
the safest latency tier as soon as a sender deadline is missed. Shared
capture requires GStreamer's RTP/ONVIF timestamp elements; output-time timestamp
fallback cannot align rooms. The daemon's status JSON reports `shared_audio`
source/encoder/receiver counts, `video_encoders`, and `playout_latency_ms`.

These changes align the sender's media timelines. Physical playback alignment
still depends on receiver clock mapping, decoder and output-device latency.
Headless timing and packet tests do not certify audible synchronization on real
receivers, particularly across different timing protocols and audio codecs.

### Optional AAC-ELD support

doubletake selects screen audio from the receiver's advertised
`supportedFormats.screenStream` mask. Default builds use the built-in ALAC
encoder and require no FDK-AAC dependency. AAC-ELD is needed only when a
receiver advertises it without ALAC; `-no-audio` remains available for those
receivers in a default build.

AAC-ELD is distinct from AAC-LC and requires the system `libfdk-aac`
development files and cgo:

```sh
CGO_ENABLED=1 go build -tags fdk_aac -o bin/doubletake ./cmd/doubletake
```

Install the package that provides the `fdk-aac` pkg-config file and headers for
your distribution before running that command. With this build, the foreground
sender prefers AAC-ELD when offered; the daemon prefers ALAC when it can share
that encoder across receivers.

## Firewall

No router port forwarding or Internet exposure is needed. With a default-deny
host firewall, select a local UDP range instead of using ephemeral ports:

```sh
doubletake -target 192.168.1.77 -port-range 60000-60010
```

Allow that range from the receiver or trusted LAN. Reserve at least three ports
per simultaneous receiver for timing, audio control, and audio data. Event and
video connections are outbound TCP.

## Password-protected receivers

For a receiver with **Require Password** enabled, provide its configured
password with `DOUBLETAKE_CODE`:

```sh
DOUBLETAKE_CODE='...' doubletake -target 192.168.1.77
```

The same option carries the onscreen PIN during `-pair`. The environment
variable takes precedence over `-code` and avoids exposing the credential in
shell history or process listings. **Require Password** uses a fixed configured
password; it does not display a pairing PIN.

Run with `-debug` to see the challenge and whether the retry was accepted.

## Usage

H.264 uses the receiver's advertised maximum canvas when it fits within
1920x1080, even when its nominal display canvas is 720p. Missing maxima retain
the nominal size; larger maxima require the separate high-resolution codec
path. By default, doubletake requests the highest usable canvas: automatic mode
uses a receiver-advertised high-resolution HEVC mode only after the local NVENC
4K preflight succeeds, and otherwise retains the H.264 canvas. Use
`-resolution WIDTHxHEIGHT` (or `-s WIDTHxHEIGHT`) to request a smaller canvas.
The optional `@REFRESH` suffix sets the capture frame rate and overrides
`-fps`, for example `-s 1920x1080@60`.

Saved PIN/password pairings record the receiver's identity and verify it on
every reconnect. A failed identity check stops the connection; it does not
fall back to unauthenticated pairing. Older credentials without a receiver key
require pairing again once. If a receiver was reset or replaced, use `-pair`
and enter its new on-screen code to establish the replacement identity.

When connecting directly by IP, pass `-device-id ID` to identify the receiver
you intend to reach. Interactive discovery supplies this ID automatically.
Daemon clients can include `device_id` in a connect request; otherwise the
daemon uses the ID currently advertised by discovery. Without an expected ID,
an unknown device ID is treated as a first connection. Discovery and transient
pairing alone do not authenticate a receiver.

```sh
# Discover AirPlay receivers on the network and stream
doubletake

# Disable audio for video-only mirroring
doubletake -no-audio

# Connect to a specific AirPlay receiver
doubletake -target 192.168.1.77

# First-time pairing with PIN (saves credentials for reuse)
doubletake -target 192.168.1.77 -pair

# Use saved credentials
doubletake -target 192.168.1.77 -creds airplay-credentials.json

# Adjust stream settings (bitrate 0 = auto)
doubletake -target 192.168.1.77 -fps 30 -bitrate 0

# Limit the target canvas; @60 also selects the capture frame rate
doubletake -target 192.168.1.77 -resolution 1920x1080
doubletake -target 192.168.1.77 -s 1920x1080@60

# Force a lower bitrate on weaker Wi-Fi
doubletake -target 192.168.1.77 -bitrate 2500

# Override the automatic audio/video playout latencies with one joint value
doubletake -target 192.168.1.77 -target-latency-ms 100

# Hardware encoding
doubletake -target 192.168.1.77 -hwaccel nvenc   # NVIDIA
doubletake -target 192.168.1.77 -hwaccel vaapi   # Intel/AMD
doubletake -target 192.168.1.77 -hwaccel v4l2    # Stateful V4L2 encoders (many ARM SoCs)

# OpenH264 software encoding
doubletake -target 192.168.1.77 -hwaccel openh264

# Select the highest usable receiver mode (the default)
doubletake -target 192.168.1.77

# Force one codec while retaining the selected resolution ceiling
doubletake -target 192.168.1.77 -video-codec hevc
doubletake -target 192.168.1.77 -video-codec h264

# Debug mode (verbose protocol logging)
doubletake -target 192.168.1.77 -debug

# Run daemon mode and control from a second shell
doubletake -daemonize -port-range 60000-60010
doubletake-ctl status
doubletake-ctl connect 192.168.1.77
doubletake-ctl connect 192.168.1.133
doubletake-ctl disconnect 192.168.1.77
doubletake-ctl disconnect
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | AirPlay receiver IP address or hostname (skip mDNS discovery) |
| `-device-id` | | Expected receiver device ID for saved-pairing lookup and identity checking |
| `-port` | 7000 | AirPlay port |
| `-code` | | Pairing code shown on the receiver; prefer `$DOUBLETAKE_CODE` |
| `-port-range` | | Local UDP range for timing/audio and receiver control traffic (at least 3 ports) |
| `-cred-backend` | `file` | Credential backend (`file` or `keyring`) |
| `-creds` | `~/.config/doubletake/credentials.json` | Credentials file path |
| `-pair` | false | Force new pairing |
| `-fps` | 30 | Frames per second |
| `-resolution`, `-s` | `max` | Target canvas: `max` or `WIDTHxHEIGHT[@REFRESH]`; `@REFRESH` overrides `-fps` |
| `-bitrate` | 0 | Video bitrate in kbps (`0` = automatic adaptive budget) |
| `-target-latency-ms` | 0 | Joint audio/video playout latency override in milliseconds (`0` = connection-aware foreground defaults; shared 250 ms in daemon mode) |
| `-hwaccel` | auto | Encoder preference: `auto`, `nvenc`, `vaapi`, `v4l2`, `openh264`, `none` |
| `-video-codec` | auto | Screen codec: highest usable `auto`, forced `h264`, or forced `hevc` |
| `-no-audio` | false | Disable audio streaming |
| `-audio-source` | output | Selectable doubletake output, or `monitor` to copy the default local output |
| `-test` | false | Use synthetic video source |
| `-x11-window-id` | | Capture one X11 window by decimal or hexadecimal window ID |
| `-x11-window-name` | | Capture one X11 window by name; prefer `-x11-window-id` |
| `-no-cursor` | false | Omit the pointer from screen capture |
| `-daemonize` | false | Run as background daemon with Unix socket control interface |
| `-socket` | `$XDG_RUNTIME_DIR/doubletake.sock`, or `/tmp/doubletake.sock` | Daemon control socket path |
| `-debug` | false | Verbose debug logging |
| `-help`, `-h` | | Show command-line help |

Only `-hwaccel auto` tries fallback encoders, in the order `vulkanh264enc`,
`nvh264enc`, `vah264enc`, `v4l2h264enc`, `openh264enc`, then `x264enc`. Explicit selections
fail if their required GStreamer encoder is unavailable; `none` forces x264 for
H.264 or x265 for explicitly requested HEVC.
The normal `-video-codec auto` path uses the requested resolution when it fits
the ordinary H.264 canvas. For a larger receiver-advertised maximum it selects
HEVC only when the receiver advertises multi-codec screen support and the local
NVENC 4K timing preflight succeeds; otherwise it falls back to H.264. Explicit
`-video-codec hevc` remains available with `nvh265enc` or `x265enc`; use
`-hwaccel none` to force the software path. Requested dimensions larger than a
receiver or codec ceiling are fitted within that ceiling while preserving the
requested aspect ratio, then normalized to even 4:2:0 dimensions.

Main10 alone does not turn an SDR X11 or portal capture into HDR: doubletake
preserves encoder-provided HDR SEI but does not invent PQ/HLG mastering metadata
or relabel SDR colors as HDR.

### Daemon Control (`doubletake-ctl`)

```sh
doubletake-ctl status
doubletake-ctl discover
doubletake-ctl devices
doubletake-ctl connect [target] [PIN-or-password]
doubletake-ctl pin <PIN-or-password>
doubletake-ctl disconnect [target]
doubletake-ctl mute [target]
doubletake-ctl unmute [target]
```

- `disconnect` without a target stops all active streams.
- `disconnect <target>` stops only that receiver.
- `mute`/`unmute` can operate globally or per target.
- `pin` retains its historical command name, but submits whichever credential
  the daemon requests: an on-screen PIN or a configured password. It is
  targetless and therefore requires exactly one waiting receiver; use
  `connect <target> <PIN-or-password>` when multiple receivers are waiting.

Daemon streams are grouped by codec and the normalized even-sized canvas resolved
during each receiver's SETUP. Targets with the same key share one capture and
encoder; targets with a different codec or canvas use independent encoders,
so connection order does not determine another receiver's size. A daemon-wide
`-resolution` target is independently fitted to each receiver's advertised
ceiling. Receivers which resolve to the same concrete codec and canvas share
the encoder.

With the default dynamically linked backend, `status` reports the live `adaptive`,
`estimated_bandwidth_kbps`, and `rate_control_receivers` fields for each stream.
Streams sharing an encoder report the same weakest-path estimate and current
bitrate/frame rate.

Fan-out uses a bounded queue per target within each group. A
stalled target is detached when its queue fills, without blocking peers that
share the encoder. Other canvas groups continue independently as well.

## Disclaimer

The majority of code for this project was written by LLMs. I've read through the code to make sure there's nothing obviously stupid, but if you're in a production or security-sensitive environment and need to use AirPlay (for whatever reason), do not use this project.

Since I assume most of the code for this project was trained from [UxPlay](https://github.com/FDH2/UxPlay) and similar projects, I've provided this project under a similar license. Most of the reverse engineering work has already been done by many other people and this project would not be possible without them.

## License

This project is licensed under the [GNU Lesser General Public License v3.0 or later](LICENSE) (`LGPL-3.0-or-later`). See the LICENSE file for the LGPL terms and [COPYING.GPL](COPYING.GPL) for the incorporated GPLv3 terms.

Releases v0.3.2 and earlier were provided under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`).
