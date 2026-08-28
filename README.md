# doubletake

AirPlay screen mirroring sender for Linux. Streams your desktop to an Apple TV using the AirPlay mirroring protocol.

## Features

- Full AirPlay mirroring protocol (RTSP/HTTP + encrypted video stream)
- FairPlay SAP authentication (clean Go implementation)
- SRP-6a pairing with PIN and persistent credential storage
- Wayland (PipeWire/xdg-desktop-portal) and X11 screen capture
- H.264 encoding with NVENC, VA-API, OpenH264, and x264
- Capability-gated HEVC Main10/high-resolution encoding with NVENC or x265
- ChaCha20-Poly1305 stream encryption
- mDNS device discovery
- Daemon mode with multi-target streaming control (`doubletake-ctl`)
- In-process test receiver for hardware-free pairing and media-flow tests
- Automatic AirPlay screen/audio latency policy with an optional `-target-latency-ms` override
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

The `openh264` encoder requires the GStreamer `openh264enc` element, normally
provided by the plugins-bad package. Check availability with
`gst-inspect-1.0 openh264enc`.

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
- Samsung TV TU8300 Series 4K UHD
- Hisense 55A6QU
- Xiaomi 4K HDR TV (AFTBR92D74) (currently non-functional, see [#4](https://github.com/omarroth/doubletake/issues/4))

## Build

```sh
make
```

This builds the three binaries into `bin/`:

- `bin/doubletake`
- `bin/doubletake-ctl`
- `bin/doubletake-test-receiver`

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

### Optional AAC-ELD support

Doubletake selects screen audio from the receiver's advertised
`supportedFormats.screenStream` mask, preferring its built-in ALAC encoder when
available. AAC-ELD is enabled explicitly because it depends on the system
`libfdk-aac` development files and cgo:

```sh
CGO_ENABLED=1 go build -tags fdk_aac -o bin/doubletake ./cmd/doubletake
```

Install the package that provides the `fdk-aac` pkg-config file and headers for
your distribution before running that command. A default build reports a clear
error if advertised capabilities select AAC-ELD. A nonzero screen-audio mask
which advertises neither ALAC nor AAC-ELD is also rejected instead of silently
sending an unadvertised format. Use `-no-audio` to keep testing pairing, timing,
and video when the advertised audio format is unavailable.

## Firewall

doubletake reserves three consecutive UDP ports for timing and audio traffic.
Receiver-initiated NTP sessions probe the timing port during SETUP; PTP and
sender-initiated NTP sessions do not require that inbound timing traffic. The
event and video data channels are outbound TCP connections from doubletake to
ports returned by the receiver, so they do not require inbound firewall rules.
NTP and PTP use the same presentation policy; the timing protocol only changes
how timestamps are represented. In automatic mode, an ordinary connection uses
the AirPlay defaults observed in the checked-in sender artifacts: 75 ms for
video and 85 ms for screen audio. When the automatic high-resolution HEVC
preflight measures a longer local capture-to-access-unit path, doubletake adds
the same scheduling margin to both values. This keeps Apple's 10 ms relationship
while ensuring video reaches the receiver before its presentation deadline.

By default the OS assigns ephemeral ports. Use `-port-range MIN-MAX` to confine
the UDP ports to a small window you can open in your firewall (needs at least 3
ports):

```sh
doubletake -target 192.168.1.77 -port-range 60000-60010
```

Daemon mode uses the same range for every managed stream. Reserve at least
three available ports per receiver that may stream simultaneously.

Then with UFW:

```sh
sudo ufw allow from any proto udp to any port 60000:60010
```

For nftables/firewalld, add an equivalent rule allowing inbound UDP from the
receiver's address on the chosen range.

## Password-protected receivers

If the receiver has **Require Password** enabled (on an Apple TV: Settings →
AirPlay and HomeKit), it challenges the mirroring `SETUP` request with HTTP
Digest auth and mirroring fails with `HTTP 401` until doubletake answers it.
Pass the password with `-code`:

```sh
DOUBLETAKE_CODE='...' doubletake -target 192.168.1.77
```

`-code` carries whatever the receiver is asking for — the onscreen pairing PIN
during `-pair`, or the fixed password when "Require Password" is enabled.
`$DOUBLETAKE_CODE` is preferred over the flag: a command line is visible to
other users via `ps` and lands in shell history. The environment variable takes
precedence when both are set.

Pairing and Digest authentication remain separate wire protocols, but
doubletake deliberately uses one credential flow for both: a PIN/password
entered during pairing is retained for later Digest challenges and reconnects.
A receiver may consume that value during pairing, Digest auth, both, or neither.
Supplying `-code` does not by itself trigger re-pairing.

When the capability policy selects first-party CoreUtils/HAP pairing, a
configured fixed password is reserved for Digest authentication and is never
reused as an SRP pairing PIN, including with `-pair`. A legacy/HKP pairing flow
may consume the same entered value during both SRP and Digest when its protocol
requires it.

The CLI and Plasma applet prompt once after inspecting the receiver's security
mode. In the Plasma applet, an on-screen PIN uses a visible four-digit field,
while a configured password uses an unrestricted masked field. Doubletake does
not request or claim that a PIN is visible in password mode. The daemon exposes
the distinction while retaining `doubletake-ctl pin <PIN-or-password>` for
command compatibility when exactly one receiver is waiting. With concurrent
prompts, submit each value with `doubletake-ctl connect TARGET PIN-or-password`.

One thing that makes this confusing to diagnose: **"Require Password" is a
fixed password you set, not a rotating onscreen code.** Nothing appears on the
TV during `-pair`, and the prompt is asking for that configured password.

Run with `-debug` to see the challenge and whether the retry was accepted.

## Hardware-free test receiver

`doubletake-test-receiver` is an in-repository AirPlay receiver for exercising
pairing, encrypted RTSP, SETUP ordering, timing, event channels, and sustained
audio/video traffic without an Apple TV or third-party receiver. It is a
diagnostic sink, not a media player or a receiver-compatibility substitute.

Runtime selection is capability-driven. The selected device's mDNS `features`,
`fex`, `srcvers`, `protovers`, and `flags` remain available after discovery;
explicit `/info` fields take precedence and the advertisement fills omissions.
Pairing probes and the encryption state that actually negotiates then determine
the wire format. See [Receiver compatibility](docs/compatibility.md) for the
artifact cross-checks, explicitly labeled empirical exceptions, and end-to-end
flow.

Display sizing is resolved after the receiver creates its media session rather
than being frozen from the initial `/info`, which can omit `displays`. Doubletake
preflights the capture source first; on Wayland this completes the interactive
portal request and retains the authorized PipeWire source without starting the
encoder. Control SETUP then requests ordinary receiver info with
`combinedGetInfoWithControlSetup` (without a `qualifier`), and a returned `info`
dictionary takes precedence over the pre-session snapshot. If it is omitted,
doubletake makes one bounded `/info` refresh after the accepted control SETUP,
or after the accepted audio SETUP on a negotiated media-first path.

The encoder uses the resolved nominal `widthPixels`/`heightPixels` mirroring
canvas. `widthPixelsMax`/`heightPixelsMax` describe the receiver's upper decoding
ceiling; they do not select the ordinary mirroring resolution. If display
metadata remains unavailable, screen endpoints use the artifact-backed feature
28 default of 1920x1080, or 1280x720 when feature 28 is absent.

SETUP ordering is negotiated independently of the advertisement: every session
starts with Apple's control-only form and makes one media-first transition only
if that control shape is explicitly rejected. Feature 59 selects only the
initial audio descriptor (`streamConnections` versus `controlPort`), with one
alternate-shape retry after an explicit rejection. Encrypted HAP sessions keep
FairPlay material in stream descriptors; plaintext/raw sessions use available
legacy FairPlay roots on control and media SETUP.

The named profiles are receiver-side validation presets covering combinations
observed on modern Apple, Roku, LG webOS, legacy Apple TV/UxPlay, and
AirServer/Airtame implementations. They deliberately keep pairing, SETUP order,
timing, FairPlay, and audio layout as separate compatibility axes. Profile name,
advertised receiver name, model, and manufacturer do not select sender behavior;
the sender uses advertised capabilities and the protocol that actually
negotiates.
The profile table describes fixtures; the Tested Devices list above remains the
record of hardware validation.

The receiver parses the outer AirPlay video framing and counts video and audio
traffic. Its AppleTV3 and UxPlay profiles also authenticate the FairPlay key,
decrypt legacy AES-CTR video, and validate the resulting AVCC/NAL structure.
It does not decode or display video or play audio; other encrypted media paths
remain transport-only checks.

Start a Roku-compatible receiver whose configured fixed password is required by
both SRP and Digest authentication. This mode does not display a PIN:

```sh
DOUBLETAKE_RECEIVER_CODE='aaaaaaaa' \
  bin/doubletake-test-receiver -profile roku -auth combined -debug
```

Then run the real sender against it from another terminal:

```sh
DOUBLETAKE_CODE='aaaaaaaa' \
  bin/doubletake -target 127.0.0.1 -port 7000 -pair -test
```

The receiver profiles are coherent validation combinations:

| Profile | Capability/protocol combination exercised |
|---------|-------------------------------------------|
| `modern` | Omits pre-session display metadata and returns a 1920x1080 nominal canvas with a 3840x2160 ceiling through combined control SETUP info; also exercises CoreUtils HAP, encrypted control, features 41/59, PTP, `streamConnections`, ALAC, and descriptor-only FairPlay keys |
| `roku` | Rejects the initial control SETUP and exercises the one media-first fallback; third-party/HKP pairing, the `377.40.x` NTP exception, ALAC, and one alternate audio-descriptor retry under authenticated HAP |
| `lg` | Rejects the initial control SETUP and exercises the one media-first fallback; third-party/HKP HAP, feature-41 PTP with a local clock anchor, feature-59-absent `controlPort` + `shk`, and ALAC |
| `appletv3` | Rejects the initial control SETUP and exercises the one media-first fallback; raw pairing with feature 27, receiver-initiated NTP, original raw FairPlay derivation, ALAC, and plaintext root FairPlay keys |
| `uxplay` | Rejects the initial control SETUP and exercises the one media-first fallback; raw pairing without feature 27, `X-Apple-PD` FairPlay-secret mixing, NTP, ALAC, plaintext FairPlay roots, and omitted optional `eventPort` |
| `airserver` (`airtame` alias) | Accepts the initial control SETUP; a rejected HAP probe followed by raw fallback, plaintext NTP, feature-59 `streamConnections` followed by one accepted `controlPort` retry, advertised AAC-ELD, and plaintext root FairPlay keys |

Authentication modes all use the single `-code` value (or
`$DOUBLETAKE_RECEIVER_CODE`):

| Mode | Pair setup | RTSP Digest |
|------|------------|-------------|
| `none` | transient | no |
| `pin` | code required; advertises an on-screen PIN | no |
| `password` | fixed code required | no |
| `digest` | transient | code required |
| `combined` | fixed password required; no on-screen PIN | same password required |

Use `-listen 127.0.0.1:0` to choose an ephemeral port, and
`-stats-interval 1s` to print live counters. See
`doubletake-test-receiver(1)` for all options.

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
doubletake -target 192.168.1.77 -fps 30 -bitrate 0

# Force a lower bitrate on weaker Wi-Fi
doubletake -target 192.168.1.77 -bitrate 4500

# Override the automatic audio/video playout latencies with one joint value
doubletake -target 192.168.1.77 -target-latency-ms 100

# Hardware encoding
doubletake -target 192.168.1.77 -hwaccel nvenc   # NVIDIA
doubletake -target 192.168.1.77 -hwaccel vaapi   # Intel/AMD

# OpenH264 software encoding
doubletake -target 192.168.1.77 -hwaccel openh264

# Automatic capability-gated HEVC Main10/high-resolution selection is the default
doubletake -target 192.168.1.77

# Force one codec (HEVC uses the receiver's maximum canvas)
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
doubletake-ctl reset-restore-token 192.168.1.133
doubletake-ctl disconnect
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-target` | | Apple TV IP (skip mDNS discovery) |
| `-port` | 7000 | AirPlay port |
| `-code` | | Pairing PIN shown on the receiver, or its configured password when "Require Password" is enabled (see [Password-protected receivers](#password-protected-receivers)); prefer `$DOUBLETAKE_CODE` |
| `-port-range` | | Local UDP port range for timing/audio (at least 3 ports) |
| `-cred-backend` | `file` | Credential backend (`file` or `keyring`) |
| `-creds` | `~/.config/doubletake/credentials.json` | Credentials file path |
| `-pair` | false | Force new pairing |
| `-fps` | 30 | Frames per second |
| `-bitrate` | 0 | Video bitrate in kbps (`0` = auto) |
| `-target-latency-ms` | 0 | Joint audio/video playout latency override in milliseconds (`0` = automatic AirPlay policy with separate defaults) |
| `-hwaccel` | auto | Encoder preference: `auto`, `nvenc`, `vaapi`, `openh264`, `none` |
| `-video-codec` | auto | Screen codec: capability-driven `auto`, forced `h264`, or forced `hevc` |
| `-no-encrypt` | false | Disable RTSP header encryption (debugging only) |
| `-direct-key` | false | Use `shk`/`shiv` directly without SHA-512 derivation |
| `-no-audio` | false | Disable audio streaming |
| `-test` | false | Use synthetic video source |
| `-daemonize` | false | Run as background daemon with Unix socket control interface |
| `-socket` | `$XDG_RUNTIME_DIR/doubletake.sock` | Daemon control socket path |
| `-debug` | false | Verbose debug logging |

Only `-hwaccel auto` tries fallback encoders, in the order `vulkanh264enc`,
`nvh264enc`, `vah264enc`, `openh264enc`, then `x264enc`. Explicit selections
fail if their required GStreamer encoder is unavailable; `none` forces x264 for
H.264 or x265 for explicitly requested HEVC.
In the normal `-video-codec auto` path, HEVC is selected only when final
session information advertises feature 42 and a maximum above 1920x1080, and
the sender has the complete `nvh265enc` Main10/timestamp pipeline. Otherwise it
uses H.264 at the nominal canvas. Explicit `-video-codec hevc` remains available
with `nvh265enc` or `x265enc`; use `-hwaccel none` to force the software path.
Preflight verifies the automatic path with a sustained, timestamped 4K P010
sample through the same HEVC parser and RTP/ONVIF framing chain before receiver
SETUP begins. It measures the source-PTS-to-access-unit p95 and reserves a
bounded delivery margin; an unusable or excessively delayed hardware path falls
back to H.264. The result is cached per requested frame rate.

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
doubletake-ctl reset-restore-token <target>
doubletake-ctl mute [target]
doubletake-ctl unmute [target]
```

- `disconnect` without a target stops all active streams.
- `disconnect <target>` stops only that receiver.
- `mute`/`unmute` can operate globally or per target.
- `reset-restore-token <target>` stops one fully streaming receiver, clears only
  its saved Wayland portal restore token, and reconnects it on the same IP and
  port. Pairing credentials and other streams are unchanged. The command rejects
  targets sharing a capture group; disconnect those peers first so the old portal
  source can be stopped before a replacement is authorized.
- `pin` retains its historical command name, but submits whichever credential
  the daemon requests: an on-screen PIN or a configured password. It is
  targetless and therefore requires exactly one waiting receiver; use
  `connect <target> <PIN-or-password>` when multiple receivers are waiting.

Daemon streams are grouped by codec and the normalized even-sized canvas resolved
during each receiver's SETUP. Targets with the same key share one capture and
encoder; targets with a different codec or canvas use independent encoders,
so connection order does not determine another receiver's size. For example, a
receiver reporting a 1920x1080 canvas and a 3840x2160 maximum joins the
3840x2160 HEVC group when automatic HEVC is available, or the 1920x1080 H.264
group when it is unavailable or H.264 is forced.
Fan-out uses a bounded queue per target within each group. A
stalled target is detached when its queue fills, without blocking peers that
share the encoder. Other canvas groups continue independently as well.

## Disclaimer

The majority of code for this project was written by LLMs. I've read through the code to make sure there's nothing obviously stupid, but if you're in a production or security-sensitive environment and need to use AirPlay (for whatever reason), do not use this project.

Since I assume most of the code for this project was trained from [UxPlay](https://github.com/FDH2/UxPlay) and similar projects, I've provided this project under a similar license. Most of the reverse engineering work has already been done by many other people and this project would not be possible without them.

## License

This project is licensed under the [GNU Lesser General Public License v3.0 or later](LICENSE) (`LGPL-3.0-or-later`). See the LICENSE file for the LGPL terms and [COPYING.GPL](COPYING.GPL) for the incorporated GPLv3 terms.

Releases v0.3.2 and earlier were provided under the GNU General Public License v3.0 or later (`GPL-3.0-or-later`).
