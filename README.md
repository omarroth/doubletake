# doubletake

Mirror a desktop and audio to Apple TV, macOS, and compatible AirPlay receivers.

- Screen capture on Linux (Wayland and X11), macOS, and Windows.
- Automatic video quality adjustment and configurable resolution.
- System audio capture, with a selectable output on Linux.
- Multiple receivers through the daemon and [KDE Plasma widget](plasmoid/).

See the [compatibility notes](docs/compatibility.md) for tested receivers,
capture requirements, and troubleshooting.

## Install

### Linux

Download `doubletake-VERSION-linux-x86_64.tar.gz` or
`doubletake-VERSION-linux-arm64.tar.gz` from
[Releases](https://github.com/omarroth/doubletake/releases), along with
`SHA256SUMS`. Verify the download, then extract it into the filesystem root
(replace `vX.Y.Z` with the downloaded version):

```sh
sha256sum --ignore-missing -c SHA256SUMS
sudo tar -xzf doubletake-vX.Y.Z-linux-x86_64.tar.gz -C /
```

Each archive includes both commands in `/usr/bin`, manuals, bash completion,
licenses, and a systemd user service. Enable the service separately if desired.

`doubletake` requires GStreamer 1.16+ and its runtime plugins. Install FDK-AAC
to enable AAC-ELD audio; otherwise doubletake uses ALAC when supported by the
receiver. The optional standalone controller `doubletake-ctl` is static. Release
binaries target Ubuntu 20.04 and newer Linux systems.

On Ubuntu/Debian:

```sh
sudo apt install gstreamer1.0-plugins-base \
  gstreamer1.0-plugins-good gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly \
  gstreamer1.0-libav gstreamer1.0-pipewire gstreamer1.0-pulseaudio pulseaudio-utils \
  bash-completion
```

For AAC-ELD, also install `libfdk-aac2` (`libfdk-aac1` on Ubuntu 20.04).
FDK-AAC may require enabling additional package repositories.

On Arch Linux:

```sh
sudo pacman -S --needed gstreamer gst-plugins-base gst-plugins-good \
  gst-plugins-bad gst-plugins-ugly gst-libav gst-plugin-pipewire libpulse fdk-aac \
  bash-completion
```

Wayland also requires PipeWire and a working desktop screencast portal.
For AMD/Intel capture, install the package providing `vapostproc`
(`gst-plugin-va` on Arch). See [compatibility notes](docs/compatibility.md)
for compositor-specific issues.

Arch users can also use the AUR packages
[`doubletake`](https://aur.archlinux.org/packages/doubletake),
[`doubletake-git`](https://aur.archlinux.org/packages/doubletake-git), or
[`doubletake-bin`](https://aur.archlinux.org/packages/doubletake-bin).

### macOS and Windows

Download the matching archive and `SHA256SUMS` from
[Releases](https://github.com/omarroth/doubletake/releases).

| Platform | Archive |
| --- | --- |
| macOS 13+ on Apple silicon or Intel | `doubletake-VERSION-macos-universal.tar.gz` |
| Windows x86-64 | `doubletake-VERSION-windows-x86_64.zip` |
| Windows ARM64 | `doubletake-VERSION-windows-arm64.zip` |

Extract the archive into a folder and run `./doubletake` on macOS or
`.\doubletake.exe` in PowerShell. Both commands are at the top level. These
builds use the native desktop capture and need no GStreamer installation.
On macOS, allow Screen & System Audio Recording.
File, HTTP, and stdin playback require a GStreamer-enabled sender.

For AAC-ELD on Windows, put `libfdk-aac-2.dll` alongside the executable.
Use the MSYS2 package for [x86-64](https://packages.msys2.org/packages/mingw-w64-ucrt-x86_64-fdk-aac)
or [ARM64](https://packages.msys2.org/packages/mingw-w64-clang-aarch64-fdk-aac).
See the [native capture compatibility notes](docs/compatibility.md#builds-without-gstreamer).

## Build from source

Requires Go 1.25+, a C compiler, `pkg-config`, and GStreamer/FDK-AAC development headers.
On Ubuntu/Debian, install these in addition to the runtime packages:

```sh
sudo apt install build-essential pkg-config \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libfdk-aac-dev gstreamer1.0-tools
```

```sh
make                 # bin/doubletake and bin/doubletake-ctl
make test
sudo make install    # binaries, manuals, completion, licenses, and user service
```

For a user installation:

```sh
make install PREFIX="$HOME/.local" SYSTEMDUSERDIR="$HOME/.local/share/systemd/user"
```

Use `make uninstall` with the same prefix to remove an installation.
[Developer notes](docs/development.md) cover codec build options,
the diagnostic receiver, tests, and distribution packaging.

Bash completion covers both commands, their options, enum values, and file
paths. With `bash-completion` installed, open a new shell after installation.

## Builds without GStreamer

`make doubletake-native` builds the same CLI at `bin/native/TARGET/doubletake`
(`doubletake.exe` on Windows).

- macOS 13+ uses ScreenCaptureKit and VideoToolbox for desktop mirroring.
- Windows uses built-in screen capture, Media Foundation H.264, and WASAPI audio.
- Linux supports audio-only playback with PulseAudio or pipewire-pulse.

Use the regular build for file, HTTP, and stdin sources, Linux desktop
mirroring, or the selectable Linux audio output. See the
[platform details](docs/compatibility.md#builds-without-gstreamer).

## Usage

Run `doubletake` to discover receivers and select one as it appears. You can also
connect directly:

```sh
doubletake -target 192.168.1.77
```

Follow the pairing prompt on first connection; credentials are saved for reuse.
For a configured receiver password, use `DOUBLETAKE_CODE`. After resetting or
replacing a receiver, use `-pair` to pair again. Saved pairings verify the
receiver's identity on reconnect.

By default, doubletake streams audio from your default local output while it
continues playing locally. On Linux with GStreamer, use `-audio-source output`
and select **doubletake** in your sound settings to route audio to the receiver.
Use `-no-audio` for video only or `-no-video` for audio-only playback.

Resolution defaults to the highest usable receiver mode. Video bitrate and frame
rate adapt to network conditions unless you set a fixed `-bitrate`.

```sh
doubletake -s 1920x1080@60       # limit resolution and set capture frame rate
doubletake -hwaccel nvenc       # request NVIDIA hardware encoding
doubletake -hwaccel vaapi       # request Intel/AMD hardware encoding
doubletake -hwaccel none        # use software encoding
```

Common options:

| Option | Purpose |
| --- | --- |
| `-target ADDRESS` | Connect to a specific receiver |
| `-pair` | Establish a new pairing |
| `-resolution WIDTHxHEIGHT[@FPS]`, `-s` | Set the target canvas; default `max` |
| `-fps FPS` | Capture frame rate; default `30` |
| `-bitrate KBPS` | Fixed bitrate; default `0` enables adaptation |
| `-hwaccel METHOD` | `auto`, `nvenc`, `vaapi`, `v4l2`, `openh264`, or `none` |
| `-video-codec CODEC` | `auto`, `h264`, or `hevc` |
| `-audio-source SOURCE` | `monitor` (default) or selectable `output` |
| `-no-audio` | Disable audio |
| `-no-video` | Stream audio only to a receiver with a supported audio endpoint |
| `-target-latency-ms MS` | Override the audio/video playout budget |
| `-debug` | Enable diagnostic logging |

Use `doubletake -help` or `man doubletake` for all options, and
`doubletake -version` when reporting a problem.

## Play media

```sh
doubletake -target 192.168.1.77 -source ./clip.mp4
doubletake -target 192.168.1.77 -source - < clip.mkv
doubletake -target 192.168.1.77 -source 'https://example.net/clip.mp4'
doubletake ctl play ./clip.mp4 192.168.1.77
```

Custom sources play the clip's video and audio and stop at end of input.
They require a GStreamer-enabled sender. Use `-no-audio` to play video only.
GStreamer must have decoders for the input tracks. Direct HTTP(S) media URLs
are fetched by doubletake. For stdin,
use a streamable container such as Matroska or MPEG-TS and pair first if the
receiver needs an interactive PIN. For example, pipe Streamlink output with
`streamlink --stdout URL best | doubletake -target RECEIVER_IP -source -`.
With a running daemon, `play` accepts a file or URL and uses the first free
display if you omit the target. Use `doubletake ctl disconnect TARGET` to stop early.

## Multiple receivers

Start the daemon, then control it from another terminal:

```sh
doubletake -daemonize
doubletake ctl connect 192.168.1.77
doubletake ctl connect 192.168.1.133
doubletake ctl status
doubletake ctl disconnect 192.168.1.77
doubletake ctl disconnect                # stop all streams
```

The daemon shares capture and encoding where receiver formats allow it.
Use `doubletake ctl -help` for all commands.
Use `doubletake ctl volume TARGET` to read an active receiver's level or
`doubletake ctl volume TARGET -18` to set it in dB.
Mirroring sessions default to 250 ms of playout lead.

HomePods and other compatible AirPlay speakers can stream audio without screen
capture. Choose one from interactive discovery, or use
`doubletake ctl devices` and connect several in daemon mode. Start the daemon
with `-no-video` to request audio-only playback on all connections. A direct
`-target` can also identify an AirPlay 2 speaker. With `-no-video`, doubletake
looks up the audio endpoint via mDNS. It prefers realtime AirPlay 2 audio and
shares one PTP clock across compatible speakers.
Speakers that offer classic RAOP can also use that transport. Direct audio
defaults to a 2-second playout lead. Start a speaker before a mirror to let the
mirror inherit the speaker's lead. Use `-target-latency-ms` to set a common lead
regardless of connection order. `doubletake ctl status` reports the transport,
clock and playout leads for each destination.
AirPlay 2 uses transient pairing or saved HomeKit credentials. Speakers that
require a new persistent pairing cannot be enrolled in audio-only mode yet.

Direct AirPlay 2 PTP audio binds UDP ports 319 and 320 independently of
`-port-range`. If it cannot bind them, doubletake tries AirPlay 2 with NTP.
If the receiver rejects that setup, doubletake can try its advertised classic
RAOP endpoint. On Linux systems that restrict access to these ports, enable
PTP with
`sudo setcap cap_net_bind_service=+ep "$(realpath ./bin/doubletake)"`.

Classic RAOP supports clear or RSA-wrapped audio and Digest passwords.
Audio-only playback follows the captured output's volume and mute when the
sound server provides those levels. See `man doubletake-ctl` for pairing and mute commands.

To run the installed daemon as a systemd user service:

```sh
systemctl --user daemon-reload
systemctl --user enable --now doubletake.service
```

## Troubleshooting

- **Firewall:** use `-port-range 60000-60010` and allow inbound UDP to that range
  from your receivers. Reserve three ports per simultaneous receiver. Allow UDP
  ports 319 and 320 from speakers using direct AirPlay 2 PTP audio. No router
  port forwarding is needed.
- **Capture or encoder errors:** check the [compatibility notes](docs/compatibility.md).
  `-hwaccel none` selects software encoding for comparison.
- **Audio:** check that audio is playing on your default local output. If using
  `-audio-source output`, route the desired applications to **doubletake**.
  Receivers requiring AAC-ELD need FDK-AAC installed. See [audio codecs](docs/development.md#audio-codecs).

## Disclaimer and license

The majority of code for this project was written by LLMs. I've read through the code to make sure there's nothing obviously stupid, but if you're in a production or security-sensitive environment and need to use AirPlay (for whatever reason), do not use this project.

Since I assume most of the code for this project was trained from [UxPlay](https://github.com/FDH2/UxPlay) and similar projects, I've provided this project under a similar license. Most of the reverse engineering work has already been done by many other people and this project would not be possible without them.

Licensed under [LGPL-3.0-or-later](LICENSE); see [COPYING.GPL](COPYING.GPL) for
the incorporated GPLv3 terms. Releases v0.3.2 and earlier used GPL-3.0-or-later.
