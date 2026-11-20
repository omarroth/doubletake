# doubletake

Mirror a Linux desktop and audio to Apple TV, macOS, and compatible AirPlay receivers.

- Wayland and X11 screen capture, with hardware or software encoding.
- Automatic video quality adjustment and configurable resolution.
- A selectable audio output, with volume and mute controls.
- Multiple receivers through the daemon and [KDE Plasma widget](plasmoid/).

See the [compatibility notes](docs/compatibility.md) for tested receivers,
capture requirements, and troubleshooting.

## Install

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
receiver. `doubletake-ctl` is static and requires neither library. Release
binaries target Ubuntu 20.04 and newer Linux systems.

On Ubuntu/Debian:

```sh
sudo apt install gstreamer1.0-tools gstreamer1.0-plugins-base \
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

## Build from source

Requires Go 1.25+, a C compiler, `pkg-config`, and GStreamer/FDK-AAC development headers.
On Ubuntu/Debian, install these in addition to the runtime packages:

```sh
sudo apt install build-essential pkg-config \
  libgstreamer1.0-dev libgstreamer-plugins-base1.0-dev libfdk-aac-dev
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

Select **doubletake** in your sound settings to route applications to the
receiver. Use `-audio-source monitor` to copy your local output instead, or
`-no-audio` for video only.

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
| `-target ADDRESS` | Connect without discovery |
| `-pair` | Establish a new pairing |
| `-resolution WIDTHxHEIGHT[@FPS]`, `-s` | Set the target canvas; default `max` |
| `-fps FPS` | Capture frame rate; default `30` |
| `-bitrate KBPS` | Fixed bitrate; default `0` enables adaptation |
| `-hwaccel METHOD` | `auto`, `nvenc`, `vaapi`, `v4l2`, `openh264`, or `none` |
| `-video-codec CODEC` | `auto`, `h264`, or `hevc` |
| `-audio-source SOURCE` | Selectable `output` or local-output `monitor` |
| `-no-audio` | Disable audio |
| `-target-latency-ms MS` | Override the audio/video playout budget |
| `-debug` | Enable diagnostic logging |

Use `doubletake -help` or `man doubletake` for all options, and
`doubletake -version` when reporting a problem.

## Multiple receivers

Start the daemon, then control it from another terminal:

```sh
doubletake -daemonize
doubletake-ctl connect 192.168.1.77
doubletake-ctl connect 192.168.1.133
doubletake-ctl status
doubletake-ctl disconnect 192.168.1.77
doubletake-ctl disconnect                # stop all streams
```

The daemon shares capture and encoding where receiver formats allow it.
Mirroring sessions default to 250 ms of playout lead.

Discovered speakers that offer classic RAOP (UDP and ALAC) can stream audio
without screen capture. Choose one from interactive discovery, or use
`doubletake-ctl devices` and connect several in daemon mode. Classic RAOP
sessions default to a 2-second audio lead and schedule shared audio samples on
the same sender timeline. A common `-target-latency-ms` value can set the same
lead for mirror and speaker sessions if both accept it. Actual output timing
depends on receiver buffering and audio hardware.

Classic RAOP supports clear or RSA-wrapped audio and Digest passwords.
Speakers that require AirPlay 2 media playback or RAOP PIN pairing still need
those protocols. See `man doubletake-ctl` for pairing and mute commands.

To run the installed daemon as a systemd user service:

```sh
systemctl --user daemon-reload
systemctl --user enable --now doubletake.service
```

## Troubleshooting

- **Firewall:** use `-port-range 60000-60010` and allow inbound UDP to that range
  from your receivers. Reserve three ports per simultaneous receiver. No router
  port forwarding is needed.
- **Capture or encoder errors:** check the [compatibility notes](docs/compatibility.md).
  `-hwaccel none` selects software encoding for comparison.
- **Audio:** route the desired applications to the doubletake output. Receivers
  requiring AAC-ELD need FDK-AAC installed; see [audio codecs](docs/development.md#audio-codecs).

## Disclaimer and license

The majority of code for this project was written by LLMs. I've read through the code to make sure there's nothing obviously stupid, but if you're in a production or security-sensitive environment and need to use AirPlay (for whatever reason), do not use this project.

Since I assume most of the code for this project was trained from [UxPlay](https://github.com/FDH2/UxPlay) and similar projects, I've provided this project under a similar license. Most of the reverse engineering work has already been done by many other people and this project would not be possible without them.

Licensed under [LGPL-3.0-or-later](LICENSE); see [COPYING.GPL](COPYING.GPL) for
the incorporated GPLv3 terms. Releases v0.3.2 and earlier used GPL-3.0-or-later.
