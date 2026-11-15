# Compatibility

doubletake supports Linux with GStreamer 1.16 or newer. Release binaries use the
Ubuntu 20.04 glibc baseline. Hardware encoding depends on the installed plugins
and drivers; the same binary can use software encoding with `-hwaccel none`.

## Receivers tested

| Receiver | Model |
| --- | --- |
| Apple TV, 3rd generation (2013) | AppleTV3,2 |
| Apple TV 4K, 2nd generation (2021) | AppleTV11,1 |
| Apple TV 4K, 3rd generation (2022), also with 1st-generation HomePod | AppleTV14,1 |
| MacBook Pro, M5 14-inch | Mac17,2 |
| Mac mini, M4 | Mac16,10 |
| Roku Streaming Stick 4K | 3820R2 |
| Roku TV | K844X |
| Samsung TV | TU8300 Series 4K UHD |
| TCL Roku TV | 55R617 / 7120X |
| TCL TV | 55Q6C |
| Hisense TV | 55H5BR, 55A6QU |

The Xiaomi 4K HDR TV (AFTBR92D74) is reported as non-functional;
see [#4](https://github.com/omarroth/doubletake/issues/4).
Please report confirmed working receivers and failures not covered here.

macOS receivers may require accepting the connection on the receiving Mac.
Shared sender timelines do not guarantee audible synchronization between
different receiver models or external audio systems.

## Encoders and resolution

| `-hwaccel` | GStreamer elements |
| --- | --- |
| `auto` | First available supported encoder |
| `nvenc` | `nvh264enc`, then `vulkanh264enc`; `nvh265enc` for HEVC |
| `vaapi` | `vah264enc` |
| `v4l2` | `v4l2h264enc` (requires a compatible stateful hardware encoder) |
| `openh264` | `openh264enc` |
| `none` | `x264enc`, or `x265enc` for forced HEVC |

Only `auto` tries fallback methods. H.264 auto selection tries NVENC, VA, V4L2,
Vulkan, OpenH264, then x264. Explicit selections fail when their encoder is
unavailable. Live bitrate adjustment requires a mutable encoder control.
Vulkan remains a fallback because some encoder/driver combinations can crash
on shutdown; use `-hwaccel none` to compare software encoding on affected systems.

Automatic HEVC/high-resolution selection requires receiver support and a
successful local NVENC 4K timing probe. Forced `-video-codec hevc` also permits
x265. Explicit resolutions are fitted within receiver and codec limits.
Main10 encoding does not turn an SDR screen capture into HDR; existing encoder
SEI metadata is preserved.

## Wayland capture

Use the screencast portal for your compositor and ensure `pipewiresrc` is
available:

```sh
gst-inspect-1.0 pipewiresrc
```

AMD/Intel DMA-BUF capture can require the VA postprocessing plugin even when a
different encoder is selected. Check `gst-inspect-1.0 vapostproc`; Arch packages
it as `gst-plugin-va`. Older `vaapipostproc` packages do not provide that element.

- **Hyprland:** use `xdg-desktop-portal-hyprland` 1.5.0 or newer. Version 1.4.1
  can stop producing frames after exhausting its buffer pool.
  See [#62](https://github.com/omarroth/doubletake/issues/62).
- **niri:** DMA-BUF-only screencasts in niri 26.04 can fail negotiation with
  affected `pipewiresrc` versions. Use a niri version supporting shared-memory
  screencasts and, if needed, `debug { disable-pipewire-dmabuf }`.
  See [#78](https://github.com/omarroth/doubletake/issues/78).

## Audio

The selectable output requires `pactl`, PulseAudio or `pipewire-pulse`, and
GStreamer's `pulsesrc`. Its volume and mute affect the captured audio; default
routing and existing application routes are not changed automatically.

ALAC is built in. AAC-ELD support is optional and only required for receivers
which offer it without ALAC. See the [build instructions](development.md#optional-aac-eld).

Daemon mode shares one timestamped PCM source and one encoder per audio codec.
Video streams share an encoder when their resolved codec and canvas match.
Slow consumers have bounded queues so they cannot stall the other receivers.
The weakest receiver path controls quality within each shared video group.
