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
On a third-generation Apple TV, replace previously saved raw-protocol
credentials with a PIN pairing using `doubletake -pair -target ADDRESS`.
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

## macOS and Windows development builds

Install the [GStreamer runtime and development packages](https://gstreamer.freedesktop.org/download/).
With cgo enabled, `go build -o bin/ ./cmd/doubletake` builds the sender and
its daemon controller. Use `doubletake ctl -help` for daemon commands.

- macOS 13 or newer uses GStreamer's `avfvideosrc` for video and
  ScreenCaptureKit for system audio. Set `PKG_CONFIG_PATH` to
  `/Library/Frameworks/GStreamer.framework/Versions/1.0/lib/pkgconfig`.
  Allow Screen & System Audio Recording when prompted.
- On Windows, use MinGW-w64/UCRT GCC and `pkgconf`. Add GStreamer's `bin`
  directory to PATH and set `PKG_CONFIG_LIBDIR` to its `lib/pkgconfig`.
  Desktop capture uses `d3d11screencapturesrc` and `wasapi2src` for audio
  loopback. If Go rejects static LLVM LTO archives from the MSVC SDK, build
  with a private copy of the SDK and remove those `.a` archives from its
  `lib` directory. Keep the `.lib` import libraries.

CI verifies custom media playback through a loopback receiver on both
platforms. Desktop capture requires an interactive session with the
appropriate display and audio permissions.

## Builds without GStreamer

Run `make doubletake-native` on the target platform. On macOS and Windows,
a C compiler and the OS SDK are required at build time. With cgo enabled,
`go build -tags no_gstreamer -o bin/native/ ./cmd/doubletake` is equivalent.
The Linux target builds with cgo disabled.

| Platform | Desktop video | System audio |
| --- | --- | --- |
| macOS 13+ | ScreenCaptureKit display capture and VideoToolbox. H.264 by default, with explicit HEVC available. | ScreenCaptureKit monitor route |
| Windows 10+ | Primary-display GDI capture and Media Foundation's software H.264 encoder. | WASAPI loopback |
| Linux | Use the regular GStreamer build for Wayland or X11. | PulseAudio or PipeWire's PulseAudio service over its Unix socket |

On macOS, allow Screen & System Audio Recording. Windows editions that omit
Media Foundation require the Windows media components for video. On Linux,
use `-no-video` for audio-only playback, including through the daemon. These
builds include ALAC. Receivers that require AAC-ELD need a build with an
AAC-ELD encoder.

The regular build covers custom file, HTTP and stdin playback, Linux video,
and `-audio-sink output`. It also provides the GStreamer video encoders for
Windows hardware acceleration.

## Audio

Audio defaults to monitoring the local output. The selectable output
(`-audio-sink output`) requires `pactl`, PulseAudio or `pipewire-pulse`, and
GStreamer's `pulsesrc`. Use its volume and mute controls for the captured audio
and route applications to it through your sound settings.

ALAC is built in. Default Linux builds also support AAC-ELD when the external
FDK-AAC library is installed. With ALAC alone, the receiver must offer ALAC.
See [audio codec build options](development.md#audio-codecs).

Daemon mode shares one timestamped PCM source and one encoder per audio codec.
Video streams share an encoder when their resolved codec and canvas match.
Slow consumers have bounded queues so they cannot stall the other receivers.
The weakest receiver path controls quality within each shared video group.
