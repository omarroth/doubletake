# Development and release builds

## Build and test

`make` builds the dynamically linked sender and static controller in `bin/`.
Go 1.25+, a C compiler, `pkg-config`, and development headers for GStreamer 1.16+
and FDK-AAC are required. Runtime packages are listed in the [README](../README.md).

```sh
make test             # test the default linked GStreamer backend
make test-go          # test Go code without linking GStreamer
```

`make clean` removes `bin/`, `dist/`, and older build outputs in the project
root. With custom build, release, or distribution directories, it removes
the generated doubletake files and preserves unrelated contents.

The diagnostic receiver is for developer testing only:

```sh
make doubletake-test-receiver
man -l man/man1/doubletake-test-receiver.1
```

It is excluded from default builds, installation, and release assets.
Most protocol and daemon tests run headlessly against local test receivers.
To run the receiver regression matrix without contacting a device:

```sh
go test ./internal/airplay -run 'Test(Receiver|LegacyTransientPairing|RawPairVerify)' -count=1
```

The matrix covers raw, legacy HAP/AES, and CoreUtils/ChaCha sessions; identical
feature masks with different pairing protocols; authentication and reconnects;
and both accepted and rejected early RECORD requests. Legacy video is decrypted
with an independent continuous CTR stream. Modern video authenticates headers,
payloads, tags, and nonce order against fixed vectors and real sender packets.
The linked suite decodes H.264/HEVC video and ALAC/AAC-ELD audio, then simulates
presentation on the negotiated NTP/PTP clock. It checks decoded image changes,
PCM sample integrity and levels, timing, duplicates, reordering, RTP wraparound,
source timestamp gaps, RED recovery, and retransmission. Four simultaneous receivers also verify
shared capture and matching picture presentation deadlines across clocks.

```sh
CGO_ENABLED=1 go test -tags fdk_aac ./internal/airplay -run '^TestReceiverHeadless' -v
```

For a manual loopback test:

```sh
bin/doubletake-test-receiver -profile modern -stats-interval 1s
# In another terminal, use a temporary credentials file:
bin/doubletake -test -target 127.0.0.1 -port 7000 -creds /tmp/doubletake-test-creds.json
```

The diagnostic command enables headless decoding by default; `-decode=false`
retains protocol-only checks. Decoding uses GStreamer libav, the HEVC decoder
from plugins-bad, and the FDK-AAC runtime for AAC-ELD. The receiver opens no
display or audio output. Decode failures, invalid timestamps, queue overruns,
and unrecovered audio loss give it a nonzero exit status.
Reported A/V playhead separation includes the video-frame interval; matching
picture deadlines provide the finer multi-receiver synchronization check.

`-audio-drop-every 12` drops complete audio sequences, including their duplicate
datagrams, to exercise recovery. `-audio-jitter 50ms` controls the recovery and
initial reorder window. `-ntp` changes the timing advertisement independently
of the preset; combine it with `-accept-early-record` for CoreUtils/NTP startup.
The presets model protocol combinations; they do not emulate hardware decoders,
Wi-Fi radios, or speaker processing. Software decoder cold-start performance
depends on the host; presentation tests negotiate extra startup lead in CI.

Sound-server integration tests require `DOUBLETAKE_TEST_PULSE_SERVER` pointing
to a **private** PulseAudio or pipewire-pulse instance; they change routing and
volume on that server. Ordinary tests do not modify the desktop sound server.
With `pulseaudio` installed, `scripts/test-audio-output.sh` starts and removes a
private server automatically to exercise those tests.

## Audio codecs

Default Linux builds include ALAC and the external FDK-AAC bridge for AAC-ELD.
Install the FDK-AAC development headers to build it. On Linux, doubletake loads
`libfdk-aac.so.2` or `libfdk-aac.so.1` at startup and checks for AAC-ELD support.
The library is supplied by the distribution and is not bundled. If neither
library supports AAC-ELD, doubletake uses ALAC when the receiver offers it;
AAC-ELD-only receivers need the library installed or `-no-audio`.

Linux builds with headers outside the compiler's search path can set
`CGO_CPPFLAGS=-I/path/to/include`. Windows builds with cgo, including
`make doubletake-native`, look for an optional `libfdk-aac-2.dll` at startup.
For x86-64, copy it from the [MSYS2 UCRT64 FDK-AAC package](https://packages.msys2.org/packages/mingw-w64-ucrt-x86_64-fdk-aac)
next to `doubletake.exe`. Use a DLL matching the executable architecture.
Other platforms that opt in with `-tags fdk_aac` use the `fdk-aac` pkg-config
file and link the library directly.

The foreground sender prefers AAC-ELD when the receiver advertises it. The
daemon prefers an existing shared codec or ALAC when possible. Receivers still
select only formats they advertise.

On Linux, to build without FDK-AAC, retaining GStreamer and ALAC:

```sh
make BUILD_TAGS=
make test BUILD_TAGS=
```

This build cannot send audio to receivers requiring AAC-ELD without ALAC;
`-no-audio` remains available. `doubletake-ctl` is always built with cgo disabled
and requires no GStreamer or FDK-AAC runtime libraries.

## Prepare a release

Before tagging a release on `main`, run:

```sh
make test
make test-go
CGO_ENABLED=1 go test -race -tags fdk_aac ./...
CGO_ENABLED=1 go vet -tags fdk_aac ./...
make release VERSION=vX.Y.Z
(cd dist && sha256sum -c SHA256SUMS)
```

`make release` builds stripped binaries in `BUILD_DIR/release/TARGET/` and writes
`dist/doubletake-VERSION-TARGET.tar.gz` and `dist/SHA256SUMS`. `TARGET` defaults
to `linux-x86_64` or `linux-arm64` according to the Go target architecture.
Build on Ubuntu 20.04 to retain the supported glibc and GStreamer baseline;
a binary built on a newer system can require newer libraries. The sender links
GStreamer and includes the daemon controller as `doubletake ctl`. The release
also includes the standalone static controller.

The archive is a relative installation tree, with no enclosing version folder:

```text
usr/bin/doubletake
usr/bin/doubletake-ctl
usr/lib/systemd/user/doubletake.service
usr/share/bash-completion/completions/doubletake
usr/share/bash-completion/completions/doubletake-ctl -> doubletake
usr/share/licenses/doubletake/LICENSE
usr/share/licenses/doubletake/COPYING.GPL
usr/share/man/man1/doubletake.1
usr/share/man/man1/doubletake-ctl.1
```

Debian/Ubuntu and Arch packagers can extract this tree into the package staging
directory and supply their distribution's dependency and package metadata.
The tarball includes no runtime libraries, credentials, or service-enabling
hooks. Runtime dependencies are listed in the [README](../README.md).

For a source package, build first and install into `DESTDIR`:

```sh
make
make install-prebuilt PREFIX=/usr DESTDIR="$pkgdir"
```

`install-prebuilt` installs the files without invoking Go. `MANDIR`,
`SYSTEMDUSERDIR`, `BASHCOMPDIR`, and `LICENSEDIR` can be overridden for distribution
policy. The default source-install prefix remains `/usr/local`.

To package existing binaries, set `RELEASE_DIR` to a directory containing
`doubletake` and `doubletake-ctl`:

```sh
make package-release VERSION=vX.Y.Z TARGET=linux-arm64 RELEASE_DIR=/path/to/binaries
```

Packaging rejects a mismatched binary architecture. Archive ownership,
timestamps, file ordering, and gzip headers are normalized; `SOURCE_DATE_EPOCH`
defaults to the source commit's timestamp. CI checks staged installation,
uninstallation, reproducible repacking, and completion against actual command
help, including Ubuntu 20.04's bash-completion version.

CI tests Go 1.25 and the current stable toolchain on both architectures, and
builds releases with stable Go on Ubuntu 20.04. Local builds include the
supported archives present for the selected version in `SHA256SUMS`. CI
requires both architectures before writing the release manifest.
Version tags publish the two complete architecture archives and a SHA-256 manifest
only when the tagged commit is on `main`. Put release notes in an annotated tag
message; lightweight tags fall back to the commit message. No tag or release is
created by the local build targets.

## Desktop VM tests

The desktop jobs extract the x86-64 release archive and stream a real GTK test
window and a tone from a private audio sink. Ubuntu 24.04 runs Xvfb inside the
GitHub-hosted VM. A separate job boots Debian 13 in QEMU and runs Sway,
xdg-desktop-portal-wlr and PipeWire inside the guest. The guest builds portal
0.7.1 with a test-only startup check that allows shared-memory capture when
there is no GPU allocator. The sender and headless
receiver run in the same guest and share a clock for the timestamps.

Each job uploads `playback.json` and logs. The report includes time to first
picture, median and p95 video latency from GTK redraw to simulated
presentation, unique pictures per second, audio sample rate and sender
CPU time. The stream requests 24 fps and 300 ms of playout lead. The checks
require at least 16 unique pictures per second, video p95 at most 600 ms,
and sustained, non-silent decoded audio. The result includes software capture,
loopback transport, the configured buffer, and guest scheduling.

Run the same workload in a Linux VM with the desktop dependencies installed:

```sh
make doubletake-test-receiver BUILD_TAGS=
scripts/desktop-test/run.sh x11 dist/doubletake-VERSION-linux-x86_64.tar.gz \
  bin/doubletake-test-receiver desktop-report
```

`scripts/desktop-test/linux-vm.sh wayland IMAGE ARCHIVE RECEIVER REPORT_DIR`
provisions and runs the Debian cloud guest. Future macOS and Windows jobs can
reuse the on-screen timestamp format and receiver measurements with a native
fixture and capture stack on each platform.

Headless tests cover protocol, capture, audio lifetime, and multi-target daemon
behavior. Release candidates should also be checked on real Wayland/X11 desktops
and receivers, including Wi-Fi, reconnects, pairing, volume, and multiroom audio.
