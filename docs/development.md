# Development and release builds

## Build and test

`make` builds the dynamically linked sender and static controller in `bin/`.
Go 1.25+, a C compiler, `pkg-config`, and development headers for GStreamer 1.16+
and FDK-AAC are required. Runtime packages are listed in the [README](../README.md).

```sh
make test             # test the default linked GStreamer backend
make test-go          # test Go code without linking GStreamer
make test-gstreamer   # explicit alias for the linked tests
```

The diagnostic receiver is for developer testing only:

```sh
make doubletake-test-receiver
man -l man/man1/doubletake-test-receiver.1
```

It is excluded from default builds, installation, and release assets.
Most protocol and daemon tests run headlessly against local test receivers.
Sound-server integration tests require `DOUBLETAKE_TEST_PULSE_SERVER` pointing
to a **private** PulseAudio or pipewire-pulse instance; they change routing and
volume on that server. Ordinary tests do not modify the desktop sound server.
With `pulseaudio` installed, `scripts/test-audio-output.sh` starts and removes a
private server automatically to exercise those tests.

## Audio codecs

Default builds include ALAC and the external FDK-AAC encoder bridge for AAC-ELD.
Install the FDK-AAC development headers to build it. On Linux, doubletake loads
`libfdk-aac.so.2` or `libfdk-aac.so.1` at startup and checks for AAC-ELD support.
The library is supplied by the distribution and is not bundled. If neither
library supports AAC-ELD, doubletake uses ALAC when the receiver offers it;
AAC-ELD-only receivers need the library installed or `-no-audio`.

Linux builds with headers outside the compiler's search path can set
`CGO_CPPFLAGS=-I/path/to/include`. Other platforms use the `fdk-aac` pkg-config
file and link the library directly.

The foreground sender prefers AAC-ELD when the receiver advertises it. The
daemon prefers an existing shared codec or ALAC when possible. Receivers still
select only formats they advertise.

To build without FDK-AAC, retaining GStreamer and ALAC:

```sh
make BUILD_TAGS=gstreamer_cgo
make test BUILD_TAGS=gstreamer_cgo
```

This build cannot send audio to receivers requiring AAC-ELD without ALAC;
`-no-audio` remains available. `doubletake-ctl` is always built with cgo disabled
and requires no GStreamer or FDK-AAC runtime libraries.

## Prepare a release

Before tagging a release on `main`, run:

```sh
make test
make test-go
CGO_ENABLED=1 go test -race -tags 'gstreamer_cgo fdk_aac' ./...
CGO_ENABLED=1 go vet -tags 'gstreamer_cgo fdk_aac' ./...
make release VERSION=vX.Y.Z
sha256sum -c SHA256SUMS
```

Release targets write stripped, versioned binaries, manpages, and checksums in
the repository root. Build on Ubuntu 20.04 to retain the supported glibc and
GStreamer baseline; a binary built on a newer system can require newer libraries.
Check both x86-64 and ARM64 builds. The controller must remain static.

CI tests Go 1.25 and the current stable toolchain on both architectures, and
builds releases with stable Go on Ubuntu 20.04.
Version tags publish the four binaries, manpages, licenses, and a SHA-256 manifest
only when the tagged commit is on `main`. Put release notes in an annotated tag
message; lightweight tags fall back to the commit message. No tag or release is
created by the local build targets.

Headless tests cover protocol, capture, audio lifetime, and multi-target daemon
behavior. Release candidates should also be checked on real Wayland/X11 desktops
and receivers, including Wi-Fi, reconnects, pairing, volume, and multiroom audio.
