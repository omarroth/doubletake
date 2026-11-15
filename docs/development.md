# Development and release builds

## Build and test

`make` builds the dynamically linked sender and static controller in `bin/`.
Go 1.25+, a C compiler, `pkg-config`, and GStreamer 1.16+ development headers
are required. Runtime packages are listed in the [README](../README.md).

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

## Optional AAC-ELD

Install the headers, library, and `fdk-aac` pkg-config file for `libfdk-aac`, then:

```sh
make BUILD_TAGS='gstreamer_cgo fdk_aac'
make test BUILD_TAGS='gstreamer_cgo fdk_aac'
```

This retains the default GStreamer backend and adds AAC-ELD encoding. The
foreground sender prefers AAC-ELD when offered; the daemon prefers an existing
shared codec or ALAC when possible. Default and release builds require no FDK-AAC.

## Prepare a release

Keep the next release's highlights in [CHANGELOG.md](../CHANGELOG.md). Before
tagging, name its Unreleased section with the chosen version and run:

```sh
make test
make test-go
CGO_ENABLED=1 go test -race -tags gstreamer_cgo ./...
CGO_ENABLED=1 go vet -tags gstreamer_cgo ./...
make release VERSION=vX.Y.Z
sha256sum -c SHA256SUMS
```

Release targets write stripped, versioned binaries, manpages, and checksums in
the repository root. Build on Ubuntu 20.04 to retain the supported glibc and
GStreamer baseline; a binary built on a newer system can require newer libraries.
Check both x86-64 and ARM64 builds. The controller must remain static.

CI tests Go 1.25 and the current stable toolchain on both architectures, and
builds releases with stable Go on Ubuntu 20.04.
Tag builds publish the four binaries, manpages, licenses, and a SHA-256 manifest.
Annotated tag messages supply release notes; lightweight tags use the matching
changelog section. No tag or release is created by the local build targets.

Headless tests cover protocol, capture, audio lifetime, and multi-target daemon
behavior. Release candidates should also be checked on real Wayland/X11 desktops
and receivers, including Wi-Fi, reconnects, pairing, volume, and multiroom audio.
