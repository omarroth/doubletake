# Changelog

## Unreleased

Changes since 0.5.0:

- **Adaptive video:** the default sender now links GStreamer and adjusts bitrate
  and frame rate during streaming, including the weakest path in a shared group.
- **Resolution control:** `-resolution` / `-s WIDTHxHEIGHT[@FPS]` limits the target
  canvas; the default selects the highest usable receiver mode.
- **Selectable audio output:** route applications to the doubletake sink, with
  working volume, mute, saved levels, and cleanup after exit or a crash.
- **Smoother audio:** source timestamps, improved buffering and retransmission,
  and receiver-guided latency adjustment reduce gaps and hitching.
- **Shared multiroom pipelines:** daemon streams share audio capture, per-codec
  audio encoders, and compatible video encoders on a common playback timeline.
- **Live receiver search:** discovery keeps running while the list updates in a
  stable order; select a receiver immediately without pressing Enter.
- **Pairing and receiver compatibility:** verify saved receiver identities,
  improve PTP/NTP negotiation, and initialize audio correctly on macOS receivers.
- **Capture compatibility:** add V4L2 encoding, correct Wayland orientation and
  padding, preserve SEI metadata, and handle older GStreamer packet boundaries.
- **Release portability:** Ubuntu 20.04/GStreamer 1.16 builds for x86-64 and
  ARM64, a static controller, download checksums, and `-version` reporting.

Upgrade notes: the sender now requires GStreamer 1.16+ runtime libraries; the
controller remains static. The `-direct-key` and `-no-encrypt` options and the
`doubletake-static` release binary are removed. The diagnostic receiver is now a
developer-only build. Source builds require Go 1.25+ and GStreamer development headers.
