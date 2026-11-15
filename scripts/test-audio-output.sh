#!/bin/sh
# Run only on a private PulseAudio server, never the desktop sound server.
set -eu

audio_runtime=$(mktemp -d)
audio_pid=
cleanup() {
    if [ -n "$audio_pid" ]; then
        kill "$audio_pid" 2>/dev/null || true
        wait "$audio_pid" 2>/dev/null || true
    fi
    rm -rf "$audio_runtime"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

export PULSE_SERVER="unix:$audio_runtime/native"
export PULSE_RUNTIME_PATH="$audio_runtime"
export PULSE_STATE_PATH="$audio_runtime/state"
export DOUBLETAKE_TEST_PULSE_SERVER="$PULSE_SERVER"
mkdir -p "$PULSE_STATE_PATH"
pulseaudio --daemonize=no --exit-idle-time=-1 --use-pid-file=no -n \
    --load="module-native-protocol-unix socket=$audio_runtime/native auth-anonymous=1" \
    --load=module-device-restore > "$audio_runtime/server.log" 2>&1 &
audio_pid=$!
attempt=0
until pactl info >/dev/null 2>&1; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 50 ] || ! kill -0 "$audio_pid" 2>/dev/null; then
        cat "$audio_runtime/server.log" >&2
        exit 1
    fi
    sleep 0.1
done

CGO_ENABLED=1 go test -count=1 -tags "${BUILD_TAGS:-gstreamer_cgo fdk_aac}" ./internal/airplay \
    -run '^Test(AudioOutputOwnerExitIntegration|DedicatedAudioOutput.*Integration|SharedAudioOutputIntegration)$'

if pactl list short modules | grep -Fq doubletake.generation=; then
    printf 'Audio integration tests left a doubletake output behind\n' >&2
    exit 1
fi
