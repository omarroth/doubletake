#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 4 || ! $1 =~ ^(x11|wayland)$ ]]; then
    echo "Usage: $0 {x11|wayland} RELEASE_TARBALL TEST_RECEIVER REPORT_DIRECTORY" >&2
    exit 2
fi
if [[ ${DOUBLETAKE_TEST_BUS:-} != private ]]; then
    exec env DOUBLETAKE_TEST_BUS=private dbus-run-session -- "$0" "$@"
fi
mode=$1
package=$(realpath "$2")
receiver=$(realpath "$3")
mkdir -p -- "$4"
reports=$(realpath "$4")
scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
work=$(mktemp -d)
pids=()
cleanup() {
    if (( ${#pids[@]} )); then
        kill "${pids[@]}" 2>/dev/null || true
        wait "${pids[@]}" 2>/dev/null || true
    fi
    if mountpoint -q "$work/runtime/doc"; then
        fusermount3 -uz "$work/runtime/doc" || true
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
export XDG_RUNTIME_DIR="$work/runtime" XDG_CONFIG_HOME="$work/config" XDG_CACHE_HOME="$work/cache"
export XDG_SESSION_TYPE="$mode" PULSE_SERVER="unix:$work/pulse" PULSE_SINK=desktop_test
mkdir -m 700 "$XDG_RUNTIME_DIR" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$work/install"
unset DISPLAY WAYLAND_DISPLAY SWAYSOCK
tar -xzf "$package" -C "$work/install"
sender="$work/install/usr/bin/doubletake"
"$sender" -version
"$sender" ctl -version
test ! -e "$work/install/usr/bin/doubletake-test-receiver"

start() {
    local name=$1
    shift
    "$@" >"$reports/$name.log" 2>&1 &
    pids+=("$!")
}
ready() {
    for ((attempt=0; attempt<100; attempt++)); do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    echo "Timed out waiting for $*" >&2
    return 1
}
start pulse pulseaudio -n --daemonize=no --exit-idle-time=-1 --use-pid-file=no \
    --load="module-native-protocol-unix socket=$work/pulse" \
    --load="module-null-sink sink_name=desktop_test rate=44100 channels=2"
ready pactl info
pactl set-default-sink desktop_test

if [[ $mode == x11 ]]; then
    start x11 Xvfb -displayfd 3 -screen 0 640x360x24 -nolisten tcp 3>"$work/display"
    ready test -s "$work/display"
    DISPLAY=":$(cat "$work/display")"
    export DISPLAY GDK_BACKEND=x11
    ready xdpyinfo
else
    export WLR_BACKENDS=headless WLR_RENDERER=pixman WLR_LIBINPUT_NO_DEVICES=1
    export XDG_CURRENT_DESKTOP=sway GDK_BACKEND=wayland
    mkdir -p "$XDG_CONFIG_HOME/xdg-desktop-portal" "$XDG_CONFIG_HOME/xdg-desktop-portal-wlr"
    printf '[preferred]\ndefault=wlr\norg.freedesktop.impl.portal.ScreenCast=wlr\n' \
        > "$XDG_CONFIG_HOME/xdg-desktop-portal/sway-portals.conf"
    printf '[screencast]\nchooser_type=none\nmax_fps=30\n' \
        > "$XDG_CONFIG_HOME/xdg-desktop-portal-wlr/config"
    printf 'output * mode --custom 640x360@60Hz\nseat seat0 hide_cursor 1\nxwayland disable\n' > "$work/sway.conf"
    start sway sway -d -c "$work/sway.conf"
    for ((attempt=0; attempt<100; attempt++)); do
        sockets=("$XDG_RUNTIME_DIR"/wayland-*)
        for socket in "${sockets[@]}"; do
            if [[ -S $socket ]]; then export WAYLAND_DISPLAY=${socket##*/}; break 2; fi
        done
        sleep 0.1
    done
    : "${WAYLAND_DISPLAY:?Sway did not create a Wayland socket}"
    ready wayland-info
    wayland-info > "$reports/wayland-info.log"
    dbus-update-activation-environment XDG_RUNTIME_DIR XDG_CONFIG_HOME XDG_CACHE_HOME XDG_CURRENT_DESKTOP WAYLAND_DISPLAY
    start pipewire pipewire
    ready test -S "$XDG_RUNTIME_DIR/pipewire-0"
    start wireplumber wireplumber
    portal_wlr=/usr/libexec/xdg-desktop-portal-wlr
    if [[ -x $PWD/portal-build/xdg-desktop-portal-wlr ]]; then
        portal_wlr="$PWD/portal-build/xdg-desktop-portal-wlr"
    fi
    start portal-wlr "$portal_wlr" -l DEBUG
    gdbus wait --session --timeout=5 org.freedesktop.impl.portal.desktop.wlr
    start portal /usr/libexec/xdg-desktop-portal -v
    ready gdbus introspect --session --dest org.freedesktop.portal.Desktop --object-path /org/freedesktop/portal/desktop
fi

start marker /usr/bin/python3 "$scripts/marker.py"
start tone gst-launch-1.0 -q audiotestsrc is-live=true freq=440 volume=0.02 \
    '!' audioconvert '!' pulsesink device=desktop_test
/usr/bin/python3 "$scripts/stream.py" "$mode" "$sender" "$receiver" "$reports" "$work"
