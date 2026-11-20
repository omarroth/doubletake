#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 5 || ! $1 =~ ^(x11|wayland)$ ]]; then
    echo "Usage: $0 {x11|wayland} CLOUD_IMAGE RELEASE_TARBALL TEST_RECEIVER REPORT_DIRECTORY" >&2
    exit 2
fi
scripts=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mode=$1
mkdir -p -- "$5"
reports=$(realpath "$5")
work=$(mktemp -d)
vm_pid=
# shellcheck disable=SC2329
cleanup() {
    if [[ -n $vm_pid ]]; then
        kill "$vm_pid" 2>/dev/null || true
        wait "$vm_pid" 2>/dev/null || true
    fi
    rm -rf -- "$work"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

ssh-keygen -q -t ed25519 -N '' -f "$work/key"
cat > "$work/user-data" <<CLOUD
#cloud-config
users:
  - name: desktopci
    groups: [audio, video, render]
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$work/key.pub")
CLOUD
printf 'instance-id: doubletake-desktop-ci\nlocal-hostname: doubletake-ci\n' > "$work/meta-data"
genisoimage -quiet -output "$work/seed.iso" -volid cidata -joliet -rock "$work/user-data" "$work/meta-data"
qemu-img create -q -f qcow2 -F qcow2 -b "$(realpath "$2")" "$work/guest.qcow2"
qemu-img resize -q "$work/guest.qcow2" 12G

port=$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
qemu-system-x86_64 -machine q35,accel=kvm:tcg -smp 4 -m 4096 -display none \
    -serial "file:$reports/guest-console.log" -monitor none -no-reboot \
    -drive "file=$work/guest.qcow2,if=virtio,format=qcow2" \
    -drive "file=$work/seed.iso,media=cdrom,readonly=on" \
    -nic "user,model=virtio-net-pci,hostfwd=tcp:127.0.0.1:$port-:22" &
vm_pid=$!
options=(-i "$work/key" -o BatchMode=yes -o ConnectTimeout=3
    -o "UserKnownHostsFile=$work/known_hosts" -o StrictHostKeyChecking=accept-new)
guest=desktopci@127.0.0.1
ssh_guest() { ssh -p "$port" "${options[@]}" "$guest" "$@"; }

ready=false
for ((attempt=0; attempt<120; attempt++)); do
    kill -0 "$vm_pid"
    if ssh_guest true 2>"$reports/guest-ssh.log"; then
        ready=true
        break
    fi
    sleep 2
done
if [[ $ready != true ]]; then
    echo 'Guest VM never became reachable over SSH' >&2
    exit 1
fi

ssh_guest 'cloud-init status --wait && mkdir -p desktop-test reports'
scp -q -P "$port" "${options[@]}" "$3" "$guest:release.tar.gz"
scp -q -P "$port" "${options[@]}" "$4" "$guest:doubletake-test-receiver"
scp -q -P "$port" "${options[@]}" "$scripts/"{run.sh,stream.py,marker.py} "$guest:desktop-test/"
packages=(dbus-daemon pulseaudio pulseaudio-utils python3-gi python3-gi-cairo gir1.2-gtk-3.0
    gstreamer1.0-tools gstreamer1.0-libav gstreamer1.0-plugins-base gstreamer1.0-plugins-good
    gstreamer1.0-plugins-bad gstreamer1.0-plugins-ugly gstreamer1.0-pulseaudio)
if [[ $mode == wayland ]]; then
    packages+=(sway wayland-utils xdg-desktop-portal-wlr pipewire wireplumber gstreamer1.0-pipewire
        libglib2.0-bin build-essential meson pkg-config libpipewire-0.3-dev
        libwayland-dev wayland-protocols libinih-dev libgbm-dev libdrm-dev libsystemd-dev)
else
    packages+=(xvfb x11-utils)
fi
ssh_guest 'sudo apt-get update'
ssh_guest sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${packages[@]}"
if [[ $mode == wayland ]]; then
    # Trixie's portal has a shared-memory path, but its startup check also
    # requires DMA-BUF metadata. Allow the software-only output in this VM.
    curl -fsSL --retry 3 https://codeload.github.com/emersion/xdg-desktop-portal-wlr/tar.gz/refs/tags/v0.7.1 \
        -o "$work/portal.tar.gz"
    (cd "$work" && echo '4bddc236aa9d1a2b33e7f0bef09a8712ded51e8bc335a2b6c8cd1d088863e676  portal.tar.gz' | sha256sum -c)
    scp -q -P "$port" "${options[@]}" "$work/portal.tar.gz" "$guest:"
    ssh_guest 'mkdir portal-source && tar -xzf portal.tar.gz --strip-components=1 -C portal-source &&
        python3 -c "
from pathlib import Path
path = Path(\"portal-source/src/screencast/screencast.c\")
source = path.read_text()
condition = \"(cast->ctx->state->screencast_version >= 3 &&\"
assert source.count(condition) == 1
path.write_text(source.replace(condition, \"(cast->ctx->gbm && cast->ctx->state->screencast_version >= 3 &&\"))
" &&
        meson setup portal-build portal-source -Dman-pages=disabled -Dsystemd=disabled &&
        meson compile -C portal-build'
fi
status=0
ssh_guest "desktop-test/run.sh $mode ./release.tar.gz ./doubletake-test-receiver ./reports" || status=$?
scp -q -P "$port" "${options[@]}" -r "$guest:reports/." "$reports/"
exit "$status"
