#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# != 4 ]]; then
    echo "Usage: $0 VERSION TARGET BINARY_DIRECTORY OUTPUT_DIRECTORY" >&2
    exit 2
fi

version=$1
target=$2
if [[ ! $version =~ ^[[:alnum:]][[:alnum:].+_-]*$ ]]; then
    echo "Invalid package version: $version" >&2
    exit 2
fi
case $target in
    linux-x86_64) machine='Advanced Micro Devices X86-64' ;;
    linux-arm64) machine='AArch64' ;;
    *) echo "Unsupported package target: $target" >&2; exit 2 ;;
esac
epoch=${SOURCE_DATE_EPOCH:-0}
if [[ ! $epoch =~ ^[0-9]+$ ]]; then
    echo "SOURCE_DATE_EPOCH must be a nonnegative integer" >&2
    exit 2
fi

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
binaries=$(cd -- "$3" && pwd)
for binary in doubletake doubletake-ctl; do
    test -x "$binaries/$binary"
    if ! readelf --file-header "$binaries/$binary" | grep -Fq "$machine"; then
        echo "$binary does not match package target $target" >&2
        exit 1
    fi
done
mkdir -p -- "$4"
output=$(cd -- "$4" && pwd)
stage=$(mktemp -d "$output/.doubletake-stage.XXXXXX")
archive=
trap 'rm -rf -- "$stage"; if [[ -n $archive ]]; then rm -f -- "$archive"; fi' EXIT
archive=$(mktemp "$output/.doubletake-archive.XXXXXX")

make --no-print-directory -C "$root" install-prebuilt \
    BUILD_DIR="$binaries" DESTDIR="$stage" PREFIX=/usr \
    MANDIR=/usr/share/man SYSTEMDUSERDIR=/usr/lib/systemd/user \
    BASHCOMPDIR=/usr/share/bash-completion/completions \
    LICENSEDIR=/usr/share/licenses/doubletake

# Stable ownership, ordering, timestamps, and gzip headers make repacking the
# same binaries reproducible and independent of the builder's user account.
tar --format=ustar --sort=name --mtime="@$epoch" \
    --owner=0 --group=0 --numeric-owner -C "$stage" -cf - usr |
    gzip -n > "$archive"
chmod 644 "$archive"
mv -f -- "$archive" "$output/doubletake-$version-$target.tar.gz"
