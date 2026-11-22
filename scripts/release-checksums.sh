#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 3 || ! $2 =~ ^[[:alnum:]][[:alnum:].+_-]*$ ]]; then
    echo "Usage: $0 DIRECTORY VERSION TARGET..." >&2
    exit 2
fi
cd -- "$1"
version=$2
shift 2
archives=()
for target in "$@"; do
    case $target in
        linux-x86_64|linux-arm64|macos-universal) extension=tar.gz ;;
        windows-x86_64|windows-arm64) extension=zip ;;
        *) echo "Unsupported package target: $target" >&2; exit 2 ;;
    esac
    archive="doubletake-$version-$target.$extension"
    test -s "$archive"
    archives+=("$archive")
done
manifest=$(mktemp .SHA256SUMS.XXXXXX)
trap 'rm -f -- "$manifest"' EXIT
sha256sum -- "${archives[@]}" > "$manifest"
chmod 644 "$manifest"
mv -f -- "$manifest" SHA256SUMS
