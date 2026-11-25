#!/usr/bin/env bash
set -eo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
sender=$(realpath "${1:-$root/bin/doubletake}")
controller=$(realpath "${2:-$root/bin/doubletake-ctl}")
runner=()
if [[ -n ${PACKAGE_TEST_RUNNER:-} ]]; then runner=("$PACKAGE_TEST_RUNNER"); fi
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

# Exercise the real framework, including its word-break reconstruction.
# shellcheck source=/dev/null
source "${BASH_COMPLETION_FILE:-/usr/share/bash-completion/bash_completion}"
# shellcheck source=/dev/null
source "$root/completions/doubletake.bash"

complete_line()
{
    local function=$1 line=$2
    shift 2
    COMP_WORDS=("$@")
    COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
    COMP_LINE=$line
    COMP_POINT=${#line}
    COMP_TYPE=9
    COMP_KEY=9
    COMPREPLY=()
    # Some framework helpers use compopt, which is only meaningful during an
    # interactive completion. Candidate arrays are still available here.
    "$function" "${COMP_WORDS[0]}" "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD - 1]}" 2>/dev/null || :
}

expect()
{
    local candidate
    for candidate in "${COMPREPLY[@]}"; do
        if [[ $candidate == "$1" ]]; then return; fi
    done
    printf 'Missing completion %q for %q; got: %s\n' "$1" "$COMP_LINE" "${COMPREPLY[*]}" >&2
    exit 1
}

expect_empty()
{
    if ((${#COMPREPLY[@]})); then
        printf 'Unexpected completions for %q: %s\n' "$COMP_LINE" "${COMPREPLY[*]}" >&2
        exit 1
    fi
}

complete_line _doubletake 'doubletake -hwaccel nv' doubletake -hwaccel nv
expect nvenc
complete_line _doubletake 'doubletake -hwaccel=nv' doubletake -hwaccel = nv
expect nvenc
complete_line _doubletake 'doubletake --video-codec=h' doubletake --video-codec = h
expect h264
expect hevc
complete_line _doubletake 'doubletake -audio-source m' doubletake -audio-source m
expect monitor
complete_line _doubletake 'doubletake --audio-source=o' doubletake --audio-source = o
expect output
complete_line _doubletake 'doubletake --no-v' doubletake --no-v
expect --no-video
complete_line _doubletake 'doubletake -cred-backend k' doubletake -cred-backend k
expect keyring
complete_line _doubletake 'doubletake -s ma' doubletake -s ma
expect max
complete_line _doubletake 'doubletake -debug=f' doubletake -debug = f
expect false
complete_line _doubletake 'doubletake -debug ' doubletake -debug ''
expect -hwaccel
complete_line _doubletake 'doubletake --target-' doubletake --target-
expect --target-latency-ms
complete_line _doubletake 'doubletake -code secret' doubletake -code secret
expect_empty
complete_line _doubletake 'doubletake -- -' doubletake -- -
expect_empty
complete_line _doubletake 'doubletake unused -' doubletake unused -
expect_empty
complete_line _doubletake 'doubletake -x11-window-name hwaccel ' doubletake -x11-window-name hwaccel ''
expect -hwaccel
complete_line _doubletake 'doubletake -target -hwaccel ' doubletake -target -hwaccel ''
expect -hwaccel

complete_line _doubletake 'doubletake ct' doubletake ct
expect ctl
complete_line _doubletake 'doubletake ctl con' doubletake ctl con
expect connect
complete_line _doubletake_ctl 'doubletake-ctl con' doubletake-ctl con
expect connect
complete_line _doubletake_ctl 'doubletake-ctl pl' doubletake-ctl pl
expect play
complete_line _doubletake_ctl 'doubletake-ctl vol' doubletake-ctl vol
expect volume
complete_line _doubletake_ctl 'doubletake-ctl -socket connect con' doubletake-ctl -socket connect con
expect connect
complete_line _doubletake_ctl 'doubletake-ctl --socket=/tmp/d.sock con' doubletake-ctl --socket = /tmp/d.sock con
expect connect
complete_line _doubletake_ctl 'doubletake-ctl connect ' doubletake-ctl connect ''
expect_empty
complete_line _doubletake_ctl 'doubletake-ctl pin secret' doubletake-ctl pin secret
expect_empty
complete_line _doubletake_ctl 'doubletake-ctl --ver' doubletake-ctl --ver
expect --version
complete_line _doubletake_ctl 'doubletake-ctl -- con' doubletake-ctl -- con
expect connect
complete_line _doubletake_ctl 'doubletake-ctl -- -' doubletake-ctl -- -
expect_empty

cd "$scratch"
touch 'credentials with spaces.json' 'daemon socket' 'clip with spaces.mkv'
complete_line _doubletake 'doubletake -creds cred' doubletake -creds cred
expect 'credentials with spaces.json'
complete_line _doubletake_ctl 'doubletake-ctl -socket daemon' doubletake-ctl -socket daemon
expect 'daemon socket'
complete_line _doubletake 'doubletake -video-source clip' doubletake -video-source clip
expect 'clip with spaces.mkv'
complete_line _doubletake_ctl 'doubletake-ctl play clip' doubletake-ctl play clip
expect 'clip with spaces.mkv'

# Detect drift between shipped completion lists and actual command help.
for command in "$sender" "$controller"; do
    name=${command##*/}
    function=_doubletake
    if [[ $name == doubletake-ctl ]]; then function=_doubletake_ctl; fi
    "${runner[@]}" "$command" -help > "$scratch/help" 2>&1
    sed -nE 's/^  (-[^ ,]+)([ ,].*)?$/\1/p' "$scratch/help" | sort -u > "$scratch/flags"
    test -s "$scratch/flags"
    complete_line "$function" "$name -" "$name" -
    while IFS= read -r option; do expect "$option"; done < "$scratch/flags"
    for option in "${COMPREPLY[@]}"; do
        case $option in -h|-help) continue ;; esac
        if ! grep -Fxq -- "$option" "$scratch/flags"; then
            echo "Completion offers an unsupported flag for $name: $option" >&2
            exit 1
        fi
    done
    if [[ $name == doubletake-ctl ]]; then
        complete_line _doubletake_ctl "$name " "$name" ''
        while IFS= read -r command; do expect "$command"; done < <(
            awk '/^Commands:/{commands=1;next} /^Flags:/{commands=0} commands && NF {print $1}' "$scratch/help"
        )
    fi
done
echo 'Bash completion checks passed'
