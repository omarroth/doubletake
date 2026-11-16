#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C

if [[ $# != 2 ]]; then
    echo "Usage: $0 ARCHIVE TARGET" >&2
    exit 2
fi
archive=$(realpath "$1")
test "$(stat -c %a "$archive")" = 644
target=$2
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT
runner=()
if [[ -n ${PACKAGE_TEST_RUNNER:-} ]]; then runner=("$PACKAGE_TEST_RUNNER"); fi

tar -tzf "$archive" > "$scratch/entries"
while IFS= read -r entry; do
    case $entry in usr/*) ;; *) echo "Unexpected archive path: $entry" >&2; exit 1 ;; esac
    case /$entry/ in */../*) echo "Unsafe archive path: $entry" >&2; exit 1 ;; esac
done < "$scratch/entries"
tar --numeric-owner -tvzf "$archive" | awk '$2 != "0/0" {exit 1}'
mkdir "$scratch/package"
tar --no-same-owner -xzf "$archive" -C "$scratch/package"
stage=$scratch/package

cat > "$scratch/expected" <<'EOF'
usr/bin/doubletake
usr/bin/doubletake-ctl
usr/lib/systemd/user/doubletake.service
usr/share/bash-completion/completions/doubletake
usr/share/bash-completion/completions/doubletake-ctl
usr/share/licenses/doubletake/COPYING.GPL
usr/share/licenses/doubletake/LICENSE
usr/share/man/man1/doubletake-ctl.1
usr/share/man/man1/doubletake.1
EOF
find "$stage" \( -type f -o -type l \) -printf '%P\n' | sort > "$scratch/actual"
diff -u "$scratch/expected" "$scratch/actual"
while IFS= read -r file; do
    case $file in
        usr/bin/*) test "$(stat -c %a "$stage/$file")" = 755 ;;
        */completions/doubletake-ctl) test "$(readlink "$stage/$file")" = doubletake ;;
        *) test "$(stat -c %a "$stage/$file")" = 644 ;;
    esac
done < "$scratch/expected"
grep -Fxq 'ExecStart="/usr/bin/doubletake" -daemonize' "$stage/usr/lib/systemd/user/doubletake.service"
if grep -Fq '@bindir@' "$stage/usr/lib/systemd/user/doubletake.service"; then exit 1; fi
cmp "$root/LICENSE" "$stage/usr/share/licenses/doubletake/LICENSE"
cmp "$root/COPYING.GPL" "$stage/usr/share/licenses/doubletake/COPYING.GPL"
cmp "$root/completions/doubletake.bash" "$stage/usr/share/bash-completion/completions/doubletake"
for binary in doubletake doubletake-ctl; do
    "${runner[@]}" "$stage/usr/bin/$binary" -version
done

# Repacking under a restrictive umask must preserve bytes and permissions.
name=${archive##*/}
version=${name#doubletake-}
version=${version%-"$target".tar.gz}
epoch=$(stat -c %Y "$stage/usr/bin/doubletake")
(
    umask 077
    SOURCE_DATE_EPOCH=$epoch "$root/scripts/package-release.sh" "$version" "$target" "$stage/usr/bin" "$scratch/repacked"
)
cmp "$archive" "$scratch/repacked/$name"

# A mislabeled architecture must never produce a published archive.
wrong_target=linux-arm64
if [[ $target == linux-arm64 ]]; then wrong_target=linux-x86_64; fi
if "$root/scripts/package-release.sh" "$version" "$wrong_target" "$stage/usr/bin" "$scratch/rejected" > "$scratch/rejected.log" 2>&1; then
    echo 'Packager accepted binaries for the wrong architecture' >&2
    exit 1
fi

# Exercise package-manager staging, prefix overrides, reinstall, and uninstall
# without a Go toolchain. Preserve unrelated files in the installation root.
mkdir "$scratch/tools"
cat > "$scratch/tools/go" <<'EOF'
#!/bin/sh
touch "$PACKAGE_TEST_COMPILER_MARKER"
exit 1
EOF
chmod +x "$scratch/tools/go"
export PACKAGE_TEST_COMPILER_MARKER=$scratch/compiler-invoked
custom=$scratch/custom
for _ in 1 2; do
    PATH="$scratch/tools:$PATH" make --no-print-directory -C "$root" install-prebuilt \
        BUILD_DIR="$stage/usr/bin" DESTDIR="$custom" PREFIX='/opt/doubletake test' \
        SYSTEMDUSERDIR=/usr/share/systemd/user
done
test ! -e "$PACKAGE_TEST_COMPILER_MARKER"
grep -Fxq 'ExecStart="/opt/doubletake test/bin/doubletake" -daemonize' "$custom/usr/share/systemd/user/doubletake.service"
touch "$custom/opt/doubletake test/share/licenses/doubletake/keep"
PATH="$scratch/tools:$PATH" make --no-print-directory -C "$root" uninstall \
    DESTDIR="$custom" PREFIX='/opt/doubletake test' SYSTEMDUSERDIR=/usr/share/systemd/user
find "$custom" \( -type f -o -type l \) -printf '%P\n' > "$scratch/remaining"
test "$(cat "$scratch/remaining")" = 'opt/doubletake test/share/licenses/doubletake/keep'
test ! -e "$PACKAGE_TEST_COMPILER_MARKER"
echo "Release package checks passed: $target"
