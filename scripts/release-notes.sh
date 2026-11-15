#!/bin/sh
set -eu

tag=${1:?usage: release-notes.sh TAG}
ref="refs/tags/$tag"
if [ "$(git cat-file -t "$ref")" = tag ]; then
    notes=$(git for-each-ref --format='%(contents)' "$ref")
    if [ -n "$notes" ]; then
        printf '%s\n' "$notes"
        exit 0
    fi
fi

# Prefer a versioned entry; Unreleased also supports local release candidates.
extract() {
    awk -v wanted="$1" '
        /^## / {
            if (found) exit
            heading = $2
            gsub(/[\[\]]/, "", heading)
            sub(/^v/, "", heading)
            found = heading == wanted
            next
        }
        found && (printed || /[^[:space:]]/) { print; printed = 1 }
    ' CHANGELOG.md
}
notes=$(extract "${tag#v}")
if [ -z "$notes" ]; then
    notes=$(extract Unreleased)
fi
if [ -z "$notes" ]; then
    printf 'No release notes for %s in CHANGELOG.md\n' "$tag" >&2
    exit 1
fi
printf '%s\n' "$notes"
