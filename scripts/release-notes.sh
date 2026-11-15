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

git log -1 --format='%B' "$ref"
