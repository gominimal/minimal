#!/usr/bin/env bash
#
# latest-staged-version.sh — the default promote target: the most recently
# STAGED COMMIT, not just the most recently staged thing.
#
# promote.yml resolves an omitted --version by taking the newest row under
# versions/. Nightly builds stage under their short sha; versioned release
# builds stage under their semver. Sorting both by creation time would make
# whichever ran last the default — and a versioned row is promoted
# deliberately, by name, never as "whatever is newest". So this filters to
# commit-sha rows before picking.
#
# The rows are `versions/<name>/components` manifests written by
# stage-release.sh; `<name>` is either an 8-char short sha (the nightly
# default) or a semver. A sha row is 7-40 lowercase hex characters — the same
# commit names set-channel.sh and the installer already consume.
#
# Usage: scripts/latest-staged-version.sh [--bucket gs://minimal-one]
# Prints the short sha on stdout. Exit 0 = resolved, 1 = nothing staged (a
# bucket with zero commit rows cannot be promoted by default).
#
# Requires: gcloud authenticated for --bucket (read-only listing).

set -euo pipefail

# die <message> — print it with the script prefix on stderr and exit 1.
die() {
    printf 'latest-staged-version: %s\n' "$1" >&2
    exit 1
}

# usage [code] — print the header comment block as help and exit.
usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

BUCKET="gs://minimal-one"
while [ $# -gt 0 ]; do
    case "$1" in
        --bucket) [ -n "${2:-}" ] || die "--bucket needs a URL"; BUCKET="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

command -v gcloud >/dev/null 2>&1 \
    || die "gcloud not found — the default promote target is read from the bucket"

# `gcloud storage ls -l` prints `SIZE  CREATION_TIME  NAME` per row; the
# resolution keys on the creation time and pulls the version name out of the
# NAME by pattern, not column position.
#
# `|| true`: on an empty bucket gcloud errors and/or the greps emit nothing,
# which under pipefail would abort before the emptiness check below.
listings="$(gcloud storage ls -l "$BUCKET/versions/*/components" 2>/dev/null | grep -v '^TOTAL:' || true)"

newest="$(printf '%s\n' "$listings" | sort -k2 | awk '{print $NF}' \
    | { grep -oE 'versions/[^[:space:]]+/components' || true; } \
    | cut -d/ -f2 \
    | while IFS= read -r name; do
        # Only commit rows are promotable targets; semver packaging rows are
        # not. A sha row is 7-40 lowercase hex characters.
        case "$name" in
            *[!0-9a-f]*) continue ;;
        esac
        len="${#name}"
        if [ "$len" -ge 7 ] && [ "$len" -le 40 ]; then
            printf '%s\n' "$name"
        fi
    done | tail -n 1)"

if [ -z "$newest" ]; then
    die "no staged commit versions under $BUCKET/versions/ — stage a release first (stage-release.sh) or pass --sha"
fi

printf '%s\n' "$newest"
