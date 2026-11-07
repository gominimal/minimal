#!/usr/bin/env bash
#
# set-package-version.sh — set the workspace package.version.
#
# Cargo.lock repeats the version for every workspace crate, and CI runs with
# --locked, so both files change. A workspace crate is a lock entry with no
# `source` line. A registry crate that shares the old version keeps it.
#
# Usage: scripts/set-package-version.sh [--repo DIR] VERSION

set -euo pipefail

die() {
    printf 'set-package-version: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

REPO="." NEW=""
while [ $# -gt 0 ]; do
    case "$1" in
        --repo)    [ -n "${2:-}" ] || die "--repo needs a directory"; REPO="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        -*)        die "unknown argument: $1 (try --help)" ;;
        *)         NEW="$1"; shift ;;
    esac
done
[[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "not a version: '$NEW'"

toml="$REPO/Cargo.toml"
lock="$REPO/Cargo.lock"
[ -f "$toml" ] && [ -f "$lock" ] || die "no Cargo.toml and Cargo.lock in $REPO"

old="$(sed -n 's/^package\.version[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' "$toml" | head -n 1)"
[ -n "$old" ] || die "could not read package.version from $toml"

sed "s/^package\.version[[:space:]]*=.*/package.version = \"$NEW\"/" "$toml" >"$toml.new"
mv "$toml.new" "$toml"

# One [[package]] block at a time, so the `source` line after `version` decides.
awk -v old="version = \"$old\"" -v new="version = \"$NEW\"" '
    function flush(   i) {
        for (i = 1; i <= n; i++) {
            if (block[i] == old && !sourced) block[i] = new
            print block[i]
        }
        n = 0; sourced = 0
    }
    /^\[\[package\]\]$/ { flush() }
    /^source = /        { sourced = 1 }
                        { block[++n] = $0 }
    END                 { flush() }
' "$lock" >"$lock.new"
mv "$lock.new" "$lock"

printf 'set-package-version: %s -> %s\n' "$old" "$NEW"
