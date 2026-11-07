#!/usr/bin/env bash
#
# check-promotion.sh — refuse a promotion to `stable` that must not happen.
#
# A candidate never goes to `stable`: the promotion would ship it to every user
# and tag it. A version below the current `stable` is refused too, because it
# moves users backwards: staged 0.7.3, emergency 0.7.4, then 0.7.3 again.
# --rollback allows that second case on purpose. Nothing allows the first.
#
# A nightly sha has no order against a version, so it passes with a warning, as
# does any version when `stable` holds a sha.
#
# Usage: scripts/check-promotion.sh --version V --current STABLE [--rollback]

set -euo pipefail

die() {
    printf 'check-promotion: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

VERSION="" CURRENT="" ROLLBACK=0
while [ $# -gt 0 ]; do
    case "$1" in
        --version)  [ -n "${2:-}" ] || die "--version needs a version"; VERSION="$2"; shift 2 ;;
        --current)  [ -n "${2:-}" ] || die "--current needs a version"; CURRENT="$2"; shift 2 ;;
        --rollback) ROLLBACK=1; shift ;;
        -h|--help)  usage 0 ;;
        *)          die "unknown argument: $1 (try --help)" ;;
    esac
done
if [ -z "$VERSION" ] || [ -z "$CURRENT" ]; then die "--version and --current are required"; fi

core='[0-9]+\.[0-9]+\.[0-9]+'
sha='[0-9a-f]{7,40}'
candidate="$core-[0-9A-Za-z.-]+"

# Checked first, so nothing passes over an unreadable `stable`.
[[ "$CURRENT" =~ ^($sha|$core|$candidate)$ ]] || die "cannot read the current stable: '$CURRENT'"

if [[ "$VERSION" =~ ^$sha$ ]]; then
    printf '::warning::%s is a nightly sha, which has no order against stable (%s)\n' "$VERSION" "$CURRENT"
    exit 0
fi
[[ "$VERSION" =~ ^$core ]] || die "'$VERSION' is neither a version nor a nightly sha"
[[ "$VERSION" =~ ^$core$ ]] || die "$VERSION is a candidate; a candidate never goes to stable. Stage the final version"
if [[ "$CURRENT" =~ ^$sha$ ]]; then
    printf '::warning::stable is the nightly sha %s, which has no order against %s\n' "$CURRENT" "$VERSION"
    exit 0
fi

# VERSION is a final, so only the core of CURRENT matters: a final outranks a
# candidate of the same core.
current_core="${CURRENT%%-*}"
if [ "$VERSION" != "$current_core" ] \
    && [ "$(printf '%s\n%s\n' "$VERSION" "$current_core" | sort -V | head -n 1)" = "$VERSION" ]; then
    if [ "$ROLLBACK" -eq 0 ]; then
        die "$VERSION is below stable ($CURRENT). To roll back on purpose, set rollback"
    fi
    printf '::warning::rolling stable back from %s to %s\n' "$CURRENT" "$VERSION"
    exit 0
fi
printf 'check-promotion: %s can replace stable (%s)\n' "$VERSION" "$CURRENT"
