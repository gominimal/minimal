#!/usr/bin/env bash
#
# resolve-release-version.sh — which released version does a commit belong to?
#
# The promote flow's packaging publishes (the AUR PKGBUILD, the Homebrew
# formula) key on a semver: the AUR fetches versions/<semver>/ from the
# installer bucket, the formula fetches the GitHub Release v<semver>. Promote
# only knows the staged short SHA it is pointing a channel at, so that SHA has
# to be resolved to a release. It is a lookup, not a computation:
#
#   1. A v<semver> tag pointing EXACTLY at the SHA wins — promoting the release
#      commit itself. Prerelease tags (v0.6.0-rc1) are not releases: when one
#      is what points at the SHA, resolution stops there and skips (falling
#      back would re-publish an older release and downgrade users).
#   2. Otherwise the newest released tag reachable FROM the SHA — the nightly
#      that gets promoted usually sits after the tag commit, so --exact-match
#      never fires for it (that was the silent permanent no-op this script
#      replaces; git describe --exact-match alone is not enough).
#
# Exit codes:
#   0   a release version was resolved; printed on stdout WITHOUT the v prefix
#   3   no release version applies — the caller should skip its publish with
#       the stderr notice (untagged sha, or only prerelease tags apply)
#   1   hard failure: no git, unknown sha, bad arguments. A missing tool must
#       fail the job, never masquerade as "nothing to publish".
#
# Usage: scripts/resolve-release-version.sh [--repo DIR] [--sha SHA]
#   --repo  git repository to resolve in (default: the script's checkout root)
#   --sha   commit (full or short sha) to resolve (default: HEAD)
#
# Requires: git. The caller must have fetched tags (actions/checkout
# fetch-depth: 0 fetches all history and tags).

set -euo pipefail

die() {
    printf 'resolve-release-version: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

REPO=""
SHA=""
while [ $# -gt 0 ]; do
    case "$1" in
        --repo) [ -n "${2:-}" ] || die "--repo needs a directory"; REPO="$2"; shift 2 ;;
        --sha)  [ -n "${2:-}" ] || die "--sha needs a commit"; SHA="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$REPO" ] || REPO="$(cd "$(dirname "$0")/.." && pwd)"
[ -n "$SHA" ] || SHA="HEAD"

command -v git >/dev/null 2>&1 \
    || die "git not found — the semver resolution needs the repo's tags (install git; do not skip the publish silently)"

# An unknown sha, a typo, or a missing/checkout-without-tags repo is a caller
# bug, not "nothing to publish" — fail the job with the cause named.
git -C "$REPO" rev-parse --verify --quiet "${SHA}^{commit}" >/dev/null 2>&1 \
    || die "git cannot resolve $SHA in $REPO (bad sha, or the checkout has no history/tags — actions/checkout needs fetch-depth: 0)"

# A released version is a plain vX.Y.Z tag: no prerelease tail (the AUR's
# pacman forbids hyphens in pkgver and Homebrew has no channel to keep an RC
# off), no build metadata.
released_tag() {
    grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$' || true
}

# git_out <args...> — git's stdout with its exit status demoted to success.
# "No tags apply" is a normal resolution outcome here, and under pipefail a
# failing git in a pipeline would otherwise abort the script mid-resolution;
# the failures that DO matter (no git, unresolvable sha) are checked above.
git_out() {
    git -C "$REPO" "$@" 2>/dev/null || true
}

skip() {
    printf 'resolve-release-version: %s\n' "$1" >&2
    exit 3
}

# Tags pointing at the SHA itself, newest version first (--points-at takes
# the next bare argument as its object, so every option precedes it).
# Empty when none do.
exact="$(git_out tag --sort=-version:refname --format='%(refname:short)' \
              --points-at "$SHA" | released_tag)"
if [ -n "$exact" ]; then
    printf '%s\n' "${exact#v}"
    exit 0
fi

# A tag on the sha that is NOT a release (an RC) must not fall through to an
# older release below — that would publish a downgrade.
prerelease_here="$(git_out tag --sort=-version:refname \
                       --format='%(refname:short)' --points-at "$SHA")"
if [ -n "$prerelease_here" ]; then
    skip "sha $SHA is tagged $(printf '%s ' "$prerelease_here" | sed 's/ $//') — a prerelease, not a release; not publishing"
fi

# Newest released tag reachable from the sha (the promoted nightly sits after
# the tag commit). --exclude drops prerelease tags so an RC between releases
# cannot hijack the resolution.
reachable="$(git_out describe --tags --abbrev=0 \
                  --match 'v[0-9]*' --exclude 'v*-*' "$SHA" | released_tag)"
if [ -z "$reachable" ]; then
    skip "no released v* tag reachable from $SHA — nothing to publish"
fi

printf '%s\n' "${reachable#v}"
