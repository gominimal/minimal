#!/usr/bin/env bash
#
# set-channel.sh — point a distribution channel at an already-staged version.
#
# The curl|bash installer (docs/specs/07-spec-installer) resolves a channel to a
# version by fetching a mutable pointer file at the bucket root (`stable`,
# `unstable`, …) whose sole contents are a version string. This script writes
# that pointer.
#
# It is deliberately separate from `stage-release.sh`: staging uploads immutable
# `versions/<VERSION>/…` artifacts and changes nothing users receive; flipping a
# channel is the single mutating action that actually ships a version. Keeping
# them apart means a version can be staged and smoke-tested (via its immutable
# URL) before it is promoted, and promotion — including rollback to a prior
# already-staged version — is one cheap, reversible command.
#
# Usage:
#   scripts/set-channel.sh --channel NAME --version VER [options]
#
# Options (env var in parens overrides the default; flags win over env):
#   --channel NAME   Channel/pointer to write, e.g. stable   (CHANNEL)
#   --version VER    Version the channel should point at      (VERSION)
#   --bucket URL     gs:// bucket URL                         (BUCKET, default: gs://minimal-one)
#   --dry-run        Print what would be written; touch nothing
#   -h, --help       Show this help
#
# Requires: bash and (unless --dry-run) an authenticated `gcloud`.

set -euo pipefail

die() {
    printf 'set-channel: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

CHANNEL="${CHANNEL:-}"
VERSION="${VERSION:-}"
BUCKET="${BUCKET:-gs://minimal-one}"
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --channel) CHANNEL="$2"; shift 2 ;;
        --version) VERSION="$2"; shift 2 ;;
        --bucket)  BUCKET="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *)         die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$CHANNEL" ] || die "missing --channel"
[ -n "$VERSION" ] || die "missing --version"

# Both land in a URL/path and the pointer body; hold them to the charset the
# installer validates (spec R2.1/R2.2) so a channel can never smuggle a path
# segment or a newline into the version string.
case "$CHANNEL" in
    *[!A-Za-z0-9._-]*) die "channel '$CHANNEL' contains characters outside [A-Za-z0-9._-]" ;;
esac
case "$VERSION" in
    *[!A-Za-z0-9._-]*) die "version '$VERSION' contains characters outside [A-Za-z0-9._-]" ;;
esac

# A channel must only ever point at a version that is actually staged; otherwise
# the installer resolves the pointer and then 404s on the components manifest.
manifest_url="$BUCKET/versions/$VERSION/components"

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'set-channel: would point %s/%s -> %s (after verifying %s exists)\n' \
        "$BUCKET" "$CHANNEL" "$VERSION" "$manifest_url" >&2
    exit 0
fi

command -v gcloud >/dev/null 2>&1 || die "gcloud not found (use --dry-run to skip)"

gcloud storage objects describe "$manifest_url" >/dev/null 2>&1 \
    || die "version '$VERSION' is not staged ($manifest_url not found); run stage-release.sh first"

workdir="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-channel)"
trap 'rm -rf "$workdir"' EXIT
pointer="$workdir/pointer"
printf '%s\n' "$VERSION" >"$pointer"

# Mutable pointer: barely cache (30s) so a promotion propagates promptly while
# still shielding the bucket from per-install request storms.
gcloud storage cp \
    --cache-control="public, max-age=30" \
    "$pointer" "$BUCKET/$CHANNEL"

printf 'set-channel: %s now points to %s\n' "$CHANNEL" "$VERSION" >&2
