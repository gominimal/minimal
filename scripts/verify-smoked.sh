#!/usr/bin/env bash
#
# verify-smoked.sh — the promotion gate: were THESE bytes smoked?
#
# A release run that passes its shipped-artifact smokes records
# versions/<VERSION>/smoked (scripts/record-smoked.sh): the SHA-256 of the
# row's `components` manifest plus the run that smoked it. This gate re-reads
# the live manifest, hashes it, and requires the digests to match. Provenance
# is therefore a property of the row: a version nobody smoked has no marker,
# and a row re-staged after its smoke carries a manifest the marker no longer
# describes. Both fail, before any channel pointer is touched.
#
# This replaces inferring provenance from a `nightly.yml` run id, which the
# versioned release path could never satisfy (so every promotion overrode
# it). Every release run — nightly or versioned — smokes and records, so the
# gate runs on the default path and `override_provenance` is back to being
# the documented emergency it says it is.
#
# Usage:
#   scripts/verify-smoked.sh --version VER [--bucket gs://minimal-one]
#
# Options (env var in parens overrides the default; flags win over env):
#   --version VER     Staged version (short sha or semver)   (VERSION)
#   --bucket URL      gs:// bucket URL                        (BUCKET, default: gs://minimal-one)
#   -h, --help        Show this help
#
# Exit codes: 0 verified (prints the smoking run); 1 no marker, digest
# mismatch, unreadable marker, or a hard error.
#
# Requires: bash, sha256sum, jq, and an authenticated `gcloud`.

set -euo pipefail

die() {
    printf 'verify-smoked: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

VERSION="${VERSION:-}"
BUCKET="${BUCKET:-gs://minimal-one}"

while [ $# -gt 0 ]; do
    case "$1" in
        --version|--bucket)
            [ $# -ge 2 ] || die "missing value for $1"
            case "$1" in
                --version) VERSION="$2" ;;
                --bucket)  BUCKET="$2" ;;
            esac
            shift 2 ;;
        -h|--help) usage 0 ;;
        *)         die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$VERSION" ] || die "missing --version"
case "$VERSION" in
    *[!A-Za-z0-9._-]*) die "version '$VERSION' contains characters outside [A-Za-z0-9._-]" ;;
esac
command -v gcloud >/dev/null 2>&1 || die "gcloud not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"
command -v jq >/dev/null 2>&1 || die "jq not found"

row="$BUCKET/versions/$VERSION"
workdir="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-verify-smoked)"
trap 'rm -rf "$workdir"' EXIT

gcloud storage cat "$row/components" >"$workdir/components" 2>/dev/null \
    || die "versions/$VERSION is not staged ($row/components missing)"

gcloud storage cat "$row/smoked" >"$workdir/smoked" 2>/dev/null \
    || die "versions/$VERSION has no smoked marker ($row/smoked missing): no release run smoked these bytes, or its smoke failed — promotion refused. A documented emergency may set override_provenance."

recorded="$(jq -r '.components_sha256 // empty' "$workdir/smoked" 2>/dev/null || true)"
run_url="$(jq -r '.run_url // empty' "$workdir/smoked" 2>/dev/null || true)"
[ -n "$recorded" ] || die "$row/smoked is unreadable or carries no components_sha256 — refusing to trust it"

live="$(sha256sum "$workdir/components" | cut -d' ' -f1)"
if [ "$live" != "$recorded" ]; then
    die "versions/$VERSION was re-staged after it was smoked: live components sha256 $live, smoked $recorded (by ${run_url:-<unknown run>}) — the bytes on the row are not the bytes that passed; re-run the release smoke before promoting"
fi

printf 'verify-smoked: versions/%s smoked by %s (components sha256 %s)\n' "$VERSION" "${run_url:-<unknown run>}" "$live"
