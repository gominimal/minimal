#!/usr/bin/env bash
#
# record-smoked.sh — record that a staged version's bytes passed the smoke.
#
# Provenance is a property of the ROW, not of run history. After the
# shipped-artifact smokes pass, the release run writes
# versions/<VERSION>/smoked: a JSON marker carrying the SHA-256 of the row's
# `components` manifest (which itself carries every artifact's SHA-256), the
# commit the row was built from, and the run that smoked it. Promotion
# (scripts/verify-smoked.sh) then checks
# "these exact bytes were smoked" against the live manifest instead of
# inferring it from a workflow run id — so a re-staged row can never inherit
# a stale blessing, and the check runs on the default path rather than being
# overridden every time.
#
# The marker is rewritten, not write-once: it is derived from the live
# manifest by the run that smoked it, and a deliberate --restage (the only
# way the manifest changes) re-runs the smoke and re-records. It is served
# uncached so a verifier never reads a stale blessing.
#
# Usage:
#   scripts/record-smoked.sh --version VER --run-url URL [options]
#
# Options (env var in parens overrides the default; flags win over env):
#   --version VER     Staged version (short sha or semver)   (VERSION)
#   --run-url URL     The workflow run that smoked it         (RUN_URL)
#   --run-id ID       Its numeric run id                      (RUN_ID, optional)
#   --sha SHA         The commit the row was built from        (COMMIT_SHA, optional;
#                     a semver row's only link back to its source — the docs
#                     rebuild on promotion pins to it)
#   --bucket URL      gs:// bucket URL                        (BUCKET, default: gs://minimal-one)
#   --dry-run         Print the marker; write nothing
#   -h, --help        Show this help
#
# Exit codes: 0 recorded; 1 the version is not staged, or a hard error.
#
# Requires: bash, sha256sum, and an authenticated `gcloud`.

set -euo pipefail

# die <message> — print it with the script prefix on stderr and exit 1.
die() {
    printf 'record-smoked: %s\n' "$1" >&2
    exit 1
}

# usage [code] — print the header comment block as help and exit.
usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

VERSION="${VERSION:-}"
RUN_URL="${RUN_URL:-}"
RUN_ID="${RUN_ID:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
BUCKET="${BUCKET:-gs://minimal-one}"
DRY_RUN=0

while [ $# -gt 0 ]; do
    case "$1" in
        --version|--run-url|--run-id|--sha|--bucket)
            [ $# -ge 2 ] || die "missing value for $1"
            case "$1" in
                --version) VERSION="$2" ;;
                --run-url) RUN_URL="$2" ;;
                --run-id)  RUN_ID="$2" ;;
                --sha)     COMMIT_SHA="$2" ;;
                --bucket)  BUCKET="$2" ;;
            esac
            shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *)         die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$VERSION" ] || die "missing --version"
[ -n "$RUN_URL" ] || die "missing --run-url"
case "$VERSION" in
    *[!A-Za-z0-9._-]*) die "version '$VERSION' contains characters outside [A-Za-z0-9._-]" ;;
esac
case "$COMMIT_SHA" in
    ""|*[!0-9a-f]*) [ -z "$COMMIT_SHA" ] || die "--sha '$COMMIT_SHA' is not a lowercase hex commit sha" ;;
esac
command -v gcloud >/dev/null 2>&1 || die "gcloud not found"
command -v sha256sum >/dev/null 2>&1 || die "sha256sum not found"

row="$BUCKET/versions/$VERSION"
workdir="$(mktemp -d 2>/dev/null || mktemp -d -t minimal-smoked)"
trap 'rm -rf "$workdir"' EXIT

# The live manifest, read directly (never through the public edge cache: a
# restaged row must be hashed as it is now, not as an edge remembers it).
gcloud storage cat "$row/components" >"$workdir/components" 2>/dev/null \
    || die "versions/$VERSION is not staged ($row/components missing) — nothing to record"
[ -s "$workdir/components" ] || die "$row/components is empty"
digest="$(sha256sum "$workdir/components" | cut -d' ' -f1)"

printf '{"version":"%s","sha":"%s","components_sha256":"%s","run_url":"%s","run_id":"%s","smoked_at":"%s"}\n' \
    "$VERSION" "$COMMIT_SHA" "$digest" "$RUN_URL" "$RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$workdir/smoked"

printf '=== %s/smoked ===\n' "$row" >&2
cat "$workdir/smoked" >&2

if [ "$DRY_RUN" -eq 1 ]; then
    printf 'record-smoked: dry run, nothing written\n' >&2
    exit 0
fi

gcloud storage cp \
    --cache-control="no-cache, max-age=0" \
    "$workdir/smoked" "$row/smoked"

printf 'record-smoked: versions/%s smoked by %s (components sha256 %s)\n' "$VERSION" "$RUN_URL" "$digest" >&2
