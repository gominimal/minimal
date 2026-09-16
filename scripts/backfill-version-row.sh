#!/usr/bin/env bash
#
# backfill-version-row.sh — restage an already-shipped release under its semver.
#
# versions/<semver>/ rows are staged by the release workflow on tag push — a
# convention this repo adopted mid-stream, so no release shipped before it has
# one. Downstream packaging (publish-aur.sh, package-nfpm.sh, the brew
# formula's bucket fetches) keys on the semver row, so the one release in that
# gap needs a row built by hand. This fetches the release's artifacts from its
# sha-keyed row (the row that shipped it) and hands them to stage-release.sh,
# so the semver row is written by the same script and cache headers as every
# other staging write — never by an ad-hoc gcloud call here.
#
# The restage uses stage-release.sh's CURRENT component table against the old
# row's artifacts: rows whose artifact the old release never shipped (e.g.
# minvmd-linux-arm64 before the static-musl build) are omitted with a warning
# (--allow-missing), and files the table copies from the checkout (the
# AppArmor set) come from the current tree. A backfilled row is therefore a
# packaging-addressable restatement of the release, not a byte-identical
# clone; channels keep pointing at the sha row, which is untouched.
#
# Usage:
#   scripts/backfill-version-row.sh --sha <short-sha> --version <semver> \
#       [--bucket gs://minimal-one] [--dry-run]
#
# Requires: bash, curl, sha256sum, and (unless --dry-run) an authenticated
# gcloud for the bucket write.

set -euo pipefail

die() {
    printf 'backfill-version-row: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

SHA=""
SEMVER=""
BUCKET="gs://minimal-one"
BUCKET_PUBLIC="${MINIMAL_BUCKET_URL:-https://storage.googleapis.com/minimal-one}"
DRY_RUN=0
while [ $# -gt 0 ]; do
    case "$1" in
        --sha)     [ -n "${2:-}" ] || die "--sha needs a value"; SHA="$2"; shift 2 ;;
        --version) [ -n "${2:-}" ] || die "--version needs a value"; SEMVER="$2"; shift 2 ;;
        --bucket)  [ -n "${2:-}" ] || die "--bucket needs a URL"; BUCKET="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage 0 ;;
        *)         die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$SHA" ] || die "--sha is required (the short sha the release was staged under)"
[ -n "$SEMVER" ] || die "--version is required (the semver to restage under, without the v prefix)"
# Same safe charset as stage-release.sh/set-channel.sh: these become path
# segments.
case "$SEMVER" in *[!A-Za-z0-9._-]*) die "version '$SEMVER' contains characters outside [A-Za-z0-9._-]" ;; esac

sha_row="$BUCKET_PUBLIC/versions/$SHA"
components_url="$sha_row/components"
workdir="$(mktemp -d 2>/dev/null || mktemp -d -t backfill-version-row)"
trap 'rm -rf "$workdir"' EXIT

# The sha row's manifest lists what the release actually shipped; its src
# column names the artifacts to re-fetch.
curl -fsSL --retry 3 -o "$workdir/components" "$components_url" \
    || die "cannot download $components_url — is $SHA staged in the bucket? (see stage-release.sh)"

artifacts="$workdir/artifacts"
mkdir -p "$artifacts"
n=0
while IFS= read -r src; do
    basename="${src##*/}"
    url="$BUCKET_PUBLIC/$src"
    curl -fsSL --retry 3 -o "$artifacts/$basename" "$url" \
        || die "cannot download $url (from $components_url)"
    n=$((n + 1))
done < <(awk '!/^#/ && $NF ~ /^versions\// {print $NF}' "$workdir/components")

[ "$n" -gt 0 ] || die "no artifacts listed in $components_url — refusing to build an empty row"
echo "backfill-version-row: fetched $n artifact(s) from $SHA"

# stage-release.sh owns the row layout, the manifest, and the cache headers;
# --allow-missing because an old release may lack artifacts the current table
# lists. Fails loudly if a REQUIRED artifact is absent.
stage_args=(
    --artifacts-dir "$artifacts"
    --version "$SEMVER"
    --bucket "$BUCKET"
    --allow-missing
)
[ "$DRY_RUN" -eq 1 ] && stage_args+=(--dry-run)
script_dir="$(cd "$(dirname "$0")" && pwd)"
"$script_dir/stage-release.sh" "${stage_args[@]}"

echo "backfill-version-row: staged versions/$SEMVER from $SHA"
