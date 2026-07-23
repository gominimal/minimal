#!/usr/bin/env bash
#
# prune-releases.sh — delete GitHub Releases older than a cutoff age.
#
# Every release build publishes a `release-<sha>` GitHub Release (see
# release.yml). These accumulate indefinitely; this script prunes the old ones.
#
# It is decoupled from what users actually install: the curl|bash installer
# resolves versions from the GCS buckets (gs://minimal-shim, gs://minimal-one),
# not from GitHub Releases, so deleting an old Release removes a redundant
# artifact copy, not a live install target. It is also decoupled from the
# version scheme: `crates/version` derives versions via `git describe --match
# 'v*'`, which ignores `release-<sha>` tags.
#
# SAFETY:
#   * DRY-RUN BY DEFAULT — prints what it would delete; changes nothing until
#     you pass --execute.
#   * --keep-latest N always retains the N newest matching releases regardless of
#     age, so a lull in releases can never empty out the list.
#   * EXACT vMAJOR.MINOR.PATCH releases are NEVER deleted, whatever --match is set
#     to — a hard, unconditional guard. Pre-releases (v0.5.0-rc1) and other
#     suffixed tags are NOT protected and remain prunable.
#
# Usage:
#   scripts/prune-releases.sh [options]
#
# Options (env var in parens overrides the default; flags win over env):
#   --older-than SPEC  Age cutoff, any GNU `date -d` spec   (OLDER_THAN, default: 2 months)
#   --keep-latest N    Always retain the N newest matches    (KEEP_LATEST, default: 10)
#   --match GLOB       Only delete releases whose tag matches (MATCH, default: release-*)
#   --repo OWNER/NAME  Target repo                            (REPO, default: inferred from cwd)
#   --cleanup-tags     Also delete the underlying git tag, not just the Release
#   --execute          Actually delete (otherwise dry-run)
#   -h, --help         Show this help
#
# Requires: bash, GNU date, and `gh` authenticated with write access to the repo.

set -euo pipefail

die() {
    printf 'prune-releases: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

OLDER_THAN="${OLDER_THAN:-2 months}"
KEEP_LATEST="${KEEP_LATEST:-10}"
MATCH="${MATCH:-release-*}"
REPO="${REPO:-}"
CLEANUP_TAGS=0
EXECUTE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --older-than)   OLDER_THAN="$2"; shift 2 ;;
        --keep-latest)  KEEP_LATEST="$2"; shift 2 ;;
        --match)        MATCH="$2"; shift 2 ;;
        --repo)         REPO="$2"; shift 2 ;;
        --cleanup-tags) CLEANUP_TAGS=1; shift ;;
        --execute)      EXECUTE=1; shift ;;
        -h|--help)      usage 0 ;;
        *)              die "unknown argument: $1 (try --help)" ;;
    esac
done

command -v gh >/dev/null 2>&1 || die "gh not found"
case "$KEEP_LATEST" in
    '' | *[!0-9]*) die "--keep-latest must be a non-negative integer, got '$KEEP_LATEST'" ;;
esac

# Cutoff as a Unix epoch. `date -d` handles relative specs like "2 months ago".
CUTOFF="$(date -u -d "$OLDER_THAN ago" +%s)" \
    || die "could not parse --older-than '$OLDER_THAN' (needs GNU date)"

# gh's {owner}/{repo} template infers from cwd; an explicit --repo overrides both
# the API path and `gh release delete`.
api_repo="{owner}/{repo}"
repo_flag=()
if [ -n "$REPO" ]; then
    api_repo="$REPO"
    repo_flag=(--repo "$REPO")
fi

cleanup_flag=()
[ "$CLEANUP_TAGS" -eq 1 ] && cleanup_flag=(--cleanup-tag)

# Every release as `tag<TAB>epoch`, newest first. Drafts have a null
# published_at, so fall back to created_at; fromdateiso8601 turns the GitHub UTC
# timestamp into an epoch. --paginate walks every page; sort descending so
# --keep-latest can retain the newest N regardless of age.
mapfile -t rows < <(
    gh api --paginate "repos/$api_repo/releases" \
        --jq '.[] | [.tag_name, ((.published_at // .created_at) | fromdateiso8601)] | @tsv' \
        | sort -t"$(printf '\t')" -k2 -nr
)

deleted=0
kept_recent=0
kept_fresh=0
skipped=0
protected=0
rank=0
for row in "${rows[@]}"; do
    tag="${row%%$'\t'*}"
    epoch="${row##*$'\t'}"

    # HARD GUARD: never delete an EXACT vMAJOR.MINOR.PATCH release, whatever
    # --match says — these are the hand-cut version releases the installer and
    # `git describe` depend on. Anchored so only a bare `v1.2.3` is protected;
    # pre-releases (`v0.5.0-rc1`) and any other suffixed tag remain prunable.
    if [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        protected=$((protected + 1))
        continue
    fi

    # Only consider tags the caller asked for (default: the auto-cut release-*).
    # $MATCH is a deliberate glob pattern (default `release-*`), so it must
    # stay unquoted to match as a glob rather than a literal.
    # shellcheck disable=SC2254
    case "$tag" in
        $MATCH) ;;
        *) skipped=$((skipped + 1)); continue ;;
    esac

    # Rank among matching releases; always retain the newest KEEP_LATEST.
    rank=$((rank + 1))
    if [ "$rank" -le "$KEEP_LATEST" ]; then
        kept_recent=$((kept_recent + 1))
        continue
    fi

    # Past the keep-window: delete only if also older than the age cutoff.
    if [ "$epoch" -ge "$CUTOFF" ]; then
        kept_fresh=$((kept_fresh + 1))
        continue
    fi

    if [ "$EXECUTE" -eq 0 ]; then
        printf 'would delete: %s\n' "$tag"
        deleted=$((deleted + 1))
        continue
    fi
    if gh release delete "$tag" --yes "${cleanup_flag[@]}" "${repo_flag[@]}"; then
        printf 'deleted: %s\n' "$tag"
        deleted=$((deleted + 1))
    else
        die "failed to delete release '$tag'"
    fi
done

verb="would delete"
[ "$EXECUTE" -eq 1 ] && verb="deleted"
printf 'prune-releases: %s %d release(s); kept %d newest + %d within age; protected %d vX.Y.Z; skipped %d non-matching\n' \
    "$verb" "$deleted" "$kept_recent" "$kept_fresh" "$protected" "$skipped" >&2
[ "$EXECUTE" -eq 0 ] && printf 'prune-releases: dry-run — re-run with --execute to delete\n' >&2
exit 0
