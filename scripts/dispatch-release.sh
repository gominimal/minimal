#!/usr/bin/env bash
#
# dispatch-release.sh — run release.yml versioned on a release line and wait.
#
# A dispatch builds the branch tip as it stands when the run starts, so the
# tip is checked before the dispatch and the run's commit after it. A run on
# any other commit is cancelled: it has not been rehearsed, and it could stage
# under a number that can't be used again. Cancelling is safe because staging
# comes after the builds.
#
# Usage:
#   scripts/dispatch-release.sh --line release/X.Y.x --sha SHA --dry-run true|false \
#       [--restage true|false]
#
# Needs gh, with GH_TOKEN holding actions:write, and GITHUB_REPOSITORY.
# POLL_SECONDS sets the wait between status reads (default 60).

set -euo pipefail

die() {
    printf 'dispatch-release: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

LINE="" SHA="" DRY_RUN="" RESTAGE="false"
while [ $# -gt 0 ]; do
    case "$1" in
        --line)    [ -n "${2:-}" ] || die "--line needs a branch"; LINE="$2"; shift 2 ;;
        --sha)     [ -n "${2:-}" ] || die "--sha needs a commit"; SHA="$2"; shift 2 ;;
        --dry-run) [ -n "${2:-}" ] || die "--dry-run needs true or false"; DRY_RUN="$2"; shift 2 ;;
        --restage) [ -n "${2:-}" ] || die "--restage needs true or false"; RESTAGE="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *)         die "unknown argument: $1 (try --help)" ;;
    esac
done
if [ -z "$LINE" ] || [ -z "$SHA" ]; then die "--line and --sha are required"; fi
[ "$DRY_RUN" = "true" ] || [ "$DRY_RUN" = "false" ] || die "--dry-run must be true or false"
[ -n "${GITHUB_REPOSITORY:-}" ] || die "GITHUB_REPOSITORY is not set"
repo="repos/$GITHUB_REPOSITORY"

tip="$(gh api "$repo/git/ref/heads/$LINE" --jq .object.sha)"
[ "$tip" = "$SHA" ] || die "$LINE moved from $SHA to $tip; run Stage release again"

# return_run_details makes the dispatch answer with the run it created.
run_id="$(gh api -X POST "$repo/actions/workflows/release.yml/dispatches" \
    -f ref="$LINE" -F return_run_details=true \
    -f 'inputs[versioned]=true' -f "inputs[dry_run]=$DRY_RUN" -f "inputs[restage]=$RESTAGE" \
    --jq .workflow_run_id)"
[ -n "$run_id" ] || die "dispatched release.yml but GitHub returned no run id; find the run in Actions"
url="https://github.com/$GITHUB_REPOSITORY/actions/runs/$run_id"
printf 'dispatch-release: %s (dry_run=%s, restage=%s) on %s\n' "$url" "$DRY_RUN" "$RESTAGE" "$SHA"

# Retry the read: an unchecked run could stage a commit that moved in. If
# every read fails, treat the commit as unknown and cancel.
run_sha=""
for try in 1 2 3; do
    if run_sha="$(gh api "$repo/actions/runs/$run_id" --jq .head_sha)"; then break; fi
    run_sha=""
    [ "$try" -eq 3 ] || sleep "${POLL_SECONDS:-60}"
done
if [ "$run_sha" != "$SHA" ]; then
    gh api -X POST "$repo/actions/runs/$run_id/cancel" >/dev/null
    die "$url built ${run_sha:-an unknown commit}, not $SHA; cancelled it"
fi

# A failed read is not a failed run: the Nov 4 nightly lost an attempt to one
# 502, so keep polling. The job's timeout bounds this loop.
while :; do
    sleep "${POLL_SECONDS:-60}"
    state="$(gh api "$repo/actions/runs/$run_id" --jq '"\(.status) \(.conclusion)"' || echo "unknown")"
    case "$state" in
        "completed success")
            printf 'dispatch-release: %s passed\n' "$url"
            exit 0 ;;
        completed\ *) die "$url ended: ${state#completed }" ;;
    esac
done
