#!/usr/bin/env bash
#
# cancel-stale-queue-runs.sh — cancel merge-queue runs of a workflow whose
# queue group no longer exists.
#
# ci-macos.yml keys its concurrency on github.ref, and a merge-queue group's
# ref (gh-readonly-queue/<branch>/pr-N-<base sha>) is unique per (re)build. So
# when the queue rebuilds its groups (an entry is dropped, times out, or is
# dequeued) the old group's run is never cancelled. On the single shared macOS
# runner those orphans back up every later group. This script finds them and
# cancels them; .github/workflows/macos-queue-janitor.yml schedules it.
#
# A run is stale iff its head SHA is not the head commit of any live
# merge-queue entry on the branch. Only `merge_group` runs are ever touched.
#
# ORDERING: the workflow's non-completed runs are listed FIRST, and the live
# queue entries are read SECOND. Every listed run was created for an entry
# that existed before the entries are read, so a group built in between can
# never be mistaken for stale.
#
# SAFETY:
#   * DRY-RUN BY DEFAULT — prints what it would cancel; changes nothing until
#     you pass --execute.
#   * A failed or null merge-queue query (or a truncated entry list) aborts
#     before anything is cancelled: an empty live set is never inferred from
#     an error. A genuinely empty queue (no entries) is valid and makes every
#     listed group run stale.
#
# Usage:
#   scripts/cancel-stale-queue-runs.sh [options]
#
# Options (env var in parens overrides the default; flags win over env):
#   --repo OWNER/NAME  Target repo                 (REPO, default: $GITHUB_REPOSITORY)
#   --workflow FILE    Workflow file to police     (WORKFLOW, default: ci-macos.yml)
#   --branch NAME      Merge-queue target branch   (BRANCH, default: main)
#   --execute          Actually cancel (otherwise dry-run)
#   -h, --help         Show this help
#
# Requires: bash, jq, and `gh` authenticated with actions:write on the repo.
# GH overrides the gh command (the test harness points it at a stub).

set -euo pipefail

die() {
    printf 'cancel-stale-queue-runs: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
WORKFLOW="${WORKFLOW:-ci-macos.yml}"
BRANCH="${BRANCH:-main}"
GH="${GH:-gh}"
EXECUTE=0

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)     REPO="$2"; shift 2 ;;
        --workflow) WORKFLOW="$2"; shift 2 ;;
        --branch)   BRANCH="$2"; shift 2 ;;
        --execute)  EXECUTE=1; shift ;;
        -h|--help)  usage 0 ;;
        *)          die "unknown argument: $1 (try --help)" ;;
    esac
done

command -v jq >/dev/null 2>&1 || die "jq not found"
command -v "$GH" >/dev/null 2>&1 || die "$GH not found"
case "$REPO" in
    */*) ;;
    *) die "--repo OWNER/NAME is required (or set GITHUB_REPOSITORY)" ;;
esac

# 1. Every non-completed merge_group run of the workflow, as one JSON array of
#    {id, head_sha, head_branch, event}. The event filter is repeated in jq so
#    a run of any other event can never be cancelled, whatever the API returns.
raw_runs=""
for status in queued in_progress waiting pending requested; do
    page="$("$GH" api --paginate \
        "repos/$REPO/actions/workflows/$WORKFLOW/runs?event=merge_group&status=$status&per_page=100" \
        --jq '.workflow_runs[] | {id, head_sha, head_branch, event}')" \
        || die "could not list $status $WORKFLOW runs; cancelling nothing"
    raw_runs+="$page"$'\n'
done
runs_json="$(jq -s --arg prefix "gh-readonly-queue/$BRANCH/" \
    'map(select(.event == "merge_group" and ((.head_branch // "") | startswith($prefix))))
     | unique_by(.id)' <<<"$raw_runs")" \
    || die "could not parse the $WORKFLOW run list"

# 2. The live merge-queue entries' head SHAs, read only after step 1.
# shellcheck disable=SC2016 # GraphQL variables, not shell expansions.
query='query($owner: String!, $name: String!, $branch: String!) {
  repository(owner: $owner, name: $name) {
    mergeQueue(branch: $branch) {
      entries(first: 100) {
        pageInfo { hasNextPage }
        nodes { headCommit { oid } }
      }
    }
  }
}'
queue_raw="$("$GH" api graphql -f query="$query" \
    -f owner="${REPO%%/*}" -f name="${REPO#*/}" -f branch="$BRANCH")" \
    || die "merge-queue query failed; cancelling nothing"
live_json="$(jq -c '
    if (.errors // []) | length > 0 then error("graphql errors: \(.errors | map(.message) | join("; "))")
    elif .data.repository.mergeQueue == null then error("mergeQueue is null")
    elif .data.repository.mergeQueue.entries.pageInfo.hasNextPage then error("entry list truncated")
    else [.data.repository.mergeQueue.entries.nodes[].headCommit.oid]
    end' <<<"$queue_raw")" \
    || die "unusable merge-queue response; cancelling nothing"

# 3. Decide and act: one line per run.
cancelled=0
kept=0
failed=0
while IFS=$'\t' read -r verdict id sha branch; do
    if [ "$verdict" = keep ]; then
        printf 'kept:      %s %s %s\n' "$id" "$sha" "$branch"
        kept=$((kept + 1))
    elif [ "$EXECUTE" -eq 0 ]; then
        printf 'would cancel: %s %s %s\n' "$id" "$sha" "$branch"
        cancelled=$((cancelled + 1))
    elif "$GH" api -X POST "repos/$REPO/actions/runs/$id/cancel" >/dev/null; then
        printf 'cancelled: %s %s %s\n' "$id" "$sha" "$branch"
        cancelled=$((cancelled + 1))
    else
        # Usually the run finished between listing and cancelling (HTTP 409);
        # a warning, not a reason to skip the remaining runs.
        printf 'cancel failed: %s %s %s\n' "$id" "$sha" "$branch" >&2
        failed=$((failed + 1))
    fi
done < <(jq -r --argjson live "$live_json" \
    '.[] | [(if (.head_sha | IN($live[])) then "keep" else "cancel" end), .id, .head_sha, .head_branch] | @tsv' \
    <<<"$runs_json")

verb="would cancel"
[ "$EXECUTE" -eq 1 ] && verb="cancelled"
printf 'cancel-stale-queue-runs: %s %d stale %s run(s); kept %d live; %d cancel(s) failed; live queue entries: %d\n' \
    "$verb" "$cancelled" "$WORKFLOW" "$kept" "$failed" "$(jq length <<<"$live_json")" >&2
[ "$EXECUTE" -eq 0 ] && printf 'cancel-stale-queue-runs: dry-run — re-run with --execute to cancel\n' >&2
exit 0
