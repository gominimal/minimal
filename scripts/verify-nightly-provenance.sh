#!/usr/bin/env bash
#
# verify-nightly-provenance.sh — assert a staged version was built by nightly.
#
# Promotion (promote.yml) only lets a channel point at a version the nightly
# release workflow actually produced. A version passes when the GitHub Actions
# API shows a successful run of the nightly workflow whose head commit matches
# the staged version's short SHA AND whose smoke-success aggregator job actually
# ran (conclusion "success", not "skipped"); otherwise this script exits
# non-zero and the promotion fails before the channel pointer is touched.
#
# A no-op nightly run that skipped its build (the SHA was already staged) also
# skips the smoke jobs, so it does NOT pass verification — the version must
# have been smoked by a prior run that actually built and tested it.
#
# Usage:
#   scripts/verify-nightly-provenance.sh --sha SHORTSHA [options]
#
# Options (env var in parens overrides the default; flags win over env):
#   --sha SHORTSHA    Staged version (short SHA) to verify   (SHA)
#   --repo OWNER/REPO Repository whose runs to query         (REPO, default: $GITHUB_REPOSITORY)
#   --workflow FILE   Workflow file that must have built it  (WORKFLOW_FILE, default: nightly.yml)
#   -h, --help        Show this help
#
# Requires: an authenticated `gh` with actions:read on the repository.

set -euo pipefail

die() {
    printf 'verify-nightly-provenance: %s\n' "$1" >&2
    exit 1
}

usage() {
    sed -n '2,/^set -euo/{/^set -euo/!p;}' "$0" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

SHA="${SHA:-}"
REPO="${REPO:-${GITHUB_REPOSITORY:-}}"
WORKFLOW_FILE="${WORKFLOW_FILE:-nightly.yml}"

while [ $# -gt 0 ]; do
    case "$1" in
        --sha|--repo|--workflow)
            # Guard $2: under `set -u` a trailing valueless flag would abort
            # with an unbound-variable error instead of a usable message.
            [ $# -ge 2 ] || die "missing value for $1"
            case "$1" in
                --sha)      SHA="$2" ;;
                --repo)     REPO="$2" ;;
                --workflow) WORKFLOW_FILE="$2" ;;
            esac
            shift 2 ;;
        -h|--help)  usage 0 ;;
        *)          die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$SHA" ] || die "missing --sha"
[ -n "$REPO" ] || die "missing --repo (and GITHUB_REPOSITORY is unset)"

# Staged versions are `git rev-parse --short=8` SHAs: 8 hex chars, longer only
# on prefix collision, and a full 40-char SHA is always acceptable. Refuse
# anything shorter so a stray fragment can't prefix-match an unrelated run.
case "$SHA" in
    *[!0-9a-fA-F]*) die "sha '$SHA' contains non-hex characters" ;;
esac
[ "${#SHA}" -ge 8 ] || die "sha '$SHA' is too short (staged versions are 8+ hex chars)"
[ "${#SHA}" -le 40 ] || die "sha '$SHA' is longer than a full 40-char commit SHA"

command -v gh >/dev/null 2>&1 || die "gh not found"

sha_lc=$(printf '%s' "$SHA" | tr '[:upper:]' '[:lower:]')

# One "head_sha run_id html_url" line per successful run. Capture before
# grepping so a grep -m1 early exit can't SIGPIPE gh under pipefail.
runs=$(gh api --paginate \
    "repos/${REPO}/actions/workflows/${WORKFLOW_FILE}/runs?status=success&per_page=100" \
    --jq '.workflow_runs[] | "\(.head_sha) \(.id) \(.html_url)"')

# Anchor the prefix match to the head_sha field (hex run, then the space
# before the run_id) so the input can only ever match a prefix of the commit SHA.
match=$(printf '%s\n' "$runs" | grep -m1 -E "^${sha_lc}[0-9a-f]* " || true)

[ -n "$match" ] || die "version '$SHA' was not built by a successful ${WORKFLOW_FILE} run in ${REPO}; \
promote a nightly-built version, or re-dispatch with the emergency provenance override"

# Extract run_id (second field) and html_url (third field onwards).
run_id="${match#* }"      # drop head_sha
run_id="${run_id%% *}"    # keep only run_id
run_url="${match#* }"     # drop head_sha
run_url="${run_url#* }"   # drop run_id, leaving html_url

# Verify that smoke tests actually ran (not skipped). A no-op nightly run where
# the check job found an already-staged version skips all build/smoke jobs; the
# overall run still succeeds, but we must not promote a version that bypassed
# the smoke test suite. The smoke-success aggregator job exists with conclusion
# "success" only when the smoke jobs actually executed and passed.
smoke_conclusion=$(gh api \
    "repos/${REPO}/actions/runs/${run_id}/jobs?per_page=100" \
    --jq '.jobs[] | select(.name == "smoke-success") | .conclusion' 2>/dev/null || true)

if [ "$smoke_conclusion" != "success" ]; then
    if [ -z "$smoke_conclusion" ]; then
        die "version '$SHA' in ${WORKFLOW_FILE} run ${run_url} has no smoke-success job; \
smoke tests must complete before promotion"
    else
        die "version '$SHA' in ${WORKFLOW_FILE} run ${run_url} has smoke-success with conclusion '$smoke_conclusion' (not 'success'); \
smoke tests must pass before promotion"
    fi
fi

printf 'verify-nightly-provenance: %s was built by %s run %s (smoke-success: %s)\n' \
    "$SHA" "$WORKFLOW_FILE" "$run_url" "$smoke_conclusion" >&2
