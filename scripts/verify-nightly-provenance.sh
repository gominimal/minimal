#!/usr/bin/env bash
#
# verify-nightly-provenance.sh — assert a staged version was built by nightly.
#
# Promotion (promote.yml) only lets a channel point at a version the nightly
# release workflow actually produced. A version passes when the GitHub Actions
# API shows a successful run of the nightly workflow whose head commit matches
# the staged version's short SHA; otherwise this script exits non-zero and the
# promotion fails before the channel pointer is touched.
#
# A nightly run that skipped its build because the SHA was already staged still
# counts: the run pointed the `nightly` channel at that SHA, so the version went
# through the nightly path either way.
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
        --sha)      SHA="$2"; shift 2 ;;
        --repo)     REPO="$2"; shift 2 ;;
        --workflow) WORKFLOW_FILE="$2"; shift 2 ;;
        -h|--help)  usage 0 ;;
        *)          die "unknown argument: $1 (try --help)" ;;
    esac
done

[ -n "$SHA" ] || die "missing --sha"
[ -n "$REPO" ] || die "missing --repo (and GITHUB_REPOSITORY is unset)"

# Staged versions are short (8-hex) commit SHAs; insist on a sane prefix so a
# stray short string can't accidentally prefix-match an unrelated run.
case "$SHA" in
    *[!0-9a-fA-F]*) die "sha '$SHA' contains non-hex characters" ;;
esac
[ "${#SHA}" -ge 7 ] || die "sha '$SHA' is too short (need at least 7 hex chars)"

command -v gh >/dev/null 2>&1 || die "gh not found"

sha_lc=$(printf '%s' "$SHA" | tr '[:upper:]' '[:lower:]')

# One "head_sha html_url" line per successful run. Capture before grepping so a
# grep -m1 early exit can't SIGPIPE gh under pipefail.
runs=$(gh api --paginate \
    "repos/${REPO}/actions/workflows/${WORKFLOW_FILE}/runs?status=success&per_page=100" \
    --jq '.workflow_runs[] | "\(.head_sha) \(.html_url)"')

match=$(printf '%s\n' "$runs" | grep -m1 "^${sha_lc}" || true)

[ -n "$match" ] || die "version '$SHA' was not built by a successful ${WORKFLOW_FILE} run in ${REPO}; \
promote a nightly-built version, or re-dispatch with the emergency provenance override"

printf 'verify-nightly-provenance: %s was built by %s run %s\n' \
    "$SHA" "$WORKFLOW_FILE" "${match#* }" >&2
