#!/usr/bin/env bash
# Docs-site build + link gate. The LOGIC of the docs-site lane lives here (and
# in the `docs-check` justfile recipe), not in the workflow YAML: per
# CONTRIBUTING.md and docs/ci-strategy.md the CI layer is a thin scheduler over
# the tests, scripts/, and the justfile — coverage is extended through this
# script, never by growing .github/workflows/. docs-site.yml only installs the
# toolchain (Node, lychee), invokes this script, and uploads the rendered site.
#
# Modes:
#   build         install site deps (npm ci) + `npm run docs:build`
#   links         site-absolute-link guard + OFFLINE lychee internal-link check
#   all (default) build, then links
#   online-links  ONLINE lychee sweep of external URLs (the weekly advisory job)
#
# lychee: the docs-site workflow installs it before calling the link modes, so
# it is always present in CI. When it is absent locally the lychee sweep is
# SKIPPED with a note (the grep-based site-absolute guard, needing only grep,
# always runs) — matching how `just test-installer` skips shellcheck when it is
# not installed. The site-absolute guard is the load-bearing local check; the
# lychee pass is the CI addition.
#
# Usage: scripts/docs-check.sh [build|links|all|online-links]
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" # globs below (docs/**, docs/reference/, *.md) resolve from the root

MODE="${1:-all}"

# npm ci is the clean, lockfile-exact install CI needs; a fresh CI checkout
# never carries node_modules, so it always runs there. Locally we skip it when
# node_modules is already present to keep repeated runs fast.
docs_build() {
  command -v npm >/dev/null 2>&1 \
    || { echo "docs-check: 'npm' not found — install Node >= 22 (package.json engines)" >&2; exit 1; }
  if [ -d node_modules ]; then
    echo "docs-check: node_modules present, skipping npm ci"
  else
    npm ci
  fi
  npm run docs:build
}

# A `](/...)` link resolves against whatever base the page is served under —
# wrong on the mirrored gominimal/webapp copy and dead when the page is read
# in-repo on GitHub. Relative links work everywhere.
forbid_site_absolute_links() {
  if grep -rnF '](/' docs/reference/ --include='*.md'; then
    echo "docs-check: site-absolute links ('](/') found under docs/reference/ — use relative links" >&2
    exit 1
  fi
}

# --offline verifies file-to-file links and #fragments only; external URLs are
# skipped (the online sweep covers those, without third-party outages breaking
# PRs). Absent lychee => skip with a note (see header).
offline_link_check() {
  if command -v lychee >/dev/null 2>&1; then
    lychee --offline --no-progress --include-fragments 'docs/**/*.md' '*.md'
  else
    echo "docs-check: 'lychee' not found — skipping the offline internal-link check (see https://github.com/lycheeverse/lychee)" >&2
  fi
}

# Weekly advisory sweep of EXTERNAL URLs. Advisory only: the workflow runs this
# under continue-on-error so third-party outages / rate limits never redden the
# repo (failures surface in the Actions log for a human to triage).
online_link_check() {
  if command -v lychee >/dev/null 2>&1; then
    lychee --no-progress 'docs/**/*.md' '*.md'
  else
    echo "docs-check: 'lychee' not found — skipping the online link sweep (see https://github.com/lycheeverse/lychee)" >&2
  fi
}

case "$MODE" in
  build)        docs_build ;;
  links)        forbid_site_absolute_links; offline_link_check ;;
  all)          docs_build; forbid_site_absolute_links; offline_link_check ;;
  online-links) online_link_check ;;
  *)
    echo "usage: scripts/docs-check.sh [build|links|all|online-links]" >&2
    exit 2
    ;;
esac
