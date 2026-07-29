#!/usr/bin/env bash
# Fail the job when an `actions/cache` save silently did not land.
#
# WHY THIS EXISTS
# ---------------
# `actions/cache/save` tars its payload into RUNNER_TEMP and compresses it in
# place. When that write runs out of disk, tar and zstd die and the action
# downgrades the failure to `##[warning]Failed to save:` — the step, the job,
# and the required check all stay green while the cache entry silently freezes
# at whatever version last fit.
#
# That is not hypothetical. The `dogfood` lane's Cargo-state entry grows by
# roughly 100 MB per save (cargo never GCs, so each run appends the new
# lockfile's artifacts on top of every older one). At ~5.9 GB the archive
# stopped fitting on the runner and every save from 2026-07-27 on died with
# `zstd: error 70 : Write error : cannot write block : No space left on
# device`. Nobody noticed for two days: each later run restored the frozen
# entry through `restore-keys`, rebuilt the tree from scratch — 55 s of cargo
# became 10-13 min — and the lane only went red when a slow runner finally
# overran the job timeout, which pointed at a cancelled build rather than at
# the cache.
#
# Usage: ci-verify-cache-saved.sh <cache-key>
#
# Needs GH_TOKEN with `actions: read` and GITHUB_REPOSITORY (both are ambient
# in Actions). A missing entry is a hard error; an unusable API is only a
# warning, so a token or outage problem cannot fail an otherwise good build.
set -euo pipefail

key="${1:-}"
if [ -z "$key" ]; then
    echo "usage: $0 <cache-key>" >&2
    exit 2
fi
repo="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is not set}"

if ! total="$(gh api "repos/$repo/actions/caches?key=$key" --jq '.total_count')"; then
    echo "::warning::could not query the Actions cache API; skipping the save check for $key"
    exit 0
fi

if [ "$total" -gt 0 ]; then
    echo "cache entry present: $key"
    exit 0
fi

# The save step ran and reported success, yet no entry exists. Disk is the
# usual culprit, so print it here — this output is the whole point of the
# check, and it is what the next person will read first.
echo "::error::cache key $key was not saved; the save step's failure was downgraded to a warning (check the log above for 'Failed to save')"
echo "--- df -h ---"
df -h / "${RUNNER_TEMP:-/tmp}" || true
exit 1
