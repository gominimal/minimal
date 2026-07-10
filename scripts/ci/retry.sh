#!/usr/bin/env bash
# Retry a command a fixed number of times with a fixed sleep, for transient
# network failures in CI. Introduced for apt-get installs — the one step
# class with recorded transient failures in this repo's lane history (the
# only main-branch KVM lane failure and both of its manual re-runs died in
# "Install build dependencies"). Deterministic work must happen OUTSIDE the
# retried command so a hard failure fails fast instead of being re-run to
# the job timeout.
#
# Usage: scripts/ci/retry.sh <attempts> <sleep-seconds> <command> [args...]
set -euo pipefail

ATTEMPTS="${1:?usage: retry.sh <attempts> <sleep-seconds> <command...>}"
SLEEP="${2:?usage: retry.sh <attempts> <sleep-seconds> <command...>}"
shift 2

for attempt in $(seq 1 "$ATTEMPTS"); do
  if "$@"; then
    exit 0
  fi
  if [ "$attempt" -lt "$ATTEMPTS" ]; then
    echo "::warning::attempt $attempt/$ATTEMPTS failed: $*; retrying in ${SLEEP}s" >&2
    sleep "$SLEEP"
  fi
done
echo "::error::command failed after $ATTEMPTS attempts: $*" >&2
exit 1
