#!/usr/bin/env bash
# Soak harness: run the unified session e2e (scripts/session-e2e.sh) N times
# back-to-back against a VM-backed target, reaping leftover VM processes
# between iterations, to shake out the boot / first-connect raciness (the
# vsock-bridge wedge class) that a single PR-lane run cannot surface. Reports
# a pass/fail tally and exits non-zero if ANY iteration failed.
#
# Then, once, the bulk host→guest upload proof (scripts/bulk-upload-e2e.sh):
# no session-e2e iteration pushes enough data through the guest vsock to catch
# the transport-reset class (https://github.com/gominimal/minimal/issues/869),
# which needs a project that is large AFTER compression. It runs on the same
# VM-backed setup the caller already provides, does its own (probabilistic)
# iterations, and cleans up after itself. Its result gates the exit status too.
#
# The caller sets the VM up exactly as the KVM lane does — minvmd + minimal
# on PATH, MINVMD_KERNEL_PATH / MINVMD_ROOTFS_PATH / MINVMD_INITRAMFS set,
# libkrun on the loader path — and passes the VM knobs through the
# environment (E2E_VM=1 E2E_MINIMAL_ARGS="--provider local-minvmd" E2E_PROJECT_DIR=/tmp),
# same as the lane invocation. Each iteration runs session-e2e.sh, which
# creates its own fresh XDG state, so every pass is a clean cold start.
#
# Environment:
#   SOAK_MIN_FREE_MIB   free-space floor, in MiB, for the filesystem holding the
#                       per-iteration state dirs (default 4096). See the
#                       headroom check below for why this harness needs one.
#
# Usage: scripts/soak-session-e2e.sh [iterations] [boot-log-dir]
set -uo pipefail

ITER="${1:-10}"
case "$ITER" in
  '' | *[!0-9]*) echo "iterations must be a positive integer, got: '$ITER'" >&2; exit 2 ;;
esac
[ "$ITER" -ge 1 ] || { echo "iterations must be >= 1, got: $ITER" >&2; exit 2; }

LOGDIR="${2:-$(mktemp -d /tmp/mnl-soak.XXXXXX)}"
mkdir -p "$LOGDIR" || { echo "cannot create boot-log dir: '$LOGDIR'" >&2; exit 2; }
# Absolutise: MINVMD_BOOT_LOG is consumed by minvmd as given (vmm_child.rs takes
# the env value verbatim), and both child harnesses cd into their own project
# dir before any `min` call, so a relative LOGDIR would resolve against that dir
# instead. minvmd only warns and boots on when the console file cannot be
# created, so the guest log — the half of #869 worth having — would vanish
# silently, exactly when a failing run needs it.
LOGDIR="$(cd "$LOGDIR" && pwd)"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Reap leftovers a failed boot may strand (the detached __krun-vmm grandchild
# and the gvproxy switch can linger and wedge the next iteration's bridge).
reap() { "$ROOT/scripts/reap-vms.sh"; }
# Reap on any exit, including a mid-run cancel (a cancelled CI job sends TERM,
# an interactive Ctrl-C sends INT), so orphaned VM processes never outlive the
# harness. The EXIT trap preserves the script's own exit status.
trap 'reap' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# ── Disk headroom ────────────────────────────────────────────────────────────
# Repeating a VM-backed e2e is the one thing this repo does that can genuinely
# exhaust a CI runner's disk: each iteration's state dir carries the provider's
# per-VM data volume, whose host allocation is everything the guest wrote (its
# package cache, the session rootfs, the workspace). session-e2e.sh reclaims
# its own state dir, so this should now stay flat — but "should" is what the
# nightly already believed. The failure mode is what makes a check worth having:
# a real ENOSPC kills the runner AGENT, and the job then reports `failure` with
# this step still `in_progress` and NO retrievable log lines, no uploaded
# artifacts, nothing to read. So measure the headroom, print it every iteration
# (the per-check delta is exactly the number that says whether reclamation is
# working), and stop with a real error while a runner is still alive to report.
case "$(uname -s)" in
  Darwin) STATE_FS=/tmp ;;    # where session-e2e.sh puts its state dir,
  *) STATE_FS="$HOME" ;;      # per platform (its sun_path / hardlink split)
esac
MIN_FREE_MIB="${SOAK_MIN_FREE_MIB:-4096}"
case "$MIN_FREE_MIB" in
  '' | *[!0-9]*) echo "SOAK_MIN_FREE_MIB must be a non-negative integer, got: '$MIN_FREE_MIB'" >&2; exit 2 ;;
esac

# Free MiB on the filesystem holding "$1". `df -Pk` is the portable spelling:
# -P pins one line per filesystem (GNU df wraps a long device name onto two
# otherwise, which would shift the columns) and -k pins 1024-byte blocks
# (macOS df reports 512-byte ones by default).
free_mib() { df -Pk "$1" 2>/dev/null | awk 'NR == 2 { print int($4 / 1024) }'; }

LAST_FREE=""
# Report headroom, and fail the step if it has fallen below the floor. "$1"
# names what is about to run, for the error text.
check_free() {
  local now delta
  now="$(free_mib "$STATE_FS")"
  case "$now" in
    '' | *[!0-9]*)
      echo "::warning::could not read free space on $STATE_FS — headroom check skipped"
      return 0
      ;;
  esac
  if [ -n "$LAST_FREE" ]; then
    delta=$((now - LAST_FREE))
    echo "disk: ${now} MiB free on $STATE_FS (${delta} MiB since the last check)"
  else
    echo "disk: ${now} MiB free on $STATE_FS (floor ${MIN_FREE_MIB} MiB)"
  fi
  LAST_FREE="$now"
  [ "$now" -ge "$MIN_FREE_MIB" ] && return 0
  echo "::error::only ${now} MiB free on $STATE_FS before $1 (floor ${MIN_FREE_MIB} MiB; override with SOAK_MIN_FREE_MIB). Stopping here so this reports as a failed step: an actual ENOSPC kills the runner agent, and the job then reports 'failure' with no log lines at all."
  return 1
}

pass=0
fail=0
for i in $(seq 1 "$ITER"); do
  echo "::group::soak iteration $i/$ITER"
  reap
  if ! check_free "soak iteration $i/$ITER"; then
    echo "::endgroup::"
    exit 1
  fi
  if MINVMD_BOOT_LOG="$LOGDIR/boot-$i.log" "$ROOT/scripts/session-e2e.sh"; then
    pass=$((pass + 1))
    echo "iteration $i: OK"
  else
    fail=$((fail + 1))
    echo "::warning::soak iteration $i FAILED"
  fi
  echo "::endgroup::"
done
# Final reap is handled by the EXIT trap.

echo "::group::bulk host→guest upload proof"
reap
if ! check_free "the bulk upload proof"; then
  echo "::endgroup::"
  exit 1
fi
if MINVMD_BOOT_LOG="$LOGDIR/boot-bulk.log" "$ROOT/scripts/bulk-upload-e2e.sh"; then
  bulk=OK
else
  bulk=FAILED
  echo "::warning::bulk upload proof FAILED"
fi
echo "::endgroup::"

# Closing headroom, reported not enforced: everything is already done, and a
# `::error::` here would paint a run that passed red.
echo "disk: $(free_mib "$STATE_FS") MiB free on $STATE_FS at the end of the run"
echo "soak complete: $pass passed, $fail failed (of $ITER); bulk upload proof: $bulk"
# Require every iteration to have run AND passed — a short-circuited loop that
# ran zero iterations must not report success.
[ "$fail" -eq 0 ] && [ "$pass" -eq "$ITER" ] && [ "$bulk" = OK ]
