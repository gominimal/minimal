#!/usr/bin/env bash
# Soak harness: run the unified session e2e (scripts/session-e2e.sh) N times
# back-to-back against a VM-backed target, reaping leftover VM processes
# between runs, to shake out the boot / first-connect raciness (the
# vsock-bridge wedge class) that a single PR-lane run cannot surface. Reports
# a pass/fail tally and exits non-zero if ANY iteration failed.
#
# An iteration runs the cold-boot core cases (SOAK_CASES below), each as its
# own session-e2e.sh invocation. Every invocation gets a fresh state dir, so
# each case is a cold VM boot followed by a first connect. An iteration does
# not run the whole lane: the KVM lane already runs it on every push to main,
# and one whole-lane run now takes over 20 minutes on a hosted runner, so ten
# of them cannot fit the nightly job's time limit.
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
# same as the lane invocation. Each session-e2e.sh invocation creates its own
# fresh XDG state, so every pass is a clean cold start.
#
# Environment:
#   SOAK_CASES          the session-e2e.sh case names each iteration runs, in
#                       order, separated by spaces (default: lifecycle
#                       session_exec sandbox restart). `all` runs the whole
#                       lane once per iteration instead.
#   SOAK_CASE_TIMEOUT_SECS  time limit, in seconds, for one case's
#                       session-e2e.sh run (default 240). A run that hangs
#                       past it counts as a failed case, and the soak goes on
#                       to the next case instead of losing the rest of the
#                       night to the job's time limit. Not applied with `all`.
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

# The cases each iteration runs. Each one autospawns the daemon in a fresh VM
# and then makes the first connect its proof needs: list, warm call and
# destroy; a non-interactive exec; an interactive attach over the vsock
# bridge; a daemon stop and its autospawn.
CASES="${SOAK_CASES-lifecycle session_exec sandbox restart}"
case "$CASES" in
  all) CASES="" ;;  # session-e2e.sh with no argument runs the whole lane
  *[![:space:]]*) ;;
  *) echo "SOAK_CASES names no case; set it to case names or 'all'" >&2; exit 2 ;;
esac
# Check every name once, up front: session-e2e.sh refuses an unknown case
# only when it runs, so a misspelt name would fail the same case in every
# iteration. The accepted names are read from the arm of session-e2e.sh's
# final dispatch that calls "proof_$1", so the two lists cannot drift. Some
# proof_ functions are helpers that this arm does not name, and they are
# refused here too.
dispatch_cases() {
  awk '
    /^case "\$\{1:-\}" in$/ { in_case = 1; arm = 0; names = ""; next }
    /^esac$/                { in_case = 0; next }
    in_case && /^    ;;$/   { arm = 1; next }
    in_case && arm && /^    "proof_\$1"$/ { print names; exit }
    in_case && arm          { names = names " " $0 }
  ' "$ROOT/scripts/session-e2e.sh" | tr '|\\)' '   '
}
KNOWN_CASES=" $(dispatch_cases | tr -s ' \t' '  ') "
if [ -z "${KNOWN_CASES// /}" ]; then
  echo "could not read the case names from scripts/session-e2e.sh" >&2
  exit 2
fi
for c in $CASES; do
  case "$KNOWN_CASES" in
    *" $c "*) ;;
    *) echo "SOAK_CASES names '$c', which is not a case of scripts/session-e2e.sh" >&2; exit 2 ;;
  esac
done

# A healthy case takes well under a minute; a cold guest boot can spend up
# to about 70 s probing hardware first. 240 s leaves room for that, and a
# hang then costs at most this plus the kill grace below (5 minutes), so
# the job's slack absorbs a few hangs and still reaches the steps after the
# soak.
CASE_TIMEOUT="${SOAK_CASE_TIMEOUT_SECS:-240}"
case "$CASE_TIMEOUT" in
  '' | *[!0-9]*) echo "SOAK_CASE_TIMEOUT_SECS must be a positive integer, got: '$CASE_TIMEOUT'" >&2; exit 2 ;;
esac
# Compare as a number, so 0 and 00 are both refused: GNU timeout reads a
# zero limit as no limit at all.
if [ "$((10#$CASE_TIMEOUT))" -eq 0 ]; then
  echo "SOAK_CASE_TIMEOUT_SECS must be a positive integer, got: '$CASE_TIMEOUT'" >&2
  exit 2
fi
# A case that outlives its limit gets SIGTERM, which runs session-e2e.sh's
# teardown. That teardown stops the daemon and the VM, and against a wedged
# daemon it can hang too, so SIGKILL follows if the case is still running
# this long after the SIGTERM. Not exported: e2e_timeout reads it in this
# shell, and session-e2e.sh's own calls of the helper keep their behaviour.
# shellcheck disable=SC2034 # read by e2e_timeout, which is sourced below
E2E_TIMEOUT_KILL_AFTER=60
# e2e_timeout: a host-side timeout that also works with no GNU timeout on
# PATH, as on a stock Mac.
# shellcheck disable=SC1091
source "$ROOT/scripts/e2e-host-timeout.sh"

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
  iter_ok=1
  if [ -z "$CASES" ]; then
    MINVMD_BOOT_LOG="$LOGDIR/boot-$i.log" "$ROOT/scripts/session-e2e.sh" || iter_ok=0
  else
    first=1
    for c in $CASES; do
      # The iteration's own reap above already cleared the first case's way.
      [ "$first" -eq 1 ] || reap
      first=0
      rc=0
      MINVMD_BOOT_LOG="$LOGDIR/boot-$i-$c.log" \
        e2e_timeout "$CASE_TIMEOUT" "$ROOT/scripts/session-e2e.sh" "$c" || rc=$?
      if [ "$rc" -eq 124 ]; then
        iter_ok=0
        echo "::warning::soak iteration $i: case $c did not finish within ${CASE_TIMEOUT}s and was stopped (boot log: boot-$i-$c.log)"
      elif [ "$rc" -ne 0 ]; then
        iter_ok=0
        echo "::warning::soak iteration $i: case $c FAILED"
      fi
    done
  fi
  if [ "$iter_ok" -eq 1 ]; then
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
