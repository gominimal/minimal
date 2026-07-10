#!/usr/bin/env bash
# Soak harness: run the unified session e2e (scripts/session-e2e.sh) N times
# back-to-back against a VM-backed target, reaping leftover VM processes
# between iterations, to shake out the boot / first-connect raciness (the
# vsock-bridge wedge class) that a single PR-lane run cannot surface. Reports
# a pass/fail tally and exits non-zero if ANY iteration failed.
#
# The caller sets the VM up exactly as the KVM lane does — minvmd + minimal
# on PATH, MINVMD_KERNEL_PATH / MINVMD_ROOTFS_PATH / MINVMD_INITRAMFS set,
# libkrun on the loader path — and passes the VM knobs through the
# environment (E2E_VM=1 E2E_MINIMAL_ARGS=--minvmd E2E_PROJECT_DIR=/tmp),
# same as the lane invocation. Each iteration runs session-e2e.sh, which
# creates its own fresh XDG state, so every pass is a clean cold start.
#
# Usage: scripts/soak-session-e2e.sh [iterations] [boot-log-dir]
set -uo pipefail

ITER="${1:-10}"
LOGDIR="${2:-$(mktemp -d /tmp/mnl-soak.XXXXXX)}"
mkdir -p "$LOGDIR"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Reap leftovers a failed boot may strand (Guest::drop kills only its own
# minvmd; the detached __krun-vmm grandchild and the gvproxy switch can
# linger and wedge the next iteration's bridge). sudo: relay leftovers can
# be root-owned.
reap() {
  sudo pkill -x minvmd 2>/dev/null || true
  sudo pkill -f __krun-vmm 2>/dev/null || true
  sudo pkill -f gvproxy 2>/dev/null || true
}

pass=0
fail=0
for i in $(seq 1 "$ITER"); do
  echo "::group::soak iteration $i/$ITER"
  reap
  if MINVMD_BOOT_LOG="$LOGDIR/boot-$i.log" "$ROOT/scripts/session-e2e.sh"; then
    pass=$((pass + 1))
    echo "iteration $i: OK"
  else
    fail=$((fail + 1))
    echo "::warning::soak iteration $i FAILED"
  fi
  echo "::endgroup::"
done
reap

echo "soak complete: $pass passed, $fail failed (of $ITER)"
[ "$fail" -eq 0 ]
