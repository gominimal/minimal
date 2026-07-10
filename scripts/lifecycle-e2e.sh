#!/usr/bin/env bash
# Daemon lifecycle proof: `minvmd run --detach` → `status` (Running) →
# `stop` → `status` (Stopped, documented non-zero exit). Exercises the
# supervised daemon path that the boot/session e2e
# harnesses do not cover.
#
# Target-agnostic: resolves `minvmd` from PATH (no cargo), so the same proof
# runs on the Linux/KVM lane today and a macOS testbed later. Requires jq,
# plus the usual VM env from the caller:
#   MINVMD_KERNEL_PATH / MINVMD_ROOTFS_PATH / MINVMD_INITRAMFS
#   MINVMD_BOOT_LOG (optional) guest console capture
#
# Usage: scripts/lifecycle-e2e.sh
set -euo pipefail

command -v minvmd >/dev/null || { echo "::error::minvmd not on PATH"; exit 1; }
command -v jq >/dev/null || { echo "::error::jq is required"; exit 1; }

# Scratch dir for status captures; EXIT-trap teardown so a failed assert
# can't strand a running daemon on the runner.
WORK="$(mktemp -d /tmp/mnl-lifecycle.XXXXXX)"
teardown() {
  minvmd stop >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap teardown EXIT

echo "::group::run --detach"
minvmd run --detach --timeout 30
echo "::endgroup::"

echo "::group::status (expect running)"
# `run --detach` returns once the host UDS accepts connections, which
# libkrun opens early in VM setup — slightly ahead of the supervisor's
# Starting->Running transition (set after the guest READY marker). Poll
# status (up to ~15s) for Running rather than asserting immediately. jq
# parses structurally so the check doesn't break on harmless JSON
# formatting changes.
for _ in $(seq 1 75); do
  minvmd status --json > "$WORK/status.json" || true
  if jq -e '.state == "running" and (.vmm_pid | type == "number")' "$WORK/status.json" >/dev/null; then
    break
  fi
  sleep 0.2
done
cat "$WORK/status.json"
minvmd status # exit 0 == Running
jq -e '.state == "running" and (.vmm_pid | type == "number")' "$WORK/status.json"
echo "::endgroup::"

echo "::group::stop"
minvmd stop
echo "::endgroup::"

echo "::group::status (expect stopped)"
# `status`/`status --json` exit 1 when stopped (documented), so capture
# without tripping set -e / pipefail, then assert structurally.
minvmd status --json > "$WORK/status-after.json" || true
cat "$WORK/status-after.json"
jq -e '.state == "stopped"' "$WORK/status-after.json"
# Also confirm the documented non-zero exit for the stopped state.
if minvmd status; then echo "::error::expected non-zero status exit after stop"; exit 1; fi
echo "::endgroup::"

echo "daemon lifecycle OK"
