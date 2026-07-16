#!/usr/bin/env bash
# Daemon lifecycle proof: `minvmd config set` → `run --detach` →
# `status` (Running) → `stop` → `status` (Stopped, documented non-zero
# exit). Exercises the supervised daemon path that the boot/session e2e
# harnesses do not cover.
#
# Also proves the #747 resource surface end-to-end against a real VM:
# a persisted `config set --ram-mib` is consumed at boot (the running VM
# reports that RAM, R2.5/R2.6), and `status --json` on a live VM carries
# host-visible resource metrics (R9.1) and a warnings array (R9.9) — none
# of which a unit test can exercise, since they need a booted VMM process.
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
  # Drop the resource config this proof persisted so it cannot alter the
  # session-e2e boot that runs next on the same default state dir.
  rm -f "${XDG_STATE_HOME:-$HOME/.local/state}/minimal/providers/local-0/config.toml"
  rm -rf "$WORK"
}
trap teardown EXIT

# Persist a resource config BEFORE boot so the running VM demonstrably
# consumes it (R2.3/R2.4/R2.5). 3072 MiB differs from the x86_64 default
# (2048) and is MMIO-hole-safe (<=3072), so `status` reporting 3072 while
# running is unambiguous proof the persisted config reached the VMM child at
# boot rather than an env override or the default.
echo "::group::config set + show (persist ram_mib for next boot)"
minvmd config set --ram-mib 3072
minvmd config show --json > "$WORK/config.json"
cat "$WORK/config.json"
jq -e '.ram_mib == 3072 and .ram_mib_source == "config"' "$WORK/config.json"
echo "::endgroup::"

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

echo "::group::resource metrics + config consumed at boot (#747)"
# The running VM must report (a) the ram it actually booted with — the 3072
# persisted above, not the 2048 default (R2.5/R2.6); (b) live host-visible
# metrics (R9.1); and (c) a warnings array (R9.9). cpu_percent and the disk
# byte counters may legitimately be 0 on an idle VM, so assert they are
# numeric rather than positive; a live VMM process always has resident_bytes
# > 0.
jq -e '
  .ram_mib == 3072
  and (.vcpus | type) == "number"
  and (.metrics | type) == "object"
  and (.metrics.cpu_percent | type) == "number"
  and (.metrics.resident_bytes | type) == "number"
  and .metrics.resident_bytes > 0
  and (.metrics.disk_read_bytes | type) == "number"
  and (.metrics.disk_written_bytes | type) == "number"
  and (.warnings | type) == "array"
' "$WORK/status.json"
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
