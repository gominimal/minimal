#!/bin/bash
# Measure minvmd boot-to-READY latency, host-observed.
#
# Times `minvmd boot` (non-foreground: returns once the guest writes its READY
# marker, leaving the VM up) across N runs, tearing the VM down between runs, and
# reports min/median/max in milliseconds. This is the harness used to find that
# the gzip kernel decompress was ~77 ms of a ~146 ms boot (fixed by shipping the
# kernel uncompressed + KRUN_KERNEL_FORMAT_RAW → ~67 ms).
#
# macOS-only (minvmd boots a libkrun microVM via Hypervisor.framework). The
# minvmd binary must be codesigned with the hypervisor entitlement first:
#   cargo build -p minvmd --bin minvmd
#   codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/debug/minvmd
#
# Usage:
#   MINVMD_KERNEL_PATH=... MINVMD_ROOTFS_PATH=... scripts/bench-minvmd-boot.sh [N] [minvmd-binary]
set -uo pipefail

N="${1:-10}"
BIN="${2:-./target/debug/minvmd}"

: "${MINVMD_KERNEL_PATH:?set MINVMD_KERNEL_PATH to the (uncompressed) kernel image}"
: "${MINVMD_ROOTFS_PATH:?set MINVMD_ROOTFS_PATH to the rootfs ext4 image}"
[ -x "$BIN" ] || { echo "minvmd binary not found/executable: $BIN" >&2; exit 1; }
command -v perl >/dev/null || { echo "perl required for sub-ms timing" >&2; exit 1; }

now_ms() { perl -MTime::HiRes=time -e 'printf "%d", time()*1000'; }
teardown() { pkill -f "__krun-vmm" 2>/dev/null; sleep 0.5; }

trap teardown EXIT

# Warmup (page-cache the kernel/rootfs; first boot is cold).
teardown
timeout 20 "$BIN" boot >/dev/null 2>&1
teardown

samples=()
for _ in $(seq 1 "$N"); do
  t0="$(now_ms)"
  if timeout 20 "$BIN" boot >/tmp/.bench-minvmd.out 2>/dev/null && grep -q vm-up /tmp/.bench-minvmd.out; then
    t1="$(now_ms)"
    samples+=( "$(( t1 - t0 ))" )
  else
    echo "warning: a boot did not reach vm-up" >&2
  fi
  teardown
done

[ "${#samples[@]}" -gt 0 ] || { echo "no successful boots" >&2; exit 1; }

sorted=($(printf '%s\n' "${samples[@]}" | sort -n))
c="${#sorted[@]}"
printf 'boot-to-READY (ms): min=%d median=%d max=%d  (n=%d)\n' \
  "${sorted[0]}" "${sorted[$((c / 2))]}" "${sorted[$((c - 1))]}" "$c"
printf 'samples: %s\n' "${samples[*]}"
