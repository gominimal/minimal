#!/bin/bash
# Measure minvmd boot-to-READY latency, host-observed.
#
# Times `minvmd boot` (non-foreground: returns once the guest writes its READY
# marker, leaving the VM up) across N runs, tearing the VM down between runs, and
# reports min/median/max in milliseconds. This is the harness used to find that
# the gzip kernel decompress was ~77 ms of a ~146 ms boot (fixed by shipping the
# kernel uncompressed + KRUN_KERNEL_FORMAT_RAW → ~67 ms).
#
# Runs on macOS (Hypervisor.framework) and Linux (KVM) — minvmd abstracts the
# backend via libkrun. The script body is portable (perl/pkill/timeout/sort).
#
# macOS only: the minvmd binary must be codesigned with the hypervisor
# entitlement before it can boot a VM:
#   cargo build -p minvmd --bin minvmd
#   codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/debug/minvmd
# Linux needs no codesigning — KVM access is governed by /dev/kvm permissions.
#
# Usage:
#   MINVMD_KERNEL_PATH=... MINVMD_ROOTFS_PATH=... MINVMD_INITRAMFS=... \
#     scripts/bench-minvmd-boot.sh [N] [minvmd-binary]
# All three artifact paths are required (minvmd boot needs kernel + rootfs +
# initramfs).
set -uo pipefail

N="${1:-10}"
BIN="${2:-./target/debug/minvmd}"

: "${MINVMD_KERNEL_PATH:?set MINVMD_KERNEL_PATH to the (uncompressed) kernel image}"
: "${MINVMD_ROOTFS_PATH:?set MINVMD_ROOTFS_PATH to the rootfs ext4 image}"
: "${MINVMD_INITRAMFS:?set MINVMD_INITRAMFS to the guest initramfs cpio (minvmd boot needs all three)}"
for v in MINVMD_KERNEL_PATH MINVMD_ROOTFS_PATH MINVMD_INITRAMFS; do
  [ -f "${!v}" ] || { echo "$v points at a missing file: ${!v}" >&2; exit 1; }
done
[ -x "$BIN" ] || { echo "minvmd binary not found/executable: $BIN" >&2; exit 1; }
# Absolute path for the teardown pattern (see `teardown` below): the running
# processes carry it, and it is what keeps a sibling checkout's VM out of range.
BIN_ABS="$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")"
command -v perl >/dev/null || { echo "perl required for sub-ms timing" >&2; exit 1; }
# GNU coreutils ships `timeout`, but Homebrew installs it as `gtimeout` unless
# the gnubin dir is on PATH — accept either so the macOS path works out of box.
if command -v timeout >/dev/null; then
  TIMEOUT=timeout
elif command -v gtimeout >/dev/null; then
  TIMEOUT=gtimeout
else
  echo "timeout/gtimeout required (install GNU coreutils)" >&2; exit 1
fi

# A healthy boot reaches READY in well under a second; cap each attempt so a
# broken setup fails fast instead of looking hung for minutes.
#
# Boot invocations below redirect stdin from /dev/null: GNU timeout runs the
# command in its own (background) process group, and with a TTY on stdin and
# MINVMD_BOOT_LOG unset, libkrun's console setup tcsetattr()s the terminal —
# SIGTTOU then stops the whole group and the boot dies silently at the timeout.
BOOT_TIMEOUT=12
OUT="$(mktemp -t bench-minvmd.XXXXXX)"
# Parent for the per-run state dirs (see boot_once). A SHORT /tmp template, not
# `mktemp -d -t`: on macOS that honours TMPDIR and yields a ~50-byte
# /var/folders/... path, and the daemon socket beneath it
# (`providers/local-minvmd0/ssh.sock`) then blows the 103-byte sun_path limit,
# so every boot dies before it starts. Matches scripts/session-e2e.sh.
SCRATCH="$(mktemp -d /tmp/mnvb.XXXXXX)"

now_ms() { perl -MTime::HiRes=time -e 'printf "%d", time()*1000'; }
# SIGKILL, not TERM: a VM in krun_start_enter ignores SIGTERM, so a leaked
# __krun-vmm (e.g. from a Ctrl-C'd foreground boot) would otherwise hold the
# bridge socket and make every subsequent boot fail.
#
# Matching is scoped to THIS checkout, the same discipline scripts/reap-vms.sh
# documents: a bare `-f "__krun-vmm"` matches EVERY checkout's VM, so running
# this bench beside a parallel working copy would SIGKILL that copy's live dev
# stack — sessions and all — between every run. Both the supervisor and the
# __krun-vmm grandchild re-exec via current_exe(), so both carry the binary's
# absolute path in their cmdline. Resolved to an absolute path because $BIN is
# conventionally passed relative (`./target/debug/minvmd`), which would match
# nothing here.
teardown() { pkill -9 -f "$BIN_ABS" 2>/dev/null; sleep 0.3; }

# Tear down on normal exit AND on Ctrl-C / kill, so an interrupt never leaves a
# detached VM running (and the run stops promptly instead of deferring).
trap 'teardown; rm -f "$OUT"; rm -rf "$SCRATCH"' EXIT
trap 'echo; echo "interrupted — tearing down" >&2; teardown; exit 130' INT TERM

# One boot into a FRESH state dir; 0 iff the guest reached READY.
#
# Fresh per run for two reasons. Correctness: teardown SIGKILLs the VM, which
# leaves the bound `ssh.sock` behind, and libkrun registers that path with
# listen=true on the next boot — it then hangs in krun_start_enter until the
# timeout, so every run after the first silently FAILED. Fidelity: this is a
# COLD-boot benchmark, and a reused state dir carries the previous run's data
# volume, which is not the state a cold boot starts from.
#
# It also isolates the bench from any other checkout: minvmd refuses to boot
# when the DEFAULT state dir already has a VM registered, and that dir is shared
# across checkouts even though the binaries are not — so a sibling dev stack
# alone was enough to make every run fail with "minvmd is already running".
boot_once() {
  local sd="$SCRATCH/run$1"
  mkdir -p "$sd"
  "$TIMEOUT" "$BOOT_TIMEOUT" "$BIN" --minimal-state-dir "$sd" boot </dev/null >"$OUT" 2>&1
  grep -qx vm-up "$OUT"
}

# Warmup (page-cache the kernel/rootfs; the first boot is cold). Fail loudly here
# if the artifacts/codesign are wrong, rather than silently N times below.
echo "warming up (cold boot, discarded)…" >&2
teardown
if ! boot_once warmup; then
  echo "warmup boot did not reach vm-up — check artifacts, codesign, and libkrun:" >&2
  tail -6 "$OUT" >&2
  exit 1
fi
teardown

samples=()
for i in $(seq 1 "$N"); do
  t0="$(now_ms)"
  if boot_once "$i"; then
    t1="$(now_ms)"; ms="$(( t1 - t0 ))"; samples+=( "$ms" )
    printf 'run %2d/%d: %4d ms\n' "$i" "$N" "$ms" >&2
  else
    printf 'run %2d/%d: FAILED (no vm-up)\n' "$i" "$N" >&2
  fi
  teardown
done

[ "${#samples[@]}" -gt 0 ] || { echo "no successful boots" >&2; exit 1; }

sorted=()
while IFS= read -r line; do sorted+=("$line"); done < <(printf '%s\n' "${samples[@]}" | sort -n)
c="${#sorted[@]}"
printf 'boot-to-READY (ms): min=%d median=%d max=%d  (n=%d)\n' \
  "${sorted[0]}" "${sorted[$((c / 2))]}" "${sorted[$((c - 1))]}" "$c"
printf 'samples: %s\n' "${samples[*]}"
