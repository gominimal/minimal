#!/usr/bin/env bash
# Kill leftover microVM host processes a failed or killed session can strand:
# minvmd, its detached __krun-vmm grandchild, the gvproxy switch, and the box
# egress proxy minvmd supervises beside it. Any of them wedges the next VM —
# the first three the host->guest vsock bridge (the leftover-wedge class), the
# proxy its redemption listener, whose fixed port the next boot's proxy cannot
# bind while a leftover holds it.
# Best-effort, and sudo because a relay leftover can be root-owned.
# `sudo -n` keeps it non-interactive: without passwordless sudo it fails fast
# instead of blocking on a password prompt in CI. The proper fix is
# harness-side process-group reaping, tracked separately.
#
# Matching is scoped to THIS checkout's binaries: the persistent leftovers all
# carry the absolute repo path in their cmdline (minvmd's supervisor and
# __krun-vmm re-exec via current_exe(); gvproxy is spawned from the full
# MINVMD_GVPROXY_BIN path, the proxy from the full MINVMD_BEP_BIN path), so a
# bare-name pkill would only add collateral — an unrelated checkout's live VM,
# or podman's gvproxy.
#
# The proxy pattern ends the binary name at a space or end-of-cmdline because
# `bep` is a prefix of this checkout's own test binaries
# (`target/debug/deps/bep-<hash>`), which a looser pattern would reap mid-run.
#
# Usage: scripts/reap-vms.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# User-owned leftovers first — this must not depend on sudo succeeding.
pkill -f "$ROOT/.*minvmd" 2>/dev/null || true
pkill -f "$ROOT/.*gvproxy" 2>/dev/null || true
pkill -f "$ROOT/.*/bep( |\$)" 2>/dev/null || true
# Root-owned relay leftovers need sudo; -n fails fast without passwordless sudo.
sudo -n pkill -f "$ROOT/.*minvmd" 2>/dev/null || true
sudo -n pkill -f "$ROOT/.*gvproxy" 2>/dev/null || true
sudo -n pkill -f "$ROOT/.*/bep( |\$)" 2>/dev/null || true
