#!/usr/bin/env bash
# Kill leftover microVM host processes a failed or killed session can strand:
# minvmd, its detached __krun-vmm grandchild, and the gvproxy switch. Any of
# them wedges the next VM's host->guest vsock bridge (the leftover-wedge
# class). Best-effort, and sudo because a relay leftover can be root-owned.
# `sudo -n` keeps it non-interactive: without passwordless sudo it fails fast
# instead of blocking on a password prompt in CI. The proper fix is
# harness-side process-group reaping, tracked separately.
#
# Matching is scoped to THIS checkout's binaries: the persistent leftovers all
# carry the absolute repo path in their cmdline (minvmd's supervisor and
# __krun-vmm re-exec via current_exe(); gvproxy is spawned from the full
# MINVMD_GVPROXY_BIN path), so a bare-name pkill would only add collateral —
# an unrelated checkout's live VM, or podman's gvproxy.
#
# Usage: scripts/reap-vms.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
sudo -n pkill -f "$ROOT/.*minvmd" 2>/dev/null || true
sudo -n pkill -f "$ROOT/.*gvproxy" 2>/dev/null || true
