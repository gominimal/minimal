#!/usr/bin/env bash
# Kill leftover microVM host processes a failed or killed session can strand:
# minvmd, its detached __krun-vmm grandchild, the gvproxy switch, and the
# credential broker. Any of them wedges the next run — the first three the
# host->guest vsock bridge (the leftover-wedge class), the broker the loopback
# port and control socket the next broker binds.
# Best-effort, and sudo because a relay leftover can be root-owned.
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
# User-owned leftovers first — this must not depend on sudo succeeding.
pkill -f "$ROOT/.*minvmd" 2>/dev/null || true
pkill -f "$ROOT/.*gvproxy" 2>/dev/null || true
# The broker is a subcommand of a daemon that also serves sessions, so this row
# matches the `broker` argv and not the binary name: `minimald` alone would take
# down this checkout's live session daemon too. (`minvmd broker` is already
# covered by the minvmd row above, which reaps that daemon wholesale.)
pkill -f "$ROOT/.*minimald broker" 2>/dev/null || true
# Root-owned relay leftovers need sudo; -n fails fast without passwordless sudo.
sudo -n pkill -f "$ROOT/.*minvmd" 2>/dev/null || true
sudo -n pkill -f "$ROOT/.*gvproxy" 2>/dev/null || true
sudo -n pkill -f "$ROOT/.*minimald broker" 2>/dev/null || true
