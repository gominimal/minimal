#!/usr/bin/env bash
# Kill leftover microVM host processes a failed or killed session can strand:
# minvmd, its detached __krun-vmm grandchild, and the gvproxy switch. Any of
# them wedges the next VM's host->guest vsock bridge (the leftover-wedge
# class). Best-effort, and sudo because a relay leftover can be root-owned.
# `sudo -n` keeps it non-interactive: without passwordless sudo it fails fast
# instead of blocking on a password prompt in CI. The proper fix is
# harness-side process-group reaping, tracked separately.
#
# Usage: scripts/reap-vms.sh
set -u
sudo -n pkill -x minvmd 2>/dev/null || true
sudo -n pkill -f __krun-vmm 2>/dev/null || true
sudo -n pkill -f gvproxy 2>/dev/null || true
