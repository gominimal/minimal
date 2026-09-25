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
# Usage: scripts/reap-vms.sh [--vm <NAME>]
#
# Without --vm, every VM this checkout spawned is reaped: the default VM's and
# each named VM's processes alike. With --vm <NAME>, only that named VM's
# processes are matched: every minvmd re-exec of a named VM carries
# `--vm <NAME>` on its cmdline (the detached supervisor and its __krun-vmm
# child), and the VM's gvproxy switch carries the per-name socket directory in
# its argv (`.../local-minvmd0/<NAME>/gvproxy-switch.sock`). Other VMs of this
# checkout — and every other checkout's VMs — keep running.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# The VM to reap by name, or empty for "every VM this checkout spawned".
VM=""
if [ "${1:-}" = "--vm" ]; then
  if [ "$#" -lt 2 ] || [ -z "$2" ]; then
    echo "usage: $0 [--vm <NAME>]" >&2
    exit 2
  fi
  VM="$2"
  shift 2
fi
if [ "$#" -gt 0 ]; then
  echo "usage: $0 [--vm <NAME>]" >&2
  exit 2
fi

# Quote ERE metacharacters so a VM name matches literally in `pkill -f`.
ere_quote() {
  printf '%s' "$1" | sed -e 's/[][\\.*^+|(){}?$]/\\&/g'
}

# The `pkill -f` pattern for this checkout's minvmd processes (the supervisor
# and its __krun-vmm child), pinned to one named VM when asked for. Matching
# rides the absolute checkout path, never a bare name.
minvmd_pat() {
  local pat
  pat="$ROOT/.*minvmd"
  if [ -n "$VM" ]; then
    pat="$pat.*--vm[= ]$(ere_quote "$VM")( |$)"
  fi
  printf '%s' "$pat"
}

# The `pkill -f` pattern for this checkout's gvproxy switches. A named VM's
# switch is the one whose argv carries that VM's per-name socket directory.
gvproxy_pat() {
  if [ -n "$VM" ]; then
    printf '%s/.*gvproxy.*local-minvmd[0-9]+/%s/' "$ROOT" "$(ere_quote "$VM")"
  else
    printf '%s/.*gvproxy' "$ROOT"
  fi
}

# User-owned leftovers first — this must not depend on sudo succeeding.
pkill -f "$(minvmd_pat)" 2>/dev/null || true
pkill -f "$(gvproxy_pat)" 2>/dev/null || true
# Root-owned relay leftovers need sudo; -n fails fast without passwordless sudo.
sudo -n pkill -f "$(minvmd_pat)" 2>/dev/null || true
sudo -n pkill -f "$(gvproxy_pat)" 2>/dev/null || true
