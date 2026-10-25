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
# Usage: scripts/reap-vms.sh [--vm <NAME>] [--root <DIR>]
#
# --root <DIR> matches binaries under DIR instead of this checkout. CI's macOS
# e2e runs a prebuilt testbed and fetched gvproxy from $RUNNER_TEMP, outside
# the checkout, and the runner persists across jobs (#2456).
#
# Without --vm, every VM this checkout spawned is reaped: the default VM's and
# each named VM's processes alike. With --vm <NAME>, only that named VM's
# processes are matched: every minvmd re-exec of a named VM carries
# `--vm <NAME>` on its cmdline (the detached supervisor and its __krun-vmm
# child), and the VM's gvproxy switch carries the per-name socket directory in
# its argv (`.../local-minvmd0/<NAME>/gvproxy-switch.sock`). Other VMs of this
# checkout — and every other checkout's VMs — keep running.
#
# `--vm default` is the bare invocation, not a name search: the default VM's
# processes carry no `--vm` flag (minvmd and autospawn omit it for the default
# name) and its switch socket sits in no per-name subdirectory, so the
# name-pinned patterns would match nothing and the script would exit 0 having
# reaped no VM at all.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

usage() {
  echo "usage: $0 [--vm <NAME>] [--root <DIR>]" >&2
  exit 2
}

# The VM to reap by name, or empty for "every VM this checkout spawned".
VM=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --vm | --root)
      if [ "$#" -lt 2 ] || [ -z "$2" ]; then
        usage
      fi
      if [ "$1" = "--vm" ]; then
        VM="$2"
      else
        # Every trailing slash goes, so `//` is refused as `/` is.
        ROOT="$2"
        while [ "${ROOT%/}" != "$ROOT" ]; do ROOT="${ROOT%/}"; done
      fi
      shift 2
      ;;
    *)
      usage
      ;;
  esac
done
# `--root /` (or `//`) strips to nothing, and an empty root would match every minvmd and
# gvproxy on the machine, under sudo too.
if [ -z "$ROOT" ]; then
  echo "$0: --root must name a directory other than /" >&2
  exit 2
fi

# `default` (paths::DEFAULT_VM_NAME) is the default VM, not a name to pin: its
# processes carry no `--vm` flag and its switch socket sits in no per-name
# subdirectory, so the name-pinned patterns would reap nothing. Clearing the
# name makes the invocation the bare one, which does reap the default VM.
if [ "$VM" = "default" ]; then
  VM=""
fi

# Quote ERE metacharacters so a VM name matches literally in `pkill -f`.
ere_quote() {
  printf '%s' "$1" | sed -e 's/[][\\.*^+|(){}?$]/\\&/g'
}

# The root as a literal in the patterns below: a path can carry `.` or `+`.
ROOT_RE="$(ere_quote "$ROOT")"

# The `pkill -f` pattern for this checkout's minvmd processes (the supervisor
# and its __krun-vmm child), pinned to one named VM when asked for. Matching
# rides the absolute checkout path, never a bare name.
minvmd_pat() {
  local pat
  pat="$ROOT_RE/.*minvmd"
  if [ -n "$VM" ]; then
    pat="$pat.*--vm[= ]$(ere_quote "$VM")( |$)"
  fi
  printf '%s' "$pat"
}

# The `pkill -f` pattern for this checkout's gvproxy switches. A named VM's
# switch is the one whose argv carries that VM's per-name socket directory.
# `gvproxy` must sit in the executable's own path, the first word of the
# cmdline, so the pattern is anchored at its start: `pkill -f` matches
# anywhere, and a `bep serve` of this checkout names gvproxy only in its
# listener's path, which can sit under the checkout too. gvproxy is spawned
# from its full path, so its cmdline starts with it.
gvproxy_pat() {
  if [ -n "$VM" ]; then
    printf '^%s/[^ ]*gvproxy.*local-minvmd[0-9]+/%s/' "$ROOT_RE" "$(ere_quote "$VM")"
  else
    printf '^%s/[^ ]*gvproxy' "$ROOT_RE"
  fi
}

# SIGKILL, because a VM in `krun_start_enter` ignores SIGTERM: a plain pkill
# leaves exactly the leftover this script exists to remove.
# User-owned leftovers first — this must not depend on sudo succeeding.
pkill -9 -f "$(minvmd_pat)" 2>/dev/null || true
pkill -9 -f "$(gvproxy_pat)" 2>/dev/null || true
# Root-owned relay leftovers need sudo; -n fails fast without passwordless sudo.
sudo -n pkill -9 -f "$(minvmd_pat)" 2>/dev/null || true
sudo -n pkill -9 -f "$(gvproxy_pat)" 2>/dev/null || true
