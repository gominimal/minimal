#!/usr/bin/env bash
# The ONE session e2e, invoked by every target lane. Drives the real user
# path through the `min` CLI — which abstracts where the daemon lives —
# so the identical proof runs against all three deployment targets:
#
#   Linux native (DM2)   minimald on the host          (no extra env)
#   Linux KVM    (DM3)   minimald in a minvmd microVM  E2E_VM=1 E2E_MINIMAL_ARGS=--minvmd
#   macOS HVF    (DM1)   minimald in a minvmd microVM  E2E_VM=1 (macOS is always VM-backed)
# (DM numbers are the deployment models in docs/specs/03-spec-networking.)
#
# Flow: from a guaranteed-clean state, `min activate` must auto-spawn the
# target's daemon and create a session; then list, warm-call, destroy
# (verified delisted), and a clean `min stop`. Timing is reported but NOT
# asserted.
#
# In-session exec over the daemon's SSH surface is NOT exercised here: only
# `min run <task>` is accepted (arbitrary exec was removed), and a task needs
# a `minimal.toml` in the otherwise-empty session workspace — which this shell
# harness cannot seed on the VM lanes (the workspace lives inside the guest).
# That path is proven in Rust instead: `exec::tests::end_to_end::exec_runs_echo_task`
# (host daemon) and `minimald_exec_over_bridge` (over the libkrun bridge).
#
# VM targets (E2E_VM=1) additionally need, from the caller:
#   - a codesigned/linkable `minvmd` on PATH (min spawns it by name)
#   - MINVMD_KERNEL_PATH / MINVMD_ROOTFS_PATH / MINVMD_INITRAMFS
#     (propagate through the `minvmd run --detach` re-exec)
#   - MINVMD_BOOT_LOG (optional) to capture the guest console
#   The guest sees no host project dir yet (no project sync), so VM lanes
#   pass E2E_PROJECT_DIR=/tmp — a path that exists in the guest image.
#
# Environment:
#   E2E_MINIMAL_ARGS    global args for every `min` call (e.g. --minvmd)
#   E2E_PROJECT_DIR     project to activate (default: repo root)
#   E2E_ACTIVATE_ARGS   extra args for `min activate` (e.g. a future
#                       `--loadout dev` once the loadouts CLI lands, #686)
#   E2E_VM              set to 1 for VM-backed targets (extra teardown +
#                       diagnostics: minvmd stop, guest boot log)
#
# Usage: scripts/session-e2e.sh
set -uo pipefail # not -e: capture failures so we can dump diagnostics

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_DIR="${E2E_PROJECT_DIR:-$ROOT}"
E2E_VM="${E2E_VM:-}"

# Fresh state under /tmp — NOT $TMPDIR: macOS's deep $TMPDIR would push
# `.../minimal/providers/local-0/*.sock` past the 104-byte sun_path limit.
# Post-#690, all daemon state (minvmd.toml, locks, the bridge socket) lives
# under $XDG_STATE_HOME/minimal/providers/local-0 on every platform, so a
# fresh dir guarantees the clean (no-daemon) cold-start on persistent
# runners. XDG_CACHE_HOME is deliberately left alone so package pulls reuse
# the host/CI cache across runs.
WORK="$(mktemp -d /tmp/mnl-e2e.XXXXXX)"
export XDG_RUNTIME_DIR="$WORK/runtime"
export XDG_STATE_HOME="$WORK/state"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME"
chmod 700 "$XDG_RUNTIME_DIR"

# The CLI's tracing layer writes to STDOUT (ot::StdoutWriter, minimal/src/
# main.rs), so at the default level the autospawn INFO lines interleave with
# the session id `activate` prints for piping. Quiet the logs; the last-line
# extraction below stays defensive in case a level sneaks through.
export RUST_LOG="${RUST_LOG:-warn}"

# Millisecond clock: GNU date on Linux; macOS `date` has no %N, use perl.
if [ -z "$(date +%s%3N | tr -d '0-9')" ]; then
  now_ms() { date +%s%3N; }
else
  now_ms() { perl -MTime::HiRes=time -e 'printf "%d", time()*1000'; }
fi

# Every CLI call goes through this so E2E_MINIMAL_ARGS applies uniformly.
# Word-splitting of the args is intended.
mnl() {
  # shellcheck disable=SC2086
  min ${E2E_MINIMAL_ARGS:-} "$@"
}

teardown() {
  mnl stop --force >/dev/null 2>&1 || true
  if [ -n "$E2E_VM" ]; then
    minvmd stop >/dev/null 2>&1 || true
  fi
}
trap teardown EXIT

# On any failure, dump what a detached daemon hides — the CLI's own stderr,
# the daemon's state/log files (and, on VM targets, the guest boot console)
# — then stop everything and fail.
fail() {
  echo "::group::session-e2e diagnostics"
  echo "--- activate stderr ---"; cat "$WORK/activate.err" 2>/dev/null || true
  echo "--- min ls ---"; mnl ls 2>&1 || true
  echo "--- state dir ---"; find "$XDG_STATE_HOME" -type f 2>/dev/null | head -50
  find "$XDG_STATE_HOME" -type f \( -name '*.log' -o -name '*.toml' -o -name '*.json' \) 2>/dev/null \
    | while read -r f; do echo "--- $f (tail) ---"; tail -40 "$f"; done
  if [ -n "$E2E_VM" ]; then
    echo "--- guest boot console (tail) ---"
    tail -80 "${MINVMD_BOOT_LOG:-/nonexistent}" 2>/dev/null || echo "(no boot log — VM never started)"
  fi
  echo "::endgroup::"
  teardown
  exit 1
}

# Cold: `min activate` must auto-spawn the target's daemon and print the
# new session id on stdout. The id is the LAST stdout line (any log lines
# that slip through the RUST_LOG filter precede it), validated as a UUID.
echo "::group::cold activate (auto-spawns the daemon)"
t0=$(now_ms)
# shellcheck disable=SC2086
activate_out="$(cd "$PROJECT_DIR" && mnl activate . ${E2E_ACTIVATE_ARGS:-} 2>"$WORK/activate.err")" \
  || { echo "::error::cold 'min activate' failed to auto-spawn the daemon / create a session"; fail; }
t1=$(now_ms)
sid="$(printf '%s\n' "$activate_out" | tail -n1 | tr -d '\r')"
echo "session: $sid (cold activate: $((t1 - t0))ms)"
if ! printf '%s' "$sid" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
  echo "::error::activate's last stdout line is not a session UUID: '$sid'"
  echo "--- full activate stdout ---"; printf '%s\n' "$activate_out"
  fail
fi
echo "::endgroup::"

# The session must be listed.
mnl ls --raw 2>/dev/null | grep -Fqx "$sid" \
  || { echo "::error::'min ls --raw' does not list new session $sid"; fail; }

# Warm: the daemon is up; a second CLI call must succeed without respawning.
t0=$(now_ms)
mnl ls >/dev/null 2>&1 || { echo "::error::warm 'min ls' failed"; fail; }
t1=$(now_ms)
echo "warm 'min ls': $((t1 - t0))ms"

# Destroy the session; it must drop out of the listing.
mnl destroy "$sid" >/dev/null 2>&1 \
  || { echo "::error::'min destroy $sid' failed"; fail; }
if mnl ls --raw 2>/dev/null | grep -Fqx "$sid"; then
  echo "::error::session $sid still listed after destroy"; fail
fi

# Shut the daemon down; it must not survive.
mnl stop >/dev/null 2>&1 || { echo "::error::'min stop' failed"; fail; }

# On VM targets the daemon IS the guest's pid-1, so stopping it must take the
# VM down with it: the guest resets, the supervisor reaps the VMM child and
# writes Stopped. A guest that instead exits init panics the kernel, leaving the
# VM "running" behind a bridge socket nothing answers on (#730). `minvmd status`
# exits 0 when running, 1 when stopped, 2 on lock contention — so match the code
# exactly rather than treating every non-zero exit as proof of a stopped VM.
if [ -n "$E2E_VM" ]; then
  minvmd status >/dev/null 2>&1
  rc=$?
  case "$rc" in
    1) ;; # stopped: what a clean `min stop` must leave behind
    0)
      echo "::error::VM is still running after 'minimal stop' (the guest did not take it down)"
      fail
      ;;
    *)
      echo "::error::'minvmd status' failed with exit $rc (expected 0=running or 1=stopped)"
      fail
      ;;
  esac
fi

# And the daemon must come back: the next command autospawns a fresh one rather
# than hanging on (or erroring against) the one just stopped — the user-visible
# half of #730.
mnl ls >/dev/null 2>&1 \
  || { echo "::error::'minimal ls' after 'minimal stop' did not restart the daemon"; fail; }

echo "session e2e OK"
