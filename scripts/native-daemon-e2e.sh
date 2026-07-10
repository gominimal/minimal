#!/usr/bin/env bash
# Native minimald daemon end-to-end (DM2: no VM). Drives the real user path
# on a Linux host: `minimal activate` must auto-spawn the NATIVE minimald
# (`minimald run --detach`), create a session for the project, exec a command
# in it over the daemon's SSH surface, list/destroy the session, and shut the
# daemon down — asserting exit codes and output, never internals.
#
# Mirrors the macOS autospawn e2e's shape (fresh state, cold-start proof,
# diagnostics dump on failure) for the Linux-native lane. Timing is reported
# but NOT asserted: session creation materializes the project's stack from
# the package cache, whose cost belongs to the cache, not this proof.
#
# Requirements:
#   - Linux host with unprivileged user namespaces enabled
#     (kernel.apparmor_restrict_unprivileged_userns=0 on Ubuntu 24.04+)
#   - `minimal` and `minimald` on PATH (built from this repo)
#   - `ssh` on PATH (attach shells out to it; ProxyCommand uses
#     `minimal proxy`, so no socat/nc needed)
#
# Environment:
#   E2E_PROJECT_DIR     project to activate (default: repo root — its
#                       .minimal/minimal.toml is the known-good fixture)
#   E2E_ACTIVATE_ARGS   extra args for `minimal activate` (e.g. a future
#                       `--loadout dev` once the loadouts CLI lands, #686)
#
# Usage: scripts/native-daemon-e2e.sh
set -uo pipefail # not -e: capture failures so we can dump diagnostics

case "$(uname -s)" in
  Linux) ;;
  *) echo "native-daemon-e2e.sh is Linux-only (got $(uname -s))" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PROJECT_DIR="${E2E_PROJECT_DIR:-$ROOT}"
WORK="$(mktemp -d)"

# Fresh runtime + state dirs guarantee the clean (no-daemon) starting state:
# the socket lives under XDG_RUNTIME_DIR and minimald's state under
# XDG_STATE_HOME (honored on Linux). XDG_CACHE_HOME is deliberately left
# alone so package pulls reuse the host/CI cache across runs.
export XDG_RUNTIME_DIR="$WORK/runtime"
export XDG_STATE_HOME="$WORK/state"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME"
chmod 700 "$XDG_RUNTIME_DIR"

# The CLI's tracing layer writes to STDOUT (ot::StdoutWriter, minimal/src/
# main.rs), so at the default level the autospawn INFO lines interleave with
# the session id `activate` prints for piping. Quiet the logs; the last-line
# extraction below stays defensive in case a level sneaks through.
export RUST_LOG="${RUST_LOG:-warn}"

now_ms() { date +%s%3N; }

# On any failure, dump what the detached daemon hides — the CLI's own
# stderr, the daemon's state/log files, and the session list — then stop
# the daemon and fail.
fail() {
  echo "::group::native-daemon-e2e diagnostics"
  echo "--- activate stderr ---"; cat "$WORK/activate.err" 2>/dev/null || true
  echo "--- attach stderr ---"; cat "$WORK/attach.err" 2>/dev/null || true
  echo "--- minimal ls ---"; minimal ls 2>&1 || true
  echo "--- state dir ---"; find "$XDG_STATE_HOME" -type f 2>/dev/null | head -50
  find "$XDG_STATE_HOME" -type f \( -name '*.log' -o -name '*.toml' -o -name '*.json' \) 2>/dev/null \
    | while read -r f; do echo "--- $f (tail) ---"; tail -40 "$f"; done
  echo "::endgroup::"
  minimal stop --force >/dev/null 2>&1 || true
  exit 1
}
trap 'minimal stop --force >/dev/null 2>&1 || true' EXIT

# Cold: `minimal activate` must auto-spawn the native minimald and print the
# new session id on stdout. Word-splitting of E2E_ACTIVATE_ARGS is intended.
# The id is the LAST stdout line (any log lines that slip through the RUST_LOG
# filter precede it), validated as a UUID before use.
echo "::group::cold activate (auto-spawns native minimald)"
t0=$(now_ms)
# shellcheck disable=SC2086
activate_out="$(cd "$PROJECT_DIR" && minimal activate . ${E2E_ACTIVATE_ARGS:-} 2>"$WORK/activate.err")" \
  || { echo "::error::cold 'minimal activate' failed to auto-spawn minimald / create a session"; fail; }
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
minimal ls --raw 2>/dev/null | grep -Fqx "$sid" \
  || { echo "::error::'minimal ls --raw' does not list new session $sid"; fail; }

# Exec a command in the session (non-interactive attach) and assert its
# stdout and exit status — the full CLI -> UDS -> daemon -> sandbox path.
echo "::group::exec in session"
marker="native-e2e-$$"
out="$(minimal attach "$sid" --command "echo $marker && uname -s" 2>"$WORK/attach.err")" \
  || { echo "::error::'minimal attach --command' exited non-zero"; fail; }
echo "$out"
case "$out" in
  *"$marker"*) ;;
  *) echo "::error::session exec output missing marker '$marker'"; fail ;;
esac
case "$out" in
  *Linux*) ;;
  *) echo "::error::session exec output missing 'Linux' (uname -s inside the sandbox)"; fail ;;
esac
echo "::endgroup::"

# Warm: the daemon is up; a second CLI call must succeed without respawning.
t0=$(now_ms)
minimal ls >/dev/null 2>&1 || { echo "::error::warm 'minimal ls' failed"; fail; }
t1=$(now_ms)
echo "warm 'minimal ls': $((t1 - t0))ms"

# Destroy the session; it must drop out of the listing.
minimal destroy "$sid" >/dev/null 2>&1 \
  || { echo "::error::'minimal destroy $sid' failed"; fail; }
if minimal ls --raw 2>/dev/null | grep -Fqx "$sid"; then
  echo "::error::session $sid still listed after destroy"; fail
fi

# Shut the daemon down; it must not survive.
minimal stop >/dev/null 2>&1 || { echo "::error::'minimal stop' failed"; fail; }

echo "native daemon e2e OK"
