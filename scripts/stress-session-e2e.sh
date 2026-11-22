#!/usr/bin/env bash
# Concurrency/stress proof: mint N sessions CONCURRENTLY against one daemon,
# then bulk-tear-down. Where session-e2e.sh drives one session through its full
# interactive lifecycle, this hammers the daemon's spawn/list/teardown paths
# under parallel load — the "supervision under stress" surface of
# docs/ci-strategy.md §6 that a single-session proof and an N-serial soak
# (scripts/soak-session-e2e.sh loops session-e2e.sh one-at-a-time) never touch.
#
# The N starts fire in parallel from a cold state, so the FIRST auto-spawns
# the daemon while the rest race to connect during its bring-up — deliberately
# maximizing the boot/first-connect raciness a serial run cannot surface.
#
# Uses the same lane env as session-e2e.sh (E2E_MINIMAL_ARGS / E2E_VM /
# E2E_PROJECT_DIR) so it runs against every target the same way. VM lanes
# additionally need a codesigned/linkable minvmd on PATH + the image env vars.
#
# Usage: scripts/stress-session-e2e.sh [N]   (N defaults to 5)
set -uo pipefail # not -e: capture failures so we can dump diagnostics

command -v jq >/dev/null 2>&1 \
  || { echo "::error::jq is not on PATH; the teardown check reads 'min box list -o json' with it" >&2; exit 2; }

N="${1:-5}"
case "$N" in
  '' | *[!0-9]*) echo "N must be a positive integer, got: '$N'" >&2; exit 2 ;;
esac
[ "$N" -ge 1 ] || { echo "N must be >= 1, got: $N" >&2; exit 2; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_VM="${E2E_VM:-}"
# Resolve + seed a SMALL pinned project to activate, exactly as session-e2e.sh
# does: `min session start` uploads the dir, so it must carry a pinned [upstream] +
# a light `shell` stack and stay small. All N starts share this one dir (each
# still mints a distinct box, under its own --name); a dir we create is removed
# wholesale on exit.
SEED_DIR=""
if [ -z "${E2E_PROJECT_DIR:-}" ] || { [ -n "$E2E_VM" ] && [ "${E2E_PROJECT_DIR:-}" = "/tmp" ]; }; then
  SEED_DIR="$(mktemp -d /tmp/mnl-stress-project.XXXXXX)"
  PROJECT_DIR="$SEED_DIR"
else
  PROJECT_DIR="$E2E_PROJECT_DIR"
fi
if [ -n "$SEED_DIR" ] || { [ ! -e "$PROJECT_DIR/minimal.toml" ] && [ ! -e "$PROJECT_DIR/.minimal/minimal.toml" ]; }; then
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$PROJECT_DIR/minimal.toml"
  if ! grep -q '^\[upstream\]' "$PROJECT_DIR/minimal.toml" \
     || ! grep -q '^locked_commit' "$PROJECT_DIR/minimal.toml"; then
    echo "::error::seeded minimal.toml lacks a pinned [upstream] from $ROOT/.minimal/minimal.toml"
    exit 1
  fi
fi

# Fresh state dir, same platform split + sun_path budget reasoning as
# session-e2e.sh (macOS: /tmp, never $TMPDIR; Linux: under $HOME, same device
# as the cache so minimald's hardlinks don't cross filesystems).
case "$(uname -s)" in
  Darwin)
    WORK="$(mktemp -d /tmp/mnl-stress.XXXXXX)"
    export XDG_STATE_HOME="$WORK/state"
    ;;
  *)
    WORK="$(mktemp -d "$HOME/.mnl-stress.XXXXXX")"
    export XDG_STATE_HOME="$WORK"
    ;;
esac
export XDG_RUNTIME_DIR="$WORK/runtime"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME"
chmod 700 "$XDG_RUNTIME_DIR"
export RUST_LOG="${RUST_LOG:-warn}"

mnl() {
  # shellcheck disable=SC2086
  min ${E2E_MINIMAL_ARGS:-} "$@"
}

# The hosts `min host list` shows as running, one per line. A lane's
# E2E_MINIMAL_ARGS picks the provider: `local-minvmd` on a VM lane, else `local`.
running_hosts() {
  mnl host list 2>/dev/null | awk -v p="$1" '(p == "" || $2 == p) && $3 == "running" { print $1 }'
}

teardown() {
  for h in $(running_hosts ""); do
    mnl host stop "$h" --force >/dev/null 2>&1 || true
  done
  if [ -n "$E2E_VM" ]; then
    minvmd stop >/dev/null 2>&1 || true
  fi
  [ -n "$SEED_DIR" ] && rm -rf "$SEED_DIR"
  rm -rf "$WORK"
}
trap teardown EXIT

fail() {
  echo "::group::stress diagnostics"
  echo "--- min ls ---"; mnl ls 2>&1 || true
  for f in "$WORK"/activate.*.out "$WORK"/activate.*.err; do
    [ -e "$f" ] || continue
    echo "--- $f ---"; cat "$f" 2>/dev/null || true
  done
  find "$XDG_STATE_HOME" -type f \( -name '*.log' -o -name '*.toml' \) 2>/dev/null \
    | while read -r f; do echo "--- $f (tail) ---"; tail -40 "$f"; done
  echo "::endgroup::"
  exit 1
}

is_uuid() {
  printf '%s' "$1" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
}

echo "::group::mint $N sessions concurrently (cold start)"
# Fire all N in parallel; each writes its session id (last stdout line) to a
# per-worker file. The first start auto-spawns the daemon; the rest race in.
# --detach makes `min session start` print the box id and return; a distinct
# --name per worker keeps the N starts from refusing each other's held name.
pids=""
for i in $(seq 1 "$N"); do
  (
    out="$(cd "$PROJECT_DIR" && mnl session start --detach --name "stress-$i" 2>"$WORK/activate.$i.err")"
    printf '%s\n' "$out" | tail -n1 | tr -d '\r' > "$WORK/activate.$i.out"
  ) &
  pids="$pids $!"
done
# Wait for every worker; remember if any exited non-zero.
worker_fail=0
for p in $pids; do wait "$p" || worker_fail=1; done
echo "::endgroup::"

# Collect + validate the N session ids.
sids=""
count=0
for i in $(seq 1 "$N"); do
  sid="$(cat "$WORK/activate.$i.out" 2>/dev/null || true)"
  if ! is_uuid "$sid"; then
    echo "::error::concurrent start #$i did not print a session UUID (got: '$sid')"
    worker_fail=1
    continue
  fi
  sids="$sids $sid"
  count=$((count + 1))
done
if [ "$worker_fail" -ne 0 ] || [ "$count" -ne "$N" ]; then
  echo "::error::expected $N concurrently-minted sessions, got $count valid"
  fail
fi
echo "minted $count/$N sessions concurrently"

# Every minted session must be listed — the daemon tracked all N under load.
listing="$(mnl ls --raw 2>/dev/null || true)"
for sid in $sids; do
  printf '%s\n' "$listing" | grep -Fqx "$sid" \
    || { echo "::error::session $sid missing from 'min ls --raw' after concurrent mint"; fail; }
done
listed="$(printf '%s\n' "$listing" | grep -Ecx '[0-9a-f-]{36}' || true)"
echo "all $N sessions listed (min ls --raw reports $listed)"

# Bulk teardown: one `min host stop <host> --force` must stop every box, then
# take the daemon (and, on a VM lane, the guest) down cleanly despite N live
# sessions.
if [ -n "$E2E_VM" ]; then host_provider=local-minvmd; else host_provider=local; fi
host="$(running_hosts "$host_provider" | head -n1)"
if [ -z "$host" ]; then
  echo "::error::'min host list' shows no running $host_provider host"
  mnl host list 2>&1 || true
  fail
fi
mnl host stop "$host" --force >/dev/null 2>&1 \
  || { echo "::error::'min host stop $host --force' failed under load"; fail; }
if [ -n "$E2E_VM" ]; then
  minvmd status >/dev/null 2>&1
  rc=$?
  case "$rc" in
    1) ;; # stopped
    0) echo "::error::VM still running after 'min host stop $host --force' with $N sessions"; fail ;;
    *) echo "::error::'minvmd status' failed with exit $rc"; fail ;;
  esac
fi

# And the daemon comes back cleanly: the next command autospawns a fresh one
# in which no minted box still runs (the concurrent set was stopped, not
# orphaned). `min host stop` keeps the box records, so every minted box must
# still be listed, and none of them in the running state.
if ! after="$(mnl box list --all -o json)"; then
  echo "::error::failed to list boxes after teardown (daemon did not restart cleanly)"
  fail
fi
for sid in $sids; do
  if ! state="$(printf '%s\n' "$after" | jq -er --arg id "$sid" '.[] | select(.id == $id) | .state')"; then
    echo "::error::box $sid is missing from 'min box list --all' after 'min host stop $host --force'"
    printf '%s\n' "$after"
    fail
  fi
  if [ "$state" = running ]; then
    echo "::error::box $sid still running after 'min host stop $host --force'"
    printf '%s\n' "$after"
    fail
  fi
done

echo "session stress OK ($N concurrent sessions minted, listed, and stopped)"
