#!/usr/bin/env bash
# Bulk host→guest upload proof: `min activate` a project carrying a large,
# COMPRESSIBLE fixture, N times, and fail if ANY attempt errors or hangs.
#
# Regression cover for the vsock transport reset in
# https://github.com/gominimal/minimal/issues/869. A guest kernel bump
# (6.12.43 → 6.12.94, https://github.com/gominimal/pkgs/pull/311) crossed Linux
# 6.12.92, where a new queued-skb-overhead check turned a previously silent
# vsock protocol violation into a fatal connection reset. Every `min activate`
# carrying a real project failed from that day on, and NOTHING went red for
# three weeks — no test we had moves enough data through the guest vsock to
# trip it. Client side the signature is:
#
#   error: Failed to upload project files: copying tar stream to channel: channel closed
#
# and guest side, in boot.log:
#
#   session ended with error error=Protocol error: No buffer space available (os error 105)
#
# WHY THE FIXTURE MUST BE COMPRESSIBLE. The trigger is write RATE, not volume,
# duration or file count — the client has to hand the channel a large number of
# already-compressed bytes as fast as it can produce them. Measured on the
# issue, three runs each:
#
#   45 MiB ext4-image slice  → 12.78 MB on the wire  → FAILS ~89% of runs
#   512 MB incompressible    → 512 MB on the wire    → passes (the zstd encoder
#                                                      becomes the bottleneck
#                                                      and throttles the writer)
#   20,000 files / 78 MB     → 78 MB                 → passes
#   45 MiB slice, other offset → 0.11 MB             → passes
#
# So a fixture of random bytes — the obvious thing to reach for — is exactly
# wrong: it hides the bug. This script synthesizes one with the compressibility
# of the measured reproducer instead of committing a 49 MiB binary: each MiB is
# a fresh 256 KiB of xorshift32 output written four times, so zstd (level 3,
# 2 MiB window — what async_compression defaults to) resolves three quarters of
# every MiB to matches and emits ~1/4 of the input, while the literal quarter
# stays incompressible enough to be stored raw. Measured: 51,380,224 bytes in,
# 12,884,004 bytes out (3.99:1) — within 1% of the 12,784,144 bytes that
# reproduced on the issue — and it costs ~0.4s of perl to generate. The
# compressed size is re-checked at run time (below) so a future change that
# accidentally makes the fixture incompressible fails loudly instead of
# silently disarming this canary.
#
# The failure is probabilistic (~89%, not 100%), so a single activate is not a
# detector: it would miss a regression 11% of the time. Five activates put the
# miss probability at 0.11^5 = 1.6e-5 — one missed night per ~170 years of
# nightlies — and keep detection at 97% even if CI hardware halves the trigger
# rate to 50%. Any single failure fails the whole run.
#
# #869 also sometimes HANGS the client outright rather than erroring
# (https://github.com/gominimal/inbox/issues/335, observed at 9 and 13 minutes),
# so every activate runs under a wall-clock deadline and a hang counts as a
# failure. A hang also stops the loop — five deadlines back to back would burn
# the nightly's whole job budget, and one is already conclusive.
#
# Environment (same knobs as scripts/session-e2e.sh, which this mirrors):
#   E2E_MINIMAL_ARGS              global args for every `min` call (e.g. --provider local-minvmd)
#   E2E_VM                        set to 1 for VM-backed targets (extra teardown
#                                 + guest boot log in the diagnostics)
#   MINVMD_BOOT_LOG               optional override for the guest-console path
#   BULK_ACTIVATE_TIMEOUT_SECS    per-activate deadline (default 420)
#
# Usage: scripts/bulk-upload-e2e.sh [iterations]
set -uo pipefail # not -e: capture failures so we can dump diagnostics

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_VM="${E2E_VM:-}"

ITER="${1:-5}"
case "$ITER" in
  '' | *[!0-9]*) echo "iterations must be a positive integer, got: '$ITER'" >&2; exit 2 ;;
esac
[ "$ITER" -ge 1 ] || { echo "iterations must be >= 1, got: $ITER" >&2; exit 2; }

# Fixture geometry — see the compressibility discussion above. The band is wide
# on purpose: it is a tripwire against a fixture that stops being compressible
# (or becomes trivially compressible, the 0.11 MB case that passes), not a
# golden-size assertion.
FIXTURE_MIB=49
FIXTURE_MIN_ZSTD=8000000
FIXTURE_MAX_ZSTD=20000000

# A warm activate is seconds; even a cold one (VM boot ≤150s, then the session
# mint) fits well inside this, while the observed hangs ran 9-13 minutes.
DEADLINE_SECS="${BULK_ACTIVATE_TIMEOUT_SECS:-420}"
case "$DEADLINE_SECS" in
  '' | *[!0-9]*) echo "BULK_ACTIVATE_TIMEOUT_SECS must be a positive integer, got: '$DEADLINE_SECS'" >&2; exit 2 ;;
esac
[ "$DEADLINE_SECS" -ge 1 ] || { echo "BULK_ACTIVATE_TIMEOUT_SECS must be >= 1, got: $DEADLINE_SECS" >&2; exit 2; }

# Debug logging on either side of the transport makes #869 disappear (the issue
# measured 4/4 passes under MINVMD_KRUN_LOG=debug, and RUST_LOG=debug on the
# client is enough on its own). An inherited value would leave this script
# unable to fail, so pin the level rather than defaulting it — and say so when
# we drop one, so nobody thinks their debug run was a clean proof.
if [ -n "${RUST_LOG:-}" ] && [ "$RUST_LOG" != warn ]; then
  echo "note: ignoring inherited RUST_LOG='$RUST_LOG' — client debug logging masks #869"
fi
export RUST_LOG=warn
if [ -n "${MINVMD_KRUN_LOG:-}" ]; then
  echo "note: unsetting MINVMD_KRUN_LOG='$MINVMD_KRUN_LOG' — libkrun debug logging masks #869"
  unset MINVMD_KRUN_LOG
fi

# Throwaway project dir, removed wholesale on teardown. Short template: the
# basename is embedded in the task dir under the state root and the deepest
# socket there has to fit sun_path's 108 bytes (see scripts/session-e2e.sh).
PROJECT_DIR="$(mktemp -d /tmp/mnlb.XXXXXX)"

# Fresh state dir so the daemon cold-starts, with the same platform split as
# session-e2e.sh: on Linux the workdir must sit on the same filesystem as the
# package cache (minimald hardlinks packages into each session rootfs, and
# hardlinks cannot cross devices), on macOS $TMPDIR paths overflow sun_path.
# XDG_CACHE_HOME is deliberately left alone so package pulls stay warm.
case "$(uname -s)" in
  Darwin)
    WORK="$(mktemp -d /tmp/mnl-bulk.XXXXXX)" || { echo "::error::mktemp failed for WORK" >&2; exit 1; }
    export XDG_STATE_HOME="$WORK/state"
    ;;
  *)
    WORK="$(mktemp -d "$HOME/.mnl-bulk.XXXXXX")" || { echo "::error::mktemp failed for WORK" >&2; exit 1; }
    export XDG_STATE_HOME="$WORK"
    ;;
esac
export XDG_RUNTIME_DIR="$WORK/runtime"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME"
chmod 700 "$XDG_RUNTIME_DIR"

# Every CLI call goes through this so E2E_MINIMAL_ARGS applies uniformly.
# Word-splitting of the args is intended.
mnl() {
  # shellcheck disable=SC2086
  min ${E2E_MINIMAL_ARGS:-} "$@"
}

# Leave nothing behind: a canary that strands a session (or a VM) per run is
# worse than no canary. Sessions first — `min stop` refuses while any is live
# unless forced, and the fixture dir goes whether or not the daemon cooperates.
teardown() {
  mnl destroy --all --force >/dev/null 2>&1 || true
  mnl stop --force >/dev/null 2>&1 || true
  if [ -n "$E2E_VM" ]; then
    minvmd stop >/dev/null 2>&1 || true
  fi
  rm -rf "$PROJECT_DIR" "$WORK"
}
CUR_PID=''
cleanup_child() {
  [ -n "$CUR_PID" ] && kill "$CUR_PID" 2>/dev/null
}
trap 'cleanup_child; teardown' EXIT
trap 'cleanup_child; teardown; exit 130' INT
trap 'cleanup_child; teardown; exit 143' TERM

# Dump what a detached daemon hides: the CLI's own stderr, the daemon state/log
# files, and on VM targets the guest console — where #869 prints its half of the
# story ("No buffer space available (os error 105)").
diagnostics() {
  echo "::group::bulk-upload diagnostics"
  echo "--- activate stderr ---"; cat "$WORK/activate.err" 2>/dev/null || true
  echo "--- activate stdout ---"; cat "$WORK/activate.out" 2>/dev/null || true
  echo "--- min ls ---"; mnl ls 2>&1 || true
  find "$XDG_STATE_HOME" -type f \( -name '*.log' -o -name '*.toml' \) 2>/dev/null \
    | while read -r f; do echo "--- $f (tail) ---"; tail -40 "$f"; done
  if [ -n "$E2E_VM" ]; then
    echo "--- guest boot console (tail) ---"
    tail -80 "${MINVMD_BOOT_LOG:-$XDG_STATE_HOME/minimal/providers/local-minvmd0/boot.log}" 2>/dev/null \
      || echo "(no boot log — VM never started)"
  fi
  # Diagnostic bundle (`min bug`): the daemon's own logs/state/config that the
  # tail-dumps can't reach. Collected here while the state dir still exists (the
  # EXIT teardown wipes $WORK). The daemon may be wedged or gone, so bound the
  # guest wait and fall back to a host-only bundle. Under a VM soak the boot-log
  # dir is the job's uploaded soak-logs, so the bundle ships with the run; the
  # /tmp fallback survives the $WORK teardown for a local no-VM run.
  echo "--- min bug (diagnostic bundle) ---"
  bug_dir="${MINVMD_BOOT_LOG:+$(dirname "$MINVMD_BOOT_LOG")}"
  bug_out="${bug_dir:-/tmp}/minimal-diag-bulk-$(date +%s).tar.zst"
  if mnl bug --guest-timeout-secs 30 --output "$bug_out" >/dev/null 2>&1 \
    || mnl bug --no-guest --output "$bug_out" >/dev/null 2>&1; then
    echo "wrote diagnostic bundle: $bug_out ($(wc -c <"$bug_out" 2>/dev/null || echo '?') bytes)"
  else
    echo "(min bug produced no bundle)"
  fi
  echo "::endgroup::"
}

# Run "$@" with stdin closed under a wall-clock deadline, returning its exit
# status or 124 (GNU timeout's code) if it had to be killed. Hand-rolled
# because `timeout` is not on a stock macOS, and because running the VM stack
# under it wedges the boot: libkrun tcsetattr()s from timeout's background
# process group and SIGTTOU stops the group. </dev/null is load-bearing for the
# same reason — and it is also what puts `min activate` in its non-interactive
# mode, where it neither prompts for the non-VCS upload confirmation (#770) nor
# expects a keypress for policy gating.
run_deadline() {
  local secs="$1"
  shift
  "$@" </dev/null &
  local pid=$!
  CUR_PID=$pid
  local waited=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$waited" -ge "$secs" ]; then
      kill -TERM "$pid" 2>/dev/null
      sleep 5
      kill -KILL "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
      CUR_PID=''
      return 124
    fi
    sleep 1
    waited=$((waited + 1))
  done
  CUR_PID=''
  wait "$pid"
}

# Seed the project exactly as session-e2e.sh does: the repo's `[upstream]`
# verbatim (same locked_commit → same warmed cache keys, zero pin drift) plus a
# light `shell` stack. The graph loader rejects an unpinned upstream, so verify
# the block actually came across.
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
  echo "::error::seeded minimal.toml lacks a pinned [upstream] (need repo + locked_commit) from $ROOT/.minimal/minimal.toml"
  exit 1
fi

# The payload. Each MiB is a fresh 256 KiB of xorshift32 output repeated four
# times: deterministic (fixed seed → byte-identical every run, so a failure is
# reproducible), ~4:1 under zstd, and cheap to both generate and compress —
# which is the point, since a fixture the encoder has to work at throttles the
# writer and hides the bug. 32-bit arithmetic keeps it independent of perl's
# integer width; perl is already a dependency of scripts/session-e2e.sh.
FIXTURE="$PROJECT_DIR/bulk-fixture.bin"
echo "::group::fixture (${FIXTURE_MIB} MiB, ~4:1 compressible)"
perl -e '
  my $s = 0x9E3779B9;
  for my $mib (1 .. $ARGV[0]) {
    my $quarter = "";
    for (1 .. (256 * 1024 / 4)) {
      $s ^= ($s << 13) & 0xFFFFFFFF;
      $s ^= ($s >> 17);
      $s ^= ($s << 5)  & 0xFFFFFFFF;
      $quarter .= pack("N", $s);
    }
    print $quarter x 4;
  }
' "$FIXTURE_MIB" > "$FIXTURE" || { echo "::error::could not generate the upload fixture"; exit 1; }

raw_bytes="$(wc -c < "$FIXTURE" | tr -d ' ')"
[ "$raw_bytes" -eq $((FIXTURE_MIB * 1024 * 1024)) ] \
  || { echo "::error::fixture is $raw_bytes bytes, expected $((FIXTURE_MIB * 1024 * 1024))"; exit 1; }

# On-the-wire size is the discriminator, so assert it rather than trusting the
# generator. Level 3 single-threaded mirrors the client's encoder
# (async_compression's ZstdEncoder default).
if command -v zstd >/dev/null 2>&1; then
  wire_bytes="$(zstd -3 -T1 -c "$FIXTURE" 2>/dev/null | wc -c | tr -d ' ')"
  case "$wire_bytes" in
    '' | *[!0-9]*)
      echo "::warning::could not measure the fixture's compressed size — skipping the check"
      ;;
    *)
      echo "fixture: $raw_bytes bytes raw, $wire_bytes bytes on the wire"
      if [ "$wire_bytes" -lt "$FIXTURE_MIN_ZSTD" ] || [ "$wire_bytes" -gt "$FIXTURE_MAX_ZSTD" ]; then
        echo "::error::fixture compresses to $wire_bytes bytes, outside [$FIXTURE_MIN_ZSTD, $FIXTURE_MAX_ZSTD]"
        echo "  This proof needs a payload that is LARGE AFTER COMPRESSION and cheap to"
        echo "  compress — see https://github.com/gominimal/minimal/issues/869. Too"
        echo "  compressible and there is nothing on the wire; incompressible and the"
        echo "  encoder throttles the writer. Either way the bug goes undetected."
        exit 1
      fi
      ;;
  esac
else
  echo "::warning::zstd not found — skipping the fixture compressibility check (expect ~12.9 MB on the wire)"
fi
echo "::endgroup::"

# `min activate` uploads the CURRENT directory, not the path argument (#873),
# so the project dir has to be the cwd. Everything else here is absolute.
cd "$PROJECT_DIR" || { echo "::error::cannot cd into $PROJECT_DIR"; exit 1; }

# Warm the daemon outside the timed loop: autospawn (a VM boot on VM targets) is
# minutes of variance that has nothing to do with the upload, and folding it
# into iteration 1's deadline would make that deadline meaningless.
echo "::group::warm the daemon (autospawn)"
# shellcheck disable=SC2086
if ! run_deadline "$DEADLINE_SECS" min ${E2E_MINIMAL_ARGS:-} ls >/dev/null 2>"$WORK/activate.err"; then
  echo "::error::the daemon did not come up ('min ls' failed or exceeded ${DEADLINE_SECS}s)"
  diagnostics
  exit 1
fi
echo "::endgroup::"

pass=0
fail=0
for i in $(seq 1 "$ITER"); do
  echo "::group::bulk upload $i/$ITER (${FIXTURE_MIB} MiB project)"
  # shellcheck disable=SC2086
  run_deadline "$DEADLINE_SECS" \
    min ${E2E_MINIMAL_ARGS:-} activate . >"$WORK/activate.out" 2>"$WORK/activate.err"
  rc=$?

  sid="$(tail -n1 "$WORK/activate.out" 2>/dev/null | tr -d '\r')"
  if [ "$rc" -eq 0 ] \
     && printf '%s' "$sid" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
    pass=$((pass + 1))
    echo "iteration $i: OK (session $sid)"
    # Destroy as we go: one live session at a time, and nothing to leak if the
    # run is cancelled mid-loop.
    mnl destroy "$sid" >/dev/null 2>&1 \
      || echo "::warning::could not destroy session $sid (the teardown sweep will retry)"
  else
    fail=$((fail + 1))
    # Close the iteration's group first: the annotations below are the point of
    # the run, and folding them into a collapsed group buries them.
    echo "::endgroup::"
    if [ "$rc" -eq 124 ]; then
      echo "::error::iteration $i: 'min activate' still running after ${DEADLINE_SECS}s — the #869 hang (https://github.com/gominimal/inbox/issues/335)"
    elif [ "$rc" -eq 0 ]; then
      echo "::error::iteration $i: activate's last stdout line is not a session UUID: '$sid'"
    else
      echo "::error::iteration $i: 'min activate' exited $rc — check for 'Failed to upload project files: copying tar stream to channel: channel closed' (https://github.com/gominimal/minimal/issues/869)"
    fi
    diagnostics
    # Sweep whatever a failed activate left half-created before the next pass.
    mnl destroy --all --force >/dev/null 2>&1 || true
    # A hang costs a full deadline; five of them would burn the nightly's whole
    # budget, and one is already conclusive. Errors are cheap, so keep going —
    # the pass/fail tally is what identifies the ~89% signature.
    if [ "$rc" -eq 124 ]; then
      echo "::warning::stopping after a hang; $((ITER - i)) iteration(s) not run"
      break
    fi
    continue
  fi
  echo "::endgroup::"
done

echo "bulk upload proof: $pass passed, $fail failed (of $ITER)"
[ "$fail" -eq 0 ] && [ "$pass" -eq "$ITER" ]
