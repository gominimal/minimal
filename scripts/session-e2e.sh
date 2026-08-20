#!/usr/bin/env bash
# The ONE session e2e, invoked by every target lane. Drives the real user
# path through the `min` CLI — which abstracts where the daemon lives —
# so the IDENTICAL proof runs against all three deployment targets:
#
#   Linux native   minimald on the host          (no extra env)
#   Linux KVM      minimald in a minvmd microVM  E2E_VM=1 E2E_MINIMAL_ARGS="--provider local-minvmd"
#   macOS HVF      minimald in a minvmd microVM  E2E_VM=1 (macOS is always VM-backed)
#
# Two proofs, in order, on EVERY lane:
#
#  1. Lifecycle: from a guaranteed-clean state, `min session activate` must auto-spawn
#     the target's daemon and create a session; then list, warm-call, destroy
#     (verified delisted), and a clean `min stop` that the next command
#     auto-respawns from.
#
#  2. Session sandbox: with the session live, attach an INTERACTIVE shell —
#     which forks a real hakoniwa sandbox (on a VM lane, inside the guest, over
#     the vsock bridge) — and prove the in-sandbox `min` helper. Inside the
#     sandbox we `min add <tool>` a package that is NOT in the launcher
#     baseline (base/coreutils/socat), then run it: the tool being absent
#     before and runnable after proves `min add` reached the daemon over the
#     in-sandbox `/run/minenv_sock` relay and hardlinked the package into the
#     live rootfs. This is lane-agnostic: it operates on the session workspace,
#     not the host project, so the identical attach+add+run runs everywhere.
#     Timing is reported but NOT asserted.
#
#     A session is interactive by design, so we drive it like a real user
#     through a REAL pty (scripts/e2e-attach-pty.py) rather than a pipe: pump
#     the command stream, then, when the shell exits and the daemon shows its
#     Detach/Delete prompt, answer it with keystrokes (Down + Enter => Delete).
#     A pipe is not a tty and could not answer that prompt. Selecting Delete
#     tears the session down, so it must be delisted afterwards. The same daemon
#     prompt runs whether local or in-guest, so the pty driver covers every lane.
#
# Host-side project seed: `min session activate` runs client-side and, since #758,
# BAILS (rather than scaffolding over an existing config) when the target dir
# has no `minimal.toml` and stdin is non-interactive; and since #748 it UPLOADS
# the project dir into the session. So we activate a small, self-seeded dir
# carrying the repo's own pinned `[upstream]` + a light `shell` stack — never
# the repo root (uploading the whole tree, and scaffolding over its
# `.minimal/minimal.toml`, is the clobber #758 prevents). On the VM lanes the
# caller passes E2E_PROJECT_DIR=/tmp; we seed a small subdir under it so the
# upload stays small. Every seed we create is removed on teardown.
#
# VM targets (E2E_VM=1) additionally need, from the caller:
#   - a codesigned/linkable `minvmd` on PATH (min spawns it by name)
#   - MINVMD_KERNEL_PATH / MINVMD_ROOTFS_PATH / MINVMD_INITRAMFS
#     (propagate through the `minvmd run --detach` re-exec)
#   - MINVMD_BOOT_LOG (optional) to override the guest-console capture path
#
# Environment:
#   E2E_MINIMAL_ARGS    global args for every `min` call (e.g. --provider local-minvmd)
#   E2E_PROJECT_DIR     project to activate (default: a self-seeded throwaway
#                       dir; VM lanes pass /tmp)
#   E2E_ACTIVATE_ARGS   extra args for `min session activate` (e.g. a future
#                       `--loadout dev` once the loadouts CLI lands, #686)
#   E2E_VM              set to 1 for VM-backed targets (extra teardown +
#                       diagnostics: minvmd stop, guest boot log)
#
# Usage: scripts/session-e2e.sh
set -uo pipefail # not -e: capture failures so we can dump diagnostics

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_VM="${E2E_VM:-}"

# The non-baseline package the sandbox proof adds and then runs. It must be a
# real upstream package that is genuinely ABSENT from a fresh shell-stack
# sandbox — the `shell` stack composes `base` (bash, coreutils, tar, gzip, …)
# plus `curl`, so anything in that set (tar included, which an earlier revision
# used and which is a `base` runtime dep) would already be present and prove
# nothing. `jq` is a standalone upstream package pulled in by none of them, and
# its `--version` banner (`jq-1.x`) is a distinctive, greppable marker that
# never appears in the echoed command stream.
ADD_TOOL="jq"
ADD_TOOL_MARKER="jq-1"

# Resolve + seed the project to activate. Since #748, `min session activate` UPLOADS the
# project dir into the session, so the target must (a) carry a `minimal.toml`
# (also what the #758 client pre-flight requires) and (b) stay SMALL, as the
# whole dir is uploaded. SEED_DIR is a throwaway we created and remove wholesale
# on teardown; SEEDED_MFILE is a lone minimal.toml dropped into a caller's dir.
SEED_DIR=""
SEEDED_MFILE=""
TASK_SEED_DIR="" # seeded by the `min task run` proof below; removed on teardown
HOOK_SEED_DIR="" # seeded by the lifecycle-hooks proof below; removed on teardown
if [ -z "${E2E_PROJECT_DIR:-}" ]; then
  # Native: self-seed a small throwaway — never $ROOT (uploading the whole repo,
  # and scaffolding over its `.minimal/`, is the very clobber #758 prevents).
  # Short template on purpose: the basename is embedded in the task dir under
  # the state root, inside the sun_path budget (see the workdir comment below).
  SEED_DIR="$(mktemp -d /tmp/mnlp.XXXXXX)"
  PROJECT_DIR="$SEED_DIR"
elif [ -n "$E2E_VM" ] && [ "$E2E_PROJECT_DIR" = "/tmp" ]; then
  # VM lanes pass /tmp; uploading all of /tmp is impractical, so seed a small
  # subdir under it and upload that instead. Use a UNIQUE mktemp dir (like the
  # native branch), never a fixed name: a persistent/self-hosted runner may run
  # VM lanes concurrently, and a fixed dir would let them clobber each other's
  # seed; a fresh dir also sidesteps any stale/unpinned leftover. Removed on
  # teardown.
  SEED_DIR="$(mktemp -d /tmp/mnl-e2e-project.XXXXXX)"
  PROJECT_DIR="$SEED_DIR"
else
  PROJECT_DIR="$E2E_PROJECT_DIR"
fi

# Seed a pinned minimal.toml: the repo's `[upstream]` verbatim (same
# locked_commit → same warmed cache keys, zero pin drift) plus a light `shell`
# stack. A dir we own (SEED_DIR) always gets a fresh one — never trust a
# leftover; a caller-provided dir is seeded only if it has none (never clobber).
if [ -n "$SEED_DIR" ] || { [ ! -e "$PROJECT_DIR/minimal.toml" ] && [ ! -e "$PROJECT_DIR/.minimal/minimal.toml" ]; }; then
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$PROJECT_DIR/minimal.toml"
  # The upstream MUST be pinned — `min session activate` uploads this and the graph
  # loader rejects an unpinned upstream.
  if ! grep -q '^\[upstream\]' "$PROJECT_DIR/minimal.toml" \
     || ! grep -q '^locked_commit' "$PROJECT_DIR/minimal.toml"; then
    echo "::error::seeded minimal.toml lacks a pinned [upstream] (need repo + locked_commit) from $ROOT/.minimal/minimal.toml"
    exit 1
  fi
  # A dir we own is cleaned wholesale; otherwise track the lone file we dropped.
  [ -n "$SEED_DIR" ] || SEEDED_MFILE="$PROJECT_DIR/minimal.toml"
fi
# A dir we own also becomes a VCS root (a bare `.git` marker, exactly like
# the task seed below): the headless upload gate then ships the seed into
# the session workspace. The sandbox proof's banner assertion depends on
# it — the orientation banner tests /workbench/minimal.toml in-shell at
# print time, so the blueprint must actually be IN the workspace for the
# `min init` pointer to stay suppressed.
[ -z "$SEED_DIR" ] || mkdir "$SEED_DIR/.git"

# Fresh state dir — a clean (no-daemon) cold-start on persistent runners:
# post-#690, all daemon state (minvmd.toml, locks, the bridge socket) lives
# under $XDG_STATE_HOME/minimal/providers/local-minvmd0 on every platform.
# XDG_CACHE_HOME is deliberately left alone so package pulls reuse the
# host/CI cache across runs — which pins where the state dir may live on a
# Linux-native lane: minimald HARDLINKS built packages from the cache into
# each session rootfs under the state dir, and hardlinks cannot cross
# filesystems ("Invalid cross-device link" at session spawn on hosts with a
# tmpfs /tmp). So on Linux the workdir lives under $HOME (same device as the
# cache, like production's ~/.local/state), and doubles as the state root
# directly — the extra /state hop is sun_path budget we cannot spare: the
# deepest socket, tasks/<seed>-<ts>-<n>-<pid>/run/minenv_sock, fits 108 only
# from a production-depth root. macOS stays on /tmp — NOT $TMPDIR, whose deep
# paths overflow its 104-byte limit ($HOME-based paths do too; its lanes are
# VM-backed, so the daemon and its hardlinks live inside the guest anyway).
case "$(uname -s)" in
  Darwin)
    WORK="$(mktemp -d /tmp/mnl-e2e.XXXXXX)"
    export XDG_STATE_HOME="$WORK/state"
    ;;
  *)
    WORK="$(mktemp -d "$HOME/.mnl-e2e.XXXXXX")"
    export XDG_STATE_HOME="$WORK"
    ;;
esac
export XDG_RUNTIME_DIR="$WORK/runtime"
mkdir -p "$XDG_RUNTIME_DIR" "$XDG_STATE_HOME"
chmod 700 "$XDG_RUNTIME_DIR"

# Hermetic user config: the CLI resolves loadouts and config.toml under
# XDG_CONFIG_HOME, and the sandbox proof below asserts the zero-config
# orientation banner (built-in `default` loadout). An operator's own
# `default_loadouts`/`default.toml` must not leak into the canonical proof.
export XDG_CONFIG_HOME="$WORK/config"

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
  [ -n "$SEED_DIR" ] && rm -rf "$SEED_DIR"
  [ -n "$SEEDED_MFILE" ] && rm -f "$SEEDED_MFILE"
  [ -n "$TASK_SEED_DIR" ] && rm -rf "$TASK_SEED_DIR"
  [ -n "$HOOK_SEED_DIR" ] && rm -rf "$HOOK_SEED_DIR"
  # And the state dir — which is NOT just metadata. On a VM lane it holds the
  # provider's per-VM writable data volume
  # (`minimal/providers/local-minvmd0/data-vol.raw`), a sparse image whose HOST
  # allocation is everything the guest wrote into it: its package cache, the
  # session rootfs, the workspace. WORK is fresh per run, so nothing is shared
  # and every run pays that allocation again. Leaving one behind is survivable;
  # scripts/soak-session-e2e.sh runs this script TEN times back-to-back, so ten
  # accumulate on one runner — and the nightly soak now dies inside that step
  # with the runner agent gone (job `failure`, step still `in_progress`, no
  # retrievable log lines and no uploaded artifacts), which is the shape a
  # runner ENOSPC takes. The sibling harnesses (bulk-upload-e2e.sh,
  # stress-session-e2e.sh) already remove theirs; this one was the outlier.
  # `fail` collects every diagnostic — including the `min bug` bundle, which it
  # writes OUTSIDE $WORK — before calling this.
  rm -rf "$WORK"
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
    tail -80 "${MINVMD_BOOT_LOG:-$XDG_STATE_HOME/minimal/providers/local-minvmd0/boot.log}" 2>/dev/null || echo "(no boot log — VM never started)"
  fi
  # Diagnostic bundle (`min bug`): the daemon's own logs/state/config, which the
  # tail-dumps above can't reach (it runs detached, often in-guest). The daemon
  # may be wedged or already gone, so bound the guest wait and fall back to a
  # host-only bundle. Written next to the boot log — under a VM soak that dir is
  # the job's uploaded soak-logs — so a failing nightly ships a real bundle, not
  # just scraped tails. now_ms keeps per-iteration bundles from colliding. The
  # fallback is /tmp, NOT $WORK: teardown removes the state dir, so a bundle
  # written there would die with it (same reasoning as bulk-upload-e2e.sh).
  echo "--- min bug (diagnostic bundle) ---"
  bug_dir="${MINVMD_BOOT_LOG:+$(dirname "$MINVMD_BOOT_LOG")}"
  bug_out="${bug_dir:-/tmp}/minimal-diag-session-$(now_ms).tar.zst"
  if mnl bug --guest-timeout-secs 30 --output "$bug_out" >/dev/null 2>&1 \
    || mnl bug --no-guest --output "$bug_out" >/dev/null 2>&1; then
    echo "wrote diagnostic bundle: $bug_out ($(wc -c <"$bug_out" 2>/dev/null || echo '?') bytes)"
  else
    echo "(min bug produced no bundle)"
  fi
  echo "::endgroup::"
  teardown
  exit 1
}

# The sandbox proof below forks a real session sandbox, which needs
# unprivileged user namespaces. On Ubuntu 24.04+ the AppArmor restriction
# (kernel.apparmor_restrict_unprivileged_userns=1) denies those to the
# unconfined daemon this script spawns, so on a restricted native-Linux host
# (stock CI runners included) load the shipped remediation — the minimald
# AppArmor profile, attached to the minimald this run will spawn — exactly as
# docs/reference/linux-host-setup.md tells users to. VM lanes skip this: their
# sandbox userns is created by the in-guest root daemon. `sudo -n` so a host
# without passwordless sudo gets a clear pointer instead of a mid-script
# prompt (the proof would die at uid_map otherwise).
if [ -z "$E2E_VM" ] && [ "$(uname -s)" = Linux ] \
    && [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = 1 ]; then
  minimald_bin="$(command -v minimald || true)"
  if [ -n "$minimald_bin" ] \
      && sudo -n "$ROOT/scripts/install-apparmor-profile.sh" --path "$minimald_bin"; then
    echo "restricted host: minimald AppArmor profile loaded (attached: $minimald_bin)"
  else
    echo "::warning::this host restricts unprivileged user namespaces and the minimald AppArmor profile could not be loaded; the sandbox proof will fail — see docs/reference/linux-host-setup.md"
  fi
fi

# Cold: `min session activate` must auto-spawn the target's daemon and print the
# new session id on stdout. The id is the LAST stdout line (any log lines
# that slip through the RUST_LOG filter precede it), validated as a UUID.
echo "::group::cold activate (auto-spawns the daemon)"
# Explicit name: the sandbox proof asserts the orientation banner
# interpolates the ACTUAL session name at the first prompt; an autogen
# name would make that assertion a moving target. The state dir is fresh
# per run, so a fixed name cannot collide.
SESSION_NAME="e2e-banner"
t0=$(now_ms)
# shellcheck disable=SC2086
activate_out="$(cd "$PROJECT_DIR" && mnl session activate . --name "$SESSION_NAME" ${E2E_ACTIVATE_ARGS:-} 2>"$WORK/activate.err")" \
  || { echo "::error::cold 'min session activate' failed to auto-spawn the daemon / create a session"; fail; }
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

# ---------------------------------------------------------------------------
# Non-interactive exec proof: `min session exec <sid> '<cmd>'` runs the
# command in the session's namespaces and relays its stdout and exit code. The
# daemon services this by re-execing ITSELF as the nsenter shim, which is a
# different path from the interactive attach below and the one that broke in
# #1175 (in the VM, pid-1's `current_exe()` is the unreachable initramfs
# `/init`, so every exec died with ENOENT while interactive attach worked).
# Ordered before the pty proof, which deletes the session.
echo "::group::session exec proof (min session exec)"
# shellcheck disable=SC2016 # $PWD must expand in the SESSION's shell, not here.
exec_out="$(mnl session exec "$sid" 'echo EXEC_OK $PWD' 2>"$WORK/exec.err")" || {
  echo "::error::'min session exec $sid' failed"
  echo "--- stdout ---"; printf '%s\n' "$exec_out"
  echo "--- stderr ---"; cat "$WORK/exec.err" 2>/dev/null || true
  fail
}
# The cwd proves it ran in the session's mount namespace, not on the host.
if [[ "$exec_out" != *"EXEC_OK /workbench"* ]]; then
  echo "::error::'min session exec' did not run in the session (expected 'EXEC_OK /workbench')"
  echo "--- stdout ---"; printf '%s\n' "$exec_out"
  echo "--- stderr ---"; cat "$WORK/exec.err" 2>/dev/null || true
  fail
fi
# The command's exit code must be the CLI's, not a blanket 0/1.
mnl session exec "$sid" 'exit 7' >/dev/null 2>&1
rc=$?
if [ "$rc" -ne 7 ]; then
  echo "::error::'min session exec \"exit 7\"' exited $rc (expected the command's 7)"
  fail
fi
echo "session exec proof OK"
echo "::endgroup::"

# ---------------------------------------------------------------------------
# `min task run` proof: a declared task runs in an ephemeral session — output
# streamed through, the task's exit code relayed, the session destroyed
# afterwards (or kept with --keep). Runs against its own tiny seeded project:
# the shared PROJECT_DIR seed deliberately declares no tasks, so this seed
# carries the same pinned [upstream] + shell stack PLUS the tasks (and the
# same `.git` marker, so the headless upload gate ships the config into the
# session). Skipped when the
# caller supplied a project we didn't seed — its minimal.toml declares none of
# these tasks. Short mktemp template on purpose (mirrors the PROJECT_DIR
# seed): the basename lands in the state root's task-dir paths, inside the
# sun_path budget.
if [ -n "$SEED_DIR" ] || [ -n "$SEEDED_MFILE" ]; then
  echo "::group::task run proof (min task run: ephemeral session loop)"
  TASK_SEED_DIR="$(mktemp -d /tmp/mnlt.XXXXXX)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
    printf '\n[tasks.e2e-echo]\necho = "TASK_RUN_E2E_OK"\n'
    printf '\n[tasks.e2e-fail]\nbash = "exit 7"\n'
  } > "$TASK_SEED_DIR/minimal.toml"
  mkdir "$TASK_SEED_DIR/.git"

  # The loop: run → the task's output on stdout → exit 0 → session gone.
  t0=$(now_ms)
  task_out="$(cd "$TASK_SEED_DIR" && mnl task run e2e-echo 2>"$WORK/task-run.err")"
  rc=$?
  t1=$(now_ms)
  if [ "$rc" -ne 0 ]; then
    echo "::error::'min task run e2e-echo' exited $rc (expected 0)"
    echo "--- task stderr ---"; cat "$WORK/task-run.err" 2>/dev/null || true
    fail
  fi
  # Glob, not grep — same SIGPIPE-under-pipefail reasoning as the attach
  # proof's markers.
  if [[ "$task_out" != *TASK_RUN_E2E_OK* ]]; then
    echo "::error::'min task run e2e-echo' did not stream the task's output"
    echo "--- task stdout ---"; printf '%s\n' "$task_out"
    echo "--- task stderr ---"; cat "$WORK/task-run.err" 2>/dev/null || true
    fail
  fi
  # Capture-then-glob, never `mnl ls | grep -q`: grep's early exit SIGPIPEs
  # the ls under pipefail and the leftover check would falsely pass.
  ls_out="$(mnl ls 2>/dev/null)"
  if [[ "$ls_out" == *task-e2e-echo-* ]]; then
    echo "::error::ephemeral session still listed after 'min task run e2e-echo'"
    fail
  fi
  echo "task run loop: output + destroy OK ($((t1 - t0))ms)"

  # The task's exit code must come back as ours — and the failing run's
  # session must be torn down just the same.
  (cd "$TASK_SEED_DIR" && mnl task run e2e-fail >/dev/null 2>"$WORK/task-fail.err")
  rc=$?
  if [ "$rc" -ne 7 ]; then
    echo "::error::'min task run e2e-fail' exited $rc (expected the task's exit code 7)"
    echo "--- task stderr ---"; cat "$WORK/task-fail.err" 2>/dev/null || true
    fail
  fi
  ls_out="$(mnl ls 2>/dev/null)"
  if [[ "$ls_out" == *task-e2e-fail-* ]]; then
    echo "::error::ephemeral session still listed after a failing 'min task run'"
    fail
  fi
  echo "task run exit-code relay: 7 → 7 OK"

  # --keep retains the session, named task-<task>-<hex>, attachable later.
  (cd "$TASK_SEED_DIR" && mnl task run e2e-echo --keep >/dev/null 2>"$WORK/task-keep.err") \
    || { echo "::error::'min task run e2e-echo --keep' failed"; cat "$WORK/task-keep.err" 2>/dev/null || true; fail; }
  kept="$(mnl ls 2>/dev/null | grep -o 'task-e2e-echo-[0-9a-f]\{4\}' | head -n1)"
  if [ -z "$kept" ]; then
    echo "::error::--keep did not leave a 'task-e2e-echo-*' session listed"
    mnl ls 2>&1 || true
    fail
  fi
  # The destroy dirty gate: the kept session's task process has exited, so
  # no host is running and its at-risk state is unknowable — the gate must
  # refuse a headless (no TTY) destroy without --force, naming the escape
  # hatch. (Were a host live, the seed's empty `.git` marker would make VCS
  # mode decline into the activation-delta fallback instead; only a
  # proven-clean tree may destroy headless without --force.)
  if mnl session destroy "$kept" >/dev/null 2>"$WORK/destroy-refuse.err"; then
    echo "::error::headless 'min session destroy' without --force should refuse"
    fail
  fi
  grep -q -- "--force" "$WORK/destroy-refuse.err" \
    || { echo "::error::headless destroy refusal does not name --force"; cat "$WORK/destroy-refuse.err" 2>/dev/null || true; fail; }
  mnl session destroy --force "$kept" >/dev/null 2>&1 \
    || { echo "::error::could not destroy kept session $kept"; fail; }
  echo "task run --keep: session $kept retained; dirty gate refused headless destroy OK"

  # Unknown task: an instant client-side error listing what IS declared.
  if (cd "$TASK_SEED_DIR" && mnl task run no-such-task >/dev/null 2>"$WORK/task-unknown.err"); then
    echo "::error::'min task run no-such-task' unexpectedly succeeded"
    fail
  fi
  grep -q 'e2e-echo' "$WORK/task-unknown.err" \
    || { echo "::error::unknown-task error does not list the declared tasks"; cat "$WORK/task-unknown.err" 2>/dev/null || true; fail; }

  # Muscle-memory catch: the hidden bare `min run <task>` errors naming the
  # canonical spelling.
  if mnl run e2e-echo >/dev/null 2>"$WORK/task-alias.err"; then
    echo "::error::hidden 'min run' unexpectedly succeeded"
    fail
  fi
  grep -q 'min task run' "$WORK/task-alias.err" \
    || { echo "::error::hidden 'min run' error does not name 'min task run'"; cat "$WORK/task-alias.err" 2>/dev/null || true; fail; }

  echo "task run proof OK"
  echo "::endgroup::"
fi

# ---------------------------------------------------------------------------
# Lifecycle-hooks proofs. These are the only coverage of hook execution that
# goes through the real nsenter injection: the unit tests substitute a
# host-side command builder for it, so a break in the injection, in the
# script upload, or in the client/daemon round trip would not show up there.
#
# Seeded projects of their own, like the task-run proof, because the shared
# seed declares no hooks.
if [ -n "$SEED_DIR" ] || [ -n "$SEEDED_MFILE" ]; then
  # Every fixture below is a project, and a project's hooks only run once the
  # user has allow-listed it. Written up front so nothing has to be answered
  # interactively — and note this is only writable in advance because the
  # policy stores the project path as the CLIENT knows it. A daemon that
  # stamped its own per-session workspace copy would make this unmatchable,
  # which is what `hooks_gate_refuses_without_an_allow_entry` below pins from
  # the other side.
  hook_allow() {
    mkdir -p "$XDG_CONFIG_HOME/minimal"
    printf '[hooks]\nallow = ["%s"]\n' "$1" > "$XDG_CONFIG_HOME/minimal/user_policy.toml"
  }
  # `mktemp -d`, then resolve it. macOS's /tmp is a symlink to /private/tmp,
  # and `min session activate .` reports the project by its RESOLVED path —
  # so an allow entry written against the unresolved one names a project the
  # daemon never sees, and the activation fails the gate on that lane only.
  # Every hooks fixture goes through here so the path in the policy and the
  # path in the record are the same string on every host.
  hook_mktemp() {
    local dir
    dir="$(mktemp -d "$1")" || return 1
    (cd "$dir" && pwd -P)
  }
  # The `[upstream]` stanza every fixture needs, plus the shell stack.
  hook_seed_preamble() {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  }
  # Grep the daemon's file log. The only way to observe a hook whose session
  # is gone by the time you could look (`on_destroy`), and the reason those
  # fixtures exit non-zero: RUST_LOG is `warn` here, so the INFO "hook ran"
  # record is not emitted, but the WARN "hook failed" record is — and it
  # carries the hook's captured output, which is the evidence.
  hook_log_has() {
    find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f \
      -exec grep -l -- "$1" {} + 2>/dev/null | head -n1
  }
  # Whether that log is on THIS host. On a VM lane minimald runs inside the
  # guest and writes to a guest tmpfs (`/run/minimal`), which no host path
  # reaches — the host's log dir holds only `minvmd.log`. So the assertions
  # that read a hook's captured output are native-only.
  #
  # What is NOT skipped anywhere: that the destroy still completed. That half
  # of the contract ("a failing teardown hook must not block the teardown")
  # is asserted off `min ls` on every lane, and `on_detach` — the other
  # headless teardown hook — is proved on every lane too, by a marker read
  # back through the session rather than out of a log.
  hook_log_readable() { [ -z "$E2E_VM" ]; }

  # -- A. The four transitions, one session ---------------------------------
  # One fixture and one activation covering activate → attach → detach →
  # destroy. Separate activations would be separate package installs for no
  # extra coverage.
  echo "::group::lifecycle hooks: the four transitions"
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlh.XXXXXX)"
  # shellcheck disable=SC2016 # `$MINIMAL_HOOK_EVENT` and `$0` must reach the
  # TOML *unexpanded*: they are for the hook's own shell to expand inside the
  # session, and expanding them here would write this script's values instead
  # — which is exactly what these assertions are checking did not happen.
  {
    hook_seed_preamble
    # No shebang on the first hook: proves the POSIX-`sh` default.
    # `$MINIMAL_HOOK_EVENT` proves the metadata env reaches the hook.
    printf '\n[[session.lifecycle_hooks]]\n'
    printf 'description = "e2e transition markers"\n'
    printf 'on_activate = { type = "inline", value = "echo HOOK_OK $MINIMAL_HOOK_EVENT > /home/hook-activate" }\n'
    printf 'on_attach   = { type = "inline", value = "echo HOOK_ATTACH_OK" }\n'
    printf 'on_detach   = { type = "inline", value = "echo HOOK_OK $MINIMAL_HOOK_EVENT > /home/hook-detach" }\n'
    # Non-zero on purpose: makes the daemon log the run at WARN *with its
    # output*, which is the only evidence that outlives the session — and
    # asserts the contract that a failing teardown hook still tears down.
    printf 'on_destroy  = { type = "inline", value = "echo HOOK_DESTROY_OK; exit 3" }\n'
    # A second hook, dispatched by shebang rather than the default, writing
    # the interpreter it actually ran under.
    printf '\n[[session.lifecycle_hooks]]\n'
    printf 'description = "e2e shebang dispatch"\n'
    printf 'on_activate = { type = "inline", value = "#!/usr/bin/bash\\necho $0 > /home/hook-shebang\\n" }\n'
  } > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"
  hook_allow "$HOOK_SEED_DIR"

  hook_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt 2>"$WORK/hooks-activate.err")" || {
    echo "::error::'min session activate' with project hooks failed"
    echo "--- stderr ---"; cat "$WORK/hooks-activate.err" 2>/dev/null || true
    fail
  }

  # on_activate. Read back from INSIDE the session, so this asserts the hook
  # ran in the session's namespaces rather than anywhere on the host.
  hook_out="$(mnl session exec "$hook_sid" 'cat /home/hook-activate' 2>"$WORK/hooks-read.err")" || {
    echo "::error::could not read the activate hook's marker from the session"
    echo "--- stderr ---"; cat "$WORK/hooks-read.err" 2>/dev/null || true
    fail
  }
  if [[ "$hook_out" != *"HOOK_OK on_activate"* ]]; then
    echo "::error::on_activate hook did not run in the session (marker: '$hook_out')"
    echo "--- activate stderr ---"; cat "$WORK/hooks-activate.err" 2>/dev/null || true
    fail
  fi

  # Shebang dispatch: the second hook ran under the interpreter it named, not
  # the default. Resolved against the SESSION's filesystem, which is the part
  # no unit test can reach.
  sheb_out="$(mnl session exec "$hook_sid" 'cat /home/hook-shebang' 2>/dev/null)"
  if [[ "$sheb_out" != *bash* ]]; then
    echo "::error::shebang hook did not run under the interpreter it named (\$0: '$sheb_out')"
    fail
  fi
  echo "on_activate + shebang dispatch OK"

  # on_attach and on_detach, over a REAL pty — `on_attach` writes to the
  # terminal you are attached to, and a detach is by definition something a
  # non-interactive caller cannot perform. Answer the exit prompt with `keep`
  # (Enter, the first option) so leaving the shell is a detach rather than a
  # destroy.
  #
  # This attach also proves `TERM`, and this is the only place in the lane
  # that can: the session's shell was minted HEADLESSLY, by the activation
  # hooks above, with no terminal in the picture — the exact shape that used
  # to leave a session with no `TERM` at all for its whole life (every later
  # attach reused that shell), so `less` in it fell back to ncurses' generic
  # `unknown` entry. A pinned `TERM` on the driver makes the assertion below
  # exact whatever the lane's own terminal is; the unit tests cover the
  # decision, but only a real sandbox proves the value reaches a real bash.
  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  # Leave a mark IN the shell — a plain shell variable, never exported, so it
  # lives in that process and nowhere else. The re-attach below reads it back.
  # Deliberately not `$$`: the session shell is pid 1 of its own namespace, so
  # a replacement shell would report pid 1 too and the check would be vacuous.
  # Leaves by the ctrl-w detach chord (`E2E_PTY_DETACH`), NOT by `exit`.
  # `exit` ends the session's shell, and the "re-attach" below would then land
  # on a freshly minted one — which would still report the new terminal (a new
  # shell takes `TERM` from its launch env) while proving nothing about
  # re-attaching. Detaching leaves the shell running, which is what the mark
  # above is read back out of.
  # shellcheck disable=SC2016 # `$TERM` must reach the SESSION's shell unexpanded.
  attach_out="$(E2E_PTY_COMMANDS='cat /home/hook-activate
echo TERM_INSHELL=$TERM
__e2e_same_shell=yes' \
    E2E_PTY_DETACH=1 TERM=xterm-256color python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min ${E2E_MINIMAL_ARGS:-} session attach "$hook_sid" \
    2>"$WORK/hooks-attach.err")" || {
    echo "::error::pty attach for the hooks proof failed"
    echo "--- transcript ---"; printf '%s\n' "$attach_out"
    echo "--- stderr ---"; cat "$WORK/hooks-attach.err" 2>/dev/null || true
    fail
  }
  # `on_attach` runs on the attached terminal, so its output is in the
  # transcript. Glob, not grep — same SIGPIPE-under-pipefail reasoning as the
  # sandbox proof's marker checks.
  if [[ "$attach_out" != *HOOK_ATTACH_OK* ]]; then
    echo "::error::on_attach hook output did not reach the attached terminal"
    echo "--- transcript ---"; printf '%s\n' "$attach_out"
    fail
  fi
  # The attaching terminal must be what the shell reports, even though this
  # shell was minted for hooks rather than for a terminal. Matching the FULL
  # `TERM_INSHELL=<value>` is what makes this real: the pty echoes the typed
  # `echo TERM_INSHELL=$TERM` verbatim (the shell expands it only on the
  # output side), so an empty or stale `TERM` cannot satisfy it.
  if [[ "$attach_out" != *"TERM_INSHELL=xterm-256color"* ]]; then
    echo "::error::the attached terminal's TERM did not reach the session shell"
    echo "--- transcript ---"; printf '%s\n' "$attach_out"
    fail
  fi
  # Keeping at the exit prompt is a detach, and the session must survive it.
  if ! mnl ls --raw 2>/dev/null | grep -q -- "$hook_sid"; then
    echo "::error::session gone after answering the exit prompt with 'keep'"
    fail
  fi
  # `on_detach` is headless (the terminal it would have used is the thing
  # that just left), so its marker is read back the same way as activate's.
  # Reported by the departing binding rather than by anything we called, so
  # it lands shortly after the attach returns.
  detached=""
  for _ in $(seq 1 40); do
    if mnl session exec "$hook_sid" 'cat /home/hook-detach' 2>/dev/null | grep -q HOOK_OK; then
      detached=1; break
    fi
    sleep 0.25
  done
  if [ -z "$detached" ]; then
    echo "::error::on_detach hook did not run after the attach ended"
    echo "--- transcript ---"; printf '%s\n' "$attach_out"
    fail
  fi
  echo "on_attach (on the terminal) + on_detach (headless, after leaving) OK"
  echo "TERM reached the hook-launched shell from the attaching terminal OK"

  # Re-attach to the SAME (still-running) shell from a terminal that calls
  # itself something else. `TERM` is a per-attach fact, so the shell must now
  # report the new one: the value is not fixed when the shell is minted, and
  # the daemon-installed hook re-reads it. This is the case a user hits by
  # attaching from a second machine or emulator.
  #
  # The in-shell mark is asserted alongside it, because `TERM` alone cannot
  # tell the two explanations apart: a daemon that *replaced* the shell would
  # also report the new terminal, while silently destroying everything the
  # session was running. Only the original process still holds that variable.
  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  # shellcheck disable=SC2016 # `$TERM` must reach the SESSION's shell unexpanded.
  reattach_out="$(E2E_PTY_COMMANDS='echo TERM_INSHELL=$TERM
echo SHELLMARK=[$__e2e_same_shell]
exit' E2E_PTY_ANSWER=keep TERM=vt220 python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min ${E2E_MINIMAL_ARGS:-} session attach "$hook_sid" \
    2>"$WORK/hooks-reattach.err")" || {
    echo "::error::pty re-attach for the TERM proof failed"
    echo "--- transcript ---"; printf '%s\n' "$reattach_out"
    echo "--- stderr ---"; cat "$WORK/hooks-reattach.err" 2>/dev/null || true
    fail
  }
  if [[ "$reattach_out" != *"TERM_INSHELL=vt220"* ]]; then
    echo "::error::re-attaching from a different terminal did not update TERM"
    echo "--- transcript ---"; printf '%s\n' "$reattach_out"
    fail
  fi
  # `SHELLMARK=[yes]` can only come from the shell that ran the assignment;
  # a replacement prints `SHELLMARK=[]`, which is why the brackets are there.
  if [[ "$reattach_out" != *"SHELLMARK=[yes]"* ]]; then
    echo "::error::the re-attach did not land on the same shell (its state was gone)"
    echo "--- transcript ---"; printf '%s\n' "$reattach_out"
    fail
  fi
  echo "re-attach from a different terminal updated TERM in the same shell OK"

  # on_destroy. The session's filesystem goes with it, so the evidence is the
  # daemon log — and the failing hook must not have blocked the teardown.
  mnl session destroy --force "$hook_sid" >/dev/null 2>&1 \
    || { echo "::error::could not destroy the hooks session $hook_sid"; fail; }
  if hook_log_readable; then
    destroy_log=""
    for _ in $(seq 1 40); do
      destroy_log="$(hook_log_has HOOK_DESTROY_OK)"
      [ -n "$destroy_log" ] && break
      sleep 0.25
    done
    if [ -z "$destroy_log" ]; then
      echo "::error::on_destroy hook left no record in the daemon log"
      echo "--- log dir ---"; ls -la "$XDG_STATE_HOME/minimal/logs" 2>/dev/null || true
      fail
    fi
    echo "on_destroy OK (ran, output captured, and a non-zero exit still destroyed)"
  else
    echo "on_destroy: output check skipped (guest-side daemon log)"
  fi
  # Lane-agnostic half: a failing teardown hook must not keep the session.
  if mnl ls --raw 2>/dev/null | grep -q -- "$hook_sid"; then
    echo "::error::a failing on_destroy hook blocked the teardown"
    fail
  fi
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  echo "::endgroup::"

  # -- B. External hook scripts ---------------------------------------------
  # The longest untested chain in the feature: the client resolves the path
  # against its anchor, refuses a symlink at any component, tars it up; the
  # daemon unpacks it under the session's hooks dir with its own per-entry
  # validation; and at run time the daemon re-derives the same staged path
  # from the hook's source and reads it. Every piece has unit coverage;
  # nothing covered the wire between them.
  echo "::group::lifecycle hooks: external scripts"
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlx.XXXXXX)"
  {
    hook_seed_preamble
    printf '\n[[session.lifecycle_hooks]]\n'
    printf 'description = "e2e external script"\n'
    printf 'on_activate = { type = "external", value = "hooks/setup.sh" }\n'
  } > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git" "$HOOK_SEED_DIR/hooks"
  printf '#!/usr/bin/bash\necho HOOK_EXTERNAL_OK > /home/hook-external\n' \
    > "$HOOK_SEED_DIR/hooks/setup.sh"
  chmod +x "$HOOK_SEED_DIR/hooks/setup.sh"
  hook_allow "$HOOK_SEED_DIR"

  ext_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt 2>"$WORK/hooks-ext.err")" || {
    echo "::error::activation with an external hook script failed"
    echo "--- stderr ---"; cat "$WORK/hooks-ext.err" 2>/dev/null || true
    fail
  }
  ext_out="$(mnl session exec "$ext_sid" 'cat /home/hook-external' 2>/dev/null)"
  if [[ "$ext_out" != *HOOK_EXTERNAL_OK* ]]; then
    echo "::error::external hook script did not run (marker: '$ext_out')"
    echo "--- activate stderr ---"; cat "$WORK/hooks-ext.err" 2>/dev/null || true
    fail
  fi
  mnl session destroy --force "$ext_sid" >/dev/null 2>&1 || true
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  echo "external hook script proof OK (staged, uploaded, resolved, ran)"
  echo "::endgroup::"

  # -- C. The refusals ------------------------------------------------------
  # Three ways hooks must NOT run, each spanning the client/daemon boundary.
  echo "::group::lifecycle hooks: refusals"
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlr.XXXXXX)"
  {
    hook_seed_preamble
    printf '\n[[session.lifecycle_hooks]]\n'
    printf 'description = "e2e refusal fixture"\n'
    printf 'on_activate = { type = "inline", value = "echo HOOK_REFUSAL_MARKER > /home/hook-refusal; exit 9" }\n'
  } > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"

  # C1: no allow entry + --no-prompt. The consent boundary for arbitrary code
  # execution: it must refuse, and the error must carry a snippet the user
  # can act on. Asserting the snippet's CONTENT is what catches a regression
  # to an unmatchable project path.
  rm -f "$XDG_CONFIG_HOME/minimal/user_policy.toml"
  if (cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt >/dev/null 2>"$WORK/hooks-gate.err"); then
    echo "::error::activation with un-allow-listed project hooks should have refused"
    fail
  fi
  if ! grep -q "hooks" "$WORK/hooks-gate.err" || ! grep -qF -- "$HOOK_SEED_DIR" "$WORK/hooks-gate.err"; then
    echo "::error::the hooks refusal does not name the project in an actionable snippet"
    echo "--- stderr ---"; cat "$WORK/hooks-gate.err" 2>/dev/null || true
    fail
  fi
  echo "gate refuses an un-allow-listed project, naming it OK"

  # C2: a failing on_activate fails the ACTIVATION — the session must not
  # come up, and the error must name the hook and what it printed.
  hook_allow "$HOOK_SEED_DIR"
  if (cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt >/dev/null 2>"$WORK/hooks-failact.err"); then
    echo "::error::activation should have failed on a failing on_activate hook"
    fail
  fi
  if ! grep -qi "hook" "$WORK/hooks-failact.err"; then
    echo "::error::the failed-activation error does not mention the hook"
    echo "--- stderr ---"; cat "$WORK/hooks-failact.err" 2>/dev/null || true
    fail
  fi
  echo "a failing on_activate aborts the activation OK"

  # C3: --no-hooks. Both ends honour it (the client strips its loadouts'
  # before sending, the daemon strips the project's), so the same fixture
  # that just failed the activation must now come up clean.
  nohooks_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt --no-hooks 2>"$WORK/hooks-nohooks.err")" || {
    echo "::error::'--no-hooks' activation failed"
    echo "--- stderr ---"; cat "$WORK/hooks-nohooks.err" 2>/dev/null || true
    fail
  }
  if mnl session exec "$nohooks_sid" 'cat /home/hook-refusal' >/dev/null 2>&1; then
    echo "::error::'--no-hooks' session ran its project's on_activate hook anyway"
    fail
  fi
  # And the composition records that it has none, rather than carrying hooks
  # every later transition has to remember to skip.
  nohooks_list="$(mnl session hooks "$nohooks_sid" 2>/dev/null)"
  if [[ "$nohooks_list" != *"No lifecycle hooks"* ]]; then
    echo "::error::'--no-hooks' session still lists composed hooks: $nohooks_list"
    fail
  fi
  mnl session destroy --force "$nohooks_sid" >/dev/null 2>&1 || true
  echo "--no-hooks suppresses execution and composition OK"
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  rm -f "$XDG_CONFIG_HOME/minimal/user_policy.toml"
  echo "::endgroup::"

  # -- Loadout-declared hooks ------------------------------------------------
  # A different path from everything above: composed on the CLIENT, ungated
  # (they are the user's own file, not a project's), and staged under a
  # different prefix. XDG_CONFIG_HOME is hermetic here, so the loadout only
  # exists for this block.
  echo "::group::lifecycle hooks: loadout-declared"
  mkdir -p "$XDG_CONFIG_HOME/minimal/loadouts"
  cat > "$XDG_CONFIG_HOME/minimal/loadouts/hookdev.toml" <<'LOADOUT'
description = "e2e loadout hooks"

[[lifecycle_hooks]]
on_activate = { type = "inline", value = "echo HOOK_LOADOUT_OK > /home/hook-loadout" }
LOADOUT
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnll.XXXXXX)"
  hook_seed_preamble > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"

  # No `[hooks] allow` written: a loadout's hooks face no policy gate, and
  # --no-prompt proves it — a gate would fail the activation here.
  lo_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt --loadout hookdev 2>"$WORK/hooks-loadout.err")" || {
    echo "::error::activation with a loadout-declared hook failed"
    echo "--- stderr ---"; cat "$WORK/hooks-loadout.err" 2>/dev/null || true
    fail
  }
  lo_out="$(mnl session exec "$lo_sid" 'cat /home/hook-loadout' 2>/dev/null)"
  if [[ "$lo_out" != *HOOK_LOADOUT_OK* ]]; then
    echo "::error::loadout-declared hook did not run (marker: '$lo_out')"
    echo "--- activate stderr ---"; cat "$WORK/hooks-loadout.err" 2>/dev/null || true
    fail
  fi
  mnl session destroy --force "$lo_sid" >/dev/null 2>&1 || true
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  rm -f "$XDG_CONFIG_HOME/minimal/loadouts/hookdev.toml"
  echo "loadout-declared hooks proof OK (ran, ungated)"
  echo "::endgroup::"
fi
# ---------------------------------------------------------------------------
# Session-sandbox proof (every lane). Everything above proves the lifecycle;
# this forks a real sandbox and proves the in-sandbox `min add`. A session is
# interactive by design, so we drive it like a real user through a REAL pty
# (scripts/e2e-attach-pty.py), NOT a pipe — a pipe is not a tty and cannot
# answer the session-exit prompt. The driver:
#   1. records that $ADD_TOOL is ABSENT before the add (a baseline tool would
#      already be present, so the add would prove nothing),
#   2. `min add`s it into this session,
#   3. `hash -r` so bash re-scans PATH for the freshly hardlinked binary,
#   4. runs it — its version banner round-tripping proves it is now runnable,
#   5. `exit`s, then answers the Detach/Delete prompt with keystrokes (Down +
#      Enter => "Delete"), the genuine interactive teardown — which destroys the
#      session, so it must then be delisted.
echo "::group::sandbox proof (interactive attach via pty: min add $ADD_TOOL + run)"
t0=$(now_ms)
# shellcheck disable=SC2086
attach_out="$(python3 "$ROOT/scripts/e2e-attach-pty.py" "$ADD_TOOL" \
  min ${E2E_MINIMAL_ARGS:-} session attach "$sid" 2>"$WORK/exec.err")"
rc=$?
t1=$(now_ms)
if [ "$rc" -ne 0 ]; then
  echo "::error::interactive 'min session attach $sid' (pty) exited $rc (expected 0)"
  echo "--- attach output ---"; printf '%s\n' "$attach_out"
  echo "--- driver stderr ---"; cat "$WORK/exec.err" 2>/dev/null || true
  fail
fi
# Match with a bash glob, NOT `printf ... | grep -q`: `min add`'s pty progress
# bars can flood `$attach_out` to megabytes, and `grep -q` exits on the first
# match while `printf` is still writing — that SIGPIPE, under `pipefail`,
# becomes the pipeline's non-zero exit and a FALSE "not found". A glob on the
# variable touches no pipe, so it is immune.
#
# Must have been absent before the add — otherwise the add proves nothing.
if [[ "$attach_out" != *TOOL_ABSENT_BEFORE* ]]; then
  echo "::error::'$ADD_TOOL' was already present before 'min add' (pick a non-baseline tool)"
  echo "--- attach output ---"; printf '%s\n' "$attach_out"
  fail
fi
# And runnable after — its version banner must round-trip on stdout.
if [[ "$attach_out" != *"$ADD_TOOL_MARKER"* ]]; then
  echo "::error::in-sandbox 'min add $ADD_TOOL' did not make it runnable (no '$ADD_TOOL_MARKER')"
  echo "--- attach output ---"; printf '%s\n' "$attach_out"
  echo "--- driver stderr ---"; cat "$WORK/exec.err" 2>/dev/null || true
  fail
fi
# Orientation banner: the first interactive prompt must have printed the
# two orientation lines, with the ACTUAL session name and loadout list
# interpolated in-shell from the $MINIMAL_* vars (daemon baseline +
# client-composed). XDG_CONFIG_HOME is hermetic (see the export above),
# so the composed loadout is deterministically the built-in `default`.
if [[ "$attach_out" != *"minimal · session $SESSION_NAME · loadout default (built-in)"* ]]; then
  echo "::error::attach output lacks the orientation banner line (session name + loadout list)"
  echo "--- attach output ---"; printf '%s\n' "$attach_out"
  fail
fi
if [[ "$attach_out" != *"detach: ctrl-w"* ]]; then
  echo "::error::attach output lacks the orientation banner's detach line"
  echo "--- attach output ---"; printf '%s\n' "$attach_out"
  fail
fi
# The banner tests /workbench/minimal.toml IN-SHELL at print time, so this
# asserts the workspace's real state: our owned seed is a VCS root whose
# upload shipped the blueprint, so the `min init` pointer must not have
# printed. Only asserted for a seed we own — a caller-provided
# E2E_PROJECT_DIR controls its own upload-gate outcome.
if [ -n "$SEED_DIR" ] && [[ "$attach_out" == *"no minimal.toml here"* ]]; then
  echo "::error::banner shows the 'min init' pointer despite the uploaded minimal.toml"
  echo "--- attach output ---"; printf '%s\n' "$attach_out"
  fail
fi
echo "sandbox proof: in-sandbox 'min add $ADD_TOOL' + run OK, orientation banner rendered ($((t1 - t0))ms)"
echo "::endgroup::"

# We answered the exit prompt with "Delete", so the session was destroyed and
# must have dropped out of the listing — this doubles as the interactive
# delete/lifecycle-teardown proof.
if mnl ls --raw 2>/dev/null | grep -Fqx "$sid"; then
  echo "::error::session $sid still listed after answering 'Delete' at the exit prompt"
  fail
fi

# ---------------------------------------------------------------------------
# Lifecycle hooks across a daemon restart. Staged around the stop/respawn
# proof below rather than as its own block, because the restart is the point:
# a session's hooks live in a composition snapshot on disk, and a daemon that
# has never composed this session has to reconstruct them from it. Activated
# here, asserted after the respawn.
HOOK_RESTART_SID=""
if [ -n "$SEED_DIR" ] || [ -n "$SEEDED_MFILE" ]; then
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlp2.XXXXXX)"
  {
    hook_seed_preamble
    printf '\n[[session.lifecycle_hooks]]\n'
    printf 'description = "e2e restart survivor"\n'
    # Non-zero for the same reason as the transitions fixture: the WARN
    # record is what carries the output past the session's own lifetime.
    printf 'on_destroy = { type = "inline", value = "echo HOOK_RESTART_OK; exit 3" }\n'
  } > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"
  hook_allow "$HOOK_SEED_DIR"
  HOOK_RESTART_SID="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt 2>"$WORK/hooks-restart.err")" || {
    echo "::error::activation for the hooks-restart proof failed"
    echo "--- stderr ---"; cat "$WORK/hooks-restart.err" 2>/dev/null || true
    fail
  }
  rm -f "$XDG_CONFIG_HOME/minimal/user_policy.toml"
fi

# Shut the daemon down; it must not survive.
# Keep stderr: discarding it leaves a failing stop indistinguishable from every
# other one, and this assertion's error text is the whole diagnosis.
mnl stop >/dev/null 2>"$WORK/stop.err" \
  || { echo "::error::'min stop' failed"; cat "$WORK/stop.err" 2>/dev/null; fail; }

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

# The hooks staged before the stop must have survived it. This daemon never
# composed that session — it is reading the snapshot off disk — so both halves
# are worth asserting: that it can still SAY what the hooks are, and that it
# can still RUN one.
if [ -n "$HOOK_RESTART_SID" ]; then
  echo "::group::lifecycle hooks: survive a daemon restart"
  restart_list="$(mnl session hooks "$HOOK_RESTART_SID" 2>"$WORK/hooks-restart-list.err")"
  if [[ "$restart_list" != *on_destroy* ]]; then
    echo "::error::hooks did not survive the daemon restart: $restart_list"
    echo "--- stderr ---"; cat "$WORK/hooks-restart-list.err" 2>/dev/null || true
    fail
  fi
  mnl session destroy --force "$HOOK_RESTART_SID" >/dev/null 2>&1 \
    || { echo "::error::could not destroy the hooks-restart session"; fail; }
  # Same lane split as the transitions block: the hook's output is only
  # readable where the daemon logs to this host. The listing above already
  # proved the snapshot survived on every lane.
  if hook_log_readable; then
    restart_log=""
    for _ in $(seq 1 40); do
      restart_log="$(hook_log_has HOOK_RESTART_OK)"
      [ -n "$restart_log" ] && break
      sleep 0.25
    done
    if [ -z "$restart_log" ]; then
      echo "::error::on_destroy did not run for a session composed by a previous daemon"
      fail
    fi
  fi
  if mnl ls --raw 2>/dev/null | grep -q -- "$HOOK_RESTART_SID"; then
    echo "::error::the hooks-restart session survived its destroy"
    fail
  fi
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  echo "hooks survive a daemon restart OK (listed, and still executable)"
  echo "::endgroup::"
fi

echo "session e2e OK"
