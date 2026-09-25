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
# Every proof this script can run, as one `case` on the first argument (see
# the dispatch at the bottom). With NO argument every block runs, in exactly
# the order below; with a case name only that proof runs, standalone, against
# the same fresh state dir and seeds the full lane gets. Each proof is
# self-contained: it activates (and destroys) its own sessions.
#   lifecycle                        cold activate → list → warm → destroy
#   session_exec                     `min session exec` in the session's namespaces
#   guest_egress                     curl from inside the session to the internet
#   own_ip                           `--network own_ip` tap + switch attach
#   task_run                         `min task run` / `min session run` loop
#   hooks                            lifecycle hooks, loadouts, patches, shells
#   skip_scaffold                    the daemon-scaffolded blueprint upload lane
#   sandbox                          interactive attach: in-sandbox `min add`
#   restart                          daemon stop → autospawn, hooks survive
#   min_internal_names_through_proxy NET-001..004 through the shipped proxy
#
# Usage: scripts/session-e2e.sh [case]
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
PATCH_SRC_DIR="" # patch sources for the patch-modes proof; removed on teardown
SKIP_SEED_DIR="" # seeded by the skip-lane scaffold proof below; removed on teardown
OWNIP_SEED_DIR="" # seeded by the own-IP proof below; removed on teardown
PROXY_SEED_DIR="" # seeded by the min.internal proxy proof; removed on teardown
PROXY_OWN_SEED_DIR="" # its own-address box's seed; removed on teardown
PROXY_HOST_DIR="" # the host-loopback dir that proof serves; removed on teardown
PROXY_HOST_SRV_PID="" # the host-loopback server it starts; killed on teardown
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
  [ -n "$PATCH_SRC_DIR" ] && rm -rf "$PATCH_SRC_DIR"
  [ -n "$SKIP_SEED_DIR" ] && rm -rf "$SKIP_SEED_DIR"
  [ -n "$OWNIP_SEED_DIR" ] && rm -rf "$OWNIP_SEED_DIR"
  [ -n "$PROXY_SEED_DIR" ] && rm -rf "$PROXY_SEED_DIR"
  [ -n "$PROXY_OWN_SEED_DIR" ] && rm -rf "$PROXY_OWN_SEED_DIR"
  [ -n "$PROXY_HOST_DIR" ] && rm -rf "$PROXY_HOST_DIR"
  if [ -n "$PROXY_HOST_SRV_PID" ]; then
    kill "$PROXY_HOST_SRV_PID" 2>/dev/null || true
  fi
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

# Fixtures and log helpers shared by several proofs (the hooks proofs, the
# restart proof, the min.internal proxy proof), so they are defined once
# here rather than inside whichever proof block happens to run first.
#
# Every fixture below is a project, and a project's hooks only run once the
# user has allow-listed it. Written up front so nothing has to be answered
# interactively — and note this is only writable in advance because the
# policy stores the project path as the CLIENT knows it. A daemon that
# stamped its own per-session workspace copy would make this unmatchable,
# which is what `hooks_gate_refuses_without_an_allow_entry` pins from
# the other side.
hook_allow() {
  mkdir -p "$XDG_CONFIG_HOME/minimal"
  printf '[hooks]\nallow = ["%s"]\n' "$1" > "$XDG_CONFIG_HOME/minimal/user_policy.toml"
}
# `mktemp -d`, then resolve it. macOS's /tmp is a symlink to /private/tmp,
# and `min session activate .` reports the project by its RESOLVED path —
# so an allow entry written against the unresolved one names a project the
# daemon never sees, and the activation fails the gate on that lane only.
# Every fixture goes through here so the path in the policy and the path in
# the record are the same string on every host.
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
# Grep the daemon's file log. The only way to observe a record whose session
# is gone by the time you could look (`on_destroy`), or one the daemon emits
# while serving (a hook's WARN record, a proxy refusal).
hook_log_has() {
  find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f \
    -exec grep -l -- "$1" {} + 2>/dev/null | head -n1
}
# Whether that log is on THIS host. On a VM lane minimald runs inside the
# guest and writes to a guest tmpfs (`/run/minimal`), which no host path
# reaches — the host's log dir holds only `minvmd.log`. So the assertions
# that read daemon-side records are native-only.
#
# What is NOT skipped anywhere: that the destroy still completed. That half
# of the contract ("a failing teardown hook must not block the teardown")
# is asserted off `min ls` on every lane, and `on_detach` — the other
# headless teardown hook — is proved on every lane too, by a marker read
# back through the session rather than out of a log.
hook_log_readable() { [ -z "$E2E_VM" ]; }

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
proof_lifecycle() {
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
}

# ---------------------------------------------------------------------------
# Non-interactive exec proof: `min session exec <sid> '<cmd>'` runs the
# command in the session's namespaces and relays its stdout and exit code. The
# daemon services this by re-execing ITSELF as the nsenter shim, which is a
# different path from the interactive attach below and the one that broke in
# #1175 (in the VM, pid-1's `current_exe()` is the unreachable initramfs
# `/init`, so every exec died with ENOENT while interactive attach worked).
# Ordered before the pty proof, which deletes the session.
proof_session_exec() {
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
# A multi-word argv must reach the session with the quoting the local shell
# already removed. ssh has no argv on the wire — it joins its trailing
# arguments with spaces and the far side reshells the result — so passing them
# through word by word let `sh -c` take LINE1 as its `$0`, so it never printed.
# The client now sends a `min://argv` request carrying the words as data
# (gominimal/inbox#558).
argv_out="$(mnl session exec "$sid" sh -c 'echo LINE1; echo LINE2' 2>"$WORK/exec-argv.err")" || {
  echo "::error::'min session exec $sid sh -c ...' failed"
  echo "--- stderr ---"; cat "$WORK/exec-argv.err" 2>/dev/null || true
  fail
}
if [ "$argv_out" != "$(printf 'LINE1\nLINE2')" ]; then
  echo "::error::multi-word argv lost its quoting: expected 'LINE1/LINE2', got '$argv_out'"
  fail
fi
# A command that merely looks like one of the daemon's own belongs to the
# session. The daemon used to claim every string starting with `min ` and refuse
# what it did not recognise, which made the session's own `min` unreachable
# through exec; only the `min://` scheme addresses the daemon now.
lookalike_err="$WORK/exec-lookalike.err"
mnl session exec "$sid" 'min --version' >"$WORK/exec-lookalike.out" 2>"$lookalike_err"
if grep -q "unsupported command" "$lookalike_err"; then
  echo "::error::the daemon hijacked a session command instead of routing it"
  echo "--- stderr ---"; cat "$lookalike_err"
  fail
fi
echo "session exec proof OK"
echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# Guest egress proof. Every VM lane wires the gvproxy switch for the guest's
# egress (NAT + DNS), yet nothing else here asserts it works — and gvproxy
# resolution is best-effort and never errors, so a lane that silently loses the
# switch boots switchless, has no egress, and still reports green. The symptom
# then reaches a user as a bogus "could not resolve host" that is not a DNS
# problem. Prove reachability from inside the live session: the `shell` stack
# composes curl, so no package is added. Gated on a seed we own, because only
# then is the shell stack (and thus curl) guaranteed present.
#
# What is asserted is what the symptom is: THIS SESSION can reach the internet.
# So the bar is one host answering, over several hosts and several attempts —
# not every host answering first time. Two things taught that. A single attempt
# per host made the lane depend on two third-party endpoints both being up, and
# main went red on a docs-only commit when example.com returned HTTP:200 and
# example.org then lost the TLS handshake (curl 35, HTTP:000) — the first host
# had already proven DNS, NAT and TLS all worked, so the run failed on weather.
# Requiring every host to answer has the same flaw at a longer timescale: an
# endpoint down for the whole retry window still fails a session with provably
# working egress. A switchless boot has no NAT and no DNS, so it fails every
# host on every attempt and is caught exactly as before — that is the thing
# this proof exists to catch, and one host answering cannot mask it.
#
# The cost is that a partial fault — one name resolving, another not — lands as
# a warning rather than a failure. That is the intended trade: the lane is a
# gate on the session, and no CI gate should turn red because example.org is
# having a bad minute.
proof_guest_egress() {
if [ -n "$SEED_DIR" ] || [ -n "$SEEDED_MFILE" ]; then
  echo "::group::guest egress proof (curl from inside the session)"
  egress_ok=0
  egress_total=0
  egress_failed=""
  for egress_host in example.com example.org; do
    egress_total=$((egress_total + 1))
    egress_status=0
    egress_out=""
    for egress_try in 1 2 3; do
      egress_out="$(mnl session exec "$sid" \
        "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 30 https://$egress_host" \
        2>"$WORK/egress.err")"
      egress_status=$?
      if [ "$egress_status" -eq 0 ] && [ "$egress_out" = "HTTP:200" ]; then
        break
      fi
      # Not ::error:: — a retried attempt is not a lane failure, and annotating
      # it would put a red mark on a run that goes on to pass.
      if [ "$egress_try" -lt 3 ]; then
        echo "guest egress to https://$egress_host failed on attempt ${egress_try}/3 (exec status ${egress_status}, got '${egress_out:-<none>}'); retrying in $((egress_try * 3))s"
        cat "$WORK/egress.err" 2>/dev/null || true
        sleep "$((egress_try * 3))"
      fi
    done
    if [ "$egress_status" -eq 0 ] && [ "$egress_out" = "HTTP:200" ]; then
      egress_ok=$((egress_ok + 1))
    else
      egress_failed="${egress_failed} https://$egress_host (exec status ${egress_status}, got '${egress_out:-<none>}')"
      # Warned, not failed: another host answering proves the session's egress,
      # which makes this that endpoint's problem and not the lane's. Still
      # surfaced, so a partial fault is visible instead of silently absorbed.
      echo "::warning::guest egress to https://$egress_host failed all 3 attempts (exec status ${egress_status}, got '${egress_out:-<none>}', want HTTP:200); not fatal while another host still proves the session has egress."
      echo "--- curl stderr ($egress_host) ---"; cat "$WORK/egress.err" 2>/dev/null || true
    fi
  done
  if [ "$egress_ok" -eq 0 ]; then
    echo "::error::guest egress failed every attempt against all ${egress_total} hosts —${egress_failed}: the session has no working egress. On a VM lane (E2E_VM='${E2E_VM:-}') a lost gvproxy switch is one hypothesis — a switchless boot has no NAT/DNS — but a nonzero exec status or a non-200 code can equally be a DNS, TLS/CA, or exec-transport failure; the per-host curl stderr is above and the guest boot console follows in the diagnostics."
    fail
  fi
  echo "guest egress proof OK (DNS + HTTPS reachable from the session; ${egress_ok}/${egress_total} hosts answered)"
  echo "::endgroup::"
fi
}

# ---------------------------------------------------------------------------
# Own-IP proof: a `--network own-ip` session gets a tap of its own, relayed to
# the gvproxy switch. Gated on MINVMD_GVPROXY_BIN, the one signal that a switch
# exists (`just e2e` sets it; `just e2e-native` does not). The relay is
# attached before `activate` returns, so a refused client fails there; the
# namespace side is read from /proc and /etc (a session rootfs has no iproute2)
# in ONE exec, checked at the top level so an exec hiccup is not a net result.
proof_own_ip() {
if [ -n "${MINVMD_GVPROXY_BIN:-}" ]; then
  echo "::group::own-IP session proof (--network own-ip)"
  OWNIP_SEED_DIR="$(mktemp -d /tmp/mnlo.XXXXXX)"
  OWNIP_SEED_DIR="$(cd "$OWNIP_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$OWNIP_SEED_DIR/minimal.toml"
  # The `.git` marker the headless upload gate wants; its own directory, since
  # a path that already has a session does not mint a second one.
  mkdir "$OWNIP_SEED_DIR/.git"

  ownip_sid="$(cd "$OWNIP_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-own-ip --network own-ip 2>"$WORK/ownip.err")" || {
    echo "::error::'min session activate --network own-ip' failed"
    echo "--- stderr ---"; cat "$WORK/ownip.err" 2>/dev/null || true
    fail
  }
  ownip_sid="$(printf '%s\n' "$ownip_sid" | tail -n1 | tr -d '\r')"

  if ! mnl session exec "$ownip_sid" sh -c \
    'echo ---DEV---; cat /proc/net/dev; echo ---ROUTE---; cat /proc/net/route; echo ---RESOLV---; cat /etc/resolv.conf' \
    >"$WORK/ownip-facts.out" 2>"$WORK/ownip-facts.err" || [ ! -s "$WORK/ownip-facts.out" ]; then
    # The captured streams travel in the annotation, workflow-escaped.
    ownip_body=""
    for f in "$WORK/ownip-facts.err" "$WORK/ownip-facts.out" "$WORK/ownip.err"; do
      [ -s "$f" ] || continue
      ownip_body="$ownip_body%0A--- $(basename "$f") ---%0A$(head -c 1200 "$f" | sed 's/%/%25/g; s/\r/%0D/g' | awk '{printf "%s%%0A", $0}')"
    done
    echo "::error::could not read the own-IP session's network state — the probe failed, which says nothing about the tap${ownip_body}"
    echo "--- stdout ---"; cat "$WORK/ownip-facts.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/ownip-facts.err" 2>/dev/null || true
    echo "--- activate stderr ---"; cat "$WORK/ownip.err" 2>/dev/null || true
    fail
  fi
  # Everything between one marker and the next.
  ownip_section() {
    awk -v want="---$1---" '
      $0 == want   { grab = 1; next }
      /^---.*---$/ { grab = 0 }
      grab         { print }
    ' "$WORK/ownip-facts.out"
  }

  # An interface besides `lo`: /proc/net/dev's two header lines carry `|`, every
  # interface line carries `:`, so two or more colons means the tap is there.
  ownip_dev="$(ownip_section DEV)"
  if [ "$(printf '%s\n' "$ownip_dev" | grep -c ':')" -lt 2 ]; then
    echo "::error::own-IP session has no interface besides lo; the tap never came up"
    echo "--- all probed facts ---"; cat "$WORK/ownip-facts.out"
    echo "--- activate stderr ---"; cat "$WORK/ownip.err" 2>/dev/null || true
    fail
  fi

  # A default route on that interface: destination 0.0.0.0, eight zeroes in
  # field 2 of /proc/net/route. Without it the tap would be up but reach nothing.
  ownip_route="$(ownip_section ROUTE)"
  if ! printf '%s\n' "$ownip_route" \
    | awk 'NR > 1 && $2 == "00000000" && $1 != "lo" { found = 1 } END { exit !found }'; then
    echo "::error::own-IP session has no default route off its tap"
    echo "--- all probed facts ---"; cat "$WORK/ownip-facts.out"
    fail
  fi

  # The resolver points at the switch (100.64/16, the default subnet), not at
  # the host stub (127.0.0.53), which is unreachable from a fresh netns. Glob,
  # not `printf | grep -q`: grep's early exit SIGPIPEs the printf under
  # `pipefail` and would read as "not found".
  ownip_resolv="$(ownip_section RESOLV)"
  if [[ "$ownip_resolv" != *"nameserver 100.64."* ]]; then
    echo "::error::own-IP session's resolver does not point at the switch"
    echo "--- all probed facts ---"; cat "$WORK/ownip-facts.out"
    fail
  fi

  mnl session destroy --force "$ownip_sid" >/dev/null 2>&1 || true
  rm -rf "$OWNIP_SEED_DIR"; OWNIP_SEED_DIR=""
  echo "own-IP session proof OK (tap up, default route, switch resolver)"
  echo "::endgroup::"
else
  echo "own-IP session proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
fi
}

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
proof_task_run() {
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
  # `min session run <session> <task>` runs a declared task against a session
  # that already exists, rather than composing one of its own. It reaches the
  # daemon as a named `min://task/run` form, so nothing about the task's name
  # is inferred from the text — the routing a bare string used to decide by
  # prefix-sniffing (gominimal/inbox#558).
  sr_out="$(mnl session run "$kept" e2e-echo 2>"$WORK/session-run.err")"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "::error::'min session run $kept e2e-echo' exited $rc (expected 0)"
    echo "--- stderr ---"; cat "$WORK/session-run.err" 2>/dev/null || true
    fail
  fi
  if [[ "$sr_out" != *TASK_RUN_E2E_OK* ]]; then
    echo "::error::'min session run' did not stream the task's output, got '$sr_out'"
    fail
  fi
  # The task's exit code is the client's, as it is for `min task run`.
  mnl session run "$kept" e2e-fail >/dev/null 2>&1
  rc=$?
  if [ "$rc" -ne 7 ]; then
    echo "::error::'min session run $kept e2e-fail' exited $rc (expected 7)"
    fail
  fi
  echo "session run proof OK (task in an existing session, exit relay 7 → 7)"

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
}

# ---------------------------------------------------------------------------
# Lifecycle-hooks proofs. These are the only coverage of hook execution that
# goes through the real nsenter injection: the unit tests substitute a
# host-side command builder for it, so a break in the injection, in the
# script upload, or in the client/daemon round trip would not show up there.
#
# Seeded projects of their own, like the task-run proof, because the shared
# seed declares no hooks.
proof_hooks() {
if [ -n "$SEED_DIR" ] || [ -n "$SEEDED_MFILE" ]; then
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
  # Leaves by the session detach chord (`E2E_PTY_DETACH`: ctrl-] then d, the
  # shipped default), NOT by `exit`.
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

  # -- Directory-layout loadout ----------------------------------------------
  # The same loadout, filed as `<name>/loadout.toml` instead of `<name>.toml`
  # so it can be kept under version control. The proof is deliberately an
  # EXTERNAL hook script plus a patch, because both anchor at
  # `<loadouts>/<name>/` — which under this layout is the directory holding
  # `loadout.toml` itself. If discovery and anchoring ever disagreed about
  # which directory a loadout owns, the script would fail to stage and the
  # patch would resolve to nothing; neither can pass by accident.
  echo "::group::loadout layouts: <name>/loadout.toml"
  mkdir -p "$XDG_CONFIG_HOME/minimal/loadouts/vcdev"
  cat > "$XDG_CONFIG_HOME/minimal/loadouts/vcdev/loadout.toml" <<'LOADOUT'
description = "e2e directory-layout loadout"

patches = [
  { dest = ".config/vcdev.conf", source = "$LOADOUT_ROOT/vcdev.conf" },
]

[[lifecycle_hooks]]
on_activate = { type = "external", value = "activate.sh" }
LOADOUT
  printf 'VCDEV_PATCH_OK\n' > "$XDG_CONFIG_HOME/minimal/loadouts/vcdev/vcdev.conf"
  # `/usr/bin/bash` for the same reason the external-hook fixture above uses
  # it: it is the interpreter the session is known to have.
  printf '#!/usr/bin/bash\necho HOOK_VCDEV_OK > /home/hook-vcdev\n' \
    > "$XDG_CONFIG_HOME/minimal/loadouts/vcdev/activate.sh"
  chmod +x "$XDG_CONFIG_HOME/minimal/loadouts/vcdev/activate.sh"
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlv.XXXXXX)"
  hook_seed_preamble > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"

  vc_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt --loadout vcdev 2>"$WORK/loadout-vcdev.err")" || {
    echo "::error::activation with a directory-layout loadout failed"
    echo "--- stderr ---"; cat "$WORK/loadout-vcdev.err" 2>/dev/null || true
    fail
  }
  vc_hook="$(mnl session exec "$vc_sid" 'cat /home/hook-vcdev' 2>/dev/null)"
  if [[ "$vc_hook" != *HOOK_VCDEV_OK* ]]; then
    echo "::error::directory-layout loadout's external hook did not run (marker: '$vc_hook')"
    echo "--- activate stderr ---"; cat "$WORK/loadout-vcdev.err" 2>/dev/null || true
    fail
  fi
  vc_patch="$(mnl session exec "$vc_sid" 'cat ~/.config/vcdev.conf' 2>/dev/null)"
  if [[ "$vc_patch" != *VCDEV_PATCH_OK* ]]; then
    echo "::error::\$LOADOUT_ROOT patch from a directory-layout loadout did not land (got: '$vc_patch')"
    echo "--- activate stderr ---"; cat "$WORK/loadout-vcdev.err" 2>/dev/null || true
    fail
  fi
  mnl session destroy --force "$vc_sid" >/dev/null 2>&1 || true
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  rm -rf "$XDG_CONFIG_HOME/minimal/loadouts/vcdev"
  echo "directory-layout loadout proof OK (discovered, \$LOADOUT_ROOT patch + external hook resolved)"
  echo "::endgroup::"

  # -- Patch file modes ------------------------------------------------------
  # A patch's permission bits cross three hops, and each has unit coverage of
  # its own end only: the client stamps the source's mode on the tar header,
  # the daemon applies it when unpacking into `<workspace>/patches/`, and the
  # copy into the session home carries it the rest of the way. A bit dropped
  # anywhere in there makes a patched script silently unrunnable, which is
  # only observable from inside a real session — so it is asserted by RUNNING
  # the patched script, not just by reading its mode back.
  echo "::group::patch file modes"
  PATCH_SRC_DIR="$(hook_mktemp /tmp/mnlpm.XXXXXX)"
  # `/usr/bin/bash`, like the external-hook fixture above: it is the
  # interpreter every lane's session is known to have.
  printf '#!/usr/bin/bash\necho PATCHED_TOOL_OK\n' > "$PATCH_SRC_DIR/tool.sh"
  chmod 755 "$PATCH_SRC_DIR/tool.sh"
  printf 'token = "hunter2"\n' > "$PATCH_SRC_DIR/secret.toml"
  chmod 600 "$PATCH_SRC_DIR/secret.toml"
  mkdir -p "$XDG_CONFIG_HOME/minimal/loadouts"
  {
    printf 'description = "e2e patch modes"\n\n'
    printf 'patches = [\n'
    printf '  { dest = "bin/tool.sh", source = "%s/tool.sh" },\n' "$PATCH_SRC_DIR"
    printf '  { dest = "secret.toml", source = "%s/secret.toml" },\n' "$PATCH_SRC_DIR"
    printf ']\n'
  } > "$XDG_CONFIG_HOME/minimal/loadouts/patchmode.toml"
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlpp.XXXXXX)"
  hook_seed_preamble > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"

  pm_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt --loadout patchmode 2>"$WORK/patch-modes.err")" || {
    echo "::error::activation with a patch-carrying loadout failed"
    echo "--- stderr ---"; cat "$WORK/patch-modes.err" 2>/dev/null || true
    fail
  }
  # `ls -l` rather than `stat -c %a`: portable across whatever the shell stack
  # ships. The leading mode string is the assertion; a trailing ACL/SELinux
  # marker would not disturb a substring match.
  pm_out="$(mnl session exec "$pm_sid" \
    'ls -l /home/bin/tool.sh /home/secret.toml; /home/bin/tool.sh' 2>/dev/null)"
  if [[ "$pm_out" != *"-rwxr-xr-x"* ]]; then
    echo "::error::patched script lost its 0755 mode: '$pm_out'"
    echo "--- activate stderr ---"; cat "$WORK/patch-modes.err" 2>/dev/null || true
    fail
  fi
  if [[ "$pm_out" != *"-rw-------"* ]]; then
    echo "::error::patched secret did not keep its 0600 mode: '$pm_out'"
    fail
  fi
  if [[ "$pm_out" != *PATCHED_TOOL_OK* ]]; then
    echo "::error::patched script was not runnable in the session: '$pm_out'"
    fail
  fi
  mnl session destroy --force "$pm_sid" >/dev/null 2>&1 || true
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  rm -rf "$PATCH_SRC_DIR"; PATCH_SRC_DIR=""
  rm -f "$XDG_CONFIG_HOME/minimal/loadouts/patchmode.toml"
  echo "patch file modes proof OK (0755 runs, 0600 stays private)"
  echo "::endgroup::"

  # -- The session shell -----------------------------------------------------
  # A loadout's `SHELL` picks the shell the attach mints, when the session has
  # it installed. Only an interactive attach can show this: `min session exec`
  # runs `bash -c` through nsenter and never touches the session shell, so it
  # would pass no matter what got spawned. Both cases below need no extra
  # package — `sh` is a symlink the `bash` package ships, and `zsh` is the
  # not-installed case precisely because nothing pulls it in.
  #
  # `$0` is the assertion, not `$SHELL`: it is the shell's own argv[0], so it
  # reports the process that is actually running rather than a variable the
  # daemon also sets. Wrapped in `printf` so the marker appears only in the
  # OUTPUT — the pty echoes what we type, and a bare `echo` of the marker would
  # match its own echo.
  echo "::group::session shell from a loadout's SHELL"
  mkdir -p "$XDG_CONFIG_HOME/minimal/loadouts"
  printf 'description = "e2e session shell"\n\n[vars]\nSHELL = "/usr/bin/sh"\n' \
    > "$XDG_CONFIG_HOME/minimal/loadouts/shelldev.toml"
  # Not installed in this session, so this one must fall back to bash and say
  # so on the terminal.
  printf 'description = "e2e missing shell"\n\n[vars]\nSHELL = "/usr/bin/zsh"\n' \
    > "$XDG_CONFIG_HOME/minimal/loadouts/shellmissing.toml"
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlsh.XXXXXX)"
  hook_seed_preamble > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"

  sh_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt --loadout shelldev 2>"$WORK/shell-sh.err")" || {
    echo "::error::activation with a SHELL-carrying loadout failed"
    echo "--- stderr ---"; cat "$WORK/shell-sh.err" 2>/dev/null || true
    fail
  }
  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  # shellcheck disable=SC2016 # `$0` must reach the SESSION's shell unexpanded.
  sh_out="$(E2E_PTY_COMMANDS='printf "SESSION_SHELL_IS[%s]\n" "$0"
exit' python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min ${E2E_MINIMAL_ARGS:-} session attach "$sh_sid" \
    2>"$WORK/shell-sh-attach.err")" || {
    echo "::error::pty attach for the session-shell proof failed"
    echo "--- transcript ---"; printf '%s\n' "$sh_out"
    echo "--- stderr ---"; cat "$WORK/shell-sh-attach.err" 2>/dev/null || true
    fail
  }
  if [[ "$sh_out" != *"SESSION_SHELL_IS[/usr/bin/sh]"* ]]; then
    echo "::error::loadout SHELL=/usr/bin/sh did not become the session shell"
    echo "--- transcript ---"; printf '%s\n' "$sh_out"
    fail
  fi
  echo "declared shell OK (SHELL=/usr/bin/sh started sh, not bash)"
  # The driver's "Delete" at the exit prompt is not this proof's teardown: the
  # daemon hands a shell's exit to the attached binding best-effort (a
  # non-blocking send it drops when the binding's queue is full — "could not
  # hand the teardown to the binding; no shell-exit prompt will render"), and
  # this shell exits within milliseconds of starting. When the hand-off drops,
  # no prompt renders, the attach still ends cleanly, and the session survives
  # to block the unforced `min stop` below. Destroy it explicitly; a no-op when
  # the prompt already did.
  mnl session destroy --force "$sh_sid" >/dev/null 2>&1 || true

  # The fallback: a shell that isn't installed leaves bash running AND tells
  # the user why, on the terminal, before the first prompt.
  miss_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt --loadout shellmissing 2>"$WORK/shell-missing.err")" || {
    echo "::error::activation with an uninstalled SHELL failed"
    echo "--- stderr ---"; cat "$WORK/shell-missing.err" 2>/dev/null || true
    fail
  }
  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  # shellcheck disable=SC2016 # `$0` must reach the SESSION's shell unexpanded.
  miss_out="$(E2E_PTY_COMMANDS='printf "SESSION_SHELL_IS[%s]\n" "$0"
exit' python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min ${E2E_MINIMAL_ARGS:-} session attach "$miss_sid" \
    2>"$WORK/shell-missing-attach.err")" || {
    echo "::error::pty attach for the shell-fallback proof failed"
    echo "--- transcript ---"; printf '%s\n' "$miss_out"
    echo "--- stderr ---"; cat "$WORK/shell-missing-attach.err" 2>/dev/null || true
    fail
  }
  if [[ "$miss_out" != *"SESSION_SHELL_IS[/usr/bin/bash]"* ]]; then
    echo "::error::an uninstalled SHELL did not fall back to bash"
    echo "--- transcript ---"; printf '%s\n' "$miss_out"
    fail
  fi
  if [[ "$miss_out" != *"min add --session zsh"* ]]; then
    echo "::error::the fallback notice did not reach the terminal"
    echo "--- transcript ---"; printf '%s\n' "$miss_out"
    fail
  fi
  # Same best-effort prompt as above; same explicit teardown.
  mnl session destroy --force "$miss_sid" >/dev/null 2>&1 || true
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  rm -f "$XDG_CONFIG_HOME/minimal/loadouts/shelldev.toml"
  rm -f "$XDG_CONFIG_HOME/minimal/loadouts/shellmissing.toml"
  echo "shell fallback proof OK (bash started, notice names the package)"
  echo "::endgroup::"

  # -- A patched-in .bashrc --------------------------------------------------
  # The session bash is started `--noprofile --rcfile <daemon rc>`, so it finds
  # no startup file by itself: the daemon's rc is what sources the user's.
  # Only an interactive attach can show that — `min session exec` runs
  # `bash -c` through nsenter and reads no rc at all — and only a real session
  # proves the whole hop, since the unit tests run that rc against a temp dir
  # rather than against a patched session home.
  #
  # The second half of the marker is the ORDER: `__minimal_attach_env` is the
  # daemon's `TERM`-refresh hook, defined earlier in the same rc, so a
  # `.bashrc` that can see it is one that ran after the hook went in.
  echo "::group::session bash sources a patched .bashrc"
  PATCH_SRC_DIR="$(hook_mktemp /tmp/mnlrc.XXXXXX)"
  cat > "$PATCH_SRC_DIR/bashrc" <<'BASHRC'
__e2e_hook_seen=no
declare -F __minimal_attach_env >/dev/null && __e2e_hook_seen=yes
export E2E_BASHRC_RAN=yes
BASHRC
  mkdir -p "$XDG_CONFIG_HOME/minimal/loadouts"
  {
    printf 'description = "e2e patched bashrc"\n\n'
    printf 'patches = [\n'
    printf '  { dest = ".bashrc", source = "%s/bashrc" },\n' "$PATCH_SRC_DIR"
    printf ']\n'
  } > "$XDG_CONFIG_HOME/minimal/loadouts/bashrcdev.toml"
  HOOK_SEED_DIR="$(hook_mktemp /tmp/mnlrr.XXXXXX)"
  hook_seed_preamble > "$HOOK_SEED_DIR/minimal.toml"
  mkdir "$HOOK_SEED_DIR/.git"

  rc_sid="$(cd "$HOOK_SEED_DIR" && mnl session activate . --no-prompt --loadout bashrcdev 2>"$WORK/bashrc.err")" || {
    echo "::error::activation with a .bashrc-patching loadout failed"
    echo "--- stderr ---"; cat "$WORK/bashrc.err" 2>/dev/null || true
    fail
  }
  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  # shellcheck disable=SC2016 # both vars must reach the SESSION's shell unexpanded.
  rc_out="$(E2E_PTY_COMMANDS='printf "BASHRC_MARK[%s/%s]\n" "$E2E_BASHRC_RAN" "$__e2e_hook_seen"
exit' python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min ${E2E_MINIMAL_ARGS:-} session attach "$rc_sid" \
    2>"$WORK/bashrc-attach.err")" || {
    echo "::error::pty attach for the patched-.bashrc proof failed"
    echo "--- transcript ---"; printf '%s\n' "$rc_out"
    echo "--- stderr ---"; cat "$WORK/bashrc-attach.err" 2>/dev/null || true
    fail
  }
  if [[ "$rc_out" != *"BASHRC_MARK[yes/yes]"* ]]; then
    echo "::error::the patched ~/.bashrc did not run after the attach-env hook"
    echo "--- transcript ---"; printf '%s\n' "$rc_out"
    fail
  fi
  # Same best-effort exit prompt as the shell proofs above; same explicit
  # teardown.
  mnl session destroy --force "$rc_sid" >/dev/null 2>&1 || true
  rm -rf "$HOOK_SEED_DIR"; HOOK_SEED_DIR=""
  rm -rf "$PATCH_SRC_DIR"; PATCH_SRC_DIR=""
  rm -f "$XDG_CONFIG_HOME/minimal/loadouts/bashrcdev.toml"
  echo "patched .bashrc proof OK (sourced, and after the daemon's hook)"
  echo "::endgroup::"
fi
}
# ---------------------------------------------------------------------------
# Skip-lane scaffold proof (every lane). Every other seed here deliberately
# becomes a VCS root so the headless upload gate ships it; this one does the
# opposite. A non-VCS, non-empty directory with no `minimal.toml` (and no
# explicit `--sync`) is the one shape where the gate SKIPS the upload, so the
# session's blueprint is not the user's — it is the one the daemon scaffolds
# into the workspace. Its packages must reach the box: they used to be decided
# by a composition that ran before the scaffold, so the session came up
# without the packages its own `/workbench/minimal.toml` declared
# (gominimal/inbox#601). Mints its own session; nothing here touches $sid.
proof_skip_scaffold() {
echo "::group::skip-lane scaffold (no VCS root, no minimal.toml: the daemon writes the blueprint)"
SKIP_SEED_DIR="$(mktemp -d /tmp/mnlsc.XXXXXX)"
# Non-empty (an empty dir skips the upload for a different reason), and
# deliberately WITHOUT a `.git` marker or a `minimal.toml` — both would take
# the activation off the skip lane. /tmp has no mfile above it, so the
# client's walk up finds none either.
printf 'skip-lane seed\n' > "$SKIP_SEED_DIR/README"
# `--no-prompt` plus stdin from /dev/null: headless, which is what turns the
# non-VCS upload confirmation into a silent skip.
skip_activate_out="$(cd "$SKIP_SEED_DIR" \
  && mnl session activate . --name e2e-scaffold --no-prompt </dev/null 2>"$WORK/skip-activate.err")" || {
  echo "::error::'min session activate' from a non-VCS dir with no minimal.toml failed"
  echo "--- stdout ---"; printf '%s\n' "$skip_activate_out"
  echo "--- stderr ---"; cat "$WORK/skip-activate.err" 2>/dev/null || true
  fail
}
skip_sid="$(printf '%s\n' "$skip_activate_out" | tail -n1 | tr -d '\r')"
# One exec: the blueprint the daemon wrote, then whether the box carries what
# it declares. `vim` is the discriminator — the scaffold always declares it and
# it is in none of the launcher's baseline packages (base/coreutils/socat), so
# its presence can only have come from the scaffolded mfile.
skip_probe="$(mnl session exec "$skip_sid" \
  'cat /workbench/minimal.toml; command -v vim >/dev/null 2>&1 && echo VIM_PRESENT || echo VIM_ABSENT' \
  2>"$WORK/skip-exec.err")" || {
  echo "::error::'min session exec' against the skip-lane session failed"
  echo "--- stdout ---"; printf '%s\n' "$skip_probe"
  echo "--- stderr ---"; cat "$WORK/skip-exec.err" 2>/dev/null || true
  fail
}
# Glob, never `| grep -q` — same SIGPIPE-under-pipefail reasoning as the
# sandbox proof's markers.
if [[ "$skip_probe" != *'"vim"'* ]]; then
  echo "::error::the daemon-scaffolded /workbench/minimal.toml does not declare vim; the assertion below would prove nothing"
  echo "--- probe ---"; printf '%s\n' "$skip_probe"
  fail
fi
if [[ "$skip_probe" != *VIM_PRESENT* ]]; then
  echo "::error::the session lacks a package its own scaffolded /workbench/minimal.toml declares (gominimal/inbox#601)"
  echo "--- probe ---"; printf '%s\n' "$skip_probe"
  echo "--- activate stderr ---"; cat "$WORK/skip-activate.err" 2>/dev/null || true
  fail
fi
mnl session destroy --force "$skip_sid" >/dev/null 2>&1 || true
rm -rf "$SKIP_SEED_DIR"; SKIP_SEED_DIR=""
echo "skip-lane scaffold proof OK (scaffolded blueprint's packages reached the box)"
echo "::endgroup::"
}

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
proof_sandbox() {
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
if [[ "$attach_out" != *"detach: ctrl-] then d"* ]]; then
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
}

# ---------------------------------------------------------------------------
# Lifecycle hooks across a daemon restart. Staged around the stop/respawn
# proof below rather than as its own block, because the restart is the point:
# a session's hooks live in a composition snapshot on disk, and a daemon that
# has never composed this session has to reconstruct them from it. Activated
# here, asserted after the respawn.
proof_restart() {
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
}

# ---------------------------------------------------------------------------
# `min.internal` names through the shipped hostname proxy, end to end
# (NET-001..NET-004). The proxy minimald already serves — the :7654 egress
# proxy, the one a client reaches as an HTTP(S)_PROXY — is the only thing
# that routes a `<name>.min.internal` request, so this proof drives it the
# way a client does: from inside a real box, through the proxy, at a real
# HTTP responder running in another box. Never by talking to the proxy's
# implementation directly, and never from outside a box — a box is where
# these names live.
#
# Every request is printed with its status and the daemon log line it
# produced, in the order they hit the proxy, so the transcript and the
# daemon log's tail (the `min bug` bundle's first stop) read as the run's
# narrative. A request the proxy ROUTES leaves no record at any level —
# refusals and the deprecation notices are what the proxy logs (that split
# is NET-001's own logging requirement) — so the case says so where it is
# true rather than leaving a hole in the output.
#
# Lane gating, both halves decided by where the shipped surfaces actually
# run:
#   * Own-address boxes exist only where a switch does
#     (`MINVMD_GVPROXY_BIN` — the same gate the own-IP proof uses), and
#     every such lane is VM-backed, so the daemon's records are guest-side.
#   * The daemon's file log is only readable where the daemon is native
#     (`hook_log_readable`). Where it is not, the statuses are still
#     asserted on every lane; the records are named in the output instead.
#
# Host gating, decided the same way — by where the proof's own prerequisites
# actually are, not by naming a host:
#   * A host that is itself a sandbox (a container, a session box this very
#     product hosts) denies the nested mount namespaces a box's rootfs needs,
#     and its session program dies at spawn: no probe inside a box can run.
#     The case says so and keeps the one assertion that survives it — the
#     hostname registration, which is daemon-side and needs no box at all.
#   * A host that already runs a minimald has :7654 — EGRESS_PROXY_PORT, a
#     fixed constant — taken, and this run's daemon never owns it: requests
#     through the proxy would reach a daemon that knows nothing of this
#     run's boxes. The daemon's own `min ls` warning names exactly this, so
#     the case degrades to host.min.internal, the one name requirement that
#     needs no listener, and says what it did not run.
# CI's native lane has neither conflict and runs every assertion.
#
# Ordered LAST in the whole-lane run on purpose: it restarts the daemon (see
# the RUST_LOG note inside) and nothing after it depends on the one before.
proof_min_internal_names_through_proxy() {
  echo "::group::min.internal names through the hostname proxy (NET-001..NET-004)"

  # The daemon's file log, newest first: the log this case's assertions read.
  # One file per calendar day; within a run the newest is the live one.
  proxy_daemon_log() {
    find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null \
      | sort | tail -n1
  }
  # Its current line count (0 when the daemon has not written one yet).
  proxy_daemon_log_lines() {
    local f
    f="$(proxy_daemon_log)"
    if [ -n "$f" ]; then wc -l < "$f"; else printf '0\n'; fi
  }
  # The lines the log gained since its first $1 — the record(s) ONE request
  # produced. The file writer is asynchronous, so callers poll this.
  proxy_daemon_log_since() {
    local f
    f="$(proxy_daemon_log)"
    [ -n "$f" ] || return 0
    tail -n "+$(($1 + 1))" "$f"
  }
  # Prints the daemon record that registered $1's box name — the registration
  # that is WHY the name routes (NET-001's daemon half, the one piece of it
  # every host can prove: no session sandbox and no listener is involved).
  # Asserted, not just shown: a box whose name is not registered cannot
  # route, whatever the host below it can or cannot run.
  proxy_print_registration() {
    hook_log_readable || return 0
    local f line
    for _ in $(seq 1 10); do
      f="$(proxy_daemon_log)"
      if [ -n "$f" ]; then
        line="$(grep -h -- 'registered PTask hostname' "$f" 2>/dev/null \
          | grep -F -- "$1.min.internal" | tail -n1)"
        if [ -n "$line" ]; then
          echo "daemon log: $line"
          return 0
        fi
      fi
      sleep 0.25
    done
    echo "::error::no 'registered PTask hostname' record for $1.min.internal in the daemon log"
    echo "--- daemon log (tail) ---"; tail -20 "$(proxy_daemon_log)" 2>/dev/null || true
    fail
  }

  # One request, reported. Sends GET $3 from inside box $1 — through the
  # shipped proxy at 127.0.0.1:7654 when $4 is "proxy", direct when "" — and
  # prints the two lines the case owes the transcript: the request with its
  # status, and the daemon log line it produced (or why there is none).
  # $5 names the log record the request is expected to produce, which is
  # what the poll below waits for; a routed request takes "" and does not
  # wait long. Sets PROXY_STATUS / PROXY_BODY / PROXY_LOG / PROXY_LABEL for
  # the caller's `proxy_want`.
  proxy_request() {
    local box="$1" label="$2" url="$3" mode="$4" want_log="${5:-}"
    local before out rc i
    PROXY_LABEL="$label"
    before="$(proxy_daemon_log_lines)"
    if [ "$mode" = proxy ]; then
      out="$(mnl session exec "$box" \
        "curl -sS --max-time 20 -x http://127.0.0.1:7654 -o /home/proxy.body -w '%{http_code}' '$url'" \
        2>"$WORK/proxy-curl.err")"
    else
      out="$(mnl session exec "$box" \
        "curl -sS --max-time 20 -o /home/proxy.body -w '%{http_code}' '$url'" \
        2>"$WORK/proxy-curl.err")"
    fi
    rc=$?
    PROXY_STATUS="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r\n')"
    if [ "$rc" -ne 0 ]; then
      echo "::error::$label: curl did not complete the request (exit $rc)"
      echo "--- curl stderr ---"; cat "$WORK/proxy-curl.err" 2>/dev/null || true
      fail
    fi
    PROXY_BODY="$(mnl session exec "$box" 'cat /home/proxy.body' 2>/dev/null || true)"
    echo "$label: GET $url -> HTTP ${PROXY_STATUS:-<none>} ${PROXY_BODY:0:48}"
    if ! hook_log_readable; then
      PROXY_LOG=""
      echo "daemon log: (guest-side daemon on this lane — the statuses above are the assertion)"
      return 0
    fi
    PROXY_LOG=""
    for i in $(seq 1 20); do
      PROXY_LOG="$(proxy_daemon_log_since "$before")"
      if [ -n "$want_log" ]; then
        case "$PROXY_LOG" in
          *"$want_log"*) break ;;
        esac
      elif [ -n "$PROXY_LOG" ]; then
        break
      fi
      [ "$i" -ge 4 ] && [ -z "$want_log" ] && break # a routed request: no record to wait for
      sleep 0.25
    done
    if [ -n "$PROXY_LOG" ]; then
      printf '%s\n' "$PROXY_LOG" | sed 's/^/daemon log: /'
    elif [ "$mode" = proxy ]; then
      echo "daemon log: (no record — the proxy logs refusals and deprecation notices, not the requests it serves)"
    else
      echo "daemon log: (no record — a direct request never reaches the proxy)"
    fi
  }
  # Asserts the last `proxy_request`: $1 = the HTTP status, $2 = a substring
  # the body must carry ("" to skip), $3 = a substring of the daemon log
  # record the request must have left ("" when it must not need one, or on a
  # lane whose log is not readable).
  proxy_want() {
    if [ "${PROXY_STATUS:-}" != "$1" ]; then
      echo "::error::$PROXY_LABEL: expected HTTP $1, got '${PROXY_STATUS:-<none>}'"
      echo "--- curl stderr ---"; cat "$WORK/proxy-curl.err" 2>/dev/null || true
      fail
    fi
    if [ -n "$2" ] && [[ "${PROXY_BODY:-}" != *"$2"* ]]; then
      echo "::error::$PROXY_LABEL: the answer does not carry '$2' (got: '${PROXY_BODY:-<empty>}')"
      fail
    fi
    if [ -n "$3" ] && hook_log_readable && [[ "${PROXY_LOG:-}" != *"$3"* ]]; then
      echo "::error::$PROXY_LABEL: the daemon log record this request must leave ('$3') did not appear"
      echo "--- daemon log (tail) ---"
      tail -20 "$(proxy_daemon_log)" 2>/dev/null || true
      fail
    fi
  }

  # The host-loopback listener NET-003 and NET-004 must reach: a plain
  # python3 http.server bound to the host's loopback (python3 is an e2e
  # prerequisite on every lane). host.min.internal and the deprecated
  # literal both have to land on it — via the box's /etc/hosts natively, via
  # the switch's NAT'd host alias on a VM host — and the marker it serves is
  # what proves the request reached the HOST and not something else.
  # Started only once a probe needs it: the two degradation paths below
  # never start a responder they cannot use.
  proxy_start_host_listener() {
    PROXY_HOST_DIR="$(hook_mktemp /tmp/mnlph.XXXXXX)"
    printf '%s\n' "$PROXY_HOST_MARKER" > "$PROXY_HOST_DIR/marker"
    ( cd "$PROXY_HOST_DIR" && exec python3 -m http.server "$PROXY_HOST_PORT" --bind 127.0.0.1 ) \
      >/dev/null 2>"$WORK/proxy-hostsrv.err" &
    PROXY_HOST_SRV_PID=$!
    for _ in $(seq 1 40); do
      if [ "$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:$PROXY_HOST_PORT/marker" 2>/dev/null || true)" = "200" ]; then
        return 0
      fi
      sleep 0.25
    done
    echo "::error::the host-loopback http.server never answered on 127.0.0.1:$PROXY_HOST_PORT"
    echo "--- server stderr ---"; cat "$WORK/proxy-hostsrv.err" 2>/dev/null || true
    fail
  }

  # NET-003 from one box: host.min.internal must land on the host's
  # loopback, straight from the box (no proxy in the picture — this is the
  # one name requirement a host that cannot serve :7654 can still prove).
  # $1 = the box's session id, $2 = the label the prints carry.
  proxy_assert_host_by_name() {
    proxy_request "$1" "$2: host.min.internal reaches the host's loopback" \
      "http://host.min.internal:$PROXY_HOST_PORT/marker" direct ""
    proxy_want 200 "$PROXY_HOST_MARKER" ""
    # What the box resolved the name to. Native: 127.0.0.1, written into the
    # box's /etc/hosts by the HostNet plan — asserted, it is pinned. VM: the
    # switch zone's host alias, which gvproxy NATs to the host's loopback —
    # printed, not asserted, so a lane on a custom subnet does not fail here.
    mnl session exec "$1" \
      "curl -sv --max-time 10 -o /dev/null http://host.min.internal:$PROXY_HOST_PORT/marker" \
      >/dev/null 2>"$WORK/proxy-hostresolve.err" || true
    proxy_resolved="$(grep -m1 'Connected to host.min.internal' "$WORK/proxy-hostresolve.err" || true)"
    echo "$2: host.min.internal resolved in the box: ${proxy_resolved:-<curl never connected>}"
    if hook_log_readable && [[ "$proxy_resolved" != *"127.0.0.1"* ]]; then
      echo "::error::host.min.internal did not resolve to the host's loopback in the box (expected 127.0.0.1)"
      echo "--- curl -v ---"; cat "$WORK/proxy-hostresolve.err" 2>/dev/null || true
      fail
    fi
  }

  # The daemon's filter comes from RUST_LOG at spawn, and this lane runs it
  # at `warn` — which drops the INFO records half this case is about: the
  # NET-002 deprecation notice and the hostname registrations. Restart so
  # the daemon this case talks to runs with minimald's net modules at info
  # (the CLI's own modules stay at warn, so the session-id extraction every
  # proof uses is untouched). Only worth doing where the log is readable; a
  # VM lane's daemon keeps its records guest-side either way. Sessions
  # survive a daemon restart (the restart proof pins that), and none is
  # live by the time the whole-lane run reaches here.
  if hook_log_readable; then
    mnl stop >/dev/null 2>&1 || true # a standalone run has no daemon yet
    export RUST_LOG="warn,minimald::net::dns=info,minimald::net::switch=info"
  fi

  # The names, ports and markers. Ports are fixed on purpose — they must
  # agree across the execs that start and probe each responder — and high
  # enough to need no privilege.
  PROXY_NAME="e2e-proxy"             # the host-address box, the request origin
  PROXY_OWN_NAME="e2e-own-proxy"     # the own-address box, on switch lanes
  PROXY_BOX_PORT=18080               # the in-box responders' listen port
  PROXY_OWN_EXTERNAL_PORT=18082      # ... published externally by --ingress
  PROXY_HOST_PORT=18081              # the host-loopback listener (NET-003/004)
  PROXY_DEAD_PORT=19090              # nothing listens: an upstream-refused 502
  PROXY_CLOSED_PORT=19091            # not in the own box's ingress map: a 403
  PROXY_HOST_ALIAS="100.64.255.254"  # the deprecated literal (NET-004)
  PROXY_BOX_MARKER="PROXY_ROUTED_OK" # what the in-box responders answer with
  PROXY_HOST_MARKER="HOST_LOOPBACK_OK" # what the host-loopback server answers

  # The request origin: a host-address box (the default network), sharing
  # its host's loopback — which is how it reaches the proxy at all, on every
  # lane (natively the host's loopback; on a VM lane the guest's, where the
  # in-guest daemon serves :7654).
  PROXY_SEED_DIR="$(hook_mktemp /tmp/mnlpr.XXXXXX)"
  hook_seed_preamble > "$PROXY_SEED_DIR/minimal.toml"
  mkdir "$PROXY_SEED_DIR/.git"
  proxy_sid="$(cd "$PROXY_SEED_DIR" && mnl session activate . --no-prompt \
    --name "$PROXY_NAME" 2>"$WORK/proxy-activate.err")" || {
    echo "::error::'min session activate' for the proxy proof's origin box failed"
    echo "--- stderr ---"; cat "$WORK/proxy-activate.err" 2>/dev/null || true
    fail
  }
  proxy_sid="$(printf '%s\n' "$proxy_sid" | tail -n1 | tr -d '\r')"
  proxy_print_registration "$PROXY_NAME"

  # ---- capability gates: what THIS host can run ---------------------------
  # The proof's assertions are about a box, a proxy and a host loopback, and
  # a host can lack any of them. Both gates degrade by observed fact, not by
  # host detection, and say exactly what they skipped — the own-IP proof's
  # switch gate is the precedent. CI's native lane runs everything.
  #
  # 1. The session's sandbox program. A host that is itself a sandbox — a
  #    plain container, or a session box like the ones this product hosts —
  #    denies the nested mount namespaces a box's rootfs needs, and the
  #    session program then dies at spawn: no probe inside the box can run.
  #    One throwaway exec decides; the registration above already proved the
  #    daemon half of NET-001 on its own.
  if ! mnl session exec "$proxy_sid" 'true' >"$WORK/proxy-execgate.err" 2>&1 \
     && ! { sleep 1; mnl session exec "$proxy_sid" 'true' >"$WORK/proxy-execgate.err" 2>&1; }; then
    echo "min.internal proxy proof SKIPPED — this host cannot run a session sandbox"
    echo "  (exec: $(head -n1 "$WORK/proxy-execgate.err" 2>/dev/null || true))"
    if hook_log_readable; then
      echo "  asserted here: the registration record above, the daemon half of NET-001."
      echo "  routing, refusals and the deprecation notices need a host whose boxes can"
      echo "  run; the native CI lane runs all of them"
    else
      echo "  a VM lane's boxes run inside its guest, so this is a lane-level fault:"
      echo "  nothing this case asserts can run without them"
    fi
    mnl session destroy --force "$proxy_sid" >/dev/null 2>&1 || true
    echo "::endgroup::"
    return 0
  fi

  # 2. The hostname proxy's listen address. EGRESS_PROXY_PORT is fixed at
  #    7654 (crates/minimald/src/net/proxy.rs), and a host that already runs
  #    a minimald — a dev box serving its own sessions — has it taken: this
  #    run's daemon retries with backoff and never owns the port, and every
  #    probe through the proxy would reach a daemon that knows nothing about
  #    this run's boxes. `min ls` carries exactly that warning, so the warning
  #    IS the gate. It gets a few seconds to clear first — the whole-lane run
  #    restarts the daemon just above, and the stop-race with the proof before
  #    this one must not read as a conflict — then degrades to the one name
  #    requirement that needs no listener at all.
  proxy_bind_taken=0
  for _ in 1 2 3 4 5; do
    proxy_ls_out="$(mnl ls 2>&1)"
    case "$proxy_ls_out" in
      *"session hostnames will not route"*) proxy_bind_taken=1 ;;
      *) proxy_bind_taken=0; break ;;
    esac
    [ "$_" = 5 ] || sleep 3
  done
  if [ "$proxy_bind_taken" -eq 1 ]; then
    proxy_start_host_listener
    proxy_assert_host_by_name "$proxy_sid" "NET-003 (degraded)"
    echo "min.internal proxy routing SKIPPED — another daemon owns 127.0.0.1:7654 on this host"
    echo "  asserted here: host.min.internal, straight from the box"
    hook_log_readable && echo "  and the registration record above, the daemon half of NET-001"
    echo "  routing and the refusals need this run's daemon to own :7654, and the"
    echo "  native CI lane has no such conflict"
    mnl session destroy --force "$proxy_sid" >/dev/null 2>&1 || true
    echo "::endgroup::"
    return 0
  fi

  proxy_start_host_listener

  # socat carries the in-box responder below. It is a launcher baseline
  # package (crates/minimald/src/session_host.rs BASELINE_PACKAGES), so every
  # box ships it — at /usr/bin: packages install with --prefix=/usr, and the
  # generic rootfs has no /bin, so the case says the absolute path, the
  # daemon's own convention for in-box argv, rather than lean on PATH.
  mnl session exec "$proxy_sid" 'test -x /usr/bin/socat' >/dev/null 2>&1 \
    || { echo "::error::the session has no socat at /usr/bin/socat (a launcher baseline package — every box ships one)"; fail; }
  # The responder this box serves: one fixed 200 whose body is the marker,
  # written by the SESSION's shell so the Content-Length can never drift
  # from the body it frames (the format is double-quoted there on purpose —
  # ${#body} is the session shell's own arithmetic), then socat serving it
  # per connection.
  mnl session exec "$proxy_sid" \
    "body=$PROXY_BOX_MARKER; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/http200" \
    >/dev/null 2>"$WORK/proxy-responder.err" \
    || { echo "::error::could not write the in-box responder's response"; cat "$WORK/proxy-responder.err" 2>/dev/null || true; fail; }
  # `nohup ... >/dev/null 2>&1 &` is the documented detach form
  # (docs/reference/cli-min.md, `session exec`): the listener has to outlive
  # the exec that starts it, and every probe below is its own exec.
  mnl session exec "$proxy_sid" \
    "nohup /usr/bin/socat TCP-LISTEN:$PROXY_BOX_PORT,reuseaddr,fork SYSTEM:\"cat /home/http200\" >/dev/null 2>&1 &" \
    >/dev/null 2>"$WORK/proxy-responder.err" \
    || { echo "::error::could not start the in-box responder"; cat "$WORK/proxy-responder.err" 2>/dev/null || true; fail; }
  proxy_responder_ready=""
  for _ in $(seq 1 40); do
    if [ "$(mnl session exec "$proxy_sid" \
      "curl -sS --max-time 5 -o /home/ready.body -w '%{http_code}' http://127.0.0.1:$PROXY_BOX_PORT/" \
      2>/dev/null || true)" = "200" ]; then
      proxy_responder_ready=1; break
    fi
    sleep 0.25
  done
  if [ -z "$proxy_responder_ready" ]; then
    echo "::error::the in-box responder never answered a direct curl — the proxy is not in the picture yet"
    echo "--- socat exec stderr ---"; cat "$WORK/proxy-responder.err" 2>/dev/null || true
    fail
  fi

  # ---- NET-001: a live box's two-label name routes to that box -----------
  proxy_request "$proxy_sid" "NET-001: a live box's name routes through the proxy" \
    "http://$PROXY_NAME.min.internal:$PROXY_BOX_PORT/" proxy ""
  proxy_want 200 "$PROXY_BOX_MARKER" ""

  # ---- NET-002: the deprecated three-label form routes the same ----------
  # `<name>.<host-id>.min.internal` (host id `local`, the daemon default)
  # must still reach the box AND say so in the log.
  proxy_request "$proxy_sid" "NET-002: the three-label form routes (and is noticed)" \
    "http://$PROXY_NAME.local.min.internal:$PROXY_BOX_PORT/" proxy \
    'deprecated three-label hostname'
  proxy_want 200 "$PROXY_BOX_MARKER" 'deprecated three-label hostname'
  # The daemon's file log is JSON lines, so the fields read
  # `"two_label":"<name>"` — the pattern below is that shape.
  if hook_log_readable; then
    case "$PROXY_LOG" in
      *"two_label\":\"$PROXY_NAME.min.internal\""*) ;;
      *)
        echo "::error::NET-002: the deprecation notice does not name the two-label form"
        echo "--- notice record ---"; printf '%s\n' "$PROXY_LOG"
        fail
        ;;
    esac
  fi

  # ---- NET-001: every refusal, and each one logged ------------------------
  # No live box owns the name: a clean gateway error, logged.
  proxy_request "$proxy_sid" "NET-001 refusal: no live box owns the name" \
    "http://e2e-ghost-e2e.min.internal:$PROXY_BOX_PORT/" proxy \
    'no live box owns this hostname'
  proxy_want 502 "" 'no live box owns this hostname'
  if hook_log_readable; then
    case "$PROXY_LOG" in
      *"host\":\"e2e-ghost-e2e.min.internal\""*) ;;
      *)
        echo "::error::the refusal record does not name the host that was asked for"
        echo "--- refusal record ---"; printf '%s\n' "$PROXY_LOG"
        fail
        ;;
    esac
  fi

  # A live box, a dead port: the upstream refused the connection.
  proxy_request "$proxy_sid" "NET-001 refusal: the upstream box refused the connection" \
    "http://$PROXY_NAME.min.internal:$PROXY_DEAD_PORT/" proxy \
    'the upstream box refused the connection'
  proxy_want 502 "" 'the upstream box refused the connection'

  # A request head the proxy cannot parse: 400, logged like every refusal.
  # curl cannot send this, so write the head by hand over the connection.
  proxy_bogus="$(mnl session exec "$proxy_sid" \
    "printf 'BOGUS-REQUEST-HEAD\r\n\r\n' | /usr/bin/socat -t 3 - TCP:127.0.0.1:7654" \
    2>"$WORK/proxy-bogus.err" || true)"
  if [[ "$proxy_bogus" != *"400 Bad Request"* ]]; then
    echo "::error::an unparseable request head did not get the proxy's 400 (got: '$proxy_bogus')"
    echo "--- socat stderr ---"; cat "$WORK/proxy-bogus.err" 2>/dev/null || true
    fail
  fi
  echo "NET-001 refusal: an unparseable head -> HTTP 400 Bad Request"
  if hook_log_readable; then
    proxy_bogus_log=""
    for _ in $(seq 1 10); do
      proxy_bogus_log="$(grep -h -- 'unparseable request head' "$(proxy_daemon_log)" 2>/dev/null | tail -n1)"
      [ -n "$proxy_bogus_log" ] && break
      sleep 0.25
    done
    if [ -z "$proxy_bogus_log" ]; then
      echo "::error::the proxy did not log the 400 refusal (no 'unparseable request head' record)"
      fail
    fi
    echo "daemon log: $proxy_bogus_log"
  fi

  # ---- NET-003: host.min.internal from a host-address box -------------------
  proxy_assert_host_by_name "$proxy_sid" "NET-003"

  # ---- NET-001's own-address half: a VM host's lease route -----------------
  # Gated like the own-IP proof: MINVMD_GVPROXY_BIN is the one signal that a
  # switch exists. On every lane that sets it the daemon is in a VM, so its
  # records are guest-side and the statuses carry the assertion.
  PROXY_OWN_SID=""
  if [ -n "${MINVMD_GVPROXY_BIN:-}" ]; then
    PROXY_OWN_SEED_DIR="$(hook_mktemp /tmp/mnlpo.XXXXXX)"
    hook_seed_preamble > "$PROXY_OWN_SEED_DIR/minimal.toml"
    mkdir "$PROXY_OWN_SEED_DIR/.git"
    PROXY_OWN_SID="$(cd "$PROXY_OWN_SEED_DIR" && mnl session activate . --no-prompt \
      --name "$PROXY_OWN_NAME" --network own_ip \
      --ingress "$PROXY_OWN_EXTERNAL_PORT:$PROXY_BOX_PORT" 2>"$WORK/proxy-own.err")" || {
      echo "::error::'min session activate --network own_ip --ingress ...' failed"
      echo "--- stderr ---"; cat "$WORK/proxy-own.err" 2>/dev/null || true
      fail
    }
    PROXY_OWN_SID="$(printf '%s\n' "$PROXY_OWN_SID" | tail -n1 | tr -d '\r')"
    proxy_print_registration "$PROXY_OWN_NAME"

    # The responder inside the own-address box, on the INTERNAL port the
    # ingress declaration publishes (the proxy dials the lease at the mapped
    # internal port, and the box's ingress gate admits exactly those).
    mnl session exec "$PROXY_OWN_SID" \
      "body=$PROXY_BOX_MARKER; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/http200" \
      >/dev/null 2>"$WORK/proxy-own-responder.err" \
      || { echo "::error::could not write the own-address box's response"; cat "$WORK/proxy-own-responder.err" 2>/dev/null || true; fail; }
    mnl session exec "$PROXY_OWN_SID" \
      "nohup /usr/bin/socat TCP-LISTEN:$PROXY_BOX_PORT,reuseaddr,fork SYSTEM:\"cat /home/http200\" >/dev/null 2>&1 &" \
      >/dev/null 2>"$WORK/proxy-own-responder.err" \
      || { echo "::error::could not start the own-address box's responder"; cat "$WORK/proxy-own-responder.err" 2>/dev/null || true; fail; }
    proxy_own_ready=""
    for _ in $(seq 1 40); do
      if [ "$(mnl session exec "$PROXY_OWN_SID" \
        "curl -sS --max-time 5 -o /home/ready.body -w '%{http_code}' http://127.0.0.1:$PROXY_BOX_PORT/" \
        2>/dev/null || true)" = "200" ]; then
        proxy_own_ready=1; break
      fi
      sleep 0.25
    done
    if [ -z "$proxy_own_ready" ]; then
      echo "::error::the own-address box's responder never answered a direct curl"
      echo "--- socat exec stderr ---"; cat "$WORK/proxy-own-responder.err" 2>/dev/null || true
      fail
    fi

    # Its PUBLISHED port routes to the box's lease — straight to it, on the
    # switch, not via any host-side forwarder.
    proxy_request "$proxy_sid" "NET-001: an own-address box's published port routes to its lease" \
      "http://$PROXY_OWN_NAME.min.internal:$PROXY_OWN_EXTERNAL_PORT/" proxy ""
    proxy_want 200 "$PROXY_BOX_MARKER" ""

    # A port the box never published: refused at the proxy, where the host,
    # the session and the port are all in hand — never dialed into a gate
    # that would only drop the SYN.
    proxy_request "$proxy_sid" "NET-001 refusal: an own-address box's unpublished port" \
      "http://$PROXY_OWN_NAME.min.internal:$PROXY_CLOSED_PORT/" proxy \
      'the box has not published this port'
    proxy_want 403 "" 'the box has not published this port'

    # NET-003's own-address half: the box resolves host.min.internal through
    # the switch zone, to the alias gvproxy NATs to the host's loopback.
    proxy_assert_host_by_name "$PROXY_OWN_SID" "NET-003 (own-address box)"

    # NET-004: the deprecated literal itself. It must still reach the host's
    # loopback, and the box's egress relay must notice the connection — the
    # notice is the reason the address is deprecated. The relay runs in the
    # daemon (in-guest on every switch lane today), so its record is
    # readable exactly where the daemon is native; the lanes that have a
    # switch and an in-guest daemon assert the routing and name the notice,
    # which the switch.rs unit tests pin.
    proxy_request "$PROXY_OWN_SID" "NET-004: the deprecated literal still reaches the host's loopback" \
      "http://$PROXY_HOST_ALIAS:$PROXY_HOST_PORT/marker" direct ""
    proxy_want 200 "$PROXY_HOST_MARKER" ""
    if hook_log_readable; then
      proxy_notice=""
      for _ in $(seq 1 10); do
        proxy_notice="$(grep -h -- 'deprecated literal host address' "$(proxy_daemon_log)" 2>/dev/null | tail -n1)"
        [ -n "$proxy_notice" ] && break
        sleep 0.25
      done
      if [ -z "$proxy_notice" ]; then
        echo "::error::the box's egress relay did not log the connection to the deprecated literal"
        fail
      fi
      echo "daemon log: $proxy_notice"
    else
      echo "NET-004 notice: (guest-side daemon log on this lane; its emission is pinned by the switch.rs unit tests)"
    fi

    mnl session destroy --force "$PROXY_OWN_SID" >/dev/null 2>&1 || true
  else
    echo "own-address half SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
  fi

  mnl session destroy --force "$proxy_sid" >/dev/null 2>&1 || true
  echo "min.internal names through the proxy OK (routed, refused, deprecated, resolved — each printed with its daemon log line)"
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# Dispatch on the first argument: every proof in today's order when none is
# given, or exactly the named one. The names are the proof functions' suffixes.
case "${1:-}" in
  "")
    proof_lifecycle
    proof_session_exec
    proof_guest_egress
    proof_own_ip
    proof_task_run
    proof_hooks
    proof_skip_scaffold
    proof_sandbox
    proof_restart
    proof_min_internal_names_through_proxy
    ;;
  lifecycle | session_exec | guest_egress | own_ip | task_run | hooks \
    | skip_scaffold | sandbox | restart | min_internal_names_through_proxy)
    "proof_$1"
    ;;
  *)
    echo "usage: $0 [case]"
    echo "  no argument: every proof, in the whole-lane order"
    echo "  cases: lifecycle session_exec guest_egress own_ip task_run hooks"
    echo "         skip_scaffold sandbox restart min_internal_names_through_proxy"
    exit 2
    ;;
esac

echo "session e2e OK"
