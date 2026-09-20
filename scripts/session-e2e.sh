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
#   E2E_CASE            run ONE named case (a `case_<name>` function below)
#                       alone after the shared setup, instead of the whole
#                       sequence; the first positional argument means the
#                       same. An unknown name exits 2.
#
# Usage: scripts/session-e2e.sh [<case>]
#   With no case: the whole proof. With a case (or E2E_CASE=<case>): only that
#   case, which activates its own session, and the script exits with its
#   result. An unknown case exits 2. Known cases:
#     min_internal_names_through_proxy
#     fresh_install_own_ip_ingress_publishes_loopback
#     session_outbound_request
#     native_resolution_without_proxy_env
#     own_ip_egress_declared_and_enforced
#     network_posture_from_stock_install
#     escape_reaches_only_declared_union
#     box_name_resolves_natively_without_proxy
#     fresh_linux_kvm_activate_local_minvmd
#     fresh_arm64_kvm_activate_local_minvmd
#     hostnames_recover_and_two_daemons_route
#     proxy_refuses_like_direct
#     port_publishes_on_listen_and_box_outlives_client
#     github_only_allowlist
#     expose_from_inside_box
#     two_named_vms_on_one_machine
#     bep_second_box_needs_no_sign_in
#     bep_box_env_holds_sealed_value_only
#     bep_root_ca_present_in_box_trust_store
#     bep_proxy_env_and_no_proxy_are_set
#     bep_git_and_gh_against_private_repo
#     bep_first_slice_no_plaintext_anywhere
#     bep_stopped_box_values_refused_within_60s
#     bep_logout_refuses_all_members_within_60s
#     bep_store_reference_reaches_upstream_without_key_in_box
#     bep_claude_code_and_mcp_client_send_handle_unmodified
set -uo pipefail # not -e: capture failures so we can dump diagnostics

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_VM="${E2E_VM:-}"
E2E_CASE="${E2E_CASE:-${1:-}}"

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
BEP_SEED_DIR="" # seeded by the bep grant case below; removed on teardown
BEP_REF_SEEDS="" # the bep reference cases' seeds, space-separated; removed on teardown
OUTBOUND_SEED_DIR="" # seeded by the outbound-reach case below; removed on teardown
NATRES_SEED_DIR="" # seeded by the native resolution proof below; removed on teardown
NATRES_REMOVE=""   # the `min net setup --remove` that undoes that proof's install
BOXID_SEED_DIR=""  # seeded by the box-identity proof's first box; removed on teardown
BOXID_SEED_DIR2="" # seeded by the box-identity proof's second box; removed on teardown
BOXID_REMOVE=""    # the `min net setup --remove` that undoes that proof's install
HR_VM_SEED_DIR=""  # seeded by the two-daemons proof's VM session below; removed on teardown
GHA_SEED_DIRS=""   # seeded dirs (space-separated) for the box-to-box allowlist proof; removed on teardown
HR_OCCUPIER_PID=""       # the two-daemons proof's port-occupier; killed on teardown
HR_NATIVE_SOCAT_PID=""   # the two-daemons proof's native responder; killed on teardown
HR_VM_SOCAT_PID=""       # the two-daemons proof's VM responder; killed on teardown
PRD_SEED_DIR=""    # seeded by the proxy-honours-the-same-rules proof below; removed on teardown
EXPOSE_SEED_DIR=""  # seeded by the min-net-expose proof below; removed on teardown
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
  [ -n "$BEP_SEED_DIR" ] && rm -rf "$BEP_SEED_DIR"
  # Word-splitting is intended: one seed dir per reference-case spec.
  # shellcheck disable=SC2086
  [ -n "$BEP_REF_SEEDS" ] && rm -rf $BEP_REF_SEEDS
  [ -n "$OUTBOUND_SEED_DIR" ] && rm -rf "$OUTBOUND_SEED_DIR"
  [ -n "$NATRES_SEED_DIR" ] && rm -rf "$NATRES_SEED_DIR"
  [ -n "$BOXID_SEED_DIR" ] && rm -rf "$BOXID_SEED_DIR"
  [ -n "$BOXID_SEED_DIR2" ] && rm -rf "$BOXID_SEED_DIR2"
  [ -n "$HR_VM_SEED_DIR" ] && rm -rf "$HR_VM_SEED_DIR"
  [ -n "$PRD_SEED_DIR" ] && rm -rf "$PRD_SEED_DIR"
  [ -n "$EXPOSE_SEED_DIR" ] && rm -rf "$EXPOSE_SEED_DIR"
  # shellcheck disable=SC2086 # a space-separated list of dirs on purpose.
  [ -n "$GHA_SEED_DIRS" ] && rm -rf $GHA_SEED_DIRS
  # The two-daemons proof's port-occupier and responders: backgrounded, and
  # only reaped on that proof's own happy path, so a `fail` partway through
  # (occupier still up to 300s, socat responders up to their -T30 idle
  # timeout) would otherwise outlive the case and hold the loopback port.
  [ -n "$HR_OCCUPIER_PID" ] && { kill "$HR_OCCUPIER_PID" 2>/dev/null || true; }
  [ -n "$HR_NATIVE_SOCAT_PID" ] && { kill "$HR_NATIVE_SOCAT_PID" 2>/dev/null || true; }
  [ -n "$HR_VM_SOCAT_PID" ] && { kill "$HR_VM_SOCAT_PID" 2>/dev/null || true; }
  # Undo the privileged resolver setup the native resolution proof installed,
  # so the runner is left as it was found (the hook would otherwise outlive
  # the daemon it points at).
  # shellcheck disable=SC2086 # the remove command is a word list on purpose.
  [ -n "$NATRES_REMOVE" ] && { sudo -n $NATRES_REMOVE >/dev/null 2>&1 || true; }
  # shellcheck disable=SC2086 # the remove command is a word list on purpose.
  [ -n "$BOXID_REMOVE" ] && { sudo -n $BOXID_REMOVE >/dev/null 2>&1 || true; }
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

# ---------------------------------------------------------------------------
# Named cases: each is a `case_<name>` function selected by E2E_CASE and run
# alone after the shared setup (workdir, seed, hermetic config). The legacy
# sequence below runs only when no case is selected.
# ---------------------------------------------------------------------------

# BEP-003: a box declaring a GitHub grant is created while a sign-in is held
# without any sign-in prompt, and fails with the defined error
# `github_sign_in_required` — again with no prompt — while none is held.
# Which half runs depends on `min auth status` on THIS host: CI holds no
# sign-in (a Linux host has no keychain backend at all), so it proves the
# refusal half and says the held half was not exercised; an operator signed
# in with `min auth login` proves the held half. Both halves close stdin, so
# a prompt would die on EOF instead of hanging the lane.
case_bep_second_box_needs_no_sign_in() {
  echo "::group::bep: a box declaring a GitHub grant needs no sign-in prompt"
  BEP_SEED_DIR="$(mktemp -d /tmp/mnlbep.XXXXXX)"
  cp "$PROJECT_DIR/minimal.toml" "$BEP_SEED_DIR/minimal.toml"
  mkdir "$BEP_SEED_DIR/.git"
  # The grant, with the GitHub host set admitted and explicit `proxy_env`
  # steering (the default `dns` is refused until the box-zone resolver
  # exists). `mode` is left to the CLI's default, so the box needs no
  # own-IP networking on lanes without gvproxy.
  cat >>"$BEP_SEED_DIR/minimal.toml" <<'EOF'

[session.network.egress]
allow_dns_hosts = ["github.com", "api.github.com", "uploads.github.com", "codeload.github.com"]

[session.network.bep]
steering = "proxy_env"

[[session.grants]]
module = "github"
env = "GITHUB_TOKEN"
source = "broker"
EOF
  local held=""
  if mnl auth status >"$WORK/auth-status.out" 2>&1 \
      && grep -q "signed in as" "$WORK/auth-status.out"; then
    held=1
  fi
  if [ -n "$held" ]; then
    # Held: the first box AND a second one, each created with no prompt.
    local n bep_out bep_sid
    for n in 1 2; do
      bep_out="$(cd "$BEP_SEED_DIR" \
        && mnl session activate . --name "e2e-bep-$n" --no-input </dev/null 2>"$WORK/bep-activate-$n.err")" || {
        echo "::error::box $n declaring a GitHub grant was not created while a sign-in is held"
        echo "--- stdout ---"; printf '%s\n' "$bep_out"
        echo "--- stderr ---"; cat "$WORK/bep-activate-$n.err" 2>/dev/null || true
        fail
      }
      bep_sid="$(printf '%s\n' "$bep_out" | tail -n1 | tr -d '\r')"
      if grep -q -i -E 'sign.in|min auth login' "$WORK/bep-activate-$n.err"; then
        echo "::error::box $n's activation raised the sign-in while one is held"
        echo "--- stderr ---"; cat "$WORK/bep-activate-$n.err"
        fail
      fi
      mnl session destroy --force "$bep_sid" >/dev/null 2>&1 \
        || { echo "::error::could not destroy box $n ($bep_sid)"; fail; }
    done
    echo "two boxes declaring a GitHub grant created with no sign-in prompt OK"
  else
    echo "no GitHub sign-in is held on this host: the held half is not exercised here"
    # Not held: exit 3, the defined error on stderr, no prompt, no box.
    local bep_rc=0 bep_out
    bep_out="$(cd "$BEP_SEED_DIR" \
      && mnl session activate . --name e2e-bep-refused --no-input </dev/null 2>"$WORK/bep-refused.err")" || bep_rc=$?
    if [ "$bep_rc" != 3 ]; then
      echo "::error::a box declaring a GitHub grant with no sign-in held exited $bep_rc, not 3"
      echo "--- stdout ---"; printf '%s\n' "$bep_out"
      echo "--- stderr ---"; cat "$WORK/bep-refused.err" 2>/dev/null || true
      fail
    fi
    if ! grep -q "github_sign_in_required" "$WORK/bep-refused.err"; then
      echo "::error::the refusal does not name the defined error github_sign_in_required"
      echo "--- stderr ---"; cat "$WORK/bep-refused.err" 2>/dev/null || true
      fail
    fi
    if mnl ls 2>/dev/null | grep -q "e2e-bep-refused"; then
      echo "::error::a box was created despite the refusal"
      fail
    fi
    echo "grant with no sign-in held: exit 3, github_sign_in_required, no prompt, no box OK"
  fi
  rm -rf "$BEP_SEED_DIR"; BEP_SEED_DIR=""
  echo "::endgroup::"
}

# The three proxy-steered proofs below (BEP-007, BEP-011, BEP-012) share one
# box: a GitHub grant under `proxy_env` steering with one `no_proxy` entry of
# its own. As in the case above, which half runs depends on the sign-in held
# on THIS host: with none (every CI lane) the refusal half is proved — exit 3,
# `github_sign_in_required`, no box — and the box half is reported as not
# exercised; an operator signed in with `min auth login`, with the proxy
# running (the mint is recorded over its control socket and the root it
# publishes seeds the trust store), proves the box half.
BEP_SID="" # the steered box, when a sign-in is held; destroyed by the case
bep_seed_steered_box() {
  BEP_SEED_DIR="$(mktemp -d /tmp/mnlbep.XXXXXX)"
  cp "$PROJECT_DIR/minimal.toml" "$BEP_SEED_DIR/minimal.toml"
  mkdir "$BEP_SEED_DIR/.git"
  cat >>"$BEP_SEED_DIR/minimal.toml" <<'EOF'

[session.network.egress]
allow_dns_hosts = ["github.com", "api.github.com", "uploads.github.com", "codeload.github.com"]

[session.network.bep]
steering = "proxy_env"
no_proxy = ["release-assets.githubusercontent.com"]

[[session.grants]]
module = "github"
env = "GITHUB_TOKEN"
source = "broker"
EOF
}
# Activates the seeded box as `$1` when a sign-in is held, setting BEP_SID
# (returns 0); with none held, proves the refusal half and returns 1. Stdin
# is closed either way, so a prompt would die on EOF instead of hanging.
bep_activate_steered_box() {
  local name="$1" bep_out
  BEP_SID=""
  if mnl auth status >"$WORK/auth-status.out" 2>&1 \
      && grep -q "signed in as" "$WORK/auth-status.out"; then
    bep_out="$(cd "$BEP_SEED_DIR" \
      && mnl session activate . --name "$name" --no-input </dev/null 2>"$WORK/$name.err")" || {
      echo "::error::the steered box $name was not created while a sign-in is held"
      echo "--- stdout ---"; printf '%s\n' "$bep_out"
      echo "--- stderr ---"; cat "$WORK/$name.err" 2>/dev/null || true
      fail
    }
    BEP_SID="$(printf '%s\n' "$bep_out" | tail -n1 | tr -d '\r')"
    return 0
  fi
  echo "no GitHub sign-in is held on this host: the box half is not exercised here"
  local bep_rc=0
  bep_out="$(cd "$BEP_SEED_DIR" \
    && mnl session activate . --name "$name" --no-input </dev/null 2>"$WORK/$name.err")" || bep_rc=$?
  if [ "$bep_rc" != 3 ]; then
    echo "::error::the steered box $name with no sign-in held exited $bep_rc, not 3"
    echo "--- stdout ---"; printf '%s\n' "$bep_out"
    echo "--- stderr ---"; cat "$WORK/$name.err" 2>/dev/null || true
    fail
  fi
  if ! grep -q "github_sign_in_required" "$WORK/$name.err"; then
    echo "::error::the refusal does not name the defined error github_sign_in_required"
    echo "--- stderr ---"; cat "$WORK/$name.err" 2>/dev/null || true
    fail
  fi
  if mnl ls 2>/dev/null | grep -q "$name"; then
    echo "::error::a box was created despite the refusal"
    fail
  fi
  echo "grant with no sign-in held: exit 3, github_sign_in_required, no box OK"
  return 1
}
bep_teardown_steered_box() {
  if [ -n "$BEP_SID" ]; then
    mnl session destroy --force "$BEP_SID" >/dev/null 2>&1 \
      || { echo "::error::could not destroy the steered box ($BEP_SID)"; fail; }
    BEP_SID=""
  fi
  rm -rf "$BEP_SEED_DIR"; BEP_SEED_DIR=""
}

# BEP-007: inside the box the grant's variable holds the sealed value
# (`minsealed1.…`) and nothing in the environment is a plaintext GitHub token.
case_bep_box_env_holds_sealed_value_only() {
  echo "::group::bep: the grant variable holds the sealed value only"
  bep_seed_steered_box
  if bep_activate_steered_box e2e-bep-sealed; then
    local value
    value="$(mnl session exec "$BEP_SID" 'printenv GITHUB_TOKEN' 2>"$WORK/bep-sealed.err")" || {
      echo "::error::GITHUB_TOKEN is not set in the box"
      echo "--- stderr ---"; cat "$WORK/bep-sealed.err" 2>/dev/null || true
      fail
    }
    case "$value" in
      minsealed1.*) ;;
      *) echo "::error::GITHUB_TOKEN does not hold a sealed value (no minsealed1. prefix)"; fail ;;
    esac
    # GitHub's token prefixes (ghu_ gho_ ghp_ ghs_ ghr_) appear nowhere in
    # the box environment: the sealed value is all the box gets.
    if mnl session exec "$BEP_SID" 'env' 2>/dev/null | grep -q -E 'gh[oprsu]_[A-Za-z0-9]{8,}'; then
      echo "::error::a plaintext GitHub token is present in the box environment"
      fail
    fi
    echo "GITHUB_TOKEN holds the sealed value and no plaintext token OK"
  fi
  bep_teardown_steered_box
  echo "::endgroup::"
}

# BEP-011: the host's interception root is in the box trust store.
case_bep_root_ca_present_in_box_trust_store() {
  echo "::group::bep: the interception root is in the box trust store"
  bep_seed_steered_box
  if bep_activate_steered_box e2e-bep-root; then
    local anchors
    anchors="$(mnl session exec "$BEP_SID" \
      'grep -c "BEGIN CERTIFICATE" /etc/ssl/certs/minimal-bep-root.pem' 2>"$WORK/bep-root.err")" || {
      echo "::error::/etc/ssl/certs/minimal-bep-root.pem is missing from the box trust store"
      echo "--- stderr ---"; cat "$WORK/bep-root.err" 2>/dev/null || true
      fail
    }
    if [ "$(printf '%s' "$anchors" | tr -d '[:space:]')" -lt 1 ] 2>/dev/null; then
      echo "::error::the trust store file carries no certificate"
      fail
    fi
    echo "interception root present in /etc/ssl/certs OK"
  fi
  bep_teardown_steered_box
  echo "::endgroup::"
}

# BEP-012: HTTPS_PROXY and HTTP_PROXY point at the proxy, and NO_PROXY carries
# the local zone plus the spec's own entry.
case_bep_proxy_env_and_no_proxy_are_set() {
  echo "::group::bep: the proxy environment and NO_PROXY are set"
  bep_seed_steered_box
  if bep_activate_steered_box e2e-bep-proxy; then
    local proxy_env https_proxy http_proxy no_proxy host
    # shellcheck disable=SC2016 # the variables must expand in the SESSION.
    proxy_env="$(mnl session exec "$BEP_SID" \
      'printf "%s\n%s\n%s\n" "$HTTPS_PROXY" "$HTTP_PROXY" "$NO_PROXY"' 2>"$WORK/bep-proxy.err")" || {
      echo "::error::reading the proxy environment in the box failed"
      echo "--- stderr ---"; cat "$WORK/bep-proxy.err" 2>/dev/null || true
      fail
    }
    https_proxy="$(printf '%s\n' "$proxy_env" | sed -n 1p | tr -d '\r')"
    http_proxy="$(printf '%s\n' "$proxy_env" | sed -n 2p | tr -d '\r')"
    no_proxy="$(printf '%s\n' "$proxy_env" | sed -n 3p | tr -d '\r')"
    if [ "$https_proxy" != "http://127.0.0.1:7656" ] || [ "$http_proxy" != "http://127.0.0.1:7656" ]; then
      echo "::error::HTTPS_PROXY/HTTP_PROXY do not point at the proxy: '$https_proxy' / '$http_proxy'"
      fail
    fi
    for host in .min.internal host.min.internal localhost 127.0.0.1 release-assets.githubusercontent.com; do
      case ",$no_proxy," in
        *",$host,"*) ;;
        *) echo "::error::NO_PROXY lacks $host: '$no_proxy'"; fail ;;
      esac
    done
    echo "proxy environment set, NO_PROXY carries the local zone and the spec's entry OK"
  fi
  bep_teardown_steered_box
  echo "::endgroup::"
}

# The git/gh proof needs the two tools in the box, so it seeds its own spec:
# the steered box above plus `git` and `gh` as PACKAGES. Packages are not
# configuration — the box still gets no credential helper, no gh host file and
# no token on disk, which is what BEP-015's "no tool configuration" names.
bep_seed_github_box() {
  BEP_SEED_DIR="$(mktemp -d /tmp/mnlbep.XXXXXX)"
  cp "$PROJECT_DIR/minimal.toml" "$BEP_SEED_DIR/minimal.toml"
  mkdir "$BEP_SEED_DIR/.git"
  cat >>"$BEP_SEED_DIR/minimal.toml" <<'EOF'

[session]
packages = ["git", "gh"]

[session.network.egress]
allow_dns_hosts = ["github.com", "api.github.com", "uploads.github.com", "codeload.github.com"]

[session.network.bep]
steering = "proxy_env"

[[session.grants]]
module = "github"
env = "GITHUB_TOKEN"
source = "broker"
EOF
}

# Runs one shell line in the box, failing the lane with "$1 failed in the box"
# (plus both streams) on a non-zero exit. The command's stdout is left in
# $WORK/bep-github.out for the caller to read.
bep_in_box() {
  local what="$1"
  shift
  if ! mnl session exec "$BEP_SID" "$*" >"$WORK/bep-github.out" 2>"$WORK/bep-github.err"; then
    echo "::error::$what failed in the box"
    echo "--- stdout ---"; cat "$WORK/bep-github.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-github.err" 2>/dev/null || true
    fail
  fi
}

# The proof body BEP-015 and the first-slice case share: with the box live,
# assert it starts from no tool configuration, then drive `gh api`, `git
# clone` and `git push` against a private repository of the signed-in
# account. Every request rides the sealed value in GITHUB_TOKEN through the
# proxy the box's HTTPS_PROXY points at; the proxy substitutes the real
# credential and forwards on its own validated leg, so nothing in the box ever
# holds a GitHub token. Leaves the account as it found it — the throwaway
# branch is deleted on both paths.
bep_prove_github_from_box() {
  # The box starts from no tool configuration: no git config, no stored
  # credentials, no gh host file. A marker distinguishes "nothing is there"
  # from an exec that did not run at all.
  local cfg_probe
  # shellcheck disable=SC2016 # $HOME/$f must expand in the BOX, not here.
  cfg_probe="$(mnl session exec "$BEP_SID" \
    'for f in "$HOME/.gitconfig" "$HOME/.git-credentials" "$HOME/.config/gh/hosts.yml"; do [ -e "$f" ] && { echo "CARRIES $f"; exit 0; }; done; echo CLEAN' \
    2>"$WORK/bep-cfg.err")" || {
    echo "::error::probing the box for tool configuration failed"
    echo "--- stderr ---"; cat "$WORK/bep-cfg.err" 2>/dev/null || true
    fail
  }
  if ! printf '%s\n' "$cfg_probe" | grep -q '^CLEAN$'; then
    echo "::error::the box carries tool configuration the proof must start without"
    printf '%s\n' "$cfg_probe"
    fail
  fi

  # `gh api`: the account the held sign-in is for. gh sends the sealed value
  # it finds in GITHUB_TOKEN and the proxy decides on it.
  bep_in_box "gh api user" 'gh api user --jq .login'
  local login
  login="$(tail -n1 "$WORK/bep-github.out" | tr -d '\r')"
  if [ -z "$login" ]; then
    echo "::error::gh api user returned no login"
    cat "$WORK/bep-github.out" 2>/dev/null || true
    fail
  fi
  echo "gh api user OK ($login)"

  # A private repository of that account for the clone and push proofs.
  bep_in_box "gh api user/repos" \
    'gh api "user/repos?visibility=private&affiliation=owner&per_page=1" --jq ".[0].full_name"'
  local repo
  repo="$(tail -n1 "$WORK/bep-github.out" | tr -d '\r')"
  if [ -z "$repo" ] || [ "$repo" = null ]; then
    echo "::error::the signed-in account ($login) owns no private repository, so the clone and push proof has no target"
    fail
  fi

  # `git clone`: the sealed value rides as the Basic password, the idiom that
  # needs no credential helper. GIT_TERMINAL_PROMPT=0 turns a refusal into an
  # error instead of a prompt that would hang the lane.
  bep_in_box "git clone of the private repo $repo" \
    "set -e; export GIT_TERMINAL_PROMPT=0; rm -rf \"\$HOME/bep-proof\"; git clone -q --depth 1 \"https://x-access-token:\$GITHUB_TOKEN@github.com/$repo.git\" \"\$HOME/bep-proof\"; git -C \"\$HOME/bep-proof\" rev-parse HEAD"
  if ! grep -qE '^[0-9a-f]{40}$' "$WORK/bep-github.out"; then
    echo "::error::the clone of $repo produced no commit"
    cat "$WORK/bep-github.out" 2>/dev/null || true
    fail
  fi
  echo "git clone of the private repo $repo OK"

  # `git push`: an empty commit on a throwaway branch, pushed and then
  # deleted, so the proof leaves the account as it found it. `-c user.*` is
  # commit metadata on the command line, not configuration left in the box.
  local branch="minimal-e2e-bep-$$"
  local push_line
  push_line="set -e; export GIT_TERMINAL_PROMPT=0; cd \"\$HOME/bep-proof\"; git -c user.name=minimal-e2e -c user.email=e2e@minimal.invalid commit -q --allow-empty -m 'e2e: bep proxy proof'; git push -q origin \"HEAD:refs/heads/$branch\"; git push -q origin --delete \"$branch\""
  if ! mnl session exec "$BEP_SID" "$push_line" \
      >"$WORK/bep-push.out" 2>"$WORK/bep-push.err"; then
    echo "::error::git push against $repo failed in the box"
    echo "--- stdout ---"; cat "$WORK/bep-push.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-push.err" 2>/dev/null || true
    # Never leave the throwaway branch behind on the account.
    mnl session exec "$BEP_SID" \
      "cd \"\$HOME/bep-proof\" && git push -q origin --delete \"$branch\"" \
      >/dev/null 2>&1 || true
    fail
  fi
  echo "git push and delete of $branch on $repo OK"
  echo "git clone, git push and gh api against a private repo from a box with no tool configuration OK"
}

# BEP-015: with the proxy running beside gvproxy, `git clone`, `git push` and
# `gh api` against a private repository of the signed-in account succeed from a
# box that was given no tool configuration.
#
# Which half runs depends on the sign-in held on THIS host, as in the cases
# above: with none (every CI lane) the refusal half is proved — exit 3,
# `github_sign_in_required`, no box — and the git/gh half is reported as not
# exercised; an operator signed in with `min auth login`, with the proxy up
# beside gvproxy, proves it.
case_bep_git_and_gh_against_private_repo() {
  echo "::group::bep: git and gh reach a private repository from a box"
  bep_seed_github_box
  if bep_activate_steered_box e2e-bep-github; then
    bep_prove_github_from_box
  fi
  bep_teardown_steered_box
  echo "::endgroup::"
}

# Every shape a GitHub credential takes in the clear: the five token prefixes
# GitHub issues (gho_ ghp_ ghr_ ghs_ ghu_) followed by its body. The sealed
# value a box carries is `minsealed1.<...>` and matches none of them, which is
# what makes this a usable sweep rather than a tautology.
BEP_TOKEN_RE='gh[oprsu]_[A-Za-z0-9]{8,}'

# The demo box of the first slice: the git/gh box plus `github:user-token` in
# its declared scopes — the honest spelling of the `full` member an un-enrolled
# host mints — so the spec review renders the `full` marker over a grant that
# declared something rather than over one that declared nothing (BEP-038).
bep_seed_first_slice_box() {
  bep_seed_github_box
  printf 'scopes = ["github:user-token"]\n' >>"$BEP_SEED_DIR/minimal.toml"
}

# Unpacks the .tar.zst bundle $1 into the fresh directory $2 with whichever
# decompressor this host has, echoing the bundle root on success. Returns 1 when
# the host has neither tar --zstd nor zstd, so the caller can say the sweep was
# not exercised instead of failing on a missing tool.
bep_unpack_bundle() {
  local bundle="$1" dest="$2" manifest
  mkdir -p "$dest"
  tar --zstd -xf "$bundle" -C "$dest" 2>/dev/null \
    || { command -v zstd >/dev/null 2>&1 \
         && zstd -dc "$bundle" 2>/dev/null | tar -xf - -C "$dest" 2>/dev/null; } \
    || return 1
  manifest="$(find "$dest" -maxdepth 2 -name manifest.json 2>/dev/null | head -n1)"
  [ -n "$manifest" ] || return 1
  dirname "$manifest"
}

# The first slice, end to end (BEP-015, BEP-038, BEP-042) with the sweep the
# whole slice rests on: no plaintext GitHub credential in the box, in the
# proxy's own trail, or in a support bundle taken from this host.
#
# What runs on every lane: `min box spec` — which renders the review even when
# it refuses the spec — shows this host's interception root, the resolved
# `proxy_env` steering, the `full` marker for the declared `github:user-token`
# and the GitHub v1 upstream host set; and `min bug` writes a bundle that
# carries the proxy's socket probe, accounts for the audit trail, and holds no
# token shape anywhere in it.
#
# What the held half adds, as in the cases above: the box itself — the sealed
# value in GITHUB_TOKEN and no plaintext beside it, `git clone`, `git push` and
# `gh api` against a private repository from a box given no tool configuration,
# and `min box audit` reading the proxy's own records back for that box. With no
# sign-in held (every CI lane) the refusal half is proved instead: exit 3 from
# both the spec review and the activation, naming `github_sign_in_required`.
case_bep_first_slice_no_plaintext_anywhere() {
  echo "::group::bep: the first slice end to end, with no plaintext anywhere"
  bep_seed_first_slice_box

  # 1. The review surface. A refused spec still renders it, so this half runs
  #    whatever sign-in the host holds; `spec_rc` carries which it was.
  local spec_rc=0 want
  (cd "$BEP_SEED_DIR" && mnl box spec .) \
    >"$WORK/bep-spec.out" 2>"$WORK/bep-spec.err" || spec_rc=$?
  for want in \
      "interception root:" \
      "steering: proxy_env" \
      "declared github:user-token" \
      "minted full" \
      "upstreams: github.com, api.github.com, uploads.github.com, codeload.github.com"; do
    if ! grep -qF -- "$want" "$WORK/bep-spec.out"; then
      echo "::error::min box spec does not show '$want'"
      echo "--- stdout ---"; cat "$WORK/bep-spec.out" 2>/dev/null || true
      echo "--- stderr ---"; cat "$WORK/bep-spec.err" 2>/dev/null || true
      fail
    fi
  done
  if grep -qE "$BEP_TOKEN_RE" "$WORK/bep-spec.out" "$WORK/bep-spec.err"; then
    echo "::error::min box spec printed something token-shaped"
    fail
  fi
  echo "min box spec shows the root, proxy_env steering, the full marker and the v1 upstream set OK"

  # 2. The box, when this host holds a sign-in.
  if bep_activate_steered_box e2e-bep-slice; then
    if [ "$spec_rc" != 0 ]; then
      echo "::error::min box spec exited $spec_rc for a spec this host went on to honour"
      echo "--- stderr ---"; cat "$WORK/bep-spec.err" 2>/dev/null || true
      fail
    fi
    if ! grep -qF "HTTPS_PROXY=http://127.0.0.1:7656" "$WORK/bep-spec.out"; then
      echo "::error::the admitted spec does not render the proxy environment the box is created with"
      cat "$WORK/bep-spec.out" 2>/dev/null || true
      fail
    fi

    # The delivered value is sealed, and nothing beside it is a token.
    local value
    value="$(mnl session exec "$BEP_SID" 'printenv GITHUB_TOKEN' 2>"$WORK/bep-slice.err")" || {
      echo "::error::GITHUB_TOKEN is not set in the box"
      echo "--- stderr ---"; cat "$WORK/bep-slice.err" 2>/dev/null || true
      fail
    }
    case "$value" in
      minsealed1.*) ;;
      *) echo "::error::GITHUB_TOKEN does not hold a sealed value (no minsealed1. prefix)"; fail ;;
    esac
    if mnl session exec "$BEP_SID" 'env' 2>/dev/null | grep -qE "$BEP_TOKEN_RE"; then
      echo "::error::a plaintext GitHub token is present in the box environment"
      fail
    fi

    # The slice's own work: clone, push and the API call, through the proxy.
    bep_prove_github_from_box

    # The trail the proxy alone writes, read back for this box and no other.
    # An empty trail is not a failure yet: nothing writes the proxy's box
    # attachments until the own-IP attachment slice does, so a decision can be
    # made for a box the proxy could not attribute.
    if ! mnl box audit e2e-bep-slice -o jsonl \
        >"$WORK/bep-audit.jsonl" 2>"$WORK/bep-audit.err"; then
      echo "::error::min box audit could not read the box's trail"
      echo "--- stderr ---"; cat "$WORK/bep-audit.err" 2>/dev/null || true
      fail
    fi
    if grep -qE "$BEP_TOKEN_RE" "$WORK/bep-audit.jsonl"; then
      echo "::error::the audit trail carries a plaintext GitHub token"
      fail
    fi
    if [ -s "$WORK/bep-audit.jsonl" ]; then
      echo "min box audit read $(wc -l <"$WORK/bep-audit.jsonl" | tr -d ' ') record(s) for the box, none carrying a credential OK"
    else
      echo "the proxy recorded nothing for this box (no attachment is written for it yet)"
    fi
  else
    if [ "$spec_rc" != 3 ]; then
      echo "::error::min box spec exited $spec_rc, not 3, for a spec this host refuses"
      echo "--- stderr ---"; cat "$WORK/bep-spec.err" 2>/dev/null || true
      fail
    fi
    if ! grep -q "github_sign_in_required" "$WORK/bep-spec.err"; then
      echo "::error::min box spec's refusal does not name github_sign_in_required"
      cat "$WORK/bep-spec.err" 2>/dev/null || true
      fail
    fi
    echo "min box spec refuses the spec with exit 3 and github_sign_in_required OK"
  fi

  # 3. The support bundle, on every lane: a report about this slice has to carry
  #    the proxy's side of it, and must never carry a credential.
  local bundle="$WORK/bep-bundle.tar.zst" root
  if ! mnl bug --no-guest --output "$bundle" >"$WORK/bep-bug.out" 2>"$WORK/bep-bug.err"; then
    echo "::error::min bug wrote no bundle"
    echo "--- stdout ---"; cat "$WORK/bep-bug.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-bug.err" 2>/dev/null || true
    fail
  fi
  if root="$(bep_unpack_bundle "$bundle" "$WORK/bep-bundle")"; then
    if [ ! -f "$root/bep/probe.json" ]; then
      echo "::error::the bundle does not carry the proxy's socket probe (bep/probe.json)"
      find "$root" -maxdepth 2 | head -40
      fail
    fi
    # The trail is either in the bundle or accounted for in the manifest —
    # never silently missing, which is what teaches a reader to stop looking.
    if [ -f "$root/bep/audit.log" ]; then
      if grep -qE "$BEP_TOKEN_RE" "$root/bep/audit.log"; then
        echo "::error::the bundled audit trail carries a plaintext GitHub token"
        fail
      fi
      echo "the bundle carries the proxy's audit tail, with no credential in it OK"
    elif grep -q '"bep/' "$root/manifest.json"; then
      echo "the bundle has no audit trail to carry and the manifest says why OK"
    else
      echo "::error::the bundle neither carries bep/audit.log nor explains its absence"
      cat "$root/manifest.json" 2>/dev/null || true
      fail
    fi
    if grep -rIqE "$BEP_TOKEN_RE" "$root" 2>/dev/null; then
      echo "::error::a plaintext GitHub token is present in the diagnostic bundle"
      grep -rIlE "$BEP_TOKEN_RE" "$root" 2>/dev/null | head -10
      fail
    fi
    echo "no plaintext GitHub token anywhere in the diagnostic bundle OK"
  else
    echo "::warning::this host has neither tar --zstd nor zstd; the bundle sweep was not exercised"
  fi

  bep_teardown_steered_box
  echo "::endgroup::"
}

# BEP-043: removing a box refuses every sealed value that named it, inside a
# minute of the removal completing.
#
# The box declares no grant on purpose. What BEP-043 turns on is the revocation
# the removal submits for the box it removes, and a box with no grant submits the
# same one — so this runs on every lane instead of only where a sign-in is held,
# and the values a grant box carries stay the first slice's case.
#
# Every lane proves the command path: the box is created and removed, the removal
# accounts for its revocation — recorded with the proxy, or said plainly not to
# be, never silently dropped — and prints nothing token-shaped. Where a proxy is
# running, its own trail for that box carries the revocation record, and the
# removal's own elapsed time is what the sixty seconds is measured against.
case_bep_stopped_box_values_refused_within_60s() {
  echo "::group::bep: a removed box's values are refused within 60 s"
  BEP_SEED_DIR="$(mktemp -d /tmp/mnlbep.XXXXXX)"
  cp "$PROJECT_DIR/minimal.toml" "$BEP_SEED_DIR/minimal.toml"
  mkdir "$BEP_SEED_DIR/.git"

  local name=e2e-bep-stopped sid started elapsed
  sid="$(cd "$BEP_SEED_DIR" \
    && mnl session activate . --name "$name" --no-input </dev/null 2>"$WORK/bep-stopped.err")" || {
    echo "::error::the box to remove was not created"
    echo "--- stderr ---"; cat "$WORK/bep-stopped.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$sid" | tail -n1 | tr -d '\r')"

  started="$(date +%s)"
  mnl session destroy --force "$sid" >"$WORK/bep-rm.out" 2>"$WORK/bep-rm.err" || {
    echo "::error::removing the box failed"
    echo "--- stdout ---"; cat "$WORK/bep-rm.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-rm.err" 2>/dev/null || true
    fail
  }
  elapsed=$(( $(date +%s) - started ))

  if mnl ls --raw 2>/dev/null | grep -Fqx "$sid"; then
    echo "::error::the box is still listed after its removal"
    fail
  fi
  if grep -qE "$BEP_TOKEN_RE" "$WORK/bep-rm.out" "$WORK/bep-rm.err"; then
    echo "::error::the removal printed something token-shaped"
    fail
  fi

  if mnl box audit "$name" -o jsonl >"$WORK/bep-rm-audit.jsonl" 2>"$WORK/bep-rm-audit.err" \
      && grep -q '"kind":"revocation"' "$WORK/bep-rm-audit.jsonl"; then
    if [ "$elapsed" -gt 60 ]; then
      echo "::error::the removal took ${elapsed}s, so its revocation was not in force within 60s"
      fail
    fi
    echo "the proxy's trail carries the removal's revocation for $name (${elapsed}s) OK"
  elif grep -q "did not record the revocation" "$WORK/bep-rm.err"; then
    echo "no proxy took the revocation on this host: the removal said so and still completed OK"
  else
    echo "::error::the removal neither recorded a revocation nor said why it could not"
    echo "--- stderr ---"; cat "$WORK/bep-rm.err" 2>/dev/null || true
    echo "--- trail ---"; cat "$WORK/bep-rm-audit.jsonl" 2>/dev/null || true
    fail
  fi

  rm -rf "$BEP_SEED_DIR"; BEP_SEED_DIR=""
  echo "::endgroup::"
}

# BEP-044: `min auth logout` refuses every sealed GitHub member on this host,
# inside a minute of the logout completing.
#
# Never run against a held sign-in: signing an operator's own machine out is not
# this script's to do, so with one held the case says so and exercises nothing.
# With none held — every CI lane — the logout still proves what the requirement
# turns on: the command completes, accounts for its revocation (recorded with the
# proxy, or said plainly not to be) and prints nothing token-shaped; where a
# proxy is running, its trail carries the revocation whose subject is every box.
# A host with no keychain backend at all (every Linux lane) refuses the command
# naming that, which is the honest outcome there — it holds no sign-in to revoke
# members of either.
case_bep_logout_refuses_all_members_within_60s() {
  echo "::group::bep: a logout refuses every member within 60 s"
  if mnl auth status >"$WORK/bep-logout-status.out" 2>&1 \
      && grep -q "signed in as" "$WORK/bep-logout-status.out"; then
    echo "a GitHub sign-in is held on this host: not exercised, because this case would sign it out"
    echo "::endgroup::"
    return
  fi

  local started elapsed logout_rc=0
  started="$(date +%s)"
  mnl auth logout >"$WORK/bep-logout.out" 2>"$WORK/bep-logout.err" || logout_rc=$?
  elapsed=$(( $(date +%s) - started ))
  if grep -qE "$BEP_TOKEN_RE" "$WORK/bep-logout.out" "$WORK/bep-logout.err"; then
    echo "::error::the logout printed something token-shaped"
    fail
  fi
  if [ "$logout_rc" != 0 ]; then
    if grep -q "no keychain backend" "$WORK/bep-logout.err"; then
      echo "this host has no keychain backend: the logout is refused naming it, and no member was ever minted here OK"
      echo "::endgroup::"
      return
    fi
    echo "::error::min auth logout failed for a reason other than a missing keychain backend"
    echo "--- stdout ---"; cat "$WORK/bep-logout.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-logout.err" 2>/dev/null || true
    fail
  fi
  if ! grep -q "no sign-in was held" "$WORK/bep-logout.out"; then
    echo "::error::the logout does not report that this host held no sign-in"
    echo "--- stdout ---"; cat "$WORK/bep-logout.out" 2>/dev/null || true
    fail
  fi

  # The revocation covers every box, so its subject is `*` — one record, read
  # back through the same trail a box's own records are read from.
  if mnl box audit '*' -o jsonl >"$WORK/bep-logout-audit.jsonl" 2>"$WORK/bep-logout-audit.err" \
      && grep -q '"kind":"revocation"' "$WORK/bep-logout-audit.jsonl"; then
    if [ "$elapsed" -gt 60 ]; then
      echo "::error::the logout took ${elapsed}s, so its revocation was not in force within 60s"
      fail
    fi
    echo "the proxy's trail carries the logout's revocation over every box (${elapsed}s) OK"
  elif grep -q "did not record the revocation" "$WORK/bep-logout.err"; then
    echo "no proxy took the revocation on this host: the logout said so and still completed OK"
  else
    echo "::error::the logout neither recorded a revocation nor said why it could not"
    echo "--- stderr ---"; cat "$WORK/bep-logout.err" 2>/dev/null || true
    echo "--- trail ---"; cat "$WORK/bep-logout-audit.jsonl" 2>/dev/null || true
    fail
  fi

  # And no sign-in is held afterwards: a logout never leaves one behind.
  if mnl auth status 2>&1 | grep -q "signed in as"; then
    echo "::error::a sign-in is still held after the logout"
    fail
  fi
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# The Keychain slice, end to end (BEP-032, BEP-035, BEP-036, BEP-038, BEP-050,
# BEP-063): a value this host holds, referred to by identifier from a box spec,
# with the box holding a short-lived handle and never the value.
#
# What runs on every lane: `min secret set` puts a value on the host or says
# plainly that this host has no store to put it in, and never echoes it; a
# reference no rule of the operator's registers is refused with exit 3 naming
# it, before any box exists; a reference whose registered authority the box's
# own egress does not admit is refused naming exactly the missing host; and,
# with the rule and the egress agreeing, `min box spec` renders the reference
# with the authorities registered for it and admits the spec.
#
# What a host holding the value adds: the box itself — the handle in the
# variable the reference names, and the stored value nowhere in it.
#
# What NO lane proves yet, and what these cases therefore do not assert: the
# injected request. The injection is the proxy's own (BEP-032, decided and
# proved in `crates/bep`), but the proxy binary this host runs is started with
# no `[secret-store-rules]` and no host store (`crates/bep/src/main.rs`), so a
# box request carrying a handle is decided against no rule and refused. Handing
# the running proxy the operator's rules and the host store is unbuilt work; the
# cases say so out loud at the point they would test it rather than making a
# request whose failure they would have to excuse.
BEP_REF_ID="e2e-bep-reference"     # the identifier these cases store under
BEP_REF_MCP_ID="e2e-bep-mcp-token" # the MCP client's identifier
BEP_REF_VALUE=""                   # the value this run stores; never printed
BEP_REF_STORED=""                  # set when this host's store took it

# Writes the operator's own `[secret-store-rules]` — the blocks given as $@ —
# into the hermetic client config this run uses. Never a project's: what a
# stored value may reach is the operator's to say, not a project's (BEP-037).
bep_write_store_rules() {
  local block
  mkdir -p "$XDG_CONFIG_HOME/minimal"
  : >"$XDG_CONFIG_HOME/minimal/config.toml"
  for block in "$@"; do
    printf '%s\n' "$block" >>"$XDG_CONFIG_HOME/minimal/config.toml"
  done
}

# The rule an operator registers for Claude Code's key: the Anthropic API
# authority, injected as the `x-api-key` header that client already sends its
# credential in.
bep_anthropic_rule() {
  cat <<RULE

[[secret-store-rules]]
store    = "keychain"
id       = "$BEP_REF_ID"
upstream = ["api.anthropic.com:443"]
inject   = { header = "x-api-key" }
action   = "allow"
RULE
}

# Seeds a box spec in a fresh dir — echoed, and removed on teardown — that
# refers to $BEP_REF_ID in the variable $1 and admits $2.. as its egress hosts.
# `proxy_env` steering, as every box today declares: no host runs the box-zone
# resolver the default `dns` needs.
bep_seed_reference_box() {
  local env_var="$1"; shift
  local dir host hosts=""
  dir="$(mktemp -d /tmp/mnlbep.XXXXXX)"
  BEP_REF_SEEDS="$BEP_REF_SEEDS $dir"
  cp "$PROJECT_DIR/minimal.toml" "$dir/minimal.toml"
  mkdir "$dir/.git"
  for host in "$@"; do
    hosts="$hosts${hosts:+, }\"$host\""
  done
  cat >>"$dir/minimal.toml" <<SPEC

[session.network.egress]
allow_dns_hosts = [$hosts]

[session.network.bep]
steering = "proxy_env"

[[session.references]]
store  = "keychain"
id     = "$BEP_REF_ID"
env    = "$env_var"
source = "store"
SPEC
  printf '%s\n' "$dir"
}

# Stores this run's value under $BEP_REF_ID, or reports that this host holds no
# store to put it in. Either way the value is never echoed back (BEP-050).
bep_store_the_value() {
  BEP_REF_VALUE="e2e-bep-not-a-real-key-$(now_ms)"
  BEP_REF_STORED=""
  if printf '%s\n' "$BEP_REF_VALUE" \
      | mnl secret set "$BEP_REF_ID" >"$WORK/bep-secret-set.out" 2>"$WORK/bep-secret-set.err"; then
    BEP_REF_STORED=1
    if ! grep -qF "$BEP_REF_ID" "$WORK/bep-secret-set.out"; then
      echo "::error::min secret set did not name the identifier it stored"
      cat "$WORK/bep-secret-set.out" 2>/dev/null || true
      fail
    fi
    if grep -qF "$BEP_REF_VALUE" "$WORK/bep-secret-set.out" "$WORK/bep-secret-set.err"; then
      echo "::error::min secret set echoed the value it stored"
      fail
    fi
    echo "min secret set stored a value under \`$BEP_REF_ID\`, printing the identifier and no value OK"
  elif grep -q "no keychain backend" "$WORK/bep-secret-set.err"; then
    echo "::notice::this host holds no keychain, so nothing below that needs a stored value runs: min secret set named the missing backend, which is all it can prove here"
  else
    echo "::error::min secret set neither stored the value nor named the missing keychain backend"
    echo "--- stderr ---"; cat "$WORK/bep-secret-set.err" 2>/dev/null || true
    fail
  fi
}

# Takes back out what `bep_store_the_value` put in, and the rules with it.
bep_drop_the_value() {
  local id
  if [ -n "$BEP_REF_STORED" ]; then
    for id in "$BEP_REF_ID" "$BEP_REF_MCP_ID"; do
      mnl secret rm "$id" >/dev/null 2>&1 || true
    done
  fi
  BEP_REF_STORED=""
  rm -f "$XDG_CONFIG_HOME/minimal/config.toml"
}

# Refuses an activation of the box spec in $1, named $2: exit 3, every grep
# pattern in $3.. on its stderr, and no box left behind. Stdin is closed, so a
# prompt would die on EOF rather than hang the lane.
bep_refuse_activation() {
  local dir="$1" name="$2"; shift 2
  local rc=0 out want
  out="$(cd "$dir" \
    && mnl session activate . --name "$name" --no-input </dev/null 2>"$WORK/$name.err")" || rc=$?
  if [ "$rc" != 3 ]; then
    echo "::error::activating $name exited $rc, not 3"
    echo "--- stdout ---"; printf '%s\n' "$out"
    echo "--- stderr ---"; cat "$WORK/$name.err" 2>/dev/null || true
    fail
  fi
  for want in "$@"; do
    if ! grep -qF -- "$want" "$WORK/$name.err"; then
      echo "::error::the refusal of $name does not say '$want'"
      echo "--- stderr ---"; cat "$WORK/$name.err" 2>/dev/null || true
      fail
    fi
  done
  if mnl ls 2>/dev/null | grep -q "$name"; then
    echo "::error::a box was created despite the refusal of $name"
    fail
  fi
}

case_bep_store_reference_reaches_upstream_without_key_in_box() {
  echo "::group::bep: a box refers to a stored key and holds a handle, never the key"
  bep_store_the_value

  # 1. No rule of the operator's registers the identifier: refused with exit 3
  #    naming the reference, by the review and by the activation, with no box
  #    created (BEP-035).
  bep_write_store_rules ""
  local unregistered rc=0
  unregistered="$(bep_seed_reference_box ANTHROPIC_API_KEY api.anthropic.com)"
  (cd "$unregistered" && mnl box spec .) \
    >"$WORK/bep-ref-norule.out" 2>"$WORK/bep-ref-norule.err" || rc=$?
  if [ "$rc" != 3 ] \
      || ! grep -qF "keychain reference \`$BEP_REF_ID\`" "$WORK/bep-ref-norule.err" \
      || ! grep -qF "matches no \`[secret-store-rules]\` rule" "$WORK/bep-ref-norule.err"; then
    echo "::error::an unregistered reference was not refused with exit 3 naming it (exit $rc)"
    echo "--- stdout ---"; cat "$WORK/bep-ref-norule.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-ref-norule.err" 2>/dev/null || true
    fail
  fi
  # The review still shows the reviewer what the spec declares, and says the
  # reference reaches nothing rather than leaving a blank where its
  # authorities go.
  if ! grep -qF "keychain reference \`$BEP_REF_ID\`: authorities none registered" \
      "$WORK/bep-ref-norule.out"; then
    echo "::error::the review does not show the declared reference as registering nothing"
    cat "$WORK/bep-ref-norule.out" 2>/dev/null || true
    fail
  fi
  bep_refuse_activation "$unregistered" e2e-bep-ref-norule \
    "keychain reference \`$BEP_REF_ID\`" "matches no \`[secret-store-rules]\` rule"
  echo "an unregistered reference: exit 3 naming it from both surfaces, no box OK"

  # 2. Registered, but the box's own egress does not admit the authority the
  #    rule registers: refused naming exactly the missing host (BEP-036).
  bep_write_store_rules "$(bep_anthropic_rule)"
  local narrow
  narrow="$(bep_seed_reference_box ANTHROPIC_API_KEY github.com)"
  bep_refuse_activation "$narrow" e2e-bep-ref-narrow \
    "keychain reference \`$BEP_REF_ID\`" "missing: api.anthropic.com"
  echo "a reference the box's egress does not admit: exit 3 naming the missing host, no box OK"

  # 3. The rule and the egress agree: the review renders the reference with the
  #    authorities registered for it, steers the box to the proxy that will
  #    inject the value, admits the spec, and shows no value (BEP-038).
  local admitted
  admitted="$(bep_seed_reference_box ANTHROPIC_API_KEY api.anthropic.com)"
  if ! (cd "$admitted" && mnl box spec .) \
      >"$WORK/bep-ref-spec.out" 2>"$WORK/bep-ref-spec.err"; then
    echo "::error::a registered, admitted reference was refused by the review"
    echo "--- stdout ---"; cat "$WORK/bep-ref-spec.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-ref-spec.err" 2>/dev/null || true
    fail
  fi
  local want
  for want in \
      "keychain reference \`$BEP_REF_ID\`: authorities api.anthropic.com:443" \
      "HTTPS_PROXY=http://127.0.0.1:7656"; do
    if ! grep -qF -- "$want" "$WORK/bep-ref-spec.out"; then
      echo "::error::the review of an admitted reference does not show '$want'"
      cat "$WORK/bep-ref-spec.out" 2>/dev/null || true
      fail
    fi
  done
  if grep -qF "$BEP_REF_VALUE" "$WORK/bep-ref-spec.out" "$WORK/bep-ref-spec.err"; then
    echo "::error::the review printed the stored value"
    fail
  fi
  echo "min box spec renders the reference's authorities, steers the box, shows no value OK"

  # 4. The box, on a host that holds the value: the handle in the variable the
  #    reference names, and the value nowhere in the box (BEP-032, BEP-063).
  if [ -n "$BEP_REF_STORED" ]; then
    local sid value
    sid="$(cd "$admitted" \
      && mnl session activate . --name e2e-bep-ref --no-input </dev/null \
        2>"$WORK/bep-ref-activate.err" | tail -n1 | tr -d '\r')"
    if [ -z "$sid" ]; then
      echo "::error::the box referring to a stored value was not created"
      echo "--- stderr ---"; cat "$WORK/bep-ref-activate.err" 2>/dev/null || true
      fail
    fi
    value="$(mnl session exec "$sid" 'printenv ANTHROPIC_API_KEY' 2>"$WORK/bep-ref-env.err")" || {
      echo "::error::the reference's variable is not set in the box"
      echo "--- stderr ---"; cat "$WORK/bep-ref-env.err" 2>/dev/null || true
      fail
    }
    case "$value" in
      minsealed1.*) ;;
      *) echo "::error::the reference's variable holds no sealed handle (no minsealed1. prefix)"; fail ;;
    esac
    if mnl session exec "$sid" 'env' 2>/dev/null | grep -qF "$BEP_REF_VALUE"; then
      echo "::error::the stored value is present in the box environment"
      fail
    fi
    echo "the box holds the sealed handle in ANTHROPIC_API_KEY and the stored value nowhere OK"
    # The proxy's own trail for this box, which must carry no value whatever it
    # decided. A trail that cannot be read is said so: an unread file proves
    # nothing and must not pass for an empty one.
    if mnl box audit e2e-bep-ref -o jsonl \
        >"$WORK/bep-ref-audit.jsonl" 2>"$WORK/bep-ref-audit.err"; then
      if grep -qF "$BEP_REF_VALUE" "$WORK/bep-ref-audit.jsonl"; then
        echo "::error::the proxy's trail carries the stored value"
        fail
      fi
      if [ -s "$WORK/bep-ref-audit.jsonl" ]; then
        echo "the proxy recorded $(wc -l <"$WORK/bep-ref-audit.jsonl" | tr -d ' ') decision(s) for the box, none carrying the value OK"
      else
        echo "the proxy recorded nothing for this box (none is attached to it here)"
      fi
    else
      echo "::warning::the proxy's trail for this box could not be read, so it was not examined"
      cat "$WORK/bep-ref-audit.err" 2>/dev/null || true
    fi
    # The rest of this case's name — the request that reaches the upstream
    # carrying the injected value — is not asserted, because nothing on any host
    # can satisfy it yet: see the note above `BEP_REF_ID`. No request is made
    # here rather than one whose refusal the case would have to accept.
    echo "::notice::not asserted: the box's request to api.anthropic.com carrying the injected value. The proxy this host runs is started with no [secret-store-rules] and no host store (crates/bep/src/main.rs), so a request carrying a handle is refused, not injected. Handing the running proxy the rules and the store is unbuilt."
    mnl session destroy --force "$sid" >/dev/null 2>&1 \
      || { echo "::error::could not destroy the box referring to a stored value"; fail; }
  else
    echo "::notice::not asserted on this lane: the box half — the handle in the variable and the value nowhere in the box. This host holds no store to put a value in, so only the refusals and the review above ran."
  fi

  bep_drop_the_value
  echo "::endgroup::"
}

# OQ2, BEP-034, BEP-038: the two client shapes this slice bets on — Claude
# Code's `x-api-key` and an MCP client's `Authorization: Bearer` — are exactly
# what an operator may register, so each client sends what it is given in the
# variable it already reads, in the header its own requests already carry,
# unmodified.
#
# On every lane: a rule naming a header the proxy owns is refused when the
# configuration is read, and both client-shaped rules then load and both
# references are admitted — so admitting these two is a decision and not a
# rubber stamp. On a host holding the values the box is created too, and each
# client's variable holds a single-line, header-safe handle: what the client
# puts in the header the rule names is exactly what Minimal put in the variable.
case_bep_claude_code_and_mcp_client_send_handle_unmodified() {
  echo "::group::bep: Claude Code and an MCP client send the handle unmodified"
  bep_store_the_value

  # A rule naming a header that would reframe the request rather than
  # authenticate it is refused when the configuration is read (BEP-034).
  bep_write_store_rules "
[[secret-store-rules]]
store    = \"keychain\"
id       = \"$BEP_REF_ID\"
upstream = [\"api.anthropic.com:443\"]
inject   = { header = \"Cookie\" }
"
  local reframing rc=0
  reframing="$(bep_seed_reference_box ANTHROPIC_API_KEY api.anthropic.com)"
  (cd "$reframing" && mnl box spec .) \
    >"$WORK/bep-clients-denied.out" 2>"$WORK/bep-clients-denied.err" || rc=$?
  if [ "$rc" = 0 ] || ! grep -qF "Cookie" "$WORK/bep-clients-denied.err"; then
    echo "::error::a rule injecting into Cookie was not refused when the config was read (exit $rc)"
    echo "--- stderr ---"; cat "$WORK/bep-clients-denied.err" 2>/dev/null || true
    fail
  fi
  echo "a rule injecting into a header the proxy owns is refused when the config is read OK"

  # The two client shapes, each registered for its own identifier, in one box.
  bep_write_store_rules "$(bep_anthropic_rule)" "
[[secret-store-rules]]
store    = \"keychain\"
id       = \"$BEP_REF_MCP_ID\"
upstream = [\"mcp.example.com:443\"]
inject   = { header = \"authorization\", prefix = \"Bearer \" }
action   = \"allow\"
"
  local both
  both="$(bep_seed_reference_box ANTHROPIC_API_KEY api.anthropic.com mcp.example.com)"
  cat >>"$both/minimal.toml" <<SPEC

[[session.references]]
store  = "keychain"
id     = "$BEP_REF_MCP_ID"
env    = "MCP_SERVER_TOKEN"
source = "store"
SPEC
  if ! (cd "$both" && mnl box spec .) \
      >"$WORK/bep-clients-spec.out" 2>"$WORK/bep-clients-spec.err"; then
    echo "::error::a box referring to both client shapes was refused by the review"
    echo "--- stdout ---"; cat "$WORK/bep-clients-spec.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-clients-spec.err" 2>/dev/null || true
    fail
  fi
  local want
  for want in \
      "keychain reference \`$BEP_REF_ID\`: authorities api.anthropic.com:443" \
      "keychain reference \`$BEP_REF_MCP_ID\`: authorities mcp.example.com:443"; do
    if ! grep -qF -- "$want" "$WORK/bep-clients-spec.out"; then
      echo "::error::the review does not show '$want'"
      cat "$WORK/bep-clients-spec.out" 2>/dev/null || true
      fail
    fi
  done
  echo "both client shapes are registrable and both references are admitted OK"

  # The box, on a host that holds the values: each client's own variable holds
  # a handle it can put in a header untouched — one line, printable ASCII, no
  # whitespace — which is the shape OQ2 bets every intended client passes
  # through. The value itself is nowhere in the box.
  if [ -n "$BEP_REF_STORED" ]; then
    local sid var value
    sid="$(cd "$both" \
      && mnl session activate . --name e2e-bep-clients --no-input </dev/null \
        2>"$WORK/bep-clients-activate.err" | tail -n1 | tr -d '\r')"
    if [ -z "$sid" ]; then
      echo "::error::the box referring to both client shapes was not created"
      echo "--- stderr ---"; cat "$WORK/bep-clients-activate.err" 2>/dev/null || true
      fail
    fi
    for var in ANTHROPIC_API_KEY MCP_SERVER_TOKEN; do
      value="$(mnl session exec "$sid" "printenv $var" 2>"$WORK/bep-clients-env.err" | tr -d '\r')" || {
        echo "::error::$var is not set in the box"
        echo "--- stderr ---"; cat "$WORK/bep-clients-env.err" 2>/dev/null || true
        fail
      }
      case "$value" in
        minsealed1.*) ;;
        *) echo "::error::$var holds no sealed handle (no minsealed1. prefix)"; fail ;;
      esac
      if [ "$(printf '%s' "$value" | wc -l | tr -d ' ')" != 0 ] \
          || printf '%s' "$value" | LC_ALL=C grep -q '[^!-~]'; then
        echo "::error::$var holds something no client could send as a header value unmodified"
        fail
      fi
    done
    if mnl session exec "$sid" 'env' 2>/dev/null | grep -qF "$BEP_REF_VALUE"; then
      echo "::error::the stored value is present in the box environment"
      fail
    fi
    echo "each client's variable holds a single-line, header-safe handle and no value OK"
    mnl session destroy --force "$sid" >/dev/null 2>&1 \
      || { echo "::error::could not destroy the box referring to both client shapes"; fail; }
  else
    echo "::notice::not asserted on this lane: the in-box half — each client's variable holding a header-safe handle. This host holds no store to put a value in, so only the refused Cookie rule and the two admitted references above ran."
  fi

  bep_drop_the_value
  echo "::endgroup::"
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

# ---------------------------------------------------------------------------
# Case selection: a `test:` line names one proof
# (`./scripts/session-e2e.sh <case>`), but the script took no argument — every
# group below ran unconditionally regardless of it. `E2E_CASE` (or the first
# positional arg) now selects exactly one named case and skips the whole
# lifecycle+sandbox sequence below; an unrecognised name is a hard error
# rather than a silent no-op, so a typo in a `test:` line fails loudly instead
# of "passing" by running everything. Reusable by later tasks: add a
# `run_case_<name>` function above the dispatch below and a matching arm in it.

# NET-001..004: `<name>.min.internal` / `host.min.internal` through the B5
# host-side egress proxy that already ships (crates/minimald/src/net/{dns,
# proxy,switch}.rs). The HostNet half (NET-001's core + unwanted-case clauses,
# NET-002) runs on every lane: the proxy's own outbound connect for a
# `target=loopback` registration always lands wherever `minimald` itself
# runs — this host natively, or the guest on a VM lane — and a HostNet box
# shares exactly that namespace, so a listener started inside it is "the box"
# the name routes to. The own-IP half (NET-001's VM-host clause, NET-003,
# NET-004) needs a real switch and is gated on MINVMD_GVPROXY_BIN, same as the
# own-IP proof below.
run_case_min_internal_names_through_proxy() {
  echo "::group::min.internal names through the proxy (NET-001..004)"

  # The registration/deprecation notices this case asserts on are logged at
  # INFO (crates/minimald/src/net/{dns,switch}.rs); the suite's default
  # RUST_LOG=warn would drop them. Scoped to the net module so everything else
  # stays as quiet as the rest of the script expects. Safe here: nothing has
  # spawned a daemon yet, and this case spawns its own.
  export RUST_LOG="warn,minimald::net=info"

  # Greps the daemon's own file log for a pattern, reporting SKIPPED instead
  # of failing on a VM lane: minimald runs in-guest there and logs to guest
  # tmpfs, which no host path reaches (same rationale as the lifecycle-hooks
  # proof's hook_log_has/hook_log_readable further down).
  assert_log_has() {
    if [ -z "$E2E_VM" ] && find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f \
        -exec grep -q -- "$1" {} + 2>/dev/null; then
      echo "daemon log: found '$1' ($2)"
      return 0
    fi
    if [ -n "$E2E_VM" ]; then
      echo "daemon log check SKIPPED for $2 (E2E_VM: minimald's log is in guest tmpfs, unreachable from here)"
      return 0
    fi
    echo "::error::daemon log has no record matching '$1' ($2)"
    fail
  }

  # One request through the 7654 proxy: prints it, returns its HTTP status.
  # Retried up to 10x (1s apart) while the status doesn't match `want` — the
  # target listener was just forked and may not have bound yet, and while it
  # hasn't, the proxy's own "upstream-unreachable" 502 is itself a valid HTTP
  # response curl returns immediately, so a retry loop that only re-tries on
  # curl-level failure (empty/"000") never actually waits out that race. A
  # caller with no `want` (an intentionally-negative check) still gets that
  # baseline connectivity retry, then returns on the first real response.
  proxy_status() {
    local authority="$1" want="${2:-}" status=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
        --proxy 127.0.0.1:7654 "http://$authority/" 2>"$WORK/mi-curl.err")"
      if [ -n "$status" ] && [ "$status" != "000" ] && { [ -z "$want" ] || [ "$status" = "$want" ]; }; then
        break
      fi
      sleep 1
    done
    echo "GET http://$authority/ via proxy 127.0.0.1:7654 -> ${status:-<no response>}" >&2
    printf '%s' "$status"
  }

  # Same, but issued from inside a session (`min session exec`), for the
  # switch-mediated NET-003/NET-004 checks below.
  exec_status() {
    local sid="$1" url="$2" status=""
    for _ in 1 2 3; do
      status="$(mnl session exec "$sid" curl -sS -o /dev/null -w '%{http_code}' --max-time 10 "$url" \
        2>"$WORK/mi-curl.err")"
      [ -n "$status" ] && [ "$status" != "000" ] && break
      sleep 1
    done
    echo "(inside $sid) GET $url -> ${status:-<no response>}" >&2
    printf '%s' "$status"
  }

  # -- NET-001 (HostNet) + NET-002 (deprecated 3-label zone) -----------------
  hn_name="e2e-min-internal"
  hn_port=18099
  hn_out="$(cd "$PROJECT_DIR" && mnl session activate . --name "$hn_name" 2>"$WORK/mi-hn-activate.err")" || {
    echo "::error::'min session activate --name $hn_name' failed"
    cat "$WORK/mi-hn-activate.err" 2>/dev/null || true
    fail
  }
  hn_sid="$(printf '%s\n' "$hn_out" | tail -n1 | tr -d '\r')"
  echo "hostnet session: $hn_sid"

  # A responder inside the box's OWN netns. HostNet shares minimald's own
  # netns (native: this host's; VM lane: the guest's), which is exactly where
  # the proxy's outbound connect for a `target=127.0.0.1` registration lands
  # — so a listener started here IS "the box" the name routes to. `socat` is
  # in the launcher baseline (base/coreutils/socat), needing no `min add`.
  mnl session exec "$hn_sid" \
    'printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" > /tmp/mi-resp.http' \
    || { echo "::error::could not seed the HostNet responder's canned response"; fail; }
  mnl session exec "$hn_sid" socat -T30 "TCP-LISTEN:$hn_port,bind=127.0.0.1,reuseaddr,fork" \
    'SYSTEM:cat /tmp/mi-resp.http' >"$WORK/mi-hn-socat.log" 2>&1 &
  hn_socat_pid=$!

  core_status="$(proxy_status "$hn_name.min.internal:$hn_port" 200)"
  if [ "$core_status" != "200" ]; then
    echo "::error::NET-001: routing $hn_name.min.internal through the proxy got '$core_status', want 200"
    cat "$WORK/mi-curl.err" 2>/dev/null || true
    fail
  fi
  echo "NET-001 OK: $hn_name.min.internal routed through the proxy to the HostNet box"

  legacy_status="$(proxy_status "$hn_name.local.min.internal:$hn_port" 200)"
  if [ "$legacy_status" != "200" ]; then
    echo "::error::NET-002: the deprecated <name>.local.min.internal zone got '$legacy_status', want 200"
    fail
  fi
  assert_log_has "routed a deprecated three-label box name" "NET-002 deprecation notice"
  echo "NET-002 OK: the deprecated 3-label zone routed with a deprecation notice"

  ghost_status="$(proxy_status "e2e-min-internal-ghost.min.internal:$hn_port")"
  if [ "$ghost_status" != "502" ]; then
    echo "::error::NET-001 (unwanted case): an unregistered name got '$ghost_status', want 502"
    fail
  fi
  assert_log_has "no-live-box-owns-the-name" "NET-001 refusal reason"
  echo "NET-001 (unwanted case) OK: an unregistered name was refused and the refusal was logged"

  kill "$hn_socat_pid" 2>/dev/null || true
  wait "$hn_socat_pid" 2>/dev/null || true
  mnl session destroy --force "$hn_sid" >/dev/null 2>&1 || true

  # -- NET-001 (own-IP, VM host) + NET-003 + NET-004 -------------------------
  if [ -n "${MINVMD_GVPROXY_BIN:-}" ]; then
    oi_name="e2e-min-internal-ownip"
    oi_ext=18100
    oi_int=8080
    host_port=18199

    # Mirrors the own-IP proof's own seed: a separate dir, since a path that
    # already has a session does not mint a second one.
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
    mkdir "$OWNIP_SEED_DIR/.git"

    oi_out="$(cd "$OWNIP_SEED_DIR" && mnl session activate . --no-prompt \
      --name "$oi_name" --network own_ip --ingress "$oi_ext:$oi_int" 2>"$WORK/mi-oi-activate.err")" || {
      echo "::error::'min session activate --network own_ip --ingress' failed"
      cat "$WORK/mi-oi-activate.err" 2>/dev/null || true
      fail
    }
    oi_sid="$(printf '%s\n' "$oi_out" | tail -n1 | tr -d '\r')"
    echo "own-IP session: $oi_sid"

    mnl session exec "$oi_sid" \
      'printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" > /tmp/mi-resp.http' \
      || { echo "::error::could not seed the own-IP responder's canned response"; fail; }
    mnl session exec "$oi_sid" socat -T30 "TCP-LISTEN:$oi_int,reuseaddr,fork" \
      'SYSTEM:cat /tmp/mi-resp.http' >"$WORK/mi-oi-socat.log" 2>&1 &
    oi_socat_pid=$!

    oi_route_status="$(proxy_status "$oi_name.min.internal:$oi_ext" 200)"
    if [ "$oi_route_status" != "200" ]; then
      echo "::error::NET-001: an own-IP session's name did not route through the proxy on a VM host"
      cat "$WORK/mi-curl.err" 2>/dev/null || true
      fail
    fi
    echo "NET-001 OK: an own-IP session's name routed through the proxy (VM host included)"

    # A responder on THIS machine's real loopback: gvproxy NATs a box's
    # connection to its host-gateway alias (100.64.255.254, `host.min.internal`
    # per NET-003) to wherever gvproxy itself runs — this host natively, or the
    # true outer host on a VM lane (crates/minimald/src/net/policy.rs
    # host_reach_address / HostReach::Switch).
    python3 -m http.server "$host_port" --bind 127.0.0.1 --directory "$WORK" \
      >"$WORK/mi-host-responder.log" 2>&1 &
    host_resp_pid=$!
    host_ready=0
    for _ in 1 2 3 4 5; do
      curl -sS -o /dev/null --max-time 2 "http://127.0.0.1:$host_port/" 2>/dev/null && { host_ready=1; break; }
      sleep 1
    done
    if [ "$host_ready" -ne 1 ]; then
      echo "::error::the host-loopback responder for NET-003/NET-004 never came up on 127.0.0.1:$host_port"
      fail
    fi

    net003_status="$(exec_status "$oi_sid" "http://host.min.internal:$host_port/")"
    if [ "$net003_status" != "200" ]; then
      echo "::error::NET-003: host.min.internal did not reach the host's loopback from an own-IP box"
      cat "$WORK/mi-curl.err" 2>/dev/null || true
      fail
    fi
    echo "NET-003 OK: host.min.internal resolved and reached the host's loopback"

    net004_status="$(exec_status "$oi_sid" "http://100.64.255.254:$host_port/")"
    if [ "$net004_status" != "200" ]; then
      echo "::error::NET-004: the legacy literal host address did not route as host.min.internal"
      cat "$WORK/mi-curl.err" 2>/dev/null || true
      fail
    fi
    assert_log_has "deprecated literal host address" "NET-004 deprecation notice"
    echo "NET-004 OK: the legacy literal routed as host.min.internal, with a deprecation notice"

    kill "$oi_socat_pid" "$host_resp_pid" 2>/dev/null || true
    wait "$oi_socat_pid" 2>/dev/null || true
    wait "$host_resp_pid" 2>/dev/null || true
    mnl session destroy --force "$oi_sid" >/dev/null 2>&1 || true
    rm -rf "$OWNIP_SEED_DIR"; OWNIP_SEED_DIR=""
  else
    echo "own-IP / host.min.internal proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
  fi

  echo "::endgroup::"
}

# NET-107: one outbound request from inside a live session, asserted on any
# lane. Every VM lane wires the gvproxy switch for the guest's egress (NAT +
# DNS), yet nothing else here asserts it works — and gvproxy resolution is
# best-effort and never errors, so a lane that silently loses the switch boots
# switchless, has no egress, and still reports green. The symptom then reaches a
# user as a bogus "could not resolve host" that is not a DNS problem. The
# `shell` stack composes curl, so no package is added; the caller is responsible
# for handing over a session whose project seed we control (and thus has curl).
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
assert_session_outbound_reach() {
  local sid="$1"
  echo "::group::guest egress proof (curl from inside the session)"
  local egress_ok=0 egress_total=0 egress_failed="" egress_host egress_status egress_out egress_try
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
}

# NET-107 as a named case: its own session, so the `test:` line stands alone
# instead of depending on the sequence below having reached the egress group.
# Its own project seed too, rather than $PROJECT_DIR: curl reaches the box only
# through the `shell` stack this seeds, which is why the inline proof below runs
# for a seed we own and no other. Against a caller-provided E2E_PROJECT_DIR that
# carries its own minimal.toml, the case would otherwise fail for want of curl
# rather than for want of egress.
run_case_session_outbound_request() {
  local out sid
  OUTBOUND_SEED_DIR="$(mktemp -d /tmp/mnlb.XXXXXX)"
  OUTBOUND_SEED_DIR="$(cd "$OUTBOUND_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$OUTBOUND_SEED_DIR/minimal.toml"
  mkdir "$OUTBOUND_SEED_DIR/.git"
  out="$(cd "$OUTBOUND_SEED_DIR" && mnl session activate . --no-prompt --name e2e-outbound \
    2>"$WORK/outbound-activate.err")" || {
    echo "::error::'min session activate' failed for the outbound-reach case"
    cat "$WORK/outbound-activate.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  echo "outbound-reach session: $sid"
  assert_session_outbound_reach "$sid"
  mnl session destroy --force "$sid" >/dev/null 2>&1 || true
  rm -rf "$OUTBOUND_SEED_DIR"; OUTBOUND_SEED_DIR=""
}

# NET-040: `min session activate --network own_ip --ingress 8080:8080` publishes
# the box's port on HOST loopback, so a request to 127.0.0.1:8080 comes back
# with what the server INSIDE the box wrote. Staged as close to a fresh install
# as a lane gets: the state dir is fresh per run and a case runs before anything
# has spawned a daemon, so the CLI auto-spawns the target's daemon, the daemon
# spawns the switch, and the forward is asked for at activate time
# (crates/minimald/src/net/policy.rs apply_ingress -> gvproxy's
# /services/forwarder/expose, which binds 127.0.0.1 only). Gated on
# MINVMD_GVPROXY_BIN, the one signal that a switch exists — a target without one
# has no own-IP mode to publish from, same as the own-IP proof below.
run_case_fresh_install_own_ip_ingress_publishes_loopback() {
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "own-IP ingress proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
    return 0
  fi
  echo "::group::own-IP --ingress publishes on host loopback (NET-040)"

  # The requirement names 8080:8080 literally, the host side included, so the
  # port is not a free choice here: a listener already on it would answer in the
  # box's place (and the switch's own bind would fail). That is a host problem
  # worth saying out loud rather than papering over with a different port.
  local port=8080 marker="INGRESS_E2E_OK"
  if curl -sS -o /dev/null --max-time 2 "http://127.0.0.1:$port/" 2>/dev/null; then
    echo "::error::something already answers on 127.0.0.1:$port; NET-040 publishes exactly that address and needs it free"
    fail
  fi

  local out sid body=""
  out="$(cd "$PROJECT_DIR" && mnl session activate . --no-prompt --name e2e-ingress \
    --network own_ip --ingress "$port:$port" 2>"$WORK/ingress-activate.err")" || {
    echo "::error::'min session activate --network own_ip --ingress $port:$port' failed"
    cat "$WORK/ingress-activate.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  echo "own-IP ingress session: $sid"

  # The server INSIDE the box, on the mapping's internal port. Bound on all the
  # box's addresses (no `bind=`): the switch forwards to the box's tap address,
  # not to its loopback. `socat` is in the launcher baseline
  # (base/coreutils/socat), so nothing has to be added first. The body carries a
  # marker, because a bare 200 from something else on the host must not pass for
  # the box's answer; the response is close-delimited, so the canned bytes need
  # no Content-Length arithmetic.
  mnl session exec "$sid" \
    "printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n$marker\n' > /tmp/ingress-resp.http" \
    || { echo "::error::could not seed the in-box responder's canned response"; fail; }
  mnl session exec "$sid" socat -T30 "TCP-LISTEN:$port,reuseaddr,fork" \
    'SYSTEM:cat /tmp/ingress-resp.http' >"$WORK/ingress-socat.log" 2>&1 &
  local socat_pid=$!

  # The published address, read from the HOST. Retried: the responder was just
  # forked and the forward is live before it binds, so early attempts can be
  # refused for reasons that say nothing about the mapping.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    body="$(curl -sS --max-time 10 "http://127.0.0.1:$port/" 2>"$WORK/ingress-curl.err")"
    [[ "$body" == *"$marker"* ]] && break
    sleep 1
  done
  if [[ "$body" != *"$marker"* ]]; then
    echo "::error::NET-040: GET http://127.0.0.1:$port/ did not return the in-box server's response (want '$marker', got '${body:-<no response>}')"
    echo "--- curl stderr ---"; cat "$WORK/ingress-curl.err" 2>/dev/null || true
    echo "--- in-box responder log ---"; cat "$WORK/ingress-socat.log" 2>/dev/null || true
    echo "--- activate stderr ---"; cat "$WORK/ingress-activate.err" 2>/dev/null || true
    kill "$socat_pid" 2>/dev/null || true
    fail
  fi
  echo "NET-040 OK: 127.0.0.1:$port answered with the in-box server's response"

  kill "$socat_pid" 2>/dev/null || true
  wait "$socat_pid" 2>/dev/null || true
  mnl session destroy --force "$sid" >/dev/null 2>&1 || true
  echo "::endgroup::"
}

# Native resolution proof (NET-009, NET-122, NET-123): a session start's
# stderr carries the resolver advisory naming the exact setup command, and
# asks nothing (stdin is never a tty); running that command — root, once —
# makes `<name>.min.internal` resolve through the host's own resolver for any
# process with every proxy variable unset; and a session start afterwards
# prints no advisory. Native Linux only: a VM-backed target's daemon lives in
# the guest and judges nothing about the host, and the privileged step needs
# passwordless sudo, exactly as the AppArmor remediation above does.
run_case_native_resolution_without_proxy_env() {
  local natres_name natres_sid setup_cmd setup_argv resolved
  echo "::group::native resolution proof (min net setup, then resolve with no proxy env)"
  if [ -n "$E2E_VM" ]; then
    echo "native resolution proof SKIPPED (VM-backed target: the host-side answerer is not part of this proof)"
    echo "::endgroup::"
    return 0
  fi
  if [ "$(uname -s)" != Linux ] || ! sudo -n true 2>/dev/null; then
    echo "native resolution proof SKIPPED (needs Linux with passwordless sudo for the privileged setup step)"
    echo "::endgroup::"
    return 0
  fi
  # The session whose start is advised and whose name the host then resolves.
  # A `none` box: it is published at a loopback address of its own, which the
  # zone answers whether or not the box runs, whereas a host-address box on
  # the shared address answers NODATA until something runs in it (NET-128) —
  # and nothing attaches to this one.
  NATRES_SEED_DIR="$(mktemp -d /tmp/mnlr.XXXXXX)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$NATRES_SEED_DIR/minimal.toml"
  mkdir "$NATRES_SEED_DIR/.git"
  natres_name="e2e-natres"
  natres_sid="$(cd "$NATRES_SEED_DIR" && mnl session activate . --no-prompt \
    --network none --name "$natres_name" 2>"$WORK/natres-advise.err")" || {
    echo "::error::'min session activate' failed for the native resolution case"
    echo "--- stderr ---"; cat "$WORK/natres-advise.err" 2>/dev/null || true
    fail
  }
  natres_sid="$(printf '%s\n' "$natres_sid" | tail -n1 | tr -d '\r')"
  echo "native resolution session: $natres_sid"
  # NET-122: the advisory names the exact command, on a line of its own.
  setup_cmd="$(grep -E '^ *sudo .* net setup$' "$WORK/natres-advise.err" | head -n1 | sed 's/^ *//')"
  if [ -z "$setup_cmd" ]; then
    echo "::error::activate printed no resolver advisory naming 'sudo ... net setup'"
    echo "--- activate stderr ---"; cat "$WORK/natres-advise.err" 2>/dev/null || true
    fail
  fi
  echo "advisory command: $setup_cmd"
  # Run it exactly as advised, minus the `sudo` the runner's own `sudo -n`
  # supplies so a missing password can never turn into a prompt here.
  setup_argv="${setup_cmd#sudo }"
  NATRES_REMOVE="$setup_argv --remove"
  # shellcheck disable=SC2086,SC2024 # a word list on purpose; the output file is ours, not root's.
  if ! sudo -n $setup_argv >"$WORK/setup.out" 2>&1; then
    echo "::error::'$setup_cmd' failed"
    echo "--- output ---"; cat "$WORK/setup.out"
    fail
  fi
  cat "$WORK/setup.out"

  # NET-009: the host resolver answers the box name for an ordinary process
  # — no proxy, no PAC, no proxy variable — with a host loopback address.
  resolved="$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    getent hosts "$natres_name.min.internal" 2>&1)"
  if ! printf '%s\n' "$resolved" | grep -Eq '^127\.'; then
    echo "::error::'$natres_name.min.internal' did not resolve natively to a loopback address: '$resolved'"
    echo "--- resolvectl status ---"; resolvectl status 2>&1 | tail -30 || true
    fail
  fi
  echo "resolved natively: $resolved"

  # NET-122's WHILE: with the hook in place a session start advises nothing.
  mnl session destroy --force "$natres_sid" >/dev/null 2>&1 || true
  natres_sid="$(cd "$NATRES_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-natres-hooked 2>"$WORK/natres.err")" || {
    echo "::error::'min session activate' after the resolver setup failed"
    echo "--- stderr ---"; cat "$WORK/natres.err" 2>/dev/null || true
    fail
  }
  natres_sid="$(printf '%s\n' "$natres_sid" | tail -n1 | tr -d '\r')"
  if grep -q 'net setup' "$WORK/natres.err"; then
    echo "::error::a session start after the resolver setup still printed the advisory"
    echo "--- stderr ---"; cat "$WORK/natres.err"
    fail
  fi
  mnl session destroy --force "$natres_sid" >/dev/null 2>&1 || true
  rm -rf "$NATRES_SEED_DIR"; NATRES_SEED_DIR=""
  echo "native resolution proof OK (advised, set up, resolved with no proxy env, no re-advisory)"
  echo "::endgroup::"
}

# NET T18: an own-address box's egress is declared and enforced, end to end.
# Gated on MINVMD_GVPROXY_BIN like the own-IP proof above — own-IP needs a
# real switch, VM-backed or not.
#
# The `min` CLI has no flag yet for a bespoke allow list (NET-060 is proven at
# the `sessions` crate's own unit level, `spec_accepts_egress_fields`), so
# this proves the one declaration reachable end to end today: the deny-all
# default for a box with no `egress` section at all (NET-074/075/076). That
# default declares an empty `allow_subnets` list — `min session policy` names
# it — which reaches nothing outside the resolver carve-out
# (crates/sessions/src/core/net_verdict.rs), while a box activated before the
# window is in force still reaches everywhere, and the CLI says the change is
# coming before it lands.
run_case_own_ip_egress_declared_and_enforced() {
  echo "::group::own-IP egress: declared and enforced (NET T18)"

  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "own-IP egress proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
    echo "::endgroup::"
    return 0
  fi

  # Same shape as the own-IP proof's own seed above: a separate dir with the
  # repo's [upstream] plus the shell stack (curl, needed below).
  OWNIP_SEED_DIR="$(mktemp -d /tmp/mnleg.XXXXXX)"
  OWNIP_SEED_DIR="$(cd "$OWNIP_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$OWNIP_SEED_DIR/minimal.toml"
  mkdir "$OWNIP_SEED_DIR/.git"

  # Greps whichever host log this lane actually writes the drop to: native
  # minimald enforces in its own process (crates/minimald/src/net/switch.rs,
  # "network policy violation"), while a VM-backed host decides on minvmd
  # instead (crates/minvmd/src/net/filter.rs, "frame leaving the VM dropped by
  # the host-side filter") because minimald runs inside the guest there.
  # Checking both patterns against both log globs needs no E2E_VM branch.
  assert_egress_drop_logged() {
    if find "$XDG_STATE_HOME/minimal/logs" -type f \
        \( -name 'minimald.log.*' -o -name 'minvmd.log.*' \) \
        -exec grep -q -e "network policy violation" \
                      -e "frame leaving the VM dropped by the host-side filter" {} + \
        2>/dev/null; then
      echo "daemon log: found the egress-drop warning"
      return 0
    fi
    echo "::error::no daemon log recorded the disallowed connection's drop"
    fail
  }

  # -- Announced, not yet in force: activate says the change is coming ------
  # The note (crates/minimal/src/cmd/session.rs) is printed client-side
  # before the daemon is even contacted, so this is the CLI's own decision —
  # nothing has spawned a daemon yet, and this case spawns its own.
  unset MINIMAL_EGRESS_DENY_ALL_WINDOW MINIMAL_EGRESS_DENY_ALL_OPT_OUT
  pre_sid="$(cd "$OWNIP_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-egress-pre --network own-ip 2>"$WORK/egress-pre.err")" || {
    echo "::error::'min session activate --network own-ip' (window announced) failed"
    cat "$WORK/egress-pre.err" 2>/dev/null || true
    fail
  }
  pre_sid="$(printf '%s\n' "$pre_sid" | tail -n1 | tr -d '\r')"
  if ! grep -q "deny-all the default" "$WORK/egress-pre.err"; then
    echo "::error::activate did not announce the coming deny-all default"
    cat "$WORK/egress-pre.err"
    fail
  fi
  echo "NET-076 OK: activate announced the coming deny-all default before it was in force"

  # -- An allowed connection completes: no default in force, nothing denied -
  pre_status=""
  for _ in 1 2 3; do
    pre_status="$(mnl session exec "$pre_sid" curl -sS -o /dev/null -w '%{http_code}' \
      --max-time 30 https://example.com 2>"$WORK/egress-pre-curl.err")"
    [ "$pre_status" = "200" ] && break
    sleep 1
  done
  if [ "$pre_status" != "200" ]; then
    echo "::error::an allowed connection did not complete before the deny-all default was in force (got '$pre_status')"
    cat "$WORK/egress-pre-curl.err" 2>/dev/null || true
    fail
  fi
  echo "allowed-connection OK: a box that declares nothing reaches out before the default lands"
  mnl session destroy --force "$pre_sid" >/dev/null 2>&1 || true

  # -- Force the window: an already-running daemon keeps the environment it
  # was launched with, so trying the forced window against it would just
  # re-read the same "announced" state. Stop it and let the next activate
  # respawn one that inherits MINIMAL_EGRESS_DENY_ALL_WINDOW=in-force.
  mnl stop --force >/dev/null 2>"$WORK/egress-stop.err" || {
    echo "::error::'min stop' before the forced-window activate failed"
    cat "$WORK/egress-stop.err" 2>/dev/null || true
    fail
  }
  export MINIMAL_EGRESS_DENY_ALL_WINDOW=in-force

  sid="$(cd "$OWNIP_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-egress --network own-ip 2>"$WORK/egress-activate.err")" || {
    echo "::error::'min session activate --network own-ip' (window in force) failed"
    cat "$WORK/egress-activate.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$sid" | tail -n1 | tr -d '\r')"
  echo "own-IP session (deny-all default in force): $sid"
  if grep -q "deny-all the default" "$WORK/egress-activate.err"; then
    echo "::error::activate still announced the coming change once the window was in force"
    cat "$WORK/egress-activate.err"
    fail
  fi

  # -- Declared: an undeclared box's egress is the deny-all allow_subnets=[] -
  policy_json="$(mnl session policy "$sid" 2>"$WORK/egress-policy.err")" || {
    echo "::error::'min session policy' failed"
    cat "$WORK/egress-policy.err" 2>/dev/null || true
    fail
  }
  if [[ "$policy_json" != *'"allow_subnets":[]'* ]]; then
    echo "::error::NET-074: the box's declared egress is not the empty (deny-all) allow_subnets list"
    echo "$policy_json"
    fail
  fi
  if ! grep -q "deny-all" "$WORK/egress-policy.err"; then
    echo "::error::NET-075: 'min session policy' did not name the box's posture deny-all"
    cat "$WORK/egress-policy.err"
    fail
  fi
  echo "NET-074/075 OK: no egress section declared no destination, and is named deny-all"

  # -- A disallowed connection drops silently: no reset, so curl hangs to its
  # own timeout rather than failing fast (a reset would take seconds, not this).
  deny_start_ms="$(now_ms)"
  mnl session exec "$sid" curl -sS -o /dev/null -w '%{http_code}' --max-time 10 https://example.com \
    >"$WORK/egress-deny.out" 2>"$WORK/egress-deny.err"
  deny_rc=$?
  deny_elapsed_ms=$(( $(now_ms) - deny_start_ms ))
  deny_status="$(cat "$WORK/egress-deny.out" 2>/dev/null)"
  echo "(inside $sid) GET https://example.com -> rc=$deny_rc status=${deny_status:-<none>} elapsed=${deny_elapsed_ms}ms"
  if [ "$deny_rc" -eq 0 ] || [ "$deny_status" = "200" ]; then
    echo "::error::NET-062: a disallowed connection completed; the deny-all default did not enforce"
    fail
  fi
  if [ "$deny_elapsed_ms" -lt 6000 ]; then
    echo "::error::NET-062: a disallowed connection failed in ${deny_elapsed_ms}ms — that is a fast refusal, not a silent drop"
    cat "$WORK/egress-deny.err" 2>/dev/null || true
    fail
  fi
  echo "NET-062 OK: a disallowed connection dropped silently (timed out, not reset)"
  assert_egress_drop_logged
  echo "NET-062 (rate-limited warning) OK: the drop is logged"

  mnl session destroy --force "$sid" >/dev/null 2>&1 || true
  rm -rf "$OWNIP_SEED_DIR"; OWNIP_SEED_DIR=""
  unset MINIMAL_EGRESS_DENY_ALL_WINDOW
  echo "::endgroup::"
}

# Integration: the whole network-posture story in one lane, tying together
# what NET-035/036 (help + reference), NET-038/039 (`none`), and NET-040/107
# (`own_ip` ingress + outbound reach) each prove on their own — so a
# regression in how the pieces COMPOSE (choosing a posture on a stock
# install), not just in one piece alone, fails a single named case. The
# own-IP and outbound-reach legs are the existing named cases above, called
# directly rather than re-deriving their retry/response logic here.
run_case_network_posture_from_stock_install() {
  echo "::group::network posture: --network/--ingress shown in help and the reference"
  local help_out
  help_out="$(mnl session activate --help 2>&1)" || {
    echo "::error::'min session activate --help' failed"
    fail
  }
  for needle in --network --ingress none host_ip own_ip; do
    if ! printf '%s' "$help_out" | grep -q -- "$needle"; then
      echo "::error::'min session activate --help' does not show '$needle'"
      printf '%s\n' "$help_out"
      fail
    fi
  done
  local ref_file="$ROOT/docs/reference/cli-min.md"
  for needle in --network --ingress none host_ip own_ip; do
    if ! grep -q -- "$needle" "$ref_file"; then
      echo "::error::$ref_file does not document '$needle'"
      fail
    fi
  done
  echo "help + reference OK: --network and --ingress, with none/host_ip/own_ip, are both shown"
  echo "::endgroup::"

  echo "::group::network posture: a --network none box accepts attach and reaches nothing"
  local none_out none_sid attach_out
  none_out="$(cd "$PROJECT_DIR" && mnl session activate . --no-prompt --name e2e-posture-none \
    --network none 2>"$WORK/posture-none-activate.err")" || {
    echo "::error::'min session activate --network none' failed"
    cat "$WORK/posture-none-activate.err" 2>/dev/null || true
    fail
  }
  none_sid="$(printf '%s\n' "$none_out" | tail -n1 | tr -d '\r')"
  echo "none-network session: $none_sid"

  # The attach path, not the sandbox network layer: a trivial exec is the
  # same non-interactive stand-in the session-exec proof above uses, and is
  # what network_none_attach_works asserts at the unit level too.
  attach_out="$(mnl session exec "$none_sid" echo mi-posture-none-attach-ok 2>"$WORK/posture-none-exec.err")"
  if [ "$attach_out" != "mi-posture-none-attach-ok" ]; then
    echo "::error::a --network none box refused a trivial exec (the attach path); got '${attach_out:-<none>}'"
    cat "$WORK/posture-none-exec.err" 2>/dev/null || true
    mnl session destroy --force "$none_sid" >/dev/null 2>&1 || true
    fail
  fi
  echo "NET-039 OK: a --network none box accepts attach"

  if mnl session exec "$none_sid" curl -sS -o /dev/null --max-time 5 http://example.com \
      >/dev/null 2>"$WORK/posture-none-curl.err"; then
    echo "::error::a --network none box reached http://example.com; it must reach nothing"
    cat "$WORK/posture-none-curl.err" 2>/dev/null || true
    mnl session destroy --force "$none_sid" >/dev/null 2>&1 || true
    fail
  fi
  echo "NET-038 OK: a --network none box reaches nothing"

  mnl session destroy --force "$none_sid" >/dev/null 2>&1 || true
  echo "::endgroup::"

  # NET-040: own-IP --ingress on loopback. Gated inside the case itself on
  # MINVMD_GVPROXY_BIN — the one signal a switch exists — so a target with no
  # switch SKIPs rather than fails, same as running it standalone.
  run_case_fresh_install_own_ip_ingress_publishes_loopback
  # NET-107: outbound reach from a session, on every lane (not gated on a
  # switch — a native lane has no switch to lose and still needs the check).
  run_case_session_outbound_request
}

# NET-082/NET-083/NET-130, the three enforcement/observability pieces of the
# escape bound (NET-085) this script can check end to end against a REAL
# VM-backed box, over the shipped `min` CLI:
#
#   - NET-083: the box itself has no CAP_NET_RAW, so it cannot forge a
#     source address locally in the first place.
#   - NET-082: the guest boots with IPv6 disabled, so no netns in it --
#     this box's own included -- ever has an IPv6 route.
#   - NET-130: the box's effective policy (`min session policy`) shows the
#     node-plane baseline set (registry, cache, resolver) beside its rules.
#
# NET-085's own bound -- that a spoofed source reaches only the union of
# resident boxes' DECLARED egress plus that baseline set -- is proven as a
# T0 system test against the real production filter/relay in
# crates/minvmd/tests/escape_bound_integration.rs
# (`cargo nextest run -p minvmd vm_escape_bounded_to_resident_union`): it
# plays the root-in-VM spoofer directly against `HostFilter`, admitting only
# the resident union and nothing to an address no box holds. Reproducing
# that same forged-frame handshake here, from this script, needs a box with
# a non-trivial DECLARED egress to bound the spoof against, and there is no
# shipped way to declare one yet: `activate_session` hard-codes
# `egress: None` (crates/minimal/src/cmd/session.rs), and NET-076 says the
# deny-all default for an absent `egress` section is "announced but not yet
# in force" -- every resident box's declared reach is "everything" until
# that CLI/config surface lands, so a spoof-and-verify rerun here would
# bound a forged address against nothing narrower than the three checks
# below already establish. This case is honest about that gap rather than
# faking a bound with no declaration behind it.
run_case_escape_reaches_only_declared_union() {
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "escape-bound proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
    return 0
  fi
  echo "::group::escape into the VM reaches only the declared union (NET-082, NET-083, NET-130)"

  ESCAPE_SEED_DIR="$(mktemp -d /tmp/mnlx.XXXXXX)"
  ESCAPE_SEED_DIR="$(cd "$ESCAPE_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$ESCAPE_SEED_DIR/minimal.toml"
  mkdir "$ESCAPE_SEED_DIR/.git"

  local esc_out esc_sid
  esc_out="$(cd "$ESCAPE_SEED_DIR" && mnl session activate . --no-prompt --name e2e-escape \
    --network own_ip 2>"$WORK/mi-escape-activate.err")" || {
    echo "::error::'min session activate --network own_ip' failed for the escape-bound case"
    cat "$WORK/mi-escape-activate.err" 2>/dev/null || true
    fail
  }
  esc_sid="$(printf '%s\n' "$esc_out" | tail -n1 | tr -d '\r')"
  echo "escape-bound session: $esc_sid"

  # NET-083: no CAP_NET_RAW in the box's own capability set.
  local capeff
  capeff="$(mnl session exec "$esc_sid" grep -m1 '^CapEff:' /proc/self/status \
    2>"$WORK/mi-escape-caps.err" | awk '{print $2}')"
  if [ -z "$capeff" ]; then
    echo "::error::could not read the box's CapEff from /proc/self/status"
    cat "$WORK/mi-escape-caps.err" 2>/dev/null || true
    fail
  fi
  if (( (16#$capeff) & 0x2000 )); then
    echo "::error::NET-083: the box's process retains CAP_NET_RAW (CapEff=$capeff)"
    fail
  fi
  echo "NET-083 OK: the box has no CAP_NET_RAW (CapEff=$capeff)"

  # NET-082: no IPv6 route anywhere in the guest, this box's own netns
  # included -- `/proc/net/ipv6_route` is either absent or empty with
  # `ipv6.disable=1` on the kernel command line.
  local v6route
  v6route="$(mnl session exec "$esc_sid" sh -c \
    'if [ -e /proc/net/ipv6_route ]; then cat /proc/net/ipv6_route; fi' \
    2>"$WORK/mi-escape-v6.err")"
  if [ -n "$v6route" ]; then
    echo "::error::NET-082: the guest has an IPv6 route (expected none): $v6route"
    fail
  fi
  echo "NET-082 OK: no IPv6 route in the guest"

  # NET-130: the baseline set (registry, cache, resolver -- BaselineCategory::ALL)
  # is shown beside the box's effective rules.
  local shown marker
  shown="$(mnl session policy "$esc_sid" 2>"$WORK/mi-escape-policy.err")" || {
    echo "::error::'min session policy' failed for the escape-bound case"
    cat "$WORK/mi-escape-policy.err" 2>/dev/null || true
    fail
  }
  for marker in '"baseline"' '"category":"registry"' '"category":"cache"' '"category":"resolver"'; do
    if [[ "$shown" != *"$marker"* ]]; then
      echo "::error::NET-130: the policy line is missing $marker: $shown"
      fail
    fi
  done
  echo "NET-130 OK: the baseline set (registry, cache, resolver) is shown beside the effective rules"

  echo "::warning::NET-085's union-bound reach test (a spoofed source admitted only to the resident union plus the baseline set) is not reproduced live here: no shipped surface lets this script declare a box's egress yet, so there is no non-trivial declared reach to bound a spoof against on a real host today. cargo nextest run -p minvmd vm_escape_bounded_to_resident_union is the T0 system test proving that bound against the real filter; once a box can declare egress end to end, this case should replay it against a live session."

  mnl session destroy --force "$esc_sid" >/dev/null 2>&1 || true
  rm -rf "$ESCAPE_SEED_DIR"; ESCAPE_SEED_DIR=""
  echo "::endgroup::"
}

# NET-009, NET-010, NET-018, NET-019, NET-122: the whole "names resolve
# natively, by identity" story, composed into one proof — each requirement
# above already has its own unit-level verify command; this is what breaks
# when the pieces do not compose. The one advisory command from a session
# start; running it once; two own-address boxes on the SAME port resolving
# natively to two DIFFERENT loopback addresses with no proxy, PAC file, or
# proxy environment variable anywhere; `activate` and `ls` both reporting
# native DNS as the live surface; and the hostname proxy still routing the
# first box by name. The one TCP reachability check rides that proxy leg,
# landing on the box's `--ingress`-published port: NET-121 (a forwarder
# onto a box's OWN leased address, bound before its name is registered) is
# not yet implemented on this branch, so nothing on the host serves that
# leased address directly yet — an own-IP box's name resolves to a real,
# distinct address today, but only its `--ingress`-published port answers a
# connection. Gated exactly like the native resolution proof above (Linux,
# passwordless sudo for the privileged setup step) plus the own-IP proof's
# switch gate (own-IP boxes need a real switch, VM-backed or not).
run_case_box_name_resolves_natively_without_proxy() {
  echo "::group::box names resolve natively, by identity (min net setup, two own-address boxes, no proxy)"
  if [ -n "$E2E_VM" ]; then
    echo "native box-identity proof SKIPPED (VM-backed target: the host-side answerer is not part of this proof)"
    echo "::endgroup::"
    return 0
  fi
  if [ "$(uname -s)" != Linux ] || ! sudo -n true 2>/dev/null; then
    echo "native box-identity proof SKIPPED (needs Linux with passwordless sudo for the privileged setup step)"
    echo "::endgroup::"
    return 0
  fi
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "native box-identity proof SKIPPED (no MINVMD_GVPROXY_BIN: own-IP boxes need a real switch)"
    echo "::endgroup::"
    return 0
  fi

  local port=3000 web_name=e2e-boxid-web api_name=e2e-boxid-api
  local web_marker=BOXID_WEB_OK
  local web_sid api_sid web_resolved api_resolved web_addr api_addr
  local setup_cmd setup_argv web_socat_pid
  local proxy_status=""

  BOXID_SEED_DIR="$(mktemp -d /tmp/mnlbw.XXXXXX)"
  BOXID_SEED_DIR="$(cd "$BOXID_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$BOXID_SEED_DIR/minimal.toml"
  mkdir "$BOXID_SEED_DIR/.git"

  # A second, SEPARATE seed dir: a path that already has a session does not
  # mint a second one (same reasoning as the own-IP proof's own seed above).
  BOXID_SEED_DIR2="$(mktemp -d /tmp/mnlba.XXXXXX)"
  BOXID_SEED_DIR2="$(cd "$BOXID_SEED_DIR2" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$BOXID_SEED_DIR2/minimal.toml"
  mkdir "$BOXID_SEED_DIR2/.git"

  # The first box, started BEFORE the setup step: its activate stderr is
  # where the NET-122 advisory (naming the exact command) is captured. It
  # also declares `--ingress`: the box's own leased address answers no
  # connection yet (NET-121's forwarder onto it is not implemented on this
  # branch), and `register_own_ip` (dns.rs) always routes the hostname
  # proxy's own-IP boxes to loopback, not to the lease — the published port
  # is the one address anything outside the box can actually reach today.
  web_sid="$(cd "$BOXID_SEED_DIR" && mnl session activate . --no-prompt \
    --name "$web_name" --network own_ip --ingress "$port:$port" \
    2>"$WORK/boxid-web-activate.err")" || {
    echo "::error::'min session activate --network own_ip --ingress $port:$port --name $web_name' failed"
    cat "$WORK/boxid-web-activate.err" 2>/dev/null || true
    fail
  }
  web_sid="$(printf '%s\n' "$web_sid" | tail -n1 | tr -d '\r')"
  echo "own-address session: $web_sid ($web_name)"

  setup_cmd="$(grep -E '^ *sudo .* net setup$' "$WORK/boxid-web-activate.err" | head -n1 | sed 's/^ *//')"
  if [ -z "$setup_cmd" ]; then
    echo "::error::activate printed no resolver advisory naming 'sudo ... net setup'"
    echo "--- activate stderr ---"; cat "$WORK/boxid-web-activate.err" 2>/dev/null || true
    fail
  fi
  echo "advisory command: $setup_cmd"
  # Run it exactly as advised, minus the `sudo` the runner's own `sudo -n`
  # supplies so a missing password can never turn into a prompt here.
  setup_argv="${setup_cmd#sudo }"
  BOXID_REMOVE="$setup_argv --remove"
  # shellcheck disable=SC2086,SC2024 # a word list on purpose; the output file is ours, not root's.
  if ! sudo -n $setup_argv >"$WORK/boxid-setup.out" 2>&1; then
    echo "::error::'$setup_cmd' failed"
    echo "--- output ---"; cat "$WORK/boxid-setup.out"
    fail
  fi
  cat "$WORK/boxid-setup.out"

  # The second box, started AFTER the setup step: NET-018's "activate
  # reports the native surface" half lives on THIS box's stderr. It
  # declares no `--ingress`: it exists only to prove NET-010's per-box
  # address, so it needs no listener of its own.
  api_sid="$(cd "$BOXID_SEED_DIR2" && mnl session activate . --no-prompt \
    --name "$api_name" --network own_ip 2>"$WORK/boxid-api-activate.err")" || {
    echo "::error::'min session activate --network own_ip --name $api_name' failed"
    cat "$WORK/boxid-api-activate.err" 2>/dev/null || true
    fail
  }
  api_sid="$(printf '%s\n' "$api_sid" | tail -n1 | tr -d '\r')"
  echo "own-address session: $api_sid ($api_name)"
  if ! grep -q "resolves natively on this host; that is the live surface" "$WORK/boxid-api-activate.err"; then
    echo "::error::NET-018: 'min session activate' did not report native DNS as the live surface"
    cat "$WORK/boxid-api-activate.err"
    fail
  fi
  if ! grep -q "hostname proxy keeps serving too" "$WORK/boxid-api-activate.err"; then
    echo "::error::NET-019: 'min session activate' did not say the hostname proxy keeps serving"
    cat "$WORK/boxid-api-activate.err"
    fail
  fi
  echo "NET-018/NET-019 OK: activate reported native DNS as the live surface, proxy still serving"

  # NET-009: the host resolver answers each box's name for an ordinary
  # process — no proxy, no PAC, no proxy variable anywhere. The unset list
  # matches the native resolution proof above.
  web_resolved="$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    getent hosts "$web_name.min.internal" 2>&1)"
  if ! printf '%s\n' "$web_resolved" | grep -Eq '^127\.'; then
    echo "::error::'$web_name.min.internal' did not resolve natively to a loopback address: '$web_resolved'"
    fail
  fi
  api_resolved="$(env -u http_proxy -u https_proxy -u HTTP_PROXY -u HTTPS_PROXY \
    -u all_proxy -u ALL_PROXY -u no_proxy -u NO_PROXY \
    getent hosts "$api_name.min.internal" 2>&1)"
  if ! printf '%s\n' "$api_resolved" | grep -Eq '^127\.'; then
    echo "::error::'$api_name.min.internal' did not resolve natively to a loopback address: '$api_resolved'"
    fail
  fi
  web_addr="$(printf '%s\n' "$web_resolved" | awk '{print $1; exit}')"
  api_addr="$(printf '%s\n' "$api_resolved" | awk '{print $1; exit}')"
  echo "resolved natively: $web_name -> $web_addr, $api_name -> $api_addr"

  # NET-010: two boxes on the SAME port answer at two DIFFERENT addresses —
  # no translation, no collision.
  if [ "$web_addr" = "$api_addr" ]; then
    echo "::error::NET-010: two own-address boxes answered the same loopback address ($web_addr)"
    fail
  fi
  echo "NET-010 OK: each box has its own loopback address ($web_addr != $api_addr)"

  # A responder inside the web box (`mnl session exec`) — `socat` is in the
  # launcher baseline, needing no `min add`. No `bind=`: like the own-IP
  # ingress proof above, the switch forwards to the box's own tap address,
  # not to a host loopback address, so the responder listens on all of the
  # box's addresses rather than the leased one nothing outside it can reach.
  mnl session exec "$web_sid" \
    "printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n$web_marker\n' > /tmp/boxid-web.http" \
    || { echo "::error::could not seed the web box's canned response"; fail; }
  mnl session exec "$web_sid" socat -T30 "TCP-LISTEN:$port,reuseaddr,fork" \
    'SYSTEM:cat /tmp/boxid-web.http' >"$WORK/boxid-web-socat.log" 2>&1 &
  web_socat_pid=$!

  # NET-018's other half: `min ls` reports the same native-surface notice.
  mnl ls >/dev/null 2>"$WORK/boxid-ls.err" || {
    echo "::error::'min ls' failed"
    cat "$WORK/boxid-ls.err" 2>/dev/null || true
    kill "$web_socat_pid" 2>/dev/null || true
    fail
  }
  if ! grep -q "resolves natively on this host; that is the live surface" "$WORK/boxid-ls.err"; then
    echo "::error::NET-018: 'min ls' did not report native DNS as the live surface"
    cat "$WORK/boxid-ls.err"
    kill "$web_socat_pid" 2>/dev/null || true
    fail
  fi
  echo "NET-018 OK: 'min ls' reported native DNS as the live surface too"

  # NET-019: the hostname proxy keeps serving the same box anyway, for
  # anything already pointed at it — native resolution is additive, not a
  # replacement. `register_own_ip` (dns.rs) always routes an own-IP box's
  # name to loopback, so this doubles as the case's one real reachability
  # check: it lands on the web box's `--ingress`-published port.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    proxy_status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
      --proxy 127.0.0.1:7654 "http://$web_name.min.internal:$port/" 2>"$WORK/boxid-proxy-curl.err")"
    [ "$proxy_status" = "200" ] && break
    sleep 1
  done
  if [ "$proxy_status" != "200" ]; then
    echo "::error::NET-019: the hostname proxy no longer routes $web_name.min.internal:$port (got '${proxy_status:-<no response>}')"
    cat "$WORK/boxid-proxy-curl.err" 2>/dev/null || true
    cat "$WORK/boxid-web-socat.log" 2>/dev/null || true
    kill "$web_socat_pid" 2>/dev/null || true
    fail
  fi
  echo "NET-019 OK: the hostname proxy still routes $web_name.min.internal"

  kill "$web_socat_pid" 2>/dev/null || true
  wait "$web_socat_pid" 2>/dev/null || true
  mnl session destroy --force "$web_sid" >/dev/null 2>&1 || true
  mnl session destroy --force "$api_sid" >/dev/null 2>&1 || true
  rm -rf "$BOXID_SEED_DIR" "$BOXID_SEED_DIR2"; BOXID_SEED_DIR=""; BOXID_SEED_DIR2=""
  echo "native box-identity proof OK (advised, set up, two own-address boxes resolve natively to distinct addresses, activate/ls agree, and the hostname proxy still reaches the published one)"
  echo "::endgroup::"
}

# NET-049 (x86_64) / NET-051 (arm64): on a Linux host of that arch that can run
# a microVM, `min --provider local-minvmd session activate` activates a session.
# Everything the box needs is what the Linux install ships (NET-048/NET-050,
# proved over the release table and the installer by
# `just test-installer linux_<arch>_manifest_ships_vm_stack`): `minvmd` found on
# PATH by name, the guest payload under the three stock file names, and the
# switch minvmd spawns for the guest's egress. So the case invents none of them
# — it requires each the way an install leaves it, SKIPs when this target has
# none of it (a hosted runner with no /dev/kvm, or the other arch), and
# otherwise boots the real thing.
#
# `--provider local-minvmd` is spelled out HERE rather than inherited from
# E2E_MINIMAL_ARGS: the requirement names that flag, so the case must exercise
# the flag and not a lane's default. That means bare `min`, not `mnl`, and the
# case stops the daemon it spawned under that provider itself — the suite's
# teardown only knows the lane's provider.
#
# "Fresh": $XDG_STATE_HOME is a per-run dir and a named case runs before
# anything has spawned a daemon, so the CLI auto-spawns minvmd, which boots the
# VM — the cold path a just-installed host takes.
run_case_fresh_kvm_activate_local_minvmd() {
  local arch_label="$1" want_uname="$2"
  echo "::group::a fresh $arch_label Linux install with KVM activates a --provider local-minvmd box"

  if [ "$(uname -s)" != Linux ]; then
    echo "fresh-KVM activate SKIPPED (this proof is about the LINUX install; host is $(uname -s))"
    echo "::endgroup::"
    return 0
  fi
  if [ "$(uname -m)" != "$want_uname" ]; then
    echo "fresh-KVM activate SKIPPED (this case proves the $arch_label install; host is $(uname -m))"
    echo "::endgroup::"
    return 0
  fi
  # The requirement says "with KVM", and that is a property of the HOST, not of
  # this script: without a usable /dev/kvm minvmd cannot boot at all
  # (crates/minvmd/src/cmd/mod.rs says so in as many words), so there is no
  # fresh-install claim to make here.
  if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
    echo "fresh-KVM activate SKIPPED (no usable /dev/kvm: this host cannot boot a microVM)"
    echo "::endgroup::"
    return 0
  fi

  # The VM host daemon, resolved the way the CLI resolves it: by NAME on PATH,
  # which is where the install puts it (bin/minvmd -> ~/.local/bin).
  local minvmd_bin
  minvmd_bin="$(command -v minvmd || true)"
  if [ -z "$minvmd_bin" ]; then
    echo "fresh-KVM activate SKIPPED (no minvmd on PATH: this target has no VM host daemon)"
    echo "::endgroup::"
    return 0
  fi
  echo "VM host daemon on PATH: $minvmd_bin"

  # The guest payload, under the three names the install places in its data dir
  # ($XDG_DATA_HOME/minimal/{vmlinuz,rootfs.img,initramfs.cpio} — the defaults
  # crates/minvmd/src/image.rs resolves). A lane that stages its own testbed
  # payload points the MINVMD_* overrides at it instead; either way the files
  # about to be booted must exist before the case claims a box can boot.
  local data_dir kernel_path rootfs_path initramfs_path payload
  data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/minimal"
  kernel_path="${MINVMD_KERNEL_PATH:-$data_dir/vmlinuz}"
  rootfs_path="${MINVMD_ROOTFS_PATH:-$data_dir/rootfs.img}"
  initramfs_path="${MINVMD_INITRAMFS:-$data_dir/initramfs.cpio}"
  for payload in "$kernel_path" "$rootfs_path" "$initramfs_path"; do
    if [ ! -f "$payload" ]; then
      echo "fresh-KVM activate SKIPPED (no guest payload at $payload: this target ships no VM stack)"
      echo "::endgroup::"
      return 0
    fi
  done
  echo "guest payload: $kernel_path, $rootfs_path, $initramfs_path"

  # The switch, the last shipped piece: minvmd spawns it for the guest's egress,
  # and a session mint pulls packages over that egress. A target without one
  # would fail the activate for want of a network rather than for want of the
  # provider, which is not this requirement's claim.
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ] && ! command -v gvproxy-min >/dev/null 2>&1; then
    echo "fresh-KVM activate SKIPPED (no switch: MINVMD_GVPROXY_BIN unset and no gvproxy-min on PATH)"
    echo "::endgroup::"
    return 0
  fi

  local out sid got
  out="$(cd "$PROJECT_DIR" && min --provider local-minvmd session activate . --no-prompt \
    --name "e2e-kvm-$arch_label" 2>"$WORK/kvm-activate.err")" || {
    echo "::error::'min --provider local-minvmd session activate' failed on a fresh $arch_label Linux host with KVM"
    cat "$WORK/kvm-activate.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  echo "local-minvmd session: $sid"

  # Activated, not merely accepted: a trivial exec round-trips through the
  # guest's daemon over the vsock bridge — the same non-interactive stand-in the
  # session-exec proof uses.
  got="$(min --provider local-minvmd session exec "$sid" echo mi-kvm-activate-ok \
    2>"$WORK/kvm-exec.err")"
  if [ "$got" != mi-kvm-activate-ok ]; then
    echo "::error::the --provider local-minvmd box refused a trivial exec; got '${got:-<none>}'"
    cat "$WORK/kvm-exec.err" 2>/dev/null || true
    min --provider local-minvmd session destroy --force "$sid" >/dev/null 2>&1 || true
    fail
  fi

  # And it is the VM backend that hosted it, not the host-native daemon wearing
  # the flag: all local-minvmd state lives under the provider's own root
  # (post-#690), which only a minvmd-backed activate creates.
  local prov_dir="$XDG_STATE_HOME/minimal/providers/local-minvmd0"
  if [ ! -d "$prov_dir" ]; then
    echo "::error::no local-minvmd provider state at $prov_dir: the session was not hosted in a microVM"
    min --provider local-minvmd session destroy --force "$sid" >/dev/null 2>&1 || true
    fail
  fi
  echo "OK: a fresh $arch_label Linux install with KVM activated $sid with --provider local-minvmd"

  min --provider local-minvmd session destroy --force "$sid" >/dev/null 2>&1 || true
  min --provider local-minvmd stop --force >/dev/null 2>&1 || true
  minvmd stop >/dev/null 2>&1 || true
  echo "::endgroup::"
}

run_case_fresh_linux_kvm_activate_local_minvmd() {
  run_case_fresh_kvm_activate_local_minvmd amd64 x86_64
}

run_case_fresh_arm64_kvm_activate_local_minvmd() {
  run_case_fresh_kvm_activate_local_minvmd arm64 aarch64
}

# NET-020..022 (recovery) + NET-024..027 (port choice / two daemons): the
# hostname-proxy port mechanics land as unit proofs in crates/minimald/src/
# net/proxy.rs; this stitches them into one end-to-end case. Gated on a
# native `minimald` binary being on PATH — the whole case is unreachable on
# macOS, which has no native daemon backend at all (AGENTS.md "Platform
# matrix") — and the two-daemons half is additionally gated on
# MINVMD_GVPROXY_BIN, the same signal the own-IP proofs above use for "this
# target has no switch". Unlike the native-only cases above (e.g.
# native_resolution_without_proxy_env), this one does NOT skip on E2E_VM:
# the two-daemons half needs a native minimald *and* a VM-backed one live
# at once, so on the Linux/KVM lane (E2E_VM=1, with a built native minimald
# also on PATH) it deliberately starts that native daemon alongside the
# VM-backed target under test.
run_case_hostnames_recover_and_two_daemons_route() {
  echo "::group::hostnames recover, and two daemons share a machine (NET-020..022, NET-024..027)"

  if ! command -v minimald >/dev/null 2>&1; then
    echo "hostnames-recover-and-two-daemons proof SKIPPED (no native minimald binary on PATH: this host runs minvmd only)"
    echo "::endgroup::"
    return 0
  fi

  mnl --provider local-minimald stop --force >/dev/null 2>&1 || true

  # -- Occupy the proxy port, activate: see the reason and remedy (NET-020) -
  # `min` autospawn never passes --hostname-proxy-port (it only ever starts a
  # daemon with no port configured), so the only way to reach the fault an
  # operator's flag can hit is to start the daemon ourselves, configured to a
  # port we already hold: bound as given, never substituted (NET-024), so the
  # bind fails exactly the way it would for that operator, rather than
  # silently falling back to a free port the way an unconfigured daemon does
  # (NET-025).
  hr_port_file="$WORK/hr-occupied-port"
  python3 -c '
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 0))
s.listen(1)
print(s.getsockname()[1], flush=True)
time.sleep(300)
' >"$hr_port_file" 2>"$WORK/hr-occupier.err" &
  HR_OCCUPIER_PID=$!
  hr_port=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    hr_port="$(tr -d '[:space:]' <"$hr_port_file" 2>/dev/null)"
    [ -n "$hr_port" ] && break
    sleep 1
  done
  if [ -z "$hr_port" ]; then
    echo "::error::could not occupy a loopback port to force the hostname-proxy bind to fail"
    cat "$WORK/hr-occupier.err" 2>/dev/null || true
    fail
  fi
  echo "occupied 127.0.0.1:$hr_port to force the native daemon's configured hostname-proxy bind to fail"

  if ! minimald run --detach --instance-num 0 --hostname-proxy-port "$hr_port" \
      >"$WORK/hr-minimald.out" 2>"$WORK/hr-minimald.err"; then
    echo "::error::'minimald run --detach --hostname-proxy-port $hr_port' failed"
    cat "$WORK/hr-minimald.err" 2>/dev/null || true
    fail
  fi

  hr_out="$(cd "$PROJECT_DIR" && mnl --provider local-minimald session activate . --no-prompt \
    --name e2e-hostrecover 2>"$WORK/hr-activate.err")" || {
    echo "::error::'min session activate' (native, configured port held) failed"
    cat "$WORK/hr-activate.err" 2>/dev/null || true
    fail
  }
  hr_sid="$(printf '%s\n' "$hr_out" | tail -n1 | tr -d '\r')"
  echo "native session (hostname-proxy port held): $hr_sid"

  if ! grep -q "warning: session hostnames will not route:" "$WORK/hr-activate.err"; then
    echo "::error::NET-020: activate did not report why box hostnames will not route"
    cat "$WORK/hr-activate.err"
    fail
  fi
  if ! grep -q "remedy: free the listen address" "$WORK/hr-activate.err"; then
    echo "::error::NET-020: activate reported the reason but not the remedy"
    cat "$WORK/hr-activate.err"
    fail
  fi
  echo "NET-020 OK: activate printed why box hostnames will not route, and the remedy"

  # -- Free it: ls clears without a restart (NET-021, NET-022) -------------
  kill "$HR_OCCUPIER_PID" 2>/dev/null || true
  wait "$HR_OCCUPIER_PID" 2>/dev/null || true
  HR_OCCUPIER_PID=""
  echo "freed 127.0.0.1:$hr_port"

  # The daemon's retry loop started backing off (up to the 30s cap) from its
  # very first failed bind at startup, not from when we free the port here,
  # so the wait after freeing can span most of one full backoff cycle.
  hr_cleared=0
  for _ in $(seq 1 90); do
    mnl --provider local-minimald ls >"$WORK/hr-ls.out" 2>"$WORK/hr-ls.err" || true
    if ! grep -q "warning: session hostnames will not route:" "$WORK/hr-ls.err"; then
      hr_cleared=1
      break
    fi
    sleep 1
  done
  if [ "$hr_cleared" -ne 1 ]; then
    echo "::error::NET-021/022: 'min ls' still warns that hostnames will not route, 90s after the port was freed with no daemon restart"
    cat "$WORK/hr-ls.err" 2>/dev/null || true
    fail
  fi
  echo "NET-021/022 OK: the daemon rebound on its own; 'min ls' stopped warning with no restart"

  # -- A native and a VM daemon both route names at once (NET-024..027) ----
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "two-daemons proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch, so a VM daemon cannot come up)"
    mnl --provider local-minimald session destroy --force "$hr_sid" >/dev/null 2>&1 || true
    mnl --provider local-minimald stop --force >/dev/null 2>&1 || true
    echo "::endgroup::"
    return 0
  fi

  hr_native_port="$hr_port"
  echo "native daemon's hostname proxy: 127.0.0.1:$hr_native_port"

  HR_VM_SEED_DIR="$(mktemp -d /tmp/mnlhr.XXXXXX)"
  HR_VM_SEED_DIR="$(cd "$HR_VM_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$HR_VM_SEED_DIR/minimal.toml"
  mkdir "$HR_VM_SEED_DIR/.git"

  hr_vm_out="$(cd "$HR_VM_SEED_DIR" && mnl --provider local-minvmd session activate . --no-prompt \
    --name e2e-hostrecover-vm 2>"$WORK/hr-vm-activate.err")" || {
    echo "::error::'min session activate --provider local-minvmd' failed"
    cat "$WORK/hr-vm-activate.err" 2>/dev/null || true
    fail
  }
  hr_vm_sid="$(printf '%s\n' "$hr_vm_out" | tail -n1 | tr -d '\r')"
  echo "VM session: $hr_vm_sid"

  hr_vm_port="$(grep -o 'proxy at 127\.0\.0\.1:[0-9]\{1,5\}' "$WORK/hr-vm-activate.err" \
    | tail -n1 | grep -o '[0-9]\{1,5\}$')"
  if [ -z "$hr_vm_port" ]; then
    echo "::error::NET-026: activate did not print the VM daemon's discovered hostname-proxy port"
    cat "$WORK/hr-vm-activate.err"
    fail
  fi
  echo "VM daemon's hostname proxy: 127.0.0.1:$hr_vm_port"

  if [ "$hr_vm_port" = "$hr_native_port" ]; then
    echo "::error::NET-027: the native and VM daemons ended up sharing one hostname-proxy port ($hr_vm_port)"
    fail
  fi
  echo "NET-025/026 OK: the two daemons discovered different ports ($hr_native_port native, $hr_vm_port VM)"

  # Retried the same way `proxy_status` above is: the target listener was
  # just forked and may not have bound yet, and while it hasn't, the
  # proxy's own "upstream-unreachable" 502 is itself a valid HTTP response
  # curl returns immediately, so a `want` (when given) is retried past too.
  hr_proxy_status() {
    local proxy_port="$1" authority="$2" want="${3:-}" status=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
        --proxy "127.0.0.1:$proxy_port" "http://$authority/" 2>"$WORK/hr-curl.err")"
      if [ -n "$status" ] && [ "$status" != "000" ] && { [ -z "$want" ] || [ "$status" = "$want" ]; }; then
        break
      fi
      sleep 1
    done
    echo "GET http://$authority/ via proxy 127.0.0.1:$proxy_port -> ${status:-<no response>}" >&2
    printf '%s' "$status"
  }

  mnl --provider local-minimald session exec "$hr_sid" \
    'printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" > /tmp/hr-resp.http' \
    || { echo "::error::could not seed the native responder's canned response"; fail; }
  mnl --provider local-minimald session exec "$hr_sid" socat -T30 "TCP-LISTEN:18101,bind=127.0.0.1,reuseaddr,fork" \
    'SYSTEM:cat /tmp/hr-resp.http' >"$WORK/hr-native-socat.log" 2>&1 &
  HR_NATIVE_SOCAT_PID=$!

  mnl --provider local-minvmd session exec "$hr_vm_sid" \
    'printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" > /tmp/hr-resp.http' \
    || { echo "::error::could not seed the VM responder's canned response"; fail; }
  mnl --provider local-minvmd session exec "$hr_vm_sid" socat -T30 "TCP-LISTEN:18101,bind=127.0.0.1,reuseaddr,fork" \
    'SYSTEM:cat /tmp/hr-resp.http' >"$WORK/hr-vm-socat.log" 2>&1 &
  HR_VM_SOCAT_PID=$!

  hr_native_status="$(hr_proxy_status "$hr_native_port" "e2e-hostrecover.min.internal:18101" 200)"
  if [ "$hr_native_status" != "200" ]; then
    echo "::error::NET-027: the native daemon did not route its own box while the VM daemon was also live"
    fail
  fi
  hr_vm_status="$(hr_proxy_status "$hr_vm_port" "e2e-hostrecover-vm.min.internal:18101" 200)"
  if [ "$hr_vm_status" != "200" ]; then
    echo "::error::NET-027: the VM daemon did not route its own box while the native daemon was also live"
    fail
  fi
  echo "NET-027 OK: the native and VM daemons both routed their own box's name at the same time"

  hr_crossed_status="$(hr_proxy_status "$hr_native_port" "e2e-hostrecover-vm.min.internal:18101")"
  if [ "$hr_crossed_status" != "502" ]; then
    echo "::error::NET-027: the native daemon's proxy routed the VM daemon's box name (got $hr_crossed_status, want 502)"
    fail
  fi
  echo "NET-027 (unwanted case) OK: each daemon answers for its own boxes only"

  kill "$HR_NATIVE_SOCAT_PID" "$HR_VM_SOCAT_PID" 2>/dev/null || true
  wait "$HR_NATIVE_SOCAT_PID" 2>/dev/null || true
  wait "$HR_VM_SOCAT_PID" 2>/dev/null || true
  HR_NATIVE_SOCAT_PID=""; HR_VM_SOCAT_PID=""
  mnl --provider local-minvmd session destroy --force "$hr_vm_sid" >/dev/null 2>&1 || true
  mnl --provider local-minimald session destroy --force "$hr_sid" >/dev/null 2>&1 || true
  rm -rf "$HR_VM_SEED_DIR"; HR_VM_SEED_DIR=""
  mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
  mnl --provider local-minimald stop --force >/dev/null 2>&1 || true
  echo "::endgroup::"
}

# NET-069, NET-071: a request through the hostname proxy is decided by the
# SAME admission rule a direct connection to the target box would trip — a
# port the box did not declare is refused on both surfaces, and the one it
# did declare routes on both, so the proxy is never a second, looser way in.
# Needs a real switch (own-IP addressing), same gate as the own-IP proofs
# above.
#
# NET-070 (a caller whose own egress rules deny the target) is not
# reproduced live in this case: being decided as a registered box's OWN
# caller through the proxy needs a peer with a custom egress declaration,
# and session-e2e has no shipped surface to give one a rule set narrower
# than the deny-all default (the same gap
# run_case_escape_reaches_only_declared_union notes for NET-085) — a
# ::warning:: below points at the unit test that already proves that half.
run_case_proxy_refuses_like_direct() {
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "hostname-proxy parity proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
    return 0
  fi
  echo "::group::the hostname proxy honours the same rules as a direct connection (NET-069, NET-071)"

  PRD_SEED_DIR="$(mktemp -d /tmp/mnlpd.XXXXXX)"
  PRD_SEED_DIR="$(cd "$PRD_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$PRD_SEED_DIR/minimal.toml"
  mkdir "$PRD_SEED_DIR/.git"

  local prd_name=e2e-proxy-parity declared_port=18160 undeclared_port=18161
  for p in "$declared_port" "$undeclared_port"; do
    if curl -sS -o /dev/null --max-time 2 "http://127.0.0.1:$p/" 2>/dev/null; then
      echo "::error::something already answers on 127.0.0.1:$p; this case needs it free"
      fail
    fi
  done

  local prd_out prd_sid
  prd_out="$(cd "$PRD_SEED_DIR" && mnl session activate . --no-prompt \
    --name "$prd_name" --network own_ip --ingress "$declared_port:$declared_port" \
    2>"$WORK/prd-activate.err")" || {
    echo "::error::'min session activate --network own_ip --ingress' failed"
    cat "$WORK/prd-activate.err" 2>/dev/null || true
    fail
  }
  prd_sid="$(printf '%s\n' "$prd_out" | tail -n1 | tr -d '\r')"
  echo "proxy-parity session: $prd_sid"

  # A live responder on the ONE port this box declares. Nothing ever listens
  # on undeclared_port, inside the box or on the host: reaching it would
  # prove only that nothing answered, not that the request was refused, so
  # the proxy must refuse it before ever attempting to connect (proxy.rs
  # decides the verdict before the upstream connect).
  mnl session exec "$prd_sid" \
    'printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" > /tmp/prd-resp.http' \
    || { echo "::error::could not seed the proxy-parity responder's canned response"; fail; }
  mnl session exec "$prd_sid" socat -T30 "TCP-LISTEN:$declared_port,reuseaddr,fork" \
    'SYSTEM:cat /tmp/prd-resp.http' >"$WORK/prd-socat.log" 2>&1 &
  local prd_socat_pid=$!

  # Greps the daemon's own file log, SKIPPED on a VM lane (guest tmpfs, same
  # rationale as the min.internal proof above).
  assert_log_has() {
    if [ -z "$E2E_VM" ] && find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f \
        -exec grep -q -- "$1" {} + 2>/dev/null; then
      echo "daemon log: found '$1' ($2)"
      return 0
    fi
    if [ -n "$E2E_VM" ]; then
      echo "daemon log check SKIPPED for $2 (E2E_VM: minimald's log is in guest tmpfs, unreachable from here)"
      return 0
    fi
    echo "::error::daemon log has no record matching '$1' ($2)"
    fail
  }

  # The direct-connection side of each pair: the host loopback address a
  # direct connection would dial — the declared port's forwarder (NET T19:
  # bound before the box's name is registered), or nothing at all for the
  # undeclared one. Retried like proxy_status below: the responder was just
  # forked and the forward can be live before it binds.
  direct_status() {
    local port="$1" want="${2:-}" status=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 5 \
        "http://127.0.0.1:$port/" 2>"$WORK/prd-direct.err")"
      if [ -n "$status" ] && [ "$status" != "000" ] && { [ -z "$want" ] || [ "$status" = "$want" ]; }; then
        break
      fi
      sleep 1
    done
    echo "GET http://127.0.0.1:$port/ direct -> ${status:-<no response>}" >&2
    printf '%s' "$status"
  }

  # One request through the 7654 proxy, same shape as the min.internal proof.
  proxy_status() {
    local authority="$1" want="${2:-}" status=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
        --proxy 127.0.0.1:7654 "http://$authority/" 2>"$WORK/prd-proxy.err")"
      if [ -n "$status" ] && [ "$status" != "000" ] && { [ -z "$want" ] || [ "$status" = "$want" ]; }; then
        break
      fi
      sleep 1
    done
    echo "GET http://$authority/ via proxy 127.0.0.1:7654 -> ${status:-<no response>}" >&2
    printf '%s' "$status"
  }

  # -- The declared port: both surfaces reach the same box, the same way ----
  local direct_declared proxy_declared
  direct_declared="$(direct_status "$declared_port" 200)"
  proxy_declared="$(proxy_status "$prd_name.min.internal:$declared_port" 200)"
  echo "declared port $declared_port: direct -> ${direct_declared:-<none>}, proxied -> ${proxy_declared:-<none>}"
  if [ "$direct_declared" != "200" ] || [ "$proxy_declared" != "200" ]; then
    echo "::error::NET-071: the declared port must route on both surfaces alike (direct=$direct_declared, proxied=$proxy_declared)"
    fail
  fi
  echo "NET-071 OK: the declared port routes the same way, direct and proxied"

  # -- The undeclared port: both surfaces refuse it, side by side -----------
  local direct_undeclared proxy_undeclared
  direct_undeclared="$(direct_status "$undeclared_port")"
  proxy_undeclared="$(proxy_status "$prd_name.min.internal:$undeclared_port")"
  echo "undeclared port $undeclared_port: direct -> ${direct_undeclared:-refused}, proxied -> ${proxy_undeclared:-<none>}"
  if [ "$direct_undeclared" = "200" ]; then
    echo "::error::the undeclared port answered a direct connection; nothing should be listening there"
    fail
  fi
  if [ "$proxy_undeclared" != "403" ]; then
    echo "::error::NET-069: an undeclared port through the proxy got '$proxy_undeclared', want 403 (direct got '$direct_undeclared')"
    fail
  fi
  echo "NET-069 OK: the undeclared port is refused on both surfaces, exactly as a direct connection is (direct: ${direct_undeclared:-refused}, proxied: 403 Forbidden)"
  assert_log_has "target-box-did-not-declare-the-port" "NET-069 refusal reason"

  echo "::warning::NET-070 (a caller whose own egress rules deny the target) is not reproduced live in this case: being decided as a registered box's own caller through the proxy needs a peer with a custom egress declaration, and session-e2e has no shipped surface to give one a rule set narrower than the deny-all default (the same gap run_case_escape_reaches_only_declared_union notes for NET-085 above) — cargo nextest run -p minimald proxy_caller_egress_denied proves that half directly, at Tier T2, and proxy_parity_across_network_modes proves the two network modes agree given the same rules."

  kill "$prd_socat_pid" 2>/dev/null || true
  wait "$prd_socat_pid" 2>/dev/null || true
  mnl session destroy --force "$prd_sid" >/dev/null 2>&1 || true
  rm -rf "$PRD_SEED_DIR"; PRD_SEED_DIR=""
  echo "::endgroup::"
}

# NET-014..017, tied together end to end: a port no --ingress names publishes
# ITSELF the moment a process in the box starts listening on one its rules
# permit (NET-016), answers by name at once, keeps answering once the client
# that started it is gone (NET-015: a box outlives its client), and a port
# nothing ever published refuses a direct connection instantly rather than
# hanging (NET-014). HostNet (the default network mode; no --network or
# --ingress flag) runs this on every lane, same reasoning as the HostNet half
# of run_case_min_internal_names_through_proxy above: it permits every port
# that carries one (its own listeners already answer them at the shared
# address), and that address is reachable through the proxy wherever
# minimald itself runs — this host natively, or the guest on a VM lane.
run_case_port_publishes_on_listen_and_box_outlives_client() {
  echo "::group::a listened-on port publishes itself, and the box outlives its client (NET-014..017)"

  local pl_name=e2e-portlisten pl_port=18210 pl_unpub_port=18211
  local pl_sid pl_status attach_out
  local pl_unpub_start_ms pl_unpub_elapsed_ms pl_unpub_status

  pl_sid="$(cd "$PROJECT_DIR" && mnl session activate . --name "$pl_name" 2>"$WORK/pl-activate.err")" || {
    echo "::error::'min session activate --name $pl_name' failed"
    cat "$WORK/pl-activate.err" 2>/dev/null || true
    fail
  }
  pl_sid="$(printf '%s\n' "$pl_sid" | tail -n1 | tr -d '\r')"
  echo "session: $pl_sid ($pl_name)"

  # Attach over a REAL pty (a session is interactive by design), start a
  # responder in the FOREGROUND on a port no --ingress names, then leave by
  # the shipped detach chord (ctrl-] then d) once it goes quiet — never
  # `exit`, which would end the shell (and the responder with it) rather than
  # just the attach. `socat` is in the launcher baseline (base/coreutils/
  # socat), needing no `min add`. -T300 is a safety net this case's own
  # cleanup below is expected to beat, not a timeout this proof relies on.
  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  attach_out="$(E2E_PTY_COMMANDS="printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n' > /tmp/pl-resp.http
socat -T300 TCP-LISTEN:$pl_port,reuseaddr,fork SYSTEM:'cat /tmp/pl-resp.http'" \
    E2E_PTY_DETACH=1 python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min ${E2E_MINIMAL_ARGS:-} session attach "$pl_sid" \
    2>"$WORK/pl-attach.err")" || {
    echo "::error::the pty attach that starts the box's responder and detaches did not exit cleanly"
    echo "--- transcript ---"; printf '%s\n' "$attach_out"
    echo "--- stderr ---"; cat "$WORK/pl-attach.err" 2>/dev/null || true
    mnl session destroy --force "$pl_sid" >/dev/null 2>&1 || true
    fail
  }

  # The attach above returned by DETACHING, not by destroying — so a session
  # still listed here is already the box outliving its client (NET-015),
  # before we have even checked whether the port it started still answers.
  if ! mnl ls --raw 2>/dev/null | grep -q -- "$pl_sid"; then
    echo "::error::NET-015: the session is gone after its only attach detached rather than destroyed"
    fail
  fi

  # NET-016: reach the listened-on port by name, through the proxy — with no
  # --ingress typed for it, and the client that started it already gone, so
  # this doubles as NET-015's reachability half: the box outlived it.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    pl_status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
      --proxy 127.0.0.1:7654 "http://$pl_name.min.internal:$pl_port/" 2>"$WORK/pl-curl.err")"
    [ "$pl_status" = "200" ] && break
    sleep 1
  done
  echo "GET http://$pl_name.min.internal:$pl_port/ via proxy -> ${pl_status:-<no response>}"
  if [ "$pl_status" != "200" ]; then
    echo "::error::NET-016: the listened-on port did not publish itself at $pl_name.min.internal:$pl_port"
    cat "$WORK/pl-curl.err" 2>/dev/null || true
    fail
  fi
  echo "NET-016 OK: the port published itself on listen, with no --ingress typed for it"
  echo "NET-015 OK: it still answered after the attach that started it detached — the box outlived its client"

  # NET-014: a port nothing ever published refuses a direct connection
  # instantly, rather than hanging to curl's own timeout — checked from
  # inside the box's own netns (`min session exec`), which is where a
  # HostNet box's published address actually lives (this host natively, or
  # the guest on a VM lane).
  pl_unpub_start_ms="$(now_ms)"
  pl_unpub_status="$(mnl session exec "$pl_sid" curl -sS -o /dev/null -w '%{http_code}' \
    --max-time 10 "http://127.0.0.1:$pl_unpub_port/" 2>"$WORK/pl-unpub-curl.err")"
  pl_unpub_elapsed_ms=$(( $(now_ms) - pl_unpub_start_ms ))
  echo "(inside $pl_sid) GET http://127.0.0.1:$pl_unpub_port/ -> status=${pl_unpub_status:-<none>} elapsed=${pl_unpub_elapsed_ms}ms"
  if [ "$pl_unpub_status" = "200" ]; then
    echo "::error::NET-014: an unpublished port answered a connection; nothing should be listening there"
    fail
  fi
  if [ "$pl_unpub_elapsed_ms" -ge 5000 ]; then
    echo "::error::NET-014: an unpublished port took ${pl_unpub_elapsed_ms}ms to refuse — that is a timeout, not connection-refused"
    cat "$WORK/pl-unpub-curl.err" 2>/dev/null || true
    fail
  fi
  echo "NET-014 OK: the unpublished port refused instantly (${pl_unpub_elapsed_ms}ms), not a timeout"

  mnl session exec "$pl_sid" 'pkill socat >/dev/null 2>&1 || true' >/dev/null 2>&1 || true
  mnl session destroy --force "$pl_sid" >/dev/null 2>&1 || true
  echo "port-on-listen proof OK: published itself by name at once, outlived its client after detach, and an unpublished port refused instantly"
  echo "::endgroup::"
}

# NET-072, NET-073: a box resolves a sibling's box-zone name with no
# `allow_dns_hosts` entry naming it, and a connection to that name opens only
# when BOTH sides' rules allow it. This needs no CLI change to reach live:
# `gvproxy_network.rs` registers every own-IP session's lease into the shared
# box zone at activation regardless of what it declares, so two ordinary
# own-IP boxes are already siblings the moment both exist.
#
# NET-066, NET-067, and NET-068 — a hostname-only `allow_dns_hosts` letting
# apt/git/npm/pip/a container pull complete, and an allowed name that
# resolves into a denied range refused and logged — are NOT reproduced live
# below: no shipped `min` surface lets this script declare a session's egress
# allowlist at all yet (`activate_session`, crates/minimal/src/cmd/
# session.rs, hardcodes `egress: None`; the box spec's `[network]` field
# schema is an explicit non-goal of this spec, deferred to
# gominimal/inbox#570). `cargo nextest run -p minvmd
# hostname_allowlist_toolchain_completes` (T29) and `cargo nextest run -p
# minimald denied_range_resolution_refused denied_range_resolution_logged`
# (T27) are the real system/unit proofs of those two clauses today; once
# `min session activate` can declare `egress.allow_dns_hosts`, this case
# should replay them against a live session instead of a warning.
run_case_github_only_allowlist() {
  echo "::group::box-to-box reach under both boxes' rules (NET-072, NET-073)"
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "box-to-box proof SKIPPED (no MINVMD_GVPROXY_BIN: own-IP boxes need a real switch)"
    echo "::endgroup::"
    return 0
  fi

  local port=18300 undeclared_port=18301
  local marker=GHA_TARGET_OK
  local target_dir source_dir target2_dir source2_dir
  local target_sid source_sid target2_sid source2_sid target_socat_pid
  local target_undeclared_socat_pid
  local status rc

  # A fresh, self-seeded dir per session — a path that already has a session
  # does not mint a second one (same reasoning as the own-IP proof's seed).
  seed_gha_dir() {
    local d
    d="$(mktemp -d /tmp/mnlg.XXXXXX)"
    d="$(cd "$d" && pwd -P)"
    {
      awk '
        /^\[upstream\]/            { grab = 1; print; next }
        grab && (/^$/ || /^\[/)    { exit }
        grab                       { print }
      ' "$ROOT/.minimal/minimal.toml"
      printf '\n[stack]\nuse = "shell"\n'
    } > "$d/minimal.toml"
    mkdir "$d/.git"
    printf '%s' "$d"
  }

  # -- Both sides allow it, and the target's half alone refuses --------------
  unset MINIMAL_EGRESS_DENY_ALL_WINDOW
  target_dir="$(seed_gha_dir)"; GHA_SEED_DIRS="$GHA_SEED_DIRS $target_dir"
  target_sid="$(cd "$target_dir" && mnl session activate . --no-prompt \
    --name e2e-gha-target --network own_ip --ingress "$port:$port" \
    2>"$WORK/gha-target-activate.err")" || {
    echo "::error::'min session activate --network own_ip --ingress $port:$port' failed for the box-to-box target"
    cat "$WORK/gha-target-activate.err" 2>/dev/null || true
    fail
  }
  target_sid="$(printf '%s\n' "$target_sid" | tail -n1 | tr -d '\r')"
  echo "box-to-box target: $target_sid (e2e-gha-target, declares port $port)"

  source_dir="$(seed_gha_dir)"; GHA_SEED_DIRS="$GHA_SEED_DIRS $source_dir"
  source_sid="$(cd "$source_dir" && mnl session activate . --no-prompt \
    --name e2e-gha-source --network own_ip 2>"$WORK/gha-source-activate.err")" || {
    echo "::error::'min session activate --network own_ip' failed for the box-to-box source"
    cat "$WORK/gha-source-activate.err" 2>/dev/null || true
    fail
  }
  source_sid="$(printf '%s\n' "$source_sid" | tail -n1 | tr -d '\r')"
  echo "box-to-box source: $source_sid (e2e-gha-source, declares nothing)"

  mnl session exec "$target_sid" \
    "printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n$marker\n' > /tmp/gha-target.http" \
    || { echo "::error::could not seed the target box's canned response"; fail; }
  mnl session exec "$target_sid" socat -T30 "TCP-LISTEN:$port,reuseaddr,fork" \
    'SYSTEM:cat /tmp/gha-target.http' >"$WORK/gha-target-socat.log" 2>&1 &
  target_socat_pid=$!

  # NET-072: the source resolves the target's box-zone name and reaches its
  # declared port with no `allow_dns_hosts` entry anywhere naming it — box-
  # zone resolution and reach need none.
  status=""
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    status="$(mnl session exec "$source_sid" curl -sS -o /dev/null -w '%{http_code}' \
      --max-time 10 "http://e2e-gha-target.min.internal:$port/" 2>"$WORK/gha-source-curl.err")"
    [ "$status" = "200" ] && break
    sleep 1
  done
  echo "(inside $source_sid) GET http://e2e-gha-target.min.internal:$port/ -> ${status:-<no response>}"
  if [ "$status" != "200" ]; then
    echo "::error::NET-072/NET-073: the source box did not reach the target's box-zone name at its declared port"
    cat "$WORK/gha-source-curl.err" 2>/dev/null || true
    cat "$WORK/gha-target-socat.log" 2>/dev/null || true
    kill "$target_socat_pid" 2>/dev/null || true
    fail
  fi
  echo "NET-072/NET-073 OK: the source box resolved and reached the target's box-zone name (both sides allowed it)"

  # NET-073, the target's half alone refuses: the same name, a port the
  # target never declared. The source's egress still admits it (nothing is
  # denied here yet), so only the target's ingress gate stands in the way.
  # A live-but-undeclared responder backs this: without one, "refused"
  # would just as well mean "nothing is listening there", proving nothing
  # about the ingress gate itself.
  mnl session exec "$target_sid" socat -T10 "TCP-LISTEN:$undeclared_port,reuseaddr,fork" \
    'SYSTEM:cat /tmp/gha-target.http' >"$WORK/gha-target-undeclared-socat.log" 2>&1 &
  target_undeclared_socat_pid=$!

  # Positive control: loopback inside the target box itself bypasses the
  # ingress gate under test, so it proves the responder is actually up
  # before the cross-box refusal below is read as policy rather than a
  # race against socat's startup.
  status=""
  for _ in 1 2 3 4 5; do
    status="$(mnl session exec "$target_sid" curl -sS -o /dev/null -w '%{http_code}' \
      --max-time 5 "http://127.0.0.1:$undeclared_port/" 2>"$WORK/gha-undeclared-ready.err")"
    [ "$status" = "200" ] && break
    sleep 1
  done
  if [ "$status" != "200" ]; then
    echo "::error::the undeclared-port responder never became ready (loopback check inside the target)"
    cat "$WORK/gha-undeclared-ready.err" 2>/dev/null || true
    kill "$target_socat_pid" "$target_undeclared_socat_pid" 2>/dev/null || true
    fail
  fi
  echo "undeclared-port responder is up (loopback positive control): http://127.0.0.1:$undeclared_port/ -> 200"

  status="$(mnl session exec "$source_sid" curl -sS -o /dev/null -w '%{http_code}' \
    --max-time 8 "http://e2e-gha-target.min.internal:$undeclared_port/" 2>"$WORK/gha-undeclared-curl.err")"
  rc=$?
  echo "(inside $source_sid) GET http://e2e-gha-target.min.internal:$undeclared_port/ -> rc=$rc status=${status:-<none>}"
  if [ "$rc" -eq 0 ] || [ "$status" = "200" ]; then
    echo "::error::NET-073: the target answered on a port it never declared as ingress"
    kill "$target_socat_pid" "$target_undeclared_socat_pid" 2>/dev/null || true
    fail
  fi
  echo "NET-073 OK: an undeclared port refused the connection (the target's half of the rule alone, even with a live responder behind it)"

  kill "$target_socat_pid" "$target_undeclared_socat_pid" 2>/dev/null || true
  wait "$target_socat_pid" 2>/dev/null || true
  wait "$target_undeclared_socat_pid" 2>/dev/null || true
  mnl session destroy --force "$target_sid" >/dev/null 2>&1 || true
  mnl session destroy --force "$source_sid" >/dev/null 2>&1 || true

  # -- The source's half alone refuses ---------------------------------------
  # A running daemon keeps the environment it was launched with (same
  # reasoning as the own-IP egress proof above), so forcing the deny-all
  # default needs a fresh daemon: stop, export the var, and let the next
  # activate respawn one that inherits it. Both boxes below are new — a box
  # never survives the daemon that hosts it going away.
  mnl stop --force >/dev/null 2>"$WORK/gha-stop.err" || {
    echo "::error::'min stop' before the forced-window box-to-box activate failed"
    cat "$WORK/gha-stop.err" 2>/dev/null || true
    fail
  }
  export MINIMAL_EGRESS_DENY_ALL_WINDOW=in-force

  target2_dir="$(seed_gha_dir)"; GHA_SEED_DIRS="$GHA_SEED_DIRS $target2_dir"
  target2_sid="$(cd "$target2_dir" && mnl session activate . --no-prompt \
    --name e2e-gha-target2 --network own_ip --ingress "$port:$port" \
    2>"$WORK/gha-target2-activate.err")" || {
    echo "::error::'min session activate --network own_ip --ingress $port:$port' (deny-all in force) failed for the box-to-box target"
    cat "$WORK/gha-target2-activate.err" 2>/dev/null || true
    fail
  }
  target2_sid="$(printf '%s\n' "$target2_sid" | tail -n1 | tr -d '\r')"

  source2_dir="$(seed_gha_dir)"; GHA_SEED_DIRS="$GHA_SEED_DIRS $source2_dir"
  source2_sid="$(cd "$source2_dir" && mnl session activate . --no-prompt \
    --name e2e-gha-source2 --network own_ip 2>"$WORK/gha-source2-activate.err")" || {
    echo "::error::'min session activate --network own_ip' (deny-all in force) failed for the box-to-box source"
    cat "$WORK/gha-source2-activate.err" 2>/dev/null || true
    fail
  }
  source2_sid="$(printf '%s\n' "$source2_sid" | tail -n1 | tr -d '\r')"

  mnl session exec "$target2_sid" \
    "printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n$marker\n' > /tmp/gha-target.http" \
    || { echo "::error::could not seed the second target box's canned response"; fail; }
  mnl session exec "$target2_sid" socat -T20 "TCP-LISTEN:$port,reuseaddr,fork" \
    'SYSTEM:cat /tmp/gha-target.http' >"$WORK/gha-target2-socat.log" 2>&1 &
  target_socat_pid=$!

  # Positive control: loopback inside target2 itself bypasses the deny-all
  # policy under test, so it proves the responder is actually up before the
  # refusal below is read as the source's egress rule rather than a race
  # against socat's startup (the happy-path proof above needs up to ten
  # such retries for its first 200; this box gets no less).
  status=""
  for _ in 1 2 3 4 5; do
    status="$(mnl session exec "$target2_sid" curl -sS -o /dev/null -w '%{http_code}' \
      --max-time 5 "http://127.0.0.1:$port/" 2>"$WORK/gha-target2-ready.err")"
    [ "$status" = "200" ] && break
    sleep 1
  done
  if [ "$status" != "200" ]; then
    echo "::error::the second target box's canned responder never became ready (loopback check)"
    cat "$WORK/gha-target2-ready.err" 2>/dev/null || true
    kill "$target_socat_pid" 2>/dev/null || true
    fail
  fi
  echo "second target's responder is up (loopback positive control): http://127.0.0.1:$port/ -> 200"

  status="$(mnl session exec "$source2_sid" curl -sS -o /dev/null -w '%{http_code}' \
    --max-time 8 "http://e2e-gha-target2.min.internal:$port/" 2>"$WORK/gha-denied-curl.err")"
  rc=$?
  echo "(inside $source2_sid) GET http://e2e-gha-target2.min.internal:$port/ -> rc=$rc status=${status:-<none>}"
  if [ "$rc" -eq 0 ] || [ "$status" = "200" ]; then
    echo "::error::NET-073: a deny-all source box reached the target's box-zone name anyway"
    kill "$target_socat_pid" 2>/dev/null || true
    fail
  fi
  echo "NET-073 OK: a deny-all source box's own rules refused the box-zone name too (the source's half of the rule alone), even though the target still declares the same port and its responder was confirmed live"

  echo "::warning::NET-066/NET-067/NET-068's other two-thirds of this task's proof (a hostname-only allow_dns_hosts letting apt/git/npm/pip/a container pull complete, and an allowed name resolving into a denied range refused and logged) is not reproduced live above: no shipped 'min' surface lets this script declare a session's egress allowlist yet (activate_session, crates/minimal/src/cmd/session.rs, hardcodes egress: None). cargo nextest run -p minvmd hostname_allowlist_toolchain_completes and cargo nextest run -p minimald denied_range_resolution_refused denied_range_resolution_logged are the real proofs of those two clauses today; once 'min session activate' can declare egress.allow_dns_hosts, this case should replay them against a live session instead of a warning."

  kill "$target_socat_pid" 2>/dev/null || true
  wait "$target_socat_pid" 2>/dev/null || true
  mnl session destroy --force "$target2_sid" >/dev/null 2>&1 || true
  mnl session destroy --force "$source2_sid" >/dev/null 2>&1 || true
  unset MINIMAL_EGRESS_DENY_ALL_WINDOW
  echo "::endgroup::"
}

# NET-043..047, tied together end to end: `min net expose <port>` run INSIDE
# the box (the in-sandbox `min` helper, over `/run/minenv_sock`) is decided
# against its `dynamic_ingress` setting three ways in this one case — allow
# publishes it at once (NET-043), deny refuses it with a typed reason
# (NET-044), and ask puts the decision to the human attached to the SAME
# box, over the SAME terminal `min net expose` itself is running on, answered
# by one keystroke exactly as the daemon renders it (NET-045) — and every one
# of those three decisions, whoever took it, lands in the daemon's local
# audit log (NET-046). own-IP only: the address `min net expose` publishes
# onto is the box's own, which needs a real switch, same gating as every
# other own-IP case above.
run_case_expose_from_inside_box() {
  echo "::group::min net expose, decided against dynamic_ingress: allow/ask/deny, every decision audited (NET-043..047)"
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "min net expose proof SKIPPED (no MINVMD_GVPROXY_BIN: own-IP boxes need a real switch)"
    echo "::endgroup::"
    return 0
  fi

  local allow_port=19180 deny_port=19181 ask_port=19182
  local allow_name=e2e-expose-allow deny_name=e2e-expose-deny ask_name=e2e-expose-ask
  local sid out audit attach_out ask_status

  EXPOSE_SEED_DIR="$(mktemp -d /tmp/mnlxp.XXXXXX)"
  EXPOSE_SEED_DIR="$(cd "$EXPOSE_SEED_DIR" && pwd -P)"
  {
    awk '
      /^\[upstream\]/            { grab = 1; print; next }
      grab && (/^$/ || /^\[/)    { exit }
      grab                       { print }
    ' "$ROOT/.minimal/minimal.toml"
    printf '\n[stack]\nuse = "shell"\n'
  } > "$EXPOSE_SEED_DIR/minimal.toml"
  mkdir "$EXPOSE_SEED_DIR/.git"

  # The last decision the daemon's local audit log recorded for `box_name`
  # (NET-046), read straight from its JSON Lines file rather than through
  # `jq` — nothing shipped assumes that on the host. SKIPPED, not failed, on
  # a VM lane: minimald runs in-guest there and the log is in guest tmpfs,
  # unreachable from here (same rationale as assert_log_has elsewhere above).
  audit_line_for() {
    if [ -n "$E2E_VM" ]; then
      return 0
    fi
    find "$XDG_STATE_HOME/minimal/audit" -name 'decisions.jsonl' -type f \
      -exec grep -h -- "\"box_name\":\"$1\"" {} + 2>/dev/null | tail -n1
  }

  # -- allow: publishes at once, from inside the box, nobody asked -----------
  out="$(cd "$EXPOSE_SEED_DIR" && mnl session activate . --no-prompt --name "$allow_name" \
    --network own_ip --dynamic-ingress allow 2>"$WORK/expose-allow-activate.err")" || {
    echo "::error::'min session activate --network own_ip --dynamic-ingress allow' failed"
    cat "$WORK/expose-allow-activate.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  echo "allow session: $sid ($allow_name)"

  out="$(mnl session exec "$sid" min net expose "$allow_port" 2>"$WORK/expose-allow.err")" || {
    echo "::error::NET-043: 'min net expose $allow_port' (dynamic_ingress allow) was refused inside an allowing box"
    cat "$WORK/expose-allow.err" 2>/dev/null || true
    mnl session destroy --force "$sid" >/dev/null 2>&1 || true
    fail
  }
  case "$out" in
    "published $allow_name.min.internal:$allow_port at "*) ;;
    *)
      echo "::error::NET-043: 'min net expose $allow_port' did not report a publication; got '$out'"
      fail
      ;;
  esac
  echo "NET-043 OK: allow published it from inside the box at once: $out"

  audit="$(audit_line_for "$allow_name")"
  if [ -z "$E2E_VM" ]; then
    if [ -z "$audit" ] || [[ "$audit" != *'"outcome":"published"'* ]] \
        || [[ "$audit" != *'"decided_by":"policy"'* ]] || [[ "$audit" != *'"setting":"allow"'* ]]; then
      echo "::error::NET-046: the audit log has no allow/published/policy record for $allow_name; got '${audit:-<none>}'"
      fail
    fi
    echo "NET-046 OK: the allow decision is in the audit log: $audit"
  fi

  mnl session destroy --force "$sid" >/dev/null 2>&1 || true

  # -- deny: refused with a typed reason, nothing published ------------------
  out="$(cd "$EXPOSE_SEED_DIR" && mnl session activate . --no-prompt --name "$deny_name" \
    --network own_ip --dynamic-ingress deny 2>"$WORK/expose-deny-activate.err")" || {
    echo "::error::'min session activate --network own_ip --dynamic-ingress deny' failed"
    cat "$WORK/expose-deny-activate.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  echo "deny session: $sid ($deny_name)"

  if mnl session exec "$sid" min net expose "$deny_port" >"$WORK/expose-deny.out" 2>"$WORK/expose-deny.err"; then
    echo "::error::NET-044: 'min net expose $deny_port' succeeded inside a denying box; it must refuse"
    cat "$WORK/expose-deny.out" 2>/dev/null || true
    mnl session destroy --force "$sid" >/dev/null 2>&1 || true
    fail
  fi
  if ! grep -q "denies it" "$WORK/expose-deny.err"; then
    echo "::error::NET-044: the refusal did not name the dynamic_ingress setting; got:"
    cat "$WORK/expose-deny.err"
    fail
  fi
  echo "NET-044 OK: deny refused it with a typed reason: $(cat "$WORK/expose-deny.err")"

  audit="$(audit_line_for "$deny_name")"
  if [ -z "$E2E_VM" ]; then
    if [ -z "$audit" ] || [[ "$audit" != *'"outcome":"refused"'* ]] \
        || [[ "$audit" != *'"decided_by":"policy"'* ]] || [[ "$audit" != *'"setting":"deny"'* ]]; then
      echo "::error::NET-046: the audit log has no deny/refused/policy record for $deny_name; got '${audit:-<none>}'"
      fail
    fi
    echo "NET-046 OK: the deny decision is in the audit log: $audit"
  fi

  mnl session destroy --force "$sid" >/dev/null 2>&1 || true

  # -- ask: the human attached to the SAME box decides, one keystroke --------
  out="$(cd "$EXPOSE_SEED_DIR" && mnl session activate . --no-prompt --name "$ask_name" \
    --network own_ip --dynamic-ingress ask 2>"$WORK/expose-ask-activate.err")" || {
    echo "::error::'min session activate --network own_ip --dynamic-ingress ask' failed"
    cat "$WORK/expose-ask-activate.err" 2>/dev/null || true
    fail
  }
  sid="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  echo "ask session: $sid ($ask_name)"

  # A one-shot pty driver, generated here rather than added to the shared
  # scripts/e2e-attach-pty.py: that helper answers only the session-exit
  # menu (a `Select`), a different prompt shape than the plain `[y/N]`
  # keystroke `min net expose` raises (NET-045). Typed into the freshly
  # attached shell, `min net expose <port>` reaches the daemon over the
  # in-sandbox helper — which asks the human attached to THIS box, over this
  # SAME channel, exactly the case this proof needs a real pty for (a pipe
  # could not answer it). Detaching afterwards (not `exit`) leaves the shell
  # alive, so the attach process ends cleanly with no exit-menu to answer.
  cat > "$WORK/expose-ask-pty.py" <<'PY'
"""One-shot pty driver for a single `[y/N]` ask prompt mid-attach (NET-045).

Types <command> into the freshly-attached shell, waits for <marker> — the
rendered question's leading text — to appear on the SAME raw channel the
shell is on (the daemon prompts over the attach itself, not a separate one),
sends one keystroke ('y') to answer it, waits for the reply to settle, then
leaves by the shipped detach chord (ctrl-] then d) so the box's shell
survives: a bare `exit` would end it and raise the session-exit menu
instead, which this one-shot driver does not handle.

Usage: expose-ask-pty.py <command> <marker> <attach-argv...>
Prints the captured transcript on stdout. Exits 0 iff the marker was seen,
answered, and the attach process exited 0.
"""
import os
import pty
import select
import signal
import sys
import time

command = sys.argv[1]
marker = sys.argv[2].encode()
attach_argv = sys.argv[3:]

DEADLINE = time.monotonic() + 120

pid, fd = pty.fork()
if pid == 0:  # child
    os.execvp(attach_argv[0], attach_argv)
    os._exit(127)

buf = bytearray()
answered = False
detached = False


def drain_ready(timeout):
    if select.select([fd], [], [], timeout)[0]:
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            return None
        return chunk or None
    return b""


try:
    # The shell only starts once the sandbox is minted; bytes written before
    # then buffer in the pty (same reasoning as scripts/e2e-attach-pty.py).
    time.sleep(1.5)
    os.write(fd, (command + "\n").encode())

    quiet = 0
    while time.monotonic() < DEADLINE:
        chunk = drain_ready(1.0)
        if chunk is None:
            break  # EOF / closed
        buf.extend(chunk)
        quiet = 0 if chunk else quiet + 1
        if not answered and marker in bytes(buf):
            # The daemon intercepts this keystroke before the shell ever
            # sees it; the trailing '\n' is swallowed with it.
            os.write(fd, b"y\n")
            answered = True
            quiet = 0
        elif answered and not detached and quiet >= 2:
            os.write(fd, b"\x1dd")
            detached = True
finally:
    try:
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == 0:
            time.sleep(2)
            wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == 0:
            os.kill(pid, signal.SIGKILL)
            _, status = os.waitpid(pid, 0)
    except ChildProcessError:
        status = 0

sys.stdout.buffer.write(bytes(buf))
sys.stdout.flush()
ok = answered and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
sys.exit(0 if ok else 1)
PY

  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  attach_out="$(python3 "$WORK/expose-ask-pty.py" \
    "min net expose $ask_port" "asks to publish port $ask_port/tcp of box \`$ask_name\`" \
    min ${E2E_MINIMAL_ARGS:-} session attach "$sid" \
    2>"$WORK/expose-ask-attach.err")"
  ask_status=$?
  if [ "$ask_status" -ne 0 ]; then
    echo "::error::NET-045: the ask prompt for 'min net expose $ask_port' was never seen or never answered"
    echo "--- transcript ---"; printf '%s\n' "$attach_out"
    echo "--- stderr ---"; cat "$WORK/expose-ask-attach.err" 2>/dev/null || true
    mnl session destroy --force "$sid" >/dev/null 2>&1 || true
    fail
  fi
  if ! printf '%s' "$attach_out" | tr -d '\r' | grep -q "asks to publish port $ask_port/tcp of box \`$ask_name\`"; then
    echo "::error::NET-045: the attached terminal never showed the ask question"
    printf '%s\n' "$attach_out"
    fail
  fi
  if ! printf '%s' "$attach_out" | tr -d '\r' | grep -q "published $ask_name.min.internal:$ask_port at "; then
    echo "::error::NET-045: answering 'y' did not publish the port"
    printf '%s\n' "$attach_out"
    fail
  fi
  echo "NET-045 OK: the human attached to the box was asked, over its own terminal, and their 'y' published it"

  audit="$(audit_line_for "$ask_name")"
  if [ -z "$E2E_VM" ]; then
    if [ -z "$audit" ] || [[ "$audit" != *'"outcome":"published"'* ]] \
        || [[ "$audit" != *'"decided_by":"attached-human"'* ]] || [[ "$audit" != *'"setting":"ask"'* ]]; then
      echo "::error::NET-046: the audit log has no ask/published/attached-human record for $ask_name; got '${audit:-<none>}'"
      fail
    fi
    echo "NET-046 OK: the ask decision is in the audit log: $audit"
  fi

  mnl session destroy --force "$sid" >/dev/null 2>&1 || true
  rm -rf "$EXPOSE_SEED_DIR"; EXPOSE_SEED_DIR=""
  echo "min net expose proof OK: allow published at once, deny refused with a typed reason, ask put it to the attached human and their answer decided it — every decision landed in the audit log"
  echo "::endgroup::"
}

# NET-052..059: two VM box hosts on one machine, end to end. `minvmd
# --vm-name <name>` gives a second VM its own state, socket and daemon; `min
# ls`/attach/`min net expose` then address boxes across both from the box
# name alone, no global flag naming the VM. `min` itself has no flag yet that
# PLACES a new box on a named VM (S7b/arch#45 tracks that CLI surface) —
# activation always targets whatever `--minimal-dir` resolves to, which is
# always the `default` VM — so this case reaches the SECOND VM's own,
# already-running daemon by pointing `--minimal-dir` at a scratch root whose
# provider-instance path IS that VM's real directory, via a symlink. The
# named VM is already up by then, so this only ever CONNECTS; nothing here
# spawns a second daemon at a divergent path. Every other command below (ls,
# net expose, attach) runs with no override at all — the named VM is
# discoverable there for real, the way NET-057/058 actually work.
run_case_two_named_vms_on_one_machine() {
  echo "::group::two named VMs on one machine, end to end (NET-052..059)"

  local minvmd_bin
  minvmd_bin="$(command -v minvmd || true)"
  if [ -z "$minvmd_bin" ]; then
    echo "two-named-VMs proof SKIPPED (no minvmd on PATH: this target has no VM host daemon)"
    echo "::endgroup::"
    return 0
  fi
  local data_dir kernel_path rootfs_path initramfs_path payload
  data_dir="${XDG_DATA_HOME:-$HOME/.local/share}/minimal"
  kernel_path="${MINVMD_KERNEL_PATH:-$data_dir/vmlinuz}"
  rootfs_path="${MINVMD_ROOTFS_PATH:-$data_dir/rootfs.img}"
  initramfs_path="${MINVMD_INITRAMFS:-$data_dir/initramfs.cpio}"
  for payload in "$kernel_path" "$rootfs_path" "$initramfs_path"; do
    if [ ! -f "$payload" ]; then
      echo "two-named-VMs proof SKIPPED (no guest payload at $payload: this target ships no VM stack)"
      echo "::endgroup::"
      return 0
    fi
  done
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ] && ! command -v gvproxy-min >/dev/null 2>&1; then
    echo "two-named-VMs proof SKIPPED (no switch: MINVMD_GVPROXY_BIN unset and no gvproxy-min on PATH)"
    echo "::endgroup::"
    return 0
  fi

  local tnv_prov_dir tnv_beta_dir
  tnv_prov_dir="$XDG_STATE_HOME/minimal/providers/local-minvmd0"
  tnv_beta_dir="$tnv_prov_dir/vms/beta"
  "$minvmd_bin" --vm-name beta stop >/dev/null 2>&1 || true

  # -- 1. The default VM's own box -----------------------------------------
  local default_out default_sid default_port
  default_out="$(cd "$PROJECT_DIR" && mnl --provider local-minvmd session activate . --no-prompt \
    --name e2e-tnv-default 2>"$WORK/tnv-default-activate.err")" || {
    echo "::error::'min --provider local-minvmd session activate' failed for the default VM"
    cat "$WORK/tnv-default-activate.err" 2>/dev/null || true
    fail
  }
  default_sid="$(printf '%s\n' "$default_out" | tail -n1 | tr -d '\r')"
  default_port="$(grep -o 'proxy at 127\.0\.0\.1:[0-9]\{1,5\}' "$WORK/tnv-default-activate.err" \
    | tail -n1 | grep -o '[0-9]\{1,5\}$')"
  echo "default VM's box: $default_sid (hostname proxy: 127.0.0.1:${default_port:-?})"

  # -- 2. A second, NAMED VM: its own state, socket, daemon (NET-052..054) -
  if ! "$minvmd_bin" --vm-name beta run --detach --timeout 150 \
      >"$WORK/tnv-beta-run.out" 2>"$WORK/tnv-beta-run.err"; then
    echo "::error::'minvmd --vm-name beta run --detach' failed to bring up the second named VM"
    cat "$WORK/tnv-beta-run.err" 2>/dev/null || true
    mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
    mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
    fail
  fi
  if [ ! -S "$tnv_beta_dir/ssh.sock" ]; then
    echo "::error::NET-052/054: VM 'beta' has no own socket at $tnv_beta_dir/ssh.sock"
    "$minvmd_bin" --vm-name beta stop >/dev/null 2>&1 || true
    mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
    mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
    fail
  fi
  echo "NET-052/054 OK: VM 'beta' has its own state/socket/daemon under $tnv_beta_dir"
  if [ ! -e "$tnv_prov_dir/ssh.sock" ] || [ ! -e "$tnv_prov_dir/minvmd.toml" ]; then
    echo "::error::NET-053: the default VM's own paths moved when 'beta' was created"
    "$minvmd_bin" --vm-name beta stop >/dev/null 2>&1 || true
    mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
    mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
    fail
  fi
  echo "NET-053 OK: the default VM's own paths ($tnv_prov_dir) are unchanged"

  # -- 3. A box ON that named VM. `min` has no --vm flag yet (see the comment
  #    above this case); reach beta's already-running daemon by pointing
  #    --minimal-dir at a scratch root whose provider-instance path IS
  #    beta's real directory. -------------------------------------------
  local beta_client_dir beta_out beta_sid beta_port
  beta_client_dir="$(mktemp -d "$WORK/tnv-beta-client.XXXXXX")"
  mkdir -p "$beta_client_dir/providers"
  ln -s "$tnv_beta_dir" "$beta_client_dir/providers/local-minvmd0"
  beta_out="$(cd "$PROJECT_DIR" && mnl --minimal-dir "$beta_client_dir" --provider local-minvmd \
    session activate . --no-prompt --name e2e-tnv-beta 2>"$WORK/tnv-beta-activate.err")" || {
    echo "::error::'min session activate' against the named VM 'beta' failed"
    cat "$WORK/tnv-beta-activate.err" 2>/dev/null || true
    "$minvmd_bin" --vm-name beta stop >/dev/null 2>&1 || true
    mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
    mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
    fail
  }
  beta_sid="$(printf '%s\n' "$beta_out" | tail -n1 | tr -d '\r')"
  beta_port="$(grep -o 'proxy at 127\.0\.0\.1:[0-9]\{1,5\}' "$WORK/tnv-beta-activate.err" \
    | tail -n1 | grep -o '[0-9]\{1,5\}$')"
  echo "beta VM's box: $beta_sid (hostname proxy: 127.0.0.1:${beta_port:-?})"

  # From here on every failure branch shares this cleanup (both boxes, beta's
  # own daemon, then the default provider) — `teardown`'s trap only ever
  # knew the default VM. Factored out because it now repeats at every step,
  # unlike this file's usual inline style.
  tnv_cleanup() {
    mnl --minimal-dir "$beta_client_dir" --provider local-minvmd \
      session destroy --force "$beta_sid" >/dev/null 2>&1 || true
    "$minvmd_bin" --vm-name beta stop >/dev/null 2>&1 || true
    mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
    mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
  }

  if [ "$(mnl --provider local-minvmd session exec "$default_sid" echo tnv-default-ok \
      2>/dev/null)" != tnv-default-ok ]; then
    echo "::error::the default VM's box did not respond to a trivial exec"
    tnv_cleanup; fail
  fi
  if [ "$(mnl --minimal-dir "$beta_client_dir" --provider local-minvmd session exec "$beta_sid" \
      echo tnv-beta-ok 2>/dev/null)" != tnv-beta-ok ]; then
    echo "::error::VM 'beta''s box did not respond to a trivial exec"
    tnv_cleanup; fail
  fi
  echo "both boxes are live: $default_sid on 'default', $beta_sid on 'beta'"

  # -- 4. 'min ls' shows the VM per box (NET-057) --------------------------
  local ls_out
  ls_out="$(mnl --provider local-minvmd ls 2>"$WORK/tnv-ls.err")" || {
    echo "::error::'min ls' failed with two VMs running"
    cat "$WORK/tnv-ls.err" 2>/dev/null || true
    tnv_cleanup; fail
  }
  if ! printf '%s\n' "$ls_out" | grep -E '^default[[:space:]]' | grep -q e2e-tnv-default; then
    echo "::error::NET-057: 'min ls' does not list e2e-tnv-default under VM 'default'"
    printf '%s\n' "$ls_out"
    tnv_cleanup; fail
  fi
  if ! printf '%s\n' "$ls_out" | grep -E '^beta[[:space:]]' | grep -q e2e-tnv-beta; then
    echo "::error::NET-057: 'min ls' does not list e2e-tnv-beta under VM 'beta'"
    printf '%s\n' "$ls_out"
    tnv_cleanup; fail
  fi
  echo "NET-057 OK: 'min ls' names the VM holding each box"

  # -- 5. 'min net expose' resolves the VM from the box name alone (NET-058) -
  # Neither box declared --network own_ip, so the daemon that actually holds
  # 'e2e-tnv-beta' refuses this for ITS OWN domain reason (no address of its
  # own to publish at) rather than "no such session" — which is exactly the
  # signal that resolution reached beta's daemon and not the default one,
  # with no --vm flag naming it.
  local expose_out
  expose_out="$(mnl --provider local-minvmd net expose 18402 --session e2e-tnv-beta 2>&1)"
  if ! printf '%s' "$expose_out" | grep -q "no address of its own"; then
    echo "::error::NET-058: 'min net expose --session e2e-tnv-beta' did not resolve to VM 'beta': $expose_out"
    tnv_cleanup; fail
  fi
  echo "NET-058 OK (expose): resolved 'e2e-tnv-beta' to VM 'beta' with no --vm flag ($expose_out)"

  # -- 6. attach resolves the VM from the box name alone (NET-058) --------
  # A real pty (a session is interactive by design): write a marker inside
  # whichever box the name resolves to, then leave by the shipped detach
  # chord. The marker is then read back through beta's own connection —
  # present there proves the attach landed in VM 'beta''s box, which is the
  # only box anywhere named 'e2e-tnv-beta'.
  local attach_out
  attach_out="$(E2E_PTY_COMMANDS="echo tnv-attach-marker-beta > /tmp/tnv-attach-marker" \
    E2E_PTY_DETACH=1 python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min --provider local-minvmd session attach e2e-tnv-beta \
    2>"$WORK/tnv-attach.err")" || {
    echo "::error::the pty attach to 'e2e-tnv-beta' by name did not exit cleanly"
    echo "--- transcript ---"; printf '%s\n' "$attach_out"
    cat "$WORK/tnv-attach.err" 2>/dev/null || true
    tnv_cleanup; fail
  }
  if [ "$(mnl --minimal-dir "$beta_client_dir" --provider local-minvmd session exec "$beta_sid" \
      cat /tmp/tnv-attach-marker 2>/dev/null)" != tnv-attach-marker-beta ]; then
    echo "::error::NET-058: attaching to 'e2e-tnv-beta' by name did not land in VM 'beta''s box"
    tnv_cleanup; fail
  fi
  echo "NET-058 OK (attach): attaching to 'e2e-tnv-beta' by name resolved to VM 'beta' alone"

  # -- 7. Both VMs' names route through the host's hostname surface at the
  #    same time (NET-059) -------------------------------------------------
  local tnv_port=18400
  mnl --provider local-minvmd session exec "$default_sid" \
    'printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" > /tmp/tnv-resp.http' \
    || { echo "::error::could not seed the default box's canned responder"; tnv_cleanup; fail; }
  mnl --provider local-minvmd session exec "$default_sid" socat -T30 \
    "TCP-LISTEN:$tnv_port,bind=127.0.0.1,reuseaddr,fork" 'SYSTEM:cat /tmp/tnv-resp.http' \
    >"$WORK/tnv-default-socat.log" 2>&1 &
  local tnv_default_socat_pid=$!

  mnl --minimal-dir "$beta_client_dir" --provider local-minvmd session exec "$beta_sid" \
    'printf "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n" > /tmp/tnv-resp.http' \
    || {
      echo "::error::could not seed the beta box's canned responder"
      kill "$tnv_default_socat_pid" 2>/dev/null || true
      tnv_cleanup; fail
    }
  mnl --minimal-dir "$beta_client_dir" --provider local-minvmd session exec "$beta_sid" socat -T30 \
    "TCP-LISTEN:$tnv_port,bind=127.0.0.1,reuseaddr,fork" 'SYSTEM:cat /tmp/tnv-resp.http' \
    >"$WORK/tnv-beta-socat.log" 2>&1 &
  local tnv_beta_socat_pid=$!

  tnv_proxy_status() {
    local proxy_port="$1" authority="$2" status=""
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      status="$(curl -sS -o /dev/null -w '%{http_code}' --max-time 10 \
        --proxy "127.0.0.1:$proxy_port" "http://$authority/" 2>"$WORK/tnv-curl.err")"
      [ -n "$status" ] && [ "$status" != "000" ] && break
      sleep 1
    done
    echo "GET http://$authority/ via proxy 127.0.0.1:$proxy_port -> ${status:-<no response>}" >&2
    printf '%s' "$status"
  }

  local default_status beta_status
  default_status="$(tnv_proxy_status "$default_port" "e2e-tnv-default.min.internal:$tnv_port")"
  if [ "$default_status" != "200" ]; then
    echo "::error::NET-059: the default VM's own proxy did not route its own box while beta was also live"
    kill "$tnv_default_socat_pid" "$tnv_beta_socat_pid" 2>/dev/null || true
    tnv_cleanup; fail
  fi
  beta_status="$(tnv_proxy_status "$beta_port" "e2e-tnv-beta.min.internal:$tnv_port")"
  if [ "$beta_status" != "200" ]; then
    echo "::error::NET-059: VM 'beta''s own proxy did not route its own box while the default VM was also live"
    kill "$tnv_default_socat_pid" "$tnv_beta_socat_pid" 2>/dev/null || true
    tnv_cleanup; fail
  fi
  echo "NET-059 OK: both VMs' names routed through their own daemon's proxy at the same time"

  kill "$tnv_default_socat_pid" "$tnv_beta_socat_pid" 2>/dev/null || true
  wait "$tnv_default_socat_pid" 2>/dev/null || true
  wait "$tnv_beta_socat_pid" 2>/dev/null || true

  # -- 8. Stopping one VM leaves the other running (NET-055) --------------
  if ! "$minvmd_bin" --vm-name beta stop >"$WORK/tnv-beta-stop.out" 2>"$WORK/tnv-beta-stop.err"; then
    echo "::error::'minvmd --vm-name beta stop' failed"
    cat "$WORK/tnv-beta-stop.err" 2>/dev/null || true
    tnv_cleanup; fail
  fi
  if "$minvmd_bin" --vm-name beta status >/dev/null 2>&1; then
    echo "::error::NET-055: VM 'beta' still reports Running after its own stop"
    tnv_cleanup; fail
  fi
  if ! "$minvmd_bin" status >/dev/null 2>&1; then
    echo "::error::NET-055: the default VM stopped too when only 'beta' was told to"
    mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
    mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
    fail
  fi
  if [ "$(mnl --provider local-minvmd session exec "$default_sid" echo tnv-default-still-alive \
      2>/dev/null)" != tnv-default-still-alive ]; then
    echo "::error::NET-055: the default VM's box stopped answering after 'beta' alone was stopped"
    mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
    mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
    fail
  fi
  echo "NET-055 OK: stopping VM 'beta' left the default VM (and its box) running"

  mnl --provider local-minvmd session destroy --force "$default_sid" >/dev/null 2>&1 || true
  mnl --provider local-minvmd stop --force >/dev/null 2>&1 || true
  rm -rf "$beta_client_dir"
  echo "::endgroup::"
}

E2E_CASE="${E2E_CASE:-${1:-}}"
if [ -n "$E2E_CASE" ]; then
  case "$E2E_CASE" in
    min_internal_names_through_proxy) run_case_min_internal_names_through_proxy; exit $? ;;
    fresh_install_own_ip_ingress_publishes_loopback)
      run_case_fresh_install_own_ip_ingress_publishes_loopback; exit $? ;;
    session_outbound_request) run_case_session_outbound_request; exit $? ;;
    native_resolution_without_proxy_env) run_case_native_resolution_without_proxy_env; exit $? ;;
    own_ip_egress_declared_and_enforced) run_case_own_ip_egress_declared_and_enforced; exit $? ;;
    network_posture_from_stock_install) run_case_network_posture_from_stock_install; exit $? ;;
    escape_reaches_only_declared_union) run_case_escape_reaches_only_declared_union; exit $? ;;
    box_name_resolves_natively_without_proxy)
      run_case_box_name_resolves_natively_without_proxy; exit $? ;;
    fresh_linux_kvm_activate_local_minvmd)
      run_case_fresh_linux_kvm_activate_local_minvmd; exit $? ;;
    fresh_arm64_kvm_activate_local_minvmd)
      run_case_fresh_arm64_kvm_activate_local_minvmd; exit $? ;;
    hostnames_recover_and_two_daemons_route) run_case_hostnames_recover_and_two_daemons_route; exit $? ;;
    proxy_refuses_like_direct) run_case_proxy_refuses_like_direct; exit $? ;;
    port_publishes_on_listen_and_box_outlives_client)
      run_case_port_publishes_on_listen_and_box_outlives_client; exit $? ;;
    github_only_allowlist) run_case_github_only_allowlist; exit $? ;;
    expose_from_inside_box) run_case_expose_from_inside_box; exit $? ;;
    two_named_vms_on_one_machine) run_case_two_named_vms_on_one_machine; exit $? ;;
    *)
      # BEP's cases are `case_<name>` functions defined above, dispatched by
      # name rather than enumerated so a new one needs no arm here. Try that
      # family before calling the name unknown; a name in NEITHER family
      # still exits 2, so a typo in a `test:` line fails loudly.
      if declare -F "case_$E2E_CASE" >/dev/null; then
        "case_$E2E_CASE"
        echo "session e2e case $E2E_CASE OK"
        exit 0
      fi
      echo "::error::unknown e2e case '$E2E_CASE' (known: min_internal_names_through_proxy, fresh_install_own_ip_ingress_publishes_loopback, session_outbound_request, native_resolution_without_proxy_env, own_ip_egress_declared_and_enforced, network_posture_from_stock_install, escape_reaches_only_declared_union, box_name_resolves_natively_without_proxy, fresh_linux_kvm_activate_local_minvmd, fresh_arm64_kvm_activate_local_minvmd, hostnames_recover_and_two_daemons_route, proxy_refuses_like_direct, port_publishes_on_listen_and_box_outlives_client, github_only_allowlist, expose_from_inside_box, two_named_vms_on_one_machine)" >&2
      exit 2
      ;;
  esac
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

# ---------------------------------------------------------------------------
# Guest egress proof (NET-107), the same assertion the `session_outbound_request`
# case runs — see assert_session_outbound_reach above for what it proves and why
# one host answering is the bar. Gated on a seed we own, because only then is the
# shell stack (and thus curl) guaranteed present in the session.
if [ -n "$SEED_DIR" ] || [ -n "$SEEDED_MFILE" ]; then
  assert_session_outbound_reach "$sid"
fi

# ---------------------------------------------------------------------------
# Own-IP proof: a `--network own-ip` session gets a tap of its own, relayed to
# the gvproxy switch. Gated on MINVMD_GVPROXY_BIN, the one signal that a switch
# exists (`just e2e` sets it; `just e2e-native` does not). The relay is
# attached before `activate` returns, so a refused client fails there; the
# namespace side is read from /proc and /etc (a session rootfs has no iproute2)
# in ONE exec, checked at the top level so an exec hiccup is not a net result.
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
