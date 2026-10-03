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
#   MINIMAL_E2E_MIN     the exact `min` this run drives — an executable named
#                       `min` with its matching daemon beside it — for a caller
#                       that must smoke a SPECIFIC build (a release smoke)
#                       rather than whatever this checkout has under target/;
#                       when set, the repo-binary fallback in the min-resolution
#                       block is skipped entirely (see there)
#
# Every proof this script can run, as one `case` on the first argument (see
# the dispatch at the bottom). With NO argument every block runs, in exactly
# the order below; with a case name only that proof runs, standalone, against
# the same fresh state dir and seeds the full lane gets. Most proofs mint (and
# destroy) the sessions they need themselves; `session_exec`,
# `session_outbound_request` and `sandbox` instead share the one `lifecycle`
# activates first in a whole-lane run — and mint an equivalent session of their
# own when they run alone (see proof_shared_session), so every case name below
# is runnable by itself.
#   lifecycle                        cold activate → list → warm → destroy
#   session_exec                     `min session exec` in the session's namespaces
#   session_outbound_request         an outbound request from inside the session (NET-107)
#   own_ip                           `--network own_ip` tap + switch attach
#   own_ip_egress_declared_and_enforced
#                                    the four egress fields declared, allowed
#                                    and disallowed connections, the coming
#                                    deny-all announcement, and the opt-out
#   task_run                         `min task run` / `min session run` loop
#   hooks                            lifecycle hooks, loadouts, patches, shells
#   skip_scaffold                    the daemon-scaffolded blueprint upload lane
#   sandbox                          interactive attach: in-sandbox `min add`
#   restart                          daemon stop → autospawn, hooks survive
#   fresh_install_own_ip_ingress_publishes_loopback
#                                    a real install.sh run ships the switch;
#                                    own-IP ingress answers at the box's own
#                                    loopback address, read from the record
#   network_posture_from_stock_install
#                                    from a real install.sh run: --network and
#                                    --ingress in help+reference+hints, a none
#                                    box that attaches and reaches nothing,
#                                    the stock posture's reach, own-IP again
#   linux_stock_install_runs_vm_boxes
#                                    from a real install.sh run on a KVM host:
#                                    the VM stack the stock install ships runs
#                                    a box end to end — activate, listed, exec,
#                                    destroy delisted — off the images and
#                                    switch the install placed, with the VM
#                                    host daemon's start record naming them
#   min_internal_names_through_proxy NET-001..004 through the shipped proxy
#   proxy_refuses_like_direct        the proxy refuses exactly as the switch
#                                    does: paired direct/proxied attempts,
#                                    h2 closed, h2c stripped (NET-069..071, 135)
#   native_resolution_without_proxy_env
#                                    NET-009/122/123: the advisory, the probe,
#                                    and host-OS resolution with no proxies
#   hostnames_recover_and_two_daemons_route NET-020..027 warning, recovery,
#                                   two daemons on one machine routing
#   retired_surfaces_gone            NET-109/110: the retired surfaces are gone,
#                                    and a direct-tcpip forward relays for real
#   two_named_vms_on_one_machine     NET-052..059: a second named VM with its
#                                    own state, one `min ls` listing both,
#                                    box names resolving to their VM, both
#                                    routing at once, stop one leaves the other
#
# Usage: scripts/session-e2e.sh [case]
set -uo pipefail # not -e: capture failures so we can dump diagnostics

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
E2E_VM="${E2E_VM:-}"

# The VM-backed cases documented as such above and invoked directly by their
# task test lines: the fresh-install KVM activation proofs (NET-049/NET-051),
# the stock-install integration case, and the two-named-VMs integration case
# (NET-052..059). When called that way, behave as if the caller exported the
# KVM lane environment variables: E2E_VM=1 and
# E2E_MINIMAL_ARGS="--provider local-minvmd". Without this the script's
# min_daemon probe defaults to minimald on Linux and the standalone case fails
# before it reaches the proof.
case "${1:-}" in
  fresh_linux_kvm_activate_local_minvmd | fresh_arm64_kvm_activate_local_minvmd \
    | linux_stock_install_runs_vm_boxes | two_named_vms_on_one_machine)
    E2E_VM="${E2E_VM:-1}"
    if [ -z "${E2E_MINIMAL_ARGS:-}" ]; then
      E2E_MINIMAL_ARGS="--provider local-minvmd"
    fi
    ;;
esac

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

# The name of the session `lifecycle` activates and the exec/outbound/sandbox
# proofs share (see proof_shared_session).
SESSION_NAME="e2e-banner"

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
NATIVE_SEED_DIR="" # seeded by the native-resolution proof below; removed on teardown
NATIVE_REVERT_LINK="" # the link that proof pointed the host resolver at; reverted on teardown
PROXY_SEED_DIR="" # seeded by the min.internal proxy proof; removed on teardown
PROXY_OWN_SEED_DIR="" # its own-address box's seed; removed on teardown
PROXY_HOST_DIR="" # the host-loopback dir that proof serves; removed on teardown
PROXY_HOST_SRV_PID="" # the host-loopback server it starts; killed on teardown
PAR_SEED_DIR="" # seeded by the proxy-parity proof below; removed on teardown
PAR_OWN_SEED_DIR="" # its own-address target box's seed; removed on teardown
PAR_CALLER_SEED_DIR="" # its denied-caller box's seed; removed on teardown
RECOVER_SEED_DIR="" # the hostnames-recovery proof's seed; removed on teardown
SECOND_SEED_DIR="" # its second-daemon box's seed; removed on teardown
RECOVER_STATE2_DIR="" # the second daemon's state base; `mnl2 stop` on teardown
RECOVER_HOLDER_PID="" # the port holder the recovery proof starts; killed
RECOVER_SWITCH_SOCK="" # the minvmd switch socket beat C moves; restored
RECOVER_SWITCH_HOLD="" # where beat C parks it mid-proof
RETIRED_SEED_DIR="" # seeded by the retired-surfaces proof below; removed on teardown
RETIRED_FWD_PID="" # the `min net forward` it starts; killed on teardown
EGRESS_SEED_DIR="" # seeded by the own-IP egress proof below; removed on teardown
TWO_VM_NAME="" # the named VM the two-named-VMs proof creates; stopped on teardown
TWO_VM_SEED_A_DIR="" # that proof's default-VM box seed; removed on teardown
TWO_VM_SEED_B_DIR="" # its named-VM box seed; removed on teardown
TWO_VM_FWD_PID="" # the `min net forward` it starts; killed on teardown
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
#
# The one exception is the daemon's exec records: `minimald::exec` logs one
# INFO line per accepted exec naming the command (crates/minimald/src/exec.rs,
# "exec request"), and that line is the only record of what a lane asked a
# session to run once the session is gone — which is exactly what the outbound
# case (NET-107) owes its diagnostics: when its probe fails, the `min bug`
# bundle's daemon-log tail carries the probe's exec lines. `minimald::…` names
# a daemon module, so the CLI's own stdout stays at warn and the extraction
# above is untouched. The daemon inherits this RUST_LOG at autospawn, so a
# whole-lane run and a standalone case both get it.
export RUST_LOG="${RUST_LOG:-warn,minimald::exec=info}"

# Millisecond clock: GNU date on Linux; macOS `date` has no %N, use perl.
if [ -z "$(date +%s%3N | tr -d '0-9')" ]; then
  now_ms() { date +%s%3N; }
else
  now_ms() { perl -MTime::HiRes=time -e 'printf "%d", time()*1000'; }
fi

# The CLI this script drives is THIS REPO'S `min`. Its callers put it on
# PATH — CI's native lane exports `PATH="$PWD/target/debug:$PATH"`, `just
# e2e`/`just e2e-native` build it first — but a `min` found on PATH is not
# always that CLI: a host that is itself a minimal session box ships the
# in-sandbox `min` HELPER (crates/mctx/src/min_helper.sh), a relay that
# answers only add/task/search/check and prints its usage for every other
# subcommand, and it shadows the real CLI — so the run dies at the first
# `min session activate` with a bare `Usage: min <subcommand>` that names no
# real cause. `--version` tells the two apart (the helper has none), so:
# keep the PATH `min` when it is the real CLI, else fall back to a build of
# this checkout — its own target dir first, then the environment's
# CARGO_TARGET_DIR (an out-of-tree build cache) — and put the winning dir
# ON PATH, because the CLI autospawns its daemon by bare name
# (crates/minimal/src/autospawn.rs) and the pair must come from one build.
#
# The daemon that name resolves to on THIS run is `minimald` on a native
# run and `minvmd` on a VM-backed one: macOS is always VM-backed (no native
# minimald builds there), and a Linux run is VM-backed exactly when
# E2E_MINIMAL_ARGS carries `--provider local-minvmd`, which every VM lane
# passes (the justfile's e2e-env, the KVM lane, the VM smokes) — E2E_VM
# itself is deliberately not consulted: it marks teardown and log placement,
# not the backend the CLI will spawn. Autospawn looks the daemon up on PATH
# (a bare `Command::new`), never beside the CLI, so "findable" means ON
# PATH. A `min` whose daemon is unfindable sails through a gate that does
# not check this and dies only at the first activate's autospawn — an
# error that names no real cause — so every branch below must leave the
# daemon findable, and the gate after all of them holds each to it.
min_daemon=minimald
if [ "$(uname -s)" = Darwin ]; then
  min_daemon=minvmd
else
  case "${E2E_MINIMAL_ARGS:-}" in
    *local-minvmd*) min_daemon=minvmd ;;
  esac
fi
#
# That fallback picks this checkout's build for EVERY lane, release smokes
# included, and a smoke must never find itself driving something other than
# the artifact it exists to smoke. A caller that needs a SPECIFIC `min`
# names it with MINIMAL_E2E_MIN (an executable named `min`, with its
# matching daemon beside it — the sibling whose dir this branch puts FIRST
# on PATH, so autospawn then resolves the pair from one build): the choice
# is final, and the fallback is skipped entirely.
if [ -n "${MINIMAL_E2E_MIN:-}" ]; then
  if [ ! -x "$MINIMAL_E2E_MIN" ] || [ "$(basename -- "$MINIMAL_E2E_MIN")" != min ] \
     || [ ! -x "$(dirname -- "$MINIMAL_E2E_MIN")/$min_daemon" ]; then
    echo "::error::MINIMAL_E2E_MIN must be an executable named 'min' with its matching '$min_daemon' beside it (got: '$MINIMAL_E2E_MIN')" >&2
    exit 1
  fi
  min_cli_dir="$(cd "$(dirname -- "$MINIMAL_E2E_MIN")" && pwd)"
  PATH="$min_cli_dir:$PATH"
  export PATH
elif command -v min >/dev/null 2>&1 && min --version >/dev/null 2>&1 \
     && command -v "$min_daemon" >/dev/null 2>&1; then
  # The PATH pair is whole — keep it, dir and all, exactly as found.
  :
else
  min_cli_dir=""
  for d in "$ROOT/target/debug" "${CARGO_TARGET_DIR:-/nonexistent}/debug"; do
    if [ -x "$d/min" ]; then
      min_cli_dir="$d"
      break
    fi
  done
  # Nothing prebuilt — but this checkout can build the pair itself, and every
  # case below is runnable standalone from a bare checkout, so do the same
  # build `just e2e-native` does first (`cargo build -p minimald --bin
  # minimald -p minimal --bin min --locked`): the CLI plus the one daemon it
  # autospawns by name, `min_daemon` computed above per OS/backend. Dormant on
  # real lanes — they export target/debug on PATH or pass MINIMAL_E2E_MIN, so
  # one of the branches above already won — so this only pays where the gates
  # below would otherwise have nothing to check. A sandboxed bare checkout
  # (the agent runtime boxes are themselves session boxes: `min` on PATH is
  # the in-sandbox helper, and target/ is empty) is exactly that: the pair
  # builds, and the case then runs — or skips on its own prerequisites —
  # instead of the run dying at the CLI gate with a build instruction the
  # caller cannot read mid-verify.
  if [ -z "$min_cli_dir" ] && command -v cargo >/dev/null 2>&1; then
    echo "no usable 'min' on PATH and no build under target/; building the pair this run drives (cargo build --locked -p minimal --bin min -p $min_daemon --bin $min_daemon)"
    if (cd "$ROOT" && cargo build --locked -p minimal --bin min \
        -p "$min_daemon" --bin "$min_daemon") >"$WORK/cli-build.log" 2>&1; then
      for d in "$ROOT/target/debug" "${CARGO_TARGET_DIR:-/nonexistent}/debug"; do
        if [ -x "$d/min" ]; then
          min_cli_dir="$d"
          break
        fi
      done
      if [ -n "$min_cli_dir" ]; then
        echo "built the pair: $min_cli_dir/min and $min_cli_dir/$min_daemon"
      fi
    else
      echo "::warning::building the CLI pair failed — the gates below name what is missing. Build log tail follows:" >&2
      tail -20 "$WORK/cli-build.log" 2>/dev/null || true
    fi
  fi
  if [ -n "$min_cli_dir" ]; then
    PATH="$min_cli_dir:$PATH"
    export PATH
  fi
fi
# One gate over all three branches: whatever won, `min` is the repo CLI and
# the daemon it autospawns by name is findable on the PATH this run leaves
# behind — the pair, checked here once, so a broken one fails NOW, naming
# both halves, instead of at the first 'session activate'.
if ! command -v min >/dev/null 2>&1 || ! min --version >/dev/null 2>&1; then
  echo "::error::no usable 'min' CLI on this host: the 'min' on PATH is not" \
    "the repo CLI (it takes no --version; on a session box it is the in-sandbox" \
    "helper, which has no 'session' subcommands), and neither $ROOT/target/debug" \
    "nor ${CARGO_TARGET_DIR:-\$CARGO_TARGET_DIR}/debug has a build of it." \
    "Build one (just e2e, or cargo build -p minimal --bin min --locked) and" \
    "put its dir on PATH, as CI does." >&2
  exit 1
fi
if ! command -v "$min_daemon" >/dev/null 2>&1; then
  echo "::error::no usable '$min_daemon' on this host: the 'min' this run drives" \
    "autospawns it by bare name (crates/minimal/src/autospawn.rs), so it must be" \
    "on PATH — the pair has to come from one build — or the first 'session" \
    "activate' fails with no real cause named. Build the pair this lane drives" \
    "('just e2e-native': min + minimald, native; 'just e2e': min + minvmd, VM)" \
    "or put an existing '$min_daemon' dir on PATH, as CI does." >&2
  exit 1
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
  # The named VM the two-named-VMs proof may have created: it is NOT the
  # default VM `minvmd stop` above took down, and a leaked one keeps its own
  # supervisor, VMM and switch alive — the same wedge a leaked default VM
  # leaves, one directory deeper.
  if [ -n "$TWO_VM_NAME" ]; then
    minvmd --vm "$TWO_VM_NAME" stop >/dev/null 2>&1 || true
  fi
  [ -n "$SEED_DIR" ] && rm -rf "$SEED_DIR"
  [ -n "$SEEDED_MFILE" ] && rm -f "$SEEDED_MFILE"
  [ -n "$TASK_SEED_DIR" ] && rm -rf "$TASK_SEED_DIR"
  [ -n "$HOOK_SEED_DIR" ] && rm -rf "$HOOK_SEED_DIR"
  [ -n "$PATCH_SRC_DIR" ] && rm -rf "$PATCH_SRC_DIR"
  [ -n "$SKIP_SEED_DIR" ] && rm -rf "$SKIP_SEED_DIR"
  [ -n "$OWNIP_SEED_DIR" ] && rm -rf "$OWNIP_SEED_DIR"
  [ -n "$NATIVE_SEED_DIR" ] && rm -rf "$NATIVE_SEED_DIR"
  # The native-resolution proof points the HOST resolver at the daemon's
  # answerer; a run that died between that and its own revert must not leave
  # the change behind. `resolvectl revert` restores the link's DNS state and
  # `ip link del` removes the dedicated link the command created — the soak
  # runs this script ten times on one runner, so the next iteration must
  # find the host as this one did.
  if [ -n "$NATIVE_REVERT_LINK" ]; then
    sudo -n resolvectl revert "$NATIVE_REVERT_LINK" >/dev/null 2>&1 || true
    sudo -n ip link del "$NATIVE_REVERT_LINK" >/dev/null 2>&1 || true
  fi
  [ -n "$PROXY_SEED_DIR" ] && rm -rf "$PROXY_SEED_DIR"
  [ -n "$PROXY_OWN_SEED_DIR" ] && rm -rf "$PROXY_OWN_SEED_DIR"
  [ -n "$PROXY_HOST_DIR" ] && rm -rf "$PROXY_HOST_DIR"
  if [ -n "$PROXY_HOST_SRV_PID" ]; then
    kill "$PROXY_HOST_SRV_PID" 2>/dev/null || true
  fi
  [ -n "$PAR_SEED_DIR" ] && rm -rf "$PAR_SEED_DIR"
  [ -n "$PAR_OWN_SEED_DIR" ] && rm -rf "$PAR_OWN_SEED_DIR"
  [ -n "$PAR_CALLER_SEED_DIR" ] && rm -rf "$PAR_CALLER_SEED_DIR"
  # The hostnames-recovery proof's extras: the port holder it starts, the
  # second daemon it brings up (its sessions were destroyed in the proof,
  # but the daemon itself outlives them), and the switch socket beat C may
  # have moved — restoring it matters on a mid-beat failure, because a VM
  # lane with the socket gone never recovers its datapath and every later
  # case (and the soak's next run) would boot into a broken switch.
  if [ -n "$RECOVER_HOLDER_PID" ]; then
    kill "$RECOVER_HOLDER_PID" 2>/dev/null || true
  fi
  if [ -n "$RECOVER_STATE2_DIR" ]; then
    min --minimal-dir "$RECOVER_STATE2_DIR" stop --force >/dev/null 2>&1 || true
  fi
  if [ -n "$RECOVER_SWITCH_HOLD" ] && [ -n "$RECOVER_SWITCH_SOCK" ]; then
    mv "$RECOVER_SWITCH_HOLD" "$RECOVER_SWITCH_SOCK" 2>/dev/null || true
  fi
  [ -n "$RECOVER_SEED_DIR" ] && rm -rf "$RECOVER_SEED_DIR"
  [ -n "$SECOND_SEED_DIR" ] && rm -rf "$SECOND_SEED_DIR"
  [ -n "$RETIRED_SEED_DIR" ] && rm -rf "$RETIRED_SEED_DIR"
  [ -n "$EGRESS_SEED_DIR" ] && rm -rf "$EGRESS_SEED_DIR"
  [ -n "$TWO_VM_SEED_A_DIR" ] && rm -rf "$TWO_VM_SEED_A_DIR"
  [ -n "$TWO_VM_SEED_B_DIR" ] && rm -rf "$TWO_VM_SEED_B_DIR"
  # The two-named-VMs proof's forward holds a laptop-side listener; INT is
  # the documented stop, KILL the backstop.
  if [ -n "$TWO_VM_FWD_PID" ]; then
    kill -INT "$TWO_VM_FWD_PID" 2>/dev/null || true
    sleep 0.5 2>/dev/null || true
    kill -9 "$TWO_VM_FWD_PID" 2>/dev/null || true
  fi
  # The forward holds the laptop-side listener; INT is the documented stop,
  # KILL the backstop so a hung relay cannot outlive the run.
  if [ -n "$RETIRED_FWD_PID" ]; then
    kill -INT "$RETIRED_FWD_PID" 2>/dev/null || true
    sleep 0.5 2>/dev/null || true
    kill -9 "$RETIRED_FWD_PID" 2>/dev/null || true
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

# Mint (and validate) the session the exec, outbound and sandbox proofs share
# with `lifecycle`. `min session activate` must auto-spawn the target's daemon
# and print the new session id on stdout; the id is the LAST stdout line (any
# log lines that slip through the RUST_LOG filter precede it), validated as a
# UUID. In a whole-lane run `lifecycle` has minted it already and this returns
# immediately; standalone, the proof that needs one mints its own here, so
# every case the dispatch accepts runs on its own.
#
# Explicit name: the sandbox proof asserts the orientation banner interpolates
# the ACTUAL session name at the first prompt; an autogen name would make that
# assertion a moving target. The state dir is fresh per run, so a fixed name
# cannot collide.
proof_shared_session() {
  local out t0 t1
  [ -n "${sid:-}" ] && return 0
  echo "activating the shared session ($SESSION_NAME)"
  t0=$(now_ms)
  # shellcheck disable=SC2086
  out="$(cd "$PROJECT_DIR" && mnl session activate . --name "$SESSION_NAME" ${E2E_ACTIVATE_ARGS:-} 2>"$WORK/activate.err")" \
    || { echo "::error::'min session activate' failed to auto-spawn the daemon / create a session"; fail; }
  t1=$(now_ms)
  sid="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r')"
  echo "session: $sid (cold activate: $((t1 - t0))ms)"
  if ! printf '%s' "$sid" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
    echo "::error::activate's last stdout line is not a session UUID: '$sid'"
    echo "--- full activate stdout ---"; printf '%s\n' "$out"
    fail
  fi
}

# Cold: `min session activate` must auto-spawn the target's daemon and print the
# new session id on stdout (proof_shared_session does the activation and the
# UUID check; this proof then carries the listing and warm-call halves).
proof_lifecycle() {
echo "::group::cold activate (auto-spawns the daemon)"
proof_shared_session
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
proof_shared_session
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
# Session outbound request (NET-107): WHILE a session runs with network access,
# an outbound request from inside it must complete. The case runs after the
# cold activate — `lifecycle` mints the session it probes in a whole-lane run,
# and the case mints an equivalent one itself when it runs alone
# (proof_shared_session) — then curls a public host from inside that session.
#
# Every VM lane wires the gvproxy switch for the guest's egress (NAT + DNS),
# yet nothing else here asserts it works — and gvproxy resolution is
# best-effort and never errors, so a lane that silently loses the switch boots
# switchless, has no egress, and still reports green. A switchless boot has no
# NAT and no DNS, so it fails every host on every attempt and the case fails —
# that is the thing this case exists to catch, and one host answering cannot
# mask it. The symptom otherwise reaches a user as a bogus "could not resolve
# host" that is not a DNS problem. The `shell` stack composes curl, so no
# package is added. Gated on a seed we own, because only then is the shell
# stack (and thus curl) guaranteed present.
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
# working egress.
#
# The cost is that a partial fault — one name resolving, another not — lands as
# a warning rather than a failure. That is the intended trade: the lane is a
# gate on the session, and no CI gate should turn red because example.org is
# having a bad minute.
#
# Observability: every host tried is printed with its outcome — the host, the
# HTTP code it answered, and the attempt it answered on — so the transcript
# reads the probe instead of only its summary.
#
# Diagnostics: the daemon logs one INFO record per accepted exec naming the
# command (`minimald::exec`, admitted by the RUST_LOG default above), so when
# this case fails, the `min bug` bundle's daemon-log tail carries the probe's
# exec lines.
proof_session_outbound_request() {
if [ -n "$SEED_DIR" ] || [ -n "$SEEDED_MFILE" ]; then
  echo "::group::session outbound request proof (NET-107: an outbound request completes from inside the session)"
  proof_shared_session
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
        echo "session outbound to https://$egress_host failed on attempt ${egress_try}/3 (exec status ${egress_status}, got '${egress_out:-<none>}'); retrying in $((egress_try * 3))s"
        cat "$WORK/egress.err" 2>/dev/null || true
        sleep "$((egress_try * 3))"
      fi
    done
    if [ "$egress_status" -eq 0 ] && [ "$egress_out" = "HTTP:200" ]; then
      egress_ok=$((egress_ok + 1))
      echo "session outbound to https://$egress_host: HTTP 200 (attempt ${egress_try}/3)"
    else
      egress_failed="${egress_failed} https://$egress_host (exec status ${egress_status}, got '${egress_out:-<none>}')"
      # Warned, not failed: another host answering proves the session's egress,
      # which makes this that endpoint's problem and not the lane's. Still
      # surfaced, so a partial fault is visible instead of silently absorbed.
      echo "::warning::session outbound to https://$egress_host failed all 3 attempts (exec status ${egress_status}, got '${egress_out:-<none>}', want HTTP:200); not fatal while another host still proves the session reaches the network."
      echo "--- curl stderr ($egress_host) ---"; cat "$WORK/egress.err" 2>/dev/null || true
    fi
  done
  if [ "$egress_ok" -eq 0 ]; then
    echo "::error::the outbound request failed every attempt against all ${egress_total} hosts —${egress_failed}: the session has no working egress (NET-107). On a VM lane (E2E_VM='${E2E_VM:-}') a lost gvproxy switch is one hypothesis — a switchless boot has no NAT/DNS and fails every host — but a nonzero exec status or a non-200 code can equally be a DNS, TLS/CA, or exec-transport failure; the per-host curl stderr is above and the guest boot console follows in the diagnostics."
    fail
  fi
  echo "session outbound request OK (DNS + HTTPS reachable from the session; ${egress_ok}/${egress_total} hosts answered)"
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
# The host address a daemon published an own-IP box's ingress on, read from
# the expose record in the daemon's log (NET-040's observability record: one
# line per exposed mapping, naming the address the switch actually bound).
# Reading it — rather than assuming 127.0.0.1 — is what keeps this harness
# honest about NET-010: an own-address box publishes at the address the
# answerer granted it out of the reserved local range, and the record is the
# one place on the host that names it. $1 = the daemon's log file, $2 = the
# session name; prints the newest matching record's host address, nothing
# when no record names the session.
published_loopback_host() {
  grep -h -- 'exposed ingress port on the host loopback' "$1" 2>/dev/null \
    | grep -F "\"session\":\"$2\"" | tail -n1 \
    | sed -n 's/.*"host":"\([0-9][0-9.]*\)".*/\1/p'
}

# ---------------------------------------------------------------------------
# Own-IP egress declared and enforced, end to end (NET T20). Gated on
# MINVMD_GVPROXY_BIN like the own-IP proof above: own-address enforcement lives
# on the switch, so a target without one has nothing to prove here.
#
# This case drives the four egress flags the CLI exposes today
# (`--allow-subnets`, `--allow-dns-hosts`, `--allow-protocols`, `--deny-subnets`)
# through an own-address box, checks that `min session policy` shows the
# effective rules, proves an allowed connection completes and a disallowed one
# is dropped silently and logged, and records the deny-all default story around
# it: while the default is only announced this build still allows a bare
# own-address box and prints the coming change; an explicit deny-all declaration
# stands in for the in-force default to show the box reaching nothing; and the
# announcement names the opt-out flag that keeps the prior default.
proof_own_ip_egress_declared_and_enforced() {
  echo "::group::own-IP egress: declared and enforced (NET T20)"

  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "own-IP egress proof SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
    echo "::endgroup::"
    return 0
  fi

  EGRESS_SEED_DIR="$(hook_mktemp /tmp/mnleg.XXXXXX)"
  hook_seed_preamble > "$EGRESS_SEED_DIR/minimal.toml"
  mkdir "$EGRESS_SEED_DIR/.git"

  # The drop warning is a daemon-side record. On a native lane that log lives
  # on this host; on a VM lane it is inside the guest tmpfs, inaccessible here
  # (see hook_log_readable). Use the file's existing helper so the assertion
  # only runs where it can actually read the log, and fails closed when it
  # cannot.
  assert_egress_drop_logged() {
    if ! hook_log_readable; then
      echo "egress-drop log check skipped (guest-side daemon log on VM lane)"
      return 0
    fi
    if [ -n "$(hook_log_has 'network policy violation')" ]; then
      echo "daemon log: found the egress-drop warning"
      return 0
    fi
    echo "::error::no daemon log recorded the disallowed connection's drop"
    fail
  }

  # Whether one of this proof's curl probes actually reached a server. curl
  # ALWAYS writes its -w line — and writes `HTTP:000` when nothing answered —
  # so a completed exchange is a zero exit OR any real status back, whatever
  # the code and whatever curl then thought of the certificate. Judging by
  # `HTTP:200` alone (an earlier draft) would read a redirect or a TLS
  # complaint after a live answer as a drop, and prove enforcement nobody
  # enforced.
  egress_curl_answered() {
    local eca_rc="$1" eca_status="$2"
    [ "$eca_rc" -eq 0 ] && return 0
    [ -n "$eca_status" ] && [ "$eca_status" != "HTTP:000" ] && return 0
    return 1
  }

  # ---- NET-076: the coming deny-all default is announced -------------------
  # A bare own-address box still allows everything while the default is only
  # announced, but the user is told what is coming and how to keep the current
  # behaviour.
  announce_sid="$(cd "$EGRESS_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-egress-announce --network own_ip 2>"$WORK/egress-announce.err")" || {
    echo "::error::'min session activate --network own_ip' (announcement probe) failed"
    cat "$WORK/egress-announce.err" 2>/dev/null || true
    fail
  }
  announce_sid="$(printf '%s\n' "$announce_sid" | tail -n1 | tr -d '\r')"
  if ! grep -q "Heads-up: the next release denies all external reach" "$WORK/egress-announce.err"; then
    echo "::error::activate did not announce the coming deny-all default (NET-076)"
    cat "$WORK/egress-announce.err" 2>/dev/null || true
    fail
  fi
  if ! grep -q -- "--egress-deny-all-opt-out" "$WORK/egress-announce.err"; then
    echo "::error::the deny-all announcement did not name the opt-out flag"
    cat "$WORK/egress-announce.err" 2>/dev/null || true
    fail
  fi
  echo "NET-076 OK: activate announced the coming default and named the opt-out"

  # The remaining probes exercise allowed/disallowed flows against the public
  # internet, so they follow the same weather-aware policy as
  # proof_session_outbound_request: at least one host must answer to prove the
  # box can reach the network, but no CI gate turns red because example.com or
  # example.org is having a bad minute. A helper returns 0 if >=1 host answers.
  # The hosts are the caller's: the default pair is the sibling proof's, and a
  # policy-bound box names only the destination its rules admit — probing a
  # destination the box's own policy forbids could never answer, so asking one
  # to prove its reachability that way is vacuous (the declared box below
  # names example.com, the one host its allow list admits; example.org's
  # disallowed outcome is asserted in its own right further down).
  egress_reachability_probe() {
    local er_sid="$1" er_prefix="$2"
    shift 2
    local er_hosts="$*"
    [ -n "$er_hosts" ] || er_hosts="example.com example.org"
    local er_ok=0 er_total=0 er_failed=""
    local er_host er_try er_out er_status
    for er_host in $er_hosts; do
      er_total=$((er_total + 1))
      er_status=0
      er_out=""
      for er_try in 1 2 3; do
        er_out="$(mnl session exec "$er_sid" \
          "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 30 https://$er_host" \
          2>"$WORK/${er_prefix}-reach.err")"
        er_status=$?
        if [ "$er_status" -eq 0 ] && [ "$er_out" = "HTTP:200" ]; then
          break
        fi
        if [ "$er_try" -lt 3 ]; then
          echo "reachability probe https://$er_host failed on attempt ${er_try}/3 (status ${er_status}, got '${er_out:-<none>}'); retrying"
          cat "$WORK/${er_prefix}-reach.err" 2>/dev/null || true
          sleep "$((er_try * 3))"
        fi
      done
      if [ "$er_status" -eq 0 ] && [ "$er_out" = "HTTP:200" ]; then
        er_ok=$((er_ok + 1))
        echo "reachability probe https://$er_host: HTTP 200 (attempt ${er_try}/3)"
      else
        er_failed="${er_failed} https://$er_host (status ${er_status}, got '${er_out:-<none>}')"
        echo "reachability probe https://$er_host failed all 3 attempts; transcript above"
      fi
    done
    if [ "$er_ok" -gt 0 ]; then
      echo "external-reachability guard OK (${er_ok}/${er_total} hosts answered)"
      return 0
    fi
    echo "::warning::external-reachability guard failed for ${er_prefix} box against all ${er_total} hosts (${er_failed}); the remaining probes that need the public internet are skipped as warnings"
    return 1
  }

  if egress_reachability_probe "$announce_sid" "announce" example.com example.org; then
    echo "allowed-connection OK: a bare box still reaches the network during the announcement"
  else
    echo "allowed-connection WARNING: the bare box could not prove external reachability; the announcement text and opt-out were still verified above"
  fi

  # ---- the destination the declared box must be refused, proven live first --
  # NET-062's drop is only meaningful against a destination this lane can
  # actually reach: a connection nobody could have completed reads as a
  # "silent drop" on a networkless lane, which is enforcement nobody enforced.
  # So the SAME run first asks a box with NO egress section — the announce box
  # above, which the announcement phase still leaves unrestricted — to
  # complete the exact connection the declared box must be refused. Its
  # completing proves the destination is live and reachable through this
  # switch fabric, so the declared box's non-completion below can only be its
  # own rules — and it doubles as the reach the coming deny-all default takes
  # away (NET-074).
  #
  # The destination is a LITERAL public address, and it is chosen so nothing
  # the declared box admits can ever cover it. Its allow subnets are a
  # documentation range and its deny subnets another, which leaves the one
  # other way an address outside `allow_subnets` still connects: a DNS pin,
  # design §5.3's DNS-pinned admission, which admits an *address* for the
  # window its name resolved in — and admits it however the application
  # learned it, `curl --resolve` included, because the pin table is keyed by
  # address alone (crates/minimald/src/net/dns_gate.rs). An earlier round
  # probed a host-resolved address of example.com itself on the belief that
  # "the box's own resolution" and the host's never agree; the macOS lane is
  # where they do — both ride the same upstream — so the pinned address was
  # held, the "disallowed" connection was an allowed one, and the proof read
  # a completed connection as a failure to enforce. The candidates are public
  # anycast service endpoints, live on 443 and stable by design, that the one
  # name this box pins (example.com) can never resolve to — and being
  # literals, no resolver has to agree with anything for the probe to run.
  # Two of them, because a lane whose network blocks one still deserves the
  # proof: the first the bare box reaches is the one the declared box must be
  # refused.
  egress_disallowed_dst=""
  for egress_dst_candidate in 1.1.1.1 9.9.9.9; do
    for egress_dst_try in 1 2 3; do
      egress_dst_out="$(mnl session exec "$announce_sid" \
        "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 20 https://$egress_dst_candidate/" \
        2>"$WORK/egress-dst-live.err")"
      egress_dst_rc=$?
      if egress_curl_answered "$egress_dst_rc" "${egress_dst_out:-}"; then
        egress_disallowed_dst="$egress_dst_candidate"
        echo "control GET https://$egress_dst_candidate/ from the bare box -> ${egress_dst_out:-<none>} (attempt ${egress_dst_try}/3): the destination is live on this lane, so the declared box below must be refused this same connection"
        break
      fi
      echo "control GET https://$egress_dst_candidate/ from the bare box failed on attempt ${egress_dst_try}/3 (rc ${egress_dst_rc}, got '${egress_dst_out:-<none>}')"
      cat "$WORK/egress-dst-live.err" 2>/dev/null || true
      if [ "$egress_dst_try" -lt 3 ]; then
        sleep 3
      fi
    done
    if [ -n "$egress_disallowed_dst" ]; then
      break
    fi
  done
  if [ -z "$egress_disallowed_dst" ]; then
    echo "::warning::the bare box could not reach a disallowed candidate destination on this run, so the disallowed-connection drop below is skipped as a weather warning (without this control a non-completion would be indistinguishable from a dead route)"
  fi
  mnl session destroy --force "$announce_sid" >/dev/null 2>&1 || true

  # ---- NET-060/061/062/063: four-field declaration, effective rules, drop --
  # The allowed list is intentionally narrow: one non-loopback documentation
  # CIDR, example.com, and TCP+UDP. The CIDR is TEST-NET-3 (RFC 5737): a range
  # no real destination ever sits inside, so the rule can never admit live
  # traffic — but it is a genuine allow rule, unlike the loopback entry an
  # earlier round used: the infrastructure deny set always refuses 127.0.0.0/8
  # (design §5.3's rebinding defence, CIDR-admitted flows included), so a
  # `127.0.0.1/32` rule can never admit anything and would present a dead
  # entry as a working allow rule. The resolver carve-out handles DNS to the
  # switch gateway, so example.com resolves and is admitted by name.
  declare_sid="$(cd "$EGRESS_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-egress-declared --network own_ip \
    --allow-subnets 203.0.113.0/24 \
    --allow-dns-hosts example.com \
    --allow-protocols tcp \
    --allow-protocols udp \
    --deny-subnets 198.51.100.0/24 \
    2>"$WORK/egress-declared.err")" || {
    echo "::error::'min session activate' with the four egress fields failed"
    cat "$WORK/egress-declared.err" 2>/dev/null || true
    fail
  }
  declare_sid="$(printf '%s\n' "$declare_sid" | tail -n1 | tr -d '\r')"
  if grep -q "Heads-up: the next release denies all external reach" "$WORK/egress-declared.err"; then
    echo "::error::a declared box was announced as if it had no egress section"
    cat "$WORK/egress-declared.err" 2>/dev/null || true
    fail
  fi
  echo "own-IP session with four egress fields: $declare_sid"

  policy_out="$(mnl session policy "$declare_sid" 2>"$WORK/egress-policy.err")" || {
    echo "::error::'min session policy' failed for the declared box"
    cat "$WORK/egress-policy.err" 2>/dev/null || true
    fail
  }
  echo "effective policy of the declared box:"
  printf '%s\n' "$policy_out" | sed 's/^/  /'
  if ! grep -q "subnets  203.0.113.0/24" <<<"$policy_out" \
    || ! grep -q "dns hosts  example.com" <<<"$policy_out" \
    || ! grep -q "protocols  tcp, udp" <<<"$policy_out" \
    || ! grep -q "deny subnets  198.51.100.0/24" <<<"$policy_out"; then
    echo "::error::'min session policy' did not show all four declared egress fields"
    echo "--- raw policy output ---"
    printf '%s\n' "$policy_out"
    fail
  fi
  echo "NET-061 OK: the four egress fields are visible in the effective policy"

  # The connection probes need the public internet. Their control is the
  # allowed name's own completion (NET-063): example.com is the one
  # destination this box's rules admit, so its completing proves both the
  # lane's network and the allowed path — and, on the SAME run, separates a
  # policy drop from a dead network, which is what lets the fast-failure
  # branches below be hard fails instead of weather warnings. The control's
  # result is kept for the deny-all stand-in further down, whose own
  # reachability cannot be probed from itself (it reaches nothing by
  # construction, so a guard run from it could never pass).
  declared_reach_ok=0
  if egress_reachability_probe "$declare_sid" "declared" example.com; then
    declared_reach_ok=1
    echo "NET-063 OK: https://example.com completed — allowed by name and protocol, and the control that separates a policy drop below from a dead network"

    # ---- NET-062: a packet to an unadmitted address drops silently ---------
    # The silent drop NET-062 binds is a packet property, not a name one: a
    # name outside `allow_dns_hosts` is a resolver matter (design §5.3 refuses
    # non-matching names at resolution), so the drop is proven against a
    # destination ADDRESS no rule and no pin admits — the literal chosen and
    # proven live further up, from the bare box, in this same run. Two
    # controls bracket it: the bare box's completed connection to the very
    # destination (a live destination on this lane, reached through the same
    # fabric) and this box's own completed connection to example.com above
    # (this box's network and its allowed path), so a non-completion here is
    # neither a dead route nor a dead box, and a fast refusal is the box's own
    # doing rather than weather.
    if [ -z "$egress_disallowed_dst" ]; then
      echo "::warning::NET-062: the disallowed-address drop is skipped as a weather warning (the bare box reached no candidate destination above, so a drop here would prove nothing about the rules)"
    else
      deny_start_ms="$(now_ms)"
      mnl session exec "$declare_sid" \
        "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 10 https://$egress_disallowed_dst/" \
        >"$WORK/egress-deny-ip.out" 2>"$WORK/egress-deny-ip.err"
      deny_rc=$?
      deny_elapsed_ms=$(( $(now_ms) - deny_start_ms ))
      deny_status="$(cat "$WORK/egress-deny-ip.out" 2>/dev/null)"
      deny_err="$(tr '\n' ' ' < "$WORK/egress-deny-ip.err" 2>/dev/null)"
      echo "disallowed-address GET https://$egress_disallowed_dst/ -> rc=$deny_rc status=${deny_status:-<none>} elapsed=${deny_elapsed_ms}ms curl: ${deny_err:-<none>}"
      if egress_curl_answered "$deny_rc" "${deny_status:-}"; then
        echo "::error::NET-062: a connection to an address no rule admits ($egress_disallowed_dst) completed — the bare box completed this same connection above, so the lane reaches the destination and the egress rules did not enforce"
        cat "$WORK/egress-deny-ip.err" 2>/dev/null || true
        fail
      fi
      if printf '%s' "$deny_err" | grep -qi 'reset by peer'; then
        echo "::error::NET-062: the disallowed connection was reset, not dropped silently"
        cat "$WORK/egress-deny-ip.err" 2>/dev/null || true
        fail
      fi
      if [ "$deny_elapsed_ms" -ge 6000 ]; then
        echo "NET-062 OK: the disallowed connection to $egress_disallowed_dst dropped silently (no answer and no reset until the 10 s timeout), while the bare box completed the same connection in this run"
        assert_egress_drop_logged
        echo "NET-062 (rate-limited warning) OK: the drop is logged"
      else
        echo "::error::NET-062: the disallowed connection failed in ${deny_elapsed_ms}ms — a fast refusal, not a silent drop. The controls bracketing this probe (the bare box's completed connection to the same destination, and this box's own to https://example.com) both completed on this run, so the network path is alive and the fast failure is the box's own doing"
        cat "$WORK/egress-deny-ip.err" 2>/dev/null || true
        fail
      fi
    fi

    # ---- the disallowed NAME, its own assertion ----------------------------
    # example.org is outside `allow_dns_hosts`, so its connection must not
    # complete. Whether it is refused FAST at resolution (the design outcome:
    # the resolver refuses a non-matching name) or TIMES OUT with no reset
    # (the current relay leaves the name unpinned and drops the SYN) is NOT
    # asserted either way — reconciling those two is the dns_gate work's, not
    # this proof's — but the observed outcome is printed, with the curl error
    # and the elapsed time, so the transcript names which behaviour this
    # build has.
    name_deny_start_ms="$(now_ms)"
    mnl session exec "$declare_sid" \
      "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 10 https://example.org" \
      >"$WORK/egress-deny-name.out" 2>"$WORK/egress-deny-name.err"
    name_rc=$?
    name_elapsed_ms=$(( $(now_ms) - name_deny_start_ms ))
    name_status="$(cat "$WORK/egress-deny-name.out" 2>/dev/null)"
    name_err="$(tr '\n' ' ' < "$WORK/egress-deny-name.err" 2>/dev/null)"
    if egress_curl_answered "$name_rc" "${name_status:-}"; then
      echo "::error::https://example.org completed — a name outside allow_dns_hosts reached its destination; the egress rules did not enforce"
      cat "$WORK/egress-deny-name.err" 2>/dev/null || true
      fail
    fi
    name_outcome="fast refusal"
    if grep -qi 'could not resolve' "$WORK/egress-deny-name.err" 2>/dev/null; then
      name_outcome="fast resolver refusal"
    elif [ "$name_elapsed_ms" -ge 6000 ]; then
      name_outcome="timeout with no reset"
    fi
    echo "disallowed-name GET https://example.org -> rc=$name_rc status=${name_status:-<none>} elapsed=${name_elapsed_ms}ms ($name_outcome) curl: ${name_err:-<none>}"
  else
    echo "allowed/disallowed-connection WARNING: the declared box could not complete its allowed connection to https://example.com; the connection assertions that need the public internet are skipped as weather warnings"
  fi

  # ---- NET-074 stand-in: no egress section reaches nothing once the default
  # is in force. The shipped phase is announced, so we exercise the
  # enforcement shape with an explicit deny-all declaration (deny 0.0.0.0/0);
  # the unit and CLI tests already cover the in-force resolution, and the
  # announcement above covers the transition notice. This is a stand-in for
  # NET-074's REACH only: NET-075's observable is the word `deny all` in
  # `min session policy`, which an explicit-rule box cannot show — it shows
  # its rule — so that rendering stays with the CLI tests that pin it.
  deny_all_sid="$(cd "$EGRESS_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-egress-deny-all --network own_ip \
    --deny-subnets 0.0.0.0/0 \
    2>"$WORK/egress-deny-all.err")" || {
    echo "::error::'min session activate --deny-subnets 0.0.0.0/0' failed"
    cat "$WORK/egress-deny-all.err" 2>/dev/null || true
    fail
  }
  deny_all_sid="$(printf '%s\n' "$deny_all_sid" | tail -n1 | tr -d '\r')"

  # "A box with no effective reach reaches nothing" only means something if
  # the lane can already reach the public internet — otherwise the
  # non-completion being asserted here is just the dead network. The control
  # is the declared box's guard from THIS run, not a probe from the deny-all
  # box itself: that box reaches nothing by construction, so a guard run from
  # it could never pass and the assertion would always be skipped. Branch on
  # the control — a hard assertion when it passed, a weather warning when it
  # did not — and probe the same endpoint the control just proved answers.
  if [ "$declared_reach_ok" != 1 ]; then
    echo "::warning::NET-074: the declared box could not prove external reachability in this run, so the deny-all stand-in's reach assertion is skipped as a weather warning"
  else
    deny_all_start_ms="$(now_ms)"
    mnl session exec "$deny_all_sid" \
      "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 10 https://example.com" \
      >"$WORK/egress-deny-all.out" 2>"$WORK/egress-deny-all-curl.err"
    deny_all_rc=$?
    deny_all_elapsed_ms=$(( $(now_ms) - deny_all_start_ms ))
    deny_all_status="$(cat "$WORK/egress-deny-all.out" 2>/dev/null)"
    deny_all_err="$(tr '\n' ' ' < "$WORK/egress-deny-all-curl.err" 2>/dev/null)"
    if egress_curl_answered "$deny_all_rc" "${deny_all_status:-}"; then
      echo "::error::a deny-all box reached an external destination"
      cat "$WORK/egress-deny-all-curl.err" 2>/dev/null || true
      fail
    fi
    # Two outcomes are legitimate for this box, and only two: the resolver
    # refuses the name outright (example.com is in no allow list, and the
    # address it resolves to sits inside the 0.0.0.0/0 deny), or the SYN
    # leaves, matches the deny, and gets no answer until the timeout — the
    # silent drop NET-062 binds, which is what an enforcing filter looks like
    # from inside the box. A fast failure that is neither of those means the
    # connection reached something that answered it, and the control that
    # gated this branch completed https://example.com from the declared box in
    # this run, so the destination answers on this lane: the fast failure is
    # the box's own escaping SYN (or a broken probe), never weather. The
    # disallowed-IP probe above hard-fails this same shape; accepting it here
    # would print a policy hole as `NET-074 OK`.
    deny_all_outcome="fast refusal"
    if grep -qi 'could not resolve' "$WORK/egress-deny-all-curl.err" 2>/dev/null; then
      deny_all_outcome="fast resolver refusal"
    elif [ "$deny_all_elapsed_ms" -ge 6000 ]; then
      deny_all_outcome="timeout with no reset"
    fi
    echo "deny-all GET https://example.com -> rc=$deny_all_rc status=${deny_all_status:-<none>} elapsed=${deny_all_elapsed_ms}ms ($deny_all_outcome) curl: ${deny_all_err:-<none>}"
    if printf '%s' "$deny_all_err" | grep -qi 'reset by peer'; then
      echo "::error::NET-074: the deny-all box's connection to https://example.com was reset by the destination — the SYN escaped the 0.0.0.0/0 deny and reached a server this run's control proved answers"
      cat "$WORK/egress-deny-all-curl.err" 2>/dev/null || true
      fail
    fi
    if [ "$deny_all_outcome" = "fast refusal" ]; then
      echo "::error::NET-074: the deny-all box failed in ${deny_all_elapsed_ms}ms — a fast refusal that is neither a resolver refusal nor a silent drop. The control above completed https://example.com from the declared box in this run, so the destination answers on this lane and the fast failure is the box's own escaping connection or a broken probe, not weather"
      cat "$WORK/egress-deny-all-curl.err" 2>/dev/null || true
      fail
    fi
    echo "NET-074 OK: a box with no effective external reach gets nothing (explicit deny-all stand-in for the in-force default)"
  fi

  mnl session destroy --force "$declare_sid" >/dev/null 2>&1 || true
  mnl session destroy --force "$deny_all_sid" >/dev/null 2>&1 || true
  rm -rf "$EGRESS_SEED_DIR"; EGRESS_SEED_DIR=""
  echo "own-IP egress declared and enforced OK"
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# Fresh-install loopback publish proof (NET-040/NET-041/NET-102): from a REAL
# scripts/install.sh run into a fresh HOME — a local mock bucket built out of
# THIS checkout's own binaries, reached through the same stub-curl trick
# install_test.sh uses, so the installer itself runs unmodified — the
# installed pair must serve an own-IP box whose `--ingress 8080:8080` mapping
# answers ON THE HOST at the box's OWN loopback address with the box's own
# server's response — the address read from the daemon's expose record, never
# assumed: an own-address box publishes at the address the answerer granted it
# out of the reserved local range (NET-010), so a proof that probed a fixed
# 127.0.0.1 would be looking at the interim, not the box.
# That is the own-address pipeline in the exact shape a user gets it: the
# installer ships gvproxy-min into ~/.local/bin (and names the path it
# verified), the daemon finds it there through switch::installed_gvproxy_bin,
# and the switch publishes the box's port on the host loopback — with one
# record in the daemon's log per exposed mapping (host, port, session).
#
# Gating, decided by where the proof's pieces actually run:
#   * Native Linux only. A VM lane's daemon runs in the guest while the pair
#     this proof installs lives host-side (macOS is always VM-backed), so
#     there is no fresh-install story to drive there — those lanes'
#     own-address boxes are the proxy proof's own-address half.
#   * The box needs a TUN device: its session program opens /dev/net/tun for
#     its in-namespace tap, and a host that is itself a sandbox (the
#     agent-runtime boxes this harness runs on) has none and cannot mknod one,
#     so the box cannot come up no matter what this proof ships. Gate on the
#     device and skip when it is absent — the same prerequisite the
#     own-ip tap root integration harness asserts on the native netns lane,
#     which has it and runs this case for real.
#   * The switch binary to ship: $MINVMD_GVPROXY_BIN, the justfile's
#     .scratch/gvproxy, or the pinned fetch. Unlike own_ip this never SKIPS
#     for want of one: a lane that cannot ship a switch cannot prove what
#     this case exists for, so the fetch failing is a failure.
#   * The system-package half (the daemon serving the same mapping from
#     /usr/bin/gvproxy-min, the nfpm/AUR dest) runs only on a lane that can
#     stage that path — writable /usr/bin, never over an existing binary;
#     the probe ORDER that finds it is pinned by the switch crate's resolver
#     tests either way.
#   * The host half of the mapping is <the box's address>:<host port>, the
#     address from the expose record and the port below. The port is 8080; a
#     host that already has a listener at 127.0.0.1:8080 (the agent-runtime
#     boxes this harness itself runs on do) takes the fallback 18082 instead —
#     the box always serves its INTERNAL 8080, so the mapping exercised is
#     always <host-port>:8080 and a clean host runs it exactly as the proof
#     sentence says. The claim guards the one publish that could ever land on
#     127.0.0.1: the interim a box with no granted address of its own
#     publishes on — which cannot happen on this lane (the range is bindable
#     on every Linux host), but costs nothing to keep honest.
#
# Ordered after `restart`: it stops whatever daemon is up and swaps the
# driving pair to the installed one, so nothing that still shares the
# `lifecycle` session may follow it. The whole body runs in a subshell — HOME,
# PATH, MINIMAL_BIN and RUST_LOG all change for the installed pair and must
# revert before the next proof runs — and a failure exits the subshell, with
# the wrapper calling fail so the run still dumps its diagnostics.
proof_fresh_install_own_ip_ingress_publishes_loopback() {
local fi_arch fi_gvproxy fi_root fi_home fi_bucket fi_stubbin fi_seed fi_out
local fi_h_minimald fi_h_minimal fi_h_gvmin fi_sid fi_sid2 fi_log fi_rec
local fi_ready fi_answered fi_status fi_bucket_host fi_hport fi_portpat
local fi_host fi_host2 fi_pkg_log
local fi_lane_minimald fi_restore_profile
if [ -n "$E2E_VM" ] || [ "$(uname -s)" != Linux ]; then
  echo "fresh-install loopback publish SKIPPED (VM-backed lane: the pair this proof installs lives host-side)"
  return 0
fi
case "$(uname -m)" in
  x86_64)        fi_arch=amd64 ;;
  aarch64|arm64) fi_arch=arm64 ;;
  *)
    echo "fresh-install loopback publish SKIPPED (no release arch for $(uname -m))"
    return 0
    ;;
esac

# The box opens /dev/net/tun for its in-namespace tap; without the device its
# session program cannot spawn, and a host that is itself a sandbox cannot
# mknod one either. Skip rather than fail: the failure would say nothing about
# this branch, and the native CI lane — where the tap root integration harness
# already builds a tap — runs the case for real.
if [ ! -c /dev/net/tun ]; then
  echo "fresh-install loopback publish SKIPPED (no /dev/net/tun on this host: an own-IP box cannot open its in-namespace tap; runs for real on a host that has the device)"
  return 0
fi

# The proof's mapping is 8080:8080 — the box serves its INTERNAL 8080, the
# switch publishes the host half at the box's own address out of the reserved
# local range (read from the expose record below). What is claimed here is the
# host PORT: 127.0.0.1:<port> is where a box with no granted address of its own
# would publish (the interim), and a host may already have a listener at the
# 8080 one (the agent-runtime boxes this harness itself runs on do), so claim
# it BEFORE anything is installed and take the fallback port when it is
# occupied — the whole pipeline — install, switch discovery, expose, host
# answer, log record — is exercised either way, and a clean host runs the
# mapping exactly as the proof sentence says it.
fi_hport=8080
if curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:$fi_hport/" 2>/dev/null; then
  if curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:18082/" 2>/dev/null; then
    echo "::error::both 127.0.0.1:8080 and the fallback 18082 already answer on this host; the loopback publish proof needs one of them free"
    fail
  fi
  fi_hport=18082
  echo "127.0.0.1:8080 is already answering on this host — publishing the mapping on the fallback port $fi_hport instead (the box still serves its internal 8080)"
fi
fi_portpat="\"port\":$fi_hport"

# The daemon THIS lane was driving, resolved before the proof swaps PATH and
# HOME over to the installed pair. On a host that restricts unprivileged user
# namespaces (stock Ubuntu 24.04+) the harness's start-up block attached the
# minimald AppArmor profile to this binary, and attaching it to anything else
# REPLACES the recorded set — so the re-attach inside the proof must name this
# one too, or the proofs that follow would lose the profile and with it every
# sandbox they fork.
fi_lane_minimald="$(command -v minimald 2>/dev/null || true)"

# The switch binary the fresh install will ship. `just e2e` and a dev who ran
# `just gvproxy` already have one; otherwise fetch the pinned release — the
# installer's own pinned artifact, verified against vendor/gvproxy/gvproxy.lock.
if [ -n "${MINVMD_GVPROXY_BIN:-}" ] && [ -x "$MINVMD_GVPROXY_BIN" ]; then
  fi_gvproxy="$MINVMD_GVPROXY_BIN"
elif [ -x "$ROOT/.scratch/gvproxy" ]; then
  fi_gvproxy="$ROOT/.scratch/gvproxy"
else
  mkdir -p "$WORK/fresh-install"
  if ! "$ROOT/scripts/fetch-gvproxy.sh" "$WORK/fresh-install/gvproxy" \
      >"$WORK/fresh-install/fetch-gvproxy.out" 2>&1; then
    echo "::error::could not fetch the pinned gvproxy the fresh install must ship"
    cat "$WORK/fresh-install/fetch-gvproxy.out" 2>/dev/null || true
    fail
  fi
  fi_gvproxy="$WORK/fresh-install/gvproxy"
fi

echo "::group::fresh install publishes an own-IP ingress on the host loopback"
# Everything the proof builds lives under $WORK/fresh-install, so the state
# dir's teardown covers all of it — no extra bookkeeping.
fi_root="$WORK/fresh-install"
fi_home="$fi_root/home"
fi_bucket="$fi_root/bucket"
fi_stubbin="$fi_root/stubbin"
fi_seed="$fi_root/seed"
fi_out="$fi_root/install.out"
fi_bucket_host="https://mock.invalid/minimal-fresh"
mkdir -p "$fi_home" "$fi_bucket/versions/v1" "$fi_stubbin" "$fi_seed"
hook_seed_preamble > "$fi_seed/minimal.toml"
# The `.git` marker the headless upload gate wants.
mkdir "$fi_seed/.git"

# The mock bucket: the real artifacts this lane drives — its own `min` and
# `minimald`, plus the gvproxy the installer must ship — behind the pinned
# host the stub curl below maps to this dir. A `curl | sh` install without
# the network; the real transport is CI's real-bucket installer run.
cp "$(command -v min)"      "$fi_bucket/versions/v1/minimal-linux-$fi_arch"
cp "$(command -v minimald)" "$fi_bucket/versions/v1/minimald-linux-$fi_arch"
cp "$fi_gvproxy"            "$fi_bucket/versions/v1/gvproxy-min-linux-$fi_arch"
printf 'v1\n' >"$fi_bucket/stable"
fi_sha() { sha256sum "$1" | awk '{print $1}'; }
fi_h_minimald="$(fi_sha "$fi_bucket/versions/v1/minimald-linux-$fi_arch")"
fi_h_minimal="$(fi_sha "$fi_bucket/versions/v1/minimal-linux-$fi_arch")"
fi_h_gvmin="$(fi_sha "$fi_bucket/versions/v1/gvproxy-min-linux-$fi_arch")"
{
  printf '# format: 1\n'
  printf '# component   os      arch    version   sha256   kind   dest   src\n'
  printf '\n'
  printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
    minimald linux "$fi_arch" v1 "$fi_h_minimald" file bin/minimald "versions/v1/minimald-linux-$fi_arch"
  printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
    minimal linux "$fi_arch" v1 "$fi_h_minimal" file bin/min "versions/v1/minimal-linux-$fi_arch"
  printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
    gvproxy-min linux "$fi_arch" v1 "$fi_h_gvmin" file bin/gvproxy-min "versions/v1/gvproxy-min-linux-$fi_arch"
} >"$fi_bucket/versions/v1/components"

cat >"$fi_stubbin/curl" <<STUB
#!/bin/sh
# Fake curl: maps the pinned bucket host to the local dir this proof built —
# the same trick install_test.sh uses, so the real installer runs unmodified;
# its own HTTPS/TLS flags are accepted and ignored.
out= url=
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    https://*|http://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
[ -n "\$url" ] || { echo "stub curl: no url" >&2; exit 2; }
rel="\${url#$fi_bucket_host/}"
src="$fi_bucket/\$rel"
[ -f "\$src" ] || { echo "stub curl: 404 \$url" >&2; exit 22; }
if [ -n "\$out" ]; then cp "\$src" "\$out"; else cat "\$src"; fi
STUB
chmod +x "$fi_stubbin/curl"
# Force the wget path off so the downloader selection is deterministic.
cat >"$fi_stubbin/wget" <<'STUB'
#!/bin/sh
echo "stub wget should not be used here" >&2
exit 1
STUB
chmod +x "$fi_stubbin/wget"

if (
  # The install itself, into the fresh home: the same command a user runs,
  # over the stub transport. MINIMAL_BIN pins the prefix the installer and
  # the daemon's binary probe both resolve (~/.local/bin under the fresh
  # HOME is the default anyway; explicit so a stray env cannot redirect it).
  HOME="$fi_home" MINIMAL_BIN="$fi_home/.local/bin" \
  PATH="$fi_stubbin:$PATH" \
  MINIMAL_OVERRIDE_INSTALLER_BUCKET="$fi_bucket_host" \
    sh "$ROOT/scripts/install.sh" >"$fi_out" 2>&1 || {
      echo "::error::the fresh install failed"
      echo "--- install output ---"; cat "$fi_out" 2>/dev/null || true
      exit 1
    }
  # NET-041's installer half: the install NAMES the switch binary it verified.
  grep -qE 'switch-binary +verified +[^ ]*/bin/gvproxy-min$' "$fi_out" || {
    echo "::error::the install output does not name the switch binary it verified"
    echo "--- install output (tail) ---"; tail -25 "$fi_out" 2>/dev/null || true
    exit 1
  }
  [ -x "$fi_home/.local/bin/gvproxy-min" ] || {
    echo "::error::the fresh install did not ship an executable gvproxy-min"
    exit 1
  }

  # A host that restricts unprivileged user namespaces confines the permission
  # to the executable paths the minimald profile names, and this proof's pair
  # sits under a fresh mktemp home that none of the stock tunables can cover
  # (`@{HOME}/.local/bin/minimald` matches a real home, not a nested one) — so
  # the INSTALLED daemon comes up unconfined and every sandbox it forks dies
  # writing /proc/self/uid_map with EPERM, far from the cause: the first thing
  # this proof would see is the socat probe below failing with nothing in its
  # stderr that names it. Attach it exactly as the installer's own advisory
  # tells a user to, before the pair is driven. `--path` replaces the recorded
  # set, so the lane's binary is named alongside it (see fi_lane_minimald); the
  # EXIT trap below puts the set back on the way out.
  fi_restore_profile=0
  if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = 1 ]; then
    fi_attach_args=()
    for fi_p in "$fi_home/.local/bin/minimald" "$fi_lane_minimald"; do
      [ -n "$fi_p" ] && [ -e "$fi_p" ] && fi_attach_args+=(--path "$fi_p")
    done
    if ! sudo -n "$ROOT/scripts/install-apparmor-profile.sh" "${fi_attach_args[@]}"; then
      echo "::error::this host restricts unprivileged user namespaces and the minimald AppArmor profile could not be attached to the installed pair, so its session sandbox cannot start (see docs/reference/linux-host-setup.md)"
      exit 1
    fi
    fi_restore_profile=1
    echo "restricted host: minimald AppArmor profile attached to the installed pair ($fi_home/.local/bin/minimald)"
  fi
  # One EXIT trap for the whole subshell, so every path out of it — the early
  # exits above included — undoes both things the proof staged on the host: the
  # package-path switch (the /usr/bin/gvproxy-min half below) and the profile
  # attachment set it widened above. Neither way this function is reached is
  # visible to shellcheck — `trap` calls it out of a subshell shellcheck
  # cannot follow (SC2317, on older shellchecks) and the subshell's own
  # fall-through calls it too (SC2329, on newer ones) — so the directive below
  # silences both, and it covers the whole definition, body included.
  # shellcheck disable=SC2317,SC2329
  fi_cleanup() {
    rm -f /usr/bin/gvproxy-min 2>/dev/null || true
    if [ "${fi_restore_profile:-0}" = 1 ] && [ -n "$fi_lane_minimald" ]; then
      sudo -n "$ROOT/scripts/install-apparmor-profile.sh" \
        --path "$fi_lane_minimald" >/dev/null 2>&1 || echo "::warning::could not restore the minimald AppArmor profile's attachment set (sudo -n failed); it still names the installed pair's path, which this proof deletes with its work dir" >&2
    fi
  }
  trap fi_cleanup EXIT

  # Drive the INSTALLED pair: its dir goes first on PATH (the CLI autospawns
  # its daemon by bare name, so the pair must resolve from one dir) and HOME
  # becomes the fresh install's, which is exactly how the daemon finds the
  # switch the installer shipped (switch::installed_gvproxy_bin probes
  # \$MINIMAL_BIN, then ~/.local/bin). The expose record this proof reads
  # from the daemon log is INFO while the harness quiets the CLI to `warn`
  # for output parsing, so the activate that autospawns the daemon alone
  # carries the noisier filter — as a command-local assignment, never a
  # subshell export, so nothing leaks past this proof.
  # The swap is deliberately subshell-local (SC2030): the lane's own env
  # must not pick it up, so the change dying with this proof's subshell is
  # the point — see the comment above.
  # shellcheck disable=SC2030
  export HOME="$fi_home" MINIMAL_BIN="$fi_home/.local/bin" PATH="$fi_home/.local/bin:$PATH"
  mnl stop --force >/dev/null 2>&1 || true
  fi_sid="$(cd "$fi_seed" && RUST_LOG=info mnl session activate . --no-prompt \
    --name e2e-fresh-ingress --network own_ip --ingress "$fi_hport":8080 \
    2>"$fi_root/activate.err")" || {
    echo "::error::the installed pair failed to activate an own-IP session with an ingress mapping"
    echo "--- activate stderr ---"; cat "$fi_root/activate.err" 2>/dev/null || true
    exit 1
  }
  fi_sid="$(printf '%s\n' "$fi_sid" | tail -n1 | tr -d '\r')"

  # socat carries the in-box responder (a launcher baseline package, at
  # /usr/bin in every box), serving one 200 whose body is the marker; the
  # detach form is the documented one for a listener that must outlive the
  # exec that starts it.
  mnl session exec "$fi_sid" 'test -x /usr/bin/socat' >/dev/null 2>"$fi_root/socat-probe.err" || {
    echo "::error::probing the box for /usr/bin/socat failed (it is a launcher baseline package, so an empty stderr below means the file is not there — anything else is a spawn failure the probe surfaced for free)"
    echo "--- probe stderr ---"; cat "$fi_root/socat-probe.err" 2>/dev/null || true
    exit 1
  }
  mnl session exec "$fi_sid" \
    "body=fi-fresh-install-own-ip; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/http200" \
    >/dev/null 2>"$fi_root/responder.err" || {
    echo "::error::could not write the in-box responder's response"
    cat "$fi_root/responder.err" 2>/dev/null || true
    exit 1
  }
  mnl session exec "$fi_sid" \
    "nohup /usr/bin/socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:\"cat /home/http200\" >/dev/null 2>&1 &" \
    >/dev/null 2>"$fi_root/responder.err" || {
    echo "::error::could not start the in-box responder"
    cat "$fi_root/responder.err" 2>/dev/null || true
    exit 1
  }
  fi_ready=""
  for _ in $(seq 1 40); do
    if [ "$(mnl session exec "$fi_sid" \
      "curl -sS --max-time 5 -o /home/ready.body -w '%{http_code}' http://127.0.0.1:8080/" \
      2>/dev/null || true)" = "200" ]; then
      fi_ready=1; break
    fi
    sleep 0.25
  done
  [ -n "$fi_ready" ] || {
    echo "::error::the in-box responder never answered a direct curl — the publish is not in the picture yet"
    exit 1
  }

  # NET-040 observability: one daemon-log record per exposed mapping, with
  # the host address, the port and the session — and NET-010's address: the
  # record names the box's own granted address, which the host probe below
  # targets. Read it before probing, never assume 127.0.0.1.
  fi_log="$(find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null | sort | tail -n1)"
  fi_rec=""
  for _ in $(seq 1 10); do
    fi_rec="$(grep -h -- 'exposed ingress port on the host loopback' "$fi_log" 2>/dev/null \
      | grep -F '"session":"e2e-fresh-ingress"' | tail -n1)"
    [ -n "$fi_rec" ] && break
    sleep 0.25
  done
  if [ -z "$fi_rec" ]; then
    echo "::error::no expose record in the daemon log names the session"
    echo "--- daemon log (tail) ---"; tail -20 "$fi_log" 2>/dev/null || true
    exit 1
  fi
  fi_host="$(published_loopback_host "$fi_log" e2e-fresh-ingress)"
  case "$fi_rec" in
    *'"host":"'"$fi_host"'"'*"$fi_portpat"*) ;;
    *)
      echo "::error::the expose record does not carry a host address and the published port $fi_hport"
      echo "--- record ---"; printf '%s\n' "$fi_rec"
      exit 1
      ;;
  esac
  case "$fi_host" in
    127.0.64.*)
      ;;
    *)
      echo "::error::the box published at ${fi_host:-<no address in the record>}, which is not an address out of the reserved local range 127.0.64.0/24 — an own-IP box's mapping answers at its own granted address (NET-010), and on this Linux lane the range is always bindable so the 127.0.0.1 interim never stands in for it"
      echo "--- record ---"; printf '%s\n' "$fi_rec"
      exit 1
      ;;
  esac
  echo "daemon log: $fi_rec"

  # NET-040: the mapping answers ON THE HOST loopback, at that address, with
  # the box's own server's response.
  fi_answered=""
  fi_status=""
  for _ in $(seq 1 40); do
    fi_status="$(curl -sS --max-time 5 -o "$fi_root/host.body" -w '%{http_code}' \
      "http://$fi_host:$fi_hport/" 2>/dev/null || true)"
    if [ "$fi_status" = "200" ] && grep -q "fi-fresh-install-own-ip" "$fi_root/host.body" 2>/dev/null; then
      fi_answered=1; break
    fi
    sleep 0.25
  done
  [ -n "$fi_answered" ] || {
    echo "::error::the host loopback never answered at $fi_host:$fi_hport (last status: '${fi_status:-none}')"
    echo "--- host body ---"; cat "$fi_root/host.body" 2>/dev/null || true
    exit 1
  }
  echo "$fi_host:$fi_hport answered the box's own server (200: $(cat "$fi_root/host.body"))"

  mnl session destroy --force "$fi_sid" >/dev/null 2>&1 || true
  mnl stop --force >/dev/null 2>&1 || true
  # The switch goes down with the daemon; wait out the forward it held at the
  # box's address so the package-path half below cannot collide with a
  # lingering bind on the same address if the answerer hands it back out.
  for _ in $(seq 1 20); do
    curl -sS --max-time 2 -o /dev/null "http://$fi_host:$fi_hport/" 2>/dev/null || break
    sleep 0.25
  done

  # The system-package half: the daemon must serve the same mapping when the
  # only switch binary it can find is /usr/bin/gvproxy-min (the nfpm/AUR
  # dest), not the one the installer placed in ~/.local/bin. Gated on what
  # this lane permits — never over an existing binary — and the subshell's
  # EXIT trap (set above) removes the staged one on every path out of the proof.
  if [ -w /usr/bin ] && [ ! -e /usr/bin/gvproxy-min ]; then
    cp "$fi_home/.local/bin/gvproxy-min" /usr/bin/gvproxy-min
    rm -f "$fi_home/.local/bin/gvproxy-min"
    fi_sid2="$(cd "$fi_seed" && RUST_LOG=info mnl session activate . --no-prompt \
      --name e2e-fresh-ingress-pkg --network own_ip --ingress "$fi_hport":8080 \
      2>"$fi_root/activate-pkg.err")" || {
      echo "::error::the daemon did not serve an own-IP box from the package-path switch binary"
      echo "--- activate stderr ---"; cat "$fi_root/activate-pkg.err" 2>/dev/null || true
      exit 1
    }
    fi_sid2="$(printf '%s\n' "$fi_sid2" | tail -n1 | tr -d '\r')"
    mnl session exec "$fi_sid2" \
      "body=fi-fresh-install-pkgpath; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/http200" \
      >/dev/null 2>&1
    mnl session exec "$fi_sid2" \
      "nohup /usr/bin/socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:\"cat /home/http200\" >/dev/null 2>&1 &" \
      >/dev/null 2>&1
    # This box's own address, from its own record — the second daemon may hold
    # the same address as the first (its grant was released at destroy) or a
    # different one; the record says which, the probe does not guess. The log
    # path is re-read: this activate spawned a daemon of its own, and the day
    # may have rolled over to a new file since the first half read it.
    fi_pkg_log=""
    fi_host2=""
    for _ in $(seq 1 10); do
      fi_pkg_log="$(find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null | sort | tail -n1)"
      fi_host2="$(published_loopback_host "$fi_pkg_log" e2e-fresh-ingress-pkg)"
      [ -n "$fi_host2" ] && break
      sleep 0.25
    done
    case "$fi_host2" in
      127.0.64.*) ;;
      *)
        echo "::error::the package-path box published at ${fi_host2:-<no expose record>}, which is not an address out of the reserved local range 127.0.64.0/24 (NET-010)"
        echo "--- activate stderr ---"; cat "$fi_root/activate-pkg.err" 2>/dev/null || true
        exit 1
        ;;
    esac
    fi_answered=""
    for _ in $(seq 1 40); do
      if curl -sS --max-time 5 -o "$fi_root/host-pkg.body" \
          "http://$fi_host2:$fi_hport/" 2>/dev/null \
          && grep -q "fi-fresh-install-pkgpath" "$fi_root/host-pkg.body" 2>/dev/null; then
        fi_answered=1; break
      fi
      sleep 0.25
    done
    [ -n "$fi_answered" ] || {
      echo "::error::the package-path switch never published the mapping at $fi_host2:$fi_hport"
      echo "--- activate stderr ---"; cat "$fi_root/activate-pkg.err" 2>/dev/null || true
      exit 1
    }
    echo "package-path half OK: /usr/bin/gvproxy-min served the same mapping at $fi_host2:$fi_hport ($(cat "$fi_root/host-pkg.body"))"
    mnl session destroy --force "$fi_sid2" >/dev/null 2>&1 || true
  else
    if [ -e /usr/bin/gvproxy-min ]; then
      echo "package-path half SKIPPED (a gvproxy-min is already installed at /usr/bin/gvproxy-min, which this proof never touches)"
    else
      echo "package-path half SKIPPED (/usr/bin is not writable on this lane) — the /usr/bin/gvproxy-min probe order is pinned by the switch crate's resolver tests"
    fi
  fi

  # Leave the lane as it was: the installed daemon stopped, so the next proof
  # auto-respawns the checkout's own pair from the restored PATH.
  mnl stop --force >/dev/null 2>&1 || true
); then
  :
else
  fail
fi
echo "fresh-install loopback publish OK (installed pair, shipped switch, host-loopback answer, logged expose)"
echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# The network postures of a stock install, end to end (the S2 integration
# case). From a REAL scripts/install.sh run into a fresh HOME — the same
# mock-bucket install the loopback-publish proof above uses, minus its
# system-package half — the INSTALLED pair must let a user choose a box's
# network posture from the command line and get exactly what the choice
# says:
#
#   * the chooser is findable: `min session activate --help` carries
#     `--network` with its none|host_ip|own_ip values and `--ingress`
#     (NET-035), the CLI reference documents both (NET-036), and the old
#     hyphenated spellings still parse, each printing a one-line hint
#     naming the current one (NET-037) — `no-net` is driven for real (a
#     box activated through it), `host-net` and `own-ip` at the parser,
#     through an invocation whose only failure is the bogus project path
#     it is given, so acceptance is visible: the hint prints and no clap
#     error does. The current spellings print no hint.
#   * a `--network none` box accepts attach — a REAL pty attach, and the
#     exec probes below which ride the same session channel — and reaches
#     nothing outside itself (NET-038, NET-039): its namespace holds no
#     interface besides `lo` and no default route, and the host's own
#     listener — answering on the host before the probe starts — is
#     refused from inside the box, fast, and a public host is
#     unreachable too. The stock posture (host_ip, the default) completes
#     an outbound request (NET-107).
#   * from the fresh install, `--network own_ip --ingress 8080:8080`
#     answers ON THE HOST at the box's own loopback address with the box's
#     own server's response (NET-040, NET-010) — and that box completes an
#     outbound request through the switch the installer shipped (NET-107's
#     switch half).
#
# Lane gating, decided by where the proof's pieces actually run:
#   * Native Linux only: the install pair lives host-side on a VM lane
#     (the loopback-publish proof's reason). An arch without a release
#     binary for this channel is skipped the same way.
#   * The own-IP half additionally needs a tap (/dev/net/tun), and a host
#     without one cannot come up as an own-IP box no matter what the
#     install ships. The gate holds ONLY that half — help, hints, the
#     none box and the stock posture's reach need no tap — so a tap-less
#     host still proves every other clause and says what it left unrun.
#     The bucket ships the switch only when that half will run; without
#     it the manifest carries no switch row and the install log is
#     asserted to record the skip instead.
#   * When the own-IP half will run, the switch binary the fresh install
#     must ship is $MINVMD_GVPROXY_BIN, the justfile's .scratch/gvproxy,
#     or the pinned fetch — never a skip: a lane that cannot ship a
#     switch cannot prove what this case exists for.
#   * A host whose boxes cannot exec degrades by observed fact (the
#     proxy case's gate): the install, the help, the reference and the
#     hints run without a box; on CI or a VM lane a tripped exec gate
#     fails.
#
# Ordered after the loopback-publish proof for the same reason it is
# ordered after `restart`: the case swaps the driving pair to the
# installed one, so nothing that still shares the lane's session may
# follow before the swap is undone.
proof_network_posture_from_stock_install() {
  local np_arch np_gvproxy np_want_switch
  if [ -n "$E2E_VM" ] || [ "$(uname -s)" != Linux ]; then
    echo "network posture SKIPPED (VM-backed lane: the pair this proof installs lives host-side)"
    return 0
  fi
  case "$(uname -m)" in
    x86_64) np_arch=amd64 ;;
    aarch64|arm64) np_arch=arm64 ;;
    *)
      echo "network posture SKIPPED (no release arch for $(uname -m))"
      return 0
      ;;
  esac
  if [ -c /dev/net/tun ]; then
    np_want_switch=1
  else
    np_want_switch=0
    echo "own-IP half SKIPPED (no /dev/net/tun: an own-IP box cannot open its in-namespace tap; the help, hint, none-box and stock-posture halves still run)"
  fi

  echo "::group::network posture from a stock install (help, hints, none box, own-ip, reach)"

  # Everything the case builds lives under $WORK/posture, so the state
  # dir's teardown covers all of it — no extra bookkeeping.
  local np_root="$WORK/posture"
  local np_home="$np_root/home"
  local np_bucket="$np_root/bucket" np_stubbin="$np_root/stubbin"
  local np_out="$np_root/install.log" np_bucket_host
  np_bucket_host="https://mock.invalid/minimal-posture"
  POSTURE_HELP="$np_root/activate-help.txt"
  POSTURE_HOST_MARKER="posture-host-listener-ok"
  POSTURE_OWNIP_MARKER="posture-ownip-box-ok"
  mkdir -p "$np_home" "$np_bucket/versions/v1" "$np_stubbin"

  # The switch the fresh install will ship — only when the own-IP half
  # will run (see the tap gate above).
  if [ "$np_want_switch" -eq 1 ]; then
    if [ -n "${MINVMD_GVPROXY_BIN:-}" ] && [ -x "$MINVMD_GVPROXY_BIN" ]; then
      np_gvproxy="$MINVMD_GVPROXY_BIN"
    elif [ -x "$ROOT/.scratch/gvproxy" ]; then
      np_gvproxy="$ROOT/.scratch/gvproxy"
    else
      if ! "$ROOT/scripts/fetch-gvproxy.sh" "$np_root/gvproxy" \
        >"$np_root/fetch-gvproxy.out" 2>&1; then
        echo "::error::could not fetch the pinned gvproxy the fresh install must ship"
        cat "$np_root/fetch-gvproxy.out" 2>/dev/null || true
        fail
      fi
      np_gvproxy="$np_root/gvproxy"
    fi
    cp "$np_gvproxy" "$np_bucket/versions/v1/gvproxy-min-linux-$np_arch"
  fi
  cp "$(command -v min)" "$np_bucket/versions/v1/minimal-linux-$np_arch"
  cp "$(command -v minimald)" "$np_bucket/versions/v1/minimald-linux-$np_arch"
  printf 'v1\n' >"$np_bucket/stable"
  np_sha() { sha256sum "$1" | awk '{print $1}'; }
  local np_h_minimald np_h_minimal
  np_h_minimald="$(np_sha "$np_bucket/versions/v1/minimald-linux-$np_arch")"
  np_h_minimal="$(np_sha "$np_bucket/versions/v1/minimal-linux-$np_arch")"
  {
    printf '# format: 1\n'
    printf '# component   os      arch    version   sha256   kind   dest                 src\n'
    printf '\n'
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
      minimald linux "$np_arch" v1 "$np_h_minimald" file bin/minimald \
      "versions/v1/minimald-linux-$np_arch"
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
      minimal linux "$np_arch" v1 "$np_h_minimal" file bin/min \
      "versions/v1/minimal-linux-$np_arch"
    if [ "$np_want_switch" -eq 1 ]; then
      local np_h_gvmin
      np_h_gvmin="$(np_sha "$np_bucket/versions/v1/gvproxy-min-linux-$np_arch")"
      printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
        gvproxy-min linux "$np_arch" v1 "$np_h_gvmin" file bin/gvproxy-min \
        "versions/v1/gvproxy-min-linux-$np_arch"
    fi
  } >"$np_bucket/versions/v1/components"

  # The installer's curl, mapped to the mock bucket (the loopback-publish
  # proof's stub: a fake curl, so the real installer runs unmodified and
  # its HTTPS flags are accepted and ignored).
  cat >"$np_stubbin/curl" <<STUB
#!/bin/sh
# Fake curl: maps the mock bucket host to the local dir this proof built —
# the same trick install_test.sh uses, so the real installer runs unmodified;
# its own HTTPS/TLS flags are accepted and ignored.
out= url=
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    https://*|http://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
[ -n "\$url" ] || { echo "stub curl: no url" >&2; exit 2; }
rel="\${url#$np_bucket_host/}"
src="$np_bucket/\$rel"
[ -f "\$src" ] || { echo "stub curl: 404 \$url" >&2; exit 22; }
if [ -n "\$out" ]; then cp "\$src" "\$out"; else cat "\$src"; fi
STUB
  chmod +x "$np_stubbin/curl"
  # Force the wget path off so the downloader selection is deterministic.
  cat >"$np_stubbin/wget" <<'STUB'
#!/bin/sh
echo "stub wget should not be used here" >&2
exit 1
STUB
  chmod +x "$np_stubbin/wget"

  # The lane daemon this run was driving, resolved before HOME and PATH
  # swap to the installed pair (the AppArmor restore below needs it).
  local np_lane_minimald
  np_lane_minimald="$(command -v minimald 2>/dev/null || true)"

  if (
    # ---- the fresh install --------------------------------------------------
    # The $PATH read below (SC2031) is meant to see the lane's PATH: the
    # loopback-publish proof's subshell swap never reaches this proof, so
    # nothing is lost.
    # shellcheck disable=SC2031
    HOME="$np_home" MINIMAL_BIN="$np_home/.local/bin" \
      PATH="$np_stubbin:$PATH" \
      MINIMAL_OVERRIDE_INSTALLER_BUCKET="$np_bucket_host" \
      sh "$ROOT/scripts/install.sh" >"$np_out" 2>&1 || {
      echo "::error::the fresh install failed"
      echo "--- install output ---"
      cat "$np_out" 2>/dev/null || true
      exit 1
    }
    echo "step: sh scripts/install.sh (fresh HOME, mock bucket) → exit 0"
    if [ "$np_want_switch" -eq 1 ]; then
      grep -qE 'switch-binary +verified +[^ ]*/bin/gvproxy-min' "$np_out" || {
        echo "::error::the install output does not name the switch binary it verified"
        echo "--- install output (tail) ---"
        tail -25 "$np_out" 2>/dev/null || true
        exit 1
      }
    else
      grep -qE 'switch-binary +skipped' "$np_out" || {
        echo "::error::the install output does not record the switch-binary skip the manifest without the switch row made"
        echo "--- install output (tail) ---"
        tail -25 "$np_out" 2>/dev/null || true
        exit 1
      }
    fi
    [ -x "$np_home/.local/bin/min" ] && [ -x "$np_home/.local/bin/minimald" ] || {
      echo "::error::the fresh install did not ship an executable min/minimald pair"
      tail -25 "$np_out" 2>/dev/null || true
      exit 1
    }
    if [ "$np_want_switch" -eq 1 ] && [ ! -x "$np_home/.local/bin/gvproxy-min" ]; then
      echo "::error::the fresh install did not ship an executable gvproxy-min"
      exit 1
    fi
    echo "install log: $(grep -E 'switch-binary +(verified|skipped)' "$np_out" | tail -n1)"

    # ---- AppArmor, restricted hosts (the loopback-publish proof's block) ----
    local np_restore_profile=0
    if [ "$(cat /proc/sys/kernel/apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = 1 ]; then
      local np_attach_args=()
      local np_p
      for np_p in "$np_home/.local/bin/minimald" "$np_lane_minimald"; do
        if [ -n "$np_p" ] && [ -e "$np_p" ]; then
          np_attach_args+=(--path "$np_p")
        fi
      done
      if ! sudo -n "$ROOT/scripts/install-apparmor-profile.sh" "${np_attach_args[@]}"; then
        echo "::error::this host restricts unprivileged user namespaces and the minimald AppArmor profile could not be attached to the installed pair, so its session sandbox cannot start (see docs/reference/linux-host-setup.md)"
        exit 1
      fi
      np_restore_profile=1
      echo "restricted host: minimald AppArmor profile attached to the installed pair ($np_home/.local/bin/minimald)"
    fi

    # One EXIT trap for the whole subshell: every path out of it — the
    # early exits above included — undoes what the proof staged on the
    # host, and a nonzero exit carries the case's diagnostics: the install
    # log, the help capture and the installed daemon's log tail (rc 3 is
    # the exec-gate skip, not a failure).
    # shellcheck disable=SC2317,SC2329
    np_cleanup() {
      local np_rc=$?
      if [ "$np_rc" -ne 0 ] && [ "$np_rc" -ne 3 ]; then
        echo "--- install log (tail) ---"
        tail -30 "$np_out" 2>/dev/null || true
        echo "--- min session activate --help (captured) ---"
        cat "$POSTURE_HELP" 2>/dev/null || true
        echo "--- installed daemon log (tail) ---"
        find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null \
          | sort | tail -n1 | xargs -r tail -30 2>/dev/null || true
      fi
      if [ -n "${POSTURE_HOST_PID:-}" ]; then
        kill "$POSTURE_HOST_PID" 2>/dev/null || true
      fi
      if [ "${np_restore_profile:-0}" = 1 ] && [ -n "$np_lane_minimald" ]; then
        sudo -n "$ROOT/scripts/install-apparmor-profile.sh" \
          --path "$np_lane_minimald" >/dev/null 2>&1 \
          || echo "::warning::could not restore the minimald AppArmor profile's attachment set (sudo -n failed)" >&2
      fi
      trap - EXIT
    }
    trap np_cleanup EXIT

    # ---- drive the INSTALLED pair -------------------------------------------
    # As in the loopback-publish proof, the swap is deliberately subshell-local
    # (SC2030/SC2031): the lane's env must stay as it was, and the $PATH read
    # is the lane's PATH — no earlier proof's swap reaches here.
    # shellcheck disable=SC2030,SC2031
    export HOME="$np_home" MINIMAL_BIN="$np_home/.local/bin" PATH="$np_home/.local/bin:$PATH"
    mnl stop --force >/dev/null 2>&1 || true

    # The daemon the case drives autospawns on the FIRST daemon-touching
    # call, so that call alone carries the noisier filter: the daemon keeps
    # INFO records (the expose record the own-IP half prints below) while
    # the CLI's own stdout stays quiet for the session-id extraction.
    # Command-local, never exported.
    RUST_LOG=info mnl ls >/dev/null 2>"$np_root/autospawn.err" || {
      echo "::error::the installed pair's daemon did not come up"
      echo "--- stderr ---"
      cat "$np_root/autospawn.err" 2>/dev/null || true
      exit 1
    }
    echo "step: RUST_LOG=info min ls (autospawns the installed daemon) → exit 0"

    # ---- NET-035: the chooser is in `--help` --------------------------------
    mnl session activate --help >"$POSTURE_HELP" 2>"$np_root/help.err"
    local np_help_rc=$?
    echo "step: min session activate --help → exit $np_help_rc (captured at $POSTURE_HELP)"
    if [ "$np_help_rc" -ne 0 ]; then
      echo "::error::'min session activate --help' failed"
      echo "--- stderr ---"
      cat "$np_root/help.err" 2>/dev/null || true
      exit 1
    fi
    if ! grep -q -- '--network' "$POSTURE_HELP" \
      || ! grep -q -- 'none|host_ip|own_ip' "$POSTURE_HELP" \
      || ! grep -q -- '--ingress' "$POSTURE_HELP" \
      || ! grep -q -- 'EXT:INT' "$POSTURE_HELP" \
      || ! grep -q -- 'no-net' "$POSTURE_HELP"; then
      echo "::error::'min session activate --help' does not carry the network posture flags (NET-035): --network with its none|host_ip|own_ip values, --ingress, and the legacy spellings named"
      exit 1
    fi
    echo "help carries --network <none|host_ip|own_ip>, --ingress <EXT:INT[/PROTO]>, and the legacy spellings"

    # ---- NET-036: the reference documents the chooser -----------------------
    if ! grep -q -- '--network <none' "$ROOT/docs/reference/cli-min.md" \
      || ! grep -q -- '--ingress <EXT:INT' "$ROOT/docs/reference/cli-min.md" \
      || ! grep -Eq 'no-net.*host-net.*own-ip' "$ROOT/docs/reference/cli-min.md"; then
      echo "::error::the CLI reference (docs/reference/cli-min.md) does not document --network and --ingress with the legacy spellings (NET-036)"
      grep -n -- '--network' "$ROOT/docs/reference/cli-min.md" | head -5 || true
      exit 1
    fi
    echo "step: reference check (docs/reference/cli-min.md carries --network, --ingress, legacy spellings) → exit 0"

    # ---- NET-037: the legacy spellings parse, each with a rename hint -------
    # `no-net` is driven for real: a box activated THROUGH the legacy
    # spelling is the acceptance the requirement names, and its stderr must
    # carry the hint. `host-net` and `own-ip` are driven at the parser,
    # through an invocation whose only failure is the bogus project path it
    # is given: the hint prints while the arguments parse, before any path
    # is resolved, and a refusal to accept the spelling would be a clap
    # error instead.
    local np_hint_seed="$np_root/seeds/hint" np_hint_err="$np_root/hint.err"
    local np_hint_sid np_hint_rc
    mkdir -p "$np_hint_seed"
    hook_seed_preamble >"$np_hint_seed/minimal.toml"
    mkdir "$np_hint_seed/.git"
    np_hint_sid="$(cd "$np_hint_seed" && mnl session activate . --no-prompt \
      --name e2e-posture-hint --network no-net 2>"$np_hint_err")"
    np_hint_rc=$?
    echo "step: min session activate --network no-net (a real activation through the legacy spelling) → exit $np_hint_rc"
    if [ "$np_hint_rc" -ne 0 ]; then
      echo "::error::the legacy spelling --network no-net did not activate a session (NET-037)"
      echo "--- stderr ---"
      cat "$np_hint_err" 2>/dev/null || true
      exit 1
    fi
    np_hint_sid="$(printf '%s\n' "$np_hint_sid" | tail -n1 | tr -d '\r')"
    case "$(cat "$np_hint_err")" in
      *"note: --network no-net"*"--network none"*) ;;
      *)
        echo "::error::the legacy spelling --network no-net did not print the rename hint naming the current spelling (NET-037)"
        echo "--- stderr ---"
        cat "$np_hint_err" 2>/dev/null || true
        exit 1
        ;;
    esac
    echo "hint: $(head -n1 "$np_hint_err")"
    mnl ls --raw 2>/dev/null | grep -Fqx "$np_hint_sid" || {
      echo "::error::the session activated through --network no-net is not listed"
      exit 1
    }
    echo "step: min ls --raw lists the legacy-spelling session → exit 0"
    mnl session destroy --force "$np_hint_sid" >/dev/null 2>&1 || true
    echo "step: min session destroy --force (the hint probe's throwaway) → exit 0"

    local np_legacy np_probe_err np_probe_rc
    for np_legacy in host-net own-ip; do
      # The path below must NOT exist: the activation's only failure is the
      # path resolution, after the arguments (the hint) have parsed.
      np_probe_err="$np_root/legacy-$np_legacy.err"
      mnl session activate "$np_root/seeds/no-such-dir-$np_legacy" \
        --network "$np_legacy" >/dev/null 2>"$np_probe_err"
      np_probe_rc=$?
      echo "step: min session activate <absent-dir> --network $np_legacy → exit $np_probe_rc (parser-level probe)"
      case "$(cat "$np_probe_err")" in
        *"note: --network $np_legacy"*) ;;
        *)
          echo "::error::the legacy spelling --network $np_legacy did not print the rename hint (NET-037)"
          echo "--- stderr ---"
          cat "$np_probe_err" 2>/dev/null || true
          exit 1
          ;;
      esac
      case "$(cat "$np_probe_err")" in
        *"invalid value"*)
          echo "::error::the legacy spelling --network $np_legacy was refused by the parser (NET-037)"
          echo "--- stderr ---"
          cat "$np_probe_err" 2>/dev/null || true
          exit 1
          ;;
      esac
      echo "  hint: $(head -n1 "$np_probe_err")"
    done

    # ---- the stock posture reaches the network (NET-107) ---------------------
    # A default host-address box, activated explicitly with the current
    # spelling. Its exec doubles as the case's capability gate: a host that
    # cannot run a box's sandbox can run nothing below, and the gate
    # degrades by observed fact — the proxy case's rule.
    local np_hostip_seed="$np_root/seeds/hostip" np_hostip_err="$np_root/hostip.err"
    local np_host_sid
    mkdir -p "$np_hostip_seed"
    hook_seed_preamble >"$np_hostip_seed/minimal.toml"
    mkdir "$np_hostip_seed/.git"
    np_host_sid="$(cd "$np_hostip_seed" && mnl session activate . --no-prompt \
      --name e2e-posture-hostip --network host_ip 2>"$np_hostip_err")" || {
      echo "::error::the stock posture (--network host_ip) did not activate"
      echo "--- stderr ---"
      cat "$np_hostip_err" 2>/dev/null || true
      exit 1
    }
    np_host_sid="$(printf '%s\n' "$np_host_sid" | tail -n1 | tr -d '\r')"
    echo "step: min session activate --network host_ip (the stock posture) → exit 0, session $np_host_sid"
    if grep -q -- 'note: --network' "$np_hostip_err"; then
      echo "::error::the current spelling --network host_ip printed a legacy hint"
      echo "--- stderr ---"
      cat "$np_hostip_err" 2>/dev/null || true
      exit 1
    fi
    echo "policy of the stock posture box:"
    mnl session policy "$np_host_sid" 2>"$np_root/hostip-policy.err" | sed 's/^/  /' || {
      echo "::error::'min session policy' failed for the stock posture box"
      cat "$np_root/hostip-policy.err" 2>/dev/null || true
      exit 1
    }
    if ! mnl session exec "$np_host_sid" 'true' >"$np_root/execgate.err" 2>&1 \
      && ! { sleep 1; mnl session exec "$np_host_sid" 'true' >"$np_root/execgate.err" 2>&1; }; then
      if [ -z "${CI:-}" ] && [ -z "$E2E_VM" ]; then
        echo "::warning::the box halves SKIPPED — this host cannot run a session sandbox"
        echo "  (exec: $(head -n1 "$np_root/execgate.err" 2>/dev/null || true))"
        echo "  asserted above: the install, the help capture, the reference and the three legacy hints."
        echo "  the postures' in-box behavior needs a host whose boxes can run; on CI or a VM lane this gate fails instead"
        mnl session destroy --force "$np_host_sid" >/dev/null 2>&1 || true
        mnl stop --force >/dev/null 2>&1 || true
        exit 3
      fi
      echo "::error::this lane cannot run a session sandbox, so no box can be driven: the posture behavior cannot be asserted"
      echo "  (exec: $(head -n1 "$np_root/execgate.err" 2>/dev/null || true))"
      exit 1
    fi
    posture_outbound "$np_host_sid" "the stock posture (host_ip)"
    mnl session destroy --force "$np_host_sid" >/dev/null 2>&1 || true
    echo "step: min session destroy --force (the stock posture's box) → exit 0"

    # ---- the none box: accepts attach, reaches nothing (NET-038, NET-039) ---
    local np_none_seed="$np_root/seeds/none" np_none_err="$np_root/none.err"
    local np_none_sid
    mkdir -p "$np_none_seed"
    hook_seed_preamble >"$np_none_seed/minimal.toml"
    mkdir "$np_none_seed/.git"
    np_none_sid="$(cd "$np_none_seed" && mnl session activate . --no-prompt \
      --name e2e-posture-none --network none 2>"$np_none_err")" || {
      echo "::error::the none posture did not activate"
      echo "--- stderr ---"
      cat "$np_none_err" 2>/dev/null || true
      exit 1
    }
    np_none_sid="$(printf '%s\n' "$np_none_sid" | tail -n1 | tr -d '\r')"
    echo "step: min session activate --network none → exit 0, session $np_none_sid"
    if grep -q -- 'note: --network' "$np_none_err"; then
      echo "::error::the current spelling --network none printed a legacy hint"
      echo "--- stderr ---"
      cat "$np_none_err" 2>/dev/null || true
      exit 1
    fi
    echo "policy of the none box:"
    mnl session policy "$np_none_sid" 2>/dev/null | sed 's/^/  /' || true

    # The namespace's shape: one interface (lo), no default route.
    posture_probe "$np_none_sid" 'echo ---DEV---; cat /proc/net/dev; echo ---ROUTE---; cat /proc/net/route'
    if [ "$POSTURE_EXEC_RC" -ne 0 ]; then
      echo "::error::the none box's namespace probe failed"
      echo "--- stderr ---"
      cat "$WORK/posture-probe.err" 2>/dev/null || true
      exit 1
    fi
    local np_dev np_route np_iface_count
    np_dev="$(printf '%s\n' "$POSTURE_EXEC_OUT" | np_section DEV)"
    np_route="$(printf '%s\n' "$POSTURE_EXEC_OUT" | np_section ROUTE)"
    np_iface_count="$(printf '%s\n' "$np_dev" | grep -c ':')"
    if [ "$np_iface_count" -ne 1 ] \
      || ! printf '%s\n' "$np_dev" | grep -q '^[[:space:]]*lo:'; then
      echo "::error::the none box's namespace does not hold exactly the loopback interface (NET-038)"
      echo "--- probed facts ---"
      printf '%s\n' "$POSTURE_EXEC_OUT"
      exit 1
    fi
    if printf '%s\n' "$np_route" | awk 'NR > 1 && $2 == "00000000" { found = 1 } END { exit !found }'; then
      echo "::error::the none box's namespace has a default route (NET-038)"
      echo "--- probed facts ---"
      printf '%s\n' "$POSTURE_EXEC_OUT"
      exit 1
    fi
    echo "the none box's namespace: one interface (lo), no default route"

    # The host-side listener the reach probes measure against: a plain
    # python3 http.server bound to the host's loopback (the proxy case's
    # pattern). The none box's 127.0.0.1 is its OWN loopback — the same
    # literal address, a different namespace — so "the host answers, the
    # box cannot reach it" is the isolation fact, not an outage.
    POSTURE_HOST_DIR="$np_root/host-listener"
    mkdir -p "$POSTURE_HOST_DIR"
    printf '%s\n' "$POSTURE_HOST_MARKER" >"$POSTURE_HOST_DIR/marker"
    local np_hport="" np_cand
    for np_cand in 18085 18086 18087 18088; do
      if np_port_free "$np_cand"; then
        np_hport="$np_cand"
        break
      fi
    done
    if [ -z "$np_hport" ]; then
      echo "::error::no free candidate port among 18085-18088 for the host-side listener"
      exit 1
    fi
    (cd "$POSTURE_HOST_DIR" && exec python3 -m http.server "$np_hport" --bind 127.0.0.1) \
      >/dev/null 2>"$np_root/host-listener.err" &
    POSTURE_HOST_PID=$!
    local np_up=""
    for _ in $(seq 1 40); do
      if [ "$(curl -sS --max-time 5 -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:$np_hport/marker" 2>/dev/null || true)" = "200" ]; then
        np_up=1
        break
      fi
      sleep 0.25
    done
    if [ -z "$np_up" ]; then
      echo "::error::the host-side listener never answered on 127.0.0.1:$np_hport"
      echo "--- listener stderr ---"
      cat "$np_root/host-listener.err" 2>/dev/null || true
      exit 1
    fi
    echo "step: python3 -m http.server $np_hport --bind 127.0.0.1 (host-side) → exit 0, answers 200"

    # The box cannot reach it: refused, fast — never a timeout.
    local np_t0 np_t1
    np_t0=$(now_ms)
    posture_probe "$np_none_sid" "curl -sS --max-time 5 -o /dev/null http://127.0.0.1:$np_hport/"
    np_t1=$(now_ms)
    if [ "$POSTURE_EXEC_RC" -eq 0 ]; then
      echo "::error::the none box reached the host's listener at 127.0.0.1:$np_hport — its namespace is not empty (NET-038)"
      exit 1
    fi
    if [ $((np_t1 - np_t0)) -ge 4000 ]; then
      echo "::error::the none box's refused connection took $((np_t1 - np_t0))ms — a refusal must be fast, not a timeout (NET-038)"
      echo "--- curl stderr ---"
      cat "$WORK/posture-probe.err" 2>/dev/null || true
      exit 1
    fi
    echo "the none box cannot reach the host's listener (exit $POSTURE_EXEC_RC in $((np_t1 - np_t0))ms: $(head -n1 "$WORK/posture-probe.err" 2>/dev/null || true))"

    # ...and a public host is unreachable too.
    np_t0=$(now_ms)
    posture_probe "$np_none_sid" "curl -sS --max-time 8 -o /dev/null https://example.com"
    np_t1=$(now_ms)
    if [ "$POSTURE_EXEC_RC" -eq 0 ]; then
      echo "::error::the none box completed an outbound request to https://example.com (NET-038)"
      exit 1
    fi
    echo "the none box cannot reach the internet (exit $POSTURE_EXEC_RC in $((np_t1 - np_t0))ms: $(head -n1 "$WORK/posture-probe.err" 2>/dev/null || true))"

    # The attach: a REAL pty attach to the none box (the sandbox case's
    # driver), answered with the detach lane so the session stays for its
    # destroy below. The marker the typed command prints is the proof the
    # attach reached the box.
    local np_attach_out
    # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
    np_attach_out="$(E2E_PTY_COMMANDS='echo POSTURE_NONE_ATTACH_OK
exit' E2E_PTY_ANSWER=keep python3 "$ROOT/scripts/e2e-attach-pty.py" - \
      min ${E2E_MINIMAL_ARGS:-} session attach "$np_none_sid" \
      2>"$np_root/none-attach.err")" || {
      echo "::error::the pty attach to the none box failed (NET-039)"
      echo "--- transcript ---"
      printf '%s\n' "$np_attach_out"
      echo "--- stderr ---"
      cat "$np_root/none-attach.err" 2>/dev/null || true
      exit 1
    }
    echo "step: pty attach to the none box → exit 0"
    if [[ "$np_attach_out" != *POSTURE_NONE_ATTACH_OK* ]]; then
      echo "::error::the none box did not answer through the attached terminal (NET-039)"
      echo "--- transcript ---"
      printf '%s\n' "$np_attach_out"
      exit 1
    fi
    echo "attach: POSTURE_NONE_ATTACH_OK came back through the attached terminal"
    mnl session destroy --force "$np_none_sid" >/dev/null 2>&1 || true
    echo "step: min session destroy --force (the none box) → exit 0"

    # ---- the own-IP posture: publish on the host loopback, reach out --------
    # The host PORT is claimed the loopback-publish proof's way (8080, the
    # 18082 fallback when 8080 is taken): the box publishes at its own granted
    # address, and this guards the interim at 127.0.0.1 a box with no grant of
    # its own would publish on. The ADDRESS is read from the expose record
    # below, never assumed.
    if [ "$np_want_switch" -eq 1 ]; then
      local np_hport2=8080
      if curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:$np_hport2/" 2>/dev/null; then
        if curl -sS --max-time 2 -o /dev/null "http://127.0.0.1:18082/" 2>/dev/null; then
          echo "::error::both 127.0.0.1:8080 and the fallback 18082 already answer on this host; the own-IP half needs one of them free"
          exit 1
        fi
        np_hport2=18082
        echo "127.0.0.1:8080 is already answering on this host — publishing the mapping on the fallback port $np_hport2 instead (the box still serves its internal 8080)"
      fi
      local np_ownip_seed="$np_root/seeds/ownip" np_own_err="$np_root/ownip-activate.err"
      local np_own_sid
      mkdir -p "$np_ownip_seed"
      hook_seed_preamble >"$np_ownip_seed/minimal.toml"
      mkdir "$np_ownip_seed/.git"
      np_own_sid="$(cd "$np_ownip_seed" && mnl session activate . --no-prompt \
        --name e2e-posture-ownip --network own_ip --ingress "$np_hport2":8080 \
        2>"$np_own_err")" || {
        echo "::error::the installed pair failed to activate an own-IP session with an ingress mapping"
        echo "--- stderr ---"
        cat "$np_own_err" 2>/dev/null || true
        exit 1
      }
      np_own_sid="$(printf '%s\n' "$np_own_sid" | tail -n1 | tr -d '\r')"
      echo "step: min session activate --network own_ip --ingress $np_hport2:8080 → exit 0, session $np_own_sid"
      if grep -q -- 'note: --network' "$np_own_err"; then
        echo "::error::the current spelling --network own_ip printed a legacy hint"
        echo "--- stderr ---"
        cat "$np_own_err" 2>/dev/null || true
        exit 1
      fi
      # socat carries the in-box responder (a launcher baseline package, at
      # /usr/bin in every box), serving one 200 whose body is the marker;
      # the loopback-publish proof's detach form, verbatim.
      posture_probe_quiet "$np_own_sid" 'test -x /usr/bin/socat' || {
        echo "::error::probing the box for /usr/bin/socat failed (it is a launcher baseline package — an empty stderr below means the file is not there)"
        echo "--- probe stderr ---"
        cat "$WORK/posture-probe.err" 2>/dev/null || true
        exit 1
      }
      posture_probe "$np_own_sid" \
        "body=$POSTURE_OWNIP_MARKER; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/http200"
      if [ "$POSTURE_EXEC_RC" -ne 0 ]; then
        echo "::error::could not write the in-box responder's response"
        echo "--- stderr ---"
        cat "$WORK/posture-probe.err" 2>/dev/null || true
        exit 1
      fi
      posture_probe "$np_own_sid" \
        "nohup /usr/bin/socat TCP-LISTEN:8080,reuseaddr,fork SYSTEM:\"cat /home/http200\" >/dev/null 2>&1 &"
      if [ "$POSTURE_EXEC_RC" -ne 0 ]; then
        echo "::error::could not start the in-box responder"
        echo "--- stderr ---"
        cat "$WORK/posture-probe.err" 2>/dev/null || true
        exit 1
      fi
      local np_ready=""
      for _ in $(seq 1 40); do
        if [ "$(mnl session exec "$np_own_sid" \
          "curl -sS --max-time 5 -o /home/ready.body -w '%{http_code}' http://127.0.0.1:8080/" \
          2>/dev/null || true)" = "200" ]; then
          np_ready=1
          break
        fi
        sleep 0.25
      done
      if [ -z "$np_ready" ]; then
        echo "::error::the in-box responder never answered a direct curl — the publish is not in the picture yet"
        exit 1
      fi
      echo "the box answers its own ingress mapping at 127.0.0.1:8080"
      # The box's published host address, from its expose record (NET-010): an
      # own-IP box publishes at its own granted address out of the reserved
      # local range, so the host probe targets the record's address — never a
      # fixed 127.0.0.1.
      local np_daemon_log np_expose np_host
      np_daemon_log="$(find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null | sort | tail -n1)"
      np_host=""
      for _ in $(seq 1 10); do
        np_host="$(published_loopback_host "$np_daemon_log" e2e-posture-ownip)"
        [ -n "$np_host" ] && break
        sleep 0.25
      done
      case "$np_host" in
        127.0.64.*) ;;
        *)
          echo "::error::the own-IP box published at ${np_host:-<no expose record>}, which is not an address out of the reserved local range 127.0.64.0/24 (NET-010)"
          echo "--- daemon log (tail) ---"
          tail -20 "$np_daemon_log" 2>/dev/null || true
          exit 1
          ;;
      esac
      local np_status
      np_status="$(curl -sS --max-time 5 -o "$np_root/host-answer.body" -w '%{http_code}' \
        "http://$np_host:$np_hport2/" 2>"$np_root/host-answer.err" || true)"
      if [ "$np_status" != "200" ] \
        || ! grep -Fq "$POSTURE_OWNIP_MARKER" "$np_root/host-answer.body" 2>/dev/null; then
        echo "::error::the fresh install's own-IP ingress did not answer on the host loopback at $np_host:$np_hport2 (NET-040)"
        echo "  status: $np_status, body: $(cat "$np_root/host-answer.body" 2>/dev/null || true)"
        echo "--- curl stderr ---"
        cat "$np_root/host-answer.err" 2>/dev/null || true
        exit 1
      fi
      echo "step: host curl http://$np_host:$np_hport2/ → 200, body carries the box's marker (NET-040)"

      # Observability, not an assertion: the loopback-publish proof owns
      # the expose record's assert. Print the record the address above came
      # from.
      local np_expose=""
      for _ in $(seq 1 10); do
        np_expose="$(grep -h -- 'exposed ingress port on the host loopback' "$np_daemon_log" 2>/dev/null \
          | grep -F '"session":"e2e-posture-ownip"' | tail -n1)"
        if [ -n "$np_expose" ]; then
          break
        fi
        sleep 0.25
      done
      if [ -n "$np_expose" ]; then
        echo "daemon log: $np_expose"
      else
        echo "daemon log: (no expose record found — the host answer above is the assertion)"
      fi
      echo "policy of the own-IP box:"
      mnl session policy "$np_own_sid" 2>/dev/null | sed 's/^/  /' || true
      posture_outbound "$np_own_sid" "the own-IP posture (switch lane)"
      mnl session destroy --force "$np_own_sid" >/dev/null 2>&1 || true
      mnl stop --force >/dev/null 2>&1 || true
      for _ in $(seq 1 20); do
        curl -sS --max-time 2 -o /dev/null "http://$np_host:$np_hport2/" 2>/dev/null || break
        sleep 0.25
      done
    else
      echo "own-IP half SKIPPED (no /dev/net/tun: the fresh install ships no switch and the half is gated on the tap — see the skip note at the top)"
    fi

    # Leave the lane as it was: the installed daemon stopped, so the next
    # proof auto-respawns the checkout's own pair from the restored PATH.
    mnl stop --force >/dev/null 2>&1 || true
  ); then
    :
  else
    local np_rc=$?
    if [ "$np_rc" -eq 3 ]; then
      echo "network posture from a stock install SKIPPED (this host cannot run a session sandbox; the install, help, reference and hint halves above still ran)"
      echo "::endgroup::"
      return 0
    fi
    fail
  fi
  echo "network posture from a stock install OK (chooser in help+reference+hints, none box isolated, own-ip answered on the host, live postures reached the network)"
  echo "::endgroup::"
}

# The posture case's own helpers. posture_probe drives one `min session
# exec` and prints the command, its exit status and the captured output
# (the case's observability contract), leaving them in POSTURE_EXEC_RC and
# POSTURE_EXEC_OUT; posture_probe_quiet is the ready-loop variant (status
# only); posture_outbound is the tolerant outbound probe (the
# session_outbound_request proof's shape); np_section and np_port_free are
# the section splitter and the bind-probe the reach probes need.
posture_probe() {
  local np_sid="$1" np_cmd="$2"
  POSTURE_EXEC_OUT="$(mnl session exec "$np_sid" "$np_cmd" 2>"$WORK/posture-probe.err")"
  POSTURE_EXEC_RC=$?
  echo "exec: $np_cmd"
  echo "  exit: $POSTURE_EXEC_RC"
  if [ -n "$POSTURE_EXEC_OUT" ]; then
    printf '%s\n' "$POSTURE_EXEC_OUT" | sed 's/^/  | /'
  fi
}
posture_probe_quiet() {
  POSTURE_EXEC_OUT="$(mnl session exec "$1" "$2" 2>"$WORK/posture-probe.err")"
  POSTURE_EXEC_RC=$?
  [ "$POSTURE_EXEC_RC" -eq 0 ]
}
posture_outbound() {
  local np_sid="$1" np_label="$2"
  local np_h np_t np_status np_out np_ok=0 np_failed=""
  for np_h in example.com example.org; do
    np_status=0
    np_out=""
    for np_t in 1 2 3; do
      # The request runs INSIDE the box (NET-107: from inside the session).
      np_out="$(mnl session exec "$np_sid" \
        "curl -sS -o /dev/null -w 'HTTP:%{http_code}' --max-time 30 https://$np_h" \
        2>"$WORK/posture-outbound.err")"
      np_status=$?
      echo "exec: curl -sS https://$np_h (from inside $np_label, attempt $np_t) → exit $np_status (got '${np_out:-<none>}')"
      if [ "$np_status" -eq 0 ] && [ "$np_out" = "HTTP:200" ]; then
        break
      fi
      if [ "$np_t" -lt 3 ]; then
        echo "  retrying in $((np_t * 3))s"
        sleep "$((np_t * 3))"
      fi
    done
    if [ "$np_status" -eq 0 ] && [ "$np_out" = "HTTP:200" ]; then
      np_ok=$((np_ok + 1))
    else
      np_failed="$np_failed https://$np_h"
      # Warned, not failed: the other host answering proves the box's
      # egress, which makes this that endpoint's problem. Surfaced, so a
      # partial fault is visible.
      echo "::warning::outbound from $np_label to https://$np_h failed all 3 attempts (exec status $np_status, got '${np_out:-<none>}'); not fatal while the other host still proves the box reaches the network."
      cat "$WORK/posture-outbound.err" 2>/dev/null || true
    fi
  done
  if [ "$np_ok" -eq 0 ]; then
    echo "::error::$np_label completed an outbound request against no host (${np_failed}) — the box has no working egress (NET-107)"
    exit 1
  fi
}
np_section() {
  awk -v want="---$1---" '
    $0 == want   { grab = 1; next }
    /^---.*---$/ { grab = 0 }
    grab         { print }
  '
}
np_port_free() {
  python3 -c 'import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
s.close()' "$1"
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
    printf '\n[tasks.e2e-envprint]\nexec = "printenv E2E_INHERIT_MARKER"\nenv_vars.E2E_INHERIT_MARKER = { inherit = true }\n'
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

  # env_vars inherit crosses the VM boundary: the client reads the value out
  # of the invoking shell and the task's `printenv` sees it inside the
  # session. The var is project-origin, so it must be allow-listed first.
  # The export lives in THIS shell — the invoking shell the client resolves
  # against — not in the run's subshell, where it would reach `min` just the
  # same but read as an accident (SC2030).
  mkdir -p "$XDG_CONFIG_HOME/minimal"
  printf '[vars]\nallow = ["E2E_INHERIT_MARKER"]\n' > "$XDG_CONFIG_HOME/minimal/user_policy.toml"
  export E2E_INHERIT_MARKER=hello-from-the-host
  env_out="$(cd "$TASK_SEED_DIR" && mnl task run e2e-envprint 2>"$WORK/env-inherit.err")"
  rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "::error::'min task run e2e-envprint' with inherited var exited $rc (expected 0)"
    echo "--- task stderr ---"; cat "$WORK/env-inherit.err" 2>/dev/null || true
    fail
  fi
  if [[ "$env_out" != *hello-from-the-host* ]]; then
    echo "::error::inherited env var did not reach the task, got '$env_out'"
    fail
  fi
  echo "env_vars inherit: value crossed the VM boundary OK"

  # An inherited var that is not set in the invoking shell is a client-side
  # error naming the var, before any session is composed.
  unset E2E_INHERIT_MARKER
  (cd "$TASK_SEED_DIR" && mnl task run e2e-envprint >/dev/null 2>"$WORK/env-unset.err")
  rc=$?
  if [ "$rc" -ne 1 ]; then
    echo "::error::'min task run e2e-envprint' with unset inherited var exited $rc (expected 1)"
    fail
  fi
  grep -q 'E2E_INHERIT_MARKER is not set in this shell' "$WORK/env-unset.err" \
    || { echo "::error::unset inherited var error does not name the var"; cat "$WORK/env-unset.err" 2>/dev/null || true; fail; }
  echo "env_vars inherit: unset var refused client-side OK"

  # Without the allow entry the var is refused at the policy gate, and the
  # error carries the `[vars] allow` snippet to paste.
  rm -f "$XDG_CONFIG_HOME/minimal/user_policy.toml"
  export E2E_INHERIT_MARKER=hello-from-the-host
  (cd "$TASK_SEED_DIR" && mnl task run e2e-envprint >/dev/null 2>"$WORK/env-ungranted.err")
  rc=$?
  if [ "$rc" -ne 1 ]; then
    echo "::error::'min task run e2e-envprint' with ungranted var exited $rc (expected 1)"
    fail
  fi
  grep -Fq '[vars]' "$WORK/env-ungranted.err" \
    || { echo "::error::ungranted var error does not carry the [vars] allow snippet"; cat "$WORK/env-ungranted.err" 2>/dev/null || true; fail; }
  grep -Fq 'allow =' "$WORK/env-ungranted.err" \
    || { echo "::error::ungranted var error does not carry the allow = entry"; cat "$WORK/env-ungranted.err" 2>/dev/null || true; fail; }
  grep -q 'E2E_INHERIT_MARKER' "$WORK/env-ungranted.err" \
    || { echo "::error::ungranted var error does not name the var"; cat "$WORK/env-ungranted.err" 2>/dev/null || true; fail; }
  unset E2E_INHERIT_MARKER # leave the invoking shell as this proof found it
  echo "env_vars inherit: ungranted var refused at the policy gate OK"

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
proof_shared_session
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
# Native host-OS resolution of a box name, with no proxy settings anywhere
# (NET-009, with the client halves of NET-122 and NET-123).
#
# The session-start advisory (NET-122) must print on a host whose resolver is
# not configured for the zone, and name the EXACT command that points it at
# the daemon's zone answerer — this case runs the text it printed, verbatim,
# not a reconstruction of it, so what the user would have copied is what is
# proved. And session start must never prompt: this case drives `min session
# activate` from a script with no answers to give, so the activate completing
# at all is half the proof. The other half, where this host can run it: after
# the command, a plain `getent hosts` — any process, through the host's
# NATIVE resolver — resolves the session's name with every proxy variable
# stripped, which is the whole point of pointing the resolver at the
# answerer instead of exporting proxies (NET-009).
#
# NET-123's present arm is asserted from the daemon's own record: the
# session-start bind probe ran at this create and picked the reserved local
# range, not the 127.0.0.1 interim (on Linux the probe always succeeds — the
# whole 127/8 is `lo`'s — so the interim arm itself is macOS-only and is
# pinned by the minimald unit tests, with the CLI advisory carrying no
# interim sentence on these lanes, asserted alongside). The probe record is
# INFO, and the lane runs its daemon at warn, so this case (like the proxy
# case after it, which is ordered LAST on purpose) restarts with its own
# RUST_LOG first; no session is live here, and the restart proof pins that
# they survive regardless.
#
# Lane gating, by observed fact as ever:
#   * The advisory and its command assert on EVERY lane — the CLI detects the
#     hook host-side, whatever side the daemon is on.
#   * The daemon's probe record and the host half (run the command, resolve)
#     are native-only: a VM lane's daemon and answerer live in the guest, so
#     its log is guest-side (`hook_log_readable`) and its answerer is not
#     this host's loopback. The KVM/macOS lanes assert the advisory; the
#     native lane proves the whole path.
#   * The host half needs `resolvectl`, `getent` and passwordless `sudo`, and
#     a skip is only honest on a developer host (the proxy case's gate
#     doctrine); a CI native lane that cannot run the command is a red lane.
#   * A dev host that already routes the zone to THIS daemon's answerer sees
#     the advisory correctly quiet (NET-122's only quiet state, once the
#     interim is out of the picture and nothing blocks the command — a host
#     whose lookups bypass resolved's stub is told the blocker even on a
#     hook that routes, so it lands in the branch above); the resolution
#     check below still runs there, and passing it is the assertion that
#     the quiet was right.
# ---------------------------------------------------------------------------
proof_native_resolution_without_proxy_env() {
  echo "::group::native min.internal resolution with no proxy settings (NET-009, NET-122, NET-123)"

  # The daemon's file log, newest first (one file per calendar day).
  native_log() {
    find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null \
      | sort | tail -n1
  }

  NATIVE_NAME="e2e-native"
  # What this run actually asserted, for the closing line — a degraded run
  # must not claim the halves it skipped.
  native_proved=""
  # Set when the advisory named no command because this host's lookups
  # bypass systemd-resolved's stub (NET-122's detection): the resolution
  # check cannot pass on a host no command can configure.
  native_bypassed=""
  NATIVE_SEED_DIR="$(hook_mktemp /tmp/mnlnr.XXXXXX)"
  hook_seed_preamble > "$NATIVE_SEED_DIR/minimal.toml"
  mkdir "$NATIVE_SEED_DIR/.git"

  # Restart with the daemon's rpc module at INFO, so this create's probe
  # record is written, and the zone answerer at DEBUG, so its per-lookup
  # lines are too — a resolution failure below can then say whether the
  # query ever reached the answerer. The poll below re-spawns the daemon
  # under it.
  if hook_log_readable; then
    mnl stop >/dev/null 2>&1 || true # a standalone run has no daemon yet
    export RUST_LOG="warn,minimald::rpc=info,minimald::net::answerer=debug"
  fi

  # Warm the daemon and wait until its answerer is on record, so the
  # advisory's trigger — the create response carrying the answerer port —
  # cannot race the listener the daemon spawns beside it (the proxy case's
  # degradation is this same race, read from the other end).
  native_port=""
  for _ in $(seq 1 40); do
    native_port="$(mnl ls 2>/dev/null \
      | sed -n 's/^ZONE ANSWERER: *listening on 127\.0\.0\.1:\([0-9][0-9]*\) (UDP).*/\1/p' \
      | head -n1)"
    [ -n "$native_port" ] && break
    sleep 0.25
  done
  if [ -z "$native_port" ]; then
    if [ -z "${CI:-}" ] && [ -z "$E2E_VM" ]; then
      echo "::warning::native-resolution proof SKIPPED — this host's daemon never owned its zone answerer"
      echo "  (a dev host running another minimald holds the ports; with no answerer port there"
      echo "   is no command to name, and NET-122's advisory correctly stays quiet)"
      rm -rf "$NATIVE_SEED_DIR"; NATIVE_SEED_DIR=""
      echo "::endgroup::"
      return 0
    fi
    echo "::error::the daemon's zone answerer never came up (no ZONE ANSWERER line in min ls)"
    fail
  fi

  # NET-122: the advisory, on the activate's stderr. No prompt anywhere in
  # the path — this script could not answer one.
  native_err="$WORK/native-activate.err"
  native_sid="$(cd "$NATIVE_SEED_DIR" && mnl session activate . --no-prompt \
    --name "$NATIVE_NAME" 2>"$native_err")" || {
    echo "::error::'min session activate' for the native-resolution proof failed"
    echo "--- stderr ---"; cat "$native_err" 2>/dev/null || true
    fail
  }
  native_sid="$(printf '%s\n' "$native_sid" | tail -n1 | tr -d '\r')"
  echo "activated $NATIVE_NAME ($native_sid); answerer on 127.0.0.1:$native_port"

  # The command the advisory named: the line after its lead-in, de-indented —
  # exactly what a user would have copied off the terminal.
  native_cmd="$(grep -A1 -F -- "Configure the host's resolver for the zone with:" \
    "$native_err" 2>/dev/null | tail -n1 | sed 's/^  //')"

  if [ -n "$native_cmd" ]; then
    # The command must name this platform's mechanism and THIS daemon's
    # answerer port, and be a command (sudo) the user runs, not one this
    # session start ran for them.
    case "$(uname -s)" in
      Linux)
        native_want_a="resolvectl"
        native_want_b="127.0.0.1:$native_port"
        ;;
      Darwin)
        native_want_a="/etc/resolver/min.internal"
        native_want_b="port $native_port"
        ;;
      *)
        native_want_a=""; native_want_b=""
        ;;
    esac
    if [ -n "$native_want_a" ]; then
      case "$native_cmd" in
        *"$native_want_a"*) ;;
        *)
          echo "::error::the advisory's command does not name $native_want_a (got: '$native_cmd')"
          echo "--- activate stderr ---"; cat "$native_err" 2>/dev/null || true
          fail
          ;;
      esac
      case "$native_cmd" in
        *"$native_want_b"*) ;;
        *)
          echo "::error::the advisory's command does not name this answerer, $native_want_b (got: '$native_cmd')"
          echo "--- activate stderr ---"; cat "$native_err" 2>/dev/null || true
          fail
          ;;
      esac
    fi
    case "$native_cmd" in
      sudo*) ;;
      *) echo "::error::the advisory's command is not one the user runs (got: '$native_cmd')"; fail ;;
    esac
    echo "advisory named the exact command: $native_cmd"
    native_proved="advised"

    # NET-123's present arm, client side: a probe that found the reserved
    # range adds no interim sentence to the advisory. On the lanes that run
    # Linux daemons (native guest, or the Linux host of a VM lane) the
    # probe always succeeds, so the word must be absent.
    if [ "$(uname -s)" = Linux ] && grep -q -- interim "$native_err"; then
      echo "::error::the advisory names the 127.0.0.1 interim where the probe found the reserved range"
      echo "--- activate stderr ---"; cat "$native_err" 2>/dev/null || true
      fail
    fi
  elif grep -q -- 'bypass systemd-resolved' "$native_err" 2>/dev/null; then
    # An advisory that names no command: this host's lookups never reach
    # systemd-resolved's stub, so the routing-domain command would
    # configure nothing a host process consults — NET-122's detection says
    # so instead of printing a dead command. Only a dev host can see this;
    # a lane's lookups go through the stub, so CI must always get the
    # command above.
    native_bypassed=yes
    echo "advisory said this host's lookups bypass systemd-resolved's stub (NET-122 detection):"
    echo "  $(grep -F -- 'bypass systemd-resolved' "$native_err" 2>/dev/null | head -n1)"
    if [ -n "${CI:-}" ] || [ -n "$E2E_VM" ]; then
      echo "::error::this lane's host bypasses systemd-resolved's stub, so NET-009 cannot be proved on it"
      echo "--- activate stderr ---"; cat "$native_err" 2>/dev/null || true
      echo "--- /etc/resolv.conf ---"; cat /etc/resolv.conf 2>&1 || true
      fail
    fi
    native_proved="advised-bypass"
  else
    # No advisory. NET-122's only quiet state is a hook that already routes
    # this answerer's port with nothing blocking the command (the create
    # carried the port — warmed above — and no Linux lane reports the
    # interim), so this is a dev host that configured the zone against this
    # daemon before. CI's fresh runners never see it, which is why it is an
    # error there.
    if [ -n "${CI:-}" ] || [ -n "$E2E_VM" ]; then
      echo "::error::no advisory on the activate's stderr, and this lane's resolver is not configured for the zone (NET-122)"
      echo "--- activate stderr ---"; cat "$native_err" 2>/dev/null || true
      fail
    fi
    echo "::warning::no advisory printed — this host's resolver already routes the zone to this answerer (NET-122's quiet state)"
    echo "  the resolution check below is then the assertion that the quiet was right"
  fi

  # NET-123's present arm, daemon side: the session-start probe record this
  # create produced, with the surface it picked.
  if hook_log_readable; then
    native_probe=""
    for _ in $(seq 1 20); do
      native_probe="$(grep -h -- 'picked the publish surface' "$(native_log)" 2>/dev/null \
        | grep -F -- "$native_sid" | tail -n1 || true)"
      [ -n "$native_probe" ] && break
      sleep 0.25
    done
    if [ -z "$native_probe" ]; then
      echo "::error::no session-start loopback-probe record for $native_sid in the daemon log"
      echo "--- daemon log (tail) ---"; tail -20 "$(native_log)" 2>/dev/null || true
      fail
    fi
    echo "daemon log: $native_probe"
    native_proved="${native_proved:+$native_proved, }probed"
    case "$native_probe" in
      *reserved-range*) ;;
      *)
        echo "::error::the session-start probe did not pick the reserved range (got: '$native_probe')"
        fail
        ;;
    esac
    if ! printf '%s' "$native_probe" | grep -Eq -- 'interim_loopback" *: *false'; then
      echo "::error::the probe record does not read interim_loopback=false (got: '$native_probe')"
      fail
    fi
  fi

  # ---- the host half: run the command, then resolve with no proxy env -----
  if [ -n "$E2E_VM" ]; then
    echo "host half SKIPPED (VM-backed target: the answerer is guest-side; the native lane proves it)"
  elif ! command -v resolvectl >/dev/null 2>&1 \
       || ! command -v ip >/dev/null 2>&1 \
       || ! command -v getent >/dev/null 2>&1 \
       || ! sudo -n true >/dev/null 2>&1; then
    if [ -z "${CI:-}" ]; then
      echo "::warning::native-resolution host half SKIPPED — this host cannot run the advisory's command"
      echo "  (needs resolvectl, ip, getent and passwordless sudo; CI's native lane has all four)"
      echo "  asserted here: the advisory's exact command and the daemon's probe record above"
    else
      echo "::error::a CI native lane must be able to run the advisory's command (resolvectl, ip, getent, passwordless sudo)"
      fail
    fi
  else
    if [ -n "$native_cmd" ]; then
      # Record the link BEFORE running the command, so a half-failed run
      # still leaves the teardown a link to remove: the command creates
      # the dedicated link and then configures DNS on it, so the creation
      # can succeed while a later `resolvectl` step fails — and a teardown
      # with no link recorded would skip the undo below and leave the link
      # on a host the soak's next iteration expects to find as this one
      # did. Undoing is the teardown's `resolvectl revert` on this link —
      # restoring its DNS state, whatever this host had before the proof
      # touched it — and `ip link del`, removing the dedicated link the
      # command created.
      NATIVE_REVERT_LINK="$(printf '%s\n' "$native_cmd" \
        | sed -n 's/.*resolvectl dns \([^ ][^ ]*\) .*/\1/p')"
      if [ -z "$NATIVE_REVERT_LINK" ]; then
        echo "::error::could not find the link in the advisory's command, so it was not run — this run cannot undo a command it cannot name (got: '$native_cmd')"
        echo "--- activate stderr ---"; cat "$native_err" 2>/dev/null || true
        fail
      fi
      # Run the exact command the advisory printed — verbatim, as the user
      # would have. Passwordless sudo is the gate above, so it cannot prompt.
      if ! sh -c "$native_cmd" >"$WORK/native-cmd.out" 2>"$WORK/native-cmd.err"; then
        echo "::error::the advisory's command did not run (are resolvectl and ip usable here?)"
        echo "--- command ---"; echo "$native_cmd"
        echo "--- output ---"; cat "$WORK/native-cmd.out" "$WORK/native-cmd.err" 2>/dev/null || true
        fail
      fi
      echo "ran the advisory's command"
    elif [ -n "$native_bypassed" ]; then
      echo "no command to run: this host's lookups bypass systemd-resolved's stub, so no routing-domain command could reach them"
    else
      echo "no command to run (the advisory was quiet); the resolution check below is the assertion"
    fi

    if [ -n "$native_bypassed" ]; then
      # NET-009's WHERE names a host whose native resolver is configured for
      # the zone; a host whose lookups never reach resolved's stub cannot be
      # one, and the advisory already said so — the check would fail for a
      # fact the detection explained, not for a defect.
      echo "resolution check SKIPPED — this host's lookups never reach systemd-resolved, so they cannot carry the zone"
    else
      # NET-009: any process on the host, through the host's NATIVE resolver,
      # with every proxy variable stripped from its environment.
      native_resolved="$(env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
        -u ALL_PROXY -u all_proxy getent hosts "$NATIVE_NAME.min.internal" 2>/dev/null || true)"
      if [ -z "$native_resolved" ]; then
        echo "::error::$NATIVE_NAME.min.internal did not resolve on the host with no proxy settings"
        # The two causes this could be, each answered by its own read below —
        # all read-only, so nothing here can prompt:
        #   1. whether host lookups reach resolved's stub at all — `getent`
        #      uses the `dns` NSS module against /etc/resolv.conf, and a file
        #      naming the upstream directly never travels through resolved,
        #      so a per-link routing domain cannot apply to it;
        #   2. whether the query reached the answerer and what it answered —
        #      resolved's own verdict, and the answerer's log lines for this
        #      very name (the case runs the daemon with the answerer at
        #      DEBUG for exactly this).
        # `resolvectl dns`'s Global line is printed in full too: nothing
        # this script or the advisory's command runs can set a global server
        # (every resolvectl verb is per-link, and a foreign resolv.conf loads
        # with no port), so resolved.conf and its dropins — the only inputs
        # that can — are dumped to name the source when one appears.
        echo "--- /etc/resolv.conf ---"; cat /etc/resolv.conf 2>&1 || true
        echo "--- nsswitch hosts ---"
        grep -E '^[[:space:]]*hosts:' /etc/nsswitch.conf 2>&1 || true
        echo "--- resolvectl domain ---"; resolvectl domain 2>&1 || true
        echo "--- resolvectl dns ---"; resolvectl dns 2>&1 || true
        echo "--- resolvectl query ---"
        resolvectl query "$NATIVE_NAME.min.internal" 2>&1 || true
        echo "--- resolved.conf and dropins ---"
        cat /etc/systemd/resolved.conf /etc/systemd/resolved.conf.d/*.conf 2>&1 || true
        if hook_log_readable; then
          native_answers="$(grep -h -- 'zone-answerer' "$(native_log)" 2>/dev/null \
            | grep -F -- "$NATIVE_NAME.min.internal" | tail -n20 || true)"
          if [ -n "$native_answers" ]; then
            echo "--- zone answerer: this query ---"
            printf '%s\n' "$native_answers"
          else
            echo "--- zone answerer: no log line for this query — it never reached the answerer ---"
            echo "  (the daemon log's last zone-answerer lines, for contrast:)"
            grep -h -- 'zone-answerer' "$(native_log)" 2>/dev/null | tail -n5 || true
          fi
        fi
        fail
      fi
      echo "resolved $NATIVE_NAME.min.internal with no proxy settings: $native_resolved"
      case "$native_resolved" in
        *127.0.0.1*|*127.0.64.*) ;;
        *)
          echo "::error::the name resolved outside the box zone's loopback (got: '$native_resolved')"
          fail
          ;;
      esac

      native_proved="${native_proved:+$native_proved, }resolved"
    fi

    if [ -n "$NATIVE_REVERT_LINK" ]; then
      # Undo the whole command: `resolvectl revert` restores the link's
      # DNS state, `ip link del` removes the dedicated link itself — the
      # next iteration (the soak runs this script ten times) must find the
      # host as this run did. The record is kept when a deletion fails, so
      # the teardown retries it: this block must not clear the variable on
      # a link it could not remove.
      if sudo resolvectl revert "$NATIVE_REVERT_LINK" >/dev/null 2>&1; then
        echo "reverted the routing domain on $NATIVE_REVERT_LINK"
      else
        echo "::warning::could not revert the routing domain on $NATIVE_REVERT_LINK (this host's resolver still carries it)"
      fi
      if sudo ip link del "$NATIVE_REVERT_LINK" >/dev/null 2>&1; then
        echo "removed the dedicated link $NATIVE_REVERT_LINK"
        NATIVE_REVERT_LINK=""
      else
        echo "::warning::could not remove the dedicated link $NATIVE_REVERT_LINK (this host still carries it)"
      fi
    fi
  fi

  mnl session destroy --force "$native_sid" >/dev/null 2>&1 || true
  echo "native min.internal resolution with no proxy settings OK (${native_proved:-advisory race} — each printed)"
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# Session hostnames that recover, and two daemons sharing one machine, end
# to end (NET-020..NET-027). Four surfaces, driven the way a person drives
# them — activate, `min ls`, and a request from inside a box:
#
#   A. A held port at activate and on the list (NET-020). A python3 holder
#      occupies 127.0.0.1:<pin> before the daemon starts, the daemon comes
#      up pinned to that port (--hostname-proxy-port), and both activate
#      and `min ls` must say what failed, whose fault it is, and what
#      clears it — the daemon's bind report, remedy included.
#   B. Recovery without a restart (NET-021, NET-022). Free the port; the
#      daemon's own retry loop binds it, `min ls` stops warning and starts
#      printing the listening line on the SAME daemon process — asserted
#      by pid continuity, because a restart would clear the warning too.
#      The daemon log carries the pair the retry leaves: the unavailable
#      warns with their next-retry schedule, then the recovered/serving
#      infos that say the listener is back.
#   C. The lost datapath (NET-023, VM lanes only). The switch socket
#      disappears from under minvmd; within one monitor period minvmd
#      must warn that guest attach and egress are down.
#   D. Two daemons, one machine (NET-024..NET-027). A second daemon under
#      its own state dir comes up on its own port — its default is busy,
#      so it selects (NET-025) — `min ls` discovers both ports (NET-026),
#      and each box's name routes through its OWN daemon while the other
#      daemon refuses it (NET-027).
#
# Lane gating, decided by where the shipped surfaces actually live:
# beats A, B and D need a host-native daemon the run can pin
# (--hostname-proxy-port) and a host whose boxes can exec; on a VM lane
# the guest's pid-1 hardcodes no proxy port (crates/minimald/src/main.rs)
# and a second daemon there would be another minvmd, so the VM branch
# proves only beat C. A native lane has no switch, so it prints beat C's
# skip the same honest way. Nothing is skipped silently: every skip says
# what it did not assert.
proof_hostnames_recover_and_two_daemons_route() {
  echo "::group::hostnames recover, and two daemons share a machine (NET-020..NET-027)"

  # Beat D's in-box responders (the proxy proof's socat form, below). Their
  # ports are fixed, never OS-assigned: a daemon that finds its port taken
  # relocates by asking the OS for a free one (crates/minimald/src/server.rs
  # binds port 0), and the OS only ever hands out ephemeral-range ports — so
  # neither daemon can land on these, and a responder can never collide with
  # a proxy listener. The band sits beside the proxy proof's 18080-18082,
  # which runs only after this proof has torn its boxes down. Both boxes
  # answer with one marker: the URL's port names the box, so a 200 carrying
  # it proves the request reached a box of this run through the daemon it
  # named.
  RECOVER_BOX_PORT=18080                 # box A's (e2e-recover) responder
  SECOND_BOX_PORT=18081                  # box B's (e2e-second) responder
  RECOVER_BOX_MARKER="RECOVER_ROUTED_OK" # what the in-box responders answer

  # The daemon log readers. The log dir is per state base, so the two
  # daemons of beat D read from different dirs — the helper takes the base;
  # the first daemon's is this run's $XDG_STATE_HOME/minimal, the second's
  # is $RECOVER_STATE2_DIR.
  recover_daemon_log() {
    find "${1:-$XDG_STATE_HOME/minimal}/logs" -name 'minimald.log.*' -type f 2>/dev/null \
      | sort | tail -n1
  }
  recover_daemon2_log() { recover_daemon_log "$RECOVER_STATE2_DIR"; }
  recover_minvmd_log() {
    find "$XDG_STATE_HOME/minimal/logs" -name 'minvmd.log.*' -type f 2>/dev/null \
      | sort | tail -n1
  }

  # Whether 127.0.0.1:$1 is free to bind — the probe that picks the pin,
  # then confirms the holder took it. Deliberately a bind probe, not a
  # connect one: a held-but-never-listening socket is exactly the situation
  # beat A stages.
  recover_port_free() {
    python3 -c 'import socket,sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    sys.exit(1)
s.close()' "$1"
  }

  # One request through ONE daemon's proxy, reported: runner ($1 — `mnl` or
  # `mnl2`), box ($2), proxy address ($3), URL ($4), label ($5). Sets
  # RECOVER_STATUS / RECOVER_BODY for `recover_route_want`, and prints each
  # request with its status so the transcript reads as the run's narrative.
  recover_route() {
    local runner="$1" box="$2" proxy_addr="$3" url="$4"
    RECOVER_ROUTE_LABEL="$5"
    RECOVER_STATUS="$("$runner" session exec "$box" \
      "curl -sS --max-time 20 -x http://$proxy_addr -o /home/proxy.body -w '%{http_code}' '$url'" \
      2>"$WORK/recover-curl.err" | tail -n1 | tr -d '\r\n')"
    if [ ! -s "$WORK/recover-curl.err" ] && [ -z "$RECOVER_STATUS" ]; then
      echo "::error::$RECOVER_ROUTE_LABEL: curl produced no status (exec output empty)"
      fail
    fi
    RECOVER_BODY="$("$runner" session exec "$box" 'cat /home/proxy.body' 2>/dev/null || true)"
    echo "$RECOVER_ROUTE_LABEL: GET $url via $proxy_addr -> HTTP ${RECOVER_STATUS:-<none>} ${RECOVER_BODY:0:48}"
  }
  # Asserts the last `recover_route`: $1 = the HTTP status, $2 = a substring
  # the body must carry ("" to skip).
  recover_route_want() {
    if [ "${RECOVER_STATUS:-}" != "$1" ]; then
      echo "::error::$RECOVER_ROUTE_LABEL: expected HTTP $1, got '${RECOVER_STATUS:-<none>}'"
      echo "--- curl stderr ---"; cat "$WORK/recover-curl.err" 2>/dev/null || true
      fail
    fi
    if [ -n "$2" ] && [[ "${RECOVER_BODY:-}" != *"$2"* ]]; then
      echo "::error::$RECOVER_ROUTE_LABEL: the answer does not carry '$2' (got: '${RECOVER_BODY:-<empty>}')"
      fail
    fi
  }

  # The in-box responder of beat D — the proxy proof's socat form verbatim:
  # socat is a launcher baseline package every box ships at /usr/bin, and
  # the response is written by the SESSION's shell so the Content-Length
  # can never drift from the body it frames.
  # $1 = runner, $2 = session id, $3 = the port the responder listens on.
  recover_start_responder() {
    local runner="$1" sid="$2" port="$3" ready
    "$runner" session exec "$sid" 'test -x /usr/bin/socat' >/dev/null 2>&1 \
      || { echo "::error::the session has no socat at /usr/bin/socat (a launcher baseline package — every box ships one)"; fail; }
    "$runner" session exec "$sid" \
      "body=$RECOVER_BOX_MARKER; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/http200" \
      >/dev/null 2>"$WORK/recover-responder.err" \
      || { echo "::error::could not write the in-box responder's response"; cat "$WORK/recover-responder.err" 2>/dev/null || true; fail; }
    "$runner" session exec "$sid" \
      "nohup /usr/bin/socat TCP-LISTEN:$port,reuseaddr,fork SYSTEM:\"cat /home/http200\" >/dev/null 2>&1 &" \
      >/dev/null 2>"$WORK/recover-responder.err" \
      || { echo "::error::could not start the in-box responder"; cat "$WORK/recover-responder.err" 2>/dev/null || true; fail; }
    ready=""
    for _ in $(seq 1 40); do
      if [ "$("$runner" session exec "$sid" \
        "curl -sS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$port/" \
        2>/dev/null || true)" = "200" ]; then
        ready=1; break
      fi
      sleep 0.25
    done
    if [ -z "$ready" ]; then
      echo "::error::the in-box responder never answered a direct curl on 127.0.0.1:$port"
      echo "--- responder stderr ---"; cat "$WORK/recover-responder.err" 2>/dev/null || true
      fail
    fi
  }

  # Tear-down of the two-daemon half, shared by its normal end and its
  # degradation path. The second daemon must never leak: it would keep
  # holding whatever port it selected, and the next run's pick (or the soak's
  # next rep) would inherit the confusion this case exists to explain.
  recover_two_daemon_cleanup() {
    mnl session destroy --force "$recover_sid" >/dev/null 2>&1 || true
    if [ -n "${second_sid:-}" ]; then
      mnl2 session destroy --force "$second_sid" >/dev/null 2>&1 || true
    fi
    if [ -n "$RECOVER_STATE2_DIR" ]; then
      mnl2 stop >/dev/null 2>&1 || true
    fi
    RECOVER_STATE2_DIR=""
    if [ -n "$SAVED_RUST_LOG" ]; then
      export RUST_LOG="$SAVED_RUST_LOG"
    else
      unset RUST_LOG
    fi
  }

  # Skips degrade by observed fact and only ever on a developer host: CI
  # sets CI=true on every lane, and E2E_VM marks the VM-backed targets —
  # a tripped gate there is a lane-level fault, not a degraded proof.
  recover_gate_can_skip() { [ -z "${CI:-}" ] && [ -z "$E2E_VM" ]; }

  # The pids whose cmdline carries $1, straight off /proc — pgrep -f's
  # answer without the procps dependency (musl guest images and slim CI
  # images both lack it). Beat B reads the pinned daemon's pid from here
  # twice, to prove the recovery happened without a restart.
  recover_pids_for() {
    local proc entry pat="$1"
    for proc in /proc/[0-9]*; do
      [ -r "$proc/cmdline" ] || continue
      # 2>/dev/null BEFORE the file redirect: a pid can vanish between the
      # glob and the open, and the shell reports the failed redirect to the
      # stderr in effect at that point — discard it first, or every scan
      # prints noise for pids that died mid-scan.
      entry="$(tr '\0' ' ' 2>/dev/null <"$proc/cmdline" || true)"
      case "$entry" in
        *"$pat"*) printf '%s\n' "${proc#/proc/}" ;;
      esac
    done
  }

  # ---- the VM branch: only beat C exists there ----------------------------
  if [ "$min_daemon" = minvmd ]; then
    mnl ls >/dev/null 2>&1 || true # a standalone run: make sure the VM is up
    RECOVER_SWITCH_SOCK="$XDG_STATE_HOME/minimal/providers/local-minvmd0/gvproxy-switch.sock"
    for _ in $(seq 1 120); do
      [ -S "$RECOVER_SWITCH_SOCK" ] && break
      sleep 1
    done
    if [ ! -S "$RECOVER_SWITCH_SOCK" ]; then
      if [ -n "${MINVMD_GVPROXY_BIN:-}" ]; then
        echo "::error::the minvmd switch socket never appeared at $RECOVER_SWITCH_SOCK — there is no datapath to lose, so NET-023 cannot be proven"
        fail
      fi
      echo "beat C (lost switch datapath) SKIPPED: this minvmd runs switchless (no MINVMD_GVPROXY_BIN), so there is no datapath to lose"
      echo "  (asserted here: nothing — NET-023 needs a switch; the switch lanes carry the assertion)"
      echo "::endgroup::"
      return 0
    fi
    echo "beat C: the switch socket is $RECOVER_SWITCH_SOCK"

    # The monitor polls every 30 s (crates/minvmd/src/net.rs
    # DEFAULT_DATAPATH_CHECK_INTERVAL), so the warn lands within a minute
    # of the socket going away. Move the socket aside — the daemon's connect
    # then fails with ENOENT, the same fact a crashed gvproxy presents.
    recover_vmd_log="$(recover_minvmd_log)"
    recover_vmd_lines=0
    if [ -n "$recover_vmd_log" ]; then
      recover_vmd_lines="$(wc -l <"$recover_vmd_log" | tr -d ' ')"
    fi
    recover_t0="$(now_ms)"
    mv "$RECOVER_SWITCH_SOCK" "$WORK/gvproxy-switch.sock.hold"
    RECOVER_SWITCH_HOLD="$WORK/gvproxy-switch.sock.hold"
    echo "switch socket moved aside at t=0; minvmd's monitor should warn within its 30 s period"

    recover_lost_record=""
    for _ in $(seq 1 60); do
      recover_vmd_log="$(recover_minvmd_log)"
      if [ -n "$recover_vmd_log" ]; then
        recover_lost_record="$(tail -n "+$((recover_vmd_lines + 1))" "$recover_vmd_log" 2>/dev/null \
          | grep -F -- 'switch datapath lost' | tail -n1 || true)"
        [ -n "$recover_lost_record" ] && break
      fi
      sleep 1
    done
    if [ -z "$recover_lost_record" ]; then
      echo "::error::minvmd did not warn 'switch datapath lost' within a minute of the socket disappearing (NET-023)"
      echo "--- minvmd log (tail) ---"
      tail -20 "${recover_vmd_log:-<no minvmd log>}" 2>/dev/null || true
      fail
    fi
    echo "minvmd warned $(( $(now_ms) - recover_t0 )) ms after the socket disappeared"
    echo "minvmd log: $recover_lost_record"

    # Put the datapath back before anything else runs on this VM — a lane
    # that continues switchless would fail everywhere else, and teardown
    # restores it too if something below fails mid-beat.
    mv "$RECOVER_SWITCH_HOLD" "$RECOVER_SWITCH_SOCK"
    RECOVER_SWITCH_HOLD=""
    for _ in $(seq 1 40); do
      [ -S "$RECOVER_SWITCH_SOCK" ] && break
      sleep 0.25
    done
    if [ ! -S "$RECOVER_SWITCH_SOCK" ]; then
      echo "::error::the switch socket did not come back after the restore — the VM's datapath is still down for whatever runs next"
      fail
    fi
    echo "switch socket restored"

    # Beats A, B, D need a host-native daemon this run can pin; the guest
    # daemon's pid-1 hardcodes no --hostname-proxy-port, and a second
    # daemon here would be another minvmd — neither story is stageable on
    # a VM lane, and the minvmd net.rs unit tests pin the warn's emission.
    echo "beats A/B/D SKIPPED on this lane: the daemon is the guest's pid-1 (no pin-able --hostname-proxy-port)"
    echo "  (asserted here: NET-023, beat C above; the pid-1 posture is crates/minimald/src/main.rs)"
    echo "::endgroup::"
    return 0
  fi

  # ---- the native branch: beats A, B, D -----------------------------------
  #
  # The daemon's filter comes from RUST_LOG at spawn, and this lane runs it
  # at `warn` — which drops the INFO records beat B asserts (recovered,
  # serving). Stop whatever daemon a previous proof left and spawn this
  # case's own, pinned, with minimald::server at info. `run --detach`
  # returns only once the daemon is listening, so there is no autospawn
  # race behind it.
  mnl stop >/dev/null 2>&1 || true # a standalone run has no daemon yet
  SAVED_RUST_LOG="${RUST_LOG:-}"
  export RUST_LOG="warn,minimald::server=info"

  # Pick the port the story holds: 7654 first — the documented default, the
  # one every HTTP(S)_PROXY recipe assumes — falling back to spares on a
  # dev host where a daemon outside this run already owns it. Either way
  # the invariant beat D needs holds: 7654 is busy when the second daemon
  # starts, so it always ends up relocating to a selected port.
  RECOVER_PIN=""
  for recover_cand in 7654 18754 18755; do
    if recover_port_free "$recover_cand"; then RECOVER_PIN="$recover_cand"; break; fi
  done
  if [ -z "$RECOVER_PIN" ]; then
    echo "::error::no free candidate port among 7654/18754/18755 to stage the held-port story on"
    fail
  fi
  echo "beat A: pinning the daemon to 127.0.0.1:$RECOVER_PIN and holding it"

  python3 -c 'import socket,sys,time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("127.0.0.1", int(sys.argv[1])))
s.listen(1)
while True:
    time.sleep(3600)' "$RECOVER_PIN" \
    >/dev/null 2>"$WORK/recover-holder.err" &
  RECOVER_HOLDER_PID=$!
  holder_bound=""
  for _ in $(seq 1 40); do
    if ! recover_port_free "$RECOVER_PIN"; then holder_bound=1; break; fi
    sleep 0.25
  done
  if [ -z "$holder_bound" ]; then
    echo "::error::the port holder never took 127.0.0.1:$RECOVER_PIN — the story cannot be staged"
    echo "--- holder stderr ---"; cat "$WORK/recover-holder.err" 2>/dev/null || true
    fail
  fi
  echo "port holder: python3 holding 127.0.0.1:$RECOVER_PIN (pid $RECOVER_HOLDER_PID)"

  minimald run --detach --instance-num 0 --hostname-proxy-port "$RECOVER_PIN" \
    >"$WORK/recover-spawn.out" 2>"$WORK/recover-spawn.err" \
    || { echo "::error::could not spawn the daemon pinned to 127.0.0.1:$RECOVER_PIN"
         echo "--- spawn stderr ---"; cat "$WORK/recover-spawn.err" 2>/dev/null || true
         fail; }

  # ---- beat A: the reason and the remedy, at activate and on the list -----
  RECOVER_SEED_DIR="$(hook_mktemp /tmp/mnlrc.XXXXXX)"
  hook_seed_preamble > "$RECOVER_SEED_DIR/minimal.toml"
  mkdir "$RECOVER_SEED_DIR/.git"
  recover_sid="$(cd "$RECOVER_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-recover 2>"$WORK/recover-activate.err")" \
    || { echo "::error::'min session activate' against the pinned daemon failed"
         echo "--- stderr ---"; cat "$WORK/recover-activate.err" 2>/dev/null || true
         fail; }
  recover_sid="$(printf '%s\n' "$recover_sid" | tail -n1 | tr -d '\r')"

  recover_activate_err="$(cat "$WORK/recover-activate.err" 2>/dev/null || true)"
  case "$recover_activate_err" in
    *"session hostnames will not route"*"could not bind 127.0.0.1:$RECOVER_PIN"*"Remedy: free the listen address"*) ;;
    *)
      echo "::error::activate against the held port did not warn with the reason and the remedy (NET-020)"
      echo "--- activate stderr ---"; cat "$WORK/recover-activate.err" 2>/dev/null || true
      fail
      ;;
  esac
  if ! grep -F -q -- 'min session activate' "$WORK/recover-activate.err" \
     || ! grep -F -q -- 'again to check' "$WORK/recover-activate.err"; then
    echo "::error::the activate warning's recovery sentence does not name the command it rode on (NET-020)"
    echo "--- activate stderr ---"; cat "$WORK/recover-activate.err" 2>/dev/null || true
    fail
  fi
  echo "activate warned:"; sed 's/^/  /' "$WORK/recover-activate.err"

  recover_ls_out="$(mnl ls 2>&1)"
  case "$recover_ls_out" in
    *"session hostnames will not route"*"could not bind 127.0.0.1:$RECOVER_PIN"*"Remedy: free the listen address"*) ;;
    *)
      echo "::error::min ls against the held port did not warn with the reason and the remedy (NET-020)"
      echo "--- min ls output ---"; printf '%s\n' "$recover_ls_out"
      fail
      ;;
  esac
  if ! printf '%s\n' "$recover_ls_out" | grep -F -q -- 'again to check' \
     || ! printf '%s\n' "$recover_ls_out" | grep -F -q -- 'min ls'; then
    echo "::error::the ls warning's recovery sentence does not name the command it rode on (NET-020)"
    echo "--- min ls output ---"; printf '%s\n' "$recover_ls_out"
    fail
  fi
  printf '%s\n' "$recover_ls_out" | grep -F -- 'session hostnames will not route' | sed 's/^/  /'

  # The daemon log's own record: the warn the retry left, with its status
  # and next-retry schedule (the file log is JSON lines).
  recover_bind_record=""
  for _ in $(seq 1 20); do
    recover_bind_record="$(grep -F -- "could not bind 127.0.0.1:$RECOVER_PIN" \
      "$(recover_daemon_log)" 2>/dev/null | tail -n1 || true)"
    [ -n "$recover_bind_record" ] && break
    sleep 0.25
  done
  if [ -z "$recover_bind_record" ]; then
    echo "::error::no bind-failure record for 127.0.0.1:$RECOVER_PIN in the daemon log (the diagnostics bundle tails this log — it must carry the story)"
    echo "--- daemon log (tail) ---"; tail -20 "$(recover_daemon_log)" 2>/dev/null || true
    fail
  fi
  # Two separate substring checks, never one ordered glob: the file log is
  # JSON with its fields rendered alphabetically, so "next_retry" sorts
  # BEFORE "status" and a single `*status*next_retry*` pattern could never
  # match a real record.
  case "$recover_bind_record" in
    *'"status":"unavailable"'*) ;;
    *)
      echo "::error::the bind-failure record does not carry its unavailable status"
      echo "--- record ---"; printf '%s\n' "$recover_bind_record"
      fail
      ;;
  esac
  case "$recover_bind_record" in
    *'"next_retry"'*) ;;
    *)
      echo "::error::the bind-failure record does not carry its next-retry schedule"
      echo "--- record ---"; printf '%s\n' "$recover_bind_record"
      fail
      ;;
  esac
  echo "daemon log: $recover_bind_record"

  # ---- beat B: free the port; recovery, no restart ------------------------
  recover_pid_before="$(recover_pids_for "hostname-proxy-port $RECOVER_PIN" | head -n1)"
  if [ -z "$recover_pid_before" ]; then
    echo "::error::cannot find the daemon pinned to --hostname-proxy-port $RECOVER_PIN — the no-restart proof has no pid to compare"
    fail
  fi
  echo "beat B: freeing 127.0.0.1:$RECOVER_PIN (killing the holder, pid $RECOVER_HOLDER_PID)"
  kill "$RECOVER_HOLDER_PID" 2>/dev/null || true
  RECOVER_HOLDER_PID=""

  # The retry loop's next attempt is at most one backoff cap (30 s) away,
  # so 90 one-second ls polls is generous. Cleared means BOTH halves: the
  # warning gone AND the listening line on the pinned port.
  recover_cleared=""
  for recover_try in $(seq 1 90); do
    recover_ls_after="$(mnl ls 2>&1)"
    recover_port_now="$(printf '%s\n' "$recover_ls_after" | grep -F -- 'HOSTNAME PROXY' \
      | grep -oE '127\.0\.0\.1:[0-9]+' | head -n1 | cut -d: -f2 || true)"
    if [ "$recover_port_now" = "$RECOVER_PIN" ]; then
      case "$recover_ls_after" in
        *"session hostnames will not route"*) ;; # serving but still warning: keep polling
        *) recover_cleared=1; break ;;
      esac
    fi
    sleep 1
  done
  if [ -z "$recover_cleared" ]; then
    echo "::error::min ls did not clear the warning and report the pinned listener back after the port was freed (NET-021, NET-022)"
    echo "--- last min ls output ---"; printf '%s\n' "${recover_ls_after:-<none>}"
    fail
  fi
  echo "min ls cleared the warning after ${recover_try} one-second poll(s); it now reads:"
  printf '%s\n' "$recover_ls_after" | grep -E -- 'HOSTNAME PROXY|ZONE ANSWERER' | sed 's/^/  /'

  recover_pid_after="$(recover_pids_for "hostname-proxy-port $RECOVER_PIN" | head -n1)"
  if [ "$recover_pid_after" != "$recover_pid_before" ]; then
    echo "::error::the daemon's pid changed across the recovery ($recover_pid_before -> ${recover_pid_after:-<none>}) — a restart clears the warning too, so this proves nothing (NET-022 is about the daemon recovering on its own)"
    fail
  fi
  echo "daemon pid unchanged across the recovery ($recover_pid_before): no restart"

  recover_recover_record=""
  for _ in $(seq 1 30); do
    recover_recover_record="$(grep -F -- 'host-side proxy is serving after retrying' \
      "$(recover_daemon_log)" 2>/dev/null | tail -n1 || true)"
    [ -n "$recover_recover_record" ] && break
    sleep 1
  done
  if [ -z "$recover_recover_record" ]; then
    echo "::error::no 'serving after retrying' record in the daemon log — the retry's recovery is the diagnostics story NET-021 owes"
    echo "--- daemon log (tail) ---"; tail -20 "$(recover_daemon_log)" 2>/dev/null || true
    fail
  fi
  case "$recover_recover_record" in
    *'"status":"recovered"'*) ;;
    *)
      echo "::error::the recovered record does not carry its recovered status"
      echo "--- record ---"; printf '%s\n' "$recover_recover_record"
      fail
      ;;
  esac
  case "$recover_recover_record" in
    *"\"addr\":\"127.0.0.1:$RECOVER_PIN\""*) ;;
    *)
      echo "::error::the recovered record does not name the recovered address"
      echo "--- record ---"; printf '%s\n' "$recover_recover_record"
      fail
      ;;
  esac
  echo "daemon log: $recover_recover_record"

  recover_serving_record="$(grep -F -- 'hostname proxy is serving on its configured port' \
    "$(recover_daemon_log)" 2>/dev/null | tail -n1 || true)"
  case "$recover_serving_record" in
    *"\"port\":$RECOVER_PIN"*) ;;
    "" | *)
      echo "::error::no serving record for the pinned port in the daemon log"
      echo "--- record ---"; printf '%s\n' "${recover_serving_record:-<none>}"
      fail
      ;;
  esac
  echo "daemon log: $recover_serving_record"

  # ---- beat D: a second daemon on the same machine ------------------------
  echo "beat D: a second daemon under its own state dir"
  RECOVER_STATE2_DIR="$WORK/state2"
  mkdir -p "$RECOVER_STATE2_DIR"
  mnl2() { min --minimal-dir "$RECOVER_STATE2_DIR" "$@"; }

  # Boot it through the CLI's own autospawn, then read the port `min ls`
  # discovers (NET-026): the default is busy (the first daemon holds 7654,
  # or the dev daemon that made us pick a spare pin does), so this daemon
  # selects a free one (NET-025) and reports it.
  recover_ls2=""
  for _ in $(seq 1 60); do
    if recover_ls2="$(mnl2 ls 2>&1)"; then break; fi
    sleep 0.5
  done
  recover_port2=""
  if [ -n "$recover_ls2" ]; then
    recover_port2="$(printf '%s\n' "$recover_ls2" | grep -F -- 'HOSTNAME PROXY' \
      | grep -oE '127\.0\.0\.1:[0-9]+' | head -n1 | cut -d: -f2 || true)"
  fi
  for _ in $(seq 1 60); do
    [ -n "$recover_port2" ] && break
    recover_ls2="$(mnl2 ls 2>&1)"
    recover_port2="$(printf '%s\n' "$recover_ls2" | grep -F -- 'HOSTNAME PROXY' \
      | grep -oE '127\.0\.0\.1:[0-9]+' | head -n1 | cut -d: -f2 || true)"
    sleep 0.5
  done
  if [ -z "$recover_port2" ]; then
    echo "::error::the second daemon never reported a HOSTNAME PROXY port (NET-026)"
    echo "--- min ls output ---"; printf '%s\n' "${recover_ls2:-<none>}"
    fail
  fi
  if [ "$recover_port2" = "$RECOVER_PIN" ]; then
    echo "::error::both daemons report the same proxy port 127.0.0.1:$recover_port2 — the second one should have relocated off its busy default (NET-025)"
    fail
  fi
  echo "two daemons: one on 127.0.0.1:$RECOVER_PIN, two on 127.0.0.1:$recover_port2 (both from min ls discovery)"

  # The in-box half of NET-027 needs a box whose sandbox can exec. Same
  # gate as the proxy proof's: fail on CI or a VM lane, degrade honestly
  # for a developer host whose sandbox denies the nested namespaces.
  if ! mnl session exec "$recover_sid" 'true' >"$WORK/recover-execgate.err" 2>&1 \
     && ! { sleep 1; mnl session exec "$recover_sid" 'true' >"$WORK/recover-execgate.err" 2>&1; }; then
    if recover_gate_can_skip; then
      echo "::warning::two-daemon routing half SKIPPED — this host cannot run a session sandbox"
      echo "  (exec: $(head -n1 "$WORK/recover-execgate.err" 2>/dev/null || true))"
      echo "  asserted here: both daemons came up on distinct discovered ports (the lines above)."
      echo "  the per-daemon routing matrix needs boxes that can exec; on CI or a VM lane this gate fails instead"
      recover_two_daemon_cleanup
      echo "::endgroup::"
      return 0
    fi
    echo "::error::this lane cannot run a session sandbox, so no in-box request can be sent"
    echo "  (exec: $(head -n1 "$WORK/recover-execgate.err" 2>/dev/null || true))"
    fail
  fi

  SECOND_SEED_DIR="$(hook_mktemp /tmp/mnlr2.XXXXXX)"
  hook_seed_preamble > "$SECOND_SEED_DIR/minimal.toml"
  mkdir "$SECOND_SEED_DIR/.git"
  second_sid="$(cd "$SECOND_SEED_DIR" && mnl2 session activate . --no-prompt \
    --name e2e-second 2>"$WORK/recover-second-activate.err")" \
    || { echo "::error::'min session activate' on the second daemon failed"
         echo "--- stderr ---"; cat "$WORK/recover-second-activate.err" 2>/dev/null || true
         fail; }
  second_sid="$(printf '%s\n' "$second_sid" | tail -n1 | tr -d '\r')"
  echo "second box: $second_sid on daemon 2"

  recover_start_responder mnl "$recover_sid" "$RECOVER_BOX_PORT"
  recover_start_responder mnl2 "$second_sid" "$SECOND_BOX_PORT"

  # The routing matrix: each name routes through its OWN daemon — and
  # through the port `min ls` discovered for it — while the OTHER daemon
  # refuses it, because a registry is per daemon (NET-027).
  recover_route mnl "$recover_sid" "127.0.0.1:$RECOVER_PIN" \
    "http://e2e-recover.min.internal:$RECOVER_BOX_PORT/" \
    "NET-027: box A's name routes through daemon 1 on the port min discovered"
  recover_route_want 200 "$RECOVER_BOX_MARKER"
  recover_route mnl2 "$second_sid" "127.0.0.1:$recover_port2" \
    "http://e2e-second.min.internal:$SECOND_BOX_PORT/" \
    "NET-027: box B's name routes through daemon 2 on the port min discovered"
  recover_route_want 200 "$RECOVER_BOX_MARKER"
  recover_route mnl "$recover_sid" "127.0.0.1:$recover_port2" \
    "http://e2e-recover.min.internal:$RECOVER_BOX_PORT/" \
    "NET-027: daemon 2 does not know box A's name — it refuses"
  recover_route_want 502 ""
  recover_route mnl2 "$second_sid" "127.0.0.1:$RECOVER_PIN" \
    "http://e2e-second.min.internal:$SECOND_BOX_PORT/" \
    "NET-027: daemon 1 does not know box B's name — it refuses"
  recover_route_want 502 ""

  # Daemon 2's log tells its half of the story: the relocation warn (its
  # default was busy) and the serving record naming the selected port.
  recover_reloc_record=""
  for _ in $(seq 1 20); do
    recover_reloc_record="$(grep -F -- 'the default hostname-proxy port is busy' \
      "$(recover_daemon2_log)" 2>/dev/null | tail -n1 || true)"
    [ -n "$recover_reloc_record" ] && break
    sleep 0.5
  done
  if [ -z "$recover_reloc_record" ]; then
    echo "::error::no relocation record in daemon 2's log — its default port was busy, so NET-025's warn is owed"
    echo "--- daemon 2 log (tail) ---"; tail -20 "$(recover_daemon2_log)" 2>/dev/null || true
    fail
  fi
  echo "daemon 2 log: $recover_reloc_record"

  recover_serving2_record="$(grep -F -- 'hostname proxy is serving on its selected port' \
    "$(recover_daemon2_log)" 2>/dev/null | tail -n1 || true)"
  case "$recover_serving2_record" in
    *"\"port\":$recover_port2"*) ;;
    "" | *)
      echo "::error::daemon 2's serving record does not name the selected port $recover_port2"
      echo "--- record ---"; printf '%s\n' "${recover_serving2_record:-<none>}"
      fail
      ;;
  esac
  echo "daemon 2 log: $recover_serving2_record"

  recover_two_daemon_cleanup

  echo "beat C (lost switch datapath) SKIPPED on this native lane: there is no minvmd switch here —"
  echo "  that record is the VM lanes' assertion (its emission is pinned by the minvmd net.rs unit tests)"
  echo "hostnames recover and two daemons route OK (reason+remedy at activate and ls, cleared without a restart, second daemon selected and both routed)"
  echo "::endgroup::"
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
# ---------------------------------------------------------------------------
# NET-132: the host-side stack peer owns the proxy's infrastructure address.
# These two cases are gated exactly like the own-IP proof: a switch must exist
# (`MINVMD_GVPROXY_BIN` on the lane), and nothing else. The own-address box
# attaches inside the guest on the VM-backed lanes, so the host's /dev/net/tun
# and user namespaces say nothing about whether it can; a box that fails to
# attach is a failure of the case, not a skip. Without a switch the case prints
# what it cannot assert and returns 0.
#
# What is proved:
#   * switch_steers_proxy_mac_frames_to_the_host_stack: a frame addressed to the
#     proxy's MAC (52:54:00:40:ff:fc) leaves the guest, reaches the host-side
#     peer, and is answered (or reset/ICMP'd) back to the originating box, never
#     to any other box.
#   * switch_answers_no_arp_for_the_proxy_address: the gvproxy switch itself does
#     not answer ARP for 100.64.255.252; the host stack peer does.
proof_switch_steers_proxy_mac_frames_to_the_host_stack() {
  echo "::group::switch steers proxy-MAC frames to the host stack peer (NET-132)"
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "switch_steers_proxy_mac_frames_to_the_host_stack SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
    echo "::endgroup::"
    return 0
  fi

  # When we can run, the test is identical in shape to the own-IP proof: boot an
  # own-address box and, from inside it, send an Ethernet frame addressed to the
  # proxy MAC. Because the box has no raw socket privileges (NET-083), we instead
  # route to the proxy's address: the in-box stack emits the frame with the right
  # destination MAC and source MAC derived from the box's lease. A TCP SYN to the
  # proxy address on an unlistened port proves the frame reached the peer (it
  # returns a TCP RST) and that the answer comes back to this box only (no other
  # guest sees it). The RST is what the BepHost unit test already pins; here we
  # prove the end-to-end path through the switch handles the proxy MAC correctly.
  local bep_sid bep_ip proxy_ip proxy_mac
  proxy_ip="100.64.255.252"
  proxy_mac="52:54:00:40:ff:fc"

  BEP_SEED_DIR="$(hook_mktemp /tmp/mnlbep.XXXXXX)"
  hook_seed_preamble > "$BEP_SEED_DIR/minimal.toml"
  mkdir "$BEP_SEED_DIR/.git"

  bep_sid="$(cd "$BEP_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-bep-mac --network own_ip 2>"$WORK/bep-mac.err")" || {
    echo "::error::'min session activate --network own_ip' failed for BEP MAC test"
    cat "$WORK/bep-mac.err" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  }
  bep_sid="$(printf '%s\n' "$bep_sid" | tail -n1 | tr -d '\r')"

  if ! mnl session exec "$bep_sid" sh -c 'cat /proc/net/dev' >"$WORK/bep-dev.out" 2>"$WORK/bep-dev.err"; then
    echo "::error::could not read /proc/net/dev from the own-IP box"
    cat "$WORK/bep-dev.err" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  fi
  if [ "$(grep -c ':' "$WORK/bep-dev.out")" -lt 2 ]; then
    echo "::error::own-IP box has no tap interface; the switch did not attach"
    cat "$WORK/bep-dev.out"
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  fi

  # The box's lease address — the source the SYN below carries. A session
  # rootfs has no iproute2, so it is read from /proc/net/fib_trie (every
  # local address sits on a `|-- A.B.C.D` line followed by `/32 host LOCAL`)
  # and parsed here on the host, like the own-IP proof reads its facts.
  if ! mnl session exec "$bep_sid" sh -c 'cat /proc/net/fib_trie' >"$WORK/bep-fib.out" 2>"$WORK/bep-fib.err"; then
    echo "::error::could not read /proc/net/fib_trie from the own-IP box"
    cat "$WORK/bep-fib.err" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  fi
  bep_ip="$(awk '/\|--/ { addr = $2 }
                 /\/32 host LOCAL/ && addr !~ /^127\./ { print addr; exit }' "$WORK/bep-fib.out")"
  if [ -z "$bep_ip" ]; then
    echo "::error::could not determine the own-IP box's switch address from /proc/net/fib_trie"
    echo "--- fib_trie ---"; cat "$WORK/bep-fib.out" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  fi

  # RST proves the peer received the frame and answered; a non-RST fast refusal
  # would mean the switch dropped or mis-routed it. socat carries the probe: it
  # is a launcher baseline package every box ships at /usr/bin, and a connect
  # the peer resets fails at once with "Connection refused" on its stderr,
  # while a dropped SYN runs into connect-timeout.
  mnl session exec "$bep_sid" 'test -x /usr/bin/socat' >/dev/null 2>&1 || {
    echo "::error::the session has no socat at /usr/bin/socat (a launcher baseline package — every box ships one)"
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  }
  # The reset alone does not prove the steer: a reset from the gateway's own
  # stack would read the same. The ARP entry the SYN left behind names the MAC
  # the frame went to, so the proof reads it from the same box after the probe
  # and requires the peer's MAC, not the gateway's.
  mnl session exec "$bep_sid" \
    "/usr/bin/socat /dev/null TCP:$proxy_ip:443,connect-timeout=5 2>/tmp/bep-mac-probe.err; cat /tmp/bep-mac-probe.err >&2; cat /proc/net/arp" \
    >"$WORK/bep-mac-arp.out" 2>"$WORK/bep-mac-probe.err" || true
  local bep_mac_seen
  bep_mac_seen="$(awk -v ip="$proxy_ip" '$1 == ip { print $4; exit }' "$WORK/bep-mac-arp.out")"
  if grep -q "Connection refused" "$WORK/bep-mac-probe.err" && [ "$bep_mac_seen" = "$proxy_mac" ]; then
    echo "BEP MAC test OK: TCP SYN from $bep_ip to $proxy_ip went to $proxy_mac, reached the host stack peer and returned RST"
  elif [ -n "$bep_mac_seen" ] && [ "$bep_mac_seen" != "$proxy_mac" ]; then
    echo "::error::TCP SYN from $bep_ip to $proxy_ip went to $bep_mac_seen, not the peer's $proxy_mac; the switch did not steer the proxy-MAC frame"
    cat "$WORK/bep-mac-probe.err" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  else
    echo "::error::TCP SYN from $bep_ip to $proxy_ip did not produce a RST; proxy-MAC frame may not have reached the peer"
    cat "$WORK/bep-mac-probe.err" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  fi

  mnl session destroy --force "$bep_sid" >/dev/null 2>&1 || true
  rm -rf "$BEP_SEED_DIR"
  BEP_SEED_DIR=""
  echo "switch steers proxy-MAC frames to the host stack peer OK"
  echo "::endgroup::"
}

proof_switch_answers_no_arp_for_the_proxy_address() {
  echo "::group::switch answers no ARP for the proxy address (NET-132)"
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ]; then
    echo "switch_answers_no_arp_for_the_proxy_address SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch)"
    echo "::endgroup::"
    return 0
  fi

  # The BepHost unit test pins this for the peer's stack; the e2e case checks
  # that gvproxy itself does not answer. We boot an own-address box and make
  # its kernel ARP for the proxy address: the MAC it resolves must be the
  # peer's, not the gateway's.
  local bep_sid proxy_ip proxy_mac bep_arp_mac
  proxy_ip="100.64.255.252"
  proxy_mac="52:54:00:40:ff:fc"

  BEP_SEED_DIR="$(hook_mktemp /tmp/mnlbep.XXXXXX)"
  hook_seed_preamble > "$BEP_SEED_DIR/minimal.toml"
  mkdir "$BEP_SEED_DIR/.git"

  bep_sid="$(cd "$BEP_SEED_DIR" && mnl session activate . --no-prompt \
    --name e2e-bep-arp --network own_ip 2>"$WORK/bep-arp.err")" || {
    echo "::error::'min session activate --network own_ip' failed for BEP ARP test"
    cat "$WORK/bep-arp.err" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  }
  bep_sid="$(printf '%s\n' "$bep_sid" | tail -n1 | tr -d '\r')"

  # A box ships no arping and no iproute2, so the ARP exchange is observed
  # through what it leaves behind: a connect attempt to the proxy address
  # makes the box's kernel ARP for it (socat is a launcher baseline package at
  # /usr/bin; the connect's own outcome is the steering case's business), and
  # /proc/net/arp then names the MAC that answered. One shell-form string,
  # so the in-box side needs no nested quoting.
  mnl session exec "$bep_sid" 'test -x /usr/bin/socat' >/dev/null 2>&1 || {
    echo "::error::the session has no socat at /usr/bin/socat (a launcher baseline package — every box ships one)"
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  }
  mnl session exec "$bep_sid" \
    "/usr/bin/socat /dev/null TCP:$proxy_ip:443,connect-timeout=5 >/dev/null 2>&1; cat /proc/net/arp" \
    >"$WORK/bep-arp.out" 2>"$WORK/bep-arp-run.err" || true

  # /proc/net/arp: `IP address  HW type  Flags  HW address  Device  Mask`;
  # an unanswered request leaves an incomplete entry (all-zero HW address).
  bep_arp_mac="$(awk -v ip="$proxy_ip" '$1 == ip { print $4; exit }' "$WORK/bep-arp.out")"
  if [ "$bep_arp_mac" = "$proxy_mac" ]; then
    echo "BEP ARP test OK: proxy address $proxy_ip resolves to peer MAC $proxy_mac, not the gateway"
  else
    echo "::error::proxy address $proxy_ip did not resolve to the peer MAC $proxy_mac (got '${bep_arp_mac:-<no entry>}'); the switch may be answering ARP itself"
    echo "--- /proc/net/arp ---"; cat "$WORK/bep-arp.out" 2>/dev/null || true
    echo "--- stderr ---"; cat "$WORK/bep-arp-run.err" 2>/dev/null || true
    rm -rf "$BEP_SEED_DIR"
    BEP_SEED_DIR=""
    fail
  fi

  mnl session destroy --force "$bep_sid" >/dev/null 2>&1 || true
  rm -rf "$BEP_SEED_DIR"
  BEP_SEED_DIR=""
  echo "switch answers no ARP for the proxy address OK"
  echo "::endgroup::"
}

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
  # produced, and nothing else. The file writer is asynchronous, and the
  # daemon logs plenty besides the request while one is in flight — on CI the
  # `minimald::server` SSH-handshake warnings chief among them — so the window
  # is filtered to the net modules this case is about (their `target`, the
  # module path in the JSON record). That is also what makes a routed request
  # print its gap instead of an unrelated record: the proxy logs every
  # refusal and both deprecation notices, and nothing for a request it serves.
  # Callers poll this.
  proxy_daemon_log_since() {
    local f
    f="$(proxy_daemon_log)"
    [ -n "$f" ] || return 0
    tail -n "+$(($1 + 1))" "$f" | grep -E -- '"target": *"minimald::net::' || true
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
  # $1 = the box's session id, $2 = the label the prints carry, $3 = the
  # box's address mode: `host` (shares its host's network) or `own` (a
  # lease of its own on the switch).
  proxy_assert_host_by_name() {
    proxy_request "$1" "$2: host.min.internal reaches the host's loopback" \
      "http://host.min.internal:$PROXY_HOST_PORT/marker" direct ""
    proxy_want 200 "$PROXY_HOST_MARKER" ""
    # What the box resolved the name to — read from curl's write-out, not its
    # verbose trace. `%{remote_ip}` is the address of the connection curl made,
    # and write-out spelling has been stable for a decade; the -v trace has not:
    # the proof's first CI run grepped its `Connected to host (ip) port N`
    # line, which the curl every box ships (upstream pins 8.22) stopped
    # printing — it says `Established connection to host (ip port N) from local
    # port M` — so the grep came back empty and the whole lane failed. What
    # the answer is depends on where the box stands, not on the lane: a
    # host-address box on a native host shares the host's namespace, so the
    # HostNet plan pins 127.0.0.1 in its /etc/hosts — asserted there, it is
    # pinned. Every other box resolves the switch zone's host alias, which
    # gvproxy NATs to the host's loopback — a host-address box on a VM host,
    # and an own-address box on ANY host, native included: its lease is a
    # switch address, so the switch zone answers, never /etc/hosts (the
    # own-ip plan carries no hosts entry). Printed, not asserted, so a lane
    # on a custom subnet does not fail here.
    proxy_resolved="$(mnl session exec "$1" \
      "curl -sS --max-time 10 -o /dev/null -w '%{remote_ip}' http://host.min.internal:$PROXY_HOST_PORT/marker" \
      2>"$WORK/proxy-hostresolve.err" | tail -n1 | tr -d '\r\n')" || true
    echo "$2: host.min.internal resolved in the box: ${proxy_resolved:-<curl never connected>}"
    # The 127.0.0.1 pin belongs to the host-address box on a native host —
    # gated on the box's mode, never on the lane: a native host driving a
    # switch (a developer run) puts the own-address half through this same
    # function with hook_log_readable true, and its answer is the switch
    # alias, so a lane gate here would fail that run spuriously.
    if [ "${3:-}" = host ] && hook_log_readable && [ "${proxy_resolved:-}" != "127.0.0.1" ]; then
      echo "::error::host.min.internal did not resolve to the host's loopback in the box (expected 127.0.0.1, got '${proxy_resolved:-<none>}')"
      echo "--- curl stderr ---"; cat "$WORK/proxy-hostresolve.err" 2>/dev/null || true
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
  # switch gate is the precedent.
  #
  # A skip is only ever honest on a developer host: a lane that exists to run
  # these assertions and cannot is a red lane, not a degraded proof, because a
  # green run that asserted nothing is precisely the regression these gates
  # must never hide. CI sets CI=true on every lane; E2E_VM marks the VM-backed
  # targets, where the boxes live in the guest, so a tripped gate there is a
  # lane-level fault by definition. Only a host with neither may skip, and it
  # is told so in a warning annotation, never as part of a passing transcript.
  proxy_gate_can_skip() { [ -z "${CI:-}" ] && [ -z "$E2E_VM" ]; }

  # 1. The session's sandbox program. A host that is itself a sandbox — a
  #    plain container, or a session box like the ones this product hosts —
  #    denies the nested mount namespaces a box's rootfs needs, and the
  #    session program then dies at spawn: no probe inside the box can run.
  #    One throwaway exec decides; the registration above already proved the
  #    daemon half of NET-001 on its own.
  if ! mnl session exec "$proxy_sid" 'true' >"$WORK/proxy-execgate.err" 2>&1 \
     && ! { sleep 1; mnl session exec "$proxy_sid" 'true' >"$WORK/proxy-execgate.err" 2>&1; }; then
    if proxy_gate_can_skip; then
      echo "::warning::min.internal proxy proof SKIPPED — this host cannot run a session sandbox"
      echo "  (exec: $(head -n1 "$WORK/proxy-execgate.err" 2>/dev/null || true))"
      echo "  asserted here: the registration record above, the daemon half of NET-001."
      echo "  routing, refusals and the deprecation notices need a host whose boxes can run;"
      echo "  on CI or a VM lane this gate fails instead"
      mnl session destroy --force "$proxy_sid" >/dev/null 2>&1 || true
      echo "::endgroup::"
      return 0
    fi
    echo "::error::this lane cannot run a session sandbox, so no probe inside a box can run: nothing this case asserts can be asserted"
    echo "  (exec: $(head -n1 "$WORK/proxy-execgate.err" 2>/dev/null || true))"
    echo "  on a VM lane the boxes live in the guest, so this is a lane-level fault"
    fail
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
  for proxy_bind_try in 1 2 3 4 5; do
    proxy_ls_out="$(mnl ls 2>&1)"
    case "$proxy_ls_out" in
      *"session hostnames will not route"*) proxy_bind_taken=1 ;;
      *) proxy_bind_taken=0; break ;;
    esac
    [ "$proxy_bind_try" = 5 ] || sleep 3
  done
  if [ "$proxy_bind_taken" -eq 1 ]; then
    if proxy_gate_can_skip; then
      proxy_start_host_listener
      proxy_assert_host_by_name "$proxy_sid" "NET-003 (degraded)" host
      echo "::warning::min.internal proxy routing SKIPPED — another daemon owns 127.0.0.1:7654 on this host"
      echo "  asserted here: host.min.internal, straight from the box"
      hook_log_readable && echo "  and the registration record above, the daemon half of NET-001"
      echo "  routing and the refusals need this run's daemon to own :7654; on CI or a VM"
      echo "  lane this gate fails instead"
      mnl session destroy --force "$proxy_sid" >/dev/null 2>&1 || true
      echo "::endgroup::"
      return 0
    fi
    echo "::error::another daemon owns 127.0.0.1:7654, so this run's daemon cannot route session hostnames: every probe through the proxy would reach a daemon that knows nothing about this run's boxes"
    echo "--- min ls ---"; printf '%s\n' "${proxy_ls_out:-}"
    fail
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
  proxy_assert_host_by_name "$proxy_sid" "NET-003" host

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
    proxy_assert_host_by_name "$PROXY_OWN_SID" "NET-003 (own-address box)" own

    # NET-004: the deprecated literal itself. It must still reach the host's
    # loopback, and the box's egress relay must notice the connection — the
    # notice is the reason the address is deprecated. The relay runs in the
    # daemon, and every lane that has a switch (MINVMD_GVPROXY_BIN, the gate
    # around this half) also runs with E2E_VM=1 — the justfile's `e2e-env`
    # and the KVM lane set the pair together — so the `hook_log_readable`
    # branch below is UNREACHABLE FROM CI: it serves developer runs only, a
    # host driving a native daemon against a switch by hand. The switch lanes
    # CI does run assert the routing and name the notice, whose emission the
    # switch.rs unit tests pin.
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
# The hostname proxy honours the switch's rules, end to end (NET-069, NET-070,
# NET-071, NET-135). The rule is parity, and parity is proved by PAIRS: the
# same target attempted directly and through the proxy, the two attempts
# printed side by side with the refusal each got. A readable-log lane also
# prints the daemon record a refusal left, so the transcript shows the proxy's
# answer beside the direct leg's; on a VM lane the records are the guest
# daemon's, and the `min bug` bundle a failing run writes (see `fail`) carries
# them — the statuses pair the refusals meanwhile.
#
# The pairing covers three shapes:
#   * an undeclared port — refused by the OS on the direct leg (host-address
#     box: nothing listens), refused by the proxy with that same refusal as
#     its reason (502), and on a VM lane refused by the target's ingress
#     declaration on BOTH legs (dropped SYN direct, 403 proxied);
#   * a caller whose egress rules deny the target — the caller's own gate
#     drops its direct SYN, and the proxy refuses its request before dialing
#     (403), against the same request routing from an ungated box;
#   * the protocol discipline (NET-135) — the HTTP/2 prior-knowledge preface
#     is closed without a status where a direct connection is served, and an
#     h2c upgrade offer is stripped where a direct connection passes it
#     through, both read from the upstream's own echo.
proof_proxy_refuses_like_direct() {
  echo "::group::the hostname proxy honours the switch's rules (NET-069/070/071, NET-135)"

  # The daemon's file log, newest first, and the net-module records it gained
  # since line $1 — the window ONE paired attempt produces. Same shape as the
  # min.internal proof's helpers above, whose filtering note applies here too
  # (the daemon logs plenty besides a request; only the net modules are this
  # case's business). Callers poll for a pattern.
  par_daemon_log() {
    find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null \
      | sort | tail -n1
  }
  par_log_lines() {
    local f
    f="$(par_daemon_log)"
    if [ -n "$f" ]; then wc -l < "$f"; else printf '0\n'; fi
  }
  par_log_since() {
    local f
    f="$(par_daemon_log)"
    [ -n "$f" ] || return 0
    tail -n "+$(($1 + 1))" "$f" | grep -E -- '"target": *"minimald::net::' || true
  }
  # The window that has gained a record matching $2 within ~5s (the file
  # writer is asynchronous), else the last window — so the failing assert
  # below prints what actually landed.
  par_log_wait() {
    local before="$1" want="$2" i w=""
    for i in $(seq 1 20); do
      w="$(par_log_since "$before")"
      case "$w" in *"$want"*) break ;; esac
      sleep 0.25
    done
    printf '%s\n' "$w"
  }

  # One DIRECT attempt from a box: curl's exit code and its stderr ARE the
  # refusal a direct connection gets — an OS-refused connection is curl 7, a
  # SYN a target's gate silently dropped is a connect timeout, curl 28.
  par_direct() { # $1 box, $2 url, $3 max-time
    mnl session exec "$1" "curl -sS --max-time $3 -o /dev/null '$2'" \
      2>"$WORK/par-direct.err"
    PAR_RC=$?
  }
  # One proxied attempt from a box: the status line and the body, via the
  # proxy at $3 — host loopback from a host-address box, the daemon's own
  # switch address from a box with a lease.
  par_proxied() { # $1 box, $2 url, $3 proxy address, $4 max-time
    local out
    out="$(mnl session exec "$1" \
      "curl -sS --max-time $4 -x http://$3 -o /home/par.body -w '%{http_code}' '$2'" \
      2>"$WORK/par-proxied.err")" || true
    PAR_STATUS="$(printf '%s\n' "$out" | tail -n1 | tr -d '\r\n')"
    PAR_BODY="$(mnl session exec "$1" 'cat /home/par.body' 2>/dev/null || true)"
  }
  # The paired print — the two lines this case owes the transcript per pair.
  par_pair() { # $1 label, $2 the direct attempt's line, $3 the proxied one
    printf 'pair %s\n' "$1"
    printf '  direct:  %s\n' "$2"
    printf '  proxied: %s\n' "$3"
  }

  # The names and ports. Ports are fixed on purpose (the execs that start and
  # probe the responders must agree) and high enough to need no privilege;
  # 18080-18084 and 19090/19091 belong to the proofs around this one.
  PAR_NAME="e2e-par"                # the origin box, host-address, every lane
  PAR_OWN_NAME="e2e-par-own"        # the target box, own-address, VM lanes
  PAR_CALLER_NAME="e2e-par-caller"  # the denied caller, own-address, VM lanes
  PAR_ECHO_PORT=18085               # the in-box echo responder (served + routed)
  PAR_DEAD_PORT=18086               # nothing listens: the OS refusal, both legs
  PAR_OWN_PORT=18087                # the target's published port (ext == int)
  PAR_OWN_CLOSED_PORT=18088         # never published: dropped direct, 403 proxied
  PAR_OWN_MARKER="PAR_OWN_ROUTED_OK"

  # The request origin: a host-address box, sharing its host's loopback —
  # which is how it reaches the proxy at 127.0.0.1:7654, on every lane.
  PAR_SEED_DIR="$(hook_mktemp /tmp/mnlpd.XXXXXX)"
  hook_seed_preamble > "$PAR_SEED_DIR/minimal.toml"
  mkdir "$PAR_SEED_DIR/.git"
  par_sid="$(cd "$PAR_SEED_DIR" && mnl session activate . --no-prompt \
    --name "$PAR_NAME" 2>"$WORK/par-activate.err")" || {
    echo "::error::'min session activate' for the parity proof's origin box failed"
    echo "--- stderr ---"; cat "$WORK/par-activate.err" 2>/dev/null || true
    fail
  }
  par_sid="$(printf '%s\n' "$par_sid" | tail -n1 | tr -d '\r')"

  # ---- capability gates: what THIS host can run ---------------------------
  # The same two gates the min.internal proof runs, for the same reasons; a
  # skip is honest only on a developer host (no CI, no VM lane).
  par_gate_can_skip() { [ -z "${CI:-}" ] && [ -z "$E2E_VM" ]; }

  # 1. The session's sandbox program. A host that is itself a sandbox denies
  #    the nested mount namespaces a box's rootfs needs: no probe inside a
  #    box can run, and nothing this case asserts can be asserted.
  if ! mnl session exec "$par_sid" 'true' >"$WORK/par-execgate.err" 2>&1 \
     && ! { sleep 1; mnl session exec "$par_sid" 'true' >"$WORK/par-execgate.err" 2>&1; }; then
    if par_gate_can_skip; then
      echo "::warning::proxy parity proof SKIPPED — this host cannot run a session sandbox"
      echo "  (exec: $(head -n1 "$WORK/par-execgate.err" 2>/dev/null || true))"
      mnl session destroy --force "$par_sid" >/dev/null 2>&1 || true
      echo "::endgroup::"
      return 0
    fi
    echo "::error::this lane cannot run a session sandbox, so no probe inside a box can run: nothing this case asserts can be asserted"
    echo "  (exec: $(head -n1 "$WORK/par-execgate.err" 2>/dev/null || true))"
    echo "  on a VM lane the boxes live in the guest, so this is a lane-level fault"
    fail
  fi

  # 2. The hostname proxy's listen address (:7654, EGRESS_PROXY_PORT). A host
  #    that already runs a minimald has it taken, and every probe through the
  #    proxy would reach a daemon that knows nothing about this run's boxes.
  par_bind_taken=0
  for par_bind_try in 1 2 3 4 5; do
    par_ls_out="$(mnl ls 2>&1)"
    case "$par_ls_out" in
      *"session hostnames will not route"*) par_bind_taken=1 ;;
      *) par_bind_taken=0; break ;;
    esac
    [ "$par_bind_try" = 5 ] || sleep 3
  done
  if [ "$par_bind_taken" -eq 1 ]; then
    if par_gate_can_skip; then
      echo "::warning::proxy parity proof SKIPPED — another daemon owns 127.0.0.1:7654 on this host"
      echo "  every probe through the proxy would reach a daemon that knows nothing about this run's boxes"
      mnl session destroy --force "$par_sid" >/dev/null 2>&1 || true
      echo "::endgroup::"
      return 0
    fi
    echo "::error::another daemon owns 127.0.0.1:7654, so this run's daemon cannot route session hostnames: every probe through the proxy would reach a daemon that knows nothing about this run's boxes"
    echo "--- min ls ---"; printf '%s\n' "${par_ls_out:-}"
    fail
  fi

  # socat carries the responders below and base64 carries the echo script in;
  # both are launcher-baseline packages (crates/minimald/src/session_host.rs
  # BASELINE_PACKAGES), at /usr/bin — packages install with --prefix=/usr and
  # the generic rootfs has no /bin, so the absolute paths are the daemon's own
  # convention for in-box argv.
  mnl session exec "$par_sid" 'test -x /usr/bin/socat' >/dev/null 2>&1 \
    || { echo "::error::the session has no socat at /usr/bin/socat (a launcher baseline package — every box ships one)"; fail; }
  mnl session exec "$par_sid" 'test -x /usr/bin/base64' >/dev/null 2>&1 \
    || { echo "::error::the session has no base64 at /usr/bin/base64 (a coreutils package — every box ships it)"; fail; }

  # The echo responder the protocol pairs need: it answers every head with a
  # 200 whose body is the head it received, lines joined with '|'. The body is
  # the assertion: what the UPSTREAM received is what the echo carries, so the
  # strip's effect — and the direct leg's pass-through — is read from the box
  # that would have had to honour the upgrade. Delivered through base64
  # (python3 encodes it host-side; python3 is an e2e prerequisite on every
  # lane), because a shell-quoted delivery would fight the script's own
  # quoting.
  par_echo_script="$(cat <<'PAR_EO'
head=
while IFS= read -r line; do
  line=${line%$'\r'}
  [ -n "$line" ] || break
  head="$head|$line"
done
printf 'HTTP/1.1 200 OK\r\nContent-Length: %s\r\nConnection: close\r\n\r\n%s' "${#head}" "$head"
PAR_EO
)"
  par_echo_b64="$(printf '%s' "$par_echo_script" | python3 -c \
    'import base64,sys; sys.stdout.write(base64.b64encode(sys.stdin.buffer.read()).decode())')"
  mnl session exec "$par_sid" "printf %s '$par_echo_b64' | /usr/bin/base64 -d > /home/par-echo.sh" \
    >/dev/null 2>"$WORK/par-echo.err" \
    || { echo "::error::could not write the echo responder's script"; cat "$WORK/par-echo.err" 2>/dev/null || true; fail; }
  # `nohup ... &` is the documented detach form (docs/reference/cli-min.md,
  # `session exec`): the responder has to outlive the exec that starts it.
  mnl session exec "$par_sid" \
    "nohup /usr/bin/socat TCP-LISTEN:$PAR_ECHO_PORT,reuseaddr,fork SYSTEM:'/usr/bin/bash /home/par-echo.sh' >/dev/null 2>&1 &" \
    >/dev/null 2>"$WORK/par-echo.err" \
    || { echo "::error::could not start the echo responder"; cat "$WORK/par-echo.err" 2>/dev/null || true; fail; }
  par_ready=""
  for _ in $(seq 1 40); do
    if [ "$(mnl session exec "$par_sid" \
      "curl -sS --max-time 5 -o /home/par-ready.body -w '%{http_code}' http://127.0.0.1:$PAR_ECHO_PORT/" \
      2>/dev/null || true)" = "200" ]; then
      par_ready=1; break
    fi
    sleep 0.25
  done
  [ -n "$par_ready" ] || {
    echo "::error::the echo responder never answered a direct curl — the proxy is not in the picture yet"
    echo "--- socat exec stderr ---"; cat "$WORK/par-echo.err" 2>/dev/null || true
    fail
  }

  # ---- the baseline: a published port routes ------------------------------
  # Every refusal below is the proxy's decision, not a broken route; this is
  # the clean 200 that says the routing machinery is live when they are read.
  # The echo body carries the request the upstream received.
  par_proxied "$par_sid" "http://$PAR_NAME.min.internal:$PAR_ECHO_PORT/" "127.0.0.1:7654" 20
  echo "routed baseline: GET http://$PAR_NAME.min.internal:$PAR_ECHO_PORT/ via the proxy -> HTTP ${PAR_STATUS:-<none>}"
  [ "${PAR_STATUS:-}" = 200 ] || {
    echo "::error::the routed baseline did not return 200 (got '${PAR_STATUS:-<none>}')"
    echo "--- curl stderr ---"; cat "$WORK/par-proxied.err" 2>/dev/null || true
    fail
  }
  case "$PAR_BODY" in *"$PAR_NAME.min.internal"*) ;; *)
    echo "::error::the routed baseline's answer does not echo the request that reached the upstream"
    echo "--- body ---"; printf '%s\n' "$PAR_BODY" | head -5
    fail ;;
  esac

  # ---- pair 1 (NET-069, NET-071): an undeclared port, host-address box ----
  # The box declares no ingress at all, so the switch has no gate to sit
  # between: the OS refuses the DIRECT connection (nothing listens), and the
  # proxy must hand the request to exactly that refusal — a 502 whose reason
  # is the upstream's refusal — instead of swallowing it or dialing wide.
  par_before="$(par_log_lines)"
  par_direct "$par_sid" "http://127.0.0.1:$PAR_DEAD_PORT/" 5
  par_direct_rc="$PAR_RC"
  par_direct_line="GET http://127.0.0.1:$PAR_DEAD_PORT/ -> curl exit $PAR_RC: $(head -n1 "$WORK/par-direct.err" 2>/dev/null || true)"
  par_proxied "$par_sid" "http://$PAR_NAME.min.internal:$PAR_DEAD_PORT/" "127.0.0.1:7654" 20
  par_pair "an undeclared port, host-address box" \
    "$par_direct_line" \
    "GET http://$PAR_NAME.min.internal:$PAR_DEAD_PORT/ via the proxy -> HTTP ${PAR_STATUS:-<none>} ($(head -n1 "$WORK/par-proxied.err" 2>/dev/null || true))"
  [ "$par_direct_rc" -eq 7 ] || {
    echo "::error::the direct attempt to the undeclared port did not end in a refused connection (curl exit $par_direct_rc, expected 7)"
    echo "--- curl stderr ---"; cat "$WORK/par-direct.err" 2>/dev/null || true
    fail
  }
  [ "${PAR_STATUS:-}" = 502 ] || {
    echo "::error::the proxied attempt to the undeclared port did not get the proxy's 502 (got '${PAR_STATUS:-<none>}')"
    echo "--- curl stderr ---"; cat "$WORK/par-proxied.err" 2>/dev/null || true
    fail
  }
  if hook_log_readable; then
    par_pair_log="$(par_log_wait "$par_before" 'the upstream box refused the connection')"
    printf '%s\n' "$par_pair_log" | sed 's/^/  daemon log: /'
    case "$par_pair_log" in *"the upstream box refused the connection"*) ;; *)
      echo "::error::the proxy did not log the upstream refusal beside the direct attempt's refusal"
      echo "--- daemon log (tail) ---"; tail -20 "$(par_daemon_log)" 2>/dev/null || true
      fail ;;
    esac
    case "$par_pair_log" in *'"host":"'"$PAR_NAME.min.internal"'"'*) ;; *)
      echo "::error::the refusal record does not name the host the request asked for"
      echo "--- record ---"; printf '%s\n' "$par_pair_log"
      fail ;;
    esac
  else
    echo "  (the refusal record is the guest daemon's on this lane — a failing run's diagnostics bundle carries it)"
  fi

  # ---- pair 2 (NET-135): the HTTP/2 prior-knowledge preface ---------------
  # The same bytes to both: to the echo upstream directly (an HTTP/1.1 server
  # serves them as a request head, which is what the direct half shows) and
  # to the proxy, which routes HTTP/1.1 requests and CONNECT tunnels only —
  # it closes instead of answering, because there is no protocol switch
  # behind it to offer and tunneling one would bypass the routing core's
  # refusals entirely.
  par_before="$(par_log_lines)"
  par_h2_direct="$(mnl session exec "$par_sid" \
    "printf 'PRI * HTTP/2.0\r\n\r\n' | /usr/bin/socat -t 3 - TCP:127.0.0.1:$PAR_ECHO_PORT" \
    2>"$WORK/par-h2-direct.err" || true)"
  par_h2_proxied="$(mnl session exec "$par_sid" \
    "printf 'PRI * HTTP/2.0\r\n\r\n' | /usr/bin/socat -t 3 - TCP:127.0.0.1:7654" \
    2>"$WORK/par-h2-proxy.err" || true)"
  par_pair "the HTTP/2 prior-knowledge preface" \
    "the preface to the echo upstream -> $(printf '%s' "$par_h2_direct" | head -n1)" \
    "the preface to the proxy -> $(if [ -n "$par_h2_proxied" ]; then printf '%s' "$par_h2_proxied" | head -n1; else printf '<no bytes: the connection closed without a status>'; fi)"
  case "$par_h2_direct" in *"200 OK"*) ;; *)
    echo "::error::the echo upstream did not serve the preface as an HTTP/1.1 head — the pair's direct half is broken, not the proxy's close"
    echo "--- socat stderr ---"; cat "$WORK/par-h2-direct.err" 2>/dev/null || true
    fail ;;
  esac
  case "$par_h2_proxied" in
    *"HTTP/"*)
      echo "::error::the proxy answered the HTTP/2 prior-knowledge preface instead of closing it (got: '$(printf '%s' "$par_h2_proxied" | head -n1)')"
      echo "--- socat stderr ---"; cat "$WORK/par-h2-proxy.err" 2>/dev/null || true
      fail ;;
  esac
  echo "  the proxy closed the preface connection: $(printf '%s' "$par_h2_proxied" | wc -c | tr -d ' ') bytes came back"
  if hook_log_readable; then
    par_pair_log="$(par_log_wait "$par_before" 'closed an HTTP/2 prior-knowledge connection')"
    printf '%s\n' "$par_pair_log" | sed 's/^/  daemon log: /'
    case "$par_pair_log" in *"closed an HTTP/2 prior-knowledge connection"*) ;; *)
      echo "::error::the proxy did not log closing the HTTP/2 prior-knowledge connection"
      echo "--- daemon log (tail) ---"; tail -20 "$(par_daemon_log)" 2>/dev/null || true
      fail ;;
    esac
  fi

  # ---- pair 3 (NET-135): an h2c upgrade offer -----------------------------
  # The SAME head to both legs, differing only in where it is dialed: the
  # request line is absolute-form (what a request through a proxy carries)
  # and carries `Upgrade: h2c` with its paired `HTTP2-Settings`. Direct, the
  # echo upstream receives the offer verbatim; through the proxy, the offer
  # must be GONE — the request routed as the HTTP/1.1 request it is, so the
  # upstream cannot answer a protocol switch the proxy cannot splice.
  par_h2c_head() { # $1 the authority the head names, $2 the dial target
    printf "printf 'GET http://%s/ HTTP/1.1\\r\\nHost: %s\\r\\nUpgrade: h2c\\r\\nHTTP2-Settings: AAMAAABkAAQAAP__\\r\\nConnection: Upgrade, HTTP2-Settings\\r\\n\\r\\n' | /usr/bin/socat -t 3 - TCP:%s" \
      "$1" "$1" "$2"
  }
  par_h2c_direct="$(mnl session exec "$par_sid" \
    "$(par_h2c_head "$PAR_NAME.min.internal:$PAR_ECHO_PORT" "127.0.0.1:$PAR_ECHO_PORT")" \
    2>"$WORK/par-h2c-direct.err" || true)"
  par_h2c_proxied="$(mnl session exec "$par_sid" \
    "$(par_h2c_head "$PAR_NAME.min.internal:$PAR_ECHO_PORT" "127.0.0.1:7654")" \
    2>"$WORK/par-h2c-proxy.err" || true)"
  par_pair "an h2c upgrade offer" \
    "the same head, direct to the echo upstream -> $(printf '%s' "$par_h2c_direct" | head -n1)" \
    "the same head, via the proxy -> $(printf '%s' "$par_h2c_proxied" | head -n1)"
  echo "  what the direct upstream received: $(printf '%s' "$par_h2c_direct" | tr -d '\r' | tr '\n' ' ' | cut -c1-160)"
  echo "  what the proxied upstream received: $(printf '%s' "$par_h2c_proxied" | tr -d '\r' | tr '\n' ' ' | cut -c1-160)"
  case "$par_h2c_direct" in *"Upgrade: h2c"*) ;; *)
    echo "::error::the echo upstream did not echo the upgrade offer verbatim — the pair's direct half is broken, not the proxy's strip"
    echo "--- socat stderr ---"; cat "$WORK/par-h2c-direct.err" 2>/dev/null || true
    fail ;;
  esac
  case "$par_h2c_proxied" in *"200 OK"*) ;; *)
    echo "::error::the h2c request did not route as plain HTTP/1.1 (got: '$(printf '%s' "$par_h2c_proxied" | head -n1)')"
    echo "--- socat stderr ---"; cat "$WORK/par-h2c-proxy.err" 2>/dev/null || true
    fail ;;
  esac
  case "$par_h2c_proxied" in
    *h2c*|*"HTTP2-Settings"*)
      echo "::error::the h2c upgrade offer reached the upstream through the proxy — the echo of what it received carries it"
      fail ;;
  esac

  # ---- the switch halves (NET-069/NET-070 across boxes) -------------------
  # Gated on E2E_VM, and the gate is the address fabric these pairs route
  # over, not the switch binary: the pairs go BETWEEN boxes — an own-address
  # target's lease, and a caller whose lease the egress verdict reads. On a
  # VM lane both boxes stand on the switch and the daemon serves the proxy
  # from inside it (a denied caller reaches it at the daemon's own switch
  # address). On a native host the daemon is off the switch — a lease is
  # deliberately not host-answerable (NET-127/128) — so a direct attempt from
  # the host's namespace cannot route to a box's lease, and the pair would
  # not be honest to run there.
  if [ -n "$E2E_VM" ]; then
    PAR_OWN_SEED_DIR="$(hook_mktemp /tmp/mnlpx.XXXXXX)"
    hook_seed_preamble > "$PAR_OWN_SEED_DIR/minimal.toml"
    mkdir "$PAR_OWN_SEED_DIR/.git"
    PAR_OWN_SID="$(cd "$PAR_OWN_SEED_DIR" && mnl session activate . --no-prompt \
      --name "$PAR_OWN_NAME" --network own_ip \
      --ingress "$PAR_OWN_PORT:$PAR_OWN_PORT" 2>"$WORK/par-own.err")" || {
      echo "::error::'min session activate --network own_ip --ingress ...' for the parity proof's target box failed"
      echo "--- stderr ---"; cat "$WORK/par-own.err" 2>/dev/null || true
      fail
    }
    PAR_OWN_SID="$(printf '%s\n' "$PAR_OWN_SID" | tail -n1 | tr -d '\r')"

    # The target's published-port responder: one fixed 200 whose body is the
    # marker, on the INTERNAL port the ingress declaration publishes (the
    # proxy dials the lease at the mapped internal port, and the box's
    # ingress gate admits exactly those) — the min.internal proof's pattern.
    mnl session exec "$PAR_OWN_SID" \
      "body=$PAR_OWN_MARKER; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/par-own200" \
      >/dev/null 2>"$WORK/par-own-resp.err" \
      || { echo "::error::could not write the target box's response"; cat "$WORK/par-own-resp.err" 2>/dev/null || true; fail; }
    mnl session exec "$PAR_OWN_SID" \
      "nohup /usr/bin/socat TCP-LISTEN:$PAR_OWN_PORT,reuseaddr,fork SYSTEM:\"cat /home/par-own200\" >/dev/null 2>&1 &" \
      >/dev/null 2>"$WORK/par-own-resp.err" \
      || { echo "::error::could not start the target box's responder"; cat "$WORK/par-own-resp.err" 2>/dev/null || true; fail; }
    par_own_ready=""
    for _ in $(seq 1 40); do
      if [ "$(mnl session exec "$PAR_OWN_SID" \
        "curl -sS --max-time 5 -o /home/par-ready.body -w '%{http_code}' http://127.0.0.1:$PAR_OWN_PORT/" \
        2>/dev/null || true)" = "200" ]; then
        par_own_ready=1; break
      fi
      sleep 0.25
    done
    [ -n "$par_own_ready" ] || {
      echo "::error::the target box's responder never answered a direct curl"
      echo "--- socat exec stderr ---"; cat "$WORK/par-own-resp.err" 2>/dev/null || true
      fail
    }

    # The published port routes (the baseline the refusals below pair with).
    par_proxied "$par_sid" "http://$PAR_OWN_NAME.min.internal:$PAR_OWN_PORT/" "127.0.0.1:7654" 20
    echo "target baseline: GET http://$PAR_OWN_NAME.min.internal:$PAR_OWN_PORT/ via the proxy -> HTTP ${PAR_STATUS:-<none>}"
    [ "${PAR_STATUS:-}" = 200 ] || {
      echo "::error::the target's published port did not route (got '${PAR_STATUS:-<none>}')"
      echo "--- curl stderr ---"; cat "$WORK/par-proxied.err" 2>/dev/null || true
      fail
    }
    case "$PAR_BODY" in *"$PAR_OWN_MARKER"*) ;; *)
      echo "::error::the routed answer is not the target box's marker response"
      echo "--- body ---"; printf '%s\n' "$PAR_BODY" | head -3
      fail ;;
    esac

    # ---- pair 4: an undeclared port, own-address target --------------------
    # Both legs are refused by the ONE declaration: the proxy refuses the
    # request before dialing (403, where the host, the session and the port
    # are all in hand), and the target's ingress gate drops the direct SYN —
    # a drop is not a reset, so the direct leg is a connect timeout, which is
    # itself the assertion that the gate sat between.
    par_direct "$par_sid" "http://$PAR_OWN_NAME.min.internal:$PAR_OWN_CLOSED_PORT/" 5
    par_direct_rc="$PAR_RC"
    par_direct_line="GET http://$PAR_OWN_NAME.min.internal:$PAR_OWN_CLOSED_PORT/ -> curl exit $PAR_RC: $(head -n1 "$WORK/par-direct.err" 2>/dev/null || true)"
    par_proxied "$par_sid" "http://$PAR_OWN_NAME.min.internal:$PAR_OWN_CLOSED_PORT/" "127.0.0.1:7654" 20
    par_pair "an undeclared port, own-address box" \
      "$par_direct_line" \
      "GET http://$PAR_OWN_NAME.min.internal:$PAR_OWN_CLOSED_PORT/ via the proxy -> HTTP ${PAR_STATUS:-<none>} ($(head -n1 "$WORK/par-proxied.err" 2>/dev/null || true))"
    [ "$par_direct_rc" -eq 28 ] || {
      echo "::error::the direct attempt to the target's unpublished port did not end in a connect timeout (curl exit $par_direct_rc, expected 28) — the target's ingress gate did not drop it, or something answered"
      echo "--- curl stderr ---"; cat "$WORK/par-direct.err" 2>/dev/null || true
      fail
    }
    [ "${PAR_STATUS:-}" = 403 ] || {
      echo "::error::the proxied attempt to the target's unpublished port did not get the proxy's 403 (got '${PAR_STATUS:-<none>}')"
      echo "--- curl stderr ---"; cat "$WORK/par-proxied.err" 2>/dev/null || true
      fail
    }

    # ---- pair 5 (NET-070): a caller whose egress rules deny the target -----
    # The caller is an own-address box whose ONE allowed destination is the
    # daemon's own address on the switch — where the in-guest proxy listens.
    # The switch's resolver and ARP keep their built-in carve-outs, so the
    # box still resolves names; every other destination, the target's lease
    # chief among them, is denied by the caller's own compiled rules. The
    # literal is the default switch subnet's daemon address (the subnet every
    # lane this script runs on uses; the alias literal the min.internal proof
    # prints carries the same posture).
    PAR_CALLER_SEED_DIR="$(hook_mktemp /tmp/mnlpy.XXXXXX)"
    hook_seed_preamble > "$PAR_CALLER_SEED_DIR/minimal.toml"
    mkdir "$PAR_CALLER_SEED_DIR/.git"
    PAR_CALLER_SID="$(cd "$PAR_CALLER_SEED_DIR" && mnl session activate . --no-prompt \
      --name "$PAR_CALLER_NAME" --network own_ip \
      --allow-subnets 100.64.255.253/32 2>"$WORK/par-caller.err")" || {
      echo "::error::'min session activate --network own_ip --allow-subnets ...' for the parity proof's denied caller failed"
      echo "--- stderr ---"; cat "$WORK/par-caller.err" 2>/dev/null || true
      fail
    }
    PAR_CALLER_SID="$(printf '%s\n' "$PAR_CALLER_SID" | tail -n1 | tr -d '\r')"

    # The control: the SAME request from the ungated origin box routes. The
    # denial below is the caller's rules, not the target's port map — this
    # names the published port, which the pair above proved routes.
    par_proxied "$par_sid" "http://$PAR_OWN_NAME.min.internal:$PAR_OWN_PORT/" "127.0.0.1:7654" 20
    echo "caller control: the same proxied request from an ungated box -> HTTP ${PAR_STATUS:-<none>}"
    [ "${PAR_STATUS:-}" = 200 ] || {
      echo "::error::the control request from the ungated origin box did not route (got '${PAR_STATUS:-<none>}') — the refusals below would not be the caller's"
      echo "--- curl stderr ---"; cat "$WORK/par-proxied.err" 2>/dev/null || true
      fail
    }

    par_direct "$PAR_CALLER_SID" "http://$PAR_OWN_NAME.min.internal:$PAR_OWN_PORT/" 5
    par_direct_rc="$PAR_RC"
    par_direct_line="GET http://$PAR_OWN_NAME.min.internal:$PAR_OWN_PORT/ -> curl exit $PAR_RC: $(head -n1 "$WORK/par-direct.err" 2>/dev/null || true)"
    par_proxied "$PAR_CALLER_SID" "http://$PAR_OWN_NAME.min.internal:$PAR_OWN_PORT/" "100.64.255.253:7654" 20
    par_pair "a caller whose egress rules deny the target" \
      "$par_direct_line" \
      "GET http://$PAR_OWN_NAME.min.internal:$PAR_OWN_PORT/ via the proxy at the daemon's switch address -> HTTP ${PAR_STATUS:-<none>} ($(head -n1 "$WORK/par-proxied.err" 2>/dev/null || true))"
    [ "$par_direct_rc" -eq 28 ] || {
      echo "::error::the denied caller's direct attempt did not end in a connect timeout (curl exit $par_direct_rc, expected 28) — the caller's egress gate did not drop it"
      echo "--- curl stderr ---"; cat "$WORK/par-direct.err" 2>/dev/null || true
      fail
    }
    [ "${PAR_STATUS:-}" = 403 ] || {
      echo "::error::the denied caller's proxied attempt did not get the proxy's 403 (got '${PAR_STATUS:-<none>}')"
      echo "--- curl stderr ---"; cat "$WORK/par-proxied.err" 2>/dev/null || true
      fail
    }
    echo "  (both pairs' refusals are one rule each — no ingress mapping for pair 4, egress-undeclared-subnet for pair 5 —"
    echo "   decided by the same compiled policy on both legs; the records are the guest daemon's on this lane and ride"
    echo "   the diagnostics bundle a failing run writes)"

    mnl session destroy --force "$PAR_CALLER_SID" >/dev/null 2>&1 || true
    mnl session destroy --force "$PAR_OWN_SID" >/dev/null 2>&1 || true
  else
    echo "switch halves SKIPPED (no E2E_VM: the between-box pairs need the guest fabric — a direct attempt"
    echo "  to a box's lease, and the proxy at the daemon's own switch address — which a host-side daemon has none of)"
  fi

  mnl session destroy --force "$par_sid" >/dev/null 2>&1 || true
  echo "the hostname proxy honours the switch's rules OK (each pair printed with both refusals; the readable lanes' records beside them)"
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# The retired surfaces are gone, end to end (NET-109, NET-110). The mTLS/OIDC
# HTTPS reverse proxy, its daemon-issued client certificates and the
# `min ssh-forward` verb came out of the tree, `min login` stopped minting,
# and `direct-tcpip` stayed — serving in EVERY build now that the feature
# gate is gone. The source-scan unit tests (`retired_surfaces_absent`,
# `login_mints_no_certificate`, `cli_reference_has_no_retired_commands`)
# hold the tree to that statically; this case holds the runtime to it, on
# the build the lane actually drives:
#
#   * `min ssh-forward` does not parse — the argument parser refuses the
#     verb by name, with its usage.
#   * `min login` mints nothing: it succeeds without a daemon, prints the
#     one nothing-to-mint line, and leaves no client.pem / client.key /
#     ca.pem in the config directory where the mint used to write them —
#     and the `--cert-dir` flag that steered those writes is refused too.
#   * the retired proxy's :7655 listener is gone: with this run's daemon up,
#     nothing answers HTTP there (the egress proxy's :7654 is the one
#     listener left). No gate in front of this probe on purpose: a dev host
#     still carrying an OLD daemon would hold :7655, and that is exactly the
#     regression this probe exists to catch, loudly.
#   * and the surface that replaced them works: a real `min net forward`
#     binds a laptop-side listener and relays an HTTP request from this
#     host over the session's SSH channel — one direct-tcpip channel per
#     accepted connection — to a responder running in the box, and ends
#     with Ctrl-C taking the listener down with it.
#
# "In a release build": direct-tcpip is served in every build since the
# gate went, so the debug build CI's lanes drive and a release build
# exercise the same handler; this case is the one a release smoke drives
# with MINIMAL_E2E_MIN (see the min-resolution block at the top) when the
# smoke wants the pair it names rather than this checkout's debug build.
#
# The daemon's per-channel-open record is INFO and the lane's daemon runs
# at `warn`, so on a native lane the case restarts it — as the min.internal
# proxy case above does — with the daemon's connection module at info: the
# daemon log, and with it the `min bug` bundle's tail of it, then names
# every direct-tcpip channel open with its session and box port. On a VM
# lane the daemon's log is guest-side and unreadable here; the response the
# forward returned carries the assertion, as it does for the proxy case.
#
# Ordered LAST in the whole-lane run, for that same restart: nothing after
# it depends on the one before.
proof_retired_surfaces_gone() {
echo "::group::retired surfaces gone (ssh-forward, login, :7655, direct-tcpip)"

  # The daemon's file log, newest first — one file per calendar day; within
  # a run the newest is the live one (the proxy case's helper, for the one
  # record this case reads).
  retired_daemon_log() {
    find "$XDG_STATE_HOME/minimal/logs" -name 'minimald.log.*' -type f 2>/dev/null \
      | sort | tail -n1
  }

  # The per-channel-open record the case asserts on is INFO, and the daemon
  # this lane runs writes at `warn` — restart it with the daemon's
  # connection module at info (the CLI's own modules stay at warn, so the
  # session-id extraction every proof uses is untouched). Only worth doing
  # where the log is readable; a VM lane's daemon keeps its records
  # guest-side either way. Sessions survive a daemon restart (the restart
  # proof pins that), and none is live by the time the whole-lane run
  # reaches here.
  if hook_log_readable; then
    mnl stop >/dev/null 2>&1 || true # a standalone run has no daemon yet
    export RUST_LOG="warn,minimald::connection=info"
  fi

  # ---- the retired verb: `min ssh-forward` does not parse ------------------
  # Client-side, before any daemon: the argument parser must refuse the verb
  # by name — the same refusal the unit test holds the tree to.
  retired_sf="$(mnl ssh-forward dev 18080:127.0.0.1:80 2>&1)"
  retired_sf_rc=$?
  if [ "$retired_sf_rc" -eq 0 ] || [[ "$retired_sf" != *"unrecognized subcommand 'ssh-forward'"* ]]; then
    echo "::error::'min ssh-forward' did not get the parser's refusal (exit $retired_sf_rc):"
    printf '%s\n' "$retired_sf" | head -5 | sed 's/^/  /'
    fail
  fi
  echo "retired surface: min ssh-forward → refused (exit $retired_sf_rc: unrecognized subcommand 'ssh-forward')"

  # ---- the retired mint: `min login` mints nothing --------------------------
  # Runs without a daemon, prints the one notice, and leaves the config
  # directory — where the minted client.pem/client.key/ca.pem used to land —
  # exactly as it found it. The file list is snapshotted around the call so
  # the assertion is about what THIS login did, not what the tree contains.
  retired_config_before="$(find "$XDG_CONFIG_HOME" -type f 2>/dev/null | sort)"
  retired_login="$(mnl login 2>"$WORK/retired-login.err")"
  retired_login_rc=$?
  retired_login="$(printf '%s\n' "$retired_login" | tr -d '\r')"
  if [ "$retired_login_rc" -ne 0 ] || [[ "$retired_login" != *"Nothing to mint"* ]]; then
    echo "::error::'min login' did not print the nothing-to-mint notice (exit $retired_login_rc):"
    printf '%s\n' "$retired_login" | head -5 | sed 's/^/  /'
    echo "--- stderr ---"; cat "$WORK/retired-login.err" 2>/dev/null || true
    fail
  fi
  echo "retired surface: min login → \"$retired_login\""
  retired_config_after="$(find "$XDG_CONFIG_HOME" -type f 2>/dev/null | sort)"
  if [ "$retired_config_before" != "$retired_config_after" ]; then
    echo "::error::'min login' wrote to the config directory, where the minted certificates used to land:"
    diff <(printf '%s\n' "$retired_config_before") <(printf '%s\n' "$retired_config_after") \
      | sed 's/^/  /'
    fail
  fi
  if find "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" -type f \( -name 'client.pem' -o -name 'client.key' -o -name 'ca.pem' \) 2>/dev/null \
    | grep -q .; then
    echo "::error::the retired client certificate material exists on this host (client.pem / client.key / ca.pem):"
    find "$XDG_CONFIG_HOME" "$XDG_STATE_HOME" -type f \( -name 'client.pem' -o -name 'client.key' -o -name 'ca.pem' \) 2>/dev/null \
      | sed 's/^/  /'
    fail
  fi

  # `--cert-dir`, the flag that steered the retired writes, is refused too.
  retired_cd="$(mnl login --cert-dir /tmp/mnl-retired-certs 2>&1)"
  retired_cd_rc=$?
  if [ "$retired_cd_rc" -eq 0 ] || [[ "$retired_cd" != *"--cert-dir"* ]]; then
    echo "::error::'min login --cert-dir' did not get the parser's refusal (exit $retired_cd_rc):"
    printf '%s\n' "$retired_cd" | head -5 | sed 's/^/  /'
    fail
  fi
  echo "retired surface: min login --cert-dir → refused (exit $retired_cd_rc, the flag is named in the usage)"

  # ---- the session the forward drives ---------------------------------------
  # A default (host-address) box: the user's own path, the one the forward
  # exists for. Its own seed keeps the case standalone — the whole-lane run
  # reaches it after `sandbox` has deleted the shared session.
  RETIRED_NAME="e2e-retired"             # the session's name
  RETIRED_BOX_PORT=18083                 # the in-box responder's listen port
  RETIRED_LOCAL_PORT=18084               # the forward's laptop-side listener
  RETIRED_PROXY_PORT=7655                # the retired HTTPS proxy's port
  RETIRED_BOX_MARKER="RETIRED_FORWARD_OK" # what the in-box responder answers
  RETIRED_SEED_DIR="$(hook_mktemp /tmp/mnlrt.XXXXXX)"
  hook_seed_preamble > "$RETIRED_SEED_DIR/minimal.toml"
  mkdir "$RETIRED_SEED_DIR/.git"
  retired_sid="$(cd "$RETIRED_SEED_DIR" && mnl session activate . --no-prompt \
    --name "$RETIRED_NAME" 2>"$WORK/retired-activate.err")" || {
    echo "::error::'min session activate' for the retired-surfaces proof failed"
    echo "--- stderr ---"; cat "$WORK/retired-activate.err" 2>/dev/null || true
    fail
  }
  retired_sid="$(printf '%s\n' "$retired_sid" | tail -n1 | tr -d '\r')"
  if ! printf '%s' "$retired_sid" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
    echo "::error::activate's last stdout line is not a session UUID: '$retired_sid'"
    echo "--- stderr ---"
    cat "$WORK/retired-activate.err" 2>/dev/null || true
    fail
  fi
  echo "session: $retired_sid (the daemon is up: this run owns the listeners now)"

  # ---- the retired listener: nothing answers on :7655 ------------------------
  # Natively the daemon is up on this host, so the absence is this DAEMON's
  # absence, not an idle host's. Deliberately ungated: another minimald on
  # this host would hold :7654 (the proxy case above degrades on that), but an
  # OLD daemon would hold :7655 — and that is the regression this probe
  # catches. On a VM lane the daemon is guest-side and this probe sees only
  # the host loopback, where the retired proxy was published through the
  # switch's forwarder: what it asserts there is that nothing publishes :7655
  # on the host any more, and the success line says so.
  curl -sS --max-time 5 -o /dev/null "http://127.0.0.1:$RETIRED_PROXY_PORT/" \
    >"$WORK/retired-proxy.out" 2>"$WORK/retired-proxy.err"
  retired_proxy_rc=$?
  if [ "$retired_proxy_rc" -eq 0 ]; then
    echo "::error::something answered HTTP on the retired proxy's :$RETIRED_PROXY_PORT — the HTTPS reverse proxy is supposed to be gone (NET-109)"
    echo "  if this is a dev host carrying an old minimald, that old daemon is the finding; check what listens there"
    echo "--- curl ---"; cat "$WORK/retired-proxy.out" 2>/dev/null || true
    fail
  fi
  if [ -n "$E2E_VM" ]; then
    echo "retired surface: HTTPS reverse proxy :$RETIRED_PROXY_PORT → nothing published on the host loopback (guest-side daemon; curl exit $retired_proxy_rc: $(head -n1 "$WORK/retired-proxy.err" 2>/dev/null || true))"
  else
    echo "retired surface: HTTPS reverse proxy :$RETIRED_PROXY_PORT → nothing answers (curl exit $retired_proxy_rc: $(head -n1 "$WORK/retired-proxy.err" 2>/dev/null || true))"
  fi

  # ---- capability gate: what THIS host can run -------------------------------
  # The forward's responder runs in the box, so the box's sandbox must run.
  # Same gate, same degrade, as the min.internal proxy case above: a host
  # that is itself a sandbox (a plain container, a session box) denies the
  # nested mount namespaces and every exec dies at spawn. The retired-surface
  # probes above already ran — they need no box — so the degrade keeps those
  # and says what it left unrun. On CI or a VM lane this gate fails instead.
  if ! mnl session exec "$retired_sid" 'true' >"$WORK/retired-execgate.err" 2>&1 \
     && ! { sleep 1; mnl session exec "$retired_sid" 'true' >"$WORK/retired-execgate.err" 2>&1; }; then
    if [ -z "${CI:-}" ] && [ -z "$E2E_VM" ]; then
      echo "::warning::retired-surfaces forward half SKIPPED — this host cannot run a session sandbox"
      echo "  (exec: $(head -n1 "$WORK/retired-execgate.err" 2>/dev/null || true))"
      echo "  asserted here: the ssh-forward, login and :7655 probes above."
      echo "  the direct-tcpip forward needs a box whose sandbox can run; on CI or a VM lane this gate fails instead"
      mnl session destroy --force "$retired_sid" >/dev/null 2>&1 || true
      echo "::endgroup::"
      return 0
    fi
    echo "::error::this lane cannot run a session sandbox, so the forward's responder cannot start: the direct-tcpip half of this case cannot be asserted"
    echo "  (exec: $(head -n1 "$WORK/retired-execgate.err" 2>/dev/null || true))"
    echo "  on a VM lane the boxes live in the guest, so this is a lane-level fault"
    fail
  fi

  # socat carries the in-box responder. It is a launcher baseline package
  # (crates/minimald/src/session_host.rs BASELINE_PACKAGES), so every box
  # ships it — at /usr/bin: packages install with --prefix=/usr, and the
  # generic rootfs has no /bin, so the case says the absolute path, the
  # daemon's own convention for in-box argv, rather than lean on PATH.
  mnl session exec "$retired_sid" 'test -x /usr/bin/socat' >/dev/null 2>&1 \
    || { echo "::error::the session has no socat at /usr/bin/socat (a launcher baseline package — every box ships one)"; fail; }
  # The responder, written by the SESSION's shell so the Content-Length can
  # never drift from the body it frames (the format is double-quoted there
  # on purpose — ${#body} is the session shell's own arithmetic), then socat
  # serving it per connection; `nohup ... &` is the documented detach form
  # (docs/reference/cli-min.md, `session exec`) so the listener outlives the
  # exec that starts it.
  mnl session exec "$retired_sid" \
    "body=$RETIRED_BOX_MARKER; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/retired200" \
    >/dev/null 2>"$WORK/retired-responder.err" \
    || { echo "::error::could not write the in-box responder's response"; cat "$WORK/retired-responder.err" 2>/dev/null || true; fail; }
  mnl session exec "$retired_sid" \
    "nohup /usr/bin/socat TCP-LISTEN:$RETIRED_BOX_PORT,reuseaddr,fork SYSTEM:\"cat /home/retired200\" >/dev/null 2>&1 &" \
    >/dev/null 2>"$WORK/retired-responder.err" \
    || { echo "::error::could not start the in-box responder"; cat "$WORK/retired-responder.err" 2>/dev/null || true; fail; }
  retired_responder_ready=""
  for _ in $(seq 1 40); do
    if [ "$(mnl session exec "$retired_sid" \
      "curl -sS --max-time 5 -o /home/retired-ready.body -w '%{http_code}' http://127.0.0.1:$RETIRED_BOX_PORT/" \
      2>/dev/null || true)" = "200" ]; then
      retired_responder_ready=1; break
    fi
    sleep 0.25
  done
  if [ -z "$retired_responder_ready" ]; then
    echo "::error::the in-box responder never answered a direct curl — the forward is not in the picture yet"
    echo "--- socat exec stderr ---"; cat "$WORK/retired-responder.err" 2>/dev/null || true
    fail
  fi

  # ---- the forward: direct-tcpip relays, in the build this lane drives -------
  # The user's own path (NET-104): `min net forward` stays in the foreground,
  # prints its banner on stderr once the laptop-side listener is bound, and
  # every accepted connection gets its own direct-tcpip channel — the thing
  # the retired ssh-forward verb used to be the CLI for.
  echo "opening the forward: min net forward $RETIRED_NAME $RETIRED_LOCAL_PORT:$RETIRED_BOX_PORT"
  # Not `mnl ... &`: mnl is a function, so `$!` would be a subshell that ignores
  # SIGINT; exec the binary so the pid is `min`'s and Ctrl-C reaches it.
  # shellcheck disable=SC2086
  ( exec min ${E2E_MINIMAL_ARGS:-} net forward "$retired_sid" "$RETIRED_LOCAL_PORT:$RETIRED_BOX_PORT" ) \
    >"$WORK/retired-forward.out" 2>"$WORK/retired-forward.err" &
  RETIRED_FWD_PID=$!
  retired_fwd_ready=""
  for _ in $(seq 1 40); do
    if grep -q "Forwarding localhost:$RETIRED_LOCAL_PORT" "$WORK/retired-forward.err" 2>/dev/null; then
      retired_fwd_ready=1; break
    fi
    # Died before it ever bound: report it now, with what it said.
    if ! kill -0 "$RETIRED_FWD_PID" 2>/dev/null; then
      break
    fi
    sleep 0.25
  done
  if [ -z "$retired_fwd_ready" ]; then
    echo "::error::the forward never bound its laptop-side listener (no 'Forwarding localhost:$RETIRED_LOCAL_PORT' banner)"
    echo "--- forward stderr ---"; cat "$WORK/retired-forward.err" 2>/dev/null || true
    echo "--- forward stdout ---"; cat "$WORK/retired-forward.out" 2>/dev/null || true
    fail
  fi
  echo "forward banner: $(head -n1 "$WORK/retired-forward.err" 2>/dev/null || true)"

  # One request through the forward — the response is the case's assertion
  # that direct-tcpip relays in the build this lane drives.
  retired_fwd_status="$(curl -sS --max-time 20 -o "$WORK/retired-fwd.body" \
    -w '%{http_code}' "http://127.0.0.1:$RETIRED_LOCAL_PORT/" 2>"$WORK/retired-fwd.err")"
  retired_fwd_rc=$?
  retired_fwd_body="$(cat "$WORK/retired-fwd.body" 2>/dev/null || true)"
  if [ "$retired_fwd_rc" -ne 0 ] || [ "$retired_fwd_status" != "200" ] \
    || [[ "$retired_fwd_body" != *"$RETIRED_BOX_MARKER"* ]]; then
    echo "::error::the request through the forward did not get the in-box responder's answer (curl exit $retired_fwd_rc, HTTP ${retired_fwd_status:-<none>}, body '${retired_fwd_body:0:48}')"
    echo "--- curl stderr ---"; cat "$WORK/retired-fwd.err" 2>/dev/null || true
    echo "--- forward stderr ---"; cat "$WORK/retired-forward.err" 2>/dev/null || true
    fail
  fi
  echo "forward response: GET http://127.0.0.1:$RETIRED_LOCAL_PORT/ -> HTTP $retired_fwd_status $retired_fwd_body"

  # The daemon's record of the channel open it served (INFO — the restart
  # above put the connection module there). The record names the session the
  # channel forwarded for and the box port it reached, so the daemon log —
  # and with it the `min bug` bundle's tail of it — carries the opens.
  if hook_log_readable; then
    retired_open_log=""
    for _ in $(seq 1 20); do
      retired_open_log="$(grep -h -- 'direct-tcpip channel open' "$(retired_daemon_log)" 2>/dev/null \
        | grep -E -- "\"port\": *${RETIRED_BOX_PORT}[,}]" | tail -n1)"
      [ -n "$retired_open_log" ] && break
      sleep 0.25
    done
    if [ -z "$retired_open_log" ]; then
      echo "::error::the daemon log carries no direct-tcpip channel-open record for port $RETIRED_BOX_PORT"
      echo "--- daemon log (tail) ---"; tail -20 "$(retired_daemon_log)" 2>/dev/null || true
      fail
    fi
    case "$retired_open_log" in
      *"$retired_sid"*) ;;
      *)
        echo "::error::the direct-tcpip record does not name the session it forwarded for ($retired_sid)"
        echo "--- record ---"; printf '%s\n' "$retired_open_log"
        fail
        ;;
    esac
    echo "daemon log: $retired_open_log"
  else
    echo "daemon log: (guest-side daemon on this lane — the response above is the assertion)"
  fi

  # ---- and the forward ends when its person ends it --------------------------
  # Ctrl-C is the manual half of the forward's lifecycle: INT ends it, the
  # listener closes with it, and the next request to the local port is
  # refused rather than served by a forward that outlived its person.
  kill -INT "$RETIRED_FWD_PID" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$RETIRED_FWD_PID" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$RETIRED_FWD_PID" 2>/dev/null; then
    echo "::error::the forward did not end on Ctrl-C"
    echo "--- forward stderr ---"; cat "$WORK/retired-forward.err" 2>/dev/null || true
    kill -9 "$RETIRED_FWD_PID" 2>/dev/null || true
    fail
  fi
  wait "$RETIRED_FWD_PID" 2>/dev/null
  retired_fwd_rc=$?
  RETIRED_FWD_PID=""
  if [ "$retired_fwd_rc" -ne 0 ]; then
    echo "::error::the forward exited $retired_fwd_rc on Ctrl-C (expected a clean 0)"
    echo "--- forward stderr ---"; cat "$WORK/retired-forward.err" 2>/dev/null || true
    fail
  fi
  echo "forward: closed on Ctrl-C (exit 0: $(grep -h -- 'closed' "$WORK/retired-forward.err" 2>/dev/null | tail -n1))"
  curl -sS --max-time 5 -o /dev/null "http://127.0.0.1:$RETIRED_LOCAL_PORT/" \
    2>"$WORK/retired-after.err"
  retired_after_rc=$?
  if [ "$retired_after_rc" -eq 0 ]; then
    echo "::error::the laptop-side listener survived the forward's end — a request to localhost:$RETIRED_LOCAL_PORT still answers"
    fail
  fi
  echo "forward: the listener closed with it (curl exit $retired_after_rc: $(head -n1 "$WORK/retired-after.err" 2>/dev/null || true))"

  mnl session destroy --force "$retired_sid" >/dev/null 2>&1 \
    || { echo "::error::could not destroy the retired-surfaces session"; fail; }
  echo "retired surfaces gone OK (ssh-forward refused, login mints nothing, :7655 dark, and the direct-tcpip forward relayed and closed)"
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# Shared by the NET-049/NET-051 fresh-install KVM activation proofs and the
# stock-install integration case: locate the lane's guest images, stage the
# mock bucket the real install.sh installs from, write the stub downloaders,
# run the installer into a fresh HOME, and drive the installed pair (activate,
# UUID, listed) — then the start-record assertion below. What each proof keeps
# for itself is policy: the arch it gates on, whether the switch is required
# (fetch-or-fail) or optional (omit the row), which rows the installer's
# output must carry, and how far the box is driven (activation only, or exec
# and destroy too).
# ---------------------------------------------------------------------------
# Shared by the fresh-install VM proofs (the NET-049/NET-051 activation case
# and the stock-install case below): the VM host daemon's start record must
# exist and name the kernel, rootfs and initramfs it resolved — from the
# installed data prefix of the home $1 was installed into — and, when $2 is
# non-empty (the proof shipped a switch), that switch from the installed bin
# dir. Runs INSIDE the caller's install-proof subshell, so every failure
# `exit 1`s and the caller's `if ( ... )` turns the unwind into its own
# `fail`; prints the record it matched.
#
# WHERE the record lives: an autospawned daemon is a detached supervisor,
# which routes its tracing to the daily-rotated file sink under the state
# base's logs dir (`minvmd.log*`, dated and unsuffixed — crates/minvmd/src/
# main.rs). Its stderr — run.log, where a boot failure's diagnosis lands —
# carries only what tracing does not. Both are searched, file sink first;
# the first file that carries the record is the one that proves it.
#
# WHEN it lands: activate returns once the VM is serving, which can precede
# the appender's first flush, and the dated file is created by the daemon's
# own start — after the CLI's autospawn call returned. So the LOOKUP runs
# inside the retry loop (it used to run once, before it, and grep whatever
# it resolved there 20 times over) and the total wait is 20 s, well past
# the seconds a first flush can take.
fresh_vm_start_record_asserts_installed_images() {
  local fsr_home="$1" fsr_switch="$2"
  local fsr_rec fsr_log fsr_cand fsr_key fsr_want fsr_data
  fsr_log_candidates() {
    # Newest first: the dated file sorts after the unsuffixed name, and a
    # later date after an earlier one.
    find "$XDG_STATE_HOME/minimal/logs" -maxdepth 1 -name 'minvmd.log*' -type f 2>/dev/null | sort -r
    printf '%s\n' "$XDG_STATE_HOME/minimal/providers/local-minvmd0/run.log"
  }
  fsr_rec=""
  fsr_log=""
  for _ in $(seq 1 40); do
    while IFS= read -r fsr_cand; do
      [ -f "$fsr_cand" ] || continue
      fsr_rec="$(grep -h -- 'starting VM' "$fsr_cand" 2>/dev/null | tail -n1)"
      [ -z "$fsr_rec" ] && continue
      fsr_log="$fsr_cand"
      break
    done < <(fsr_log_candidates)
    [ -n "$fsr_rec" ] && break
    sleep 0.5
  done
  if [ -z "$fsr_rec" ]; then
    echo "::error::no 'starting VM' record in any VM host daemon log after 20 s"
    echo "--- paths searched (tail of each) ---"
    while IFS= read -r fsr_cand; do
      echo "--- $fsr_cand ---"
      if [ -f "$fsr_cand" ]; then
        tail -30 "$fsr_cand" 2>/dev/null || true
      else
        echo "(no such file)"
      fi
    done < <(fsr_log_candidates)
    echo "--- log dir listing ---"
    ls -la "$XDG_STATE_HOME/minimal/logs" 2>/dev/null || echo "(no log dir)"
    exit 1
  fi

  # The file sink writes one flat JSON object per line (crates/mlog) with the
  # record's own fields nested under "fields", in the subscriber's key order —
  # alphabetical (a BTreeMap in json-subscriber), not the record's declaration
  # order. So each field is matched on its own: one ordered pattern would pin
  # an ordering the JSON layer does not promise.
  for fsr_key in kernel rootfs initramfs switch; do
    fsr_want="\"$fsr_key\":"
    case "$fsr_rec" in
      *"$fsr_want"*) ;;
      *)
        echo "::error::the VM host daemon start line does not name its $fsr_key"
        echo "--- record ---"; printf '%s\n' "$fsr_rec"
        exit 1
        ;;
    esac
  done

  # And the values are the point: with no MINVMD_* overrides, the daemon must
  # have resolved each guest image from the installed data prefix — the same
  # paths the install check verified the installer stamped — and the switch
  # from the installed bin dir when the proof staged one.
  fsr_data="$fsr_home/.local/share/minimal"
  for fsr_pair in "kernel=$fsr_data/vmlinuz" "rootfs=$fsr_data/rootfs.img" \
                  "initramfs=$fsr_data/initramfs.cpio"; do
    fsr_key="${fsr_pair%%=*}"
    fsr_want="\"$fsr_key\":\"${fsr_pair#*=}\""
    case "$fsr_rec" in
      *"$fsr_want"*) ;;
      *)
        echo "::error::the VM host daemon start line does not resolve its $fsr_key from the installed data prefix"
        echo "--- record ---"; printf '%s\n' "$fsr_rec"
        echo "--- expected ---"; printf '%s\n' "$fsr_want"
        exit 1
        ;;
    esac
  done
  if [ -n "$fsr_switch" ]; then
    fsr_want="\"switch\":\"$fsr_home/.local/bin/gvproxy-min\""
    case "$fsr_rec" in
      *"$fsr_want"*) ;;
      *)
        echo "::error::the VM host daemon start line does not resolve the switch from the installed bin dir"
        echo "--- record ---"; printf '%s\n' "$fsr_rec"
        echo "--- expected ---"; printf '%s\n' "$fsr_want"
        exit 1
        ;;
    esac
  fi
  echo "VM host daemon start line ($fsr_log): $fsr_rec"
}

# ---------------------------------------------------------------------------
# The mock-bucket install-and-drive half the VM proofs share.
# ---------------------------------------------------------------------------

# Locate the guest images the lane already built/fetched — the caller's
# MINVMD_*_PATH overrides when set and present, else the justfile's .scratch
# copies (the same sources every VM proof reads). Sets STAGED_KERNEL,
# STAGED_ROOTFS and STAGED_INITRAMFS; the CALLER owns the availability check
# and its skip message, because where the check sits is the caller's policy:
# the stock-install case must skip before it would fetch a switch it cannot
# use, the fresh-kvm proofs resolve their (optional) switch first.
locate_vm_guest_images() {
  if [ -n "${MINVMD_KERNEL_PATH:-}" ] && [ -f "$MINVMD_KERNEL_PATH" ]; then
    STAGED_KERNEL="$MINVMD_KERNEL_PATH"
  else
    STAGED_KERNEL="$ROOT/.scratch/vmlinuz"
  fi
  if [ -n "${MINVMD_ROOTFS_PATH:-}" ] && [ -f "$MINVMD_ROOTFS_PATH" ]; then
    STAGED_ROOTFS="$MINVMD_ROOTFS_PATH"
  else
    STAGED_ROOTFS="$ROOT/.scratch/rootfs.img"
  fi
  if [ -n "${MINVMD_INITRAMFS:-}" ] && [ -f "$MINVMD_INITRAMFS" ]; then
    STAGED_INITRAMFS="$MINVMD_INITRAMFS"
  else
    STAGED_INITRAMFS="$ROOT/.scratch/initramfs.cpio"
  fi
}

# Stage the mock bucket the real install.sh below installs from: the seed
# project (a pinned minimal.toml plus a bare .git marker, so the headless
# upload gate ships it), then every component a Linux release ships for the
# arch — min, minvmd, the guest kernel, rootfs and initramfs, and, when $5 is
# non-empty, the switch — the stable pointer, and the components manifest the
# installer hashes. The caller owns the dirs (and creates them, because the
# stock-install case's fetch below writes its own log under the root first).
# $5 is the caller's SWITCH POLICY: the stock-install case resolves one or
# fails (a switchless guest cannot mint a session — its in-guest package pull
# has no other end — so a bucket without a switch would prove nothing), the
# fresh-kvm proofs may ship none and the row is omitted.
# Fails the run naming the missing binary when min/minvmd are not on PATH,
# BEFORE anything is staged: a missing one must not surface later as "the
# install failed" with the cause buried in the install log. A --provider
# local-minvmd activation needs only these two on the host — the guest runs
# minimald, not the host.
stage_vm_mock_bucket() {
  local smb_label="$1" smb_bucket="$2" smb_seed="$3" smb_arch="$4" smb_switch="$5"
  local smb_h_minimal smb_h_minvmd smb_h_kernel smb_h_rootfs smb_h_initramfs smb_h_switch
  hook_seed_preamble > "$smb_seed/minimal.toml"
  mkdir "$smb_seed/.git"
  if ! command -v min >/dev/null 2>&1 || ! command -v minvmd >/dev/null 2>&1; then
    echo "::error::$smb_label requires min and minvmd on PATH"
    fail
  fi
  cp "$(command -v min)"      "$smb_bucket/versions/v1/minimal-linux-$smb_arch"
  cp "$(command -v minvmd)"   "$smb_bucket/versions/v1/minvmd-linux-$smb_arch"
  cp "$STAGED_KERNEL"         "$smb_bucket/versions/v1/vmlinuz-$smb_arch"
  cp "$STAGED_ROOTFS"         "$smb_bucket/versions/v1/rootfs-$smb_arch.img"
  cp "$STAGED_INITRAMFS"      "$smb_bucket/versions/v1/initramfs-$smb_arch.cpio"
  if [ -n "$smb_switch" ]; then
    cp "$smb_switch"          "$smb_bucket/versions/v1/gvproxy-min-linux-$smb_arch"
  fi
  printf 'v1\n' >"$smb_bucket/stable"
  smb_sha() { sha256sum "$1" | awk '{print $1}'; }
  smb_h_minimal="$(smb_sha "$smb_bucket/versions/v1/minimal-linux-$smb_arch")"
  smb_h_minvmd="$(smb_sha "$smb_bucket/versions/v1/minvmd-linux-$smb_arch")"
  smb_h_kernel="$(smb_sha "$smb_bucket/versions/v1/vmlinuz-$smb_arch")"
  smb_h_rootfs="$(smb_sha "$smb_bucket/versions/v1/rootfs-$smb_arch.img")"
  smb_h_initramfs="$(smb_sha "$smb_bucket/versions/v1/initramfs-$smb_arch.cpio")"
  if [ -n "$smb_switch" ]; then
    smb_h_switch="$(smb_sha "$smb_bucket/versions/v1/gvproxy-min-linux-$smb_arch")"
  fi
  {
    printf '# format: 1\n'
    printf '# component   os      arch    version   sha256   kind   dest                 src\n'
    printf '\n'
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
      minimal linux "$smb_arch" v1 "$smb_h_minimal" file bin/min "versions/v1/minimal-linux-$smb_arch"
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
      minvmd linux "$smb_arch" v1 "$smb_h_minvmd" file bin/minvmd "versions/v1/minvmd-linux-$smb_arch"
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
      vmlinuz linux "$smb_arch" v1 "$smb_h_kernel" file data/vmlinuz "versions/v1/vmlinuz-$smb_arch"
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
      rootfs linux "$smb_arch" v1 "$smb_h_rootfs" file data/rootfs.img "versions/v1/rootfs-$smb_arch.img"
    printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
      initramfs linux "$smb_arch" v1 "$smb_h_initramfs" file data/initramfs.cpio "versions/v1/initramfs-$smb_arch.cpio"
    if [ -n "$smb_switch" ]; then
      printf '%-12s %-7s %-7s %-9s %-64s %-6s %-20s %s\n' \
        gvproxy-min linux "$smb_arch" v1 "$smb_h_switch" file bin/gvproxy-min "versions/v1/gvproxy-min-linux-$smb_arch"
    fi
  } >"$smb_bucket/versions/v1/components"
}

# The stub downloaders the installer resolves first on PATH: a fake curl
# mapping the pinned mock-bucket host to the local dir (the same trick
# install_test.sh uses, so the real installer runs unmodified and its own
# HTTPS/TLS flags are accepted and ignored), and a wget that refuses, so the
# downloader selection is deterministic.
write_install_stubs() {
  local wis_stubbin="$1" wis_bucket="$2" wis_bucket_host="$3"
  cat >"$wis_stubbin/curl" <<STUB
#!/bin/sh
# Fake curl: map the pinned bucket host to this local dir.
out= url=
while [ \$# -gt 0 ]; do
  case "\$1" in
    -o) out="\$2"; shift 2 ;;
    https://*|http://*) url="\$1"; shift ;;
    *) shift ;;
  esac
done
[ -n "\$url" ] || { echo "stub curl: no url" >&2; exit 2; }
rel="\${url#$wis_bucket_host/}"
src="$wis_bucket/\$rel"
[ -f "\$src" ] || { echo "stub curl: 404 \$url" >&2; exit 22; }
if [ -n "\$out" ]; then cp "\$src" "\$out"; else cat "\$src"; fi
STUB
  chmod +x "$wis_stubbin/curl"
  cat >"$wis_stubbin/wget" <<'STUB'
#!/bin/sh
echo "stub wget should not be used here" >&2
exit 1
STUB
  chmod +x "$wis_stubbin/wget"
}

# A REAL scripts/install.sh run into the fresh HOME the caller made, off the
# mock bucket, with no path overrides. Runs INSIDE the caller's install-proof
# subshell, so a failed install `exit 1`s the subshell — naming the cause and
# printing the installer's own log — and the caller's `if ( ... )` turns the
# unwind into its own `fail`.
#
# XDG_DATA_HOME outranks HOME in both the installer's data-prefix resolution
# (scripts/install.sh) and the daemon's image resolver
# (crates/minvmd/src/image.rs), and the harness does not hermeticize it — a
# host or CI that exports it would land the guest images in a different
# prefix from the $home/.local/share/minimal the caller asserts, for the
# install check below and the start-line values alike. A genuinely fresh
# install has it unset, so drop it (this subshell only, like the
# installed-pair env swap the drive helper's callers scope before the call).
run_mock_bucket_install() {
  local rmi_home="$1" rmi_bucket_host="$2" rmi_stubbin="$3" rmi_out="$4" rmi_label="$5"
  unset XDG_DATA_HOME
  # Fresh install into the throwaway home, no path overrides. The PATH change
  # is intentionally scoped to this subshell (SC2031).
  # shellcheck disable=SC2031
  HOME="$rmi_home" MINIMAL_BIN="$rmi_home/.local/bin" \
    PATH="$rmi_stubbin:$PATH" \
    MINIMAL_OVERRIDE_INSTALLER_BUCKET="$rmi_bucket_host" \
    sh "$ROOT/scripts/install.sh" >"$rmi_out" 2>&1 || {
      echo "::error::$rmi_label"
      echo "--- install log ---"; cat "$rmi_out" 2>/dev/null || true
      exit 1
    }
}

# Drive the INSTALLED pair. The caller's install-proof subshell has already
# swapped HOME/MINIMAL_BIN/PATH to the installed prefixes and dropped every
# MINVMD_* override — a swap the CALLER must make, because one made in here
# would die with this helper's command-substitution subshell — so image and
# switch resolution must come from the installed prefixes alone. Stops any
# daemon under the harness's state base; then activates a VM box and checks
# the outcome: the CLI's last stdout line is the new session's UUID, and
# `min ls --raw` lists it. Prints the UUID on stdout — every diagnostic goes
# to STDERR, so the capture keeps only the id. Returns nonzero on any
# failure; the caller (in its install-proof subshell) unwinds with
# `exit 1`, printing any extra diagnostics of its own first.
#
# The RUST_LOG filter rides on the ONE activate that autospawns the daemon:
# the 'starting VM' record the start-record helper asserts on is INFO, and a
# daemon's filter comes from RUST_LOG at autospawn (it inherits the CLI's
# env), while this harness quiets the whole run to `warn` for output parsing —
# which would drop the record before it reaches any sink. A command-local
# assignment (never an export) so nothing leaks past the proof, and `minvmd`
# is the daemon's crate, so the CLI's own stdout stays quiet and the
# last-line UUID extraction keeps working.
drive_installed_vm_pair() {
  local dvp_seed="$1" dvp_name="$2" dvp_err="$3"
  local dvp_activate_label="$4" dvp_ls_label="$5"
  local dvp_sid
  mnl stop --force >/dev/null 2>&1 || true
  dvp_sid="$(cd "$dvp_seed" && RUST_LOG="warn,minvmd=info" mnl session activate . --no-prompt --name "$dvp_name" 2>"$dvp_err")" || {
    echo "::error::$dvp_activate_label" >&2
    echo "--- activate stderr ---" >&2
    cat "$dvp_err" 1>&2 2>/dev/null || true
    return 1
  }
  dvp_sid="$(printf '%s\n' "$dvp_sid" | tail -n1 | tr -d '\r')"
  if ! printf '%s' "$dvp_sid" | grep -Eqx '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'; then
    echo "::error::activate's last stdout line is not a session UUID: '$dvp_sid'" >&2
    return 1
  fi
  if ! mnl ls --raw 2>/dev/null | grep -Fqx "$dvp_sid"; then
    echo "::error::'min ls --raw' does not list $dvp_ls_label $dvp_sid" >&2
    return 1
  fi
  printf '%s\n' "$dvp_sid"
}
proof_fresh_kvm_activate_local_minvmd_for_arch() {
  local target_arch="$1"
  if [ -z "$E2E_VM" ] || [ "$(uname -s)" != Linux ]; then
    echo "fresh-install KVM activate ($target_arch) SKIPPED (VM-backed Linux lane only)"
    return 0
  fi
  local host_arch
  case "$(uname -m)" in
    x86_64) host_arch=amd64 ;;
    aarch64|arm64) host_arch=arm64 ;;
    *)
      echo "fresh-install KVM activate ($target_arch) SKIPPED (no release arch for $(uname -m))"
      return 0
      ;;
  esac
  if [ "$host_arch" != "$target_arch" ]; then
    echo "fresh-install KVM activate ($target_arch) SKIPPED (host is $host_arch)"
    return 0
  fi
  if [ ! -e /dev/kvm ] || [ ! -w /dev/kvm ]; then
    echo "fresh-install KVM activate ($target_arch) SKIPPED (no writable /dev/kvm)"
    return 0
  fi

  echo "::group::fresh-install KVM activation ($target_arch) with local-minvmd (NET-049/NET-051)"

  local fk_root fk_home fk_bucket fk_stubbin fk_out fk_seed
  fk_root="$WORK/fresh-kvm-$target_arch"
  fk_home="$fk_root/home"
  fk_bucket="$fk_root/bucket"
  fk_stubbin="$fk_root/stubbin"
  fk_out="$fk_root/install.out"
  fk_seed="$fk_root/seed"
  mkdir -p "$fk_home" "$fk_bucket/versions/v1" "$fk_stubbin" "$fk_seed"

  local fk_bucket_host="https://mock.invalid/minimal-fresh-kvm-$target_arch"

  # Locate the guest images the lane already built/fetched (the shared
  # helper reads the same MINVMD_*_PATH / .scratch sources).
  locate_vm_guest_images

  # The switch the fresh install may ship: the lane's env override or the
  # justfile's .scratch copy — never a fetch. An install without a switch
  # still proves the activation half (a --provider local-minvmd activation
  # needs no switch), so the empty path downgrades to a switchless install;
  # the assertions and the start-record check below wrap on it.
  local fk_gvproxy
  if [ -n "${MINVMD_GVPROXY_BIN:-}" ] && [ -x "$MINVMD_GVPROXY_BIN" ]; then
    fk_gvproxy="$MINVMD_GVPROXY_BIN"
  elif [ -x "$ROOT/.scratch/gvproxy" ]; then
    fk_gvproxy="$ROOT/.scratch/gvproxy"
  else
    fk_gvproxy=""
  fi

  if [ ! -f "$STAGED_KERNEL" ] || [ ! -f "$STAGED_ROOTFS" ] || [ ! -f "$STAGED_INITRAMFS" ]; then
    echo "fresh-install KVM activate ($target_arch) SKIPPED (guest images not available)"
    echo "::endgroup::"
    return 0
  fi

  # Stage the mock bucket (the empty switch above omits the gvproxy-min row
  # the stock install always ships) and the stub downloaders the installer
  # resolves first on PATH.
  stage_vm_mock_bucket \
    "fresh-install KVM activate" \
    "$fk_bucket" "$fk_seed" "$target_arch" "$fk_gvproxy"
  write_install_stubs "$fk_stubbin" "$fk_bucket" "$fk_bucket_host"

  if (
    # A REAL install.sh run into the throwaway home, off the mock bucket
    # (the shared helper owns the XDG_DATA_HOME drop and the install
    # failure's diagnostics).
    run_mock_bucket_install "$fk_home" "$fk_bucket_host" "$fk_stubbin" "$fk_out" \
      "the fresh install (VM stack) failed"

    [ -x "$fk_home/.local/bin/min" ] \
      && [ -x "$fk_home/.local/bin/minvmd" ] || {
      echo "::error::the fresh install did not ship min/minvmd"
      tail -25 "$fk_out" 2>/dev/null || true
      exit 1
    }
    [ -f "$fk_home/.local/share/minimal/vmlinuz" ] \
      && [ -f "$fk_home/.local/share/minimal/rootfs.img" ] \
      && [ -f "$fk_home/.local/share/minimal/initramfs.cpio" ] || {
      echo "::error::the fresh install did not ship the guest images into the data prefix"
      exit 1
    }
    if [ -n "$fk_gvproxy" ]; then
      grep -qE 'switch-binary +verified +[^ ]*/bin/gvproxy-min$' "$fk_out" || {
        echo "::error::the install output does not name the switch binary it verified"
        tail -25 "$fk_out" 2>/dev/null || true
        exit 1
      }
      [ -x "$fk_home/.local/bin/gvproxy-min" ] || {
        echo "::error::the fresh install did not ship an executable gvproxy-min"
        exit 1
      }
    fi

    # NET-049/NET-051 observability: activate and list through the shared
    # driver (the UUID the destroy below takes), then the VM host daemon's
    # start log line must name the kernel, rootfs, initramfs and switch it
    # resolved — from the installed prefix, with no MINVMD_* override
    # anywhere (the assertion lives in the shared helper, which names where
    # the record is searched and why).
    #
    # The installed-pair env swap is scoped to this subshell (SC2030/SC2031)
    # and lives HERE, in the caller: a swap the driver made inside itself
    # would die with its command-substitution subshell, and the destroy/stop
    # below would run on the lane's pair.
    # shellcheck disable=SC2030,SC2031
    export HOME="$fk_home" MINIMAL_BIN="$fk_home/.local/bin" PATH="$fk_home/.local/bin:$PATH"
    unset MINVMD_KERNEL_PATH MINVMD_ROOTFS_PATH MINVMD_INITRAMFS MINVMD_GVPROXY_BIN
    fk_sid="$(drive_installed_vm_pair \
      "$fk_seed" "e2e-fresh-kvm-$target_arch" "$fk_root/activate.err" \
      "the installed pair failed to activate a session with local-minvmd and no image overrides" \
      "the fresh-install KVM session")" || exit 1

    fresh_vm_start_record_asserts_installed_images "$fk_home" "$fk_gvproxy"

    mnl session destroy --force "$fk_sid" >/dev/null 2>&1 || true
    mnl stop --force >/dev/null 2>&1 || true
  ); then
    :
  else
    fail
  fi
  echo "fresh-install KVM activation ($target_arch) OK"
  echo "::endgroup::"
}

proof_fresh_linux_kvm_activate_local_minvmd() {
  proof_fresh_kvm_activate_local_minvmd_for_arch amd64
}

proof_fresh_arm64_kvm_activate_local_minvmd() {
  proof_fresh_kvm_activate_local_minvmd_for_arch arm64
}

# ---------------------------------------------------------------------------
# The stock install runs VM boxes, end to end (the S14 integration case).
# From a REAL scripts/install.sh run into a fresh HOME — the mock-bucket
# install the fresh-kvm proofs use, shipping the VM stack the Linux releases
# ship (min, minvmd, the guest kernel, rootfs and initramfs, and the switch) —
# the INSTALLED pair must run a VM box through the user's whole path, with no
# MINVMD_* override anywhere:
#
#   * the install places every component and says so; the pair it leaves
#     behind is a stock one: the images in the installed data prefix, the
#     switch in the installed bin dir (NET-048/NET-050's runtime half);
#   * `min session activate --provider local-minvmd` boots the microVM and
#     prints the new session — the activation's outcome, observed — and the
#     session is listed;
#   * a command run in the box (`min session exec`) returns its output: the
#     bridge, the guest, and the session namespace all work from the
#     installed pair alone (NET-049/NET-051 end to end, not just activation);
#   * the VM host daemon's start record names the images and the switch it
#     booted (the run's diagnostics), and destroying the session delists it.
#
#   The case prints the installed components on success and again whenever
#   the activation or the exec fails: the installed pair's provenance is
#   the first thing a reader needs when the stock minvmd will not boot.
#
# Lane gating, decided by where the proof's pieces actually run:
#   * VM-backed Linux only, for the arch of the host (an arch without a
#     release binary for this channel is skipped the same way): the proof
#     boots a microVM, and the driving pair it installs is the one the
#     lane's release would ship.
#   * /dev/kvm must be present and writable: KVM is the isolation tier this
#     proof is for, and a host without it cannot run a VM box at all.
#   * the guest images, from the same sources the fresh-kvm proofs read.
#   * the switch is REQUIRED, never skipped: a stock install ships
#     gvproxy-min, and a switchless guest cannot mint a session (its
#     in-guest package pull has no other end), so a bucket without a switch
#     would prove nothing. MINVMD_GVPROXY_BIN, the justfile's .scratch
#     copy, or the pinned fetch — and when the fetch itself fails the case
#     fails, saying what a lane needs to run it.
#
# Ordered after the fresh-kvm activation proofs for the same reason they
# are ordered where they are: the case swaps the driving pair to the
# installed one and stops the daemon under the harness's state base before
# it activates — both inside its own subshell, so nothing that shares the
# lane's session may run beside it, and the lane env the later proofs see
# is the one this script started with.
proof_linux_stock_install_runs_vm_boxes() {
  local sb_arch
  if [ -z "$E2E_VM" ] || [ "$(uname -s)" != Linux ]; then
    echo "stock-install VM boxes SKIPPED (VM-backed Linux lane only)"
    return 0
  fi
  case "$(uname -m)" in
    x86_64)        sb_arch=amd64 ;;
    aarch64|arm64) sb_arch=arm64 ;;
    *)
      echo "stock-install VM boxes SKIPPED (no release arch for $(uname -m))"
      return 0
      ;;
  esac
  if [ ! -e /dev/kvm ] || [ ! -w /dev/kvm ]; then
    echo "stock-install VM boxes SKIPPED (no writable /dev/kvm)"
    return 0
  fi

  echo "::group::stock install runs VM boxes end to end ($sb_arch, installed pair, KVM)"

  local sb_root sb_home sb_bucket sb_stubbin sb_out sb_seed sb_name
  local sb_gvproxy sb_bucket_host
  sb_root="$WORK/stock-vm-$sb_arch"
  sb_bucket_host="https://mock.invalid/minimal-stock-vm-$sb_arch"
  sb_home="$sb_root/home"
  sb_bucket="$sb_root/bucket"
  sb_stubbin="$sb_root/stubbin"
  sb_out="$sb_root/install.out"
  sb_seed="$sb_root/seed"
  sb_name="e2e-stock-vm-$sb_arch"
  mkdir -p "$sb_home" "$sb_bucket/versions/v1" "$sb_stubbin" "$sb_seed"

  # Locate the guest images the lane already built/fetched (the shared
  # helper reads the same MINVMD_*_PATH / .scratch sources), and skip when
  # they are not there — BEFORE the switch resolution below, so a lane
  # without the images never pays for (or fails on) a gvproxy fetch it
  # cannot use.
  locate_vm_guest_images
  if [ ! -f "$STAGED_KERNEL" ] || [ ! -f "$STAGED_ROOTFS" ] || [ ! -f "$STAGED_INITRAMFS" ]; then
    echo "stock-install VM boxes SKIPPED (guest images not available)"
    echo "::endgroup::"
    return 0
  fi

  # The switch the stock install must ship: the lane's env override, the
  # justfile's .scratch copy, or the pinned fetch — the same sources the
  # loopback-publish proof reads, minus the skip: a lane that cannot ship a
  # switch cannot run a box end to end, which is what this case exists for.
  if [ -n "${MINVMD_GVPROXY_BIN:-}" ] && [ -x "$MINVMD_GVPROXY_BIN" ]; then
    sb_gvproxy="$MINVMD_GVPROXY_BIN"
  elif [ -x "$ROOT/.scratch/gvproxy" ]; then
    sb_gvproxy="$ROOT/.scratch/gvproxy"
  else
    if ! "$ROOT/scripts/fetch-gvproxy.sh" "$sb_root/gvproxy" \
        >"$sb_root/fetch-gvproxy.out" 2>&1; then
      echo "::error::could not fetch the pinned gvproxy the stock install must ship (set MINVMD_GVPROXY_BIN or stage $ROOT/.scratch/gvproxy)"
      cat "$sb_root/fetch-gvproxy.out" 2>/dev/null || true
      fail
    fi
    sb_gvproxy="$sb_root/gvproxy"
  fi

  # Stage the mock bucket — every component a Linux release ships for this
  # arch, switch REQUIRED, so the install under test IS the stock one — and
  # the stub downloaders the installer resolves first on PATH.
  stage_vm_mock_bucket \
    "the stock-install case" \
    "$sb_bucket" "$sb_seed" "$sb_arch" "$sb_gvproxy"
  write_install_stubs "$sb_stubbin" "$sb_bucket" "$sb_bucket_host"

  # The installed pair's provenance, in the installer's own words: printed
  # after the install (observability) and again by every activate/exec
  # failure below (the plan's "the case prints the install log") — when the
  # stock minvmd will not boot, which components this install actually
  # shipped is the first thing a reader needs.
  sb_print_installed_components() {
    echo "--- installed components ---"
    grep -E '^  [a-z0-9-]+ +(installed|current|verified|skipped)' "$sb_out" 2>/dev/null \
      || { echo "--- install log (tail) ---"; tail -25 "$sb_out" 2>/dev/null || true; }
  }

  if (
    # A REAL install.sh run into the throwaway home, off the mock bucket
    # (the shared helper owns the XDG_DATA_HOME drop and the install
    # failure's diagnostics).
    run_mock_bucket_install "$sb_home" "$sb_bucket_host" "$sb_stubbin" "$sb_out" \
      "the stock install (VM stack) failed"

    # Observability: what the stock install placed, in its own words (the
    # helper prints it again on any activate/exec failure below).
    sb_print_installed_components
    for sb_comp in minvmd vmlinuz rootfs initramfs; do
      grep -qE "^  $sb_comp +(installed|current)" "$sb_out" || {
        echo "::error::the install output does not name $sb_comp as placed"
        echo "--- install log (tail) ---"; tail -25 "$sb_out" 2>/dev/null || true
        exit 1
      }
    done
    # The switch row, beside the four image rows: the installer says which
    # path it verified (NET-041), and a stock install must be the row that
    # names the shipped gvproxy-min — the same grep the fresh-kvm proofs
    # keep (the switch is REQUIRED here, so no skip branch around it).
    grep -qE 'switch-binary +verified +[^ ]*/bin/gvproxy-min$' "$sb_out" || {
      echo "::error::the install output does not name the switch binary it verified"
      echo "--- install log (tail) ---"; tail -25 "$sb_out" 2>/dev/null || true
      exit 1
    }

    # The VM stack is on disk where a stock install puts it.
    [ -x "$sb_home/.local/bin/min" ] \
      && [ -x "$sb_home/.local/bin/minvmd" ] || {
      echo "::error::the stock install did not ship min/minvmd"
      echo "--- install log (tail) ---"; tail -25 "$sb_out" 2>/dev/null || true
      exit 1
    }
    [ -f "$sb_home/.local/share/minimal/vmlinuz" ] \
      && [ -f "$sb_home/.local/share/minimal/rootfs.img" ] \
      && [ -f "$sb_home/.local/share/minimal/initramfs.cpio" ] || {
      echo "::error::the stock install did not ship the guest images into the data prefix"
      exit 1
    }
    [ -x "$sb_home/.local/bin/gvproxy-min" ] || {
      echo "::error::the stock install did not ship an executable gvproxy-min"
      exit 1
    }

    # Activate, list: the shared driver, whose UUID the whole path below is
    # driven by.
    #
    # The installed-pair env swap is scoped to this subshell (SC2030/SC2031)
    # and lives HERE, in the caller: a swap the driver made inside itself
    # would die with its command-substitution subshell, and the exec,
    # destroy, ls and stop below would run on the lane's pair, not the
    # installed one.
    # shellcheck disable=SC2030,SC2031
    export HOME="$sb_home" MINIMAL_BIN="$sb_home/.local/bin" PATH="$sb_home/.local/bin:$PATH"
    unset MINVMD_KERNEL_PATH MINVMD_ROOTFS_PATH MINVMD_INITRAMFS MINVMD_GVPROXY_BIN
    sb_sid="$(drive_installed_vm_pair \
      "$sb_seed" "$sb_name" "$sb_root/activate.err" \
      "the stock-installed pair failed to activate a VM box" \
      "the stock-installed VM session")" || {
      sb_print_installed_components
      exit 1
    }
    echo "activation: the stock-installed pair brought up VM box '$sb_name' as session $sb_sid"

    # End to end: a command run IN the box, over the bridge, from the
    # installed pair alone. The cwd proves it ran in the session's mount
    # namespace, not on the host (the session exec proof's own marker).
    # shellcheck disable=SC2016 # $PWD must expand in the SESSION's shell, not here.
    sb_exec="$(mnl session exec "$sb_sid" 'echo STOCK_VM_BOX_OK $PWD' 2>"$sb_root/exec.err")" || {
      echo "::error::'min session exec' into the stock-installed VM box failed"
      echo "--- exec stderr ---"; cat "$sb_root/exec.err" 2>/dev/null || true
      sb_print_installed_components
      exit 1
    }
    # The same substring match proof_session_exec uses (line ~678): the
    # harness's contract for this command is "the marker is in the output",
    # not byte equality — an exact compare breaks on a trailing banner line.
    if [[ "$sb_exec" != *"STOCK_VM_BOX_OK /workbench"* ]]; then
      echo "::error::the exec did not run in the box (expected 'STOCK_VM_BOX_OK /workbench')"
      echo "--- exec stdout ---"; printf '%s\n' "$sb_exec"
      echo "--- exec stderr ---"; cat "$sb_root/exec.err" 2>/dev/null || true
      exit 1
    fi
    echo "end to end: the box answered its exec with: $sb_exec"

    # And the box leaves when the user destroys it: delisted, not lingering.
    mnl session destroy --force "$sb_sid" >/dev/null 2>&1 || {
      echo "::error::could not destroy the stock-installed VM session $sb_sid"
      exit 1
    }
    if mnl ls --raw 2>/dev/null | grep -Fqx "$sb_sid"; then
      echo "::error::the stock-installed VM session survived its destroy"
      exit 1
    fi
    echo "destroy: the box is gone from 'min ls'"

    # Diagnostics: the VM host daemon's start record names the images and the
    # switch it booted, resolved from the prefixes this install stamped.
    fresh_vm_start_record_asserts_installed_images "$sb_home" "$sb_gvproxy"

    mnl stop --force >/dev/null 2>&1 || true
  ); then
    :
  else
    fail
  fi
  echo "stock install runs VM boxes OK ($sb_arch: VM stack shipped, box activated, exec'd, destroyed delisted, images logged)"
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# Two named VMs on one machine, end to end (NET-052..NET-059). The story a
# second VM exists for: the boxes of one project must not see another's, and
# the operator never says which VM they mean — the name decides. Driven the
# way a user drives it, through `min` alone, on one host with both VMs up:
#
#   * `min --vm <name> session activate` creates the second VM — its own
#     state directory, bridge socket and host daemon under a per-name
#     subdirectory of the provider directory (NET-052/NET-054), the default
#     VM's paths left exactly where they were (NET-053);
#   * `min ls` — no flag — is ONE listing of both VMs: every box's row
#     carries the VM it lives on (NET-057), and every routing fact is named
#     per VM, because each VM's proxy publishes on a host port of its own
#     (NET-059's discovery half);
#   * `min session attach <box>` finds the VM from the box name alone, no
#     global flag (NET-058): it lands in the OTHER VM's box, says which VM
#     it landed in, and proves where it landed by reading a mark only that
#     box wrote;
#   * both VMs' box names route through the host's hostname surface at the
#     same time (NET-059): a request through each VM's published port
#     reaches that VM's box and is refused the other VM's name — the same
#     per-daemon matrix the two-daemons proof pins natively, here for two
#     VMs, entered from the host the way a laptop actually enters;
#   * `min net forward`, the exposing verb this tree ships, addresses a box
#     by name on the two-VM host and relays for real. `min net expose` —
#     the verb NET-058 names beside attach, the one that reuses attach's
#     box-name resolution (crates/minimal/src/attach.rs) — has not landed,
#     so the cross-VM half of the exposing story is the resolution the
#     attach above proves (its per-path pin is the
#     box_name_resolves_vm_without_flag unit test); when it lands, this
#     beat becomes its e2e;
#   * stopping the NAMED VM leaves the default VM serving (NET-055): its
#     boxes still listed, its host daemon still running, its published
#     port still routing.
#
# The diagnostics this case owes are the two VM host daemons' own start
# records: one line per boot, each naming its VM and its state directory
# (crates/minvmd/src/cmd/run.rs), in the one log directory every VM of a
# state base shares — the support bundle's answer to "which VM is this?".
# Both boots happen INSIDE this case — the default VM is stopped first, so
# neither record can belong to an earlier case's daemon — each under the
# RUST_LOG ride that keeps the INFO record alive.
proof_two_named_vms_on_one_machine() {
  # Gates, by observed fact, in the fresh-install KVM proofs' shape: a
  # native run hosts no VMs to name (its one daemon refuses `--vm`), a host
  # without the guest images cannot boot even one VM, a switchless VM
  # target can neither mint a box (the in-guest pkgs clone needs the
  # switch's egress) nor publish either proxy (the publish rides the host
  # gvproxy) so the routing half would be staging nothing, and on Linux the
  # hypervisor is /dev/kvm — macOS needs no such gate, libkrun is its
  # hypervisor.
  if [ "$min_daemon" != minvmd ]; then
    echo "two_named_vms_on_one_machine SKIPPED (this run drives '$min_daemon': a named VM is a minvmd-backed story)"
    return 0
  fi
  locate_vm_guest_images
  if [ ! -f "$STAGED_KERNEL" ] || [ ! -f "$STAGED_ROOTFS" ] || [ ! -f "$STAGED_INITRAMFS" ]; then
    echo "two_named_vms_on_one_machine SKIPPED (guest images not available)"
    return 0
  fi
  if [ -z "${MINVMD_GVPROXY_BIN:-}" ] || [ ! -x "$MINVMD_GVPROXY_BIN" ]; then
    echo "two_named_vms_on_one_machine SKIPPED (no MINVMD_GVPROXY_BIN: this target has no switch, so no box could mint and neither VM could publish its proxy)"
    return 0
  fi
  if [ "$(uname -s)" = Linux ] && { [ ! -e /dev/kvm ] || [ ! -w /dev/kvm ]; }; then
    echo "two_named_vms_on_one_machine SKIPPED (no writable /dev/kvm: this host cannot boot a VM)"
    return 0
  fi

  echo "::group::two named VMs on one machine (NET-052..NET-059)"

  # The case's own names. The VM is `alpha` — the name the minvmd fixtures
  # use (crates/minvmd/tests/named_vm_integration.rs), so a reader maps this
  # run onto them — and a legal one: 5 bytes of lowercase ASCII inside the
  # 24-byte budget paths::validate_vm_name binds, adding exactly one path
  # component to every socket below. $WORK is already one component deeper
  # than a stock ~/.local/state, and the deepest path this case creates
  # (alpha's switch socket) stays under the 108-byte sun_path bound
  # crates/minvmd/src/sock.rs enforces.
  TWO_VM_NAME="alpha"
  tw_name="$TWO_VM_NAME"
  TWO_VM_A_NAME="e2e-two-vm-a"   # the default VM's box
  TWO_VM_B_NAME="e2e-two-vm-b"   # alpha's box
  TWO_VM_A_PORT=18090            # box A's in-box responder
  TWO_VM_B_PORT=18091            # box B's in-box responder
  TWO_VM_LOCAL_PORT=18093         # the `min net forward` laptop-side listener
  TWO_VM_A_MARKER="TWO_VM_A_OK"  # what box A's responder answers
  TWO_VM_B_MARKER="TWO_VM_B_OK"  # what box B's responder answers
  # The default VM's state directory is the provider root itself — its paths
  # are unchanged (NET-053) — and the named VM's is the per-name
  # subdirectory of it (NET-054).
  tw_root="$XDG_STATE_HOME/minimal/providers/local-minvmd0"
  tw_alpha="$tw_root/$tw_name"

  # The named VM's own CLI surface: the same harness args plus the one flag
  # that selects the VM, exactly as a user types it.
  two_vm_mn() {
    # shellcheck disable=SC2086
    min ${E2E_MINIMAL_ARGS:-} --vm "$tw_name" "$@"
  }

  # The host port one VM's hostname proxy published, read from a `min ls`
  # listing's discovery line: `HOSTNAME PROXY:  <vm> listening on
  # 127.0.0.1:<port>`. awk's field compare, not a substring: the VM column
  # is padded, and one VM's name can be a prefix of another's.
  two_vm_ls_proxy_port() {
    printf '%s\n' "${2:-}" | awk -v vm="$1" \
      '$1 == "HOSTNAME" && $2 == "PROXY:" && $3 == vm {
         sub(/^127\.0\.0\.1:/, "", $6); print $6; exit
       }'
  }

  # One request from the HOST through one VM's published proxy port — the
  # way a laptop enters: HTTP(S)_PROXY points at the published port, the
  # request lands in that VM's in-guest proxy, which resolves the name in
  # its own registry and dials its own box. $1 = the published port, $2 =
  # the URL, $3 = the label the transcript line carries.
  two_vm_route() {
    TWO_VM_ROUTE_LABEL="$3"
    TWO_VM_STATUS="$(curl -sS --max-time 20 -x "http://127.0.0.1:$1" \
      -o "$WORK/two-vm-route.body" -w '%{http_code}' "$2" 2>"$WORK/two-vm-route.err" \
      | tail -n1 | tr -d '\r\n')"
    TWO_VM_BODY="$(cat "$WORK/two-vm-route.body" 2>/dev/null || true)"
    echo "$3: GET $2 via 127.0.0.1:$1 -> HTTP ${TWO_VM_STATUS:-<none>} ${TWO_VM_BODY:0:48}"
  }
  # Asserts the last `two_vm_route`: $1 = the HTTP status, $2 = a substring
  # the body must carry ("" to skip).
  two_vm_route_want() {
    if [ "${TWO_VM_STATUS:-}" != "$1" ]; then
      echo "::error::$TWO_VM_ROUTE_LABEL: expected HTTP $1, got '${TWO_VM_STATUS:-<none>}'"
      echo "--- curl stderr ---"; cat "$WORK/two-vm-route.err" 2>/dev/null || true
      fail
    fi
    if [ -n "$2" ] && [[ "${TWO_VM_BODY:-}" != *"$2"* ]]; then
      echo "::error::$TWO_VM_ROUTE_LABEL: the answer does not carry '$2' (got: '${TWO_VM_BODY:-<empty>}')"
      fail
    fi
  }

  # The in-box responder, the proxy proof's socat form verbatim: socat is a
  # launcher baseline package every box ships at /usr/bin, and the response
  # is written by the SESSION's shell so the Content-Length can never drift
  # from the body it frames. $1 = the runner (mnl or two_vm_mn), $2 = the
  # session id, $3 = the listen port, $4 = the marker to answer with.
  two_vm_start_responder() {
    local runner="$1" sid="$2" port="$3" marker="$4" ready
    "$runner" session exec "$sid" 'test -x /usr/bin/socat' >/dev/null 2>&1 \
      || { echo "::error::the session has no socat at /usr/bin/socat (a launcher baseline package — every box ships one)"; fail; }
    "$runner" session exec "$sid" \
      "body=$marker; printf \"HTTP/1.1 200 OK\r\nContent-Length: \${#body}\r\nConnection: close\r\n\r\n%s\" \"\$body\" > /home/http200" \
      >/dev/null 2>"$WORK/two-vm-responder.err" \
      || { echo "::error::could not write the in-box responder's response"; cat "$WORK/two-vm-responder.err" 2>/dev/null || true; fail; }
    "$runner" session exec "$sid" \
      "nohup /usr/bin/socat TCP-LISTEN:$port,reuseaddr,fork SYSTEM:\"cat /home/http200\" >/dev/null 2>&1 &" \
      >/dev/null 2>"$WORK/two-vm-responder.err" \
      || { echo "::error::could not start the in-box responder"; cat "$WORK/two-vm-responder.err" 2>/dev/null || true; fail; }
    ready=""
    for _ in $(seq 1 40); do
      if [ "$("$runner" session exec "$sid" \
        "curl -sS --max-time 5 -o /dev/null -w '%{http_code}' http://127.0.0.1:$port/" \
        2>/dev/null || true)" = "200" ]; then
        ready=1; break
      fi
      sleep 0.25
    done
    if [ -z "$ready" ]; then
      echo "::error::the in-box responder never answered a direct curl on 127.0.0.1:$port"
      echo "--- responder stderr ---"; cat "$WORK/two-vm-responder.err" 2>/dev/null || true
      fail
    fi
    echo "responder: $runner session $sid answers 127.0.0.1:$port with $marker"
  }

  # The VM host daemon log every VM of this state base shares (one dated
  # file per day; the newest is the live one), and the lines it gained since
  # a snapshot count. The two start records asserted below must be THIS
  # run's, so they are read from the tail after the snapshot — never from
  # the whole file, which on a whole-lane run carries the fresh-install
  # proofs' boots too.
  two_vm_minvmd_log() {
    find "$XDG_STATE_HOME/minimal/logs" -maxdepth 1 -name 'minvmd.log*' -type f 2>/dev/null \
      | sort | tail -n1
  }
  two_vm_log_since() {
    local f
    f="$(two_vm_minvmd_log)"
    [ -n "$f" ] || return 0
    tail -n "+$(($1 + 1))" "$f"
  }

  # ---- two VMs, each with its own box --------------------------------------
  # The default VM comes down first, whatever an earlier case left running:
  # both boots must happen in THIS case, or the two start records below
  # could belong to an earlier case's daemon and the diagnostics beat would
  # be vacuous. `stop --force` answers the exit prompt a live box would
  # print, and `min stop` waits for the VM to finish shutting down
  # (crates/minimal/src/autospawn.rs), so the status poll is a backstop,
  # not the wait.
  mnl stop --force >/dev/null 2>&1 || true
  tw_stopped=""
  for _ in $(seq 1 30); do
    case "$(minvmd status --json 2>/dev/null || true)" in
      *'"state":"stopped"'*) tw_stopped=1; break ;;
    esac
    sleep 1
  done
  if [ -z "$tw_stopped" ]; then
    echo "::error::the default VM never reached 'stopped' after 'min stop --force' — a VM still up here would make the start-record assertion below someone else's"
    minvmd status --json 2>&1 || true
    fail
  fi
  echo "stop: the default VM is down; both boots happen in this case"
  # The shared log snapshot both start records must land after.
  tw_log="$(two_vm_minvmd_log)"
  tw_log_lines=0
  if [ -n "$tw_log" ]; then tw_log_lines="$(wc -l < "$tw_log" | tr -d ' ')"; fi

  # Box A on the default VM. The RUST_LOG filter rides each of the two
  # activates that autospawn a daemon, command-local (the house pattern from
  # drive_installed_vm_pair): the 'starting VM' record is INFO, a daemon's
  # filter comes from RUST_LOG at autospawn, and this harness runs the whole
  # lane at `warn` — which would drop the records the diagnostics beat
  # asserts before they reached any sink.
  TWO_VM_SEED_A_DIR="$(hook_mktemp /tmp/mnltwa.XXXXXX)"
  hook_seed_preamble > "$TWO_VM_SEED_A_DIR/minimal.toml"
  mkdir "$TWO_VM_SEED_A_DIR/.git"
  tw_a_sid="$(cd "$TWO_VM_SEED_A_DIR" && RUST_LOG="warn,minvmd=info" \
      mnl session activate . --no-prompt --name "$TWO_VM_A_NAME" \
      2>"$WORK/two-vm-a-activate.err")" \
    || { echo "::error::'min session activate' for the default VM's box failed"
         echo "--- stderr ---"; cat "$WORK/two-vm-a-activate.err" 2>/dev/null || true
         fail; }
  tw_a_sid="$(printf '%s\n' "$tw_a_sid" | tail -n1 | tr -d '\r')"
  echo "box A: $tw_a_sid ($TWO_VM_A_NAME) on VM default — min session activate, no flag"

  # Box B on the NAMED VM — the case's own subject: `min --vm alpha session
  # activate` creates the VM if it is not there, because autospawn forwards
  # the name to the daemon it spawns (crates/minimal/src/autospawn.rs), so
  # this one command is both the creation and the first use of it.
  TWO_VM_SEED_B_DIR="$(hook_mktemp /tmp/mnltwb.XXXXXX)"
  hook_seed_preamble > "$TWO_VM_SEED_B_DIR/minimal.toml"
  mkdir "$TWO_VM_SEED_B_DIR/.git"
  tw_b_sid="$(cd "$TWO_VM_SEED_B_DIR" && RUST_LOG="warn,minvmd=info" \
      two_vm_mn session activate . --no-prompt --name "$TWO_VM_B_NAME" \
      2>"$WORK/two-vm-b-activate.err")" \
    || { echo "::error::'min --vm $tw_name session activate' failed to create the named VM and activate a box in it"
         echo "--- stderr ---"; cat "$WORK/two-vm-b-activate.err" 2>/dev/null || true
         fail; }
  tw_b_sid="$(printf '%s\n' "$tw_b_sid" | tail -n1 | tr -d '\r')"
  echo "box B: $tw_b_sid ($TWO_VM_B_NAME) on VM $tw_name — min --vm $tw_name session activate"

  # ---- NET-052/053/054: each VM's own state, the default's unchanged ------
  # The named VM's state directory is its own (NET-052): its state file and
  # its bridge socket live under the per-name subdirectory (NET-054) — and
  # the default VM's are still at the provider root, which is what NET-053
  # means here: alpha exists now, and the default VM did not move.
  [ -f "$tw_root/minvmd.toml" ] \
    || { echo "::error::the default VM has no state file at $tw_root/minvmd.toml"; fail; }
  [ -S "$tw_root/ssh.sock" ] \
    || { echo "::error::the default VM's bridge socket is not at $tw_root/ssh.sock — its paths moved (NET-053)"; fail; }
  [ -f "$tw_alpha/minvmd.toml" ] \
    || { echo "::error::the named VM has no state file of its own at $tw_alpha/minvmd.toml (NET-052/NET-054)"; fail; }
  [ -S "$tw_alpha/ssh.sock" ] \
    || { echo "::error::the named VM's bridge socket is not in its own state directory (NET-052)"; fail; }
  echo "state: default VM $tw_root/{minvmd.toml,ssh.sock} · named VM $tw_alpha/{minvmd.toml,ssh.sock}"

  # And both host daemons are alive at once — the daemon half of NET-052, at
  # the level only a real second VM reaches (the minvmd harness pins it with
  # lock-holders standing in for daemons; these are the two boots).
  tw_status_a="$(minvmd status --json 2>/dev/null || true)"
  tw_status_b="$(minvmd --vm "$tw_name" status --json 2>/dev/null || true)"
  case "$tw_status_a" in
    *'"state":"running"'*) ;;
    *) echo "::error::the default VM's host daemon is not running after its box activated ($tw_status_a)"
       fail ;;
  esac
  case "$tw_status_b" in
    *'"state":"running"'*) ;;
    *) echo "::error::the named VM's host daemon is not running — two VMs each need a daemon of their own (NET-052) ($tw_status_b)"
       fail ;;
  esac
  echo "daemons: default '$tw_status_a' · $tw_name '$tw_status_b'"

  # ---- NET-057: one listing, both VMs, every box attributed ----------------
  tw_ls="$(mnl ls 2>"$WORK/two-vm-ls.err")" \
    || { echo "::error::'min ls' — no flag — failed on a two-VM host"
         echo "--- stderr ---"; cat "$WORK/two-vm-ls.err" 2>/dev/null || true
         fail; }
  # The table's VM column: each box's row names the VM it lives on. awk
  # field compare again — the column is padded, and a name can be a prefix.
  if ! printf '%s\n' "$tw_ls" | awk -v vm=default -v sid="$tw_a_sid" \
       '$1 == vm && $2 == sid { found = 1 } END { exit !found }'; then
    echo "::error::min ls does not show box A's row attributed to VM default (NET-057)"
    echo "--- min ls output ---"; printf '%s\n' "$tw_ls"
    fail
  fi
  if ! printf '%s\n' "$tw_ls" | awk -v vm="$tw_name" -v sid="$tw_b_sid" \
       '$1 == vm && $2 == sid { found = 1 } END { exit !found }'; then
    echo "::error::min ls does not show box B's row attributed to VM $tw_name (NET-057)"
    echo "--- min ls output ---"; printf '%s\n' "$tw_ls"
    fail
  fi
  printf '%s\n' "$tw_ls" | sed 's/^/  /'
  # The machine surface of the same statement: `min ls --json` stays ONE
  # object whose single sessions array carries every VM's boxes, each
  # attributed — a pipeline parsing `.sessions` sees both VMs without ever
  # knowing a flag (crates/minimal/src/cmd/list.rs).
  for tw_vm in default "$tw_name"; do
    tw_json_has="$(mnl ls --json 2>/dev/null | python3 -c '
import json, sys
doc = json.load(sys.stdin)
print("yes" if any(s.get("vm") == sys.argv[1] for s in doc["sessions"]) else "no")' \
      "$tw_vm" 2>/dev/null || true)"
    if [ "$tw_json_has" != "yes" ]; then
      echo "::error::min ls --json's one sessions array does not attribute a box to VM '$tw_vm' (NET-057)"
      mnl ls --json 2>&1 | head -40 || true
      fail
    fi
  done
  echo "min ls --json: both VMs' boxes in one sessions array, each entry attributed to its VM"

  # ---- NET-059's discovery: two published ports, one per VM ----------------
  tw_port_a="$(two_vm_ls_proxy_port default "$tw_ls")"
  tw_port_b="$(two_vm_ls_proxy_port "$tw_name" "$tw_ls")"
  if [ -z "$tw_port_a" ] || [ -z "$tw_port_b" ]; then
    echo "::error::min ls did not report a HOSTNAME PROXY port for each VM — each VM's proxy must publish on a host port of its own, and the listing says which is whose (NET-059)"
    echo "--- min ls output ---"; printf '%s\n' "$tw_ls"
    fail
  fi
  if [ "$tw_port_a" = "$tw_port_b" ]; then
    echo "::error::both VMs published the same host proxy port 127.0.0.1:$tw_port_a — each needs a port of its own for both to route at once (NET-059)"
    fail
  fi
  echo "published proxy ports (min ls): default 127.0.0.1:$tw_port_a · $tw_name 127.0.0.1:$tw_port_b"

  # ---- the in-box responders the routing matrix answers through ------------
  two_vm_start_responder mnl "$tw_a_sid" "$TWO_VM_A_PORT" "$TWO_VM_A_MARKER"
  two_vm_start_responder two_vm_mn "$tw_b_sid" "$TWO_VM_B_PORT" "$TWO_VM_B_MARKER"

  # ---- NET-059: both names route at the same time, each through its VM -----
  # From the HOST, through each VM's published port — the only surface the
  # host has of either proxy, since each is reachable only inside its own
  # guest. Two routing halves and two refusals: a registry is per daemon,
  # so each VM's port answers its own boxes and refuses the other VM's
  # names — the matrix NET-027 pins for two daemons, here for two VMs.
  two_vm_route "$tw_port_a" "http://$TWO_VM_A_NAME.min.internal:$TWO_VM_A_PORT/" \
    "NET-059: through the default VM's port, its own box's name routes"
  two_vm_route_want 200 "$TWO_VM_A_MARKER"
  two_vm_route "$tw_port_b" "http://$TWO_VM_B_NAME.min.internal:$TWO_VM_B_PORT/" \
    "NET-059: through $tw_name's port, its own box's name routes — at the same time"
  two_vm_route_want 200 "$TWO_VM_B_MARKER"
  two_vm_route "$tw_port_a" "http://$TWO_VM_B_NAME.min.internal:$TWO_VM_B_PORT/" \
    "NET-059 refusal: the default VM's port does not know $tw_name's box name"
  two_vm_route_want 502 ""
  two_vm_route "$tw_port_b" "http://$TWO_VM_A_NAME.min.internal:$TWO_VM_A_PORT/" \
    "NET-059 refusal: $tw_name's port does not know the default VM's box name"
  two_vm_route_want 502 ""

  # ---- NET-058: the box name alone decides --------------------------------
  # A mark only alpha's box wrote, so the attach below proves WHERE it
  # landed by what it can read, not by trusting its own announcement.
  two_vm_mn session exec "$tw_b_sid" \
    "printf 'ATTACHED_IN_ALPHA_BOX_OK' > /home/two-vm-b.mark" \
    >/dev/null 2>"$WORK/two-vm-mark.err" \
    || { echo "::error::could not write the mark inside $tw_name's box"
         cat "$WORK/two-vm-mark.err" 2>/dev/null || true
         fail; }
  # The attach is driven from a shell whose selected VM is the DEFAULT one —
  # no --vm anywhere in its argv, exactly as a user's shell stands — so
  # finding e2e-two-vm-b is the CLI's own work: ask the selected VM first,
  # then every VM's socket, and say which one answered. Over a real pty (an
  # interactive attach's own requirement), answering the exit prompt with
  # `keep` so the session survives for the destroy below.
  # shellcheck disable=SC2086 # E2E_MINIMAL_ARGS must word-split.
  tw_attach_out="$(E2E_PTY_COMMANDS='cat /home/two-vm-b.mark
exit' E2E_PTY_ANSWER=keep python3 "$ROOT/scripts/e2e-attach-pty.py" - \
    min ${E2E_MINIMAL_ARGS:-} session attach "$TWO_VM_B_NAME" \
    2>"$WORK/two-vm-attach.err")" || {
    echo "::error::the pty attach by box name failed"
    echo "--- transcript ---"; printf '%s\n' "$tw_attach_out"
    echo "--- stderr ---"; cat "$WORK/two-vm-attach.err" 2>/dev/null || true
    fail
  }
  if [[ "$tw_attach_out" != *"Attaching to session $TWO_VM_B_NAME ("*"on VM $tw_name"* ]]; then
    echo "::error::the attach did not announce the VM it resolved the box name to (NET-058)"
    echo "--- transcript ---"; printf '%s\n' "$tw_attach_out"
    fail
  fi
  if [[ "$tw_attach_out" != *"ATTACHED_IN_ALPHA_BOX_OK"* ]]; then
    echo "::error::the attach landed outside $tw_name's box — the mark only that box wrote did not come back"
    echo "--- transcript ---"; printf '%s\n' "$tw_attach_out"
    fail
  fi
  printf '%s\n' "$tw_attach_out" | grep -F -- "on VM $tw_name" | sed 's/^/  /'
  echo "attach by name: 'min session attach $TWO_VM_B_NAME' — no flag — landed in $tw_name's box and said so"

  # ---- the shipping exposing verb: forward a box's service by name --------
  # `min net forward` stays in the foreground, prints its banner on stderr
  # once the laptop-side listener is bound, and relays every connection over
  # the session's direct-tcpip channel. Here the SESSION it names is chosen
  # by box name on a host running two VMs — the exposing verb this tree
  # ships. `min net expose` (NET-058's other verb) has not landed; the
  # cross-VM half of the exposing story is the resolution the attach above
  # proved, and no assertion is staged for a verb that does not exist.
  echo "opening the forward: min net forward $TWO_VM_A_NAME $TWO_VM_LOCAL_PORT:$TWO_VM_A_PORT"
  # Not `mnl ... &`: mnl is a function, so `$!` would be a subshell that
  # ignores SIGINT; exec the binary so the pid is `min`'s and Ctrl-C reaches
  # it.
  # shellcheck disable=SC2086
  ( exec min ${E2E_MINIMAL_ARGS:-} net forward "$TWO_VM_A_NAME" \
      "$TWO_VM_LOCAL_PORT:$TWO_VM_A_PORT" ) \
    >"$WORK/two-vm-forward.out" 2>"$WORK/two-vm-forward.err" &
  TWO_VM_FWD_PID=$!
  tw_fwd_ready=""
  for _ in $(seq 1 40); do
    if grep -q "Forwarding localhost:$TWO_VM_LOCAL_PORT" "$WORK/two-vm-forward.err" 2>/dev/null; then
      tw_fwd_ready=1; break
    fi
    kill -0 "$TWO_VM_FWD_PID" 2>/dev/null || break # died before it ever bound
    sleep 0.25
  done
  if [ -z "$tw_fwd_ready" ]; then
    echo "::error::'min net forward' by box name never bound its laptop-side listener (no 'Forwarding localhost:$TWO_VM_LOCAL_PORT' banner)"
    echo "--- forward stderr ---"; cat "$WORK/two-vm-forward.err" 2>/dev/null || true
    fail
  fi
  echo "forward banner: $(head -n1 "$WORK/two-vm-forward.err" 2>/dev/null || true)"
  tw_fwd_status="$(curl -sS --max-time 20 -o "$WORK/two-vm-fwd.body" \
    -w '%{http_code}' "http://127.0.0.1:$TWO_VM_LOCAL_PORT/" 2>"$WORK/two-vm-fwd.err")"
  tw_fwd_rc=$?
  tw_fwd_body="$(cat "$WORK/two-vm-fwd.body" 2>/dev/null || true)"
  if [ "$tw_fwd_rc" -ne 0 ] || [ "$tw_fwd_status" != "200" ] \
     || [[ "$tw_fwd_body" != *"$TWO_VM_A_MARKER"* ]]; then
    echo "::error::the request through the forward did not reach the box its NAME named (curl exit $tw_fwd_rc, HTTP ${tw_fwd_status:-<none>}, body '${tw_fwd_body:0:48}')"
    echo "--- curl stderr ---"; cat "$WORK/two-vm-fwd.err" 2>/dev/null || true
    echo "--- forward stderr ---"; cat "$WORK/two-vm-forward.err" 2>/dev/null || true
    fail
  fi
  echo "forward response: GET http://127.0.0.1:$TWO_VM_LOCAL_PORT/ -> HTTP $tw_fwd_status $tw_fwd_body"
  kill -INT "$TWO_VM_FWD_PID" 2>/dev/null || true
  for _ in $(seq 1 40); do
    kill -0 "$TWO_VM_FWD_PID" 2>/dev/null || break
    sleep 0.25
  done
  if kill -0 "$TWO_VM_FWD_PID" 2>/dev/null; then
    echo "::error::the forward did not end on Ctrl-C"
    echo "--- forward stderr ---"; cat "$WORK/two-vm-forward.err" 2>/dev/null || true
    kill -9 "$TWO_VM_FWD_PID" 2>/dev/null || true
    fail
  fi
  wait "$TWO_VM_FWD_PID" 2>/dev/null
  tw_fwd_rc=$?
  TWO_VM_FWD_PID=""
  if [ "$tw_fwd_rc" -ne 0 ]; then
    echo "::error::the forward exited $tw_fwd_rc on Ctrl-C (expected a clean 0)"
    echo "--- forward stderr ---"; cat "$WORK/two-vm-forward.err" 2>/dev/null || true
    fail
  fi
  echo "forward: closed on Ctrl-C, laptop-side listener gone with it"
  echo "note: 'min net expose' has not landed — the cross-VM box-name resolution is the one the attach above proved; 'min net forward' is the shipping exposing verb"

  # ---- NET-055: stopping one VM leaves the other serving -------------------
  # Box B goes first — a user's order — then the named VM itself, by the stop
  # hint the CLI prints for a named VM. The default VM must not notice.
  two_vm_mn session destroy --force "$tw_b_sid" >/dev/null 2>&1 \
    || { echo "::error::could not destroy $tw_name's box"; fail; }
  echo "destroy: box B on VM $tw_name — min --vm $tw_name session destroy --force"
  minvmd --vm "$tw_name" stop >"$WORK/two-vm-stop.out" 2>"$WORK/two-vm-stop.err" \
    || { echo "::error::'minvmd --vm $tw_name stop' failed"
         echo "--- stderr ---"; cat "$WORK/two-vm-stop.err" 2>/dev/null || true
         fail; }
  TWO_VM_NAME="" # teardown stops the named VM only while it may be alive
  tw_stopped=""
  for _ in $(seq 1 60); do
    case "$(minvmd --vm "$tw_name" status --json 2>/dev/null || true)" in
      *'"state":"stopped"'*) tw_stopped=1; break ;;
    esac
    sleep 1
  done
  if [ -z "$tw_stopped" ]; then
    echo "::error::the named VM never reached 'stopped' after 'minvmd --vm $tw_name stop'"
    minvmd --vm "$tw_name" status --json 2>&1 || true
    fail
  fi
  echo "stop: minvmd --vm $tw_name stop -> '$(minvmd --vm "$tw_name" status --json 2>/dev/null || true)'"
  # The named VM is gone from the one listing — a stopped VM contributes
  # nothing, silently, because a listing spanning every VM cannot error on
  # one that is down. And the default VM did not move: its box is still
  # listed, its daemon still running, its published port still routing its
  # box's name. With only one VM left the table loses its VM column — the
  # single-VM rendering every consumer of `min ls` has always read — so the
  # default's row is asserted by its id alone.
  tw_ls_after="$(mnl ls 2>&1)"
  if printf '%s\n' "$tw_ls_after" | grep -Fq -- "$tw_b_sid"; then
    echo "::error::the stopped named VM's box is still in the listing — a stopped VM must contribute nothing"
    echo "--- min ls output ---"; printf '%s\n' "$tw_ls_after"
    fail
  fi
  if ! printf '%s\n' "$tw_ls_after" | grep -Fq -- "$tw_a_sid"; then
    echo "::error::the default VM's box left the listing when $tw_name stopped (NET-055)"
    echo "--- min ls output ---"; printf '%s\n' "$tw_ls_after"
    fail
  fi
  case "$(minvmd status --json 2>/dev/null || true)" in
    *'"state":"running"'*) ;;
    *) echo "::error::the default VM's host daemon is no longer running after $tw_name stopped (NET-055)"
       minvmd status --json 2>&1 || true
       fail ;;
  esac
  two_vm_route "$tw_port_a" "http://$TWO_VM_A_NAME.min.internal:$TWO_VM_A_PORT/" \
    "NET-055: with $tw_name stopped, the default VM still routes its box's name"
  two_vm_route_want 200 "$TWO_VM_A_MARKER"
  # And the named VM's state outlives its daemon: the stop ends the VM, not
  # the state it was created with — it is still there to boot again.
  [ -f "$tw_alpha/minvmd.toml" ] \
    || { echo "::error::the named VM's state directory did not outlive its stop"; fail; }
  echo "state after stop: $tw_alpha/minvmd.toml still on disk — the named VM's state outlives its daemon"
  printf '%s\n' "$tw_ls_after" | sed 's/^/  /'

  # ---- the diagnostics: each daemon log names its VM and state directory ---
  # Two start records, one per boot, each naming the VM it started and the
  # state directory it serves — read from the tail after the snapshot, so
  # they are this run's on a whole-lane run too.
  tw_rec_a=""
  tw_rec_b=""
  for _ in $(seq 1 40); do
    [ -n "$tw_rec_a" ] || tw_rec_a="$(two_vm_log_since "$tw_log_lines" \
      | grep -F -- '"vm":"default"' | grep -F -- 'starting VM' | tail -n1 || true)"
    [ -n "$tw_rec_b" ] || tw_rec_b="$(two_vm_log_since "$tw_log_lines" \
      | grep -F -- "\"vm\":\"$tw_name\"" | grep -F -- 'starting VM' | tail -n1 || true)"
    [ -n "$tw_rec_a" ] && [ -n "$tw_rec_b" ] && break
    sleep 0.5
  done
  if [ -z "$tw_rec_a" ] || [ -z "$tw_rec_b" ]; then
    echo "::error::the VM host daemon log is missing a 'starting VM' record for one of the two VMs (default: '${tw_rec_a:-<none>}' · $tw_name: '${tw_rec_b:-<none>}')"
    echo "--- log dir ---"; ls -la "$XDG_STATE_HOME/minimal/logs" 2>/dev/null || echo "(no log dir)"
    echo "--- log (tail) ---"; tail -20 "$(two_vm_minvmd_log)" 2>/dev/null || true
    fail
  fi
  # Each record names its own state directory, and the two differ — NET-054's
  # per-name subdirectory as the log sees it.
  case "$tw_rec_a" in
    *'"state_dir":"'"$tw_root"'"'*) ;;
    *) echo "::error::the default VM's start record does not name its state directory"
       echo "--- record ---"; printf '%s\n' "$tw_rec_a"
       fail ;;
  esac
  case "$tw_rec_b" in
    *'"state_dir":"'"$tw_alpha"'"'*) ;;
    *) echo "::error::the named VM's start record does not name its own state directory"
       echo "--- record ---"; printf '%s\n' "$tw_rec_b"
       fail ;;
  esac
  echo "VM host daemon start record (default): $tw_rec_a"
  echo "VM host daemon start record ($tw_name): $tw_rec_b"

  mnl session destroy --force "$tw_a_sid" >/dev/null 2>&1 \
    || { echo "::error::could not destroy the default VM's box"; fail; }
  echo "destroy: box A on VM default — min session destroy --force"
  echo "two named VMs on one machine OK (own state each, one listing with both, box names resolving to their VM, both routing at once, stop one leaves the other)"
  echo "::endgroup::"
}

# ---------------------------------------------------------------------------
# Dispatch on the first argument: every proof in today's order when none is
# given, or exactly the named one. The names are the proof functions' suffixes.
case "${1:-}" in
  "")
    proof_lifecycle
    proof_session_exec
    proof_session_outbound_request
    proof_own_ip
    proof_own_ip_egress_declared_and_enforced
    proof_task_run
    proof_hooks
    proof_skip_scaffold
    proof_sandbox
    proof_restart
    proof_fresh_install_own_ip_ingress_publishes_loopback
    proof_network_posture_from_stock_install
    proof_fresh_linux_kvm_activate_local_minvmd
    proof_fresh_arm64_kvm_activate_local_minvmd
    proof_linux_stock_install_runs_vm_boxes
    proof_native_resolution_without_proxy_env
    proof_hostnames_recover_and_two_daemons_route
    proof_min_internal_names_through_proxy
    proof_proxy_refuses_like_direct
    proof_retired_surfaces_gone
    proof_switch_steers_proxy_mac_frames_to_the_host_stack
    proof_switch_answers_no_arp_for_the_proxy_address
    proof_two_named_vms_on_one_machine
    ;;
  lifecycle | session_exec | session_outbound_request | own_ip | own_ip_egress_declared_and_enforced | task_run | hooks \
    | skip_scaffold | sandbox | restart | fresh_install_own_ip_ingress_publishes_loopback \
    | network_posture_from_stock_install | native_resolution_without_proxy_env \
    | hostnames_recover_and_two_daemons_route \
    | min_internal_names_through_proxy | proxy_refuses_like_direct | retired_surfaces_gone \
    | fresh_linux_kvm_activate_local_minvmd | fresh_arm64_kvm_activate_local_minvmd \
    | linux_stock_install_runs_vm_boxes | two_named_vms_on_one_machine \
    | switch_steers_proxy_mac_frames_to_the_host_stack | switch_answers_no_arp_for_the_proxy_address)
    "proof_$1"
    ;;
  *)
    echo "usage: $0 [case]"
    echo "  no argument: every proof, in the whole-lane order"
    echo "  cases: lifecycle session_exec session_outbound_request own_ip own_ip_egress_declared_and_enforced task_run hooks"
    echo "         skip_scaffold sandbox restart fresh_install_own_ip_ingress_publishes_loopback"
    echo "         network_posture_from_stock_install native_resolution_without_proxy_env"
    echo "         fresh_linux_kvm_activate_local_minvmd fresh_arm64_kvm_activate_local_minvmd"
    echo "         linux_stock_install_runs_vm_boxes"
    echo "         hostnames_recover_and_two_daemons_route"
    echo "         min_internal_names_through_proxy proxy_refuses_like_direct retired_surfaces_gone"
    echo "         switch_steers_proxy_mac_frames_to_the_host_stack switch_answers_no_arp_for_the_proxy_address"
    echo "         two_named_vms_on_one_machine"
    exit 2
    ;;
esac

echo "session e2e OK"
