# justfile — repo-wide task runner; the local twin of the frozen CI workflows
# (docs/ci-strategy.md §8: CI YAML schedules, the logic lives here + scripts/).
# OS-specific recipes carry [linux]/[macos] attributes — `just --list` shows
# only this host's. `just --list` renders ONLY the last comment line above a
# recipe, so that line must be a standalone summary (warnings included);
# rationale, CI pointers and caveats go above it, separated by a bare `#`.

scratch      := justfile_directory() / ".scratch"
arch         := arch()
musl-target  := arch + "-unknown-linux-musl"
# Flat libkrun link/runtime prefix for the DYNAMIC upstream package (Linux;
# macOS links the Homebrew install). No longer on the dev stack's path — kept
# for `just libkrun`, which still fetches it.
krun-prefix  := env('HOME') / ".krun"
# Prefix for the STATIC libkrun the dev stack links (Linux). Built from the
# vendored pin, not fetched; `just clean` removes it.
krun-static  := scratch / "libkrun-static" / musl-target
# Guest networking features baked into the initramfs (networking-wg deferred).
features     := "networking-proxy"
kernel       := scratch / "vmlinuz"
rootfs       := scratch / "rootfs.img"
initramfs    := scratch / "initramfs.cpio"
gvproxy      := scratch / "gvproxy"
# On Linux minvmd builds for the musl target (static libkrun — the linkage
# users receive), so it lands under target/<triple>/ rather than target/debug.
# macOS keeps the native debug dir.
minvmd-dir   := if os() == "linux" { justfile_directory() / "target" / musl-target / "debug" } else { justfile_directory() / "target/debug" }
minvmd-bin   := minvmd-dir / "minvmd"
minimald-bin := justfile_directory() / "target/debug/minimald"
# The CLI crate is `minimal`; its [[bin]] target is `min`.
min-bin      := justfile_directory() / "target/debug/min"
# State dir for the host-native minimald that `just up` runs on Linux.
native-dir   := scratch / "native-state"

# The workspace doesn't compile natively on macOS (minimald/lcache/mctx are
# Linux-only): scope to the darwin-capable crates there; `just test-cross`
# covers the rest. The Linux lanes run nextest's ci profile; macOS has none.
scope      := if os() == "macos" { "-p minvmd -p sessions" } else { "--workspace" }
# Crates carrying a `fuzz/` workspace. `rcache` is Linux-only: it pulls in
# `lcache`, which uses the Linux-only `common::renameat2`.
fuzz-crates := if os() == "macos" { "args common diagnostics graph mfile paths" } else { "args common diagnostics graph mfile paths rcache" }
ci-profile := if os() == "macos" { "" } else { "--profile ci" }
e2e-env    := "E2E_VM=1 E2E_PROJECT_DIR=/tmp" + if os() == "linux" { " E2E_MINIMAL_ARGS='--provider local-minvmd'" } else { "" }

# Shared dev-stack env: target/debug on PATH so autospawn finds sibling
# binaries; MINVMD_* are inert outside the VM recipes. 150s timeouts: the
# generic guest kernel can spend 40-70s probing hardware before pid-1 starts,
# overrunning the 60s READY / 75s autospawn / 30s lifecycle defaults.
#
# minvmd-dir leads: on Linux it holds the musl build, and `min` autospawns
# `minvmd` by bare name. No LD_LIBRARY_PATH — minvmd links libkrun statically
# and dlopens nothing, so there is nothing for the loader to resolve.
export PATH := minvmd-dir + ":" + justfile_directory() / "target/debug:" + env('PATH')
export MINVMD_KERNEL_PATH := kernel
export MINVMD_ROOTFS_PATH := rootfs
export MINVMD_INITRAMFS := initramfs
export MINVMD_READY_TIMEOUT_SECS := env('MINVMD_READY_TIMEOUT_SECS', '150')
export MINIMAL_SPAWN_TIMEOUT_SECS := env('MINIMAL_SPAWN_TIMEOUT_SECS', '150')
export MINVMD_LIFECYCLE_BOOT_TIMEOUT_SECS := env('MINVMD_LIFECYCLE_BOOT_TIMEOUT_SECS', '150')

[private]
default:
    @just --list

# ── build & fetch ────────────────────────────────────────────────────────────
#
# Prereqs — macOS: `brew install slp/krun/libkrun zstd jq`.
# Linux: a KVM host with kvm-group membership, Rust + protoc + jq + cpio + zstd.
# See crates/minvmd/README.md for the manual bring-up.

# Prebuilt from the public cache via the per-commit package index — nothing is
# built or materialized locally (scripts/fetch-prebuilt.sh; pkgs commit pinned
# in .minimal/minimal.toml).
#
# Fetch the prebuilt guest kernel + generic rootfs (`just clean` forces a refresh).
artifacts:
    @mkdir -p {{scratch}}
    @[ -f {{kernel}} ] || scripts/fetch-prebuilt.sh kernel {{kernel}} {{arch}}
    @[ -f {{rootfs}} ] || scripts/fetch-prebuilt.sh rootfs {{rootfs}} {{arch}}

# Not on the dev stack's path any more — see `libkrun-static`. Kept because
# nightly-tests.yml still builds against the upstream package, and this is how
# you reproduce that locally.
#
# Fetch the prebuilt DYNAMIC libkrun + libkrunfw into the link/runtime prefix.
[linux]
libkrun:
    scripts/fetch-prebuilt.sh krun {{krun-prefix}} {{arch}}

# The linkage Linux users actually receive, and what `minvmd-build` and
# `test-vm` link against. Built from the vendored pin rather than fetched.
# Skips when already built; `just clean` forces a rebuild.
#
# Build the STATIC libkrun (libkrun.a) from the vendored pin.
[linux]
libkrun-static:
    @[ -f {{krun-static}}/libkrun.a ] || scripts/build-libkrun-linux.sh {{krun-static}} {{musl-target}}

# Fetch the pinned gvproxy switch (guest egress + own-IP; missing = switchless boot).
gvproxy:
    @mkdir -p {{scratch}}
    @[ -x {{gvproxy}} ] || scripts/fetch-gvproxy.sh {{gvproxy}}

# Cross-compile minimald → initramfs /init with the networking features.
initramfs:
    FEATURES={{features}} scripts/build-initramfs.sh {{initramfs}} {{musl-target}}

# Compiles the guest minimald here, then hands the binary to
# scripts/build-initramfs.sh via MINIMALD_BIN (its prebuilt mode), so the script
# packs the cpio without compiling anything itself. That sidesteps the script's
# `cross` fallback, which is what `just initramfs` lands on when it can't prove a
# usable host toolchain — on macOS it can never prove one, because it compares a
# raw `uname -m` ("arm64") against the target triple's arch ("aarch64").
#
# REQUIREMENTS — all must already be on PATH; use `just initramfs` (Docker +
# `cross`) instead when they are not:
#   - a Rust toolchain with the `{{musl-target}}` target installed
#   - cargo-zigbuild and zig, which supply the musl linker for the cross link
#
# Build minimald → initramfs /init using the cross toolchain on PATH (no container).
initramfs-nodocker:
    cargo zigbuild -p minimald --profile initramfs \
      --target {{musl-target}} --features {{features}}
    MINIMALD_BIN="{{justfile_directory()}}/target/{{musl-target}}/initramfs/minimald" \
      scripts/build-initramfs.sh {{initramfs}} {{musl-target}}

# The ad-hoc (-s -) hypervisor-entitlement codesign must be the LAST touch:
# any later cargo call that relinks minvmd drops it (EINVAL from krun_start_enter).
#
# Build minvmd (debug); codesign is the last touch.
[macos]
minvmd-build:
    cargo build -p minvmd --bin minvmd --locked
    codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - {{minvmd-bin}}

# The same target and linkage the release ships, so the dev stack exercises
# what users run. MINVMD_REQUIRE_LIBKRUN makes a missing libkrun.a an error
# rather than a silent runtime-bailing stub.
#
# Build minvmd (debug, static musl against the vendored libkrun.a).
[linux]
minvmd-build: libkrun-static
    MINVMD_REQUIRE_LIBKRUN=static LIBKRUN_PREFIX="{{krun-static}}" \
      cargo build -p minvmd --bin minvmd --locked --target {{musl-target}}

# Build the `min` CLI.
minimal-cli:
    cargo build -p minimal --locked

# Build a host-native (glibc) minimald with the networking features (for `just up`).
[linux]
minimald-build:
    cargo build -p minimald --features {{features}} --locked

# ── run & inspect ────────────────────────────────────────────────────────────

# Run the dev-built `min` CLI, args forwarded (e.g. `just min loadout list`).
min *args:
    @cargo build {{ if os() == "macos" { "-p minimal" } else { "-p minimal -p minimald" } }} --locked
    @"{{min-bin}}" {{args}}

# Print `export` lines for running the stack by hand: eval "$(just env)".
env:
    @printf 'export %s="%s"\n' \
      PATH "$PATH" \
      MINVMD_KERNEL_PATH "$MINVMD_KERNEL_PATH" MINVMD_ROOTFS_PATH "$MINVMD_ROOTFS_PATH" \
      MINVMD_INITRAMFS "$MINVMD_INITRAMFS" \
      MINVMD_GVPROXY_BIN "{{gvproxy}}" \
      MINVMD_READY_TIMEOUT_SECS "$MINVMD_READY_TIMEOUT_SECS" \
      MINIMAL_SPAWN_TIMEOUT_SECS "$MINIMAL_SPAWN_TIMEOUT_SECS"

# Subshell with the dev env loaded (exit to leave).
shell:
    @echo "minimal dev shell: target/debug on PATH, MINVMD_* set (exit to leave)"
    @MINVMD_GVPROXY_BIN="{{gvproxy}}" "${SHELL:-sh}"

# Report the supervised minvmd lifecycle state.
status:
    @"{{minvmd-bin}}" status

# Stop the supervised minvmd (SIGTERM → SIGKILL).
stop:
    @"{{minvmd-bin}}" stop

# The built libkrun.a goes too: it is keyed to the vendored pin, so a stale one
# would silently outlive a pin bump.
#
# Remove the bring-up artifacts this justfile manages (never all of .scratch).
clean:
    rm -f {{kernel}} {{rootfs}} {{initramfs}} {{gvproxy}}
    rm -rf {{scratch}}/libkrun-static

# Kill THIS checkout's stranded VM processes (they wedge the next VM's vsock bridge).
reap:
    scripts/reap-vms.sh

# Run before landing a guest-kernel bump (the `virtio-linux` version in pkgs, or
# the `locked_commit` that pulls it in): stable-tree commits touching vsock,
# virtio and the guest console — the surface the guest control plane rides on.
# `just kernel-review --pkgs ~/code/pkgs` reads both versions from a checkout.
# Review a guest-kernel bump (`just kernel-review 6.12.43 6.12.94`). Needs `gh`.
kernel-review *args:
    scripts/kernel-bump-review.sh {{args}}

# ── CI-parity gates ──────────────────────────────────────────────────────────

# Fail fast with an install hint when a required tool is missing.
_need tool hint:
    @command -v {{tool}} >/dev/null 2>&1 || { echo "'{{tool}}' not found — install with: {{hint}}" >&2; exit 1; }

_nextest: (_need "cargo-nextest" "cargo install cargo-nextest --locked")

# Apply rustfmt across the workspace (the fixer for a red `just fmt-check`).
fmt:
    cargo fmt --all

# Clippy's `--fix` can shuffle whitespace during its rewrites, so the trailing
# `cargo fmt` normalizes whatever landed. `--allow-dirty` skips the
# clean-worktree check — the usual case here is running mid-edit with
# staged/unstaged work.
#
# Autofix pass: fmt, clippy --fix, fmt again (safe to run mid-edit).
fix:
    cargo fmt --all
    cargo clippy {{scope}} --all-targets --fix --allow-dirty -- -D warnings
    cargo fmt --all

# CI: ci.yml `fmt`.
#
# Check rustfmt across the workspace without writing (`just fmt` is the fixer).
fmt-check:
    cargo fmt --all -- --check

# CI: ci.yml `clippy` / the ci-macos.yml `unit` scope.
#
# Clippy over all targets at this host's scope, warnings denied.
clippy:
    cargo clippy {{scope}} --all-targets --locked -- -D warnings

# A local advisories failure may just mean newer RUSTSEC data than CI's last run.
# CI: ci.yml `cargo-deny` (advisories/bans/licenses/sources).
#
# cargo-deny's all-features check: advisories, bans, licenses, sources.
deny: (_need "cargo-deny" "cargo install cargo-deny --locked")
    cargo deny --all-features check

# The declared MSRV floor (`package.rust-version` in the root Cargo.toml, inherited
# by every crate) still type-checks. cargo-hack drives the check against the
# declared version; the toolchain the check runs under is fetched by rustup.
# CI: nightly-tests.yml `msrv` (blocking).
#
# The declared MSRV floor still type-checks (cargo-hack).
msrv: (_need "cargo-hack" "cargo install cargo-hack --locked")
    cargo hack check --rust-version --workspace --all-targets --locked

# miri on `switch` — the vsock/subnet/MAC primitives (docs/ci-strategy.md §6
# "vsock framing"). Zero deps + pure integer/IP tests, so it compiles and
# interprets under miri in seconds. Needs the nightly toolchain + miri component:
#   rustup toolchain install nightly && rustup +nightly component add miri
# CI: nightly-tests.yml `miri` (non-blocking). Widen the set as more crates prove clean.
#
# miri over `switch`'s vsock/subnet/MAC primitives (needs nightly + the miri component).
miri:
    cargo +nightly miri test -p switch

# Kani bounded-verification harnesses over the pure security cores
# (rcache index_file parse, sessions PathDecision lattice). See
# scripts/kani.sh for install + the 0.67.0 pin rationale. #1109.
kani: (_need "cargo-kani" "cargo install --locked kani-verifier --version 0.67.0 && cargo kani setup")
    ./scripts/kani.sh

# Each `fuzz/` dir is its OWN workspace (so the nightly/sanitizer build can't
# perturb the main one), which means no workspace-wide build ever compiles
# them — they bitrot silently as the crates they target evolve. Plain `cargo
# check` on stable is enough to catch it: no nightly, no sanitizer.
#
# Type-check every cargo-fuzz target (bitrot guard). See docs/fuzzing.md.
fuzz-check:
    #!/usr/bin/env sh
    set -eu
    for c in {{fuzz-crates}}; do
        echo "== crates/$c/fuzz =="
        # No --locked: fuzz Cargo.lock files are gitignored (see fuzz/.gitignore).
        cargo check --manifest-path "crates/$c/fuzz/Cargo.toml" --all-targets
    done

# Needs nightly (libFuzzer + sanitizers). The RSS cap is load-bearing: these
# decoders can allocate from an untrusted length field, and the cap turns an
# unbounded-allocation bug into a catchable crash rather than an ambient OOM.
# Seed the corpus first for the structured targets (docs/fuzzing.md).
#
# Run one fuzz target: `just fuzz graph graph_from_bytes -max_total_time=60`.
fuzz crate target *args: (_need "cargo-fuzz" "cargo install cargo-fuzz --locked")
    #!/usr/bin/env sh
    set -eu
    cd crates/{{crate}}
    # libFuzzer never loads a dictionary on its own — it has to be passed. Any
    # target with a `fuzz/<target>.dict` gets it automatically; a dict only
    # biases mutation, so a target without one is not an error.
    dict=""
    [ -f "fuzz/{{target}}.dict" ] && dict="-dict=fuzz/{{target}}.dict"
    cargo +nightly fuzz run {{target}} -- -rss_limit_mb=2048 $dict {{args}}

# Unit + in-process integration tests. CI: every lane's core-tests suite.
test: _nextest
    cargo nextest run {{scope}} {{ci-profile}} --locked --no-tests=fail

# Doctests — nextest can't run them, so they are their own surface.
doctest:
    cargo test {{scope}} --doc --locked

# The old `cargo test -- --include-ignored` pre-PR surface; the env-gated
# VM/netns harnesses self-skip here (`just test-vm` runs those for real).
#
# The #[ignore] tests GitHub runners can't run — NO CI lane covers these.
[linux]
test-ignored: _nextest
    cargo nextest run --workspace --locked --profile ci --run-ignored ignored-only --no-tests=fail

# COST: the first run compiles the workspace under emulation and can take an
# hour+; later runs are incremental. HOME=/tmp: the container has no HOME.
#
# clippy + tests for the Linux-only crates from a Mac (musl in Docker; not minvmd).
[macos]
test-cross: (_need "cross" "cargo install cross --locked")
    @docker info >/dev/null 2>&1 || { echo "docker daemon not running (cross needs it) — start Docker Desktop or OrbStack" >&2; exit 1; }
    cross clippy --workspace --exclude minvmd --all-targets --target {{musl-target}} --locked -- -D warnings
    CROSS_CONTAINER_OPTS="--env HOME=/tmp" cross test --workspace --exclude minvmd --target {{musl-target}} --locked

# Not replicated: commitlint, the dogfood jobs, the installer lane (`just test-installer`).
#
# The local PR gate set, cheapest first.
[linux]
ci: fmt-check clippy deny test doctest test-ignored
    @echo "ci: local PR gates green"

# The local PR gate set, cheapest first (`just test-cross` covers the Linux-only crates).
[macos]
ci: fmt-check clippy deny test doctest
    @echo "ci: local PR gates green"

# Run the curl|sh installer's tests under every POSIX sh. CI: ci-shell-installer.yml.
test-installer:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v shellcheck >/dev/null 2>&1; then
        echo "== shellcheck --shell=sh =="
        shellcheck --shell=sh scripts/install.sh scripts/install_test.sh
    else
        echo "== shellcheck not found, skipping static check =="
    fi
    for sh in sh dash; do
        command -v "$sh" >/dev/null 2>&1 || { echo "== $sh not found, skipping =="; continue; }
        echo "== running install_test.sh under $sh =="
        SH="$sh" "$sh" scripts/install_test.sh
    done

# The reviewed harness the frozen ci-shell-installer.yml can't widen to; CI runs
# the same check through crates/common/tests/shell_lint.rs (part of `just test`).
#
# Shellcheck EVERY script under scripts/ (not just the installer's two files).
lint-shell:
    bash scripts/lint-shell.sh

# Shellcheck runs too, when present.
#
# Run the promotion provenance gate's test harness (stubbed `gh`, no network or auth).
test-promote-gate:
    #!/usr/bin/env bash
    set -euo pipefail
    if command -v shellcheck >/dev/null 2>&1; then
        echo "== shellcheck =="
        shellcheck scripts/verify-nightly-provenance.sh scripts/verify-nightly-provenance_test.sh
    else
        echo "== shellcheck not found, skipping static check =="
    fi
    echo "== running verify-nightly-provenance_test.sh =="
    bash scripts/verify-nightly-provenance_test.sh

# ── VM & e2e surfaces ────────────────────────────────────────────────────────

# VM recipes need writable /dev/kvm on Linux; no-op on macOS (HVF).
[macos]
_kvm:

[linux]
_kvm:
    @[ -e /dev/kvm ] && [ -w /dev/kvm ] || { echo "needs writable /dev/kvm (kvm group membership); one-off: sg kvm -c 'just <recipe>'" >&2; exit 1; }

# minvmd's VM harnesses (tests/*_integration.rs). CI: `test-kvm` / macOS `e2e`.
[macos]
test-vm: _nextest artifacts initramfs
    #!/usr/bin/env sh
    set -eu
    export MINVMD_E2E=1 MINVMD_BIN="{{minvmd-bin}}" XDG_STATE_HOME="{{scratch}}/test-state"
    # CI's archive pattern: build EVERYTHING, codesign minvmd LAST (a later
    # cargo call would relink it → entitlement lost), run from the archive.
    cargo nextest archive -p minvmd --locked --archive-file "{{scratch}}/nextest-archive.tar.zst"
    cargo build -p minvmd --bin minvmd --locked
    cargo build -p minimal --bin min --locked
    # Resolve the FFI-smoke binary from cargo itself (an mtime-sorted ls can
    # pick a stale build config), BEFORE codesign — the last cargo call allowed.
    testbin="$(cargo test -p minvmd --test krun_smoke_integration --no-run --locked --message-format=json 2>/dev/null \
      | sed -n 's/.*"executable":"\([^"]*krun_smoke_integration[^"]*\)".*/\1/p' | head -1)"
    [ -n "$testbin" ] && [ -x "$testbin" ] || { echo "krun_smoke_integration test binary not resolved via cargo" >&2; exit 1; }
    codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - "{{minvmd-bin}}"
    # The FFI smoke boots libkrun IN-PROCESS from the unsigned test binary:
    # run it kernel-less and directly — never via cargo, never from the filterset.
    env -u MINVMD_KERNEL_PATH -u MINVMD_ROOTFS_PATH -u MINVMD_INITRAMFS \
      "$testbin" --include-ignored --nocapture
    cargo-nextest nextest run --archive-file "{{scratch}}/nextest-archive.tar.zst" \
      --workspace-remap "{{justfile_directory()}}" --profile vm \
      --run-ignored all --no-tests=fail \
      -E 'binary(/_integration$/) and not binary(/_root_integration$/) and not binary(krun_smoke_integration)'

# minvmd's VM harnesses (tests/*_integration.rs). CI: ci-linux-kvm.yml `test-kvm`.
[linux]
test-vm: _nextest _kvm artifacts initramfs minvmd-build
    MINVMD_E2E=1 MINVMD_BIN="{{minvmd-bin}}" XDG_STATE_HOME="{{scratch}}/test-state" \
      MINVMD_REQUIRE_LIBKRUN=static LIBKRUN_PREFIX="{{krun-static}}" \
      cargo nextest run -p minvmd --profile vm --target {{musl-target}} \
      --run-ignored all --no-tests=fail \
      -E 'binary(/_integration$/) and not binary(/_root_integration$/)'

# CI: ci-linux-native.yml `minimald-root-integration`. The AppArmor policy
# can't unlock this surface — its namespaces come from hashed-path test
# binaries and /usr/bin/unshare, which a per-binary profile can't cover.
#
# minimald's netns/tap proofs (the tests sudo their own netns commands).
[linux]
test-root-integration: _nextest gvproxy
    @[ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "0" ] || { echo "this host restricts unprivileged user namespaces, which this surface needs from hashed-path test binaries (the AppArmor policy can't cover those); leave this lane to CI, or see docs/reference/linux-host-setup.md before relaxing the restriction host-wide" >&2; exit 1; }
    MINIMALD_NETNS_TEST=1 GVPROXY_BIN="{{gvproxy}}" cargo nextest run -p minimald --profile ci --run-ignored all --no-tests=fail -E 'binary(/_root_integration$/)'

# minvmd-build is LAST so its macOS codesign is the final touch on the binary.
#
# The unified session e2e against the VM-backed daemon. CI: the session e2e steps.
e2e: _kvm artifacts gvproxy initramfs minimal-cli minvmd-build
    {{e2e-env}} MINVMD_GVPROXY_BIN="{{gvproxy}}" ./scripts/session-e2e.sh

# CI: ci-linux-native.yml `native-daemon-e2e`.
#
# The SAME session e2e against a host-native minimald (no VM).
[linux]
e2e-native:
    cargo build -p minimald --bin minimald -p minimal --bin min --locked
    @just _userns-check
    ./scripts/session-e2e.sh

# Boots switchless like CI's step — MINVMD_GVPROXY_BIN deliberately not set.
#
# Daemon lifecycle proof (run --detach → Running → stop → Stopped). CI: `lifecycle`.
test-lifecycle: (_need "jq" "brew install jq (or apt install jq)") _kvm artifacts initramfs minvmd-build
    XDG_STATE_HOME="{{scratch}}/test-state" ./scripts/minvmd-lifecycle.sh

# nightly-tests.yml runs 10 reps, then `just bulk-upload`. The reap between
# iterations kills THIS checkout's live dev stack — not just the soak's own VMs.
#
# Nightly soak parity: N session-e2e reps; reaps between them — WILL kill your dev stack.
soak n="10": _kvm artifacts gvproxy initramfs minimal-cli minvmd-build
    {{e2e-env}} MINVMD_GVPROXY_BIN="{{gvproxy}}" ./scripts/soak-session-e2e.sh {{n}} "{{scratch}}/soak-logs"

# Each pass uploads a 49 MiB project (~13 MB on the wire) and destroys its session.
#
# Bulk host→guest upload proof (#869): N `min session activate`s of a large, compressible project.
bulk-upload n="5": _kvm artifacts gvproxy initramfs minimal-cli minvmd-build
    {{e2e-env}} MINVMD_GVPROXY_BIN="{{gvproxy}}" ./scripts/bulk-upload-e2e.sh {{n}}

# Mints N sessions CONCURRENTLY against one daemon (vs. the soak's N-serial reps),
# then bulk-tears-down — the supervision-under-load surface of ci-strategy §6.
#
# Concurrency stress proof. CI: a non-fatal step in nightly-tests.yml `session-e2e-soak`.
stress n="5": _kvm artifacts gvproxy initramfs minimal-cli minvmd-build
    {{e2e-env}} MINVMD_GVPROXY_BIN="{{gvproxy}}" ./scripts/stress-session-e2e.sh {{n}}

# ── stack bring-up ───────────────────────────────────────────────────────────
#
# `just up` = this host's default run mode; `just down` stops it.
#   macOS: Linux VM over Hypervisor.framework (the only macOS mode).
#   Linux: host-native minimald, no VM. `just up-kvm`: Linux + VM over KVM.
# Each backend has its own provider dir: the native daemon dials
# providers/local-minimald0/ssh.sock, the minvmd VM providers/local-minvmd0/ssh.sock
# (minvmd binds it directly, #690, so no bridge is needed). Select the VM
# backend with `--provider local-minvmd`.

# The daemon can reset the very first connect after boot/bind; retry briefly.
_smoke *args:
    #!/usr/bin/env sh
    for _ in 1 2 3 4 5; do
      MINVMD_GVPROXY_BIN="{{gvproxy}}" "{{min-bin}}" {{args}} ls && exit 0
      sleep 2
    done
    echo "min ls failed after retries" >&2; exit 1

# Bring the stack up: Linux VM over Hypervisor.framework (`min ls` autospawns minvmd).
[macos]
up: artifacts gvproxy initramfs minvmd-build minimal-cli && (_smoke)

# `just up` with the initramfs built from the cross toolchain on PATH rather than
# through `cross` — see `initramfs-nodocker` for what that requires. The iteration
# loop for a guest-minimald change: this rebuilds and repacks /init every run.
# minvmd-build stays LAST so its codesign is the final touch on the binary.
#
# Bring the stack up, building the initramfs without a container.
[macos]
up-nodocker: artifacts gvproxy initramfs-nodocker minvmd-build minimal-cli && (_smoke)

# Bring the stack up: host-native minimald, no VM (`just up-kvm` for the VM stack).
[linux]
up: minimald-build minimal-cli gvproxy && (_smoke "--minimal-dir" native-dir)
    #!/usr/bin/env sh
    set -eu
    sock="{{native-dir}}/providers/local-minimald0/ssh.sock"
    pidf="{{scratch}}/minimald.pid"
    mkdir -p "{{native-dir}}"
    # PID files survive reboots and PIDs get reused: only trust the pidfile if
    # the PID is still THIS checkout's minimald (prefix match tolerates the
    # "(deleted)" suffix a rebuilt binary leaves on /proc/<pid>/exe).
    owns() { case "$(readlink "/proc/$1/exe" 2>/dev/null)" in "{{minimald-bin}}"*) return 0 ;; *) return 1 ;; esac; }
    if [ -S "$sock" ] && [ -f "$pidf" ] && owns "$(cat "$pidf")"; then
      echo "native minimald already up: $sock"
    else
      rm -f "$sock" "$pidf"
      setsid "{{minimald-bin}}" \
        --minimal-state-dir "{{native-dir}}" --minimal-cache-dir "{{native-dir}}/cache" \
        run --instance-num 0 --gvproxy-bin "{{gvproxy}}" > "{{scratch}}/minimald.log" 2>&1 &
      echo $! > "$pidf"
      for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done
    fi
    [ -S "$sock" ] || { echo "minimald failed to bind $sock; see {{scratch}}/minimald.log" >&2; exit 1; }
    # Warn-only: the daemon runs without the AppArmor profile, but every
    # `activate` sandbox dies at uid_map EPERM until it's installed.
    just _userns-check || true
    echo "up: host-native minimald at $sock (pid $(cat "$pidf"))"
    echo "  own-IP demo: min --minimal-dir {{native-dir}} session activate -n net1 --network own-ip . && min --minimal-dir {{native-dir}} session attach net1"

# Bring the stack up: native Linux + one Linux VM over KVM (stop with `just stop`).
[linux]
up-kvm: _kvm artifacts gvproxy initramfs minvmd-build minimal-cli && (_smoke "--provider" "local-minvmd")
    MINVMD_GVPROXY_BIN="{{gvproxy}}" "{{minvmd-bin}}" run --detach --timeout "$MINVMD_READY_TIMEOUT_SECS"
    @echo "up-kvm: VM booted; minimald reachable at providers/local-minvmd0/ssh.sock"

# Stop the stack `just up` started.
[macos]
down: stop

# Stop the stack `just up` started (the host-native minimald).
[linux]
down:
    #!/usr/bin/env sh
    set -eu
    pidf="{{scratch}}/minimald.pid"
    [ -f "$pidf" ] || { echo "no native minimald running"; exit 0; }
    pid="$(cat "$pidf")"
    # Never signal a reused PID: the pidfile is only trusted if the process is
    # still this checkout's minimald (see the matching check in `up`).
    case "$(readlink "/proc/$pid/exe" 2>/dev/null)" in
      "{{minimald-bin}}"*) ;;
      *) rm -f "$pidf"; echo "stale pidfile (pid $pid is not this checkout's minimald); removed"; exit 0 ;;
    esac
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$pid" 2>/dev/null || true; rm -f "$pidf"
    echo "native minimald stopped (pid $pid)"

# Ubuntu 24.04+ gates unprivileged userns behind AppArmor. The fix is the
# installer's per-binary profile (grants userns to minimald ALONE — flipping
# the sysctl hands it to everything). Details: docs/reference/linux-host-setup.md.
[linux]
_userns-check:
    #!/usr/bin/env sh
    set -eu
    if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" = "0" ]; then exit 0; fi
    if [ -e /etc/apparmor.d/minimald ] && grep -rqs "{{minimald-bin}}" /etc/apparmor.d/tunables 2>/dev/null; then exit 0; fi
    echo "note: this host restricts unprivileged user namespaces (Ubuntu 24.04+);" >&2
    echo "  minimald's session sandbox cannot start until its AppArmor profile is" >&2
    echo "  installed — a one-time step that needs root:" >&2
    echo "      sudo scripts/install-apparmor-profile.sh --path {{minimald-bin}}" >&2
    exit 1
