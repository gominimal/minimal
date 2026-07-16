# justfile — repo-wide task runner. Lives at the workspace root.
#
# Recipes are grouped by crate where they're crate-specific.

# The -rel twins are repo-relative because the shim-VM materialize (see
# `artifacts`) can only write outputs back through repo-relative paths; the
# absolute forms are derived from them so guard, write, and consumers can
# never disagree.
scratch-rel := ".scratch"
scratch     := justfile_directory() / scratch-rel
# Host CPU arch — drives the materialized guest artifacts and the musl target.
# aarch64 on Apple Silicon; x86_64 on most Linux hosts.
arch        := arch()
musl-target := arch + "-unknown-linux-musl"
# Flat libkrun link/runtime prefix (Linux only; macOS uses the Homebrew install).
krun-prefix := env_var('HOME') / ".krun"
# Guest minimald networking features baked into the initramfs (R4.x): the HTTPS
# reverse proxy (mTLS). The WireGuard mesh peer (networking-wg) is disabled for
# now (UC7 / UC2b-A deferred).
features    := "networking-proxy"
kernel-rel  := scratch-rel / "vmlinuz"
rootfs-rel  := scratch-rel / "rootfs.img"
kernel      := justfile_directory() / kernel-rel
rootfs      := justfile_directory() / rootfs-rel
initramfs   := scratch / "initramfs.cpio"
gvproxy     := scratch / "gvproxy"
minvmd-bin  := justfile_directory() / "target/debug/minvmd"
# The CLI's binary target is `min` (crates/minimal/Cargo.toml [[bin]]); the
# crate it comes from is still `minimal`, hence `cargo build -p minimal`.
min-bin     := justfile_directory() / "target/debug/min"

# Re-run any time the entitlements file or binary changes. Ad-hoc signing
# (`-s -`) requires no Apple Developer membership; the binary only runs on the
# host that signed it, which is correct for dev builds.

# Build a release `minvmd` and code-sign it with the hypervisor entitlement.
codesign-minvmd:
    cargo build -p minvmd --release
    codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - {{justfile_directory()}}/target/release/minvmd

# ── minimal → minvmd → minimald bring-up (macOS/HVF or Linux/KVM) ───────────
#
# `just dm1` (macOS/HVF) and `just dm3` (Linux/KVM) bring the whole stack up
# with full guest networking:
#   1. materialize the guest kernel + generic rootfs into .scratch
#   2. cross-compile minimald → initramfs /init WITH the networking features
#   3. build minvmd (codesign on macOS), build the `min` CLI
#   4. run `min ls`, which auto-spawns `minvmd run --detach`; minvmd boots
#      the microVM whose initramfs pid-1 is minimald, which serves the session
#      over the host UDS bridge.
#
# Prereqs:
#   macOS  — `brew install slp/krun/libkrun`; the `minimal` shim on PATH.
#   Linux  — a KVM host; durable `kvm` group membership (`sudo usermod -aG kvm
#            $USER`, then re-login) so the autospawned minvmd can open /dev/kvm;
#            a Rust toolchain + protoc + jq + cpio. libkrun is fetched by `dm3`.
# See crates/minvmd/README.md for the manual equivalent.

# macOS: via the `minimal` SHIM (~/.minimal/shim/bin/minimal — runs the CLI in a
# VM; --output must be a repo-RELATIVE path, see the recipe). Distinct from the
# `min` binary this repo builds. Linux: via fetch-artifact.sh (builds `mip` from
# source).

# Materialize the guest kernel + generic rootfs into .scratch. Skips a fetch when
# the artifact already exists; `just clean` first to force a refresh.
artifacts:
    #!/usr/bin/env sh
    set -eu
    mkdir -p {{scratch}}
    # `minimal materialize` runs in a VM via the shim; on a cold cache its
    # overlay-sync can transiently drop the output ("copying output file I/O
    # error … No such file or directory"). Retry a few times before failing.
    #
    # The --output path MUST be repo-RELATIVE: outputs come back to the host
    # via the project-dir sync overlay, and an absolute path — even one under
    # the repo — reliably fails the copy-out with the same I/O error.
    materialize() {
      n=0
      until minimal materialize --output "$1" --arch "$2" "$3"; do
        n=$((n + 1))
        [ "$n" -ge 3 ] && { echo "materialize $3 failed after $n attempts" >&2; return 1; }
        echo "materialize $3 failed (attempt $n); retrying…" >&2
        rm -f "$1"
        sleep 2
      done
    }
    case "$(uname -s)" in
      Darwin)
        # Both artifacts present — nothing to fetch, so don't demand the shim.
        [ -f {{kernel}} ] && [ -f {{rootfs}} ] && exit 0
        # Resolve the shim: PATH first, then its install location — a dev
        # shell without ~/.minimal/shim/bin on PATH shouldn't fail here.
        if command -v minimal >/dev/null 2>&1; then :; elif [ -x "$HOME/.minimal/shim/bin/minimal" ]; then
          PATH="$HOME/.minimal/shim/bin:$PATH"
        else
          echo "the \`minimal\` shim is required (not on PATH, not at ~/.minimal/shim/bin/minimal); see the bring-up prereqs above" >&2
          exit 1
        fi
        [ -f {{kernel}} ] || materialize {{kernel-rel}} {{arch}} virtio-kernel
        [ -f {{rootfs}} ] || materialize {{rootfs-rel}} {{arch}} minvmd-rootfs
        ;;
      Linux)
        [ -f {{kernel}} ] || scripts/fetch-artifact.sh virtio-kernel {{kernel}} {{arch}}
        [ -f {{rootfs}} ] || scripts/fetch-artifact.sh minvmd-rootfs {{rootfs}} {{arch}}
        ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac

# macOS uses the Homebrew install, so this is a no-op there.

# Fetch libkrun + libkrunfw into the link/runtime prefix (Linux only).
libkrun:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Linux) scripts/fetch-libkrun.sh {{krun-prefix}} {{arch}} ;;
      *) echo "libkrun: macOS uses the Homebrew install; nothing to fetch" ;;
    esac

# Uses `cross`/Docker for the musl toolchain.

# Cross-compile minimald → initramfs /init with the networking features baked in.
initramfs:
    FEATURES={{features}} scripts/build-initramfs.sh {{initramfs}} {{musl-target}}

# Not yet consumed by `minvmd run`; provided for the netns/relay e2e flows.

# Fetch the pinned gvproxy switch binary into .scratch (skips if already present).
gvproxy:
    #!/usr/bin/env sh
    set -eu
    mkdir -p {{scratch}}
    [ -x {{gvproxy}} ] || scripts/fetch-gvproxy.sh {{gvproxy}}

# macOS: codesign with the hypervisor entitlement (must be the last thing to
# touch the binary). Linux: build with the libkrun prefix exported so build.rs
# links the real (non-stub) implementation.

# Build minvmd (debug).
minvmd-build: libkrun
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin)
        cargo build -p minvmd --bin minvmd --locked
        codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - {{minvmd-bin}}
        ;;
      Linux)
        export LIBKRUN_PREFIX="{{krun-prefix}}"
        export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        cargo build -p minvmd --bin minvmd --locked
        ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac

# Build the `min` CLI (from the `minimal` crate; its [[bin]] target is `min`).
minimal-cli:
    cargo build -p minimal --locked

# Run the `min` CLI against the workspace's own debug build. Prepends
# `target/debug/` to `$PATH` so `min`'s auto-spawn can find the sibling
# daemon binary (it invokes it by name). On Linux that sibling is minimald;
# on macOS minimald doesn't compile natively (hakoniwa/procfs are Linux-only)
# and the daemon is minvmd-hosted anyway, so only the CLI is built (use
# `just up` for the full VM bring-up). Arguments after `just min` are
# forwarded verbatim.
#
# Example:
#   just min activate --loadout helix --attach
#   just min loadout list
#   just min dirs
min *args:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) cargo build -p minimal ;;
      *)      cargo build -p minimal -p minimald ;;
    esac
    PATH="{{justfile_directory()}}/target/debug:$PATH" "{{min-bin}}" {{args}}

# Print `export` lines wiring the dev-built binaries and guest artifacts into
# the environment — the same setup `dm1`/`dm3` do internally, for running
# `min`/`minvmd` by hand against the built stack. Load into the current
# shell with:  eval "$(just env)"
env:
    #!/usr/bin/env sh
    set -eu
    printf 'export MINVMD_KERNEL_PATH="%s"\n' '{{kernel}}'
    printf 'export MINVMD_ROOTFS_PATH="%s"\n' '{{rootfs}}'
    printf 'export MINVMD_INITRAMFS="%s"\n' '{{initramfs}}'
    printf 'export MINVMD_BOOT_LOG="%s"\n' '{{scratch}}/boot.log'
    printf 'export MINVMD_GVPROXY_BIN="%s"\n' '{{gvproxy}}'
    printf 'export PATH="%s:$PATH"\n' '{{justfile_directory()}}/target/debug'
    case "$(uname -s)" in
      Linux) printf 'export LD_LIBRARY_PATH="%s${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\n' '{{krun-prefix}}' ;;
    esac

# Drop into a subshell with that environment loaded (exit to leave).
shell:
    #!/usr/bin/env sh
    set -eu
    eval "$(just env)"
    echo "minimal dev shell: target/debug on PATH, MINVMD_* set (exit to leave)"
    exec "${SHELL:-sh}"

# Report the supervised minvmd lifecycle state.
status:
    "{{minvmd-bin}}" status

# Stop the supervised minvmd (SIGTERM → SIGKILL).
stop:
    "{{minvmd-bin}}" stop

# Remove only the bring-up artifacts this justfile manages (.scratch is a shared
# scratchpad — do NOT blow the whole directory away).
clean:
    rm -f {{kernel}} {{rootfs}} {{initramfs}} {{gvproxy}} {{scratch}}/boot.log

# Run the curl|sh installer's test harness under every POSIX sh available. The
# installer targets strict POSIX sh, so dash conformance is checked alongside sh
# (spec docs/specs/07-spec-installer, Verification §2); shellcheck --shell=sh is
# run when present.
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

# ── CI-parity gates & test surfaces ──────────────────────────────────────────
#
# Local entry points for the same checks CI runs (docs/ci-strategy.md §8: the
# workflows are a thin frozen scheduler; the justfile + scripts/ are the
# reviewed logic). Each recipe's comment names its CI counterpart so parity is
# reviewable. OS dispatch follows the lanes: Linux gets the native/KVM
# surfaces, macOS the ci-macos ones plus cross-compiled (Docker) coverage of
# the Linux-only crates.

# Fail fast with an install hint when a required tool is missing.
_need tool hint:
    @command -v {{tool}} >/dev/null 2>&1 || { echo "'{{tool}}' not found — install with: {{hint}}" >&2; exit 1; }

# Apply rustfmt across the workspace (the fixer for a red `just fmt-check`).
fmt:
    cargo fmt --all

# CI parity: ci.yml `fmt`.
fmt-check:
    cargo fmt --all -- --check

# CI parity: ci.yml `clippy` (Linux, workspace-wide). On macOS the workspace
# doesn't compile natively (minimald/lcache/mctx are Linux-only), so mirror
# ci-macos.yml `unit` (-p minvmd); `just test-cross` covers the Linux-only
# crates from a Mac.
clippy:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) cargo clippy -p minvmd --all-targets --locked -- -D warnings ;;
      *)      cargo clippy --workspace --all-targets --locked -- -D warnings ;;
    esac

# CI parity: ci.yml `cargo-deny` (the EmbarkStudios action defaults to
# `cargo deny --all-features check`: advisories/bans/licenses/sources over the
# full feature graph, config deny.toml). A local advisories failure may just
# mean newer RUSTSEC data than CI's last run; nightly re-checks advisories
# blocking.
deny: (_need "cargo-deny" "cargo install cargo-deny --locked")
    cargo deny --all-features check

# Unit + in-process integration tests.
# CI parity: the core-tests composite on ci-linux-native.yml `tests` — the
# Linux branch is its exact command (--profile ci: fail-fast off, slow tests
# killed at 5x60s, junit to target/nextest/ci/junit.xml). On macOS this
# mirrors ci-macos.yml `unit` (-p minvmd -p sessions via nextest; the
# workspace is uncompilable there, and that job has no nextest profile) — run
# `just test-cross` for the Linux-only crates. Locally-runnable #[ignore]
# tests are a separate surface: `just test-ignored`.
test: (_need "cargo-nextest" "cargo install cargo-nextest --locked")
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) cargo nextest run -p minvmd -p sessions --locked --no-tests=fail ;;
      *)      cargo nextest run --workspace --locked --profile ci --no-tests=fail ;;
    esac

# The ungated #[ignore] tests — ignored only because GitHub runners can't run
# them (e.g. mctx's layer-init/build proofs need nested user namespaces,
# minimald's git_receive_pack proof), i.e. MEANT to be run on a dev machine.
# This is the surface `cargo test -- --include-ignored` used to cover in the
# pre-PR flow; no CI lane runs these, so a local run is the only gate. The
# env-gated VM/netns harnesses also match --run-ignored but self-skip without
# their MINVMD_E2E / MINIMALD_NETNS_TEST env (use `just test-vm` /
# `just test-root-integration` to actually run those). Linux-only: the crates
# carrying these tests don't compile natively on macOS.
test-ignored:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Linux) ;;
      *) echo "test-ignored is Linux-only (mctx/minimald don't compile natively here); SKIP on $(uname -s)"; exit 0 ;;
    esac
    command -v cargo-nextest >/dev/null 2>&1 || { echo "'cargo-nextest' not found — install with: cargo install cargo-nextest --locked" >&2; exit 1; }
    cargo nextest run --workspace --locked --profile ci --run-ignored ignored-only --no-tests=fail

# The Linux-crate surface from a macOS host: clippy + tests for every
# workspace crate except minvmd (libkrun linkage), cross-compiled to musl in
# Docker. This is the local stand-in for what the Linux lanes check natively —
# including minimald, which cannot compile on darwin. The container has no
# HOME, which breaks env::tests — hence HOME=/tmp.
#
# COST WARNING: the first run compiles the whole workspace for {{musl-target}}
# inside the container, and nickel-lang-parser's LALRPOP build script may run
# under CPU emulation — that first build can take an hour or more. Later runs
# reuse target/{{musl-target}} and are incremental. On Linux this is a clean
# SKIP: the native `just test`/`just clippy` already cover the workspace.
test-cross:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) ;;
      *) echo "test-cross is for macOS hosts; native 'just test' covers the workspace here. SKIP"; exit 0 ;;
    esac
    command -v cross >/dev/null 2>&1 || { echo "'cross' not found — install with: cargo install cross --locked" >&2; exit 1; }
    docker info >/dev/null 2>&1 || { echo "docker daemon not running (cross needs it) — start Docker Desktop or OrbStack" >&2; exit 1; }
    cross clippy --workspace --exclude minvmd --all-targets --target {{musl-target}} --locked -- -D warnings
    CROSS_CONTAINER_OPTS="--env HOME=/tmp" cross test --workspace --exclude minvmd --target {{musl-target}} --locked

# Doctests — nextest can't run them, so they are their own surface, exactly as
# CI treats them. CI parity: core-tests composite (`cargo test --workspace
# --doc --locked`); macOS covers the doc tests of the crates its unit lane
# tests.
doctest:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) cargo test -p minvmd -p sessions --doc --locked ;;
      *)      cargo test --workspace --doc --locked ;;
    esac

# The PR gate set, locally: quick gates (ci.yml fmt/clippy/cargo-deny) + core
# tests (nextest + doctests) + the locally-runnable #[ignore] tests (Linux;
# clean SKIP on macOS), cheapest first. On macOS add `just test-cross` when
# touching the Linux-only crates. Deliberately NOT replicated: commitlint
# (needs node + the PR commit range — docs/commit-conventions.md), the
# dogfood/minimal-check jobs (released-binary-vs-repo-config checks), and the
# path-filtered installer lane (`just test-installer` when touching
# scripts/install*).
ci: fmt-check clippy deny test doctest test-ignored
    @echo "ci: local PR gates green"

# minvmd's VM integration harnesses (crates/minvmd/tests/*_integration.rs).
# CI parity: ci-linux-kvm.yml `test-kvm` / ci-macos.yml `e2e` — the same
# `-p minvmd` scope those lanes archive, same filtersets, --profile vm,
# --run-ignored all, --no-tests=fail. The §10 suffix convention selects
# WITHIN that scope: a `*_integration.rs` harness in another crate is not
# picked up here or by the CI VM lanes today. XDG_STATE_HOME is isolated to
# .scratch so harness-spawned daemons can't clobber the real
# ~/.local/state/minimal. Stranded VMs after a failed run: `just reap`.
test-vm: (_need "cargo-nextest" "cargo install cargo-nextest --locked") artifacts gvproxy initramfs libkrun
    #!/usr/bin/env sh
    set -eu
    export MINVMD_E2E=1 MINVMD_BIN="{{minvmd-bin}}"
    export MINVMD_KERNEL_PATH="{{kernel}}" MINVMD_ROOTFS_PATH="{{rootfs}}"
    export MINVMD_INITRAMFS="{{initramfs}}" MINVMD_BOOT_LOG="{{scratch}}/boot.log"
    export XDG_STATE_HOME="{{scratch}}/test-state"
    case "$(uname -s)" in
      Darwin)
        # CI's archive pattern, for the same reason CI uses it: build
        # EVERYTHING first, codesign minvmd as the last touch (any later cargo
        # invocation with minvmd in its build graph relinks it → entitlement
        # lost → EINVAL from krun_start_enter), then run from the archive,
        # which never rebuilds.
        cargo nextest archive -p minvmd --locked --archive-file "{{scratch}}/nextest-archive.tar.zst"
        cargo build -p minvmd --bin minvmd --locked
        cargo build -p minimal --bin min --locked
        # Resolve the FFI-smoke binary from cargo itself (an mtime-sorted ls
        # can pick a stale binary from an abandoned build config), and do it
        # BEFORE codesign — it is the last cargo invocation allowed.
        testbin="$(cargo test -p minvmd --test krun_smoke_integration --no-run --locked --message-format=json 2>/dev/null \
          | sed -n 's/.*"executable":"\([^"]*krun_smoke_integration[^"]*\)".*/\1/p' | head -1)"
        [ -n "$testbin" ] && [ -x "$testbin" ] || { echo "krun_smoke_integration test binary not resolved via cargo" >&2; exit 1; }
        codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - "{{minvmd-bin}}"
        # FFI smoke (ci-macos.yml): boots libkrun IN-PROCESS from the
        # (unsigned) test binary, so it must run kernel-less and be invoked
        # directly — never via cargo (relink) and never from the filterset.
        env -u MINVMD_KERNEL_PATH -u MINVMD_ROOTFS_PATH -u MINVMD_INITRAMFS \
          "$testbin" --include-ignored --nocapture
        cargo-nextest nextest run --archive-file "{{scratch}}/nextest-archive.tar.zst" \
          --workspace-remap "{{justfile_directory()}}" --profile vm \
          --run-ignored all --no-tests=fail \
          -E 'binary(/_integration$/) and not binary(/_root_integration$/) and not binary(krun_smoke_integration)'
        ;;
      Linux)
        [ -e /dev/kvm ] && [ -w /dev/kvm ] || { echo "test-vm needs writable /dev/kvm; try: sg kvm -c 'just test-vm'" >&2; exit 1; }
        export LIBKRUN_PREFIX="{{krun-prefix}}"
        export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        cargo build -p minvmd --bin minvmd --locked
        cargo nextest run -p minvmd --profile vm --run-ignored all --no-tests=fail \
          -E 'binary(/_integration$/) and not binary(/_root_integration$/)'
        ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac

# minimald root-integration proofs (netns/tap via gvproxy; no KVM needed).
# CI parity: ci-linux-native.yml `minimald-root-integration` — same env,
# profile, and filterset; the tests sudo their own tap/netns commands.
test-root-integration:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Linux) ;;
      *) echo "root-integration is Linux-only (netns/CAP_NET_ADMIN); SKIP on $(uname -s)"; exit 0 ;;
    esac
    command -v cargo-nextest >/dev/null 2>&1 || { echo "'cargo-nextest' not found — install with: cargo install cargo-nextest --locked" >&2; exit 1; }
    # Ubuntu 24.04+ gates unprivileged userns behind apparmor; CI flips it too.
    v="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)"
    [ "$v" = "0" ] || { echo "unprivileged userns is restricted; run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0" >&2; exit 1; }
    just gvproxy
    MINIMALD_NETNS_TEST=1 GVPROXY_BIN="{{gvproxy}}" \
      cargo nextest run -p minimald --profile ci --run-ignored all --no-tests=fail \
      -E 'binary(/_root_integration$/)'

# The unified session e2e (scripts/session-e2e.sh) against this host's
# VM-backed daemon. CI parity: ci-macos.yml session e2e (Darwin: E2E_VM=1, no
# E2E_MINIMAL_ARGS — macOS is always VM-backed) and ci-linux-kvm.yml session
# e2e (Linux/DM3: E2E_VM=1 E2E_MINIMAL_ARGS=--minvmd). The script isolates its
# own XDG state under /tmp. Dep order matters: minvmd-build LAST, so its macOS
# codesign is the final touch on the binary. Stranded VMs: `just reap`.
e2e: artifacts gvproxy initramfs minimal-cli minvmd-build
    #!/usr/bin/env sh
    set -eu
    export MINVMD_KERNEL_PATH="{{kernel}}" MINVMD_ROOTFS_PATH="{{rootfs}}"
    export MINVMD_INITRAMFS="{{initramfs}}" MINVMD_BOOT_LOG="{{scratch}}/e2e-boot.log"
    export MINVMD_GVPROXY_BIN="{{gvproxy}}"
    export PATH="{{justfile_directory()}}/target/debug:$PATH"
    case "$(uname -s)" in
      Darwin)
        E2E_VM=1 E2E_PROJECT_DIR=/tmp ./scripts/session-e2e.sh
        ;;
      Linux)
        [ -e /dev/kvm ] && [ -w /dev/kvm ] || { echo "e2e (VM) needs writable /dev/kvm; try: sg kvm -c 'just e2e' — or use 'just e2e-native'" >&2; exit 1; }
        export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        E2E_VM=1 E2E_MINIMAL_ARGS=--minvmd E2E_PROJECT_DIR=/tmp ./scripts/session-e2e.sh
        ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac

# The SAME session e2e against a host-native minimald (no VM; DM2 — the Linux
# default run mode). CI parity: ci-linux-native.yml `native-daemon-e2e` —
# combined minimald+min build, PATH prepend, no E2E_* env.
e2e-native:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Linux) ;;
      *) echo "native-daemon e2e is Linux-only (minimald); SKIP on $(uname -s)"; exit 0 ;;
    esac
    v="$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)"
    [ "$v" = "0" ] || { echo "unprivileged userns is restricted; run: sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0" >&2; exit 1; }
    cargo build -p minimald --bin minimald -p minimal --bin min --locked
    export PATH="{{justfile_directory()}}/target/debug:$PATH"
    ./scripts/session-e2e.sh

# Supervised daemon lifecycle proof (run --detach → status Running → stop →
# status Stopped). CI parity: ci-linux-kvm.yml `lifecycle`
# (scripts/minvmd-lifecycle.sh); CI only schedules it on the KVM lane, but the
# script is target-agnostic, so it runs here on both hosts. Like CI's
# lifecycle step, this boots the VM switchless: MINVMD_GVPROXY_BIN is
# deliberately NOT exported (CI's lifecycle runs before that lane fetches
# gvproxy, so the switchless boot path is what it proves).
test-lifecycle: artifacts initramfs minvmd-build
    #!/usr/bin/env sh
    set -eu
    command -v jq >/dev/null 2>&1 || { echo "'jq' not found — install with: brew install jq (or apt install jq)" >&2; exit 1; }
    export MINVMD_KERNEL_PATH="{{kernel}}" MINVMD_ROOTFS_PATH="{{rootfs}}"
    export MINVMD_INITRAMFS="{{initramfs}}" MINVMD_BOOT_LOG="{{scratch}}/lifecycle-boot.log"
    export XDG_STATE_HOME="{{scratch}}/test-state"
    export PATH="{{justfile_directory()}}/target/debug:$PATH"
    case "$(uname -s)" in
      Linux)
        [ -e /dev/kvm ] && [ -w /dev/kvm ] || { echo "test-lifecycle needs writable /dev/kvm; try: sg kvm -c 'just test-lifecycle'" >&2; exit 1; }
        export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        ;;
    esac
    ./scripts/minvmd-lifecycle.sh

# Nightly soak parity: N session-e2e repetitions (nightly-tests.yml
# `session-e2e-soak` runs 10). The soak script reaps between iterations and on
# exit via scripts/reap-vms.sh — scoped to this checkout's binaries, but it
# WILL kill this repo's own live dev stack (e.g. from `just up`) each pass.
soak n="10": artifacts gvproxy initramfs minimal-cli minvmd-build
    #!/usr/bin/env sh
    set -eu
    export MINVMD_KERNEL_PATH="{{kernel}}" MINVMD_ROOTFS_PATH="{{rootfs}}"
    export MINVMD_INITRAMFS="{{initramfs}}"
    export MINVMD_GVPROXY_BIN="{{gvproxy}}"
    export PATH="{{justfile_directory()}}/target/debug:$PATH"
    export E2E_VM=1 E2E_PROJECT_DIR=/tmp
    case "$(uname -s)" in
      Darwin) ;;
      Linux)
        [ -e /dev/kvm ] && [ -w /dev/kvm ] || { echo "soak needs writable /dev/kvm; try: sg kvm -c 'just soak'" >&2; exit 1; }
        export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        export E2E_MINIMAL_ARGS=--minvmd
        ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac
    ./scripts/soak-session-e2e.sh {{n}} "{{scratch}}/soak-logs"

# Kill stranded VM host processes (minvmd, __krun-vmm, gvproxy) after a failed
# or interrupted harness run — leftovers wedge the next VM's vsock bridge.
# Scoped to THIS checkout's binaries (path-anchored pkill), so other checkouts'
# live VMs and unrelated gvproxies (e.g. podman's) are untouched. Needs
# passwordless sudo for root-owned relay leftovers; without it, sudo -n fails
# fast and user-owned processes still die.
reap:
    scripts/reap-vms.sh

# ── DM1 / DM2 / DM3 deployment-model bring-up ────────────────────────────────
#
# DM1: macOS (Apple Silicon) host + Linux VM(s) over Hypervisor.framework. This
#      is the primary bring-up on macOS; on Linux it is a clean SKIP (use `dm3`
#      for the native-Linux + VM equivalent over KVM).
# DM2: native Linux, a host-native `minimald` (no VM), reachable over UDS at
#      providers/local-0/ssh.sock — the same path the `min` CLI dials, so no
#      bridge is needed. Own-IP is rootless (hakoniwa RustSlirp builds the tap
#      inside the sandbox's own user+net namespace — no setcap).
# DM3: native Linux + one Linux VM (minimald as initramfs pid-1 in libkrun). The
#      Linux CLI dials providers/local-0/ssh.sock, which minvmd binds directly
#      (the socket/path coordination fix, #690) — no bridge/symlink needed. Run
#      under `sg kvm` if the shell lacks the kvm group.

# Bring the stack up for THIS host's DEFAULT run mode — the `just up` the docs
# reference (CONTRIBUTING.md, docs/ci-strategy.md §8/§10). macOS → dm1 (VM over
# HVF is the only macOS mode); Linux → dm2 (native minimald is the default run
# mode on Linux — use `just dm3` explicitly for the VM/KVM stack).
up:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) exec just dm1 ;;
      Linux)  exec just dm2 ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac

# On Linux this is a clean SKIP (use `dm3`). min auto-spawns `minvmd run
# --detach`, so minvmd must be on PATH and the MINVMD_* artifact paths exported —
# both are set here and inherited by the detached supervisor.

# DM1 — macOS host + Linux VM over Hypervisor.framework: bring the full stack up.
dm1:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) ;;
      *) echo "DM1 needs macOS (Hypervisor.framework). SKIP on $(uname -s); use 'just dm3' for native Linux + VM over KVM." ; exit 0 ;;
    esac
    echo "DM1 (macOS + Linux VM over HVF): bringing the stack up."
    just artifacts gvproxy initramfs minvmd-build minimal-cli
    export MINVMD_KERNEL_PATH="{{kernel}}"
    export MINVMD_ROOTFS_PATH="{{rootfs}}"
    export MINVMD_INITRAMFS="{{initramfs}}"
    export MINVMD_BOOT_LOG="{{scratch}}/boot.log"
    # Host gvproxy switch: minvmd spawns it for guest egress (root netns + own-IP
    # PTasks). Best-effort — skipped if the binary is absent.
    export MINVMD_GVPROXY_BIN="{{gvproxy}}"
    export PATH="{{justfile_directory()}}/target/debug:$PATH"
    "{{min-bin}}" ls

# Build a host-native (glibc) minimald WITH the networking features, for DM2.
minimald-build:
    cargo build -p minimald --features {{features}}

# DM3 — native Linux + one Linux VM. Boots the VM; minvmd binds the CLI socket.
dm3: artifacts gvproxy initramfs minvmd-build minimal-cli
    #!/usr/bin/env sh
    set -eu
    [ -e /dev/kvm ] || { echo "DM3 needs /dev/kvm (KVM host)"; exit 1; }
    [ -w /dev/kvm ] || { echo "DM3: /dev/kvm not writable here; retry: sg kvm -c 'just dm3'"; exit 1; }
    export MINVMD_KERNEL_PATH="{{kernel}}" MINVMD_ROOTFS_PATH="{{rootfs}}"
    export MINVMD_INITRAMFS="{{initramfs}}" MINVMD_BOOT_LOG="{{scratch}}/boot.log"
    export MINVMD_GVPROXY_BIN="{{gvproxy}}"
    export PATH="{{justfile_directory()}}/target/debug:$PATH"
    export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
    # Boot the VM explicitly (the CLI's autospawn would also work, but an
    # explicit boot keeps ordering clear and lets us raise the READY timeout).
    # The generic guest kernel can spend 40-50s probing hardware before pid-1
    # (minimald) even starts, which overruns minvmd's 60s READY default on a
    # cold boot; give it headroom (overridable by the caller).
    export MINVMD_READY_TIMEOUT_SECS="${MINVMD_READY_TIMEOUT_SECS:-150}"
    "{{minvmd-bin}}" run --detach --timeout 75
    # No socket bridge: since the socket/path coordination fix (#690) minvmd binds
    # the CLI-facing <state>/providers/local-0/ssh.sock directly — exactly the path
    # the `minimal` CLI dials. (The old `ln -sf` from a runtime-dir socket clobbered
    # minvmd's own live socket, so every dial fell through to a failing autospawn.)
    echo "DM3 up: VM booted; minimald reachable at providers/local-0/ssh.sock"
    # The guest SSH server can reset the very first connect right after boot, so
    # retry briefly rather than fail the recipe on that one-shot race.
    ok=0
    for _ in $(seq 1 5); do
      if "{{min-bin}}" ls; then ok=1; break; fi
      sleep 2
    done
    [ "$ok" = 1 ] || { echo "DM3: min ls failed after retries" >&2; exit 1; }

# DM2 — native Linux, host-native minimald (no VM) over UDS. Runs minimald under
# a dedicated state dir; the CLI reaches it with `--minimal-dir`, which (via the
# autospawn gate) connects directly instead of booting a VM.
dm2: minimald-build minimal-cli gvproxy
    #!/usr/bin/env sh
    set -eu
    dir="{{scratch}}/dm2-state"
    sock="$dir/providers/local-0/ssh.sock"
    pidf="{{scratch}}/dm2-minimald.pid"
    bin="{{justfile_directory()}}/target/debug/minimald"
    mkdir -p "$dir"
    # Own-IP is rootless: hakoniwa's RustSlirp builds each PTask's tap inside the
    # sandbox's own user+net namespace, so the daemon needs no `setcap` / elevated
    # privilege. (It does need an unprivileged-user-namespace-capable host.)
    if [ -S "$sock" ] && [ -f "$pidf" ] && kill -0 "$(cat "$pidf")" 2>/dev/null; then
      echo "DM2 minimald already up: $sock"
    else
      # --gvproxy-bin points the per-host OwnIp switch at the pinned local gvproxy,
      # so no system install (/usr/lib/minimal/bin/gvproxy) is required.
      setsid "$bin" \
        --minimal-state-dir "$dir" --minimal-cache-dir "$dir/cache" \
        run --instance-num 0 --gvproxy-bin "{{gvproxy}}" > {{scratch}}/dm2-minimald.log 2>&1 &
      echo $! > "$pidf"
      for _ in $(seq 1 50); do [ -S "$sock" ] && break; sleep 0.1; done
    fi
    [ -S "$sock" ] || { echo "DM2 minimald failed to bind $sock; see {{scratch}}/dm2-minimald.log" >&2; exit 1; }
    echo "DM2 up: host-native minimald at $sock (pid $(cat "$pidf"))"
    echo "  own-IP: {{min-bin}} --minimal-dir $dir activate -n net1 --network own-ip . && \\"
    echo "          {{min-bin}} --minimal-dir $dir attach net1   # curl http://example.com -> 200"
    # Same first-connect retry as dm3: minimald can reset the very first SSH
    # connect right after binding the socket, which trips the CLI's autospawn
    # (and fails the recipe) even though the daemon is healthy.
    ok=0
    for _ in $(seq 1 5); do
      if "{{min-bin}}" --minimal-dir "$dir" ls; then ok=1; break; fi
      sleep 2
    done
    [ "$ok" = 1 ] || { echo "DM2: min ls failed after retries; see {{scratch}}/dm2-minimald.log" >&2; exit 1; }

# Stop the DM2 host-native minimald.
dm2-down:
    #!/usr/bin/env sh
    set -eu
    pidf="{{scratch}}/dm2-minimald.pid"
    [ -f "$pidf" ] || { echo "no DM2 minimald running"; exit 0; }
    pid="$(cat "$pidf")"; kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    kill -9 "$pid" 2>/dev/null || true; rm -f "$pidf"
    echo "DM2 minimald stopped (pid $pid)"
