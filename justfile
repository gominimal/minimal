# justfile — repo-wide task runner. Lives at the workspace root.
#
# Recipes are grouped by crate where they're crate-specific.

scratch     := justfile_directory() / ".scratch"
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
kernel      := scratch / "vmlinuz"
rootfs      := scratch / "rootfs.img"
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
# VM; --output must stay under the repo). Distinct from the `min` binary this
# repo builds. Linux: via fetch-artifact.sh (builds `mip` from source).

# Materialize the guest kernel + generic rootfs into .scratch. Skips a fetch when
# the artifact already exists; `just clean` first to force a refresh.
artifacts:
    #!/usr/bin/env sh
    set -eu
    mkdir -p {{scratch}}
    # `minimal materialize` runs in a VM via the shim; on a cold cache its
    # overlay-sync can transiently drop the output ("copying output file I/O
    # error … No such file or directory"). Retry a few times before failing.
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
        [ -f {{kernel}} ] || materialize {{kernel}} {{arch}} virtio-kernel
        [ -f {{rootfs}} ] || materialize {{rootfs}} {{arch}} minvmd-rootfs
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
        cargo build -p minvmd --bin minvmd
        codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - {{minvmd-bin}}
        ;;
      Linux)
        export LIBKRUN_PREFIX="{{krun-prefix}}"
        export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        cargo build -p minvmd --bin minvmd
        ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac

# Build the `min` CLI (from the `minimal` crate; its [[bin]] target is `min`).
minimal-cli:
    cargo build -p minimal

# Run the `min` CLI against the workspace's own debug build. Prepends
# `target/debug/` to `$PATH` so `min`'s auto-spawn can find the sibling
# `minimald` binary (it invokes it by name). Arguments after `just min` are
# forwarded verbatim.
#
# Example:
#   just min activate --loadout helix --attach
#   just min loadout list
#   just min dirs
min *args:
    cargo build -p minimal -p minimald
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
    "{{min-bin}}" --minimal-dir "$dir" ls

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
