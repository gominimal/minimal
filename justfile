# justfile — repo-wide task runner. Lives at the workspace root.
#
# Recipes are grouped by crate where they're crate-specific.

scratch     := justfile_directory() / ".scratch"
# Host CPU arch in Rust naming (aarch64 on Apple Silicon; x86_64 on most Linux
# hosts) — drives the musl cross-compile target.
arch        := arch()
musl-target := arch + "-unknown-linux-musl"
# Same arch in the OCI naming `minimal materialize --arch` expects (arm64/amd64,
# not aarch64/x86_64) — drives the materialized guest artifacts.
guest-arch  := if arch() == "aarch64" { "arm64" } else if arch() == "x86_64" { "amd64" } else { arch() }
# Flat libkrun link/runtime prefix (Linux only; macOS uses the Homebrew install).
krun-prefix := env_var('HOME') / ".krun"
# Guest minimald networking features baked into the initramfs (R4.x): the HTTPS
# reverse proxy (mTLS) and the WireGuard mesh peer.
features    := "networking-proxy,networking-wg"
kernel      := scratch / "vmlinuz"
rootfs      := scratch / "rootfs.img"
initramfs   := scratch / "initramfs.cpio"
gvproxy     := scratch / "gvproxy"
minvmd-bin  := justfile_directory() / "target/debug/minvmd"
minimal     := justfile_directory() / "target/debug/minimal"

# Re-run any time the entitlements file or binary changes. Ad-hoc signing
# (`-s -`) requires no Apple Developer membership; the binary only runs on the
# host that signed it, which is correct for dev builds.

# Build a release `minvmd` and code-sign it with the hypervisor entitlement.
codesign-minvmd:
    cargo build -p minvmd --release
    codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - {{justfile_directory()}}/target/release/minvmd

# ── minimal → minvmd → minimald bring-up (macOS/HVF or Linux/KVM) ───────────
#
# `just up` brings the whole stack up with full guest networking:
#   1. materialize the guest kernel + generic rootfs into .scratch
#   2. cross-compile minimald → initramfs /init WITH the networking features
#   3. build minvmd (codesign on macOS), build the `minimal` CLI
#   4. run `minimal ls`, which auto-spawns `minvmd run --detach`; minvmd boots
#      the microVM whose initramfs pid-1 is minimald, which serves the session
#      over the host UDS bridge.
#
# Prereqs:
#   macOS  — `brew install slp/krun/libkrun`; the `minimal` shim on PATH.
#   Linux  — a KVM host; durable `kvm` group membership (`sudo usermod -aG kvm
#            $USER`, then re-login) so the autospawned minvmd can open /dev/kvm;
#            a Rust toolchain + protoc + jq + cpio. libkrun is fetched by `up`.
# See crates/minvmd/README.md for the manual equivalent.

# macOS: via the `minimal` shim (runs in a VM; --output must stay under the repo).
# Linux: via fetch-artifact.sh (builds `minimal` from source, materializes natively).

# Materialize the guest kernel + generic rootfs into .scratch. Skips a fetch when
# the artifact already exists; `just clean` first to force a refresh.
artifacts:
    #!/usr/bin/env sh
    set -eu
    mkdir -p {{scratch}}
    case "$(uname -s)" in
      Darwin)
        # The macOS `minimal` shim materializes inside a VM and only writes the
        # artifact when --output is repo-RELATIVE: an absolute path silently
        # builds the wrong arch and drops the kernel Image (copy: No such file).
        # The recipe cwd is the repo root, so strip it to a relative path.
        repo="$(pwd)"; kabs="{{kernel}}"; rabs="{{rootfs}}"
        [ -f "$kabs" ] || minimal materialize --output "${kabs#"$repo/"}" --arch {{guest-arch}} virtio-kernel
        [ -f "$rabs" ] || minimal materialize --output "${rabs#"$repo/"}" --arch {{guest-arch}} minvmd-rootfs
        ;;
      Linux)
        [ -f {{kernel}} ] || scripts/fetch-artifact.sh virtio-kernel {{kernel}} {{guest-arch}}
        [ -f {{rootfs}} ] || scripts/fetch-artifact.sh minvmd-rootfs {{rootfs}} {{guest-arch}}
        ;;
      *) echo "unsupported host $(uname -s)" >&2; exit 1 ;;
    esac

# macOS uses the Homebrew install, so this is a no-op there.

# Fetch libkrun + libkrunfw into the link/runtime prefix (Linux only).
libkrun:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Linux) scripts/fetch-libkrun.sh {{krun-prefix}} {{guest-arch}} ;;
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

# Build the `minimal` CLI (minimal crate).
minimal-cli:
    cargo build -p minimal

# minimal auto-spawns `minvmd run --detach`, so minvmd must be on PATH and the
# MINVMD_* artifact paths exported; both are set here and inherited by the
# detached supervisor. On Linux LD_LIBRARY_PATH is also inherited so libkrun can
# dlopen libkrunfw at runtime.

# Bring the full stack up and list sessions.
up: artifacts gvproxy initramfs minvmd-build minimal-cli
    #!/usr/bin/env sh
    set -eu
    export MINVMD_KERNEL_PATH="{{kernel}}"
    export MINVMD_ROOTFS_PATH="{{rootfs}}"
    export MINVMD_INITRAMFS="{{initramfs}}"
    export MINVMD_BOOT_LOG="{{scratch}}/boot.log"
    # Host gvproxy switch: minvmd spawns it for guest egress (root netns + own-IP
    # PTasks). Best-effort — skipped if the binary is absent.
    export MINVMD_GVPROXY_BIN="{{gvproxy}}"
    export PATH="{{justfile_directory()}}/target/debug:$PATH"
    case "$(uname -s)" in
      Linux) export LD_LIBRARY_PATH="{{krun-prefix}}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" ;;
    esac
    "{{minimal}}" ls

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
#      is the `up` path on macOS; on Linux it is a clean SKIP (use `dm3` for the
#      native-Linux + VM equivalent over KVM).
# DM2: native Linux, a host-native `minimald` (no VM), reachable over UDS at
#      providers/local-0/ssh.sock — the same path the `minimal` CLI dials, so no
#      bridge is needed. Own-IP is rootless (hakoniwa RustSlirp builds the tap
#      inside the sandbox's own user+net namespace — no setcap).
# DM3: native Linux + one Linux VM (minimald as initramfs pid-1 in libkrun). The
#      Linux CLI dials providers/local-0/ssh.sock, but minvmd bridges the guest
#      at $XDG_RUNTIME_DIR/minimal/minimald.sock, so `dm3` symlinks the former to
#      the latter. Run under `sg kvm` if the shell lacks the kvm group.

# DM1 — macOS host + Linux VM over Hypervisor.framework (the `up` path on macOS).
dm1:
    #!/usr/bin/env sh
    set -eu
    case "$(uname -s)" in
      Darwin) ;;
      *) echo "DM1 needs macOS (Hypervisor.framework). SKIP on $(uname -s); use 'just dm3' for native Linux + VM over KVM." ; exit 0 ;;
    esac
    echo "DM1 (macOS + Linux VM over HVF): bringing the stack up."
    just up

# Build a host-native (glibc) minimald WITH the networking features, for DM2.
minimald-build:
    cargo build -p minimald --features {{features}}

# DM3 — native Linux + one Linux VM. Boots the VM, then bridges the CLI socket.
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
    # Boot the VM explicitly (the CLI's autospawn would also work, but booting
    # here keeps the F1 bridge ordering clear). The configurable READY/UDS
    # timeouts cover the ~20-30s cold boot.
    "{{minvmd-bin}}" run --detach --timeout 75
    # F1 bridge: the Linux CLI dials <state>/providers/local-0/ssh.sock, but the
    # guest is reached via minvmd's <runtime>/minimal/minimald.sock — link them.
    runtime="${XDG_RUNTIME_DIR:-$HOME/.minimal/local}"
    state="${XDG_STATE_HOME:-$HOME/.local/state}"
    cli="$state/minimal/providers/local-0/ssh.sock"
    mkdir -p "$(dirname "$cli")"
    ln -sf "$runtime/minimal/minimald.sock" "$cli"
    echo "DM3 up: VM booted; CLI socket bridged -> $runtime/minimal/minimald.sock"
    # The guest SSH server can reset the very first connect right after boot, so
    # retry briefly rather than fail the recipe on that one-shot race.
    ok=0
    for _ in $(seq 1 5); do
      if "{{minimal}}" ls; then ok=1; break; fi
      sleep 2
    done
    [ "$ok" = 1 ] || { echo "DM3: minimal ls failed after retries" >&2; exit 1; }

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
    echo "  own-IP: {{minimal}} --minimal-dir $dir activate -n net1 --network own-ip . && \\"
    echo "          {{minimal}} --minimal-dir $dir attach net1   # curl http://example.com -> 200"
    "{{minimal}}" --minimal-dir "$dir" ls

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
