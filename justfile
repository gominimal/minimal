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
# reverse proxy (mTLS) and the WireGuard mesh peer.
features    := "networking-proxy,networking-wg"
kernel      := scratch / "vmlinuz"
rootfs      := scratch / "rootfs.img"
initramfs   := scratch / "initramfs.cpio"
gvproxy     := scratch / "gvproxy"
minvmd-bin  := justfile_directory() / "target/debug/minvmd"
minimal     := justfile_directory() / "target/debug/minimal2"

# Re-run any time the entitlements file or binary changes. Ad-hoc signing
# (`-s -`) requires no Apple Developer membership; the binary only runs on the
# host that signed it, which is correct for dev builds.

# Build a release `minvmd` and code-sign it with the hypervisor entitlement.
codesign-minvmd:
    cargo build -p minvmd --release
    codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - {{justfile_directory()}}/target/release/minvmd

# ── minimal2 → minvmd → minimald bring-up (macOS/HVF or Linux/KVM) ───────────
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
        [ -f {{kernel}} ] || minimal materialize --output {{kernel}} --arch {{arch}} virtio-kernel
        [ -f {{rootfs}} ] || minimal materialize --output {{rootfs}} --arch {{arch}} minvmd-rootfs
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

# Build the `minimal` CLI (minimal2 crate).
minimal-cli:
    cargo build -p minimal2

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
