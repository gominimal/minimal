# justfile — repo-wide task runner. Lives at the workspace root.
#
# Recipes are grouped by crate where they're crate-specific.

# Build a release `minvmd` binary and code-sign it with the hypervisor
# entitlement. Re-run any time the entitlements file or binary changes.
# Ad-hoc signing (`-s -`) requires no Apple Developer membership; the binary
# only runs on the host that signed it, which is correct for dev builds.
codesign-minvmd:
    cargo build -p minvmd --release
    codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/release/minvmd

# --- Networking / VM bring-up (epic #478) ---------------------------------
#
# Lane A = native minimald on the host (DM2). Lane B = minvmd microVM (DM1, KVM).
# These recipes mirror the CI lanes (.github/workflows/ci-netns.yml and
# ci-linux-kvm.yml) so a dev reproduces them locally with one command each.
# Lane A needs passwordless sudo; Lane B needs /dev/kvm (see `setup-kvm-group`).

# Host arch, used to name guest artifacts and the musl target.
# Override per-invocation: `just arch=x86_64 setup-minvmd`.
arch := `uname -m`

# libkrun runtime/link prefix for Lane B. Override with the KRUN_PREFIX env var.
krun_prefix := env_var_or_default("KRUN_PREFIX", env_var("HOME") / ".krun")

# Fetch the pinned gvproxy switch binary into .scratch/ (no sudo, no install).
fetch-gvproxy:
    @mkdir -p .scratch
    ./scripts/fetch-gvproxy.sh .scratch/gvproxy

# Lane A — netns proofs: UC1 (no-net refuses egress) + UC6 (PTask-to-PTask).
test-netns: fetch-gvproxy
    MINIMALD_NETNS_TEST=1 GVPROXY_BIN="{{justfile_directory()}}/.scratch/gvproxy" \
        cargo test -p minimald -p sandbox2 -p minimald-rpc netns -- --include-ignored --nocapture

# Lane A — UC7 WireGuard mesh netns proof (builds unprivileged, runs as root).
test-mesh-netns: fetch-gvproxy
    #!/usr/bin/env bash
    set -euo pipefail
    bin=$(cargo test -p minimald --features networking-wg --test mesh_uc7 \
            --no-run --message-format=json \
          | jq -r 'select(.executable != null and (.target.name? == "mesh_uc7")) | .executable' \
          | tail -1)
    echo "mesh_uc7 binary: $bin"
    sudo -E MINIMALD_NETNS_TEST=1 GVPROXY_BIN="$PWD/.scratch/gvproxy" \
        "$bin" --include-ignored --nocapture

# Lane A — networking feature unit suites (networking-wg + networking-proxy).
test-net-features:
    cargo test -p minimald --features networking-wg
    cargo test -p minimald --features networking-proxy

# Lane A — netns proofs + mesh proof + feature suites.
test-net-lane-a: test-netns test-mesh-netns test-net-features

# Lane B — one-time setup: fetch libkrun + guest kernel/rootfs, build initramfs.
# build-initramfs.sh uses `cross` (Docker); on a native-arch host you can skip
# Docker — see crates/minvmd/README.md ("No Docker?") for the musl-gcc path.
setup-minvmd:
    @mkdir -p .scratch
    ./scripts/fetch-libkrun.sh "{{krun_prefix}}" "{{arch}}"
    ./scripts/fetch-artifact.sh virtio-kernel .scratch/vmlinuz    "{{arch}}"
    ./scripts/fetch-artifact.sh minvmd-rootfs .scratch/rootfs.img "{{arch}}"
    ./scripts/build-initramfs.sh .scratch/initramfs.cpio "{{arch}}-unknown-linux-musl"

# Lane B — minvmd VM E2E: boot READY round-trip + session command over the bridge.
test-minvmd-e2e:
    #!/usr/bin/env bash
    set -euo pipefail
    krun="{{krun_prefix}}"
    common="LIBKRUN_PREFIX=$krun LD_LIBRARY_PATH=$krun MINVMD_E2E=1 \
        MINVMD_KERNEL_PATH=$PWD/.scratch/vmlinuz \
        MINVMD_ROOTFS_PATH=$PWD/.scratch/rootfs.img \
        MINVMD_INITRAMFS=$PWD/.scratch/initramfs.cpio"
    sg kvm -c "env $common MINVMD_BOOT_LOG=$PWD/.scratch/boot-e2e.log \
        cargo test -p minvmd --test boot_e2e -- --include-ignored --nocapture"
    sg kvm -c "env $common \
        cargo test -p minvmd --test minimald_session_e2e -- --include-ignored --nocapture --exact minimald_exec_over_bridge"

# Lane B — print the one-time `sudo usermod -aG kvm` step (durable /dev/kvm access).
setup-kvm-group:
    @echo "Run once, then re-login (or prefix VM commands with 'sg kvm -c ...'):"
    @echo "  sudo usermod -aG kvm $USER"

# Run a native minimald (DM2) foreground, OwnIp switch -> fetched gvproxy (no install).
run-minimald *ARGS: fetch-gvproxy
    cargo run -p minimald -- run --gvproxy-bin "{{justfile_directory()}}/.scratch/gvproxy" {{ARGS}}
