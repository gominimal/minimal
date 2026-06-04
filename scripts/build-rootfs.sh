#!/usr/bin/env bash
# build-rootfs.sh — assemble a bootable minvmd guest rootfs.
#
# Takes the pinned Alpine minirootfs staged by `fetch-alpine.sh` and overlays
# the bits needed to boot under libkrun and satisfy the minvmd boot contract:
#
#   - socat (vsock-capable) extracted from a pinned, sha256-verified .apk
#   - /sbin/minvmd-stub-init  — bring-up guest workload (READY marker + echo)
#   - /etc/minvmd/manifest    — the guest-side contract (exec targets, ports)
#
# The overlay is applied IN PLACE into the fetch-alpine cache dir, so the
# assembled rootfs lives at the same path:
#
#   export MINVMD_ROOTFS_PATH="$(scripts/build-rootfs.sh --print-path)"
#
# Format: directory, consumed by libkrun via `krun_set_root` (v0.1). No ext4
# image, no virtiofs host mounts — the rootfs is self-contained.
#
# Idempotent: a `.minvmd-overlay.ok` marker records the overlay revision +
# socat sha; a matching marker short-circuits re-download and re-extract.
#
# Boot model: libkrun's built-in init runs as guest pid-1 and exec's the
# `krun_set_exec` target. OpenRC never runs, so there is no DHCP wait and no
# net-dependent init step — the rootfs reaches userspace with zero network.
# Production exec target is `/sbin/minimald` (cross-compiled, dropped in by a
# follow-up); for bring-up the target is `/sbin/minvmd-stub-init`.
#
# To bump socat: update SOCAT_VERSION and the per-arch SOCAT_SHA256 below, and
# bump OVERLAY_REVISION to force re-application over existing caches.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OVERLAY_REVISION="2"

# socat from Alpine v3.21 main; depends only on so:libc.musl, which the base
# minirootfs already provides (verified via APKINDEX). sha256 is of the .apk.
SOCAT_VERSION="1.8.0.3-r0"
declare -A SOCAT_SHA256=(
    [aarch64]="7cc3f5bade7fba9cd828b94560ce9f35de61246e19ecb595098110e81cf1c9ae"
    [x86_64]="caaad9c79573220fe100aad81487b20306c0745cb96baf5813f45fb212e8be90"
)

print_path_only=0
if [[ "${1:-}" == "--print-path" ]]; then
    print_path_only=1
fi

# Resolve the staged base path from fetch-alpine.sh (single source of truth for
# the Alpine version + cache layout). Path shape: <cache>/<version>/<arch>.
rootfs_path="$("$SCRIPT_DIR/fetch-alpine.sh" --print-path)"
arch="$(basename "$rootfs_path")"

if [[ "$print_path_only" -eq 1 ]]; then
    echo "$rootfs_path"
    exit 0
fi

socat_sha="${SOCAT_SHA256[$arch]:-}"
if [[ -z "$socat_sha" ]]; then
    echo "build-rootfs.sh: no pinned socat sha256 for arch $arch" >&2
    exit 1
fi

marker="$rootfs_path/.minvmd-overlay.ok"
marker_value="rev=$OVERLAY_REVISION socat=$socat_sha"

if [[ -f "$marker" ]] && [[ "$(cat "$marker")" == "$marker_value" ]]; then
    echo "build-rootfs.sh: overlay up to date at $rootfs_path" >&2
    exit 0
fi

# Ensure the base is staged + verified (idempotent; no-op on cache hit).
"$SCRIPT_DIR/fetch-alpine.sh" >&2

apk="socat-${SOCAT_VERSION}.apk"
apk_url="https://dl-cdn.alpinelinux.org/alpine/v3.21/main/${arch}/${apk}"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

echo "build-rootfs.sh: downloading $apk_url" >&2
curl -fsSL "$apk_url" -o "$tmpdir/$apk"

actual_sha="$(shasum -a 256 "$tmpdir/$apk" | awk '{print $1}')"
if [[ "$actual_sha" != "$socat_sha" ]]; then
    echo "build-rootfs.sh: sha256 mismatch for $apk" >&2
    echo "  expected: $socat_sha" >&2
    echo "  actual:   $actual_sha" >&2
    exit 1
fi

# Extract into a scratch dir, then copy only the payload (usr/). apk metadata
# entries (.PKGINFO, .SIGN.*, .pre-install, .trigger) are dotfiles at the
# archive root and are deliberately not copied into the rootfs.
mkdir -p "$tmpdir/extract"
tar -xzf "$tmpdir/$apk" -C "$tmpdir/extract"
cp -a "$tmpdir/extract/usr/." "$rootfs_path/usr/"

# Guest bring-up workload. Replaced in production by /sbin/minimald.
cat > "$rootfs_path/sbin/minvmd-stub-init" <<'STUB'
#!/bin/sh
# minvmd bring-up stub — guest workload for VM boot verification.
#
# This is NOT the production workload. In production libkrun exec's
# /sbin/minimald via krun_set_exec; this stub stands in for boot/bridge tests.
# libkrun's own init (/init.krun) is pid-1: it mounts /proc, /sys and /dev and
# forks this script as the workload.
#
# Contract:
#
#   vsock 7350  READY marker (guest CONNECTS out). The host registers this port
#               with the plain krun_add_vsock_port (listen=false): the host's
#               UDS listener accepts an inbound bridge and the guest connects to
#               host CID 2 and writes "READY\n". The host reads one line to
#               confirm boot completion (R2.4).
#   vsock 2222  echo bridge (guest LISTENs). The host registers this port with
#               krun_add_vsock_port2(listen=true) and connects inward; each
#               connection is cat-looped (bridge_e2e, R3).
set -eu

# Defensive: /init.krun already mounts these before forking us (harmless if so).
mount -t proc  proc /proc 2>/dev/null || true
mount -t sysfs sys  /sys  2>/dev/null || true

# READY marker: connect out to the host (CID 2 = VMADDR_CID_HOST) on port 7350
# and write "READY\n". The host reads one line and closes, so socat returns
# promptly. Retry briefly in case the vsock device isn't up the instant we start.
i=0
while [ "$i" -lt 50 ]; do
    printf 'READY\n' | socat -t2 - VSOCK-CONNECT:2:7350 && break
    i=$((i + 1))
    sleep 0.1
done

# Stay alive as the guest workload: echo bridge on vsock 2222 (R3). exec so this
# socat is the long-lived process and reaps its own per-connection children.
exec socat VSOCK-LISTEN:2222,fork EXEC:cat
STUB
chmod 0755 "$rootfs_path/sbin/minvmd-stub-init"

# Guest-side contract, machine- and human-readable.
mkdir -p "$rootfs_path/etc/minvmd"
cat > "$rootfs_path/etc/minvmd/manifest" <<MANIFEST
# minvmd guest rootfs contract (overlay rev $OVERLAY_REVISION)
#
# format=krun_set_root-directory
# exec_target_production=/sbin/minimald   (dropped in by a follow-up; absent here)
# exec_target_bringup=/sbin/minvmd-stub-init
#
# vsock_port_ready=7350    guest CONNECTS out (host listen=false); writes "READY\n" once at boot
# vsock_port_bridge=2222   guest LISTENs (host listen=true); echoes (cat) per connection
#
# net=none   virtiofs=none   init=libkrun-builtin (/init.krun, no OpenRC)
# exec=krun_set_exec(/sbin/minvmd-stub-init); MINVMD_EXEC overrides
socat=$SOCAT_VERSION
MANIFEST

echo "$marker_value" > "$marker"
echo "build-rootfs.sh: overlay applied to $rootfs_path ($arch, socat $SOCAT_VERSION)" >&2
