# minvmd

Host daemon (macOS/HVF or Linux/KVM) that boots a Linux microVM via libkrun and
registers a host UNIX socket ↔ in-VM `minimald` vsock bridge, so the `minimal`
CLI can reach a Linux session daemon without knowing a VM exists. Specs:
`docs/specs/01-spec-minvmd-host-daemon/` (daemon) and
`docs/specs/02-spec-minvmd-linux-kvm/` (Linux/KVM).

minimald runs the guest as **pid-1, shipped as the initramfs `/init`** (a cpio of
the cross-compiled static binary) rather than baked into the rootfs. The guest
boots from three artifacts:
- **kernel** — the upstream `virtio-kernel-raw` package's uncompressed `Image`
  (`virtio-kernel` output).
- **rootfs** — the upstream `microvm-rootfs` package's **generic** ext4 image
  (`minvmd-rootfs` output), loaded as a block device (`krun_add_disk2` →
  `/dev/vda`); the initramfs `/init` mounts it and `chroot`s in.
- **initramfs** — `scripts/build-initramfs.sh` cross-compiles `minimald` to a
  static aarch64 binary and packs it as the cpio `/init`.

## Run the boot verification locally (Apple Silicon)

Prereqs:
- Apple Silicon Mac with Docker (for the `cross` musl toolchain).
- libkrun, either of:
  - the pinned source build CI links and the release ships:
    `scripts/build-libkrun-macos.sh some-prefix-dir` (builds the commit pinned
    in `vendor/libkrun/libkrun.lock`), then `export LIBKRUN_PREFIX=some-prefix-dir`
    before building minvmd;
  - `brew install slp/krun/libkrun` (third-party tap) — the local-dev fallback:
    with `LIBKRUN_PREFIX` unset, minvmd's build.rs defaults to `/opt/homebrew/lib`.
- The `minimal` shim on `PATH` (`~/.minimal/shim/bin/minimal`). On macOS,
  `materialize` runs `minimal` inside a Linux VM; a from-source macOS build
  cannot run the build pipeline (sandbox2 is Linux-only).

```sh
# 1. Materialize the kernel + GENERIC guest rootfs INTO THE REPO.
#    macOS caveat: the shim runs minimal in a VM and only syncs the project dir
#    back to the host, so --output MUST be a path under the repo. A /tmp path is
#    written inside the VM and never appears on the host.
mkdir -p .scratch
minimal materialize --output .scratch/vmlinuz    --arch aarch64 virtio-kernel
minimal materialize --output .scratch/rootfs.img --arch aarch64 minvmd-rootfs

# 2. Build the guest initramfs (cross-compiles minimald → static aarch64, cpio).
scripts/build-initramfs.sh .scratch/initramfs.cpio

# 3. Build minvmd WITHOUT running.
cargo build -p minvmd --bin minvmd

# 4. Codesign minvmd with the hypervisor entitlement. This MUST be the last
#    thing to touch the binary: a later `cargo run`/`cargo test` relinks and
#    unsigns it, and krun_start_enter then fails with EINVAL.
codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/debug/minvmd

# 5. Boot. The kernel runs the initramfs /init (minimald) as pid-1; minimald
#    mounts the rootfs (/dev/vda) + pseudo-fs, then writes READY over vsock.
export MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz"
export MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img"   # generic microvm-rootfs
export MINVMD_INITRAMFS="$PWD/.scratch/initramfs.cpio"
target/debug/minvmd boot --foreground   # vm-up = minimald READY from the initramfs
```

## Run the boot verification locally (Linux / KVM)

On a Linux host with `/dev/kvm`, minvmd links libkrun's KVM backend and boots
natively — **no Docker, no codesigning**. Unlike macOS, `materialize` runs the
build pipeline directly, so a native host (aarch64 *or* x86_64) materializes its
own artifacts. This is the same flow as the `ci-linux-kvm.yml` lane.

Prereqs:
- A KVM-capable Linux host, and membership in the `kvm` group (durable — see the
  note at the end).
- A Rust toolchain plus `protoc`, `jq`, and `cpio`. For the no-Docker initramfs
  build you also need `musl-gcc` and the `<arch>-unknown-linux-musl` target.

`ARCH` drives every step — set it to the host arch:

```sh
ARCH=aarch64                       # or x86_64
RUST_MUSL="${ARCH}-unknown-linux-musl"
KRUN_PREFIX="$HOME/.krun"
mkdir -p .scratch

# 1. libkrun (+ its libkrunfw firmware) from the upstream `libkrun` package. A
#    CACHE FETCH keyed by the pinned upstream commit — NOT a from-source build
#    (libkrunfw would otherwise compile a guest kernel). Extracts libkrun.so* +
#    libkrunfw.so* into $KRUN_PREFIX, a flat link/runtime prefix.
./scripts/fetch-libkrun.sh "$KRUN_PREFIX" "$ARCH"

# 2. Guest kernel + generic rootfs (cache fetches of the upstream packages).
./scripts/fetch-artifact.sh virtio-kernel .scratch/vmlinuz    "$ARCH"
./scripts/fetch-artifact.sh minvmd-rootfs .scratch/rootfs.img "$ARCH"

# 3. Initramfs (minimald cross-compiled to a static musl binary, packed as /init).
scripts/build-initramfs.sh .scratch/initramfs.cpio "$RUST_MUSL"   # uses `cross` (Docker)

# 4. Build minvmd. LIBKRUN_PREFIX must point at the POPULATED prefix from step 1
#    BEFORE this build: build.rs trusts the env var's presence to emit the real
#    (libkrun-linking) cfg + an rpath to it. Build before step 1 finishes and you
#    get the runtime-bailing stub.
export LIBKRUN_PREFIX="$KRUN_PREFIX"
export LD_LIBRARY_PATH="$KRUN_PREFIX${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cargo build -p minvmd --bin minvmd

# 5. Boot. minvmd needs LD_LIBRARY_PATH at runtime too: libkrun dlopen()s
#    libkrunfw.so.5 from the prefix (it is not a link-time DT_NEEDED).
export MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz"
export MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img"
export MINVMD_INITRAMFS="$PWD/.scratch/initramfs.cpio"
export MINVMD_BOOT_LOG="$PWD/.scratch/boot.log"   # guest hvc0 console
sg kvm -c "LD_LIBRARY_PATH=$KRUN_PREFIX ./target/debug/minvmd boot --foreground"
# vm-up on stdout = minimald READY from the initramfs (R2.4).
```

**No Docker?** Replace step 3 with a native musl build of minimald, then pack the
cpio yourself:

```sh
env CC_${ARCH}_unknown_linux_musl=musl-gcc \
    "CARGO_TARGET_$(echo "$ARCH" | tr a-z A-Z)_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc" \
    cargo build -p minimald --profile initramfs --target "$RUST_MUSL"
STAGE="$(mktemp -d)"
mkdir -p "$STAGE"/dev "$STAGE"/proc "$STAGE"/sys "$STAGE"/newroot
cp "target/$RUST_MUSL/initramfs/minimald" "$STAGE/init"
( cd "$STAGE" && find . | cpio -o -H newc ) > .scratch/initramfs.cpio
rm -rf "$STAGE"
```

### E2E tests (Linux)

No codesigning on Linux, so `cargo test` works directly. With the artifacts from
steps 1–3 and the libkrun env from step 4 exported (mirrors the CI lane's test
steps):

```sh
sg kvm -c "env LD_LIBRARY_PATH=$KRUN_PREFIX \
  MINVMD_E2E=1 \
  MINVMD_KERNEL_PATH=$PWD/.scratch/vmlinuz \
  MINVMD_ROOTFS_PATH=$PWD/.scratch/rootfs.img \
  MINVMD_INITRAMFS=$PWD/.scratch/initramfs.cpio \
  cargo test -p minvmd --test boot_integration -- --include-ignored --nocapture"

sg kvm -c "env LD_LIBRARY_PATH=$KRUN_PREFIX \
  MINVMD_E2E=1 \
  MINVMD_KERNEL_PATH=$PWD/.scratch/vmlinuz \
  MINVMD_ROOTFS_PATH=$PWD/.scratch/rootfs.img \
  MINVMD_INITRAMFS=$PWD/.scratch/initramfs.cpio \
  cargo test -p minvmd --test minimald_session_integration \
    -- --include-ignored --nocapture --exact minimald_exec_over_bridge"
```

(Two invocations, mirroring the CI lane's separate steps. `--exact` is passed to
every selected `--test` binary, so combining both binaries under one
`--exact minimald_exec_over_bridge` would run zero tests in `boot_integration`. The
`--exact` filter on `minimald_session_integration` selects the bridge case; that binary
has other, non-bridge cases. Drop it to run all of them.)

`/dev/kvm` access: the device node is recreated on every VM teardown, which wipes
any `setfacl` ACL — so an ACL grant lasts a single boot. The durable fix is group
membership (survives node recreation); `sg kvm -c '…'` picks it up without a
re-login:

```sh
sudo usermod -aG kvm "$USER"   # one-time
```

Gotchas:
- `minvmd boot` is the raw boot primitive and does **not** update `minvmd.toml`,
  so `minvmd status`/`stop` report "stopped"/"not running" even while the VM is
  up. The lifecycle (`minvmd.toml`) is the supervisor's job — use `minvmd run
  --detach` / `status` / `stop` to exercise it. Kill a stray `boot` VM by PID
  (the `boot` parent + its hidden `__krun-vmm` child).
- **Requires libkrun >= 1.19.0** (BLK=1 for `krun_add_disk2`, plus the vsock
  TX-chain fix). The upstream `libkrun` package already pins 1.19.0.

## E2E tests (macOS)

`MINVMD_E2E=1`-gated, `#[ignore]` by default. On macOS, run the prebuilt test
binaries directly — `cargo test` after signing relinks and unsigns `minvmd`. (On
Linux there is no signing step; see "E2E tests (Linux)" above.)

```sh
cargo test -p minvmd --test boot_integration --test minimald_session_integration --no-run
codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/debug/minvmd

# boot READY round-trip:
testbin="$(ls -1t target/debug/deps/boot_integration-* | grep -v '\.d$' | head -1)"
MINVMD_E2E=1 \
MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz" \
MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img" \
MINVMD_INITRAMFS="$PWD/.scratch/initramfs.cpio" \
  "$testbin" --include-ignored --nocapture

# full session (russh client → CreateSession → exec) over the bridge:
testbin="$(ls -1t target/debug/deps/minimald_session_integration-* | grep -v '\.d$' | head -1)"
MINVMD_E2E=1 \
MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz" \
MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img" \
MINVMD_INITRAMFS="$PWD/.scratch/initramfs.cpio" \
  "$testbin" --include-ignored --nocapture --exact minimald_exec_over_bridge
```

## Boot-latency benchmark

`scripts/bench-minvmd-boot.sh` times `minvmd boot` to the guest READY marker over
N runs (default 10) and reports min/median/max. Needs a codesigned `minvmd` and
the kernel + rootfs + initramfs paths:

```sh
MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz" \
MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img" \
MINVMD_INITRAMFS="$PWD/.scratch/initramfs.cpio" \
  scripts/bench-minvmd-boot.sh
```

CI runs it (informational) in the `boot-e2e` job.

## How it boots

- Kernel loaded via `krun_set_kernel` as a raw uncompressed aarch64 `Image`
  (`KernelFormat::Raw`). The `virtio-kernel` output is built by the upstream
  `virtio-kernel-raw` package, which decompresses upstream's `Image.gz` at build
  time. Loading raw skips libkrun's in-VMM gzip decompress (~77 ms, over half of
  boot-to-READY).
- The kernel boots the **initramfs** (`krun_set_kernel`'s initramfs arg): it
  unpacks into a RAM root and runs `/init` (= minimald) as PID 1. cmdline is just
  `console=hvc0` — no `root=`/`init=` (those are for a block root).
- minimald-as-`/init` mounts `/dev` (devtmpfs; the kernel does NOT auto-mount it
  for an initramfs root), mounts the rootfs (`krun_add_disk2` → `/dev/vda`) and
  `chroot`s into it so `/bin/sh` + libs resolve, then writes `READY\n` on vsock
  port 7350 (boot marker, R2.4).
- `minvmd` registers the host UDS bridge via
  `krun_add_vsock_port2(.., listen = true)`; minimald serves SSH directly on that
  vsock port (`run_on_vsock`), so the `minimal` CLI's connection reaches the
  session with no in-guest relay. **Requires libkrun >= 1.19.0** — 1.18.1's vsock
  device intermittently stalled a direct session (multi-descriptor TX-chain bug,
  fixed upstream); the prior workaround was a socat vsock→UDS relay.

## Notes

- The guest rootfs is the **generic** upstream `microvm-rootfs` package (an ext4
  image built from `base` + `socat`) — minimald is delivered by the initramfs, so
  nothing is baked into the rootfs.
- Session state persists on a per-VM writable data volume, attached as
  `/dev/vdb` (`docs/specs/08-spec-vm-ext4-volume`). The host provisions a
  sparse raw image (`data-vol.raw` in the instance's state dir; 256 GiB
  ceiling by default, `MINVMD_VOLUME_BYTES` overrides the size and
  `MINVMD_DATA_VOLUME_PATH` the location), and the guest runs first-boot
  `mkfs.ext4` against it — keyed off ext4 superblock detection, so later
  boots just mount it. minimald mounts the volume at `/var/lib/minimal` and
  relocates cache + state onto it; sessions survive VM restarts.
- In CI (`.github/workflows/ci-macos.yml`) the kernel + rootfs are materialized on
  a cheap Linux runner (`scripts/fetch-artifact.sh` — cache pulls of the upstream
  packages' prebuilt aarch64 artifacts) and the initramfs is cross-compiled
  there; all three are handed to the self-hosted boot job as artifacts.
