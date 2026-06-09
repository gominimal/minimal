# minvmd

macOS-only host daemon that boots a Linux microVM via libkrun and registers a
host UNIX socket ↔ in-VM `minimald` vsock bridge, so the `minimal` CLI can reach
a Linux session daemon on macOS without knowing a VM exists. Spec:
`docs/specs/01-spec-minvmd-host-daemon/`.

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
- `brew install slp/krun/libkrun` — third-party tap; required by minvmd.
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

## E2E test (boot READY round-trip)

`MINVMD_E2E=1`-gated, `#[ignore]` by default. Run the prebuilt test binary
directly — `cargo test` after signing relinks and unsigns `minvmd`.

```sh
cargo test -p minvmd --test boot_e2e --no-run
codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/debug/minvmd
testbin="$(ls -1t target/debug/deps/boot_e2e-* | grep -v '\.d$' | head -1)"
MINVMD_E2E=1 \
MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz" \
MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img" \
MINVMD_INITRAMFS="$PWD/.scratch/initramfs.cpio" \
  "$testbin" --include-ignored --nocapture
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
  `krun_add_vsock_port2(.., listen = true)`; the guest-side relay that serves the
  full session over it lands in a follow-up.

## Notes

- The guest rootfs is the **generic** upstream `microvm-rootfs` package (an ext4
  image built from `base` + `socat`) — minimald is delivered by the initramfs, so
  nothing is baked into the rootfs.
- Session state is on a tmpfs (`/run/minimal`, ephemeral); a persistent data disk
  (which needs a way to `mke2fs` it) is a follow-up.
- In CI (`.github/workflows/ci-macos.yml`) the kernel + rootfs are materialized on
  a cheap Linux runner (`scripts/fetch-artifact.sh` — cache pulls of the upstream
  packages' prebuilt aarch64 artifacts) and the initramfs is cross-compiled
  there; all three are handed to the self-hosted boot job as artifacts.
