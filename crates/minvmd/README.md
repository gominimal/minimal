# minvmd

macOS-only host daemon that boots a Linux microVM via libkrun and bridges a host
UNIX socket to in-VM `minimald`, so the `minimal` CLI reaches a Linux session
daemon on macOS without knowing a VM exists. Spec:
`docs/specs/01-spec-minvmd-host-daemon/`.

The guest boots from two artifacts produced by the `minimal` package system,
both from upstream `gominimal/pkgs`:
- **kernel** — the `virtio-kernel-raw` package's uncompressed `Image`
  (`virtio-kernel` output).
- **rootfs** — the `microvm-rootfs` package's ext4 image (`minvmd-rootfs`
  output), loaded as a block device (`krun_add_disk2` → `/dev/vda`).

## Run the boot verification locally (Apple Silicon)

Prereqs:
- Apple Silicon Mac.
- `brew install slp/krun/libkrun` — third-party tap; required by minvmd.
- The `minimal` shim on `PATH` (`~/.minimal/shim/bin/minimal`). On macOS,
  `materialize` runs `minimal` inside a Linux VM; a from-source macOS build
  cannot run the build pipeline (sandbox2 is Linux-only).

```sh
# 1. Materialize the kernel + guest rootfs INTO THE REPO.
#    macOS caveat: the shim runs minimal in a VM and only syncs the project dir
#    back to the host, so --output MUST be a path under the repo. A /tmp path is
#    written inside the VM and never appears on the host.
#    The kernel output is an uncompressed Image (virtio-kernel-raw decompresses
#    upstream's Image.gz at build time), loaded raw (KRUN_KERNEL_FORMAT_RAW) to
#    skip libkrun's ~77 ms in-VMM decompress.
mkdir -p .scratch
minimal materialize --output .scratch/vmlinuz    --arch aarch64 virtio-kernel
minimal materialize --output .scratch/rootfs.img --arch aarch64 minvmd-rootfs

# 2. Build minvmd (+ minimal2 for the autospawn path) WITHOUT running.
cargo build -p minvmd --bin minvmd -p minimal2 --bin minimal2

# 3. Codesign minvmd with the hypervisor entitlement. This MUST be the last
#    thing to touch the binary: a later `cargo run`/`cargo test` relinks and
#    unsigns it, and krun_start_enter then fails with EINVAL.
codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/debug/minvmd

# 4. Run. MINVMD_ROOTFS_PATH is the ext4 .img FILE (block device), not a dir.
export PATH="$PWD/target/debug:$PATH"
export MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz"
export MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img"
minimal2 ls        # cold: auto-spawns minvmd, boots the VM, prints []
minvmd status      # running
minimal2 ls        # warm: < 500 ms
minvmd stop
```

## E2E tests (boot + bridge)

`MINVMD_E2E=1`-gated, `#[ignore]` by default. Run the prebuilt test binary
directly — `cargo test` after signing relinks and unsigns `minvmd`.

```sh
cargo test -p minvmd --test boot_e2e --test bridge_e2e --no-run
codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/debug/minvmd
testbin="$(ls -1t target/debug/deps/boot_e2e-* | grep -v '\.d$' | head -1)"
MINVMD_E2E=1 \
MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz" \
MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img" \
  "$testbin" --include-ignored --nocapture
```

## Boot-latency benchmark

`scripts/bench-minvmd-boot.sh` times `minvmd boot` to the guest READY marker over
N runs (default 10) and reports min/median/max. Needs a codesigned `minvmd` and
the kernel + rootfs paths:

```sh
MINVMD_KERNEL_PATH="$PWD/.scratch/vmlinuz" \
MINVMD_ROOTFS_PATH="$PWD/.scratch/rootfs.img" \
  scripts/bench-minvmd-boot.sh
```

CI runs it (informational) in the `boot-e2e` job. Typical: ~67 ms median on
Apple Silicon — see the uncompressed-kernel note below.

## How it boots

- Kernel loaded via `krun_set_kernel` as a raw uncompressed aarch64 `Image`
  (`KRUN_KERNEL_FORMAT_RAW`). The `virtio-kernel` output is built by the upstream
  `virtio-kernel-raw` package, which decompresses upstream's `Image.gz` at build
  time. Loading raw skips libkrun's in-VMM gzip decompress (~77 ms, over half of
  boot-to-READY).
- Rootfs loaded via `krun_add_disk2` as `/dev/vda`; cmdline
  `console=hvc0 root=/dev/vda rootfstype=ext4 ro init=<exec-target>`. A block
  root has **no** libkrun `/init.krun`, so the kernel runs the exec target
  (`MINVMD_EXEC`, default `/sbin/microvm-init`) directly as PID 1; devtmpfs
  auto-mounts `/dev`, giving the workload `/dev/vsock`.
- The guest writes `READY\n` on vsock port 7350 (boot marker, R2.4) and serves
  the bridge on vsock port 2222 (R3); `minvmd` registers the host UDS via
  `krun_add_vsock_port2(.., listen = true)`.

## Notes

- The guest rootfs is the upstream `microvm-rootfs` package (an ext4 image built
  from `base` + `socat`, packed with `mke2fs`). The exec target is the bring-up
  stub `/sbin/microvm-init`; `/sbin/minimald` is the production target (Stage 2).
- In CI (`.github/workflows/ci-macos.yml`) the kernel is materialized on a Linux
  runner and the rootfs on the self-hosted aarch64 runner; both are handed to the
  boot jobs as artifacts.
