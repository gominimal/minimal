---
id: arch-minvmd-linux-kvm
title: "minvmd Linux KVM backend — architecture"
kind: architecture
status: planned
tracking-issue: 397
---

# minvmd Linux KVM backend — architecture

## Chosen approach

Extend `crates/minvmd` from macOS-only to Linux by removing the
`#[cfg(target_os = "macos")]` guards that gate `pub mod krun`, `build.rs`
link directives, `image::kernel_format()`, and `VmConfig::apply()`. The
VMM child and boot command paths each gain a `run_linux()` function
mirroring the existing `run_macos()` with two omissions: no code-signing
step and no Hypervisor.framework check; instead, a `/dev/kvm` file-access
check gates the daemon start. The existing macOS e2e test files (`boot_e2e.rs`,
`minimald_session_e2e.rs`, `bridge_e2e.rs`) drop their
`#[cfg(target_os = "macos")]` file-level attribute and gain a CI job on
a KVM-capable Linux runner.

The process model, socket model, and lifecycle state machine from
`arch-minvmd-host-daemon` (informed by arch-minvmd-host-daemon) are unchanged —
all three are already platform-agnostic.

### Why this is a mechanical change, not an architecture decision

libkrun exports the **same C API** on macOS (Hypervisor.framework) and
Linux (KVM). The platform difference is internal to the library and
invisible at the FFI boundary in `krun/raw.rs`. The `extern "C"` block is
already annotated `#[link(name = "krun")]` with no platform qualifier; the
safe wrappers in `krun/ctx.rs` require no change. Extending to Linux is
therefore primarily:

1. **Build script** (`build.rs`): emit `rustc-link-search` and `-rpath`
   for Linux, defaulting to `/usr` (Fedora `dnf install libkrun-devel` path)
   with the same `LIBKRUN_PREFIX` override as macOS.
2. **Module gating** (`lib.rs`): remove the `#[cfg(target_os = "macos")]`
   guard on `pub mod krun` so the FFI module is compiled on Linux.
3. **Kernel format** (`image.rs`): remove the `#[cfg(target_os = "macos")]`
   guard on `kernel_format()`. The function body is unchanged — Linux and
   macOS use the same libkrun kernel format conventions.
4. **VmConfig::apply** (`vm.rs`): remove the `#[cfg(target_os = "macos")]`
   guard. The method body is unchanged.
5. **VMM child and boot** (`cmd/vmm_child.rs`, `cmd/boot.rs`): add
   `run_linux()` alongside `run_macos()`, dispatched via the `run()` entry
   point. The boot sequence is identical; the only material difference is
   that Linux requires no `codesign` step (KVM access is controlled by
   `/dev/kvm` file permissions, not entitlements).
6. **`/dev/kvm` capability check** (`cmd/vmm_child.rs` or `cmd/boot.rs`):
   open `/dev/kvm` O_RDONLY before calling into libkrun. Return a clear
   error on `ENOENT` (module not loaded) or `EACCES` (user not in `kvm`
   group).
7. **Test un-gating and CI** (`tests/*.rs`, `.github/workflows/`): remove
   `#![cfg(target_os = "macos")]` from the three e2e test files; add a
   Linux KVM CI job on a self-hosted KVM runner.
8. **`main.rs`**: update the crate description from "macOS-only" to
   "VM provider host daemon".

There is no genuine architecture fork. A single defensible approach exists
and is consistent with the spec (informed by #397) and the prior macOS
architecture (informed by arch-minvmd-host-daemon).

### Platform-gating strategy: remove guards rather than add a cfg feature

Alternative A (add a Cargo feature flag `kvm-backend`) was considered and
rejected. The `#[cfg]` guards exist only because the build was macOS-only
at inception — they are not expressing a meaningful feature split.
Introducing a feature adds complexity (CI matrix, feature-combination
tests, documentation) for no benefit: both KVM and Hypervisor.framework
are supported by the same libkrun library with the same API. Removing the
guards and extending `build.rs` is the minimum change.

## Data and interface changes

### `crates/minvmd/build.rs`

`CARGO_CFG_TARGET_OS == "linux"` branch added alongside the existing macOS
branch. Emits `cargo:rustc-link-search=native=${LIBKRUN_PREFIX}/lib` and
`cargo:rustc-link-arg=-Wl,-rpath,${LIBKRUN_PREFIX}/lib`, defaulting
`LIBKRUN_PREFIX` to `/usr`. This matches the Fedora/RHEL package path
(`dnf install libkrun-devel` → `/usr/lib`) and the runner provisioning
convention that uses `LIBKRUN_PREFIX`.

### `crates/minvmd/src/lib.rs`

`pub mod krun` becomes unconditional (no `#[cfg(target_os = "macos")]`).
The `extern "C"` block in `krun/raw.rs` links `libkrun` on both platforms
via the link attribute already present.

### `crates/minvmd/src/image.rs`

`kernel_format()` becomes unconditional. The function body is unchanged —
`aarch64` returns `KernelFormat::Raw`; `x86_64` returns `KernelFormat::Elf`.
These are the correct values for the libkrun KVM backend as well.

### `crates/minvmd/src/vm.rs`

`VmConfig::apply()` `#[cfg(target_os = "macos")]` attribute is removed. The
method body is unchanged and uses only `crate::krun::Context` methods, which
are now unconditionally available.

### `crates/minvmd/src/cmd/vmm_child.rs`

`run_linux()` is added alongside `run_macos()`. The Linux path calls the
same sequence as macOS:

1. Resolve kernel/rootfs/initramfs paths and marker socket from env vars.
2. Create a libkrun `Context`.
3. Apply `VmConfig` (2 vCPU / 1024 MiB, kernel + initramfs, ext4 root
   disk, vsock bridge).
4. Register the READY-marker vsock port.
5. Call `ctx.start_enter()`.

Differences from macOS:
- **`/dev/kvm` check** before `krun_create_ctx`: open `/dev/kvm` with
  `O_RDONLY`; return a clear error on `ENOENT` or `EACCES`.
- **No code-signing**: the `codesign` step in `run_macos` is macOS-only and
  is simply absent from `run_linux`.

`run()` dispatches: `#[cfg(target_os = "linux")]` → `run_linux()`;
`#[cfg(target_os = "macos")]` → `run_macos()`. The "macOS only" bail is
removed.

### `crates/minvmd/src/cmd/boot.rs`

`run_linux()` added mirroring `run_macos()`. No code-signing step. The
READY-marker socket creation, VMM child spawn, and `vm-up` wait logic are
identical. The "macOS only" bail is removed.

### `crates/minvmd/src/cmd/run.rs`

The "macOS only" bail is removed. The supervisor loop, `--detach`
readiness gate, and lifecycle management all use platform-agnostic code
(`lifecycle.rs`, `state.rs`, `sock.rs`); no Linux-specific changes are
needed beyond removing the bail.

### `crates/minvmd/src/main.rs`

Crate description updated from "macOS-only host daemon" to "VM provider
host daemon". macOS-specific subcommand messaging removed.

### `crates/minvmd/tests/{boot_e2e,minimald_session_e2e,bridge_e2e}.rs`

`#![cfg(target_os = "macos")]` file-level attribute removed. Each test
remains `#[ignore]` by default; the `MINVMD_E2E=1` + env-var gate is
unchanged. The test bodies require no change.

### `.github/workflows/` (new CI job)

A Linux KVM e2e job on a self-hosted KVM-capable runner (GCP nested-virt or
equivalent). It provisions libkrun ≥ 1.19.0, materializes the kernel +
rootfs + initramfs from Minimal packages, sets `MINVMD_E2E=1`, and runs
`cargo test -p minvmd -- --include-ignored`. Initially `continue-on-error:
true`; promoted to required once the runner is stable.

## Alternatives considered

### Option A: Cargo feature flag `kvm-backend`

Rejected. The existing `#[cfg(target_os = "macos")]` guards are not a
meaningful feature split — they exist only because the macOS implementation
came first. A feature flag would add CI matrix complexity and require
users to pass `--features kvm-backend` on Linux for no expressive benefit.
Removing the guards is the simpler and correct approach.

### Option B: Separate `minvmd-linux` binary / crate

Rejected. The process model, socket model, lifecycle state machine, and
libkrun FFI surface are identical on both platforms. A separate binary
would duplicate the entire implementation. The spec calls for extending
the existing crate.

## Knowledge gaps

Distillery search returned `arch-minvmd-host-daemon` (score 0.69) as the
closest prior architecture record. That record is the direct predecessor:
this change extends it to Linux. All load-bearing assumptions below are
settled from the prior architecture and the repo working tree.

## Assumption ledger

| slug | statement | bucket | evidence / citation |
|------|-----------|--------|---------------------|
| `libkrun-api-identical` | libkrun exports the same C API on macOS and Linux; the Hypervisor.framework vs KVM difference is internal to the library | settled | `krun/raw.rs` `extern "C"` block has no platform qualifier; spec Design Considerations (informed by #397) |
| `no-codesign-linux` | Linux KVM access is controlled by `/dev/kvm` file permissions, not code-signing entitlements | settled | spec Design Considerations § "No code-signing on Linux" (informed by #397); `/dev/kvm` is a standard Linux kernel interface |
| `libkrun-version-floor` | libkrun ≥ 1.19.0 is required on Linux for the vsock multi-descriptor TX fix (same as macOS) | settled | spec Open Questions §3 (informed by #397); the fix is in shared vsock device code, not platform-specific; informed by arch-minvmd-host-daemon |
| `kernel-format-unchanged` | libkrun KVM backend uses the same kernel format conventions as Hypervisor.framework (Raw for aarch64, Elf for x86_64) | settled | spec § "libkrun API is the same on both platforms" (informed by #397); `image::kernel_format()` body is unchanged |
| `unit-tests-platform-agnostic` | Existing unit tests in `vm.rs`, `image.rs`, `sock.rs`, `lifecycle.rs`, `state.rs` contain no `#[cfg(target_os)]` guards | settled | Serena: `image.rs` test body is already unconditional; `vm.rs`, `sock.rs`, `state.rs`, `lifecycle.rs` tests confirmed platform-agnostic |
