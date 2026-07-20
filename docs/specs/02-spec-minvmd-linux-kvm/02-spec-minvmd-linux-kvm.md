---
id: spec-minvmd-linux-kvm
title: "minvmd Linux KVM backend"
kind: spec
status: shipped
tracking-issue: 397
supersedes:
---

# minvmd Linux KVM backend

## Context

`minvmd` was built in #311 as the macOS-only VM provider daemon. Every
libkrun-touching path is currently gated behind `#[cfg(target_os = "macos")]`,
and the daemon bails at runtime on Linux with a "macOS only" error. The macOS
implementation is complete: libkrun FFI wrappers (`src/krun/raw.rs`,
`src/krun/ctx.rs`), VM configuration builder (`src/vm.rs`), the
UDS↔vsock bridge (via `krun_add_vsock_port2`), lifecycle daemon
(`src/lifecycle.rs`, `src/state.rs`), and a bidirectional bash session e2e
(`tests/minimald_session_integration.rs`) all work end-to-end on macOS (informed by
#374, merged 2026-06-11).

Linux hosts today reach `minimald` over direct UDS with namespace (hakoniwa)
sandboxing. When a user requests VM isolation on a Linux host — including GCP
nested-virt instances with `/dev/kvm` — there is no `minvmd` path. This
spec adds it.

libkrun supports both macOS (Hypervisor.framework) and Linux (KVM) through the
**same C API**. The Hypervisor.framework vs KVM difference is internal to
libkrun and invisible at the FFI boundary. Extending `minvmd` to Linux is
therefore primarily a matter of removing the macOS-only `#[cfg]` guards and
extending the build script, with small Linux-specific handling where needed
(no code-signing entitlements; different default libkrun prefix).

This spec covers the change to `crates/minvmd/` that makes the daemon
build, boot a microVM, bridge UDS↔vsock, and pass the bidirectional session
e2e on a Linux host. It builds on the package-served kernel and rootfs from
#367, the minimald-as-pid-1 initramfs from #373, and the direct vsock
session path from #374.

**Networking** remains out of scope — owned by the minvmd networking issue
(gvproxy/TSI userspace net).

**Selection surface** (the mechanism by which a Linux session chooses VM
isolation over namespace isolation) is treated as an open question (see Open
Questions below). For this spec, VM isolation on Linux requires manually
running `minvmd run --detach` before using `minimal`; the auto-spawn path in
`minimal` stays a no-op on Linux. The full selection surface — per-session
flag, loadout field, or policy — is deferred to a follow-up under #396.

## Introduction/Overview

`minvmd` currently compiles to a runtime-bailing stub on Linux. This spec
removes that restriction: after landing, `minvmd run` on a Linux host with
`/dev/kvm` boots a microVM (libkrun KVM backend), bridges a host UDS to the
in-VM `minimald` over vsock, and the `minimal` CLI reaches `minimald`
transparently — the same path as macOS, without any Hypervisor.framework
dependency.

The Session Domain Model (`docs/internal/session-domain-diag.md`) already shows a
"Local Linux deployment" where both `minimald` (direct namespace provider) and
`minvmd` (VM provider) coexist on the same host, each exposing its own socket.
This spec realizes the `minvmd` side of that diagram for Linux
(informed by the session domain model in `docs/internal/session-domain-diag.md`).

## Goals

1. `minvmd` builds green on Linux (`x86_64-unknown-linux-gnu` and
   `aarch64-unknown-linux-gnu`); the macOS build is unaffected.
2. On a Linux host with `/dev/kvm`, `minvmd boot --foreground` boots a
   microVM from the package-served kernel + initramfs, receives the guest
   `READY` marker, and exits 0.
3. The UDS↔vsock bridge works on Linux: `minimal` reaches in-VM `minimald`
   via the host UDS without knowing a VM exists.
4. The bidirectional bash session e2e (`tests/minimald_session_integration.rs`)
   passes on Linux, mirroring the macOS Stage-2 e2e.
5. Warm-boot latency on Linux/KVM is measured and reported against the
   ~75 ms macOS baseline.

## User Stories

- As a Linux developer with `/dev/kvm`, I want to run `minvmd run --detach`
  so that I can start a VM-isolated `minimald` and reach it via UDS, the
  same way macOS users do.
- As a CI maintainer, I want the `minvmd` e2e tests to run on a Linux KVM
  runner so that regressions in the Linux path are caught automatically.
- As a Linux developer, I want `minvmd stop` and `minvmd status` to work on
  Linux so that I can manage the VM lifecycle from the host.
- As a macOS developer, I want the existing macOS build and e2e tests to
  remain unchanged so that my workflow is not disrupted.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1;
> R2.1 for Unit 2). These IDs are referenced directly by the planner — do
> not renumber after approval.

---

### Unit 1: Un-gate libkrun from macOS — build and link on Linux

**Purpose:** Make `crates/minvmd` compile cleanly on Linux by extending the
build script and removing the `#[cfg(target_os = "macos")]` guards that gate
the `krun` module and the VM configuration. No runtime change yet — the
daemon still bails on `boot` and `run` until Unit 2.

**Depends on:** None

**Affected areas:** `crates/minvmd/build.rs`, `crates/minvmd/src/lib.rs`,
`crates/minvmd/src/krun/mod.rs`, `crates/minvmd/src/image.rs`,
`crates/minvmd/src/vm.rs`

**Baseline:** `build.rs` is a no-op on Linux; `lib.rs` gates `pub mod krun`
on `#[cfg(target_os = "macos")]`; `image::kernel_format()` and
`VmConfig::apply()` are both macOS-only. All of this is **ALREADY IN PLACE**
as the current macOS-only implementation — no new krun code is written;
the guards are removed.

**Functional Requirements:**

- **R1.1**: `build.rs` shall emit `cargo:rustc-link-search=native=` and
  `cargo:rustc-link-arg=-Wl,-rpath,` link directives on Linux in addition to
  macOS. The Linux default prefix shall be `/usr`, with the same
  `LIBKRUN_PREFIX` env-var override as macOS. A comment shall note that on
  Linux the typical install locations are `/usr/lib` (Fedora/RHEL: `dnf
  install libkrun-devel`) and `/usr/local/lib` (source build); CI shall
  install the library at the path used by the runner's provisioning step.
- **R1.2**: `lib.rs` shall make `pub mod krun` unconditionally available (no
  `#[cfg(target_os = "macos")]` guard). All existing `krun/raw.rs` and
  `krun/ctx.rs` code compiles on Linux; the `#[link(name = "krun")]`
  attribute on the `extern "C"` block is already platform-agnostic (libkrun
  exports the same symbols on both platforms) and requires no change.
- **R1.3**: `image::kernel_format()` shall be un-gated from macOS and return
  the arch-appropriate `KernelFormat` on Linux: `KernelFormat::Raw` for
  `aarch64` (uncompressed kernel image, same as macOS aarch64) and
  `KernelFormat::Elf` for `x86_64` (`bzImage`, same as macOS x86_64). On
  Linux, libkrun's KVM backend uses the same kernel format conventions as the
  Hypervisor.framework backend.
- **R1.4**: `VmConfig::apply()` shall be un-gated from macOS. The method body
  is unchanged; the `#[cfg(target_os = "macos")]` attribute is removed.
- **R1.5**: `cargo build -p minvmd` on Linux shall exit 0 with no warnings
  (after supplying libkrun at the link path from R1.1). The existing unit
  tests in `vm.rs`, `image.rs`, `sock.rs`, `lifecycle.rs`, and `state.rs`
  shall all pass on Linux (they are already platform-agnostic).

**Proof Artifacts:**

1. **CLI:** `cargo build -p minvmd` on a Linux host with libkrun installed
   exits 0 — demonstrates the crate links cleanly against libkrun on Linux.
2. **Test:** `cargo test -p minvmd` (excluding e2e tests) on Linux exits 0 —
   demonstrates existing unit tests pass on Linux.

---

### Unit 2: VMM child on Linux — KVM boot, READY marker, UDS↔vsock bridge

**Purpose:** Make `minvmd boot` and `minvmd run` functional on Linux. Since
libkrun's API is identical on both platforms, the Linux VMM child and boot
paths are near-copies of the macOS paths with two differences: no code-signing
step is required on Linux, and the check-capability gate uses `/dev/kvm`
instead of Hypervisor.framework availability.

**Depends on:** Unit 1

**Affected areas:** `crates/minvmd/src/cmd/vmm_child.rs`,
`crates/minvmd/src/cmd/boot.rs`, `crates/minvmd/src/cmd/run.rs`,
`crates/minvmd/src/main.rs`

**Functional Requirements:**

- **R2.1**: `cmd/vmm_child.rs` shall add a `run_linux()` function alongside
  the existing `run_macos()`. The Linux path calls the same sequence:
  resolve kernel/rootfs/initramfs paths, create a libkrun `Context`, apply
  `VmConfig` (2 vCPU / 1024 MiB, kernel + initramfs, ext4 root disk,
  vsock bridge on `VSOCK_BRIDGE_PORT`), register the READY-marker vsock port,
  and call `ctx.start_enter()`. The top-level `run()` function dispatches to
  `run_linux()` on `target_os = "linux"` and to `run_macos()` on macOS;
  the "macOS only" bail is removed.
- **R2.2**: `cmd/boot.rs` shall add a `run_linux()` function mirroring
  `run_macos()`. The only material difference is that Linux requires no
  code-signing entitlements (the `codesign` step is macOS-only). The READY-
  marker socket creation, VMM child spawn, and `vm-up` wait logic are
  identical. The "macOS only" bail is removed.
- **R2.3**: `cmd/run.rs` shall be un-gated from macOS in the same way. The
  supervisor loop, `--detach` readiness gate, and lifecycle management all use
  platform-agnostic code (`lifecycle.rs`, `state.rs`, `sock.rs`); no
  Linux-specific changes are needed in this file beyond removing the bail.
- **R2.4**: A KVM capability check shall be added to the daemon start path.
  Before `krun_start_enter`, `minvmd` shall verify that `/dev/kvm` is
  accessible (readable) on Linux. If not accessible, `boot` and `run` shall
  exit with a clear user-facing error naming `/dev/kvm` and suggesting
  privilege/module remediation. On macOS the check is skipped (Hypervisor
  .framework availability is verified by `krun_create_ctx` itself).
- **R2.5**: `main.rs` shall update the crate description from "macOS-only
  host daemon" to "VM provider host daemon" and remove any macOS-specific
  messaging from subcommand docs.

**Proof Artifacts:**

1. **CLI:** `MINVMD_KERNEL_PATH=<k> MINVMD_ROOTFS_PATH=<r> MINVMD_INITRAMFS=<i> minvmd boot --foreground`
   on a Linux host with `/dev/kvm` prints `vm-up` within 10 s — demonstrates
   KVM boot + READY marker round-trip on Linux.
2. **Test:** `MINVMD_E2E=1 cargo test -p minvmd --test boot_integration -- --include-ignored`
   on a Linux host with `/dev/kvm` exits 0 — demonstrates the automated boot
   e2e passes (test is un-gated from macOS in Unit 3).

---

### Unit 3: Linux e2e tests and latency benchmark

**Purpose:** Un-gate the existing macOS-only e2e tests so they run on Linux,
add a CI job on a KVM-capable Linux runner, and capture warm-boot latency to
establish the Linux/KVM baseline.

**Depends on:** Unit 2

**Affected areas:** `crates/minvmd/tests/boot_integration.rs`,
`crates/minvmd/tests/minimald_session_integration.rs`,
`crates/minvmd/tests/bridge_e2e.rs`,
`.github/workflows/` (new Linux KVM e2e job),
`scripts/bench-minvmd-boot.sh` (or equivalent on Linux)

**Functional Requirements:**

- **R3.1**: `tests/boot_integration.rs` shall remove the `#![cfg(target_os = "macos")]`
  file-level attribute. The READY-marker round-trip test shall run on Linux
  when `MINVMD_E2E=1` and the kernel/rootfs/initramfs env vars are set; it is
  still gated `#[ignore]` by default. The test body is unchanged.
- **R3.2**: `tests/minimald_session_integration.rs` shall remove the
  `#![cfg(target_os = "macos")]` attribute. The bidirectional bash session
  e2e (russh client → UDS bridge → guest vsock → minimald SSH → exec) shall
  run on Linux under the same gate (`MINVMD_E2E=1` + env vars). The test
  body is unchanged; libkrun ≥ 1.19.0 is required on the Linux runner (same
  requirement as macOS).
- **R3.3**: `tests/bridge_e2e.rs` shall be un-gated from macOS in the same
  way. The 5-concurrent-connection multiplexing test shall run on Linux.
  (`bridge_e2e.rs` was later removed in the auto-discovery migration —
  superseded by `minimald_session_integration.rs`.)
- **R3.4**: The CI configuration shall add a Linux KVM e2e job. The job runs
  on a self-hosted Linux runner with `/dev/kvm` access (GCP nested-virt or
  equivalent). It provisions libkrun ≥ 1.19.0, materializes the kernel +
  rootfs + initramfs from Minimal packages, sets `MINVMD_E2E=1`, and runs
  `cargo test -p minvmd -- --include-ignored`. The job is allowed-to-fail
  initially (as the macOS e2e job was) and is promoted to required once the
  runner is stable.
- **R3.5**: Warm-boot latency on Linux/KVM shall be measured by running
  `scripts/bench-minvmd-boot.sh` (or a Linux-compatible equivalent) on the
  KVM runner with a sample of ≥ 10 boot cycles. The min/median/max latency
  shall be reported in the pull request description as a comment against the
  ~75 ms macOS baseline. No performance gate is enforced — this is a
  measurement and documentation requirement.

**Proof Artifacts:**

1. **Test:** `MINVMD_E2E=1 cargo test -p minvmd --test minimald_session_integration -- --include-ignored`
   on a Linux host with `/dev/kvm` exits 0, proving the bidirectional bash
   session e2e passes on Linux over the host UDS→vsock bridge.
2. **File:** The pull request description contains a latency table (min /
   median / max boot-to-READY) from the Linux/KVM benchmark run, cited
   against the ~75 ms macOS baseline — demonstrates R3.5 was executed.

---

## Non-Goals

- **Selection surface / auto-spawn on Linux.** `minimal`'s
  `ensure_minvmd_running()` on Linux remains a no-op in this spec. A user
  opts into VM isolation by running `minvmd run --detach` manually. The
  per-session flag, loadout field, or policy mechanism is deferred to a
  follow-up under #396. This explicitly defers the "interacts with the
  taskspec capability envelope" aspect from the tracking issue open question.
- **Provider-interface formal spec.** The `docs/internal/session-domain-diag.md`
  Provider contract ("every provider delivers a reachable `minimald` endpoint
  over UDS") is sufficient for this spec. A formal provider-interface spec
  covering CF Firecracker, GCP, Daytona, and other backends is a separate
  concern under #396.
- **Networking.** gvproxy/TSI userspace networking is out of scope (tracked
  by the minvmd networking issue).
- **Cross-compilation.** Linux builds target the host arch; cross-compilation
  for mismatched host/guest arches is not in scope.

## Design Considerations

### libkrun API is the same on both platforms

libkrun exports the same `krun_*` C symbols on macOS and Linux. The
Hypervisor.framework vs KVM difference is entirely internal to the library.
The FFI bindings in `src/krun/raw.rs` require no changes; the safe wrappers
in `src/krun/ctx.rs` require no changes. Un-gating is largely a mechanical
removal of `#[cfg(target_os = "macos")]` attributes.

### No code-signing on Linux

macOS requires a `codesign --entitlements minvmd.entitlements` step to grant
`com.apple.security.hypervisor`. Linux has no equivalent requirement — KVM
access is controlled by `/dev/kvm` file permissions (typically `kvm` group
membership or `chmod 666`). The `minvmd.entitlements` file and the `justfile`
code-signing target are macOS-only and require no change.

### libkrun installation on Linux

On macOS, libkrun is installed via the Homebrew tap (`slp/krun/libkrun`) at
`/opt/homebrew/lib`. On Linux the typical install paths are:
- Fedora/RHEL: `dnf install libkrun-devel` → `/usr/lib`
- Ubuntu/Debian: source build → `/usr/local/lib` (no distro package as of
  this writing)
- CI self-hosted runners: provisioned to the path used by `LIBKRUN_PREFIX`

The `build.rs` default of `/usr` covers the Fedora path; GCP nested-virt
runners provisioned via the infrastructure team use the configured path.

### Relation to the session domain model

`docs/internal/session-domain-diag.md` (informed by the session domain model) already
models Linux as a coexistence scenario: `minimald` (direct namespace provider)
and `minvmd` (VM provider) each expose their own UDS; `minimal` discovers both.
This spec realizes the `minvmd` side of the Linux deployment diagram without
changing the `minimal`/`minimal` discovery logic.

## Repository Standards

- `cargo fmt && cargo test -- --include-ignored` clean before merge.
- `cargo clippy --allow-dirty --fix --all-targets -- -D warnings` clean
  before merge.
- Commit messages follow Conventional Commits (per `docs/commit-conventions.md`).
- All `unsafe` additions carry `// SAFETY:` comments naming libkrun
  preconditions (per the existing FFI discipline in `src/krun/raw.rs`).

## Open Questions

1. **VM-vs-namespace selection surface.** When should a Linux session
   automatically use `minvmd` (VM isolation) vs `minimald` (namespace
   isolation)? Options: per-session `--vm` flag; loadout field in
   `minimal.toml`; presence-based policy (if `/dev/kvm` and `minvmd` are
   both running, use VM). This interacts with the taskspec capability envelope
   (#161). Deferred to a follow-up issue under #396. For this PR, the user
   explicitly invokes `minvmd run --detach` to opt into VM isolation.

2. **Provider-interface formal contract.** The informal contract "every
   provider delivers a reachable `minimald` endpoint over UDS" is satisfied
   by this implementation (via the vsock bridge) and by the direct-native
   `minimald` path. Whether to formalize this as a spec for the provider
   interface — covering CF Firecracker, GCP, Daytona, and other backends —
   is a separate question under #396. Not blocked by this spec.

3. **libkrun version floor on Linux.** libkrun ≥ 1.19.0 is required on macOS
   (vsock multi-descriptor TX fix; informed by #374). The same floor is
   assumed for Linux since the fix is in the shared vsock device code, not
   platform-specific. The CI runner provisioning must enforce this floor.

## Technical Considerations

- **KVM capability check (R2.4):** Opening `/dev/kvm` for a brief
  `O_RDONLY` check is the idiomatic Linux KVM availability test. Returns
  `ENOENT` if the module is not loaded, `EACCES` if the user is not in the
  `kvm` group. Both errors warrant distinct user-facing messages.
- **Marker socket nonce on Linux:** `/dev/urandom` is available on all Linux
  distributions; the nonce-generation logic in `cmd/boot.rs` (`run_macos`)
  is unchanged for Linux.
- **`krun_start_enter` semantics on Linux:** Same as macOS — the call diverges
  on success by calling `exit()`. The VMM child process model
  (parent/supervisor + hidden `__krun-vmm` child) is unchanged.
- **Existing unit tests:** `lifecycle.rs`, `state.rs`, `sock.rs`, and
  `image.rs` tests are already platform-agnostic (no `#[cfg(target_os)]`
  guards); they will pass on Linux without modification.

## Security Considerations

- `/dev/kvm` access on Linux is controlled by file permissions (typically
  group `kvm`). `minvmd` does not attempt to escalate permissions; it fails
  early with a clear error if `/dev/kvm` is not accessible.
- The guest microVM is isolated by KVM hardware virtualization; the trust
  boundary is the same as macOS (libkrun → KVM hypervisor boundary).
- The host UDS is created with the same `0700` parent directory and `0600`
  socket permissions as on macOS (implemented in `src/sock.rs`, already
  platform-agnostic).
- No new secrets or credentials are introduced.

## Verification

The following tests confirm this spec end-to-end. All gated tests require a
Linux host with `/dev/kvm`, libkrun ≥ 1.19.0, and the package-served
kernel + rootfs + initramfs.

| Unit | Gate | Command | Expected result |
|------|------|---------|-----------------|
| R1.5 | — | `cargo build -p minvmd` (Linux) | Exit 0 |
| R1.5 | — | `cargo test -p minvmd` (Linux, unit tests) | All pass |
| R2.3 | `MINVMD_E2E=1` + env vars | `minvmd boot --foreground` (Linux) | Prints `vm-up` ≤ 10 s |
| R3.1 | `MINVMD_E2E=1` + env vars | `cargo test -p minvmd --test boot_integration -- --include-ignored` | Exit 0 |
| R3.2 | `MINVMD_E2E=1` + env vars | `cargo test -p minvmd --test minimald_session_integration -- --include-ignored` | Exit 0 |
| R3.5 | `MINVMD_E2E=1` + env vars | `scripts/bench-minvmd-boot.sh` (Linux, ≥ 10 runs) | Latency table in PR description |
