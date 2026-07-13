---
id: spec-minvmd-host-daemon
title: "minvmd macOS VM provider host daemon"
kind: spec
status: planned
supersedes:
---

# minvmd macOS VM provider host daemon

## Context

`minimal` is a declarative package manager and build system. On Linux,
`minimald` (the session daemon) runs natively and the CLI talks to it over
a UNIX domain socket. On macOS there is no native Linux namespace support,
so a microVM is required to host `minimald`. `minvmd` is the host daemon
that fills this gap: it boots a Linux microVM via libkrun (Hypervisor.framework
on macOS, KVM on Linux), supervises its lifecycle, and bridges a host UDS to a
vsock port inside the VM so the `minimal` CLI can talk to `minimald`
transparently.

The crate already exists in the workspace at `crates/minvmd/` with FFI
bindings (`src/krun/raw.rs`), safe wrappers (`src/krun/ctx.rs`), typed
errors (`src/error.rs`), a build script for libkrun linking, macOS
entitlements, and a CLI skeleton. Unit 1's requirements (R1.2, R1.3)
are acceptance criteria for the existing scaffolding — they validate
that the code already landed meets the spec's safety and error-handling
standards; they are not new-from-scratch deliverables. This spec covers
the remaining work to make the daemon functional end-to-end: VM boot
with a real kernel and rootfs, the UDS↔vsock bridge, and the lifecycle
daemon (auto-spawn, status, stop).

Networking is explicitly deferred to [#160](https://github.com/gominimal/minimal/issues/160).
The crate builds and runs on Linux via libkrun's KVM backend, exercised by the
dedicated Linux/KVM CI lane (`ci-linux-kvm.yml`).

## Introduction/Overview

`minvmd` is the third process in the Minimal One architecture (alongside
`minimal` and `minimald`). It exists solely to absorb the VM boundary
that macOS imposes. The daemon:

1. Boots a Linux microVM from a `virtio-linux` kernel and Alpine rootfs
   via libkrun's Hypervisor.framework backend.
2. Bridges a host UDS to a vsock port inside the VM so `minimal` reaches
   `minimald` without knowing a VM exists.
3. Auto-spawns on first CLI call (Docker-Desktop model), survives client
   exit, and exposes `status`/`stop` subcommands for introspection and
   graceful shutdown.

## Goals

1. `crates/minvmd` builds green on macOS (aarch64 + x86_64) and Linux
   (x86_64 via KVM); no CI regressions.
2. `minimal` CLI on macOS opens a connection to in-VM `minimald` over a
   host UDS without knowing a VM exists (transparent vsock bridge).
3. VM boots from a `virtio-linux` kernel + Alpine rootfs in under ~5 s
   cold; warm reattach is sub-second.
4. `minvmd` auto-spawns on first CLI call and survives client exit.
5. `minvmd status` / `minvmd stop` work; PID and socket discovery follow
   XDG conventions; concurrent CLI invocations don't race lifecycle.

## User Stories

- As a Mac user, I want to run `minimal ls` on a fresh install so that
  I get `[]` end-to-end without manually starting a VM.
- As a Mac user, I want my second `minimal ls` to be instant so that the
  VM cold-start cost is amortized.
- As a Mac user, I want to run `minvmd status` so that I can see VM
  state, vcpus, ram, and uptime.
- As a Mac user, I want to run `minvmd stop` so that the VM shuts down
  gracefully and the next `minimal` call cold-starts a fresh VM.
- As a Linux user, I want `minvmd` to not be installed at all so that my
  install path stays simple.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for
> Unit 1; R2.1 for Unit 2). These IDs are referenced directly by the
> planner — do not renumber after approval.

### Unit 1: Crate scaffold, FFI wrappers, libkrun smoke test

**Purpose:** Land the bones — crate, FFI bindings, build script, codesign
step. Boot a libkrun context to the marker "VM started, exited cleanly"
with no rootfs work.

**Depends on:** None

**Affected areas:** `crates/minvmd/` (existing), `crates/minvmd/src/krun/`
(existing), `crates/minvmd/minvmd.entitlements` (existing),
`crates/minvmd/build.rs` (existing), `Cargo.toml` (workspace), `justfile`

**Functional Requirements:**

- **R1.1**: The `minvmd` crate shall compile on `aarch64-apple-darwin`
  and `x86_64-apple-darwin`, and shall build and run natively on
  `x86_64-unknown-linux-gnu` via libkrun's KVM backend.
  (translated from plan: step R1.1)
- **R1.2**: FFI bindings shall live in a single `src/krun/raw.rs` module;
  every `unsafe` call shall carry a `// SAFETY:` comment naming the
  libkrun preconditions (pointer lifetime, NUL-termination, range bounds,
  ownership transfer). (translated from plan: step R1.2)
- **R1.3**: Safe wrappers (`src/krun/ctx.rs`) shall validate all inputs
  in safe Rust before crossing the FFI boundary; FFI return codes shall
  be translated to a typed `VmError::Backend { op, source }` preserving
  the original errno via `io::Error::from_raw_os_error`. The
  return-code translation lives as a free function in the `krun` FFI
  module. (translated from plan: step R1.3)
- **R1.4**: Release builds shall be code-signed with
  `minvmd.entitlements` granting `com.apple.security.hypervisor` and
  nothing else; a `justfile` target shall reproduce the signing step
  locally. (translated from plan: step R1.4)
- **R1.5**: A smoke test `tests/krun_smoke_e2e.rs` (gated on
  `MINVMD_E2E=1`, marked `#[ignore]` by default) shall create a
  libkrun context, configure 1 vcpu + 512 MiB, set `/bin/true` as
  exec, and confirm `krun_start_enter` exits cleanly.
  (translated from plan: step R1.5)

**Proof Artifacts:**

1. **File:** `crates/minvmd/src/krun/raw.rs` contains FFI declarations
   for `krun_create_ctx`, `krun_set_vm_config`, `krun_set_exec`,
   `krun_start_enter`, `krun_free_ctx` with `// SAFETY:` comments —
   demonstrates the FFI scaffold and safety discipline.
2. **CLI:** `MINVMD_E2E=1 cargo test -p minvmd --test krun_smoke_e2e -- --include-ignored`
   exits 0 on a Mac with libkrun installed — demonstrates end-to-end
   FFI bring-up.

---

### Unit 2: VM bring-up with virtio-linux kernel + Alpine rootfs

**Purpose:** Actual Linux boot. `minvmd boot` brings up an Alpine VM
that reaches userspace and writes a "READY" marker to vsock from its
guest workload. libkrun's built-in init (`/init.krun`) runs as PID 1,
mounts `/proc`, `/sys`, `/dev`, and execs the workload set via
`krun_set_exec` — so the rootfs needs no init system (no OpenRC).

**Depends on:** Unit 1

**Affected areas:** `crates/minvmd/src/image.rs` (new),
`crates/minvmd/src/vm.rs` (new), `crates/minvmd/src/cmd/boot.rs` (new),
`crates/minvmd/src/cmd/vmm_child.rs` (new)

**Functional Requirements:**

- **R2.1**: The kernel artifact shall be the `vmlinuz` output of the
  `virtio-linux` minimal package; on aarch64 the artifact is `Image.gz`,
  on x86_64 `bzImage`. Path resolution shall happen at runtime via a
  `MINVMD_KERNEL_PATH` env var. The kernel shall be loaded directly — no EFI
  firmware, no disk image — via `krun_set_kernel` with the arch-appropriate
  libkrun format: `KRUN_KERNEL_FORMAT_PE_GZ` for the aarch64 `Image.gz` (the
  aarch64 loader implements only `RAW` and `PE_GZ`; `IMAGE_GZ` is x86_64-only
  and returns `KernelFormatUnsupported` on aarch64) and `KRUN_KERNEL_FORMAT_ELF`
  for the x86_64 `bzImage`. The `virtio-linux` kernel shall be built with
  virtio-MMIO (not PCI), `VIRTIO_FS`/`FUSE`, `VIRTIO_VSOCKETS`, and
  `VIRTIO_CONSOLE`/HVC all `=y` (the default cmdline carries `nomodule`).
  (translated from plan: step R2.1)
- **R2.2**: The rootfs shall be an Alpine minirootfs (version-pinned,
  sha256-verified). For v0.1 the path is supplied via `MINVMD_ROOTFS_PATH`;
  `scripts/fetch-alpine.sh` stages the base and `scripts/build-rootfs.sh`
  overlays the guest workload (`/sbin/minvmd-stub-init`) plus its runtime
  closure (socat and the sha256-pinned `readline` + `libncursesw` apks it
  dynamically links). The result is a directory consumed by `krun_set_root` as
  virtio-fs — no disk image. (translated from plan: step R2.2)
- **R2.3**: `minvmd boot` (parent) shall configure the libkrun context
  via the safe wrappers, then fork-exec a hidden
  `minvmd __krun-vmm` child that calls `krun_start_enter`. The child shall set
  the guest workload via `krun_set_exec` (default `/sbin/minvmd-stub-init`,
  overridable by `MINVMD_EXEC`) with an explicit minimal envp, leave the kernel
  cmdline unset (libkrun's default supplies `console=hvc0 rootfstype=virtiofs
  rw` and injects `init=/init.krun`), and configure 2 vCPU / 1024 MiB. The
  parent shall write a `vmm.pid` file and surface child-exit codes via signal
  handling. (translated from plan: step R2.3)
- **R2.4**: Boot shall complete to a guest-side marker within 5 s on a warm
  laptop; the parent shall block on this marker before reporting boot success.
  The marker is **guest-initiated**: the host registers the marker port (7350)
  with the plain `krun_add_vsock_port` (≡ `krun_add_vsock_port2(.., listen =
  false)`) and listens on the host UDS; the guest workload connects to
  AF_VSOCK CID 2 (host) port 7350 and writes `READY\n`, which libkrun bridges
  to the host. This is the opposite direction from the R3 `ssh.sock` bridge
  (`listen = true`, host-initiated). (translated from plan: step R2.4)
- **R2.5**: No network device shall be added to the libkrun config in
  v0.1; gvproxy/TSI integration is owned by #160.
  (translated from plan: step R2.5)

**Proof Artifacts:**

1. **CLI:** `MINVMD_KERNEL_PATH=<path> MINVMD_ROOTFS_PATH=<path> minvmd boot --foreground`
   boots and prints `vm-up` to stdout within 5 s, and a host-side reader
   on the vsock marker socket reads `READY` — demonstrates kernel+rootfs
   come up.
2. **Test:** `tests/boot_e2e.rs` (gated `MINVMD_E2E=1`, `#[ignore]`)
   asserts the marker round-trip end-to-end — demonstrates automated
   boot verification.

---

### Unit 3: UDS↔vsock bridge for `ssh.sock`

**Purpose:** The product feature — a host UDS the CLI talks to, bridged
by libkrun to the in-VM vsock port where `minimald` listens.
Bidirectional, transport-agnostic, multiple concurrent connections.
**minvmd does not relay bytes itself** — libkrun owns the host UDS and
the vsock forwarding.

**Depends on:** Unit 2

**Affected areas:** `crates/minvmd/src/krun/raw.rs` (add
`krun_add_vsock_port2`), `crates/minvmd/src/krun/ctx.rs` (wrap it),
`crates/minvmd/src/vm.rs` (register the vsock port before boot),
`crates/minvmd/src/sock.rs` (host UDS path resolution, parent-dir +
permissions), guest-side vsock stub

**Functional Requirements:**

- **R3.1**: Before `krun_start_enter`, `minvmd` shall register the host
  UDS via `krun_add_vsock_port2(ctx, VSOCK_PORT, HOST_UDS_PATH, listen = true)`.
  `listen = true` means connections are initiated from the host side:
  libkrun listens on the host UDS and bridges each accepted connection
  to a guest process listening on vsock `VSOCK_PORT`.
  (translated from plan: step R3.1)
- **R3.2**: The host UDS path shall be
  `$XDG_RUNTIME_DIR/minimal/minimald.sock`; if `XDG_RUNTIME_DIR` is
  unset the fallback is `~/.minimal/local/minimald.sock`. `minvmd`
  shall create the parent directory with mode 0700 if absent and verify
  the bound socket is owner-only (0600). (translated from plan: step R3.2)
- **R3.3**: libkrun shall multiplex multiple concurrent host
  connections, each bridged to an independent vsock connection to
  `VSOCK_PORT`; `minvmd` carries no per-connection state.
  (translated from plan: step R3.3)
- **R3.4**: v0.1 uses a vsock stub. The guest-side responder is a small
  stub that listens on vsock `VSOCK_PORT` directly and answers the
  health / `list-sessions` ping with an empty list. The real `minimald`
  swap-in is deferred (Open Questions). (translated from plan: step R3.4)
- **R3.5**: On guest unavailability, host connect/exchange shall fail at
  the libkrun bridge; `minvmd` shall `tracing::warn!` where observable,
  and `minimal`'s provider discovery shall treat the failed connect as
  "stale provider — prune and continue". The TSI ~62-concurrent-connection
  cap shall be documented as a comment near the vsock registration.
  (translated from plan: step R3.5)

**Proof Artifacts:**

1. **Test:** `tests/bridge_e2e.rs` (gated `MINVMD_E2E=1`, `#[ignore]`)
   boots a VM whose guest listens on vsock `VSOCK_PORT`, opens 5
   concurrent host UDS connections, each writes a distinct payload and
   reads it back. All 5 succeed — demonstrates libkrun-multiplexed
   bidirectional bridging. (Removed in the auto-discovery migration: it
   bridged the Stage-1 socat-echo stub that minimald-as-pid1 replaced
   with a direct SSH session server; session coverage of the bridge is
   now `tests/minimald_session_e2e.rs`.)
2. **CLI:** With a stub `minimald` reachable on vsock `VSOCK_PORT`,
   running `nc -U $XDG_RUNTIME_DIR/minimal/minimald.sock` from the host
   yields the empty `list-sessions` response end-to-end — demonstrates
   the host→guest path.

---

### Unit 4: Lifecycle daemon — auto-spawn, status, stop

**Purpose:** Daemon UX. `minimal` calling `minvmd` for the first time
auto-spawns it; subsequent calls reuse; `minvmd status` introspects;
`minvmd stop` shuts down gracefully.

**Depends on:** Unit 3

**Affected areas:** `crates/minvmd/src/cmd/{run,status,stop}.rs` (new),
`crates/minvmd/src/state.rs` (new), `crates/minvmd/src/lifecycle.rs`
(new), `crates/minimal/src/main.rs` (extend)

**Functional Requirements:**

- **R4.1**: State and PID files shall live under
  `$XDG_STATE_HOME/minimal/minvmd/` (default
  `~/.local/state/minimal/minvmd/`): `state.toml` (lifecycle enum:
  `NotProvisioned | Stopped | Starting | Running | Stopping`, plus
  `vmm_pid` + `started_at`), `vmm.pid`, `lifecycle.lock`. `state.toml`
  writes shall be atomic (tmp + rename + fsync).
  (translated from plan: step R4.1)
- **R4.2**: `minvmd run` shall be a foreground supervisor;
  `minvmd run --detach` shall background-spawn and return only after the
  host UDS is accepting connections, with a configurable timeout (default
  8 s). (translated from plan: step R4.2)
- **R4.3**: `minvmd status` shall print human-readable status by default
  and JSON with `--json` (fields: `state`, `vmm_pid`, `uptime_seconds`,
  `vcpus`, `ram_mib`). Exit code 0 if running, 1 if stopped, 2 on lock
  contention. (translated from plan: step R4.3)
- **R4.4**: `minvmd stop` shall SIGTERM the vmm child, wait up to 5 s,
  SIGKILL on timeout, then remove `vmm.pid` and reset `state.toml` to
  `Stopped`. The command shall be idempotent.
  (translated from plan: step R4.4)
- **R4.5**: On macOS and Linux, `crates/minimal` shall check `state.toml`
  before connecting to the UDS; if no `minvmd` is running it shall spawn
  `minvmd run --detach` and wait (with timeout) for the UDS. On targets
  with no minvmd backend this path shall be a no-op. (translated from
  plan: step R4.5; Linux enabled once minvmd gained a KVM backend.)
- **R4.6**: State transitions shall be guarded by an `fd-lock`-style
  file lock on `lifecycle.lock` so concurrent CLI invocations cannot
  race. Recovery from a panicking transition shall be handled by an RAII
  guard that resets to `Stopped` on drop without explicit commit.
  (translated from plan: step R4.6)
- **R4.7**: All lifecycle transitions shall pass through a pure
  `next_state(current: Lifecycle, action: Action) -> Result` function
  with no I/O, exhaustively unit-tested.
  (translated from plan: step R4.7)

**Proof Artifacts:**

1. **Test:** `crates/minvmd/src/lifecycle.rs` includes table-driven
   `#[test]`s for every legal and illegal transition;
   `cargo test -p minvmd lifecycle::` passes — demonstrates the pure
   state machine.
2. **CLI:** `minvmd stop && minvmd status --json` prints
   `{"state":"stopped",...}` and exits 1 — demonstrates stop + status
   semantics.
3. **CLI:** From a clean state (no minvmd running), `minimal ls` on a
   Mac succeeds within 8 s and a subsequent `minvmd status` reports
   `running`; a second `minimal ls` completes in < 500 ms — demonstrates
   auto-spawn + warm reuse.

## Non-Goals

- **Networking** — gated on #160. v0.1 VMs have no net device.
- **Multi-VM / multi-tenant** — single named VM (`default`); multi-VM
  is a v0.2+ concern.
- **`minvmd init` / OCI image fetch / cosign verification** — kernel and
  rootfs paths are passed in via env.
- **Virtiofs / live host mounts** — per reference-impl lessons (TCC +
  provenance xattr issues), v0.1 has zero live mounts.
- **`brew services` registration** — auto-spawn from the CLI suffices
  for v0.1.
- **PTY supervision / session sandboxing** — those live in `minimald`.
- **OS suspend/resume of the VM, RAM resizing, vcpu hot-add.**
- **Lifting code from reference impl** — patterns only, no vendoring.

## Design Considerations

### Process model

`krun_start_enter` never returns on success — it `exit()`s with the
guest workload's exit code. This forces a parent/child split:

```text
minvmd run                       (parent — supervisor)
  └── minvmd __krun-vmm          (hidden child — calls krun_start_enter)
       └── libkrun + Alpine VM   (the actual VM)
            └── /init.krun (pid-1, libkrun-supplied)
                 └── minimald   (guest workload, via krun_set_exec)
```

Parent owns: `state.toml`, `lifecycle.lock`, and lifecycle supervision.
The host UDS is **not** a parent-owned accept loop — libkrun binds and
forwards it (registered via `krun_add_vsock_port2` before the child
enters), so neither parent nor child runs a userspace byte relay. Child
owns: libkrun context, kernel/rootfs paths. They communicate via a
single-use auth token plus signals.

### Socket model

`minimald` speaks SSH (russh) over a raw `UnixListener` stream and works
over any bidirectional byte stream. libkrun's `krun_add_vsock_port2`
delivers exactly that, so `minvmd` stays a thin lifecycle/transport
daemon rather than a userspace byte relay. The provider-owns-socket and
connect-and-prune discovery rules from `docs/session-domain-diag.md`
hold under this model.

### Hard lessons baked in

- **No `$HOME` virtiofs** — TCC + provenance xattr issues on macOS.
- **TSI ~62 concurrent connection cap** — fine for v0.1 (< 10
  concurrent), documented near the vsock registration.
- **Error fidelity** — never collapse `Backend { op, source }` into a
  `String`; the errno survives via `io::Error::from_raw_os_error`.
- **Stubs are sticky** — every stub shall `panic!`/`bail!`/`unimplemented!`
  explicitly; no silent no-ops.

## Repository Standards

- Workspace conventions from `CLAUDE.md`: workspace-pinned deps;
  `cargo fmt && cargo test -- --include-ignored`;
  `cargo clippy --allow-dirty --fix --all-targets -- -D warnings`;
  no `println!`/`eprintln!` outside the CLI surface (use `tracing`);
  structured fields not interpolated strings; typed error enums in
  library code, `anyhow::Result` only at CLI boundaries.
- Commit messages follow Conventional Commits (`docs/commit-conventions.md`):
  imperative mood, lower-case description, no trailing period. Type is
  the dominant change (`feat`, `fix`, `docs`, etc.); scope is the
  affected crate name in parentheses (e.g. `feat(minvmd): ...`). One
  logical change per commit.
- Rust coding standards from `docs/rust-coding-standards.md`: functional
  over imperative (iterator chains, combinators on Option/Result);
  cheapest reference that works (`&str` over `&String`, `&Path` over
  `&PathBuf`); make illegal states unrepresentable; newtypes for domain
  values; `#[must_use]` on Result-shaped returns; `#[non_exhaustive]` on
  public enums/structs that may grow; private by default, widen to
  `pub(crate)` before `pub`.
- Naming: `minvmd` (matches `minimald`).
- Platform gates: `#[cfg(target_os = "macos")]` for all libkrun-touching
  code; a stub Linux entry that `bail!`s.
- Tests: integration tests under `tests/`; libkrun-touching tests
  `#[ignore]` and gated on `MINVMD_E2E=1`; pure state-machine + parser
  tests run unconditionally.
- Unsafe: every `unsafe` block carries a `// SAFETY:` comment.
- Dependencies: `nix`, `tokio`, `anyhow`, `serde`, `toml`, `tracing`
  (already in workspace); `fd-lock` (new, workspace-pin). Link libkrun
  directly via `build.rs`.

## Open Questions

1. **Alpine rootfs source.** v0.1 uses `scripts/fetch-alpine.sh`
   (download + sha256-verify). Migration to a sibling `alpine-minirootfs`
   minimal package is a follow-up once `virtio-linux` merges.
2. **Vsock port for `minimald`.** Proposed 2222 (avoids reference impl's
   agent port 7350). Confirm with #156 owner. (`VSOCK_PORT` is a named
   constant either way.)
3. **Guest-side vsock terminator.** RESOLVED → vsock-native `minimald`:
   generalize the russh listener edge over `impl AsyncRead + AsyncWrite`
   and add a `run_on_vsock`. v0.1 ships the vsock stub (R3.4); the
   swap-in is a follow-up in `minimald`.
4. **In-VM `minimald` supervision.** Proposed: run as pid-1 via
   `krun_set_exec` for v0.1; revisit if zombie reaping becomes painful.
5. **Brew distribution.** Out of scope per non-goals; the codesign step
   must be reproducible on contributors' machines (`justfile` target).

## Technical Considerations

- **libkrun linking** — pinned to a known-good version (v1.18.0).
  `build.rs` emits `cargo:rustc-link-search` and
  `cargo:rustc-link-arg=-Wl,-rpath` pointing at `/opt/homebrew/lib`
  with a `LIBKRUN_PREFIX` env override.
- **Hidden `__krun-vmm` subcommand** — not in `--help`;
  verified-via-auth-token; the only entry point that calls
  `krun_start_enter`.
- **State file format** — TOML with serde; one file per VM (in v0.1,
  only `default`). Lifecycle enum is
  `NotProvisioned | Stopped | Starting | Running | Stopping`.
- **Auto-spawn from `minimal`** — implementation lives in
  `crates/minimal/src/autospawn.rs`, gated
  `#[cfg(any(target_os = "macos", target_os = "linux"))]` and invoked from
  `main.rs`. Enabled on both macOS and Linux.

## Security Considerations

- Single entitlement: `com.apple.security.hypervisor`. No network, no
  file-access-outside-home.
- Host UDS perms: mode 0600, owner-only.
- No authentication on the bridge — access is mode-gated. Do not expose
  the bridge over TCP without rethinking auth.
- Single-use auth token between parent `minvmd run` and child
  `minvmd __krun-vmm`: written to state dir mode 0600, verified by
  child, deleted on first read.
- v0.1 trusts caller-supplied kernel and rootfs paths without integrity
  verification; provenance and integrity checking are deferred to a
  future version.

## Verification

| Check | Command |
|---|---|
| Lint  | `cargo clippy --allow-dirty --fix --all-targets -- -D warnings` |
| Build | `cargo build -p minvmd` (full on macOS and Linux) |
| Test  | `cargo test -p minvmd` (unit + pure); `MINVMD_E2E=1 cargo test -p minvmd -- --include-ignored` (full) |

**CI gate:** the Linux/KVM lane (`ci-linux-kvm.yml`) builds and boots
`minvmd` on x86_64; macOS coverage runs on the Apple Silicon lane
(`ci-macos.yml`).
