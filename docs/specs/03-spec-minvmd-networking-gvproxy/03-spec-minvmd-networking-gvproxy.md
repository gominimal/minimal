---
id: spec-minvmd-networking-gvproxy
title: "minvmd networking — gvproxy userspace net for VM sessions"
kind: spec
status: planned
tracking-issue: 404
supersedes:
---

# minvmd networking — gvproxy userspace net for VM sessions

## Context

`minvmd` boots a Linux microVM and bridges a host UDS to the in-VM
`minimald` over vsock. The VM currently has **no outbound network
connectivity**: libkrun's TSI (Transport Socket Interface) is the only
transport in the `VmConfig.apply()` path, and `vm.rs` carries the comment
"gvproxy/TSI integration is tracked in #160" with a placeholder noting the
~62-concurrent-connection cap at R3.5.

TSI is a kernel-side socket-emulation shim (`tsi_hijack`) that multiplexes
guest AF_INET sockets over a single host-side transport. The practical ceiling
is ~62 concurrent `connect()`s before new ones fail with `ENODATA`
(errno 61). The cache-fetch parallelism target is 200 concurrent outbound
connections; TSI is structurally incompatible with that target (informed by
#204).

`containers/gvisor-tap-vsock` (`gvproxy`) is a userspace network stack that
implements the passt protocol over a Unix socket. libkrun v1.18+ exposes
`krun_set_passt_fd(ctx_id, fd)` to attach an external passt-compatible process
to the guest's virtio-net device. With gvproxy, the guest gets a full
virtio-net NIC backed by gvproxy's NAT gateway; the ~62-connection cap is
eliminated.

This spec adds gvproxy as the default outbound network transport for
`minvmd`-managed VMs, with TSI remaining selectable as a fallback. It applies
to both the macOS (Hypervisor.framework) and Linux (KVM) VM paths, since
`krun_set_passt_fd` is platform-agnostic. It also wires the network allowlist
enforcement hook — the call site and stub function that will carry the
taskspec `network` declaration into policy enforcement in a follow-up.

DNS and port-forwarding are flagged as explicit sub-items and are deferred
(see Non-Goals).

## Introduction/Overview

`minvmd` will spawn one `gvproxy` child process per VM, connected to the VM's
virtio-net device via `krun_set_passt_fd`. The gvproxy child is owned by the
VM supervisor (`cmd/run.rs`) and is reaped when the VM stops or crashes, with
no orphan processes after `minimal stop` or an abnormal exit.

The mechanism:

1. The supervisor (`run_foreground`) creates a Unix socketpair before spawning
   any child.
2. One end of the socketpair is passed to `gvproxy` (via `--fd <n>`); gvproxy
   reads/writes VM network frames on this FD.
3. The other end's FD number is exported to the VMM child via `MINVMD_NET_FD`;
   the VMM child calls `krun_set_passt_fd(ctx, fd)` before `krun_start_enter`.
4. libkrun creates a virtio-net device wired to the FD; the guest kernel sees a
   regular `eth0` interface with gvproxy acting as NAT gateway.

TSI remains available as a fallback: when `MINVMD_NETMODE=tsi` is set (or
when gvproxy is not found on `PATH`), no `krun_set_passt_fd` call is made and
libkrun falls back to its built-in TSI shim.

The network allowlist enforcement hook is a call site in the boot path wired
to a `check_network_policy(policy: &NetworkPolicy)` function. The function
body is a no-op (policy default: open / allow all) for this spec. The
taskspec `network` field (specced in the capability envelope issue) will be
wired to this call site in a follow-up.

## Goals

1. VM sessions get outbound connectivity via gvproxy by default; TSI
   selectable via `MINVMD_NETMODE=tsi` or automatic fallback when gvproxy is
   absent.
2. 200 concurrent outbound connects from within the VM succeed without
   EMFILE / ENODATA errors.
3. `minvmd run` spawns a gvproxy child per VM, wired to the virtio-net device
   via `krun_set_passt_fd`; the child is reaped on VM stop or crash — no
   orphans after `minimal stop` or an abnormal supervisor exit.
4. The network allowlist enforcement hook is wired: `check_network_policy` is
   called in the boot path before the VM starts, with the current `NetworkPolicy`
   value; the function returns `Ok(())` (open policy) for this spec.
5. Both macOS (Hypervisor.framework) and Linux (KVM) VM paths benefit without
   platform-specific divergence in the gvproxy integration code.

## User Stories

- As a developer using `minimal run` inside a macOS-hosted VM, I want
  `cargo fetch` / `pip install` / cache-fetch to work concurrently at scale so
  that fresh builds complete without ENODATA failures.
- As a developer using `minimal run` inside a Linux KVM-hosted VM, I want the
  same outbound network parity as the macOS path so that identical workloads
  behave consistently.
- As an operator, I want `minimal stop` to leave no orphan `gvproxy` processes
  so that the host is clean after each session.
- As an operator, I want `MINVMD_NETMODE=tsi` to opt back into TSI for
  debugging or environments where gvproxy is unavailable.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1;
> R2.1 for Unit 2). These IDs are referenced directly by the planner — do
> not renumber after approval.

---

### Unit 1: gvproxy child spawn, lifecycle, and reap

**Purpose:** `minvmd`'s supervisor creates a Unix socketpair, spawns a gvproxy
child with one end, exports the other end's FD to the VMM child, and reaps
gvproxy on every exit path (clean stop, crash, boot failure). A new
`crates/minvmd/src/net.rs` module owns the `NetworkMode` type and the gvproxy
process management helpers.

**Depends on:** None

**Affected areas:**
- `crates/minvmd/src/net.rs` (new)
- `crates/minvmd/src/cmd/run.rs`
- `crates/minvmd/src/state.rs`

**Baseline:** No networking module or gvproxy-related code exists in
`crates/minvmd/src/`. The `run_foreground` function in `cmd/run.rs` spawns
only the VMM child. `State` carries `vmm_pid: Option<u32>` but no gvproxy pid.
All Unit 1 requirements are **new work**.

**Functional Requirements:**

- **R1.1**: `crates/minvmd/src/net.rs` shall define:
  - `enum NetworkMode { GvProxy, Tsi }` — the two supported transport modes.
  - `fn resolve_net_mode() -> NetworkMode` — reads `MINVMD_NETMODE` env var;
    returns `NetworkMode::GvProxy` when the var is unset or set to `"gvproxy"`,
    `NetworkMode::Tsi` when set to `"tsi"`. Any other value logs a warning and
    falls back to `NetworkMode::GvProxy`.
  - `fn gvproxy_bin() -> std::path::PathBuf` — resolves the gvproxy binary:
    `MINVMD_GVPROXY_PATH` env var if set, otherwise `"gvproxy"` (resolved via
    `PATH` by the OS when spawned).

- **R1.2**: `net.rs` shall define `fn spawn_gvproxy(net_fd: RawFd) -> Result<Child>` that:
  - Spawns the binary from `gvproxy_bin()` with the argument `--fd <net_fd>`.
  - Sets `stdin`, `stdout`, and `stderr` to `Stdio::null()` on the gvproxy
    child (gvproxy logs over the FD, not stdio).
  - The `net_fd` end of the socketpair must **not** have `FD_CLOEXEC` set before
    this call so it survives the spawn (the caller is responsible for clearing it).
  - Returns the `std::process::Child` handle; the caller owns reaping.
  - Returns an `Err` with a clear message when the binary is not found.

- **R1.3**: `cmd/run.rs`'s `run_foreground` function (macOS + Linux, replacing
  the macOS-only bail) shall:
  - Call `resolve_net_mode()`.
  - When `GvProxy`: create a Unix socketpair (`socketpair(AF_UNIX, SOCK_STREAM, 0)`
    via `libc::socketpair`); clear `FD_CLOEXEC` on the gvproxy-side FD; spawn
    gvproxy via `spawn_gvproxy(gvproxy_fd)` before spawning the VMM child;
    export the VMM-side FD number as `MINVMD_NET_FD=<n>` in the VMM child's
    environment; close the gvproxy-side FD in the parent after gvproxy has
    started (the child owns it).
  - When `Tsi`: skip the above; `MINVMD_NET_FD` is not set.
  - In all exit paths (boot failure, VMM child exit, signal), call
    `gvproxy_child.kill()` and `gvproxy_child.wait()` before returning so no
    orphan remains. The `StartingGuard` drop path must also kill gvproxy.

- **R1.4**: `State` in `state.rs` shall gain an optional field
  `gvproxy_pid: Option<u32>` alongside the existing `vmm_pid`. The field is
  `None` when `NetworkMode::Tsi` is active or when gvproxy has not yet started.
  It is serialized to / deserialized from the state file (JSON) so that a
  supervisor crash leaves the PID readable for external cleanup tooling; it is
  not used by `minvmd stop` for signal delivery (the stop path already signals
  `vmm_pid`, which causes the VMM child to exit, which causes the supervisor to
  reap gvproxy).

- **R1.5**: `minvmd stop` and `minvmd status` shall continue to work
  correctly when gvproxy is in use. `status.rs` may optionally report the
  gvproxy PID in its output; it must not fail when `gvproxy_pid` is `None`.

**Proof Artifacts:**

1. **Test:** `cargo test -p minvmd net::` passes — unit tests in `net.rs`
   verify `resolve_net_mode` returns `GvProxy` by default and `Tsi` when
   `MINVMD_NETMODE=tsi` is set; tests use `serial_test` to isolate env-var
   mutations. Demonstrates the mode-selection logic is correct before any
   process is spawned.
2. **CLI:** `MINVMD_NETMODE=tsi MINVMD_E2E=1 cargo test -p minvmd --test
   minimald_session_e2e -- --include-ignored` passes — the existing session
   e2e continues to work with TSI mode selected, proving the fallback path is
   not broken by Unit 1's changes.

---

### Unit 2: libkrun passt/virtio-net FFI and VmConfig integration

**Purpose:** Add `krun_set_passt_fd` to the FFI surface and wire it into
`VmConfig.apply()` so the guest gets a virtio-net NIC backed by gvproxy when
`GvProxy` mode is active. The VMM child reads `MINVMD_NET_FD` and calls the
new wrapper before `krun_start_enter`.

**Depends on:** Unit 1

**Affected areas:**
- `crates/minvmd/src/krun/raw.rs`
- `crates/minvmd/src/krun/ctx.rs`
- `crates/minvmd/src/vm.rs`
- `crates/minvmd/src/cmd/vmm_child.rs`

**Baseline:**
- `raw.rs` lists libkrun v1.18+ declarations; `krun_set_passt_fd` is not yet
  declared.
- `ctx.rs` has no networking methods beyond `add_vsock_port` and `add_vsock_port2`
  (used for the minimald control socket bridge).
- `VmConfig` has no `net_mode` field; `VmConfig.apply()` carries the comment
  "R2.5: no network device in v0.1."
- `vmm_child.rs` does not read `MINVMD_NET_FD`.
All Unit 2 requirements are **new work**.

**Functional Requirements:**

- **R2.1**: `raw.rs` shall add the FFI declaration:
  ```rust
  pub fn krun_set_passt_fd(ctx_id: u32, fd: i32) -> i32;
  ```
  The declaration shall carry a `// SAFETY:` comment documenting that `fd`
  must be a valid open file descriptor for the duration of the call, that
  libkrun takes ownership of the networking FD (the caller must not close it
  after this call), and that `ctx_id` must refer to a live context.

- **R2.2**: `ctx.rs` shall add a safe wrapper:
  ```rust
  pub fn set_passt_fd(&mut self, fd: std::os::unix::io::RawFd) -> Result<(), VmError>
  ```
  that validates `fd >= 0` before the FFI call (returning `VmError::Io` wrapping
  `EBADF` on negative values) and translates the return code via
  `raw::check_backend`.

- **R2.3**: `VmConfig` shall gain a new field `net_mode: NetworkMode` (imported
  from `crate::net`). `VmConfig::new` shall gain a corresponding parameter. The
  existing `VmConfig.apply()` on macOS shall remove the "R2.5: no network device"
  comment and add a branch:
  - When `net_mode == NetworkMode::GvProxy`: call `ctx.set_passt_fd(fd)` where
    `fd` is passed as a new parameter to `apply` (i.e., `apply` grows signature
    to `fn apply(&self, ctx: &mut Context, net_fd: Option<RawFd>)`). A
    `net_fd` of `None` is treated as TSI. A `Some(fd)` calls `set_passt_fd`.
  - When `net_mode == NetworkMode::Tsi`: no `set_passt_fd` call; libkrun's
    built-in TSI shim handles guest networking as before.
  - The `cfg(target_os = "macos")` gate on `apply` shall be removed (R2.4).

- **R2.4**: `VmConfig.apply()` shall be un-gated from macOS. On Linux, the
  method body is identical to macOS: the same `krun_set_passt_fd` call works
  on both backends. (libkrun's `krun_set_passt_fd` is platform-agnostic per
  its C API documentation.)

- **R2.5**: `cmd/vmm_child.rs`'s `run()` function shall:
  - Read `MINVMD_NET_FD` env var; if present and parseable as a `RawFd`,
    pass `Some(fd)` to `VmConfig.apply()`; if absent or unparseable, pass
    `None` (TSI fallback).
  - Remove the `#[cfg(not(target_os = "macos"))]` bail so the VMM child
    compiles and runs on Linux as well (aligned with the Linux KVM spec #397).
  - Log at `tracing::info!` whether gvproxy or TSI mode is active.

**Proof Artifacts:**

1. **Test:** `cargo test -p minvmd vm::` and `cargo test -p minvmd krun::`
   pass — unit tests in `vm.rs` verify `VmConfig` stores the `net_mode` field
   correctly for both enum variants; `ctx.rs` tests verify `set_passt_fd`
   rejects negative FDs with a typed error. Demonstrates the new FFI wrapper
   surface is sound before any real VM is booted.
2. **CLI:** `MINVMD_E2E=1 cargo test -p minvmd --test minimald_session_e2e
   -- --include-ignored` passes on macOS with gvproxy on PATH — demonstrates
   the end-to-end VM boot + UDS↔vsock bridge still works with gvproxy wired.

---

### Unit 3: Network allowlist enforcement hook

**Purpose:** Wire the call site for network policy enforcement into the VM
boot path. The hook is called with the current `NetworkPolicy` before the VM
starts; its body is a no-op (policy default: open). This establishes the
interface that a future spec will flesh out once the taskspec `network`
declaration surface (capability envelope issue) is available.

**Depends on:** Unit 1

**Affected areas:**
- `crates/minvmd/src/net.rs` (extend)
- `crates/minvmd/src/cmd/run.rs`

**Baseline:** No `NetworkPolicy` type or `check_network_policy` function exists
in the codebase. No call site for network policy enforcement exists.
All Unit 3 requirements are **new work**.

**Functional Requirements:**

- **R3.1**: `net.rs` shall define:
  ```rust
  /// The network access policy for a VM session.
  ///
  /// `Open` permits all outbound connections. `Allowlist` is reserved for
  /// future enforcement once the taskspec `network` declaration is wired in.
  #[derive(Debug, Clone)]
  pub enum NetworkPolicy {
      Open,
      Allowlist(Vec<String>),  // hostnames or CIDR strings; unused in v1
  }

  /// Check whether the given network policy permits the session to start.
  ///
  /// Currently always returns `Ok(())` (policy default: open). A future
  /// spec will implement allowlist enforcement once the taskspec `network`
  /// declaration is available.
  pub fn check_network_policy(policy: &NetworkPolicy) -> Result<(), PolicyError> {
      match policy {
          NetworkPolicy::Open => Ok(()),
          NetworkPolicy::Allowlist(_) => Ok(()),   // no-op in v1
      }
  }
  ```
  `PolicyError` shall be a new typed error variant in `crate::error` (or a
  dedicated `net::PolicyError` newtype) carrying a human-readable refusal
  message. It is unused in v1 but must be defined so future callers can match
  on it.

- **R3.2**: `cmd/run.rs`'s `run_foreground` shall call
  `check_network_policy(&NetworkPolicy::Open)` before spawning gvproxy (or
  before setting up TSI when in TSI mode). The call is early-exit: an `Err`
  from the hook aborts the boot and surfaces via `anyhow::Error`. The current
  always-Ok implementation makes this a no-op in practice.

- **R3.3**: The `check_network_policy` call site shall carry a doc comment:
  ```rust
  // Wire the taskspec `network` declaration here once the capability envelope
  // (see capability-envelope tracking issue) is available. Replace
  // `NetworkPolicy::Open` with the resolved policy from the task's network
  // declaration.
  ```
  This comment is the breadcrumb for the follow-up spec.

**Proof Artifacts:**

1. **Test:** `cargo test -p minvmd net::check_network_policy` passes — a unit
   test verifies `check_network_policy(&NetworkPolicy::Open)` returns `Ok(())`
   and `check_network_policy(&NetworkPolicy::Allowlist(vec![...]))` also
   returns `Ok(())`. Demonstrates the hook is wired and its no-op behavior is
   tested before enforcement is added.

---

## Non-Goals

- **Actual network filtering / allowlist enforcement.** The hook body is a
  no-op; real enforcement is a follow-up dependent on the capability envelope
  issue.
- **Linux namespace sandbox path sharing gvproxy code.** Whether the
  `sandbox2`-backed namespace path shares the same gvproxy integration is an
  open question (see below); out of scope here.
- **DNS configuration.** The guest relies on gvproxy's built-in DNS resolver
  (resolves from the host's system resolver). Configurable per-VM DNS is a
  future sub-item.
- **Port-forwarding (guest→host or host→guest).** Explicit port-forwarding
  rules via gvproxy are a future sub-item.
- **gvproxy binary packaging.** This spec does not specify how gvproxy is
  installed (Homebrew formula, Fedora package, static binary, etc.). It is
  expected to be on `PATH` or pointed to via `MINVMD_GVPROXY_PATH`. Packaging
  is deferred.
- **Connection-count limit / semaphore on the orchestrator side.** The
  proposed fix in #204 (a `tokio::sync::Semaphore` in `orchestrator/src/lib.rs`)
  is a separate, complementary change and is not in scope here.

## Design Considerations

### gvproxy FD handoff via socketpair

The socketpair approach avoids a race condition inherent in listening on a
named socket path: the supervisor would need to know the path before gvproxy
starts listening, or poll. A socketpair is created atomically by the parent;
both ends are immediately valid. The FD number is stable across the
`fork`+`exec` boundary as long as `FD_CLOEXEC` is cleared on the gvproxy-side
FD before the spawn.

The VMM child is a separate `exec`'d process. `std::process::Command` on Unix
inherits all FDs that do not have `FD_CLOEXEC`. The parent clears
`FD_CLOEXEC` on the VMM-side FD before spawning the VMM child, and sets it
on the gvproxy-side FD (already consumed by gvproxy) to prevent leaking it
into the VMM child.

### TSI coexistence

TSI is libkrun's default when `krun_set_passt_fd` is not called. The fallback
path (`MINVMD_NETMODE=tsi` or gvproxy absent) simply omits the
`krun_set_passt_fd` call. No TSI-specific code needs to be added; the existing
behavior is preserved. The `add_vsock_port2` call for the minimald control
socket bridge is **not** a TSI feature — it is libkrun's vsock-to-UDS bridge,
orthogonal to the outbound networking mode, and remains unchanged in all modes.

### Platform parity (macOS + Linux)

`krun_set_passt_fd` is declared in libkrun's C API with no
platform-specific guards. The Hypervisor.framework (macOS) and KVM (Linux)
backends in libkrun both support the passt virtio-net mode. `VmConfig.apply()`
can therefore be un-gated from macOS (R2.4), and the same gvproxy integration
code runs on both platforms.

### gvproxy orphan prevention

gvproxy is a child of the supervisor (`run_foreground`), not of the VMM child.
The VMM child holds the VMM-side FD; when the VMM child exits (whether cleanly,
via signal, or via crash), the FD is closed by the OS, and gvproxy's reads on
the gvproxy-side FD return EOF. gvproxy exits on EOF. The supervisor also
explicitly kills and waits for gvproxy before returning, covering the case
where gvproxy does not self-exit promptly.

## Repository Standards

- All new `unsafe` blocks in `raw.rs` shall carry `// SAFETY:` comments
  per the repository's FFI discipline (established in spec-minvmd-host-daemon).
- Safe wrappers in `ctx.rs` validate inputs in safe Rust before crossing the
  FFI boundary, per the same standard.
- The `net.rs` module shall have `#[cfg(test)]` unit tests covering at minimum
  `resolve_net_mode` and `check_network_policy` with `serial_test` isolation
  for env-var mutations.
- Commit messages follow Conventional Commits; the implementing PR uses
  `feat(minvmd-net):` as the scope prefix.

## Open Questions

1. **Deny-vs-allow default for the network allowlist.** When enforcement is
   added, should the default be "open unless declared" (allowlist opt-in) or
   "deny unless declared" (allowlist required)? The answer affects the
   `NetworkPolicy::Open` semantics. This is an ADR-worthy decision that blocks
   enforcement implementation. For this spec, `Open` = allow all, which is the
   safe do-nothing default.

2. **Warn-vs-silent for declared-but-unenforced capabilities.** If a task
   declares a `network` allowlist but enforcement is not yet active, should
   `minvmd` warn at boot time? The `check_network_policy` call site (R3.2)
   could log a warning when `NetworkPolicy::Allowlist` is passed but the body
   is a no-op. Deferred; the R3.3 comment is the breadcrumb.

3. **Per-task vs per-VM enforcement granularity.** When multiple tasks share a
   VM (a future capability), a per-VM network policy is coarse. Per-task
   enforcement would require inside-VM filtering (e.g., an eBPF policy in the
   initramfs). This is an ADR-worthy decision; for this spec, enforcement
   granularity is VM-level and irrelevant (the hook is a no-op).

4. **Linux namespace sandbox path.** Does `sandbox2` (the namespace-based
   isolation path for Linux hosts without `/dev/kvm`) share the gvproxy
   integration code, or does it use a separate mechanism? Deferred to a
   follow-up. This spec touches only the libkrun VMM path.

5. **libkrun version verification.** `krun_set_passt_fd` appeared in libkrun
   v1.18. The implementing PR should verify the function is present in the
   version shipped by the Homebrew tap (`slp/krun`) and the Fedora/RHEL
   package used in CI before declaring the FFI binding.

## Technical Considerations

- **FD lifetime across fork+exec.** Care is required to clear `FD_CLOEXEC` on
  the correct FD before each spawn: gvproxy-side FD before gvproxy spawn
  (then set `FD_CLOEXEC` after), VMM-side FD before VMM child spawn (then
  close in parent after spawn). Incorrect FD flag management would silently
  hand the wrong FD to one process.

- **socketpair AF_UNIX + SOCK_STREAM.** gvproxy expects a stream socket; a
  `SOCK_DGRAM` socketpair would cause protocol errors. The `libc::socketpair`
  call should use `libc::AF_UNIX | libc::SOCK_STREAM | libc::SOCK_CLOEXEC`
  (then clear `FD_CLOEXEC` on the appropriate end before the relevant spawn).

- **gvproxy boot race.** gvproxy must be ready to accept frames before the VM
  boots (libkrun starts sending frames immediately after `krun_set_passt_fd`).
  gvproxy's `--fd` mode is ready immediately on startup (no listen-accept
  round trip); the socketpair handoff avoids the race.

- **TSI 62-connection cap root cause.** TSI multiplexes all guest TCP/IP
  connections over a single host socket via a state-tracking shim; the ~62
  limit is an internal state-table bound in libkrun's TSI implementation. It
  is NOT a per-process FD limit or a kernel `fs.file-nr` constraint (as #204
  diagnoses). gvproxy bypasses TSI entirely by replacing it with a real
  virtio-net device.

## Security Considerations

- The gvproxy child inherits the host user's network access. Any outbound
  connection the host can make, the VM guest can make via gvproxy. The
  `check_network_policy` hook is the future point of enforcement.
- The socketpair FDs should be `SOCK_CLOEXEC` by default and selectively
  cleared only for the intended child. This prevents unintended FD leaks to
  other child processes spawned later.
- gvproxy runs as the same user as `minvmd`. No privilege escalation is
  introduced.

## Verification

- `cargo test -p minvmd` (excluding e2e tests) passes on macOS and Linux after
  landing, with no regressions in existing tests.
- `MINVMD_E2E=1 cargo test -p minvmd --test minimald_session_e2e -- --include-ignored`
  passes on macOS with gvproxy on PATH.
- `MINVMD_NETMODE=tsi MINVMD_E2E=1 cargo test -p minvmd --test
  minimald_session_e2e -- --include-ignored` passes (TSI fallback unchanged).
- 200 concurrent outbound connects from within the VM succeed: verified by
  the concurrent-connect proof test in Unit 2's e2e (R2 proof artifact 2).
