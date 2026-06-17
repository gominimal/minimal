---
id: arch-minvmd-networking-gvproxy
title: minvmd networking — gvproxy userspace net for VM sessions — architecture
kind: architecture
status: planned
tracking-issue: 404
---

# minvmd networking — gvproxy userspace net for VM sessions — architecture

## Chosen approach

`minvmd` will spawn one `gvproxy` child process per VM, connected to the VM's virtio-net device via libkrun's `krun_set_passt_fd` API. The gvproxy child is owned by the VM supervisor (`run_foreground`) and is reaped when the VM stops or crashes, ensuring no orphan processes after `minimal stop` or an abnormal exit.

The mechanism uses a Unix socketpair to wire the gvproxy process to the guest's virtio-net device:

1. The supervisor (`run_foreground`) creates a Unix `socketpair(AF_UNIX, SOCK_STREAM, 0)` before spawning any child.
2. One end of the socketpair is passed to `gvproxy` via its `--fd <n>` argument; gvproxy reads/writes VM network frames on this FD.
3. The other end's FD number is exported to the VMM child via `MINVMD_NET_FD` environment variable.
4. The VMM child calls `krun_set_passt_fd(ctx, fd)` before `krun_start_enter`, which tells libkrun to create a virtio-net device wired to the FD.
5. The guest kernel sees a regular `eth0` interface with gvproxy acting as NAT gateway.

TSI (Transport Socket Interface) remains available as a fallback: when `MINVMD_NETMODE=tsi` is set or when gvproxy is not found on `PATH`, no `krun_set_passt_fd` call is made and libkrun falls back to its built-in TSI shim.

The network allowlist enforcement hook is a call site in the boot path wired to a `check_network_policy(policy: &NetworkPolicy)` function. The function body is a no-op (policy default: open / allow all) for this spec. The taskspec `network` field (specced in the capability envelope issue) will be wired to this call site in a follow-up.

## Data and interface changes

### New module: `crates/minvmd/src/net.rs`

A new networking module that owns:

- `enum NetworkMode { GvProxy, Tsi }` — the two supported transport modes
- `fn resolve_net_mode() -> NetworkMode` — reads `MINVMD_NETMODE` env var; returns `GvProxy` by default
- `fn gvproxy_bin() -> std::path::PathBuf` — resolves the gvproxy binary path via `MINVMD_GVPROXY_PATH` env var or defaults to `"gvproxy"` (resolved via `PATH`)
- `fn spawn_gvproxy(net_fd: RawFd) -> Result<Child>` — spawns gvproxy with `--fd <net_fd>` argument
- `enum NetworkPolicy { Open, Allowlist(Vec<String>) }` — network access policy for a VM session
- `fn check_network_policy(policy: &NetworkPolicy) -> Result<(), PolicyError>` — enforcement hook (currently always returns `Ok(())`)

### Changes to `crates/minvmd/src/cmd/run.rs`

`run_foreground` will be extended to:

- Call `resolve_net_mode()` to determine whether to use gvproxy or TSI
- When `GvProxy` mode:
  - Create a Unix socketpair before spawning the VMM child
  - Clear `FD_CLOEXEC` on the gvproxy-side FD to ensure it survives the spawn
  - Spawn gvproxy via `spawn_gvproxy(gvproxy_fd)` before spawning the VMM child
  - Export the VMM-side FD number as `MINVMD_NET_FD=<n>` in the VMM child's environment
  - Close the gvproxy-side FD in the parent after gvproxy has started
- Call `check_network_policy(&NetworkPolicy::Open)` before spawning gvproxy (early-exit on error)
- In all exit paths (boot failure, VMM child exit, signal), call `gvproxy_child.kill()` and `gvproxy_child.wait()` to ensure no orphans
- The `StartingGuard` drop path must also kill gvproxy

### Changes to `crates/minvmd/src/state.rs`

`State` struct will gain an optional field `gvproxy_pid: Option<u32>` alongside the existing `vmm_pid`. The field is:
- `None` when `NetworkMode::Tsi` is active or when gvproxy has not yet started
- Serialized to / deserialized from the state file (JSON) so that a supervisor crash leaves the PID readable for external cleanup tooling
- Not used by `minvmd stop` for signal delivery (the stop path already signals `vmm_pid`, which causes the VMM child to exit, which causes the supervisor to reap gvproxy)

### New FFI binding in `crates/minvmd/src/krun/raw.rs`

```rust
pub fn krun_set_passt_fd(ctx_id: u32, fd: i32) -> i32;
```

This declaration carries a `// SAFETY:` comment documenting that:
- `fd` must be a valid open file descriptor for the duration of the call
- libkrun takes ownership of the networking FD (the caller must not close it after this call)
- `ctx_id` must refer to a live context

### Safe wrapper in `crates/minvmd/src/krun/ctx.rs`

```rust
pub fn set_passt_fd(&mut self, fd: std::os::unix::io::RawFd) -> Result<(), VmError>
```

This validates `fd >= 0` before the FFI call (returning `VmError::Io` wrapping `EBADF` on negative values) and translates the return code via `raw::check_backend`.

### Changes to `crates/minvmd/src/vm.rs`

`VmConfig` will gain a new field `net_mode: NetworkMode` (imported from `crate::net`). `VmConfig::new` will gain a corresponding parameter.

The existing `VmConfig.apply()` will:
- Remove the "R2.5: no network device in v0.1" comment
- Grow its signature to `fn apply(&self, ctx: &mut Context, net_fd: Option<RawFd>)`
- Add a branch:
  - When `net_mode == NetworkMode::GvProxy` and `net_fd` is `Some(fd)`: call `ctx.set_passt_fd(fd)`
  - When `net_mode == NetworkMode::Tsi` or `net_fd` is `None`: no `set_passt_fd` call; libkrun's built-in TSI shim handles guest networking as before
- Remove the `#[cfg(target_os = "macos")]` gate on `apply()` — the method becomes platform-agnostic since `krun_set_passt_fd` works on both macOS (Hypervisor.framework) and Linux (KVM)

### Changes to `crates/minvmd/src/cmd/vmm_child.rs`

The `run()` function will:
- Read `MINVMD_NET_FD` env var; if present and parseable as a `RawFd`, pass `Some(fd)` to `VmConfig.apply()`; if absent or unparseable, pass `None` (TSI fallback)
- Remove the `#[cfg(not(target_os = "macos"))]` bail so the VMM child compiles and runs on Linux as well (aligned with the Linux KVM spec minimal#397)
- Log at `tracing::info!` whether gvproxy or TSI mode is active

## Alternatives considered

### Alternative A: gvproxy as a sibling process of the supervisor

Instead of spawning gvproxy as a child of the supervisor, spawn it as a separate process tree (e.g., via a systemd service or a separate launcher).

**Rejected because:**
- The supervisor loses control over gvproxy lifecycle — if the supervisor crashes, gvproxy becomes an orphan
- Complicates the cleanup path: `minimal stop` would need to track gvproxy's PID separately and signal it, introducing a race condition
- Adds deployment complexity: users would need to manage two separate processes

The child-of-supervisor model ensures gvproxy is automatically reaped when the VM exits, matching the existing process model for the VMM child (informed by arch-minvmd-host-daemon).

### Alternative B: Use TSI exclusively, do not add gvproxy

Continue using libkrun's built-in TSI socket-emulation shim for all networking.

**Rejected because:**
- TSI has a practical ceiling of ~62 concurrent connections (documented in the existing codebase at `vm.rs` line 48: "R3.5: TSI ~62-concurrent-connection cap")
- The cache-fetch parallelism target is 200 concurrent outbound connections (informed by minimal#204)
- TSI multiplexes all guest TCP/IP connections over a single host transport via a state-tracking shim; the ~62 limit is an internal state-table bound in libkrun's TSI implementation
- gvproxy bypasses TSI entirely by replacing it with a real virtio-net device backed by a userspace network stack

TSI remains selectable as a fallback via `MINVMD_NETMODE=tsi` for debugging or environments where gvproxy is unavailable.

### Alternative C: In-kernel networking via tap devices

Use Linux tap devices or macOS vmnet.framework instead of gvproxy's userspace network stack.

**Rejected because:**
- tap devices require root privileges or specific capabilities (CAP_NET_ADMIN) — `minvmd` runs as the user
- macOS vmnet.framework requires entitlements that are incompatible with the existing code-signing model
- Cross-platform: tap is Linux-only; vmnet is macOS-only; gvproxy works on both
- gvproxy's passt protocol is already supported by libkrun via `krun_set_passt_fd` since v1.18

gvproxy is the minimal-privilege, cross-platform solution.

## Assumption ledger

| Assumption | Bucket | Evidence | Depends on |
|------------|--------|----------|------------|
| `krun_set_passt_fd` exists in libkrun v1.18+ | settled | Confirmed in libkrun C API documentation; function signature matches spec R2.1 | R2.1, R2.2 |
| gvproxy binary will be available on PATH or via `MINVMD_GVPROXY_PATH` | settled | Spec explicitly defers packaging; detection and fallback to TSI is in scope (R1.2) | R1.1, R1.2 |
| socketpair FD handoff survives fork+exec when `FD_CLOEXEC` is cleared | settled | Standard Unix FD inheritance behavior; documented in POSIX `fork()` / `exec()` semantics | R1.3 |
| libkrun's `krun_set_passt_fd` is platform-agnostic (macOS + Linux) | settled | Confirmed by spec R2.4 and arch-minvmd-linux-kvm: libkrun exports the same C API on macOS (Hypervisor.framework) and Linux (KVM) (informed by arch-minvmd-linux-kvm) | R2.4 |
| gvproxy exits on EOF when the socketpair FD is closed | settled | Standard gvproxy behavior documented in `containers/gvisor-tap-vsock` — gvproxy's main loop reads frames from the FD and exits on EOF | R1.3 orphan prevention |
| TSI remains functional when `krun_set_passt_fd` is not called | settled | Confirmed by existing codebase behavior: `VmConfig.apply()` does not call any networking FFI in v0.1, and TSI is libkrun's default (informed by crates/minvmd/src/vm.rs line 26: "R2.5: no network device in v0.1") | R1.3 |
| 200 concurrent outbound connects will succeed with gvproxy | settled | gvproxy implements a full virtio-net device with no connection-count limit; confirmed by `containers/gvisor-tap-vsock` design (informed by minimal#204: TSI cap is ~62, gvproxy has no such limit) | Spec Goal 2 |

All assumptions are settled. No spikes are required.

## Knowledge gaps

### Prior constraints

- **Networking was explicitly deferred in `arch-minvmd-host-daemon`:** "gvproxy/TSI integration (#160) is explicitly out of scope for v0.1. The TSI ~62-concurrent-connection cap is documented as a constraint near the vsock registration but does not affect the v0.1 architecture (< 10 concurrent connections expected)." (informed by arch-minvmd-host-daemon). This spec lifts that deferral by adding gvproxy support while keeping TSI as a fallback.

- **The process model (parent supervisor, child VMM) is established:** `run_foreground` already spawns the VMM child and supervises it until exit. gvproxy becomes a second child of the supervisor, reusing the same lifecycle pattern (informed by arch-minvmd-host-daemon).

- **The platform-agnostic design is established:** `arch-minvmd-linux-kvm` removed platform gates from `VmConfig.apply()` because libkrun exports the same C API on macOS and Linux. `krun_set_passt_fd` follows the same pattern (informed by arch-minvmd-linux-kvm).

### Referenced-but-missing artifacts

None. All referenced prior work is present in the knowledge store.

### Contradictions

None. This spec is consistent with the prior architecture decisions.

### Thin areas

- **Network allowlist enforcement:** The `check_network_policy` hook is wired but its body is a no-op. Real enforcement (deny-vs-allow default, warn-vs-silent for unenforced capabilities, per-task vs per-VM granularity) depends on the capability envelope issue and is explicitly deferred by the spec's Open Questions section. This is not a gap — it is a deliberate phasing decision.

- **DNS configuration and port-forwarding:** Explicit DNS configuration and port-forwarding rules via gvproxy are flagged as future sub-items in the spec's Non-Goals section. The guest relies on gvproxy's built-in DNS resolver (resolves from the host's system resolver) for this spec.

- **Linux namespace sandbox path:** Whether `sandbox2` (the namespace-based isolation path for Linux hosts without `/dev/kvm`) shares the gvproxy integration code is an open question flagged by the spec. Out of scope for this architecture; this spec touches only the libkrun VMM path.

## Verification

- `cargo test -p minvmd` passes on macOS and Linux after landing, with no regressions in existing tests.
- `MINVMD_E2E=1 cargo test -p minvmd --test minimald_session_e2e -- --include-ignored` passes on macOS with gvproxy on PATH.
- `MINVMD_NETMODE=tsi MINVMD_E2E=1 cargo test -p minvmd --test minimald_session_e2e -- --include-ignored` passes (TSI fallback unchanged).
- The architecture sub-issue is created as a child of tracking issue minimal#404.
- This architecture PR references minimal#404 but does not use a closing keyword (the tracking issue must stay open).
