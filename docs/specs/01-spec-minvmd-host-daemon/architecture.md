---
id: arch-minvmd-host-daemon
title: "minvmd macOS VM provider host daemon, architecture"
kind: architecture
status: shipped
---

# minvmd macOS VM provider host daemon - architecture

## Chosen approach

`minvmd` is a thin lifecycle-and-transport daemon that bridges macOS to
the Linux-native `minimald` via libkrun's Hypervisor.framework backend.
The architecture follows the plan's three-process model and the session
domain model in `docs/internal/session-domain-diag.md`
(translated from plan: Process model).

### Process model

`krun_start_enter` never returns on success, it calls `exit()` with the
guest workload's exit code. This forces a parent/child split
(translated from plan: Process model):

```text
minvmd run                       (parent — supervisor)
  └── minvmd __krun-vmm          (hidden child — calls krun_start_enter)
       └── libkrun + Alpine VM   (the actual VM)
            └── /init.krun (pid-1, libkrun-supplied)
                 └── minimald   (guest workload, via krun_set_exec)
```

- **Parent** (`minvmd run`): owns `state.toml`, `lifecycle.lock`, lifecycle
  supervision, and the `--detach` readiness gate. Does **not** own a byte
  relay, libkrun binds and forwards the host UDS itself.
- **Child** (`minvmd __krun-vmm`): hidden subcommand; configures the
  libkrun context (kernel, rootfs, vsock ports, vm config), then calls
  `krun_start_enter` which diverges. Authenticated to the parent via a
  single-use token in the state directory (mode 0600, deleted on first read).
- **Guest**: Alpine minirootfs. libkrun's built-in `/init.krun` is pid-1
  (mounts `/proc`, `/sys`, `/dev`); it execs the workload set via
  `krun_set_exec`, `minimald`, or the v0.1 vsock stub. No init system in the
  rootfs.

### Socket model (libkrun-owned, no host relay)

The spec evaluated two options and chose Option A
(translated from plan: Socket model):

`minimald` speaks SSH (russh) over a raw `UnixListener` stream and works
over any bidirectional byte stream. libkrun's `krun_add_vsock_port2`
delivers exactly that: `minvmd` registers the host UDS path with
`listen = true` (host-initiated direction) before boot, and libkrun
listens on the host UDS and bridges each accepted connection to a guest
process listening on vsock `VSOCK_PORT`. `minvmd` carries no
per-connection state and runs no userspace byte relay.

The provider-owns-socket and connect-and-prune discovery rules from
`docs/internal/session-domain-diag.md` hold under this model: the host UDS *is*
the provider socket. A stale socket after a crash fails connect-and-check
and is pruned by `minimal`.

### Lifecycle state machine

All state transitions pass through a pure `next_state(current, action) ->
Result` function with no I/O, exhaustively unit-tested
(translated from plan: R4.7). The lifecycle enum is:

```text
NotProvisioned → Starting → Running → Stopping → Stopped
                                                    ↑
                            (crash / guard drop) ───┘
```

State is persisted atomically (tmp + rename + fsync) to
`$XDG_STATE_HOME/minimal/minvmd/state.toml`. Concurrent access is guarded
by an `fd-lock`-style file lock on `lifecycle.lock`. An RAII
`StartingGuard` resets the state to `Stopped` on drop without explicit
commit, preventing stuck `Starting` states after crashes
(translated from plan: R4.6, reference pattern from `min-ctl`).

### Platform gating

All libkrun-touching code is behind `#[cfg(target_os = "macos")]`. On
Linux, the crate compiles to a runtime-bailing stub, the `krun` module
is excluded entirely, and the CLI entry point `bail!`s if invoked. This
keeps the existing Linux-only CI green (translated from plan: R1.1).

The existing codebase already implements this: `lib.rs` gates `pub mod
krun` on `target_os = "macos"`, and `build.rs` only emits link directives
on macOS.

### Auto-spawn from `minimal`

On macOS, `crates/minimal` checks `state.toml` before connecting to the
provider UDS. If no `minvmd` is running, it spawns
`minvmd run --detach` and waits (with timeout, default 8 s) for the UDS to
accept connections. On Linux this path is a no-op, `minimald` runs
natively (translated from plan: R4.5).

## Data and interface changes

### New modules in `crates/minvmd/src/`

| Module | Purpose |
|--------|---------|
| `image.rs` | Kernel and rootfs path resolution via `MINVMD_KERNEL_PATH` / `MINVMD_ROOTFS_PATH` env vars; arch-aware kernel format selection |
| `vm.rs` | VM configuration builder: assembles the libkrun context (vcpus, ram, kernel, rootfs, vsock ports) |
| `sock.rs` | Host UDS path resolution (`$XDG_RUNTIME_DIR/minimal/minimald.sock`), parent-dir creation (mode 0700), post-bind permission verification (0600) |
| `state.rs` | Atomic `state.toml` persistence (serde + toml), `vmm.pid` management |
| `lifecycle.rs` | Pure lifecycle state machine (`next_state`), `StartingGuard` RAII recovery |
| `cmd/boot.rs` | `minvmd boot --foreground` subcommand |
| `cmd/vmm_child.rs` | Hidden `minvmd __krun-vmm` child entry point |
| `cmd/run.rs` | `minvmd run` / `minvmd run --detach` supervisor |
| `cmd/status.rs` | `minvmd status` / `minvmd status --json` |
| `cmd/stop.rs` | `minvmd stop` (SIGTERM → wait 5 s → SIGKILL) |

### New FFI surface in `krun/raw.rs`

`krun_add_vsock_port2` (Unit 3), the host-initiated vsock bridge
registration. This supplements the existing `krun_add_vsock_port` which
is the guest-initiated variant.

### New workspace dependency

`fd-lock`, file-descriptor-based advisory locking for `lifecycle.lock`.
Workspace-pinned in `Cargo.toml`.

### Changes to `crates/minimal`

A `#[cfg(target_os = "macos")]` block in `src/main.rs` adds the
auto-spawn check: read `state.toml`, conditionally spawn
`minvmd run --detach`, wait for the UDS.

### No changes to `minimald`

v0.1 uses a vsock stub (R3.4). The real `minimald` swap-in (vsock-native
listener via `impl AsyncRead + AsyncWrite`) is a follow-up in
`crates/minimald`, confirmed by the `minimald` crate owner as option (b)
(informed by gominimal/minimal#280).

## Alternatives considered

### Option B: userspace byte relay in `minvmd`

`minvmd` would `accept()` on the host UDS and `tokio::io::copy_bidirectional`
each connection to a guest vsock connection. Rejected because:

- Adds a per-connection async task and buffer in `minvmd`, duplicating
  work libkrun already does in-kernel.
- Increases latency (extra userspace hop).
- Adds complexity: connection lifecycle, backpressure, error recovery all
  become `minvmd`'s problem.

libkrun's `krun_add_vsock_port2` delivers the same semantics with zero
`minvmd` code. The only trade-off is less observability (no per-connection
metrics in `minvmd`), acceptable for v0.1 (translated from plan: Socket
model Option A vs Option B).

### Direct `minimald` on macOS (no VM)

Not viable, `minimald` depends on Linux namespaces for sandbox isolation.
macOS has no equivalent. The VM boundary is the minimum viable isolation
layer.

## Knowledge gaps

- **No prior architecture records exist** in the knowledge store for this
  project. This is the first architecture record (`arch-minvmd-host-daemon`).
- **Networking deferred.** gvproxy/TSI integration (#160) is explicitly
  out of scope for v0.1. The TSI ~62-concurrent-connection cap is
  documented as a constraint near the vsock registration but does not
  affect the v0.1 architecture (< 10 concurrent connections expected).
- **Guest-side `minimald` swap-in path.** The vsock stub (R3.4) is a
  known thin area. The decision to use vsock-native `minimald` (option b)
  is confirmed but the implementation lives in `crates/minimald`, not
  `crates/minvmd` (informed by gominimal/minimal#280).
