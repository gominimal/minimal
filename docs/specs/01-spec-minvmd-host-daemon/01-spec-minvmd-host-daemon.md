# 01-spec-minvmd-host-daemon

**Source:** [gominimal/inbox#164](https://github.com/gominimal/inbox/issues/164) · parent [#151](https://github.com/gominimal/inbox/issues/151) · proposal [Minimal as a Session Manager](https://www.notion.so/360040938a8981cc9e01f675b40b071d) · kernel dep [gominimal/pkgs#154](https://github.com/gominimal/pkgs/pull/154) · reference impl `~/code/min-ctl`

## Introduction/Overview

`minvmd` is the macOS-only host daemon that brings up a Linux microVM via libkrun, supervises its lifecycle, and bridges a host UDS to a vsock port inside the VM so the `minimal` CLI can talk to `minimald` transparently — exactly as it does natively on Linux. It is the third process in the Minimal One architecture (alongside `minimal` and `minimald`) and exists solely to absorb the VM boundary that macOS imposes.

The crate is reimplemented clean in the minimal workspace, drawing patterns and hard-won lessons from `~/code/min-ctl` (FFI safety, lifecycle state machine, RAII recovery guards, error fidelity, no `$HOME` virtiofs, TSI connection-cap awareness) but not vendoring its code. Networking is explicitly deferred to #160.

## Goals

1. New `crates/minvmd` builds green on macOS (aarch64 + x86_64), no-op shim on Linux, no CI regressions on the Linux-only workflow.
2. `minimal` CLI on macOS opens a connection to in-VM `minimald` over a host UDS without knowing a VM exists (transparent vsock bridge).
3. VM boots from a `virtio-linux` kernel + Alpine rootfs in under ~5s cold; warm reattach is sub-second.
4. `minvmd` auto-spawns on first CLI call (Docker-Desktop model per #151) and survives client exit.
5. `minvmd status` / `minvmd stop` work; PID and socket discovery follow XDG conventions; concurrent CLI invocations don't race lifecycle.

## User Stories

- As a Mac user, I want to run `minimal ls` on a fresh install so that I get `[]` end-to-end without manually starting a VM.
- As a Mac user, I want my second `minimal ls` to be instant so that the VM cold-start cost is amortized.
- As a Mac user, I want to run `minvmd status` so that I can see VM state, vcpus, ram, and uptime.
- As a Mac user, I want to run `minvmd stop` so that the VM shuts down gracefully and the next `minimal` call cold-starts a fresh VM.
- As a Linux user, I want `minvmd` to not be installed at all so that my install path stays simple.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1; R2.1 for Unit 2). These IDs are referenced directly by the planner — do not renumber after approval.

### Unit 1: Crate scaffold, FFI wrappers, libkrun smoke test

**Purpose:** Land the bones — crate, FFI bindings, build script, codesign step. Boot a libkrun context to the marker "VM started, exited cleanly" with no rootfs work.

**Depends on:** None

**Affected areas:** `crates/minvmd/` (new), `crates/minvmd/src/krun/` (new), `crates/minvmd/minvmd.entitlements` (new), `crates/minvmd/build.rs` (new), `Cargo.toml` (workspace), `justfile`

**Functional Requirements:**
- **R1.1**: The `minvmd` crate shall compile on `aarch64-apple-darwin` and `x86_64-apple-darwin` and shall compile to a no-op stub on `target_os = "linux"` so the existing Linux-only CI stays green.
- **R1.2**: FFI bindings shall live in a single `src/krun/raw.rs` module; every `unsafe` call shall carry a `// SAFETY:` comment naming the libkrun preconditions (pointer lifetime, NUL-termination, range bounds, ownership transfer).
- **R1.3**: Safe wrappers (`src/krun/ctx.rs`) shall validate all inputs in safe Rust (range checks, NUL-termination, allocation lifetimes) before crossing the FFI boundary; FFI return codes shall be translated to a typed `VmError::Backend { op: &'static str, code: i32 }` preserving the original errno magnitude.
- **R1.4**: Release builds shall be code-signed with `minvmd.entitlements` granting `com.apple.security.hypervisor` and nothing else; a `justfile` target shall reproduce the signing step locally.
- **R1.5**: A smoke test `tests/krun_smoke.rs` (gated on `MINVMD_E2E=1`, marked `#[ignore]` by default) shall create a libkrun context, configure 1 vcpu + 512 MiB, set `/bin/true` as exec, and confirm `krun_start_enter` exits cleanly.

**Proof Artifacts:**
- File: `crates/minvmd/src/krun/raw.rs` contains FFI declarations for the libkrun functions used in this unit (`krun_create_ctx`, `krun_set_vm_config`, `krun_set_exec`, `krun_start_enter`, `krun_free_ctx`) with `// SAFETY:` comments demonstrates the FFI scaffold and safety discipline.
- CLI: `MINVMD_E2E=1 cargo test -p minvmd --test krun_smoke -- --include-ignored` exits 0 on a Mac with libkrun installed demonstrates end-to-end FFI bring-up.

---

### Unit 2: VM bring-up with virtio-linux kernel + Alpine rootfs

**Purpose:** Actual Linux boot. `minvmd boot` brings up an Alpine VM that reaches userspace and writes a "READY" marker to vsock from a guest-side init.

**Depends on:** Unit 1

**Affected areas:** `crates/minvmd/src/image.rs` (new), `crates/minvmd/src/vm.rs` (new), `crates/minvmd/src/cmd/boot.rs` (new), `crates/minvmd/src/cmd/vmm_child.rs` (new)

**Functional Requirements:**
- **R2.1**: The kernel artifact shall be the `vmlinuz` output of the `virtio-linux` minimal package (pkgs#154); on aarch64 the artifact is `Image.gz`, on x86_64 `bzImage`. Path resolution shall happen at runtime via a `MINVMD_KERNEL_PATH` env var so the package-graph wiring can land in a follow-up without changing this spec.
- **R2.2**: The rootfs shall be an Alpine minirootfs (version-pinned, sha256-verified). For v0.1 the path is supplied via `MINVMD_ROOTFS_PATH`; staging is performed by `scripts/fetch-alpine.sh` (downloads upstream Alpine minirootfs, verifies sha256, extracts to `~/.cache/minimal/minvmd/rootfs/`). Migration to a sibling `alpine-minirootfs` minimal package is tracked as an open question.
- **R2.3**: `minvmd boot` (parent) shall configure the libkrun context via the safe wrappers, then `exec`-spawn a hidden `minvmd __krun-vmm` child that calls `krun_start_enter` (the parent does not block on `krun_start_enter` because that call never returns on success). The parent shall write a `vmm.pid` file and surface child-exit codes via signal handling.
- **R2.4**: Boot shall complete to a guest-side marker (writes `READY\n` on a designated vsock port) within 5s on a warm laptop; the parent shall block on this marker before reporting boot success.
- **R2.5**: No network device shall be added to the libkrun config in v0.1; gvproxy/TSI integration is owned by #160. Default libkrun vsock is acceptable since v0.1 does not expose TCP to the guest.

**Proof Artifacts:**
- CLI: `MINVMD_KERNEL_PATH=/tmp/vmlinuz MINVMD_ROOTFS_PATH=/tmp/alpine-minirootfs minvmd boot --foreground` boots and prints `vm-up` to stdout within 5s, and a host-side reader on the vsock marker socket reads `READY` demonstrates kernel+rootfs come up.
- Test: `tests/boot_e2e.rs` (gated `MINVMD_E2E=1`, `#[ignore]`) asserts the marker round-trip end-to-end.

---

### Unit 3: UDS↔vsock bridge for `ssh.sock`

**Purpose:** The product feature — host UDS the CLI talks to, vsock to the guest where `minimald` listens. Bidirectional, transport-agnostic, multiple concurrent connections.

**Depends on:** Unit 2

**Affected areas:** `crates/minvmd/src/bridge.rs` (new), `crates/minvmd/src/sock.rs` (new), `crates/minvmd/src/vm.rs` (extend boot to register the vsock port + spawn the bridge)

**Functional Requirements:**
- **R3.1**: `minvmd` shall expose a host UDS at `$XDG_RUNTIME_DIR/minimal/minimald.sock` (fallback `~/.minimal/local/minimald.sock`) that bridges to a designated vsock port (proposed 2222; confirmed against #156) inside the VM. The UDS shall be created with mode 0600 and owned by the invoking user.
- **R3.2**: The bridge shall accept multiple concurrent host connections; each connection shall splice bytes bidirectionally between the host UDS and a fresh vsock connection until either side closes (use `tokio::io::copy_bidirectional` or equivalent).
- **R3.3**: On guest unavailability (VM crash, `minimald` exit, vsock connection refused), the host UDS shall keep accepting connections; failed connections shall return a typed `BridgeError::GuestUnavailable` and a `tracing::warn!` log without taking the listener down.
- **R3.4**: The bridge shall be transport-agnostic — no SSH/russh parsing, no protocol awareness. Bytes in, bytes out. (russh subsystem dispatch lives in `minimald`, per #156.)
- **R3.5**: TSI loopback's ~62-concurrent-connection cap (per `~/code/min-ctl` lessons.md) shall be documented in `crates/minvmd/src/bridge.rs` as a comment; v0.1 does not require more than ~10 concurrent client connections so this is acceptable.

**Proof Artifacts:**
- Test: `tests/bridge_e2e.rs` (gated `MINVMD_E2E=1`, `#[ignore]`) boots a VM running guest-side `socat VSOCK-LISTEN:2222,fork EXEC:cat`, opens 5 concurrent host UDS connections, each writes a distinct payload and reads it back. All 5 succeed demonstrates concurrent bidirectional bridging.
- CLI: With a stub `minimald` in the VM that returns an empty list to a `list-sessions` RPC, running `nc -U ~/.local/state/minimal/minvmd/minimald.sock` from the host (or a CLI integration) yields the empty list end-to-end demonstrates the host→guest path.

---

### Unit 4: Lifecycle daemon — auto-spawn, status, stop

**Purpose:** Daemon UX. `minimal` calling `minvmd` for the first time auto-spawns it; subsequent calls reuse; `minvmd status` introspects; `minvmd stop` shuts down gracefully.

**Depends on:** Unit 3

**Affected areas:** `crates/minvmd/src/cmd/{run,status,stop}.rs` (new), `crates/minvmd/src/state.rs` (new), `crates/minvmd/src/lifecycle.rs` (new), `crates/minimal2/src/main.rs` (extend)

**Functional Requirements:**
- **R4.1**: State and PID files shall live under `$XDG_STATE_HOME/minimal/minvmd/` (default `~/.local/state/minimal/minvmd/`): `state.toml` (lifecycle enum + `vmm_pid` + `started_at`), `vmm.pid`, `lifecycle.lock`. `state.toml` writes shall be atomic (tmp + rename + fsync).
- **R4.2**: `minvmd run` shall be a foreground supervisor (parent of the libkrun child + owner of the bridge); `minvmd run --detach` shall background-spawn and return only after the host UDS is accepting connections, with a configurable timeout (default 8s).
- **R4.3**: `minvmd status` shall print human-readable status by default and JSON with `--json` (fields: `state`, `vmm_pid`, `uptime_seconds`, `vcpus`, `ram_mib`). Exit code 0 if running, 1 if stopped, 2 on lock contention.
- **R4.4**: `minvmd stop` shall SIGTERM the vmm child, wait up to 5s, SIGKILL on timeout, then remove `vmm.pid` and reset `state.toml` to `Stopped`. The command shall be idempotent — stopping an already-stopped VM exits 0.
- **R4.5**: On macOS, `crates/minimal2` shall check `state.toml` before connecting to the UDS; if no `minvmd` is running it shall spawn `minvmd run --detach` and wait (with timeout) for the UDS. On Linux this path shall be a no-op.
- **R4.6**: State transitions shall be guarded by an `fd-lock`-style file lock on `lifecycle.lock` so concurrent CLI invocations cannot race. Recovery from a panicking transition (e.g. crash mid-`Starting`) shall be handled by an RAII guard modelled on `min-ctl`'s `StartingGuard` — drop without explicit commit resets to `Stopped`.
- **R4.7**: All lifecycle transitions shall pass through a pure `next_state(current: Lifecycle, action: Action) -> Result<Lifecycle, InvalidTransition>` function with no I/O, exhaustively unit-tested.

**Proof Artifacts:**
- Test: `crates/minvmd/src/lifecycle.rs` includes table-driven `#[test]`s for every legal and illegal transition; `cargo test -p minvmd lifecycle::` passes demonstrates the pure state machine.
- CLI: `minvmd stop && minvmd status --json` prints `{"state":"stopped",...}` and exits 1 demonstrates stop + status semantics.
- CLI: From a clean state (no minvmd running), `minimal ls` on a Mac succeeds within 8s and a subsequent `minvmd status` reports `running`; a second `minimal ls` completes in <500ms demonstrates auto-spawn + warm reuse.

## Non-Goals (Out of Scope)

- **Networking** — gated on #160 (gvproxy spike). v0.1 VMs have no net device; in-session package installs and outbound git operations will not work yet. Document loudly.
- **Multi-VM / multi-tenant** — single named VM (`default`); multi-VM is a v0.2+ concern.
- **`minvmd init` / OCI image fetch / cosign verification** — kernel and rootfs paths are passed in via env. Image-fetch pipelines are a separate concern (`virtio-linux` + a future Alpine package + the minimal graph).
- **Virtiofs / live host mounts** — per `~/code/min-ctl` lessons (TCC + provenance xattr issues, fd starvation), v0.1 has zero live mounts. File transport into the VM is `minimald`'s problem (tar push/pull per #151).
- **`brew services` registration** — auto-spawn from the CLI suffices for v0.1; a brew service can layer on later without changing the contract.
- **PTY supervision / session sandboxing** — those live in `minimald`, not `minvmd`.
- **Linux build of `minvmd`** beyond the no-op shim — nothing to run on Linux.
- **OS suspend/resume of the VM, RAM resizing, vcpu hot-add** — deferred.
- **Lifting code from `min-ctl`** — we reference patterns only; no code vendoring.

## Design Considerations

### Process model

`krun_start_enter` never returns on success — it `exit()`s with the guest workload's exit code. This forces a parent/child split:

```
minvmd run                       (parent — supervisor)
  └── minvmd __krun-vmm          (hidden child — calls krun_start_enter)
       └── libkrun + Alpine VM   (the actual VM)
            └── minimald (pid-1) (in-VM, via krun_set_exec)
```

Parent owns: `state.toml`, `lifecycle.lock`, host UDS listener, vsock bridge accept loop. Child owns: libkrun context, kernel/rootfs paths. They communicate via a single-use auth token (written to state dir mode 0600, verified by child, deleted immediately) plus signals. This pattern is lifted from `~/code/min-ctl/src/cmd/vmm_child.rs` and `~/code/min-ctl/src/cmd/start.rs`.

### Reference patterns (no code vendored)

| Pattern | min-ctl reference |
|---|---|
| FFI safety wrappers | `src/vm/krun/raw.rs` |
| Lifecycle state machine | `src/vm/lifecycle.rs` |
| `StartingGuard` RAII recovery | `src/cmd/start.rs:64-138` |
| Atomic state persistence | `src/vm/state.rs` |
| Child VMM entry pattern | `src/cmd/vmm_child.rs` |
| Single-use auth token (T36) | `src/cmd/start.rs` |
| XDG home resolution | `src/home.rs` |

### Hard lessons baked in

- **No `$HOME` virtiofs** — TCC + provenance xattr issues on macOS Tahoe. Zero virtiofs mounts in v0.1.
- **TSI ~62 concurrent connection cap** — fine for v0.1 (<10 concurrent), document the constraint, revisit when networking lands.
- **Error fidelity** — never collapse `Backend { op, code: errno }` into a `String`; wrap-and-rethrow preserves the errno.
- **Stubs are sticky** — every stub shall `panic!`/`bail!`/`unimplemented!` explicitly; no silent no-ops.

### What we deliberately do not do (vs min-ctl)

- No OCI image fetch + cosign — the package graph owns image integrity.
- No K8s quantity / Go duration parsers, no `config.toml` — overkill for v0.1.
- No `shell` / `attach` / `exec` / `push` / `pull` / `mount` / `logs` / `mcp` subcommands — those are min-ctl's product surface, not minvmd's. minvmd is a pure transport-and-VM-lifecycle daemon.

## Repository Standards

- Workspace conventions from `CLAUDE.md`: workspace-pinned deps; `cargo fmt && cargo test -- --include-ignored`; `cargo clippy --allow-dirty --fix --all-targets -- -D warnings`; no `println!`/`eprintln!` outside the CLI surface (use `tracing`); structured fields not interpolated strings (`tracing::info!(pkg = %name, "msg")`); typed error enums in library code, `anyhow::Result` only at CLI boundaries.
- Naming: `minvmd` (matches `minimald`).
- Platform gates: `#[cfg(target_os = "macos")]` for all libkrun-touching code; a stub Linux entry that `bail!`s.
- Tests: integration tests under `tests/`; libkrun-touching tests `#[ignore]` and gated on `MINVMD_E2E=1`; pure state-machine + parser tests run unconditionally.
- Unsafe: every `unsafe` block carries a `// SAFETY:` comment justifying every caller invariant.
- Dependencies: `nix`, `tokio`, `anyhow`, `serde`, `toml`, `tracing` (already in workspace); `fd-lock` (new, workspace-pin). Link libkrun directly via `build.rs`; do not pull a `libkrun` crate dependency.

## Verification

**Project maturity:** Established

**Available commands:**
| Check | Command |
|---|---|
| Lint  | `cargo clippy --allow-dirty --fix --all-targets -- -D warnings` |
| Build | `cargo build -p minvmd` (Linux: shim; macOS: full) |
| Test  | `cargo test -p minvmd` (unit + pure); `MINVMD_E2E=1 cargo test -p minvmd -- --include-ignored` (full) |

**Greenfield bootstrapping:** N/A — all commands available

**End-to-end manual verification (Mac):**
1. `cargo build -p minvmd --release && codesign --entitlements crates/minvmd/minvmd.entitlements --force -s - target/release/minvmd`
2. Build `virtio-linux` (pkgs#154); stage an Alpine minirootfs via `scripts/fetch-alpine.sh`; export `MINVMD_KERNEL_PATH` and `MINVMD_ROOTFS_PATH`.
3. `minvmd run --detach && minvmd status --json` → reports `{"state":"running",...}`.
4. `nc -U ~/.local/state/minimal/minvmd/minimald.sock` reaches a stub `minimald` running in the VM.
5. `minvmd stop && minvmd status` → reports `stopped`, exit 1.

**CI gate:** existing Linux-only CI stays green via the no-op shim. Optional `build-macos` job that runs `cargo check -p minvmd` once a Mac runner is available.

## Technical Considerations

- **libkrun linking** — pinned to a known-good version (initially the slp/krun Homebrew tap version used by min-ctl, currently v1.18.0). `build.rs` emits `cargo:rustc-link-search` and `cargo:rustc-link-arg=-Wl,-rpath` pointing at `/opt/homebrew/lib` with a `LIBKRUN_PREFIX` env override.
- **Hidden `__krun-vmm` subcommand** — modelled on min-ctl's `src/cmd/vmm_child.rs`. Not in `--help`; verified-via-auth-token; the only entry point that calls `krun_start_enter`.
- **State file format** — TOML with serde; one file per VM (in v0.1, only `default`). Lifecycle enum is `NotProvisioned | Stopped | Starting | Running | Stopping`.
- **Auto-spawn from `minimal2`** — implementation lives in `crates/minimal2/src/main.rs` behind `#[cfg(target_os = "macos")]`. On Linux it is a no-op; the CLI talks to `minimald` directly.

## Security Considerations

- Single entitlement: `com.apple.security.hypervisor`. No network, no file-access-outside-home, no Apple Developer Program membership required (ad-hoc signing via `codesign -s -`).
- Host UDS perms: mode 0600, owner-only. `LOCAL_PEERCRED` check recommended but not required at v0.1 since the UDS perms already gate access.
- No authentication on the bridge — fine because access is mode-gated. Do not expose the bridge over TCP without rethinking auth.
- Single-use auth token between parent `minvmd run` and child `minvmd __krun-vmm` (T36 pattern from min-ctl): written to `$XDG_STATE_HOME/minimal/minvmd/vmm.auth` mode 0600, verified by child, deleted on first read. Prevents stray re-execs of the hidden subcommand.
- Image provenance is deferred — v0.1 reads kernel + rootfs from caller-supplied paths. Once the minimal package graph wires the artifacts, content-addressed hashes already provide integrity.

## Success Metrics

- Mac developer runs `minimal ls` on a fresh install with no setup beyond install + first-time package fetch and gets a result in < 8s cold, < 500ms warm.
- Crate compiles green in CI on Linux (no-op shim) and is buildable on Mac.
- Smoke test (`MINVMD_E2E=1`) covers FFI bring-up, boot-to-marker, and 5-way concurrent bridge connections.
- Zero `unsafe` blocks without a `// SAFETY:` comment. Zero `unwrap()` outside `#[cfg(test)]`. Zero `println!`/`eprintln!` outside the CLI surface.

## Open Questions

1. **Alpine rootfs source.** v0.1 spec specifies `scripts/fetch-alpine.sh` (download + sha256-verify upstream Alpine minirootfs to `~/.cache/minimal/minvmd/rootfs/`). Migration path: write a sibling `alpine-minirootfs` minimal package in `gominimal/pkgs` once `virtio-linux` (#154) merges, then minvmd consumes both via the package graph instead of env vars. Track as a follow-up issue.
2. **Vsock port for `minimald`.** Proposed 2222 (avoids min-ctl's agent port 7350 so they can coexist on a Mac dev box). Confirm with #156 owner.
3. **Bridge transport on the guest side.** Does `minimald` in v0.1 listen on vsock directly via `vhost-vsock` kernel support, or on a UDS inside the VM with a tiny shim forwarding to vsock? Direct vsock is lighter system-wide; UDS+shim is lighter on `minimald`. Defer to #156 / `minimald` owner.
4. **In-VM `minimald` supervision.** Run `minimald` as pid-1 via `krun_set_exec(..., "minimald")`, or boot a tiny init (busybox/OpenRC) that launches it? Pid-1 is simpler but `minimald` then owns signal forwarding + zombie reaping. Proposed: pid-1 for v0.1; revisit if reaping becomes painful.
5. **Brew distribution.** Out of scope per non-goals, but flagging that the codesign step must be reproducible on contributors' machines — justfile target covers this.
