---
id: spec-vm-ext4-volume
title: "Per-VM writable ext4 volume: cache, staging, and sessions"
kind: spec
status: planned
tracking-issue: 583
supersedes:
---

# Per-VM writable ext4 volume: cache, staging, and sessions

## Context

Sandbox composition hardlinks package files from the local cache into per-sandbox
rootfs staging trees. Hardlinks cannot cross device boundaries (`EXDEV`), so the
cache and the staging trees must live on the same filesystem. Today both sit on
the per-boot `/run` tmpfs inside the guest (`minimal_state_dir = /run/minimal`,
`minimal_cache_dir = /run/minimal/cache`; `crates/minimald/src/main.rs:302-305`).
The tmpfs is mounted unsized, defaulting to ~½ guest RAM, and overflows with
`StorageFull` unpacking large packages — driving a stop-gap RAM bump to 4096 MiB
aarch64 / 2048 MiB x86_64 (`crates/minvmd/src/cmd/mod.rs:73-90`). All session
state dies with the VM.

The hardlink topology is confirmed in the code:

- Session/task rootfs staging: `crates/minimald/src/env.rs:282-284` — hardlinks
  from cache into `/tasks/<session>/` via `common::hardlink_dir_contents`.
- Package-build rootfs staging: `crates/op/src/specs.rs:284` — same primitive
  into `/sandboxes/<build>/`.
- The primitive: `crates/common/src/lib.rs:209-224` — tolerates only
  `AlreadyExists`, propagates every other error including `EXDEV` as
  `HardlinkFailed`. There is no cross-device fallback.

Two corrections already established in the tracking issue are taken as given:

- Staging trees live under `minimal_state_dir` (not `/tmp`); hakoniwa's `/tmp`
  `TempDir` is only a pivot-root bind-mount point.
- `OUTPUT_DIR` is copy-based, not hardlink-based; it is cross-FS-safe
  (`crates/sandbox2/src/lib.rs:1142`, `crates/lcache/src/lib.rs:103`). Only the
  cache → rootfs-assembly edge is constrained by `EXDEV`.

The session workbench (`/sessions/<id>/tree`, bind-mounted read-write at
`/workbench`; `crates/sandbox2/src/lib.rs:43,671-686`) is co-located on the
same volume for capacity (workspace uploads share the `StorageFull` failure mode)
and persistence (in-guest edits are user data with no host copy).

This spec covers the **VM-backed model only** (libkrun: macOS/HVF, Linux/KVM).
The writable volume is guest-only. Project files cross the boundary by workspace
upload or git download, never a host filesystem mount. The non-VM (hakoniwa)
sandbox path is out of scope.

Prior art: closed WIP PR #573 ("seeded cache disk + workspace upload") explored
this problem (informed by #573). This spec replaces that work. The workspace
upload receiver already landed via #423 (`crates/minimald/src/rpc.rs:402-410`);
only the client-side `Client::upload_workspace` needs porting past the crate
rename (#603).

## Introduction/Overview

This spec replaces the single per-boot `/run` tmpfs with a **per-VM persistent
writable ext4 volume** (`/dev/vdb`). Placing cache, rootfs staging, and session
workbenches on one volume resolves the `EXDEV` constraint by construction and
moves session state off RAM onto durable storage.

The disk topology is two RAW virtio-blk devices:

- `/dev/vda` — base rootfs, read-only, shared, content-addressed (unchanged).
- `/dev/vdb` — per-VM writable RAW ext4, carries `minimal_state_dir =
  /var/lib/minimal` (cache, `tasks/`, `sandboxes/`, `sessions/`).

Provisioning is guest-driven on first boot: the host creates a sparse raw file;
the guest probes for an ext4 superblock and runs `mkfs.ext4` only when none is
found (idempotent). Subsequent boots detect the filesystem and skip mkfs.

A **`VolumeProvisioner` abstraction** (`ensure(vm_id, size) -> image_path`,
idempotent) isolates the host-side materialization strategy from the guest boot
path. The guest keys exclusively off superblock detection, never off a "disk is
blank" assumption. This is the Phase 2 forward-compat requirement: replacing
`BlankRawProvisioner` with a `ReflinkProvisioner` (deferred) is a pure
host-side swap with no guest or boot-path change (informed by #583).

Clean shutdown requires a quiesce step — the guest `syncfs` + volume unmount
before VMM teardown — because today every stop is an unclean unmount: `minvmd
stop` SIGTERMs libkrun directly (`crates/minvmd/src/cmd/stop.rs:71-113`)
without invoking the Shutdown RPC that landed in #613. With user data now on the
volume, unclean unmount must produce a bounded, recoverable failure (ext4 journal
replay), not silent data loss.

## Goals

1. Cache, rootfs-staging (`tasks/`, `sandboxes/`), and session workbenches share
   one writable filesystem (`/dev/vdb`); builds that hardlink from the cache
   succeed in-VM on both macOS/HVF and Linux/KVM with no sync-out step.
2. Session worktrees (`/sessions/<id>/tree`) are created on the volume;
   `/workbench` is backed by them; in-guest edits survive a clean VM restart.
3. Provisioning a new VM creates a blank sparse raw volume; the guest formats it
   on first boot (idempotent, superblock-detected) and reuses it on subsequent
   boots.
4. Clean shutdown quiesces the volume (guest syncfs + unmount) before VMM
   teardown; the writable disk is attached with flush/sync semantics; an unclean
   shutdown is recoverable via ext4 journal replay.
5. Volume mount/attach failure when session state exists is loud — no silent
   tmpfs fallback, no false READY.
6. A corrupt `sessions/index.json` self-heals from per-session `record.json`
   files, not by failing startup.
7. Workspace upload against a non-empty persistent worktree has defined,
   documented semantics.
8. A host-side provider index maps session id → volume image path, supporting
   future multi-minvmd routing.
9. `DiskFormat` stays `Raw`; the base rootfs remains a raw ext4 image.

## User Stories

- As a developer running `minimal attach` in a VM session, I want to build
  packages without hitting `StorageFull`, so that large packages like claude-code
  compose successfully without raising guest RAM.
- As a developer with an active VM session, I want my in-guest `/workbench` edits
  to survive a clean VM restart, so that I do not need to re-upload my project
  after restarting the VM.
- As a macOS developer, I want `minvmd stop` to quiesce the VM cleanly, so that
  my session state is intact when I restart.
- As a platform engineer, I want volume mount failure to surface loudly, so that
  a corrupt or missing volume does not silently produce a degraded session.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1;
> R2.1 for Unit 2). These IDs are referenced directly by the planner — do
> not renumber after approval.

---

### Unit 1: Per-VM writable volume — host provisioning + guest attachment + state dir relocation

**Purpose:** Resolve the `EXDEV` failure by placing the cache and rootfs-staging
trees on a shared writable ext4 volume. Introduces the host provisioner, the
`krun_add_disk3` FFI binding, and the guest mount step.

**Depends on:** None

**Affected areas:**
- `crates/minvmd/src/krun/raw.rs` — `krun_add_disk3` FFI declaration
- `crates/minvmd/src/krun/ctx.rs` — `Context::add_disk_with_sync` wrapper
- `crates/minvmd/src/volume.rs` (new) — `VolumeProvisioner` trait + `BlankRawProvisioner`
- `crates/minvmd/src/vm.rs` — attach `/dev/vdb` via `add_disk_with_sync`
- `crates/minimald/src/guest.rs` — `mount_state_volume("/dev/vdb")` in `enter_rootfs`
- `crates/minimald/src/main.rs` — state dir paths → `/var/lib/minimal`
- `scripts/build-rootfs.sh` or `scripts/stage-release.sh` — `/var/lib/minimal` mountpoint + `e2fsprogs` in closure

**Baseline:**
- `krun/raw.rs` declares `krun_add_disk2` (no sync control); `krun_add_disk3`
  (`libkrun.h:278-284`, `direct_io` + `sync_mode`) is not yet declared — **NOT
  YET IN CODEBASE**.
- `vm.rs` calls `ctx.add_disk("root", &self.rootfs_path, DiskFormat::Raw, true)` —
  one disk, no second disk — **WRITABLE VOLUME NOT YET ATTACHED**.
- `main.rs:302-305` sets `minimal_state_dir = /run/minimal`, `minimal_cache_dir
  = /run/minimal/cache` — **STILL ON TMPFS**.
- `guest.rs:139-221` mounts only `/dev/vda` read-only, then transitions to the
  new root — **NO WRITABLE VOLUME MOUNT STEP**.
- `DiskFormat` enum has only `Raw = 0` (`krun/raw.rs:40-44`); `QCOW2` is a
  comment, not a variant — **ALREADY SATISFIES the Raw-only constraint**.

**Functional Requirements:**

- **R1.1**: `crates/minvmd/src/krun/raw.rs` shall declare `krun_add_disk3` as
  an `extern "C"` FFI function with the signature from `libkrun.h:278-284`:
  `krun_add_disk3(ctx_id: u32, block_id: *const c_char, disk_path: *const
  c_char, disk_format: u32, read_only: bool, direct_io: bool, sync_mode: bool)
  -> i32`. A `// SAFETY:` comment shall document all caller preconditions. No
  `Qcow2` variant shall be added to `DiskFormat`; the comment at `raw.rs:39`
  remains a comment.

- **R1.2**: `crates/minvmd/src/krun/ctx.rs` shall add `Context::add_disk_with_sync`
  alongside the existing `add_disk`. The new method accepts `direct_io: bool` and
  `sync_mode: bool` and delegates to `raw::krun_add_disk3` via the same
  `CString` construction and `check_backend` error translation as `add_disk`.

- **R1.3**: `crates/minvmd/src/volume.rs` (new file) shall define a
  `VolumeProvisioner` trait:
  ```rust
  pub trait VolumeProvisioner {
      fn ensure(&self, vm_id: &str, size_bytes: u64) -> Result<PathBuf, VolumeError>;
  }
  ```
  and a `BlankRawProvisioner` implementation that creates a sparse raw file at a
  deterministic path (e.g. `<state_dir>/volumes/<vm_id>.raw`) sized `size_bytes`
  via `fallocate(FALLOC_FL_KEEP_SIZE)` (Linux) or `ftruncate` (macOS/Linux
  portable fallback). The call is idempotent: if the file already exists at the
  expected size, `ensure` returns its path immediately. Error type `VolumeError`
  shall be a `thiserror`-derived typed enum. The default volume size shall be a
  named constant defaulting to 32 GiB, overridable via the `MINVMD_VOLUME_BYTES`
  environment variable.

- **R1.4**: `crates/minvmd/src/vm.rs` shall call `ctx.add_disk_with_sync` after
  the existing `ctx.add_disk("root", ...)` call to attach the writable volume as
  `"data"` at `read_only=false, direct_io=false, sync_mode=true`. The volume
  path is resolved by calling `BlankRawProvisioner::ensure(vm_id, size)` before
  constructing the `Context`. `vm_id` is derived from the state directory path
  (a stable per-VM identifier). The volume path is stored in `VmConfig` or
  passed through as a field; it must be passed to the VMM child process.

- **R1.5**: `crates/minimald/src/guest.rs` shall add a `mount_state_volume(device: &str)`
  function and call it from `enter_rootfs` immediately after the `/dev/vda` RO
  mount and before the `MS_MOVE` root transition. The function:
  - Opens the device and probes for a valid ext4 superblock (reads the magic
    number at byte offset 1080: `0x53EF`). This is the idempotency gate — mkfs
    runs only when the superblock is absent or corrupt.
  - If no valid superblock is found, shells out to `mkfs.ext4 -F <device>` and
    logs the result. A failure here is fatal: return the error.
  - Mounts the device read-write at `{NEWROOT}/var/lib/minimal` with `MS_NOATIME`.
    The mountpoint must exist on the read-only rootfs image (created by R1.7).
  - Returns `Err` on any unexpected I/O error or non-zero mkfs exit.

- **R1.6**: `crates/minimald/src/main.rs:302-305` shall update the guest-mode
  `global_args` to set `minimal_state_dir = /var/lib/minimal` and `minimal_cache_dir
  = /var/lib/minimal/cache`. The `/run/minimal` tmpfs paths are replaced; `/run`
  and `/tmp` remain tmpfs-backed as today.

- **R1.7**: The base rootfs image build shall add `/var/lib/minimal` as an empty
  directory (a bind-mount point for the writable volume) and include `e2fsprogs`
  (`mkfs.ext4`) in the rootfs closure. The rootfs image format stays raw ext4
  (`rootfs.img`); no packaging change to the release artifact shape (informed by
  `.minimal/minimal.toml:52-56` and `scripts/stage-release.sh:118`).

- **R1.8**: The RAM stop-gap in `crates/minvmd/src/cmd/mod.rs:73-90` shall reduce
  the default RAM from 4096/2048 MiB back to a lower baseline (e.g. 1024 MiB)
  once the cache no longer competes with the tmpfs. The exact value is
  implementation judgment; the comment documenting the stop-gap shall be updated
  or removed. This is a best-effort requirement: if baseline memory pressure is
  observed in CI, a higher value is acceptable.

**Proof Artifacts:**

1. **Test:** An integration test (`crates/minvmd/tests/` or `crates/minimald/tests/`)
   boots the VM, runs a build that hardlinks from the cache into a sandbox staging
   tree, and asserts the build succeeds with no `EXDEV` error — demonstrates the
   same-FS constraint is satisfied.
2. **CLI:** `minvmd boot --foreground` on macOS/HVF starts the VM, the guest
   mounts `/dev/vdb`, and the READY marker arrives — confirms the second disk is
   attached, formatted, and mounted before the guest signals readiness.

---

### Unit 2: Shutdown quiesce, crash safety, and loud mount failure

**Purpose:** Make the writable volume safe to hold user data. Today every VM
stop is an unclean unmount. This unit adds a quiesce path so clean stops leave
the ext4 journal in a replay-able, fully-flushed state, and makes mount failure
loud rather than silently degraded.

**Depends on:** Unit 1

**Affected areas:**
- `crates/minimald/src/server.rs` — Shutdown RPC handler
- `crates/minimald/src/guest.rs` — quiesce logic (syncfs + remount-ro/umount); loud mount failure
- `crates/minimald/src/main.rs` — no silent tmpfs fallback on mount failure; READY gated
- `crates/minvmd/src/cmd/stop.rs` — invoke Shutdown RPC before SIGTERM

**Baseline:**
- `stop.rs:71-113` sends SIGTERM to the libkrun process and waits up to 5 s —
  **NO SHUTDOWN RPC INVOCATION**.
- The Shutdown RPC (#613) tears down sessions but performs **NO VOLUME SYNCFS
  OR UNMOUNT** — `server.rs:342-395` drains connections, then the process exits.
- `guest.rs:139-221` has no quiesce step and no mount-failure guard.
- `main.rs:302-305` does not check that the volume is mounted before emitting
  READY.

**Functional Requirements:**

- **R2.1**: `crates/minimald/src/guest.rs` shall add a `quiesce_state_volume(device: &str)`
  function. It shall:
  - Call `syncfs(2)` on an open file descriptor to the `/var/lib/minimal` mount
    point, flushing all pending writes to the block device.
  - Attempt `umount2("/var/lib/minimal", MNT_DETACH)` (or remount read-only as
    a fallback if `umount` is refused due to busy processes); log any unmount
    error as a warning, never propagate it (best-effort).
  - Be called from the Shutdown RPC handler (R2.2) as the last step before
    acknowledging the shutdown.

- **R2.2**: `crates/minimald/src/server.rs` shall extend the Shutdown RPC handler
  to call `quiesce_state_volume` (R2.1) after all sessions are drained and before
  the process exits. The quiesce must complete (or time out with a warning) before
  the handler acknowledges to the caller. A quiesce timeout of 10 s is sufficient;
  the handler proceeds regardless.

- **R2.3**: `crates/minvmd/src/cmd/stop.rs` shall invoke the Shutdown RPC on the
  in-VM `minimald` before sending SIGTERM to the libkrun process. The RPC call
  uses the existing vsock bridge to reach the in-VM minimald. If the RPC fails
  (e.g. guest already gone), `stop` logs the failure and proceeds with SIGTERM;
  the existing 5 s SIGTERM → SIGKILL escalation is unchanged.

- **R2.4**: `crates/minimald/src/main.rs` (guest init path) shall gate the READY
  marker on successful volume mount. If `mount_state_volume` (R1.5) returns an
  error, the guest shall log a fatal-level error and either exit or emit a
  `DEGRADED` marker instead of `READY`. A silent tmpfs fallback is explicitly
  prohibited: no code path shall substitute `/run/minimal` when `/dev/vdb` mount
  fails.

- **R2.5**: If session state already exists on the volume (detectable by checking
  for `sessions/` on the mounted filesystem) and the volume fails to mount, the
  guest shall emit a distinct `MOUNT_FAILED` marker (or equivalent sentinel)
  rather than `READY`. `minvmd run` shall surface this condition as a user-visible
  error. This ensures that a corrupt or missing volume does not produce a ghost
  READY that appears to the host as a healthy VM.

**Proof Artifacts:**

1. **Test:** A test sends `minvmd stop` to a running VM, then confirms the volume
   image is mountable (ext4 journal clean) on the host after teardown — demonstrates
   the quiesce path flushed the journal.
2. **Test:** A test boots a VM with a missing or incorrectly-sized `/dev/vdb` and
   asserts that no `READY` marker arrives within the boot timeout — demonstrates
   R2.4 and R2.5 (loud failure, no silent fallback).

---

### Unit 3: Session persistence, self-heal, upload-on-resume, and provider index

**Purpose:** Define and implement the operational contracts that follow from
user data living permanently on the volume: session persistence across restarts,
recovery from corrupt index, upload semantics against a non-empty worktree, and
the host-side mapping from session id to volume image.

**Depends on:** Unit 1, Unit 2

**Affected areas:**
- `crates/sessions/src/store.rs` — corrupt index self-heal
- `crates/minimald/src/guest.rs` or boot path — `sessions/` exemption from reset
- `crates/minimald/src/rpc.rs` — upload-on-resume semantics
- `crates/minvmd/src/provider_index.rs` (new) — session → image → VM map

**Baseline:**
- `sessions/store.rs:382-396`: `Store::new` already calls `self_heal()` after
  loading the index — **SELF-HEAL MECHANISM EXISTS**. However, `serde_json::from_reader`
  at line 386 propagates a deserialization error directly (no catch-and-rebuild)
  — a corrupt `index.json` hard-fails at startup, after READY.
- `sessions/` is currently inside `/run/minimal`; no boot-time reset logic is
  needed today because the tmpfs is ephemeral. With the persistent volume,
  `providers/` must continue to reset while `sessions/` must not.
- `rpc.rs:402-410` unpacks a zstd-compressed tar into `paths.working` via
  `async_tar::Archive::unpack` — **NO NON-EMPTY CHECK, NO STAGED SWAP, NO
  ATOMICITY GUARANTEE**.
- No host-side session → volume index exists.

**Functional Requirements:**

- **R3.1**: `crates/sessions/src/store.rs` `Store::new` shall catch a
  deserialization error from `serde_json::from_reader` and fall back to a
  `Index::default()`, then rely on the existing `self_heal()` call to rebuild
  the index from per-session `record.json` files. A `tracing::warn!` with the
  original error and the count of sessions recovered shall be emitted. After
  self-heal, `flush_index()` commits the rebuilt index. The hard-fail path is
  replaced; `Store::new` may still fail on I/O errors (directory creation,
  file-open), but never on a corrupt JSON file alone.

- **R3.2**: The guest boot path (`crates/minimald/src/guest.rs` or the volume
  mount step) shall ensure `providers/` is reset on each boot while `sessions/`
  is preserved. A `providers/` reset already occurs on the PR #573 branch via
  commit `ee5299cc` scoping the boot reset to `providers/`; this requirement
  makes that behaviour explicit and tested. The implementation shall log a
  `tracing::info!` naming each reset directory and the count of entries removed.

- **R3.3**: `crates/minimald/src/rpc.rs` upload handler shall enforce the
  following semantics for workspace upload against a persistent worktree:
  - If the target worktree directory is non-empty (contains any files) and no
    `force=true` flag is set in the RPC, return an error to the client with a
    message indicating the worktree is non-empty.
  - If `force=true` is set, unpack into a staging directory adjacent to the
    worktree, then atomically replace it (via `rename(2)`). A mid-stream
    failure leaves the staging directory (not the live worktree) in a partial
    state; the next upload or a cleanup pass removes it.
  - The atomicity constraint is: after a successful upload RPC, the worktree is
    either the pre-upload state or the new state, never a partial mix.
  - A `force=false` upload to an empty worktree succeeds as today (no staging
    needed).

- **R3.4**: `crates/minvmd/src/provider_index.rs` (new file) shall define a
  `ProviderIndex` struct that persists a JSON map from session UUIDv7 → `VolumeEntry`
  (`{ image_path: PathBuf, vm_id: String }`). It shall implement `insert`,
  `get_by_session`, and `remove` operations, and `flush` (atomic rename-based
  JSON write). The index file shall be stored at `<minvmd_state_dir>/session_index.json`.
  `VolumeEntry` uses `session_id: SessionId` (UUIDv7, globally unique) as the key;
  no two VMs may share a session id.

- **R3.5**: `minvmd` shall update the `ProviderIndex` (R3.4) on session lifecycle
  events received from the in-VM `minimald` via the vsock RPC bridge: session
  created → insert; session destroyed → remove. The in-VM minimald shall emit
  these events over a new `SessionLifecycle` RPC (or extend an existing one).
  Full multi-VM routing (dispatch `attach`/`activate` to the owning VM) is
  #311 scope; this requirement only creates and maintains the index.

**Proof Artifacts:**

1. **Test:** A test writes a deliberately corrupt `sessions/index.json` to the
   volume, boots the VM, and asserts `minimald` reaches READY without error and
   the session count recovered from `record.json` matches expectation — demonstrates
   R3.1.
2. **Test:** A test uploads a workspace to a non-empty worktree without `force=true`
   and asserts the RPC returns an error; uploads with `force=true` succeed and the
   prior worktree content is atomically replaced — demonstrates R3.3.

---

## Non-Goals

- **Phase 2 (host-FS reflink CoW) and Phase 3 (single writable root).** Deferred.
  The `VolumeProvisioner` seam (R1.3) and guest superblock-detection (R1.5) keep
  Phase 2 a pure host-side swap with no guest/boot-path change.
- **qcow2 overlays.** No `Qcow2` variant is added to `DiskFormat`; no qcow2
  overlay-creation path is added. Deferred per #648.
- **Multi-VM session routing** beyond maintaining the index (R3.4, R3.5). Full
  `attach`/`activate` dispatch to the owning VM is #311 scope.
- **Non-VM (hakoniwa) sandbox path.** The `EXDEV` root cause applies there too
  via `XDG_CACHE_HOME`; not addressed here.
- **Workspace upload client** (`Client::upload_workspace` port past #603 crate
  rename). This is a dependency, not a deliverable of this spec; it is listed
  in Dependencies below.

## Design Considerations

### Why two disks rather than a read-write root

Keeping the base rootfs read-only and shared avoids per-VM image divergence and
simplifies rootfs upgrades (clone the new base, migrate state — no `qemu-img
rebase` risk). The writable volume is the only entity that varies per VM.

### Guest-side mkfs vs host-side mkfs

The host on macOS has no `mke2fs`/`mkfs.ext4`. Placing the first-boot mkfs in
the guest (R1.5) is the only portable approach. The superblock probe is the
idempotency gate: a VM that restarts after a partial mkfs re-runs mkfs cleanly.
`mkfs.ext4 -F` (force, no interactive prompt) is safe when called against the
raw block device.

### `krun_add_disk3` vs `krun_add_disk2`

`krun_add_disk2` has no sync control (`crates/minvmd/src/krun/raw.rs:143-149`).
`krun_add_disk3` adds `direct_io` and `sync_mode` flags (`libkrun.h:278-284`).
The writable volume must be attached with `sync_mode=true` to bound the data-loss
window on unclean shutdown. `direct_io=false` is correct for guest ext4 (the
guest filesystem's page cache and the block-level write ordering interact poorly
with O_DIRECT; leave it to the guest journal).

### Quiesce ordering

`quiesce_state_volume` (R2.1) must run after session drain (existing shutdown
behaviour in #613) and before VMM SIGTERM. The Shutdown RPC handler is the right
place: the host calls the RPC, the guest drains sessions and quiesces, the RPC
returns, `minvmd stop` sends SIGTERM. If the RPC times out (guest hung), SIGTERM
proceeds; the ext4 journal absorbs the unclean shutdown within the writeback
window, bounded to ≤ `commit=5s` seconds of data.

### Sessions directory exempt from boot reset

`providers/` is reset on each boot (established in PR #573 commit `ee5299cc`)
because provider registrations are ephemeral. `sessions/` must not be reset —
it is the source of truth for persistent workbenches. The guard in R3.2 makes
this explicit. Any future reset logic must not glob `*` under `minimal_state_dir`
without excluding `sessions/` and `cache/`.

### Upload-on-resume atomicity

The current upload path (`rpc.rs:402-410`) is a streaming tar unpack directly
into `paths.working` — no staging, no atomicity. With a persistent worktree this
is a data-corruption risk: a mid-stream failure leaves a partial mix. R3.3
introduces a staged-swap: unpack into `.working.upload-staging`, then rename. The
staging directory is adjacent to the live worktree on the same volume, making
`rename(2)` an in-filesystem operation (no `EXDEV`).

## Repository Standards

- `cargo fmt && cargo test -- --include-ignored` clean before merge.
- `cargo clippy --allow-dirty --fix --all-targets -- -D warnings` clean before
  merge.
- Commit messages follow Conventional Commits (per `docs/commit-conventions.md`).
- All `unsafe` additions carry `// SAFETY:` comments (per FFI discipline in
  `src/krun/raw.rs`).
- No blocking I/O in async context; `mount_state_volume` and `quiesce_state_volume`
  run on the guest init path (pid-1, synchronous) and are not async.

## Open Questions

1. **Volume size default.** 32 GiB as a default for `BlankRawProvisioner` is a
   guess; ext4 thin-provisions within the sparse file so the host only allocates
   blocks actually written. Is 32 GiB the right ceiling, or should the first
   Sprint ship with a smaller default and let it be tunable via `MINVMD_VOLUME_BYTES`?

2. **`minvmd stop` RPC transport.** The Shutdown RPC (#613) currently reaches
   `minimald` over the UDS bridge. Does `minvmd stop` have a live UDS path to
   the in-VM `minimald` at the time it is called, or does it need to open a new
   connection? The vsock bridge is torn down on SIGTERM, so the RPC must complete
   before SIGTERM (already required by R2.3). Confirm the RPC client call path in
   `stop.rs` for correctness.

3. **SessionLifecycle RPC shape.** R3.5 defers to a new or extended RPC to emit
   session lifecycle events from the guest to the host. Is there already a planned
   shape for this in the #311 scope, or should this spec define it from scratch?

## Technical Considerations

- **ext4 superblock magic (`0x53EF`)** is at bytes 56–57 of the superblock, which
  starts at byte offset 1024 from the device start (total offset 1080 for the
  magic). This is stable across all ext4 versions and requires reading only 2
  bytes for the probe.
- **`fallocate(FALLOC_FL_KEEP_SIZE)`** creates a sparse file on Linux; macOS
  does not support `fallocate`, so `ftruncate` (which also creates a sparse/thin
  file on APFS and HFS+) is the portable fallback.
- **Session UUIDv7** — globally unique, monotonically ordered by creation time.
  The `ProviderIndex` key is the session UUIDs, ensuring no collision across VMs
  or host reboots.
- **krun_add_disk3 is in libkrun ≥ 1.19.0.** The installed version is confirmed
  at 1.19.0 (`libkrun.h:278-284`); no library upgrade is required.

## Security Considerations

- The writable volume is guest-only. No host path mounts or serves it; project
  files arrive only via workspace upload or git download (informed by #583).
- `mkfs.ext4 -F` is run only inside the guest against `/dev/vdb`. The guest
  cannot influence the host volume provisioning path.
- The `ProviderIndex` (R3.4) is a host-side file. Session UUIDv7 keys are
  generated by the guest; the host treats them as opaque identifiers and does
  not act on them without a corresponding VolumeEntry.
- Workspace upload with `force=true` (R3.3) replaces the worktree atomically;
  the staging directory is inside the same volume subtree, never spilling to host
  paths.

## Verification

| Unit | Req | Proof type | Command / observable |
|------|-----|-----------|----------------------|
| R1 | R1.4, R1.5, R1.6 | Test | In-VM build that hardlinks from cache into sandbox staging exits 0 (no `EXDEV`) |
| R1 | R1.5 | CLI | `minvmd boot --foreground` on macOS/HVF: VM reaches READY with `/dev/vdb` mounted |
| R2 | R2.3, R2.1 | Test | `minvmd stop` on a running VM → host can mount volume image with clean ext4 journal |
| R2 | R2.4, R2.5 | Test | VM boot with missing/corrupt `/dev/vdb` produces no `READY` marker within boot timeout |
| R3 | R3.1 | Test | Corrupt `sessions/index.json` → `minimald` reaches READY; sessions recovered from `record.json` |
| R3 | R3.3 | Test | Upload to non-empty worktree without `force=true` returns error; upload with `force=true` atomically replaces worktree |
