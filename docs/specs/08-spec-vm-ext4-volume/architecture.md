---
id: arch-vm-ext4-volume
title: Per-VM writable ext4 volume — architecture
kind: architecture
status: shipped
tracking-issue: 583
---

# Per-VM writable ext4 volume — architecture

## Chosen approach

Replace the per-boot `/run` tmpfs with a per-VM persistent writable RAW ext4
volume (`/dev/vdb`). Placing the package cache, rootfs-staging trees, and
session workbenches on the same block device resolves the `EXDEV` hardlink
constraint by construction. The disk topology is two RAW virtio-blk devices:
`/dev/vda` (base rootfs, read-only, shared, content-addressed; unchanged) and
`/dev/vdb` (per-VM writable, carries `minimal_state_dir = /var/lib/minimal`).

The host creates a sparse raw file (`ensure_sparse_raw`); the guest formats it
on first boot via `mkfs.ext4` keyed on ext4 superblock detection (byte offset
1080 magic `0x53EF`) — idempotent, platform-portable (macOS has no `mke2fs`).
Subsequent boots detect the superblock and skip mkfs.

Clean shutdown is a guest `syncfs` + `umount` driven by `minvmd stop`
invoking the existing Shutdown RPC before SIGTERM. A failed `/dev/vdb` mount
is loud — `MOUNT_FAILED` marker, no READY, no silent tmpfs fallback — once
session state (user data) lives on the volume.

This is a three-crate change: `minvmd` (FFI, host provisioning, VM lifecycle),
`minimald` (guest boot, state paths, shutdown quiesce), and `sessions`
(corrupt-index recovery). No trait abstraction is introduced for provisioning;
the Phase-2 reflink provisioner is a pure host-side strategy swap behind the
same function-and-path contract with no guest or boot-path change.

## Data and interface changes

### FFI layer (`crates/minvmd/src/krun/`)

**`raw.rs` additions:**

- `krun_add_disk3` extern "C" function mirroring `libkrun.h:278-284`. Signature:
  ```rust
  pub fn krun_add_disk3(
      ctx_id: u32,
      block_id: *const c_char,
      disk_path: *const c_char,
      disk_format: u32,
      read_only: bool,
      direct_io: bool,
      sync_mode: u32,
  ) -> i32;
  ```
  A `// SAFETY:` block covers all caller preconditions (NUL-terminated
  C strings, ctx_id validity, call-duration lifetime of pointers).

- `SyncMode` `#[repr(u32)]` enum: `None = 0`, `Relaxed = 1`, `Full = 2`.
  Models the `KRUN_SYNC_*` tri-state exactly — `sync_mode` is `uint32_t`,
  not a bool (an earlier spec draft was incorrect on this point).

No `Qcow2` variant is added to `DiskFormat`; the comment at `raw.rs:39`
remains a comment.

**`ctx.rs` additions:**

- `Context::add_disk_with_sync(block_id, path, format, read_only, direct_io, sync_mode)`:
  delegates to `krun_add_disk3` via the same CString construction and
  `check_backend` error translation as the existing `add_disk`.

ALREADY EXISTS: `krun_add_disk2` FFI — `crates/minvmd/src/krun/raw.rs:178-185`.
Foundation for disk attach; `krun_add_disk3` adds sync/direct-io control.

ALREADY EXISTS: `Context::add_disk` — `crates/minvmd/src/krun/ctx.rs:224-251`.
Foundation for the new `add_disk_with_sync` (parallel method, same patterns).

ALREADY EXISTS: `DiskFormat::Raw = 0` — `crates/minvmd/src/krun/raw.rs:40-44`.
The Raw-only constraint is already satisfied.

### Volume provisioning (`crates/minvmd/src/volume.rs`, new)

- `pub fn ensure_sparse_raw(path: &Path, size_bytes: u64) -> Result<(), VolumeError>`:
  creates a sparse raw file at `path` via `File::set_len` (lazy allocation on
  both APFS and ext4) when absent; leaves an existing image untouched. Never
  resizes in place — shrinking would truncate a live guest ext4.
  `VolumeError` is a `thiserror`-derived typed enum (informed by ADR-0001).

- `pub fn resolve_data_volume_path() -> PathBuf`: reads
  `MINVMD_DATA_VOLUME_PATH` (used verbatim when set) or falls back to
  `<XDG_STATE_HOME>/minvmd/data-vol.raw`. Volume size via
  `MINVMD_VOLUME_BYTES` (named constant, default 32 GiB).

### VM configuration (`crates/minvmd/src/vm.rs`)

- `VmConfig` gains `data_volume_path: PathBuf`.

- `VmConfig::apply()` (the `#[cfg(minvmd_libkrun)]` path): after the existing
  `ctx.add_disk("root", &self.rootfs_path, DiskFormat::Raw, true)` call, adds:
  1. `ensure_sparse_raw(&self.data_volume_path, volume_bytes)` — idempotent,
     safe to call whether the file exists or not.
  2. `ctx.add_disk_with_sync("data", &self.data_volume_path, DiskFormat::Raw, false, direct_io, sync_mode)`.
  Sync parameters come from `MINVMD_DISK_SYNC` (`none`|`relaxed`|`full`,
  default **`relaxed`**) and `MINVMD_DISK_DIRECT_IO` (default `false`).
  `resolve_data_volume_path()` is called by the supervisor before constructing
  `VmConfig`, so `data_volume_path` is already resolved when `apply()` runs.

### Guest boot (`crates/minimald/src/guest.rs`)

New functions:

- `pub fn mount_state_volume(device: &str) -> io::Result<()>`:
  - Opens `device` and reads the ext4 magic word at byte offset 1080 (`0x53EF`).
  - If the magic word is **absent** (blank/uninitialized volume): shells out to
    `mkfs.ext4 -F <device>`, hardened per the empirical findings in #672:
    - **Undersize guard:** reject a device below a 16 MiB floor
      (`MKFS_MIN_DEVICE_BYTES`) with `Err` *before* invoking mkfs, rather than
      handing `mkfs.ext4` a nonsensical block count.
    - **Trailing margin:** size the filesystem ~1 MiB (`MKFS_MARGIN_BYTES`)
      below the device via an explicit block count, so it survives libkrun's
      backing-file trailer shave. Found via a 3-boot persistence test — without
      the margin the volume fails to re-mount on the next boot.
    - **No lazy-init storm:** `-E lazy_itable_init=0,lazy_journal_init=0` zeroes
      the inode table and journal at format time instead of via a background
      `ext4lazyinit` thread that competes with first-boot build I/O; combined
      with a reduced inode ratio (`-i 65536`) the eager init stays cheap.

    A mkfs failure is fatal (returns `Err`). mkfs runs only when no ext4
    signature is present — never when one exists, so a persistent session disk
    is never reformatted out from under its data.
  - If the magic word is **present**: mounts the existing filesystem; the ext4
    journal replays any unclean-shutdown state on mount. Never mkfs. If the
    mount fails, run `e2fsck -p <device>` and retry the mount once; if it still
    fails, fail closed (returns `Err`) so the failure surfaces as `MOUNT_FAILED`
    rather than silently wiping the volume.
  - Mounts the device read-write at `{NEWROOT}/var/lib/minimal` with
    `MS_NOATIME`. The mountpoint must exist on the RO rootfs (created by R1.7).
  - Returns `Err` on any unexpected I/O or non-zero mkfs exit.

- `pub fn quiesce_state_volume() -> io::Result<()>`:
  - Calls `syncfs(2)` on an open fd to `/var/lib/minimal`, flushing all pending
    writes to the block device.
  - Attempts `umount2("/var/lib/minimal", MNT_DETACH)`. Errors are logged as
    warnings and never propagated (best-effort).

- `pub async fn emit_mount_failed_marker() -> io::Result<()>`:
  - Writes `MOUNT_FAILED\n` to `BOOT_MARKER_PORT` (extends the existing
    boot-marker vsock protocol). Uses the same retry-with-backoff pattern as
    `emit_ready_marker`.

`enter_rootfs` gains a `mount_state_volume("/dev/vdb")` call immediately after
the `/dev/vda` RO mount and before the `MS_MOVE` root transition.

### State directory paths (`crates/minimald/src/main.rs`)

In the hardcoded in-VM config block (`is_minimal_microvm()` branch,
currently at `main.rs:302-305`):

- `minimal_state_dir = /var/lib/minimal`
- `minimal_cache_dir = /var/lib/minimal/cache`

**READY gate (new):** if `mount_state_volume` fails, the boot path calls
`emit_mount_failed_marker().await` and exits (or loops in degraded mode
matching the existing no-rootfs path). No code path substitutes `/run/minimal`
on a volume failure. The existing rootfs-failure path
(`enter_rootfs` returning `Err` → simple READY loop) is unchanged — that
covers the initramfs-only recovery case where no rootfs is attached.

### Shutdown quiesce (`crates/minimald/src/server.rs`)

Shutdown RPC handler: call `quiesce_state_volume()` after all sessions are
drained and before the process exits. Apply a 10-second timeout (caller
proceeds regardless — the journal replay backstop handles the unclean-unmount
case). A quiesce error is logged as a warning, not surfaced to the caller.

ALREADY EXISTS: Shutdown RPC infrastructure — merged via PR #613 (informed by
#613). `server.rs` already drains sessions; only the syncfs/unmount step is new.

### Stop command (`crates/minvmd/src/cmd/stop.rs`)

Before Phase 2 (SIGTERM): resolve the minimald host UDS path via
`crate::sock::resolve_uds_path()`; create a short-lived tokio runtime
(`tokio::runtime::Builder::new_current_thread().build()`); call the Shutdown
RPC via a minimald_rpc client (already a workspace dependency) within a
10-second timeout. Log any RPC failure and proceed to SIGTERM/SIGKILL
regardless (the existing 5-second SIGTERM → SIGKILL escalation is unchanged).

ALREADY EXISTS: Host→guest vsock bridge (VSOCK_BRIDGE_PORT) — `crates/minvmd/src/vm.rs`
via `VmConfig::apply()`. `stop.rs` uses the same host UDS path this bridge
exposes to reach in-VM `minimald`.

### Session store (`crates/sessions/src/store.rs`)

`Store::new` (currently `store.rs:353-367`): wrap the
`serde_json::from_reader` call in a `match`. On deserialization error:
- Emit `tracing::warn!` with the original error.
- Fall back to `Index::default()`.
- Rely on the existing `self_heal()` call to rebuild the index from per-session
  `record.json` files.
- Call `flush_index()` to commit the rebuilt index.
- Proceed; `Store::new` may still fail on I/O errors (directory creation,
  file-open), but never on a corrupt JSON document alone.

ALREADY EXISTS: `Store::self_heal()` — `crates/sessions/src/store.rs:369-382`.
The rebuild mechanism exists; only the corrupt-JSON fallback at `Store::new`
is missing.

### Boot reset (guest boot path)

After `mount_state_volume` succeeds and before emitting READY: reset
`<state>/providers/` (remove all entries) and leave `<state>/sessions/`
intact. Emit `tracing::info!` naming each reset directory and the entry count
removed. This makes explicit the behavior already present on branch #573 commit
`ee5299cc` (informed by #573) and makes it testable.

### Workspace upload (`crates/minimald/src/rpc.rs`)

`unpack_workspace_files` (currently `rpc.rs:384-413`) gains:

- **Non-empty check:** if the target worktree (`paths.working`) contains any
  files and `force=false`, return an RPC error to the client with a clear
  message.
- **Staged-swap (force=true):** unpack the archive into a staging directory
  adjacent to the worktree (`<worktree>-staging-<uuid>`); then
  `renameat2(RENAME_EXCHANGE, worktree, staging)` to atomically swap the two
  directories (ext4 supports this on Linux 3.15+); then remove the now-old
  staging content. A mid-stream unpack failure leaves the partial tree in
  staging (the live worktree is untouched); the next upload or a cleanup pass
  removes it.
- **force=false to an empty worktree:** proceeds as today (direct unpack,
  no staging needed).

ALREADY EXISTS: `unpack_workspace_files` — `crates/minimald/src/rpc.rs:384-413`,
landed via PR #423. The zstd-decompression and tar-unpack pipeline is in
place; atomicity semantics and the non-empty check are new.

### Provider index (`crates/minvmd/src/provider_index.rs`, new)

- `ProviderIndex` struct: JSON map keyed by `SessionId` (UUIDv7) →
  `VolumeEntry { image_path: PathBuf, vm_id: String }`. The session id is the
  map key only, not repeated in `VolumeEntry`. Operations: `insert`,
  `get_by_session`, `remove`, `flush` (atomic rename-based JSON write). Stored
  at `<minvmd_state_dir>/session_index.json`.
- Session lifecycle events: `minimald` emits session-created and
  session-destroyed events over a persistent guest→host vsock connection (new
  `SessionLifecycle` RPC direction, using the same vsock guest-outbound
  mechanism as the boot-marker port — connect, keep open, stream events).
  `minvmd` receives and updates `ProviderIndex`. Full multi-VM routing
  (`attach`/`activate` dispatch to the owning VM) is #311 scope; this spec
  only creates and maintains the index so that routing is not blocked later.

### Rootfs build

`scripts/build-rootfs.sh` or `scripts/stage-release.sh`: add `/var/lib/minimal`
as an empty directory (bind-mount point) and `e2fsprogs` (`mkfs.ext4`,
`e2fsck`) to the rootfs closure. The rootfs format stays raw ext4 (`rootfs.img`); no change to
the release artifact shape (informed by `.minimal/minimal.toml:52-56` and
`scripts/stage-release.sh:118`).

## Alternatives considered

**qcow2 data disk or backing-file overlay.** Rejected: `DiskFormat` has only
`Raw = 0` (`raw.rs:40-44`); no `Qcow2` variant exists or is added. No
host-side overlay-creation path exists in libkrun (`krun_add_disk3` opens an
image; it takes no backing-file parameter). `qemu-img` is not in the closure.
qcow2 adds a metadata-corruption surface on hard-kill (requires `qemu-img
check -r`) that RAW does not carry. RAW avoids all of this at no cost to
Phase 1 acceptance (informed by #583 scope-narrowing analysis).

**`VolumeProvisioner` trait abstraction.** Rejected (YAGNI). The Phase-2
reflink provisioner is a pure host-side strategy swap: a different way to
create the file at `data_volume_path`. The guest keys exclusively on
superblock detection, never on a "disk is blank" assumption, so Phase 2 is
host-side only regardless of whether a trait exists. Three similar provisioner
strategies is speculative; a plain function and a future `if reflink_available`
branch suffice. No trait is introduced.

**Host-side `mkfs.ext4` before attaching the disk.** Rejected: macOS has no
`mke2fs`/`mkfs.ext4`. Guest-side mkfs on first boot is the only
cross-platform option. Superblock detection makes it idempotent.

**Silent tmpfs fallback on `/dev/vdb` mount failure.** Rejected: session
worktrees are user data with no host copy; a fallback to `/run/minimal` would
serve a ghost READY that appears healthy to the host while state is actually
lost. Loud failure (MOUNT_FAILED marker, no READY) is the only safe posture
once persistent user data is on the volume.

**`full` sync mode as default for `krun_add_disk3`.** Rejected: macOS/HVF
benchmarks (spec Proof Artifact 4, 2026-07-07) show `full` is ≈12× slower
than `relaxed` (254 MB/s vs 3.1 GB/s) while `relaxed` still honours
`VIRTIO_BLK_F_FLUSH`, keeping ext4 journal ordering and bounding the
crash-recovery data-loss window. `full` is preserved as a tunable via
`MINVMD_DISK_SYNC=full`.

## Assumption ledger

| Slug | Statement | Bucket | Evidence / citation | Depends-on |
|---|---|---|---|---|
| krun-add-disk3-signature | `krun_add_disk3` signature at `libkrun.h:278-284` matches the expected Rust binding; `sync_mode` is `uint32_t` (not `bool`), values 0/1/2 (NONE/RELAXED/FULL) | settled | Verified against libkrun 1.19.0 header; macOS/HVF throughput run confirmed in spec Proof Artifact 4 (2026-07-07, informed by #583) | R1.1, R1.2 |
| sparse-raw-allocate-on-write | Sparse raw file (`File::set_len` / `ftruncate`) allocates blocks lazily on both APFS (macOS) and Linux host filesystems; the host never pre-allocates the full volume size | settled | APFS: confirmed — 2 GiB guest write → host image grows from 4 KiB to exactly 2048 MiB (spec Proof Artifact 3, macOS run, 2026-07-07, informed by #583); Linux: documented behavior of `ftruncate` + `fallocate(KEEP_SIZE)` on sparse-capable filesystems; CI Proof Artifact 3 Linux run verifies empirically | R1.3, R1.4 |
| rename-exchange-ext4 | `renameat2(RENAME_EXCHANGE)` is supported by the ext4 guest filesystem and available in the guest kernel image | settled | Linux kernel: RENAME_EXCHANGE added in Linux 3.15; ext4 documented support; the same virtio-linux guest kernel already enables modern features (user namespaces, hakoniwa sandbox builds) requiring ≥ Linux 3.8 | R3.3 |
| shutdown-rpc-reachable | The Shutdown RPC is reachable from `minvmd stop` via the existing host UDS ↔ guest vsock bridge | settled | `VmConfig::apply()` registers the host UDS → guest vsock bridge at VSOCK_BRIDGE_PORT; Shutdown RPC handler exists in `server.rs` merged via PR #613 (informed by #613); `stop.rs` reaches the same host UDS via `sock::resolve_uds_path()` | R2.3 |
| syncfs-bounded-flush | `syncfs(2)` on the `/var/lib/minimal` mount causes the ext4 journal to flush to the block device within a bounded time well under the 10-second quiesce timeout | settled | Linux semantics: `syncfs` is a blocking syscall that waits for all dirty pages and journal entries to reach the underlying block device; ext4 journal is sized (default 128 MiB) to flush quickly at modern I/O rates | R2.1, R2.2 |
| lifecycle-vsock-persistent | A persistent guest→host vsock connection for `SessionLifecycle` events is feasible using the same mechanism as `BOOT_MARKER_PORT` | needs-spike | Contradicted by #588: libkrun's vsock device wedges when a guest→host connection overlaps a host→guest one. The boot-marker is safe only because it is connect→write→**close** *before* the SSH bridge is used; a connection held open for the VM's lifetime overlaps every host→guest SSH/attach and hits the wedge continuously — not just at boot. This is the same failure mode that red-lit autospawn-e2e on #672 (an awaited best-effort expose serialized vsock use and dodged the wedge; detaching it exposed it as `ssh connect: Disconnected`). The lifecycle channel needs a wedge-safe transport — a one-shot/serialized guest→host emit or a host-initiated poll — not a held-open socket. Spike the transport before R3.5 planning. | R3.5 |

## Knowledge gaps

**No contradictions with prior decisions.** The error-handling strategy
(ADR-0001) applies: `VolumeError` in the new `volume.rs` uses `thiserror`
(library crate); `stop.rs` uses `anyhow` context (application crate)
(informed by ADR-0001).

**Thin area: `renameat2(RENAME_EXCHANGE)` usage.** No prior precedent in this
codebase for atomic directory swap via `RENAME_EXCHANGE`. The system call is
well-documented (Linux 3.15+, `man 2 renameat2`); the pattern is standard
for atomic directory replacement.

**Open spike: `SessionLifecycle` vsock transport (`lifecycle-vsock-persistent`).**
The libkrun vsock device wedges under concurrent guest→host and host→guest
connections (#588). A held-open guest→host lifecycle socket would collide with
the host→guest SSH/attach bridge continuously — the same failure that broke
autospawn-e2e on #672. Spike a wedge-safe transport (one-shot/serialized emit,
or host-initiated poll) before committing R3.5 to a persistent connection.

**Referenced prior work.** Precursor PR #573 (closed WIP: seeded cache disk +
workspace upload) is referenced throughout the spec but not available in the
knowledge store. The workspace upload receiver that landed from it (#423) is
confirmed in the codebase at `crates/minimald/src/rpc.rs:402-410` (informed by
#423). PR #671 (closed, unmerged: Unit 1 implementation attempt) represents
in-progress work on this feature; self-filtered as the feature's own prior
implementation rather than settled prior art.
