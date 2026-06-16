# [minimald] Lifecycle Management: `run --detach`, `status`, `stop`

## Objective

Equip `minimald` with daemon lifecycle management matching the pattern established by `minvmd` (crates/minvmd). Currently `minimald` is foreground-only (`minimald run` without `--detach`, no `status`, no `stop`). The `minvmd` crate provides a complete, exhaustively tested lifecycle infrastructure that serves as the direct template. This work makes `minimald` a proper daemon that: starts in the background, reports its status, stops gracefully, survives client exits, and can be auto-spawned by `minimal2` on Linux.

---

## Implementation Plan

### Phase 1: Shared Lifecycle State Machine (pure, no I/O)

- [ ] **Extract lifecycle module into a shared crate** — Move `crates/minvmd/src/lifecycle.rs` to a new `crates/minimal-daemon-core/src/lifecycle.rs` (or directly into `crates/minimald/src/lifecycle.rs` if sharing is deferred). Re-export from `minvmd` to preserve backward compatibility. The `Lifecycle` enum, `Action` enum, `TransitionError`, and `next_state()` function have zero I/O dependencies and are the canonical state machine for both daemons. This avoids duplicating the exhaustive test suite.

- [ ] **Verify state machine generality** — Confirm the `Lifecycle` variants (`NotProvisioned`, `Stopped`, `Starting`, `Running`, `Stopping`) and `Action` variants (`Provision`, `Start`, `MarkRunning`, `Stop`, `MarkStopped`, `Fail`) apply identically to `minimald`. The `minvmd`-specific comment about "VM booting" on `Starting` is a doc nuance; the state semantics are identical: `Starting` means "daemon process spawned, waiting for readiness," `Running` means "server loop is accepting connections."

- [ ] **Add to `minimald` Cargo.toml** — If the lifecycle module is shared via a new crate, add the dependency to `crates/minimald/Cargo.toml`. If placed directly in `minimald/src/lifecycle.rs`, ensure `serde` derives are available (already present).

### Phase 2: State Persistence (`minimald/src/state.rs`)

- [ ] **Implement `State` struct** — Create `crates/minimald/src/state.rs` with a `State` struct mirroring `crates/minvmd/src/state.rs:33-41`: `lifecycle: Lifecycle`, `pid: Option<u32>` (the daemon's own PID, analogous to `vmm_pid`), `started_at: Option<u64>`. Serialize/deserialize via `serde`.

- [ ] **Implement `StateDir`** — Mirror `crates/minvmd/src/state.rs:57-146` with directory at `$XDG_STATE_HOME/minimal/minimald/` (or `~/.local/state/minimal/minimald/` as fallback), holding `state.toml`, `lifecycle.lock`, and `daemon.pid` files. Key methods:
  - `default_path()`: resolve the standard state directory
  - `state_path()`, `lock_path()`, `pid_path()`: path accessors
  - `read_state()`: deserialize `state.toml`; return `NotProvisioned` if file absent
  - `write_state()`: atomic write via `tmp → fsync → rename`
  - `open_lock_file()` / `lifecycle_lock()`: `fd-lock::RwLock` wrapping `lifecycle.lock`

- [ ] **Implement `StartingGuard`** — Mirror `crates/minvmd/src/state.rs:156-197`. RAII guard that resets persisted state to `Stopped` on drop unless `commit()` is called. Critical property: if the daemon panics or returns early during the `Starting` phase, the guard resets to `Stopped` so the daemon cannot be left indefinitely stuck in `Starting`.

- [ ] **Write unit tests** — Mirror the test suite from `crates/minvmd/src/state.rs:201-348`:
  - State TOML round-trip
  - Missing state file returns `NotProvisioned`
  - Atomic write uses tmp-then-rename (no `.toml.tmp` left behind)
  - Lifecycle lock acquire/release
  - Lifecycle lock prevents concurrent access (`WouldBlock`)
  - `StartingGuard` resets to `Stopped` on uncommitted drop
  - `StartingGuard` does not reset when committed

### Phase 3: `run --detach` (background the daemon)

- [ ] **Add `--detach` flag to `minimald run`** — Extend `ListenArgs` in `crates/minimald/src/main.rs:159-184` with `--detach: bool` and `--detach-timeout: u64` (default 4s — faster than `minvmd`'s 8s since no VM boot).

- [ ] **Implement foreground supervisor** — Restructure `async_main()` to factor out the core server-accept loop into a function that takes a `Config` and runs `Server::run(config, listener)`. When `--detach` is false, run this inline (current behavior preserved).

- [ ] **Implement `run_detach()`** — When `--detach` is true:
  1. Acquire lifecycle lock, read state, validate the transition (`NotProvisioned → Provision → Stopped`, then `Stopped → Start → Starting`), write `Starting` state, release lock.
  2. Spawn `minimald run` (foreground mode) as a child process via `Command::new(current_exe).arg("run").stdin(null).stdout(null).stderr(null)` with `setsid()` in `pre_exec` (same pattern as `crates/minvmd/src/cmd/run.rs:78-110`).
  3. Write PID to `daemon.pid` and update state with `pid: Some(child_id)` under lock.
  4. Poll the UDS socket path (`listen_on()`) until it accepts connections, using the `poll_uds_ready` pattern from `crates/minvmd/src/cmd/run.rs:47-65` (100ms intervals, timeout).
  5. On socket readiness: transition state to `Running` under lock, write `started_at` timestamp, commit the `StartingGuard`.
  6. On timeout or failure: kill the child, reset state to `Stopped`, return error.

- [ ] **Add detach guard in the foreground path** — When `minimald run` runs in foreground mode (without `--detach`), on startup: update state to `Running` with `pid: Some(std::process::id())` and `started_at`. On graceful exit (SIGTERM/SIGINT), transition state back to `Stopped` and clean up `daemon.pid`. Use a `StartingGuard` around the boot sequence to handle early failures.

### Phase 4: `status` and `stop` Subcommands

- [ ] **Add `Status` subcommand** — Mirror `crates/minvmd/src/cmd/status.rs`:
  - `minimald status`: human-readable output (`stopped`, `starting`, `stopping`, `running (pid=X, uptime=Ys)`)
  - `minimald status --json`: JSON object with `state`, `pid`, `uptime_seconds`
  - Exit codes: 0 if `Running`, 1 if stopped, 2 on lock contention
  - Non-blocking `try_read()` on lifecycle lock to detect concurrent transitions

- [ ] **Add `Stop` subcommand** — Mirror `crates/minvmd/src/cmd/stop.rs`:
  - Idempotent: no-op when already `Stopped`, `NotProvisioned`, or `Stopping`
  - Read `pid` from `state.toml` (under lock)
  - Send `SIGTERM` to the daemon PID, wait 5s, escalate to `SIGKILL`
  - Handle `ESRCH` (process already gone) gracefully
  - Reset state to `Stopped`, remove `daemon.pid`
  - Reject invalid PIDs (zero, exceeding `pid_t::MAX`)

- [ ] **Wire subcommands into `minimald` CLI** — Add to the `Command` enum in `crates/minimald/src/main.rs:119-128`:
  - `Status { #[arg(long)] json: bool }`
  - `Stop`

- [ ] **Write unit tests for `status` and `stop`** — Mirror the test suites from `crates/minvmd/src/cmd/status.rs:122-201` and `crates/minvmd/src/cmd/stop.rs:123-235`, adapted for `minimald`'s state directory path.

### Phase 5: Auto-spawn in `minimal2` (Linux)

- [ ] **Extend `minimal2` auto-spawn for Linux** — Modify `crates/minimal2/src/autospawn.rs` (currently no-op on Linux at `autospawn.rs:113-117`). On Linux:
  1. Resolve `minimald`'s UDS path (should match `minimald listen_on()`: `$XDG_STATE_HOME/minimal/providers/local-0/ssh.sock`).
  2. Check if the daemon is already running by running `minimald status` (or directly connecting to the UDS).
  3. If not running, spawn `minimald run --detach` and poll the UDS via `poll_uds_ready` (timeout ~4s).
  4. Return the `Client` connected to the resolved socket.

- [ ] **Fix socket path resolution in `minimal2`** — Update `crates/minimal2/src/client.rs:182-186` (`resolve_socket_path`) to resolve to `$XDG_STATE_HOME/minimal/providers/local-0/ssh.sock` on Linux, matching `minimald`'s `listen_on()` (crates/minimald/src/main.rs:114-116). The current code resolves to `$XDG_RUNTIME_DIR/minimal/minimald.sock` which is a `minvmd`-specific path that doesn't match `minimald`'s actual listen path.

---

## Verification Criteria

- `minimald run --detach` spawns the daemon in background, returns only after the UDS is accepting connections, and the daemon survives the parent process exit.
- `minimald status` returns `stopped` (exit 1) when daemon is not running, `running (pid=X, uptime=Ys)` (exit 0) when running, and `status --json` outputs valid JSON.
- `minimald stop` terminates a running daemon gracefully, resets state to `Stopped`, and is idempotent (can be called repeatedly without errors).
- Two concurrent `minimald run --detach` invocations are prevented by the lifecycle lock (second one fails with a clear error).
- `minimald status` during an in-progress start returns exit code 2 (lock contention) rather than a stale snapshot.
- On Linux, `minimal2 ls` (without `--minimal-dir` override) auto-spawns `minimald` if not running, connects, and lists sessions.
- All state machine, state persistence, status, and stop unit tests pass.
- `minimald`'s existing `run` (foreground, no `--detach`) behavior is unchanged for scripting and debugging use.

---

## Potential Risks and Mitigations

1. **Risk: Breaking `minvmd` by extracting shared lifecycle module**
   - Mitigation: If extracting to a shared crate, keep `minvmd`'s existing `lifecycle.rs` as a thin re-export for backward compatibility. Run `minvmd`'s full test suite after extraction. If this proves too invasive, duplicate the lifecycle module within `minimald` (it's ~80 lines of pure code + ~200 lines of tests) and add a comment cross-referencing the canonical source.

2. **Risk: `fd-lock` dependency not yet in `minimald`'s Cargo.toml**
   - Mitigation: Add `fd-lock` workspace dependency (already at `Cargo.toml:63` as `fd-lock = "4"`). Also add `toml` (already at workspace level, `Cargo.toml:112`). Both are already used by `minvmd`.

3. **Risk: Daemon PID tracking race during `run --detach`**
   - Mitigation: Follow `minvmd`'s proven pattern: write PID to `daemon.pid` and update state under the lifecycle lock immediately after `Command::spawn()`. Before committing `Running`, re-read state under lock to detect if a concurrent `stop` already reset the lifecycle. If so, kill the child and bail.

4. **Risk: Linux vs. macOS divergence in auto-spawn**
   - Mitigation: Gate Linux auto-spawn logic with `#[cfg(target_os = "linux")]`. On macOS, `minvmd`'s existing auto-spawn path (`minvmd run --detach`) remains unchanged. The auto-spawn function signature should handle both platforms — the existing macOS path calls `ensure_minvmd_running()`, the new Linux path calls `ensure_minimald_running()`.

5. **Risk: Socket cleanup between daemon restarts**
   - Mitigation: `minimald` already removes the stale socket before binding (`crates/minimald/src/main.rs:313-317`). Ensure `stop` does not remove the socket (it belongs to the daemon process, which cleans it up on exit). If the daemon crashes, the stale socket removal on next `run` handles it.

## Outstanding / Not in Scope

| Item | Rationale |
|------|-----------|
| `minimald doctor` command | Tracked separately in `gominimal/inbox#209` |
| Session rename (`RenameSession` RPC) | Separate feature; requires RPC contract + store changes |
| PTY interactive shell | Blocked on daemon-side PTY support (`exec.rs:650-654`) |
| `minimald` on macOS | Only runs inside the VM; no native macOS binary needed |
