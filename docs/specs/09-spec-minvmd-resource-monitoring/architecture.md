---
id: arch-minvmd-resource-monitoring
title: minvmd resource monitoring, configuration, and warnings — architecture
kind: architecture
status: planned
tracking-issue: 747
---

# minvmd resource monitoring, configuration, and warnings — architecture

## Chosen approach

Three host-side additions to the `minvmd` crate, sharing one insight: the VM runs
inside the supervised VMM child process (`State.vmm_pid`), so the host can both
*observe* it (sample the PID) and *configure* it (persist boot parameters read on
the next launch).

1. **Sampler** (`metrics.rs`) — `sample(pid)` reads host-visible CPU %, resident
   bytes, and cumulative disk read/write for the VMM PID via the `sysinfo` crate.
   Cross-platform (macOS/HVF, Linux/KVM) with no per-OS branch. `status --json`
   samples only for a running VM and emits a typed `StatusReport` with a
   `metrics` object (or `null`).

2. **Config** (`config.rs` + `cmd/config.rs`) — `ResourceConfig { vcpus, ram_mib }`
   persists to `config.toml` in the provider-instance dir, **separate from the
   runtime `State`** so a stop/crash reset cannot wipe it. `resolve_resources()`
   resolves `env ?? config ?? default` (values + sources) in one pass from a
   single config read; `boot`/`run` snapshot it once pre-spawn and hand the pair
   to `vmm_child` via `MINVMD_BOOTED_*`, and `config show` reports the same
   resolution. The `Running` state records that pre-spawn snapshot
   (`State.booted_*`) — by construction what the VM booted with — and `status`
   reports *those* for a live VM.

3. **Warnings** — proactive only: over-allocation vs host cores/memory, the
   x86_64 MMIO hole, and a host-derived vCPU ceiling (logical cores minus a
   two-core host reserve), all checked at `config set`;
   plus a supervisor post-exit resource hint on a guest workload's non-zero exit.
   There is **no** host-side reactive pressure threshold (see the removed-warnings
   note under Alternatives).

The config-vs-state separation, the `env ?? config ?? default` precedence, and
the boot-time snapshot (so `status` reports what the VM *actually booted with*,
not a later `config set`'s next-boot value) are the load-bearing decisions; all
are motivated below.

## Data and interface changes

### New files

- `crates/minvmd/src/metrics.rs` — `VmMetrics`, `sample(pid) -> Option<VmMetrics>`
  (raw host-visible sampling only; no pressure thresholds).
- `crates/minvmd/src/config.rs` — `ResourceConfig { vcpus: Option<u8>, ram_mib:
  Option<u32> }` with `read(dir)` / `write(dir)` (atomic).
- `crates/minvmd/src/cmd/config.rs` — `run_show(json)`, `run_set(vcpus, ram_mib)`,
  `HostCapacity::probe()`, pure `validate_resources`.
- `crates/minvmd/tests/config_cli_integration.rs` — CLI e2e (no VM required).

### Changed surfaces

- `state.rs` — extract `pub(crate) fn atomic_write_toml<T: Serialize>(target,
  value)`; `write_state` delegates to it (behaviour unchanged). Shared with
  `ResourceConfig::write`.
- `cmd/mod.rs` — `DEFAULT_VM_VCPUS`, `VM_VCPUS_ENV`, `env_ram_mib`/`env_vcpus`
  (private), `persisted_resource_config` (sanitizing hand-edited invalid
  values), `resolve_resources`/`effective_resources`, and the `MINVMD_BOOTED_*`
  parent→child snapshot env vars. `vm_ram_mib()` is removed (its two callers
  move to the effective resolution).
- `cmd/status.rs` — inline `json!` → `#[derive(Serialize)] StatusReport { …,
  metrics }`; pure `build_report`; metrics sampled only when running.
- `cmd/vmm_child.rs` — `VmConfig::new` from the parent's `MINVMD_BOOTED_*`
  snapshot (local resolution only as a fallback).
- `cmd/run.rs` — abnormal-exit resource hint before the existing `bail!`.
- `main.rs` — `Command::Config { action: ConfigAction::{Show, Set} }`.
- `Cargo.toml` (workspace + crate) — `sysinfo` dependency.

### `status --json` schema delta

Existing keys (`state`, `vmm_pid`, `uptime_seconds`, `vcpus`, `ram_mib`) keep
their types; for a running VM `vcpus`/`ram_mib` are the booted snapshot. One key
is added:

```json
{
  "metrics": {                    // null unless running
    "cpu_percent": 12.5,
    "resident_bytes": 1073741824,
    "disk_read_bytes": 0,
    "disk_written_bytes": 0
  }
}
```

## Alternatives considered

- **Hand-rolled sampling** (`/proc/<pid>/{stat,statm,io}` on Linux +
  `proc_pid_rusage` FFI on macOS) instead of `sysinfo`. Rejected: two platform
  code paths and macOS `unsafe` FFI for a marginal dependency saving; `sysinfo`
  is on blessed.rs and covers both uniformly. Cost accepted: a ~200 ms two-sample
  CPU read per `status` call and added compile time.
- **Config in `State` / `minvmd.toml`** (as the `status.rs` comment literally
  suggested). Rejected: `State::stopped()` and `StartingGuard` reset runtime state
  on every stop/crash, which would silently wipe persisted config; a sibling
  `config.toml` decouples user intent from ephemeral runtime state.
- **Report the next-boot `effective_*` resolution as the live values** (no boot
  snapshot). Rejected during review: `status` would misreport a running VM's
  resources after a `config set`. Chosen instead: stamp the resolved boot values
  into `State.booted_*` (R2.6) and report those.
- **Host-side reactive `memory_pressure`/`disk_pressure` threshold warnings.**
  Prototyped, then **removed** after review: they are unmeasurable host-side. The
  VMM's RSS includes the guest's reclaimable page cache, so a threshold fires on
  any long-running VM (false alarm); the data volume's host allocation is a
  monotonic high-water mark, not guest ext4 free space, so a disk threshold fires
  too late or never (false negative), and its `MINVMD_VOLUME_BYTES` advice is a
  no-op on an existing image. Accurate df/cgroup warnings need an in-guest agent
  (`minimal-vm-mac` does exactly this in-guest) — out of scope. The reliable
  reactive signal kept is the supervisor's abnormal-exit hint.

## Assumption ledger

| slug | statement | bucket | evidence |
|------|-----------|--------|----------|
| vmm-rss-reflects-guest | The VMM process's RSS/CPU/disk-I/O meaningfully reflect the guest, since libkrun runs the guest inside that process. | confident | libkrun architecture; `minimal-vm-mac` samples the same host process by PID. |
| sysinfo-cross-platform-diskio | `sysinfo` `Process::disk_usage()` is populated on both macOS and Linux. | confident | sysinfo supports process disk usage on Linux/macOS/Windows/FreeBSD; verified by the self-sample test. |
| env-divergence-resolved | A running `status` reflects the live VM's actual booted `vcpus`/`ram_mib`, including env-override boots, via `State.booted_*`. | confident | R2.6. |
| max-vcpus-host-derived | The host-derived ceiling (`max_vm_vcpus`: logical cores − 2, floored at the default) stays at or below the guest kernel's `CONFIG_NR_CPUS`, so a clamped/validated count never bricks the boot. | needs-confirm | the guest kernel config is not pinned in this repo; generic configs ship `CONFIG_NR_CPUS` ≥ 64, but a very-many-core host could exceed it (PR #775 review chose host-derived over a fixed cap of 8). |

## Knowledge gaps

- The exact wall-clock cost of the two-sample CPU read under a loaded host is
  unmeasured; `MINIMUM_CPU_UPDATE_INTERVAL` (~200 ms) is the floor. If `status`
  latency matters, a future `--no-metrics` fast path or a single-sample CPU
  estimate could be added.
- Whether operators want a machine-stable exit code from `config set` on warnings
  (today: warnings are non-fatal, exit 0). Left as exit-0-with-stderr for now.
