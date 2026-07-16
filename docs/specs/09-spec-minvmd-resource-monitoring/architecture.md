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
   runtime `State`** so a stop/crash reset cannot wipe it. `effective_vcpus()` /
   `effective_ram_mib()` resolve `env ?? config ?? default`; `vmm_child` boots
   from them and `config show` reports them. The `Running` state additionally
   records the resolved boot-time values (`State.booted_*`), and `status` reports
   *those* for a live VM (see the warning-denominator decision below).

3. **Warnings** — proactive (over-allocation vs host cores/memory + the x86_64
   MMIO hole, checked at `config set`) and reactive (memory/disk pressure vs the
   configured caps, evaluated by `status`; plus a supervisor post-exit hint).

The config-vs-state separation, the `env ?? config ?? default` precedence, and
the boot-time snapshot (so the reactive warning measures live RSS against the cap
the VM *actually booted with*, not a later `config set`'s next-boot value) are the
load-bearing decisions; all are motivated below.

## Data and interface changes

### New files

- `crates/minvmd/src/metrics.rs` — `VmMetrics`, `Warning`, `sample(pid) ->
  Option<VmMetrics>`, `data_volume_usage() -> Option<(u64, u64)>`,
  `evaluate_warnings(&VmMetrics, ram_mib, disk_used, disk_cap) -> Vec<Warning>`.
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
  (private), `persisted_resource_config`, `effective_ram_mib`/`effective_vcpus`.
  `vm_ram_mib()` is removed (its two callers move to `effective_ram_mib`).
- `cmd/status.rs` — inline `json!` → `#[derive(Serialize)] StatusReport { …,
  metrics, warnings }`; pure `build_report`; metrics sampled only when running.
- `cmd/vmm_child.rs` — `VmConfig::new(effective_vcpus(), effective_ram_mib(), …)`.
- `cmd/run.rs` — abnormal-exit resource hint before the existing `bail!`.
- `main.rs` — `Command::Config { action: ConfigAction::{Show, Set} }`.
- `Cargo.toml` (workspace + crate) — `sysinfo` dependency.

### `status --json` schema delta

Existing keys (`state`, `vmm_pid`, `uptime_seconds`, `vcpus`, `ram_mib`) keep
their types; `vcpus`/`ram_mib` are now the *effective* values. Two keys are added:

```json
{
  "metrics": {                    // null unless running
    "cpu_percent": 12.5,
    "resident_bytes": 1073741824,
    "disk_read_bytes": 0,
    "disk_written_bytes": 0
  },
  "warnings": [                   // [] unless a threshold is crossed
    { "kind": "memory_pressure", "message": "VM resident memory is 92% of its …" }
  ]
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
  snapshot). Rejected during review: it makes the `memory_pressure` warning
  measure live RSS against the wrong cap — `config set --ram-mib 16384` on a VM
  booted at 2048 silences a genuine OOM warning. Chosen instead: stamp the
  resolved boot values into `State.booted_*` (R2.6) and report/warn against those.
- **Guest-internal metrics / cgroup + `df` reactive warnings** (as
  `minimal-vm-mac` does in-guest). Rejected for v0.2: no in-guest agent exists;
  host-observable proxies (VMM RSS vs cap, sparse-image allocation vs cap) deliver
  the same guidance without a guest round-trip.

## Assumption ledger

| slug | statement | bucket | evidence |
|------|-----------|--------|----------|
| vmm-rss-reflects-guest | The VMM process's RSS/CPU/disk-I/O meaningfully reflect the guest, since libkrun runs the guest inside that process. | confident | libkrun architecture; `minimal-vm-mac` samples the same host process by PID. |
| sysinfo-cross-platform-diskio | `sysinfo` `Process::disk_usage()` is populated on both macOS and Linux. | confident | sysinfo supports process disk usage on Linux/macOS/Windows/FreeBSD; verified by the self-sample test. |
| blocks-tracks-sparse-usage | `MetadataExt::blocks() × 512` tracks a sparse raw image's real allocation. | confident | `st_blocks` is allocated 512-B blocks on APFS and ext4. |
| env-divergence-resolved | A running `status` reflects the live VM's actual booted `vcpus`/`ram_mib`, including env-override boots, via `State.booted_*`. | confident | R2.6; the warning denominator uses the booted cap, not the next-boot resolution. |
| default-256gib-volume | The 256 GiB default data volume means `disk_pressure` rarely fires, which is correct (only near-full). | confident | `volume.rs:DEFAULT_VOLUME_BYTES`. |

## Knowledge gaps

- The exact wall-clock cost of the two-sample CPU read under a loaded host is
  unmeasured; `MINIMUM_CPU_UPDATE_INTERVAL` (~200 ms) is the floor. If `status`
  latency matters, a future `--no-metrics` fast path or a single-sample CPU
  estimate could be added.
- Whether operators want a machine-stable exit code from `config set` on warnings
  (today: warnings are non-fatal, exit 0). Left as exit-0-with-stderr for now.
