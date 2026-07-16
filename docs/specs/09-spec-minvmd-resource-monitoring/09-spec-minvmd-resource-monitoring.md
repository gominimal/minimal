---
id: spec-minvmd-resource-monitoring
title: "minvmd resource monitoring, configuration, and warnings"
kind: spec
status: planned
tracking-issue: 747
supersedes:
---

# minvmd resource monitoring, configuration, and warnings

## Context

`minvmd status --json` reports `vcpus` and `ram_mib` as **static boot-time
values** (R4.3 of the host-daemon spec): `vcpus` is the hardcoded literal `2` and
`ram_mib` is `crate::cmd::vm_ram_mib()` (env `MINVMD_VM_RAM_MIB` or an
arch-conditional default) — `crates/minvmd/src/cmd/status.rs:93-104`. There is no
way to observe live resource utilisation during a session, and no way to change a
VM's resource allocation short of setting an environment variable on the daemon.
A code comment at that site already anticipates this work: *"A future change that
stores these in minvmd.toml can report the live VM's actual values."*

The daemon already tracks everything needed to close the gap. The VM runs inside
a supervised child process whose PID is persisted as `State.vmm_pid`
(`crates/minvmd/src/state.rs:78`; written in `run.rs:414`), and libkrun runs the
guest *inside* that host process — so the host-visible CPU / resident-memory /
disk-I/O of `vmm_pid` reflects the VM. State is persisted as TOML in the
provider-instance dir with an atomic tmp→fsync→rename writer
(`state.rs:150-161`), and `VmConfig::validate_for` + `VmError::Configuration`
(`vm.rs:148-181`, `error.rs:55-58`) are the established validation precedent.

Prior art `minimal-vm-mac` confirms the shape but implements none of it in Rust:
`minctl` samples the host VMM process by PID (`ps -p <pid>`), resource config is
environment-variable-only with **no validation**, and warnings are reactive,
in-guest, post-mortem — OOM via `/sys/fs/cgroup/memory.events` and disk-full via
`df … ≥95%`, each pointing the user at the knob to raise. This spec ports those
ideas to a host-side, typed, tested implementation.

`vcpus`/`ram_mib` are read at boot from `crate::cmd::effective_*` and are static
for the VM's lifetime. This work monitors the *current* allocation and persists
config for the *next* boot; live hot-add / resize of a running VM is explicitly a
non-goal, per the host-daemon spec's deferral of "RAM resizing, vcpu hot-add"
(`docs/specs/01-spec-minvmd-host-daemon/01-spec-minvmd-host-daemon.md:335`).

## Introduction/Overview

Three additions, all host-side:

1. **Live metrics** in `status --json`: a `metrics` object (CPU %, resident bytes,
   disk read/written bytes) sampled from `vmm_pid` via the cross-platform
   `sysinfo` crate, `null` when the VM is stopped.
2. **A `minvmd config` surface**: `config show` prints the effective resource
   configuration and each value's source; `config set --vcpus/--ram-mib`
   validates against host capacity and persists to a new `config.toml` in the
   provider-instance dir, consumed at the next boot.
3. **Warnings**, in two forms: **proactive** over-allocation warnings at
   `config set` (requested value exceeds host cores/memory, or straddles the
   x86_64 MMIO hole), and **reactive** threshold warnings surfaced by `status`
   when a running VM's resident memory nears its RAM cap or its data volume nears
   full — plus a supervisor post-exit resource hint on abnormal VMM-child exit.

Configuration is kept in a **separate `config.toml`**, not in the runtime
`State`: `State::stopped()` and `StartingGuard` reset runtime state on every stop
or crash, which would silently wipe config stored there. Resolution precedence is
`environment override ?? persisted config ?? built-in default`, preserving the
existing `MINVMD_VM_RAM_MIB` power-user escape hatch.

Metrics are **host-visible VMM-process** usage, not guest-internal per-process
metrics (minvmd runs no in-guest agent). The reactive warnings are likewise
host-observable thresholds (sampled RSS vs the configured cap; the sparse data
volume's on-disk allocation vs its cap), not guest cgroup / `df` introspection.

## Goals

1. `minvmd status --json` reports live CPU, resident memory, and disk I/O for a
   running VM alongside the existing static fields, and `null` metrics when
   stopped, without disturbing the running VM.
2. `minvmd config set` validates and persists `vcpus`/`ram_mib` to the state dir;
   the next boot uses the persisted values; `minvmd config show` reports them and
   their source.
3. `minvmd config set` warns (non-fatally) when a requested value over-allocates
   host resources or hits the x86_64 MMIO hole, and rejects structurally invalid
   values.
4. A running VM approaching a memory or disk limit surfaces a reactive warning via
   `status`; an abnormal VMM-child exit prints a resource hint.
5. No new behaviour on the non-VM (native minimald) path; the change is confined
   to the `minvmd` crate.

## User Stories

- As a Mac developer sizing a workload, I want `minvmd status --json` to show live
  CPU and memory use, so that I can tell whether the VM is under-provisioned.
- As a developer whose build was OOM-killed, I want `minvmd config set --ram-mib`
  to persist a larger allocation for the next boot, so that I do not have to set
  an environment variable on the daemon.
- As a developer, I want `minvmd config set` to warn me when I ask for more vcpus
  or RAM than the host has, so that I do not silently misconfigure the VM.
- As a developer, I want a running VM that is nearly out of memory or disk to tell
  me so, and name the knob to raise, so that I can react before a failure.

## Demoable Units of Work

> Requirement IDs use the format **R{unit}.{seq}** (R1.1, R1.2 for Unit 1;
> R2.1 for Unit 2). These IDs are referenced directly by the planner — do
> not renumber after approval.

---

### Unit 1: Live resource metrics in `status --json`

**Purpose:** Surface host-visible CPU / resident-memory / disk-I/O of the VMM
process in `status --json` and `status` human output.

**Depends on:** None

**Affected areas:**
- `Cargo.toml` (workspace), `crates/minvmd/Cargo.toml` — add the `sysinfo` dependency
- `crates/minvmd/src/metrics.rs` (new) — sampler
- `crates/minvmd/src/cmd/status.rs` — `StatusReport` DTO + `metrics` field
- `crates/minvmd/src/lib.rs` — `pub mod metrics;`

**Baseline:**
- `status --json` emits an inline `serde_json::json!` with `state`, `vmm_pid`,
  `uptime_seconds`, `vcpus: 2`, `ram_mib` — no live metrics (`status.rs:93-104`).
- No `sysinfo`, no `/proc`/`getrusage` sampling exists anywhere in the crate.

**Functional Requirements:**

- **R1.1**: `crates/minvmd/src/metrics.rs` (new) shall provide
  `pub fn sample(pid: u32) -> Option<VmMetrics>` returning host-visible
  `cpu_percent`, `resident_bytes`, `disk_read_bytes`, `disk_written_bytes` for the
  process, via the `sysinfo` crate, and `None` when no such process exists.
  `VmMetrics` derives `Serialize`.
- **R1.2**: Sampling shall not disturb the running VM (read-only process stat
  inspection). `status` shall sample only when the lifecycle is `Running` and
  `vmm_pid` is present; otherwise the `metrics` field is `null`.
- **R1.3**: `crates/minvmd/src/cmd/status.rs` shall serialise a typed
  `StatusReport { state, vmm_pid, uptime_seconds, vcpus, ram_mib, metrics,
  warnings }`. Existing fields keep their shape and types; `metrics` is
  `null`-or-object and `warnings` is an array (Unit 3). Assembly shall be a pure
  `build_report(...)` function so the JSON shape is unit-testable without a live VM.

**Proof Artifacts:**
1. **Test:** `metrics::tests::sample_of_self_returns_metrics` — `sample(std::process::id())`
   returns `Some` with non-zero `resident_bytes`; `sample(0)` returns `None`.
2. **Test:** `status::tests::report_schema_when_stopped_has_null_metrics_and_no_warnings`
   — `build_report` for a stopped state serialises all seven keys with
   `metrics: null`, `warnings: []`.
3. **CLI:** on a running VM, `minvmd status --json | jq .metrics.resident_bytes`
   prints a non-null integer.

---

### Unit 2: `minvmd config` surface + boot consumption

**Purpose:** Persist per-VM `vcpus`/`ram_mib` and consume them at boot.

**Depends on:** None

**Affected areas:**
- `crates/minvmd/src/config.rs` (new) — `ResourceConfig` persistence
- `crates/minvmd/src/state.rs` — extract `atomic_write_toml` helper; add
  `booted_vcpus`/`booted_ram_mib` runtime snapshot fields
- `crates/minvmd/src/cmd/config.rs` (new) — `show`/`set` + validation
- `crates/minvmd/src/cmd/mod.rs` — `effective_vcpus`/`effective_ram_mib`
- `crates/minvmd/src/cmd/vmm_child.rs` — boot from effective values
- `crates/minvmd/src/cmd/run.rs` — stamp booted snapshot into `Running` state
- `crates/minvmd/src/main.rs` — `config` subcommand
- `crates/minvmd/src/lib.rs` — `pub mod config;`

**Baseline:**
- `State` is `{ lifecycle, vmm_pid, started_at }` — no persisted resource params.
  `vcpus`/`ram_mib` are a literal and `vm_ram_mib()` (`cmd/mod.rs:102`).
- `vmm_child.rs` boots `VmConfig::new(2, vm_ram_mib(), …)`.

**Functional Requirements:**

- **R2.1**: `crates/minvmd/src/config.rs` (new) shall define
  `ResourceConfig { vcpus: Option<u8>, ram_mib: Option<u32> }`
  (`Serialize`/`Deserialize`/`Default`), persisted to `config.toml` in the
  provider-instance dir — **separate from `State`**, so a stop/crash reset cannot
  wipe it. `read` treats a missing file as the all-`None` default; `write` is
  atomic via the shared `crate::state::atomic_write_toml`.
- **R2.2**: `crates/minvmd/src/cmd/mod.rs` shall provide `effective_vcpus() -> u8`
  and `effective_ram_mib() -> u32`, each resolving
  `environment override ?? persisted config ?? built-in default`
  (`MINVMD_VM_VCPUS`/`MINVMD_VM_RAM_MIB`; defaults `DEFAULT_VM_VCPUS = 2` and the
  existing arch-conditional `DEFAULT_VM_RAM_MIB`). `status` (R1.3) and
  `vmm_child` shall report/boot from these.
- **R2.3**: `minvmd config set [--vcpus N] [--ram-mib M]` shall validate, merge
  into the existing persisted config, and write it atomically. Validation rejects
  `vcpus == 0` and `ram_mib < 512` (the userspace floor). With neither flag it is
  an error.
- **R2.4**: `minvmd config show [--json]` shall print the effective `vcpus`/`ram_mib`
  and each value's source (`env`/`config`/`default`).
- **R2.5**: `crates/minvmd/src/cmd/vmm_child.rs` shall construct its `VmConfig`
  from `effective_vcpus()`/`effective_ram_mib()`, so a persisted config takes
  effect on the next boot.
- **R2.6**: The `Running` state shall record the resolved boot-time `vcpus`/`ram_mib`
  as `State.booted_vcpus`/`booted_ram_mib` (runtime facts like `vmm_pid`, cleared
  on stop, `#[serde(default)]` for backward compatibility). `status` shall report
  and warn against these live values for a running VM — **not** a later
  `config set`'s next-boot resolution — falling back to `effective_*` only when
  stopped or when reading a pre-#747 state file with no snapshot.

**Proof Artifacts:**
1. **Test:** `config::tests::round_trips_through_toml` and
   `missing_file_reads_as_default` — persistence contract;
   `state::tests::pre_747_state_file_without_booted_fields_reads_as_none` —
   backward compatibility.
2. **Test:** `cmd::config::tests::{zero_vcpus_is_rejected, ram_below_floor_is_rejected}`
   — structural validation.
3. **CLI:** `minvmd config set --ram-mib 3072 && minvmd config show --json | jq
   .ram_mib` prints `3072` with `ram_mib_source: "config"`.
4. **Test:** `status::tests::running_reports_booted_snapshot_not_next_boot_resolution`
   — a running VM reports its booted cap, not the persisted next-boot value.

---

### Unit 3: Resource warnings (proactive + reactive)

**Purpose:** Warn on over-allocation at config time and on resource pressure at
runtime.

**Depends on:** Unit 1 (sampler), Unit 2 (config surface + effective values)

**Affected areas:**
- `crates/minvmd/src/cmd/config.rs` — host-capacity validation
- `crates/minvmd/src/metrics.rs` — `evaluate_warnings`, `data_volume_usage`
- `crates/minvmd/src/cmd/status.rs` — `warnings` field
- `crates/minvmd/src/cmd/run.rs` — supervisor post-exit hint

**Baseline:**
- No host-capacity check anywhere; no runtime resource warnings; the supervisor
  bails on abnormal VMM-child exit with a bare code (`run.rs`).

**Functional Requirements:**

- **R3.1**: `minvmd config set` shall probe host capacity (logical cores via std,
  total memory via `sysinfo`) and emit **non-fatal** warnings when the request
  exceeds host cores or memory, and — on `x86_64` — when `ram_mib` falls in the
  MMIO-hole range `3073..=6143`. The pure validator takes capacity as a parameter
  so it is testable without the real host.
- **R3.2**: `crates/minvmd/src/metrics.rs` shall provide
  `evaluate_warnings(metrics, ram_mib, disk_used, disk_cap) -> Vec<Warning>`
  emitting `memory_pressure` at resident-memory ≥ 90 % of the RAM cap and
  `disk_pressure` at data-volume allocation ≥ 95 % of its cap (`disk_cap == 0`
  disables the disk check). The RAM cap is the *booted* value (R2.6), not the
  next-boot resolution. `data_volume_usage()` reports the sparse image's actual
  on-disk allocation (`blocks × 512`) vs the image's own fixed size (`len`), not
  `volume_bytes()` — which would drift if `MINVMD_VOLUME_BYTES` changed after the
  image was created.
- **R3.3**: `status` (R1.3) shall include the evaluated `warnings` array when
  running (empty otherwise) and print each to stderr in human mode.
- **R3.4**: `crates/minvmd/src/cmd/run.rs` shall, on abnormal VMM-child exit,
  print a resource hint naming `minvmd config set --ram-mib/--vcpus` before it
  bails (host-side analog of `minimal-entry`'s OOM post-mortem).

**Proof Artifacts:**
1. **Test:** `cmd::config::tests::over_core_and_over_mem_warn_but_succeed` and
   `x86_mmio_hole_range_warns` — proactive warnings.
2. **Test:** `metrics::tests::{memory_pressure_fires_at_or_above_threshold,
   disk_pressure_fires_at_or_above_threshold}` and their below-threshold
   negatives — reactive thresholds.
3. **Test:** `status::tests::report_when_running_includes_metrics_and_pressure_warning`
   — a running report with RSS at its cap carries a `memory_pressure` warning.

## Non-Goals

- **Live vcpu hot-add or RAM resize of a running VM** — resolved at boot only;
  reaffirms `docs/specs/01-spec-minvmd-host-daemon/…:335`.
- **Guest-internal per-process metrics** — needs an in-guest agent; metrics are
  host-VMM-process only.
- **Reading guest cgroup `memory.events` / in-guest `df`** — the reactive warnings
  are host-observable proxies, not guest introspection.
- **Multi-VM config** — single `local-0` instance, per the v0.1 single-VM stance.

## Design Considerations

- **Config file, not `State`.** `State::stopped()`/`StartingGuard` reset runtime
  state on stop/crash; config in `State` would be wiped. `config.toml` is a
  sibling file written only by `config set`.
- **`sysinfo` over hand-rolled `/proc` + macOS `proc_pid_rusage`.** One
  blessed.rs, cross-platform dependency (macOS/HVF + Linux/KVM) covers per-process
  CPU/RSS/disk-I/O and host memory uniformly, at the cost of a ~200 ms two-sample
  CPU read per `status` call and added compile time.
- **Effective resolution keeps the env override on top.** `MINVMD_VM_RAM_MIB`
  remains a per-boot escape hatch; `config set` supplies a persisted layer beneath
  it. `config show` reports this next-boot resolution (with a `source`), while a
  running `status` reports the boot-time snapshot (R2.6) — so the two answer
  different, correctly-scoped questions ("what will next boot use" vs "what is the
  live VM running").
- **The reactive warning must measure against the live cap, not the next-boot
  cap.** Without R2.6, `config set --ram-mib 16384` on a VM booted at 2048 would
  silence a genuine `memory_pressure` warning (RSS compared against 16384 instead
  of 2048). Recording the booted values in `State` closes this.

## Repository Standards

- CLI/command layer returns `anyhow::Result` with actionable `.context`/`bail!`;
  the hand-rolled `VmError` enum is unchanged (not converted to `thiserror`).
- `sysinfo` is pinned in the workspace `[workspace.dependencies]`; the crate
  inherits via `workspace = true`.
- Requirement IDs are anchored in code/tests as `// R9.x` comments.

## Open Questions

- Resolved: the boot path stamps the resolved `vcpus`/`ram_mib` into
  `State.booted_*` (R2.6), so `status` reflects the live VM exactly — including
  env-override boots — rather than the next-boot resolution.
- Should `config set` warn when it changes a value that differs from the currently
  *running* VM's booted snapshot ("takes effect on next boot; current VM still
  runs at N")? Not implemented; the `saved: … (takes effect on next boot)` line
  already signals the deferral.

## Technical Considerations

- `data_volume_usage` uses `std::os::unix::fs::MetadataExt::blocks()` (unix-only;
  minvmd targets macOS + Linux). The default 256 GiB sparse volume means
  `disk_pressure` fires only on genuine near-full, which is intended.
- `sysinfo` is added with `default-features = false, features = ["system"]` to
  keep the dependency footprint to process + memory info.

## Security Considerations

- Metrics and warnings expose only host-visible aggregate resource figures for a
  process minvmd already owns; no new privileged access or guest data crosses the
  boundary. `config set` writes only within the provider-instance dir.

## Verification

| Req | Proof type | Command / observable |
|-----|------------|----------------------|
| R1.1 | Test | `cargo test -p minvmd metrics::tests::sample_of_self_returns_metrics` |
| R1.2/R1.3 | Test | `cargo test -p minvmd status::tests::report_schema_when_stopped_has_null_metrics_and_no_warnings` |
| R1.3 | CLI | `minvmd status --json \| jq .metrics` — object when running, `null` when stopped |
| R1.3/R9.1/R9.9 | E2E | `scripts/minvmd-lifecycle.sh` (KVM lane) asserts a live VM's `status --json` carries numeric `metrics.*` and a `warnings` array |
| R2.1 | Test | `cargo test -p minvmd config::tests` |
| R2.2 | Test | `cargo test -p minvmd cmd::config::tests::source_precedence_is_env_then_config_then_default` |
| R2.3/R2.4 | CLI | `minvmd config set --ram-mib 3072 && minvmd config show --json` |
| R2.5/R2.6 | E2E | `scripts/minvmd-lifecycle.sh` (KVM lane): `config set --ram-mib 3072` → `run --detach` → the running VM's `status --json` reports `ram_mib == 3072` (the persisted value, consumed at real boot) |
| R2.6 | Test | `cargo test -p minvmd status::tests::running_reports_booted_snapshot_not_next_boot_resolution` + `state::tests::pre_747_state_file_without_booted_fields_reads_as_none` |
| R3.1 | Test | `cargo test -p minvmd cmd::config::tests::over_core_and_over_mem_warn_but_succeed` |
| R3.2 | Test | `cargo test -p minvmd metrics::tests` (pressure thresholds) |
| R3.3 | Test | `cargo test -p minvmd status::tests::report_when_running_includes_metrics_and_pressure_warning` |
| R3.4 | Code | `crates/minvmd/src/cmd/run.rs` abnormal-exit hint |
