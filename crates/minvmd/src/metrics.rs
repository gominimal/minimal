//! Host-side resource sampling and reactive warnings for the VMM process (#747,
//! R9.1, R9.9).
//!
//! [`sample`] reads live CPU / resident-memory / disk-I/O for a PID — the VMM
//! child (`State.vmm_pid`) that libkrun runs the guest inside, so its
//! host-visible usage reflects the VM. These are **host-process** metrics, not
//! guest-internal per-process metrics (minvmd runs no in-guest agent).
//!
//! [`evaluate_warnings`] turns a sample plus the configured caps into reactive
//! threshold warnings (memory near its RAM cap, data volume near full), the
//! host-observable analog of `minimal-vm-mac`'s in-guest OOM / `df` post-mortem.

use serde::Serialize;

/// Live host-visible resource usage of the VMM process.
#[derive(Debug, Clone, Serialize)]
pub struct VmMetrics {
    /// CPU utilisation as a percentage. Summed across cores, so a multi-vcpu VM
    /// under load can exceed 100.
    pub cpu_percent: f32,
    /// Resident set size in bytes (includes guest-touched RAM pages).
    pub resident_bytes: u64,
    /// Cumulative bytes read from disk since the VMM process started.
    pub disk_read_bytes: u64,
    /// Cumulative bytes written to disk since the VMM process started.
    pub disk_written_bytes: u64,
}

/// A reactive resource warning naming the knob to raise.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Warning {
    /// Stable machine-readable discriminant (`memory_pressure`, `disk_pressure`).
    pub kind: &'static str,
    /// Human-readable guidance.
    pub message: String,
}

/// Resident memory at or above this percentage of the RAM cap raises
/// `memory_pressure`.
pub const MEM_PRESSURE_PCT: u64 = 90;

/// Data-volume allocation at or above this percentage of its cap raises
/// `disk_pressure` (mirrors `minimal-vm-mac`'s `df … ≥95%`).
pub const DISK_PRESSURE_PCT: u64 = 95;

/// Sample live resource usage for `pid`. Returns `None` when no such process
/// exists (e.g. the VM is stopped or the PID is stale).
///
/// A meaningful `cpu_percent` needs two samples spaced by sysinfo's minimum CPU
/// update interval, so this blocks for ~[`sysinfo::MINIMUM_CPU_UPDATE_INTERVAL`].
/// Reading process stats does not disturb the running VM (R9.2).
#[must_use]
pub fn sample(pid: u32) -> Option<VmMetrics> {
    use sysinfo::{MINIMUM_CPU_UPDATE_INTERVAL, Pid, ProcessesToUpdate, System};

    let pid = Pid::from_u32(pid);
    let targets = ProcessesToUpdate::Some(&[pid]);

    let mut sys = System::new();
    // First refresh seeds the CPU baseline; the process must exist now.
    sys.refresh_processes(targets, true);
    sys.process(pid)?;
    // Second refresh after the minimum interval yields a real CPU delta.
    std::thread::sleep(MINIMUM_CPU_UPDATE_INTERVAL);
    sys.refresh_processes(targets, true);
    let proc = sys.process(pid)?;

    let disk = proc.disk_usage();
    Some(VmMetrics {
        cpu_percent: proc.cpu_usage(),
        resident_bytes: proc.memory(),
        disk_read_bytes: disk.total_read_bytes,
        disk_written_bytes: disk.total_written_bytes,
    })
}

/// The data volume's `(used_bytes, cap_bytes)`: actual on-disk allocation of the
/// sparse image (`blocks × 512`, real consumption not the apparent size) against
/// the image's own size. The cap is the image's apparent length (`len`), fixed
/// when `ensure_sparse_raw` created it and never resized — the true ext4 ceiling
/// — rather than `volume_bytes()`, which would drift if `MINVMD_VOLUME_BYTES`
/// changed after creation. `None` when the image is absent.
#[must_use]
pub fn data_volume_usage() -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt as _;

    let path = crate::volume::resolve_data_volume_path();
    let meta = std::fs::metadata(&path).ok()?;
    Some((meta.blocks() * 512, meta.len()))
}

/// Evaluate reactive threshold warnings from a live sample and the configured
/// caps (R9.9). Pure: caps and usage are passed in, so it is unit-testable
/// without a live VM. `disk_cap == 0` disables the disk check.
#[must_use]
pub fn evaluate_warnings(
    metrics: &VmMetrics,
    ram_mib: u32,
    disk_used: u64,
    disk_cap: u64,
) -> Vec<Warning> {
    let mut warnings = Vec::new();

    let ram_bytes = u64::from(ram_mib) * 1024 * 1024;
    if ram_bytes > 0 && metrics.resident_bytes * 100 >= ram_bytes * MEM_PRESSURE_PCT {
        let pct = metrics.resident_bytes * 100 / ram_bytes;
        warnings.push(Warning {
            kind: "memory_pressure",
            message: format!(
                "VM resident memory is {pct}% of its {ram_mib} MiB allocation; \
                 raise it with `minvmd config set --ram-mib <MiB>` if builds are OOM-killed"
            ),
        });
    }

    if disk_cap > 0 && disk_used * 100 >= disk_cap * DISK_PRESSURE_PCT {
        let pct = disk_used * 100 / disk_cap;
        warnings.push(Warning {
            kind: "disk_pressure",
            message: format!(
                "data volume is {pct}% full; raise the cap with `{}=<bytes>`",
                crate::volume::VOLUME_BYTES_ENV
            ),
        });
    }

    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics_with_rss(resident_bytes: u64) -> VmMetrics {
        VmMetrics {
            cpu_percent: 0.0,
            resident_bytes,
            disk_read_bytes: 0,
            disk_written_bytes: 0,
        }
    }

    #[test]
    fn sample_of_self_returns_metrics() {
        // The current process is guaranteed to exist and be sampleable on any
        // supported platform.
        let m = sample(std::process::id()).expect("self-sample must succeed");
        assert!(m.resident_bytes > 0, "own RSS must be non-zero");
    }

    #[test]
    fn sample_of_absent_pid_returns_none() {
        // PID 0 is never a real user process to sample.
        assert!(sample(0).is_none());
    }

    #[test]
    fn memory_pressure_fires_at_or_above_threshold() {
        // 1000 MiB divides evenly by 100, so exactly-90% has no truncation slack.
        let cap_mib = 1000u32;
        let ram_bytes = u64::from(cap_mib) * 1024 * 1024;
        let at_threshold = ram_bytes * MEM_PRESSURE_PCT / 100; // exactly 90%
        let warns = evaluate_warnings(&metrics_with_rss(at_threshold), cap_mib, 0, 0);
        assert_eq!(warns.len(), 1);
        assert_eq!(warns[0].kind, "memory_pressure");
        assert!(
            warns[0].message.contains("90%"),
            "got: {}",
            warns[0].message
        );
    }

    #[test]
    fn memory_pressure_absent_below_threshold() {
        let cap_mib = 1000u32;
        let ram_bytes = u64::from(cap_mib) * 1024 * 1024;
        let below = ram_bytes / 2; // 50%
        let warns = evaluate_warnings(&metrics_with_rss(below), cap_mib, 0, 0);
        assert!(warns.is_empty(), "50% must not warn: {warns:?}");
    }

    #[test]
    fn disk_pressure_fires_at_or_above_threshold() {
        let cap = 100_000u64;
        let used = cap * DISK_PRESSURE_PCT / 100; // exactly 95%
        let warns = evaluate_warnings(&metrics_with_rss(0), 1, used, cap);
        assert_eq!(warns.len(), 1);
        assert_eq!(warns[0].kind, "disk_pressure");
        assert!(
            warns[0].message.contains("95%"),
            "got: {}",
            warns[0].message
        );
    }

    #[test]
    fn disk_pressure_absent_below_threshold_and_when_cap_zero() {
        let cap = 100_000u64;
        let warns = evaluate_warnings(&metrics_with_rss(0), 1, cap / 2, cap);
        assert!(warns.is_empty(), "50% full must not warn");
        // cap == 0 (unknown) disables the check without a divide-by-zero.
        let warns = evaluate_warnings(&metrics_with_rss(0), 1, 999, 0);
        assert!(warns.is_empty(), "unknown cap must not warn");
    }
}
