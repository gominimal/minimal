//! Host-side resource sampling of the VMM process (#747, R9.1).
//!
//! [`sample`] reads live CPU / resident-memory / disk-I/O for a PID — the VMM
//! child (`State.vmm_pid`) that libkrun runs the guest inside, so its
//! host-visible usage reflects the VM. These are **host-process** metrics, not
//! guest-internal per-process metrics (minvmd runs no in-guest agent).
//!
//! Deliberately raw: there is no host-side *pressure* threshold. Guest memory
//! and disk pressure cannot be measured accurately from the host — the VMM's RSS
//! includes the guest's reclaimable page cache (so it approaches the cap for any
//! long-running VM), and the data volume's host allocation is a monotonic
//! high-water mark, not the guest ext4's free space. The reliable reactive
//! resource signal is instead the supervisor's abnormal-exit hint
//! (`cmd::run`), which fires on a guest workload's non-zero exit.

use serde::Serialize;

/// Live host-visible resource usage of the VMM process.
#[derive(Debug, Clone, Serialize)]
pub struct VmMetrics {
    /// CPU utilisation as a percentage. Summed across cores, so a multi-vcpu VM
    /// under load can exceed 100.
    pub cpu_percent: f32,
    /// Resident set size in bytes. Host-visible; includes guest-touched RAM
    /// pages (anonymous *and* page cache), so it trends toward the RAM cap on a
    /// long-running VM and is not a memory-pressure signal.
    pub resident_bytes: u64,
    /// Cumulative bytes read from disk since the VMM process started.
    pub disk_read_bytes: u64,
    /// Cumulative bytes written to disk since the VMM process started.
    pub disk_written_bytes: u64,
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
}
