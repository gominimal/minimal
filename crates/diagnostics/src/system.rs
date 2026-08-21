//! Host system identity and capability probe for diagnostic bundles.
//!
//! Every binary that produces a bundle wants the same opening facts — what
//! OS/arch/kernel is this, who is running it, can it virtualize, how full
//! are the disks that matter. The probe is the mechanic; *which* disks
//! matter is the caller's policy, passed in as paths.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

/// Timeout for single-fact commands like `uname`; a wedged tool must not
/// eat a collector's whole budget.
const FACT_TIMEOUT: Duration = Duration::from_secs(5);

/// The opening facts of a diagnostic bundle. Every probe is best-effort:
/// a field that cannot be read is `None`, never an error.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct SystemInfo {
    pub os: &'static str,
    pub arch: &'static str,
    pub kernel: Option<String>,
    pub hostname: Option<String>,
    pub ncpu: Option<usize>,
    /// Total physical memory. A bundle records what a session asked the VM
    /// for; without the host's own number that figure cannot be judged
    /// oversized, and "the machine died under a 24 GiB allocation" stays a
    /// guess.
    pub mem_total_bytes: Option<u64>,
    pub euid: u32,
    #[cfg(target_os = "linux")]
    pub kvm: KvmInfo,
    pub disks: Vec<DiskInfo>,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct KvmInfo {
    pub exists: bool,
    /// `ok` / `enoent` / `eacces` / other errno string — ENOENT means the
    /// module isn't loaded, EACCES means the user isn't in the kvm group.
    pub open_result: String,
    pub mode: Option<String>,
    pub owner_gid: Option<u32>,
    pub user_in_kvm_group: Option<bool>,
}

/// Capacity of one caller-chosen path's filesystem, `None`s when the path
/// doesn't exist (which is itself data).
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct DiskInfo {
    pub path: String,
    pub total_bytes: Option<u64>,
    pub free_bytes: Option<u64>,
}

/// Gathers [`SystemInfo`], probing the filesystems holding `disk_paths`
/// (the caller's policy: state dir, cache dir, the bundle's destination —
/// whatever disk-full would break for that binary).
pub async fn system_info(disk_paths: &[&Path]) -> SystemInfo {
    let kernel = crate::first_stdout_line("uname", &["-srvm"], FACT_TIMEOUT).await;
    let hostname = crate::first_stdout_line("uname", &["-n"], FACT_TIMEOUT).await;
    SystemInfo {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        kernel,
        hostname,
        ncpu: std::thread::available_parallelism().map(usize::from).ok(),
        mem_total_bytes: mem_total_bytes().await,
        // SAFETY: geteuid has no failure modes or preconditions.
        euid: unsafe { libc::geteuid() },
        #[cfg(target_os = "linux")]
        kvm: kvm_info(),
        disks: disk_paths.iter().map(|p| disk_info(p)).collect(),
    }
}

/// Total physical memory in bytes, from `hw.memsize`.
#[cfg(target_os = "macos")]
async fn mem_total_bytes() -> Option<u64> {
    crate::first_stdout_line("sysctl", &["-n", "hw.memsize"], FACT_TIMEOUT)
        .await?
        .trim()
        .parse()
        .ok()
}

/// Total physical memory in bytes, from `/proc/meminfo`'s `MemTotal:` (which
/// counts kibibytes). `None` anywhere `/proc` isn't the answer — best-effort,
/// like every other probe here.
#[cfg(not(target_os = "macos"))]
async fn mem_total_bytes() -> Option<u64> {
    tokio::fs::read_to_string("/proc/meminfo")
        .await
        .ok()?
        .lines()
        .find_map(|line| line.strip_prefix("MemTotal:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()
        .map(|kib| kib * 1024)
}

fn disk_info(path: &Path) -> DiskInfo {
    let usage = crate::disk_usage(path);
    DiskInfo {
        path: path.display().to_string(),
        total_bytes: usage.map(|u| u.total_bytes),
        free_bytes: usage.map(|u| u.free_bytes),
    }
}

#[cfg(target_os = "linux")]
fn kvm_info() -> KvmInfo {
    use std::os::unix::fs::MetadataExt as _;
    let meta = std::fs::metadata("/dev/kvm").ok();
    let open_result = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
    {
        Ok(_) => "ok".to_string(),
        Err(e) => match e.kind() {
            std::io::ErrorKind::NotFound => "enoent".to_string(),
            std::io::ErrorKind::PermissionDenied => "eacces".to_string(),
            _ => e.to_string(),
        },
    };
    KvmInfo {
        exists: meta.is_some(),
        open_result,
        mode: meta.as_ref().map(|m| format!("{:o}", m.mode())),
        owner_gid: meta.as_ref().map(|m| m.gid()),
        user_in_kvm_group: user_in_group("kvm"),
    }
}

/// Whether the current user's supplementary groups include `name`.
/// `None` when the group doesn't exist or the group list can't be read.
#[cfg(target_os = "linux")]
fn user_in_group(name: &str) -> Option<bool> {
    let c_name = std::ffi::CString::new(name).ok()?;
    // SAFETY: getgrnam reads a NUL-terminated string; the returned struct is
    // a static buffer only read before any other getgr* call in this thread.
    let grp = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if grp.is_null() {
        return None;
    }
    // SAFETY: non-null getgrnam result points to a valid `group`.
    let target_gid = unsafe { (*grp).gr_gid };

    // SAFETY: first call sizes the buffer, second fills it.
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 {
        return None;
    }
    let mut gids = vec![0 as libc::gid_t; n as usize];
    // SAFETY: buffer is exactly the size getgroups asked for.
    let n = unsafe { libc::getgroups(n, gids.as_mut_ptr()) };
    if n < 0 {
        return None;
    }
    gids.truncate(n as usize);
    // SAFETY: getegid has no failure modes.
    let egid = unsafe { libc::getegid() };
    Some(gids.contains(&target_gid) || egid == target_gid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probes_are_best_effort_and_disks_follow_caller_paths() {
        let tmp = tempfile::TempDir::new().unwrap();
        let info = system_info(&[tmp.path(), Path::new("/nonexistent/diag-x")]).await;
        assert_eq!(info.os, std::env::consts::OS);
        assert_eq!(info.disks.len(), 2);
        assert!(info.disks[0].total_bytes.is_some());
        assert!(
            info.disks[1].total_bytes.is_none(),
            "a missing path is Nones, not an error"
        );
        let json = serde_json_lenient::to_value(&info).unwrap();
        assert!(json["euid"].is_u64());
        // A VM sizing recorded elsewhere in the bundle is only judgeable
        // against the host's own memory, so the probe has to land where the
        // platform can answer it.
        assert!(info.mem_total_bytes.is_none_or(|bytes| bytes > 0));
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert!(
            info.mem_total_bytes.is_some(),
            "linux and macOS both report total memory"
        );
    }
}
