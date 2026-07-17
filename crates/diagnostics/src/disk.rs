//! Filesystem capacity probes for diagnostic bundles.
//!
//! Disk exhaustion is a perennial root cause; every bundle producer wants
//! "how full is the filesystem holding X" without shelling out to `df`.

use std::path::Path;

/// Capacity of the filesystem holding a path.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct DiskUsage {
    pub total_bytes: u64,
    /// Bytes available to an unprivileged caller (`f_bavail`, not
    /// `f_bfree`) — the number that predicts the next write failing.
    pub free_bytes: u64,
}

/// The capacity of the filesystem holding `path`, or `None` when the path
/// doesn't exist or can't be statted — for a collector, "unknown" is data.
pub fn disk_usage(path: &Path) -> Option<DiskUsage> {
    use std::os::unix::ffi::OsStrExt as _;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid NUL-terminated path and out-pointer to a zeroed struct.
    if unsafe { libc::statvfs(c_path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let frsize = stat.f_frsize as u64;
    Some(DiskUsage {
        total_bytes: stat.f_blocks as u64 * frsize,
        free_bytes: stat.f_bavail as u64 * frsize,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_path_reports_nonzero_capacity() {
        let tmp = tempfile::TempDir::new().unwrap();
        let usage = disk_usage(tmp.path()).expect("tempdir filesystem is stattable");
        assert!(usage.total_bytes > 0);
        assert!(usage.free_bytes <= usage.total_bytes);
    }

    #[test]
    fn missing_path_is_none() {
        assert!(disk_usage(Path::new("/nonexistent/diag-disk-probe")).is_none());
    }
}
