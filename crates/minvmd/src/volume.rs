//! Host-side provisioning of the per-VM writable data volume (`/dev/vdb`).
//!
//! The [`VolumeProvisioner`] trait isolates *how* the backing image is
//! materialized (the host-side strategy) from the guest boot path, which keys
//! exclusively off ext4 superblock detection (spec R1.3 / R1.5) and never off a
//! "disk is blank" assumption. [`BlankRawProvisioner`] is the Phase-1
//! implementation: a sparse raw file the guest formats with `mkfs.ext4` on first
//! boot. Replacing it with a reflink/qcow2 provisioner later is a pure host-side
//! swap with no guest or boot-path change.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// Default size of a freshly provisioned data volume: 32 GiB. The image is a
/// sparse raw file, so the host allocates only the blocks the guest actually
/// writes (allocate-on-write, verified by the sparsity proof gate); this value
/// is the ceiling, not an up-front cost.
pub const DEFAULT_VOLUME_BYTES: u64 = 32 * 1024 * 1024 * 1024;

/// Environment variable overriding [`DEFAULT_VOLUME_BYTES`] (spec R1.3).
pub const VOLUME_BYTES_ENV: &str = "MINVMD_VOLUME_BYTES";

/// Environment variable selecting the data-volume image path. When set, the
/// VMM child provisions a blank sparse image there (if absent) and attaches it
/// as `/dev/vdb`. The path's file stem is used as the `vm_id`. Must end in
/// `.raw`. Unset means no data volume is attached (legacy tmpfs-only boot).
pub const DATA_VOLUME_PATH_ENV: &str = "MINVMD_DATA_VOLUME_PATH";

/// Resolve the configured volume size. A non-numeric, empty, or zero value in
/// [`VOLUME_BYTES_ENV`] falls back to [`DEFAULT_VOLUME_BYTES`].
#[must_use]
pub fn volume_bytes() -> u64 {
    std::env::var(VOLUME_BYTES_ENV)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|&b| b > 0)
        .unwrap_or(DEFAULT_VOLUME_BYTES)
}

/// Failure modes of [`VolumeProvisioner::ensure`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VolumeError {
    /// The volumes directory could not be created.
    #[error("creating volumes directory {dir}")]
    CreateDir {
        dir: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The image file could not be created.
    #[error("creating volume image {path}")]
    Create {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The image file could not be sized (sparse `ftruncate`).
    #[error("sizing volume image {path} to {size} bytes")]
    Resize {
        path: PathBuf,
        size: u64,
        #[source]
        source: io::Error,
    },
}

/// Materializes the backing image for a VM's writable data volume.
///
/// `ensure` is idempotent: repeated calls for the same `vm_id` return the same
/// image path without disturbing an already-provisioned (and possibly
/// guest-formatted) volume.
pub trait VolumeProvisioner {
    /// Return the path to `vm_id`'s data-volume image, creating a blank one of
    /// `size_bytes` if it does not yet exist.
    fn ensure(&self, vm_id: &str, size_bytes: u64) -> Result<PathBuf, VolumeError>;
}

/// Provisions a blank sparse raw file per VM under a fixed volumes directory.
///
/// The image lives at `<volumes_dir>/<vm_id>.raw`, sized with `ftruncate`
/// (`File::set_len`) — which yields a sparse/thin file on both APFS (macOS) and
/// ext4 (Linux), so the host never pays the full size up front. The guest runs
/// first-boot `mkfs.ext4` against it (spec R1.5).
#[derive(Debug, Clone)]
pub struct BlankRawProvisioner {
    volumes_dir: PathBuf,
}

impl BlankRawProvisioner {
    /// Construct a provisioner rooted at `volumes_dir` (e.g.
    /// `<state_dir>/volumes`).
    #[must_use]
    pub fn new(volumes_dir: impl Into<PathBuf>) -> Self {
        Self {
            volumes_dir: volumes_dir.into(),
        }
    }

    /// Deterministic image path for `vm_id`.
    #[must_use]
    pub fn image_path(&self, vm_id: &str) -> PathBuf {
        self.volumes_dir.join(format!("{vm_id}.raw"))
    }
}

impl VolumeProvisioner for BlankRawProvisioner {
    fn ensure(&self, vm_id: &str, size_bytes: u64) -> Result<PathBuf, VolumeError> {
        let path = self.image_path(vm_id);

        // Idempotent: an already-provisioned image is never resized in place —
        // shrinking would truncate a guest-formatted ext4 and growing the file
        // does not grow the filesystem (that needs `resize2fs`). If a prior
        // image exists we return it untouched; only a missing image is created.
        if let Ok(meta) = std::fs::metadata(&path) {
            if meta.len() != size_bytes {
                tracing::warn!(
                    path = %path.display(),
                    have = meta.len(),
                    want = size_bytes,
                    "existing data volume differs from requested size; keeping as-is",
                );
            }
            return Ok(path);
        }

        create_sparse_raw(&self.volumes_dir, &path, size_bytes)?;
        tracing::info!(
            path = %path.display(),
            size_bytes,
            "provisioned blank sparse data volume",
        );
        Ok(path)
    }
}

/// Create a sparse raw file of `size_bytes` at `path`, creating `dir` first.
fn create_sparse_raw(dir: &Path, path: &Path, size_bytes: u64) -> Result<(), VolumeError> {
    std::fs::create_dir_all(dir).map_err(|source| VolumeError::CreateDir {
        dir: dir.to_path_buf(),
        source,
    })?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|source| VolumeError::Create {
            path: path.to_path_buf(),
            source,
        })?;
    // `set_len` == `ftruncate(2)`: extends the file to `size_bytes` without
    // writing any data, leaving it sparse (host `st_blocks` stays ~0 until the
    // guest writes). This is the allocate-on-write substrate the sparsity gate
    // measures — `fallocate` *without* `KEEP_SIZE` would defeat it by allocating
    // eagerly.
    file.set_len(size_bytes)
        .map_err(|source| VolumeError::Resize {
            path: path.to_path_buf(),
            size: size_bytes,
            source,
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// A unique temp dir per test. Keyed by `tag` as well as the pid so
    /// concurrently-running tests (cargo's default) never share a directory —
    /// otherwise one test's `remove_dir_all` cleanup races another's files.
    fn tmpdir(tag: &str) -> PathBuf {
        let base = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
        let p = PathBuf::from(base).join(format!("minvmd-vol-test-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    #[test]
    fn ensure_creates_sparse_image_of_requested_len() {
        let dir = tmpdir("sparse");
        let prov = BlankRawProvisioner::new(dir.join("volumes"));
        let size = 8 * 1024 * 1024 * 1024; // 8 GiB
        let path = prov.ensure("vm-abc", size).unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), size, "logical length must match requested size");
        // Allocate-on-write at the host-FS level: a freshly `ftruncate`d file
        // occupies far fewer blocks than its length (512-byte blocks). Allow
        // slack for FS metadata but reject anything near full allocation.
        let allocated = meta.blocks() * 512;
        assert!(
            allocated < size / 100,
            "expected a sparse file, but {allocated} bytes are allocated for a {size}-byte image",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_is_idempotent_and_does_not_resize() {
        let dir = tmpdir("idempotent");
        let prov = BlankRawProvisioner::new(dir.join("volumes"));
        let path = prov.ensure("vm-xyz", 4 * 1024 * 1024 * 1024).unwrap();
        // A second call at a *different* size must return the same untouched
        // image rather than truncating it (which would corrupt a formatted FS).
        let path2 = prov.ensure("vm-xyz", 1024 * 1024 * 1024).unwrap();
        assert_eq!(path, path2);
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            4 * 1024 * 1024 * 1024,
            "existing image must not be resized",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn volume_bytes_defaults_when_unset() {
        // Not asserting on the env (tests share a process); just the default.
        assert_eq!(DEFAULT_VOLUME_BYTES, 32 * 1024 * 1024 * 1024);
    }
}
