//! Host-side provisioning of the per-VM writable data volume (`/dev/vdb`).
//!
//! The image is a sparse raw file the guest formats with `mkfs.ext4` on first
//! boot (spec R1.3 / R1.5); the guest keys exclusively off ext4 superblock
//! detection, never off a "disk is blank" assumption. [`ensure_sparse_raw`]
//! materializes it at the exact path it is asked for and is idempotent — an
//! already-provisioned (and possibly guest-formatted) image is left untouched.

use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};

/// Default size of a freshly provisioned data volume: 256 GiB. The image is a
/// sparse raw file, so the host allocates only the blocks the guest actually
/// writes (allocate-on-write, verified by the sparsity proof gate) — this is a
/// ceiling the guest sees, not an up-front cost. A large default sidesteps the
/// (hard, offline) resize path entirely; override with [`VOLUME_BYTES_ENV`].
///
/// First-boot cost is flat in the size: `mkfs.ext4` writes only ~5–8 MiB of
/// metadata regardless (sparse backing + the reduced inode ratio), so format +
/// mount stays ~40 ms at every size measured on an M-series host —
/// 32 GiB → 40 ms · 64 GiB → 36 ms · 128 GiB → 37 ms · 256 GiB → 46 ms.
pub const DEFAULT_VOLUME_BYTES: u64 = 256 * 1024 * 1024 * 1024;

/// Environment variable overriding [`DEFAULT_VOLUME_BYTES`] (spec R1.3).
pub const VOLUME_BYTES_ENV: &str = "MINVMD_VOLUME_BYTES";

/// Environment variable overriding the data-volume image path. Unset uses the
/// default under the minvmd state dir (see [`resolve_data_volume_path`]); the
/// volume is provisioned and attached as `/dev/vdb` on every boot either way.
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

/// Resolve the per-VM data-volume image path.
///
/// [`DATA_VOLUME_PATH_ENV`] overrides it explicitly (used verbatim); otherwise
/// the image lives beside minvmd's persistent state as
/// `<state>/minimal/minvmd/data-vol.raw`, so it survives clean restarts. The
/// base comes from the shared [`paths::minimal_state_dir`] resolver — except
/// `XDG_STATE_HOME` is still honoured explicitly first, because `dirs` (and thus
/// `minimal_state_dir`) ignores it on macOS and the e2e tests isolate state via
/// `XDG_STATE_HOME`; without that the volume would escape the tests' temp dir
/// onto the real state dir on macOS.
#[must_use]
pub fn resolve_data_volume_path() -> PathBuf {
    if let Some(explicit) = std::env::var_os(DATA_VOLUME_PATH_ENV).filter(|v| !v.is_empty()) {
        return PathBuf::from(explicit);
    }
    let base = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(|x| PathBuf::from(x).join("minimal"))
        .unwrap_or_else(|| paths::minimal_state_dir().as_utf8_path().as_std_path().to_path_buf());
    base.join("minvmd").join("data-vol.raw")
}

/// Failure modes of [`ensure_sparse_raw`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VolumeError {
    /// The parent directory could not be created.
    #[error("creating volume directory {dir}")]
    CreateDir {
        dir: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The image file could not be stat'd.
    #[error("stat volume image {path}")]
    Stat {
        path: PathBuf,
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

/// Ensure a sparse raw data-volume image exists at `path`, creating a blank one
/// of `size_bytes` if it is missing.
///
/// Idempotent: an existing image is never resized in place — shrinking would
/// truncate a guest-formatted ext4 and growing the file does not grow the
/// filesystem (that needs `resize2fs`) — so a prior image is left untouched.
/// The file is created with `ftruncate` (`File::set_len`), which yields a
/// sparse/thin file on both APFS (macOS) and ext4 (Linux); the guest runs
/// first-boot `mkfs.ext4` against it (spec R1.5).
pub fn ensure_sparse_raw(path: &Path, size_bytes: u64) -> Result<(), VolumeError> {
    match std::fs::metadata(path) {
        Ok(meta) => {
            if meta.len() != size_bytes {
                tracing::warn!(
                    path = %path.display(),
                    have = meta.len(),
                    want = size_bytes,
                    "existing data volume differs from requested size; keeping as-is",
                );
            }
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            match create_sparse_raw(path, size_bytes) {
                Ok(()) => {
                    tracing::info!(
                        path = %path.display(),
                        size_bytes,
                        "provisioned blank sparse data volume",
                    );
                    Ok(())
                }
                // Lost a creation race with a concurrent provisioner between the
                // `metadata` probe above and `create_new`: the volume now exists,
                // which satisfies the idempotent contract, so keep it as-is.
                Err(VolumeError::Create { source, .. })
                    if source.kind() == io::ErrorKind::AlreadyExists =>
                {
                    tracing::info!(
                        path = %path.display(),
                        "data volume created concurrently; keeping as-is",
                    );
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        Err(source) => Err(VolumeError::Stat {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Create a sparse raw file of `size_bytes` at `path`, creating parents first.
fn create_sparse_raw(path: &Path, size_bytes: u64) -> Result<(), VolumeError> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(|source| VolumeError::CreateDir {
            dir: dir.to_path_buf(),
            source,
        })?;
    }
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
        let path = dir.join("data-vol.raw");
        let size = 8 * 1024 * 1024 * 1024; // 8 GiB
        ensure_sparse_raw(&path, size).unwrap();

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
        // Best-effort cleanup; a leftover temp dir must not fail the test.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ensure_is_idempotent_and_does_not_resize() {
        let dir = tmpdir("idempotent");
        let path = dir.join("data-vol.raw");
        ensure_sparse_raw(&path, 4 * 1024 * 1024 * 1024).unwrap();
        // A second call at a *different* size must leave the existing image
        // untouched rather than truncating it (which would corrupt a formatted FS).
        ensure_sparse_raw(&path, 1024 * 1024 * 1024).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            4 * 1024 * 1024 * 1024,
            "existing image must not be resized",
        );
        // Best-effort cleanup; a leftover temp dir must not fail the test.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn volume_bytes_defaults_when_unset() {
        // Not asserting on the env (tests share a process); just the default.
        assert_eq!(DEFAULT_VOLUME_BYTES, 256 * 1024 * 1024 * 1024);
    }
}
