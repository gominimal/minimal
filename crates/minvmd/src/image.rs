//! Kernel and rootfs image resolution.
//!
//! Paths are supplied at runtime via environment variables so the binary is
//! not tied to a fixed install layout.

use std::path::PathBuf;

use crate::error::VmError;

/// Arch-appropriate libkrun kernel format.
///
/// - `aarch64`: the kernel is shipped **uncompressed** (`fetch-virtio-kernel.sh`
///   gunzips the upstream `Image.gz`) and loaded with `KernelFormat::Raw`.
///   Loading raw skips libkrun's gzip decompress, which measured ~77 ms (over
///   half of boot-to-READY) versus a `PeGz` `Image.gz`. The aarch64 loader
///   implements only RAW and PE_GZ.
/// - `x86_64`:  `virtio-linux` ships a `bzImage` → `KernelFormat::ImageGz`.
///   A bzImage is a PE/`MZ` container that embeds the `vmlinux` ELF as a
///   gzip member; libkrun's `ImageGz` loader scans for the gzip magic
///   (`1f 8b 08`), inflates that single member, and ELF-loads the result.
///   Loading it as `Elf` directly fails (`krun_start_enter` → EINVAL) because
///   the ELF loader is handed the PE container, not the inner vmlinux.
#[cfg(minvmd_libkrun)]
pub fn kernel_format() -> crate::krun::KernelFormat {
    #[cfg(target_arch = "aarch64")]
    {
        crate::krun::KernelFormat::Raw
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::krun::KernelFormat::ImageGz
    }
}

/// Resolve the kernel path from `MINVMD_KERNEL_PATH`.
///
/// Returns `VmError::MissingEnv` when the variable is unset or empty.
pub fn resolve_kernel_path() -> Result<PathBuf, VmError> {
    let val = std::env::var("MINVMD_KERNEL_PATH").map_err(|_| VmError::MissingEnv {
        var: "MINVMD_KERNEL_PATH",
    })?;
    if val.is_empty() {
        return Err(VmError::MissingEnv {
            var: "MINVMD_KERNEL_PATH",
        });
    }
    Ok(PathBuf::from(val))
}

/// Resolve the rootfs path from `MINVMD_ROOTFS_PATH`.
///
/// This is the path to a read-only ext4 root disk image (loaded via
/// `krun_add_disk2`), not a directory. Returns `VmError::MissingEnv` when the
/// variable is unset or empty.
pub fn resolve_rootfs_path() -> Result<PathBuf, VmError> {
    let val = std::env::var("MINVMD_ROOTFS_PATH").map_err(|_| VmError::MissingEnv {
        var: "MINVMD_ROOTFS_PATH",
    })?;
    if val.is_empty() {
        return Err(VmError::MissingEnv {
            var: "MINVMD_ROOTFS_PATH",
        });
    }
    Ok(PathBuf::from(val))
}

/// Resolve the initramfs path from `MINVMD_INITRAMFS`.
///
/// This is the cpio initramfs whose `/init` is minimald (booted as pid-1).
/// Returns `VmError::MissingEnv` when the variable is unset or empty.
pub fn resolve_initramfs_path() -> Result<PathBuf, VmError> {
    let val = std::env::var("MINVMD_INITRAMFS").map_err(|_| VmError::MissingEnv {
        var: "MINVMD_INITRAMFS",
    })?;
    if val.is_empty() {
        return Err(VmError::MissingEnv {
            var: "MINVMD_INITRAMFS",
        });
    }
    Ok(PathBuf::from(val))
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Serialise all tests that mutate MINVMD_KERNEL_PATH so they don't race
    // when `cargo test` runs them in parallel.
    static KERNEL_PATH_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn resolve_kernel_path_errors_on_missing_env() {
        let _g = KERNEL_PATH_LOCK.lock().unwrap();
        unsafe { std::env::remove_var("MINVMD_KERNEL_PATH") };
        let err = resolve_kernel_path().unwrap_err();
        assert!(
            matches!(
                err,
                VmError::MissingEnv {
                    var: "MINVMD_KERNEL_PATH"
                }
            ),
            "expected MissingEnv, got {err:?}"
        );
    }

    #[test]
    fn resolve_kernel_path_returns_path_when_set() {
        let _g = KERNEL_PATH_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_KERNEL_PATH", "/boot/Image.gz") };
        let path = resolve_kernel_path().unwrap();
        assert_eq!(path, std::path::PathBuf::from("/boot/Image.gz"));
        unsafe { std::env::remove_var("MINVMD_KERNEL_PATH") };
    }

    #[test]
    fn resolve_kernel_path_errors_on_empty_env() {
        let _g = KERNEL_PATH_LOCK.lock().unwrap();
        unsafe { std::env::set_var("MINVMD_KERNEL_PATH", "") };
        let err = resolve_kernel_path().unwrap_err();
        assert!(
            matches!(
                err,
                VmError::MissingEnv {
                    var: "MINVMD_KERNEL_PATH"
                }
            ),
            "expected MissingEnv, got {err:?}"
        );
        unsafe { std::env::remove_var("MINVMD_KERNEL_PATH") };
    }

    #[test]
    fn resolve_rootfs_path_errors_on_missing_env() {
        unsafe { std::env::remove_var("MINVMD_ROOTFS_PATH") };
        let err = resolve_rootfs_path().unwrap_err();
        assert!(
            matches!(
                err,
                VmError::MissingEnv {
                    var: "MINVMD_ROOTFS_PATH"
                }
            ),
            "expected MissingEnv, got {err:?}"
        );
    }

    #[cfg(minvmd_libkrun)]
    #[test]
    fn kernel_format_matches_arch() {
        let fmt = kernel_format();
        // aarch64 ships the uncompressed Image → RAW (skips the libkrun gzip
        // decompress). x86_64 ships a bzImage → IMAGE_GZ (libkrun inflates the
        // embedded gzip vmlinux and ELF-loads it).
        #[cfg(target_arch = "aarch64")]
        assert_eq!(fmt, crate::krun::KernelFormat::Raw);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(fmt, crate::krun::KernelFormat::ImageGz);
    }
}
