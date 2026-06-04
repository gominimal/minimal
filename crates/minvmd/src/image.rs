//! Kernel and rootfs image resolution.
//!
//! Paths are supplied at runtime via environment variables so the binary is
//! not tied to a fixed install layout.

use std::path::PathBuf;

use crate::error::VmError;

/// Arch-appropriate libkrun kernel format constant.
///
/// - `aarch64`: `virtio-linux` ships `Image.gz` → `KRUN_KERNEL_FORMAT_PE_GZ`.
///   The aarch64 loader implements only RAW and PE_GZ; PE_GZ decompresses the
///   gzipped image. `IMAGE_GZ` is x86_64-only and returns
///   `KernelFormatUnsupported` on aarch64.
/// - `x86_64`:  `virtio-linux` ships `bzImage`  → `KRUN_KERNEL_FORMAT_ELF`.
#[cfg(target_os = "macos")]
pub fn kernel_format() -> u32 {
    #[cfg(target_arch = "aarch64")]
    {
        crate::krun::KRUN_KERNEL_FORMAT_PE_GZ
    }
    #[cfg(target_arch = "x86_64")]
    {
        crate::krun::KRUN_KERNEL_FORMAT_ELF
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
/// Returns `VmError::MissingEnv` when the variable is unset or empty.
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

    #[cfg(target_os = "macos")]
    #[test]
    fn kernel_format_matches_arch() {
        let fmt = kernel_format();
        // aarch64 must use PE_GZ for Image.gz — IMAGE_GZ (=4) is x86_64-only and
        // returns KernelFormatUnsupported on the aarch64 libkrun loader.
        #[cfg(target_arch = "aarch64")]
        assert_eq!(fmt, crate::krun::KRUN_KERNEL_FORMAT_PE_GZ);
        #[cfg(target_arch = "x86_64")]
        assert_eq!(fmt, crate::krun::KRUN_KERNEL_FORMAT_ELF);
    }
}
