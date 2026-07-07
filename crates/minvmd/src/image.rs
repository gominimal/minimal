//! Kernel and rootfs image resolution.
//!
//! Paths are supplied at runtime via environment variables. When an override is
//! unset, each resolver falls back to the file the installer stamps into the
//! minimal data directory (`$XDG_DATA_HOME/minimal`, else
//! `$HOME/.local/share/minimal`) — but only when that file actually exists, so
//! a default install works with no env setup while a genuinely missing image
//! still errors rather than silently returning a non-existent path.

use std::path::PathBuf;

use crate::error::VmError;

/// Filenames the installer stamps into the `data/` prefix. Kept in sync with
/// `scripts/stage-release.sh` (`data/vmlinuz`, `data/rootfs.img`,
/// `data/initramfs.cpio`).
const DEFAULT_KERNEL_FILE: &str = "vmlinuz";
const DEFAULT_ROOTFS_FILE: &str = "rootfs.img";
const DEFAULT_INITRAMFS_FILE: &str = "initramfs.cpio";

/// The minimal data directory: `$XDG_DATA_HOME/minimal`, else
/// `$HOME/.local/share/minimal`. Mirrors the installer's `data` prefix
/// resolution in `scripts/install.sh`. `None` when neither `XDG_DATA_HOME` nor
/// `HOME` is set, so no default location can be computed.
fn data_dir() -> Option<PathBuf> {
    if let Some(xdg) = std::env::var("XDG_DATA_HOME")
        .ok()
        .filter(|v| !v.is_empty())
    {
        return Some(PathBuf::from(xdg).join("minimal"));
    }
    std::env::var("HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|home| PathBuf::from(home).join(".local/share/minimal"))
}

/// Return the override in `var` when set and non-empty (used verbatim, without
/// an existence check — the caller owns an explicit path). Otherwise fall back
/// to `<data-dir>/default_file`, but only when that file exists.
///
/// Errors with `VmError::MissingEnv` when the override is unset and no data
/// directory can be resolved, and `VmError::MissingImage` when the default path
/// is resolvable but no file is present there.
fn resolve_or_default(var: &'static str, default_file: &str) -> Result<PathBuf, VmError> {
    if let Some(val) = std::env::var(var).ok().filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(val));
    }
    let default = data_dir()
        .map(|dir| dir.join(default_file))
        .ok_or(VmError::MissingEnv { var })?;
    if default.exists() {
        Ok(default)
    } else {
        Err(VmError::MissingImage { var, default })
    }
}

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

/// Resolve the kernel path from `MINVMD_KERNEL_PATH`, falling back to an
/// existing `<data-dir>/vmlinuz` when the override is unset or empty.
///
/// Errors with `VmError::MissingImage` when the override is unset and no file
/// exists at the default location, or `VmError::MissingEnv` when no data
/// directory can be resolved (neither `XDG_DATA_HOME` nor `HOME` is set).
pub fn resolve_kernel_path() -> Result<PathBuf, VmError> {
    resolve_or_default("MINVMD_KERNEL_PATH", DEFAULT_KERNEL_FILE)
}

/// Resolve the rootfs path from `MINVMD_ROOTFS_PATH`, falling back to an
/// existing `<data-dir>/rootfs.img` when the override is unset or empty.
///
/// This is the path to a read-only ext4 root disk image (loaded via
/// `krun_add_disk2`), not a directory. Errors with `VmError::MissingImage` when
/// the override is unset and no file exists at the default location, or
/// `VmError::MissingEnv` when no data directory can be resolved.
pub fn resolve_rootfs_path() -> Result<PathBuf, VmError> {
    resolve_or_default("MINVMD_ROOTFS_PATH", DEFAULT_ROOTFS_FILE)
}

/// Resolve the initramfs path from `MINVMD_INITRAMFS`, falling back to an
/// existing `<data-dir>/initramfs.cpio` when the override is unset or empty.
///
/// This is the cpio initramfs whose `/init` is minimald (booted as pid-1).
/// Errors with `VmError::MissingImage` when the override is unset and no file
/// exists at the default location, or `VmError::MissingEnv` when no data
/// directory can be resolved.
pub fn resolve_initramfs_path() -> Result<PathBuf, VmError> {
    resolve_or_default("MINVMD_INITRAMFS", DEFAULT_INITRAMFS_FILE)
}

/// System-wide install path for the host gvproxy ("gvisor-tap-vsock") binary,
/// used as the final fallback when `MINVMD_GVPROXY_BIN` is unset and no
/// user-local install exists. Fetched + SHA-256-verified by
/// `scripts/fetch-gvproxy.sh` (issue #495).
pub const DEFAULT_GVPROXY_BIN: &str = "/usr/lib/minimal/bin/gvproxy";

/// Filename the installer stamps into the `bin/` prefix (see
/// `scripts/stage-release.sh`: `bin/gvproxy`).
const GVPROXY_FILE: &str = "gvproxy";

/// The user-local bin directory the installer stamps into: `$MINIMAL_BIN`, else
/// `$HOME/.local/bin`. Mirrors the installer's `bin` prefix resolution in
/// `scripts/install.sh`. `None` when neither is set.
fn installer_bin_dir() -> Option<PathBuf> {
    if let Some(bin) = std::env::var("MINIMAL_BIN").ok().filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(bin));
    }
    std::env::var("HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(|home| PathBuf::from(home).join(".local/bin"))
}

/// Resolve the host gvproxy binary path in three tiers: the `MINVMD_GVPROXY_BIN`
/// override, then an existing user-local install (`<bin-dir>/gvproxy`, where the
/// installer stamps it), then the system-wide [`DEFAULT_GVPROXY_BIN`].
///
/// Unlike the kernel/rootfs/initramfs resolvers this never errors: gvproxy is
/// only spawned for an own-IP VM, so an absent override is the common case, and
/// the system path is returned as a last resort even if nothing exists there
/// (the caller surfaces a spawn failure with that concrete path).
#[must_use]
pub fn resolve_gvproxy_path() -> PathBuf {
    // Tier 1: explicit override, honoured verbatim.
    if let Some(val) = std::env::var("MINVMD_GVPROXY_BIN")
        .ok()
        .filter(|v| !v.is_empty())
    {
        return PathBuf::from(val);
    }
    // Tier 2: user-local install from the curl|sh installer, if present.
    if let Some(local) = installer_bin_dir().map(|dir| dir.join(GVPROXY_FILE))
        && local.exists()
    {
        return local;
    }
    // Tier 3: system-wide install path (hardcoded fallback).
    PathBuf::from(DEFAULT_GVPROXY_BIN)
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    // Resolver tests mutate process-global env (the MINVMD_* overrides and
    // XDG_DATA_HOME, which feeds `data_dir`), so serialise them to avoid races
    // when `cargo test` runs them in parallel.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    // Point the data dir at an isolated temp dir by setting XDG_DATA_HOME (so
    // `data_dir` never consults the real HOME) and clearing the override var.
    fn scoped_data_dir(var: &str, xdg: &std::path::Path) {
        unsafe {
            std::env::remove_var(var);
            std::env::set_var("XDG_DATA_HOME", xdg);
        }
    }

    fn clear_env(var: &str) {
        unsafe {
            std::env::remove_var(var);
            std::env::remove_var("XDG_DATA_HOME");
        }
    }

    #[test]
    fn returns_override_verbatim_without_existence_check() {
        let _g = ENV_LOCK.lock().unwrap();
        // A non-existent explicit path is still honoured: the caller owns it.
        unsafe { std::env::set_var("MINVMD_KERNEL_PATH", "/boot/Image.gz") };
        let path = resolve_kernel_path().unwrap();
        assert_eq!(path, PathBuf::from("/boot/Image.gz"));
        clear_env("MINVMD_KERNEL_PATH");
    }

    #[test]
    fn falls_back_to_default_when_file_exists() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let want = tmp.path().join("minimal").join(DEFAULT_KERNEL_FILE);
        std::fs::create_dir_all(want.parent().unwrap()).unwrap();
        std::fs::write(&want, b"kernel").unwrap();

        scoped_data_dir("MINVMD_KERNEL_PATH", tmp.path());
        let path = resolve_kernel_path().unwrap();
        assert_eq!(path, want);
        clear_env("MINVMD_KERNEL_PATH");
    }

    #[test]
    fn errors_with_missing_image_when_default_absent() {
        let _g = ENV_LOCK.lock().unwrap();
        // XDG_DATA_HOME points at an empty temp dir: default is resolvable but
        // no file is present there.
        let tmp = tempfile::tempdir().unwrap();
        scoped_data_dir("MINVMD_ROOTFS_PATH", tmp.path());
        let err = resolve_rootfs_path().unwrap_err();
        let VmError::MissingImage { var, default } = &err else {
            panic!("expected MissingImage, got {err:?}");
        };
        assert_eq!(*var, "MINVMD_ROOTFS_PATH");
        assert_eq!(
            *default,
            tmp.path().join("minimal").join(DEFAULT_ROOTFS_FILE)
        );
        clear_env("MINVMD_ROOTFS_PATH");
    }

    #[test]
    fn empty_override_is_treated_as_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let want = tmp.path().join("minimal").join(DEFAULT_INITRAMFS_FILE);
        std::fs::create_dir_all(want.parent().unwrap()).unwrap();
        std::fs::write(&want, b"initramfs").unwrap();

        // Empty string must not be used as a path; it falls through to default.
        unsafe {
            std::env::set_var("MINVMD_INITRAMFS", "");
            std::env::set_var("XDG_DATA_HOME", tmp.path());
        }
        let path = resolve_initramfs_path().unwrap();
        assert_eq!(path, want);
        clear_env("MINVMD_INITRAMFS");
    }

    // Remove every env var the gvproxy resolver consults, so a tier is only
    // exercised by what the test sets explicitly.
    fn clear_gvproxy_env() {
        unsafe {
            std::env::remove_var("MINVMD_GVPROXY_BIN");
            std::env::remove_var("MINIMAL_BIN");
        }
    }

    #[test]
    fn gvproxy_tier1_override_wins() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_gvproxy_env();
        unsafe { std::env::set_var("MINVMD_GVPROXY_BIN", "/custom/gvproxy") };
        assert_eq!(resolve_gvproxy_path(), PathBuf::from("/custom/gvproxy"));
        clear_gvproxy_env();
    }

    #[test]
    fn gvproxy_tier2_installer_bin_when_present() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_gvproxy_env();
        let tmp = tempfile::tempdir().unwrap();
        let want = tmp.path().join(GVPROXY_FILE);
        std::fs::write(&want, b"gvproxy").unwrap();
        // MINIMAL_BIN steers installer_bin_dir without touching HOME.
        unsafe { std::env::set_var("MINIMAL_BIN", tmp.path()) };
        assert_eq!(resolve_gvproxy_path(), want);
        clear_gvproxy_env();
    }

    #[test]
    fn gvproxy_tier3_system_path_when_no_local() {
        let _g = ENV_LOCK.lock().unwrap();
        clear_gvproxy_env();
        // MINIMAL_BIN points at an empty dir: no user-local gvproxy present.
        let tmp = tempfile::tempdir().unwrap();
        unsafe { std::env::set_var("MINIMAL_BIN", tmp.path()) };
        assert_eq!(resolve_gvproxy_path(), PathBuf::from(DEFAULT_GVPROXY_BIN));
        clear_gvproxy_env();
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
