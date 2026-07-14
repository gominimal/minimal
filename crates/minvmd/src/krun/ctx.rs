//! Safe wrappers around libkrun's context API.
//!
//! Every wrapper validates inputs in safe Rust (NUL-termination via
//! `CString`, range bounds, pointer/lifetime discipline) before crossing the
//! FFI boundary, then translates the libkrun return code via
//! [`VmError::check_backend`].
//!
//! [`Context`] is an RAII handle: `Drop` calls `krun_free_ctx` so dropping
//! the value reliably releases the libkrun-side configuration. Methods that
//! consume the context ([`Context::start_enter`]) take `self` so the type
//! system prevents use-after-free / double-free.

use std::ffi::{CString, c_char};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;

use crate::error::VmError;
use crate::krun::raw;

/// A libkrun configuration context. Holds a `ctx_id` and frees it on drop.
///
/// The context is non-`Clone` / non-`Copy` so the id cannot be duplicated
/// past the lifetime of this handle.
#[must_use = "dropping the Context immediately frees the libkrun configuration"]
#[derive(Debug)]
pub struct Context {
    ctx_id: u32,
}

impl Context {
    /// Create a new libkrun configuration context.
    ///
    /// If the `MINVMD_KRUN_LOG` environment variable is set (see
    /// [`KRUN_LOG_ENV`]), libkrun's logging is configured to stderr at the
    /// corresponding level before the context is created, so bring-up itself
    /// is captured.
    pub fn create() -> Result<Self, VmError> {
        configure_logging_from_env()?;
        // SAFETY: krun_create_ctx takes no arguments and either returns a
        // non-negative ctx_id (owned by the caller until krun_free_ctx) or a
        // negative errno. No pointer or lifetime invariants apply.
        let ret = unsafe { raw::krun_create_ctx() };
        let id = raw::check_backend("krun_create_ctx", ret)?;
        Ok(Self { ctx_id: id as u32 })
    }

    /// The underlying libkrun ctx id. Exposed for tests and the rare caller
    /// that needs to drive raw FFI alongside the wrapper.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u32 {
        self.ctx_id
    }

    /// Set vcpu count and RAM (MiB). libkrun caps vcpus by hypervisor
    /// support; pass a `u8` to make over-large counts unrepresentable.
    pub fn set_vm_config(&mut self, num_vcpus: u8, ram_mib: u32) -> Result<(), VmError> {
        // SAFETY: all arguments are passed by value; ctx_id refers to a
        // context owned by `self` and not yet freed. No pointer invariants.
        let ret = unsafe { raw::krun_set_vm_config(self.ctx_id, num_vcpus, ram_mib) };
        raw::check_backend("krun_set_vm_config", ret)?;
        Ok(())
    }

    /// Set the host directory backing the guest root filesystem.
    pub fn set_root(&mut self, root_path: impl AsRef<Path>) -> Result<(), VmError> {
        let path = root_path.as_ref();
        let cstr = cstring_from_path(path, "root")?;
        // SAFETY: `cstr` is a CString owned by this stack frame; its pointer
        // is valid (NUL-terminated, non-null) until the call returns. The
        // ctx_id is owned by `self`.
        let ret = unsafe { raw::krun_set_root(self.ctx_id, cstr.as_ptr()) };
        raw::check_backend("krun_set_root", ret)?;
        drop(cstr);
        Ok(())
    }

    /// Set the executable to run inside the guest along with its argv and
    /// envp. `envp = None` tells libkrun to inherit the host environment.
    ///
    /// `argv` does *not* include argv[0] — libkrun derives that from
    /// `exec_path`. Pass the explicit arguments only.
    pub fn set_exec(
        &mut self,
        exec_path: impl AsRef<Path>,
        argv: &[impl AsRef<str>],
        envp: Option<&[impl AsRef<str>]>,
    ) -> Result<(), VmError> {
        let exec_cstr = cstring_from_path(exec_path.as_ref(), "exec")?;

        let argv_cstrs = cstrings_from_strs(argv, "argv")?;
        let mut argv_ptrs: Vec<*const c_char> = argv_cstrs.iter().map(|c| c.as_ptr()).collect();
        argv_ptrs.push(ptr::null()); // NULL-terminate per C convention

        // Bind envp storage and its pointer-vector at the same scope as the
        // FFI call so both outlive the unsafe block. `envp_cstrs == None`
        // means "inherit host env" per libkrun docs (pass NULL); a `Some`
        // (including `Some(&[])`) gets a properly NULL-terminated array.
        let envp_cstrs: Option<Vec<CString>> = envp
            .map(|entries| cstrings_from_strs(entries, "envp"))
            .transpose()?;
        let (envp_ptrs, envp_ptr): (Vec<*const c_char>, *const *const c_char) =
            match envp_cstrs.as_ref() {
                Some(cstrs) => {
                    let mut ptrs: Vec<*const c_char> = cstrs.iter().map(|c| c.as_ptr()).collect();
                    ptrs.push(ptr::null());
                    let p = ptrs.as_ptr();
                    (ptrs, p)
                }
                None => (Vec::new(), ptr::null()),
            };

        // SAFETY:
        //  - `exec_cstr` is a CString owned by this stack frame; its pointer
        //    is NUL-terminated and valid for the call.
        //  - `argv_ptrs` is owned by this stack frame, NULL-terminated, and
        //    each element points into a CString in `argv_cstrs` that is
        //    likewise owned by this stack frame for the call duration.
        //  - `envp_ptr` is either NULL (inherit host env) or points to
        //    `envp_ptrs`, a stack-owned NULL-terminated array whose elements
        //    point into `envp_cstrs`. All three locals are bound at the
        //    method scope and outlive this `unsafe` block.
        //  - `ctx_id` is owned by `self`.
        let ret = unsafe {
            raw::krun_set_exec(
                self.ctx_id,
                exec_cstr.as_ptr(),
                argv_ptrs.as_ptr(),
                envp_ptr,
            )
        };
        // Keep the backing storage alive through the call. These are no-ops
        // codegen-wise but make the lifetime contract visible to readers.
        drop(exec_cstr);
        drop(argv_ptrs);
        drop(argv_cstrs);
        drop(envp_ptrs);
        drop(envp_cstrs);
        raw::check_backend("krun_set_exec", ret)?;
        Ok(())
    }

    /// Set the kernel image to boot, its format, optional initramfs, and
    /// optional cmdline.
    pub fn set_kernel(
        &mut self,
        kernel_path: impl AsRef<Path>,
        kernel_format: raw::KernelFormat,
        initramfs: Option<impl AsRef<Path>>,
        cmdline: Option<&str>,
    ) -> Result<(), VmError> {
        let kernel_cstr = cstring_from_path(kernel_path.as_ref(), "kernel")?;
        let initramfs_cstr = initramfs
            .map(|p| cstring_from_path(p.as_ref(), "initramfs"))
            .transpose()?;
        let cmdline_cstr = cmdline
            .map(|s| cstring_from_str(s, "cmdline"))
            .transpose()?;

        let initramfs_ptr = initramfs_cstr.as_ref().map_or(ptr::null(), |c| c.as_ptr());
        let cmdline_ptr = cmdline_cstr.as_ref().map_or(ptr::null(), |c| c.as_ptr());

        // SAFETY: all *const c_char arguments either point into a CString
        // owned by this stack frame for the call duration, or are NULL
        // (libkrun documents NULL as valid for initramfs and cmdline).
        // `ctx_id` is owned by `self`.
        let ret = unsafe {
            raw::krun_set_kernel(
                self.ctx_id,
                kernel_cstr.as_ptr(),
                kernel_format as u32,
                initramfs_ptr,
                cmdline_ptr,
            )
        };
        drop(kernel_cstr);
        drop(initramfs_cstr);
        drop(cmdline_cstr);
        raw::check_backend("krun_set_kernel", ret)?;
        Ok(())
    }

    /// Register a host UNIX socket path the guest can reach over the given
    /// vsock port.
    pub fn add_vsock_port(
        &mut self,
        port: u32,
        host_socket: impl AsRef<Path>,
    ) -> Result<(), VmError> {
        let cstr = cstring_from_path(host_socket.as_ref(), "vsock_port")?;
        // SAFETY: `cstr` owned by this stack frame for the call duration;
        // `port` passed by value; `ctx_id` owned by `self`.
        let ret = unsafe { raw::krun_add_vsock_port(self.ctx_id, port, cstr.as_ptr()) };
        drop(cstr);
        raw::check_backend("krun_add_vsock_port", ret)?;
        Ok(())
    }

    /// Register a host UNIX socket path with direction control.
    ///
    /// When `listen = true`, libkrun listens on the host UDS and bridges each
    /// accepted connection to a guest process listening on `port` (host→guest,
    /// used for the minimald bridge, R3.1). When `listen = false`, the
    /// behaviour is equivalent to [`add_vsock_port`][Self::add_vsock_port]
    /// (guest→host, used for the READY marker, R2.4).
    pub fn add_vsock_port2(
        &mut self,
        port: u32,
        host_socket: impl AsRef<Path>,
        listen: bool,
    ) -> Result<(), VmError> {
        let cstr = cstring_from_path(host_socket.as_ref(), "vsock_port2")?;
        // SAFETY: `cstr` is a CString owned by this stack frame; its pointer
        // is NUL-terminated and valid until after the FFI returns. `port` and
        // `listen` are passed by value. `ctx_id` is owned by `self` and refers
        // to a context not yet freed.
        let ret = unsafe { raw::krun_add_vsock_port2(self.ctx_id, port, cstr.as_ptr(), listen) };
        drop(cstr);
        raw::check_backend("krun_add_vsock_port2", ret)?;
        Ok(())
    }

    /// Add a disk image as a virtio-blk block device backing `block_id`.
    pub fn add_disk(
        &mut self,
        block_id: &str,
        disk_path: impl AsRef<Path>,
        disk_format: raw::DiskFormat,
        read_only: bool,
    ) -> Result<(), VmError> {
        let id_cstr = cstring_from_str(block_id, "block_id")?;
        let path_cstr = cstring_from_path(disk_path.as_ref(), "disk")?;
        // SAFETY: `id_cstr` and `path_cstr` are CStrings owned by this stack
        // frame; their pointers are NUL-terminated and valid until after the
        // FFI returns. `disk_format` and `read_only` are passed by value.
        // `ctx_id` is owned by `self` and refers to a context not yet freed.
        let ret = unsafe {
            raw::krun_add_disk2(
                self.ctx_id,
                id_cstr.as_ptr(),
                path_cstr.as_ptr(),
                disk_format as u32,
                read_only,
            )
        };
        drop(id_cstr);
        drop(path_cstr);
        raw::check_backend("krun_add_disk2", ret)?;
        Ok(())
    }

    /// Add a disk image as a virtio-blk device with cache/sync control
    /// (`krun_add_disk3`). Unlike [`add_disk`][Self::add_disk], the caller
    /// selects `direct_io` (bypass host page cache) and `sync_mode` (how
    /// `VIRTIO_BLK_F_FLUSH` is honoured). Used for the writable data volume,
    /// which is attached `read_only=false` with a durability-bounding
    /// [`SyncMode`][raw::SyncMode].
    pub fn add_disk_with_sync(
        &mut self,
        block_id: &str,
        disk_path: impl AsRef<Path>,
        disk_format: raw::DiskFormat,
        read_only: bool,
        direct_io: bool,
        sync_mode: raw::SyncMode,
    ) -> Result<(), VmError> {
        let id_cstr = cstring_from_str(block_id, "block_id")?;
        let path_cstr = cstring_from_path(disk_path.as_ref(), "disk")?;
        // SAFETY: `id_cstr` and `path_cstr` are CStrings owned by this stack
        // frame; their pointers are NUL-terminated and valid until after the
        // FFI returns. `disk_format`, `read_only`, `direct_io`, and `sync_mode`
        // are passed by value (the enums are `#[repr(u32)]`). `ctx_id` is owned
        // by `self` and refers to a context not yet freed.
        let ret = unsafe {
            raw::krun_add_disk3(
                self.ctx_id,
                id_cstr.as_ptr(),
                path_cstr.as_ptr(),
                disk_format as u32,
                read_only,
                direct_io,
                sync_mode as u32,
            )
        };
        drop(id_cstr);
        drop(path_cstr);
        raw::check_backend("krun_add_disk3", ret)?;
        Ok(())
    }

    /// Redirect implicit-console output to a host file.
    pub fn set_console_output(&mut self, path: impl AsRef<Path>) -> Result<(), VmError> {
        let cstr = cstring_from_path(path.as_ref(), "console_output")?;
        // SAFETY: `cstr` owned by this stack frame for the call duration;
        // `ctx_id` owned by `self`.
        let ret = unsafe { raw::krun_set_console_output(self.ctx_id, cstr.as_ptr()) };
        drop(cstr);
        raw::check_backend("krun_set_console_output", ret)?;
        Ok(())
    }

    /// Start the microVM. **Consumes the context** because libkrun documents
    /// that `krun_start_enter` only returns on error — on success it `exit()`s
    /// the host process with the guest workload's exit code. The returned
    /// `VmError` is therefore unconditional: this function never returns
    /// `Ok(_)`. Callers that want diverging semantics on success may
    /// `std::process::exit` themselves after observing success in the parent.
    pub fn start_enter(self) -> VmError {
        // Move ctx_id out and forget `self` so `Drop` does NOT call
        // krun_free_ctx — libkrun's docs say start_enter consumes the
        // configuration regardless of outcome. Calling free after this would
        // double-free.
        let ctx_id = self.ctx_id;
        std::mem::forget(self);
        // SAFETY: `ctx_id` was owned by the consumed `self`; per libkrun's
        // docs, krun_start_enter takes ownership of the configuration. No
        // further wrapper calls referring to this id are valid.
        let ret = unsafe { raw::krun_start_enter(ctx_id) };
        match raw::check_backend("krun_start_enter", ret) {
            // libkrun's docs guarantee start_enter only returns on error
            // (success path: VMM calls exit() with the guest workload's
            // exit code). A non-negative return is therefore a protocol
            // violation; surface it as a distinct variant rather than
            // pretending it was "errno 0".
            Ok(ret) => VmError::StartEnterReturnedUnexpectedly { ret },
            Err(e) => e,
        }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: `ctx_id` was returned by a paired `krun_create_ctx` and
        // not yet freed (Context is non-Clone/non-Copy and `start_enter`
        // consumes via `mem::forget`).
        let ret = unsafe { raw::krun_free_ctx(self.ctx_id) };
        if ret < 0 {
            // Drop cannot return; surface via tracing so the failure is not
            // silently lost.
            tracing::warn!(
                ctx_id = self.ctx_id,
                code = ret.unsigned_abs() as i32,
                "krun_free_ctx returned non-zero in Drop",
            );
        }
    }
}

/// Environment variable that, when set to a non-empty value, configures
/// libkrun's logging. The value is a level name (`off`, `error`, `warn`,
/// `info`, `debug`, `trace`; case-insensitive) or the equivalent numeric
/// level `0`–`5`. Unset or empty leaves libkrun's logging at its default.
pub const KRUN_LOG_ENV: &str = "MINVMD_KRUN_LOG";

/// Configure libkrun's logging to stderr from [`KRUN_LOG_ENV`], if set.
///
/// A no-op when the variable is unset or empty. A set-but-unrecognised value
/// is a hard error ([`VmError::InvalidLogLevel`]) rather than a silent
/// fallback, so a typo in the level surfaces at start-up.
///
/// `krun_init_log` installs a process-global logger and fails if called more
/// than once, so the FFI call is memoized through a [`OnceLock`]: the first
/// configuring `create()` performs it and every caller observes the same
/// return code. `KRUN_LOG_ENV` is read on each call (it cannot change between
/// them) so an invalid value is reported consistently even before the logger
/// would be initialized.
fn configure_logging_from_env() -> Result<(), VmError> {
    static LOG_INIT_RET: OnceLock<i32> = OnceLock::new();

    let Some(raw_value) = std::env::var_os(KRUN_LOG_ENV) else {
        return Ok(());
    };
    let value = raw_value.to_string_lossy();
    if value.trim().is_empty() {
        return Ok(());
    }
    let level = parse_log_level(&value).ok_or_else(|| VmError::InvalidLogLevel {
        value: value.into_owned(),
    })?;

    let ret = *LOG_INIT_RET.get_or_init(|| {
        // SAFETY: krun_init_log takes four values by value (no pointers). The
        // `target_fd` is libkrun's sentinel for stderr; `level`, `style`, and
        // `options` are plain integers. Guarded by the enclosing `OnceLock`
        // so libkrun's install-once logger is initialized at most once.
        unsafe {
            raw::krun_init_log(
                raw::LOG_TARGET_DEFAULT,
                level as u32,
                raw::LOG_STYLE_AUTO,
                raw::LOG_OPTIONS_DEFAULT,
            )
        }
    });
    raw::check_backend("krun_init_log", ret)?;
    Ok(())
}

/// Map a [`KRUN_LOG_ENV`] value to a [`raw::LogLevel`], accepting either a
/// case-insensitive level name or the numeric level `0`–`5`.
fn parse_log_level(value: &str) -> Option<raw::LogLevel> {
    use raw::LogLevel;
    match value.trim().to_ascii_lowercase().as_str() {
        "off" | "0" => Some(LogLevel::Off),
        "error" | "1" => Some(LogLevel::Error),
        "warn" | "2" => Some(LogLevel::Warn),
        "info" | "3" => Some(LogLevel::Info),
        "debug" | "4" => Some(LogLevel::Debug),
        "trace" | "5" => Some(LogLevel::Trace),
        _ => None,
    }
}

/// Build a `CString` from a path, mapping interior NULs to a typed error.
fn cstring_from_path(path: &Path, what: &'static str) -> Result<CString, VmError> {
    // Use OsStr bytes on Unix; libkrun only ships on Unix (macOS/Linux) so we
    // can rely on `as_bytes()`.
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).map_err(|_| VmError::NulInPath {
        what,
        path: PathBuf::from(path),
    })
}

/// Build a `CString` from a string slice, mapping interior NULs to a typed
/// error.
fn cstring_from_str(s: &str, what: &'static str) -> Result<CString, VmError> {
    CString::new(s.as_bytes()).map_err(|_| VmError::NulInString {
        what,
        value: s.to_owned(),
    })
}

/// Build a `Vec<CString>` from a slice of string-like values.
fn cstrings_from_strs(
    items: &[impl AsRef<str>],
    what: &'static str,
) -> Result<Vec<CString>, VmError> {
    items
        .iter()
        .map(|s| cstring_from_str(s.as_ref(), what))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cstring_from_path_rejects_interior_nul() {
        use std::os::unix::ffi::OsStrExt;
        let bad = std::ffi::OsStr::from_bytes(b"/tmp/foo\0bar");
        let p = PathBuf::from(bad);
        let err = cstring_from_path(&p, "root").unwrap_err();
        assert!(
            matches!(err, VmError::NulInPath { what: "root", .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn cstring_from_path_accepts_normal_path() {
        let p = PathBuf::from("/tmp/foo/bar");
        cstring_from_path(&p, "root").unwrap();
    }

    #[test]
    fn cstring_from_str_rejects_interior_nul() {
        let err = cstring_from_str("KEY\0VALUE", "envp").unwrap_err();
        assert!(matches!(err, VmError::NulInString { what: "envp", .. }));
    }

    #[test]
    fn cstrings_from_strs_propagates_first_error() {
        let items = ["ok", "ba\0d", "also-ok"];
        let err = cstrings_from_strs(&items, "argv").unwrap_err();
        assert!(matches!(err, VmError::NulInString { what: "argv", .. }));
    }

    #[test]
    fn parse_log_level_accepts_names_case_insensitively() {
        use raw::LogLevel;
        assert_eq!(parse_log_level("off"), Some(LogLevel::Off));
        assert_eq!(parse_log_level("Error"), Some(LogLevel::Error));
        assert_eq!(parse_log_level("WARN"), Some(LogLevel::Warn));
        assert_eq!(parse_log_level("  info  "), Some(LogLevel::Info));
        assert_eq!(parse_log_level("debug"), Some(LogLevel::Debug));
        assert_eq!(parse_log_level("trace"), Some(LogLevel::Trace));
    }

    #[test]
    fn parse_log_level_accepts_numeric_levels() {
        use raw::LogLevel;
        assert_eq!(parse_log_level("0"), Some(LogLevel::Off));
        assert_eq!(parse_log_level("3"), Some(LogLevel::Info));
        assert_eq!(parse_log_level("5"), Some(LogLevel::Trace));
    }

    #[test]
    fn parse_log_level_rejects_unknown_values() {
        assert_eq!(parse_log_level("verbose"), None);
        assert_eq!(parse_log_level("6"), None);
        assert_eq!(parse_log_level(""), None);
    }
}
