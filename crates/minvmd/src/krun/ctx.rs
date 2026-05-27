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
    pub fn create() -> Result<Self, VmError> {
        // SAFETY: krun_create_ctx takes no arguments and either returns a
        // non-negative ctx_id (owned by the caller until krun_free_ctx) or a
        // negative errno. No pointer or lifetime invariants apply.
        let ret = unsafe { raw::krun_create_ctx() };
        let id = VmError::check_backend("krun_create_ctx", ret)?;
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
        VmError::check_backend("krun_set_vm_config", ret)?;
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
        VmError::check_backend("krun_set_root", ret)?;
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
        let envp_cstrs: Option<Vec<CString>> = match envp {
            Some(entries) => Some(cstrings_from_strs(entries, "envp")?),
            None => None,
        };
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
        VmError::check_backend("krun_set_exec", ret)?;
        Ok(())
    }

    /// Set the kernel image to boot, its format, optional initramfs, and
    /// optional cmdline.
    pub fn set_kernel(
        &mut self,
        kernel_path: impl AsRef<Path>,
        kernel_format: u32,
        initramfs: Option<impl AsRef<Path>>,
        cmdline: Option<&str>,
    ) -> Result<(), VmError> {
        let kernel_cstr = cstring_from_path(kernel_path.as_ref(), "kernel")?;
        let initramfs_cstr = match initramfs {
            Some(p) => Some(cstring_from_path(p.as_ref(), "initramfs")?),
            None => None,
        };
        let cmdline_cstr = match cmdline {
            Some(s) => Some(cstring_from_str(s, "cmdline")?),
            None => None,
        };

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
                kernel_format,
                initramfs_ptr,
                cmdline_ptr,
            )
        };
        drop(kernel_cstr);
        drop(initramfs_cstr);
        drop(cmdline_cstr);
        VmError::check_backend("krun_set_kernel", ret)?;
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
        VmError::check_backend("krun_add_vsock_port", ret)?;
        Ok(())
    }

    /// Redirect implicit-console output to a host file.
    pub fn set_console_output(&mut self, path: impl AsRef<Path>) -> Result<(), VmError> {
        let cstr = cstring_from_path(path.as_ref(), "console_output")?;
        // SAFETY: `cstr` owned by this stack frame for the call duration;
        // `ctx_id` owned by `self`.
        let ret = unsafe { raw::krun_set_console_output(self.ctx_id, cstr.as_ptr()) };
        drop(cstr);
        VmError::check_backend("krun_set_console_output", ret)?;
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
        match VmError::check_backend("krun_start_enter", ret) {
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

/// Build a `CString` from a path, mapping interior NULs to a typed error.
fn cstring_from_path(path: &Path, what: &'static str) -> Result<CString, VmError> {
    // Use OsStr bytes on Unix; libkrun is macOS-only so we can rely on
    // `as_bytes()`.
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
}
