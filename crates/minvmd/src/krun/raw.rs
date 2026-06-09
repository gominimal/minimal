//! Raw `extern "C"` FFI declarations for libkrun.
//!
//! Declarations mirror `libkrun.h` exactly (`/opt/homebrew/include/libkrun.h`
//! on Homebrew installs). They cover only the subset `minvmd` actually calls;
//! grow the surface as new wrappers in [`super::ctx`] need it.
//!
//! Reference: libkrun v1.18+ (slp/krun Homebrew tap). The build script
//! ([`crate::build`]) emits the link-search and rpath; we declare the link
//! requirement here so it travels with the symbols themselves.

use std::ffi::c_char;
use std::io;

use crate::error::VmError;

// Kernel format constants from libkrun.h, used by `krun_set_kernel`. Full enum:
// RAW=0, ELF=1, PE_GZ=2, IMAGE_BZ2=3, IMAGE_GZ=4, IMAGE_ZSTD=5. minvmd targets:
// - aarch64 `virtio-linux` ships `Image.gz` → `KRUN_KERNEL_FORMAT_PE_GZ`. The
//   aarch64 loader implements only RAW and PE_GZ; PE_GZ scans for the gzip
//   magic and decompresses. `IMAGE_GZ` (=4) is x86_64-only and returns
//   `KernelFormatUnsupported` on aarch64.
// - x86_64  `virtio-linux` ships `bzImage`  → `KRUN_KERNEL_FORMAT_ELF`. libkrun
//   loads bzImage as ELF; `IMAGE_BZ2` (=3) is bzip2 blobs, not the bzImage
//   container format.
pub const KRUN_KERNEL_FORMAT_RAW: u32 = 0;
pub const KRUN_KERNEL_FORMAT_ELF: u32 = 1;
pub const KRUN_KERNEL_FORMAT_PE_GZ: u32 = 2;
pub const KRUN_KERNEL_FORMAT_IMAGE_GZ: u32 = 4;

// Disk image formats from libkrun.h, used by `krun_add_disk2`. A squashfs or
// ext4 rootfs image is a RAW block device (the filesystem lives inside it; no
// partition table). QCOW2=1, VMDK=2 are not used by minvmd.
pub const KRUN_DISK_FORMAT_RAW: u32 = 0;

// SAFETY: every function in this block is an `extern "C"` declaration that
// inherits its safety contract from libkrun.h. Specifically:
//
// - All `*const c_char` parameters MUST be NUL-terminated valid UTF-8/ASCII
//   path/string pointers whose backing storage outlives the call. The safe
//   wrappers in [`super::ctx`] enforce this by constructing `CString`s on
//   the caller's stack and not releasing them until after the FFI returns.
// - All `*const *const c_char` "string array" parameters MUST be
//   NULL-terminated arrays of NUL-terminated string pointers; the wrappers
//   build a `Vec<*const c_char>` with a trailing `ptr::null()` and keep the
//   backing `CString`s alive for the duration of the call.
// - `ctx_id: u32` MUST refer to a context previously returned by
//   `krun_create_ctx` and not yet freed via `krun_free_ctx`. The
//   [`super::ctx::Context`] RAII wrapper owns the id and prevents
//   use-after-free at the type level.
// - `num_vcpus: u8` and `ram_mib: u32` are passed by value; range bounds are
//   defined by libkrun (vcpus ≤ `krun_get_max_vcpus()`).
// - `krun_start_enter` takes ownership of the context (consumes the
//   configuration per the C docs). The wrapper consumes `self` so the
//   context cannot be reused after this call.
// - Return values are i32: zero or positive on success, negative errno on
//   failure. [`crate::error::VmError::check_backend`] translates these.
#[link(name = "krun")]
unsafe extern "C" {
    // ----- smoke-test bring-up surface -----

    /// Create a new configuration context. Returns the ctx id (>= 0) on
    /// success or a negative errno on failure.
    pub fn krun_create_ctx() -> i32;

    /// Free a previously created context. Returns 0 on success or a negative
    /// errno on failure. Safe to call exactly once per `krun_create_ctx`.
    pub fn krun_free_ctx(ctx_id: u32) -> i32;

    /// Set the microVM's basic config: vcpu count and RAM in MiB.
    pub fn krun_set_vm_config(ctx_id: u32, num_vcpus: u8, ram_mib: u32) -> i32;

    /// Set the executable path (relative to the guest root) and its argv +
    /// envp. `argv` and `envp` must be NULL-terminated arrays of
    /// NUL-terminated strings; `envp == NULL` means inherit the host env.
    pub fn krun_set_exec(
        ctx_id: u32,
        exec_path: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> i32;

    /// Start the microVM. Consumes the configuration. On success, libkrun
    /// takes over the process and calls `exit()` with the guest workload's
    /// exit code — i.e. this function only returns on error.
    pub fn krun_start_enter(ctx_id: u32) -> i32;

    // ----- boot surface: kernel + rootfs + vsock marker -----

    /// Set the host directory to be used as the guest's root filesystem,
    /// surfaced as virtio-fs at `/dev/root` (`KRUN_FS_ROOT_TAG`).
    pub fn krun_set_root(ctx_id: u32, root_path: *const c_char) -> i32;

    /// Set the kernel image to boot. `kernel_format` is one of
    /// `KRUN_KERNEL_FORMAT_*`. `initramfs` and `cmdline` may be NULL.
    pub fn krun_set_kernel(
        ctx_id: u32,
        kernel_path: *const c_char,
        kernel_format: u32,
        initramfs: *const c_char,
        cmdline: *const c_char,
    ) -> i32;

    /// Register a host UNIX socket path that the guest will be able to reach
    /// over the given vsock port (`vhost-vsock`-style port-to-path mapping).
    /// Used by minvmd for the `READY\n` boot marker and, once the bridge
    /// lands, the host→guest path to minimald.
    pub fn krun_add_vsock_port(ctx_id: u32, port: u32, c_filepath: *const c_char) -> i32;

    /// Register a host UNIX socket path with direction control.
    ///
    /// `listen = true`: libkrun listens on the host UDS and bridges each
    /// accepted connection to a guest process listening on `port`. Used for
    /// the host→guest minimald bridge (R3.1).
    ///
    /// `listen = false`: equivalent to `krun_add_vsock_port`; the host UDS
    /// listens and the guest connects outbound. Used for the READY marker
    /// (R2.4).
    pub fn krun_add_vsock_port2(
        ctx_id: u32,
        port: u32,
        c_filepath: *const c_char,
        listen: bool,
    ) -> i32;

    /// Redirect the implicit console output to a host file. Used by the
    /// supervisor to capture early-boot kernel output for diagnostics.
    pub fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32;

    /// Add a disk image as a virtio-blk block device. `block_id` names the
    /// partition; `disk_format` is one of `KRUN_DISK_FORMAT_*`. Used to back
    /// the guest root with a squashfs/ext4 image instead of virtiofs.
    pub fn krun_add_disk2(
        ctx_id: u32,
        block_id: *const c_char,
        disk_path: *const c_char,
        disk_format: u32,
        read_only: bool,
    ) -> i32;
}

/// Translate a libkrun return code into a `Result`.
///
/// libkrun returns zero (or a positive id) on success and a negative errno on
/// failure. The errno magnitude is preserved by negating into an [`io::Error`]
/// via [`io::Error::from_raw_os_error`]; the pathological `i32::MIN` (no
/// representable negation) falls back to `EOVERFLOW`.
///
/// Lives next to the FFI declarations it guards rather than on `VmError`, so
/// the negative-errno convention stays with the bindings that produce it.
pub(crate) fn check_backend(op: &'static str, ret: i32) -> Result<i32, VmError> {
    if ret < 0 {
        let errno = ret.checked_neg().unwrap_or(libc::EOVERFLOW);
        Err(VmError::Backend {
            op,
            source: io::Error::from_raw_os_error(errno),
        })
    } else {
        Ok(ret)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_backend_passes_through_success() {
        assert_eq!(check_backend("op", 0).unwrap(), 0);
        assert_eq!(check_backend("op", 7).unwrap(), 7);
    }

    #[test]
    fn check_backend_translates_negative_to_typed_error() {
        let err = check_backend("krun_create_ctx", -22).unwrap_err();
        let VmError::Backend { op, source } = err else {
            panic!("expected Backend, got {err:?}");
        };
        assert_eq!(op, "krun_create_ctx");
        assert_eq!(
            source.raw_os_error(),
            Some(22),
            "errno magnitude must be preserved"
        );
    }

    #[test]
    fn check_backend_handles_i32_min() {
        let err = check_backend("op", i32::MIN).unwrap_err();
        let VmError::Backend { source, .. } = err else {
            panic!("expected Backend");
        };
        assert_eq!(source.raw_os_error(), Some(libc::EOVERFLOW));
    }
}
