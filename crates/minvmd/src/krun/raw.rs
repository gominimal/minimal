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

// Kernel format constants from libkrun.h. Used by `krun_set_kernel`.
//
// We only model the formats minvmd actually targets:
// - aarch64 `virtio-linux` ships `Image.gz` → `KRUN_KERNEL_FORMAT_IMAGE_GZ`
// - x86_64 `virtio-linux` ships `bzImage`  → `KRUN_KERNEL_FORMAT_IMAGE_BZ2`
pub const KRUN_KERNEL_FORMAT_RAW: u32 = 0;
pub const KRUN_KERNEL_FORMAT_ELF: u32 = 1;
pub const KRUN_KERNEL_FORMAT_PE_GZ: u32 = 2;
pub const KRUN_KERNEL_FORMAT_IMAGE_BZ2: u32 = 3;
pub const KRUN_KERNEL_FORMAT_IMAGE_GZ: u32 = 4;

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

    /// Redirect the implicit console output to a host file. Used by the
    /// supervisor to capture early-boot kernel output for diagnostics.
    pub fn krun_set_console_output(ctx_id: u32, c_filepath: *const c_char) -> i32;
}
