//! libkrun bindings and safe wrappers.
//!
//! Layering:
//! - `raw`: bare `extern "C"` declarations matching `libkrun.h` exactly. No
//!   logic. Every declaration is documented with its C contract; the
//!   `unsafe extern "C"` block carries a single block-level `// SAFETY:`
//!   comment naming the invariants the bindings inherit from the C ABI.
//! - `ctx`: safe wrappers. Every call into `raw` is guarded by a per-call
//!   `// SAFETY:` comment naming the specific invariants the wrapper enforces
//!   (NUL-termination, pointer lifetimes, range bounds, ownership transfer).
//!   Wrappers translate negative-errno returns into [`crate::error::VmError`]
//!   via [`crate::krun::raw::check_backend`].
//!
//! This module is macOS-only. On Linux, `minvmd` ships only the runtime stub
//! and never links libkrun.

mod ctx;
mod raw;

pub use ctx::Context;
pub use raw::{
    KRUN_DISK_FORMAT_RAW, KRUN_KERNEL_FORMAT_ELF, KRUN_KERNEL_FORMAT_IMAGE_GZ,
    KRUN_KERNEL_FORMAT_PE_GZ, KRUN_KERNEL_FORMAT_RAW,
};
