//! `minvmd` — the macOS-only host daemon that brings up a Linux microVM via
//! libkrun, supervises its lifecycle, and bridges a host UDS to a vsock port
//! inside the VM so the `minimal` CLI can talk to `minimald` transparently.
//!
//! This crate compiles on `aarch64-apple-darwin` and `x86_64-apple-darwin` as
//! the real implementation, and on `target_os = "linux"` as a runtime-bailing
//! stub so existing Linux-only CI stays green. The `krun` module is macOS-only
//! since it links libkrun; portable surface (errors, state, image resolution)
//! compiles on both platforms.

pub mod cmd;
pub mod error;
pub mod image;
pub mod lifecycle;
pub mod state;
pub mod vm;

#[cfg(target_os = "macos")]
pub mod krun;

pub use error::VmError;
