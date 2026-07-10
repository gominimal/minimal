//! `minvmd` — the host daemon that brings up a Linux microVM via libkrun,
//! supervises its lifecycle, and bridges a host UDS to a vsock port inside the
//! VM so the `minimal` CLI can talk to `minimald` transparently.
//!
//! The real (libkrun-linking) implementation is gated on the `minvmd_libkrun`
//! cfg emitted by the build script: always set on macOS (Hypervisor.framework),
//! and set on Linux when libkrun is installed (KVM). Without it the crate
//! compiles to a runtime-bailing stub so stock Linux CI — which has no libkrun —
//! stays green. The `krun` module links libkrun and so compiles only under that
//! cfg; the portable surface (errors, state, image resolution) compiles
//! everywhere.

pub mod cmd;
pub mod error;
pub mod image;
pub mod lifecycle;
pub mod net;
pub(crate) mod rpc_client;
pub mod sock;
pub mod state;
pub mod vm;
pub mod volume;

#[cfg(minvmd_libkrun)]
pub mod krun;

pub use error::VmError;
