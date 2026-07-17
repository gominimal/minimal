//! Crate-agnostic machinery for the `min bug` diagnostic bundle.
//!
//! The host-specific collectors (which need a live daemon client, resolved
//! paths, and the process/network state of the machine) live in
//! `minimal::diag` and `minimald::diag`; what lives here is the reusable
//! core those collectors build on:
//!
//! - [`redact`] — key-based masking of secret-shaped values, applied
//!   identically by the CLI and the daemon
//! - [`listing`] — bounded recursive directory listing (names/sizes/metadata)
//! - [`manifest`] — the bundle's self-describing manifest types
//! - [`bundle`] — the tar+zstd [`bundle::BundleWriter`] every collector writes
//!   through, which keeps the manifest complete by construction

pub mod bundle;
pub mod listing;
pub mod manifest;
pub mod redact;
