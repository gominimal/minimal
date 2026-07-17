//! App-agnostic machinery for diagnostic support bundles.
//!
//! The application-specific collectors (which need a live daemon client,
//! resolved paths, and the process/network state of the machine) live in
//! their own crates; what lives here is the reusable core those collectors
//! build on:
//!
//! - [`bundle`] — the tar+zstd [`BundleWriter`] every collector writes
//!   through, file-backed (CLI) or streaming (daemon), which keeps the
//!   manifest complete by construction
//! - [`manifest`] — the bundle's self-describing manifest types
//! - [`redact`] — key-based masking of secret-shaped values, applied
//!   identically by every producer
//! - [`listing`] — bounded recursive directory listing (names/sizes/metadata)
//! - [`capture`] — bounded subprocess output capture for command-shaped
//!   collectors

pub mod bundle;
pub mod capture;
pub mod listing;
pub mod manifest;
pub mod redact;

pub use bundle::{BundleSink, BundleWriter, LOG_TAIL_CAP};
pub use capture::{Capture, CaptureError, command_capture};
pub use listing::{Listing, listing};
pub use manifest::{CollectedEntry, CollectorError, Manifest, Redaction, SkippedEntry};
