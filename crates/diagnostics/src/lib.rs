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
//! - [`redact`] — key-based masking of secret-shaped values (JSON, TOML,
//!   and the process environment), applied identically by every producer
//! - [`listing`] — bounded recursive directory listing (names/sizes/metadata)
//! - [`capture`] — bounded subprocess output capture for command-shaped
//!   collectors
//! - [`logs`] — newest-first selection of rotated log files
//! - [`disk`] — filesystem capacity probes
//! - [`system`] — host identity/capability probe (OS, kernel, KVM, disks)
//!
//! The split with the app crates is mechanics vs. policy: the *how* lives
//! here; the *what* — which paths, which log prefixes, which env names are
//! allowlisted, where entries land in the archive — stays with the caller.

pub mod bundle;
pub mod capture;
#[cfg(unix)]
pub mod disk;
pub mod listing;
pub mod logs;
pub mod manifest;
#[cfg(unix)]
pub mod net;
#[cfg(unix)]
pub mod power;
#[cfg(unix)]
pub mod procs;
pub mod redact;
#[cfg(unix)]
pub mod system;

pub use bundle::{BundleSink, BundleWriter, LOG_TAIL_CAP, open_regular_nofollow};
pub use capture::{Capture, CaptureError, command_capture, command_stdout, first_stdout_line};
#[cfg(unix)]
pub use disk::{DiskUsage, disk_usage};
pub use listing::{Listing, listing};
pub use logs::newest_rotated;
pub use manifest::{CollectedEntry, CollectorError, Manifest, Redaction, SkippedEntry};
#[cfg(unix)]
pub use system::{DiskInfo, SystemInfo, system_info};
