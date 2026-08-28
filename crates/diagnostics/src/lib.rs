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
//! - [`kmsg`] — the kernel ring buffer, read without `dmesg`
//! - [`disk`] — filesystem capacity probes
//! - [`system`] — host identity/capability probe (OS, kernel, KVM, disks)
//! - [`terminal`] — the tty state and window size of the invoking terminal
//!
//! The split with the app crates is mechanics vs. policy: the *how* lives
//! here; the *what* — which paths, which log prefixes, which env names are
//! allowlisted, where entries land in the archive — stays with the caller.

pub mod bundle;
pub mod capture;
#[cfg(unix)]
pub mod disk;
#[cfg(unix)]
pub mod kmsg;
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
#[cfg(unix)]
pub mod terminal;

/// Per-collector deadline. Generous enough for a slow disk, small enough that
/// one wedged collector cannot stall a whole bundle — and a wedged host is
/// exactly when the bundle is wanted.
pub const COLLECTOR_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Runs one collector future under [`COLLECTOR_TIMEOUT`], recording a failure
/// or timeout in the manifest and letting the run continue. Failure isolation
/// is the contract every producer shares: no collector may abort the bundle.
///
/// A macro rather than a function so the future's borrow of the writer ends
/// before the error-recording arms re-borrow it.
///
/// The macro itself emits no log event — a bundle producer that wants one owns
/// that decision, because the same event is a background note in a daemon and
/// terminal output in a CLI. The four-argument form takes
/// `FnOnce(&str /* collector */, &str /* error */)`, called before the manifest
/// is written.
#[macro_export]
macro_rules! collect_step {
    ($w:expr, $name:expr, $fut:expr) => {
        $crate::collect_step!($w, $name, $fut, |_: &str, _: &str| {})
    };
    ($w:expr, $name:expr, $fut:expr, $on_error:expr) => {{
        let name: String = $name.into();
        let started = std::time::Instant::now();
        let failure = match tokio::time::timeout($crate::COLLECTOR_TIMEOUT, $fut).await {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(format!("{e:#}")),
            Err(_) => Some(format!("timed out after {:?}", $crate::COLLECTOR_TIMEOUT)),
        };
        if let Some(error) = failure {
            ($on_error)(name.as_str(), error.as_str());
            $w.error(name, error, started.elapsed());
        }
    }};
}

pub use bundle::{
    BundleSink, BundleWriter, LOG_TAIL_CAP, MAX_LOG_TAIL_BYTES, open_regular_nofollow,
};
pub use capture::{
    Capture, CaptureError, command_capture, command_capture_capped, command_stdout,
    first_stdout_line,
};
#[cfg(unix)]
pub use disk::{DiskUsage, disk_usage};
pub use listing::{Listing, listing};
pub use logs::{newest_matching, newest_rotated, try_newest_matching};
pub use manifest::{CollectedEntry, CollectorError, Manifest, Redaction, SkippedEntry};
#[cfg(unix)]
pub use system::{DiskInfo, SystemInfo, system_info};
#[cfg(unix)]
pub use terminal::{StreamInfo, TerminalInfo, WinSize, terminal_info};
