//! The diagnostic bundle's self-description.
//!
//! `manifest.json` is the first thing the dev team opens: it records what was
//! collected (and how it was transformed), what was deliberately withheld, and
//! which collectors failed — so an absent file is always explainable.

use serde::Serialize;

/// How a bundled file's content relates to the original.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Redaction {
    /// Copied verbatim.
    None,
    /// Secret-shaped values masked by key; structure preserved.
    Keys,
    /// Only names/sizes/metadata captured, never contents.
    ListingOnly,
    /// Only the trailing portion of a large file was captured.
    TailCapped,
    /// A streamed source exceeded its cap; only the leading portion was
    /// captured and the rest was discarded mid-stream.
    Truncated,
}

/// Top-level manifest, serialized as the bundle's `manifest.json`.
#[derive(Debug, Serialize)]
pub struct Manifest {
    /// Bump when the bundle layout changes incompatibly.
    pub schema_version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub cli_version: String,
    /// Wall-clock duration of the whole collection run.
    pub duration_ms: u64,
    pub collected: Vec<CollectedEntry>,
    pub skipped: Vec<SkippedEntry>,
    pub errors: Vec<CollectorError>,
}

pub const SCHEMA_VERSION: u32 = 1;

/// One file that made it into the bundle.
#[derive(Debug, Serialize)]
pub struct CollectedEntry {
    /// Path inside the bundle (relative to the bundle root).
    pub path: String,
    pub redaction: Redaction,
    pub bytes: u64,
}

/// Something deliberately not collected.
#[derive(Debug, Serialize)]
pub struct SkippedEntry {
    pub what: String,
    pub reason: String,
}

/// A collector that failed; the bundle carries on without its output.
#[derive(Debug, Serialize)]
pub struct CollectorError {
    pub collector: String,
    pub error: String,
    pub duration_ms: u64,
}
