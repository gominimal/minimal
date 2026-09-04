//! The diagnostic bundle's self-description.
//!
//! `manifest.json` is the first thing a bundle reader opens: it records what
//! was collected (and how it was transformed), what was deliberately
//! withheld, and which collectors failed — so an absent file is always
//! explainable.

use serde::Serialize;

/// How a bundled file's content relates to the original.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct Manifest {
    /// Bump when the bundle layout changes incompatibly.
    pub schema_version: u32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Version of the producing binary (CLI or daemon).
    pub version: String,
    /// Wall-clock duration of the whole collection run.
    pub duration_ms: u64,
    /// The project this bundle belongs to.
    pub project: ProjectScope,
    pub collected: Vec<CollectedEntry>,
    pub skipped: Vec<SkippedEntry>,
    pub errors: Vec<CollectorError>,
}

pub const SCHEMA_VERSION: u32 = 1;

/// What project a bundle was collected from.
///
/// Without it a bundle is a pile of host state: two bundles taken on one
/// machine from two checkouts read identically, so a report gets filed
/// against whichever project the reader guesses (#1211). Scope is what makes
/// a bundle attributable, which is why it sits in the manifest — the first
/// file a reader opens — rather than only in a collector's output.
///
/// The manifest's contract holds here too: absence is explainable.
/// [`ProjectScope::Unknown`] carries the reason there is no project, so
/// "collected outside a project" is a finding rather than a missing field.
#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
#[non_exhaustive]
pub enum ProjectScope {
    /// No project was resolved, for the reason given.
    Unknown { reason: String },
    /// The bundle is attributable to this project.
    Identified(ProjectIdentity),
}

impl ProjectScope {
    /// The scope a bundle carries until a producer records one. A producer
    /// with no notion of a project leaves this in place, which still answers
    /// a reader's "which project?" — with "this producer cannot say".
    pub fn unrecorded() -> Self {
        Self::Unknown {
            reason: "no project scope was recorded by the producer".to_string(),
        }
    }
}

/// The identity of the project a bundle came from.
///
/// Identity only. What the project *contains* — its packages, its tasks, its
/// environment — is the business of the collectors, which redact on their own
/// terms; nothing that could carry a configuration value belongs in the
/// manifest header.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct ProjectIdentity {
    /// The project's directory name — what its owner calls it.
    pub name: String,
    /// Absolute path of the project root on the producing host.
    pub root: String,
    /// The config file that makes the directory a project, relative to
    /// `root`: `minimal.toml` or `.minimal/minimal.toml`. Which of the two
    /// layouts is in play is worth knowing when a report says minimal never
    /// saw the config.
    pub config: String,
}

impl ProjectIdentity {
    /// Records a project by name, root, and the config file that defines it.
    /// A constructor rather than a struct literal because the type is
    /// `#[non_exhaustive]`: identity may grow a field, and producers should
    /// not have to be edited when it does.
    pub fn new(
        name: impl Into<String>,
        root: impl Into<String>,
        config: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            root: root.into(),
            config: config.into(),
        }
    }
}

/// One file that made it into the bundle.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct CollectedEntry {
    /// Path inside the bundle (relative to the bundle root).
    pub path: String,
    pub redaction: Redaction,
    pub bytes: u64,
}

/// Something deliberately not collected.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct SkippedEntry {
    pub what: String,
    pub reason: String,
}

/// A collector that failed; the bundle carries on without its output.
#[derive(Debug, Serialize)]
#[non_exhaustive]
pub struct CollectorError {
    pub collector: String,
    pub error: String,
    pub duration_ms: u64,
}
