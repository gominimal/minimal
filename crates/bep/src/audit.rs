//! The audit log: one JSONL record for every decision the proxy makes, in a
//! hash chain the proxy alone writes.
//!
//! A record is the F12 shape with a `kind` (BEP-039), so a box's trail reads
//! the same on an un-enrolled laptop as it will behind an enrolled identity
//! plane: the subject box, `act` and `txn` left empty, the upstream authority,
//! the member or store identifier or `none`, the mapped resource and
//! permission or `module_unmapped`, the decision and any marker. Every field
//! is a string the proxy already owns, which is how the log carries no
//! credential, no injected header value and no request body (BEP-040):
//! [`Record::new`] is given an [`Event`] and nothing else about the request.
//!
//! Each record carries as `previous_hash` the SHA-256 of the previous
//! record's line — the line's UTF-8 JSON bytes without the trailing newline,
//! its own `previous_hash` included — or [`Hash::ZERO`] for the first record
//! of a log (BEP-048). [`Hash::of_line`] is that whole construction, a pure
//! function over bytes, which is what a verifier and a later segment rotator
//! need of it.
//!
//! The log is opened for append only and no record in it is ever modified or
//! removed (BEP-041): [`Log::open`] finds the chain head by reading the last
//! line, and from then on the file only grows.
//!
//! A log that only grows would fill a laptop disk, so the active segment
//! rotates at [`SEGMENT_BYTES`]: the active file is renamed `<name>.<n>` and a
//! fresh one opened, with the chain head kept, so the first record of the new
//! segment carries the last record of the old one (BEP-068). [`segments`] is
//! the list a reader and a verifier walk, oldest first.
//!
//! Reading is [`Reader`], which `min box audit` renders: the records one
//! [`Subject`] wants — one box's, or every box under one — across the retained
//! segments, resumable so a `--follow` read tails what is appended after the
//! replay (BEP-042).

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

/// The audit schema every record names.
pub const SCHEMA: &str = "min/v1";

/// What the member or store identifier reads when the request carried none: an
/// off-module or unsealed request (BEP-039).
pub const NONE: &str = "none";

/// What the resource and permission read when the module maps the request to
/// neither (BEP-039).
pub const UNMAPPED: &str = "module_unmapped";

/// The size the active segment rotates at (BEP-068): 8 MiB, some tens of
/// thousands of records, which keeps one segment small enough to read and ship
/// in a support bundle while a busy host still rotates rarely.
pub const SEGMENT_BYTES: u64 = 8 * 1024 * 1024;

/// The SHA-256 of a record's line: what the next record carries as its
/// `previous_hash`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hash([u8; 32]);

impl Hash {
    /// The hash the first record of a log carries (BEP-048).
    pub const ZERO: Self = Self([0u8; 32]);

    /// The hash of `line`: a record's UTF-8 JSON bytes without the trailing
    /// newline the log writes after them.
    #[must_use]
    pub fn of_line(line: &[u8]) -> Self {
        Self(Sha256::digest(line).into())
    }

    /// The raw digest.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for Hash {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        let mut digest = [0u8; 32];
        hex::decode_to_slice(&text, &mut digest)
            .map_err(|_| D::Error::custom("a record hash is 64 hex digits"))?;
        Ok(Self(digest))
    }
}

/// What a record is about: the proxy's own account of a request, or an
/// identity event the client submits over the control socket (BEP-067).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Kind {
    /// The proxy admitted or refused a request.
    Decision,
    /// The client minted a member.
    Mint,
    /// The client revoked members.
    Revocation,
}

impl fmt::Display for Kind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Decision => "decision",
            Self::Mint => "mint",
            Self::Revocation => "revocation",
        })
    }
}

/// How a request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Decision {
    /// Forwarded, with or without a credential injected.
    Admit,
    /// Refused, with the marker the refusal names.
    Refuse,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Admit => "admit",
            Self::Refuse => "refuse",
        })
    }
}

/// What the module mapped the request to, if anything.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mapping {
    /// The resource and permission the module maps the request to.
    Mapped {
        /// The mapped resource.
        resource: String,
        /// The permission the request needs on it.
        permission: String,
    },
    /// The module maps the request to no resource or permission, so both
    /// fields of the record read [`UNMAPPED`].
    Unmapped,
}

impl Mapping {
    /// A mapped resource and permission.
    #[must_use]
    pub fn mapped(resource: impl Into<String>, permission: impl Into<String>) -> Self {
        Self::Mapped {
            resource: resource.into(),
            permission: permission.into(),
        }
    }

    /// The record's `resource` and `permission` fields.
    fn fields(&self) -> (&str, &str) {
        match self {
            Self::Mapped {
                resource,
                permission,
            } => (resource, permission),
            Self::Unmapped => (UNMAPPED, UNMAPPED),
        }
    }
}

/// Everything a record says besides its chain field: the BEP-039 field set.
///
/// The proxy fills it from the decision it has just made, never from the
/// request's bytes, so no credential, injected header value or request body
/// can reach the log through it (BEP-040).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Whether this is the proxy's decision or a client's identity event.
    pub kind: Kind,
    /// The box the record is about.
    #[serde(rename = "box")]
    pub box_id: String,
    /// The upstream authority the request named.
    pub authority: String,
    /// The member or store identifier, or `None` for an off-module or
    /// unsealed request, which records [`NONE`].
    pub credential: Option<String>,
    /// What the module mapped the request to.
    pub mapping: Mapping,
    /// How the request ended.
    pub decision: Decision,
    /// The marker the outcome names (`off_module`, `foreign_credential`,
    /// `injection_invalid`, `cohort_attributed`, …), or `None`.
    pub marker: Option<String>,
}

/// One line of the audit log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The audit schema: always [`SCHEMA`].
    pub schema: String,
    /// Whether this is the proxy's decision or a client's identity event.
    pub kind: Kind,
    /// The subject box.
    pub sub: String,
    /// The actor, left empty until a host enrolls.
    pub act: String,
    /// The transaction, left empty until a host enrolls.
    pub txn: String,
    /// The upstream authority.
    pub authority: String,
    /// The member or store identifier, or [`NONE`].
    pub credential: String,
    /// The mapped resource, or [`UNMAPPED`].
    pub resource: String,
    /// The permission the request needed, or [`UNMAPPED`].
    pub permission: String,
    /// How the request ended.
    pub decision: Decision,
    /// The outcome's marker, empty when it names none.
    pub marker: String,
    /// The hash of the previous record's line (BEP-048).
    pub previous_hash: Hash,
}

impl Record {
    /// The record `event` makes when the log's last line hashes to
    /// `previous`, or [`Hash::ZERO`] when the log holds no record yet.
    #[must_use]
    pub fn new(event: &Event, previous: Hash) -> Self {
        let (resource, permission) = event.mapping.fields();
        Self {
            schema: SCHEMA.to_owned(),
            kind: event.kind,
            sub: event.box_id.clone(),
            act: String::new(),
            txn: String::new(),
            authority: event.authority.clone(),
            credential: event.credential.clone().unwrap_or_else(|| NONE.to_owned()),
            resource: resource.to_owned(),
            permission: permission.to_owned(),
            decision: event.decision,
            marker: event.marker.clone().unwrap_or_default(),
            previous_hash: previous,
        }
    }

    /// The record's line: its UTF-8 JSON bytes, without the newline the log
    /// writes after them.
    ///
    /// # Panics
    ///
    /// Never: a record is strings and a hash, which JSON always encodes.
    #[must_use]
    pub fn line(&self) -> String {
        serde_json_lenient::to_string(self).expect("a record of strings encodes as JSON")
    }

    /// The hash the next record carries: [`Hash::of_line`] of this record's
    /// line, so the chain covers this record's own `previous_hash` too.
    #[must_use]
    pub fn line_hash(&self) -> Hash {
        Hash::of_line(self.line().as_bytes())
    }
}

/// Why a record could not be appended.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AuditError {
    /// The log could not be opened for append.
    #[error("opening the audit log {} for append: {source}", path.display())]
    Open {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The log's last line, which the next record chains onto, is unreadable.
    #[error("reading the chain head of the audit log {}: {source}", path.display())]
    Head {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The record could not be written.
    #[error("appending a record to the audit log {}: {source}", path.display())]
    Append {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// The active segment could not be rotated at its size bound.
    #[error("rotating the audit log {} to {}: {source}", path.display(), segment.display())]
    Rotate {
        path: PathBuf,
        segment: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A segment a read covers could not be read.
    #[error("reading the audit log {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    /// A segment holds a line that is no record.
    #[error("the audit log {} holds a line that is no record: {source}", path.display())]
    Malformed {
        path: PathBuf,
        #[source]
        source: serde_json_lenient::Error,
    },
}

/// The one way the audit log is ever opened: for append, created when absent,
/// never truncated and never positioned by the writer (BEP-041).
fn append_options() -> OpenOptions {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    options
}

/// The hash of the last record in the log at `path`: the SHA-256 of its final
/// non-empty line, or [`Hash::ZERO`] when the log is absent or empty.
fn head_of(path: &Path) -> Result<Hash, AuditError> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(Hash::ZERO),
        Err(source) => {
            return Err(AuditError::Head {
                path: path.to_path_buf(),
                source,
            });
        }
    };
    Ok(bytes
        .split(|byte| *byte == b'\n')
        .rev()
        .find(|line| !line.is_empty())
        .map_or(Hash::ZERO, Hash::of_line))
}

/// The hash the next record of the log appends onto: the last record's line
/// hash from the newest segment holding a record, or [`Hash::ZERO`] when no
/// segment holds one.
///
/// The walk back past an empty active segment is what keeps the chain
/// continuous when a rotation was the last thing that happened to the log
/// (BEP-068): a proxy restarting then would otherwise read an empty active
/// segment as the start of a log and chain the next record onto nothing.
fn head_of_log(active: &Path) -> Result<Hash, AuditError> {
    for segment in segments(active)?.iter().rev() {
        let head = head_of(segment)?;
        if head != Hash::ZERO {
            return Ok(head);
        }
    }
    Ok(Hash::ZERO)
}

/// The records every segment of the log at `active` holds, oldest first, each
/// with its position: its index among all of them, counting from zero.
///
/// A record's position is how the log orders it against every other, across
/// rotations: a revocation covers what was minted before it and nothing after
/// ([`crate::control::Revocations`]). A segment that is not there holds none.
///
/// # Errors
///
/// [`AuditError::Read`] when a segment cannot be read, or
/// [`AuditError::Malformed`] when one holds a line that is no record.
pub fn positioned(active: &Path) -> Result<Vec<(u64, Record)>, AuditError> {
    let mut records = Vec::new();
    for segment in segments(active)? {
        for line in record_lines(&segment)? {
            let record: Record =
                serde_json_lenient::from_str(&line).map_err(|source| AuditError::Malformed {
                    path: segment.clone(),
                    source,
                })?;
            records.push((u64::try_from(records.len()).unwrap_or(u64::MAX), record));
        }
    }
    Ok(records)
}

/// How many records every segment of the log at `active` holds.
fn records_in(active: &Path) -> Result<u64, AuditError> {
    let mut records = 0u64;
    for segment in segments(active)? {
        records += u64::try_from(record_lines(&segment)?.len()).unwrap_or(u64::MAX);
    }
    Ok(records)
}

/// The lines of `segment` that hold a record: every line but a blank one, and
/// none when the segment is not there.
fn record_lines(segment: &Path) -> Result<Vec<String>, AuditError> {
    match std::fs::read(segment) {
        Ok(bytes) => Ok(bytes
            .split(|byte| *byte == b'\n')
            .map(String::from_utf8_lossy)
            .filter(|line| !line.trim().is_empty())
            .map(std::borrow::Cow::into_owned)
            .collect()),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(source) => Err(AuditError::Read {
            path: segment.to_path_buf(),
            source,
        }),
    }
}

/// The index of a rotated segment of the log named `active`: `<active>.<n>`,
/// with `n` a decimal index, or `None` for any other name.
fn rotated_index(path: &Path, active: &str) -> Option<u32> {
    path.file_name()?
        .to_str()?
        .strip_prefix(active)?
        .strip_prefix('.')?
        .parse()
        .ok()
}

/// The log's segments, oldest first: the rotated `<name>.<n>` segments in index
/// order, then the active `<name>` (BEP-068).
///
/// The active segment is always last and always named, whether or not it
/// exists: a host whose proxy has never run has no file, which a read takes as
/// empty rather than as an error.
///
/// # Errors
///
/// [`AuditError::Read`] when the directory holding the log cannot be read.
pub fn segments(active: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut rotated: Vec<(u32, PathBuf)> = Vec::new();
    let name = active.file_name().and_then(|name| name.to_str());
    if let (Some(dir), Some(name)) = (active.parent(), name) {
        match std::fs::read_dir(dir) {
            Ok(entries) => {
                for entry in entries {
                    let path = entry
                        .map_err(|source| AuditError::Read {
                            path: dir.to_path_buf(),
                            source,
                        })?
                        .path();
                    if let Some(index) = rotated_index(&path, name) {
                        rotated.push((index, path));
                    }
                }
            }
            // No directory yet is no segment yet, as an absent log is.
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(AuditError::Read {
                    path: dir.to_path_buf(),
                    source,
                });
            }
        }
    }
    rotated.sort_unstable();
    Ok(rotated
        .into_iter()
        .map(|(_, path)| path)
        .chain([active.to_path_buf()])
        .collect())
}

/// The audit log, open for append.
///
/// The proxy holds one and is the log's sole writer, so the head read, the
/// append and the chain advance are one operation in one process and two
/// records can never share a predecessor (BEP-067).
#[derive(Debug)]
pub struct Log {
    path: PathBuf,
    file: File,
    head: Hash,
    /// How many records every segment holds: the position the next record
    /// takes.
    records: u64,
    /// The bytes the active segment holds.
    size: u64,
    /// The size the active segment rotates at (BEP-068).
    bound: u64,
}

impl Log {
    /// Opens the log at `path` for append, creating it when absent, and reads
    /// the chain head from the newest segment holding a record.
    ///
    /// # Errors
    ///
    /// When the log cannot be opened for append, or its last line cannot be
    /// read.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, AuditError> {
        let path = path.into();
        let file = append_options()
            .open(&path)
            .map_err(|source| AuditError::Open {
                path: path.clone(),
                source,
            })?;
        let size = file
            .metadata()
            .map_err(|source| AuditError::Head {
                path: path.clone(),
                source,
            })?
            .len();
        let head = head_of_log(&path)?;
        let records = records_in(&path)?;
        Ok(Self {
            path,
            file,
            head,
            records,
            size,
            bound: SEGMENT_BYTES,
        })
    }

    /// The same log rotating at `bound` bytes instead of [`SEGMENT_BYTES`]. A
    /// bound of zero rotates after every record.
    #[must_use]
    pub fn with_segment_bytes(mut self, bound: u64) -> Self {
        self.bound = bound;
        self
    }

    /// The hash the next record will carry: the last record's, or
    /// [`Hash::ZERO`] while the log holds none.
    #[must_use]
    pub fn head(&self) -> Hash {
        self.head
    }

    /// The log's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// How many records the log holds across every segment: the position the
    /// next record appended takes, counting from zero.
    #[must_use]
    pub fn records(&self) -> u64 {
        self.records
    }

    /// Appends the one record `event` makes and returns it, rotating the active
    /// segment first when it has reached its size bound (BEP-068).
    ///
    /// # Errors
    ///
    /// When the segment cannot be rotated, or the record cannot be written.
    pub fn append(&mut self, event: &Event) -> Result<Record, AuditError> {
        if self.size >= self.bound {
            self.rotate()?;
        }
        let record = Record::new(event, self.head);
        let mut line = record.line().into_bytes();
        let hash = Hash::of_line(&line);
        line.push(b'\n');
        self.file
            .write_all(&line)
            .map_err(|source| AuditError::Append {
                path: self.path.clone(),
                source,
            })?;
        self.head = hash;
        self.records += 1;
        self.size += u64::try_from(line.len()).unwrap_or(u64::MAX);
        tracing::info!(
            kind = %record.kind,
            box_id = %record.sub,
            decision = %record.decision,
            marker = %record.marker,
            "appended audit record"
        );
        Ok(record)
    }

    /// Renames the active segment to the next `<name>.<n>` and opens a fresh
    /// one, keeping the chain head so the first record of the new segment
    /// carries the final hash of the segment before it (BEP-068).
    fn rotate(&mut self) -> Result<(), AuditError> {
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        let next = segments(&self.path)?
            .iter()
            .filter_map(|segment| rotated_index(segment, name))
            .max()
            .unwrap_or(0)
            + 1;
        let segment = self.path.with_file_name(format!("{name}.{next}"));
        std::fs::rename(&self.path, &segment).map_err(|source| AuditError::Rotate {
            path: self.path.clone(),
            segment: segment.clone(),
            source,
        })?;
        self.file = append_options()
            .open(&self.path)
            .map_err(|source| AuditError::Open {
                path: self.path.clone(),
                source,
            })?;
        self.size = 0;
        tracing::info!(
            segment = %segment.display(),
            previous_hash = %self.head,
            "rotated the audit log",
        );
        Ok(())
    }
}

/// What separates a parent box from a child in a record's subject. A box's own
/// name never carries it — session names are alphanumerics, `-`, `_` and `.` —
/// so a subject holding one names a box under another.
pub const CHILD_SEPARATOR: char = '/';

/// What separates a box's name from the id of its creation in the subject a
/// value is sealed for and a revocation names: `<name>@<id>`. No session name
/// carries it either.
pub const INSTANCE_SEPARATOR: char = '@';

/// The subject a box named `name`, created as `instance`, is known by: unique
/// per creation, so a box made again under a name that was used before is a
/// different subject, and the revocation of the one before does not reach it
/// (BEP-043). The name leads, so the trail still reads by name.
#[must_use]
pub fn box_subject(name: &str, instance: &str) -> String {
    format!("{name}{INSTANCE_SEPARATOR}{instance}")
}

/// The name of the box `subject` names: what a person calls it, with the id
/// of its creation left off.
#[must_use]
pub fn box_name(subject: &str) -> &str {
    subject
        .split_once(INSTANCE_SEPARATOR)
        .map_or(subject, |(name, _)| name)
}

/// Which records a read of the log wants (BEP-042).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subject {
    /// One box's records and no other's, whether or not the box still
    /// exists: the log is the proxy's, so a reaped box's trail stays in it.
    /// A name reads every box ever created under it, each record naming its
    /// own creation; a `<name>@<id>` subject reads that one creation.
    Box(String),
    /// The records of every box under one, merged onto the one stream each
    /// record names its own box on.
    Children(String),
}

impl Subject {
    /// Whether a record whose subject is `sub` belongs in this read.
    #[must_use]
    pub fn admits(&self, sub: &str) -> bool {
        match self {
            Self::Box(box_id) => {
                sub == box_id
                    || sub
                        .strip_prefix(box_id.as_str())
                        .and_then(|rest| rest.strip_prefix(INSTANCE_SEPARATOR))
                        .is_some_and(|instance| {
                            !instance.is_empty() && !instance.contains(CHILD_SEPARATOR)
                        })
            }
            Self::Children(parent) => sub
                .strip_prefix(parent.as_str())
                .and_then(|under| under.strip_prefix(CHILD_SEPARATOR))
                .is_some_and(|child| !child.is_empty()),
        }
    }
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Box(box_id) => f.write_str(box_id),
            Self::Children(parent) => write!(f, "{parent}{CHILD_SEPARATOR}*"),
        }
    }
}

/// A read of the audit log: the records one [`Subject`] wants, across every
/// retained segment, oldest first (BEP-042).
///
/// A reader remembers how far into each segment it has read, so reading again
/// returns only what was appended since — which is what `min box audit
/// --follow` tails with. Only whole lines are ever taken: a line the proxy
/// has not finished writing is left for the next read. A segment that is not
/// there reads as empty, because a host whose proxy has never run has no log.
#[derive(Debug)]
pub struct Reader {
    /// The segments, oldest first.
    segments: Vec<PathBuf>,
    /// The bytes of each segment already returned, parallel to `segments`.
    read: Vec<u64>,
}

impl Reader {
    /// A read over `segments`, oldest first.
    #[must_use]
    pub fn open(segments: impl IntoIterator<Item = PathBuf>) -> Self {
        let segments: Vec<PathBuf> = segments.into_iter().collect();
        Self {
            read: vec![0; segments.len()],
            segments,
        }
    }

    /// How many segments the read covers.
    #[must_use]
    pub fn segments(&self) -> usize {
        self.segments.len()
    }

    /// The records `subject` wants that this reader has not returned yet, in
    /// the order the log holds them.
    ///
    /// # Errors
    ///
    /// [`AuditError::Read`] when a segment cannot be read, or
    /// [`AuditError::Malformed`] when one holds a line that is no record.
    pub fn read(&mut self, subject: &Subject) -> Result<Vec<Record>, AuditError> {
        let mut records = Vec::new();
        for (segment, read) in self.segments.iter().zip(&mut self.read) {
            let bytes = match std::fs::read(segment) {
                Ok(bytes) => bytes,
                Err(source) if source.kind() == io::ErrorKind::NotFound => continue,
                Err(source) => {
                    return Err(AuditError::Read {
                        path: segment.clone(),
                        source,
                    });
                }
            };
            let from = usize::try_from(*read)
                .unwrap_or(usize::MAX)
                .min(bytes.len());
            let mut taken = 0;
            for line in bytes[from..].split_inclusive(|byte| *byte == b'\n') {
                // A line with no newline yet is still being written: leave it.
                if !line.ends_with(b"\n") {
                    break;
                }
                taken += line.len();
                let text = String::from_utf8_lossy(&line[..line.len() - 1]);
                if text.trim().is_empty() {
                    continue;
                }
                let record: Record = serde_json_lenient::from_str(&text).map_err(|source| {
                    AuditError::Malformed {
                        path: segment.clone(),
                        source,
                    }
                })?;
                if subject.admits(&record.sub) {
                    records.push(record);
                }
            }
            *read = u64::try_from(from + taken).unwrap_or(u64::MAX);
        }
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek as _, SeekFrom, Write as _};

    use proptest::prelude::*;

    use super::*;

    fn decision(box_id: &str, authority: &str, decision: Decision) -> Event {
        Event {
            kind: Kind::Decision,
            box_id: box_id.to_owned(),
            authority: authority.to_owned(),
            credential: Some("github:user-token".to_owned()),
            mapping: Mapping::mapped("repo:acme/widgets", "contents:write"),
            decision,
            marker: None,
        }
    }

    /// The log's records, each without its newline.
    fn lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    /// BEP-039: one admit or refuse is one JSONL record under `min/v1`,
    /// carrying the field set the requirement names and nothing besides.
    #[test]
    fn every_decision_appends_one_audit_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        assert!(lines(&path).is_empty());

        let mut off_module = decision("box-a1", "packages.example", Decision::Refuse);
        off_module.credential = None;
        off_module.mapping = Mapping::Unmapped;
        off_module.marker = Some("off_module".to_owned());
        let events = [
            decision("box-a1", "api.github.com", Decision::Admit),
            off_module,
            decision("box-b2", "codeload.github.com", Decision::Admit),
        ];

        let mut appended = Vec::new();
        for (already, event) in events.iter().enumerate() {
            appended.push(log.append(event).unwrap());
            // One decision, one record: the log grew by exactly one line.
            assert_eq!(lines(&path).len(), already + 1);
        }

        // Every line is the record the append returned, and its fields are
        // the requirement's fields and the chain field, with nothing else
        // riding along.
        for (line, record) in lines(&path).iter().zip(&appended) {
            assert_eq!(
                &serde_json_lenient::from_str::<Record>(line).unwrap(),
                record
            );
            let object: std::collections::BTreeMap<String, serde_json_lenient::Value> =
                serde_json_lenient::from_str(line).unwrap();
            assert_eq!(
                object.keys().map(String::as_str).collect::<Vec<_>>(),
                [
                    "act",
                    "authority",
                    "credential",
                    "decision",
                    "kind",
                    "marker",
                    "permission",
                    "previous_hash",
                    "resource",
                    "schema",
                    "sub",
                    "txn",
                ]
            );
        }

        let admitted = &appended[0];
        assert_eq!(admitted.schema, SCHEMA);
        assert_eq!(admitted.kind, Kind::Decision);
        assert_eq!(admitted.sub, "box-a1");
        assert_eq!((admitted.act.as_str(), admitted.txn.as_str()), ("", ""));
        assert_eq!(admitted.authority, "api.github.com");
        assert_eq!(admitted.credential, "github:user-token");
        assert_eq!(admitted.resource, "repo:acme/widgets");
        assert_eq!(admitted.permission, "contents:write");
        assert_eq!(admitted.decision, Decision::Admit);
        assert_eq!(admitted.marker, "");

        // A refusal off the module names no credential and no mapping, and
        // carries the marker the refusal states.
        let refused = &appended[1];
        assert_eq!(refused.decision, Decision::Refuse);
        assert_eq!(refused.credential, NONE);
        assert_eq!(refused.resource, UNMAPPED);
        assert_eq!(refused.permission, UNMAPPED);
        assert_eq!(refused.marker, "off_module");

        // Each box is the subject of its own record only.
        assert_eq!(appended[2].sub, "box-b2");
        assert_eq!(
            appended.iter().filter(|r| r.sub == "box-a1").count(),
            2,
            "two of the three decisions are box-a1's"
        );
    }

    /// BEP-048: the first record carries the all-zero hash and every later one
    /// carries the SHA-256 of the previous line as the log holds it, its own
    /// `previous_hash` included and the trailing newline excluded.
    #[test]
    fn audit_record_carries_previous_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        assert_eq!(log.head(), Hash::ZERO);

        let first = log
            .append(&decision("box-a1", "api.github.com", Decision::Admit))
            .unwrap();
        assert_eq!(first.previous_hash, Hash::ZERO);
        assert_eq!(first.previous_hash.to_string(), "0".repeat(64));

        let second = log
            .append(&decision("box-a1", "github.com", Decision::Refuse))
            .unwrap();
        let held = lines(&path);
        // The hash is over the whole previous line, which carries a
        // `previous_hash` of its own.
        assert!(held[0].contains(&format!(r#""previous_hash":"{}""#, "0".repeat(64))));
        assert_eq!(second.previous_hash, Hash::of_line(held[0].as_bytes()));
        let digest: [u8; 32] = Sha256::digest(held[0].as_bytes()).into();
        assert_eq!(second.previous_hash.as_bytes(), &digest);
        // The newline is not part of the hashed bytes.
        assert_ne!(
            second.previous_hash,
            Hash::of_line(format!("{}\n", held[0]).as_bytes())
        );

        // A reopen finds the head from the file alone, so the chain survives a
        // proxy restart.
        drop(log);
        let mut reopened = Log::open(&path).unwrap();
        assert_eq!(reopened.head(), Hash::of_line(held[1].as_bytes()));
        let third = reopened
            .append(&decision("box-b2", "uploads.github.com", Decision::Admit))
            .unwrap();
        assert_eq!(third.previous_hash, second.line_hash());

        // End to end: every line's hash is the next line's `previous_hash`.
        let held = lines(&path);
        assert_eq!(held.len(), 3);
        for pair in held.windows(2) {
            let next: Record = serde_json_lenient::from_str(&pair[1]).unwrap();
            assert_eq!(next.previous_hash, Hash::of_line(pair[0].as_bytes()));
        }
        assert_eq!(reopened.head(), Hash::of_line(held[2].as_bytes()));
    }

    /// BEP-041: the log is opened for append and nothing already in it is
    /// modified or removed, across appends and across reopens.
    #[test]
    fn audit_log_is_opened_append_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");

        // The options the log is opened with keep what is there and put every
        // write at the end, even from a caller that has sought to the start.
        std::fs::write(&path, b"first\n").unwrap();
        let mut file = append_options().open(&path).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(b"second\n").unwrap();
        drop(file);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "first\nsecond\n");
        std::fs::remove_file(&path).unwrap();

        // Through the log: each append only extends the file, and the bytes
        // already written stay byte for byte what they were.
        let mut log = Log::open(&path).unwrap();
        let mut grew = vec![std::fs::read(&path).unwrap()];
        for authority in ["api.github.com", "github.com", "codeload.github.com"] {
            log.append(&decision("box-a1", authority, Decision::Admit))
                .unwrap();
            grew.push(std::fs::read(&path).unwrap());
        }
        for pair in grew.windows(2) {
            assert!(pair[1].starts_with(&pair[0]), "an append rewrote the log");
            assert!(pair[1].len() > pair[0].len());
        }

        // A reopen keeps every record and appends after them.
        let before = std::fs::read(&path).unwrap();
        drop(log);
        let mut reopened = Log::open(&path).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            before,
            "opening truncated the log"
        );
        reopened
            .append(&decision("box-a1", "api.github.com", Decision::Refuse))
            .unwrap();
        let after = std::fs::read(&path).unwrap();
        assert!(
            after.starts_with(&before),
            "a reopened log rewrote a record"
        );
        assert_eq!(lines(&path).len(), 4);
    }

    /// BEP-068: the active segment rotates when it reaches its size bound, the
    /// first record of the new segment carries the final hash of the segment
    /// before it, and the whole log stays one chain — across a reopen, and
    /// across a reopen that finds the active segment empty because a rotation
    /// was the last thing that happened.
    #[test]
    fn segment_rotation_continues_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        // A one-byte bound rotates at every append after the first, so each
        // segment holds one record: the boundary, not the size, is what the
        // chain has to survive.
        let mut log = Log::open(&path).unwrap().with_segment_bytes(1);
        let mut appended = Vec::new();
        for authority in ["api.github.com", "github.com", "codeload.github.com"] {
            appended.push(
                log.append(&decision("web", authority, Decision::Admit))
                    .unwrap(),
            );
        }

        // Three records, three segments: the rotated ones oldest first, then
        // the active segment last.
        let held = segments(&path).unwrap();
        assert_eq!(
            held,
            vec![
                dir.path().join("audit.log.1"),
                dir.path().join("audit.log.2"),
                path.clone(),
            ]
        );
        for segment in &held {
            assert_eq!(lines(segment).len(), 1, "{}", segment.display());
        }

        // Every boundary is chained: the first record of each new segment
        // carries the hash of the last line of the one before it.
        for pair in held.windows(2) {
            let opening: Record = serde_json_lenient::from_str(&lines(&pair[1])[0]).unwrap();
            assert_eq!(
                opening.previous_hash,
                Hash::of_line(lines(&pair[0]).last().unwrap().as_bytes()),
                "{} does not continue {}",
                pair[1].display(),
                pair[0].display()
            );
        }
        assert_eq!(appended[0].previous_hash, Hash::ZERO);
        assert_eq!(appended[2].previous_hash, appended[1].line_hash());

        // A reopen continues the chain from the active segment.
        drop(log);
        let mut reopened = Log::open(&path).unwrap();
        let fourth = reopened
            .append(&decision("web", "uploads.github.com", Decision::Admit))
            .unwrap();
        assert_eq!(fourth.previous_hash, appended[2].line_hash());
        drop(reopened);

        // And from the newest rotated segment when the active one is empty: a
        // rotation with nothing appended after it is not the start of a log.
        std::fs::rename(&path, dir.path().join("audit.log.3")).unwrap();
        let mut rotated = Log::open(&path).unwrap();
        assert_eq!(rotated.head(), fourth.line_hash());
        let fifth = rotated
            .append(&decision("web", "github.com", Decision::Refuse))
            .unwrap();
        assert_eq!(fifth.previous_hash, fourth.line_hash());

        // End to end: every record of every segment, oldest first, is one
        // chain from the zero hash.
        let bytes: Vec<Vec<u8>> = segments(&path)
            .unwrap()
            .iter()
            .map(|segment| std::fs::read(segment).unwrap_or_default())
            .collect();
        let mut links = Vec::new();
        for segment in &bytes {
            links.extend(crate::chain::links(segment).unwrap());
        }
        assert_eq!(links.len(), 5);
        assert_eq!(
            crate::chain::verify(links.iter().copied(), Hash::ZERO).unwrap(),
            fifth.line_hash()
        );
    }

    /// BEP-042: a read returns the records of the subject it names and no
    /// other's — one box, or every box under one — takes only whole lines, and
    /// returns each record once, so a later read carries only what was
    /// appended since.
    #[test]
    fn audit_reader_filters_by_subject() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        for event in [
            decision("web", "api.github.com", Decision::Admit),
            decision("api", "github.com", Decision::Admit),
            decision("web/agent-1", "api.github.com", Decision::Refuse),
            decision("web", "codeload.github.com", Decision::Admit),
            decision("web/task-build", "uploads.github.com", Decision::Admit),
            decision("api/agent-1", "api.github.com", Decision::Admit),
        ] {
            log.append(&event).unwrap();
        }

        // One box: its own records, in log order, and nothing of the box whose
        // name it is a prefix of.
        let mut reader = Reader::open([path.clone()]);
        assert_eq!(reader.segments(), 1);
        let web = reader.read(&Subject::Box("web".to_owned())).unwrap();
        assert_eq!(
            web.iter()
                .map(|record| record.authority.as_str())
                .collect::<Vec<_>>(),
            ["api.github.com", "codeload.github.com"]
        );
        assert!(web.iter().all(|record| record.sub == "web"));

        // Read again and the same records do not come back; a record appended
        // after the first read does.
        assert!(
            reader
                .read(&Subject::Box("web".to_owned()))
                .unwrap()
                .is_empty()
        );
        log.append(&decision("web", "github.com", Decision::Refuse))
            .unwrap();
        let tailed = reader.read(&Subject::Box("web".to_owned())).unwrap();
        assert_eq!(tailed.len(), 1);
        assert_eq!(tailed[0].authority, "github.com");

        // Every box under one, merged onto one stream in log order, each
        // record naming its own box — never the parent's own records, and
        // never another parent's children.
        let mut children = Reader::open([path.clone()]);
        let under_web = children.read(&Subject::Children("web".to_owned())).unwrap();
        assert_eq!(
            under_web
                .iter()
                .map(|record| record.sub.as_str())
                .collect::<Vec<_>>(),
            ["web/agent-1", "web/task-build"]
        );

        // A line still being written is left for the next read.
        let mut partial = Reader::open([path.clone()]);
        let full = std::fs::read_to_string(&path).unwrap();
        partial.read(&Subject::Box("web".to_owned())).unwrap();
        let half = decision("web", "api.github.com", Decision::Admit);
        let held = Record::new(&half, Hash::ZERO).line();
        std::fs::write(&path, format!("{full}{held}")).unwrap();
        assert!(
            partial
                .read(&Subject::Box("web".to_owned()))
                .unwrap()
                .is_empty()
        );
        std::fs::write(&path, format!("{full}{held}\n")).unwrap();
        assert_eq!(
            partial.read(&Subject::Box("web".to_owned())).unwrap().len(),
            1
        );

        // A segment that is not there reads as empty: a host whose proxy has
        // never run has no log, not an error.
        let mut absent = Reader::open([dir.path().join("rotated.jsonl")]);
        assert!(
            absent
                .read(&Subject::Box("web".to_owned()))
                .unwrap()
                .is_empty()
        );

        // A line that is no record is named, not skipped.
        std::fs::write(&path, format!("{full}not a record\n")).unwrap();
        let mut broken = Reader::open([path.clone()]);
        let error = broken
            .read(&Subject::Box("web".to_owned()))
            .expect_err("a line that is no record is an error");
        assert!(matches!(error, AuditError::Malformed { .. }), "{error}");
    }

    /// A box's name reads every box created under it, each by its own
    /// subject, and a subject with its creation's id reads that one: a box
    /// made again under a used name is a different subject, and its trail is
    /// still found by name.
    #[test]
    fn a_box_name_reads_every_creation_under_it() {
        let first = box_subject("web", "0199a4c2");
        let second = box_subject("web", "0199a4d7");
        assert_eq!(first, "web@0199a4c2");
        assert_eq!(box_name(&first), "web");
        assert_eq!(box_name("web"), "web");

        let by_name = Subject::Box("web".to_owned());
        for sub in ["web", first.as_str(), second.as_str()] {
            assert!(by_name.admits(sub), "{sub}");
        }
        // Not another box whose name it prefixes, not a creation with no id,
        // and not a box under one of its creations.
        for sub in ["webapp", "webapp@0199a4c2", "web@", "web@0199a4c2/agent-1"] {
            assert!(!by_name.admits(sub), "{sub}");
        }

        let one = Subject::Box(first.clone());
        assert!(one.admits(&first));
        assert!(!one.admits(&second));
        assert!(!one.admits("web"));
    }

    /// A request as the proxy handles it: the fields it may record, and the
    /// material it may not — the member's credential, the store's value, the
    /// header value it injects and the body.
    #[derive(Debug, Clone)]
    struct Request {
        event: Event,
        credential: String,
        store_value: String,
        injected_header: String,
        body: String,
    }

    impl Request {
        /// What no record of this request may carry.
        fn withheld(&self) -> [&str; 4] {
            [
                &self.credential,
                &self.store_value,
                &self.injected_header,
                &self.body,
            ]
        }
    }

    /// The characters a field value is built from: lowercase, so no withheld
    /// value can be a substring of one.
    const FIELD_CHARS: [char; 14] = [
        'a', 'b', 'e', 'i', 'm', 'o', 'z', '0', '5', '9', ':', '/', '.', '-',
    ];

    /// The characters a withheld value is built from: uppercase and digits, so
    /// it can be a substring of no field value, of no record literal and of no
    /// hex hash.
    const WITHHELD_CHARS: [char; 10] = ['A', 'B', 'K', 'P', 'T', 'Z', '1', '4', '7', '8'];

    fn from_chars(
        alphabet: &'static [char],
        len: std::ops::Range<usize>,
    ) -> impl Strategy<Value = String> {
        prop::collection::vec(0..alphabet.len(), len)
            .prop_map(move |picks| picks.into_iter().map(|at| alphabet[at]).collect::<String>())
    }

    /// A field value the proxy owns and may record.
    fn field() -> impl Strategy<Value = String> {
        from_chars(&FIELD_CHARS, 0..20)
    }

    /// Material the record may never carry. Tagged, so its presence in a line
    /// can only come from the writer.
    fn withheld() -> impl Strategy<Value = String> {
        from_chars(&WITHHELD_CHARS, 8..32).prop_map(|tail| format!("SECRET-{tail}"))
    }

    fn event() -> impl Strategy<Value = Event> {
        (
            prop_oneof![
                Just(Kind::Decision),
                Just(Kind::Mint),
                Just(Kind::Revocation)
            ],
            field(),
            field(),
            proptest::option::of(field()),
            prop_oneof![
                (field(), field()).prop_map(|(r, p)| Mapping::mapped(r, p)),
                Just(Mapping::Unmapped),
            ],
            prop_oneof![Just(Decision::Admit), Just(Decision::Refuse)],
            proptest::option::of(field()),
        )
            .prop_map(
                |(kind, box_id, authority, credential, mapping, decision, marker)| Event {
                    kind,
                    box_id,
                    authority,
                    credential,
                    mapping,
                    decision,
                    marker,
                },
            )
    }

    fn request() -> impl Strategy<Value = Request> {
        (event(), withheld(), withheld(), withheld(), withheld()).prop_map(
            |(event, credential, store_value, injected_header, body)| Request {
                event,
                credential,
                store_value,
                injected_header,
                body,
            },
        )
    }

    proptest! {
        /// BEP-040: two requests alike in every BEP-039 field and differing
        /// only in what the record may not carry produce the same record but
        /// for the chain field, and neither log holds any of that material.
        #[test]
        fn prop_audit_records_never_contain_secrets(
            one in request(),
            two in request(),
            prefix in prop::collection::vec(event(), 0..3),
        ) {
            let mut two = two;
            // Identical in every field of the record's field set; different
            // credential, store value, injected header and body.
            two.event = one.event.clone();

            let dir = tempfile::tempdir().unwrap();
            let (first, second) = (dir.path().join("a.jsonl"), dir.path().join("b.jsonl"));
            let mut a = Log::open(&first).unwrap();
            let mut b = Log::open(&second).unwrap();
            for earlier in &prefix {
                b.append(earlier).unwrap();
            }

            let one_record = a.append(&one.event).unwrap();
            let two_record = b.append(&two.event).unwrap();

            // The records differ in the chain field alone.
            prop_assert_eq!(
                Record { previous_hash: Hash::ZERO, ..one_record.clone() },
                Record { previous_hash: Hash::ZERO, ..two_record.clone() }
            );
            prop_assert_eq!(one_record.previous_hash, Hash::ZERO);
            if prefix.is_empty() {
                prop_assert_eq!(two_record.previous_hash, Hash::ZERO);
            } else {
                prop_assert_ne!(one_record.previous_hash, two_record.previous_hash);
            }

            // And every field of both records is the field set's or the
            // chain's: nothing withheld reached either log.
            for path in [&first, &second] {
                let held = std::fs::read_to_string(path).unwrap();
                for secret in one.withheld().into_iter().chain(two.withheld()) {
                    prop_assert!(!held.contains(secret), "the log carries {secret}");
                }
            }
        }
    }
}
