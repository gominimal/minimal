//! The proxy's audit log (BEP-039, BEP-040, BEP-041, BEP-048).
//!
//! The log is JSONL under the proxy's state directory: one line for each
//! decision, in the `min/v1` audit schema. The proxy is the log's only
//! writer.
//!
//! A record is built from a [`Decision`] alone. A `Decision` has no field
//! for a credential, an injected header value or a request body (BEP-040).
//! Its string fields are free text, so the type alone does not stop a
//! caller from putting a secret in one. The proxy fills them from the box
//! id, the request authority and the module's mapping, and never from a
//! sealed value or a header. A charset or length check cannot tell a token
//! from an identifier, so this module does not try. It does cut each field
//! to [`MAX_FIELD_BYTES`], so no one field can make a record large. A cut
//! field ends in [`CUT_MARKER`] and the hash of the full value.
//!
//! Each record carries `previous_hash`: the lowercase hex SHA-256 of the
//! previous record's line, as UTF-8 JSON bytes without the trailing newline.
//! The first record of a log carries the all-zero hash (BEP-048). The hash
//! covers the whole previous line, its own `previous_hash` included. The
//! chain functions ([`line_hash`], [`Record::from_decision`],
//! [`Record::to_line`]) are pure over bytes, and separate from the file
//! writer [`AuditLog`].
//!
//! [`AuditLog::open`] opens the file for append only, never for write or
//! truncate, so it cannot modify or remove an existing record (BEP-041).
//! The only bytes the log ever cuts are a torn tail: the part of a line
//! that a failed or interrupted append left without its newline. Such bytes
//! never formed a record. [`AuditLog::open`] also takes an exclusive lock,
//! so a second writer on the same path cannot fork the chain.
//!
//! [`AuditLog::open_dir`] writes the log as numbered segments in one
//! directory (BEP-068). When the active segment reaches its size bound,
//! the next record opens a new segment and carries the previous segment's
//! final hash, so the chain runs on across segments. A rotation then
//! removes whole segments past the retention bound, but keeps a segment
//! that holds a revocation record while a value naming its box can be
//! unexpired ([`prune`]). It never changes a segment it keeps.
//!
//! [`LogReader`] is the client's read-only view of the log, across every
//! segment in the log's directory ([`segments`]). `min box audit` reads
//! through it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The audit schema every record names.
pub const SCHEMA: &str = "min/v1/audit";

/// The identifier a record carries when the request names no member or
/// store identifier.
pub const NONE: &str = "none";

/// The resource and permission a record carries when the module maps none.
pub const MODULE_UNMAPPED: &str = "module_unmapped";

/// The most bytes a record keeps of one string field. A longer value is
/// cut at a character boundary, so a box that controls the request
/// authority cannot make one record arbitrarily large.
pub const MAX_FIELD_BYTES: usize = 512;

/// What a cut field ends in, before the hex SHA-256 of the full value.
pub const CUT_MARKER: &str = "…sha256:";

/// `value` when it fits in [`MAX_FIELD_BYTES`]. A longer value is cut at a
/// character boundary and ends in [`CUT_MARKER`] and the hex SHA-256 of the
/// full value, so the record shows the cut and two long values with the
/// same prefix stay distinct. The result is never longer than the bound.
fn bounded(value: &str) -> String {
    if value.len() <= MAX_FIELD_BYTES {
        return value.to_owned();
    }
    let digest = line_hash(value);
    let mut end = MAX_FIELD_BYTES - CUT_MARKER.len() - digest.len();
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(MAX_FIELD_BYTES);
    out.push_str(&value[..end]);
    out.push_str(CUT_MARKER);
    out.push_str(&digest);
    out
}

/// The `previous_hash` of the first record of a log.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// What a record is about. `kind` tells a proxy decision from the other
/// events of a box's trail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// The proxy admitted or refused a request.
    Decision,
    /// The client minted a member or a store handle.
    Mint,
    /// A live box was destroyed and its sealed values revoked.
    Revocation,
}

/// The outcome of a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// The proxy forwarded the request.
    Admit,
    /// The proxy refused the request.
    Refuse,
}

/// The resource and permission the module mapped the request to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Mapping {
    /// The module mapped the request to this resource and permission.
    Mapped {
        /// The mapped resource.
        resource: String,
        /// The mapped permission.
        permission: String,
    },
    /// The module maps no resource for the request.
    ModuleUnmapped,
}

/// The BEP-039 field set of one decision, and nothing more.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Decision {
    /// What the record is about.
    pub kind: Kind,
    /// The subject box's id.
    pub box_id: String,
    /// The upstream authority, `host:port`.
    pub authority: String,
    /// The member or store identifier, or `None` when the request names
    /// none (an off-module or unsealed request).
    pub identifier: Option<String>,
    /// The handle's `jti`, the audit correlation id. Empty when the request
    /// carries no handle, or when the handle does not parse.
    ///
    /// On an admitted record the handle's signature verified, so the `jti`
    /// is the signer's. On a refused record it is the value the handle
    /// claims, and the signature can be invalid. The refusal keeps it, so a
    /// forged or tampered handle still correlates.
    pub jti: String,
    /// The mapped resource and permission.
    pub mapping: Mapping,
    /// Admit or refuse.
    pub outcome: Outcome,
    /// The marker, such as `off_module`, when the decision carries one.
    pub marker: Option<String>,
}

/// One serialized audit record. The field order is the line's byte order.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Record {
    /// Always [`SCHEMA`].
    pub schema: String,
    /// What the record is about.
    pub kind: Kind,
    /// The subject box's id.
    pub subject: String,
    /// The acting identity. Empty on an un-enrolled host.
    pub act: String,
    /// The transaction id. Empty on an un-enrolled host.
    pub txn: String,
    /// The upstream authority.
    pub upstream: String,
    /// The member or store identifier, or [`NONE`].
    pub identifier: String,
    /// The handle's `jti`, or empty. A record written before the field
    /// existed reads as empty. Only an admitted record's `jti` is verified.
    /// A refused record's `jti` is the handle's claim, as [`Decision::jti`]
    /// says.
    #[serde(default)]
    pub jti: String,
    /// The mapped resource, or [`MODULE_UNMAPPED`].
    pub resource: String,
    /// The mapped permission, or [`MODULE_UNMAPPED`].
    pub permission: String,
    /// Admit or refuse.
    pub decision: Outcome,
    /// The marker, or null.
    pub marker: Option<String>,
    /// The hash of the previous record's line (BEP-048).
    pub previous_hash: String,
}

impl Record {
    /// Builds the record for `decision`, chained to `previous_hash`.
    pub fn from_decision(decision: &Decision, previous_hash: &str) -> Self {
        let (resource, permission) = match &decision.mapping {
            Mapping::Mapped {
                resource,
                permission,
            } => (bounded(resource), bounded(permission)),
            Mapping::ModuleUnmapped => (MODULE_UNMAPPED.to_owned(), MODULE_UNMAPPED.to_owned()),
        };
        Self {
            schema: SCHEMA.to_owned(),
            kind: decision.kind,
            subject: bounded(&decision.box_id),
            act: String::new(),
            txn: String::new(),
            upstream: bounded(&decision.authority),
            identifier: decision
                .identifier
                .as_deref()
                .map_or_else(|| NONE.to_owned(), bounded),
            jti: bounded(&decision.jti),
            resource,
            permission,
            decision: decision.outcome,
            marker: decision.marker.as_deref().map(bounded),
            previous_hash: previous_hash.to_owned(),
        }
    }

    /// The record's line: compact JSON, without the trailing newline.
    pub fn to_line(&self) -> String {
        // A struct of strings and unit enums always serializes.
        serde_json::to_string(self).expect("an audit record serializes")
    }
}

/// The lowercase hex SHA-256 of `line`, the bytes without the trailing
/// newline.
pub fn line_hash(line: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(line.as_ref());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('0'));
    }
    out
}

/// The hash the next record of the log in `contents` carries: the hash of
/// its last line, or [`ZERO_HASH`] for an empty log. The hash covers the
/// raw bytes of the line, so a line that is not valid UTF-8 hashes as it
/// is on disk.
pub fn head_hash(contents: impl AsRef<[u8]>) -> String {
    contents
        .as_ref()
        .split(|&b| b == b'\n')
        .rev()
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .find(|line| !line.is_empty())
        .map_or_else(|| ZERO_HASH.to_owned(), line_hash)
}

/// The `kind` of a [`QuarantineRecord`].
pub const QUARANTINE: &str = "quarantine";

/// The marker on a revocation that a quarantine records again from a moved
/// segment. It tells the copy apart from the revocation a destroy wrote,
/// so a reader of the log does not count one destroy twice.
pub const RESTATED: &str = "quarantine_restated";

/// The directory, inside the log's directory, that a quarantine moves
/// segments into ([`AuditLog::quarantine_unreadable`]).
pub const QUARANTINE_DIR: &str = "quarantine";

/// The record a quarantine appends for each segment it moves out of the
/// log. The chain runs from `from_hash` into the moved segment and on from
/// `final_hash` past it, so a verifier can bridge the gap the move leaves
/// ([`verify_chain`]). The field order is the line's byte order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuarantineRecord {
    /// Always [`SCHEMA`].
    pub schema: String,
    /// Always [`QUARANTINE`].
    pub kind: String,
    /// The moved segment's file name, now under [`QUARANTINE_DIR`].
    pub segment: String,
    /// The hash the moved segment's first record chains to.
    pub from_hash: String,
    /// The moved segment's final hash: the hash the record after it
    /// chains to.
    pub final_hash: String,
    /// The complete lines in the moved segment that did not parse.
    pub unreadable: usize,
    /// The hash of the previous record's line (BEP-048).
    pub previous_hash: String,
}

impl QuarantineRecord {
    /// The record's line: compact JSON, without the trailing newline.
    pub fn to_line(&self) -> String {
        serde_json::to_string(self).expect("a quarantine record serializes")
    }
}

/// The fields every record of the schema has, whatever its kind.
#[derive(Deserialize)]
struct Envelope {
    schema: String,
    kind: String,
    previous_hash: String,
}

/// What one complete, non-empty line of a segment holds.
#[derive(Debug)]
enum Line {
    /// A decision, mint or revocation record.
    Record(Record),
    /// A [`QuarantineRecord`].
    Quarantine(QuarantineRecord),
    /// A record of the schema whose kind this bep does not know. Its chain
    /// fields parse, so it is no corrupt line. It can still hold a
    /// revocation from a newer bep, so [`prune`] keeps its segment.
    OtherKind {
        /// The record's `previous_hash`.
        previous_hash: String,
    },
    /// A line that is no record: not JSON, not the schema, or a known
    /// kind with a field missing or malformed.
    Corrupt,
}

/// The kinds of [`Kind`], as they serialize.
const KNOWN_KINDS: [&str; 3] = ["decision", "mint", "revocation"];

fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Tells what the line `raw` holds, its newline stripped.
fn classify(raw: &[u8]) -> Line {
    if let Ok(record) = serde_json::from_slice::<Record>(raw) {
        return Line::Record(record);
    }
    let Ok(envelope) = serde_json::from_slice::<Envelope>(raw) else {
        return Line::Corrupt;
    };
    if envelope.schema != SCHEMA || !is_hash(&envelope.previous_hash) {
        return Line::Corrupt;
    }
    if envelope.kind == QUARANTINE {
        return serde_json::from_slice::<QuarantineRecord>(raw)
            .ok()
            .filter(|record| is_hash(&record.from_hash) && is_hash(&record.final_hash))
            .map_or(Line::Corrupt, Line::Quarantine);
    }
    if KNOWN_KINDS.contains(&envelope.kind.as_str()) {
        return Line::Corrupt;
    }
    Line::OtherKind {
        previous_hash: envelope.previous_hash,
    }
}

impl Line {
    /// The `previous_hash` the line carries, or `None` for a corrupt line.
    fn previous_hash(&self) -> Option<&str> {
        match self {
            Self::Record(record) => Some(&record.previous_hash),
            Self::Quarantine(record) => Some(&record.previous_hash),
            Self::OtherKind { previous_hash } => Some(previous_hash),
            Self::Corrupt => None,
        }
    }
}

/// The complete, non-empty lines of `bytes`, each without its newline.
/// The bytes after the last newline are a partial write and are left out.
fn complete_lines(bytes: &[u8]) -> impl Iterator<Item = &[u8]> {
    let complete = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |n| n + 1);
    bytes[..complete]
        .split(|&b| b == b'\n')
        .map(|raw| raw.strip_suffix(b"\r").unwrap_or(raw))
        .filter(|raw| !raw.is_empty())
}

/// Creates `dir` and its parents when absent. A directory this call creates
/// gets mode 0700, so it is the proxy's alone.
fn create_private_dir(dir: &Path) -> io::Result<()> {
    let mut dirs = fs::DirBuilder::new();
    dirs.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        dirs.mode(0o700);
    }
    dirs.create(dir)
}

/// Opens the regular file at `path` for append, and creates it with mode
/// 0600 when absent. Fails when `path` is a symlink or not a regular file.
fn open_own_file(path: &Path) -> io::Result<File> {
    // Refused before the open as well, so a symlink's target is never
    // created and a FIFO never blocks the open. The check after the
    // open still catches an entry swapped in between the two.
    match fs::symlink_metadata(path) {
        Ok(entry) if entry.file_type().is_symlink() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("audit log {} is a symlink", path.display()),
            ));
        }
        Ok(entry) if !entry.is_file() => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("audit log {} is not a regular file", path.display()),
            ));
        }
        Ok(_) => {}
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(err),
    }
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    // Checked after the open, against the open file, so a link swapped
    // in between a check and the open cannot slip through.
    ensure_own_file(path, &file)?;
    Ok(file)
}

/// Creates `dir` when absent, and locks its [`DIR_LOCK`] file. The lock
/// lasts as long as the returned file is open.
fn lock_dir(dir: &Path) -> io::Result<File> {
    create_private_dir(dir)?;
    let file = open_own_file(&dir.join(DIR_LOCK))?;
    // One writer per directory: a second one could append to a segment
    // that the first one closed, and fork the chain there.
    file.try_lock().map_err(|err| match err {
        fs::TryLockError::WouldBlock => io::Error::new(
            io::ErrorKind::WouldBlock,
            format!(
                "audit directory {} is held by another `bep serve`",
                dir.display()
            ),
        ),
        fs::TryLockError::Error(err) => err,
    })?;
    Ok(file)
}

/// Fails unless `file` is a regular file and is the entry at `path` itself,
/// not a file that a symlink at `path` leads to.
fn ensure_own_file(path: &Path, file: &File) -> io::Result<()> {
    let refuse = |why: &str| {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("audit log {} {why}", path.display()),
        ))
    };
    let entry = fs::symlink_metadata(path)?;
    if entry.file_type().is_symlink() {
        return refuse("is a symlink");
    }
    let opened = file.metadata()?;
    if !opened.is_file() {
        return refuse("is not a regular file");
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if (entry.dev(), entry.ino()) != (opened.dev(), opened.ino()) {
            return refuse("changed while it was opened");
        }
    }
    Ok(())
}

/// A second, read-only handle on the file that `file` holds open. The
/// handle never leads to an entry swapped in at `path` after the open.
fn reader_for(path: &Path, file: &File) -> io::Result<File> {
    // `/proc/self/fd/N` leads to the open file itself, whatever is at
    // `path` now. Without `/proc`, and on other systems, the path is opened
    // again, and the device and inode check below refuses a different file.
    #[cfg(target_os = "linux")]
    let reader = {
        use std::os::fd::AsRawFd as _;
        match File::open(format!("/proc/self/fd/{}", file.as_raw_fd())) {
            Ok(reader) => reader,
            Err(err) if err.kind() == io::ErrorKind::NotFound => File::open(path)?,
            Err(err) => return Err(err),
        }
    };
    #[cfg(not(target_os = "linux"))]
    let reader = File::open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let (held, read) = (file.metadata()?, reader.metadata()?);
        if (held.dev(), held.ino()) != (read.dev(), read.ino()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("audit log {} changed while it was opened", path.display()),
            ));
        }
    }
    Ok(reader)
}

/// How many bytes [`read_tail`] reads from the end of the log at a time.
const TAIL_CHUNK: u64 = 16 * 1024;

/// The end of the log that `reader` reads, enough of it to find the last
/// complete line. Returns the offset where the bytes start, and the bytes.
/// The read stops at the first chunk that holds a newline before the last
/// non-empty complete line, so its cost does not grow with the log.
fn read_tail(mut reader: &File) -> io::Result<(u64, Vec<u8>)> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    let len = reader.metadata()?.len();
    let mut start = len;
    let mut tail: Vec<u8> = Vec::new();
    while start > 0 {
        let step = start.min(TAIL_CHUNK);
        start -= step;
        let mut chunk = vec![0; step as usize];
        reader.seek(SeekFrom::Start(start))?;
        reader.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&tail);
        tail = chunk;
        if let Some(last) = tail.iter().rposition(|&b| b == b'\n') {
            let complete = &tail[..last];
            let trimmed = complete
                .iter()
                .rposition(|&b| b != b'\n' && b != b'\r')
                .map_or(&complete[..0], |n| &complete[..=n]);
            if trimmed.contains(&b'\n') {
                break;
            }
        }
    }
    Ok((start, tail))
}

/// The audit log, open for append only.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: File,
    head: String,
    /// The log's length after the last complete record.
    len: u64,
    /// Set when a failed append left bytes the log was not able to cut.
    poisoned: bool,
    /// The log's directory, the active segment's number and the bounds,
    /// when the log rotates its segments (BEP-068).
    rotation: Option<(PathBuf, u64, Rotation)>,
    /// The locked [`DIR_LOCK`] file of the log's directory, held for the
    /// life of the log when [`AuditLog::open_dir`] opened it.
    dir_lock: Option<File>,
}

/// The lock file in an audit directory. The writer that holds its lock is
/// the one writer of every segment in the directory.
pub const DIR_LOCK: &str = ".lock";

/// The size bound of an active segment: 8 MiB.
pub const SEGMENT_BYTES: u64 = 8 * 1024 * 1024;

/// The segments a rotating log keeps, the active one included, besides the
/// segments that hold a revocation still in force.
pub const RETAINED_SEGMENTS: usize = 16;

/// How long a revocation record must stay in the log: the longest validity
/// of a value that names a box. A value's expiry is the root CA's remaining
/// validity at the mint (BEP-005, BEP-063), so no value outlives the root's
/// full validity from its mint.
pub const REVOCATION_CEILING: std::time::Duration =
    std::time::Duration::from_secs(crate::publish::ROOT_VALIDITY_SECS);

/// The bounds of a rotating log (BEP-068).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// The active segment's size, in bytes, at which the next record opens
    /// a new segment.
    pub bound: u64,
    /// The newest segments always kept, the active one included. At least
    /// one is kept, whatever this is.
    pub retain: usize,
    /// How long after its last write a segment that holds a revocation
    /// record is kept.
    pub revocation_ceiling: std::time::Duration,
}

impl Default for Rotation {
    fn default() -> Self {
        Self {
            bound: SEGMENT_BYTES,
            retain: RETAINED_SEGMENTS,
            revocation_ceiling: REVOCATION_CEILING,
        }
    }
}

impl AuditLog {
    /// Opens the log at `path` for append, and creates it and its parent
    /// directory when absent. A directory it creates gets mode 0700, and the
    /// log gets mode 0600, also when it exists already. The next record
    /// chains to the log's last line, which open finds from the end of the
    /// file without a read of the whole log.
    ///
    /// The call fails when `path` is a symlink, or when another `AuditLog`
    /// holds the log open. A torn last line, which an interrupted append
    /// left without its newline, is cut off.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            create_private_dir(parent)?;
        }
        let file = open_own_file(&path)?;
        // One writer per log: a second one would chain to the same head.
        file.try_lock().map_err(|err| match err {
            fs::TryLockError::WouldBlock => io::Error::new(
                io::ErrorKind::WouldBlock,
                format!("audit log {} is held by another writer", path.display()),
            ),
            fs::TryLockError::Error(err) => err,
        })?;
        // An existing log keeps the mode it was created with, so tighten it
        // through the held descriptor.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
                file.set_permissions(fs::Permissions::from_mode(0o600))?;
            }
        }
        let (start, tail) = read_tail(&reader_for(&path, &file)?)?;
        let complete = tail.iter().rposition(|&b| b == b'\n').map_or(0, |n| n + 1);
        let len = start + complete as u64;
        if complete < tail.len() {
            tracing::warn!(
                path = %path.display(),
                torn_bytes = tail.len() - complete,
                "audit log ends in a torn line, cutting it off"
            );
            file.set_len(len)?;
        }
        let head = head_hash(&tail[..complete]);
        Ok(Self {
            path,
            file,
            head,
            len,
            poisoned: false,
            rotation: None,
            dir_lock: None,
        })
    }

    /// Opens the log in `dir` for append, as segments that rotate at
    /// `rotation`'s bound (BEP-068). The active segment is the one with the
    /// highest number, or `audit-0.jsonl` in an empty directory. When the
    /// active segment holds no record yet, the next record chains to the
    /// previous segment's last line, so the chain runs on across segments.
    ///
    /// Open first takes the lock on the directory's [`DIR_LOCK`] file, and
    /// the log holds it until it drops. So one writer at a time has the
    /// directory, and a rotation never frees a closed segment for a second
    /// writer. While another log holds the directory, the call fails with
    /// [`io::ErrorKind::WouldBlock`].
    ///
    /// Each segment has its own lock too, and open lists the directory
    /// again after it takes that lock. A writer that takes no directory
    /// lock and rotated in between releases the old segment, and a newer
    /// one shows in the second listing. Then open drops the old segment and
    /// tries the newest, which that writer holds.
    pub fn open_dir(dir: impl AsRef<Path>, rotation: Rotation) -> io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        let dir_lock = lock_dir(&dir)?;
        let found = numbered_segments(&dir)?;
        let mut log = Self::open_listed(dir, rotation, found)?;
        log.dir_lock = Some(dir_lock);
        Ok(log)
    }

    /// [`AuditLog::open_dir`] from a listing `found` taken before the call.
    fn open_listed(
        dir: PathBuf,
        rotation: Rotation,
        mut found: Vec<(u64, PathBuf)>,
    ) -> io::Result<Self> {
        // Each pass that retries saw a newer segment, so a writer that keeps
        // rotating is the only way to run out of passes.
        const PASSES: usize = 8;
        for _ in 0..PASSES {
            let (n, path) = found
                .last()
                .cloned()
                .unwrap_or_else(|| (0, dir.join(segment_name(0))));
            let mut log = Self::open(&path)?;
            let now = numbered_segments(&dir)?;
            if now.last().is_some_and(|(newest, _)| *newest > n) {
                // Dropping `log` releases the stale segment unwritten.
                found = now;
                continue;
            }
            if log.len == 0
                && let Some((_, previous)) = now.iter().rev().find(|(m, _)| *m < n)
            {
                log.head = final_hash(previous)?;
            }
            log.rotation = Some((dir, n, rotation));
            return Ok(log);
        }
        Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            format!("audit log {} is rotated by another writer", dir.display()),
        ))
    }

    /// Closes the active segment and opens the next one, whose first record
    /// carries the closed segment's final hash. Then prunes the segments
    /// past the retention bound.
    fn rotate(&mut self) -> io::Result<()> {
        let Some((dir, _, rotation)) = self.rotation.clone() else {
            return Ok(());
        };
        self.open_next()?;
        if let Err(err) = prune(&dir, &rotation, std::time::SystemTime::now()) {
            tracing::warn!(dir = %dir.display(), error = %err, "audit segments were not pruned");
        }
        Ok(())
    }

    /// Opens the segment after the active one as the active segment. Its
    /// first record carries the head of the segment it replaces.
    fn open_next(&mut self) -> io::Result<()> {
        let Some((dir, n, rotation)) = self.rotation.clone() else {
            return Ok(());
        };
        let next = dir.join(segment_name(n + 1));
        let mut opened = Self::open(&next)?;
        if opened.len != 0 {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!(
                    "audit segment {} holds records already, so the chain cannot continue in it",
                    next.display()
                ),
            ));
        }
        tracing::info!(
            closed = %self.path.display(),
            final_hash = %self.head,
            opened = %next.display(),
            "rotated the audit log"
        );
        opened.head = std::mem::take(&mut self.head);
        opened.rotation = Some((dir, n + 1, rotation));
        // The directory stays locked across the swap, so no other writer
        // can take the closed segment.
        opened.dir_lock = self.dir_lock.take();
        *self = opened;
        Ok(())
    }

    /// Moves each segment of the log that holds a complete line that does
    /// not parse into [`QUARANTINE_DIR`] in the log's directory, and starts
    /// the log past them. For each moved segment it appends one
    /// [`QuarantineRecord`], which carries the hashes the chain runs on
    /// across the gap, and then each revocation it read in that segment
    /// again, so those stay in force at later starts. A line that does
    /// not parse is lost to the log, whatever it recorded.
    ///
    /// Only a log that [`AuditLog::open_dir`] opened can quarantine, since
    /// it holds the directory. Returns the segments it moved, oldest first.
    pub fn quarantine_unreadable(&mut self) -> io::Result<Vec<Quarantined>> {
        let Some((dir, active, _)) = self.rotation.clone() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only an audit log opened as a directory of segments can quarantine",
            ));
        };
        let found = numbered_segments(&dir)?;
        let quarantine_dir = dir.join(QUARANTINE_DIR);
        // The plan reads every segment and changes nothing, so an error in
        // it leaves the log as it was.
        let mut moved = Vec::new();
        let mut active_moved = false;
        // The hash the chain carries out of the segment before this one.
        let mut previous_final: Option<String> = None;
        for (i, (n, path)) in found.iter().enumerate() {
            let bytes = fs::read(path)?;
            let lines: Vec<Line> = complete_lines(&bytes).map(classify).collect();
            let unreadable = lines
                .iter()
                .filter(|line| matches!(line, Line::Corrupt))
                .count();
            let file_final =
                head_hash(&bytes[..bytes.iter().rposition(|&b| b == b'\n').map_or(0, |n| n + 1)]);
            if unreadable == 0 {
                previous_final = Some(file_final);
                continue;
            }
            let from_hash = previous_final
                .take()
                .or_else(|| {
                    lines
                        .first()
                        .and_then(Line::previous_hash)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| ZERO_HASH.to_owned());
            // The record after the segment chains to the hash its last
            // line had when it was written, and an unreadable last line
            // can differ from it now.
            let final_hash = match found.get(i + 1) {
                Some((_, next)) => first_previous_hash(next)?.unwrap_or(file_final),
                None => file_final,
            };
            let name = path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let moved_to = quarantine_dir.join(&name);
            if fs::symlink_metadata(&moved_to).is_ok() {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!("{} exists already", moved_to.display()),
                ));
            }
            active_moved |= *n == active;
            let mut revoked: Vec<String> = Vec::new();
            for line in &lines {
                if let Line::Record(record) = line
                    && record.kind == Kind::Revocation
                    && !revoked.contains(&record.subject)
                {
                    revoked.push(record.subject.clone());
                }
            }
            // A record of a kind this bep does not know can be a newer
            // bep's revocation. The move cannot record it again, so it
            // counts it for the warn line.
            let other_kinds = lines
                .iter()
                .filter(|line| matches!(line, Line::OtherKind { .. }))
                .count();
            previous_final = Some(final_hash.clone());
            moved.push(Quarantined {
                segment: path.clone(),
                moved_to,
                record: QuarantineRecord {
                    schema: SCHEMA.to_owned(),
                    kind: QUARANTINE.to_owned(),
                    segment: name,
                    from_hash,
                    final_hash,
                    unreadable,
                    previous_hash: String::new(),
                },
                revoked,
                other_kinds,
            });
        }
        if moved.is_empty() {
            return Ok(moved);
        }
        create_private_dir(&quarantine_dir)?;
        if active_moved {
            // The log writes the records below to a segment that stays, so
            // it goes on in a new segment, chained to its head, before it
            // moves the active one.
            self.open_next()?;
        }
        // Each segment's record and revocations go to the log before the
        // segment moves. A failure or a crash between the two leaves the
        // segment in place, and the next quarantine moves it. It never
        // leaves a moved segment without its record or its revocations.
        for quarantined in &mut moved {
            self.prepare()?;
            quarantined.record.previous_hash = self.head.clone();
            self.write_line(&quarantined.record.to_line())?;
            for box_id in &quarantined.revoked {
                self.append(&Decision {
                    kind: Kind::Revocation,
                    box_id: box_id.clone(),
                    authority: String::new(),
                    identifier: None,
                    // A mint or a revocation carries no handle.
                    jti: String::new(),
                    mapping: Mapping::ModuleUnmapped,
                    outcome: Outcome::Refuse,
                    marker: Some(RESTATED.to_owned()),
                })?;
            }
            fs::rename(&quarantined.segment, &quarantined.moved_to)?;
            tracing::warn!(
                segment = %quarantined.segment.display(),
                moved_to = %quarantined.moved_to.display(),
                unreadable = quarantined.record.unreadable,
                other_kinds = quarantined.other_kinds,
                final_hash = %quarantined.record.final_hash,
                "moved an audit segment with unreadable lines to quarantine; \
                 a revocation on an unreadable line, or on a line of a kind \
                 this bep does not know (other_kinds), is no longer in force, \
                 so check the destroyed boxes that segment can record"
            );
        }
        Ok(moved)
    }

    /// The log's path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The hash the next record carries as `previous_hash`.
    pub fn head(&self) -> &str {
        &self.head
    }

    /// Appends one record for `decision` and returns it. On failure the
    /// head does not move, the partial bytes are cut off, and one warn line
    /// names the path. When the cut fails too, every later append fails.
    pub fn append(&mut self, decision: &Decision) -> io::Result<Record> {
        self.prepare()?;
        let record = Record::from_decision(decision, &self.head);
        self.write_line(&record.to_line())?;
        Ok(record)
    }

    /// Fails when an earlier append poisoned the log, and rotates the
    /// active segment when it is full, before the next line is built.
    fn prepare(&mut self) -> io::Result<()> {
        if self.poisoned {
            return Err(io::Error::other(format!(
                "audit log {} holds a torn line, reopen it",
                self.path.display()
            )));
        }
        if let Some((_, _, rotation)) = &self.rotation
            && self.len > 0
            && self.len >= rotation.bound
        {
            self.rotate()?;
        }
        Ok(())
    }

    /// Appends `line`, which chains to the head, and moves the head to it.
    fn write_line(&mut self, line: &str) -> io::Result<()> {
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        // One write call, so a short write shows as a short count.
        let written = self.file.write(&bytes).and_then(|n| {
            if n == bytes.len() {
                self.file.flush()
            } else {
                Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    format!("short write: {n} of {} bytes", bytes.len()),
                ))
            }
        });
        if let Err(err) = written {
            tracing::warn!(path = %self.path.display(), error = %err, "audit append failed");
            if let Err(cut) = self.file.set_len(self.len) {
                tracing::warn!(
                    path = %self.path.display(),
                    error = %cut,
                    "audit log keeps a torn line, later appends fail until reopen"
                );
                self.poisoned = true;
            }
            return Err(err);
        }
        self.len += bytes.len() as u64;
        self.head = line_hash(line);
        Ok(())
    }
}

/// One segment that [`AuditLog::quarantine_unreadable`] moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Quarantined {
    /// Where the segment was.
    pub segment: PathBuf,
    /// Where it is now, under [`QUARANTINE_DIR`].
    pub moved_to: PathBuf,
    /// The record the move appended to the log.
    pub record: QuarantineRecord,
    /// The box ids of the revocations read in the segment, which the move
    /// appended to the log again.
    pub revoked: Vec<String>,
    /// The lines in the segment of a kind this bep does not know. One can
    /// be a newer bep's revocation, which the move does not record again.
    pub other_kinds: usize,
}

/// The file name of segment `n` of a log: `audit-<n>.jsonl`. A log is the
/// set of these files in one directory. The segment with the highest `n`
/// is the active one, and a segment is never renamed, so a reader that
/// tails the log can key its place on the path.
pub fn segment_name(n: u64) -> String {
    format!("audit-{n}.jsonl")
}

/// The segment number of `name`, or `None` when `name` is not a segment.
fn segment_number(name: &str) -> Option<u64> {
    name.strip_prefix("audit-")?
        .strip_suffix(".jsonl")?
        .parse()
        .ok()
}

/// `~/.minimal/bep/audit`, the directory that holds the proxy's log on
/// this host.
///
/// Interim: `min box audit` reads this directory directly, through
/// [`LogReader`]. Un-enrolled, the architecture's audit paragraph and
/// Gatehouse §6.10 put the read behind the proxy's local socket (ruled on
/// gominimal/arch#137). The interim is tracked by
/// <https://github.com/gominimal/minimal/issues/2459>. When the proxy
/// serves the read there
/// (<https://github.com/gominimal/minimal/issues/2463>), the client stops
/// reading this directory.
pub fn default_dir() -> Option<PathBuf> {
    std::env::home_dir().map(|home| home.join(".minimal/bep/audit"))
}

/// Every segment of the log in `dir`, oldest first. A missing directory is
/// an empty log.
pub fn segments(dir: impl AsRef<Path>) -> io::Result<Vec<PathBuf>> {
    Ok(numbered_segments(dir.as_ref())?
        .into_iter()
        .map(|(_, path)| path)
        .collect())
}

/// Every segment of the log in `dir` with its number, oldest first.
fn numbered_segments(dir: &Path) -> io::Result<Vec<(u64, PathBuf)>> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    let mut found = Vec::new();
    for entry in entries {
        let entry = entry?;
        if let Some(n) = entry.file_name().to_str().and_then(segment_number) {
            found.push((n, entry.path()));
        }
    }
    found.sort();
    Ok(found)
}

/// The hash of the last complete line of the segment at `path`, or
/// [`ZERO_HASH`] when it holds none.
fn final_hash(path: &Path) -> io::Result<String> {
    let (_, tail) = read_tail(&File::open(path)?)?;
    let complete = tail.iter().rposition(|&b| b == b'\n').map_or(0, |n| n + 1);
    Ok(head_hash(&tail[..complete]))
}

/// The `previous_hash` of the first line of the segment at `path`, or
/// `None` when it holds no line or its first line does not parse.
fn first_previous_hash(path: &Path) -> io::Result<Option<String>> {
    let bytes = fs::read(path)?;
    Ok(complete_lines(&bytes)
        .next()
        .map(classify)
        .and_then(|line| line.previous_hash().map(str::to_owned)))
}

/// Whether the segment at `path` holds a revocation record, or can hold
/// one. A complete, non-empty line that does not parse as a record counts
/// as one, so [`prune`] keeps a segment it cannot read whole. A record of
/// a kind this bep does not know counts too. A quarantine record does not
/// count. The bytes after the last newline are a
/// partial write and count as none.
fn holds_revocation(path: &Path) -> io::Result<bool> {
    let bytes = fs::read(path)?;
    Ok(complete_lines(&bytes).any(|raw| match classify(raw) {
        Line::Record(record) => record.kind == Kind::Revocation,
        // A kind this bep does not know can be a revocation that a newer
        // bep wrote, so prune keeps its segment, as for a corrupt line.
        Line::Corrupt | Line::OtherKind { .. } => true,
        Line::Quarantine(_) => false,
    }))
}

/// Where the chain of a log stops verifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainBreak {
    /// The segment that holds the line.
    pub segment: PathBuf,
    /// The line's number in its segment, from 1.
    pub line: usize,
    /// The hash the line must carry as `previous_hash`.
    pub expected: String,
    /// The hash it carries, or `None` when the line does not parse.
    pub found: Option<String>,
}

/// Verifies the chain of the log in `dir` across every retained segment,
/// and returns the count of records it verified. Each record must carry
/// the hash of the line before it (BEP-048). The first retained record can
/// carry any hash, since the segments before it can be pruned. A gap is
/// verified only between two segments, and only when [`QuarantineRecord`]s
/// lead across it from the hash before it to the hash after it. Each of
/// those records must name a segment under [`QUARANTINE_DIR`] that agrees
/// with it, numbered between the two segments, and come after the gap.
pub fn verify_chain(dir: impl AsRef<Path>) -> io::Result<Result<usize, ChainBreak>> {
    let dir = dir.as_ref();
    let mut read = Vec::new();
    for path in segments(dir)? {
        let bytes = fs::read(&path)?;
        read.push((path, bytes));
    }
    let mut moved = Vec::new();
    for (_, path) in numbered_segments(&dir.join(QUARANTINE_DIR))? {
        let name = path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default();
        moved.push((name, fs::read(&path)?));
    }
    Ok(verify_segments(&read, &moved))
}

/// Whether `bytes`, a segment under [`QUARANTINE_DIR`], is the segment
/// that `record` says it moved: it holds `record.unreadable` lines that do
/// not parse, and its first and last lines, where they parse, carry the
/// hashes the record bridges.
fn moved_segment_matches(record: &QuarantineRecord, bytes: &[u8]) -> bool {
    let lines: Vec<Line> = complete_lines(bytes).map(classify).collect();
    let unreadable = lines
        .iter()
        .filter(|line| matches!(line, Line::Corrupt))
        .count();
    if unreadable == 0 || unreadable != record.unreadable {
        return false;
    }
    let first = lines
        .first()
        .and_then(Line::previous_hash)
        .is_none_or(|hash| hash == record.from_hash);
    let last = complete_lines(bytes).last().is_none_or(|raw| {
        matches!(classify(raw), Line::Corrupt) || line_hash(raw) == record.final_hash
    });
    first && last
}

/// [`verify_chain`] over segments already read, oldest first, and the
/// segments under [`QUARANTINE_DIR`] by file name. Pure.
pub fn verify_segments(
    segments: &[(PathBuf, Vec<u8>)],
    quarantined: &[(String, Vec<u8>)],
) -> Result<usize, ChainBreak> {
    let number_of = |path: &Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .and_then(segment_number)
    };
    let lines: Vec<(&Path, usize, &[u8], Line)> = segments
        .iter()
        .flat_map(|(path, bytes)| {
            complete_lines(bytes)
                .enumerate()
                .map(move |(i, raw)| (path.as_path(), i + 1, raw, classify(raw)))
        })
        .collect();
    // Each bridge: where it sits in the log, the moved segment's number,
    // and the record. A bridge whose moved segment is absent, or does not
    // agree with it, bridges nothing.
    let bridges: Vec<(usize, u64, &QuarantineRecord)> = lines
        .iter()
        .enumerate()
        .filter_map(|(at, (_, _, _, line))| match line {
            Line::Quarantine(record) => Some((at, record)),
            _ => None,
        })
        .filter_map(|(at, record)| {
            let number = segment_number(&record.segment)?;
            let (_, bytes) = quarantined
                .iter()
                .find(|(name, _)| *name == record.segment)?;
            moved_segment_matches(record, bytes).then_some((at, number, record))
        })
        .collect();
    // The hash of the line before, and the number of its segment.
    let mut head: Option<(String, Option<u64>)> = None;
    for (index, (path, number, raw, line)) in lines.iter().enumerate() {
        let found = line.previous_hash();
        if let Some((expected, before)) = &head {
            let bridged = found.is_some_and(|found| {
                if expected == found {
                    return true;
                }
                // A quarantine moves whole segments, so a gap opens only
                // before the first line of a segment.
                let (Some(mut after), Some(here)) = (*before, number_of(path)) else {
                    return false;
                };
                if *number != 1 {
                    return false;
                }
                let mut at = expected.as_str();
                // Each step moves to a higher segment number, so the walk
                // ends.
                while let Some((_, moved, record)) = bridges.iter().find(|(pos, moved, record)| {
                    *pos >= index && *moved > after && *moved < here && record.from_hash == at
                }) {
                    at = &record.final_hash;
                    after = *moved;
                    if at == found {
                        return true;
                    }
                }
                false
            });
            if !bridged {
                return Err(ChainBreak {
                    segment: path.to_path_buf(),
                    line: *number,
                    expected: expected.clone(),
                    found: found.map(str::to_owned),
                });
            }
        } else if found.is_none() {
            return Err(ChainBreak {
                segment: path.to_path_buf(),
                line: *number,
                expected: String::new(),
                found: None,
            });
        }
        head = Some((line_hash(raw), number_of(path)));
    }
    Ok(lines.len())
}

/// Removes the segments of the log in `dir` that are older than the newest
/// `rotation.retain`, except a segment that holds a revocation record a
/// value can still need (BEP-068). Records carry no time, so a segment's
/// last write stands for its revocations' time. No value naming a box is
/// minted after its destroy, so every value naming a revoked box expires
/// before the segment's last write plus `rotation.revocation_ceiling`.
/// Returns the segments it removed.
pub fn prune(
    dir: impl AsRef<Path>,
    rotation: &Rotation,
    now: std::time::SystemTime,
) -> io::Result<Vec<PathBuf>> {
    let found = segments(dir)?;
    let old = found.len().saturating_sub(rotation.retain.max(1));
    let mut removed = Vec::new();
    for path in &found[..old] {
        let written = fs::metadata(path)?.modified()?;
        let in_force = written
            .checked_add(rotation.revocation_ceiling)
            .is_none_or(|until| until > now);
        if in_force && holds_revocation(path)? {
            continue;
        }
        fs::remove_file(path)?;
        tracing::info!(segment = %path.display(), "removed an old audit segment");
        removed.push(path.clone());
    }
    Ok(removed)
}

/// One record a [`LogReader`] read, with its line as it is on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The parsed record.
    pub record: Record,
    /// The record's line, without the trailing newline.
    pub line: String,
}

/// What one [`LogReader::read_new`] call read.
#[derive(Debug, Default)]
pub struct ReadBatch {
    /// The records, in log order.
    pub entries: Vec<Entry>,
    /// The segments the call read new bytes from.
    pub segments: Vec<PathBuf>,
    /// The lines that did not parse as a record, and were skipped.
    pub skipped: usize,
    /// The segments that hold a skipped line, oldest first and each once.
    pub skipped_in: Vec<PathBuf>,
    /// The records of a kind other than a decision, a mint or a revocation:
    /// a quarantine record, or a kind this bep does not know. They are not
    /// counted in `skipped`.
    pub other_kinds: usize,
}

/// A read-only reader over the log in one directory, across every
/// retained segment. The first [`read_new`](Self::read_new) call reads the
/// whole log. Each later call reads only what the proxy appended since,
/// so a caller can replay the log and then tail it.
///
/// Interim: the client reads the operator-owned log files directly, under
/// file mode, in place of the read over the proxy's local socket. See
/// <https://github.com/gominimal/minimal/issues/2459>. The flip is
/// <https://github.com/gominimal/minimal/issues/2463>, when the proxy
/// serves the read.
#[derive(Debug)]
pub struct LogReader {
    dir: PathBuf,
    /// For each segment, the file it was and the offset after its last
    /// complete line read.
    offsets: std::collections::BTreeMap<PathBuf, (Option<FileIdentity>, u64)>,
}

/// The device and inode of a file, so a segment replaced by another file of
/// the same name is read again from its start.
type FileIdentity = (u64, u64);

#[cfg(unix)]
fn file_identity(metadata: &fs::Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt as _;
    Some((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn file_identity(_metadata: &fs::Metadata) -> Option<FileIdentity> {
    None
}

impl LogReader {
    /// A reader over the log in `dir`. Nothing is read until
    /// [`read_new`](Self::read_new).
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self {
            dir: dir.into(),
            offsets: std::collections::BTreeMap::new(),
        }
    }

    /// The log's directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Reads every complete line appended since the last call, segment by
    /// segment, oldest first. A line the proxy has not finished, which has
    /// no newline yet, is left for the next call.
    pub fn read_new(&mut self) -> io::Result<ReadBatch> {
        use std::io::{Read as _, Seek as _, SeekFrom};
        let mut out = ReadBatch::default();
        for path in segments(&self.dir)? {
            let (seen, start) = self.offsets.get(&path).copied().unwrap_or((None, 0));
            let mut file = match File::open(&path) {
                Ok(file) => file,
                // Pruned between the listing and the open.
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => return Err(err),
            };
            let metadata = file.metadata()?;
            let len = metadata.len();
            let identity = file_identity(&metadata);
            // A segment that is another file now, or that is shorter than
            // the place already read, was replaced or truncated. Read it
            // again from its start.
            let replaced = seen.is_some() && seen != identity;
            let start = if replaced || len < start {
                0
            } else if start > 0 && !ends_line_at(&mut file, start)? {
                // Where identity is unavailable, an offset that is not just
                // after a newline means the file changed under the reader.
                0
            } else {
                start
            };
            if len == start {
                continue;
            }
            file.seek(SeekFrom::Start(start))?;
            let mut bytes = Vec::new();
            file.read_to_end(&mut bytes)?;
            let complete = bytes.iter().rposition(|&b| b == b'\n').map_or(0, |n| n + 1);
            if complete == 0 {
                continue;
            }
            for raw in complete_lines(&bytes[..complete]) {
                match classify(raw) {
                    Line::Record(record) => out.entries.push(Entry {
                        record,
                        // A record parsed from these bytes, so they are UTF-8.
                        line: String::from_utf8_lossy(raw).into_owned(),
                    }),
                    Line::Quarantine(_) | Line::OtherKind { .. } => out.other_kinds += 1,
                    Line::Corrupt => {
                        out.skipped += 1;
                        if out.skipped_in.last() != Some(&path) {
                            out.skipped_in.push(path.clone());
                        }
                    }
                }
            }
            self.offsets
                .insert(path.clone(), (identity, start + complete as u64));
            out.segments.push(path);
        }
        Ok(out)
    }
}

/// Whether the byte just before `offset` in `file` is a newline.
fn ends_line_at(file: &mut File, offset: u64) -> io::Result<bool> {
    use std::io::{Read as _, Seek as _, SeekFrom};
    file.seek(SeekFrom::Start(offset - 1))?;
    let mut byte = [0u8; 1];
    file.read_exact(&mut byte)?;
    Ok(byte[0] == b'\n')
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "bep-audit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = fs::remove_dir_all(&dir);
            Self(dir)
        }

        fn log(&self) -> PathBuf {
            self.0.join("state").join("audit.jsonl")
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn admit() -> Decision {
        Decision {
            kind: Kind::Decision,
            box_id: "box-7f3a".into(),
            authority: "api.github.com:443".into(),
            identifier: Some("github:user-token".into()),
            jti: "jti-7f3a".into(),
            mapping: Mapping::Mapped {
                resource: "repo:gominimal/minimal".into(),
                permission: "contents:read".into(),
            },
            outcome: Outcome::Admit,
            marker: None,
        }
    }

    fn off_module() -> Decision {
        Decision {
            kind: Kind::Decision,
            box_id: "box-7f3a".into(),
            authority: "example.com:443".into(),
            identifier: None,
            jti: String::new(),
            mapping: Mapping::ModuleUnmapped,
            outcome: Outcome::Refuse,
            marker: Some("off_module".into()),
        }
    }

    fn lines(path: &Path) -> Vec<String> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    // BEP-039: one `min/v1` line for each admit or refuse, with the F12
    // fields and `act` and `txn` empty.
    #[test]
    fn every_decision_appends_one_audit_record() {
        let dir = TempDir::new();
        let mut log = AuditLog::open(dir.log()).unwrap();
        let decisions = [admit(), off_module(), admit()];
        for (n, decision) in decisions.iter().enumerate() {
            log.append(decision).unwrap();
            assert_eq!(lines(&dir.log()).len(), n + 1);
        }

        let written = lines(&dir.log());
        let first: serde_json::Value = serde_json::from_str(&written[0]).unwrap();
        assert_eq!(first["schema"], "min/v1/audit");
        assert_eq!(first["kind"], "decision");
        assert_eq!(first["subject"], "box-7f3a");
        assert_eq!(first["act"], "");
        assert_eq!(first["txn"], "");
        assert_eq!(first["upstream"], "api.github.com:443");
        assert_eq!(first["identifier"], "github:user-token");
        assert_eq!(first["resource"], "repo:gominimal/minimal");
        assert_eq!(first["permission"], "contents:read");
        assert_eq!(first["decision"], "admit");
        assert!(first["marker"].is_null());

        // A long free-text field is cut to its bound at a char boundary.
        let long = Decision {
            authority: "é".repeat(MAX_FIELD_BYTES),
            identifier: Some("x".repeat(MAX_FIELD_BYTES * 4)),
            ..admit()
        };
        let record = Record::from_decision(&long, ZERO_HASH);
        assert!(record.upstream.len() <= MAX_FIELD_BYTES);
        let (kept, digest) = record.upstream.split_once(CUT_MARKER).unwrap();
        assert!(!kept.is_empty() && kept.chars().all(|c| c == 'é'));
        assert_eq!(digest, line_hash(&long.authority));
        assert!(record.identifier.len() <= MAX_FIELD_BYTES);
        assert!(record.identifier.ends_with(&format!(
            "{CUT_MARKER}{}",
            line_hash(long.identifier.as_ref().unwrap())
        )));
        // Two long values with the same prefix give distinct records.
        let other = Decision {
            identifier: Some(format!("{}y", "x".repeat(MAX_FIELD_BYTES * 4))),
            ..long.clone()
        };
        let other = Record::from_decision(&other, ZERO_HASH);
        assert_ne!(other.identifier, record.identifier);
        // A value at the bound is kept whole, with no marker.
        let exact = Decision {
            authority: "a".repeat(MAX_FIELD_BYTES),
            ..admit()
        };
        let exact = Record::from_decision(&exact, ZERO_HASH);
        assert_eq!(exact.upstream, "a".repeat(MAX_FIELD_BYTES));

        let second: serde_json::Value = serde_json::from_str(&written[1]).unwrap();
        assert_eq!(second["upstream"], "example.com:443");
        assert_eq!(second["identifier"], "none");
        assert_eq!(second["resource"], "module_unmapped");
        assert_eq!(second["permission"], "module_unmapped");
        assert_eq!(second["decision"], "refuse");
        assert_eq!(second["marker"], "off_module");

        let keys: Vec<_> = first.as_object().unwrap().keys().cloned().collect();
        let mut expected = [
            "schema",
            "kind",
            "subject",
            "act",
            "txn",
            "upstream",
            "identifier",
            "jti",
            "resource",
            "permission",
            "decision",
            "marker",
            "previous_hash",
        ]
        .map(String::from)
        .to_vec();
        expected.sort();
        let mut keys = keys;
        keys.sort();
        assert_eq!(keys, expected);
    }

    // BEP-048: the first record carries the all-zero hash, and each later
    // one the SHA-256 of the previous line without its newline, across a
    // reopen too.
    #[test]
    fn audit_record_carries_previous_hash() {
        let dir = TempDir::new();
        let mut log = AuditLog::open(dir.log()).unwrap();
        assert_eq!(log.head(), ZERO_HASH);
        log.append(&admit()).unwrap();
        log.append(&off_module()).unwrap();
        drop(log);
        let mut log = AuditLog::open(dir.log()).unwrap();
        log.append(&admit()).unwrap();

        let written = lines(&dir.log());
        assert_eq!(written.len(), 3);
        let records: Vec<Record> = written
            .iter()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(records[0].previous_hash, ZERO_HASH);
        for n in 1..records.len() {
            let expected: String = Sha256::digest(written[n - 1].as_bytes())
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect();
            assert_eq!(records[n].previous_hash, expected);
        }
        assert_eq!(log.head(), line_hash(&written[2]));
        // The line is the record's own serialization, byte for byte.
        assert_eq!(records[2].to_line(), written[2]);
        drop(log);

        // A last line that is not UTF-8 chains by its raw bytes.
        let raw = b"{\"subject\":\"\xff\xfe\"}";
        let mut file = OpenOptions::new().append(true).open(dir.log()).unwrap();
        file.write_all(raw).unwrap();
        file.write_all(b"\n").unwrap();
        drop(file);
        let log = AuditLog::open(dir.log()).unwrap();
        let expected: String = Sha256::digest(raw)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(log.head(), expected);
    }

    // BEP-048: a torn tail from an interrupted append is cut off on open,
    // so the next record starts on its own line and chains to the last
    // complete one.
    #[test]
    fn audit_log_cuts_a_torn_last_line() {
        let dir = TempDir::new();
        let mut log = AuditLog::open(dir.log()).unwrap();
        log.append(&admit()).unwrap();
        let head = log.head().to_owned();
        drop(log);
        let mut file = OpenOptions::new().append(true).open(dir.log()).unwrap();
        file.write_all(b"{\"schema\":\"min/v1/au").unwrap();
        drop(file);

        let mut log = AuditLog::open(dir.log()).unwrap();
        assert_eq!(log.head(), head);
        log.append(&off_module()).unwrap();
        let written = lines(&dir.log());
        assert_eq!(written.len(), 2);
        let second: Record = serde_json::from_str(&written[1]).unwrap();
        assert_eq!(second.previous_hash, line_hash(&written[0]));
    }

    // BEP-048: open finds the head from the end of the log, also when the
    // last line starts before the last read chunk.
    #[test]
    fn audit_log_finds_the_head_past_one_chunk() {
        let dir = TempDir::new();
        let mut log = AuditLog::open(dir.log()).unwrap();
        while fs::metadata(dir.log()).unwrap().len() < 3 * TAIL_CHUNK {
            log.append(&admit()).unwrap();
        }
        let head = log.head().to_owned();
        drop(log);
        assert_eq!(AuditLog::open(dir.log()).unwrap().head(), head);

        // A torn tail longer than one chunk is cut off too.
        let before = fs::read(dir.log()).unwrap();
        let mut file = OpenOptions::new().append(true).open(dir.log()).unwrap();
        file.write_all(&vec![b'x'; 2 * TAIL_CHUNK as usize])
            .unwrap();
        drop(file);
        let log = AuditLog::open(dir.log()).unwrap();
        assert_eq!(log.head(), head);
        assert_eq!(fs::read(dir.log()).unwrap(), before);
    }

    // BEP-048: a second writer on the same log would fork the chain, so
    // open refuses it while the first one holds the log.
    #[test]
    fn audit_log_refuses_a_second_writer() {
        let dir = TempDir::new();
        let log = AuditLog::open(dir.log()).unwrap();
        let err = AuditLog::open(dir.log()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        drop(log);
        AuditLog::open(dir.log()).unwrap();
    }

    // A segment replaced by a shorter file is read again from its start,
    // and is not skipped for the rest of a `--follow` run.
    #[test]
    fn log_reader_rereads_a_truncated_segment() {
        let dir = TempDir::new();
        let segment = dir.0.join(segment_name(1));
        let mut log = AuditLog::open(&segment).unwrap();
        log.append(&admit()).unwrap();
        log.append(&off_module()).unwrap();
        drop(log);
        let mut reader = LogReader::new(&dir.0);
        assert_eq!(reader.read_new().unwrap().entries.len(), 2);

        fs::remove_file(&segment).unwrap();
        let mut log = AuditLog::open(&segment).unwrap();
        log.append(&off_module()).unwrap();
        drop(log);
        let batch = reader.read_new().unwrap();
        assert_eq!(batch.entries.len(), 1);
        assert_eq!(batch.entries[0].record.upstream, "example.com:443");
    }

    // A segment replaced by a longer file between two reads is read from
    // the start of the new file, not from the old offset.
    #[test]
    fn log_reader_rereads_a_replaced_longer_segment() {
        let dir = TempDir::new();
        let segment = dir.0.join(segment_name(1));
        let mut log = AuditLog::open(&segment).unwrap();
        log.append(&off_module()).unwrap();
        drop(log);
        let mut reader = LogReader::new(&dir.0);
        assert_eq!(reader.read_new().unwrap().entries.len(), 1);

        // Keep the old file open so the new one cannot reuse its inode.
        let old = segment.with_extension("old");
        fs::rename(&segment, &old).unwrap();
        let _hold = File::open(&old).unwrap();
        let mut log = AuditLog::open(&segment).unwrap();
        log.append(&admit()).unwrap();
        log.append(&admit()).unwrap();
        log.append(&off_module()).unwrap();
        drop(log);
        assert!(fs::metadata(&segment).unwrap().len() > fs::metadata(&old).unwrap().len());
        let batch = reader.read_new().unwrap();
        assert_eq!(batch.skipped, 0);
        let upstreams: Vec<_> = batch
            .entries
            .iter()
            .map(|e| e.record.upstream.as_str())
            .collect();
        assert_eq!(
            upstreams,
            [
                "api.github.com:443",
                "api.github.com:443",
                "example.com:443"
            ]
        );
    }

    // BEP-041: the descriptor carries O_APPEND and no truncate, and earlier
    // records stay byte for byte across reopens.
    #[test]
    fn audit_log_is_opened_append_only() {
        let dir = TempDir::new();
        let mut log = AuditLog::open(dir.log()).unwrap();
        log.append(&admit()).unwrap();
        log.append(&off_module()).unwrap();
        let before = fs::read(dir.log()).unwrap();

        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd as _;
            let fdinfo =
                fs::read_to_string(format!("/proc/self/fdinfo/{}", log.file.as_raw_fd())).unwrap();
            let flags = fdinfo
                .lines()
                .find_map(|l| l.strip_prefix("flags:"))
                .map(|f| u32::from_str_radix(f.trim(), 8).unwrap())
                .unwrap();
            const O_ACCMODE: u32 = 0o3;
            const O_WRONLY: u32 = 0o1;
            const O_APPEND: u32 = 0o2000;
            assert_ne!(flags & O_APPEND, 0, "audit log is not opened O_APPEND");
            assert_eq!(
                flags & O_ACCMODE,
                O_WRONLY,
                "audit log is readable or not write-only"
            );
        }
        drop(log);

        let mut log = AuditLog::open(dir.log()).unwrap();
        assert_eq!(fs::read(dir.log()).unwrap(), before, "open changed the log");
        log.append(&admit()).unwrap();
        let after = fs::read(dir.log()).unwrap();
        assert!(after.len() > before.len());
        assert_eq!(&after[..before.len()], &before[..]);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = fs::metadata(dir.log()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
            let state = dir.log().parent().unwrap().to_path_buf();
            let mode = fs::metadata(&state).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "open made a wider state directory");

            // An existing log with a wider mode is tightened on open.
            drop(log);
            fs::set_permissions(dir.log(), fs::Permissions::from_mode(0o644)).unwrap();
            log = AuditLog::open(dir.log()).unwrap();
            let mode = fs::metadata(dir.log()).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "open kept a wider log mode");
        }
        drop(log);

        // A symlink at the log's path is refused, and its target is kept.
        #[cfg(unix)]
        {
            let target = dir.0.join("elsewhere");
            fs::write(&target, b"keep\n").unwrap();
            let link = dir.0.join("state").join("linked.jsonl");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            let err = AuditLog::open(&link).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert_eq!(fs::read(&target).unwrap(), b"keep\n");

            // A dangling symlink is refused, and its target is not created.
            let missing = dir.0.join("missing");
            let dangling = dir.0.join("state").join("dangling.jsonl");
            std::os::unix::fs::symlink(&missing, &dangling).unwrap();
            let err = AuditLog::open(&dangling).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            assert!(!missing.exists(), "open created the symlink's target");

            // A directory at the path is not a regular file.
            let not_file = dir.0.join("state").join("dir.jsonl");
            fs::create_dir(&not_file).unwrap();
            let err = AuditLog::open(&not_file).unwrap_err();
            assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        }
    }

    fn rotation(bound: u64, retain: usize, ceiling_secs: u64) -> Rotation {
        Rotation {
            bound,
            retain,
            revocation_ceiling: std::time::Duration::from_secs(ceiling_secs),
        }
    }

    fn revocation(box_id: &str) -> Decision {
        Decision {
            kind: Kind::Revocation,
            box_id: box_id.into(),
            authority: String::new(),
            identifier: None,
            // A mint or a revocation carries no handle.
            jti: String::new(),
            mapping: Mapping::ModuleUnmapped,
            outcome: Outcome::Refuse,
            marker: None,
        }
    }

    // BEP-068: a quarantine of the active segment goes on in the next
    // segment, chained across the gap, and a revocation read in the moved
    // segment is recorded again.
    #[test]
    fn quarantine_of_the_active_segment_opens_the_next() {
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        let mut log = AuditLog::open_dir(&audit, rotation(1 << 20, 16, 60)).unwrap();
        log.append(&admit()).unwrap();
        log.append(&revocation("box-gone")).unwrap();
        let head = log.head().to_owned();
        drop(log);
        let active = audit.join(segment_name(0));
        let mut file = OpenOptions::new().append(true).open(&active).unwrap();
        let other = format!(r#"{{"schema":"{SCHEMA}","kind":"future","previous_hash":"{head}"}}"#);
        file.write_all(format!("{other}\n").as_bytes()).unwrap();
        file.write_all(b"not a record\n").unwrap();
        drop(file);
        assert_eq!(LogReader::new(&audit).read_new().unwrap().skipped, 1);

        let mut log = AuditLog::open_dir(&audit, rotation(1 << 20, 16, 60)).unwrap();
        let moved = log.quarantine_unreadable().unwrap();
        assert_eq!(moved.len(), 1);
        assert_eq!(moved[0].revoked, vec!["box-gone".to_owned()]);
        assert_eq!(moved[0].other_kinds, 1);
        assert_eq!(log.path(), audit.join(segment_name(1)));
        assert_eq!(moved[0].record.previous_hash, moved[0].record.final_hash);
        log.append(&off_module()).unwrap();
        drop(log);
        assert!(audit.join(QUARANTINE_DIR).join(segment_name(0)).exists());
        // The quarantine, the revocation again and the new record.
        assert_eq!(verify_chain(&audit).unwrap(), Ok(3));
        let batch = LogReader::new(&audit).read_new().unwrap();
        assert_eq!((batch.skipped, batch.other_kinds), (0, 1));
        assert!(
            batch
                .entries
                .iter()
                .any(|entry| entry.record.kind == Kind::Revocation)
        );
    }

    // BEP-049, BEP-068: a quarantine record bridges a gap only between two
    // segments, and only with the moved segment under `quarantine/`.
    #[test]
    fn forged_quarantine_record_bridges_no_gap() {
        let forge = |from_hash: &str, final_hash: &str, previous_hash: &str| {
            QuarantineRecord {
                schema: SCHEMA.to_owned(),
                kind: QUARANTINE.to_owned(),
                segment: segment_name(1),
                from_hash: from_hash.to_owned(),
                final_hash: final_hash.to_owned(),
                unreadable: 1,
                previous_hash: previous_hash.to_owned(),
            }
            .to_line()
        };
        let append_line = |path: &Path, line: &str| {
            let mut file = OpenOptions::new().append(true).open(path).unwrap();
            file.write_all(format!("{line}\n").as_bytes()).unwrap();
        };

        // A whole segment removed, and a record that names it appended.
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        // A bound of one byte: each record after the first opens a segment.
        let mut log = AuditLog::open_dir(&audit, rotation(1, 16, 60)).unwrap();
        let first = log.append(&admit()).unwrap();
        log.append(&revocation("box-gone")).unwrap();
        let third = log.append(&admit()).unwrap();
        let head = log.head().to_owned();
        drop(log);
        let removed = audit.join(segment_name(1));
        let removed_bytes = fs::read(&removed).unwrap();
        fs::remove_file(&removed).unwrap();
        let first_hash = line_hash(first.to_line());
        append_line(
            &audit.join(segment_name(2)),
            &forge(&first_hash, &third.previous_hash, &head),
        );
        assert!(verify_chain(&audit).unwrap().is_err());
        // A file of that name that holds no unreadable line does not agree.
        fs::create_dir_all(audit.join(QUARANTINE_DIR)).unwrap();
        fs::write(
            audit.join(QUARANTINE_DIR).join(segment_name(1)),
            &removed_bytes,
        )
        .unwrap();
        assert!(verify_chain(&audit).unwrap().is_err());

        // A run of records removed inside one segment.
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        let mut log = AuditLog::open_dir(&audit, rotation(1 << 20, 16, 60)).unwrap();
        let first = log.append(&admit()).unwrap();
        let second = log.append(&revocation("box-gone")).unwrap();
        let third = log.append(&admit()).unwrap();
        drop(log);
        let active = audit.join(segment_name(0));
        let kept = format!("{}\n{}\n", first.to_line(), third.to_line());
        fs::write(&active, &kept).unwrap();
        fs::create_dir_all(audit.join(QUARANTINE_DIR)).unwrap();
        fs::write(
            audit.join(QUARANTINE_DIR).join(segment_name(1)),
            format!("{}\nnot a record\n", second.to_line()),
        )
        .unwrap();
        let first_hash = line_hash(first.to_line());
        append_line(
            &active,
            &forge(
                &first_hash,
                &third.previous_hash,
                &line_hash(third.to_line()),
            ),
        );
        assert!(verify_chain(&audit).unwrap().is_err());
    }

    // BEP-068: a quarantine that fails part way moves no segment it did
    // not record, so a revocation in a bad segment stays in the log.
    #[test]
    fn quarantine_that_fails_leaves_no_moved_segment_unrecorded() {
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        // A bound of one byte: each record after the first opens a segment.
        let mut log = AuditLog::open_dir(&audit, rotation(1, 16, 60)).unwrap();
        log.append(&revocation("box-gone")).unwrap();
        log.append(&admit()).unwrap();
        log.append(&admit()).unwrap();
        drop(log);
        for n in [0, 1] {
            let mut file = OpenOptions::new()
                .append(true)
                .open(audit.join(segment_name(n)))
                .unwrap();
            file.write_all(b"not a record\n").unwrap();
        }
        // A file in the way of the second move.
        fs::create_dir_all(audit.join(QUARANTINE_DIR)).unwrap();
        let blocker = audit.join(QUARANTINE_DIR).join(segment_name(1));
        fs::write(&blocker, b"").unwrap();
        let before: Vec<Vec<u8>> = (0..3)
            .map(|n| fs::read(audit.join(segment_name(n))).unwrap())
            .collect();

        let mut log = AuditLog::open_dir(&audit, rotation(1, 16, 60)).unwrap();
        let err = log.quarantine_unreadable().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        drop(log);
        assert!(!audit.join(QUARANTINE_DIR).join(segment_name(0)).exists());
        let after: Vec<Vec<u8>> = (0..3)
            .map(|n| fs::read(audit.join(segment_name(n))).unwrap())
            .collect();
        assert_eq!(after, before);

        fs::remove_file(&blocker).unwrap();
        let mut log = AuditLog::open_dir(&audit, rotation(1, 16, 60)).unwrap();
        let moved = log.quarantine_unreadable().unwrap();
        assert_eq!(moved.len(), 2);
        assert_eq!(moved[0].revoked, vec!["box-gone".to_owned()]);
        drop(log);
        assert!(verify_chain(&audit).unwrap().is_ok());
        let batch = LogReader::new(&audit).read_new().unwrap();
        assert_eq!(batch.skipped, 0);
        assert!(
            batch
                .entries
                .iter()
                .any(|entry| entry.record.kind == Kind::Revocation)
        );
    }

    // BEP-068: a full segment opens the next one, whose first record
    // carries the previous segment's final hash, and so does a reopen into
    // a segment that holds no record yet.
    #[test]
    fn segment_rotation_continues_chain() {
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        // A bound of one byte: each record after the first opens a segment.
        let mut log = AuditLog::open_dir(&audit, rotation(1, 100, 0)).unwrap();
        for _ in 0..3 {
            log.append(&admit()).unwrap();
        }
        let found = segments(&audit).unwrap();
        assert_eq!(
            found,
            (0..3)
                .map(|n| audit.join(segment_name(n)))
                .collect::<Vec<_>>()
        );
        let mut previous = ZERO_HASH.to_owned();
        for path in &found {
            let lines = lines(path);
            assert_eq!(lines.len(), 1, "{}", path.display());
            let record: Record = serde_json::from_str(&lines[0]).unwrap();
            assert_eq!(record.previous_hash, previous, "{}", path.display());
            previous = line_hash(&lines[0]);
        }
        assert_eq!(log.head(), previous);
        assert_eq!(log.path(), audit.join(segment_name(2)));

        // A reopen resumes the chain in the active segment.
        drop(log);
        let mut log = AuditLog::open_dir(&audit, rotation(1, 100, 0)).unwrap();
        assert_eq!(log.head(), previous);
        let record = log.append(&off_module()).unwrap();
        assert_eq!(record.previous_hash, previous);
        assert_eq!(log.path(), audit.join(segment_name(3)));

        // An empty active segment, left by a stop between the open and the
        // first append, chains to the segment before it.
        let previous = log.head().to_owned();
        drop(log);
        File::create(audit.join(segment_name(4))).unwrap();
        let mut log = AuditLog::open_dir(&audit, rotation(1 << 20, 100, 0)).unwrap();
        assert_eq!(log.head(), previous);
        let record = log.append(&admit()).unwrap();
        assert_eq!(record.previous_hash, previous);
        assert_eq!(log.path(), audit.join(segment_name(4)));

        // Pruned past the retention bound, oldest first.
        drop(log);
        let mut log = AuditLog::open_dir(&audit, rotation(1, 2, 0)).unwrap();
        log.append(&admit()).unwrap();
        assert_eq!(
            segments(&audit).unwrap(),
            vec![audit.join(segment_name(4)), audit.join(segment_name(5))]
        );
    }

    // BEP-068: a writer that listed the segments before another writer
    // rotated does not lock the closed segment and fork the chain there.
    #[test]
    fn open_dir_relists_after_a_rotation() {
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        let mut writer = AuditLog::open_dir(&audit, rotation(1, 100, 0)).unwrap();
        writer.append(&admit()).unwrap();
        let stale = numbered_segments(&audit).unwrap();
        writer.append(&admit()).unwrap();
        assert_eq!(writer.path(), audit.join(segment_name(1)));
        let closed = fs::read(audit.join(segment_name(0))).unwrap();

        // The closed segment is free to lock, but the newest is held.
        let err =
            AuditLog::open_listed(audit.clone(), rotation(1, 100, 0), stale.clone()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(fs::read(audit.join(segment_name(0))).unwrap(), closed);

        // With the writer gone, the stale listing still ends on the newest.
        let head = writer.head().to_owned();
        drop(writer);
        let log = AuditLog::open_listed(audit.clone(), rotation(1, 100, 0), stale).unwrap();
        assert_eq!(log.path(), audit.join(segment_name(1)));
        assert_eq!(log.head(), head);
    }

    // BEP-068: one writer holds the audit directory for the life of its
    // log, so a rotation does not free the closed segment for a second
    // writer to append there and fork the chain.
    #[test]
    fn open_dir_refuses_a_second_writer_across_rotation() {
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        let mut writer = AuditLog::open_dir(&audit, rotation(1, 100, 0)).unwrap();
        writer.append(&admit()).unwrap();

        let err = AuditLog::open_dir(&audit, rotation(1, 100, 0)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(
            err.to_string(),
            format!(
                "audit directory {} is held by another `bep serve`",
                audit.display()
            )
        );

        // The rotation releases segment 0, and the directory stays held.
        writer.append(&admit()).unwrap();
        assert_eq!(writer.path(), audit.join(segment_name(1)));
        let closed = fs::read(audit.join(segment_name(0))).unwrap();
        let err = AuditLog::open_dir(&audit, rotation(1, 100, 0)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert_eq!(fs::read(audit.join(segment_name(0))).unwrap(), closed);
        // The lock file is not a segment.
        assert_eq!(
            segments(&audit).unwrap(),
            vec![audit.join(segment_name(0)), audit.join(segment_name(1))]
        );

        // With the writer gone, the next one continues the newest segment.
        let head = writer.head().to_owned();
        drop(writer);
        let log = AuditLog::open_dir(&audit, rotation(1, 100, 0)).unwrap();
        assert_eq!(log.path(), audit.join(segment_name(1)));
        assert_eq!(log.head(), head);
    }

    // BEP-068: a segment past the retention bound that holds a revocation
    // record stays until every value naming the box can have expired.
    #[test]
    fn segment_with_live_revocation_is_retained() {
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        let day = 24 * 60 * 60;
        let mut log = AuditLog::open_dir(&audit, rotation(1, 1, day)).unwrap();
        log.append(&admit()).unwrap();
        log.append(&revocation("0190aaaa")).unwrap();
        log.append(&admit()).unwrap();
        log.append(&admit()).unwrap();
        // Only the active segment is within the bound. Segment 1 holds the
        // revocation and is kept, segments 0 and 2 are not.
        assert_eq!(
            segments(&audit).unwrap(),
            vec![audit.join(segment_name(1)), audit.join(segment_name(3))]
        );
        assert!(holds_revocation(&audit.join(segment_name(1))).unwrap());

        // Before the ceiling has passed the segment stays.
        let soon = std::time::SystemTime::now() + std::time::Duration::from_secs(day / 2);
        assert!(
            prune(&audit, &rotation(1, 1, day), soon)
                .unwrap()
                .is_empty()
        );
        // Once every value naming the box has expired, it goes.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(2 * day);
        assert_eq!(
            prune(&audit, &rotation(1, 1, day), later).unwrap(),
            vec![audit.join(segment_name(1))]
        );
        assert_eq!(segments(&audit).unwrap(), vec![audit.join(segment_name(3))]);

        // The default ceiling is the root's full validity.
        assert_eq!(
            Rotation::default().revocation_ceiling.as_secs(),
            crate::publish::ROOT_VALIDITY_SECS
        );
    }

    // BEP-068: a complete line that does not parse can be a revocation, so
    // prune keeps its segment. A partial last line is a torn write, not a
    // record, and does not keep one.
    #[test]
    fn segment_with_unparsable_line_survives_prune() {
        let dir = TempDir::new();
        let audit = dir.0.join("audit");
        fs::create_dir_all(&audit).unwrap();
        fs::write(audit.join(segment_name(0)), b"{\"kind\":\"revoc\n").unwrap();
        fs::write(audit.join(segment_name(1)), b"{\"kind\":\"revoc").unwrap();
        fs::write(audit.join(segment_name(2)), b"").unwrap();
        assert!(holds_revocation(&audit.join(segment_name(0))).unwrap());
        assert!(!holds_revocation(&audit.join(segment_name(1))).unwrap());
        // A kind this bep does not know can be a newer bep's revocation.
        let future = dir.0.join("future.jsonl");
        fs::write(
            &future,
            format!("{{\"schema\":\"{SCHEMA}\",\"kind\":\"future_kind\",\"previous_hash\":\"{ZERO_HASH}\"}}\n"),
        )
        .unwrap();
        assert!(holds_revocation(&future).unwrap());

        let day = 24 * 60 * 60;
        let soon = std::time::SystemTime::now() + std::time::Duration::from_secs(day / 2);
        assert_eq!(
            prune(&audit, &rotation(1, 1, day), soon).unwrap(),
            vec![audit.join(segment_name(1))]
        );
        assert_eq!(
            segments(&audit).unwrap(),
            vec![audit.join(segment_name(0)), audit.join(segment_name(2))]
        );
    }

    // A request as the proxy sees it: the BEP-039 fields plus the secrets
    // a record must never carry.
    #[derive(Debug, Clone)]
    struct Request {
        decision: Decision,
        credential: String,
        injected_header: String,
        body: Vec<u8>,
    }

    fn field() -> impl Strategy<Value = String> {
        "[a-z0-9:./-]{1,24}"
    }

    fn decision_strategy() -> impl Strategy<Value = Decision> {
        (
            prop_oneof![
                Just(Kind::Decision),
                Just(Kind::Mint),
                Just(Kind::Revocation)
            ],
            field(),
            field(),
            proptest::option::of(field()),
            field(),
            proptest::option::of((field(), field())),
            any::<bool>(),
            proptest::option::of(field()),
        )
            .prop_map(
                |(kind, box_id, authority, identifier, jti, mapping, admit, marker)| Decision {
                    kind,
                    box_id,
                    authority,
                    identifier,
                    jti,
                    mapping: mapping.map_or(Mapping::ModuleUnmapped, |(resource, permission)| {
                        Mapping::Mapped {
                            resource,
                            permission,
                        }
                    }),
                    outcome: if admit {
                        Outcome::Admit
                    } else {
                        Outcome::Refuse
                    },
                    marker,
                },
            )
    }

    fn request_strategy() -> impl Strategy<Value = Request> {
        (
            decision_strategy(),
            "ghu_[A-Z]{36}",
            "Bearer [A-Z]{32}",
            proptest::collection::vec(any::<u8>(), 0..256),
        )
            .prop_map(|(decision, credential, injected_header, body)| Request {
                decision,
                credential,
                injected_header,
                body,
            })
    }

    proptest! {
        // BEP-040: two requests that differ only in body give the same record
        // apart from the chain field, and no record carries the credential,
        // the injected header value or the body.
        #[test]
        fn prop_audit_records_never_contain_secrets(
            request in request_strategy(),
            other_body in proptest::collection::vec(any::<u8>(), 0..256),
            other_credential in "ghu_[A-Z]{36}",
        ) {
            let dir = TempDir::new();
            let mut log = AuditLog::open(dir.log()).unwrap();
            let other = Request {
                body: other_body,
                credential: other_credential,
                ..request.clone()
            };
            let first = log.append(&request.decision).unwrap();
            let second = log.append(&other.decision).unwrap();
            prop_assert_eq!(
                Record { previous_hash: String::new(), ..first },
                Record { previous_hash: String::new(), ..second }
            );

            let contents = fs::read_to_string(dir.log()).unwrap();
            for secret in [
                &request.credential,
                &request.injected_header,
                &other.credential,
            ] {
                prop_assert!(!contents.contains(secret.as_str()));
            }
            // The secrets' alphabet is upper case, and every BEP-039 field
            // here is lower case, so any upper-case run of 32 came from one.
            prop_assert!(!contents.contains("ghu_"));
            prop_assert!(!contents.contains("Bearer"));
            for body in [&request.body, &other.body] {
                if body.len() >= 16 {
                    prop_assert!(!contents.as_bytes().windows(body.len()).any(|w| w == &body[..]));
                }
            }
        }
    }
}
