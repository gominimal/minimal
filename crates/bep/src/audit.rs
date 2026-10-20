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
            // Directories this call creates are the proxy's alone.
            let mut dirs = fs::DirBuilder::new();
            dirs.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt as _;
                dirs.mode(0o700);
            }
            dirs.create(parent)?;
        }
        // Refused before the open as well, so a symlink's target is never
        // created and a FIFO never blocks the open. The check after the
        // open still catches an entry swapped in between the two.
        match fs::symlink_metadata(&path) {
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
        let file = options.open(&path)?;
        // Checked after the open, against the open file, so a link swapped
        // in between a check and the open cannot slip through.
        ensure_own_file(&path, &file)?;
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
        })
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
        if self.poisoned {
            return Err(io::Error::other(format!(
                "audit log {} holds a torn line, reopen it",
                self.path.display()
            )));
        }
        let record = Record::from_decision(decision, &self.head);
        let line = record.to_line();
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
        self.head = line_hash(&line);
        Ok(record)
    }
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
            proptest::option::of((field(), field())),
            any::<bool>(),
            proptest::option::of(field()),
        )
            .prop_map(
                |(kind, box_id, authority, identifier, mapping, admit, marker)| Decision {
                    kind,
                    box_id,
                    authority,
                    identifier,
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
