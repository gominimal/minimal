//! The proxy's audit log (BEP-039, BEP-040, BEP-041, BEP-048).
//!
//! The log is JSONL under the proxy's state directory: one line for each
//! decision, in the `min/v1` audit schema. The proxy is the log's only
//! writer.
//!
//! A record is built from a [`Decision`] alone. A `Decision` has no field
//! for a credential, an injected header value or a request body, so a record
//! cannot carry one (BEP-040).
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

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// The audit schema every record names.
pub const SCHEMA: &str = "min/v1";

/// The identifier a record carries when the request names no member or
/// store identifier.
pub const NONE: &str = "none";

/// The resource and permission a record carries when the module maps none.
pub const MODULE_UNMAPPED: &str = "module_unmapped";

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
            } => (resource.clone(), permission.clone()),
            Mapping::ModuleUnmapped => (MODULE_UNMAPPED.to_owned(), MODULE_UNMAPPED.to_owned()),
        };
        Self {
            schema: SCHEMA.to_owned(),
            kind: decision.kind,
            subject: decision.box_id.clone(),
            act: String::new(),
            txn: String::new(),
            upstream: decision.authority.clone(),
            identifier: decision
                .identifier
                .clone()
                .unwrap_or_else(|| NONE.to_owned()),
            resource,
            permission,
            decision: decision.outcome,
            marker: decision.marker.clone(),
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
pub fn line_hash(line: &str) -> String {
    let digest = Sha256::digest(line.as_bytes());
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0xf), 16).unwrap_or('0'));
    }
    out
}

/// The hash the next record of the log in `contents` carries: the hash of
/// its last line, or [`ZERO_HASH`] for an empty log.
pub fn head_hash(contents: &str) -> String {
    contents
        .lines()
        .rev()
        .find(|line| !line.is_empty())
        .map_or_else(|| ZERO_HASH.to_owned(), line_hash)
}

/// The audit log, open for append only.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    file: File,
    head: String,
}

impl AuditLog {
    /// Opens the log at `path` for append, and creates it and its parent
    /// directory when absent. The next record chains to the log's last line.
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut options = OpenOptions::new();
        options.append(true).create(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        let file = options.open(&path)?;
        let head = head_hash(&fs::read_to_string(&path)?);
        Ok(Self { path, file, head })
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
    /// head does not move, and one warn line names the path.
    pub fn append(&mut self, decision: &Decision) -> io::Result<Record> {
        let record = Record::from_decision(decision, &self.head);
        let line = record.to_line();
        let mut bytes = Vec::with_capacity(line.len() + 1);
        bytes.extend_from_slice(line.as_bytes());
        bytes.push(b'\n');
        if let Err(err) = self.file.write_all(&bytes).and_then(|()| self.file.flush()) {
            tracing::warn!(path = %self.path.display(), error = %err, "audit append failed");
            return Err(err);
        }
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
        assert_eq!(first["schema"], "min/v1");
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
