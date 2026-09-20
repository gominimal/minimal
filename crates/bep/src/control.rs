//! The control socket's audit submissions: how a client's own identity events
//! reach the log the proxy alone writes.
//!
//! The client never opens the audit log. It submits a mint or a revocation
//! over the proxy's control socket and the proxy appends it to the same chain
//! as its own decisions (BEP-067), so the head read, the append and the chain
//! advance stay one operation in one process and a client's record and a
//! proxy's decision can never share a predecessor. A decision is the proxy's
//! own account of a request it handled, so the socket does not take one.
//!
//! A revocation submission is more than a record: it is what puts a box's
//! sealed values, or every member of a module on this host, beyond redemption
//! (BEP-043, BEP-044). [`Revocations`] is that set, and appending the record
//! and putting the revocation in force are one operation ([`submit`]), so an
//! intake cannot record a revocation it then fails to enforce. The set is the
//! log's own projection — [`Revocations::in_log`] rebuilds it from the
//! retained records — so a proxy that restarts still refuses what was revoked
//! before it did.
//!
//! This module is the submission vocabulary, the append and the set; the
//! socket itself — owned by the operator's user, mode `0600`, separate from
//! the redemption listener — is the listener's (BEP-063).

use std::collections::BTreeSet;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::audit::{AuditError, Event, Kind, Log, Record};
use crate::mint::EVERY_BOX;

/// What a client submits over the control socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "submit", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Submission {
    /// An identity event of the client's, for the proxy to append to the audit
    /// log. The client names the record's fields; the chain field is the
    /// writer's alone.
    Audit(Event),
}

/// The longest a revocation may take to reach the decision, in seconds
/// (BEP-043, BEP-044).
///
/// The bound is met by construction rather than by a deadline anything waits
/// on: a submission puts the revocation in force in the same operation as the
/// append, and [`crate::redeem`] reads the set per request, so the next
/// request after the submission is already refused. The constant is what the
/// tests hold the intake to, so an intake that ever polled or cached would
/// have to state its own lag against it.
pub const REVOCATION_DEADLINE_SECS: u64 = 60;

/// The revocations in force on this host: what may no longer be redeemed,
/// whatever a sealed value's own expiry says (BEP-024).
///
/// A subject is a box name, from `min box stop` or `min box rm` of that box
/// (BEP-043), or a module, from `min auth logout` on this host (BEP-044). Both
/// are the names the sealed context carries, not the ids the decision interns:
/// the set outlives any one request, while the ids are minted per request by
/// the shell.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Revocations {
    /// Box names every sealed value naming which is refused.
    boxes: BTreeSet<String>,
    /// Modules every member of which is refused on this host.
    modules: BTreeSet<String>,
}

impl Revocations {
    /// The revocations the log at `path` records, oldest first: the set a
    /// proxy starts from, so a restart refuses what was revoked before it.
    ///
    /// A log that is not there yet is no revocation at all — a host whose
    /// proxy has never run.
    ///
    /// # Errors
    ///
    /// [`AuditError::Read`] when the log cannot be read, or
    /// [`AuditError::Malformed`] when it holds a line that is no record.
    pub fn in_log(path: &Path) -> Result<Self, AuditError> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(source) => {
                return Err(AuditError::Read {
                    path: path.to_path_buf(),
                    source,
                });
            }
        };
        let mut revocations = Self::default();
        for line in text.lines().filter(|line| !line.trim().is_empty()) {
            let record: Record =
                serde_json_lenient::from_str(line).map_err(|source| AuditError::Malformed {
                    path: path.to_path_buf(),
                    source,
                })?;
            revocations.record(&record);
        }
        Ok(revocations)
    }

    /// Whether nothing is revoked.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.boxes.is_empty() && self.modules.is_empty()
    }

    /// Puts what `record` revokes in force; a record of any other kind
    /// changes nothing.
    ///
    /// A revocation naming [`EVERY_BOX`] is the logout of a sign-in, so it
    /// covers the module its member identifier names rather than a box.
    pub fn record(&mut self, record: &Record) {
        if record.kind != Kind::Revocation {
            return;
        }
        if record.sub == EVERY_BOX {
            self.modules
                .insert(module_of(&record.credential).to_owned());
        } else {
            self.boxes.insert(record.sub.clone());
        }
    }

    /// Whether every sealed value naming `box_id` is refused (BEP-043).
    #[must_use]
    pub fn covers_box(&self, box_id: &str) -> bool {
        self.boxes.contains(box_id)
    }

    /// Whether every member of `module` on this host is refused (BEP-044).
    #[must_use]
    pub fn covers_module(&self, module: &str) -> bool {
        self.modules.contains(module)
    }
}

/// The module a member identifier belongs to: `github` of
/// `github:user-token`, the one spelling the mint and the listener both write.
fn module_of(credential: &str) -> &str {
    credential.split(':').next().unwrap_or(credential)
}

/// Why a submission was refused.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControlError {
    /// The submission claims a kind only the proxy records.
    #[error(
        "a {0} record is the proxy's own account of a request; the control socket takes mint and revocation records"
    )]
    NotSubmittable(Kind),
    /// The log refused the append.
    #[error(transparent)]
    Audit(#[from] AuditError),
}

/// Appends `submission` to `log`, the proxy's own and the only writable one,
/// and puts a revocation it carries into `revocations` — one operation, so
/// nothing is recorded as revoked that is not also refused from here on
/// (BEP-043, BEP-044).
///
/// # Errors
///
/// A [`ControlError`]: the submission claims a kind only the proxy records, or
/// the log refuses the append. A submission that is refused changes neither
/// the log nor the set.
pub fn submit(
    log: &mut Log,
    revocations: &mut Revocations,
    submission: &Submission,
) -> Result<Record, ControlError> {
    let Submission::Audit(event) = submission;
    if event.kind == Kind::Decision {
        tracing::warn!(
            kind = %event.kind,
            box_id = %event.box_id,
            "refusing a control-socket submission of a record the proxy alone writes"
        );
        return Err(ControlError::NotSubmittable(event.kind));
    }
    tracing::info!(
        kind = %event.kind,
        box_id = %event.box_id,
        "appending a control-socket audit submission"
    );
    let record = log.append(event)?;
    revocations.record(&record);
    if record.kind == Kind::Revocation {
        tracing::info!(
            subject = %record.sub,
            credential = %record.credential,
            deadline_secs = REVOCATION_DEADLINE_SECS,
            "a revocation is in force; every request from here on reads it"
        );
    }
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{Decision, Hash, Mapping};

    fn event(kind: Kind) -> Event {
        Event {
            kind,
            box_id: "box-a1".to_owned(),
            authority: "api.github.com".to_owned(),
            credential: Some("github:user-token".to_owned()),
            mapping: Mapping::Unmapped,
            decision: Decision::Admit,
            marker: None,
        }
    }

    /// A client's mints and revocations join the proxy's own chain, and a
    /// client cannot submit a decision record at all.
    #[test]
    fn control_submissions_append_to_the_proxys_chain() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = Log::open(dir.path().join("audit.jsonl")).unwrap();
        let mut revocations = Revocations::default();
        let decided = log.append(&event(Kind::Decision)).unwrap();

        let minted = submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Mint)),
        )
        .unwrap();
        assert_eq!(minted.kind, Kind::Mint);
        assert_eq!(minted.previous_hash, decided.line_hash());
        // A mint revokes nothing.
        assert!(revocations.is_empty());
        let revoked = submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Revocation)),
        )
        .unwrap();
        assert_eq!(revoked.previous_hash, minted.line_hash());
        assert_ne!(revoked.previous_hash, Hash::ZERO);
        // The append and the set move together: the box is refused from here.
        assert!(revocations.covers_box("box-a1"));

        // A decision is the proxy's own: submitting one appends nothing.
        let refused = submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Decision)),
        );
        assert!(matches!(
            refused,
            Err(ControlError::NotSubmittable(Kind::Decision))
        ));
        assert_eq!(log.head(), revoked.line_hash());
        assert_eq!(
            std::fs::read_to_string(log.path()).unwrap().lines().count(),
            3
        );
    }

    /// BEP-043 and BEP-044 as the set sees them: a revocation naming a box
    /// covers that box and no other, one naming every box covers the module
    /// its member identifier names, and the set a restarted proxy rebuilds
    /// from the log is the set it had.
    #[test]
    fn revocations_cover_the_box_or_the_whole_module() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut log = Log::open(&path).unwrap();
        let mut revocations = Revocations::default();

        // A log that is not there yet revokes nothing.
        assert!(
            Revocations::in_log(&dir.path().join("never-ran.jsonl"))
                .unwrap()
                .is_empty()
        );

        // `min box rm box-a1`: that box, and nothing else.
        submit(
            &mut log,
            &mut revocations,
            &Submission::Audit(event(Kind::Revocation)),
        )
        .unwrap();
        assert!(revocations.covers_box("box-a1"));
        assert!(!revocations.covers_box("box-b2"));
        assert!(!revocations.covers_module("github"));

        // `min auth logout`: every member of the module on this host.
        let mut logout = event(Kind::Revocation);
        logout.box_id = EVERY_BOX.to_owned();
        submit(&mut log, &mut revocations, &Submission::Audit(logout)).unwrap();
        assert!(revocations.covers_module("github"));
        assert!(!revocations.covers_module("store"));
        // The wildcard subject is not a box name of its own.
        assert!(!revocations.covers_box(EVERY_BOX));

        // What a proxy that restarts reads back out of the log.
        assert_eq!(Revocations::in_log(&path).unwrap(), revocations);
    }

    /// The submission is one wire form, and it round-trips.
    #[test]
    fn control_submission_round_trips() {
        let submission = Submission::Audit(event(Kind::Mint));
        let wire = serde_json_lenient::to_string(&submission).unwrap();
        assert!(wire.contains(r#""submit":"audit""#), "{wire}");
        assert_eq!(
            serde_json_lenient::from_str::<Submission>(&wire).unwrap(),
            submission
        );
    }
}
