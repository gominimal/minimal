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
//! This module is the submission vocabulary and the append; the socket itself
//! — owned by the operator's user, mode `0600`, separate from the redemption
//! listener — is the listener's (BEP-063).

use serde::{Deserialize, Serialize};

use crate::audit::{AuditError, Event, Kind, Log, Record};

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

/// Appends `submission` to `log`, the proxy's own and the only writable one.
///
/// # Errors
///
/// A [`ControlError`]: the submission claims a kind only the proxy records, or
/// the log refuses the append.
pub fn submit(log: &mut Log, submission: &Submission) -> Result<Record, ControlError> {
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
    Ok(log.append(event)?)
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
        let decided = log.append(&event(Kind::Decision)).unwrap();

        let minted = submit(&mut log, &Submission::Audit(event(Kind::Mint))).unwrap();
        assert_eq!(minted.kind, Kind::Mint);
        assert_eq!(minted.previous_hash, decided.line_hash());
        let revoked = submit(&mut log, &Submission::Audit(event(Kind::Revocation))).unwrap();
        assert_eq!(revoked.previous_hash, minted.line_hash());
        assert_ne!(revoked.previous_hash, Hash::ZERO);

        // A decision is the proxy's own: submitting one appends nothing.
        let refused = submit(&mut log, &Submission::Audit(event(Kind::Decision)));
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
