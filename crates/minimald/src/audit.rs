//! The daemon's local audit log: one line per decision it made on its own
//! authority (NET-046).
//!
//! An un-enrolled host has no control plane to report to, so a decision it
//! takes locally — today, every `min net expose` request it decides against a
//! box's `dynamic_ingress` setting — leaves no trace anywhere else. It is
//! written here instead: an append-only JSON-lines file under the daemon's
//! state dir ([`log_path`]), one object per decision, naming the box, the port,
//! the setting the request was decided against, what became of it, and who
//! decided. `min bug` carries the tail of this file, so a port that turned out
//! to be open can be traced back to the request that opened it and the human
//! who allowed it.
//!
//! Writing a decision down never decides anything: an append that fails is
//! logged and dropped ([`record`]), because a request the human has already
//! answered stands whether or not the daemon could record it.

use std::path::{Path, PathBuf};

use serde::Serialize;
use sessions::{IpProto, SessionId};
use tokio::io::AsyncWriteExt as _;

/// Where the audit log lives under the daemon's state dir.
#[must_use]
pub fn log_path(state_dir: &Path) -> PathBuf {
    state_dir.join("audit").join("decisions.jsonl")
}

/// Who settled a dynamic ingress request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DecidedBy {
    /// The box's own `dynamic_ingress` setting settled it, with nobody asked.
    Policy,
    /// The box's setting is `ask` and the human attached to it answered.
    AttachedHuman,
    /// The box's setting is `ask` and nobody was attached to answer.
    NoOneAttached,
    /// The box's setting is `ask`, a prompt went to the attached terminal, and
    /// no answer came back — the deadline passed, or the client left with the
    /// prompt still up.
    Unanswered,
}

/// What became of a decided request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    /// The port is published.
    Published,
    /// The request was refused, and `reason` says which refusal.
    Refused,
    /// The request was permitted and could not be carried out — the record
    /// would not take the mapping — so nothing of it is published.
    Failed,
}

/// One decided dynamic ingress request, as the audit log records it.
#[derive(Debug, Clone, Serialize)]
pub struct IngressDecision {
    /// The box the request was about.
    pub session_id: SessionId,
    /// The box's name, as the zone publishes it.
    pub box_name: String,
    /// The port asked for.
    pub port: u16,
    /// The transport asked for.
    pub proto: IpProto,
    /// The box's `dynamic_ingress` setting the request was decided against:
    /// `allow`, `ask`, `deny`, or `unset`.
    pub setting: String,
    pub outcome: Outcome,
    pub decided_by: DecidedBy,
    /// The typed refusal, or the failure, in the words the client was given.
    /// `None` on a publication.
    pub reason: Option<String>,
}

/// One line of the log: the decision, stamped with when it was taken.
#[derive(Debug, Serialize)]
struct Entry<'a> {
    /// RFC 3339, in UTC.
    at: String,
    #[serde(flatten)]
    decision: &'a IngressDecision,
}

/// Appends `decision` to the audit log at `path`, creating the directory and
/// the file on first use.
///
/// Best-effort on purpose: the decision has already been taken and acted on by
/// the time this runs, so a log the daemon cannot write is a warning, not a
/// failure of the request.
pub async fn record(path: &Path, decision: &IngressDecision) {
    if let Err(error) = append(path, decision).await {
        tracing::warn!(
            %error,
            path = %path.display(),
            "could not record a decision in the local audit log",
        );
    }
}

async fn append(path: &Path, decision: &IngressDecision) -> Result<(), std::io::Error> {
    if let Some(dir) = path.parent() {
        tokio::fs::create_dir_all(dir).await?;
    }
    let entry = Entry {
        at: chrono::Utc::now().to_rfc3339(),
        decision,
    };
    // One `write_all` of one line: a reader tailing the file (the diagnostic
    // bundle) never sees half a record, and two decisions cannot interleave.
    let mut line = serde_json_lenient::to_vec(&entry).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut file = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await?;
    file.write_all(&line).await?;
    file.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision() -> IngressDecision {
        IngressDecision {
            session_id: SessionId::nil(),
            box_name: "web".to_string(),
            port: 8080,
            proto: IpProto::Tcp,
            setting: "ask".to_string(),
            outcome: Outcome::Published,
            decided_by: DecidedBy::AttachedHuman,
            reason: None,
        }
    }

    /// Each decision is one line, appended after the last, and every field a
    /// reader needs is in it — including when it was taken, which the caller
    /// never supplies.
    #[tokio::test]
    async fn every_decision_is_one_appended_line() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = log_path(dir.path());

        record(&path, &decision()).await;
        let mut second = decision();
        second.port = 9090;
        second.outcome = Outcome::Refused;
        second.decided_by = DecidedBy::NoOneAttached;
        second.reason = Some("nobody is attached to answer".to_string());
        record(&path, &second).await;

        let text = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 2, "one line per decision: {text}");
        let first: serde_json_lenient::Value = serde_json_lenient::from_str(lines[0]).unwrap();
        assert_eq!(first["box_name"], "web");
        assert_eq!(first["port"], 8080);
        assert_eq!(first["setting"], "ask");
        assert_eq!(first["outcome"], "published");
        assert_eq!(first["decided_by"], "attached-human");
        assert!(
            chrono::DateTime::parse_from_rfc3339(first["at"].as_str().unwrap()).is_ok(),
            "the record stamps when it was taken: {first}"
        );
        let second: serde_json_lenient::Value = serde_json_lenient::from_str(lines[1]).unwrap();
        assert_eq!(second["port"], 9090);
        assert_eq!(second["outcome"], "refused");
        assert_eq!(second["decided_by"], "no-one-attached");
        assert_eq!(second["reason"], "nobody is attached to answer");
    }
}
