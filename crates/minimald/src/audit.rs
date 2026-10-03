//! The local audit log for dynamic ingress decisions (NET-046).
//!
//! One JSON line per decision, appended to `<minimal_state_dir>/audit/ingress.log`:
//! when it was made, the box it concerns, the port, the box's `dynamic_ingress`
//! setting, who made the decision, and how it ended. A refused request is
//! recorded with its refusal's reason, a published one with the local address
//! the port went live on — so the log reads as the answer to "who let this
//! port out", which neither the daemon log (one line per request, but rolling)
//! nor the policy list (the live ports only) can give.
//!
//! The log is written wherever the host is un-enrolled, on purpose: with no
//! enrolled network keeping its own record of what was admitted, this file is
//! the record. It is a side channel, not part of the publish — a decision
//! that cannot be recorded still stands, and the publish it concerns was
//! already decided on policy. Callers warn and continue on a write failure
//! rather than failing the request over evidence-gathering (see
//! [`Session::expose_dynamic`](crate::session::Session::expose_dynamic)).

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;
use tokio::io::AsyncWriteExt;

/// The directory this log lives in, under the daemon's state dir.
const AUDIT_DIR: &str = "audit";
/// The file the decisions are appended to.
const INGRESS_LOG: &str = "ingress.log";

/// Serializes every append through one lock, so two session actors deciding
/// ports at the same time leave two whole lines rather than one interleaved
/// one. Daemon-wide because the state dir is: one daemon, one log.
static APPEND_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Who made the decision the record describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DecidedBy {
    /// The box's own `dynamic_ingress` setting: allowed, denied, or `ask`
    /// failing closed with nobody attached to answer.
    Policy,
    /// The attached human an `ask` was put to (NET-045).
    Human,
    /// Nobody: the `ask` arrived while no client was attached, so there was
    /// nobody to put it to. The refusal this leaves is recorded as such, not
    /// as a policy decision — the setting said ask, and nobody answered.
    Nobody,
}

/// How the decided request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum IngressOutcome {
    /// The port was published and is live.
    Published,
    /// The request was refused.
    Refused,
    /// The decision allowed the request but the publish itself failed.
    PublishFailed,
}

/// One dynamic ingress decision, as it enters the audit log. The timestamp is
/// stamped by [`append`], so every record carries the same clock spelling and
/// the caller builds only the facts.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct IngressDecision {
    /// The box the request came from — its name, or its id when unnamed.
    #[serde(rename = "box")]
    pub box_name: String,
    pub port: u16,
    /// The box's `dynamic_ingress` setting the request was decided under.
    pub decision: sessions::DynamicIngress,
    pub decided_by: DecidedBy,
    pub outcome: IngressOutcome,
    /// The refusal's or the failure's reason, when the request did not
    /// publish.
    pub reason: Option<String>,
    /// The local address the port was published at, when it was.
    pub published_at: Option<String>,
}

/// The audit log's path under `state_dir`. Shared by [`append`] and the diag
/// bundle's collector, so the file a diagnosis ships is the file a decision
/// landed in.
pub(crate) fn audit_log_path(state_dir: &Path) -> PathBuf {
    state_dir.join(AUDIT_DIR).join(INGRESS_LOG)
}

/// One line in the log, stamped at append time so the record's field order is
/// fixed where it is written: when, then who and what, then how it ended.
#[derive(Serialize)]
struct StampedLine<'a> {
    ts: String,
    #[serde(flatten)]
    decision: &'a IngressDecision,
}

/// Appends `decision` to the audit log under `state_dir`, creating the audit
/// directory on demand. `Err` means the record could not be written; the
/// decision it describes has already been made and acted on, so the caller
/// warns and moves on rather than undoing anything over it.
pub(crate) async fn append(state_dir: &Path, decision: IngressDecision) -> io::Result<()> {
    let path = audit_log_path(state_dir);
    // Recorded as one line before it is opened: a serialization failure must
    // not create the audit directory or leave a half-written line behind.
    let mut line = serde_json_lenient::to_vec(&StampedLine {
        ts: chrono::Utc::now().to_rfc3339(),
        decision: &decision,
    })
    .map_err(io::Error::other)?;
    line.push(b'\n');

    let _guard = APPEND_LOCK.lock().await;
    tokio::fs::create_dir_all(path.parent().expect("the audit log has a parent dir")).await?;
    let mut log = tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await?;
    log.write_all(&line).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The log lands under the state dir with the documented name, so the
    /// diag collector and this module can never point at two files.
    #[test]
    fn the_log_lives_in_the_state_dirs_audit_directory() {
        let path = audit_log_path(Path::new("/var/lib/minimal"));
        assert_eq!(path, PathBuf::from("/var/lib/minimal/audit/ingress.log"));
    }

    /// A decision lands as one JSON line whose fields spell the facts: the
    /// box, the port, the setting, who decided, and how it ended.
    #[tokio::test]
    async fn a_decision_lands_as_one_json_line() {
        let state_dir = tempfile::tempdir().unwrap();
        append(
            state_dir.path(),
            IngressDecision {
                box_name: "web".to_string(),
                port: 3000,
                decision: sessions::DynamicIngress::Ask,
                decided_by: DecidedBy::Human,
                outcome: IngressOutcome::Published,
                reason: None,
                published_at: Some("10.0.2.15:3000".to_string()),
            },
        )
        .await
        .unwrap();

        let log = tokio::fs::read_to_string(audit_log_path(state_dir.path()))
            .await
            .unwrap();
        assert_eq!(log.lines().count(), 1, "one line per record: {log}");
        let record: serde_json_lenient::Value =
            serde_json_lenient::from_str(log.trim()).expect("the line is one JSON object");
        assert!(record["ts"].as_str().is_some(), "stamped by append");
        assert_eq!(record["box"], "web");
        assert_eq!(record["port"], 3000);
        assert_eq!(record["decision"], "ask");
        assert_eq!(record["decided_by"], "human");
        assert_eq!(record["outcome"], "published");
        assert_eq!(record["published_at"], "10.0.2.15:3000");
        assert!(
            record.get("reason").is_some(),
            "absent fields are explicit nulls"
        );
    }

    /// The log is append-only: a second decision adds a line and leaves the
    /// first untouched, and a refusal is recorded with its reason spelled.
    #[tokio::test]
    async fn the_log_appends_without_touching_earlier_records() {
        let state_dir = tempfile::tempdir().unwrap();
        let decision = |port, outcome, reason| IngressDecision {
            box_name: "web".to_string(),
            port,
            decision: sessions::DynamicIngress::Ask,
            decided_by: DecidedBy::Nobody,
            outcome,
            reason,
            published_at: None,
        };
        append(
            state_dir.path(),
            decision(
                3000,
                IngressOutcome::Refused,
                Some("nobody is attached to answer".to_string()),
            ),
        )
        .await
        .unwrap();
        append(
            state_dir.path(),
            decision(
                3001,
                IngressOutcome::PublishFailed,
                Some("the switch refused".to_string()),
            ),
        )
        .await
        .unwrap();

        let log = tokio::fs::read_to_string(audit_log_path(state_dir.path()))
            .await
            .unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "one line per record: {log}");
        assert!(
            lines[0].contains(r#""port":3000"#) && lines[0].contains(r#""refused""#),
            "the first record is untouched: {}",
            lines[0]
        );
        let first: serde_json_lenient::Value = serde_json_lenient::from_str(lines[0]).unwrap();
        assert_eq!(first["decided_by"], "nobody");
        assert_eq!(first["reason"], "nobody is attached to answer");
        let second: serde_json_lenient::Value = serde_json_lenient::from_str(lines[1]).unwrap();
        assert_eq!(second["outcome"], "publish_failed");
    }
}
