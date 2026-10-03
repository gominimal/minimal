//! The daemon's local decision log (NET-046).
//!
//! Every dynamic ingress decision the un-enrolled host makes — the request a
//! process inside the box sends with its own `min net expose` — lands here as
//! one line, whichever way it went: allowed and published, denied by the
//! box's own declaration, asked of the attached human and answered either
//! way (NET-045), or failed closed because nobody was attached to answer.
//! The log is append-only and lives under the daemon's state directory, so
//! it outlives the session the decision was about and reads without one;
//! the diagnostic bundle ships its tail through [`crate::diag`]'s audit
//! collector, at the same [`LOG_RELATIVE`] path it holds here.
//!
//! One record per decision, each naming the box, the port, the decision the
//! box's `dynamic_ingress` setting made, who actually decided it, and the
//! outcome — the facts NET-046's "record each dynamic ingress decision" and
//! a later reader need, and no more. A record is written *after* the
//! decision is made and its effects stand, never before: a line that names
//! a publish the switch refused, or an allow the human denied, is worse
//! than no line at all.

use std::fmt;
use std::path::{Path, PathBuf};

#[cfg(unix)]
use nix::fcntl::{OFlag, open, openat};
#[cfg(unix)]
use nix::sys::stat::Mode;
use serde::Serialize;
use tokio::io::AsyncWriteExt;

/// The log's location under the daemon's state directory, spelled the same
/// relative way in the diagnostic bundle so a reader of one finds the other.
pub(crate) const LOG_RELATIVE: &str = "audit/decisions.log";

/// The audit log's own path under `state_dir`.
pub(crate) fn log_path(state_dir: &Path) -> PathBuf {
    state_dir.join(LOG_RELATIVE)
}

/// Who made the decision a record names — the fact that separates "the box
/// denies this" from "the human on the terminal said no" from "the daemon
/// failed an ask closed with nobody attached to answer".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DecidedBy {
    /// The box's own `dynamic_ingress` declaration: its deny-all default,
    /// its `deny`, or its `allow` with the range gate.
    BoxPolicy,
    /// The attached human, answering the dialog an `ask` decision routed to
    /// them (NET-045) — whichever way they answered.
    AttachedHuman,
    /// The daemon itself, failing an `ask` closed with nobody attached to
    /// answer.
    Daemon,
}

/// Who made the decision, in the kebab-case spelling the record serializes
/// with — the same way the log line names the decider, so a reader of one
/// finds the other without translating.
impl fmt::Display for DecidedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BoxPolicy => write!(f, "box-policy"),
            Self::AttachedHuman => write!(f, "attached-human"),
            Self::Daemon => write!(f, "daemon"),
        }
    }
}

/// What became of the request the decision was about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum DecisionOutcome {
    /// The port was bound on the switch and recorded as a live mapping.
    Published,
    /// The request was refused before the switch was asked anything.
    Refused,
    /// The publish could not be made.
    PublishFailed,
}

/// One dynamic ingress decision, as it is appended to the log (NET-046).
#[derive(Debug, Serialize)]
pub(crate) struct DecisionRecord {
    /// When the decision was made, RFC 3339, UTC.
    pub(crate) ts: String,
    /// The box the request was for — its name, or its id when it has none.
    #[serde(rename = "box")]
    pub(crate) box_name: String,
    /// The port the box asked to publish.
    pub(crate) port: u16,
    /// The decision the box's `dynamic_ingress` setting made for the
    /// request — `deny` (the default an absent declaration means), `allow`,
    /// or `ask`.
    pub(crate) decision: sessions::DynamicIngress,
    /// Who actually decided it — see [`DecidedBy`].
    pub(crate) decided_by: DecidedBy,
    /// What became of the request — see [`DecisionOutcome`].
    pub(crate) outcome: DecisionOutcome,
    /// The refusal's or the publish failure's own reason, when there was
    /// one: the typed error's text, the same string the in-box caller read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
}

/// Appends one decision to the log (NET-046). Best-effort by necessity: the
/// decision is already made and its effects stand, so a record that cannot
/// be written is a warned-about loss, never a refusal of the decision it
/// names — the daemon's own log, which the diagnostic bundle ships beside
/// this file's tail, carries the failure either way.
pub(crate) async fn append(state_dir: &Path, record: &DecisionRecord) {
    let path = log_path(state_dir);
    // Made on every append rather than once at daemon start: the log is the
    // state directory's child, and a daemon asked to audit its first-ever
    // decision on a fresh install should make the directory it was asked to
    // write in, not fail on one it never owned. It resolves a link planted
    // where the directory should be — `create_dir_all` follows it — and so
    // cannot be the guard itself; the open below is, because an open is the
    // one step here that can refuse one.
    if let Some(parent) = path.parent()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        tracing::warn!(
            box = %record.box_name,
            port = record.port,
            error = %e,
            "the dynamic ingress decision could not be audited: the audit \
             directory could not be made"
        );
        return;
    }
    // Serialization of a plain derived struct cannot fail; the guard is for
    // the day the record grows a type that can.
    let Ok(mut line) = serde_json_lenient::to_string(record) else {
        tracing::warn!(
            box = %record.box_name,
            port = record.port,
            "the dynamic ingress decision could not be audited: its record \
             did not serialize"
        );
        return;
    };
    line.push('\n');
    let mut file = match open_log(&path).await {
        Ok(file) => file,
        Err(e) => {
            tracing::warn!(
                box = %record.box_name,
                port = record.port,
                error = %e,
                "the dynamic ingress decision could not be audited"
            );
            return;
        }
    };
    // One append is one line, and the line is flushed before this returns:
    // `tokio::fs::File` buffers into its background pool, and an audit log
    // that could lose its most recent records to a crash on close is not
    // worth the buffer.
    let flushed = async {
        file.write_all(line.as_bytes()).await?;
        file.flush().await
    }
    .await;
    if let Err(e) = flushed {
        tracing::warn!(
            box = %record.box_name,
            port = record.port,
            error = %e,
            "the dynamic ingress decision could not be audited"
        );
    }
}

/// Opens the log for appending, refusing to follow a link at *any* component
/// of the log's own path.
///
/// The state volume is guest-writable on a VM host, so the `audit/` directory
/// is as attacker-controlled as the log file inside it — the same reason
/// `crate::diag`'s audit collector refuses a symlinked file, and this write
/// holds the line that read already does. But a check followed by an open
/// cannot hold it: a guest that swaps `audit/` for a link to a directory
/// elsewhere in the window between the two steers the daemon's append — with
/// the daemon's privileges — through it, into a target of its own choosing,
/// and no `O_NOFOLLOW` on the log's full path would notice, because it guards
/// only the final component. So nothing is checked: the directory itself is
/// opened `O_NOFOLLOW | O_DIRECTORY`, and the log is then opened *relative to
/// that descriptor*, `openat` with `O_NOFOLLOW`. Both components are pinned
/// at the moment they are opened, and there is no window at all; a link
/// standing in either place is refused at open, exactly the way
/// [`diagnostics::open_regular_nofollow`] refuses this same file for reading.
#[cfg(unix)]
async fn open_log(path: &Path) -> std::io::Result<tokio::fs::File> {
    let (dir, file_name) = match (path.parent(), path.file_name()) {
        (Some(dir), Some(file_name)) => (dir, file_name),
        // `LOG_RELATIVE` always names a file inside a directory, so this is
        // a `state_dir` that names no file at all.
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "`{}` does not name a file inside a directory",
                    path.display()
                ),
            ));
        }
    };
    let directory = open(
        dir,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| open_refused("the audit directory", e))?;
    let log = openat(
        &directory,
        file_name,
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_APPEND | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        // The daemon's own log, readable by nobody else: the only reader is
        // the diagnostic collector, in this process.
        Mode::S_IRUSR | Mode::S_IWUSR,
    )
    .map_err(|e| open_refused("the audit log", e))?;
    Ok(tokio::fs::File::from(log))
}

/// Off unix there is no `openat` to open the log through, so it is opened by
/// name; this crate's hosts are Linux, so the guard is unix's to keep.
#[cfg(not(unix))]
async fn open_log(path: &Path) -> std::io::Result<tokio::fs::File> {
    tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
}

/// An open refusal as the warn that reports the loss should carry it: which
/// half of the log's path refused, and the error behind it. `O_NOFOLLOW`
/// refuses a link as `ELOOP` — "too many levels of symbolic links" — which
/// names the link well enough once the half that refused is named beside it.
#[cfg(unix)]
fn open_refused(what: &'static str, error: nix::Error) -> std::io::Error {
    let error = std::io::Error::from(error);
    std::io::Error::new(error.kind(), format!("{what} could not be opened: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NET-046: one decision is one line under the state directory, and the
    /// line is data a reader parses rather than prose it guesses at — the
    /// box, the port, the decision the box's setting made, who decided it,
    /// and the outcome, with the reason present exactly when there was one.
    #[tokio::test]
    async fn append_writes_one_parseable_line_per_decision() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path();

        append(
            state_dir,
            &DecisionRecord {
                ts: chrono::Utc::now().to_rfc3339(),
                box_name: "web".to_string(),
                port: 3000,
                decision: sessions::DynamicIngress::Allow,
                decided_by: DecidedBy::BoxPolicy,
                outcome: DecisionOutcome::Published,
                reason: None,
            },
        )
        .await;
        append(
            state_dir,
            &DecisionRecord {
                ts: chrono::Utc::now().to_rfc3339(),
                box_name: "web".to_string(),
                port: 8080,
                decision: sessions::DynamicIngress::Ask,
                decided_by: DecidedBy::AttachedHuman,
                outcome: DecisionOutcome::Refused,
                reason: Some("dynamic ingress is denied for this box".to_string()),
            },
        )
        .await;

        let logged = std::fs::read_to_string(log_path(state_dir)).unwrap();
        let lines: Vec<&str> = logged.lines().collect();
        assert_eq!(lines.len(), 2, "one line per decision: {logged}");
        let allowed: serde_json_lenient::Value = serde_json_lenient::from_str(lines[0]).unwrap();
        assert_eq!(
            allowed["box"], "web",
            "the record names the box it decided for: {allowed}"
        );
        assert_eq!(allowed["port"], 3000);
        assert_eq!(allowed["decision"], "allow");
        assert_eq!(allowed["decided_by"], "box-policy");
        assert_eq!(allowed["outcome"], "published");
        assert!(
            allowed.get("reason").is_none(),
            "a record with nothing to say carries no empty reason: {allowed}"
        );
        let refused: serde_json_lenient::Value = serde_json_lenient::from_str(lines[1]).unwrap();
        assert_eq!(refused["box"], "web");
        assert_eq!(refused["port"], 8080);
        assert_eq!(refused["decision"], "ask");
        assert_eq!(refused["decided_by"], "attached-human");
        assert_eq!(refused["outcome"], "refused");
        assert_eq!(
            refused["reason"], "dynamic ingress is denied for this box",
            "the refusal carries the typed error the caller read: {refused}"
        );
    }

    /// The write side of the symlink guard the read side already had (the
    /// review threads on `append`): the state volume is guest-writable on a
    /// VM host, so a planted link — `decisions.log` itself, or the whole
    /// `audit/` directory — must not steer the daemon's appends into a target
    /// of someone else's choosing. What a test can see is the link that stands
    /// there when the append begins; the one that would be swapped in
    /// mid-append is closed by construction instead, the open anchored to the
    /// directory it opened and never re-resolving the path — which is why
    /// there is no third case here. Each planted case is refused, the warn
    /// line names which half of the log's own path refused, and the target the
    /// link named is untouched.
    #[tokio::test]
    async fn audit_append_refuses_a_symlinked_log() {
        let capture = crate::test_harness::captured_log();
        let record = DecisionRecord {
            ts: chrono::Utc::now().to_rfc3339(),
            box_name: "web".to_string(),
            port: 3000,
            decision: sessions::DynamicIngress::Ask,
            decided_by: DecidedBy::BoxPolicy,
            outcome: DecisionOutcome::Refused,
            reason: None,
        };

        // The file itself: `audit/decisions.log` is a symlink to a file
        // elsewhere that carries content of its own.
        {
            let dir = tempfile::tempdir().unwrap();
            let state_dir = dir.path();
            std::fs::create_dir_all(state_dir.join("audit")).unwrap();
            let planted = dir.path().join("planted.log");
            std::fs::write(&planted, "planted\n").unwrap();
            std::os::unix::fs::symlink(&planted, log_path(state_dir)).unwrap();

            append(state_dir, &record).await;

            assert_eq!(
                std::fs::read_to_string(&planted).unwrap(),
                "planted\n",
                "a symlinked log must leave its target untouched"
            );
            assert!(
                std::fs::symlink_metadata(log_path(state_dir))
                    .expect("the log path still stands")
                    .file_type()
                    .is_symlink(),
                "the refused append must not replace the symlink with a log"
            );
            let log = capture.contents();
            assert!(
                log.contains("the audit log could not be opened"),
                "the refusal names the half of the path that refused: {log}"
            );
            assert!(
                log.contains("the dynamic ingress decision could not be audited"),
                "the symlinked file is a warned-about loss, not a silent one: {log}"
            );
        }

        // The directory: `audit/` itself is a symlink to a directory
        // elsewhere, which `create_dir_all` follows and so cannot catch.
        {
            let dir = tempfile::tempdir().unwrap();
            let state_dir = dir.path();
            let planted_dir = dir.path().join("planted");
            std::fs::create_dir_all(&planted_dir).unwrap();
            std::os::unix::fs::symlink(&planted_dir, state_dir.join("audit")).unwrap();

            append(state_dir, &record).await;

            assert!(
                !planted_dir.join("decisions.log").exists(),
                "a symlinked audit directory must leave its target untouched"
            );
            let log = capture.contents();
            assert!(
                log.contains("the audit directory could not be opened"),
                "the refusal names the half of the path that refused: {log}"
            );
            assert!(
                log.contains("the dynamic ingress decision could not be audited"),
                "the symlinked directory is a warned-about loss, not a silent one: {log}"
            );
        }
    }
}
