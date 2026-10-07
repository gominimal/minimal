//! The daemon's local decision log (NET-046).
//!
//! Every dynamic ingress decision the un-enrolled host makes — the request a
//! process inside the box sends with its own `min net expose` — lands here as
//! one line, whichever way it went: allowed and published, denied by the
//! box's own declaration, asked of the attached human and answered either
//! way (NET-045), or failed closed because nobody was attached to answer.
//! The log is append-only and lives under the daemon's state directory, so
//! it outlives the session the decision was about and reads without one. It
//! is bounded: past [`MAX_LOG_BYTES`] it rotates to one kept generation
//! ([`ROTATED_RELATIVE`]), so a box asking for ports in a loop cannot fill
//! the state volume with it;
//! the diagnostic bundle ships the tail of both files through
//! [`crate::diag`]'s audit collector, at the same paths they hold here.
//! An allow whose record cannot be written is refused (fail closed); a
//! refusal whose record cannot be written still refuses.
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
use nix::fcntl::{OFlag, open, openat, renameat};
#[cfg(unix)]
use nix::sys::stat::Mode;
use serde::Serialize;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

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

/// The size the live log may reach before it rotates: the append that would
/// carry it past this renames it to [`ROTATED_RELATIVE`] first, replacing
/// the generation rotated before it, and starts a fresh one. One rotated
/// generation is kept, so the log never holds more than twice this on disk,
/// and the newest records are always in the live file.
pub(crate) const MAX_LOG_BYTES: u64 = 1024 * 1024;

/// The one rotated generation's location under the daemon's state
/// directory, spelled the same relative way in the diagnostic bundle.
pub(crate) const ROTATED_RELATIVE: &str = "audit/decisions.log.1";

/// The append lock: one per daemon, held across the whole append — the
/// open, the rotation decision, the rename, the reopen, and the write.
///
/// The log is one file under the daemon's shared state directory, written
/// by whichever session actor runs [`try_append`] at the time, and each
/// actor is its own spawned task, so two sessions can decide a rotation on
/// the same live file together. Nothing below would stop them: the size
/// read and the rename are two steps, and the second `renameat` would move
/// the fresh log the first session just created onto `.1`, taking with it
/// the entire generation the first rotation kept — the very history
/// NET-046 says must be preserved. Holding one lock across the append
/// makes the decision and the moves one step; a `tokio::sync::Mutex`
/// because the steps it serializes await.
static APPEND: Mutex<()> = Mutex::const_new(());

/// The rotated generation's own path under `state_dir`.
pub(crate) fn rotated_path(state_dir: &Path) -> PathBuf {
    state_dir.join(ROTATED_RELATIVE)
}

/// Appends one decision to the log (NET-046), best-effort: a record that
/// cannot be written is a warned-about loss, never a change to the decision
/// it names. That is right for a decision whose effect is a refusal —
/// undoing a refusal because it went unrecorded would open the port — and
/// for nothing else: an allow is recorded through [`try_append`], whose
/// failure the caller fails closed on. The daemon's own log, which the
/// diagnostic bundle ships beside this file's tail, carries the failure
/// either way.
pub(crate) async fn append(state_dir: &Path, record: &DecisionRecord) {
    if let Err(e) = try_append(state_dir, record).await {
        tracing::warn!(
            box = %record.box_name,
            port = record.port,
            error = %e,
            "the dynamic ingress decision could not be audited"
        );
    }
}

/// Appends one decision to the log (NET-046), rotating it first when the
/// line would carry it past [`MAX_LOG_BYTES`], and says whether the record
/// landed: the caller of an allow refuses the exposure on an `Err`, because
/// NET-046 requires every decision recorded and an allow is the one decision
/// that can still be taken back.
pub(crate) async fn try_append(state_dir: &Path, record: &DecisionRecord) -> std::io::Result<()> {
    try_append_capped(state_dir, record, MAX_LOG_BYTES).await
}

/// [`try_append`] with the rotation threshold passed in, so a test can rotate
/// the log without writing a mebibyte of records.
pub(crate) async fn try_append_capped(
    state_dir: &Path,
    record: &DecisionRecord,
    cap: u64,
) -> std::io::Result<()> {
    // One append at a time, across every session's actor: the rotation the
    // append may run is an open→stat→rename→reopen sequence on the one log
    // they share, so two of them crossing the cap together would race (see
    // [`APPEND`]). Held until the line is flushed, so no append starts its
    // size read against a file another is mid-rotation on.
    let _append = APPEND.lock().await;
    let path = log_path(state_dir);
    // Made on every append rather than once at daemon start: the log is the
    // state directory's child, and a daemon asked to audit its first-ever
    // decision on a fresh install should make the directory it was asked to
    // write in, not fail on one it never owned. It resolves a link planted
    // where the directory should be — `create_dir_all` follows it — and so
    // cannot be the guard itself; the open below is, because an open is the
    // one step here that can refuse one.
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await.map_err(|e| {
            std::io::Error::new(
                e.kind(),
                format!("the audit directory could not be made: {e}"),
            )
        })?;
    }
    // Serialization of a plain derived struct cannot fail; the guard is for
    // the day the record grows a type that can.
    let mut line = serde_json_lenient::to_string(record).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("the record did not serialize: {e}"),
        )
    })?;
    line.push('\n');
    let mut file = open_log(&path, line.len() as u64, cap).await?;
    // One append is one line, and the line is flushed before this returns:
    // `tokio::fs::File` buffers into its background pool, and an audit log
    // that could lose its most recent records to a crash on close is not
    // worth the buffer.
    file.write_all(line.as_bytes()).await?;
    let flushed = file.flush().await;
    drop(_append);
    flushed
}

/// Whether a log already holding `len` bytes rotates before an `incoming`
/// line lands: only when the line would carry it past `cap`, and never when
/// it is empty, so a single line longer than the cap goes into a fresh file
/// rather than rotating on every append.
fn rotates(len: u64, incoming: u64, cap: u64) -> bool {
    len > 0 && len.saturating_add(incoming) > cap
}

/// The rotated generation's file name beside the live log's.
fn rotated_name(file_name: &std::ffi::OsStr) -> std::ffi::OsString {
    let mut rotated = file_name.to_os_string();
    rotated.push(".1");
    rotated
}

/// Opens the log for appending, refusing to follow a link at *any* component
/// of the log's own path, and rotates it first when an `incoming` line would
/// carry it past `cap`.
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
///
/// The rotation runs through the same pinned directory: `renameat` moves a
/// name, never what a link at it points to, so a link planted at either name
/// is moved or replaced rather than followed, and the fresh log is opened
/// under the same `O_NOFOLLOW` guard as the first.
#[cfg(unix)]
async fn open_log(path: &Path, incoming: u64, cap: u64) -> std::io::Result<tokio::fs::File> {
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
    let open_at = || {
        openat(
            &directory,
            file_name,
            OFlag::O_WRONLY
                | OFlag::O_CREAT
                | OFlag::O_APPEND
                | OFlag::O_NOFOLLOW
                | OFlag::O_CLOEXEC,
            // The daemon's own log, readable by nobody else: the only reader
            // is the diagnostic collector, in this process.
            Mode::S_IRUSR | Mode::S_IWUSR,
        )
        .map(std::fs::File::from)
        .map_err(|e| open_refused("the audit log", e))
    };
    let mut log = open_at()?;
    if rotates(log.metadata()?.len(), incoming, cap) {
        renameat(
            &directory,
            file_name,
            &directory,
            rotated_name(file_name).as_os_str(),
        )
        .map_err(|e| {
            let error = std::io::Error::from(e);
            std::io::Error::new(
                error.kind(),
                format!("the audit log could not be rotated: {error}"),
            )
        })?;
        log = open_at()?;
    }
    Ok(tokio::fs::File::from_std(log))
}

/// Off unix there is no `openat` to open the log through, so it is opened by
/// name; this crate's hosts are Linux, so the guard is unix's to keep.
#[cfg(not(unix))]
async fn open_log(path: &Path, incoming: u64, cap: u64) -> std::io::Result<tokio::fs::File> {
    let len = match tokio::fs::metadata(path).await {
        Ok(meta) => meta.len(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => return Err(e),
    };
    if rotates(len, incoming, cap)
        && let Some(file_name) = path.file_name()
    {
        tokio::fs::rename(path, path.with_file_name(rotated_name(file_name))).await?;
    }
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

    /// The record the rotation tests write, one per port.
    fn record_for(port: u16) -> DecisionRecord {
        DecisionRecord {
            ts: chrono::Utc::now().to_rfc3339(),
            box_name: "web".to_string(),
            port,
            decision: sessions::DynamicIngress::Allow,
            decided_by: DecidedBy::BoxPolicy,
            outcome: DecisionOutcome::Published,
            reason: None,
        }
    }

    /// The ports a log file's records name, in the order they were written.
    fn ports_in(path: &Path) -> Vec<u64> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let record: serde_json_lenient::Value =
                    serde_json_lenient::from_str(line).expect("one line is one record");
                record["port"].as_u64().expect("every record names a port")
            })
            .collect()
    }

    /// The log stays within its bound however many decisions land: past the
    /// cap it rotates to one kept generation, so neither file grows past the
    /// cap, the newest record is always the live file's last line, and the
    /// two files together hold an unbroken run of the newest records, with
    /// only the oldest dropped.
    #[tokio::test]
    async fn the_log_rotates_within_its_bound_and_keeps_the_newest_records() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path();
        let line_len = serde_json_lenient::to_string(&record_for(1000))
            .unwrap()
            .len() as u64
            + 1;
        // Room for a handful of records per file, so a hundred appends
        // rotate many times over.
        let cap = line_len * 5;

        for port in 1000..1100 {
            try_append_capped(state_dir, &record_for(port), cap)
                .await
                .expect("an append to a healthy log lands");
            let live = std::fs::metadata(log_path(state_dir)).unwrap().len();
            assert!(
                live <= cap,
                "the live log stays within its cap: {live} > {cap}"
            );
            if let Ok(rotated) = std::fs::metadata(rotated_path(state_dir)) {
                assert!(
                    rotated.len() <= cap,
                    "the rotated generation stays within its cap: {} > {cap}",
                    rotated.len()
                );
            }
        }
        assert!(
            !state_dir.join("audit/decisions.log.2").exists(),
            "one rotated generation is kept, never more"
        );

        let rotated = ports_in(&rotated_path(state_dir));
        let live = ports_in(&log_path(state_dir));
        assert_eq!(
            live.last(),
            Some(&1099),
            "the newest record is the live log's last line"
        );
        let kept: Vec<u64> = rotated.into_iter().chain(live).collect();
        let first = *kept.first().expect("rotation keeps records");
        assert_eq!(
            kept,
            (first..1100).collect::<Vec<u64>>(),
            "the two files hold an unbroken run of the newest records"
        );
        assert!(
            kept.len() >= 5,
            "a rotation keeps at least a full generation: {kept:?}"
        );
    }

    /// The fail-closed caller's half of the symlink guard: `try_append`
    /// reports a refused open as an error rather than swallowing it, so an
    /// allow decided behind a planted link is never answered as recorded.
    #[tokio::test]
    async fn try_append_reports_a_refused_log() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path();
        let planted_dir = dir.path().join("planted");
        std::fs::create_dir_all(&planted_dir).unwrap();
        std::os::unix::fs::symlink(&planted_dir, state_dir.join("audit")).unwrap();

        let error = try_append(state_dir, &record_for(3000))
            .await
            .expect_err("a symlinked audit directory refuses the append");
        assert!(
            error
                .to_string()
                .contains("the audit directory could not be opened"),
            "the error names the half of the path that refused: {error}"
        );
        assert!(
            !planted_dir.join("decisions.log").exists(),
            "the refused append leaves the link's target untouched"
        );
    }

    /// [`record_for`] with the timestamp a rotation test can order by: a
    /// fixed-width sequence number rather than a clock, so the records two
    /// tasks append interleaved still read in the order they were written —
    /// the order a raced rotation would delete from the middle of.
    fn sequenced_record(port: u16, sequence: u64) -> DecisionRecord {
        DecisionRecord {
            ts: format!("{sequence:012}"),
            box_name: "web".to_string(),
            port,
            decision: sessions::DynamicIngress::Allow,
            decided_by: DecidedBy::BoxPolicy,
            outcome: DecisionOutcome::Published,
            reason: None,
        }
    }

    /// The sequence numbers a log file's records name, in file order.
    fn sequences_in(path: &Path) -> Vec<u64> {
        std::fs::read_to_string(path)
            .unwrap_or_default()
            .lines()
            .map(|line| {
                let record: serde_json_lenient::Value =
                    serde_json_lenient::from_str(line).expect("one line is one record");
                record["ts"]
                    .as_str()
                    .expect("every record names its timestamp")
                    .parse()
                    .expect("the test's timestamps are sequence numbers")
            })
            .collect()
    }

    /// The rotation is the one multi-step thing the log does, and the log is
    /// shared: every session's actor appends to the same file, and each is
    /// its own spawned task, so two of them can reach a rotation together.
    /// Unserialized, both would pass `rotates` against the same live file,
    /// and the second rename would carry away the fresh log the first just
    /// created — deleting the generation the first rotation kept. With the
    /// append held under one lock, the records both files hold are the
    /// newest ones in an unbroken write-order run: the files follow each
    /// other in the order their records were written, nothing is held
    /// twice, and the live file's last line is the very newest record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_appends_rotating_together_lose_no_records() {
        let dir = tempfile::tempdir().unwrap();
        let state_dir = dir.path().join("daemon");
        std::fs::create_dir_all(&state_dir).unwrap();
        // The sequence's fixed width keeps every line the same length, so a
        // cap of a few lines is a cap the concurrent appends keep crossing.
        let line_len = serde_json_lenient::to_string(&sequenced_record(1000, 0))
            .unwrap()
            .len() as u64
            + 1;
        let cap = line_len * 3;
        let per_task = 200u64;
        let tasks = 2u64;
        let written = tasks * per_task;
        let sequence = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));

        let mut spawned = Vec::new();
        for _ in 0..tasks {
            let state_dir = state_dir.clone();
            let sequence = sequence.clone();
            spawned.push(tokio::spawn(async move {
                for _ in 0..per_task {
                    let next = sequence.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    try_append_capped(&state_dir, &sequenced_record(next as u16, next), cap)
                        .await
                        .expect("an append to a healthy log lands");
                }
            }));
        }
        for task in spawned {
            task.await.expect("the appending task finishes");
        }

        let rotated = sequences_in(&rotated_path(&state_dir));
        let live = sequences_in(&log_path(&state_dir));
        let kept: Vec<u64> = rotated.into_iter().chain(live).collect();
        assert_eq!(
            kept,
            (written - kept.len() as u64..written).collect::<Vec<u64>>(),
            "the two files hold an unbroken run of the newest records, each once"
        );
        assert_eq!(
            kept.last(),
            Some(&(written - 1)),
            "the newest record is the live log's last line"
        );
        assert!(
            !state_dir.join("audit/decisions.log.2").exists(),
            "one rotated generation is kept, never more"
        );
        for (what, len) in [
            (
                "the live log",
                std::fs::metadata(log_path(&state_dir)).unwrap().len(),
            ),
            (
                "the rotated generation",
                std::fs::metadata(rotated_path(&state_dir)).unwrap().len(),
            ),
        ] {
            assert!(len <= cap, "{what} stays within its cap: {len} > {cap}");
        }
    }
}
