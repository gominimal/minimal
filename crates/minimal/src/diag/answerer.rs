//! The answerer service (`minzoned`) on this host, for the `min bug` bundle.
//!
//! A host whose answerer service will not start (launchd's
//! `dev.gominimal.zone` exiting 1, a failed `minzoned.service`) leaves no
//! trace in the rest of the bundle. This collector records what a reader
//! needs to tell a stale or mismatched copy from a broken one:
//!
//! - `host/answerer.json`: `minzoned --version` and the SHA-256 of the
//!   installed copy and of the copy this `min` ships beside it.
//! - `host/answerer-service.txt`: `launchctl print` on macOS,
//!   `systemctl status` elsewhere.
//! - `host/answerer-journal.txt` (not macOS): the service's journal over
//!   the [`JOURNAL_WINDOW`] before the bundle's creation time.
//! - `host/answerer.log` (macOS): the tail of the log the launchd unit
//!   sends the service's output to (`resolver::MACOS_ANSWERER_LOG_PATH`).
//!
//! Each part that cannot be read is recorded as a skip that says why.
//! [`AnswererSources`] names every path and command the collector reads,
//! so a test can point it at fixtures.

use std::fmt::Write as _;
use std::path::Path;
use std::time::Duration;

use diagnostics::{BundleWriter, Capture, CaptureError, Redaction};
use serde::Serialize;

use crate::resolver;

/// The bound on each command this collector runs. Well inside the
/// collector step's own deadline, so one wedged command still leaves time
/// for the others.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// How far before the bundle's creation time the service's journal is
/// read: the window a report of a service that will not start is about.
#[cfg(not(target_os = "macos"))]
const JOURNAL_WINDOW: chrono::TimeDelta = chrono::TimeDelta::hours(24);

/// The most journal lines kept, newest first, so a service that restarts in
/// a loop cannot fill the bundle.
#[cfg(not(target_os = "macos"))]
const JOURNAL_LINES_MAX: &str = "1000";

/// The bundle entry of the service's macOS log.
pub const LOG_ENTRY: &str = "host/answerer.log";

/// One command the collector runs, as a program and its arguments.
#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub program: String,
    pub args: Vec<String>,
}

impl CommandSpec {
    fn new(program: &str, args: &[&str]) -> Self {
        Self {
            program: program.to_string(),
            args: args.iter().map(|arg| (*arg).to_string()).collect(),
        }
    }
}

/// The service's log file and the unit that names it.
#[derive(Debug, Clone)]
pub struct LogSource {
    /// The log file.
    pub path: String,
    /// The unit file whose `StandardErrorPath` names the log. Read only to
    /// say why the log is absent.
    pub unit: String,
}

/// Everything the collector reads, so a test can give fixtures.
#[derive(Debug, Clone)]
pub struct AnswererSources {
    /// The root-owned copy the service runs.
    pub installed: Option<String>,
    /// The copy beside this `min` or on `PATH`. `None` when there is none.
    pub shipped: Option<String>,
    /// The command that prints the service manager's view of the service.
    pub service: CommandSpec,
    /// The command that prints the service's journal, where the host has
    /// one.
    pub journal: Option<CommandSpec>,
    /// The service's log file, where the host's unit writes one.
    pub log: Option<LogSource>,
}

/// The sources on this host, for a bundle created at `created_at`.
pub fn host_sources(created_at: chrono::DateTime<chrono::Utc>) -> AnswererSources {
    AnswererSources {
        installed: Some(resolver::ANSWERER_PROGRAM_PATH.to_string()),
        shipped: resolver::answerer_source(),
        service: service_command(),
        journal: journal_command(created_at),
        log: log_source(),
    }
}

#[cfg(target_os = "macos")]
fn service_command() -> CommandSpec {
    let target = format!("system/{}", resolver::ANSWERER_LAUNCHD_LABEL);
    CommandSpec::new("launchctl", &["print", &target])
}

#[cfg(not(target_os = "macos"))]
fn service_command() -> CommandSpec {
    let socket = format!("{}.socket", resolver::ANSWERER_SYSTEMD_UNIT);
    let service = format!("{}.service", resolver::ANSWERER_SYSTEMD_UNIT);
    CommandSpec::new(
        "systemctl",
        &["status", "--no-pager", "--full", &socket, &service],
    )
}

/// `journalctl` over the [`JOURNAL_WINDOW`] that ends at `created_at`.
/// It runs without `-q`, so a user who cannot read the system journal sees
/// journalctl's own note on that in the transcript, not an empty file.
#[cfg(not(target_os = "macos"))]
fn journal_command(created_at: chrono::DateTime<chrono::Utc>) -> Option<CommandSpec> {
    let socket = format!("{}.socket", resolver::ANSWERER_SYSTEMD_UNIT);
    let service = format!("{}.service", resolver::ANSWERER_SYSTEMD_UNIT);
    let since = format!("--since=@{}", (created_at - JOURNAL_WINDOW).timestamp());
    let until = format!("--until=@{}", created_at.timestamp());
    Some(CommandSpec::new(
        "journalctl",
        &[
            "--no-pager",
            "-o",
            "short-iso",
            "-n",
            JOURNAL_LINES_MAX,
            &since,
            &until,
            "-u",
            &socket,
            "-u",
            &service,
        ],
    ))
}

#[cfg(target_os = "macos")]
fn journal_command(_created_at: chrono::DateTime<chrono::Utc>) -> Option<CommandSpec> {
    None
}

#[cfg(target_os = "macos")]
fn log_source() -> Option<LogSource> {
    Some(LogSource {
        path: resolver::MACOS_ANSWERER_LOG_PATH.to_string(),
        unit: resolver::ANSWERER_PLIST_PATH.to_string(),
    })
}

#[cfg(not(target_os = "macos"))]
fn log_source() -> Option<LogSource> {
    None
}

/// One copy of `minzoned`: where it is, what it says its version is, and
/// the SHA-256 of its bytes. A field that could not be read is `None`, and
/// `errors` says why.
#[derive(Debug, Serialize)]
pub struct AnswererCopy {
    pub path: Option<String>,
    pub version: Option<String>,
    pub sha256: Option<String>,
    pub errors: Vec<String>,
}

/// `host/answerer.json`.
#[derive(Debug, Serialize)]
pub struct AnswererReport {
    /// The root-owned copy the service runs.
    pub installed: AnswererCopy,
    /// The copy beside this `min` or on `PATH`, which `min` installs.
    pub shipped: AnswererCopy,
    /// Whether the two copies hash the same. `None` when either hash is
    /// missing.
    pub same_bytes: Option<bool>,
}

/// Collects the answerer entries of this host into a bundle created at
/// `created_at`. Log tails are capped at `tail_bytes`.
pub async fn answerer(
    w: &mut BundleWriter,
    created_at: chrono::DateTime<chrono::Utc>,
    tail_bytes: u64,
) -> Result<(), anyhow::Error> {
    answerer_from(w, &host_sources(created_at), tail_bytes).await
}

/// Collects `host/answerer.json`, the service state, the journal where
/// `sources` has one and the log where `sources` has one.
pub async fn answerer_from(
    w: &mut BundleWriter,
    sources: &AnswererSources,
    tail_bytes: u64,
) -> Result<(), anyhow::Error> {
    let report = report(sources).await;
    let json = serde_json_lenient::to_vec_pretty(&report)?;
    w.add_bytes("host/answerer.json", &json, Redaction::None)
        .await?;
    transcript(w, "host/answerer-service.txt", &sources.service).await?;
    if let Some(journal) = &sources.journal {
        transcript(w, "host/answerer-journal.txt", journal).await?;
    }
    if let Some(log) = &sources.log {
        log_tail(w, log, tail_bytes).await?;
    }
    Ok(())
}

async fn report(sources: &AnswererSources) -> AnswererReport {
    let installed = copy_at(sources.installed.clone()).await;
    let shipped = copy_at(sources.shipped.clone()).await;
    let same_bytes = match (&installed.sha256, &shipped.sha256) {
        (Some(a), Some(b)) => Some(a == b),
        _ => None,
    };
    AnswererReport {
        installed,
        shipped,
        same_bytes,
    }
}

/// The version and hash of the copy at `path`. `None` is a copy that was
/// not found beside this `min` or on `PATH`.
async fn copy_at(path: Option<String>) -> AnswererCopy {
    let Some(path) = path else {
        return AnswererCopy {
            path: None,
            version: None,
            sha256: None,
            errors: vec![format!(
                "no {} beside this min or on PATH",
                resolver::ANSWERER_PROGRAM_NAME
            )],
        };
    };
    let mut errors = Vec::new();
    let sha256 = match resolver::sha256_of(&path).await {
        Ok(hash) => Some(hash),
        Err(e) => {
            errors.push(format!("sha256: {e}"));
            None
        }
    };
    // A copy that cannot be read is not run either: the hash error
    // already says why.
    let version = if sha256.is_some() {
        match diagnostics::command_stdout(&path, &["--version"], COMMAND_TIMEOUT).await {
            Ok(out) => Some(out.trim().to_string()),
            Err(e) => {
                errors.push(format!("--version: {e:#}"));
                None
            }
        }
    } else {
        None
    };
    AnswererCopy {
        path: Some(path),
        version,
        sha256,
        errors,
    }
}

/// The tail of the service's log at [`LOG_ENTRY`], or a skip that says
/// why it is not there.
async fn log_tail(
    w: &mut BundleWriter,
    log: &LogSource,
    tail_bytes: u64,
) -> Result<(), anyhow::Error> {
    let err = match w
        .add_file_tail(LOG_ENTRY, Path::new(&log.path), tail_bytes)
        .await
    {
        Ok(()) => return Ok(()),
        Err(err) => err,
    };
    let reason = if is_not_found(&err) {
        absent_log_reason(log).await
    } else {
        format!("unreadable: {err:#}")
    };
    w.skip(LOG_ENTRY, reason);
    Ok(())
}

/// Why the log at `log.path` is absent, from what its unit says.
async fn absent_log_reason(log: &LogSource) -> String {
    let path = &log.path;
    match tokio::fs::read_to_string(&log.unit).await {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            format!("absent: {path} does not exist, and the DNS service is not installed")
        }
        Err(e) => format!(
            "absent: {path} does not exist, and {} is unreadable: {e}",
            log.unit
        ),
        Ok(text) => match resolver::plist_string_value(&text, "StandardErrorPath") {
            None => format!(
                "absent: the installed DNS service predates its log. \
                 Run min finalize-install to add the log at {path}"
            ),
            Some(named) if named != path => format!(
                "absent: the installed DNS service logs to {named}, not {path}. \
                 Run min finalize-install to move the log to {path}"
            ),
            Some(_) => format!(
                "absent: {path} does not exist. \
                 Run min finalize-install to make it again"
            ),
        },
    }
}

fn is_not_found(err: &anyhow::Error) -> bool {
    err.chain()
        .filter_map(|c| c.downcast_ref::<std::io::Error>())
        .any(|io| io.kind() == std::io::ErrorKind::NotFound)
}

/// Runs `command` and adds its stdout, stderr and exit status at `dest`.
/// A command that does not start is a skip that says why. A non-zero exit
/// is still a transcript: `launchctl print` of an unloaded job and
/// `systemctl status` of a failed unit both exit non-zero, and that is the
/// finding.
async fn transcript(
    w: &mut BundleWriter,
    dest: &str,
    command: &CommandSpec,
) -> Result<(), anyhow::Error> {
    let cmd = command.program.as_str();
    let args: Vec<&str> = command.args.iter().map(String::as_str).collect();
    let (capture, timed_out) = match diagnostics::command_capture(cmd, &args, COMMAND_TIMEOUT).await
    {
        Ok(capture) => (capture, false),
        Err(CaptureError::Timeout { partial, .. }) => (partial, true),
        Err(e) => {
            w.skip(dest, format!("{cmd} did not run: {e:#}"));
            return Ok(());
        }
    };
    let text = render(cmd, &args, &capture, timed_out);
    let scrubbed = diagnostics::redact::scrub_secrets(&text);
    let redaction = match (
        &scrubbed,
        capture.stdout_dropped + capture.stderr_dropped > 0,
    ) {
        (_, true) => Redaction::Truncated,
        (std::borrow::Cow::Owned(_), false) => Redaction::Scrubbed,
        (std::borrow::Cow::Borrowed(_), false) => Redaction::None,
    };
    w.add_bytes(dest, scrubbed.as_bytes(), redaction).await
}

/// The transcript text of one command run.
fn render(cmd: &str, args: &[&str], capture: &Capture, timed_out: bool) -> String {
    let mut text = format!("$ {cmd} {}\n", args.join(" "));
    text.push_str(&String::from_utf8_lossy(&capture.stdout));
    if !capture.stderr.is_empty() {
        text.push_str("--- stderr ---\n");
        text.push_str(&String::from_utf8_lossy(&capture.stderr));
    }
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let _ = match capture.status {
        _ if timed_out => writeln!(text, "--- killed after {COMMAND_TIMEOUT:?} ---"),
        Some(status) => writeln!(text, "--- {status} ---"),
        None => writeln!(text, "--- no exit status ---"),
    };
    text
}
