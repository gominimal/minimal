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
//!   [`JOURNAL_WINDOW`]. On macOS the service writes its output to
//!   `<state>/logs/minzoned.log`, which the `logs` collector takes.
//!
//! Each part that cannot be read is recorded as a skip that says why.

use std::fmt::Write as _;
use std::time::Duration;

use diagnostics::{BundleWriter, Capture, CaptureError, Redaction};
use serde::Serialize;

use crate::resolver;

/// The bound on each command this collector runs. Well inside the
/// collector step's own deadline, so one wedged command still leaves time
/// for the others.
const COMMAND_TIMEOUT: Duration = Duration::from_secs(5);

/// How far back the service's journal is read: the window a report of a
/// service that will not start is about.
#[cfg(not(target_os = "macos"))]
const JOURNAL_WINDOW: &str = "-24h";

/// The most journal lines kept, newest first, so a service that restarts in
/// a loop cannot fill the bundle.
#[cfg(not(target_os = "macos"))]
const JOURNAL_LINES_MAX: &str = "1000";

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

/// Collects `host/answerer.json`, the service state and, off macOS, the
/// service journal.
pub async fn answerer(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let report = report().await;
    let json = serde_json_lenient::to_vec_pretty(&report)?;
    w.add_bytes("host/answerer.json", &json, Redaction::None)
        .await?;
    service_state(w).await?;
    #[cfg(not(target_os = "macos"))]
    journal(w).await?;
    Ok(())
}

async fn report() -> AnswererReport {
    let installed = copy_at(Some(resolver::ANSWERER_PROGRAM_PATH.to_string())).await;
    let shipped = copy_at(resolver::answerer_source()).await;
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

/// The service manager's view of the service, as a transcript.
#[cfg(target_os = "macos")]
async fn service_state(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let target = format!("system/{}", resolver::ANSWERER_LAUNCHD_LABEL);
    transcript(
        w,
        "host/answerer-service.txt",
        "launchctl",
        &["print", &target],
    )
    .await
}

/// The service manager's view of the service, as a transcript.
#[cfg(not(target_os = "macos"))]
async fn service_state(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let socket = format!("{}.socket", resolver::ANSWERER_SYSTEMD_UNIT);
    let service = format!("{}.service", resolver::ANSWERER_SYSTEMD_UNIT);
    transcript(
        w,
        "host/answerer-service.txt",
        "systemctl",
        &["status", "--no-pager", "--full", &socket, &service],
    )
    .await
}

/// The service's journal over [`JOURNAL_WINDOW`].
#[cfg(not(target_os = "macos"))]
async fn journal(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let socket = format!("{}.socket", resolver::ANSWERER_SYSTEMD_UNIT);
    let service = format!("{}.service", resolver::ANSWERER_SYSTEMD_UNIT);
    let since = format!("--since={JOURNAL_WINDOW}");
    transcript(
        w,
        "host/answerer-journal.txt",
        "journalctl",
        &[
            "--no-pager",
            "-q",
            "-o",
            "short-iso",
            "-n",
            JOURNAL_LINES_MAX,
            &since,
            "-u",
            &socket,
            "-u",
            &service,
        ],
    )
    .await
}

/// Runs `cmd args` and adds its stdout, stderr and exit status at `dest`.
/// A command that does not start is a skip that says why. A non-zero exit
/// is still a transcript: `launchctl print` of an unloaded job and
/// `systemctl status` of a failed unit both exit non-zero, and that is the
/// finding.
async fn transcript(
    w: &mut BundleWriter,
    dest: &str,
    cmd: &str,
    args: &[&str],
) -> Result<(), anyhow::Error> {
    let (capture, timed_out) = match diagnostics::command_capture(cmd, args, COMMAND_TIMEOUT).await
    {
        Ok(capture) => (capture, false),
        Err(CaptureError::Timeout { partial, .. }) => (partial, true),
        Err(e) => {
            w.skip(dest, format!("{cmd} did not run: {e:#}"));
            return Ok(());
        }
    };
    let text = render(cmd, args, &capture, timed_out);
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
