//! Bounded subprocess output capture for command-shaped collectors.
//!
//! One helper, one contract: run a command, capture stdout/stderr/status,
//! never outlive the timeout, never leak a child past the collection run.
//! On timeout the child is killed and the output captured so far is returned
//! inside the error — partial evidence from a hung tool is still evidence.
//!
//! Output is size-bounded as well as time-bounded: a fast, steady producer can
//! stay well inside its deadline while writing arbitrarily much, so each stream
//! retains only its most recent [`DEFAULT_CAPTURE_CAP`] bytes (tail-first,
//! because the collectors that need this filter for the newest lines) and the
//! dropped-byte count rides back on the [`Capture`].

use std::process::{ExitStatus, Stdio};
use std::time::Duration;

use tokio::io::AsyncReadExt as _;
use tokio::process::Command;

/// Everything a finished (or killed) command left behind.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Capture {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Bytes dropped from the front of `stdout` because it exceeded the size
    /// cap; `0` when the whole stream fit. Non-zero means `stdout` holds only
    /// the most recent bytes, and the bundle should record the truncation.
    pub stdout_dropped: u64,
    /// Same as [`stdout_dropped`](Self::stdout_dropped), for `stderr`.
    pub stderr_dropped: u64,
    /// `None` when the child was killed before exiting (timeout).
    pub status: Option<ExitStatus>,
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CaptureError {
    #[error("spawning `{cmd}`")]
    Spawn {
        cmd: String,
        #[source]
        source: std::io::Error,
    },
    #[error("reading `{cmd}` output")]
    Io {
        cmd: String,
        #[source]
        source: std::io::Error,
    },
    /// The command outlived its deadline and was killed; `partial` retains
    /// whatever it wrote first.
    #[error("`{cmd}` timed out after {timeout:?}")]
    Timeout {
        cmd: String,
        timeout: Duration,
        partial: Capture,
    },
    /// The command ran but exited non-zero and wrote nothing to stdout — no
    /// usable output to salvage, so a caller can fall through to the next
    /// source.
    #[error("`{cmd}` exited unsuccessfully with no output")]
    NonZero { cmd: String },
}

/// Default per-stream size cap for [`command_capture`]. Command captures in
/// this crate run to hundreds of KB to a few MB in the common case; the cap
/// sits above that so normal output is retained untouched, and well below a
/// size that would bloat a support bundle.
const DEFAULT_CAPTURE_CAP: usize = 8 * 1024 * 1024;

/// A byte buffer that retains only the most recent `cap` bytes: once a write
/// pushes it past the cap the oldest bytes are dropped, and the running count
/// of dropped bytes is kept so the caller can record the truncation. The
/// collectors that need this (kernel-journal and `pmset -g log` scrapers)
/// filter for the *newest* lines, so the tail is the half worth keeping.
struct Tail {
    cap: usize,
    buf: Vec<u8>,
    dropped: u64,
}

impl Tail {
    fn new(cap: usize) -> Self {
        Self {
            cap,
            buf: Vec::new(),
            dropped: 0,
        }
    }

    fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        if self.buf.len() > self.cap {
            let excess = self.buf.len() - self.cap;
            self.buf.drain(..excess);
            self.dropped += excess as u64;
        }
    }
}

/// Runs `cmd args…` with stdin closed, capturing stdout and stderr until the
/// process exits or `timeout` elapses. A timed-out child is killed
/// (`kill_on_drop` backstops the explicit kill) and the bytes captured so far
/// ride back in [`CaptureError::Timeout`]. Each stream is size-bounded at
/// [`DEFAULT_CAPTURE_CAP`]; use [`command_capture_capped`] to raise it.
pub async fn command_capture(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<Capture, CaptureError> {
    command_capture_capped(cmd, args, timeout, DEFAULT_CAPTURE_CAP).await
}

/// Like [`command_capture`] but with an explicit per-stream size cap, for the
/// rare collector whose output is legitimately larger than the default. `cap`
/// bounds stdout and stderr independently, tail-first; the dropped-byte counts
/// ride back on the [`Capture`] (or on the [`CaptureError::Timeout`] partial).
pub async fn command_capture_capped(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
    cap: usize,
) -> Result<Capture, CaptureError> {
    let spawn_err = |source| CaptureError::Spawn {
        cmd: cmd.to_string(),
        source,
    };
    let io_err = |source| CaptureError::Io {
        cmd: cmd.to_string(),
        source,
    };

    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(spawn_err)?;
    let mut stdout_pipe = child.stdout.take().expect("stdout was piped");
    let mut stderr_pipe = child.stderr.take().expect("stderr was piped");

    let mut stdout = Tail::new(cap);
    let mut stderr = Tail::new(cap);
    let mut out_buf = [0u8; 8192];
    let mut err_buf = [0u8; 8192];
    let (mut out_done, mut err_done) = (false, false);
    let deadline = tokio::time::sleep(timeout);
    tokio::pin!(deadline);

    let status = loop {
        tokio::select! {
            _ = &mut deadline => {
                let _ = child.start_kill();
                return Err(CaptureError::Timeout {
                    cmd: cmd.to_string(),
                    timeout,
                    partial: Capture {
                        stdout: stdout.buf,
                        stderr: stderr.buf,
                        stdout_dropped: stdout.dropped,
                        stderr_dropped: stderr.dropped,
                        status: None,
                    },
                });
            }
            n = stdout_pipe.read(&mut out_buf), if !out_done => {
                let n = n.map_err(io_err)?;
                if n == 0 { out_done = true; } else { stdout.extend(&out_buf[..n]); }
            }
            n = stderr_pipe.read(&mut err_buf), if !err_done => {
                let n = n.map_err(io_err)?;
                if n == 0 { err_done = true; } else { stderr.extend(&err_buf[..n]); }
            }
            status = child.wait(), if out_done && err_done => {
                break status.map_err(io_err)?;
            }
        }
    };
    Ok(Capture {
        stdout: stdout.buf,
        stderr: stderr.buf,
        stdout_dropped: stdout.dropped,
        stderr_dropped: stderr.dropped,
        status: Some(status),
    })
}

/// stdout of `cmd args…` when the command produced usable output: a clean
/// exit, or a non-zero exit that still wrote to stdout — the `lsof`/`ss`
/// convention, where exit 1 with a partial listing is evidence, not failure.
/// [`Spawn`](CaptureError::Spawn) and [`Timeout`](CaptureError::Timeout)
/// propagate so a caller can fall through to the next source; a silent
/// non-zero exit is [`NonZero`](CaptureError::NonZero). This is the entry
/// point the net/procs/power collectors run their command-shaped captures
/// through.
pub async fn command_stdout(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String, CaptureError> {
    let capture = command_capture(cmd, args, timeout).await?;
    if capture.status.is_some_and(|s| s.success()) || !capture.stdout.is_empty() {
        Ok(String::from_utf8_lossy(&capture.stdout).into_owned())
    } else {
        Err(CaptureError::NonZero {
            cmd: cmd.to_string(),
        })
    }
}

/// First line of `cmd args…` stdout, or `None` when the command can't run,
/// fails, or times out. The one-liner for collectors that want a single
/// fact from a tool (`uname -srvm`) and treat any failure as "unknown".
pub async fn first_stdout_line(cmd: &str, args: &[&str], timeout: Duration) -> Option<String> {
    let capture = command_capture(cmd, args, timeout).await.ok()?;
    capture.status.is_some_and(|s| s.success()).then(|| {
        String::from_utf8_lossy(&capture.stdout)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn captures_stdout_stderr_and_status() {
        let cap = command_capture(
            "sh",
            &["-c", "echo out; echo err >&2; exit 3"],
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(cap.stdout, b"out\n");
        assert_eq!(cap.stderr, b"err\n");
        assert_eq!(cap.status.unwrap().code(), Some(3));
    }

    #[tokio::test]
    async fn timeout_kills_the_child_and_retains_partial_output() {
        let err = command_capture(
            "sh",
            &["-c", "echo partial; sleep 30"],
            Duration::from_millis(300),
        )
        .await
        .unwrap_err();
        let CaptureError::Timeout { partial, .. } = err else {
            panic!("expected timeout, got: {err}");
        };
        assert_eq!(partial.stdout, b"partial\n", "pre-timeout output retained");
        assert_eq!(partial.status, None, "killed child has no exit status");
    }

    #[tokio::test]
    async fn size_cap_keeps_the_tail_and_reports_the_drop() {
        // 1000 bytes of a 10-byte repeating block, capped at 100: the retained
        // buffer is exactly the last 100 bytes and the drop count is the rest.
        let cap = command_capture_capped(
            "sh",
            &["-c", "printf '0123456789%.0s' $(seq 1 100)"],
            Duration::from_secs(10),
            100,
        )
        .await
        .unwrap();
        assert_eq!(
            cap.stdout,
            b"0123456789".repeat(10),
            "kept the newest bytes"
        );
        assert_eq!(cap.stdout_dropped, 900, "reported the discarded bytes");
    }

    #[tokio::test]
    async fn missing_binary_is_a_spawn_error() {
        let err = command_capture("definitely-not-a-real-binary", &[], Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, CaptureError::Spawn { .. }), "got: {err}");
    }

    #[tokio::test]
    async fn command_stdout_keeps_output_from_a_nonzero_exit() {
        // The lsof/ss convention: exit 1 with a partial listing is evidence.
        let out = command_stdout(
            "sh",
            &["-c", "echo listing; exit 1"],
            Duration::from_secs(10),
        )
        .await
        .unwrap();
        assert_eq!(out, "listing\n");

        // A silent non-zero exit has nothing to salvage.
        let err = command_stdout("sh", &["-c", "exit 1"], Duration::from_secs(10))
            .await
            .unwrap_err();
        assert!(matches!(err, CaptureError::NonZero { .. }), "got: {err}");
    }

    #[tokio::test]
    async fn first_stdout_line_takes_line_one_and_maps_failure_to_none() {
        let line = first_stdout_line(
            "sh",
            &["-c", "echo first; echo second"],
            Duration::from_secs(10),
        )
        .await;
        assert_eq!(line.as_deref(), Some("first"));

        let failed = first_stdout_line("sh", &["-c", "exit 1"], Duration::from_secs(10)).await;
        assert_eq!(failed, None, "non-zero exit is None, not empty");
        let missing =
            first_stdout_line("definitely-not-a-real-binary", &[], Duration::from_secs(1)).await;
        assert_eq!(missing, None);
    }
}
