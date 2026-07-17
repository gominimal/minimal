//! Bounded subprocess output capture for command-shaped collectors.
//!
//! One helper, one contract: run a command, capture stdout/stderr/status,
//! never outlive the timeout, never leak a child past the collection run.
//! On timeout the child is killed and the output captured so far is returned
//! inside the error — partial evidence from a hung tool is still evidence.

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
}

/// Runs `cmd args…` with stdin closed, capturing stdout and stderr until the
/// process exits or `timeout` elapses. A timed-out child is killed
/// (`kill_on_drop` backstops the explicit kill) and the bytes captured so far
/// ride back in [`CaptureError::Timeout`].
pub async fn command_capture(
    cmd: &str,
    args: &[&str],
    timeout: Duration,
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

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
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
                    partial: Capture { stdout, stderr, status: None },
                });
            }
            n = stdout_pipe.read(&mut out_buf), if !out_done => {
                let n = n.map_err(io_err)?;
                if n == 0 { out_done = true; } else { stdout.extend_from_slice(&out_buf[..n]); }
            }
            n = stderr_pipe.read(&mut err_buf), if !err_done => {
                let n = n.map_err(io_err)?;
                if n == 0 { err_done = true; } else { stderr.extend_from_slice(&err_buf[..n]); }
            }
            status = child.wait(), if out_done && err_done => {
                break status.map_err(io_err)?;
            }
        }
    };
    Ok(Capture {
        stdout,
        stderr,
        status: Some(status),
    })
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
    async fn missing_binary_is_a_spawn_error() {
        let err = command_capture("definitely-not-a-real-binary", &[], Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(matches!(err, CaptureError::Spawn { .. }), "got: {err}");
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
