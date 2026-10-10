use std::{fmt, path::PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Execution(#[from] ExecutionError),
    #[error(transparent)]
    Output(#[from] OutputError),
    #[error("{}: I/O error on path {}: {}", .0, .1.display(), .2)]
    IO(&'static str, PathBuf, #[source] std::io::Error),
    #[error(transparent)]
    HardlinkFailed(common::HardlinkError),
    #[error("Mapped files in rootfs are not supported: {}", .0.display())]
    MappedFile(PathBuf),
    /// Post-spawn network wiring ([`Network::attach`](crate::Network::attach))
    /// failed (e.g. an own-IP switch attach).
    #[error("{0}")]
    Network(#[source] crate::network::NetworkError),
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("{}", InvocationFailedDisplay { idx, code, reason, stderr, stdout })]
    InvocationFailed {
        idx: usize,
        code: i32,
        reason: String,
        stderr: String,
        /// Last ~4 KiB of stdout. Captured alongside stderr so build
        /// scripts that swallow their stderr (e.g. `pip install foo
        /// 2>/dev/null || true`) still leave a diagnostic trail.
        stdout: String,
    },
    #[cfg(target_os = "linux")]
    #[error("Invocation spawn failed: {0}")]
    SpawnFailed(#[source] hakoniwa::Error),
    #[error("Failed to mount {}: {}", path.display(), msg)]
    MountError { msg: &'static str, path: PathBuf },
    /// A plan that requires its own network namespace was given, but this host
    /// cannot create one. We fail closed rather than silently fall back to host
    /// networking, which would void the isolation the plan promises (spec R1.2).
    ///
    /// Carries no mode: the sandbox layer acts on plans, and the caller that
    /// chose the mode is the one that can name it.
    #[error(
        "this sandbox's network mode requires its own network \
         namespace (only host-net shares the host's), but this host \
         cannot create one"
    )]
    NetworkIsolationUnavailable,
    #[error("Execution cancelled")]
    Cancelled,
}

/// Renders [`ExecutionError::InvocationFailed`]'s multi-line message.
struct InvocationFailedDisplay<'a> {
    idx: &'a usize,
    code: &'a i32,
    reason: &'a String,
    stderr: &'a String,
    stdout: &'a String,
}

impl fmt::Display for InvocationFailedDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            idx,
            code,
            reason,
            stderr,
            stdout,
        } = self;
        write!(
            f,
            "Invocation {} failed with exit code {}: {}",
            idx, code, reason
        )?;
        if !stderr.is_empty() {
            write!(f, "\nstderr:\n{}", stderr)?;
        }
        if !stdout.is_empty() {
            write!(f, "\nstdout:\n{}", stdout)?;
        }
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    #[error(
        "Missing output file: {} in staging directory {}",
        path.display(),
        staging_dir.display()
    )]
    MissingOutput { path: PathBuf, staging_dir: PathBuf },

    #[error("Invalid output glob {pattern}: {e}")]
    InvalidGlob {
        pattern: String,
        #[source]
        e: globset::Error,
    },

    #[error(
        "Symlink {} points outside output directory: {}",
        symlink.display(),
        target.display()
    )]
    ExternalSymlink { symlink: PathBuf, target: PathBuf },
}
