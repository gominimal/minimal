use std::{fmt, path::PathBuf};

#[derive(Debug)]
pub enum Error {
    Execution(ExecutionError),
    Output(OutputError),
    IO(&'static str, PathBuf, std::io::Error),
    HardlinkFailed(common::HardlinkError),
    MappedFile(PathBuf),
    /// Post-spawn network wiring ([`Network::attach`](crate::Network::attach))
    /// failed (e.g. an own-IP switch attach).
    Network(crate::network::NetworkError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Execution(e) => e.fmt(f),
            Self::Output(e) => e.fmt(f),
            Self::HardlinkFailed(e) => e.fmt(f),
            Self::IO(op, path, err) => {
                write!(f, "{}: I/O error on path {}: {}", op, path.display(), err)
            }
            Self::MappedFile(path) => {
                write!(
                    f,
                    "Mapped files in rootfs are not supported: {}",
                    path.display()
                )
            }
            Self::Network(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Execution(e) => e.source(),
            Self::Output(e) => e.source(),
            Self::HardlinkFailed(e) => e.source(),
            Self::IO(_, _, err) => Some(err),
            Self::MappedFile(_) => None,
            Self::Network(e) => Some(e),
        }
    }
}

impl From<ExecutionError> for Error {
    fn from(value: ExecutionError) -> Self {
        Error::Execution(value)
    }
}
impl From<OutputError> for Error {
    fn from(value: OutputError) -> Self {
        Error::Output(value)
    }
}

#[derive(Debug)]
pub enum ExecutionError {
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
    SpawnFailed(hakoniwa::Error),
    MountError {
        msg: &'static str,
        path: PathBuf,
    },
    /// A [`NetworkMode`](crate::NetworkMode) that requires its own network
    /// namespace was requested, but this host cannot create one. We fail closed
    /// rather than silently fall back to host networking, which would void the
    /// isolation the mode promises (spec R1.2).
    NetworkIsolationUnavailable {
        mode: crate::NetworkMode,
    },
    Cancelled,
}

impl fmt::Display for ExecutionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvocationFailed {
                idx,
                code,
                reason,
                stderr,
                stdout,
            } => {
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
            Self::SpawnFailed(e) => {
                write!(f, "Invocation spawn failed: {}", e)
            }
            Self::MountError { msg, path } => {
                write!(f, "Failed to mount {}: {}", path.display(), msg)
            }
            Self::NetworkIsolationUnavailable { mode } => {
                write!(
                    f,
                    "network mode {mode:?} requires its own network namespace, \
                     but this host cannot create one"
                )
            }
            Self::Cancelled => {
                write!(f, "Execution cancelled")
            }
        }
    }
}

impl std::error::Error for ExecutionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvocationFailed { .. } => None,
            Self::SpawnFailed(e) => Some(e),
            Self::MountError { .. } => None,
            Self::NetworkIsolationUnavailable { .. } => None,
            Self::Cancelled => None,
        }
    }
}

#[derive(Debug)]
pub enum OutputError {
    MissingOutput { path: PathBuf, staging_dir: PathBuf },

    InvalidGlob { pattern: String, e: globset::Error },

    ExternalSymlink { symlink: PathBuf, target: PathBuf },
}

impl fmt::Display for OutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingOutput { path, staging_dir } => write!(
                f,
                "Missing output file: {} in staging directory {}",
                path.display(),
                staging_dir.display()
            ),
            Self::InvalidGlob { pattern, e } => write!(f, "Invalid output glob {}: {}", pattern, e),
            Self::ExternalSymlink { symlink, target } => write!(
                f,
                "Symlink {} points outside output directory: {}",
                symlink.display(),
                target.display()
            ),
        }
    }
}

impl std::error::Error for OutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::MissingOutput { .. } => None,
            Self::InvalidGlob { e, .. } => Some(e),
            Self::ExternalSymlink { .. } => None,
        }
    }
}
