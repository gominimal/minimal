use std::{fmt, path::PathBuf};

#[derive(Debug)]
pub enum Error {
    Execution(ExecutionError),
    Output(OutputError),
    IO(&'static str, PathBuf, std::io::Error),
    HardlinkFailed(common::HardlinkError),
    MappedFile(PathBuf),
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
