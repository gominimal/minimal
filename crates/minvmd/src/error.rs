//! Typed errors for `minvmd`.
//!
//! Library code returns `VmError`; CLI / boundary code wraps in
//! `anyhow::Result`. `Backend` preserves the original libkrun errno so the
//! source magnitude survives any wrap-and-rethrow.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Errors produced by `minvmd`'s VM layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum VmError {
    /// A libkrun FFI call returned a negative errno. `op` names the libkrun
    /// function so the caller can attribute the failure without parsing
    /// strings; `source` carries the errno as an [`io::Error`] (libkrun
    /// returns negative errnos; the sign is stripped when constructing it).
    Backend { op: &'static str, source: io::Error },

    /// A caller-supplied path contained a NUL byte and cannot be passed across
    /// the C FFI boundary. `what` identifies the parameter for diagnostics.
    NulInPath { what: &'static str, path: PathBuf },

    /// A caller-supplied string (e.g. an env var or argv entry) contained a
    /// NUL byte and cannot be passed across the C FFI boundary.
    NulInString { what: &'static str, value: String },

    /// `krun_start_enter` returned a non-negative value. libkrun's docs state
    /// the function only returns on error (on success it `exit()`s the host
    /// process with the guest workload's exit code), so a non-negative
    /// return is a protocol violation. `ret` is the raw libkrun return.
    StartEnterReturnedUnexpectedly { ret: i32 },

    /// A required environment variable was unset or empty.
    MissingEnv { var: &'static str },

    /// An I/O error outside the libkrun FFI boundary (e.g. creating or
    /// checking the socket directory, R3.2).
    Io { source: io::Error },

    /// A VM configuration is not valid for the active deployment model (R2.5):
    /// `what` names the offending field and `reason` explains why it is rejected.
    Configuration {
        what: &'static str,
        reason: &'static str,
    },
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { op, source } => {
                write!(f, "libkrun {op} failed: {source}")
            }
            Self::NulInPath { what, path } => {
                write!(
                    f,
                    "{what} path contains a NUL byte and cannot cross the FFI boundary: {}",
                    path.display()
                )
            }
            Self::NulInString { what, value } => {
                write!(
                    f,
                    "{what} contains a NUL byte and cannot cross the FFI boundary: {value:?}"
                )
            }
            Self::StartEnterReturnedUnexpectedly { ret } => {
                write!(
                    f,
                    "krun_start_enter returned {ret} but libkrun's docs say it only returns on error"
                )
            }
            Self::MissingEnv { var } => {
                write!(f, "required environment variable {var} is unset or empty")
            }
            Self::Io { source } => {
                write!(f, "I/O error: {source}")
            }
            Self::Configuration { what, reason } => {
                write!(f, "invalid VM configuration ({what}): {reason}")
            }
        }
    }
}

impl std::error::Error for VmError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Backend { source, .. } => Some(source),
            Self::NulInPath { .. }
            | Self::NulInString { .. }
            | Self::StartEnterReturnedUnexpectedly { .. }
            | Self::MissingEnv { .. }
            | Self::Configuration { .. } => None,
            Self::Io { source } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_preserves_errno_in_source() {
        let err = VmError::Backend {
            op: "krun_create_ctx",
            source: io::Error::from_raw_os_error(22),
        };
        let VmError::Backend { source, .. } = &err else {
            panic!("expected Backend, got {err:?}");
        };
        assert_eq!(
            source.raw_os_error(),
            Some(22),
            "errno magnitude must be preserved"
        );
        // `source()` exposes the io::Error so the chain is traversable.
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn display_includes_op_and_errno() {
        let err = VmError::Backend {
            op: "krun_set_vm_config",
            source: io::Error::from_raw_os_error(12),
        };
        let s = format!("{err}");
        assert!(s.contains("krun_set_vm_config"), "display: {s}");
    }

    #[test]
    fn display_start_enter_returned_unexpectedly() {
        let err = VmError::StartEnterReturnedUnexpectedly { ret: 0 };
        let s = format!("{err}");
        assert!(s.contains("krun_start_enter"), "display: {s}");
        assert!(s.contains("only returns on error"), "display: {s}");
    }

    #[test]
    fn display_nul_in_path() {
        let err = VmError::NulInPath {
            what: "rootfs",
            path: PathBuf::from("/tmp/bad"),
        };
        let s = format!("{err}");
        assert!(s.contains("rootfs"));
        assert!(s.contains("/tmp/bad"));
    }
}
