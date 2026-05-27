//! Typed errors for `minvmd`.
//!
//! Library code returns `VmError`; CLI / boundary code wraps in
//! `anyhow::Result`. `Backend` preserves the original libkrun errno so the
//! source magnitude survives any wrap-and-rethrow.

use std::fmt;
use std::path::PathBuf;

/// Errors produced by `minvmd`'s VM layer.
#[derive(Debug)]
#[non_exhaustive]
pub enum VmError {
    /// A libkrun FFI call returned a negative errno. `op` names the libkrun
    /// function so the caller can attribute the failure without parsing
    /// strings; `code` is the absolute errno magnitude (libkrun returns
    /// negative errnos; we strip the sign before surfacing).
    Backend { op: &'static str, code: i32 },

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
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend { op, code } => {
                write!(f, "libkrun {op} returned errno {code}")
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
        }
    }
}

impl std::error::Error for VmError {}

// Translating libkrun return codes is macOS-only (libkrun is not linked on
// Linux); gating prevents a dead-code error in the Linux lib build.
#[cfg(target_os = "macos")]
impl VmError {
    /// Translate a libkrun return code into a `Result`. libkrun returns zero
    /// (or a positive id) on success and a negative errno on failure; we
    /// preserve the magnitude as a positive `code`.
    #[inline]
    pub(crate) fn check_backend(op: &'static str, ret: i32) -> Result<i32, VmError> {
        if ret < 0 {
            Err(VmError::Backend {
                op,
                code: ret.unsigned_abs() as i32,
            })
        } else {
            Ok(ret)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    #[test]
    fn backend_check_passes_through_success() {
        assert_eq!(VmError::check_backend("op", 0).unwrap(), 0);
        assert_eq!(VmError::check_backend("op", 7).unwrap(), 7);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn backend_check_translates_negative_to_typed_error() {
        let err = VmError::check_backend("krun_create_ctx", -22).unwrap_err();
        match err {
            VmError::Backend { op, code } => {
                assert_eq!(op, "krun_create_ctx");
                assert_eq!(code, 22, "errno magnitude must be preserved");
            }
            other => panic!("expected Backend, got {other:?}"),
        }
    }

    #[test]
    fn display_includes_op_and_code() {
        let err = VmError::Backend {
            op: "krun_set_vm_config",
            code: 12,
        };
        let s = format!("{err}");
        assert!(s.contains("krun_set_vm_config"), "display: {s}");
        assert!(s.contains("12"), "display: {s}");
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
