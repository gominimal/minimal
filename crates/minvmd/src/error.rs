//! Typed errors for `minvmd`.
//!
//! Library code returns `VmError`; CLI / boundary code wraps in
//! `anyhow::Result`. `Backend` preserves the original libkrun errno so the
//! source magnitude survives any wrap-and-rethrow.

use std::io;
use std::path::PathBuf;

/// Errors produced by `minvmd`'s VM layer.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum VmError {
    /// A libkrun FFI call returned a negative errno. `op` names the libkrun
    /// function so the caller can attribute the failure without parsing
    /// strings; `source` carries the errno as an [`io::Error`] (libkrun
    /// returns negative errnos; the sign is stripped when constructing it).
    #[error("libkrun {op} failed: {source}")]
    Backend { op: &'static str, source: io::Error },

    /// A caller-supplied path contained a NUL byte and cannot be passed across
    /// the C FFI boundary. `what` identifies the parameter for diagnostics.
    #[error(
        "{what} path contains a NUL byte and cannot cross the FFI boundary: {}",
        path.display()
    )]
    NulInPath { what: &'static str, path: PathBuf },

    /// A caller-supplied string (e.g. an env var or argv entry) contained a
    /// NUL byte and cannot be passed across the C FFI boundary.
    #[error("{what} contains a NUL byte and cannot cross the FFI boundary: {value:?}")]
    NulInString { what: &'static str, value: String },

    /// `krun_start_enter` returned a non-negative value. libkrun's docs state
    /// the function only returns on error (on success it `exit()`s the host
    /// process with the guest workload's exit code), so a non-negative
    /// return is a protocol violation. `ret` is the raw libkrun return.
    #[error("krun_start_enter returned {ret} but libkrun's docs say it only returns on error")]
    StartEnterReturnedUnexpectedly { ret: i32 },

    /// A required environment variable was unset or empty.
    #[error("required environment variable {var} is unset or empty")]
    MissingEnv { var: &'static str },

    /// The `MINVMD_KRUN_LOG` environment variable was set to a value that is
    /// not a recognised libkrun log level (a name `off`/`error`/`warn`/`info`/
    /// `debug`/`trace` or the numeric level `0`–`5`). `value` is the offending
    /// setting.
    #[error(
        "MINVMD_KRUN_LOG value {value:?} is not a valid log level \
         (expected off/error/warn/info/debug/trace or 0-5)"
    )]
    InvalidLogLevel { value: String },

    /// The guest images could not be located: no data directory, the user's
    /// own or a system one, holds every image whose override is unset. `var`
    /// names the override of the image being resolved; `unset` names every
    /// override that is unset (so every image the lookup needed); `searched`
    /// lists each directory looked in, in order, with the files it lacked.
    #[error("{}", missing_image_text(unset, searched))]
    MissingImage {
        var: &'static str,
        unset: Vec<&'static str>,
        searched: Vec<SearchedDir>,
    },

    /// An I/O error outside the libkrun FFI boundary (e.g. creating or
    /// checking the socket directory, R3.2).
    #[error("I/O error: {source}")]
    Io { source: io::Error },

    /// A VM configuration is not valid for the active deployment model (R2.5):
    /// `what` names the offending field and `reason` explains why it is rejected.
    #[error("invalid VM configuration ({what}): {reason}")]
    Configuration {
        what: &'static str,
        reason: &'static str,
    },

    /// A `vm_egress` `allow_subnets` entry is not a syntactically valid CIDR
    /// prefix (R2.5). Validated at config time — mirroring the per-`PTask`
    /// egress check in `boxes::Record::validate_policy` — so a misconfigured
    /// subnet is named where it can be fixed, rather than surfacing opaquely
    /// when #553's egress-enforcement layer parses it. `cidr` is the offending
    /// entry.
    #[error(
        "invalid VM configuration (vm_egress): allow_subnets entry \
         {cidr:?} is not a valid CIDR prefix"
    )]
    InvalidEgressSubnet { cidr: String },
}

/// A directory the guest image lookup looked in, and the image files it
/// lacked there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchedDir {
    pub dir: PathBuf,
    pub missing: Vec<&'static str>,
}

/// The text of [`VmError::MissingImage`]: where the lookup looked, what each
/// directory lacked, and what the person can do about it.
fn missing_image_text(unset: &[&'static str], searched: &[SearchedDir]) -> String {
    let looked = if searched.is_empty() {
        "There was no directory to look in: neither XDG_DATA_HOME nor HOME is set, \
         and XDG_DATA_DIRS has no absolute entry."
            .to_owned()
    } else {
        let dirs = searched
            .iter()
            .map(|s| format!("{} (no {})", s.dir.display(), s.missing.join(", ")))
            .collect::<Vec<_>>()
            .join("; ");
        format!("Looked in {dirs}.")
    };
    let files = if unset.len() == 1 {
        "the image file"
    } else {
        "the image files"
    };
    let vars = unset.join(", ");
    format!(
        "no data directory holds the guest images this boot needs. {looked} \
         Reinstall minimal, or set {vars} to {files}."
    )
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
