//! `min doctor`: checks of this host's state that a person runs by hand.
//!
//! The one check today verifies the hash chain of the Box Egress Proxy's
//! audit log across every segment (BEP-049). Whole-log verification lives
//! here, never behind a `min box audit` flag.

use std::io::Write;
use std::path::Path;

use anyhow::Context as _;
use bep::audit::{LogCheck, verify_dir};

use crate::task::TaskExit;

/// The result line of the audit chain check, as `min doctor` prints it.
// The two outcome lines are fixed by the plan's diagnostics for BEP-049.
fn audit_line(check: &LogCheck) -> String {
    match &check.broken {
        Some((segment, record)) => format!(
            "Audit log: the hash chain breaks at record {record} of {}; a record was changed or removed.",
            segment.display()
        ),
        None if check.records == 0 => "Audit log: no records yet.".to_owned(),
        None => "Audit log: chain verified.".to_owned(),
    }
}

/// Runs every check against the audit log in `dir` and writes one line for
/// each to `out`. Returns whether every check passed.
pub(crate) fn run(dir: &Path, out: &mut impl Write) -> anyhow::Result<bool> {
    let check = verify_dir(dir)
        .with_context(|| format!("cannot read the audit log in {}", dir.display()))?;
    let outcome = match &check.broken {
        Some(_) => "broken",
        None => "verified",
    };
    tracing::info!(
        dir = %dir.display(),
        segments = ?check.segments.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        records = check.records,
        outcome,
        "checked the audit log hash chain"
    );
    writeln!(out, "{}", audit_line(&check))?;
    Ok(check.broken.is_none())
}

/// `min doctor`. Exits 1, with no further message, when a check fails.
pub(crate) fn cmd_doctor() -> anyhow::Result<()> {
    // Interim (BEP-042): the client reads the proxy's log files on the host
    // directly, as `min box audit` does.
    let dir = bep::audit::default_dir()
        .context("cannot find the home directory, so the audit log cannot be found")?;
    if run(&dir, &mut std::io::stdout().lock())? {
        Ok(())
    } else {
        Err(TaskExit(1).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bep::audit::{AuditLog, Decision, Kind, Mapping, Outcome, Rotation};

    fn decision() -> Decision {
        Decision {
            kind: Kind::Decision,
            box_id: "01920000-0000-7000-8000-000000000001".to_owned(),
            authority: "api.github.com".to_owned(),
            identifier: None,
            mapping: Mapping::ModuleUnmapped,
            outcome: Outcome::Refuse,
            marker: Some("off_module".to_owned()),
        }
    }

    fn run_to_string(dir: &Path) -> (bool, String) {
        let mut out = Vec::new();
        let passed = run(dir, &mut out).unwrap();
        (passed, String::from_utf8(out).unwrap())
    }

    // BEP-049: editing one audit record makes `min doctor` name the record
    // and the segment where the chain breaks.
    #[test]
    fn doctor_reports_a_broken_audit_chain() {
        let tmp = tempfile::tempdir().expect("a temp dir");
        let dir = tmp.path().join("audit");

        assert_eq!(
            run_to_string(&dir),
            (true, "Audit log: no records yet.\n".to_owned())
        );

        // One record to a segment, so the chain crosses segments.
        let rotation = Rotation {
            bound: 1,
            ..Rotation::default()
        };
        let mut log = AuditLog::open_dir(&dir, rotation).unwrap();
        for _ in 0..3 {
            log.append(&decision()).unwrap();
        }
        drop(log);
        assert_eq!(
            run_to_string(&dir),
            (true, "Audit log: chain verified.\n".to_owned())
        );

        // Change the first segment's record without recomputing any hash.
        // The next record, the first of the second segment, no longer
        // carries the hash of the line before it.
        let segments = bep::audit::segments(&dir).unwrap();
        assert!(segments.len() >= 2, "the log rotated: {segments:?}");
        let first = std::fs::read_to_string(&segments[0]).unwrap();
        std::fs::write(
            &segments[0],
            first.replace("api.github.com", "api.github.org"),
        )
        .unwrap();
        assert_eq!(
            run_to_string(&dir),
            (
                false,
                format!(
                    "Audit log: the hash chain breaks at record 1 of {}; a record was changed or removed.\n",
                    segments[1].display()
                )
            )
        );
    }
}
