//! `min doctor`: the checks this host can run on its own state.
//!
//! The box egress proxy's audit log is hash-chained — every record carries the
//! SHA-256 of the line before it (BEP-048) — and whole-log verification is this
//! command's job, never a flag on `min box audit`: a read of one box's trail
//! says nothing about the records of other boxes the chain runs through.
//!
//! The check walks every retained segment, oldest first, as one chain from the
//! zero hash (BEP-068), and reports the verdict per segment with the hash the
//! chain ends on. A record altered or removed without recomputing the hashes
//! that follow is reported as a failing chain, naming the segment and the
//! record that no longer follows the one before it (BEP-049). A host whose
//! proxy has written nothing has no chain to check, which reads as such rather
//! than as a fault.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context as _, bail};
use bep::audit::Hash;
use bep::chain::{self, Break};

use crate::GlobalArgs;

/// One segment as the check found it: its path and how many records it holds.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SegmentCheck {
    path: PathBuf,
    records: usize,
}

/// Where the chain broke: the segment holding the record that does not follow
/// the one before it, that record's position in the segment, and the walk's own
/// account of the break.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Broken {
    segment: PathBuf,
    record: usize,
    at: Break,
}

/// What the audit-chain check found.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AuditChain {
    /// The segments walked, oldest first. A segment that does not exist is not
    /// among them.
    segments: Vec<SegmentCheck>,
    /// The records the walk covered.
    records: usize,
    /// The hash the chain ends on, or `None` when it does not verify.
    head: Option<Hash>,
    /// The first break, when the chain does not verify.
    broken: Option<Broken>,
}

impl AuditChain {
    /// Whether the chain failed verification.
    fn failed(&self) -> bool {
        self.broken.is_some()
    }
}

/// Walks the chain the log at `active` and its rotated segments hold, as one
/// chain from the zero hash.
///
/// # Errors
///
/// When the segment list cannot be read, a segment cannot be read, or a line of
/// one is no audit record — a log whose bytes cannot be parsed is a different
/// fault from a chain that does not verify, and is reported as itself.
fn check_audit_chain(active: &Path) -> Result<AuditChain, anyhow::Error> {
    let paths = bep::audit::segments(active)?;
    let mut read: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for path in paths {
        match std::fs::read(&path) {
            Ok(bytes) => read.push((path, bytes)),
            // A segment that is not there is no segment: the active one is
            // named before the proxy has ever written it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("reading the audit segment {}", path.display())));
            }
        }
    }

    let mut segments = Vec::new();
    let mut links = Vec::new();
    for (path, bytes) in &read {
        let held = chain::links(bytes)
            .with_context(|| format!("reading the audit segment {}", path.display()))?;
        segments.push(SegmentCheck {
            path: path.clone(),
            records: held.len(),
        });
        links.extend(held);
    }

    let records = links.len();
    let (head, broken) = match chain::verify(links.iter().copied(), Hash::ZERO) {
        Ok(head) => (Some(head), None),
        Err(at) => {
            // Which segment holds the record the walk stopped at: the segments
            // are walked in order, so the counts locate it.
            let mut position = at.at;
            let mut broken = None;
            for segment in &segments {
                if position < segment.records {
                    broken = Some(Broken {
                        segment: segment.path.clone(),
                        record: position + 1,
                        at,
                    });
                    break;
                }
                position -= segment.records;
            }
            (None, broken)
        }
    };
    Ok(AuditChain {
        segments,
        records,
        head,
        broken,
    })
}

/// Writes the audit-chain verdict: the headline, then every segment with its
/// record count, then the chain head or the break.
fn render(chain: &AuditChain, out: &mut impl Write) -> Result<(), anyhow::Error> {
    if chain.records == 0 {
        writeln!(
            out,
            "audit chain: no records — the box egress proxy has written none on this host"
        )?;
        return Ok(());
    }
    let verdict = if chain.failed() { "FAILED" } else { "verified" };
    let segments = chain.segments.len();
    writeln!(
        out,
        "audit chain: {verdict} — {} records across {segments} segment{}",
        chain.records,
        if segments == 1 { "" } else { "s" }
    )?;
    for segment in &chain.segments {
        writeln!(
            out,
            "  {}: {} records",
            segment.path.display(),
            segment.records
        )?;
    }
    match (&chain.head, &chain.broken) {
        (Some(head), _) => writeln!(out, "  head: {head}")?,
        (None, Some(broken)) => writeln!(
            out,
            "  break: {}: record {} of the segment — {}",
            broken.segment.display(),
            broken.record,
            broken.at
        )?,
        // A walk that neither ends on a head nor locates its break cannot
        // happen — the counts the break is located against are the counts the
        // walk was given — but a doctor must not claim a verdict it does not
        // have.
        (None, None) => writeln!(out, "  break: somewhere the segment counts do not cover")?,
    }
    Ok(())
}

/// Reports what this host's own checks find, and exits non-zero when one of
/// them fails.
///
/// # Errors
///
/// An unreadable audit segment, a segment holding a line that is no record, or
/// a chain that does not verify (BEP-049).
pub fn cmd_doctor(global: &GlobalArgs) -> Result<(), anyhow::Error> {
    let chain = check_audit_chain(&crate::box_cmd::audit_log_path(
        global.minimal_dir.as_deref(),
    ))?;
    render(&chain, &mut std::io::stdout().lock())?;
    tracing::info!(
        segments = chain.segments.len(),
        records = chain.records,
        failed = chain.failed(),
        "checked the audit chain"
    );
    if chain.failed() {
        bail!("the box egress proxy's audit chain does not verify");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An event the proxy records for `box_id`, with the authority varying so
    /// one record is told from another.
    fn event(box_id: &str, authority: &str) -> bep::Event {
        bep::Event {
            kind: bep::Kind::Decision,
            box_id: box_id.to_owned(),
            authority: authority.to_owned(),
            credential: None,
            mapping: bep::Mapping::Unmapped,
            decision: bep::audit::Decision::Admit,
            marker: None,
        }
    }

    fn rendered(chain: &AuditChain) -> String {
        let mut out = Vec::new();
        render(chain, &mut out).expect("rendering a verdict writes");
        String::from_utf8(out).expect("the verdict is UTF-8")
    }

    /// BEP-049: a chain whose records were altered or removed without
    /// recomputing the hashes that follow is reported as failing, naming the
    /// segment and the record — across the rotated segments as well as the
    /// active one — where the same log untouched verifies and reports its head.
    #[test]
    fn doctor_reports_broken_audit_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");

        // A host whose proxy has written nothing has no chain to check.
        let empty = check_audit_chain(&path).unwrap();
        assert_eq!(empty.records, 0);
        assert!(!empty.failed());
        assert!(rendered(&empty).contains("no records"), "{empty:?}");

        // Six records over three segments: the proxy's own rotation, so the
        // chain the check walks is the chain the writer built (BEP-068).
        let mut log = bep::Log::open(&path).unwrap().with_segment_bytes(500);
        for authority in [
            "api.github.com",
            "github.com",
            "codeload.github.com",
            "uploads.github.com",
            "api.github.com",
            "github.com",
        ] {
            log.append(&event("web", authority)).unwrap();
        }
        let head = log.head();
        drop(log);

        let checked = check_audit_chain(&path).unwrap();
        assert!(checked.segments.len() > 1, "{checked:?}");
        assert_eq!(checked.records, 6);
        assert_eq!(checked.head, Some(head));
        assert!(!checked.failed());
        let text = rendered(&checked);
        assert!(text.contains("audit chain: verified"), "{text}");
        assert!(text.contains(&format!("head: {head}")), "{text}");
        for segment in &checked.segments {
            assert!(
                text.contains(&segment.path.display().to_string()),
                "{} missing from:\n{text}",
                segment.path.display()
            );
        }

        // A record of a rotated segment altered in place, with no hash after it
        // recomputed: the chain no longer verifies, and the report names the
        // segment and the record.
        let rotated = checked
            .segments
            .iter()
            .find(|segment| segment.records > 1 && segment.path != path)
            .map(|segment| segment.path.clone())
            .expect("a rotated segment holding more than one record");
        let intact = std::fs::read_to_string(&rotated).unwrap();
        let mut held: Vec<String> = intact.lines().map(str::to_owned).collect();
        held[0] = held[0].replace(r#""marker":"""#, r#""marker":"forged""#);
        assert_ne!(
            held[0],
            intact.lines().next().unwrap(),
            "the record changed"
        );
        std::fs::write(&rotated, format!("{}\n", held.join("\n"))).unwrap();

        let tampered = check_audit_chain(&path).unwrap();
        assert!(tampered.failed(), "{tampered:?}");
        assert_eq!(tampered.head, None);
        let broken = tampered.broken.clone().expect("the break is located");
        assert_eq!(broken.segment, rotated);
        // The altered record still carries what it carried, so the record after
        // it is the one that no longer follows.
        assert_eq!(broken.record, 2);
        let text = rendered(&tampered);
        assert!(text.contains("audit chain: FAILED"), "{text}");
        assert!(
            text.contains(&rotated.display().to_string()),
            "the segment is named:\n{text}"
        );
        assert!(text.contains("record 2 of the segment"), "{text}");
        assert!(
            !text.contains("head:"),
            "a failed chain claims no head:\n{text}"
        );

        // A record removed from the active segment is the same verdict: the
        // record that followed it no longer follows what is left.
        std::fs::write(&rotated, &intact).unwrap();
        let active: Vec<String> = std::fs::read_to_string(&path)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect();
        std::fs::write(&path, format!("{}\n", active[1..].join("\n"))).unwrap();
        let shortened = check_audit_chain(&path).unwrap();
        assert!(shortened.failed(), "{shortened:?}");
        assert_eq!(
            shortened
                .broken
                .as_ref()
                .expect("the break is located")
                .segment,
            path
        );

        // A line that is no record at all is a different fault, reported as
        // itself rather than as a chain that does not verify.
        std::fs::write(&path, "not a record\n").unwrap();
        let error = check_audit_chain(&path).expect_err("a line that is no record is an error");
        assert!(
            format!("{error:#}").contains("audit.log"),
            "the segment is named: {error:#}"
        );
    }
}
