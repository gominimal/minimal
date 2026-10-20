//! `min box audit`: read one box's audit trail from the local Box Egress
//! Proxy's log (BEP-042).
//!
//! The grammar is `min box audit <box|self> | --parent <box|self>
//! [-o jsonl] [--follow]`. A box id reads the records whose subject is that
//! id, a removed box included, because the log is the proxy's and `rm` and
//! `prune` never touch it. A name is an alias, never the identity: it reads
//! the live box of that name, else the newest creation under it, and the
//! command names the id it read. `--parent` merges the records of every
//! child of a box onto one stream. `--follow` replays and then tails.
//! `self` is refused on a host that is not enrolled.
//!
//! [`resolve`], [`children`] and [`render`] are pure. [`follow`] takes its
//! wait step as a closure. [`cmd_box_audit`] gathers the boxes this host
//! knows from the daemon's listing.

use std::collections::BTreeSet;
use std::path::Path;

use anyhow::Context as _;
use bep::audit::{Entry, LogReader};

use crate::{BoxAuditArgs, BoxAuditOutputFormat, GlobalArgs, client};

/// The defined error code for `self` on a host that is not enrolled.
pub(crate) const AUDIT_SELF_UNSUPPORTED_UNENROLLED: &str = "audit_self_unsupported_unenrolled";

/// The environment variable the daemon sets in every box shell.
const IN_BOX_ENV: &str = "MINIMAL_SESSION_NAME";

/// How long `--follow` waits between two reads of the log.
const FOLLOW_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);

/// `min box audit self` inside a box, on a host that is not enrolled.
#[derive(Debug)]
pub(crate) struct AuditSelfUnsupportedUnenrolled;

impl std::fmt::Display for AuditSelfUnsupportedUnenrolled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(
            "Reading your own audit trail from inside a box needs a Gatehouse. \
             On the host, run `min box audit <box>`.",
        )
    }
}

impl std::error::Error for AuditSelfUnsupportedUnenrolled {}

impl AuditSelfUnsupportedUnenrolled {
    /// The defined error code a script can branch on.
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "the machine-output error object reads it once `-o jsonl` errors are wired"
        )
    )]
    pub(crate) const fn code(&self) -> &'static str {
        AUDIT_SELF_UNSUPPORTED_UNENROLLED
    }
}

/// One box this host knows, as the listing gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KnownBox {
    /// The box id, the audit subject. A UUIDv7 sorts in creation order.
    pub id: boxes::SessionId,
    /// The friendly name, when the box has one.
    pub name: Option<String>,
    /// Whether the box is live.
    pub live: bool,
    /// The box this box is a child of, when it has one.
    pub parent: Option<boxes::SessionId>,
}

/// The box a target names, and how the command found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Resolved {
    /// The target was a box id.
    Id(String),
    /// The target was a name, and this is the id it read.
    Name { name: String, id: String },
}

impl Resolved {
    /// The audit subject.
    pub(crate) fn id(&self) -> &str {
        match self {
            Self::Id(id) | Self::Name { id, .. } => id,
        }
    }
}

/// Resolves `target` to one box id. `in_box` says whether the command runs
/// inside a box. No host is enrolled today, so `self` is always refused.
pub(crate) fn resolve(target: &str, known: &[KnownBox], in_box: bool) -> anyhow::Result<Resolved> {
    if target == "self" {
        if in_box {
            return Err(AuditSelfUnsupportedUnenrolled.into());
        }
        anyhow::bail!(
            "`self` names the box this command runs in, and this shell is not inside a box. \
             Run `min box audit <box>` with a box id or name."
        );
    }
    if let Ok(id) = boxes::SessionId::parse_str(target) {
        return Ok(Resolved::Id(id.to_string()));
    }
    let named = known
        .iter()
        .filter(|candidate| candidate.name.as_deref() == Some(target));
    // The live box, else the newest creation: a UUIDv7 sorts by time.
    let chosen = named
        .clone()
        .filter(|candidate| candidate.live)
        .max_by_key(|candidate| candidate.id)
        .or_else(|| named.max_by_key(|candidate| candidate.id));
    match chosen {
        Some(found) => Ok(Resolved::Name {
            name: target.to_owned(),
            id: found.id.to_string(),
        }),
        None => anyhow::bail!(
            "No box on this host is named `{target}`. \
             Run `min ls` to see the boxes, or run `min box audit <box-id>` for a removed box."
        ),
    }
}

/// The ids of every child of `parent` that this host knows.
pub(crate) fn children(parent: &str, known: &[KnownBox]) -> BTreeSet<String> {
    known
        .iter()
        .filter(|candidate| candidate.parent.is_some_and(|p| p.to_string() == parent))
        .map(|candidate| candidate.id.to_string())
        .collect()
}

/// Writes the entries whose subject is in `subjects`, and returns how many
/// it wrote. `name_box` puts the subject at the start of each text line.
pub(crate) fn render(
    entries: &[Entry],
    subjects: &BTreeSet<String>,
    output: Option<BoxAuditOutputFormat>,
    name_box: bool,
    out: &mut dyn std::io::Write,
) -> std::io::Result<usize> {
    let mut written = 0;
    for entry in entries
        .iter()
        .filter(|entry| subjects.contains(&entry.record.subject))
    {
        let record = &entry.record;
        match output {
            Some(BoxAuditOutputFormat::Jsonl) => writeln!(out, "{}", entry.line)?,
            None => {
                if name_box {
                    write!(out, "{}  ", record.subject)?;
                }
                let kind = match record.kind {
                    bep::audit::Kind::Decision => "decision",
                    bep::audit::Kind::Mint => "mint",
                    bep::audit::Kind::Revocation => "revocation",
                };
                let decision = match record.decision {
                    bep::audit::Outcome::Admit => "admit",
                    bep::audit::Outcome::Refuse => "refuse",
                };
                write!(
                    out,
                    "{kind}  {decision}  {}  {}  {} {}",
                    record.upstream, record.identifier, record.resource, record.permission
                )?;
                if let Some(marker) = &record.marker {
                    write!(out, "  {marker}")?;
                }
                writeln!(out)?;
            }
        }
        written += 1;
    }
    Ok(written)
}

/// Reads what is new in the log and writes the matching records. One debug
/// line names the boxes and the segments read.
fn read_and_render(
    reader: &mut LogReader,
    subjects: &BTreeSet<String>,
    output: Option<BoxAuditOutputFormat>,
    name_box: bool,
    out: &mut dyn std::io::Write,
) -> anyhow::Result<usize> {
    let batch = reader
        .read_new()
        .with_context(|| format!("failed to read the audit log in {}", reader.dir().display()))?;
    tracing::debug!(
        box_ids = ?subjects,
        segments = ?batch.segments,
        records = batch.entries.len(),
        skipped = batch.skipped,
        "read the audit log"
    );
    let written = render(&batch.entries, subjects, output, name_box, out)?;
    out.flush()?;
    Ok(written)
}

/// Replays the records for `subjects`, then tails new ones. `wait` runs
/// between two reads, and the loop ends when it returns `false`.
pub(crate) fn follow(
    reader: &mut LogReader,
    subjects: &BTreeSet<String>,
    output: Option<BoxAuditOutputFormat>,
    name_box: bool,
    out: &mut dyn std::io::Write,
    mut wait: impl FnMut() -> bool,
) -> anyhow::Result<()> {
    loop {
        read_and_render(reader, subjects, output, name_box, out)?;
        if !wait() {
            return Ok(());
        }
    }
}

/// The boxes the daemon lists. The listing carries no parent, so no box
/// has a known child yet.
async fn known_boxes(global: &GlobalArgs) -> anyhow::Result<Vec<KnownBox>> {
    super::ensure_daemon(global)?;
    let sock = client::resolve_socket_path(global.minimal_dir.as_deref(), global.use_minvmd())
        .context("Failed to resolve daemon socket path")?;
    let mut client = client::Client::connect(&sock)
        .await
        .context("Failed to connect to minimald")?;
    let listed = super::list_sessions_version_gated(&mut client).await?;
    Ok(listed
        .sessions
        .into_iter()
        .map(|entry| KnownBox {
            id: entry.id,
            name: entry.name,
            live: entry.status == boxes::BoxState::Active,
            parent: None,
        })
        .collect())
}

/// The work of `min box audit`, over the log in `dir` and the boxes in
/// `known`. Messages go to `err`, records to `out`.
pub(crate) fn run(
    args: &BoxAuditArgs,
    known: &[KnownBox],
    in_box: bool,
    dir: &Path,
    out: &mut dyn std::io::Write,
    err: &mut dyn std::io::Write,
    wait: impl FnMut() -> bool,
) -> anyhow::Result<()> {
    let (resolved, subjects, name_box) = match (&args.target, &args.parent) {
        (_, Some(parent)) => {
            let resolved = resolve(parent, known, in_box)?;
            let subjects = children(resolved.id(), known);
            (resolved, subjects, true)
        }
        (Some(target), None) => {
            let resolved = resolve(target, known, in_box)?;
            let subjects = BTreeSet::from([resolved.id().to_owned()]);
            (resolved, subjects, false)
        }
        (None, None) => anyhow::bail!("Name a box: run `min box audit <box>`."),
    };
    if let Resolved::Name { name, id } = &resolved {
        writeln!(err, "Showing {name} (box {id}).")?;
    }
    if args.parent.is_some() && subjects.is_empty() {
        writeln!(err, "Box {} has no child boxes.", resolved.id())?;
    }
    let mut reader = LogReader::new(dir);
    if args.follow {
        return follow(&mut reader, &subjects, args.output, name_box, out, wait);
    }
    let written = read_and_render(&mut reader, &subjects, args.output, name_box, out)?;
    if written == 0 && !subjects.is_empty() {
        writeln!(
            err,
            "The proxy has no audit records for box {}.",
            resolved.id()
        )?;
    }
    Ok(())
}

/// `min box audit`.
pub(crate) async fn cmd_box_audit(global: &GlobalArgs, args: BoxAuditArgs) -> anyhow::Result<()> {
    let in_box = std::env::var_os(IN_BOX_ENV).is_some();
    let names_a_box = |value: &Option<String>| {
        value
            .as_deref()
            .is_some_and(|v| v != "self" && boxes::SessionId::parse_str(v).is_err())
    };
    // Only a name needs the daemon's listing, and `--parent` needs it to
    // find the children.
    let known = if names_a_box(&args.target) || args.parent.is_some() {
        known_boxes(global).await?
    } else {
        Vec::new()
    };
    let dir = bep::audit::default_dir()
        .context("cannot find the home directory, so the audit log cannot be found")?;
    let mut stdout = std::io::stdout().lock();
    let mut stderr = std::io::stderr().lock();
    run(
        &args,
        &known,
        in_box,
        &dir,
        &mut stdout,
        &mut stderr,
        || {
            std::thread::sleep(FOLLOW_INTERVAL);
            true
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bep::audit::{AuditLog, Decision, Kind, Mapping, Outcome, segment_name};

    // UUIDv7 ids: the first 48 bits are the creation time, so B sorts after A.
    const A: &str = "01920000-0000-7000-8000-000000000001";
    const B: &str = "01930000-0000-7000-8000-000000000002";
    const C: &str = "01940000-0000-7000-8000-000000000003";

    fn id(s: &str) -> boxes::SessionId {
        boxes::SessionId::parse_str(s).unwrap()
    }

    fn decision(box_id: &str, authority: &str) -> Decision {
        Decision {
            kind: Kind::Decision,
            box_id: box_id.to_owned(),
            authority: authority.to_owned(),
            identifier: None,
            mapping: Mapping::ModuleUnmapped,
            outcome: Outcome::Refuse,
            marker: Some("off_module".to_owned()),
        }
    }

    fn append(dir: &Path, segment: u64, records: &[(&str, &str)]) {
        let mut log = AuditLog::open(dir.join(segment_name(segment))).unwrap();
        for (box_id, authority) in records {
            log.append(&decision(box_id, authority)).unwrap();
        }
    }

    fn args(target: Option<&str>, parent: Option<&str>, follow: bool) -> BoxAuditArgs {
        BoxAuditArgs {
            target: target.map(str::to_owned),
            parent: parent.map(str::to_owned),
            output: None,
            follow,
        }
    }

    fn known(id_: &str, name: &str, live: bool, parent: Option<&str>) -> KnownBox {
        KnownBox {
            id: id(id_),
            name: Some(name.to_owned()),
            live,
            parent: parent.map(id),
        }
    }

    fn run_to_strings(
        args: &BoxAuditArgs,
        boxes: &[KnownBox],
        in_box: bool,
        dir: &Path,
    ) -> (anyhow::Result<()>, String, String) {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let result = run(args, boxes, in_box, dir, &mut out, &mut err, || false);
        (
            result,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }

    // BEP-042, BEP-068: one box id, across every segment, a reaped box
    // included (the box is in no listing).
    #[test]
    fn box_audit_filters_to_one_box() {
        let dir = tempfile::tempdir().unwrap();
        append(dir.path(), 1, &[(A, "a.example:443"), (B, "b.example:443")]);
        append(
            dir.path(),
            2,
            &[(A, "a2.example:443"), (C, "c.example:443")],
        );

        let (result, out, err) =
            run_to_strings(&args(Some(A), None, false), &[], false, dir.path());
        result.unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        assert!(lines[0].contains("a.example:443"), "{out}");
        assert!(lines[1].contains("a2.example:443"), "{out}");
        assert!(
            !out.contains("b.example") && !out.contains("c.example"),
            "{out}"
        );
        assert!(lines[0].starts_with("decision  refuse"), "{out}");
        assert!(err.is_empty(), "{err}");

        // -o jsonl writes the proxy's lines as they are on disk.
        let mut jsonl = args(Some(A), None, false);
        jsonl.output = Some(BoxAuditOutputFormat::Jsonl);
        let (result, out, _) = run_to_strings(&jsonl, &[], false, dir.path());
        result.unwrap();
        for line in out.lines() {
            assert!(line.starts_with('{'), "{line}");
            assert!(line.contains(&format!("\"subject\":\"{A}\"")), "{line}");
        }
        assert_eq!(out.lines().count(), 2);

        // An id with no records says so on stderr, and stdout stays empty.
        let (result, out, err) = run_to_strings(
            &args(Some("01950000-0000-7000-8000-000000000009"), None, false),
            &[],
            false,
            dir.path(),
        );
        result.unwrap();
        assert!(out.is_empty());
        assert!(err.contains("no audit records for box 01950000-"), "{err}");
    }

    // BEP-042: a name reads the live box of that name, else the newest
    // creation under it, and names the id it read.
    #[test]
    fn box_audit_name_reads_live_else_latest_creation() {
        let dir = tempfile::tempdir().unwrap();
        append(
            dir.path(),
            1,
            &[
                (A, "a.example:443"),
                (B, "b.example:443"),
                (C, "c.example:443"),
            ],
        );

        // A is live, B is newer but not live: the live box wins.
        let boxes = [
            known(A, "web", true, None),
            known(B, "web", false, None),
            known(C, "api", true, None),
        ];
        let (result, out, err) =
            run_to_strings(&args(Some("web"), None, false), &boxes, false, dir.path());
        result.unwrap();
        assert!(
            out.contains("a.example") && !out.contains("b.example"),
            "{out}"
        );
        assert_eq!(err, format!("Showing web (box {A}).\n"));

        // No live box of the name: the newest creation.
        let boxes = [known(A, "web", false, None), known(B, "web", false, None)];
        let (result, out, err) =
            run_to_strings(&args(Some("web"), None, false), &boxes, false, dir.path());
        result.unwrap();
        assert!(
            out.contains("b.example") && !out.contains("a.example"),
            "{out}"
        );
        assert_eq!(err, format!("Showing web (box {B}).\n"));

        // No box of the name: refused, with the next step.
        let (result, _, _) =
            run_to_strings(&args(Some("db"), None, false), &boxes, false, dir.path());
        let message = result.unwrap_err().to_string();
        assert!(message.contains("named `db`"), "{message}");
        assert!(message.contains("min box audit <box-id>"), "{message}");
    }

    // BEP-042: --follow replays the box's records and then tails new ones.
    #[test]
    fn box_audit_follow_replays_then_tails() {
        let dir = tempfile::tempdir().unwrap();
        append(
            dir.path(),
            1,
            &[(A, "old.example:443"), (B, "other.example:443")],
        );

        let mut reader = LogReader::new(dir.path());
        let subjects = BTreeSet::from([A.to_owned()]);
        let mut out = Vec::new();
        let mut rounds = 0;
        let path = dir.path().to_path_buf();
        follow(&mut reader, &subjects, None, false, &mut out, || {
            rounds += 1;
            match rounds {
                // The writer appends after the replay, then rotates.
                1 => append(&path, 1, &[(A, "new.example:443"), (B, "b2.example:443")]),
                2 => append(&path, 2, &[(A, "rotated.example:443")]),
                _ => return false,
            }
            true
        })
        .unwrap();
        let out = String::from_utf8(out).unwrap();
        let hosts: Vec<&str> = out
            .lines()
            .map(|line| line.split("  ").nth(2).unwrap())
            .collect();
        assert_eq!(
            hosts,
            ["old.example:443", "new.example:443", "rotated.example:443"],
            "{out}"
        );
    }

    // BEP-042: --parent merges every child's records onto one stream, each
    // naming its box.
    #[test]
    fn box_audit_parent_merges_children() {
        let dir = tempfile::tempdir().unwrap();
        append(
            dir.path(),
            1,
            &[
                (A, "parent.example:443"),
                (B, "b.example:443"),
                (C, "c.example:443"),
            ],
        );
        let boxes = [
            known(A, "web", true, None),
            known(B, "web-1", true, Some(A)),
            known(C, "web-2", false, Some(A)),
        ];
        let (result, out, err) =
            run_to_strings(&args(None, Some("web"), false), &boxes, false, dir.path());
        result.unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2, "{out}");
        assert!(
            lines[0].starts_with(B) && lines[0].contains("b.example"),
            "{out}"
        );
        assert!(
            lines[1].starts_with(C) && lines[1].contains("c.example"),
            "{out}"
        );
        assert!(!out.contains("parent.example"), "{out}");
        assert_eq!(err, format!("Showing web (box {A}).\n"));

        // A box with no children says so.
        let (result, out, err) =
            run_to_strings(&args(None, Some(B), false), &boxes, false, dir.path());
        result.unwrap();
        assert!(out.is_empty());
        assert_eq!(err, format!("Box {B} has no child boxes.\n"));
    }

    // BEP-042: un-enrolled, `self` inside a box is the defined error.
    #[test]
    fn box_audit_self_unenrolled_refused_with_error() {
        let dir = tempfile::tempdir().unwrap();
        for audit_args in [
            args(Some("self"), None, false),
            args(None, Some("self"), false),
        ] {
            let (result, out, err) = run_to_strings(&audit_args, &[], true, dir.path());
            let error = result.unwrap_err();
            let refused = error
                .downcast_ref::<AuditSelfUnsupportedUnenrolled>()
                .expect("the defined error");
            assert_eq!(refused.code(), "audit_self_unsupported_unenrolled");
            assert_eq!(
                error.to_string(),
                "Reading your own audit trail from inside a box needs a Gatehouse. \
                 On the host, run `min box audit <box>`."
            );
            assert!(out.is_empty() && err.is_empty());
        }
        // On the host, `self` names no box.
        let (result, _, _) =
            run_to_strings(&args(Some("self"), None, false), &[], false, dir.path());
        let error = result.unwrap_err();
        assert!(
            error
                .downcast_ref::<AuditSelfUnsupportedUnenrolled>()
                .is_none()
        );
        assert!(error.to_string().contains("not inside a box"), "{error}");
    }

    // The grammar: a box or --parent, never both.
    #[test]
    fn box_audit_grammar_takes_a_box_or_parent() {
        use clap::Parser as _;
        let parse = |argv: &[&str]| crate::Cli::try_parse_from(argv);
        assert!(parse(&["min", "box", "audit", "web", "-o", "jsonl", "--follow"]).is_ok());
        assert!(parse(&["min", "box", "audit", "--parent", "self"]).is_ok());
        assert!(parse(&["min", "box", "audit"]).is_err());
        assert!(parse(&["min", "box", "audit", "web", "--parent", "api"]).is_err());
    }
}
