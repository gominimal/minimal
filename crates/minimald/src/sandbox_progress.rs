//! One-line progress for the in-sandbox `min` helper.
//!
//! The helper speaks a line protocol (`msg:`, `set_env:`, `error:`). A fetch
//! already records byte progress on the session [`OpTracker`], but the helper
//! can only redraw a single line, so this paints that tree as one `bar:` line
//! the helper reprints in place. Byte fetches win over status rows: several
//! packages downloading at once collapse into one meter.

use std::io::Write;
use std::os::unix::net::UnixStream;

use ot::{OpSnapshot, OpTracker, Operation, Progress};

/// Width of the package-name field, so the meter stays put as names change.
const NAME_WIDTH: usize = 18;
/// Cells inside the `[` `]` meter.
const BAR_WIDTH: usize = 16;

/// Drives `bar:` lines from a session operation tree.
///
/// A missing tracker means this install has nothing to paint; [`refresh`] is a
/// no-op and the helper keeps the one-shot `msg:` lines.
///
/// [`refresh`]: SandboxProgress::refresh
pub(crate) struct SandboxProgress {
    tracker: Option<OpTracker>,
    /// Last line written, so an unchanged tree does not repaint.
    last: Option<String>,
}

impl SandboxProgress {
    pub(crate) fn new(tracker: Option<OpTracker>) -> Self {
        Self {
            tracker,
            last: None,
        }
    }

    /// Writes a `bar:` line when the visible text changed.
    ///
    /// A client that has gone away must not fail the install the bar is
    /// describing; the download still completes.
    pub(crate) fn refresh(&mut self, stream: &mut UnixStream) {
        let Some(tracker) = &self.tracker else {
            return;
        };
        let line = format_bar(&tracker.snapshot());
        if line == self.last {
            return;
        }
        if let Some(line) = &line {
            let _ = writeln!(stream, "bar:{line}");
        }
        self.last = line;
    }
}

/// The single line to show for `snapshot`, or `None` when nothing relevant is
/// in flight. Check and test rows are omitted so a concurrent `min check`
/// does not take over an add's meter.
fn format_bar(snapshot: &[OpSnapshot]) -> Option<String> {
    let rows: Vec<Activity> = snapshot
        .iter()
        .filter_map(|row| row.op.as_ref().and_then(|op| activity(op, row.progress)))
        .collect();

    let fetches: Vec<&Fetch> = rows.iter().filter_map(|row| row.as_fetch()).collect();
    if !fetches.is_empty() {
        return Some(format_fetches(&fetches));
    }

    let statuses: Vec<&str> = rows.iter().filter_map(|row| row.as_status()).collect();
    if statuses.is_empty() {
        return None;
    }
    Some(truncate(&statuses.join(", "), 60))
}

struct Fetch {
    name: String,
    pos: u64,
    len: Option<u64>,
}

enum Activity {
    Fetch(Fetch),
    Status(String),
}

impl Activity {
    fn as_fetch(&self) -> Option<&Fetch> {
        match self {
            Activity::Fetch(fetch) => Some(fetch),
            Activity::Status(_) => None,
        }
    }

    fn as_status(&self) -> Option<&str> {
        match self {
            Activity::Status(status) => Some(status),
            Activity::Fetch(_) => None,
        }
    }
}

fn activity(op: &Operation, progress: Option<Progress>) -> Option<Activity> {
    let Progress { pos, len } = progress.unwrap_or(Progress { pos: 0, len: None });
    match op {
        Operation::FetchPkg { name } => Some(Activity::Fetch(Fetch {
            name: name.clone(),
            pos,
            len,
        })),
        Operation::FetchSource { url } => Some(Activity::Fetch(Fetch {
            name: url.clone(),
            pos,
            len,
        })),
        Operation::FetchIndex => Some(Activity::Fetch(Fetch {
            name: "index".to_string(),
            pos,
            len,
        })),
        Operation::ExtractPkg { name } => Some(Activity::Status(format!("Extract {name}"))),
        Operation::PackageBuild { name } => Some(Activity::Status(format!("Building {name}"))),
        Operation::CompressPkg { name } => Some(Activity::Status(format!("Compress {name}"))),
        Operation::CollectOutputs { name, .. } => Some(Activity::Status(format!("Collect {name}"))),
        Operation::Check { .. } | Operation::StandaloneTest { .. } => None,
    }
}

fn format_fetches(fetches: &[&Fetch]) -> String {
    let names = fetches
        .iter()
        .map(|fetch| fetch.name.as_str())
        .collect::<Vec<_>>();
    let names = pad(&truncate(&join_names(&names), NAME_WIDTH), NAME_WIDTH);
    let pos = fetches
        .iter()
        .fold(0u64, |acc, fetch| acc.saturating_add(fetch.pos));
    // A missing length on any fetch means the total is unknown. A reported
    // length of zero (chunked transfer, no Content-Length) is the same: a
    // meter drawn against it would sit empty while bytes still arrive.
    let len = fetches
        .iter()
        .try_fold(0u64, |acc, fetch| fetch.len.map(|n| acc.saturating_add(n)))
        .filter(|n| *n > 0);

    match len {
        Some(len) => {
            let shown = pos.min(len);
            format!(
                "Fetch {names} {} {:>10} / {:>10}",
                render_bar(shown, len),
                human_bytes(shown),
                human_bytes(len),
            )
        }
        None => format!("Fetch {names} {:>10}", human_bytes(pos)),
    }
}

/// `go`, `go, gcc`, or `go +2` once a third name would no longer fit.
fn join_names(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [a, b] => format!("{a}, {b}"),
        [a, rest @ ..] => format!("{a} +{}", rest.len()),
    }
}

fn render_bar(pos: u64, len: u64) -> String {
    let filled = ((pos as u128 * BAR_WIDTH as u128) / len as u128) as usize;
    let filled = filled.min(BAR_WIDTH);
    let body = match filled {
        0 => format!(">{}", " ".repeat(BAR_WIDTH - 1)),
        BAR_WIDTH => "=".repeat(BAR_WIDTH),
        n => format!("{}>{}", "=".repeat(n - 1), " ".repeat(BAR_WIDTH - n)),
    };
    format!("[{body}]")
}

fn human_bytes(n: u64) -> String {
    size::Size::from_bytes(n)
        .format()
        .with_style(size::Style::Abbreviated)
        .to_string()
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        s.to_string()
    } else {
        let keep = width.saturating_sub(3);
        let truncated: String = s.chars().take(keep).collect();
        format!("{truncated}...")
    }
}

fn pad(s: &str, width: usize) -> String {
    format!("{s:<width$}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

    fn fetch(root: &OpTracker, name: &str, len: u64, pos: u64) -> OpTracker {
        let op = root.new_child().with_op(Operation::FetchPkg {
            name: name.to_string(),
        });
        op.set_length(len);
        op.increment(pos);
        op
    }

    fn read_lines(stream: &UnixStream) -> Vec<String> {
        BufReader::new(stream)
            .lines()
            .collect::<Result<Vec<_>, _>>()
            .expect("peer writes utf-8 lines")
    }

    #[test]
    fn a_partial_fetch_draws_a_meter_with_sizes() {
        let root = OpTracker::new_root();
        let _go = fetch(&root, "go", 1024, 256);

        let line = format_bar(&root.snapshot()).expect("a fetch is visible");
        assert!(line.starts_with("Fetch go"), "{line}");
        assert!(line.contains("[===>            ]"), "{line}");
        assert!(line.contains("256 B"), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(!line.contains('\n'), "{line}");
    }

    #[test]
    fn a_finished_fetch_fills_the_meter() {
        let root = OpTracker::new_root();
        let _go = fetch(&root, "go", 1024, 1024);

        let line = format_bar(&root.snapshot()).expect("a fetch is visible");
        assert!(line.contains("[================]"), "{line}");
    }

    #[test]
    fn concurrent_fetches_share_one_meter() {
        let root = OpTracker::new_root();
        let _go = fetch(&root, "go", 1024, 512);
        let _gcc = fetch(&root, "gcc", 1024, 512);

        let line = format_bar(&root.snapshot()).expect("fetches are visible");
        assert!(line.contains("go, gcc"), "{line}");
        // 1024/2048 is half of the 16-cell meter: seven fills, a head, eight blanks.
        assert!(line.contains("[=======>        ]"), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(line.contains("2.00 KiB"), "{line}");
    }

    #[test]
    fn a_third_fetch_collapses_to_a_count() {
        let root = OpTracker::new_root();
        let _a = fetch(&root, "go", 100, 0);
        let _b = fetch(&root, "gcc", 100, 0);
        let _c = fetch(&root, "binutils", 100, 0);

        let line = format_bar(&root.snapshot()).expect("fetches are visible");
        assert!(line.contains("go +2"), "{line}");
        assert!(!line.contains("gcc"), "{line}");
    }

    #[test]
    fn an_unknown_length_shows_bytes_without_a_meter() {
        let root = OpTracker::new_root();
        let op = root.new_child().with_op(Operation::FetchPkg {
            name: "go".to_string(),
        });
        op.increment(2048);

        let line = format_bar(&root.snapshot()).expect("a fetch is visible");
        assert!(line.starts_with("Fetch go"), "{line}");
        assert!(!line.contains('['), "{line}");
        assert!(line.contains("2.00 KiB"), "{line}");
    }

    #[test]
    fn extract_is_a_status_line_and_a_check_is_ignored() {
        let root = OpTracker::new_root();
        let _extract = root.new_child().with_op(Operation::ExtractPkg {
            name: "go".to_string(),
        });
        let _check = root.new_child().with_op(Operation::Check {
            kind: ot::CheckKind::CheckPackages,
            name: "unrelated".to_string(),
        });

        let line = format_bar(&root.snapshot()).expect("extract is visible");
        assert_eq!(line, "Extract go");
    }

    #[test]
    fn a_live_fetch_hides_the_extract_status() {
        let root = OpTracker::new_root();
        let _extract = root.new_child().with_op(Operation::ExtractPkg {
            name: "gcc".to_string(),
        });
        let _go = fetch(&root, "go", 1024, 0);

        let line = format_bar(&root.snapshot()).expect("a fetch is visible");
        assert!(line.starts_with("Fetch go"), "{line}");
        assert!(!line.contains("Extract"), "{line}");
    }

    #[test]
    fn a_cleared_tree_has_nothing_to_paint() {
        let root = OpTracker::new_root();
        let op = fetch(&root, "go", 1024, 1024);
        op.set_done();

        assert_eq!(format_bar(&root.snapshot()), None);
    }

    #[test]
    fn refresh_writes_a_bar_line_once_until_the_meter_moves() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(Some(root.clone()));

        progress.refresh(&mut ours);
        let op = fetch(&root, "go", 1024, 256);
        progress.refresh(&mut ours);
        progress.refresh(&mut ours);
        op.increment(256);
        progress.refresh(&mut ours);
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("bar:Fetch go"), "{lines:?}");
        assert!(lines[0].contains("[===>            ]"), "{lines:?}");
        assert!(lines[1].contains("[=======>        ]"), "{lines:?}");
    }

    #[test]
    fn refresh_without_a_tracker_writes_nothing() {
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(None);
        progress.refresh(&mut ours);
        drop(ours);
        assert!(read_lines(&theirs).is_empty());
    }
}
