//! One-line progress for the in-sandbox `min` helper.
//!
//! The helper speaks a line protocol (`msg:`, `set_env:`, `error:`). A fetch
//! already records byte progress on the session [`OpTracker`], but the helper
//! can only redraw a single line, so this paints that tree as one `bar:` line
//! the helper reprints in place. An empty `bar:` tells the helper to clear the
//! row. Byte fetches win over status rows: several packages downloading at
//! once collapse into one meter.

use std::collections::{BTreeMap, HashSet};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::time::Duration;

use futures::{Stream, StreamExt as _};
use ot::{OpId, OpSnapshot, OpTracker, Operation, Progress};

/// Width of the package-name field, so the meter stays put as names change.
const NAME_WIDTH: usize = 18;
/// Cells inside the `[` `]` meter.
const BAR_WIDTH: usize = 16;
/// ~12 Hz, the same cap the SSH progress renderer uses. A fetch reports every
/// chunk; painting each one would flood the socket.
const PAINT_INTERVAL: Duration = Duration::from_millis(80);

/// Drives `bar:` lines from a session operation tree.
///
/// A missing tracker means this install has nothing to paint; [`refresh`] is a
/// no-op and the helper keeps the one-shot `msg:` lines.
///
/// [`refresh`]: SandboxProgress::refresh
pub(crate) struct SandboxProgress {
    tracker: Option<OpTracker>,
    /// Package names this run builds. The tracker is the whole session's, so a
    /// task building in another shell reports into it too; `None` shows every
    /// package row.
    scope: Option<HashSet<String>>,
    /// Every fetch seen during this run, finished ones included, so the meter
    /// totals never shrink when one download of several completes.
    fetches: BTreeMap<OpId, Fetch>,
    /// Last line written, so an unchanged tree does not repaint.
    last: Option<String>,
}

impl SandboxProgress {
    pub(crate) fn new(tracker: Option<OpTracker>, scope: Option<HashSet<String>>) -> Self {
        Self {
            tracker,
            scope,
            fetches: BTreeMap::new(),
            last: None,
        }
    }

    /// Writes a `bar:` line when the visible text changed; an empty one when
    /// the meter went away, so the helper clears the row.
    ///
    /// A client that has gone away must not fail the install the bar is
    /// describing; the download still completes.
    pub(crate) fn refresh(&mut self, stream: &mut UnixStream) {
        let Some(tracker) = &self.tracker else {
            return;
        };
        let line = self.line(&tracker.snapshot());
        if line == self.last {
            return;
        }
        let _ = writeln!(stream, "bar:{}", line.as_deref().unwrap_or(""));
        self.last = line;
    }

    /// Writes a `msg:` line. The helper clears the meter to print it, so the
    /// next [`refresh`] repaints even when the meter has not moved.
    ///
    /// [`refresh`]: SandboxProgress::refresh
    pub(crate) fn message(&mut self, stream: &mut UnixStream, text: &str) {
        let _ = writeln!(stream, "msg:{text}");
        self.last = None;
    }

    /// The single line to show for `snapshot`, or `None` when nothing relevant
    /// is in flight. Check and test rows are omitted so a concurrent
    /// `min check` does not take over an add's meter.
    fn line(&mut self, snapshot: &[OpSnapshot]) -> Option<String> {
        let mut live = HashSet::new();
        let mut statuses = Vec::new();
        for row in snapshot {
            let Some(op) = &row.op else { continue };
            let Progress { pos, len } = row.progress.unwrap_or(Progress { pos: 0, len: None });
            match self.activity(op) {
                Some(Activity::Fetch(name)) => {
                    live.insert(row.id);
                    self.fetches.insert(
                        row.id,
                        Fetch {
                            name,
                            pos,
                            len,
                            live: true,
                        },
                    );
                }
                Some(Activity::Status(status)) => statuses.push(status),
                None => {}
            }
        }
        // A fetch no longer reporting (its row dropped, or moved on to
        // extracting) is finished: count it as complete.
        for (id, fetch) in &mut self.fetches {
            if fetch.live && !live.contains(id) {
                fetch.live = false;
                if let Some(len) = fetch.len {
                    fetch.pos = len;
                }
            }
        }

        if !live.is_empty() {
            return Some(format_fetches(self.fetches.values()));
        }
        if statuses.is_empty() {
            return None;
        }
        Some(truncate(&statuses.join(", "), 60))
    }

    fn activity(&self, op: &Operation) -> Option<Activity> {
        let in_scope = |name: &str| self.scope.as_ref().is_none_or(|s| s.contains(name));
        match op {
            Operation::FetchPkg { name } if in_scope(name) => Some(Activity::Fetch(name.clone())),
            // Neither names a package, so neither can be scoped; both are
            // rare mid-install and belong to whatever is building.
            Operation::FetchSource { url } => Some(Activity::Fetch(url.clone())),
            Operation::FetchIndex => Some(Activity::Fetch("index".to_string())),
            Operation::ExtractPkg { name } if in_scope(name) => {
                Some(Activity::Status(format!("Extract {name}")))
            }
            Operation::PackageBuild { name } if in_scope(name) => {
                Some(Activity::Status(format!("Building {name}")))
            }
            Operation::CompressPkg { name } if in_scope(name) => {
                Some(Activity::Status(format!("Compress {name}")))
            }
            Operation::CollectOutputs { name, .. } if in_scope(name) => {
                Some(Activity::Status(format!("Collect {name}")))
            }
            _ => None,
        }
    }
}

/// Relays `events` to the helper through `on_event` until the stream ends,
/// painting the meter between them, then clears it.
pub(crate) async fn relay<T>(
    stream: &mut UnixStream,
    mut progress: SandboxProgress,
    mut events: impl Stream<Item = T> + Unpin,
    mut on_event: impl FnMut(T, &mut SandboxProgress, &mut UnixStream),
) {
    let mut tick = tokio::time::interval(PAINT_INTERVAL);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` is ready immediately. Consume that tick so the first paint
    // waits until a fetch has had a chance to report progress.
    tick.tick().await;

    loop {
        tokio::select! {
            biased;
            event = events.next() => {
                let Some(event) = event else { break };
                on_event(event, &mut progress, stream);
            }
            _ = tick.tick() => progress.refresh(stream),
        }
    }
    progress.refresh(stream);
}

struct Fetch {
    name: String,
    pos: u64,
    len: Option<u64>,
    live: bool,
}

enum Activity {
    Fetch(String),
    Status(String),
}

/// Names the live fetches; sizes cover every fetch this run has seen.
fn format_fetches<'a>(fetches: impl Iterator<Item = &'a Fetch> + Clone) -> String {
    let names = fetches
        .clone()
        .filter(|fetch| fetch.live)
        .map(|fetch| fetch.name.as_str())
        .collect::<Vec<_>>();
    let names = pad(&truncate(&join_names(&names), NAME_WIDTH), NAME_WIDTH);
    let pos = fetches
        .clone()
        .fold(0u64, |acc, fetch| acc.saturating_add(fetch.pos));
    // A missing length on any fetch means the total is unknown. A reported
    // length of zero (chunked transfer, no Content-Length) is the same: a
    // meter drawn against it would sit empty while bytes still arrive.
    let len = fetches
        .clone()
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

    fn line(root: &OpTracker) -> Option<String> {
        SandboxProgress::new(None, None).line(&root.snapshot())
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

        let line = line(&root).expect("a fetch is visible");
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

        let line = line(&root).expect("a fetch is visible");
        assert!(line.contains("[================]"), "{line}");
    }

    #[test]
    fn concurrent_fetches_share_one_meter() {
        let root = OpTracker::new_root();
        let _go = fetch(&root, "go", 1024, 512);
        let _gcc = fetch(&root, "gcc", 1024, 512);

        let line = line(&root).expect("fetches are visible");
        assert!(line.contains("go, gcc"), "{line}");
        // 1024/2048 is half of the 16-cell meter: seven fills, a head, eight blanks.
        assert!(line.contains("[=======>        ]"), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(line.contains("2.00 KiB"), "{line}");
    }

    #[test]
    fn a_completed_fetch_keeps_counting_toward_the_total() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let small = fetch(&root, "sqlite", 1024, 512);
        let _big = fetch(&root, "llvm", 3072, 1024);
        let before = progress
            .line(&root.snapshot())
            .expect("fetches are visible");
        assert!(before.contains("1.50 KiB"), "{before}");
        assert!(before.contains("4.00 KiB"), "{before}");

        // sqlite finishes: it leaves the name list, but its bytes stay in the
        // totals, so the meter moves forward instead of jumping back.
        drop(small);
        let after = progress.line(&root.snapshot()).expect("llvm is live");
        assert!(after.starts_with("Fetch llvm "), "{after}");
        assert!(!after.contains("sqlite"), "{after}");
        assert!(after.contains("2.00 KiB"), "{after}");
        assert!(after.contains("4.00 KiB"), "{after}");
    }

    #[test]
    fn a_fetch_moving_on_to_extract_counts_as_complete() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let go = fetch(&root, "go", 1024, 100);
        let _gcc = fetch(&root, "gcc", 1024, 0);
        progress.line(&root.snapshot());

        go.set_op(Operation::ExtractPkg {
            name: "go".to_string(),
        });
        let line = progress.line(&root.snapshot()).expect("gcc is live");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(line.contains("2.00 KiB"), "{line}");
    }

    #[test]
    fn a_third_fetch_collapses_to_a_count() {
        let root = OpTracker::new_root();
        let _a = fetch(&root, "go", 100, 0);
        let _b = fetch(&root, "gcc", 100, 0);
        let _c = fetch(&root, "binutils", 100, 0);

        let line = line(&root).expect("fetches are visible");
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

        let line = line(&root).expect("a fetch is visible");
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

        assert_eq!(line(&root).as_deref(), Some("Extract go"));
    }

    #[test]
    fn a_live_fetch_hides_the_extract_status() {
        let root = OpTracker::new_root();
        let _extract = root.new_child().with_op(Operation::ExtractPkg {
            name: "gcc".to_string(),
        });
        let _go = fetch(&root, "go", 1024, 0);

        let line = line(&root).expect("a fetch is visible");
        assert!(line.starts_with("Fetch go"), "{line}");
        assert!(!line.contains("Extract"), "{line}");
    }

    #[test]
    fn a_cleared_tree_has_nothing_to_paint() {
        let root = OpTracker::new_root();
        let op = fetch(&root, "go", 1024, 1024);
        op.set_done();

        assert_eq!(line(&root), None);
    }

    #[test]
    fn packages_outside_the_scope_are_not_shown() {
        let root = OpTracker::new_root();
        let scope = HashSet::from(["go".to_string()]);
        let mut progress = SandboxProgress::new(None, Some(scope));
        let _other = fetch(&root, "llvm", 4096, 2048);
        let _build = root.new_child().with_op(Operation::PackageBuild {
            name: "llvm".to_string(),
        });
        assert_eq!(progress.line(&root.snapshot()), None);

        let _go = fetch(&root, "go", 1024, 256);
        let line = progress.line(&root.snapshot()).expect("go is in scope");
        assert!(line.starts_with("Fetch go "), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(!line.contains("4.00 KiB"), "{line}");
    }

    #[test]
    fn refresh_writes_a_bar_line_once_until_the_meter_moves() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(Some(root.clone()), None);

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
    fn refresh_clears_the_bar_when_the_fetch_ends() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(Some(root.clone()), None);

        let op = fetch(&root, "go", 1024, 256);
        progress.refresh(&mut ours);
        drop(op);
        progress.refresh(&mut ours);
        progress.refresh(&mut ours);
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(lines[0].starts_with("bar:Fetch go"), "{lines:?}");
        assert_eq!(lines[1], "bar:", "{lines:?}");
    }

    #[test]
    fn a_message_forces_the_next_repaint() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(Some(root.clone()), None);

        let _extract = root.new_child().with_op(Operation::ExtractPkg {
            name: "go".to_string(),
        });
        progress.refresh(&mut ours);
        progress.message(&mut ours, "building gcc");
        progress.refresh(&mut ours);
        drop(ours);

        assert_eq!(
            read_lines(&theirs),
            ["bar:Extract go", "msg:building gcc", "bar:Extract go"]
        );
    }

    #[test]
    fn refresh_without_a_tracker_writes_nothing() {
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let mut progress = SandboxProgress::new(None, None);
        progress.refresh(&mut ours);
        drop(ours);
        assert!(read_lines(&theirs).is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn relay_forwards_events_and_clears_the_meter_at_the_end() {
        let root = OpTracker::new_root();
        let (mut ours, theirs) = UnixStream::pair().expect("socket pair");
        let progress = SandboxProgress::new(Some(root.clone()), None);
        let op = fetch(&root, "go", 1024, 256);

        let (tx, rx) = futures::channel::mpsc::unbounded();
        tx.unbounded_send("fetching go").expect("receiver is live");
        let feed = async {
            tokio::time::sleep(PAINT_INTERVAL * 2).await;
            drop(op);
            drop(tx);
        };
        let run = relay(&mut ours, progress, rx, |text, progress, stream| {
            progress.message(stream, text)
        });
        tokio::join!(run, feed);
        drop(ours);

        let lines = read_lines(&theirs);
        assert_eq!(lines.first().map(String::as_str), Some("msg:fetching go"));
        assert!(lines[1].starts_with("bar:Fetch go"), "{lines:?}");
        assert_eq!(lines.last().map(String::as_str), Some("bar:"), "{lines:?}");
    }
}
