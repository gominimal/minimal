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

use crate::net::classifier::{record_node_plane_fetch, url_host, url_object};
use futures::{Stream, StreamExt as _};
use ot::{OpId, OpSnapshot, OpStartHook, OpTracker, Operation, Progress};

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
    /// Every fetch seen since downloads last went idle, finished ones included,
    /// so the meter totals never shrink when one download of several completes.
    fetches: BTreeMap<OpId, Fetch>,
    /// NET-080: the hook recording this install's fetches as each starts;
    /// `None` records nothing, which is every progress but an install's.
    /// Dropped with the progress, so the record ends with the install.
    _fetch_hook: Option<OpStartHook>,
    /// Last line written, so an unchanged tree does not repaint.
    last: Option<String>,
}

impl SandboxProgress {
    pub(crate) fn new(tracker: Option<OpTracker>, scope: Option<HashSet<String>>) -> Self {
        Self {
            tracker,
            scope,
            fetches: BTreeMap::new(),
            _fetch_hook: None,
            last: None,
        }
    }

    /// NET-080: records each fetch this install triggers as node-plane
    /// traffic, under [`FetchRecord`]'s context — the daemon's own fetches,
    /// made for the box that asked, each named with the host it left for
    /// and the object it brought back.
    ///
    /// Recorded from the tracker's op-start hook, not the meter: the meter
    /// reads a snapshot every paint, and a fetch that starts and ends between
    /// two paints has left the tree before the next, so a record taken there
    /// would miss it. The hook sees every op the tree starts, exactly once.
    /// Without a tracker there is no fetch to see and nothing is recorded.
    pub(crate) fn with_fetch_record(mut self, record: FetchRecord) -> Self {
        if let Some(tracker) = &self.tracker {
            let scope = self.scope.clone();
            self._fetch_hook =
                Some(tracker.on_op_start(move |op| record_fetch(&record, scope.as_ref(), op)));
        }
        self
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
            // A zero length (chunked transfer, no Content-Length) is an
            // unknown one: a meter drawn against it would read full at once.
            let len = len.filter(|n| *n > 0);
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
        // extracting) is finished: count it as complete. One whose length was
        // never known is as long as what it received, so it cannot hide the
        // meter of the fetches still running beside it.
        for (id, fetch) in &mut self.fetches {
            if fetch.live && !live.contains(id) {
                fetch.live = false;
                match fetch.len {
                    Some(len) => fetch.pos = len,
                    None => fetch.len = Some(fetch.pos),
                }
            }
        }

        if !live.is_empty() {
            return Some(format_fetches(self.fetches.values()));
        }
        // No download in flight: a later fetch (after an extract or a build)
        // starts a fresh meter instead of inheriting these totals.
        self.fetches.clear();
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

/// NET-080: one node-plane record for the fetch `op` names, under the
/// [`FetchRecord`] an install was started with: the box the fetch was made
/// for, and — per operation, the same division the meter shows — the host it
/// leaves for and the object it brings back. A package or the index is
/// fetched from the configured remote cache; a source from the URL it names,
/// spelled as the record writes it — with neither the URL's credentials nor
/// its query, which never belong in a log line. Scoping is the meter's own: a
/// package outside the install's `scope` is not this install's fetch, while a
/// source or the index names no package to scope by and is attributed to
/// whatever is building, the same caveat the meter's row carries. Run from
/// the tracker's op-start hook, once per op as it starts.
fn record_fetch(record: &FetchRecord, scope: Option<&HashSet<String>>, op: &Operation) {
    let (host, object) = match op {
        Operation::FetchPkg { name } if scope.is_none_or(|s| s.contains(name)) => (
            record.cache_host.clone(),
            record
                .objects
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.clone()),
        ),
        // A source with no scheme is a tarball read off the operator's
        // own disk: it crosses no network, so it is no node-plane fetch.
        Operation::FetchSource { url } if !url.contains("://") => return,
        Operation::FetchSource { url } => (url_host(url), url_object(url)),
        Operation::FetchIndex => (record.cache_host.clone(), "index".to_owned()),
        _ => return,
    };
    record_node_plane_fetch(&record.box_id, record.leaf, &host, &object);
}

/// NET-080: the context the daemon's own fetches are recorded under — the
/// facts an install knows when it starts, spelled once so each fetch's
/// record is only the fetch's own: the box the fetch was made for, the host
/// the configured remote cache is fetched from, the object each package in
/// the install's scope is spelled as, and the leaf the daemon's own fetches
/// leave from. The record is the daemon's evidence that a fetch a box's
/// install triggered was the daemon's own node-plane traffic, never the
/// box's, so it names the box — the way the classifier tree names it, by
/// its leaf — that asked for the fetch it survived to make.
pub(crate) struct FetchRecord {
    /// The requesting box, named the way the tree names it: its leaf's own
    /// name when the host placed it in one, else the session's name.
    pub(crate) box_id: String,
    /// The leaf the daemon's own fetches are recorded as leaving from, where
    /// this daemon stands in one; `None` where it does not — the record's
    /// one fact about the host rather than the fetch, read once here so the
    /// line claims it only where it holds.
    pub(crate) leaf: Option<&'static str>,
    /// The host the daemon's cache fetches — packages and the index — leave
    /// for, spelled from the configured remote cache.
    pub(crate) cache_host: String,
    /// The object each in-scope package fetch is recorded as: its name with
    /// the upstream version appended when the graph knows one — the same
    /// spelling `min search` answers with.
    pub(crate) objects: BTreeMap<String, String>,
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
    // A missing length on a live fetch means the total is unknown (zero
    // lengths are already `None`). A total of zero is only possible for
    // finished fetches that received nothing; there is no meter to draw.
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
    fn a_finished_unknown_length_fetch_does_not_hide_the_meter() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let chunked = root.new_child().with_op(Operation::FetchPkg {
            name: "index-ish".to_string(),
        });
        chunked.increment(1024);
        let _go = fetch(&root, "go", 1024, 0);
        let before = progress
            .line(&root.snapshot())
            .expect("fetches are visible");
        assert!(!before.contains('['), "{before}");

        // Finished, it counts as the 1 KiB it received: go's meter returns.
        drop(chunked);
        let after = progress.line(&root.snapshot()).expect("go is live");
        assert!(after.contains("[=======>        ]"), "{after}");
        assert!(after.contains("2.00 KiB"), "{after}");
    }

    #[test]
    fn a_zero_length_is_unknown_and_never_counts_backwards() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let chunked = fetch(&root, "sqlite", 0, 5120);
        let _go = fetch(&root, "go", 1024, 0);

        // A zero length is not a total: no meter, just the bytes so far.
        let before = progress
            .line(&root.snapshot())
            .expect("fetches are visible");
        assert!(!before.contains('['), "{before}");
        assert!(before.contains("5.00 KiB"), "{before}");

        // Finished, its bytes stay counted rather than dropping to zero.
        drop(chunked);
        let after = progress.line(&root.snapshot()).expect("go is live");
        assert!(after.contains("5.00 KiB / "), "{after}");
        assert!(after.contains("6.00 KiB"), "{after}");
    }

    #[test]
    fn a_fetch_after_an_idle_gap_starts_a_fresh_meter() {
        let root = OpTracker::new_root();
        let mut progress = SandboxProgress::new(None, None);
        let go = fetch(&root, "go", 4096, 4096);
        progress.line(&root.snapshot());
        drop(go);
        let build = root.new_child().with_op(Operation::PackageBuild {
            name: "gcc".to_string(),
        });
        assert_eq!(
            progress.line(&root.snapshot()).as_deref(),
            Some("Building gcc")
        );
        drop(build);

        let _gcc = fetch(&root, "gcc", 1024, 0);
        let line = progress.line(&root.snapshot()).expect("gcc is live");
        assert!(line.contains("[>               ]"), "{line}");
        assert!(line.contains("1.00 KiB"), "{line}");
        assert!(!line.contains("5.00 KiB"), "{line}");
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

    /// Captures what this process writes to its log, so a test can read the
    /// NET-080 record the way a diagnostics bundle's daemon-log tail does.
    #[derive(Clone, Default)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl LogCapture {
        fn contents(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl std::io::Write for LogCapture {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for LogCapture {
        type Writer = LogCapture;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    /// One install's [`FetchRecord`]: the box the install belongs to, the leaf
    /// its daemon's fetches leave from — a daemon standing in its own leaf, so
    /// the record names it — the host its cache fetches leave for, and the
    /// object its package is recorded as.
    fn fetch_record() -> FetchRecord {
        FetchRecord {
            box_id: "a session".to_string(),
            leaf: Some(sandbox2::classifier::DAEMON_LEAF),
            cache_host: "cache.minimal.dev".to_string(),
            objects: BTreeMap::from([("jq".to_string(), "jq (version 1.7.1)".to_string())]),
        }
    }

    /// Captures this thread's log from the moment it is called.
    fn capture_log() -> (LogCapture, tracing::subscriber::DefaultGuard) {
        let log = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);
        (log, guard)
    }

    /// The node-plane records in `log`, one per line.
    fn records(log: &LogCapture) -> Vec<String> {
        log.contents()
            .lines()
            .filter(|line| line.contains("node-plane traffic"))
            .map(str::to_string)
            .collect()
    }

    /// NET-080: an install's package fetch is recorded as node-plane traffic
    /// at the seam, where the op starts — one info line naming the box the
    /// fetch was made for, the daemon's own leaf, the cache host it left
    /// for, and the package with its version. One line per fetch, whatever
    /// the repaints, none for a package outside the install's scope, and
    /// none for a fully cached add, which fetches nothing: its ops extract
    /// and build what the cache already holds.
    #[test]
    fn a_fetch_op_start_records_one_node_plane_line() {
        let root = OpTracker::new_root();
        let scope = HashSet::from(["jq".to_string()]);
        let (log, _guard) = capture_log();
        let mut progress = SandboxProgress::new(Some(root.clone()), Some(scope.clone()))
            .with_fetch_record(fetch_record());
        let _jq = fetch(&root, "jq", 1024, 128);

        let recorded = log.contents();
        let lines: Vec<&str> = recorded
            .lines()
            .filter(|line| line.contains("node-plane traffic"))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "one record per fetch, one fetch: {recorded}"
        );
        let line = lines[0];
        assert!(
            line.contains("INFO"),
            "the record is at the level a bundle's tail reads: {line}"
        );
        assert!(
            line.contains("leaf=daemon"),
            "the record names the leaf the fetch left from: {line}"
        );
        assert!(
            line.contains("box_id=a session"),
            "the record names the box the fetch was made for: {line}"
        );
        assert!(
            line.contains("host=cache.minimal.dev"),
            "the record names the configured cache host: {line}"
        );
        assert!(
            line.contains("object=jq (version 1.7.1)"),
            "the record names the package and its version: {line}"
        );

        // The meter repaints at ~12 Hz while a fetch runs; a fetch is an
        // event, not a meter, so the repaints record nothing more. Nor does
        // a package outside the install's scope: it is not this install's.
        progress.line(&root.snapshot());
        progress.line(&root.snapshot());
        let _llvm = fetch(&root, "llvm", 4096, 0);
        assert_eq!(
            records(&log).len(),
            1,
            "the fetch is recorded once, at its start"
        );

        // A fully cached add fetches nothing — extract and build ops over
        // what the cache already holds — so it records nothing.
        let cached = OpTracker::new_root();
        let (quiet, _guard) = capture_log();
        let mut cached_progress = SandboxProgress::new(Some(cached.clone()), Some(scope))
            .with_fetch_record(fetch_record());
        let _extract = cached.new_child().with_op(Operation::ExtractPkg {
            name: "jq".to_string(),
        });
        assert!(
            cached_progress.line(&cached.snapshot()).is_some(),
            "the cached add still paints its extract"
        );
        assert!(
            !quiet.contents().contains("node-plane traffic"),
            "a fully cached add emits no record: {}",
            quiet.contents()
        );
    }

    /// NET-080: each kind of fetch the daemon makes on the install path is
    /// recorded with its own host and object — a package from the configured
    /// remote cache, named with its version; the index from the same cache;
    /// a source from the host and the spelling its URL is recorded as. One
    /// line each, spelled from the op that started.
    #[test]
    fn each_fetch_kind_is_recorded_with_its_own_host_and_object() {
        let root = OpTracker::new_root();
        let (log, _guard) = capture_log();
        let _progress =
            SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());
        let _pkg = root.new_child().with_op(Operation::FetchPkg {
            name: "jq".to_string(),
        });
        let _source = root.new_child().with_op(Operation::FetchSource {
            url: "https://github.com/example/example/archive/v1.tar.gz".to_string(),
        });
        let _index = root.new_child().with_op(Operation::FetchIndex);

        let lines = records(&log);
        assert_eq!(
            lines.len(),
            3,
            "one record per fetch, three fetches: {lines:?}"
        );
        let read = |needle: &str| {
            lines
                .iter()
                .find(|line| line.contains(needle))
                .unwrap_or_else(|| panic!("a record names {needle}: {lines:?}"))
        };
        let pkg = read("object=jq (version 1.7.1)");
        assert!(
            pkg.contains("host=cache.minimal.dev"),
            "a package is fetched from the configured cache: {pkg}"
        );
        let index = read("object=index");
        assert!(
            index.contains("host=cache.minimal.dev"),
            "the index is fetched from the configured cache: {index}"
        );
        let source = read("v1.tar.gz");
        assert!(
            source.contains("host=github.com"),
            "a source is fetched from the host its URL names: {source}"
        );
        assert!(
            !source.contains("cache.minimal.dev"),
            "a source's host is its URL's, not the cache's: {source}"
        );
    }

    /// NET-080: a local source tarball — a `FetchSource` with no scheme —
    /// crosses no network, so it is never recorded as node-plane traffic.
    #[test]
    fn a_local_source_is_not_recorded_as_node_plane_traffic() {
        let root = OpTracker::new_root();
        let (log, _guard) = capture_log();
        let _progress =
            SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());
        let _source = root.new_child().with_op(Operation::FetchSource {
            url: "../tarballs/v4.tar.gz".to_string(),
        });

        let recorded = log.contents();
        assert!(
            !recorded.contains("node-plane traffic"),
            "a local source read is no network fetch: {recorded}"
        );
    }

    /// NET-080: a `FetchSource` URL that carries a credential — in its
    /// userinfo, or in a signed query — is recorded by neither. The record
    /// is an INFO line a bundle's daemon-log tail keeps on disk, so the host
    /// it names is the URL's authority minus its userinfo and the object it
    /// names is the URL's spelling minus the userinfo, the query, and the
    /// fragment; the raw URL itself never reaches the log.
    #[test]
    fn a_source_fetch_record_carries_no_credentials() {
        let root = OpTracker::new_root();
        let url = "https://ghp_deadbeef@github.com/example/example/archive/v1.tar.gz?X-Amz-Signature=deadbeef";
        let (log, _guard) = capture_log();
        let _progress =
            SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());
        let _source = root.new_child().with_op(Operation::FetchSource {
            url: url.to_string(),
        });

        let recorded = log.contents();
        let line = recorded
            .lines()
            .find(|line| line.contains("node-plane traffic"))
            .unwrap_or_else(|| panic!("the fetch is recorded: {recorded}"));
        assert!(
            line.contains("host=github.com"),
            "the record names the host the fetch left for: {line}"
        );
        assert!(
            line.contains("object=https://github.com/example/example/archive/v1.tar.gz"),
            "the record names the object as the URL minus what must not be \
             logged: {line}"
        );
        assert!(
            !line.contains("ghp_deadbeef") && !line.contains("X-Amz-Signature"),
            "neither the token nor the signature reaches the log: {line}"
        );
    }

    /// NET-080: a fetch that starts and ends between two paints — gone from
    /// the tree before the meter's next snapshot — is still recorded, once:
    /// the record is taken where the op starts, not where the meter looks.
    #[test]
    fn a_fetch_that_starts_and_ends_between_ticks_is_still_recorded() {
        let root = OpTracker::new_root();
        let (log, _guard) = capture_log();
        let mut progress =
            SandboxProgress::new(Some(root.clone()), None).with_fetch_record(fetch_record());

        let jq = root.new_child().with_op(Operation::FetchPkg {
            name: "jq".to_string(),
        });
        jq.set_done();
        drop(jq);

        let lines = records(&log);
        assert_eq!(lines.len(), 1, "one fetch, one record: {lines:?}");
        assert!(
            lines[0].contains("object=jq (version 1.7.1)"),
            "the record names the fetch that came and went: {}",
            lines[0]
        );
        // The meter never saw it, and painting now records nothing more.
        assert_eq!(progress.line(&root.snapshot()), None);
        assert_eq!(records(&log).len(), 1);
    }
}
