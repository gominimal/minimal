//! Indicatif renderer for the operation tree.
//!
//! A thin shim that *observes* the render-agnostic state core
//! ([`crate::OpTracker`]) and draws it with `indicatif` progress bars. It owns
//! all styling — the core stores only semantic [`Operation`]s and numeric
//! [`Progress`](crate::Progress) — so a future renderer (e.g. the daemon's
//! per-channel ANSI path, or `strides`) can replace it without touching the
//! core. This is the legacy single-terminal CLI path.
//!
//! The shim runs as a Tokio task: it waits on [`OpTracker::changed`], takes a
//! [`OpTracker::snapshot`], and reconciles a set of live `ProgressBar`s against
//! it. See `docs/specs/04-spec-ot-render-decoupling`.

use std::collections::{HashMap, HashSet};
use std::io;
use std::mem::Discriminant;
use std::sync::OnceLock;
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

use crate::{OpId, OpSnapshot, OpTracker, Operation};

/// The process-global `MultiProgress` representing the single CLI terminal,
/// shared by the renderer and [`StdoutWriter`] so plain stdout writes can
/// suspend bar drawing.
static MP: OnceLock<MultiProgress> = OnceLock::new();

fn global_progress() -> MultiProgress {
    MP.get_or_init(MultiProgress::new).clone()
}

/// Spawns an indicatif renderer that draws `root`'s operation tree to stderr,
/// onto the same `MultiProgress` that [`StdoutWriter`] suspends.
///
/// Call once per process: the CLI owns a single terminal and a single root.
/// Must be called from within a Tokio runtime (the CLI `main`s are
/// `#[tokio::main]`).
pub fn render_to_stderr(root: OpTracker) {
    tokio::spawn(IndicatifShim::new(global_progress()).run(root));
}

/// Observes an [`OpTracker`] tree and renders it as a stack of `indicatif`
/// progress bars.
pub struct IndicatifShim {
    mp: MultiProgress,
    bars: HashMap<OpId, Bar>,
}

/// A live progress bar plus the [`Operation`] variant it was built for, so a
/// change of operation type on the same node rebuilds the bar.
struct Bar {
    pg: ProgressBar,
    kind: Discriminant<Operation>,
}

impl IndicatifShim {
    /// Creates a shim that draws onto `mp`.
    pub fn new(mp: MultiProgress) -> Self {
        Self {
            mp,
            bars: HashMap::new(),
        }
    }

    /// Drives the renderer until `root` is dropped: render the current state,
    /// then repaint on each change. Intended to be `tokio::spawn`ed.
    pub async fn run(mut self, root: OpTracker) {
        let mut last = root.version();
        self.reconcile(&root.snapshot());
        loop {
            root.changed().await;
            let v = root.version();
            if v == last {
                continue;
            }
            last = v;
            self.reconcile(&root.snapshot());
        }
    }

    /// Brings the live bars in line with `snap`: create bars for newly active
    /// operations, update messages/positions, rebuild on operation-type change,
    /// and clear bars whose operation has finished or whose node is gone. New
    /// bars are positioned to preserve the snapshot's pre-order.
    fn reconcile(&mut self, snap: &[OpSnapshot]) {
        let mut seen: HashSet<OpId> = HashSet::with_capacity(snap.len());
        let mut prev: Option<ProgressBar> = None;

        for row in snap {
            let Some(op) = &row.op else {
                // A node with no active operation draws nothing and does not
                // anchor positioning.
                continue;
            };
            seen.insert(row.id);
            let kind = std::mem::discriminant(op);

            let pg = match self.bars.get(&row.id) {
                Some(existing) if existing.kind == kind => {
                    // Same operation: refresh dynamic text and progress.
                    existing.pg.set_message(op_message(op));
                    apply_progress(&existing.pg, row);
                    existing.pg.clone()
                }
                other => {
                    // New node, or the operation type changed: (re)build a bar.
                    if let Some(stale) = other {
                        stale.pg.finish_and_clear();
                    }
                    let pg = match &prev {
                        Some(after) => self.mp.insert_after(after, make_bar(op, row.depth)),
                        None => self.mp.insert(0, make_bar(op, row.depth)),
                    };
                    apply_progress(&pg, row);
                    self.bars.insert(
                        row.id,
                        Bar {
                            pg: pg.clone(),
                            kind,
                        },
                    );
                    pg
                }
            };
            prev = Some(pg);
        }

        // Drop bars for operations that completed or nodes that disappeared.
        self.bars.retain(|id, bar| {
            let keep = seen.contains(id);
            if !keep {
                bar.pg.finish_and_clear();
            }
            keep
        });
    }
}

/// Pushes a node's numeric progress onto its bar (length first so the position
/// is interpreted against the right total).
fn apply_progress(pg: &ProgressBar, row: &OpSnapshot) {
    if let Some(p) = row.progress {
        if let Some(len) = p.len {
            pg.set_length(len);
        }
        pg.set_position(p.pos);
    }
}

/// Builds a styled, hidden progress bar for `op`, indented by tree `depth`.
fn make_bar(op: &Operation, depth: usize) -> ProgressBar {
    let pg = ProgressBar::hidden().with_style(op_style(op));
    pg.set_message(op_message(op));
    if let Some(tick) = op_tick(op) {
        pg.enable_steady_tick(tick);
    }
    // Top-level operations (depth 1) are flush-left; deeper nodes are indented.
    if depth > 1 {
        pg.set_prefix(format!("{}{}", "  ".repeat((depth - 1) * 2), "↳ "));
    }
    pg
}

/// The bar style for each operation variant.
fn op_style(op: &Operation) -> ProgressStyle {
    let template = match op {
        Operation::PackageBuild { .. } => "{prefix}{spinner} Building package: {msg}",
        Operation::CollectOutputs { .. } => "{prefix}{spinner} Collect outputs for {msg}",
        Operation::ExtractPkg { .. } => "{prefix}{spinner} Extract: {msg}",
        Operation::CompressPkg { .. } => "{prefix}{spinner} Compress: {msg}",
        Operation::Check { .. } => "{prefix}{spinner} Checking: {msg}",
        Operation::StandaloneTest { .. } => "{prefix}{spinner} Test: {msg}",
        Operation::FetchPkg { .. } => {
            "{prefix}Fetch: {msg:35!} [{wide_bar}]     {decimal_bytes:9!} / {decimal_total_bytes:9!}   ETA: {eta:5!}"
        }
        Operation::FetchIndex => {
            "{prefix}Update remote index  {msg:35!} [{wide_bar}]     {decimal_bytes:9!} / {decimal_total_bytes:9!}   ETA: {eta:5!}"
        }
        Operation::FetchSource { .. } => {
            "{prefix}Fetch source: {msg:35!} [{wide_bar}]     {decimal_bytes:9!} / {decimal_total_bytes:9!}   ETA: {eta:5!}"
        }
    };
    let style = ProgressStyle::with_template(template).expect("static template is valid");
    // The byte-oriented fetch bars use a custom fill.
    match op {
        Operation::FetchPkg { .. } | Operation::FetchIndex | Operation::FetchSource { .. } => {
            style.progress_chars("=> ")
        }
        _ => style,
    }
}

/// The steady-tick interval for spinner-style operations; `None` for the
/// byte-progress fetch bars, which advance via [`apply_progress`].
fn op_tick(op: &Operation) -> Option<Duration> {
    let ms = match op {
        Operation::PackageBuild { .. } | Operation::Check { .. } => 100,
        Operation::CompressPkg { .. } => 80,
        Operation::CollectOutputs { .. }
        | Operation::ExtractPkg { .. }
        | Operation::StandaloneTest { .. } => 50,
        Operation::FetchPkg { .. } | Operation::FetchIndex | Operation::FetchSource { .. } => {
            return None;
        }
    };
    Some(Duration::from_millis(ms))
}

/// The bar message (the `{msg}` field) for an operation.
fn op_message(op: &Operation) -> String {
    match op {
        Operation::PackageBuild { name }
        | Operation::ExtractPkg { name }
        | Operation::CompressPkg { name }
        | Operation::FetchPkg { name }
        | Operation::StandaloneTest { name } => name.clone(),
        Operation::FetchSource { url } => url.clone(),
        Operation::FetchIndex => String::new(),
        Operation::Check { kind, name } => format!("{kind} {name}"),
        Operation::CollectOutputs { name, outputs } => {
            let joined = outputs.join(" ");
            let shown = match joined.char_indices().nth(30) {
                Some((idx, _)) => format!("{}...", &joined[..idx]),
                None => joined,
            };
            format!("{name}: {shown}")
        }
    }
}

/// A writer to stdout which coordinates with progress-bar drawing by
/// suspending the shared [`MultiProgress`] for the duration of each write.
pub struct StdoutWriter(MultiProgress);

impl Default for StdoutWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl StdoutWriter {
    pub fn new() -> Self {
        StdoutWriter(global_progress())
    }
}

impl io::Write for StdoutWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.suspend(|| io::stdout().write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.suspend(|| io::stdout().flush())
    }

    fn write_vectored(&mut self, bufs: &[io::IoSlice<'_>]) -> io::Result<usize> {
        self.0.suspend(|| io::stdout().write_vectored(bufs))
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.suspend(|| io::stdout().write_all(buf))
    }

    fn write_fmt(&mut self, fmt: std::fmt::Arguments<'_>) -> io::Result<()> {
        self.0.suspend(|| io::stdout().write_fmt(fmt))
    }
}

#[cfg(test)]
mod tests {
    use indicatif::ProgressDrawTarget;

    use super::*;
    use crate::CheckKind;

    // A shim whose bars draw nowhere, so reconcile logic can be exercised
    // without touching a terminal.
    fn hidden_shim() -> IndicatifShim {
        IndicatifShim::new(MultiProgress::with_draw_target(ProgressDrawTarget::hidden()))
    }

    #[test]
    fn reconcile_tracks_active_operations() {
        let root = OpTracker::new_root();
        let a = root.new_child();
        a.set_op(Operation::PackageBuild { name: "a".into() });
        let b = root.new_child();
        b.set_op(Operation::FetchPkg { name: "b".into() });

        let mut shim = hidden_shim();
        shim.reconcile(&root.snapshot());
        assert_eq!(shim.bars.len(), 2);

        // Completing one operation drops its bar on the next reconcile; the
        // other survives.
        a.set_done();
        shim.reconcile(&root.snapshot());
        assert_eq!(shim.bars.len(), 1);
    }

    #[test]
    fn reconcile_is_stable_across_repeated_snapshots() {
        let root = OpTracker::new_root();
        let n = root.new_child();
        n.set_op(Operation::Check {
            kind: CheckKind::CheckPackages,
            name: "p".into(),
        });

        let mut shim = hidden_shim();
        shim.reconcile(&root.snapshot());
        let id = *shim.bars.keys().next().unwrap();
        // A no-op reconcile must keep the same bar (no churn / re-create).
        shim.reconcile(&root.snapshot());
        assert_eq!(shim.bars.len(), 1);
        assert!(shim.bars.contains_key(&id));
    }

    #[test]
    fn reconcile_rebuilds_bar_when_operation_kind_changes() {
        let root = OpTracker::new_root();
        let n = root.new_child();
        n.set_op(Operation::PackageBuild { name: "p".into() });

        let mut shim = hidden_shim();
        shim.reconcile(&root.snapshot());
        let kind_before = shim.bars.values().next().unwrap().kind;

        n.set_op(Operation::CollectOutputs {
            name: "p".into(),
            outputs: vec!["o".into()],
        });
        shim.reconcile(&root.snapshot());

        assert_eq!(shim.bars.len(), 1);
        let kind_after = shim.bars.values().next().unwrap().kind;
        assert_ne!(kind_before, kind_after, "bar should be rebuilt for new op");
    }
}
