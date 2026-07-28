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
use std::future::Future;
use std::io;
use std::mem::Discriminant;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle, TermLike};
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;

use crate::{OpId, OpSnapshot, OpTracker, Operation};

/// Redraw rate (Hz) for the per-channel renderer. Bounds how often the full bar
/// block is repainted onto the (potentially slow) sink, regardless of how many
/// spinner ticks or state changes occur. Low enough to keep a remote link
/// uncongested, high enough that the spinner still reads as smooth motion.
const REMOTE_REFRESH_HZ: u8 = 12;

/// Begin Synchronized Update — DEC private mode 2026. A terminal that supports
/// it buffers everything until the matching [`END_SYNC_UPDATE`] and applies the
/// frame in one atomic swap, so a clear-then-redraw never shows a half-painted
/// (flickering) intermediate state. Terminals that don't recognise the mode
/// ignore it harmlessly.
const BEGIN_SYNC_UPDATE: &[u8] = b"\x1b[?2026h";
/// End Synchronized Update — see [`BEGIN_SYNC_UPDATE`].
const END_SYNC_UPDATE: &[u8] = b"\x1b[?2026l";

/// The process-global `MultiProgress` representing the single CLI terminal,
/// shared by the renderer and [`StdoutWriter`] so plain stdout writes can
/// suspend bar drawing.
static MP: OnceLock<MultiProgress> = OnceLock::new();

/// Handle to the process-global `MultiProgress` — the one [`StdoutWriter`]
/// suspends around plain stdout writes so bars and log lines don't clobber
/// each other. Callers wiring their own bars (byte-count uploads, spinners
/// for one-off phases) should [`MultiProgress::add`] them here so drawing
/// stays coordinated with the rest of the CLI.
pub fn global_progress() -> MultiProgress {
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

/// Renders `root`'s operation tree as indicatif progress bars onto an arbitrary
/// async byte sink for as long as `fut` is pending, returning `fut`'s output.
///
/// This is the render-agnostic core of the daemon's scoped progress path: it
/// takes **exclusive** use of `sink` while `fut` runs (the wrapped operation
/// must not also write to it), paints the live tree there, and on completion
/// clears the bars and flushes before returning — so the caller can hand the
/// sink (e.g. an SSH channel) back and resume writing to it. Generic over the
/// sink so it is testable against an in-memory pipe; `minimald` wraps it with a
/// `russh` channel.
///
/// `size` is `(cols, rows)` — the terminal dimensions indicatif lays bars out
/// against. Must be supplied by the caller (from the session's PTY size); there
/// is deliberately no hardcoded fallback.
///
/// Must be called from within a Tokio runtime: a background task pumps rendered
/// bytes to `sink`, and `fut` is driven on the current task.
pub async fn render_operations_while<W, F>(
    root: &OpTracker,
    sink: W,
    size: (u16, u16),
    fut: F,
) -> F::Output
where
    W: AsyncWrite + Unpin + Send + 'static,
    F: Future,
{
    // indicatif draws synchronously from its own steady-tick threads, which must
    // never block on an async write. A `TermLike` shim turns each draw into a
    // frame of ANSI bytes pushed onto this channel; the pump task owns `sink`
    // and writes the frames. Unbounded because a frame is a stateful cursor
    // sequence — dropping one mid-stream under backpressure would corrupt the
    // render — and frames are small and rate-limited by indicatif's refresh.
    let (tx, rx) = mpsc::unbounded_channel();
    let pump = tokio::spawn(pump_frames(rx, sink));

    let (cols, rows) = size;
    let term = ChannelTerm::new(cols, rows, tx);
    // `term_like` (the no-`hz` constructor) installs *no* rate limiter, so
    // indicatif redraws the whole bar block on every spinner tick *and* every
    // state mutation. Over a slow SSH link those frames pile up faster than the
    // wire can drain them, wasting bandwidth and amplifying flicker. Cap the
    // redraw rate so the spinner still animates smoothly but far fewer full
    // repaints cross the wire.
    let mp = MultiProgress::with_draw_target(ProgressDrawTarget::term_like_with_hz(
        Box::new(term),
        REMOTE_REFRESH_HZ,
    ));

    // `render_while` clears the bars on completion, then dropping the shim drops
    // the `MultiProgress` and the `ChannelTerm`, closing `tx`.
    let out = IndicatifShim::new(mp).render_while(root, fut).await;

    // `tx` is now dropped, so the pump drains the final frames (including the
    // clear) and exits; await it so every byte reaches `sink` before returning.
    let _ = pump.await;
    out
}

/// Drains rendered ANSI frames onto the sink until the renderer drops its
/// sender, flushing after each so progress appears promptly. A write error
/// (the remote went away) just ends the pump; the renderer's own teardown is
/// unaffected.
async fn pump_frames<W: AsyncWrite + Unpin>(mut rx: mpsc::UnboundedReceiver<Vec<u8>>, mut sink: W) {
    while let Some(frame) = rx.recv().await {
        if sink.write_all(&frame).await.is_err() || sink.flush().await.is_err() {
            return;
        }
    }
}

/// An indicatif [`TermLike`] that renders into ANSI byte frames instead of a
/// real terminal.
///
/// indicatif's draw calls (cursor moves, line writes, clears) are translated to
/// the equivalent escape sequences and accumulated in `buf`; a draw ends with
/// [`flush`](TermLike::flush), at which point the whole frame is sent as one
/// message — coalescing a draw into a single sink write. Newlines are emitted as
/// `\r\n` so the render is correct on a raw channel with no `ONLCR` translation
/// (mirroring the net effect indicatif relies on from a cooked TTY).
#[derive(Debug)]
struct ChannelTerm {
    cols: u16,
    rows: u16,
    tx: mpsc::UnboundedSender<Vec<u8>>,
    // Interior mutability: `TermLike` is all `&self`. A sync `Mutex` is fine —
    // it is never held across an `.await` (these methods are synchronous, called
    // from indicatif's draw, not from async code).
    buf: Mutex<Vec<u8>>,
}

impl ChannelTerm {
    fn new(cols: u16, rows: u16, tx: mpsc::UnboundedSender<Vec<u8>>) -> Self {
        Self {
            cols,
            rows,
            tx,
            buf: Mutex::new(Vec::new()),
        }
    }

    fn push(&self, bytes: &[u8]) {
        self.buf
            .lock()
            .expect("ChannelTerm buf poisoned")
            .extend_from_slice(bytes);
    }

    /// Emits a Cursor Up/Down/Forward/Back sequence, skipping the no-op `n == 0`
    /// case (`CSI 0 <x>` still moves one cell on some terminals).
    fn move_cursor(&self, n: usize, dir: u8) -> io::Result<()> {
        if n > 0 {
            self.push(format!("\x1b[{n}{}", dir as char).as_bytes());
        }
        Ok(())
    }
}

impl TermLike for ChannelTerm {
    fn width(&self) -> u16 {
        self.cols
    }
    fn height(&self) -> u16 {
        self.rows
    }

    fn move_cursor_up(&self, n: usize) -> io::Result<()> {
        self.move_cursor(n, b'A')
    }
    fn move_cursor_down(&self, n: usize) -> io::Result<()> {
        self.move_cursor(n, b'B')
    }
    fn move_cursor_right(&self, n: usize) -> io::Result<()> {
        self.move_cursor(n, b'C')
    }
    fn move_cursor_left(&self, n: usize) -> io::Result<()> {
        self.move_cursor(n, b'D')
    }

    fn write_line(&self, s: &str) -> io::Result<()> {
        self.push(s.as_bytes());
        self.push(b"\r\n");
        Ok(())
    }
    fn write_str(&self, s: &str) -> io::Result<()> {
        self.push(s.as_bytes());
        Ok(())
    }
    fn clear_line(&self) -> io::Result<()> {
        // Carriage-return to column 0, then erase to end of line.
        self.push(b"\r\x1b[K");
        Ok(())
    }

    fn flush(&self) -> io::Result<()> {
        // End of a draw (indicatif calls `flush` exactly once per complete
        // redraw): ship the accumulated frame as one message. An empty buffer
        // means nothing was drawn, so send nothing. A closed receiver (pump
        // gone) is ignored — the render tears down on its own.
        let frame = std::mem::take(&mut *self.buf.lock().expect("ChannelTerm buf poisoned"));
        if !frame.is_empty() {
            // Bracket the whole redraw in a synchronized update so a supporting
            // terminal swaps it in atomically rather than flickering through the
            // clear-then-rewrite. The wrapper is harmless on terminals that
            // don't implement it.
            let mut msg =
                Vec::with_capacity(BEGIN_SYNC_UPDATE.len() + frame.len() + END_SYNC_UPDATE.len());
            msg.extend_from_slice(BEGIN_SYNC_UPDATE);
            msg.extend_from_slice(&frame);
            msg.extend_from_slice(END_SYNC_UPDATE);
            let _ = self.tx.send(msg);
        }
        Ok(())
    }
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

    /// Drives the renderer: render the current state, then repaint on each
    /// change. Intended to be `tokio::spawn`ed for the life of the CLI process,
    /// which holds the only handle that joins it; the task owns `root`, so the
    /// `Err` arm (every tree handle dropped) does not fire here — it is the
    /// clean-exit path a daemon driver, holding `root` elsewhere, would use.
    pub async fn run(mut self, root: OpTracker) {
        let mut rx = root.subscribe();
        self.reconcile(&root.snapshot());
        while rx.changed().await.is_ok() {
            self.reconcile(&root.snapshot());
        }
    }

    /// Renders `root` onto this shim's draw target for as long as `fut` is
    /// pending, then clears the bars and returns `fut`'s output.
    ///
    /// Unlike [`run`](Self::run), which renders for the life of the tree, this
    /// is *scoped* to a single future: it `select!`s repaints (driven by
    /// [`OpTracker::subscribe`]) against `fut`'s completion. When `fut`
    /// resolves it clears the bars; dropping `self` afterwards tears down the
    /// `MultiProgress` (and, for the channel renderer, the byte sink behind it).
    /// Spinner animation comes from indicatif's own steady-tick threads, so no
    /// tick is needed in the loop.
    pub async fn render_while<F: Future>(mut self, root: &OpTracker, fut: F) -> F::Output {
        let mut rx = root.subscribe();
        self.reconcile(&root.snapshot());
        let mut fut = std::pin::pin!(fut);
        let out = loop {
            tokio::select! {
                out = &mut fut => break out,
                changed = rx.changed() => match changed {
                    // A mutation landed: repaint from a fresh snapshot.
                    Ok(()) => self.reconcile(&root.snapshot()),
                    // Every tree handle was dropped while `fut` is still
                    // pending; there is nothing left to render, so just await
                    // the future without touching the (now-static) tree.
                    Err(_) => break fut.await,
                },
            }
        };
        // Erase the bars before handing the sink back / dropping it.
        let _ = self.mp.clear();
        out
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
    use tokio::io::AsyncReadExt;

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

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn render_operations_while_returns_output_and_paints() {
        // Read end of the pipe stands in for the SSH channel's far side; the
        // renderer writes ANSI frames into the write end while the future runs.
        let (mut read, write) = tokio::io::duplex(64 * 1024);

        let root = OpTracker::new_root();
        let op_root = root.clone();
        // A future that, once running, drives some visible progress then
        // resolves with a value the renderer must hand back untouched.
        let fut = async move {
            let child = op_root.new_child();
            child.set_op(Operation::FetchPkg {
                name: "demo".into(),
            });
            child.set_length(100);
            for _ in 0..10 {
                child.increment(10);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            child.set_done();
            42usize
        };

        let out = render_operations_while(&root, write, (80, 24), fut).await;
        assert_eq!(out, 42, "the wrapped future's output is returned verbatim");

        // The far side received a non-empty ANSI render naming the operation.
        let mut buf = Vec::new();
        read.read_to_end(&mut buf).await.expect("read pipe");
        assert!(!buf.is_empty(), "progress bytes should have been written");
        let text = String::from_utf8_lossy(&buf);
        assert!(
            text.contains("demo"),
            "rendered frames mention the op: {text:?}"
        );
        assert!(text.contains('\x1b'), "frames contain ANSI escapes");
    }

    #[test]
    fn channel_term_translates_draw_calls_to_ansi_frame() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let term = ChannelTerm::new(80, 24, tx);
        assert_eq!(term.width(), 80);
        assert_eq!(term.height(), 24);

        // A representative draw: move up, return to col 0, clear, write a line.
        term.move_cursor_up(2).unwrap();
        term.write_str("\r").unwrap();
        term.clear_line().unwrap();
        term.write_line("bar").unwrap();
        // Nothing is shipped until flush coalesces the frame.
        assert!(rx.try_recv().is_err(), "no frame before flush");
        term.flush().unwrap();

        let frame = rx.try_recv().expect("a frame after flush");
        // The draw bytes, bracketed in a synchronized-update (BSU…ESU) so a
        // supporting terminal applies the whole frame atomically.
        assert_eq!(
            frame,
            b"\x1b[?2026h\x1b[2A\r\r\x1b[Kbar\r\n\x1b[?2026l".to_vec()
        );
        // An empty draw flushes nothing — not even the synchronized-update
        // wrapper, which would otherwise be an empty atomic frame.
        term.flush().unwrap();
        assert!(rx.try_recv().is_err(), "empty draw sends no frame");
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
