//! Tracking of long-running operations, so that pretty progress bars
//! can be printed.

use std::{
    sync::{Arc, Mutex, OnceLock, Weak},
    time::Duration,
};

use indicatif::{MultiProgress, ProgressBar, ProgressStyle};

/// An operation being tracked.
#[derive(Debug, Clone)]
pub enum Operation {
    PackageBuild { name: String },
    CollectOutputs { name: String, outputs: Vec<String> },
    FetchPkg { name: String },
    CompressPkg { name: String },
    ExtractPkg { name: String },
    FetchSource { url: String },
    FetchIndex,
}

#[derive(Debug, Default)]
struct TrackerInner {
    depth: usize,
    parent: Option<OpTracker>,
    op: Option<Operation>,
    children: Vec<Weak<Mutex<TrackerInner>>>,
    pg: Option<ProgressBar>,
}

impl TrackerInner {
    fn set_length(&self, length: u64) {
        if let Some(pg) = &self.pg {
            pg.set_length(length);
        }
    }
    fn increment(&self, amt: u64) {
        if let Some(pg) = &self.pg {
            pg.inc(amt);
        }
    }

    pub fn set_op(&mut self, op: Option<Operation>) {
        self.op = op;

        // Depending on the operation type, create a progress bar.
        match (&self.op, &self.pg) {
            (Some(Operation::PackageBuild { name }), _) => {
                let new_pg = ProgressBar::hidden().with_style(
                    ProgressStyle::with_template("{prefix}{spinner} Building package: {msg}")
                        .unwrap(),
                );
                new_pg.set_message(name.clone());
                new_pg.enable_steady_tick(Duration::from_millis(100));
                self.install(new_pg);
            }
            (Some(Operation::CollectOutputs { name, outputs }), _) => {
                let new_pg = ProgressBar::hidden().with_style(
                    ProgressStyle::with_template("{prefix}{spinner} Collect outputs for {msg}")
                        .unwrap(),
                );

                let s = outputs.to_vec().join(" ");
                let outputs_str = match s.char_indices().nth(30) {
                    Some((idx, _)) => format!("{}...", &s[..idx]),
                    None => s.to_string(),
                };
                new_pg.set_message(format!("{name}: {outputs_str}"));
                new_pg.enable_steady_tick(Duration::from_millis(50));
                self.install(new_pg);
            }
            (Some(Operation::ExtractPkg { name }), _) => {
                let new_pg = ProgressBar::hidden().with_style(
                    ProgressStyle::with_template("{prefix}{spinner} Extract: {msg}").unwrap(),
                );
                new_pg.set_message(name.clone());
                new_pg.enable_steady_tick(Duration::from_millis(50));
                self.install(new_pg);
            }
            (Some(Operation::CompressPkg { name }), _) => {
                let new_pg = ProgressBar::hidden().with_style(
                    ProgressStyle::with_template("{prefix}{spinner} Compress: {msg}").unwrap(),
                );
                new_pg.set_message(name.clone());
                new_pg.enable_steady_tick(Duration::from_millis(80));
                self.install(new_pg);
            }
            (Some(Operation::FetchPkg { name }), _) => {
                let new_pg = ProgressBar::hidden()
                    .with_style(ProgressStyle::with_template("{prefix}Fetch: {msg:35!} [{wide_bar}]     {decimal_bytes:9!} / {decimal_total_bytes:9!}   ETA: {eta:5!}").unwrap().progress_chars("=> "));
                new_pg.set_message(name.clone());
                self.install(new_pg);
            }
            (Some(Operation::FetchIndex), _) => {
                let new_pg = ProgressBar::hidden()
                    .with_style(ProgressStyle::with_template("{prefix}Update remote index  {msg:35!} [{wide_bar}]     {decimal_bytes:9!} / {decimal_total_bytes:9!}   ETA: {eta:5!}").unwrap().progress_chars("=> "));
                new_pg.set_message("");
                self.install(new_pg);
            }
            (Some(Operation::FetchSource { url }), _) => {
                let new_pg = ProgressBar::hidden()
                    .with_style(ProgressStyle::with_template("{prefix}Fetch source: {msg:35!} [{wide_bar}]     {decimal_bytes:9!} / {decimal_total_bytes:9!}   ETA: {eta:5!}").unwrap().progress_chars("=> "));
                new_pg.set_message(url.clone());
                self.install(new_pg);
            }
            // No operation remains but a progress bar exists. Set it to finished and remove our reference.
            (None, Some(pg)) => {
                pg.finish_and_clear();
                self.pg = None;
            }
            _ => {}
        }
    }

    fn install(&mut self, pg: ProgressBar) {
        if self.depth > 1 {
            pg.set_prefix(format!("{}{}", "  ".repeat((self.depth - 1) * 2), "↳ "));
        }
        if let Some(p) = &self.parent {
            p.install_progress(pg.clone());
        } else {
            global_progress().add(pg.clone());
        }
        self.pg = Some(pg);
    }
}

/// A node in the operation tree, potentially describing an operation.
///
/// Nodes may have a parent (unless they are the root) or children.
/// Nodes never outlive their parents.
#[derive(Debug, Clone)]
pub struct OpTracker {
    inner: Arc<Mutex<TrackerInner>>,
}

impl OpTracker {
    /// Creates a new OpTracker which is a child of the given root, if any.
    pub fn new_with_root(root_op: &Option<OpTracker>) -> OpTracker {
        match root_op {
            None => root().new_child(),
            Some(root) => root.new_child(),
        }
    }

    /// Creates and returns a new operation which is a child of self.
    pub fn new_child(&self) -> OpTracker {
        let depth = self.depth();

        let new = OpTracker {
            inner: Arc::new(Mutex::new(TrackerInner {
                depth: depth + 1,
                parent: Some(self.clone()),
                ..Default::default()
            })),
        };

        self.inner
            .lock()
            .unwrap()
            .children
            .push(Arc::downgrade(&new.inner));
        new
    }

    pub fn with_op(self, op: Operation) -> Self {
        self.set_op(op);
        self
    }
    pub fn set_op(&self, op: Operation) {
        self.inner.lock().unwrap().set_op(Some(op));
    }
    pub fn set_done(&self) {
        self.inner.lock().unwrap().set_op(None);
    }
    pub fn set_length(&self, length: u64) {
        self.inner.lock().unwrap().set_length(length);
    }
    pub fn increment(&self, amt: u64) {
        self.inner.lock().unwrap().increment(amt);
    }

    /// Returns how deep in the operation tree the operation is.
    pub fn depth(&self) -> usize {
        self.inner.lock().unwrap().depth
    }

    /// Called by a child to register their new progress bar.
    fn install_progress(&self, pg: ProgressBar) {
        let s = self.inner.lock().unwrap();
        match (&s.pg, &s.parent) {
            // We (parent) have a progress bar, child should follow
            (Some(parent_pg), _) => {
                global_progress().insert_after(parent_pg, pg);
            }
            // Parent has no progress but theres a grandparent, recurse
            (None, Some(parent)) => parent.install_progress(pg),
            // Root node with no progress bar, directly add to global MultiProgress
            (None, None) => {
                global_progress().add(pg);
            }
        }
    }
}

static ROOT: OnceLock<OpTracker> = OnceLock::new();

/// Returns the root operation tracker.
pub fn root() -> OpTracker {
    ROOT.get_or_init(|| OpTracker {
        inner: Arc::new(Mutex::new(TrackerInner {
            children: Vec::with_capacity(32),
            ..Default::default()
        })),
    })
    .clone()
}

static MP: OnceLock<MultiProgress> = OnceLock::new();

fn global_progress() -> MultiProgress {
    MP.get_or_init(MultiProgress::new).clone()
}

use std::io;

/// A writer to stdout which coordinates with printing progress bars.
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
