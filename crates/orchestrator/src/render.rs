//! Human-readable rendering of a [`BuildEvent`] stream.
//!
//! [`BuildRenderer`] folds the raw event stream a build emits into
//! line-oriented text, tracking the per-build-index → package-name map so log
//! lines can be attributed to the package that produced them. It is the one
//! place that decides how a build reads on a terminal, shared by the `mip pkg`
//! CLI and the in-session `min build` command so both render identically.

use std::collections::HashMap;

use crate::{BuildEvent, BuildEventInner};

/// Severity of a rendered [`BuildLine`], so a text sink can route it (stdout
/// vs stderr, `info!` vs `warn!`, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildLineKind {
    /// Progress or stdout content.
    Status,
    /// Content originating from a build's stderr.
    Stderr,
}

/// A single rendered line of build output. `text` is fully formatted and
/// self-contained (it already carries the package name where relevant), so a
/// line-oriented sink can print it verbatim.
#[derive(Debug, Clone)]
pub struct BuildLine {
    pub kind: BuildLineKind,
    pub text: String,
}

/// Stateful renderer folding [`BuildEvent`]s into [`BuildLine`]s.
///
/// Feed each event to [`BuildRenderer::render`] in arrival order; it returns
/// the line to show, if any. Progress lines (a build starting, a cache fetch)
/// are always emitted; per-line build logs are emitted only when `verbose`.
#[derive(Debug, Default)]
pub struct BuildRenderer {
    /// build idx → package name, learned from `Start` events so later `Log`
    /// lines carrying the same idx can be attributed.
    names: HashMap<usize, String>,
    verbose: bool,
}

impl BuildRenderer {
    /// A renderer. `verbose` enables per-line build-log output; progress lines
    /// show regardless.
    #[must_use]
    pub fn new(verbose: bool) -> Self {
        Self {
            names: HashMap::new(),
            verbose,
        }
    }

    /// Renders one event, returning the line to display, or `None` when the
    /// event produces no output (a suppressed non-verbose log line, or a
    /// `Stop`).
    pub fn render(&mut self, event: BuildEvent) -> Option<BuildLine> {
        match event.inner {
            BuildEventInner::Start {
                name, full_build, ..
            } => {
                let verb = if full_build { "building" } else { "up-to-date" };
                let text = format!("{verb} {name}");
                // Remember the name so this build's log lines can be attributed.
                self.names.insert(event.idx, name);
                Some(BuildLine {
                    kind: BuildLineKind::Status,
                    text,
                })
            }
            BuildEventInner::Hydrate { name, .. } => Some(BuildLine {
                kind: BuildLineKind::Status,
                text: format!("fetching {name}"),
            }),
            BuildEventInner::Log { is_stderr, line } => {
                if !self.verbose {
                    return None;
                }
                // Attribute the line to its package when we've seen its `Start`.
                let text = match self.names.get(&event.idx) {
                    Some(name) => format!("{name}: {line}"),
                    None => line,
                };
                let kind = if is_stderr {
                    BuildLineKind::Stderr
                } else {
                    BuildLineKind::Status
                };
                Some(BuildLine { kind, text })
            }
            BuildEventInner::Stop => None,
        }
    }
}
