//! Scoped progress rendering onto an SSH channel.
//!
//! [`ChannelProgress`] is the `russh`-concrete wrapper around
//! [`ot::render_operations_while`]: it consumes an SSH [`Channel`], an
//! [`OpTracker`], and a future, paints the tracker's live operation tree onto
//! the channel as indicatif progress bars while the future runs, and hands the
//! channel back (with the future's output) once it resolves.
//!
//! The renderer takes **exclusive** use of the channel for the future's
//! duration — the wrapped operation must not also write to it. This is the
//! "compute under a progress bar, then print the result" model; live output
//! interleaved with progress is out of scope (see
//! `docs/specs/04-spec-ot-render-decoupling`).

use std::future::Future;

use ot::OpTracker;
use russh::Channel;
use russh::server::Msg;

/// Renders an [`OpTracker`] onto an SSH channel for the lifetime of a future.
///
/// Construct with [`ChannelProgress::new`], then drive a future with
/// [`run`](ChannelProgress::run); the channel is returned alongside the
/// future's output so the caller can resume writing to it.
pub struct ChannelProgress {
    channel: Channel<Msg>,
    tracker: OpTracker,
    /// Terminal dimensions `(cols, rows)` indicatif lays bars out against —
    /// from the session's PTY size.
    size: (u16, u16),
}

impl ChannelProgress {
    /// Creates a renderer that will paint `tracker` onto `channel`, sized for a
    /// `(cols, rows)` terminal.
    #[must_use]
    pub fn new(channel: Channel<Msg>, tracker: OpTracker, size: (u16, u16)) -> Self {
        Self {
            channel,
            tracker,
            size,
        }
    }

    /// Renders progress onto the channel while `fut` runs, returning the channel
    /// and the future's output once it resolves.
    ///
    /// The channel is borrowed (via an independent writer) during rendering and
    /// returned intact — the writer only ever writes data frames, never an EOF,
    /// so the caller can keep using the channel afterwards.
    pub async fn run<F: Future>(self, fut: F) -> (Channel<Msg>, F::Output) {
        let writer = self.channel.make_writer();
        let out = ot::render_operations_while(&self.tracker, writer, self.size, fut).await;
        (self.channel, out)
    }
}
