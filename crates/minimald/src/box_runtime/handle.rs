//! The handle to a running host: the actor's mailbox and the screen
//! snapshots it answers with.

use super::*;

/// Actor messages to a [`Host`].
pub(super) enum Message {
    Kill(bool),
    /// Rename the session: update the host's display name and republish the
    /// new `MINIMAL_SESSION_NAME` through the per-attach environment channel,
    /// so the already-running shell picks it up at its next prompt.
    Rename(String),
    /// Bind a client channel to this host. The [`ConnectionEnv`] rides along
    /// on every attach — not just the one that minted the host — because it
    /// describes the terminal on the other end of *this* channel; the
    /// [`SessionKeys`] give the new channel its own negotiation state.
    Attach(Channel<Msg>, WinSize, ConnectionEnv, SessionKeys),
    GetAttrs(oneshot::Sender<HostAttrs>),
    /// Compute the workspace's at-risk report (VCS-exact when the tree is a
    /// git repository, the changed-since-activation delta otherwise) and
    /// reply with it; `Unavailable` when neither can be computed.
    GetAtRisk(oneshot::Sender<minimald_rpc::SessionDeltaResponse>),
    /// Build a command that runs `program` inside this session's sandbox, for
    /// the caller to give stdio to and spawn. The host builds it because only
    /// the host can: it holds the session process (whose namespaces are joined)
    /// and the guard (which knows the session's current environment).
    CommandInSession {
        program: std::ffi::OsString,
        args: Vec<std::ffi::OsString>,
        /// Layered over the session's own variables, replacing on a
        /// shared key. Empty for callers that want the session
        /// environment verbatim.
        extra_env: std::collections::BTreeMap<String, String>,
        reply: oneshot::Sender<Result<std::process::Command, crate::nsenter::NsenterError>>,
    },

    /// Snapshot the terminal screen for a read-only preview (`min dash`).
    /// Answered straight off the parser — no PTY resize, no I/O relay.
    GetScreen(oneshot::Sender<minimald_rpc::ScreenSnapshot>),

    /// Ask the attached human whether the box may publish `port` at runtime
    /// (NET-045): the box's `dynamic_ingress` is `ask`, so the bound client
    /// decides. Answered with the answer the human gave, or `None` when
    /// nobody is attached — a box outlives its client, and an unanswered ask
    /// is a refusal, never a publish.
    AskExpose {
        port: u16,
        reply: oneshot::Sender<Option<AskAnswer>>,
    },

    SetTitleCallback(String),
    VisualBellCallback,
    AudibleBellCallback,
    /// Test-only: shorten this host's stall bound ([`OUTPUT_STALL_TIMEOUT`])
    /// so a test can prove in milliseconds what the real bound would take the
    /// full 30 s to decide. The bound lives on the host, not the binding, so
    /// a test whose host was built inside a session reaches it through its
    /// [`HostHandle`].
    #[cfg(test)]
    SetOutputStallTimeout(std::time::Duration),
    /// Test-only: feed bytes into the session's pty as though a client had
    /// typed them, but without going through the ssh channel — which is the
    /// point: an ask dialog holds the channel's reader, so a test that needs
    /// the session to print *while a dialog is up* has no keystroke to do it
    /// with. The bytes queue straight into the pty's write buffer (see
    /// [`queue_stdin`]); queued writes, never awaited ones, so the actor's
    /// loop stays free to keep serving — exactly what a test relying on the
    /// stall bound needs it to keep doing.
    #[cfg(test)]
    FeedStdin(Vec<u8>),
}

/// Renders a vt100 cell color into the string form the
/// [`minimald_rpc::ScreenCell`] wire type uses: `"idx:<n>"` for an ANSI-256
/// palette index, `"#rrggbb"` for truecolor, `None` for the terminal default.
pub(super) fn wire_color(color: vt100::Color) -> Option<String> {
    match color {
        vt100::Color::Default => None,
        vt100::Color::Idx(n) => Some(format!("idx:{n}")),
        vt100::Color::Rgb(r, g, b) => Some(format!("#{r:02x}{g:02x}{b:02x}")),
    }
}

/// Convert a vt100 screen into the [`minimald_rpc::ScreenSnapshot`] wire
/// type. Wide-glyph continuation cells are dropped rather than emitted as
/// spaces: consumers flatten cells into width-aware text, so a placeholder
/// cell would add a phantom column per wide glyph and skew the row.
pub(super) fn screen_to_snapshot(screen: &vt100::Screen) -> minimald_rpc::ScreenSnapshot {
    use minimald_rpc::{ScreenCell, ScreenRow, ScreenSnapshot};
    let (rows, cols) = screen.size();
    let lines = (0..rows)
        .map(|row| ScreenRow {
            cells: (0..cols)
                .filter_map(|col| match screen.cell(row, col) {
                    Some(cell) if cell.is_wide_continuation() => None,
                    Some(cell) => Some(ScreenCell {
                        // A cell's contents can be wider than one char
                        // (wide glyphs); the wire type is a single char,
                        // so keep the first.
                        ch: cell.contents().chars().next().unwrap_or(' '),
                        fg: wire_color(cell.fgcolor()),
                        bg: wire_color(cell.bgcolor()),
                        bold: cell.bold(),
                        italic: cell.italic(),
                        underline: cell.underline(),
                        reverse: cell.inverse(),
                    }),
                    None => Some(ScreenCell {
                        ch: ' ',
                        fg: None,
                        bg: None,
                        bold: false,
                        italic: false,
                        underline: false,
                        reverse: false,
                    }),
                })
                .collect(),
        })
        .collect();
    let (cursor_row, cursor_col) = match screen.hide_cursor() {
        true => (None, None),
        false => {
            let (row, col) = screen.cursor_position();
            (Some(row), Some(col))
        }
    };
    ScreenSnapshot {
        rows,
        cols,
        cursor_row,
        cursor_col,
        lines,
    }
}

/// Handles callback events from the terminal parser, transmitting them to the host.
pub(super) struct ParserEventHandler(pub(super) WeakHostHandle);
impl vt100::Callbacks for ParserEventHandler {
    fn set_window_title(&mut self, _: &mut vt100::Screen, title: &[u8]) {
        self.0.set_title_cb(title);
    }
    fn audible_bell(&mut self, _: &mut vt100::Screen) {
        self.0.audible_bell_cb();
    }
    fn visual_bell(&mut self, _: &mut vt100::Screen) {
        self.0.visual_bell_cb();
    }
}

/// A handle to the session host that does not prevent the host
/// from being closed.
#[derive(Debug, Clone)]
pub(super) struct WeakHostHandle {
    sender: mpsc::WeakSender<Message>,
}

impl WeakHostHandle {
    fn set_title_cb(&mut self, title: &[u8]) {
        let title = match String::from_utf8(title.to_vec()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("Ignoring non-utf8 terminal title: {e}");
                return;
            }
        };

        if let Some(sender) = self.sender.upgrade()
            && let Err(e) = sender.try_send(Message::SetTitleCallback(title))
        {
            tracing::warn!("Dropping title update: {e}");
        }
    }
    fn audible_bell_cb(&mut self) {
        if let Some(sender) = self.sender.upgrade()
            && let Err(e) = sender.try_send(Message::AudibleBellCallback)
        {
            tracing::warn!("Dropping audible bell: {e}");
        }
    }
    fn visual_bell_cb(&mut self) {
        if let Some(sender) = self.sender.upgrade()
            && let Err(e) = sender.try_send(Message::VisualBellCallback)
        {
            tracing::warn!("Dropping visual bell: {e}");
        }
    }
}

/// How many messages the host's mailbox holds before senders block.
///
/// Small on purpose — the loop is expected to drain it promptly. It matters
/// to callers only when the loop is *not* draining: a wedged host fills this
/// in a handful of polls, after which a probe blocks in `send` rather than
/// `recv`. Both need a deadline; see
/// [`HOST_PROBE_TIMEOUT`](crate::box_actor::HOST_PROBE_TIMEOUT).
pub(crate) const HOST_MAILBOX_CAPACITY: usize = 8;

/// How long an attached binding may take no session output at all before
/// the host sheds it.
///
/// Until then a binding that falls behind gets backpressure: the host stops
/// reading the pty while the binding's mailbox is full, so the shell waits on
/// the terminal, and the loop keeps serving its own mailbox. The bound is far
/// longer than [`HOST_PROBE_TIMEOUT`](crate::box_actor::HOST_PROBE_TIMEOUT)
/// because it catches something else. The probe deadline asks whether the
/// host is alive. This one asks whether the client has stopped reading
/// altogether. A slow terminal drains a mailbox slot in milliseconds, so it
/// never gets near this bound.
pub(crate) const OUTPUT_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The handle to the session host - the running process.
#[derive(Debug, Clone)]
pub struct HostHandle {
    pub(super) sender: mpsc::Sender<Message>,
}

/// Why [`HostHandle::attach`] could not deliver the attach message.
pub enum HostAttachError {
    /// The host's mailbox is full and did not drain before the deadline.
    /// The host is still alive; the caller should retry or report busy.
    Timeout,
    /// The host's runtime loop has ended. The caller should mint a new host.
    Closed(Channel<Msg>, WinSize),
}

/// The mailbox of a [`HostHandle::wedged`] host, opaque so [`Message`] stays
/// private to this module.
///
/// Holding one is the whole point: an undrained mailbox is what makes the
/// host wedged. Dropping it turns the same handle into a *dead* host
/// instead, which is a different case and answers immediately.
#[cfg(test)]
pub(crate) struct WedgedMailbox(
    // Never read — held only so the channel stays open and undrained.
    #[allow(dead_code)] mpsc::Receiver<Message>,
);

#[cfg(test)]
impl HostHandle {
    /// A handle to a host that accepts messages and never answers one,
    /// modelling a loop parked mid-attach or mid-teardown.
    ///
    /// Faithful where it counts — the mailbox is the production size, so a
    /// test can queue past it and exercise the `send`-blocks case as well as
    /// the `recv`-blocks one.
    pub(crate) fn wedged() -> (Self, WedgedMailbox) {
        let (sender, receiver) = mpsc::channel(HOST_MAILBOX_CAPACITY);
        (Self { sender }, WedgedMailbox(receiver))
    }

    /// A handle to a host that answers every attrs probe at once (with
    /// default attrs) and ignores everything else: a live host, as far as a
    /// listing can tell.
    pub(crate) fn answering_attrs() -> Self {
        let (sender, mut receiver) = mpsc::channel(HOST_MAILBOX_CAPACITY);
        crate::traced::spawn(async move {
            while let Some(message) = receiver.recv().await {
                if let Message::GetAttrs(reply) = message {
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "a prober that went away needs no answer"
                    )]
                    let _ = reply.send(HostAttrs::default());
                }
            }
        });
        Self { sender }
    }
}

impl HostHandle {
    pub(super) fn make_weak(&self) -> WeakHostHandle {
        WeakHostHandle {
            sender: self.sender.downgrade(),
        }
    }

    // `Err(())` means one thing on every HostHandle method: the host's loop is
    // gone or wedged (a teardown race), which callers discard or read as
    // unavailable. A named error type would be better; until then, allowed.
    #[allow(clippy::result_unit_err)]
    pub async fn kill(&self, for_shutdown: bool) -> Result<(), ()> {
        match self
            .sender
            .send_timeout(
                Message::Kill(for_shutdown),
                crate::box_actor::HOST_PROBE_TIMEOUT,
            )
            .await
        {
            Ok(()) => Ok(()),
            // A closed channel, or a wedged loop that never drains its mailbox
            // so the send cannot be queued before the deadline: either way the
            // kill did not land, and the caller must not block awaiting a loop
            // that will never observe it.
            Err(_e) => Err(()),
        }
    }

    /// Renames the session: the host updates its display name and republishes
    /// the new `MINIMAL_SESSION_NAME` through the per-attach environment
    /// channel, so the already-running shell picks it up at its next prompt.
    ///
    /// Best-effort: a dead or wedged host drops the message silently, and the
    /// record-side rename has already succeeded by the time this is called.
    pub async fn rename(&self, new_name: String) {
        let _ = self
            .sender
            .send_timeout(
                Message::Rename(new_name),
                crate::box_actor::HOST_PROBE_TIMEOUT,
            )
            .await;
    }

    /// Binds `c` to this host, carrying the attaching terminal's facts.
    ///
    /// `connection` is merged into the host's stored facts on every attach, so
    /// a client attaching from a different terminal than the one that minted
    /// the shell updates `TERM` for everything the session spawns from here
    /// on. A `TERM` the attach does not declare leaves the last known value
    /// standing rather than clearing it: a client whose own `TERM` is unset
    /// (OpenSSH then sends an empty pty-req term string) has nothing to say
    /// about the terminal, which is not the same as saying there isn't one.
    pub async fn attach(
        &self,
        c: Channel<Msg>,
        sz: WinSize,
        connection: ConnectionEnv,
        keys: SessionKeys,
    ) -> Result<(), HostAttachError> {
        match self
            .sender
            .send_timeout(
                Message::Attach(c, sz, connection, keys),
                crate::box_actor::HOST_PROBE_TIMEOUT,
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(SendTimeoutError::Timeout(Message::Attach(_, _, _, _))) => {
                Err(HostAttachError::Timeout)
            }
            Err(SendTimeoutError::Closed(Message::Attach(c, sz, _, _))) => {
                Err(HostAttachError::Closed(c, sz))
            }
            Err(e) => unreachable!("{:?}", e),
        }
    }

    /// Whether both handles address the same host.
    pub fn same_host(&self, other: &Self) -> bool {
        self.sender.same_channel(&other.sender)
    }

    /// Whether the host's runtime loop is still running.
    ///
    /// A cheap, non-blocking check — the channel closes when the loop ends — so
    /// a caller deciding whether to reuse a host or mint a new one does not
    /// have to round-trip through it.
    pub fn is_alive(&self) -> bool {
        !self.sender.is_closed()
    }

    /// Builds a command that runs `program` inside this session's sandbox,
    /// joining the namespaces of the running session process.
    ///
    /// The returned command has no stdio configured: that belongs to whoever is
    /// wiring it up (an SSH exec channel pipes all three, an interactive
    /// attach would hand it a PTY). See [`Host::command_in_session`].
    ///
    /// # Errors
    ///
    /// The session process having exited, its namespaces being unreadable, or
    /// the host having stopped between this call and its reply.
    pub async fn command_in_session<I, S>(
        &self,
        program: impl AsRef<std::ffi::OsStr>,
        args: I,
    ) -> io::Result<std::process::Command>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        self.command_in_session_env(program, args, std::collections::BTreeMap::new())
            .await
    }

    /// [`Self::command_in_session`], with `extra_env` layered over the
    /// session's own variables.
    ///
    /// Separate rather than an extra parameter on the common form
    /// because [`crate::nsenter::Injection::with_env`] *replaces* the
    /// environment outright — merging has to happen host-side, where
    /// the session's variables live, and every caller that doesn't need
    /// it should keep saying so by not passing anything.
    pub async fn command_in_session_env<I, S>(
        &self,
        program: impl AsRef<std::ffi::OsStr>,
        args: I,
        extra_env: std::collections::BTreeMap<String, String>,
    ) -> io::Result<std::process::Command>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let (reply, recv) = oneshot::channel();
        let message = Message::CommandInSession {
            program: program.as_ref().to_os_string(),
            args: args
                .into_iter()
                .map(|a| a.as_ref().to_os_string())
                .collect(),
            extra_env,
            reply,
        };
        let dead = || io::Error::other("session host stopped before the command could be built");
        self.sender.send(message).await.map_err(|_| dead())?;
        recv.await.map_err(|_| dead())?.map_err(io::Error::other)
    }

    /// Returns the terminal attributes. A host that goes away between the
    /// send and the reply reads as `Err(())` rather than a panic: the loop
    /// can drop a queued responder on its way out, and that is a teardown
    /// race, not a bug in the caller.
    // `Err(())` means one thing on every HostHandle method: the host's loop is
    // gone or wedged (a teardown race), which callers discard or read as
    // unavailable. A named error type would be better; until then, allowed.
    #[allow(clippy::result_unit_err)]
    pub async fn get_attrs(&self) -> Result<HostAttrs, ()> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        match self.sender.send(Message::GetAttrs(send)).await {
            Ok(()) => recv.await.map_err(|_| ()),
            Err(SendError(Message::GetAttrs(_))) => Err(()),
            Err(e) => unreachable!("{:?}", e),
        }
    }

    /// Returns a snapshot of the terminal screen. A dead host reads as
    /// `Err(())` rather than a panic, matching [`Self::get_attrs`].
    // `Err(())` means one thing on every HostHandle method: the host's loop is
    // gone or wedged (a teardown race), which callers discard or read as
    // unavailable. A named error type would be better; until then, allowed.
    #[allow(clippy::result_unit_err)]
    pub async fn get_screen(&self) -> Result<minimald_rpc::ScreenSnapshot, ()> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        match self.sender.send(Message::GetScreen(send)).await {
            Ok(()) => recv.await.map_err(|_| ()),
            Err(SendError(Message::GetScreen(_))) => Err(()),
            Err(e) => unreachable!("{:?}", e),
        }
    }

    /// Returns what a destroy of the session's workspace would lose: the
    /// VCS-exact at-risk report when the workspace is a git repository, the
    /// changed-since-activation rows otherwise, and `Unavailable` when
    /// neither can be computed or the host is gone (a dead host reads as
    /// `Unavailable`, not a panic, because callers race teardown). The
    /// computation runs off the host's runtime loop, bounded per
    /// [`crate::workspace_delta::assess`].
    pub async fn at_risk(&self) -> minimald_rpc::SessionDeltaResponse {
        let (send, recv) = oneshot::channel();
        if self.sender.send(Message::GetAtRisk(send)).await.is_err() {
            return minimald_rpc::SessionDeltaResponse::Unavailable;
        }
        recv.await
            .unwrap_or(minimald_rpc::SessionDeltaResponse::Unavailable)
    }

    /// Asks the attached human whether the box may publish `port` at runtime
    /// (NET-045), and answers with what they said: the bound client renders
    /// the exit prompt's own dialog and picks. `None` when nobody is
    /// attached — no binding, a binding that cannot take the ask, or a host
    /// that went away before answering — which is the caller's fail-closed
    /// case, not an error to report: the typed refusal the request ends with
    /// says nobody is attached to answer.
    ///
    /// Unbounded by design: the human's answer is the only bound an ask has,
    /// so callers that must not park on it await this off the actor the
    /// request belongs to (see how [`crate::box_actor`] routes the ask).
    pub(crate) async fn ask_expose(&self, port: u16) -> Option<AskAnswer> {
        let (send, recv) = oneshot::channel();
        if self
            .sender
            .send(Message::AskExpose { port, reply: send })
            .await
            .is_err()
        {
            return None;
        }
        // A dropped answer means the host tore its binding down mid-prompt:
        // nobody is attached to answer any more.
        recv.await.ok().flatten()
    }

    /// Test-only: shorten this host's stall bound so a test can prove in
    /// milliseconds what [`OUTPUT_STALL_TIMEOUT`] would otherwise take the
    /// full 30 s to decide.
    #[cfg(test)]
    pub(crate) async fn set_output_stall_timeout(&self, timeout: std::time::Duration) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the host may already be gone; the test's own bound then decides"
        )]
        let _ = self
            .sender
            .send(Message::SetOutputStallTimeout(timeout))
            .await;
    }

    /// Test-only: feed bytes into the session's pty as though a client had
    /// typed them, without going through the ssh channel — so a test can have
    /// the session print while an ask dialog holds the channel's reader.
    #[cfg(test)]
    pub(crate) async fn feed_stdin(&self, bytes: Vec<u8>) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the host may already be gone; the test's own bounds then decide"
        )]
        let _ = self.sender.send(Message::FeedStdin(bytes)).await;
    }
}

/// Various attributes about the running terminal.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HostAttrs {
    /// The title set by the terminal, if any.
    pub(crate) title: Option<(String, SystemTime)>,
    /// The number of times the audible bell signal was send into the terminal,
    /// and the last time it was received.
    pub(crate) audible_bell: (usize, Option<SystemTime>),
    /// The number of times the visual bell signal was send into the terminal,
    /// and the last time it was received.
    pub(crate) visual_bell: (usize, Option<SystemTime>),

    /// When the last byte was sent by the process into the terminal.
    pub(crate) stdout_last: Option<SystemTime>,
    /// When the last byte was sent to the process from a binding.
    pub(crate) stdin_last: Option<SystemTime>,

    /// The launch's own placement outcome for this session's host-address
    /// box (NET-079, design §7.2's "declared and enforced" attribute):
    /// `PerBox` when the launch placed the box in a classifier leaf of its
    /// own, `None` when the box ran with the host's address and no leaf —
    /// the value the session records on the box's record, which the read
    /// surfaces then show lowered by the host's current fact
    /// ([`displayed_host_ip_enforcement`]), never the node fact re-read at
    /// launch. Nothing for a none box or an own-IP box, whose verdicts are
    /// decided on address leases rather than the host's cgroup tree.
    pub(crate) host_ip_enforcement: Option<HostIpEnforcement>,
}
