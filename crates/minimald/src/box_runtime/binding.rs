//! A binding: one SSH channel attached to a box's terminal, and the
//! shell-exit and publish prompts it shows.

use super::*;

/// Header of the prompt shown over the channel when a session's shell process
/// exits, offering to detach or delete. Exposed so tests can await its
/// appearance in the channel output before answering.
pub(crate) const SHELL_EXIT_PROMPT: &str =
    "Session shell process exited. What would you like to do with this session?";

/// How long a held chord-matcher split candidate (e.g. a lone `ESC`, a strict
/// prefix of every kitty form) is held before being flushed to the PTY as
/// data. Long enough that a chord split across SSH chunks (which reassemble
/// within milliseconds) still resolves as a chord, short enough that a bare
/// `ESC` reaching the app (e.g. leaving vim insert mode) is imperceptible.
pub(super) const CHORD_FLUSH_IDLE: std::time::Duration = std::time::Duration::from_millis(50);

/// Line rendered above the shell-exit prompt when nothing in the workspace
/// changed since activation. Exposed for the same test-await purpose as
/// [`SHELL_EXIT_PROMPT`].
pub(crate) const SHELL_EXIT_NO_CHANGES: &str = "No files changed since activation.";

/// The shell-exit prompt's Keep item.
pub(crate) const SHELL_EXIT_KEEP: &str =
    "Exit, leaving the session filesystem in place and recoverable";

/// The Keep item for a registered box, whose host-side row ends with its
/// shell (NET-138): the client resumes the row before its next attach or
/// exec, so the kept session comes back under the same addresses.
pub(crate) const SHELL_EXIT_KEEP_REGISTERED: &str = "Exit, keeping the session's files. Its \
     network registration ends with the shell and is restored when you attach or exec into \
     the session again.";

/// Header of the dialog a runtime port-publish request decided `ask` renders
/// over the channel (NET-045), asking the attached human whether the box may
/// publish the port. Exposed so tests can await its appearance in the
/// channel output before answering, for the same purpose as
/// [`SHELL_EXIT_PROMPT`]. The lead-in line above it names the box and the
/// port.
pub(crate) const ASK_PROMPT: &str = "Allow the publish to the host?";

/// How much session output one ask dialog (NET-045) parks on the binding's
/// behalf while the human thinks. The dialog runs beside a drain of the
/// binding's mailbox rather than on top of it — a dialog that let the mailbox
/// fill would wedge the pty feed behind it (see [`Binding::run`]) — but a
/// drain is still a park, so it has a bound. Past it the mailbox fills as it
/// does for any client that stopped keeping up, and the host's stall bound
/// ([`OUTPUT_STALL_TIMEOUT`]) — not this park — decides what happens to the
/// binding. This side has no byte park of its own to compare against; the
/// size is a memory bound chosen so that a dialog with a slow human survives
/// anything a session realistically prints while one is up, without letting a
/// chatty box hold an unbounded buffer hostage to an answer.
pub(super) const ASK_HELD_OUTPUT: usize = 4 * 1024 * 1024;

/// What the attached human answered to the ask dialog (NET-045): the box's
/// `dynamic_ingress` is `ask`, so the request belongs to whoever is bound to
/// this host's channel.
///
/// Every answer short of an explicit allow is
/// [`Refused`](Self::Refused) — a picked deny, or a keyed cancel: an ask
/// never publishes unconfirmed. A client that went away mid-prompt is not an
/// answer at all: the dialog ends carrying no `AskAnswer`, and the `None`
/// around it is the daemon's fail-closed refusal, not the human's, and the
/// audit says so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AskAnswer {
    /// The human picked allow: the request proceeds to the publish it came
    /// for.
    Allowed,
    /// The human picked deny or keyed a cancel: the request fails closed.
    Refused,
}

/// The ask dialog's input, wrapped so [`Binding::ask_prompt`] can tell an
/// input EOF from a keyed cancel: `Selection::Cancelled` reports both, and
/// the two mean different deciders. A keyed cancel — Ctrl-C, `q`, Escape —
/// is the human's own deny, and stays one. An input EOF is the client's
/// channel or connection going away with the dialog standing — under a raw
/// `ssh -tt` tty no keystroke produces it — so it is a terminal that can no
/// longer carry the dialog, an un-asked ask rather than an answered one. The
/// wrapper changes nothing about the bytes and records only that: the dialog
/// reads through it as through the bare channel, and the asking code consults
/// the flag once the dialog has ended.
pub(super) struct AskDialogInput<R> {
    inner: R,
    eof: bool,
}

impl<R> AskDialogInput<R> {
    /// Wraps the dialog's reader.
    pub(super) fn new(inner: R) -> Self {
        Self { inner, eof: false }
    }

    /// Whether the wrapped input reached EOF.
    fn input_eof(&self) -> bool {
        self.eof
    }
}

impl<R: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for AskDialogInput<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let filled = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            // A ready read that moved nothing forward is the reader's EOF —
            // the `AsyncRead` contract allows a zero only at the end — which
            // is the one thing this wrapper exists to remember.
            Poll::Ready(Ok(())) if buf.filled().len() == filled => {
                this.eof = true;
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

/// How many changed-file rows the shell-exit prompt lists before folding the
/// rest into an "and N more" line, keeping the prompt readable on a 24-row
/// terminal.
pub(super) const DELTA_ROWS_SHOWN: usize = 10;

/// Why the binding's mainloop ended. Declared at module scope because the
/// loop's head — the ask dialog (NET-045) — can end it too: a teardown that
/// arrives mid-dialog renders through [`Binding::render_farewell`], which
/// names the exit it ends in.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum MainloopExitReason {
    /// The host is gone: no session left to relay for.
    HostGone,
    /// The client detached.
    Detach,
    /// Another connection attached, superseding this one.
    Superceded,
    /// The session process ended; the shell-exit prompt was raised.
    ProcessExited,
    /// The daemon is shutting down.
    Shutdown,
    /// The host shed this binding: its mailbox stopped taking session output
    /// within [`OUTPUT_STALL_TIMEOUT`].
    Shed,
}

impl MainloopExitReason {
    /// The exit status the binding reports to its client, which `min session
    /// attach` exits with. An end the user chose — a detach, or the session
    /// process exiting — is 0. An end the daemon imposed is not, so a script
    /// can tell the two apart.
    pub(super) fn exit_status(&self) -> u32 {
        match self {
            Self::Detach | Self::ProcessExited => 0,
            Self::HostGone | Self::Superceded | Self::Shutdown => DAEMON_ENDED_EXIT_STATUS,
            Self::Shed => SHED_EXIT_STATUS,
        }
    }
}

/// What a binding told to end itself renders, and the mainloop exit it ends
/// in — the one rendering the four [`BindingMsg`] teardown variants share,
/// written once so the mainloop's own arm and the ask dialog a teardown
/// interrupts (NET-045) say the same farewell whichever side of a dialog the
/// message lands on.
pub(super) enum Farewell {
    /// The session process ended; the shell-exit prompt follows.
    ProcessExit {
        cause: TeardownCause,
        unwind_codes: Vec<u8>,
    },
    /// Another connection attached; this one stands down.
    Superceded(Vec<u8>),
    /// The daemon is shutting down.
    DaemonShutdown(Vec<u8>),
    /// The client detached.
    Detach(Vec<u8>),
}

pub(super) enum BindingMsg {
    Stdin(Vec<u8>),
    /// Ask the attached human whether the box may publish `port` at runtime
    /// (NET-045): the box's `dynamic_ingress` is `ask`, so this binding
    /// renders the exit prompt's dialog on the bound client and replies with
    /// the answer it brought. See [`Binding::ask_prompt`].
    AskExpose {
        port: u16,
        reply: oneshot::Sender<AskAnswer>,
    },
    /// The session was renamed while this binding is attached, so the archive
    /// the shell-exit prompt's save-then-delete lane writes carries the new
    /// name rather than the one cloned in at [`Binding::spawn`].
    Rename(String),
    /// The session process ended, so the binding should tear down and raise the
    /// shell-exit prompt. See [`TeardownCause`] for what the binding surfaces.
    ///
    /// Carries unwind codes like every other teardown. The notices and the
    /// shell-exit prompt are written into the terminal the dead process left
    /// behind, so without them both render through its mouse and keypad modes
    /// — and the user's own shell inherits them afterwards (#1210).
    TeardownDueToProcessExit {
        cause: TeardownCause,
        unwind_codes: Vec<u8>,
    },
    TeardownDueToSuperceded(Vec<u8>),
    TeardownDueToDetach(Vec<u8>),
    TeardownDueToDaemonShutdown(Vec<u8>),
}

/// The `errno` every exiting shell produces: the last slave fd closes and the
/// master reports `EIO`. Expected, and therefore never surfaced on its own —
/// see [`TeardownCause::notices`].
pub(super) const EIO_ON_EXIT: i32 = libc::EIO;

/// Whether a pty-master failure means the shell is already gone, and so
/// whether the host can afford to block on the reap before telling the binding
/// why it is going away.
///
/// `EIO` is the last slave fd closing: the shell is dead or dying, `wait`
/// returns at once, and it carries the one fact that separates an exit from a
/// kill — worth the wait.
///
/// Every other failure (a retryable `EINTR` the read loop treats as fatal, an
/// io-reactor readiness error) can leave a perfectly live process behind.
/// Blocking on `wait` there would hold the user's teardown hostage to a shell
/// that may never exit, turning an error-plus-prompt into a silent hang — the
/// exact failure this whole path exists to make visible.
pub(super) fn shell_is_already_gone(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(EIO_ON_EXIT)
}

/// Why a host is tearing its attached binding down, assembled *after* the
/// process has been reaped so that both halves are known at once.
///
/// The two are independent, and neither alone is enough to tell the user what
/// happened: the pty error says how the host found out, the exit reason says
/// what actually became of their shell.
#[derive(Debug)]
pub(super) struct TeardownCause {
    /// The master read/write failure that unwound the host, when one did.
    /// `None` when the loop's reap won the race and the pty never reported
    /// anything. The expected `EIO`-on-exit is carried here but not shown.
    pub(super) pty_err: Option<std::io::Error>,
    /// How the process ended, once reaped. `None` only if the reap failed.
    pub(super) exit: Option<ExitReason>,
}

impl TeardownCause {
    /// What to tell the user, above the shell-exit prompt, before it renders.
    ///
    /// Empty for the expected case — a shell that exited under its own control,
    /// whose death reached the host as [`EIO_ON_EXIT`] — because
    /// [`SHELL_EXIT_PROMPT`] already speaks for it. Non-empty only when the
    /// prompt alone would misrepresent what happened, which it does in two
    /// independent ways:
    ///
    /// - the master failed for some reason *other* than the shell exiting, so
    ///   the session ended without the shell necessarily having died;
    /// - the shell did not exit under its own control. This arrives as that
    ///   same expected `EIO`, so the prompt's "Session shell process exited"
    ///   is indistinguishable from the user having typed `exit` — the one case
    ///   where a killed session silently impersonates a clean one.
    pub(super) fn notices(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Some(e) = self
            .pty_err
            .as_ref()
            .filter(|e| e.raw_os_error() != Some(EIO_ON_EXIT))
        {
            out.push(format!("Error reading stdout: {e}"));
        }
        if let Some(r) = self.exit.as_ref().filter(|r| r.is_abnormal()) {
            out.push(format!("Session ended abnormally: {}", r.reason));
        }
        out
    }
}

/// Which pty-master operation produced the error that tore a host down.
///
/// Exists only for the log line: every one of these unwinds the host the same
/// way and raises the same shell-exit prompt, so without naming the syscall a
/// "session vanished" report cannot be traced back to which half of the pty
/// broke.
#[derive(Debug, Clone, Copy)]
pub(super) enum PtyOp {
    /// The io reactor failed to report read readiness.
    Readable,
    /// `read(2)` on the master.
    Read,
    /// The io reactor failed to report write readiness.
    Writable,
    /// `write(2)` on the master.
    Write,
}

impl PtyOp {
    /// The `op` field value, as a stable string a log query can match on.
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::Readable => "readable",
            Self::Read => "read",
            Self::Writable => "writable",
            Self::Write => "write",
        }
    }
}

/// A message from the binding (user terminal) to the shell process / host.
///
/// Every message tags the generation of the [`Binding`] that sent it. The
/// host bumps its active generation on every attach — before the superseded
/// binding has shut down — and discards a queued message with a stale
/// generation: input typed at the old channel predates the attach that
/// installed the current session keys, so interpreting it would apply the
/// new channel's chord (or its size) to the old channel's keystrokes.
pub(super) struct StdinMsg {
    // The sender's binding generation; must equal the host's active
    // generation to be honored.
    pub(super) generation: u64,
    pub(super) kind: StdinMsgKind,
}

impl StdinMsg {
    /// Stamps `kind` as sent by a binding of `generation`.
    pub(super) fn new(generation: u64, kind: StdinMsgKind) -> Self {
        Self { generation, kind }
    }
}

pub(super) enum StdinMsgKind {
    Bytes(bytes::Bytes),
    /// A binding left its mainloop for a reason that counts as a detach.
    TerminalUpdate(RequestedPty),
    WindowChange {
        col_width: u32,
        row_height: u32,
        pix_width: u32,
        pix_height: u32,
    },
}

/// Queues bytes for the PTY master, appended after the unwritten remainder
/// of whatever is already queued: buffered bytes are strictly older in
/// stream order than a freshly fed chunk, so replacing the buffer on top
/// would drop forwarded keystrokes — e.g. one chunk `x`+`ESC` forwards `x`
/// into the buffer and holds `ESC` as a split chord candidate, and a pty
/// still unwritable at the idle-flush deadline would then overwrite that
/// queued `x` with `ESC`.
pub(super) fn queue_stdin(buf: &mut Option<(bytes::Bytes, usize)>, bytes: Vec<u8>) {
    let mut next = match buf.take() {
        Some((pending, written)) => pending[written..].to_vec(),
        None => Vec::with_capacity(bytes.len()),
    };
    next.extend_from_slice(&bytes);
    *buf = Some((bytes::Bytes::from(next), 0));
}

/// A connection between a [`Host`] and an SSH channel.
///
/// The [`Binding`] is owned by the spawned async task, but the
/// host owns (and communicates via) the [`mpsc::Receiver`] end of
/// `stdin_tx`, and the [`mpsc::Sender`] end of `receiver`.
pub(super) struct Binding {
    /// The remote end of this binding.
    channel: Channel<Msg>,
    /// Which host binding-generation this binding owns; stamped on every
    /// [`StdinMsg`] it sends so the host can discard the queue once the
    /// binding is superseded.
    generation: u64,
    /// Channel the binding writes down to communicate stdin to the host.
    stdin_tx: mpsc::Sender<StdinMsg>,
    /// Channel the [`Host`] uses to communicate with this [`Binding`].
    receiver: mpsc::Receiver<BindingMsg>,
    /// Capability to destroy the owning session, exercised when the user picks
    /// "delete" on the shell-exit prompt. `None` for hosts spawned without a
    /// manager (the test harness), where "delete" degrades to a detach.
    control: Option<BoxControl>,
    /// Workspace-change detection, shared from the owning [`Host`], so the
    /// shell-exit prompt can lead with the files changed since activation.
    /// `None` when the baseline snapshot could not be taken.
    delta: Option<Arc<DeltaSource>>,
    /// The session's display name, used to name the archive the shell-exit
    /// prompt's save-then-delete lane writes.
    name: String,
    /// Daemon-side directory the save-then-delete lane archives into
    /// (`<minimal_state_dir>/archives`). Created on demand at save time.
    archives_dir: std::path::PathBuf,
    /// Whether the box is registered (see [`HostParams::holds_host_row`]):
    /// the shell-exit prompt's Keep item says the session cannot be
    /// attached to again.
    holds_host_row: bool,
    /// Cancelled by the host when it sheds this binding (see
    /// [`Host::shed_binding`]). A separate signal rather than a
    /// [`BindingMsg`], because a binding is shed exactly when its mailbox is
    /// full; and raced against every await that can park on a stalled
    /// client, so the binding still reaches its exit path and closes the
    /// channel.
    shed: CancellationToken,
}

/// What the host keeps of an attached binding: its mailbox, its task, and
/// the token that sheds it.
pub(super) type BindingSlot = (mpsc::Sender<BindingMsg>, JoinHandle<()>, CancellationToken);

/// The line a shed binding leaves on the terminal before its channel closes.
pub(super) const SHED_NOTICE: &[u8] =
    b"\r\nDisconnecting - the terminal stopped keeping up with session output; \
      re-attach with `min session attach`\r\n";

/// The exit status a shed binding reports. It is ssh's own "connection
/// failed" status on purpose: the client restores the terminal itself only
/// on this status (see `client_must_unwind` in the `min` CLI), and after a
/// shed it has to, because the output stream was cut mid-flight and no
/// unwind codes followed it.
pub(super) const SHED_EXIT_STATUS: u32 = 255;

/// The exit status of an attach the daemon ended: the session was destroyed
/// (or otherwise went away), another connection took it over, or the daemon
/// is shutting down. Non-zero so a script does not read it as a detach, and
/// not ssh's 255, because the daemon still spoke for itself: these ends send
/// their own unwind codes or none are owed, so the client's blind unwind (see
/// [`SHED_EXIT_STATUS`]) stays off.
pub(super) const DAEMON_ENDED_EXIT_STATUS: u32 = 254;

/// The line a binding whose host went away leaves on the terminal: the
/// session is gone, so there is no farewell from the host to render.
pub(super) const HOST_GONE_NOTICE: &[u8] = b"\r\nDisconnecting - the session is gone\r\n";

/// Hands a departing binding its teardown message and waits for it to
/// finish, so its farewell lands before whatever comes next.
///
/// The wait is bounded because this runs inside the host loop. A binding
/// whose client stopped draining can neither take the message nor finish,
/// and past [`HOST_PROBE_TIMEOUT`](crate::box_actor::HOST_PROBE_TIMEOUT) it is
/// shed instead, which still closes its channel.
pub(super) async fn retire_binding((tx, mut task, shed): BindingSlot, msg: BindingMsg) {
    let orderly = async {
        let _ = tx.send(msg).await;
        let _ = (&mut task).await;
    };
    if tokio::time::timeout(crate::box_actor::HOST_PROBE_TIMEOUT, orderly)
        .await
        .is_err()
    {
        tracing::warn!("departing binding did not finish its teardown in time; shedding it");
        shed.cancel();
    }
}

impl Binding {
    /// Spawns a new binding task for a given channel, returning objects
    /// which the owning [`Host`] should own to communicate with it.
    #[expect(
        clippy::too_many_arguments,
        reason = "one call site, which hands over the host's per-binding facts by name"
    )]
    pub(crate) async fn spawn(
        channel: Channel<Msg>,
        stdin_tx: mpsc::Sender<StdinMsg>,
        generation: u64,
        control: Option<BoxControl>,
        delta: Option<Arc<DeltaSource>>,
        name: String,
        archives_dir: std::path::PathBuf,
        holds_host_row: bool,
    ) -> BindingSlot {
        let (tx, rx) = mpsc::channel(4);
        let shed = CancellationToken::new();

        let binding = Self {
            channel,
            generation,
            stdin_tx,
            receiver: rx,
            control,
            delta,
            name,
            archives_dir,
            holds_host_row,
            shed: shed.clone(),
        };

        // The channel id ties every line this binding logs back to the
        // connection span's `accepted connection`/`closed` lines — field
        // analysis stalls without that correlation.
        // The session name rides the span too: the channel id correlates these
        // lines with the connection's `accepted connection`/`closed` pair, but
        // only the name says *which* session an operator's report is about.
        //
        // A root of its own, linked to whatever spawned it (the host loop, or
        // the request that launched the host): a binding lives as long as
        // its channel, past the attach that asked for it.
        let span = tracing::info_span!(
            parent: None,
            "binding",
            channel = %binding.channel.id(),
            session = %binding.name,
        );
        (tx, crate::traced::spawn_detached(span, binding.run()), shed)
    }

    /// Hands `kind` to the host, giving up if the binding is shed first.
    ///
    /// The host's stdin queue fills when the shell stops reading its input,
    /// and a binding parked here would never see the shed. Takes the fields
    /// it needs rather than `&self`, because [`Self::run`] has moved the
    /// channel out of `self` by the time it sends.
    async fn send_to_host(
        stdin_tx: &mpsc::Sender<StdinMsg>,
        generation: u64,
        shed: &CancellationToken,
        kind: StdinMsgKind,
    ) -> Result<(), ()> {
        tokio::select! {
            _ = stdin_tx.send(StdinMsg::new(generation, kind)) => Ok(()),
            () = shed.cancelled() => Err(()),
        }
    }

    async fn run(mut self) {
        tracing::info!("binding attached to session channel");
        let (mut rs, ws) = self.channel.split();
        let mut w = ws.make_writer();

        // Reading from the remote stops once it sends EOF;
        // the loop lives on to keep forwarding stdout.
        let mut remote_open = true;
        // The asks whose dialogs this loop's head renders one at a time
        // (NET-045), stashed by the select arm below because a dialog needs
        // the channel halves the select's own futures are borrowing.
        let mut pending_asks: VecDeque<(u16, oneshot::Sender<AskAnswer>)> = VecDeque::new();
        let exit_reason = loop {
            if let Some((port, reply)) = pending_asks.pop_front() {
                tracing::info!(
                    port,
                    "asking the attached client to allow a runtime port publish"
                );
                // The lead-in names the box as it stood when the dialog
                // started: a rename that lands mid-dialog takes effect for
                // what follows it, not for a line already on the screen.
                let dialog_name = self.name.clone();
                // The session output that arrives while the human thinks,
                // parked — see the drain below — and flushed once the
                // terminal is the relay's again.
                let mut held: Vec<u8> = Vec::new();
                // A teardown cannot wait for a human: the one that arrived
                // mid-dialog is taken aside here and rendered, through
                // [`Self::render_farewell`], once the ask it interrupted is
                // answered.
                let mut farewell: Option<Farewell> = None;
                // No answer until a human gives one. A dialog that ends
                // without the human's choice — the shed below, a teardown,
                // the host going away, a terminal that could not carry the
                // dialog — is the daemon's refusal, not the human's: the
                // reply sender drops unsent, the host reads no answer, and
                // `resume_ask` records the daemon as the decider with the
                // typed nobody-is-attached refusal. Only a dialog that
                // completed with a choice in hand is the human's answer.
                let mut answer: Option<AskAnswer> = None;
                // Whether the dialog's last write was cut short, presumed
                // yes until the arm that ran the dialog to completion says
                // otherwise: every other way out of the select below drops
                // the dialog future wherever it stood, mid-write included.
                // That matters because russh's channel writer keeps an
                // interrupted write's state — `ChannelTx` parks its send in
                // `send_fut` and answers the next `write_all` with the
                // *interrupted* write's byte count, a count that can run
                // past a shorter buffer's end and panics tokio's
                // `write_all` there (`split_at`: mid > len). The shed
                // notice and every farewell are shorter buffers, so the
                // binding would die mid-epilogue and leave the client
                // hanging on a channel that never closes. The state is
                // per-writer, so the writer is replaced rather than
                // trusted: see the refresh below.
                let mut interrupted_write = true;
                {
                    // Pinned outside the loop below, not rebuilt inside it: a
                    // select arm's future is re-created on every iteration
                    // the loop takes, and a dialog re-created per parked
                    // chunk would re-render from scratch under the human's
                    // hands — lead-in and all — for every burst the drain
                    // took.
                    let dialog = Self::ask_prompt(&dialog_name, port, rs.make_reader(), &mut w);
                    tokio::pin!(dialog);
                    loop {
                        tokio::select! {
                            // Raced against the shed: a client that stopped
                            // reading is not a client to wait on, and the
                            // host has already discarded this binding — so
                            // the ask fails closed here and the next
                            // iteration's shed arm closes the channel.
                            answered = &mut dialog => {
                                answer = answered;
                                // The dialog ran to completion: its writes
                                // all drained, so the writer beneath it is
                                // clean.
                                interrupted_write = false;
                                break;
                            }
                            () = self.shed.cancelled() => break,
                            // The drain beside the dialog. The host keeps
                            // feeding the pty into this binding's mailbox,
                            // and stops reading the pty while the mailbox is
                            // full — so a dialog that let the mailbox fill
                            // would wedge the box behind it and shed the
                            // human after [`OUTPUT_STALL_TIMEOUT`], the one
                            // client the dialog exists for. Instead the
                            // output parks in `held`, bounded by
                            // [`ASK_HELD_OUTPUT`]: past it the mailbox fills
                            // as it does for any client that stopped keeping
                            // up, and the stall bound — not an unbounded
                            // park — decides what happens to this binding.
                            msg = self.receiver.recv(), if held.len() < ASK_HELD_OUTPUT => {
                                match msg {
                                    Some(BindingMsg::Stdin(b)) => held.extend_from_slice(&b),
                                    Some(BindingMsg::Rename(name)) => self.name = name,
                                    Some(BindingMsg::AskExpose { port, reply }) => {
                                        pending_asks.push_back((port, reply));
                                    }
                                    Some(BindingMsg::TeardownDueToProcessExit { cause, unwind_codes }) => {
                                        farewell = Some(Farewell::ProcessExit { cause, unwind_codes });
                                        break;
                                    }
                                    Some(BindingMsg::TeardownDueToSuperceded(unwind_codes)) => {
                                        farewell = Some(Farewell::Superceded(unwind_codes));
                                        break;
                                    }
                                    Some(BindingMsg::TeardownDueToDaemonShutdown(unwind_codes)) => {
                                        farewell = Some(Farewell::DaemonShutdown(unwind_codes));
                                        break;
                                    }
                                    Some(BindingMsg::TeardownDueToDetach(unwind_codes)) => {
                                        farewell = Some(Farewell::Detach(unwind_codes));
                                        break;
                                    }
                                    // The host is gone: no session left to
                                    // publish for, and nobody to answer for.
                                    None => break,
                                }
                            }
                        }
                    }
                }
                if interrupted_write {
                    // A fresh writer from the same channel half, because the
                    // interrupted one may still hold a write the select
                    // dropped mid-send. Its cost is that chunk alone: it goes
                    // unsent with its window space, at most
                    // `max_packet_size` bytes, and only ever on a client that
                    // stopped reading.
                    w = ws.make_writer();
                }
                // The output that arrived while the human thought, delivered
                // now the terminal is the relay's again — raced against the
                // shed like every other write, so a client that stopped
                // reading cannot park the binding in its own flush.
                if !held.is_empty() {
                    let flushed = tokio::select! {
                        _ = w.write_all(&held) => true,
                        () = self.shed.cancelled() => false,
                    };
                    if !flushed {
                        // The flush may have been dropped mid-send, and the
                        // shed notice is the shorter buffer that would trip
                        // the interrupted write's stale byte count: a fresh
                        // writer, then the shed exit.
                        w = ws.make_writer();
                        // The shed ends the dialog without the human's
                        // answer unless the dialog had already completed
                        // under them: send the answer if there is one,
                        // and none otherwise — the dropped sender is what
                        // the host reads as the nobody-attached case.
                        if let Some(answer) = answer {
                            #[expect(
                                clippy::let_underscore_must_use,
                                reason = "the asker may be gone; its reply's fate was always its own"
                            )]
                            let _ = reply.send(answer);
                        }
                        break MainloopExitReason::Shed;
                    }
                }
                // The asker going away before the answer is not an error to
                // relay: the reply's fate was always the asker's. A dialog
                // that ended without one — a teardown that could not wait
                // for a human, a host already gone, a terminal that could
                // not carry the dialog — drops the sender instead, which is
                // the nobody-attached answer the host turns into the
                // daemon's own fail-closed refusal.
                if let Some(answer) = answer {
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the asker may be gone; its reply's fate was always its own"
                    )]
                    let _ = reply.send(answer);
                }
                if let Some(farewell) = farewell {
                    break Self::render_farewell(farewell, &mut w).await;
                }
                // The dialog's drain may have taken another ask while this
                // one stood, and nothing more arrives to wake the select
                // below — so the next dialog renders off this turn, not off
                // a message that is already spent.
                continue;
            }
            tokio::select! {
                // Remote (ssh channel) => session stdin.
                res = rs.wait(), if remote_open => match res {
                    None => remote_open = false,
                    Some(msg) => {
                        match msg {
                            russh::ChannelMsg::Data{ data } => {
                                if Self::send_to_host(&self.stdin_tx, self.generation, &self.shed, StdinMsgKind::Bytes(data)).await.is_err() {
                                    break MainloopExitReason::Shed;
                                }
                            }
                            russh::ChannelMsg::RequestPty {
                                want_reply: _,
                                term,
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                                terminal_modes,
                            } => {
                                let update = StdinMsgKind::TerminalUpdate(RequestedPty {
                                    char_sizes: (col_width, row_height),
                                    pixel_sizes: (pix_width, pix_height),
                                    term: term.to_string(),
                                    modes: terminal_modes.to_vec(),
                                });
                                if Self::send_to_host(&self.stdin_tx, self.generation, &self.shed, update).await.is_err() {
                                    break MainloopExitReason::Shed;
                                }
                            },
                            russh::ChannelMsg::WindowChange{
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                            } => {
                                let change = StdinMsgKind::WindowChange {
                                    col_width, row_height, pix_width, pix_height,
                                };
                                if Self::send_to_host(&self.stdin_tx, self.generation, &self.shed, change).await.is_err() {
                                    break MainloopExitReason::Shed;
                                }
                            },
                            // Flow-control window updates fire on every
                            // burst of bytes forwarded through the
                            // channel, v. noisy.
                            russh::ChannelMsg::WindowAdjusted { .. } => {}
                            // Duplicates of pre-attach requests the
                            // connection handler already answered (russh
                            // buffers them into the taken channel); noise on
                            // every healthy attach, so keep them out of
                            // info-level field bundles.
                            _ => tracing::debug!("ignoring channel request on attached binding: {:?}", msg),
                        };
                    }
                },
                () = self.shed.cancelled() => break MainloopExitReason::Shed,
                // Session stdout => remote (ssh channel).
                // A closed channel means the host is gone;
                // tear the attachment down.
                msg = self.receiver.recv() => {
                    let Some(msg) = msg else { break MainloopExitReason::HostGone; };
                    match msg {
                        BindingMsg::Stdin(b) => {
                            // Raced against the shed: this is where a client
                            // that stopped draining parks the binding.
                            let delivered = tokio::select! {
                                _ = w.write_all(&b) => true,
                                () = self.shed.cancelled() => false,
                            };
                            if !delivered {
                                // Dropped mid-send like the dialog and the
                                // held flush: a fresh writer, so the shed
                                // notice is not answered with the
                                // interrupted write's byte count.
                                w = ws.make_writer();
                                break MainloopExitReason::Shed;
                            }
                        },
                        BindingMsg::AskExpose { port, reply } => {
                            // Stashed rather than rendered here: the select's
                            // own arms borrow the channel halves (`rs.wait()`
                            // among them), and the dialog needs both — so the
                            // ask suspends the relay for the next iteration's
                            // head, where no arm's future is alive. One at a
                            // time, front to back: a second ask queues behind
                            // the first and takes its turn.
                            pending_asks.push_back((port, reply));
                        },
                        BindingMsg::Rename(name) => self.name = name,
                        BindingMsg::TeardownDueToProcessExit { cause, unwind_codes } => {
                            break Self::render_farewell(
                                Farewell::ProcessExit { cause, unwind_codes },
                                &mut w,
                            ).await;
                        }
                        BindingMsg::TeardownDueToSuperceded(unwind_codes) => {
                            break Self::render_farewell(Farewell::Superceded(unwind_codes), &mut w).await;
                        }
                        BindingMsg::TeardownDueToDaemonShutdown(unwind_codes) => {
                            break Self::render_farewell(Farewell::DaemonShutdown(unwind_codes), &mut w).await;
                        }
                        BindingMsg::TeardownDueToDetach(unwind_codes) => {
                            break Self::render_farewell(Farewell::Detach(unwind_codes), &mut w).await;
                        }
                    };

                }
            }
        };

        tracing::info!(reason = ?exit_reason, "binding leaving mainloop");

        // Whether the session outlives this binding, and so should run its
        // `on_detach` hooks. `HostGone` leaves no session to detach from,
        // and a shell exit resolved as "delete" flows into destruction,
        // which runs its own hooks instead.
        let session_outlives_us = match exit_reason {
            MainloopExitReason::HostGone => false,
            MainloopExitReason::ProcessExited => {
                let disposition = Self::shell_exit_prompt(
                    self.delta.as_ref(),
                    self.control.as_ref(),
                    &self.archives_dir,
                    &self.name,
                    self.holds_host_row,
                    rs.make_reader(),
                    &mut w,
                )
                .await;
                // Closes the loop on a vanished session: whether the record is
                // still there afterwards is decided here, and a `Kept` can come
                // from an explicit choice, a cancel, or a failed delete.
                tracing::info!(?disposition, "shell-exit prompt answered");
                disposition == ExitDisposition::Kept
            }
            MainloopExitReason::Detach => true,
            // NOT on supercede, however much it looks like a departure.
            // `Host::attach` sends the teardown and then awaits this
            // binding's join handle — from inside the host's own message
            // loop — so anything here that needs the host deadlocks:
            // `detached()` reaches the session actor, which reaches back
            // into the host to build the hook's command, which is blocked
            // waiting for us. The session is also still attached, just by
            // someone else, so firing `on_detach` immediately before the
            // new binding's `on_attach` would misdescribe what happened.
            MainloopExitReason::Superceded => false,
            // Not on daemon shutdown. Asking for detach hooks reaches the
            // sessions manager, which brings a session's actor *up* from
            // disk on demand and would mint a fresh sandbox to run them in
            // — the opposite of what shutdown is doing, and a race against
            // the teardown already in flight. The session is being
            // suspended, not left: `on_detach` waits for the next real
            // departure.
            MainloopExitReason::Shutdown => false,
            // Not on a shed either. Nobody chose to leave, and the terminal
            // a hook would write to is the one that stopped reading.
            MainloopExitReason::Shed => false,
        };

        // Asked of the session actor rather than run here: a detach hook is
        // not the departing shell's to run — on the shell-exit path that
        // shell is already gone, which is what ended the sandbox — so the
        // actor mints a host for it exactly as activation does. Awaited, so
        // the hooks are not racing this binding's teardown.
        if session_outlives_us && let Some(control) = self.control.as_ref() {
            control.detached().await;
        }

        let notice = match exit_reason {
            MainloopExitReason::Shed => Some(SHED_NOTICE),
            MainloopExitReason::HostGone => Some(HOST_GONE_NOTICE),
            _ => None,
        };
        if let Some(notice) = notice {
            // Bounded: after a shed the client stopped draining, so this
            // write can park exactly as the one that got the binding shed.
            // The notice is lost then, but the close below still goes out.
            // The writer is a fresh one whenever a write was cut short
            // mid-send — the mainloop replaces it at every race it drops,
            // because russh's channel writer otherwise answers this short
            // buffer with the interrupted write's byte count and tokio's
            // `write_all` panics past its end.
            let _ = tokio::time::timeout(crate::box_actor::HOST_PROBE_TIMEOUT, w.write_all(notice))
                .await;
        }

        let _ = ws.eof().await;
        let _ = ws.exit_status(exit_reason.exit_status()).await;
        let _ = ws.close().await; // needed to release the remote
    }

    /// The save half of the shell-exit prompt's save-then-delete lane:
    /// re-walks the workspace for the added + modified files and archives them
    /// to `dest`, announcing what is being saved on the way. Returns before
    /// anything is destroyed on any failure, so the caller can keep the
    /// session and re-render the prompt. An associated fn rather than a
    /// method because [`Self::run`] has already split `self.channel` by the
    /// time it saves.
    async fn save_changes<W>(
        delta: Option<&Arc<DeltaSource>>,
        dest: &std::path::Path,
        w: &mut W,
    ) -> io::Result<()>
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        let delta =
            delta.ok_or_else(|| io::Error::other("workspace change detection is unavailable"))?;
        let files = delta
            .changed_paths()
            .await
            .ok_or_else(|| io::Error::other("the workspace could not be re-walked"))?;
        let n = files.len();
        let plural = if n == 1 { "" } else { "s" };
        let _ = w
            .write_all(
                format!(
                    "\r\nSaving {n} changed file{plural} -> {}\r\n",
                    dest.display()
                )
                .as_bytes(),
            )
            .await;
        delta.archive_changed(files, dest.to_path_buf()).await
    }

    /// Renders a farewell — the unwind codes first, then whatever it has to
    /// say — and names the mainloop exit it ends in. The one rendering shared
    /// by the mainloop's four teardown arms and by the ask dialog
    /// (NET-045) a teardown interrupts, so the client sees the same farewell
    /// whichever side of a dialog the message lands on. An associated fn
    /// taking the writer piecewise, exactly like [`Self::ask_prompt`], because
    /// [`Self::run`] holds the channel halves as locals.
    async fn render_farewell<W>(farewell: Farewell, w: &mut W) -> MainloopExitReason
    where
        W: tokio::io::AsyncWrite + Unpin,
    {
        match farewell {
            Farewell::ProcessExit {
                cause,
                unwind_codes,
            } => {
                // Before the notices below and before the shell-exit prompt
                // that follows the mainloop: both render into the terminal
                // the session process just left, and it may well have left
                // mouse reporting on (#1210).
                let _ = w.write_all(&unwind_codes).await;
                // `shown` records whether the user was told anything beyond
                // the prompt itself: a suppressed notice leaves no other
                // trace, and the expected case is deliberately silent.
                let notices = cause.notices();
                let errno = cause
                    .pty_err
                    .as_ref()
                    .and_then(std::io::Error::raw_os_error);
                tracing::info!(
                    cause = if cause.pty_err.is_some() { "pty-error" } else { "process-reaped" },
                    ?errno,
                    abnormal = cause.exit.as_ref().is_some_and(ExitReason::is_abnormal),
                    exit_reason = cause.exit.as_ref().map_or("", |r| r.reason.as_str()),
                    exit_code = ?cause.exit.as_ref().map(|r| r.code),
                    shown = !notices.is_empty(),
                    "raising the shell-exit prompt",
                );
                // `\r\n`: the remote terminal is in raw mode, so a bare
                // newline stair-steps off the right margin.
                if !notices.is_empty() {
                    let _ = w.write_all(b"\r\n").await;
                    for notice in &notices {
                        let _ = w.write_all(format!("{notice}\r\n").as_bytes()).await;
                    }
                }
                MainloopExitReason::ProcessExited
            }
            Farewell::Superceded(unwind_codes) => {
                let _ = w.write_all(&unwind_codes).await;
                let _ = w
                    .write_all(
                        b"\r\nDisconnecting - session attached to from a different connection\r\n",
                    )
                    .await;
                MainloopExitReason::Superceded
            }
            Farewell::DaemonShutdown(unwind_codes) => {
                let _ = w.write_all(&unwind_codes).await;
                let _ = w
                    .write_all(b"\r\nDisconnecting - minimald is shutting down\r\n")
                    .await;
                MainloopExitReason::Shutdown
            }
            Farewell::Detach(unwind_codes) => {
                let _ = w.write_all(&unwind_codes).await;
                let _ = w.write_all(b"\r\nDetaching from session.\r\n").await;
                MainloopExitReason::Detach
            }
        }
    }

    /// The ask a runtime port-publish request decided `ask` renders to the
    /// attached human (NET-045): the exit prompt's own dialog, over the same
    /// channel halves, offering deny first so that a reflexive Enter — or any
    /// way the dialog can end without an explicit choice — fails the request
    /// closed. Answers with the answer the human gave; `None` when the
    /// dialog could not be carried — a render or read that failed on I/O, or
    /// an input EOF, the client's channel going away with the dialog
    /// standing — which is no answer rather than a deny, so the daemon owns
    /// the refusal it becomes. An associated fn taking the facts piecewise,
    /// exactly like [`Self::shell_exit_prompt`], because [`Self::run`]
    /// holds the channel halves as locals.
    async fn ask_prompt<R, W>(name: &str, port: u16, r: R, mut w: W) -> Option<AskAnswer>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        // `\r\n`: the remote terminal is in raw mode, so a bare newline
        // stair-steps off the right margin.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a client that cannot take the lead-in line cannot take the dialog either; \
                      the dialog's own result is the answer to relay"
        )]
        // The same frame the VM-backed host's dialog draws
        // (`minimal_client::ask_dialog`): the protocol on the lead-in — a
        // runtime publish is TCP — and the `? ` the question leads with.
        let _ = w
            .write_all(format!("\r\n{name} asks to publish port {port}/tcp.\r\n").as_bytes())
            .await;
        let select = async_dialog::Select::new()
            .with_prompt(format!("? {ASK_PROMPT}"))
            .items(["Deny", "Allow"])
            // Deny stands highlighted: the answer the box's own posture
            // would have given, so nothing publishes because someone held
            // Enter.
            .default(0);
        // The dialog reads through the EOF-telling wrapper, because
        // `Selection::Cancelled` says both a keyed cancel and an input EOF,
        // and the two mean different deciders.
        let mut r = AskDialogInput::new(r);
        let outcome = select.interact(&mut r, &mut w).await;
        match outcome {
            Ok(async_dialog::Selection::At(1)) => Some(AskAnswer::Allowed),
            // An explicit deny — Enter on the highlighted deny — or a keyed
            // cancel (Ctrl-C, `q`, Escape): the human's own deny — the
            // fail-closed answer, now in their hand, of an ask that never
            // publishes unconfirmed.
            Ok(_) if !r.input_eof() => Some(AskAnswer::Refused),
            // An input EOF is not any of that: under a raw `ssh -tt` tty no
            // keystroke produces channel EOF, so it means the connection
            // or the client went away with the dialog standing — a terminal
            // that can no longer carry it. That, like a render or read that
            // failed on I/O (the other way this arm is reached), is the
            // daemon's refusal, not the human's deny, so it comes back as
            // no answer: the dropped reply makes `resume_ask` record the
            // daemon as the decider.
            _ => None,
        }
    }

    /// The shell-exit prompt, run after the session process ends: leads with
    /// the files changed since activation (when `delta` is available), then
    /// offers keep / save-then-delete / delete and drives the chosen
    /// teardown through `control`. Extracted from [`Binding::run`]'s
    /// mainloop epilogue purely for readability; the bytes written to the
    /// channel are identical. An associated fn taking the binding's
    /// capabilities piecewise because `run` has already moved the channel
    /// out of `self` by this point.
    pub(super) async fn shell_exit_prompt<R, W>(
        delta: Option<&Arc<DeltaSource>>,
        control: Option<&BoxControl>,
        archives_dir: &std::path::Path,
        name: &str,
        holds_host_row: bool,
        mut r: R,
        mut w: W,
    ) -> ExitDisposition
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        // The shell process exited. For a bash shell, this usually meant someone pressed ctrl-d absent-mindedly.
        // We presume they didnt want to completely destroy the session, perhaps just detach, but lets prompt
        // to see where they wanted to go from here.
        let _ = w.write_all(b"\r\n").await;

        // Lead with what a "delete" would lose. An unavailable delta (no
        // baseline, or the re-walk failed) renders the plain prompt — the
        // exit path never blocks on change detection.
        let changed = match delta {
            Some(delta) => delta.changed_files().await,
            None => None,
        };
        let mut delete_item = "Delete, all in-session files permanently deleted".to_string();
        match &changed {
            Some(rows) if rows.is_empty() => {
                let _ = w
                    .write_all(format!("{SHELL_EXIT_NO_CHANGES}\r\n\r\n").as_bytes())
                    .await;
                delete_item.push_str(" — nothing will be lost");
            }
            Some(rows) => {
                let n = rows.len();
                let plural = if n == 1 { "" } else { "s" };
                let _ = w
                    .write_all(format!("{n} file{plural} changed since activation:\r\n").as_bytes())
                    .await;
                for row in rows.iter().take(DELTA_ROWS_SHOWN) {
                    let _ = w.write_all(format!("  {row}\r\n").as_bytes()).await;
                }
                if n > DELTA_ROWS_SHOWN {
                    let _ = w
                        .write_all(
                            format!("  ... and {} more\r\n", n - DELTA_ROWS_SHOWN).as_bytes(),
                        )
                        .await;
                }
                let _ = w.write_all(b"\r\n").await;
            }
            None => {}
        }
        // What each rendered item does. The save lane only exists when the
        // delta is known non-empty, so selections are mapped through this
        // list rather than through fixed indices.
        enum ExitChoice {
            Keep,
            SaveThenDelete,
            Delete,
        }

        // A registered box's host-side row ends with its shell (NET-138); the
        // client resumes it before the next attach or exec, so the Keep item
        // says the registration comes back rather than that nothing does.
        let keep_item = if holds_host_row {
            SHELL_EXIT_KEEP_REGISTERED
        } else {
            SHELL_EXIT_KEEP
        };
        let mut items = vec![keep_item.to_string()];
        let mut choices = vec![ExitChoice::Keep];
        // Destination for the save-then-delete lane, fixed while the prompt
        // is up so the rendered path is the path written — including across
        // a failed-write re-render.
        let archive_dest = matches!(&changed, Some(rows) if !rows.is_empty()).then(|| {
            archives_dir.join(format!(
                "{}-{}.tar.zst",
                name,
                chrono::Utc::now().format("%Y%m%dT%H%M%SZ"),
            ))
        });
        if let Some(dest) = &archive_dest {
            items.push(format!("Save changes to {}, then delete", dest.display()));
            choices.push(ExitChoice::SaveThenDelete);
        }
        items.push(delete_item);
        choices.push(ExitChoice::Delete);

        let select = async_dialog::Select::new()
            .with_prompt(SHELL_EXIT_PROMPT)
            .items(items);
        // Loops only while a save attempt fails: the session is left
        // intact and the prompt re-renders so the user can still pick keep
        // or delete explicitly. Cancel/EOF always exits as a keep, so the
        // exit path can never block permanently.
        let delete = loop {
            match select.interact(&mut r, &mut w).await {
                Ok(Selection::At(i)) => match choices[i] {
                    // User selected detach, keep going to disconnect
                    ExitChoice::Keep => break false,
                    ExitChoice::Delete => break true,
                    // Delete only ever follows a confirmed save: a failed
                    // archive write keeps the session and re-prompts.
                    ExitChoice::SaveThenDelete => {
                        let dest = archive_dest
                            .as_ref()
                            .expect("save lane is only rendered with a destination");
                        match Self::save_changes(delta, dest, &mut w).await {
                            Ok(()) => break true,
                            Err(e) => {
                                tracing::warn!(error = %e, "saving session changes failed");
                                let _ = w
                                    .write_all(
                                        format!("Failed to save changes: {e}\r\n\r\n").as_bytes(),
                                    )
                                    .await;
                            }
                        }
                    }
                },
                // User cancelled selection, safest option is to detach
                Ok(Selection::Cancelled) => break false,
                Err(e) => {
                    tracing::warn!(error = %e, "session-exit prompt failed");
                    break false;
                }
            }
        };
        // User selected delete (directly or via a confirmed save): ask the
        // manager to tear the whole session down (kill the host, remove the
        // on-disk record) before we close the channel. Awaiting is
        // deadlock-free here — the destroy cascade waits on the host
        // runtime loop (already exiting now that the process has ended),
        // never on this binding task.
        if delete {
            match control {
                Some(control) => {
                    let _ = w.write_all(b"\r\nDeleting session...\r\n").await;
                    match control.destroy().await {
                        // Destroyed: its own hooks have run, and there is no
                        // session left to detach from.
                        Ok(()) => return ExitDisposition::Destroyed,
                        Err(e) => {
                            tracing::warn!(error = %e, "session delete failed");
                            let _ = w
                                .write_all(format!("Failed to delete session: {e}\r\n").as_bytes())
                                .await;
                        }
                    }
                }
                // No manager wired (test harness): degrade to a detach.
                None => tracing::warn!("delete selected but no session control available"),
            }
        }
        // Every remaining path leaves the session standing: keep, cancel, a
        // failed delete, or a delete with nothing wired to carry it out.
        ExitDisposition::Kept
    }
}

/// What the shell-exit prompt settled on, which decides whether the session
/// is still there to run `on_detach`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExitDisposition {
    /// The session survives the shell that exited.
    Kept,
    /// The session was torn down, running its `on_destroy` hooks on the way.
    Destroyed,
}
