//! The running state of an active session.
//!
//! The [`Pty`] struct owns a master/slave pseudo-terminal pair created via
//! `openpty(3)`, exposing its file descriptors and window-size controls.
//!
//! The [`Host`] struct holds the running state of an active session.

use async_dialog::Selection;
use russh::Channel;
use russh::server::Msg;
use std::collections::{BTreeMap, VecDeque};
use std::future::Future;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::error::{SendError, SendTimeoutError};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

use crate::RequestedPty;
use crate::session::SessionPaths;
use crate::session_delta::DeltaSource;
use crate::sessions::SessionControl;
use sessions::NetworkMode;
use sessions::keys::{ChordMatcher, FeedOutcome, KeyAction, SessionKeys};
// The one per-box egress enforcement type (NET-079): shared with the session
// record that carries a box's own launch outcome, so a launch's decision and
// the record it lands on are one type with no conversion between them.
use minimald_rpc::HostIpEnforcement;
use std::sync::Arc;

mod pty;

pub use pty::*;

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
const CHORD_FLUSH_IDLE: std::time::Duration = std::time::Duration::from_millis(50);

/// Line rendered above the shell-exit prompt when nothing in the workspace
/// changed since activation. Exposed for the same test-await purpose as
/// [`SHELL_EXIT_PROMPT`].
pub(crate) const SHELL_EXIT_NO_CHANGES: &str = "No files changed since activation.";

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
const ASK_HELD_OUTPUT: usize = 4 * 1024 * 1024;

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
struct AskDialogInput<R> {
    inner: R,
    eof: bool,
}

impl<R> AskDialogInput<R> {
    /// Wraps the dialog's reader.
    fn new(inner: R) -> Self {
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
const DELTA_ROWS_SHOWN: usize = 10;

/// Emit one `tracing::info!` per item the launcher folds into the
/// session — packages, vars, and patches — tagging each with its
/// provenance so an operator can trace "where did `EDITOR=hx` come
/// from?" back to the loadout / project / package that contributed
/// it.
///
/// Baseline packages (the launcher-defaults `base`, `coreutils`,
/// `socat`) log with `source = "launcher-baseline"` so they can be
/// distinguished from composition contributions. Patches and hooks
/// still log even though the launcher can't act on them yet — an
/// operator inspecting a session should see the intent even when
/// the plumbing is deferred.
///
/// Var values are logged at `debug` (separate call) rather than
/// `info` so an accidentally-inherited secret doesn't sit in the
/// default log stream.
fn log_session_contents(
    session_name: &str,
    baseline_packages: &[&str],
    composition: Option<&sessions::core::compose::Composition>,
) {
    for p in baseline_packages {
        tracing::info!(
            session = session_name,
            domain = "package",
            name = p,
            source = "launcher-baseline",
            "session content",
        );
    }
    let Some(comp) = composition else {
        return;
    };
    for p in comp.packages() {
        tracing::info!(
            session = session_name,
            domain = "package",
            name = %p.package(),
            source = ?sessions::core::source::Provenanced::source(p),
            "session content",
        );
    }
    for v in comp.vars() {
        let var = v.var();
        tracing::info!(
            session = session_name,
            domain = "var",
            name = %var.name(),
            source = ?sessions::core::source::Provenanced::source(v),
            "session content",
        );
        tracing::debug!(
            session = session_name,
            name = %var.name(),
            value = %var.value(),
            "session var value",
        );
    }
    for sp in comp.patches() {
        let patch = sp.patch();
        tracing::info!(
            session = session_name,
            domain = "patch",
            host_source = %patch.host_path(),
            sandbox_dest = %patch.destination(),
            source = ?sessions::core::source::Provenanced::source(sp),
            "session content (patch: materialized into session home at FinalizeSession)",
        );
    }
    // Hooks are logged in setup order (project first, then loadouts —
    // see `Composition::lifecycle_hooks`), so the log reads in the
    // order the transitions will fire. Execution is still deferred, so
    // this records intent rather than an outcome; an operator
    // inspecting a session should be able to see which scripts it
    // carries and where each came from before any of them runs.
    for h in comp.lifecycle_hooks() {
        let src = sessions::core::source::Provenanced::source(h);
        let hook = h.hook();
        [
            ("on_activate", hook.on_activate()),
            ("on_destroy", hook.on_destroy()),
            ("on_attach", hook.on_attach()),
            ("on_detach", hook.on_detach()),
        ]
        .into_iter()
        .filter_map(|(event, script)| script.map(|s| (event, s)))
        .for_each(|(event, script)| {
            let kind = match script.body() {
                sessions::core::lifecyclehook::HookScriptBody::Inline(_) => "inline",
                sessions::core::lifecyclehook::HookScriptBody::External(_) => "external",
            };
            tracing::info!(
                session = session_name,
                domain = "lifecycle_hook",
                event,
                kind,
                timeout_secs = script.timeout().as_secs(),
                description = hook.description().unwrap_or_default(),
                source = ?src,
                "session content (lifecycle hook: composed, not yet executed)",
            );
        });
    }
}

/// Why the binding's mainloop ended. Declared at module scope because the
/// loop's head — the ask dialog (NET-045) — can end it too: a teardown that
/// arrives mid-dialog renders through [`Binding::render_farewell`], which
/// names the exit it ends in.
#[derive(Debug, PartialEq, Eq)]
enum MainloopExitReason {
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
    fn exit_status(&self) -> u32 {
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
enum Farewell {
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

enum BindingMsg {
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
const EIO_ON_EXIT: i32 = libc::EIO;

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
fn shell_is_already_gone(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(EIO_ON_EXIT)
}

/// Why a host is tearing its attached binding down, assembled *after* the
/// process has been reaped so that both halves are known at once.
///
/// The two are independent, and neither alone is enough to tell the user what
/// happened: the pty error says how the host found out, the exit reason says
/// what actually became of their shell.
#[derive(Debug)]
struct TeardownCause {
    /// The master read/write failure that unwound the host, when one did.
    /// `None` when the loop's reap won the race and the pty never reported
    /// anything. The expected `EIO`-on-exit is carried here but not shown.
    pty_err: Option<std::io::Error>,
    /// How the process ended, once reaped. `None` only if the reap failed.
    exit: Option<ExitReason>,
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
    fn notices(&self) -> Vec<String> {
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
enum PtyOp {
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
    fn as_str(self) -> &'static str {
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
struct StdinMsg {
    // The sender's binding generation; must equal the host's active
    // generation to be honored.
    generation: u64,
    kind: StdinMsgKind,
}

impl StdinMsg {
    /// Stamps `kind` as sent by a binding of `generation`.
    fn new(generation: u64, kind: StdinMsgKind) -> Self {
        Self { generation, kind }
    }
}

enum StdinMsgKind {
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
fn queue_stdin(buf: &mut Option<(bytes::Bytes, usize)>, bytes: Vec<u8>) {
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
struct Binding {
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
    control: Option<SessionControl>,
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
type BindingSlot = (mpsc::Sender<BindingMsg>, JoinHandle<()>, CancellationToken);

/// The line a shed binding leaves on the terminal before its channel closes.
const SHED_NOTICE: &[u8] =
    b"\r\nDisconnecting - the terminal stopped keeping up with session output; \
      re-attach with `min session attach`\r\n";

/// The exit status a shed binding reports. It is ssh's own "connection
/// failed" status on purpose: the client restores the terminal itself only
/// on this status (see `client_must_unwind` in the `min` CLI), and after a
/// shed it has to, because the output stream was cut mid-flight and no
/// unwind codes followed it.
const SHED_EXIT_STATUS: u32 = 255;

/// The exit status of an attach the daemon ended: the session was destroyed
/// (or otherwise went away), another connection took it over, or the daemon
/// is shutting down. Non-zero so a script does not read it as a detach, and
/// not ssh's 255, because the daemon still spoke for itself: these ends send
/// their own unwind codes or none are owed, so the client's blind unwind (see
/// [`SHED_EXIT_STATUS`]) stays off.
const DAEMON_ENDED_EXIT_STATUS: u32 = 254;

/// The line a binding whose host went away leaves on the terminal: the
/// session is gone, so there is no farewell from the host to render.
const HOST_GONE_NOTICE: &[u8] = b"\r\nDisconnecting - the session is gone\r\n";

/// Hands a departing binding its teardown message and waits for it to
/// finish, so its farewell lands before whatever comes next.
///
/// The wait is bounded because this runs inside the host loop. A binding
/// whose client stopped draining can neither take the message nor finish,
/// and past [`HOST_PROBE_TIMEOUT`](crate::session::HOST_PROBE_TIMEOUT) it is
/// shed instead, which still closes its channel.
async fn retire_binding((tx, mut task, shed): BindingSlot, msg: BindingMsg) {
    let orderly = async {
        let _ = tx.send(msg).await;
        let _ = (&mut task).await;
    };
    if tokio::time::timeout(crate::session::HOST_PROBE_TIMEOUT, orderly)
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
    pub(crate) async fn spawn(
        channel: Channel<Msg>,
        stdin_tx: mpsc::Sender<StdinMsg>,
        generation: u64,
        control: Option<SessionControl>,
        delta: Option<Arc<DeltaSource>>,
        name: String,
        archives_dir: std::path::PathBuf,
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
            shed: shed.clone(),
        };

        // The channel id ties every line this binding logs back to the
        // connection span's `accepted connection`/`closed` lines — field
        // analysis stalls without that correlation.
        // The session name rides the span too: the channel id correlates these
        // lines with the connection's `accepted connection`/`closed` pair, but
        // only the name says *which* session an operator's report is about.
        let span = tracing::info_span!(
            "binding",
            channel = %binding.channel.id(),
            session = %binding.name,
        );
        (tx, tokio::spawn(binding.run().instrument(span)), shed)
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
            let _ =
                tokio::time::timeout(crate::session::HOST_PROBE_TIMEOUT, w.write_all(notice)).await;
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
        let _ = w
            .write_all(format!("\r\n{name} asks to publish port {port}.\r\n").as_bytes())
            .await;
        let select = async_dialog::Select::new()
            .with_prompt(ASK_PROMPT)
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
    async fn shell_exit_prompt<R, W>(
        delta: Option<&Arc<DeltaSource>>,
        control: Option<&SessionControl>,
        archives_dir: &std::path::Path,
        name: &str,
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

        let mut items =
            vec!["Exit, leaving the session filesystem in place and recoverable".to_string()];
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
enum ExitDisposition {
    /// The session survives the shell that exited.
    Kept,
    /// The session was torn down, running its `on_destroy` hooks on the way.
    Destroyed,
}

/// How a session process ended, as `hakoniwa` accounts for it.
///
/// Kept alongside the portable exit code because the code alone cannot say
/// whether a session *ended* or was *killed*: a clean `exit 0` and a SIGKILL
/// both close every slave fd, both surface on the master as the same `EIO`,
/// and both otherwise raise the same silent shell-exit prompt. This is what
/// separates them, in the log and on the user's terminal.
#[derive(Debug, Clone)]
pub(crate) struct ExitReason {
    /// `hakoniwa`'s portable code: the inner process's own status when it
    /// exited normally, or `125` when the container itself failed or was
    /// signalled.
    pub(crate) code: i32,
    /// `Some(status)` when the inner process exited on its own, `None` when it
    /// was signalled or the container failed out from under it — the
    /// discriminator behind [`Self::is_abnormal`].
    pub(crate) exit_code: Option<i32>,
    /// `hakoniwa`'s human account, e.g. `container received signal SIGKILL` or
    /// `process(/usr/bin/bash) exited with code 0`. Shown to the user verbatim
    /// when the end was abnormal.
    pub(crate) reason: String,
}

impl ExitReason {
    /// Whether the process failed to exit under its own control — signalled,
    /// or the container failed. Exactly `hakoniwa`'s `exit_code: None`, which
    /// it sets both on its `received signal` path and on the `new_failure`
    /// path behind a container-level SIGKILL.
    pub(crate) fn is_abnormal(&self) -> bool {
        self.exit_code.is_none()
    }
}

/// A handle to a launched session process.
///
/// Abstracts the process the [`Host`] supervises so its runtime loop can be
/// driven against a real sandboxed process or a test double. `try_wait` and
/// `wait` reduce the `hakoniwa::ExitStatus` payload to a portable exit code;
/// [`Self::exit_reason`] carries the part of it that has to reach the user.
pub(crate) trait SessionProcess: Send + 'static {
    /// Returns the PID of hakoniwa's container supervisor — **not** the PID of
    /// the shell it exec'd.
    ///
    /// The supervisor unshared the sandbox's namespaces itself, so this is a
    /// valid handle for all of them except the PID namespace, which it created
    /// for its children without entering. Use
    /// [`Host::session_leader_pid`](Host::session_leader_pid) for the shell's
    /// own PID; see [`crate::nsenter`] for why the distinction matters.
    fn container_pid(&self) -> u32;
    /// Returns `Some(code)` if the process has exited, `None` if still running.
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    /// Blocks until the process exits, returning its exit code.
    fn wait(&mut self) -> io::Result<i32>;
    /// Sends a kill signal to the process.
    fn kill(&mut self) -> io::Result<()>;
    /// `hakoniwa`'s account of how the process ended, available once
    /// [`Self::try_wait`] has returned `Some` or [`Self::wait`] has returned.
    ///
    /// `None` until the reap; [`HostProcess`] caches the reason at that point
    /// and answers from it thereafter.
    fn exit_reason(&self) -> Option<ExitReason>;
}

/// A backend's answer to a reap: the portable code a [`SessionProcess`] reduces
/// the child's status to, plus the account to cache for
/// [`SessionProcess::exit_reason`].
pub(crate) struct ExitReport {
    /// The code `wait`/`try_wait` returns.
    code: i32,
    /// The account cached on the first reap.
    reason: ExitReason,
}

/// The process-creation backend behind [`HostProcess`]: the one part of a
/// [`SessionProcess`] that differs between the real sandboxed child and the
/// test double. Everything else — the exit-reason cache and its record-once
/// policy — lives in [`HostProcess`] and is shared.
pub(crate) trait ProcessBackend: Send + 'static {
    /// See [`SessionProcess::container_pid`].
    fn container_pid(&self) -> u32;
    /// See [`SessionProcess::try_wait`]; `Ok(None)` while the process runs.
    fn try_wait(&mut self) -> io::Result<Option<ExitReport>>;
    /// See [`SessionProcess::wait`].
    fn wait(&mut self) -> io::Result<ExitReport>;
    /// See [`SessionProcess::kill`].
    fn kill(&mut self) -> io::Result<()>;
    /// Logs the backend's account of an observed exit. Called exactly once per
    /// session by [`HostProcess::record_exit`]; the default is silent, so a
    /// backend with nothing to say (the mock) need not implement it.
    fn log_exit(_reason: &ExitReason) {}
}

/// The single [`SessionProcess`] implementation, generic over the backend that
/// owns the actual child. Holds the exit reason cached at the first reap, so
/// [`SessionProcess::exit_reason`] can answer after the fact for both the real
/// sandboxed child and the test double.
pub(crate) struct HostProcess<B: ProcessBackend> {
    backend: B,
    /// The reason captured at the reap; `None` until then.
    exit: Option<ExitReason>,
}

impl<B: ProcessBackend> HostProcess<B> {
    fn new(backend: B) -> Self {
        Self {
            backend,
            exit: None,
        }
    }

    /// Logs the backend's account of an observed exit and caches it for
    /// [`SessionProcess::exit_reason`], returning the portable code.
    ///
    /// Caches and logs on the first reap only, not on every subsequent one: the
    /// child caches its own status, so a `wait` following a `try_wait` that
    /// already saw the death would otherwise log the same end twice.
    fn record_exit(&mut self, report: ExitReport) -> i32 {
        if self.exit.is_none() {
            B::log_exit(&report.reason);
            self.exit = Some(report.reason);
        }
        report.code
    }
}

impl<B: ProcessBackend> SessionProcess for HostProcess<B> {
    fn container_pid(&self) -> u32 {
        self.backend.container_pid()
    }

    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        let report = self.backend.try_wait()?;
        Ok(report.map(|r| self.record_exit(r)))
    }

    fn wait(&mut self) -> io::Result<i32> {
        let report = self.backend.wait()?;
        Ok(self.record_exit(report))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.backend.kill()
    }

    fn exit_reason(&self) -> Option<ExitReason> {
        self.exit.clone()
    }
}

/// Opens a PTY of the requested size, launches the session process
/// wired to the slave side, and yields the master side plus a
/// handle to the process. The seam between the generic [`Host`]
/// runtime and the process-creation backend.
pub(crate) trait SessionLauncher {
    /// The running-process handle this launcher produces.
    type Process: SessionProcess;
    /// A value held for the session's lifetime, for its `Drop` (it owns the
    /// sandbox files backing the running process's rootfs) and as the live view
    /// of the session's environment. Dropped after [`Self::Process`].
    type Guard: SessionGuard;

    /// Launches the session's shell, placing its host-address box in a
    /// classifier leaf named by `session_id` when this host has one.
    ///
    /// `guest` is the daemon's own posture — whether this daemon is a
    /// microVM's pid 1 — handed in per launch rather than read from
    /// [`crate::guest`] inside, because the launch decision it scopes (a
    /// guest refuses a host-address box it cannot place; a native host runs
    /// it unenforced) is exactly what a launcher test has to be able to pose.
    fn launch(
        self,
        guest: bool,
        session_id: sessions::SessionId,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
    ) -> impl Future<Output = io::Result<Launched<Self::Process, Self::Guard>>> + Send;
}

/// Where a command should start in a session, and with what environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct SessionEnvironment {
    /// Absolute path inside the sandbox: `/workbench` for a session.
    pub(crate) cwd: String,
    /// The composed session variables, layout defaults included, plus anything
    /// installed into the session since it launched.
    pub(crate) vars: BTreeMap<String, String>,
}

/// The launcher-owned value a [`Host`] holds for its session's lifetime.
///
/// Primarily a `Drop` guard — it owns the sandbox files backing the running
/// process's rootfs — but it is also the live handle to the session's
/// environment.
pub(crate) trait SessionGuard: Send + 'static {
    /// The working directory and environment a command should run with in this
    /// session, as of now.
    fn command_environment(&self) -> SessionEnvironment;
}

/// The mock launcher has no sandbox, so there is nothing to describe.
#[cfg(test)]
impl SessionGuard for () {
    fn command_environment(&self) -> SessionEnvironment {
        SessionEnvironment::default()
    }
}

impl SessionGuard for crate::env::Env {
    fn command_environment(&self) -> SessionEnvironment {
        crate::env::Env::command_environment(self)
    }
}

/// The product of [`SessionLauncher::launch`].
pub(crate) struct Launched<P, G> {
    /// Master side of the launched process's PTY; the slave is wired to the
    /// process. The [`Host`] reads its stdout and writes its stdin here.
    master: OwnedFd,
    /// Handle used to wait on / signal the launched process.
    process: P,
    /// Kept alive for the session; see [`SessionLauncher::Guard`].
    guard: G,
    /// The per-sandbox network attachment (own-IP switch wiring), if any. Torn
    /// down explicitly via [`sandbox2::NetGuard::teardown`] at session end.
    /// `None` for `HostNet`/`NoNet` and for the plain mock.
    net_guard: Option<Box<dyn sandbox2::NetGuard>>,
    /// Path of the session PTY's slave side, so hooks can open the
    /// terminal briefly rather than the host retaining a descriptor.
    tty_path: std::path::PathBuf,
    /// Whether processes injected into this session are entering a none box,
    /// so the shim must reinstall the none plan's full socket-family seal;
    /// every other box's injected processes reinstall the confined-families
    /// seal the shim defaults to.  Every injection is sealed, since the
    /// filter is inherited only by children of the filtered process.
    seal_injection: bool,
    /// The box's classifier leaf (NET-079): the cgroup its egress verdict is
    /// decided on, and the one every process of the session — injected ones
    /// included — is placed in. `None` on a host that places no box: the tree
    /// is absent, and while a native session then runs unenforced rather than
    /// refused on that ground, a guest's host-address launch is refused
    /// instead (design §7.1).
    leaf: Option<sandbox2::config::ClassifierLeaf>,
    /// What the launch decided about this box's egress verdict: enforced on
    /// a leaf of its own, or unenforced on a host that could not decide per
    /// box. Carried to the host's attributes so a session can say which it
    /// runs under — the launch's own decision, not a re-derivation.
    host_ip_enforcement: Option<HostIpEnforcement>,
    /// The listen plan the launch gathered for the box it launched: the
    /// lease, the published address, the switch control channel, the gate
    /// and the publication set its watcher publishes through. `None` when
    /// the launch could build no plan — no lease, no published address or no
    /// live gate — and a mock launch that builds none starts no watcher at
    /// all. The plan rides here rather than a table between the two, so it
    /// is this launch's own from the moment it is built: it never survives
    /// to a spawn that did not gather it.
    listen_plan: Option<crate::net::listeners::ListenPlan>,
}

/// Actor messages to a [`Host`].
enum Message {
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
fn wire_color(color: vt100::Color) -> Option<String> {
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
fn screen_to_snapshot(screen: &vt100::Screen) -> minimald_rpc::ScreenSnapshot {
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
struct ParserEventHandler(WeakHostHandle);
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
struct WeakHostHandle {
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
/// [`HOST_PROBE_TIMEOUT`](crate::session::HOST_PROBE_TIMEOUT).
pub(crate) const HOST_MAILBOX_CAPACITY: usize = 8;

/// How long an attached binding may take no session output at all before
/// the host sheds it.
///
/// Until then a binding that falls behind gets backpressure: the host stops
/// reading the pty while the binding's mailbox is full, so the shell waits on
/// the terminal, and the loop keeps serving its own mailbox. The bound is far
/// longer than [`HOST_PROBE_TIMEOUT`](crate::session::HOST_PROBE_TIMEOUT)
/// because it catches something else. The probe deadline asks whether the
/// host is alive. This one asks whether the client has stopped reading
/// altogether. A slow terminal drains a mailbox slot in milliseconds, so it
/// never gets near this bound.
pub(crate) const OUTPUT_STALL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The handle to the session host - the running process.
#[derive(Debug, Clone)]
pub struct HostHandle {
    sender: mpsc::Sender<Message>,
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
}

impl HostHandle {
    fn make_weak(&self) -> WeakHostHandle {
        WeakHostHandle {
            sender: self.sender.downgrade(),
        }
    }

    pub async fn kill(&self, for_shutdown: bool) -> Result<(), ()> {
        match self
            .sender
            .send_timeout(
                Message::Kill(for_shutdown),
                crate::session::HOST_PROBE_TIMEOUT,
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
                crate::session::HOST_PROBE_TIMEOUT,
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
                crate::session::HOST_PROBE_TIMEOUT,
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
    /// [`crate::session_delta::assess`].
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
    /// request belongs to (see how [`crate::session`] routes the ask).
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

/// What the launch's leaf placement means for the box's egress record: the
/// placement is the outcome the launch records — `per_box` when this launch
/// placed this host-address box in a classifier leaf of the host's tree,
/// `none` when it did not — never the node fact re-read beside it, because
/// the record is the box's own launch outcome, not the host's state as it
/// stands now. A leaf placed over a table that is not refusing still carries
/// the leaf: the reads lower it to the state the host can currently honour
/// ([`displayed_host_ip_enforcement`]), and when the table comes back the
/// box is in the leaf its launch placed it in, so the record says so without
/// a relaunch. A host-address box without a leaf ran with the host's address
/// and no verdict of its own, and any other network mode has no host address
/// to decide on at all.
///
/// The box's declaration is the placement's other half (NET-079): a leaf
/// is only an enforcement while the declaration is one the classifier can
/// enforce, so the record is derived from the placement *plus*
/// [`classifier::unenforceable_rules`] — never from the placement or the
/// node fact alone — and a placed box whose declaration names a rule the
/// loaded table cannot enforce is recorded `none`, the state it ran in, on
/// whatever host it ran on. That is the shape the launch gate above refuses
/// when the host decides per box; this derivation is what keeps the record
/// honest for the one host that cannot decide, where the box still runs and
/// the record must not promise a verdict its rules never had.
///
/// Pure over its inputs, so the mapping is pinned where it is written.
fn host_ip_enforcement(
    network_mode: NetworkMode,
    leaf: Option<&sandbox2::config::ClassifierLeaf>,
    declaration: Option<&sessions::EgressPolicy>,
) -> Option<HostIpEnforcement> {
    match network_mode {
        NetworkMode::HostNet => Some(match leaf {
            Some(_) if crate::net::classifier::unenforceable_rules(declaration).is_empty() => {
                HostIpEnforcement::PerBox
            }
            _ => HostIpEnforcement::None,
        }),
        _ => None,
    }
}

/// The state of the session process.
///
/// Generic over the [`SessionProcess`] it supervises and the [`SessionLauncher`]
/// guard kept alive for the session, so the runtime loop can be driven against a
/// real sandboxed process or a test double.
pub(crate) struct Host<P: SessionProcess, G: SessionGuard> {
    /// Channel for actor messages via [`HostHandle`].
    receiver: mpsc::Receiver<Message>,

    /// The async task and its channel that wires the session
    /// to the ssh channel, if currently attached.
    remote: Option<BindingSlot>,

    /// See [`OUTPUT_STALL_TIMEOUT`]; a field only so a test can shorten it.
    output_stall_timeout: std::time::Duration,
    /// When the attached binding, whose mailbox is full, gets shed. Armed when
    /// the host first finds the mailbox full, and cleared as soon as a slot
    /// frees up.
    output_stall_deadline: Option<tokio::time::Instant>,

    /// The last-set pty terminal size.
    sz: WinSize,
    /// In-memory representation of the terminal state.
    parser: vt100::Parser<ParserEventHandler>,
    /// The session process.
    process: P,
    /// The pty-master failure that unwound the host, held from the moment
    /// [`Host::step`] hit it until [`Host::mainloop`] has reaped the process.
    ///
    /// The binding cannot be told why it is going away until both are known —
    /// the error says how the host noticed, the reap says what became of the
    /// shell — and the reap is the slower of the two. Set only by a pty
    /// failure, never by a deliberate kill, which is what keeps a destroy from
    /// raising a shell-exit prompt.
    pending_pty_err: Option<std::io::Error>,
    /// The master-side fd of the Pty.
    master: AsyncFd<std::fs::File>,
    /// Various attributes about the running terminal.
    attrs: HostAttrs,

    // Writer for bytes coming from the remote - i.e. 'stdin' keystrokes
    // that need to get written to the pty. Clones of this sender are
    // given to [`Binding::spawn`].
    remote_tx: mpsc::Sender<StdinMsg>,
    // Recieve-end for bytes coming from the remote - i.e. 'stdin' keystrokes.
    // We process this end.
    remote_rx: mpsc::Receiver<StdinMsg>,

    // Monotonic identity of the currently active binding. Bumped by
    // `attach()` before the new binding is spawned, so an [`StdinMsg`] whose
    // generation lags this was queued by a superseded binding and gets
    // discarded rather than interpreted under the new channel's session keys.
    binding_generation: u64,

    // Temporary buffer for reading from the pty master (i.e. 'stdout').
    stdout_buf: Vec<u8>,
    // Bytes that need to be written to the pty master (i.e. 'stdin').
    //
    // (<buffer>, <number of bytes from buffer already written>)
    stdin_buf: Option<(bytes::Bytes, usize)>,

    // The per-sandbox network attachment (own-IP switch wiring), if any. Torn
    // down explicitly in `mainloop` when the session ends, before `_guard` (and
    // thus the sandbox files) is dropped. `None` for `HostNet`/`NoNet` and
    // net-guard-less tests.
    net_guard: Option<Box<dyn sandbox2::NetGuard>>,

    /// The box's listen-publication watcher (NET-016, NET-017): publishes
    /// the ports its processes listen on when the box's ingress rules
    /// permit them, and withdraws each one whose listener closed. Started
    /// in `build` from the plan the launch staged, stopped in `mainloop`
    /// before the network attachment tears down — so every
    /// runtime-published forward is gone before the switch's tap does.
    /// `None` for boxes with nothing to publish on (tests, `HostNet`/`NoNet`,
    /// and any launch that staged no plan).
    listen_watcher: Option<crate::net::listeners::ListenWatcher>,

    /// The session's hostname-registry marker (NET-128): marked running when
    /// this host's `mainloop` starts and stopped when it returns, so a name
    /// the box shares with its node answers NODATA while no host is running.
    /// `None` for hosts built without one (tests, and a task's host).
    #[cfg(target_os = "linux")]
    name_marker: Option<NameMarker>,

    /// Path of the session PTY's slave side. Attach and detach hooks
    /// open it briefly so their stdout is a real terminal; the host
    /// never holds a descriptor on it, because one open slave fd stops
    /// the master from ever seeing EOF.
    tty_path: std::path::PathBuf,
    /// The composed hooks, so the attach and detach transitions can run
    /// them. `None` for a host spawned without one (tests, and a
    /// restart-orphaned actor).
    composition: Option<Arc<sessions::core::compose::Composition>>,
    /// Identity and paths a hook run needs.
    session_id: sessions::SessionId,
    hooks_dir: paths::DaemonAbsPath,
    workspace_dir: paths::DaemonAbsPath,

    // Destroy capability handed to each binding this host spawns, so a
    // shell-exit "delete" can tear the whole session down. `None` for hosts
    // built without a manager (the test harness).
    control: Option<SessionControl>,

    // Workspace baseline taken before the process launched, handed to each
    // binding so the shell-exit prompt can list the files changed during the
    // session. `None` when the workspace could not be walked at build time;
    // the prompt then renders without a delta.
    delta: Option<Arc<DeltaSource>>,

    // The session's workspace root, kept for the at-risk assessment
    // (`Message::GetAtRisk`): the VCS mode needs the tree path even when
    // the baseline snapshot could not be armed.
    workspace_root: std::path::PathBuf,

    // Whether processes injected into this session are entering a none box.
    // Set at launch from the plan's seal — the none plan's full seal is the
    // one an injected process must be told about explicitly, every other
    // box's confined-families seal is the shim's default — since the filter
    // installed at launch is inherited by children of the first process, not
    // by later processes that join its namespaces via `nsenter`.
    #[cfg_attr(test, allow(dead_code))]
    seal_injection: bool,

    /// The box's classifier leaf (NET-079): handed to every process injected
    /// into this session so it joins the leaf — in the shim, before it joins
    /// the box's namespaces, from the daemon's own cgroup namespace where the
    /// leaf is reachable. `None` on a host that places no box.
    #[cfg_attr(test, allow(dead_code))]
    leaf: Option<sandbox2::config::ClassifierLeaf>,

    // The session's display name, handed to each binding so the shell-exit
    // prompt's save-then-delete lane can name its archive.
    session_name: String,

    /// The attached terminal's facts as of the latest attach, layered over the
    /// session's own environment for everything this host runs in the sandbox
    /// (`command_in_session`) and republished into the session's home so the
    /// already-running shell can pick them up at its next prompt.
    connection_env: ConnectionEnv,

    /// Daemon-side path of the session's home directory — the same directory
    /// the sandbox mounts at [`SESSION_HOME_ROOT`]. Held so the per-attach
    /// environment files can be written without entering the sandbox.
    home_dir: paths::DaemonAbsPath,

    // Daemon-side directory the save-then-delete lane archives into, handed
    // to each binding alongside `delta`.
    archives_dir: std::path::PathBuf,

    // The per-channel session-key chord matcher: the negotiated leader chord
    // that enters command mode, the detach/forward subcommand keys, the bell
    // flag, plus the command-mode state and the pending split-candidate
    // buffer. Refreshed from the channel's env vars on every attach (so two
    // clients with different configs on the same session each get their own
    // chord, and a reattach never inherits a stale awaiting-subcommand state
    // or half a split candidate); defaults to `ctrl-]` / `d` when a client
    // sends no keys.
    chord_matcher: ChordMatcher,

    // Deadline for flushing a held chord-matcher split candidate: armed when a
    // stdin chunk leaves the matcher holding a partial form (e.g. a lone `ESC`,
    // a prefix of every kitty form), cleared when the next chunk resolves it or
    // the idle gap elapses and the candidate is flushed to the PTY as data.
    chord_flush_deadline: Option<tokio::time::Instant>,

    // Keeps launcher-owned resources (the session's `Env`, which owns the
    // sandbox files backing the running process's rootfs along with the context
    // and graph) alive for as long as this host (and thus the session process)
    // lives. Declared last so it is dropped after `process`: the process is torn
    // down before the sandbox files backing its rootfs are removed. Also read,
    // via `SessionGuard`, for the session's current environment.
    guard: G,
}

/// An owned snapshot of everything a hook run needs.
///
/// Owned rather than borrowed because a `Host` holds a non-`Sync`
/// `dyn NetGuard`: keeping a `&Host` alive across an await would make
/// the whole session future non-`Send`.
struct HookPlan {
    event: crate::hooks::HookEvent,
    commands: crate::hooks::InjectedCommands,
    composition: Arc<sessions::core::compose::Composition>,
    session_id: sessions::SessionId,
    session_name: String,
    hooks_dir: paths::DaemonAbsPath,
    workspace: paths::DaemonAbsPath,
    output: crate::hooks::HookOutput,
}

/// Writes the session's per-attach environment files: `env` rendered into
/// [`ATTACH_ENV_SH_REL`], [`ATTACH_ENV_FISH_REL`], and [`ATTACH_ENV_JSON_REL`]
/// under the session's `home` directory.
///
/// This is how a fact about the *current* terminal reaches a shell that was
/// spawned for a previous one — a process's `environ` cannot be rewritten from
/// outside, so the value is published to a file the shell re-reads, at every
/// prompt and before every command, through the hooks `crate::env` installs
/// into the session rootfs. Written from the daemon's side of the session home
/// rather than through the sandbox: it is the same directory, and it works
/// before the session has anything running to inject into.
///
/// Best-effort. A failure here costs a stale `TERM` in the shell, which must
/// never be allowed to refuse an attach.
async fn write_connection_env(home: paths::DaemonAbsPath, env: ConnectionEnv) {
    // Nothing to say: leave whatever the last attach published in place. An
    // attach that carries no facts is a client that couldn't describe its
    // terminal, not a client asserting there is no terminal.
    if env.is_empty() {
        return;
    }

    let dir = home.sub_path_unchecked(ATTACH_ENV_DIR_REL);
    if let Err(e) = tokio::fs::create_dir_all(dir.as_str()).await {
        tracing::warn!(error = %e, dir = %dir, "creating the per-attach env dir");
        return;
    }

    let mut sh = String::from("# Written by minimald on attach; edits are lost.\n");
    let mut fish = sh.clone();
    for (k, v) in &env {
        // Single quotes are the only quoting both shells read literally. POSIX
        // has no escape inside them, so a quote is closed, escaped, and
        // reopened; fish does take a backslash escape.
        sh.push_str(&format!("export {k}='{}'\n", v.replace('\'', r"'\''")));
        fish.push_str(&format!(
            "set -gx {k} '{}'\n",
            v.replace('\\', r"\\").replace('\'', r"\'")
        ));
    }

    // The data form. Serialized rather than hand-rendered so the escaping is
    // the serializer's problem; a failure here is not fatal to the others.
    let json = match serde_json_lenient::to_string_pretty(&env) {
        Ok(j) => Some(j),
        Err(e) => {
            tracing::warn!(error = %e, "rendering the per-attach env as JSON");
            None
        }
    };

    let files = [
        (ATTACH_ENV_SH_REL, Some(sh)),
        (ATTACH_ENV_FISH_REL, Some(fish)),
        (ATTACH_ENV_JSON_REL, json),
    ];
    for (rel, body) in files {
        let Some(body) = body else { continue };
        let path = home.sub_path_unchecked(rel);

        // Write a sibling and rename over the destination, rather than
        // truncating in place. A shell reads these files constantly — bash's
        // `DEBUG` trap sources one before every command — so an in-place
        // rewrite has a window where a reader sees a truncated file, and half
        // an `export TERM='xterm-256co` is a syntax error on the user's
        // terminal. `rename(2)` is atomic within a directory, and the sibling
        // is in the same one by construction.
        let tmp = home.sub_path_unchecked(&format!(
            "{rel}.{}.{}.tmp",
            std::process::id(),
            ATTACH_ENV_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        if let Err(e) = tokio::fs::write(tmp.as_str(), body).await {
            tracing::warn!(error = %e, path = %tmp, "writing the per-attach env file");
            // Nothing was published, so nothing is half-written — but the
            // sibling may exist and must not accumulate.
            let _ = tokio::fs::remove_file(tmp.as_str()).await;
            continue;
        }
        if let Err(e) = tokio::fs::rename(tmp.as_str(), path.as_str()).await {
            tracing::warn!(error = %e, path = %path, "publishing the per-attach env file");
            let _ = tokio::fs::remove_file(tmp.as_str()).await;
        }
    }
}

/// Distinguishes the temporary files [`write_connection_env`] renames into
/// place, so two attaches publishing at once cannot pick the same sibling and
/// clobber each other's half-written file.
static ATTACH_ENV_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Run a snapshotted plan, warning on any hook that failed.
///
/// Never fatal: an attach must not be refused, and a detach must not be
/// blocked, because a hook misbehaved.
async fn run_hook_plan(plan: HookPlan) {
    let ctx = crate::hooks::HookContext {
        session_id: plan.session_id,
        session_name: &plan.session_name,
        composition: &plan.composition,
        hooks_dir: plan.hooks_dir,
        workspace: plan.workspace,
    };
    // No budget: the only event still routed through the host is
    // `on_attach`, which runs on the user's terminal under a command
    // they can interrupt. Teardown is budgeted where it runs, on the
    // session actor.
    for o in crate::hooks::run_hooks(&plan.commands, &ctx, plan.event, plan.output, None).await {
        if o.failed() {
            tracing::warn!(
                session = plan.session_name,
                event = o.event,
                declared_by = %o.declared_by,
                status = ?o.status,
                "lifecycle hook failed",
            );
        }
    }
}

/// The real sandboxed child backend: a [`hakoniwa::Child`].
pub(crate) struct SandboxBackend {
    child: hakoniwa::Child,
    /// The box's classifier leaf (NET-079), removed when this backend — and
    /// so the session's last process — is dropped: a leaf does not outlive the
    /// box it decided.
    leaf: Option<sandbox2::config::ClassifierLeaf>,
}

impl SandboxBackend {
    /// Reduces `hakoniwa`'s account of an exit to the shared [`ExitReport`].
    fn report(s: hakoniwa::ExitStatus) -> ExitReport {
        ExitReport {
            code: s.code,
            reason: ExitReason {
                code: s.code,
                exit_code: s.exit_code,
                reason: s.reason,
            },
        }
    }
}

impl ProcessBackend for SandboxBackend {
    fn container_pid(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitReport>> {
        let status = self
            .child
            .try_wait()
            .map_err(|e| io::Error::other(format!("wait failed: {e}")))?;
        Ok(status.map(Self::report))
    }

    fn wait(&mut self) -> io::Result<ExitReport> {
        // The blocking reap the pty/step error path takes — in practice the
        // one that fires, since the master's `EIO` beats the loop's `try_wait`
        // poll to every ordinary exit.
        let s = self
            .child
            .wait()
            .map_err(|e| io::Error::other(format!("wait failed: {e}")))?;
        Ok(Self::report(s))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.child
            .kill()
            .map_err(|e| io::Error::other(format!("kill failed: {e}")))
    }

    /// Logs on every exit, not just the non-zero ones, exactly once per session
    /// (gated by [`HostProcess::record_exit`]'s cache): `hakoniwa` caches the
    /// status, so a `wait` following a `try_wait` that already saw it would
    /// otherwise log the same death twice.
    fn log_exit(reason: &ExitReason) {
        if reason.code != 0 {
            tracing::warn!(
                code = reason.code,
                exit_code = ?reason.exit_code,
                reason = %reason.reason,
                "DIAG hakoniwa container/process exited non-zero"
            );
        } else {
            tracing::info!(
                code = reason.code,
                exit_code = ?reason.exit_code,
                reason = %reason.reason,
                "hakoniwa container/process exited"
            );
        }
    }
}

impl Drop for SandboxBackend {
    /// Tears the box down and removes its leaf (NET-079): a leaf does not
    /// outlive the box it decided, and a [`hakoniwa::Child`] does not
    /// terminate when dropped — without the kill, dropping a host that never
    /// reaped its process would both orphan the sandbox and leave a leaf in
    /// the tree with a process still in it.
    ///
    /// In the ordinary paths both are no-ops: `mainloop` reaps the process
    /// before it returns (even on a kill — the loop's `wait()` at the
    /// bottom), and `hakoniwa` caches the status so `wait` after a reap
    /// returns it instead of blocking. The kill+wait here is for the paths
    /// that skip all of that — an aborted loop future, most notably — where
    /// SIGKILL is the bounded way out.
    fn drop(&mut self) {
        let Some(leaf) = self.leaf.take() else {
            return;
        };
        // `kill` and `wait` are independent: a process that already exited
        // fails the kill with `ESRCH` but still needs reaping.
        if let Err(e) = self.child.kill() {
            tracing::warn!(error = %e, "killing session process at teardown");
        }
        if let Err(e) = self.child.wait() {
            tracing::warn!(error = %e, "reaping session process at teardown");
        }
        // The leaf goes last, once nothing is in it — and outlasting the
        // box's last moments, because a SIGKILLed box's cgroup can refuse
        // its `rmdir` (`EBUSY`) for a few milliseconds after the reap while
        // the kernel empties it. A refusal at the first try would leak the
        // leaf until a later launch of the same session id reclaimed it or
        // the daemon restarted, so the removal is retried briefly before it
        // is warned about; a leaf that still refuses is a warn and an empty
        // directory — named by its session's id, so no later session can be
        // launched into it, and swept away at the next daemon start.
        if let Err(e) = remove_box_leaf_patiently(leaf.dir(), DROP_LEAF_REMOVAL_ATTEMPTS, |_| {
            std::thread::sleep(DROP_LEAF_REMOVAL_PAUSE)
        }) {
            tracing::warn!(
                leaf = %leaf.dir().display(),
                error = %e,
                "removing the session's classifier leaf"
            );
        }
    }
}

/// How many times a teardown tries to remove the box's leaf before warning
/// about a leak. One first try plus four retries.
const DROP_LEAF_REMOVAL_ATTEMPTS: usize = 5;

/// The pause between those tries: long enough for the kernel to finish
/// emptying a just-killed cgroup, short enough that a wedged teardown never
/// parks on it — 4 × 20 ms after the first refusal.
const DROP_LEAF_REMOVAL_PAUSE: std::time::Duration = std::time::Duration::from_millis(20);

/// Removes the box's leaf, retrying while a just-reaped box's cgroup may
/// still be dying: the `rmdir` of a cgroup the kernel has not finished
/// emptying comes back `EBUSY` for a few milliseconds after the last
/// process is reaped, and the removal is owed once — not indefinitely, so
/// the attempts are counted and the last refusal is returned for the caller
/// to warn.
///
/// `pause` is called with the number of the attempt that just failed —
/// before the next try — and is the seam the test drives: production sleeps
/// [`DROP_LEAF_REMOVAL_PAUSE`], a test clears the obstruction between two
/// attempts and proves the retry is what healed the removal.
fn remove_box_leaf_patiently(
    leaf: &std::path::Path,
    attempts: usize,
    mut pause: impl FnMut(usize),
) -> io::Result<()> {
    let attempts = attempts.max(1);
    for attempt in 1..attempts {
        if sandbox2::classifier::remove_box_leaf(leaf).is_ok() {
            return Ok(());
        }
        pause(attempt);
    }
    // The last attempt is the return, not another pause: its refusal is
    // what the caller warns with.
    sandbox2::classifier::remove_box_leaf(leaf)
}

/// A launched session process backed by a sandboxed [`hakoniwa::Child`].
pub(crate) type SandboxProcess = HostProcess<SandboxBackend>;

/// Packages every session sandbox gets unconditionally, regardless of
/// the client's contribution: `base` for the shell, `coreutils` for
/// `ls`/`cat`/etc, and `socat` for the `min` command bridge (the
/// helper installed at `/usr/bin/min` speaks to `/run/minenv_sock`
/// via `socat`).
const BASELINE_PACKAGES: &[&str] = &["base", "coreutils", "socat"];

/// Environment folded into a session shell at the launching attach, over and
/// above the composition. Both halves are captured from the SSH channel the
/// attach arrives on (see [`crate::session::Session::attach`]).
///
/// The two halves sit on opposite sides of the composition in precedence:
/// `inherited` are defaults the composition may override, `connection` are
/// authoritative facts that override the composition.
///
/// `inherited` is a launch-time fact: it describes the client that *created*
/// the shell and cannot be revised without respawning it. `connection` is a
/// per-attach fact — see [`ConnectionEnv`] — carried on every attach, not just
/// the one that mints the host.
///
/// The fields are read only by the real [`SandboxLauncher`]; the mock launcher
/// ignores them, so tolerate them being unread under `test`.
#[derive(Debug, Default, Clone)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct AttachEnv {
    /// Locale/timezone vars the client forwarded from its shell (`LANG`,
    /// `LC_*`, `TZ`) — OpenSSH's `AcceptEnv` set. Applied as defaults *below*
    /// the composition, so a loadout's explicit locale still wins.
    pub(crate) inherited: Vec<(String, String)>,
    /// Per-connection facts — `TERM` from the PTY request, plus the banner's
    /// detach hint the daemon derives from the channel's session keys. Applied
    /// *above* the composition, the way sshd sets `TERM`
    /// authoritatively regardless of shell dotfiles. (`SSH_TTY` and
    /// `SSH_CONNECTION`/`SSH_CLIENT` are deliberately not set: the session
    /// sandbox has no host `/dev/pts` and the Unix-socket transport has no peer
    /// address, so any value would name something that doesn't exist in-session.)
    pub(crate) connection: Vec<(String, String)>,
}

impl AttachEnv {
    /// The connection half as a map, for merging into a session environment.
    pub(crate) fn connection_env(&self) -> ConnectionEnv {
        self.connection.iter().cloned().collect()
    }

    /// Whether this attach declares a terminal (`TERM` from the PTY
    /// request). The detach hint the daemon seeds every attach with is not a
    /// terminal fact, so an empty-vs-non-empty map no longer answers this.
    pub(crate) fn declares_terminal(&self) -> bool {
        self.connection.iter().any(|(k, _)| k == "TERM")
    }
}

/// The facts that describe *the terminal currently attached*, as opposed to
/// the session's own composed environment: `TERM` from the PTY request, plus
/// the banner's detach hint derived from the channel's session keys, and
/// `MINIMAL_SESSION_NAME` when the session is renamed — republished so the
/// already-running shell picks up the new name at its next prompt.
///
/// Kept apart from [`AttachEnv`] because its lifetime is different. A session
/// shell is spawned once and lives across many attaches, so its `environ` is
/// frozen at launch — but `TERM` describes whichever terminal is on the other
/// end *now*, and a client attaching from a different terminal than the one
/// that minted the shell brings a different one. The host therefore keeps the
/// latest and republishes it on every attach ([`Host::publish_connection_env`])
/// rather than treating it as a launch-time constant.
pub(crate) type ConnectionEnv = std::collections::BTreeMap<String, String>;

/// Where the session home lives inside the sandbox.
///
/// Derived from the same `sandbox2` constant the sandbox mounts it from
/// (`crate::env::HOME_ROOT` is the same value; this module cannot use that one
/// because `env` is `cfg(not(test))` and these paths are asserted under test).
const SESSION_HOME_ROOT: &str = constcat::concat!("/", sandbox2::SESSION_HOME);

/// Session-home-relative directory holding the per-attach environment files.
const ATTACH_ENV_DIR_REL: &str = ".local/state/minimal";

/// POSIX-shell form of the per-attach environment, sourced by the baseline
/// [`BASELINE_PROMPT_COMMAND`] at every prompt.
const ATTACH_ENV_SH_REL: &str = constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.sh");

/// fish form of the same file, read by the fish hook the daemon installs into
/// the rootfs (`crate::env`). Written alongside the POSIX form because a
/// session's shell is whatever the user runs, not only the bash the daemon
/// spawns.
const ATTACH_ENV_FISH_REL: &str = constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.fish");

/// The same facts as data rather than as a script, for a shell that would
/// rather read them than evaluate them — nushell, today.
///
/// Nu cannot use either script form. `source` takes a *parse-time constant*
/// path, so it can't be pointed at `$env.MINIMAL_ATTACH_ENV_JSON`; and a
/// literal path that doesn't exist yet is a hard parse error, which would
/// break the shell outright on a session that has published nothing. Its
/// `load-env (open …)` reads this file instead, under a `path exists` guard.
/// JSON also sidesteps a third set of quoting rules — the escaping is the
/// serializer's problem, not this module's.
///
/// Every key here becomes an environment variable, so the file carries no
/// metadata (not even the "generated" banner the script forms have).
const ATTACH_ENV_JSON_REL: &str = constcat::concat!(ATTACH_ENV_DIR_REL, "/attach-env.json");

/// In-sandbox absolute path of the POSIX per-attach environment file.
pub(crate) const ATTACH_ENV_SH: &str = constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_SH_REL);

/// In-sandbox absolute path of the fish per-attach environment file.
pub(crate) const ATTACH_ENV_FISH: &str =
    constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_FISH_REL);

/// In-sandbox absolute path of the JSON per-attach environment file.
pub(crate) const ATTACH_ENV_JSON: &str =
    constcat::concat!(SESSION_HOME_ROOT, "/", ATTACH_ENV_JSON_REL);

/// The baseline shell's per-prompt wiring, in two halves.
///
/// Trigger half of the launcher-baseline orientation banner: evaluates the
/// [`BASELINE_MOTD`] payload at the first interactive prompt, then unsets
/// both vars so the banner prints exactly once and never for
/// non-interactive commands. Identical to the MOTD recipe the built-in
/// `default` loadout ships and `docs/reference/loadouts.md` ("Vars in the
/// attach shell") documents.
///
/// It carries nothing but the banner. The per-attach environment is refreshed
/// by the shell hooks the daemon installs into the rootfs (`crate::env`),
/// deliberately not from here: this variable is composed, so a loadout
/// setting its own `PROMPT_COMMAND` would replace the refresh, and the MOTD
/// recipe above would `unset` it — neither of which a session's `TERM` may
/// depend on.
const BASELINE_PROMPT_COMMAND: &str = r#"eval "$MINIMAL_MOTD"; unset PROMPT_COMMAND MINIMAL_MOTD"#;

/// Absolute workspace root inside a session sandbox, `/workbench` by
/// convention. Derived from the same [`sandbox2::SESSION_DEFAULT_WD`] the
/// sandbox uses as the shell's initial cwd (sessions never set a
/// `working_name_override`), so [`BASELINE_MOTD`]'s blueprint test cannot
/// drift from where the workspace actually lives.
const SESSION_WORKSPACE_ROOT: &str = constcat::concat!("/", sandbox2::SESSION_DEFAULT_WD);

/// Payload half of the launcher-baseline orientation banner: a STATIC
/// template. The dynamic parts resolve in-shell at print time: the
/// template interpolates `$MINIMAL_SESSION_NAME` and `$MINIMAL_LOADOUTS`
/// (both seeded by [`session_baseline_env`] — the loadout list arrives
/// from the client as the composition's first-class orientation field,
/// never as a user var); each carries a `${VAR:-fallback}` so a missing
/// var still renders sanely. Whether the workspace holds a blueprint is a
/// SESSION-filesystem fact, so it is not interpolated from anywhere — the
/// template tests [`SESSION_WORKSPACE_ROOT`] directly (both mfile
/// layouts, `minimal.toml` and `.minimal/minimal.toml`) when it prints,
/// which stays correct across skipped uploads, an in-session `min init`,
/// and attaches from unrelated host directories. TTY-gated, plain text —
/// `NO_COLOR`-safe, no box drawing.
const BASELINE_MOTD: &str = constcat::concat!(
    r#"[ -t 1 ] && { printf 'minimal · session %s · loadout %s\ndetach: %s' "${MINIMAL_SESSION_NAME:-unnamed}" "${MINIMAL_LOADOUTS:-none}" "${MINIMAL_DETACH_HINT:-ctrl-] then d}"; [ -f "#,
    SESSION_WORKSPACE_ROOT,
    r#"/minimal.toml ] || [ -f "#,
    SESSION_WORKSPACE_ROOT,
    r#"/.minimal/minimal.toml ] || printf ' · no minimal.toml here — min init to add one'; printf '\n'; }"#,
);

/// The launcher-baseline environment seeded beneath every other layer of
/// [`layer_session_env`]: the session's identity (`MINIMAL_SESSION_NAME`,
/// plus `MINIMAL_LOADOUTS` when the composition's first-class orientation
/// field carries a display list) and the once-only orientation banner
/// pair. ALL orientation env is seeded here, daemon-side, from typed
/// data — none of it rides the user var lane, so user vars and policy
/// can never collide with it. Sitting on the lowest layer means any
/// composed `PROMPT_COMMAND` — a user loadout's, or the built-in
/// default's — overrides the baseline banner cleanly, while the identity
/// vars stay available for that override to interpolate.
///
/// `loadouts_display` is `None` when the composition carries no display
/// list (a client that predates the orientation field, or no
/// composition at all): the var is then left unset so each template's
/// own `${MINIMAL_LOADOUTS:-…}` fallback renders — the baseline banner
/// falls back to `none`, the built-in default loadout's MOTD to
/// `default (built-in)`, each correct for the context it prints in.
fn session_baseline_env(
    session_name: &str,
    loadouts_display: Option<&str>,
) -> Vec<(String, String)> {
    let mut env = vec![
        ("MINIMAL_SESSION_NAME".to_string(), session_name.to_string()),
        (
            "PROMPT_COMMAND".to_string(),
            BASELINE_PROMPT_COMMAND.to_string(),
        ),
        ("MINIMAL_MOTD".to_string(), BASELINE_MOTD.to_string()),
        // Where the host republishes the attached terminal's facts. Named
        // rather than hard-coded into the prompt command so a loadout that
        // replaces `PROMPT_COMMAND` (or starts another shell) can still find
        // the file; the fish form is offered for the same reason.
        ("MINIMAL_ATTACH_ENV".to_string(), ATTACH_ENV_SH.to_string()),
        (
            "MINIMAL_ATTACH_ENV_FISH".to_string(),
            ATTACH_ENV_FISH.to_string(),
        ),
        (
            "MINIMAL_ATTACH_ENV_JSON".to_string(),
            ATTACH_ENV_JSON.to_string(),
        ),
        // The POSIX fallback tier. `$ENV` is the only startup hook a plain
        // `sh`, dash, ash, or ksh offers, and unlike the other four shells
        // there is nothing in the rootfs they read on their own — so this one
        // has to travel as a variable. It names a daemon-owned file; the file
        // is what does the work.
        ("ENV".to_string(), crate::env::ATTACH_ENV_POSIX.to_string()),
    ];
    if let Some(display) = loadouts_display {
        env.push(("MINIMAL_LOADOUTS".to_string(), display.to_string()));
    }
    env
}

/// Layers a session shell's environment by precedence, lowest first: the
/// launcher `baseline` (session identity + orientation banner), the
/// client-forwarded `inherited` locale/timezone, then the `composition` vars
/// (which may override both lower layers), then the `connection` facts
/// (which override everything — sshd-style). Later inserts win on a shared key.
fn layer_session_env(
    baseline: Vec<(String, String)>,
    inherited: Vec<(String, String)>,
    composition: Vec<(String, String)>,
    connection: Vec<(String, String)>,
) -> std::collections::HashMap<String, String> {
    let mut env = std::collections::HashMap::new();
    for (k, v) in baseline
        .into_iter()
        .chain(inherited)
        .chain(composition)
        .chain(connection)
    {
        env.insert(k, v);
    }
    env
}

/// The real [`SessionLauncher`]: evaluates a minimal context into a graph,
/// builds a sandboxed `/bin/bash`, and wires it to a freshly opened PTY.
pub(crate) struct SandboxLauncher {
    pub(crate) ctx: mctx::Context,
    /// Env captured from the SSH channel that mints this shell; see
    /// [`AttachEnv`].
    pub(crate) attach_env: AttachEnv,
    pub(crate) network_mode: NetworkMode,
    /// Shared per-host gvproxy switch. Used only for
    /// [`NetworkMode::OwnIp`] launches.
    pub(crate) net_switch: std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>>,
    /// The session's whole network policy — declared egress enforced by the
    /// switch relay's outbound leg (NET-062/063/064), static ingress port
    /// mappings applied on the switch once this `OwnIp` PTask attaches and
    /// inbound ports gated on its other leg, removed on exit. Unused by other
    /// network modes.
    pub(crate) policy: sessions::SessionPolicy,
    /// The proxy-routing-table handle the `OwnIp` lease is reported through
    /// on attach, so the box's `<name>.min.internal` route exists exactly
    /// while the box does (NET-001). Ignored by every other network mode.
    pub(crate) own_address: Option<crate::net::provider::OwnAddressReporter>,
    /// The addresses the VM host daemon handed this box's registration
    /// (T66), when it was registered: the switch address this `OwnIp` PTask
    /// attaches with instead of drawing one, and the published loopback
    /// address the host side names the box by. Ignored by every other
    /// network mode; `None` for a session the activating client did not
    /// register, which self-allocates as it always has.
    pub(crate) box_addresses: Option<sessions::BoxAddresses>,
    /// Composition to merge into the launcher's baseline packages and
    /// vars. Patches and lifecycle hooks are ignored today.
    pub(crate) composition: Option<std::sync::Arc<sessions::core::compose::Composition>>,
    /// Weak handle back to the owning session actor, for  `min` commands
    /// (e.g. `min build`) to drive session side-ops.
    pub(crate) session: crate::session::WeakSessionHandle,
    /// Whether this launch exists to run lifecycle hooks rather than to serve
    /// a person: minted by the session's hook path — activation at finalize,
    /// teardown at detach or destroy — headless, its pty read by nobody.
    ///
    /// The unenforced-placement advisory is a session surface, and a hook run
    /// is not a session start: its daemon-log record would count one hook run
    /// as one session start, and its banner would be written into a hook pty
    /// no one reads. So a hook launch emits neither form. This is *not* the
    /// launch phase (`LaunchPhase`): the destroy path's hook launch is
    /// `Attached` exactly like an attach's, and finalize's activation launch
    /// is `Activating` — only the caller that mints the launch knows what it
    /// is for, which is why it travels on the launcher.
    pub(crate) for_hooks: bool,
    /// The classifier tree this daemon places host-address boxes in: the
    /// one the privileged step installs natively, and the guest's own boot
    /// mounts for itself. A field of the launcher so the launch reads one
    /// root for its leaf, its probe and its reclaim — and so the
    /// unenforced-launch test can drive that whole path over a stand-in
    /// tree it built, which the real tree's kernel-only facts would
    /// otherwise make undrivable; production sets it from the same
    /// constant every path reads.
    pub(crate) classifier_root: std::path::PathBuf,
    /// The mount table this launch reads the classifier tree's facts over,
    /// as `/proc/self/mountinfo` spells it: `None` — every production path
    /// and the start-up check alike — reads the daemon's own, live. A field
    /// for the same reason [`Self::classifier_root`] is one: the two facts
    /// of one launch answer over one tree and one mount table, and a
    /// host's own mount table covers no stand-in tree, so a launch driven
    /// over one would read every fact as unconfined and never reach the
    /// placement it was driven to test. The field names which table
    /// answers, it never fabricates one — no client or box input reaches
    /// it, and production passes `None`.
    pub(crate) classifier_mountinfo: Option<String>,
    /// The box's runtime publications, built fresh for the spawn this
    /// launcher is about to run: the one set this launch's listen plan and
    /// the session actor's runtime expose path both read, so a port the
    /// one published is never bound by the other (NET-047's never-contend
    /// half, and the answer `min net expose` gets when the listener
    /// watcher published its port first).
    pub(crate) publications: crate::net::listeners::BoxPublications,
}

/// Reaps a freshly-spawned sandbox process if the launch is abandoned
/// before the process is handed off to a [`Launched`].
///
/// A [`hakoniwa::Child`] does not terminate when dropped, so anything
/// that lets one go without killing it orphans the sandbox — a process
/// still holding the session's rootfs after the session it belonged to
/// is gone. The `Err` arms between the spawn and the handoff reap
/// explicitly; this is what catches the third way out, a **cancelled**
/// launch future. There is a real caller: a teardown transition bounds
/// its launch with a timeout (`session::HOOK_LAUNCH_TIMEOUT`) and drops
/// this future when it expires, which without the guard would strand a
/// sandbox the destroy then tries to delete out from under.
///
/// Reaping is synchronous (`kill` + `wait` are not async), so unlike
/// [`sandbox2::PlannedLaunch`] — which has to give a lease back, and spawns
/// that release — this needs no runtime to do its work in `Drop`.
struct SpawnedProcessGuard {
    /// `None` once the process has been handed off — see
    /// [`Self::release`].
    process: Option<hakoniwa::Child>,
}

impl SpawnedProcessGuard {
    fn new(process: hakoniwa::Child) -> Self {
        Self {
            process: Some(process),
        }
    }

    /// Borrow the guarded process, for the post-spawn wiring that still
    /// needs it while the guard stays responsible for it.
    fn get_mut(&mut self) -> &mut hakoniwa::Child {
        self.process
            .as_mut()
            .expect("the process is taken only by `release`, which consumes the guard")
    }

    /// Hand the process off, disarming the guard.
    fn release(mut self) -> hakoniwa::Child {
        self.process
            .take()
            .expect("the process is taken only here, and this consumes the guard")
    }
}

impl Drop for SpawnedProcessGuard {
    fn drop(&mut self) {
        let Some(mut process) = self.process.take() else {
            return;
        };
        // `kill` and `wait` are independent: a process that already
        // exited fails the kill with `ESRCH` but still needs reaping.
        if let Err(e) = process.kill() {
            tracing::warn!(error = %e, "killing sandbox process after an abandoned launch");
        }
        if let Err(e) = process.wait() {
            tracing::warn!(error = %e, "reaping sandbox process after an abandoned launch");
        }
    }
}

/// The box's classifier leaf during its launch, removed if the launch is
/// abandoned before the leaf is handed off (NET-079).
///
/// The leaf is created before the spawn — the sandbox layer needs it to bind
/// the tree into the box and root the box's cgroup namespace at the leaf — so
/// every way out of [`SandboxLauncher::launch`] between that and the handoff
/// into [`Launched`] has to account for a leaf with no box in it: an `Err`
/// return
/// for a build that failed, and — the one no `return` covers — the future's
/// own `Drop`, which is what a teardown transition bounding its launch with
/// a timeout (`session::HOOK_LAUNCH_TIMEOUT`) takes. This guard owns the
/// leaf until `release` hands it to the [`SandboxBackend`] that keeps it for
/// the session's lifetime.
///
/// Declared *before* the [`SpawnedProcessGuard`] it shares the launch with,
/// so an abandoned launch drops in the opposite order: the process is reaped
/// first and the leaf removed after, because a cgroup that still holds a
/// process refuses its removal.
struct BoxLeafGuard {
    leaf: Option<sandbox2::config::ClassifierLeaf>,
}

impl BoxLeafGuard {
    fn new(leaf: sandbox2::config::ClassifierLeaf) -> Self {
        Self { leaf: Some(leaf) }
    }

    /// The leaf this guard owns, for the placement between the spawn and the
    /// handoff.
    fn get(&self) -> Option<&sandbox2::config::ClassifierLeaf> {
        self.leaf.as_ref()
    }

    /// Hand the leaf off, disarming the guard.
    fn release(mut self) -> sandbox2::config::ClassifierLeaf {
        self.leaf
            .take()
            .expect("the leaf is taken only here, and this consumes the guard")
    }
}

impl Drop for BoxLeafGuard {
    fn drop(&mut self) {
        let Some(leaf) = self.leaf.take() else {
            return;
        };
        // The same shape the session-end teardown's `Drop` uses: this leaf's
        // box was SIGKILLed and reaped by the [`SpawnedProcessGuard`] dropped
        // just before it (the guard is declared after this one, so the launch's
        // own drop order runs the process first), and a just-reaped box's
        // cgroup can refuse its `rmdir` (`EBUSY`) for a few milliseconds while
        // the kernel empties it. A single refusal would leak the leaf of an
        // abandoned launch — a hook launch that timed out past its spawn, most
        // notably — until the next same-id launch reclaimed it or the daemon
        // restarted, so the removal is retried briefly before it is warned
        // about.
        if let Err(e) = remove_box_leaf_patiently(leaf.dir(), DROP_LEAF_REMOVAL_ATTEMPTS, |_| {
            std::thread::sleep(DROP_LEAF_REMOVAL_PAUSE)
        }) {
            tracing::warn!(
                leaf = %leaf.dir().display(),
                error = %e,
                "removing the classifier leaf of an abandoned launch"
            );
        }
    }
}

/// The mount table a host-address launch answers over: the knob's when one
/// was set, the daemon's own, read live, when none was — the knob's `None`
/// is every production path ([`SandboxLauncher::classifier_mountinfo`]).
///
/// The distinction is not cosmetic. `None` handed through as "no table at
/// all" makes [`sandbox2::classifier::tree_is_real`] say a real tree is not
/// real — it answers from the table — so a guest, whose own boot mounted the
/// `nsdelegate` cgroup2 the tree sits on, would refuse every host-address
/// box it launched as a broken image, while a native host without a tree
/// kept running boxes unenforced: the one table read here is what both
/// halves of the launch — the decision and the placement — answer over.
fn launch_mountinfo(knob: Option<String>) -> Option<String> {
    knob.or_else(sandbox2::classifier::own_mountinfo)
}

/// The daemon's one node fact about per-box egress enforcement (NET-079):
/// whether this host can decide a host-address box's egress verdict per box,
/// and — while it cannot — the cause it cannot. One fact for the whole node,
/// because nothing it rests on is a session's: the decision reads the host's
/// own cgroup tree, its mount table, and the loaded table's effect, and the
/// cause names a state of the host, not of any box on it. The daemon's
/// start-up read seeds it ([`set_host_ip_enforcement_fact`]'s caller in
/// `main`) and every host-address launch's [`re_read_classifier_fact`]
/// refreshes it, because the fact it rests on is the table's *effect*
/// (design §7.4) — a marker survives whatever emptied the table and the
/// refusal does not.
///
/// Held as a process-global rather than a field on the server's state for
/// the same reason: the start-up read that seeds it runs before any server
/// exists. It is the node's half of every surface that shows a session: the
/// create reply states it outright (no box has launched yet to have its own
/// outcome), each read surface's refusal gate answers over its cause, and
/// the listing and the runtime-facts reply lower a box's own launch record
/// by its state — never raise one to it.
///
/// `cause` rides beside the state because the two are one fact: the state a
/// display shows and the advice the create reply carries both come from the
/// one decision the probe read — the cause is `None` only while the host
/// decides — and a fact that held the state alone could not say why.
#[derive(Clone, Copy)]
pub(crate) struct HostIpEnforcementFact {
    /// The state itself, in the enum the listing's entries carry.
    pub(crate) enforcement: minimald_rpc::HostIpEnforcement,
    /// Why the host cannot decide per box; `None` while it can, and on a
    /// fact no read has set yet (the cell's default, below), where the
    /// cause is as unread as the state.
    pub(crate) cause: Option<crate::net::classifier::Cause>,
}

impl HostIpEnforcementFact {
    /// The fact as a [`classifier::Decision`], for the gate that refuses a
    /// box over a cause. Lossless in the one direction that matters: a
    /// `per_box` state is a decided verdict with no cause, and a cause
    /// carries its own state — while a cause-less `none` state (the cell's
    /// default, before any read has set it) is not a decision at all, so it
    /// is `None`: a daemon that has not read its host refuses nothing over
    /// it, and its displays show the state without claiming a cause.
    fn decision(&self) -> Option<crate::net::classifier::Decision> {
        match (self.enforcement, self.cause) {
            (minimald_rpc::HostIpEnforcement::PerBox, _) => {
                Some(crate::net::classifier::Decision::decided())
            }
            (_, Some(cause)) => Some(crate::net::classifier::Decision::undecidable(cause)),
            (_, None) => None,
        }
    }

    /// Whether the host this fact stands for can decide a host-address
    /// box's egress verdict per box (NET-079) — the one bit of the node
    /// fact the create path reads, taking the fact exactly as the create
    /// response does rather than re-probing the host itself: a create is
    /// not a place that decides a box, and the launch that follows reads
    /// the host again for its own gate. A fact no read has set yet — the
    /// cell's default — answers `false`, so a daemon that has not read its
    /// host creates what it is handed and leaves the verdicts to its
    /// launches.
    pub(crate) fn can_decide_per_box(&self) -> bool {
        self.enforcement == minimald_rpc::HostIpEnforcement::PerBox
    }
}

/// The fact itself: the cell every surface that shows a session reads, in
/// the state the daemon's start-up read left it — `none`, with no cause, the
/// state of a daemon that has not read its host yet. Const-initializable,
/// so the one lock it sits behind is taken only by the reads and writes
/// that swap or copy a fact two machine words wide.
static HOST_IP_ENFORCEMENT_FACT: std::sync::Mutex<HostIpEnforcementFact> =
    std::sync::Mutex::new(HostIpEnforcementFact {
        enforcement: minimald_rpc::HostIpEnforcement::None,
        cause: None,
    });

/// Sets the fact from a decision the classifier read — the one write path
/// both its writers go through: the daemon's start-up read, which owns the
/// host before any session exists, and each host-address launch's
/// [`re_read_classifier_fact`], whose re-read keeps the fact current in the
/// face of the table's own effect changing under it. `pub` because the
/// start-up read is the daemon binary's (`main`), which owns the fact before
/// any of this crate's servers exist.
pub fn set_host_ip_enforcement_fact(decision: &crate::net::classifier::Decision) {
    let mut fact = HOST_IP_ENFORCEMENT_FACT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fact.enforcement = if decision.can_decide_per_box() {
        minimald_rpc::HostIpEnforcement::PerBox
    } else {
        minimald_rpc::HostIpEnforcement::None
    };
    fact.cause = decision.cause();
}

/// The fact as it stands, copied out for a surface that shows a session —
/// the copy is two machine words, so the lock is held for the copy alone and
/// never across a decision a re-read is making.
pub(crate) fn host_ip_enforcement_fact() -> HostIpEnforcementFact {
    *HOST_IP_ENFORCEMENT_FACT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Puts the fact back to its start-up default — no read, no cause — so a
/// test that set a fact of its own leaves the daemon it shares a process
/// with as it found it.
#[cfg(test)]
pub(crate) fn clear_host_ip_enforcement_fact() {
    let mut fact = HOST_IP_ENFORCEMENT_FACT
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    fact.enforcement = minimald_rpc::HostIpEnforcement::None;
    fact.cause = None;
}

/// The per-box egress enforcement a session's display surfaces show
/// (NET-079): the box's own launch record — what the launch that produced
/// this box decided about it, `per_box` if it placed the box in a classifier
/// leaf and `none` if it did not — for a host-address box the classifier did
/// not refuse, and nothing for any other box. An own-address or none box's
/// verdict is decided on address leases, never on the host's cgroup tree, and
/// a box the classifier refused at placement has no state to show, because
/// the refusal is what its launch said.
///
/// The record is lowered by the daemon's one node fact, never raised above
/// either half: a box whose launch placed it shows `per_box` only while
/// this host can decide per box, and `none` whenever it cannot — whether
/// the table stopped deciding after the placement or had not decided when
/// the placement was made, because a leaf over a table that is not
/// refusing decides nothing until it refuses again. A box its launch left
/// unplaced stays `none` for its life, whatever a later launch of another
/// box decided, because the outcome belongs to the launch that produced
/// it, not to the node as it stands now. Only a host-address box that has
/// not launched yet — a created session, or one whose launch never minted
/// a host — shows the fact alone.
///
/// The refusal half is the launch's own gate —
/// [`refused_unenforced_host_address_box`] — so a display cannot disagree
/// with a launch over which box is refused: the gate's `placed` fact, which a
/// launch knows from its own placement, is inferred here from the fact's
/// cause ([`fact_places_a_leaf`]), because the causes are what place or
/// refuse the box natively and in the guest. A cause-less fact — the cell's
/// default — places, and its gate refuses nothing, so the state shows as it
/// stands.
///
/// Pure over its inputs, so the gate and its lowering are pinned where they
/// are written.
pub(crate) fn displayed_host_ip_enforcement(
    guest: bool,
    network_mode: NetworkMode,
    verdict: sandbox2::config::Verdict,
    fact: &HostIpEnforcementFact,
    launch_record: Option<HostIpEnforcement>,
) -> Option<minimald_rpc::HostIpEnforcement> {
    if refused_unenforced_host_address_box(
        guest,
        network_mode,
        verdict,
        fact_places_a_leaf(fact.cause),
        fact.decision().as_ref(),
    )
    .is_some()
    {
        return None;
    }
    match network_mode {
        NetworkMode::HostNet => Some(match launch_record {
            // The box's own launch outcome: shown as recorded while the host
            // can still decide per box, lowered to the undecidable state the
            // host is in when it cannot — never raised above either.
            Some(recorded) => match (recorded, fact.enforcement) {
                (HostIpEnforcement::PerBox, HostIpEnforcement::PerBox) => HostIpEnforcement::PerBox,
                _ => HostIpEnforcement::None,
            },
            // No box of this session has launched yet, so there is no
            // outcome to show: the node's state is the best either half of
            // the daemon knows about a box that does not exist yet.
            None => fact.enforcement,
        }),
        _ => None,
    }
}

/// Whether a fact's cause says the step's tree is there to place a leaf in:
/// the causes that imply a box nothing places are the step's absence and the
/// mount that cannot confine, and every other cause — the two probe causes,
/// the guest's unloaded table — arises only over a tree the step already
/// installed (the marker and the delegated subtrees gate the probe), which is
/// also where a decided fact's box goes. `None` — a decided fact, or the
/// cell's default — places, so a display's refusal inference reads a decided
/// host as the placement its launches make.
///
/// `pub(crate)`: the test launcher's mock models its placement's outcome
/// from the same cause the displays infer a launch's placement over, so
/// the two never disagree about which causes place.
pub(crate) fn fact_places_a_leaf(cause: Option<crate::net::classifier::Cause>) -> bool {
    !matches!(
        cause,
        Some(
            crate::net::classifier::Cause::StepNotInstalled
                | crate::net::classifier::Cause::CannotConfine
        )
    )
}

/// Serializes the window in which a process-global test stand-in is
/// installed, or the enforcement fact a test sets: a loopback-probe one
/// (`net::loopback`), the classifier reading's (below), or the fact a launch
/// or a test wrote — under libtest, where every test in this binary shares
/// one process, a create, launch, or listing driven by another test would
/// answer over it too. Nextest runs each test in its own process; the mutex
/// keeps the in-process runner as safe.
///
/// Lives here — the module that owns the fact and the reading stand-in — so
/// the launch tests that write the fact and the RPC tests that read it share
/// one guard.
#[cfg(test)]
pub(crate) static PROBE_TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// The test stand-in for the probe's reading: a `Reading` a test hands the
/// decision in place of the live probe's, so the decision logic itself still
/// runs over the facts a test laid out — the tree and mount table a test
/// spells — and the one thing a stand-in tree cannot model, a table whose
/// effect the probe reads, is the one thing a test injects. The same
/// stand-in discipline the session-host knobs use: a fact in, never an
/// answer.
#[cfg(test)]
static CLASSIFIER_READING_STANDIN: std::sync::Mutex<Option<crate::net::classifier::Reading>> =
    std::sync::Mutex::new(None);

/// Points the decision's probe at `reading` for the rest of this process —
/// the stand-in state a test built. See [`CLASSIFIER_READING_STANDIN`].
///
/// The tests that use this take the probe-test mutex in this module for the
/// whole install→read→assert→clear window: the stand-in is process-global,
/// so under libtest — where the tests of one binary share a process — a
/// launch driven by another test would read it too.
#[cfg(test)]
pub(crate) fn install_classifier_reading_standin(reading: crate::net::classifier::Reading) {
    *CLASSIFIER_READING_STANDIN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(reading);
}

/// Withdraws the reading stand-in [`install_classifier_reading_standin`]
/// installed, so later reads probe the table for real again.
#[cfg(test)]
pub(crate) fn clear_classifier_reading_standin() {
    *CLASSIFIER_READING_STANDIN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = None;
}

/// The probe's reading the decision answers over: the live probe, except
/// under test, where a stand-in reading may be installed over the same tree
/// facts the test laid out.
#[cfg(test)]
fn classifier_reading(root: &std::path::Path, guest: bool) -> crate::net::classifier::Reading {
    let standin = CLASSIFIER_READING_STANDIN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    standin.unwrap_or_else(|| live_classifier_reading(root, guest))
}

/// The probe's reading the decision answers over: the live probe, always —
/// the non-test twin of [`classifier_reading`], spelled separately so the
/// test arm's lock is never compiled into a daemon that cannot install a
/// stand-in.
#[cfg(not(test))]
fn classifier_reading(root: &std::path::Path, guest: bool) -> crate::net::classifier::Reading {
    live_classifier_reading(root, guest)
}

/// The live probe a launch reads: a guest connects to the listener its boot
/// holds, so the port the probe is refused at is one the daemon held all
/// along, never one bound for this reading (NET-079, design §7.4); a native
/// host binds a listener per reading.
fn live_classifier_reading(root: &std::path::Path, guest: bool) -> crate::net::classifier::Reading {
    if guest {
        crate::net::classifier::read_held_filter(root)
    } else {
        crate::net::classifier::read_filter(root)
    }
}

/// The classifier fact every host-address launch reads the host for,
/// freshly, on the blocking pool: the mount table the tree answers over —
/// the knob's when one was set, the daemon's own, read live, when none was
/// ([`launch_mountinfo`]) — and the decision over the tree and that one
/// table (NET-079), returned together because the two are one fact: a
/// launch that decides a box over a table and then places it over another
/// has read nothing.
///
/// The launch's read — the decision the placement and the refusal answer
/// over — and the write that keeps the daemon's
/// one node fact ([`HOST_IP_ENFORCEMENT_FACT`]) current, in one move: the
/// read is fresh rather than a kept start-time reading, because the fact
/// the decision rests on is the table's *effect* (design §7.4) — a marker
/// survives whatever emptied the table and the refusal does not, and a
/// kept reading would survive it the same way — and the surfaces that show
/// a session read the fact, so they show this read's state and not one a
/// re-read has replaced.
///
/// The mount table rides back out beside the decision because the launch
/// answers its placement over the same one table the decision just read —
/// one blocking hop, so the live mount-table read never runs on the async
/// worker a session is being created on. `Err` says the read did not run
/// at all — the blocking task was lost or panicked — which is the launch's
/// own cause to name: a launch that cannot read the fact cannot place a
/// box.
pub(crate) async fn re_read_classifier_fact(
    root: std::path::PathBuf,
    mountinfo_knob: Option<String>,
    guest: bool,
) -> std::io::Result<(Option<String>, crate::net::classifier::Decision)> {
    tokio::task::spawn_blocking(move || {
        let mountinfo = launch_mountinfo(mountinfo_knob);
        let decision = crate::net::classifier::decide(&root, mountinfo.as_deref(), guest, || {
            classifier_reading(&root, guest)
        });
        set_host_ip_enforcement_fact(&decision);
        (mountinfo, decision)
    })
    .await
    .map_err(std::io::Error::other)
}

/// Creates the classifier leaf this session's host-address box is placed in
/// (NET-079), under the tree the privileged step installs on a native host
/// (`scripts/install-host-classifier.sh`) and the guest daemon mounts for
/// itself, named by the session's id: the leaf belongs to a session, not to
/// a display name a person can type twice.
///
/// The tree has to be *real* first — on this host's cgroup2, and in the
/// guest with `nsdelegate` — or the leaf this function would create decides
/// nothing while looking placed; see [`refused_unenforced_host_address_box`]
/// for the guest, where that state refuses a host-address launch instead of
/// running it unenforced.
///
/// And the daemon has to be able to *place a process* in a leaf of it: a
/// real tree the daemon is not inside decides its verdicts on a join the box
/// dies making, because the kernel gates a `cgroup.procs` write on write
/// permission to the common ancestor of source and destination — the
/// root-owned mount root above the tree for a daemon still in `user.slice`.
/// [`sandbox2::classifier::probe_child_placement`] performs the migration
/// with a throwaway child first, so the box's own join never runs where it
/// cannot succeed: an unplaceable session is decided here, at the launch,
/// not by a box that dies with `127` in a closure whose stderr reaches no
/// log.
///
/// `Ok(None)` means this host places no box: the tree is absent, or the
/// daemon cannot place a child in it. The session still launches, and its
/// box runs unenforced — NET-079's exception, that a host which cannot
/// decide per box never refuses the box or its connections on that ground.
///
/// `Err` means the leaf exists but cannot be this session's: another session
/// holds it, which a fresh launch of the same id cannot tolerate — two
/// sessions in one leaf would decide both their verdicts together.
async fn create_session_leaf(
    root: &std::path::Path,
    mountinfo: Option<&str>,
    guest: bool,
    session_id: &sessions::SessionId,
    session_name: &str,
    verdict: sandbox2::config::Verdict,
    can_decide_per_box: bool,
) -> io::Result<Option<sandbox2::config::ClassifierLeaf>> {
    if !sandbox2::classifier::tree_is_real(root, mountinfo, guest) {
        tracing::info!(
            session = session_name,
            tree = sandbox2::classifier::TREE_ROOT,
            install = %sandbox2::classifier::install_hint(),
            "this host has no classifier tree to place a box in; the session's \
             box runs unenforced",
        );
        return Ok(None);
    }
    // The placement the box's own join performs, tried first by a throwaway
    // child of this daemon: the proof is a migration the kernel accepted, not
    // the tree's existence. On the blocking pool, because a fork and its reap
    // do not belong on an executor thread. The probe makes its leaf in the
    // subtree this box's verdict picked, the same one its own leaf will
    // live in.
    let placement = match tokio::task::spawn_blocking({
        let root = root.to_path_buf();
        move || sandbox2::classifier::probe_child_placement(&root, verdict)
    })
    .await
    {
        Ok(placement) => placement,
        Err(join) => Err(io::Error::other(join)),
    };
    if let Err(e) = placement {
        // Which step is missing decides what a person is told to do next: a
        // tree that is not there is the installer's to install, and a tree
        // that is there but refuses this daemon means the daemon is not
        // inside the delegated slice — the state the installer's `--pid`
        // step exists for, effective on the very next launch because the
        // probe is per-launch.
        let (what, hint) = match e.kind() {
            std::io::ErrorKind::NotFound => (
                "the classifier tree is not installed on this host — the \
                 placement probe cannot even make its throwaway leaf in it",
                "the installer has to install the tree",
            ),
            std::io::ErrorKind::PermissionDenied => (
                "this daemon cannot place a process in the classifier tree",
                "it is not inside the delegated slice, so the installer's \
                 --pid step or a Delegate=yes unit has to place it",
            ),
            _ => (
                "the placement probe of the classifier tree failed",
                "the probe's error is where to start",
            ),
        };
        tracing::info!(
            session = session_name,
            error = %e,
            daemon_cgroup = ?sandbox2::classifier::own_cgroup_path(),
            install = %sandbox2::classifier::install_hint(),
            hint,
            "{what}; {hint} — the session's box runs unenforced",
        );
        return Ok(None);
    }
    match create_or_reclaim_box_leaf(root, session_id, verdict) {
        Ok((leaf, reclaimed)) => {
            if reclaimed {
                tracing::info!(
                    session = session_name,
                    leaf = %leaf.display(),
                    "reclaimed this session's empty classifier leaf — a leftover a \
                     daemon death left behind; the kernel's rmdir emptiness test \
                     let it go, and the launch created it again for this box",
                );
            }
            // One info line per host-address box launch naming its classifier
            // identity (NET-079's observability): the subtree its declaration
            // picked, the leaf that verdict placed it in, and whether this
            // host can decide per box — the fresh fact this launch's probe
            // just read from the table's effect. A leaf placed on a host
            // whose table is not loaded decides nothing while looking
            // decided, so the line never says `per_box` for one.
            if can_decide_per_box {
                tracing::info!(
                    session = session_name,
                    classifier = verdict.dir_name(),
                    leaf = %leaf.display(),
                    host_ip_enforcement = %HostIpEnforcement::PerBox.machine_str(),
                    "the host-address box's egress verdict is decided on its \
                     classifier leaf, in the {} subtree",
                    verdict.dir_name()
                );
            } else {
                tracing::info!(
                    session = session_name,
                    classifier = verdict.dir_name(),
                    leaf = %leaf.display(),
                    host_ip_enforcement = %HostIpEnforcement::None.machine_str(),
                    "the host-address box's leaf is placed in the {} subtree, \
                     but this host's classifier table is not loaded, so its \
                     egress verdict is not decided per box",
                    verdict.dir_name()
                );
            }
            Ok(Some(sandbox2::config::ClassifierLeaf::new(leaf)))
        }
        // `NotFound` is the ordinary shape of "no tree on this host": the
        // privileged step has not run. Info, not warn — it is a deployment
        // state, not a fault, and the next step on this host is to run the
        // installer, not to debug one launch.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(
                session = session_name,
                install = %sandbox2::classifier::install_hint(),
                "the classifier tree is not installed on this host; \
                 the session's box runs unenforced",
            );
            Ok(None)
        }
        // A leaf named by this session's id that survives the reclaim is
        // another session's, and the refusal below says so: two sessions in
        // one leaf would decide both their verdicts together.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(e),
        Err(e) => {
            tracing::warn!(
                session = session_name,
                error = %e,
                "creating the session's classifier leaf; the box runs unenforced",
            );
            Ok(None)
        }
    }
}

/// Creates the session's classifier leaf, reclaiming a leftover empty one.
///
/// The sweep at daemon start takes the empty leaves a daemon death leaves
/// behind, but it cannot take one made after it ran: a daemon that died
/// between creating the leaf and spawning the box into it leaves a leaf a
/// fresh launch of the same session id then finds. Whether that leaf is a
/// leftover or another session's is not for this code to guess — the
/// kernel's own emptiness test tells them apart, and it is the same
/// primitive [`sandbox2::classifier::remove_box_leaf`] runs: an `rmdir`,
/// which the kernel refuses while the cgroup holds a process. A leftover
/// goes and the leaf is created again for this launch; a leaf that stays
/// belongs to a live session, and the refusal names the `rmdir` that
/// refused, so what a person reads is what would have had to be true for
/// the leaf to have been reclaimable.
///
/// Returns the leaf and whether it is a reclaimed leftover, so the launch
/// can say so. Split out of [`create_session_leaf`] so the two halves can
/// be driven over a stand-in tree: the real tree's emptiness test is the
/// kernel's, but the reclaims over a plain directory are the same code
/// paths.
fn create_or_reclaim_box_leaf(
    root: &std::path::Path,
    session_id: &sessions::SessionId,
    verdict: sandbox2::config::Verdict,
) -> io::Result<(std::path::PathBuf, bool)> {
    let id = session_id.to_string();
    match sandbox2::classifier::create_box_leaf(root, &id, verdict) {
        Ok(leaf) => Ok((leaf, false)),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let leftover = sandbox2::classifier::box_leaf(root, &id, verdict);
            sandbox2::classifier::remove_box_leaf(&leftover)
                .and_then(|()| sandbox2::classifier::create_box_leaf(root, &id, verdict))
                .map(|leaf| (leaf, true))
                .map_err(|refused| {
                    io::Error::new(
                        std::io::ErrorKind::AlreadyExists,
                        format!(
                            "another session holds this one's classifier leaf \
                             ({session_id}): the leaf this launch found still exists \
                             and its rmdir — the kernel's own test that a cgroup \
                             holds no process — refused ({refused}), so the launch \
                             is refused rather than placing this box in another \
                             session's cgroup"
                        ),
                    )
                })
        }
        Err(e) => Err(e),
    }
}

/// Reads the one line the box's pre-exec closure reported into the
/// sandbox's `/run`, and says what it means: which cover the box took over
/// the classifier tree the launch bound for its join, or the errno that
/// killed the closure before the program ran — the `127` the spawn then
/// reports, whose stderr is the session's own terminal and reaches no
/// daemon log without this file.
///
/// Polled rather than awaited, and the file is taken away only once the
/// box's fate is known: a `failed` line is written by the closure's own
/// exit path, so nothing follows it and the removal is owed then; a `cover`
/// line is written while the closure is still heading for its exec, and a
/// closure that covered and then died past that point replaces its line —
/// the removal before that would have dropped the `failed` line carrying
/// the `127`'s diagnosis into a file nobody reads, so the watch goes on
/// until the deadline even after a line was read. A report that never
/// appears is itself a finding — a box that could not say what it did still
/// ran — and it is warned, not debugged: a leaf-bearing box whose closure
/// could not write `/run` is exactly the state this channel exists to
/// catch. Runs off the launch's critical path (it is `tokio::spawn`ed), so
/// a session is never held up by what its box did in its first
/// milliseconds.
///
/// `watch` is how long the launch's own watch waits; [`CLOSURE_REPORT_WATCH`]
/// is the production one, and a test drives the same code with a shorter
/// one.
async fn report_box_closure(
    report: std::path::PathBuf,
    session: String,
    watch: std::time::Duration,
) {
    let deadline = std::time::Instant::now() + watch;
    // The lines this closure has left so far, so a replacement or an
    // appended line is logged as the new finding it is rather than skipped
    // as a repeat — and a line already said is not said twice.
    let mut seen: Vec<String> = Vec::new();
    loop {
        match tokio::fs::read_to_string(&report).await {
            Ok(content) => {
                for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
                    if seen.iter().any(|s| s == line) {
                        continue;
                    }
                    seen.push(line.to_string());
                    if say_closure_line(line, &session) {
                        // The box's fate is known: the closure died, and it
                        // died having said so. The daemon owes the tree one
                        // line per launch, not a file per session.
                        let _ = tokio::fs::remove_file(&report).await;
                        return;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                tracing::warn!(
                    session = %session,
                    error = %e,
                    "reading the box's closure report",
                );
                return;
            }
        }
        if std::time::Instant::now() > deadline {
            if seen.is_empty() {
                tracing::warn!(
                    session = %session,
                    report = %report.display(),
                    "the box's pre-exec closure wrote no report into its /run \
                     before the watch gave up: a leaf-bearing box that could not \
                     say what it did over its classifier tree is exactly the \
                     state this channel exists to catch — no line below names \
                     its cover or its errno",
                );
            }
            // The box's fate is known by the deadline either way: the closure
            // writes within its first milliseconds, so the watch's whole
            // window without a new line is a closure that execed — or one
            // that never got to write, which the warn above just said. The
            // removal is owed now, and the box's fate is the only thing that
            // ever owed it.
            let _ = tokio::fs::remove_file(&report).await;
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// How long a launch watches its box's closure report: the closure writes
/// within its first milliseconds, so three seconds without a line it has not
/// already read is a closure that has nothing more to say.
const CLOSURE_REPORT_WATCH: std::time::Duration = std::time::Duration::from_secs(3);

/// Says what one line of the box's closure report means, and returns whether
/// the line settles the box's fate: `true` for a `failed` line, which the
/// closure writes on its way to `_exit(127)` and nothing follows; `false`
/// for a `cover` line, which it writes while still heading for its exec.
/// A cover line may carry a refused devpts remount after a `; `, since the
/// report holds one line; each part is said on its own.
fn say_closure_line(line: &str, session: &str) -> bool {
    if let Some((cover, devpts)) = line.split_once("; ") {
        let settled = say_closure_line(cover, session);
        return say_closure_line(devpts, session) || settled;
    }
    if line == "cover cgroup2" {
        tracing::info!(
            session = %session,
            cover = "cgroup2",
            "the box covered its bound classifier tree with the design's \
             own cover: a read-only cgroup2 mount of its namespace root, \
             so its own limit is readable where a runtime looks and no \
             other cgroup is reachable",
        );
    } else if let Some(errno) = line.strip_prefix("cover tmpfs-fallback errno ") {
        tracing::warn!(
            session = %session,
            cover = "tmpfs-fallback",
            mount_errno = errno,
            "the box's classifier cover fell back to an empty read-only \
             tmpfs: the kernel refused the design's cgroup2 mount of the \
             box's namespace root in its user namespace, so the box has \
             no cgroup path to write a migration to, but none to read a \
             limit from either — a recorded fallback, never the design's \
             cover",
        );
    } else if line == "cover tmpfs-fallback forced" {
        tracing::warn!(
            session = %session,
            cover = "tmpfs-fallback",
            "the box's classifier cover was forced onto its recorded \
             fallback — a launch in a test posture, never a production one",
        );
    } else if let Some(rest) = line.strip_prefix("devpts max=") {
        let (max, errno) = rest.rsplit_once(" errno ").unwrap_or((rest, "unreported"));
        tracing::warn!(
            session = %session,
            max,
            errno,
            "remounting the box's /dev/pts with a per-instance max failed; \
             the box runs on the shared PTY pool",
        );
    } else if let Some(errno) = line.strip_prefix("lo-down errno ") {
        tracing::warn!(
            session = %session,
            errno = errno,
            "the box could not bring up the loopback interface of its own \
             network namespace: it runs, but nothing in it can reach \
             127.0.0.1 or ::1",
        );
    } else if let Some(failed) = line.strip_prefix("failed ") {
        let (step, errno) = failed
            .rsplit_once(" errno ")
            .unwrap_or((failed, "unreported"));
        tracing::error!(
            session = %session,
            step = %step,
            errno = %errno,
            "the box's pre-exec closure died before its program ran: the \
             spawn reports this as exit 127, and this line is the only \
             place a daemon log ever sees which step and which errno",
        );
        return true;
    } else {
        tracing::warn!(
            session = %session,
            report = %line,
            "the box's pre-exec closure reported a line this daemon does \
             not read",
        );
    }
    false
}

/// Whether a host-address box this host cannot give a verdict of its own
/// must be refused rather than launched unenforced, and with what words:
/// the gate and the refusal are decided in one place, because the one
/// thing worse than either alone is a gate that said "refused" for words
/// that spell what the box did instead.
///
/// In the guest — this daemon being the microVM's pid 1 — the tree and the
/// table were this daemon's own boot's work, so there is no privileged step
/// a person could run to fix either half: a box that cannot be placed in a
/// leaf has no leaf to decide on at all, and a deny-all box whose table is
/// not loaded would run placed while nothing refuses its connections — a
/// verdict that looks decided and is not. The first is a broken guest
/// image; the second is the interim, guest-side classifier enforcement not
/// being available yet. Both are refused, each with the error that says
/// which it is (design §7.1). An allow box needs no verdict enforced, so a
/// guest that places it runs it.
///
/// Natively, NET-079's exception stands for every state this host can still
/// fix from itself: the step not installed, a tree no cgroup2 with
/// `nsdelegate` confines, a box that declares no verdict to enforce. Those
/// run unenforced, and the record and notice below say so. The exception
/// stops where the box's own declaration becomes the thing this host cannot
/// honour — a *placed* deny-all box over one of the two probe causes: a
/// table whose marker vouches for a refusal the probe did not read
/// (`TableNotEffective`), and a table whose effect could not be read at all
/// (`ProbeUnreadable`). Running that box would promise a refusal nothing
/// here is making, so the launch refuses it and names the cause, because
/// natively both halves are this host's to fix and the words are what tell
/// a person which one. Both causes arise only over a tree the step already
/// installed — the marker and the delegated subtrees gate the probe — so
/// the refusal is a placed box's, never an unplaced one's: a host that
/// cannot place a box has nothing decided-looking to refuse, and it keeps
/// the advisory.
///
/// Pure over its inputs, so the gate and its words are pinned where they
/// are written.
fn refused_unenforced_host_address_box(
    guest: bool,
    network_mode: NetworkMode,
    verdict: sandbox2::config::Verdict,
    placed: bool,
    decision: Option<&crate::net::classifier::Decision>,
) -> Option<String> {
    // Only a host-address box has a verdict the classifier could decide, and
    // only its launch reads a decision — the two facts are one, so the mode
    // check and the read are the same check, and a launch that read nothing
    // refuses nothing here.
    if !matches!(network_mode, NetworkMode::HostNet) {
        return None;
    }
    // The guest's unplaced box needs no decision read to refuse: there is no
    // tree to decide anything in, and that is the ground itself.
    if guest && !placed {
        return Some(
            "this guest has no classifier tree to place a host-address \
             box in: its cgroup2 is not mounted with nsdelegate, so the \
             box's verdict could not be decided and the box was refused \
             rather than run unenforced (broken guest image)"
                .to_string(),
        );
    }
    let decision = decision?;
    if guest {
        if verdict == sandbox2::config::Verdict::Deny && !decision.can_decide_per_box() {
            return Some(
                "this guest has not loaded the classifier table, so a \
                 deny-all box's connections would not be refused: the box's \
                 declaration promises a verdict nothing here refuses yet, \
                 and the box was refused rather than run unenforced \
                 (guest-side classifier enforcement is not available yet)"
                    .to_string(),
            );
        }
        return None;
    }
    if placed && verdict == sandbox2::config::Verdict::Deny {
        return match decision.cause() {
            Some(crate::net::classifier::Cause::TableNotEffective) => Some(format!(
                "this host's classifier table is marked loaded but its refusal \
                 is not in force, so a deny-all box's connections would not be \
                 refused: the box's declaration promises a verdict nothing here \
                 enforces, and the box was refused rather than run unenforced \
                 (the table's refusal is not in force — {} reloads it)",
                sandbox2::classifier::install_hint()
            )),
            Some(crate::net::classifier::Cause::ProbeUnreadable) => Some(
                "this host's classifier table's effect could not be read, so \
                 whether a deny-all box's connections would be refused is \
                 unknown: the box's declaration promises a verdict this host \
                 cannot prove, and the box was refused rather than run \
                 unenforced (the table's effect could not be read — this \
                 daemon's log carries the probe's own failure)"
                    .to_string(),
            ),
            // Everything else natively is the state this host can still fix
            // from itself — the step not installed, a tree that cannot
            // confine — or a host that decides, whose refusal no gate makes.
            // Those keep NET-079's exception, and the record and notice
            // below say what they run instead.
            _ => None,
        };
    }
    None
}

/// Whether a launch whose host-address box was not placed in a classifier
/// leaf, or was placed on a host that cannot decide per box, advises about
/// that state.
///
/// The counterpart of [`refused_unenforced_host_address_box`]: an unenforced
/// host-address box is the advisory posture on *either* kind of host —
/// natively NET-079's exception, in the guest the interim's own state — so
/// every *session* launch whose box runs without a verdict of its own says
/// so, once per launch like the resolver advisory it is modelled on
/// (design §7.1), never once per daemon. The refusals stand untouched
/// beside it: a box the guest cannot place is refused and advises nothing
/// (the refusal is that state's surface), and so is a deny-all box on a
/// table the guest has not loaded, and natively a deny-all box over either
/// probe cause — the advisory is the *other* host-address boxes' state, the
/// ones that need no verdict enforced to run, and the ruling's ask is that
/// their state be said at every session start, not left as a daemon log
/// line alone.
///
/// The state is read from the placement and the decision, not from the
/// launch's record: the record carries the placement — `per_box` for a
/// placed box, whatever the table decides — while the advisory is the box's
/// *current* state, the one the notice names, so a leaf placed over a table
/// that is not deciding advises exactly like a box nothing placed. What
/// this predicate does not carry is the launch's audience — a launch
/// minted for lifecycle hooks advises nobody (a hook run is not a session
/// start), which the launch itself folds in over
/// [`SandboxLauncher::for_hooks`]. Pure over its inputs, so the gate is
/// pinned where it is written.
fn advises_unenforced_placement(
    network_mode: NetworkMode,
    leaf: Option<&sandbox2::config::ClassifierLeaf>,
    decision: Option<&crate::net::classifier::Decision>,
) -> bool {
    matches!(network_mode, NetworkMode::HostNet)
        && !(leaf.is_some() && decision.is_some_and(|d| d.can_decide_per_box()))
}

/// The advisory text for a launch whose host-address box runs unenforced:
/// what the state is, and what would change it — spelled for the host and
/// the state that produced it, so a person reading the log is told which
/// half of the step this host owes. The guest names no install command:
/// no privileged step exists inside a microVM, so the person to tell is the
/// image's builder, and the interim's words are all the guest has to say.
fn unenforced_placement_notice(
    guest: bool,
    leaf: Option<&sandbox2::config::ClassifierLeaf>,
) -> String {
    if guest {
        return "guest-side classifier enforcement is not available yet; \
                this host-address box runs unenforced (host_ip_enforcement=none)"
            .to_string();
    }
    match leaf {
        None => format!(
            "this host places no classifier leaf for this session: its box \
             runs with the host's address and no egress verdict of its own \
             — {}",
            sandbox2::classifier::install_hint()
        ),
        Some(_) => format!(
            "this host's classifier table is not loaded, so the leaf this \
             session's box was placed in decides nothing: the box runs with \
             the host's address and no egress verdict of its own — {}",
            sandbox2::classifier::install_hint()
        ),
    }
}

/// Moves the box's container supervisor into its classifier leaf, now that
/// it exists.
///
/// The supervisor is the one process of the box that never passes through the
/// sandbox's pre-exec closure: hakoniwa forks it inside `spawn()`, before the
/// program's own child runs the closure that joins the leaf and unshares the
/// cgroup namespace onto it. It is written in by the daemon, from its own
/// namespaces where the leaf is reachable — the same place the shim later
/// writes an injected process. Everything the program forks later takes the
/// leaf from its parent, so the box is in its leaf from its first process to
/// its last.
fn place_box_processes(
    leaf: &sandbox2::config::ClassifierLeaf,
    supervisor: u32,
) -> std::io::Result<()> {
    sandbox2::classifier::place_pid(&leaf.procs(), supervisor)
}

impl SessionLauncher for SandboxLauncher {
    type Process = SandboxProcess;
    // The session env, kept alive for the session's lifetime (it owns the
    // sandbox files backing the running process's rootfs). The own-IP switch
    // attachment, when present, travels separately as `Launched::net_guard` and
    // is torn down explicitly at session end.
    type Guard = crate::env::Env;

    async fn launch(
        self,
        guest: bool,
        session_id: sessions::SessionId,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
    ) -> io::Result<Launched<SandboxProcess, Self::Guard>> {
        let ctx = self.ctx;
        // Move the session policy out of `self` up front so it can be applied
        // after the switch attach below (the rest of `self` is consumed first).
        let policy = self.policy;
        // NET-079: the cohort subtree this box's declaration places its leaf
        // in, decided from the declaration before anything is reserved and
        // before its first process exists — the same verdict the plan below
        // resolves a deny-all box through, and the one the placement's own
        // leaf is named by. The declaration is fixed at create, so a launch
        // decides it once and a box is never re-verdicted mid-flight.
        let classifier_verdict = crate::net::classifier::verdict_of(policy.egress.as_ref());
        // Whether the declaration lets a listen publish at all (NET-016):
        // `allow` with a range. Read now, before the policy moves into the
        // network plan, for the missing-listen-plan line below.
        let listens_can_publish = policy.ingress.as_ref().is_some_and(|ingress| {
            ingress.dynamic_ingress == Some(sessions::DynamicIngress::Allow)
                && ingress.dynamic_allowed_range.is_some()
        });
        let network_mode = self.network_mode;
        // The classifier tree this daemon places boxes in, moved out before
        // the rest of `self` is consumed (see the field's doc).
        let classifier_root = self.classifier_root;
        // The mount table the launch's classifier facts answer over, moved
        // out with it (see the field's doc).
        let classifier_mountinfo = self.classifier_mountinfo;
        let net_switch = self.net_switch;
        let own_address = self.own_address;
        let box_addresses = self.box_addresses;
        // The session name, registered as this PTask's `*.min.internal` hostname on
        // an own-IP attach (finding #3 / UC6); cloned because `name` is consumed by
        // the sandbox env below.
        let session_name = name.clone();
        let composition = self.composition;
        let attach_env = self.attach_env;
        let session = self.session;
        // What this launch is for, decided by the caller that minted it (see
        // [`SandboxLauncher::for_hooks`]): it gates the advisory below, never
        // the placement itself — a hook launch's box is placed like any
        // other's, or runs unenforced like any other's; only the advice is
        // for the session's audience.
        let for_hooks = self.for_hooks;
        // `graph_from_all_packages` is CPU-heavy (nickel evaluation,
        // graph construction) — run it on the blocking pool so it
        // doesn't stall the async executor.
        let (ctx, graph_result) = tokio::task::spawn_blocking(move || {
            let mut ctx = ctx;
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());
            (ctx, r)
        })
        .await
        .map_err(io::Error::other)?;
        let graph = graph_result.map_err(io::Error::other)?;

        // NET-079: the classifier leaf this host-address box's egress verdict
        // is decided on, decided *before anything is reserved* and before its
        // first process exists. Scoped to the host-address box, the one that
        // speaks with an address it did not lease: a none box has no traffic
        // to decide and an own-IP box's verdict is its own, on the address
        // it holds. The decision fails closed for the launch — a tree that
        // is absent, or a daemon that cannot place a process in it, leaves
        // the box unenforced rather than refused natively — and never reaches
        // the box's own pre-exec closure, which is where an unplaceable join
        // would die taking the leaf it cannot take. The guard owns the leaf
        // until the handoff into `Launched`, so a launch abandoned anywhere
        // in between leaves no leaf behind, and it drops after the process
        // guard below so the box's processes are gone before their leaf is
        // removed.
        //
        // Whether this host can decide per box is read fresh, per launch,
        // from the table's *effect* (design §7.4) — the start reading is not
        // kept, because a marker survives whatever emptied the table and the
        // refusal does not, and a start reading would survive it the same
        // way. The probe binds a listener, forks a child, and waits, so it
        // runs on the blocking pool, and only a host-address launch reads
        // one: no other mode has a verdict the cgroup decides, and the one
        // over the same `classifier_root` the box is placed into, so both
        // halves of this launch answer over one tree and one mount table.
        // The whole decision is kept, not only its verdict bit: the refusal
        // and the advice below say which box they are for out of the cause
        // that produced it, so the launch's words and the start-up line
        // name the same ground. The read itself is the one shared fact
        // every host-address path answers over — [`re_read_classifier_fact`],
        // the same read the create response answers over — and the knob's
        // `None` — every production path — is the daemon's own mount table
        // read live inside it, never "no table at all": a launch that
        // answered over no table would read even a guest's `nsdelegate`
        // cgroup2 as not real and refuse every host-address box in it as a
        // broken image, so the live read and the decision share that one
        // blocking hop, and the same one table is what the placement below
        // answers over too.
        let (leaf, decision) = if matches!(network_mode, NetworkMode::HostNet) {
            let (mountinfo, decision) = re_read_classifier_fact(
                classifier_root.clone(),
                classifier_mountinfo.clone(),
                guest,
            )
            .await?;
            // NET-079: the other half of what a host that decides per box
            // refuses — the declaration's own rules. The create path refuses
            // the same declaration over the same predicate while the fact
            // says the host decides, but a box created before that was true —
            // a create the fact read `none` on, or a record persisted before
            // this gate existed — still lands here, and the launch is the
            // last place that can refuse it before the box runs placed and
            // looking decided while its rules go unenforced. Gated on the
            // decision this launch has just re-read, not the node fact: the
            // fact is what a display shows, the launch's own fresh read is
            // what refuses a box. Refused *before* the leaf below is
            // allocated — a box this launch refuses to run never lands in
            // `boxes/allow` — and whatever the launch is for: a hook run of
            // the same box would run the same rules unenforced, so it is
            // refused on the same ground as any other launch. On a host that
            // cannot decide per box the gate answers nothing — NET-079's
            // exception is that host's to keep, and the refusal below is the
            // other one's.
            if let Some(rules) = crate::net::classifier::refuses_unenforceable_declaration(
                network_mode,
                decision.can_decide_per_box(),
                policy.egress.as_ref(),
            ) {
                // The one typed error the create returns over the same
                // rules: `InvalidInput`, not an `other` failure, so the
                // refusal is the same machine-mode failure wherever a
                // client meets it — the create's RPC arm keys on this
                // kind, and the kind is what an `io::Error` carries to
                // whatever downstream reads it. A launch hits the boxes
                // the create's gate never saw — created before the host
                // could decide per box, persisted from before the gate
                // existed — so the two refusals must not read as two
                // different failures of the same declaration.
                let refusal = crate::net::classifier::unenforceable_declaration_refusal(&rules);
                tracing::info!(
                    session = %session_name,
                    network_mode = ?network_mode,
                    host_ip_enforcement = %HostIpEnforcement::PerBox.machine_str(),
                    refusal = %refusal,
                    "refusing a host-address box whose declaration names rules \
                     this host's classifier cannot enforce"
                );
                return Err(refusal);
            }
            let leaf = create_session_leaf(
                &classifier_root,
                mountinfo.as_deref(),
                guest,
                &session_id,
                &session_name,
                classifier_verdict,
                decision.can_decide_per_box(),
            )
            .await?;
            (leaf, Some(decision))
        } else {
            (None, None)
        };
        let mut leaf_guard = leaf.clone().map(BoxLeafGuard::new);

        // What this launch's placement means for the box's egress record:
        // the leaf itself, never the node fact re-read beside it — the
        // record is this box's own launch outcome, and the reads lower it by
        // the fact (`displayed_host_ip_enforcement`), so a leaf placed over
        // a table that is not refusing shows `none` while the host cannot
        // decide and `per_box` once it can again, without a relaunch. The
        // declaration is the placement's other half: a box whose rules the
        // classifier cannot enforce is recorded `none` even placed, so the
        // record never promises `per_box` for rules no verdict enforces.
        // The refusal and the advice below read the one decision.
        let enforcement = host_ip_enforcement(network_mode, leaf.as_ref(), policy.egress.as_ref());

        // A host-address box this host cannot give a verdict of its own is
        // refused where the box's own declaration is the thing that cannot
        // be honoured — never for a state a person could still fix from the
        // host itself. In the guest that is every state: the tree and the
        // table were the image's own boot's work, and there is no installer
        // to run inside a microVM (design §7.1) — a box that cannot be
        // placed has no leaf to decide on at all, and a deny-all box whose
        // table is not loaded would run placed while nothing refuses its
        // connections, a verdict that looks decided and is not. The first
        // refusal names the broken image it is; the second names the
        // interim, guest-side classifier enforcement not being available
        // yet. Natively the same states keep NET-079's exception — the box
        // runs unenforced and the log says so — except the one state where
        // the step's own install is standing behind a refusal that is not
        // in force: a deny-all box placed on either probe cause, refused
        // rather than run on a refusal nothing here is making. A refused
        // box never reaches the advisory below — the refusal is the only
        // thing that launch says; the advisory is for the host-address
        // boxes that run, the ones a verdict has nothing to enforce in
        // yet.
        if let Some(refusal) = refused_unenforced_host_address_box(
            guest,
            network_mode,
            classifier_verdict,
            leaf.is_some(),
            decision.as_ref(),
        ) {
            tracing::error!(
                session = %session_name,
                network_mode = ?network_mode,
                tree = %classifier_root.display(),
                placed = leaf.is_some(),
                refusal = %refusal,
                "refusing a host-address box this host cannot decide an \
                 egress verdict for"
            );
            return Err(io::Error::other(refusal));
        }

        // The advisory for that same state, on either kind of host, as a
        // diagnostic record per launch — on the daemon's log stream, and
        // nowhere else. This is not the session's stderr channel and not a
        // field any client reads: the session reply and the CLI's start
        // output are untouched by it, so a scripted `min session start`
        // never sees this line. What a person in a session gets is the
        // banner below, written onto the session's own pty — that banner is
        // the in-session surface, and this record is its daemon-log twin,
        // attributed to the session and carrying the decision in the
        // machine spelling a reader greps for (`host_ip_enforcement`).
        // Carrying the field out to a client — over the session reply, and
        // surfaced by `min doctor` — is issue #1773, outside this task's
        // layers.
        //
        // At the placement decision, not after the build: a launch that goes
        // no further than this (a tree-less host, an env that fails to
        // build) has still been told apart, and every launch is — the
        // resolver-hook advisory this is modelled on (NET-122, design §7.1)
        // advises on every session start, the install hint it carries is the
        // answer to a host without the tree, and silencing every launch
        // after the first takes the notice away from exactly the session a
        // person is about to work in. In the guest the hint is not what the
        // state means — there is no installer to run there — so the notice
        // is the interim's own words, and the session that just started is
        // told at its own start, both here in the daemon's log and in the
        // pty banner below, never per daemon and never for a hook run.
        //
        // A launch minted for lifecycle hooks advises on neither surface: a
        // hook run is not a session start, and its record would count one
        // hook run as one. The placement itself is not gated with it.
        let advise = advises_unenforced_placement(network_mode, leaf.as_ref(), decision.as_ref())
            && !for_hooks;
        if advise {
            let notice = unenforced_placement_notice(guest, leaf.as_ref());
            tracing::info!(
                session = %session_name,
                host_ip_enforcement = %HostIpEnforcement::None.machine_str(),
                notice = %notice,
                "the session's host-address box runs unenforced on this host",
            );
        }

        // Step 1 (pre-spawn): the provider for this PTask's mode reserves what
        // the sandbox needs — for own-IP, a lease and a running gvproxy — and
        // says what it is. The decision this launch itself read above goes in
        // with them, carried rather than memoized, so the plan below follows
        // this launch's verdict fact and never a concurrent launch's.
        // `PlannedLaunch` owns the release from here: an early `Err` return
        // or a cancelled launch gives the lease back.
        let planned = sandbox2::PlannedLaunch::begin(crate::net::provider::network_for(
            network_mode,
            &net_switch,
            &session_name,
            Some(policy),
            own_address.clone(),
            box_addresses,
            decision,
        ))
        .await
        .map_err(|e| io::Error::other(format!("planning the session network: {e}")))?;

        // The none plan's full seal is the one an injected process has to be
        // told about explicitly (`--seal-none-box`); every other box's
        // confined-families seal is the shim's default. Derived from the plan
        // itself — the same data `new_container` seals the box from — so
        // launch and injection agree by construction.
        let seal_injection = planned.plan().seal() == sandbox2::SocketSeal::Full;

        // Package + env-var union of the launcher baseline and every
        // contribution the composer collected. Packages: baseline set
        // (required for a usable interactive shell) unioned with
        // everything the composition asks for, dedup-preserving-order
        // so the base packages install first. Env vars: the
        // composition's over a small launcher baseline — the session's
        // identity (`MINIMAL_SESSION_NAME`) and the once-only
        // orientation banner pair (see [`session_baseline_env`]) —
        // while sandbox2 sets the session defaults (`PS1`, `PATH`,
        // `HOME`, `LANG`, …) which these vars then override on a
        // shared key.
        //
        // Baseline is intentionally minimal: `base` for the shell,
        // `coreutils` for `ls`/`cat`/etc, and `socat` for the
        // in-sandbox `min` helper's UDS relay to the daemon. `bash`
        // is unconditionally added as a helper dep by
        // `crate::env::Env::build`, so listing it here would just
        // duplicate the entry — `socat` is added there too but is
        // named explicitly so the baseline reads as self-contained.
        //
        // Both maps carry only resolved values, so the composition-
        // vars merge doesn't need `EnvVarValue::Value(...)` at
        // each insert: `EnvArgs::with_resolved_env_vars` wraps once
        // at the boundary. Composition patches and lifecycle hooks
        // are not applied yet (the file-upload path and in-sandbox
        // exec plumbing that they need aren't wired), so they pass
        // through this stage untouched.
        // A shadow set tracks membership so the composition-union
        // pass below stays O(n) instead of the naive
        // `Vec::contains` per iteration (see clippy's O(n²) hint).
        // Two `String` allocs per baseline entry (one for the vec,
        // one for the set) — intrinsic given both need owned
        // strings and `String::clone` is a deep copy. Trivial cost
        // for a three-element baseline.
        let mut packages: Vec<String> =
            BASELINE_PACKAGES.iter().map(|s| (*s).to_string()).collect();
        let mut package_set: std::collections::HashSet<String> =
            BASELINE_PACKAGES.iter().map(|s| (*s).to_string()).collect();
        if let Some(comp) = &composition {
            for p in comp.packages() {
                let name = p.package();
                if package_set.insert(name.to_string()) {
                    packages.push(name.to_string());
                }
            }
        }
        // Env vars, layered by precedence (see [`layer_session_env`]): the
        // launcher baseline and the client-forwarded locale/timezone sit
        // below the composition, and the per-connection facts (`TERM`) sit
        // above it.
        let composition_vars: Vec<(String, String)> = composition
            .as_ref()
            .map(|c| {
                c.vars()
                    .iter()
                    .map(|v| (v.var().name().to_string(), v.var().value().to_string()))
                    .collect()
            })
            .unwrap_or_default();
        // The banner's loadout list arrives as the composition's
        // first-class orientation field; empty means "unknown" (an old
        // client) and seeds nothing — the template's `${…:-}` fallback
        // renders instead.
        let loadouts_display = composition
            .as_ref()
            .map(|c| c.orientation().loadouts_display.as_str())
            .filter(|d| !d.is_empty());
        let env_vars = layer_session_env(
            session_baseline_env(&name, loadouts_display),
            attach_env.inherited,
            composition_vars,
            attach_env.connection,
        );
        // Which shell this attach starts is decided from the composed
        // `SHELL` (see `crate::session_shell`). Read before `env_vars`
        // moves into the env build; the rootfs it has to be checked
        // against doesn't exist until that build has run.
        let requested_shell = env_vars.get("SHELL").cloned();
        // Whether anything composed a prompt. `sandbox2` sets a
        // bash-syntax `PS1` as the session default, which a shell that
        // doesn't speak those escapes prints literally — so a non-bash
        // shell gets its own (see `ShellChoice::prompt`), but only when
        // the user hasn't asked for a specific prompt themselves.
        let composed_prompt = env_vars.contains_key("PS1");
        // For the log line on the fallback path, which fires after
        // `name` has moved into `EnvArgs`.
        let session_label = name.clone();
        // Log every item that will (or would) end up in the session,
        // tagged with its provenance. Patches and lifecycle hooks are
        // included even though the launcher can't act on them yet —
        // an operator inspecting logs should see the intent.
        log_session_contents(&name, BASELINE_PACKAGES, composition.as_deref());

        // Build the env + container and spawn the process. Any failure here
        // leaves no process to reap; `planned` releases its lease on the `Err`
        // return. `planned` outlives the block, so the plan is cloned out.
        let plan = planned.plan().clone();
        let build_and_spawn = async {
            // The env owns the context, graph and the sandbox files backing the
            // running process's rootfs, so it is `Send + 'static` and can be moved
            // into the host as the guard that keeps those files alive.
            // Boxed: inlined, this reaches the cache fetchers' client stack and
            // the launch future's layout overruns rustc's query depth (128).
            let mut env_args =
                crate::env::EnvArgs::new(name, paths.working, paths.home, paths.cache, session)
                    .with_packages(packages)
                    .with_resolved_env_vars(env_vars)
                    // Session envs source package attrs (env_state_wiring,
                    // env_dir/file_mappings) exclusively through the
                    // composer so they're subject to user policy. Task-run
                    // uses a different `Env::build` (mctx::env::Env) and
                    // keeps the legacy un-gated wiring for now.
                    .without_package_attr_wiring()
                    .with_network(plan.clone())
                    .with_username(username);
            // NET-079: the leaf created before this build, so the sandbox
            // binds the tree into the box, joins the box's own first process
            // to the leaf in its pre-exec closure, and names the leaf it
            // entered on its launch log line. The guard keeps the leaf for the
            // launch's duration; this copy travels into the config.
            if let Some(leaf) = leaf_guard.as_ref().and_then(BoxLeafGuard::get).cloned() {
                env_args = env_args.with_classifier_leaf(leaf);
            }
            let mut env = Box::pin(crate::env::Env::build(ctx, graph, env_args)).await?;

            let mut container = env
                .container(&plan)
                .map_err(|e| io::Error::other(format!("container build: {e}")))?;
            container.set_session_leader();

            let pty = Pty::open(sz).map_err(|e| io::Error::other(format!("pty open: {e}")))?;

            // NET-079: a host-address box this launch runs unenforced gets
            // the advisory in the terminal itself — this banner is the
            // in-session surface, the prose a person at the terminal reads;
            // the record for that same decision went to the daemon's log at
            // the placement decision, which no client reads (issue #1773
            // tracks carrying it out). The person about to type in this
            // session is the one whose egress is not being decided, and the
            // state is the deployment's, not the session's, so the notice
            // says what would change it. A guest's *refused* box never gets
            // this far, its launch being refused (design §7.1) — but the
            // guest's other host-address boxes do, and say the interim's
            // words: a session started in a VM host that does not enforce
            // per box yet is told so at its own start, like any host's.
            // And never on a hook launch: its
            // pty is read by nobody, and a hook run is not a session start.
            if advise {
                let notice = unenforced_placement_notice(guest, leaf.as_ref());
                // The same write the shell fallback notice uses, for the
                // same reasons: onto the pty's slave, best-effort, CRLF —
                // see the comment there.
                let written = pty.dup_slave_fd().and_then(|fd| {
                    use std::io::Write as _;
                    std::fs::File::from(fd).write_all(format!("minimal: {notice}\r\n").as_bytes())
                });
                if let Err(e) = written {
                    tracing::debug!(
                        error = %e,
                        "could not print the placement notice to the terminal"
                    );
                }
            }
            // The shell, and the argv it needs to reach the daemon's
            // per-attach environment hook. Every program path here is
            // absolute (`/usr/bin/<shell>`): packages install with
            // `--prefix=/usr` and the generic rootfs has no `/bin`, so a
            // bare name or a `/bin/…` path would fail with ENOENT.
            let shell = crate::session_shell::resolve(requested_shell.as_deref(), &env.rootfs());
            if let Some(notice) = &shell.fallback {
                tracing::warn!(
                    session = %session_label,
                    requested = requested_shell.as_deref().unwrap_or_default(),
                    "{notice}",
                );
                // Onto the pty's *slave* — that is the shell's stdout, so
                // the line reaches the attached terminal ahead of the
                // first prompt. Writing to the master would feed it to
                // the shell as input instead. Best-effort: a session that
                // comes up must not fail over a notice, and the log above
                // has already recorded it. CRLF because this is a raw
                // terminal write, not a line through the shell.
                let written = pty.dup_slave_fd().and_then(|fd| {
                    use std::io::Write as _;
                    std::fs::File::from(fd).write_all(format!("minimal: {notice}\r\n").as_bytes())
                });
                if let Err(e) = written {
                    tracing::debug!(error = %e, "could not print the shell notice to the terminal");
                }
            }
            let mut command = env
                .command(&container, &shell.program, shell.args.iter().copied())
                .map_err(|e| io::Error::other(format!("build command: {e}")))?;
            // Name the shell that is actually running. The composed
            // value is a path on the machine the loadout was authored on
            // (`/opt/homebrew/bin/fish`), which resolves to nothing
            // in-session, and on the fallback path it names a shell that
            // isn't the one at this prompt.
            command.env("SHELL", &shell.program);
            // The session default `PS1` is bash's, so a shell with its
            // own prompt grammar needs the equivalent in that grammar —
            // handed the bash one, zsh renders `\[\033[…\]\u@\h` as
            // literal text. Skipped when the composition set `PS1`: that
            // is the user's own prompt, in whatever syntax they meant.
            if let Some(prompt) = shell.prompt
                && !composed_prompt
            {
                command.env("PS1", prompt);
            }
            command.stdin(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
            command.stdout(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
            let tty_path = pty.slave_path().to_path_buf();
            let (master, slave) = pty.into_fds();
            command.stderr(hakoniwa::Stdio::from(slave));

            // On the fork thread, never this one: the container dies with
            // the thread that forked it (see `sandbox2::forker`).
            let process = sandbox2::forker::on_fork_thread(move || command.spawn())
                .map_err(|e| io::Error::other(format!("exec failed: {e}")))?;
            // `command`/`container` no longer borrow `env`, so it can be moved
            // into the host to keep its backing files alive.
            drop(container);
            Ok::<_, io::Error>((env, master, process, tty_path))
        }
        .await;

        let (env, master, process, tty_path) = match build_and_spawn {
            Ok(parts) => parts,
            Err(e) => return Err(e),
        };

        // From here the process exists, so every way out of this function
        // has to account for it — including the one no `return` covers, a
        // cancelled future. `SpawnedProcessGuard` owns it until the
        // handoff at the bottom; an `Err` return or a drop reaps it.
        let mut process = SpawnedProcessGuard::new(process);

        // The box's closure report, read off the launch's critical path: the
        // cover it took over its bound classifier tree — the design's
        // read-only cgroup2 mount of its namespace root, or the recorded
        // tmpfs fallback with the errno that forced it — or the errno that
        // killed the pre-exec closure before the program ran, which is the
        // one place a `127` ever reaches a daemon log. Nothing in the session
        // waits on it; the session is up while this reads.
        if let Some(leaf) = leaf.as_ref() {
            let report = env.closure_report_path(leaf);
            let session = session_label.clone();
            tokio::spawn(
                async move { report_box_closure(report, session, CLOSURE_REPORT_WATCH).await },
            );
        }

        // NET-079: the box's supervisor is moved into its leaf right after the
        // spawn, from the daemon's own namespaces where the leaf is
        // reachable — the same place the shim later writes an injected
        // process. The program placed itself already, in the pre-exec closure
        // it ran inside the box, before it unshared the cgroup namespace onto
        // the leaf; the supervisor is the one process that never ran that
        // closure. Never fatal: a supervisor the host could not place runs in
        // the daemon's leaf, at the cost of being classified as the daemon
        // rather than its box.
        if let Some(leaf) = leaf_guard.as_ref().and_then(BoxLeafGuard::get) {
            let supervisor = process.get_mut().id();
            match place_box_processes(leaf, supervisor) {
                Ok(()) => tracing::info!(
                    session = %session_label,
                    leaf = %leaf.dir().display(),
                    supervisor,
                    "placed the session's box in its classifier leaf: the \
                     supervisor here, the program in its own pre-exec closure",
                ),
                Err(e) => tracing::warn!(
                    session = %session_label,
                    leaf = %leaf.dir().display(),
                    error = %e,
                    "placing the session's supervisor in its classifier leaf",
                ),
            }
        }

        // Step 3 (post-spawn): hand the process to the provider, which wires its
        // namespace onto the switch; a tap the sandbox layer built travels here
        // inside `Spawned`.
        //
        // Until this returns, an own-IP PTask's egress isn't up yet, but a shell
        // PTask never probes the network in this window (the SSH layer dispatches
        // commands only after `Launched` is returned).
        let net_guard: Option<Box<dyn sandbox2::NetGuard>> = {
            let spawned = sandbox2::Spawned::from_child(process.get_mut());
            match planned.attach(spawned).await {
                // The guard owns the release now; it detaches at session end.
                Ok(guard) => Some(guard),
                // The release stays with `planned`, which drops on this return.
                Err(e) => return Err(io::Error::other(e)),
            }
        };

        // Step 4 (post-attach): gather the listen-publication plan (NET-016,
        // NET-017) — everything the box's listener watcher needs, from what
        // this launch alone holds: the box's lease on the switch, the gvproxy
        // control channel its forwarder verbs ride (built the way the
        // provider's own-IP plan builds it), the published address the
        // switch granted this session (NET-010), the ingress gate the
        // attach just registered for the relay, and the box's publication
        // set, shared with the runtime expose surface so neither binds a
        // port the other already holds. The plan rides [`Launched`] to the
        // host that runs the box, which starts the watcher when it builds
        // and stops it with the session — so a box with no lease, no
        // published address or no live gate carries no plan, and its ports
        // stay unpublishable by listening.
        //
        // Read here, after `planned.attach` above returned: a successful
        // attach has already reported this spawn's lease
        // (`complete_own_ip_attach` reports it before it returns `Ok`), and
        // every launch — a respawn included — runs this step afresh, so the
        // lease the plan carries is always this spawn's own.
        let lease = crate::net::provider::attached_lease(&plan, own_address.as_ref());
        let published = own_address
            .as_ref()
            .and_then(|reporter| reporter.published_address());
        let gate = lease.and_then(crate::net::switch::live_gate);
        if matches!(network_mode, NetworkMode::OwnIp)
            && (lease.is_none() || published.is_none() || gate.is_none())
        {
            // An own-address box whose listens will never publish: said once
            // per launch, naming the fact that is missing, so a listen that
            // never publishes is not silent (NET-016) — a warning where the
            // declaration allows listens to publish, since one it allows will
            // not.
            if listens_can_publish {
                tracing::warn!(
                    session = %session_label,
                    lease = ?lease,
                    published = ?published,
                    gate = gate.is_some(),
                    "the box carries no listen plan; its listens are not published"
                );
            } else {
                tracing::info!(
                    session = %session_label,
                    lease = ?lease,
                    published = ?published,
                    gate = gate.is_some(),
                    "the box carries no listen plan; its listens are not published"
                );
            }
        }
        let listen_plan = match (lease, published, gate) {
            (Some(lease), Some(published), Some(gate)) => {
                tracing::debug!(
                    session = %session_label,
                    %lease,
                    %published,
                    "built the box's listen plan"
                );
                let switch = net_switch.lock().await;
                let control = match switch.transport() {
                    crate::net::SwitchTransport::LocalSpawn => {
                        crate::net::policy::ControlChannel::Unix(switch.control_socket())
                    }
                    crate::net::SwitchTransport::HostShuttle { cid, port } => {
                        crate::net::policy::ControlChannel::Vsock { cid, port }
                    }
                };
                Some(crate::net::listeners::ListenPlan::new(
                    session_label,
                    lease,
                    published,
                    control,
                    gate,
                    self.publications,
                ))
            }
            _ => None,
        };

        Ok(Launched {
            master,
            process: SandboxProcess::new(SandboxBackend {
                child: process.release(),
                // The backend owns the leaf from here: it is what the session
                // is placed in, and its removal at session end is the last
                // thing the box owes.
                leaf: leaf_guard.take().map(BoxLeafGuard::release),
            }),
            guard: env,
            net_guard,
            tty_path,
            seal_injection,
            // The launch's own placement outcome for this box, so the
            // session can record it without re-deriving it from things a
            // person never sees.
            host_ip_enforcement: enforcement,
            // The copy the host keeps, so every process injected into the
            // session can join the same leaf.
            leaf,
            // The box's listen plan, and with it the one handoff to the
            // host that runs the box: taken when the host builds, so a
            // cancelled launch's plan never reaches any host at all.
            listen_plan,
        })
    }
}

/// The test backend: a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) struct MockBackend {
    child: std::process::Child,
}

#[cfg(test)]
impl MockBackend {
    /// Translates a plain process status into the shape `hakoniwa` reports, so
    /// the host cannot tell a mock reap from a sandboxed one: a signalled
    /// process has no exit code of its own and carries the container's 125.
    ///
    /// The report's `code` is unchanged from what this mock always returned, so
    /// the reap value every existing test asserts on is untouched.
    fn report(s: std::process::ExitStatus) -> ExitReport {
        use std::os::unix::process::ExitStatusExt;
        let code = s.code().unwrap_or(-1);
        let reason = match s.signal() {
            Some(sig) => ExitReason {
                code: 125,
                exit_code: None,
                reason: format!("process(mock) received signal {sig}"),
            },
            None => ExitReason {
                code,
                exit_code: Some(code),
                reason: format!("process(mock) exited with code {code}"),
            },
        };
        ExitReport { code, reason }
    }
}

#[cfg(test)]
impl ProcessBackend for MockBackend {
    fn container_pid(&self) -> u32 {
        self.child.id()
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitReport>> {
        let status = self.child.try_wait()?;
        Ok(status.map(Self::report))
    }

    fn wait(&mut self) -> io::Result<ExitReport> {
        let s = self.child.wait()?;
        Ok(Self::report(s))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.child.kill()
    }
}

/// A launched session process backed by a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) type MockProcess = HostProcess<MockBackend>;

/// The sentinel stdin line that makes [`MockLauncher`]'s program exit; any
/// other line is echoed back. Lets a test observe an echo round trip while the
/// process is still alive, then trigger teardown deterministically.
#[cfg(test)]
pub(crate) const MOCK_EXIT_LINE: &str = "quit";

/// A test [`SessionLauncher`] that wires a plain, un-sandboxed host process to a
/// freshly opened PTY — so the [`Host`] runtime can be exercised end-to-end
/// without building a real sandbox (which needs packages unavailable in the
/// unit-test environment).
///
/// The launched program echoes each line of stdin back prefixed with `got:`,
/// and exits only on the [`MOCK_EXIT_LINE`] sentinel — so a test can confirm
/// stdin delivery and stdout forwarding before deterministically triggering
/// process-exit teardown.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct MockLauncher {
    /// Attached to the launched process as `Launched::net_guard`, so a test can
    /// observe network teardown; `None` for the plain mock (mirroring
    /// `HostNet`/`NoNet`).
    net_guard: Option<Box<dyn sandbox2::NetGuard>>,
    /// The placement outcome this mock launch reports (NET-079): seeded by
    /// the session's test launcher from the daemon's one node fact —
    /// `per_box` when the fact's cause says the tree is there to place a
    /// leaf in (`fact_places_a_leaf`), `none` when it does not — so a test
    /// that injects a classifier reading and re-reads the fact has the
    /// launches it drives record each box's own placement outcome over it.
    /// The mock has no sandbox, so it places nothing and models the
    /// placement's outcome; the real launcher's placement-to-record mapping
    /// is pinned where it is written, in this module's launch proofs.
    host_ip_enforcement: Option<HostIpEnforcement>,
    /// The listen plan this mock launch carries in its [`Launched`], so a
    /// test can drive the host's listener watcher over the mock box the way
    /// a real launch drives one over a sandboxed box — and, left `None`,
    /// prove a launch that carries no plan starts no watcher at all.
    listen_plan: Option<crate::net::listeners::ListenPlan>,
}

#[cfg(test)]
impl MockLauncher {
    /// A mock that attaches `net_guard`, for the network-teardown tests.
    pub(crate) fn with_net_guard(net_guard: Box<dyn sandbox2::NetGuard>) -> Self {
        Self {
            net_guard: Some(net_guard),
            host_ip_enforcement: None,
            listen_plan: None,
        }
    }

    /// A mock whose launch carries `host_ip_enforcement` as its placement
    /// outcome — the value the session's test launcher seeds from the
    /// daemon's node fact, so a test's launches record each box's own
    /// outcome over the fact a test's injected reading set.
    pub(crate) fn with_host_ip_enforcement(host_ip_enforcement: HostIpEnforcement) -> Self {
        Self {
            host_ip_enforcement: Some(host_ip_enforcement),
            ..Default::default()
        }
    }

    /// This mock with `net_guard` attached as well, so a test can observe
    /// the teardown of a host-address box's launch.
    pub(crate) fn and_net_guard(self, net_guard: Box<dyn sandbox2::NetGuard>) -> Self {
        Self {
            net_guard: Some(net_guard),
            ..self
        }
    }

    /// This mock with `listen_plan` attached, so a test can drive a box's
    /// listener watcher under whatever else its launch mirrors. The mock has
    /// no sandbox and no network namespace of its own, so the watcher
    /// resolves the box's leader as the sole child its shell runs — the
    /// shape a real container's supervisor gives the resolution — and the
    /// leader's socket table is the daemon's own, where the listening
    /// sockets the test binds in its process are the box's.
    pub(crate) fn and_listen_plan(
        mut self,
        listen_plan: crate::net::listeners::ListenPlan,
    ) -> Self {
        self.listen_plan = Some(listen_plan);
        self
    }
}

#[cfg(test)]
impl SessionLauncher for MockLauncher {
    type Process = MockProcess;
    type Guard = ();

    async fn launch(
        self,
        _guest: bool,
        _session_id: sessions::SessionId,
        _name: String,
        _username: String,
        _paths: SessionPaths,
        sz: WinSize,
    ) -> io::Result<Launched<MockProcess, ()>> {
        let pty = Pty::open(sz)?;

        // A launch that carries a listen plan starts a watcher that
        // resolves its box's leader, and a mock box's leader is the sole
        // child of its shell — so the script runs one (`sleep`, doing
        // nothing but holding the shape) beside its echo loop. The child
        // is never a job-control one — the mock's shell is not interactive
        // — so it reads no tty and touches no foreground rights.
        let leader_child = if self.listen_plan.is_some() {
            "sleep 60 & "
        } else {
            ""
        };
        let script = format!(
            r#"{leader_child}while read line; do [ "$line" = {MOCK_EXIT_LINE} ] && exit 0; printf 'got:%s\n' "$line"; done"#
        );
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg(&script);
        command.stdin(std::process::Stdio::from(pty.dup_slave_fd()?));
        command.stdout(std::process::Stdio::from(pty.dup_slave_fd()?));
        let tty_path = pty.slave_path().to_path_buf();
        let (master, slave) = pty.into_fds();
        command.stderr(std::process::Stdio::from(slave));

        let process = command.spawn()?;

        Ok(Launched {
            master,
            process: MockProcess::new(MockBackend { child: process }),
            guard: (),
            net_guard: self.net_guard,
            tty_path,
            seal_injection: false,
            // The mock has no sandbox, so no classifier placed it anywhere.
            leaf: None,
            host_ip_enforcement: self.host_ip_enforcement,
            // The plan the launch gathered, riding to the host the way a
            // real launch's plan rides: taken when the host builds.
            listen_plan: self.listen_plan,
        })
    }
}

/// The non-launcher inputs to [`Host::spawn`] and [`Host::build`].
///
/// Both entry points take the same set, and `spawn` forwards them verbatim to
/// `build`, so the parameters travel as one named bundle rather than a long
/// positional pass-through. `launcher` stays a separate generic argument.
pub(crate) struct HostParams {
    pub name: String,
    pub username: String,
    pub paths: SessionPaths,
    pub sz: WinSize,
    pub channel: Option<Channel<Msg>>,
    pub control: Option<SessionControl>,
    pub delta: Option<Arc<DeltaSource>>,
    pub archives_dir: std::path::PathBuf,
    pub session_id: sessions::SessionId,
    pub composition: Option<Arc<sessions::core::compose::Composition>>,
    pub connection_env: ConnectionEnv,
    /// The session's hostname-registry marker (NET-128): the host marks the
    /// box's name running when it takes over and stopped when it exits, so a
    /// name the box shares with its node answers NODATA while a dead box's
    /// listeners would otherwise be spoken for by the node's own. `None` for
    /// a host this daemon gave no name route to.
    #[cfg(target_os = "linux")]
    pub name_marker: Option<NameMarker>,
}

/// The host's half of the name lifecycle (NET-128): the registry and the
/// stable session id, so the host can mark its box's name running when it
/// starts and stopped when it exits. Held by [`HostParams`] and copied into
/// the [`Host`], because the mark belongs to the *host's* lifetime, not the
/// session's — a session whose host has exited keeps its name *held* (never
/// NXDOMAIN, so the box's name is not negatively cached), answering NODATA
/// at a shared address until a host runs again.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub(crate) struct NameMarker {
    /// The daemon's registry the marks land in.
    registry: std::sync::Arc<std::sync::RwLock<crate::net::dns::HostnameRegistry>>,
    /// The stable id of the session whose box's name is marked.
    session_id: sessions::SessionId,
}

#[cfg(target_os = "linux")]
impl NameMarker {
    /// Marks one session's box name, in one registry.
    pub(crate) fn new(
        registry: std::sync::Arc<std::sync::RwLock<crate::net::dns::HostnameRegistry>>,
        session_id: sessions::SessionId,
    ) -> Self {
        Self {
            registry,
            session_id,
        }
    }

    /// The box's host is running: its name answers at its address (NET-128) —
    /// the state every box is in from finalize (NET-011), so a mark that finds
    /// nothing stopped changes nothing.
    pub(crate) fn mark_running(&self) {
        self.registry
            .write()
            .expect("hostname registry lock poisoned")
            .mark_running(self.session_id);
    }

    /// The box's host has exited (NET-128): its name stays held — a stopped
    /// box is never mistaken for one that never existed — but a name it
    /// shares with the node answers NODATA until a host runs again, so the
    /// node's own listener at that port is not spoken for by a dead box.
    pub(crate) fn mark_stopped(&self) {
        self.registry
            .write()
            .expect("hostname registry lock poisoned")
            .mark_stopped(self.session_id);
    }
}

impl<P: SessionProcess, G: SessionGuard> Host<P, G> {
    /// The PID of hakoniwa's container supervisor for this session.
    ///
    /// Correct as a handle for every namespace the sandbox unshared *except*
    /// the PID namespace — which is what the own-IP tap wiring uses it for. To
    /// address the session's PID namespace, or to name the shell itself, use
    /// [`Self::session_leader_pid`].
    // Reachable only through `session_leader_pid`, which the exec path uses;
    // kept as the named counterpart so the distinction stays visible.
    #[allow(dead_code)]
    pub(crate) fn container_pid(&self) -> u32 {
        self.process.container_pid()
    }

    /// The PID of the session shell itself — the process hakoniwa exec'd inside
    /// every one of the sandbox's namespaces.
    ///
    /// # Errors
    ///
    /// [`NsenterError::NoSessionLeader`](crate::nsenter::NsenterError::NoSessionLeader)
    /// once the shell has exited; the session's namespaces do not outlive it.
    pub(crate) fn session_leader_pid(&self) -> Result<u32, crate::nsenter::NsenterError> {
        crate::nsenter::session_leader_pid(self.process.container_pid())
    }

    /// Builds a command that runs `program` inside this session's sandbox.
    ///
    /// # Errors
    ///
    /// Fails if the shell's PID cannot be resolved or pinned; see
    /// [`Self::session_leader_pid`].
    #[cfg(not(test))]
    pub(crate) fn command_in_session<I, S>(
        &self,
        program: impl AsRef<std::ffi::OsStr>,
        args: I,
        extra_env: std::collections::BTreeMap<String, String>,
    ) -> Result<std::process::Command, crate::nsenter::NsenterError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let environment = self.guard.command_environment();
        // `with_env` replaces rather than extends, so the merge happens
        // here: session variables first, then the attached terminal's facts,
        // then `extra_env`. The connection layer sits above the session's own
        // variables for the same reason it does at launch — `TERM` describes
        // the terminal, and the session's copy of it is only ever as fresh as
        // the attach that spawned the shell.
        let mut vars = environment.vars;
        vars.extend(self.connection_env.clone());
        vars.extend(extra_env);
        let injection = crate::nsenter::Injection::new(self.session_leader_pid()?, program, args)
            .with_cwd(environment.cwd)
            .with_env(vars);
        // NET-079: the box's leaf, so the injected process joins it in the
        // shim before it joins the namespaces — the only place the join can
        // happen from (see [`Injection::with_classifier_leaf`]).
        let injection = match self.leaf.clone() {
            Some(leaf) => injection.with_classifier_leaf(leaf),
            None => injection,
        };
        // Every injection is sealed: a none box's full seal is named
        // explicitly, and any other box's confined-families seal is the
        // shim's default — either way the shim reinstalls the filter the
        // launch installed, which the joined process does not inherit.
        let injection = if self.seal_injection {
            injection.seal_none_box()
        } else {
            injection
        };
        injection.command()
    }

    /// Under test, build a plain host-side command instead of injecting into
    /// a sandbox — the same swap [`MockLauncher`] makes for the launcher and
    /// `()` makes for the guard.
    ///
    /// [`MockLauncher`]'s program is an un-sandboxed `/bin/sh` with no
    /// children, so there is no container supervisor to resolve and
    /// [`Self::session_leader_pid`] cannot succeed; a test reaching this
    /// would only ever see `NoSessionLeader`. Running host-side instead
    /// keeps everything above the injection under test — the session
    /// environment, the script piping, output capture, outcome reporting,
    /// and the actor wiring that decides *when* hooks run — while
    /// [`crate::nsenter`]'s own tests cover the injection itself.
    #[cfg(test)]
    pub(crate) fn command_in_session<I, S>(
        &self,
        program: impl AsRef<std::ffi::OsStr>,
        args: I,
        extra_env: std::collections::BTreeMap<String, String>,
    ) -> Result<std::process::Command, crate::nsenter::NsenterError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let environment = self.guard.command_environment();
        let mut vars = environment.vars;
        vars.extend(self.connection_env.clone());
        vars.extend(extra_env);
        let mut cmd = std::process::Command::new(program);
        cmd.args(args);
        cmd.env_clear();
        cmd.envs(vars);
        // The mock guard reports no cwd, and an empty one would make every
        // spawn fail; a real sandbox path wouldn't resolve host-side anyway,
        // so only set what exists here.
        if !environment.cwd.is_empty() && std::path::Path::new(&environment.cwd).is_dir() {
            cmd.current_dir(&environment.cwd);
        }
        Ok(cmd)
    }

    /// Snapshot what a hook run needs, or `None` when there is nothing
    /// to run or nothing to run it in.
    fn hook_plan(&self, event: crate::hooks::HookEvent) -> Option<HookPlan> {
        let composition = self.composition.clone()?;
        let leader_pid = match self.session_leader_pid() {
            Ok(pid) => pid,
            Err(e) => {
                tracing::debug!(
                    event = event.as_str(),
                    error = %e,
                    "no session leader; skipping lifecycle hooks",
                );
                return None;
            }
        };
        let environment = self.guard.command_environment();
        Some(HookPlan {
            event,
            commands: crate::hooks::InjectedCommands {
                leader_pid,
                cwd: environment.cwd,
                vars: environment.vars,
                // A hook joins the namespaces rather than being forked from the
                // filtered shell, so the box's seal has to be handed to it the
                // same way the interactive attach path hands it to an injected
                // command: the none box's full seal by flag, the shim's
                // confined-families default for the rest.
                seal_none_box: self.seal_injection,
            },
            composition,
            session_id: self.session_id,
            session_name: self.session_name.clone(),
            hooks_dir: self.hooks_dir.clone(),
            workspace: self.workspace_dir.clone(),
            output: crate::hooks::HookOutput::Tty(self.tty_path.clone()),
        })
    }

    /// Snapshot a plan and run it, if there is anything to run.
    async fn run_hooks_for(&mut self, event: crate::hooks::HookEvent) {
        if let Some(plan) = self.hook_plan(event) {
            run_hook_plan(plan).await;
        }
    }

    /// Spawns a session host from the given launcher, wiring it to `channel` if
    /// one is supplied, and drives its runtime loop on a background task.
    ///
    /// Returns the [`HostHandle`] alongside the [`JoinHandle`] of the runtime
    /// loop, so the owner can await full teardown (process reaped, sandbox guard
    /// dropped) after issuing a [`HostHandle::kill`], and the per-box egress
    /// enforcement this launch placed the box under (NET-079) — the launch's
    /// own outcome, carried out beside the host it produced so the session
    /// can record it on the box's behalf without asking the running host
    /// back for what its launch already decided.
    pub async fn spawn<L>(
        launcher: L,
        params: HostParams,
    ) -> Result<
        (
            HostHandle,
            JoinHandle<Result<i32, std::io::Error>>,
            Option<HostIpEnforcement>,
        ),
        std::io::Error,
    >
    where
        L: SessionLauncher<Process = P, Guard = G>,
    {
        let (host, handle) = Self::build(launcher, params).await?;
        // Read out before `mainloop` takes the host: the value is the
        // launch's own, set once by `build` and never updated, and the
        // host's attrs stay what `get_attrs` serves for the session's life.
        let host_ip_enforcement = host.attrs.host_ip_enforcement;
        let task = tokio::spawn(host.mainloop());
        Ok((handle, task, host_ip_enforcement))
    }

    /// Builds the host and its handle from a launcher without spawning the
    /// runtime loop, so callers (notably tests) can drive [`Self::step`]
    /// directly and observe the host's state.
    async fn build<L>(launcher: L, params: HostParams) -> Result<(Self, HostHandle), std::io::Error>
    where
        L: SessionLauncher<Process = P, Guard = G>,
    {
        let HostParams {
            name,
            username,
            paths,
            sz,
            channel,
            control,
            delta,
            archives_dir,
            session_id,
            composition,
            connection_env,
            #[cfg(target_os = "linux")]
            name_marker,
        } = params;
        // The change-detection baseline (`delta`) is armed once per session and
        // handed in, so a host rebuilt on reattach keeps the activation-time
        // reference point rather than re-snapshotting an already-modified
        // workspace. The root is still kept for the at-risk assessment, whose
        // VCS mode needs the tree path even when no baseline could be armed.
        let workspace_root = paths.working.as_utf8_path().as_std_path().to_path_buf();
        // Kept before `launch` consumes `paths`.
        let hooks_dir = paths.hooks.clone();
        let workspace_dir = paths.working.clone();
        // Kept for `write_connection_env`, which rewrites the per-attach env
        // (TERM included) into the session's home on every reattach.
        let home_dir = paths.home.clone();

        // The launcher consumes `name`; the bindings need it too, to name the
        // archives the shell-exit prompt's save-then-delete lane writes.
        let session_name = name.clone();
        let Launched {
            master,
            process,
            guard,
            net_guard,
            tty_path,
            seal_injection,
            leaf,
            host_ip_enforcement,
            listen_plan,
        } = launcher
            .launch(
                crate::guest::is_microvm_daemon(),
                session_id,
                name,
                username,
                paths,
                sz,
            )
            .await?;

        // The listen-publication watcher (NET-016, NET-017): the plan this
        // launch gathered is the box's whole publication surface — its
        // lease, the switch's published address, the gvproxy control
        // channel, the ingress gate the attach registered, and the
        // publication set it shares with the runtime expose path. It polls
        // the listening sockets of the process the launch names the box's
        // leader (whose `/proc` entry reads the whole box's network
        // namespace) and keeps the box's published ports in step with them
        // until the session ends. A launch that carried no plan — no
        // lease, no published address — starts no watcher, and none of its
        // ports is published by listening.
        //
        // The leader itself is the watcher's to resolve, not this build's to
        // have resolved: a resolution that fails here — a shell that is
        // mid-spawn, a `/proc` that cannot answer for the moment — would
        // otherwise drop the plan with it and silently cost the box its
        // whole listen-published surface, so the build hands the container
        // PID it holds and the watcher asks on every poll until the box's
        // program is there to be found (the module's nothing-is-one-shot
        // contract, held of its start).
        let listen_watcher = listen_plan.map(|plan| {
            crate::net::listeners::ListenWatcher::start(
                plan,
                crate::net::listeners::Leader::Pending {
                    container_pid: process.container_pid(),
                },
            )
        });

        let (sender, receiver) = mpsc::channel(HOST_MAILBOX_CAPACITY);
        let handle = HostHandle { sender };

        let parser = vt100::Parser::new_with_callbacks(
            sz.rows,
            sz.cols,
            0,
            ParserEventHandler(handle.make_weak()),
        );

        let (remote_tx, remote_rx) = mpsc::channel(4);
        let master = {
            set_nonblocking(master.as_raw_fd())?;
            let file = unsafe { std::fs::File::from_raw_fd(master.into_raw_fd()) };
            AsyncFd::new(file)?
        };

        let mut host = Host {
            receiver,
            remote: None,
            output_stall_timeout: OUTPUT_STALL_TIMEOUT,
            output_stall_deadline: None,
            sz,
            parser,
            process,
            pending_pty_err: None,
            master,
            // The launch decided the box's egress verdict posture before
            // anything was reserved; the attributes carry that decision so
            // the session can say which it runs under (design §7.2's
            // declared-and-enforced attribute).
            attrs: HostAttrs {
                host_ip_enforcement,
                ..HostAttrs::default()
            },

            remote_tx,
            remote_rx,
            binding_generation: 0,
            stdout_buf: vec![0u8; 8 * 1024],
            stdin_buf: None,
            net_guard,
            listen_watcher,
            #[cfg(target_os = "linux")]
            name_marker,
            tty_path,
            composition,
            session_id,
            hooks_dir,
            workspace_dir,
            control,
            delta,
            workspace_root,
            session_name,
            archives_dir,
            connection_env,
            home_dir,
            seal_injection,
            leaf,
            chord_matcher: ChordMatcher::new(SessionKeys::default()),
            chord_flush_deadline: None,
            guard,
        };

        if let Some(channel) = channel {
            // The launch already folded these facts into the shell's
            // environment, so pass an empty map rather than re-applying them:
            // `attach` treats empty as "nothing new to say" and publishes what
            // the host already holds.
            host.attach(
                channel,
                sz,
                true,
                ConnectionEnv::new(),
                SessionKeys::default(),
            )
            .await;
        } else {
            // No client to bind, so nothing calls `attach` — publish anyway,
            // so a host minted headlessly still has the files in place before
            // anything in the session looks for them.
            host.publish_connection_env().await;
        }

        Ok((host, handle))
    }

    pub async fn mainloop(mut self) -> Result<i32, std::io::Error> {
        // The box's host is running from here: its name answers at its
        // address (NET-128) — the state it was in from finalize (NET-011), so
        // this mark only speaks where a previous host's exit had stopped it.
        #[cfg(target_os = "linux")]
        if let Some(marker) = &self.name_marker {
            marker.mark_running();
        }
        let result = loop {
            match self.process.try_wait() {
                Ok(Some(exit_code)) => {
                    // This is the host's own account, at info because it is the
                    // moment a live session stops being one. `try_wait` logged
                    // the same hakoniwa reason already, but from the process
                    // handle, which has no span and so names no session —
                    // repeat it here, where it is attributable, for the same
                    // reason the pty/step path does.
                    let exit = self.process.exit_reason();
                    tracing::info!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        exit_code,
                        abnormal = exit.as_ref().is_some_and(ExitReason::is_abnormal),
                        exit_reason = exit.as_ref().map_or("", |r| r.reason.as_str()),
                        "session process exited; reaped by the host loop",
                    );
                    // The process was reaped here before the pty surfaced its
                    // death as an `EIO`. Still notify the attached binding so the
                    // shell-exit prompt renders (and a "delete" choice can tear
                    // the session down); otherwise the binding only observes the
                    // host drop and silently detaches. Without this the prompt is
                    // lost whenever `try_wait` wins the race against the master's
                    // `EIO`.
                    //
                    // The race is structurally one-sided: `step` parks in a
                    // `select!` on the master read, and a dying process closes
                    // every slave fd, so the `EIO` normally lands before this
                    // poll comes round again — which makes this the safety net
                    // rather than the common path. It still has to hold: a
                    // `step` that wakes for some other reason first can reach
                    // here, and then this is the only thing that raises a
                    // prompt at all.
                    self.notify_remote_teardown(TeardownCause {
                        pty_err: None,
                        exit,
                    });
                    break Ok(exit_code);
                }
                Ok(None) => {}
                // Previously silent: a `wait` that fails ends the session
                // exactly like an exit does, and left no trace at all.
                Err(e) => {
                    tracing::warn!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        errno = ?e.raw_os_error(),
                        error = %e,
                        "could not wait on the session process; ending the host",
                    );
                    break Err(e);
                }
            }

            if self.step().await.is_err() {
                // Everything here is gated on a stashed pty error, so a
                // deliberate kill stays silent: `Message::Kill` also returns
                // `Err` from `step`, but a destroy or a daemon shutdown either
                // wants no prompt at all or has already sent its own teardown.
                let mut pending = self.pending_pty_err.take();
                // Read before `take_if` below can empty `pending`: with no
                // stashed pty error, the only way `step` errs is
                // `Message::Kill`, so the end was asked for.
                let requested = pending.is_none();

                // Notify *before* the reap when the process may still be
                // running, because `wait` below is unbounded — see
                // `shell_is_already_gone`. Nothing is lost by going early: a
                // live process has no exit reason to report yet.
                if let Some(e) = pending.take_if(|e| !shell_is_already_gone(e)) {
                    self.notify_remote_teardown(TeardownCause {
                        pty_err: Some(e),
                        exit: None,
                    });
                }

                let code = self.process.wait();
                let exit = self.process.exit_reason();
                // The pty/step arm that got here already logged the errno; this
                // records what reaping the process then yielded.
                //
                // Carries the reason as well as the code because this is the
                // only session-attributed line a *detached* death produces:
                // hakoniwa's own account is logged from the process handle,
                // which has no span and so names no session, and the binding's
                // prompt line never happens with nothing attached.
                //
                // A requested teardown is logged at info: its SIGKILL reaps
                // with the same abnormal reason an OOM kill does, and a warn
                // for every destroy would bury the deaths nobody asked for.
                if requested {
                    tracing::info!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        ?code,
                        abnormal = exit.as_ref().is_some_and(ExitReason::is_abnormal),
                        exit_reason = exit.as_ref().map_or("", |r| r.reason.as_str()),
                        "session process reaped after requested teardown",
                    );
                } else {
                    tracing::warn!(
                        session_id = %self.session_id,
                        session = %self.session_name,
                        ?code,
                        abnormal = exit.as_ref().is_some_and(ExitReason::is_abnormal),
                        exit_reason = exit.as_ref().map_or("", |r| r.reason.as_str()),
                        "session process reaped after pty/step error",
                    );
                }

                // Otherwise notify *after* it, which is the whole point: only
                // the reap can say whether that shell exited or was killed, and
                // on the `EIO` path it costs a few milliseconds.
                if let Some(e) = pending {
                    self.notify_remote_teardown(TeardownCause {
                        pty_err: Some(e),
                        exit,
                    });
                }
                break code;
            }
        };

        // The box's host has exited (NET-128): mark the name stopped *before*
        // the forwards come down, so there is no window in which a lookup is
        // answered at a forward whose process is already dead. The name stays
        // held — answered, never NXDOMAIN — and answers NODATA while it
        // shares an address with the node.
        #[cfg(target_os = "linux")]
        if let Some(marker) = self.name_marker.take() {
            marker.mark_stopped();
        }

        // Stop the listen-publication watcher (NET-017's last half) before
        // the network attachment tears down: the stop withdraws every port
        // the box's processes published by listening — the gate refusing
        // each first, the forward after — so no runtime-published forward
        // outlives the tap it delivers through, and no session ends with a
        // port published on its address. Declared forwards are not this
        // call's: they come down with the attachment below (NET-121).
        if let Some(watcher) = self.listen_watcher.take() {
            watcher.stop().await;
        }

        // Tear down the per-sandbox network attachment explicitly (own-IP switch
        // detach + ingress removal) on this live runtime, before `_guard` drops
        // the sandbox files. No-op for `HostNet`/`NoNet` and net-guard-less mocks.
        if let Some(net_guard) = self.net_guard.take() {
            net_guard.teardown().await;
        }

        result
    }

    /// Logs a pty-master failure and stashes it for [`Self::mainloop`] to hand
    /// to the binding once the process has been reaped.
    ///
    /// Used on any pty read/write failure — in practice the process dying closes
    /// every slave fd, so the master reports `EIO`; this is the signal to unwind
    /// the host.
    ///
    /// Deliberately does *not* notify the binding itself. The error alone
    /// cannot say whether the shell exited or was killed — both arrive as the
    /// same `EIO` — so the notice waits for the reap, which is the only thing
    /// that can tell them apart.
    fn record_pty_err(&mut self, op: PtyOp, e: std::io::Error) {
        // `errno` and `kind` are logged as their own fields, not left inside the
        // rendered message: this is the one line that says whether a session
        // died of the expected EIO-on-exit (5), of an `EINTR` (4) that the read
        // loop treated as fatal rather than retrying, or of something else
        // entirely.
        tracing::warn!(
            session_id = %self.session_id,
            session = %self.session_name,
            op = op.as_str(),
            errno = ?e.raw_os_error(),
            kind = ?e.kind(),
            error = %e,
            attached = self.remote.is_some(),
            "pty master error; tearing down host",
        );
        self.pending_pty_err = Some(e);
    }

    /// Notifies the attached binding that the session is going away, so it
    /// tears down and raises the shell-exit prompt.
    ///
    /// Called once the process has been reaped, from either route into
    /// teardown: the loop's own `try_wait` (no pty error) or a pty failure
    /// stashed by [`Self::record_pty_err`].
    ///
    /// The notice is sent best-effort with `try_send`, never awaited: the
    /// binding drains this queue in the same `select!` as its (potentially
    /// blocking) write to the ssh remote, so awaiting a full queue could wedge
    /// teardown behind a stuck remote. If the queue is full the notice is
    /// dropped — the host returns regardless, and dropping its sender closes the
    /// binding on its next turn. The message stays buffered even as this host
    /// drops, and an mpsc receiver drains its buffer before observing the closed
    /// sender, so the binding sees the teardown before falling through to
    /// `HostGone`.
    fn notify_remote_teardown(&mut self, cause: TeardownCause) {
        // Read off the screen before the binding slot is borrowed: the binding
        // has no view of this host's parser, so the codes that undo whatever
        // input modes the process left behind have to travel with the message.
        let unwind_codes = self.unwind_codes();
        match self.remote.as_mut() {
            Some((tx, ..)) => match tx.try_send(BindingMsg::TeardownDueToProcessExit {
                cause,
                unwind_codes,
            }) {
                Ok(()) => tracing::debug!(
                    session_id = %self.session_id,
                    "handed the teardown cause to the attached binding",
                ),
                // The documented best-effort drop, made visible: the binding
                // never learns why it is going away, so it falls through to
                // `HostGone` and detaches silently without a prompt — which is
                // exactly the "my session just disappeared" report, and has the
                // same user-visible shape as a healthy detach.
                Err(e) => tracing::warn!(
                    session_id = %self.session_id,
                    error = %e,
                    "could not hand the teardown to the binding; \
                     no shell-exit prompt will render",
                ),
            },
            None => tracing::debug!(
                session_id = %self.session_id,
                "session process exited with no binding attached",
            ),
        }
    }

    /// Snapshots the visible terminal screen into the structured
    /// [`minimald_rpc::ScreenSnapshot`] wire type: dimensions, the cursor
    /// position (omitted when the session hid its cursor), and every cell
    /// of the grid. Read-only — no PTY resize and no I/O relay, unlike
    /// `attach`.
    fn screen_snapshot(&self) -> minimald_rpc::ScreenSnapshot {
        screen_to_snapshot(self.parser.screen())
    }

    pub async fn step(&mut self) -> Result<(), ()> {
        // Snapshot the chord-flush deadline for the select below: the arm
        // sleeps until this absolute instant, so the timer survives the select
        // being rebuilt on every `step()` call (a bare `sleep` would restart
        // each iteration and never fire while other events keep waking the
        // loop).
        let chord_flush_deadline = self.chord_flush_deadline;
        // Output backpressure. While the attached binding's mailbox is full,
        // the pty is not read: the shell waits on the terminal instead of
        // this loop parking in a send, so the loop keeps answering its
        // mailbox. A binding that frees no slot within the stall bound is
        // shed. Snapshotted like the chord deadline, so the timer survives
        // the select being rebuilt on every call.
        let stalled_binding = self
            .remote
            .as_ref()
            .filter(|(tx, ..)| tx.capacity() == 0)
            .map(|(tx, ..)| tx.clone());
        self.output_stall_deadline = stalled_binding.as_ref().map(|_| {
            self.output_stall_deadline
                .unwrap_or_else(|| tokio::time::Instant::now() + self.output_stall_timeout)
        });
        let output_stall_deadline = self.output_stall_deadline;
        tokio::select! {
            // Read actor messages.
            Some(msg) = self.receiver.recv() => {
                match msg {
                    Message::Kill(for_shutdown) => {
                        // The other way a session ends: someone asked it to.
                        // Without this line a destroy, a daemon shutdown and a
                        // shell that died on its own are indistinguishable in
                        // the log — they all end with the host loop returning.
                        tracing::info!(
                            session_id = %self.session_id,
                            session = %self.session_name,
                            for_shutdown,
                            "session host killed on request",
                        );
                        if for_shutdown
                            && let Some(binding) = self.remote.take() {
                                // If there was a binding we just swapped out, tell it to
                                // shut down and wait for it to finish.
                                let unwind_codes = self.unwind_codes();
                                retire_binding(
                                    binding,
                                    BindingMsg::TeardownDueToDaemonShutdown(unwind_codes),
                                )
                                .await;
                            }

                        if let Err(e) = self.process.kill() {
                            tracing::warn!(error = %e, "killing session process");
                        }
                        // Drive teardown directly rather than waiting for the
                        // pty to report the death: a hangup on the master does
                        // not reliably wake `readable()`, so a killed process
                        // that produced no draining output would otherwise leave
                        // the loop parked forever. Returning `Err` makes
                        // `mainloop` reap via `wait()` and return.
                        return Err(());
                    }
                    Message::Attach(channel, sz, connection, keys) => {
                        self.attach(channel, sz, false, connection, keys).await;
                    }
                    // Unchanged name: nothing to republish.
                    Message::Rename(new_name) if new_name == self.session_name => {}
                    Message::Rename(new_name) => {
                        self.session_name = new_name.clone();
                        // The attached binding cloned the old name at spawn
                        // for its save-then-delete archive; best-effort, since
                        // the next attach clones the new one anyway.
                        if let Some((tx, ..)) = self.remote.as_ref() {
                            let _ = tx.try_send(BindingMsg::Rename(new_name.clone()));
                        }
                        // The shell's `environ` is frozen at launch, so the
                        // new name reaches it the same way `TERM` does: by
                        // republishing through the per-attach environment
                        // files the shell re-sources at every prompt.
                        self.connection_env
                            .insert("MINIMAL_SESSION_NAME".to_string(), new_name);
                        self.publish_connection_env().await;
                    }
                    Message::SetTitleCallback(title) => {
                        self.attrs.title = Some((title, SystemTime::now()));
                    }
                    Message::AudibleBellCallback => {
                        let (count, last) = &mut self.attrs.audible_bell;
                        *count += 1;
                        *last = Some(SystemTime::now());
                    }
                    Message::VisualBellCallback => {
                        let (count, last) = &mut self.attrs.visual_bell;
                        *count += 1;
                        *last = Some(SystemTime::now());
                    }
                    Message::GetAttrs(s) => {
                        let _ = s.send(self.attrs.clone());
                    }
                    Message::GetScreen(s) => {
                        let _ = s.send(self.screen_snapshot());
                    }
                    // NET-045: forward the ask to the attached client, whose
                    // binding renders the exit prompt's own dialog. Nobody
                    // attached — no binding, or one whose mailbox is wedged —
                    // answers `None` so the session refuses with the typed
                    // nobody-is-attached error rather than hanging on a
                    // dialog nobody can see.
                    Message::AskExpose { port, reply } => match self.remote.as_ref() {
                        None => {
                            // The plan's observability line: one info line per
                            // refusal for want of a client, naming the box and
                            // the port — and the one line the session-level
                            // no-host shortcut never says, so a refusal read
                            // off the log can be told to have come from a
                            // live host that found nobody on it.
                            tracing::info!(
                                session = %self.session_name,
                                port,
                                "refusing the runtime port publish ask for want of a client to answer it"
                            );
                            #[expect(
                                clippy::let_underscore_must_use,
                                reason = "the asker may already be gone; there is nothing to answer then"
                            )]
                            let _ = reply.send(None);
                        }
                        Some((tx, ..)) => {
                            let (binding_reply, binding_recv) = oneshot::channel();
                            match tx
                                .send_timeout(
                                    BindingMsg::AskExpose {
                                        port,
                                        reply: binding_reply,
                                    },
                                    crate::session::HOST_PROBE_TIMEOUT,
                                )
                                .await
                            {
                                // The human may sit at the dialog for as long
                                // as they like, so only the hand-off is
                                // bounded. The answer is awaited on a spawned
                                // task, never inside this loop: a host parked
                                // on a human stops pumping the pty and stops
                                // answering probes, and the probes that
                                // decide `is_alive` would report a live host
                                // dead.
                                Ok(()) => {
                                    tokio::spawn(async move {
                                        // The binding dropping mid-prompt — a
                                        // detach, a shed, a daemon shutdown —
                                        // is the nobody-attached case again.
                                        let answer = binding_recv.await.ok();
                                        tracing::info!(port, answer = ?answer, "the attached client answered the runtime port publish ask");
                                        #[expect(
                                            clippy::let_underscore_must_use,
                                            reason = "the asker may already be gone; there is nothing to answer then"
                                        )]
                                        let _ = reply.send(answer);
                                    });
                                }
                                Err(send_error) => {
                                    // The ask never reached a human. On a
                                    // timeout the message comes back here
                                    // (binding-level reply and all) and drops
                                    // with this arm; on a closed mailbox the
                                    // binding is already gone. Either way the
                                    // host-level answer below is what the
                                    // asker sees: nobody is attached.
                                    tracing::warn!(port, error = %send_error, "the ask could not reach the attached client");
                                    #[expect(
                                        clippy::let_underscore_must_use,
                                        reason = "the asker may already be gone; there is nothing to answer then"
                                    )]
                                    let _ = reply.send(None);
                                }
                            }
                        }
                    },
                    Message::CommandInSession {
                        program,
                        args,
                        extra_env,
                        reply,
                    } => {
                        let _ = reply.send(self.command_in_session(program, args, extra_env));
                    }
                    Message::GetAtRisk(s) => {
                        // Computed on a spawned task: the git commands and
                        // the re-walk are each bounded but can take seconds,
                        // and this loop must keep pumping the pty while
                        // they run.
                        let root = self.workspace_root.clone();
                        let delta = self.delta.clone();
                        tokio::spawn(async move {
                            let _ = s.send(crate::session_delta::assess(root, delta).await);
                        });
                    }
                    #[cfg(test)]
                    Message::SetOutputStallTimeout(timeout) => {
                        self.output_stall_timeout = timeout;
                    }
                    #[cfg(test)]
                    Message::FeedStdin(bytes) => {
                        // Queued, not awaited: a pty whose input side is
                        // wedged (the shell is blocked on an output side that
                        // nobody is draining) must not park this loop, which
                        // a test may be relying on to shed a binding on time.
                        queue_stdin(&mut self.stdin_buf, bytes);
                    }
                }
            },
            // Read from master - stdout of session process => ssh channel (if any).
            // Not while the binding's mailbox is full; see `stalled_binding`.
            r = self.master.readable(), if stalled_binding.is_none() => {
                let mut guard = match r {
                    Ok(g) => g,
                    Err(e) => {
                        // The io reactor failed to report readiness; the master
                        // is unusable, so unwind rather than panic.
                        self.record_pty_err(PtyOp::Readable, e);
                        return Err(());
                    }
                };
                match guard.try_io(|fd| fd.get_ref().read(&mut self.stdout_buf)) {
                    Ok(Ok(0)) => {},
                    Ok(Ok(n)) => {
                        let b = &self.stdout_buf[..n];
                        self.attrs.stdout_last = Some(SystemTime::now());
                        self.parser.process(b);
                        // Never an awaited send: this arm runs only while the
                        // mailbox has a free slot, and nothing else fills it
                        // in between. What can fail is a binding whose task
                        // has already ended.
                        if let Some((tx, ..)) = self.remote.as_ref()
                            && let Err(e) = tx.try_send(BindingMsg::Stdin(b.to_vec()))
                        {
                            tracing::warn!("shedding binding on stdout=>remote send: {e}");
                            self.shed_binding();
                        }
                    }
                    // Every errno except `WouldBlock` (which `try_io` routes to
                    // the arm below) lands here and is fatal to the host —
                    // `EINTR` included, which is retryable and is not retried.
                    // The errno is on the log line so a spurious teardown can
                    // be told apart from the genuine EIO-on-exit.
                    Ok(Err(e)) => {
                        self.record_pty_err(PtyOp::Read, e);
                        return Err(());
                    },
                    Err(_would_block) => {},
                }
            },
            // A slot freed up in the stalled binding's mailbox. The permit is
            // dropped at once; the point is to wake the loop so the pty read
            // arm re-arms.
            reserved = async {
                match stalled_binding.as_ref() {
                    Some(tx) => tx.reserve().await.map(drop),
                    None => std::future::pending().await,
                }
            } => {
                if reserved.is_err() {
                    tracing::warn!("shedding binding whose task has ended");
                    self.shed_binding();
                }
            }
            // The stalled binding took no output within the stall bound: its
            // client has stopped reading.
            _ = async {
                match output_stall_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                tracing::warn!(
                    session_id = %self.session_id,
                    session = %self.session_name,
                    stall = ?self.output_stall_timeout,
                    "shedding binding that took no session output within the stall bound",
                );
                self.shed_binding();
            }
            // Read from remote (ssh channel) - these keystrokes need writing to the pty.
            //
            // To ensure we never block service of reads from the master side of the pty ('stdout'),
            // we only consume new keystrokes if we have none waiting to be written to the pty, and
            // pending writes to the pty are serviced async by their own select arm (below).
            Some(msg) = self.remote_rx.recv(), if self.stdin_buf.is_none() => {
                // Discard input queued by the superseded binding: its bytes
                // predate the attach that installed the current session keys,
                // and matching them now would hand the old channel's
                // keystrokes to the new channel's chord (or its size).
                if msg.generation != self.binding_generation {
                    return Ok(());
                }
                match msg.kind {
                    StdinMsgKind::Bytes(b) => {
                        self.attrs.stdin_last = Some(SystemTime::now());

                        // Session-key chord matching over the stdin byte
                        // stream: the leader chord is swallowed and enters
                        // command mode; the next keystroke is the subcommand —
                        // detach, forward, or an unbound key that cancels. The
                        // leader is never forwarded except via the explicit
                        // forward subcommand. Coalesced and split chunks are
                        // handled by the matcher; the decisions below only map
                        // outcomes to I/O, with every PTY-bound byte (data
                        // runs and verbatim leaders) collected in stream order.
                        let mut forward: Vec<u8> = Vec::new();
                        for outcome in self.chord_matcher.feed(&b) {
                            match outcome {
                                FeedOutcome::Forward(bytes) => {
                                    forward.extend_from_slice(&bytes);
                                }
                                FeedOutcome::Action(KeyAction::Swallow) => {}
                                FeedOutcome::Action(KeyAction::EnterCommandMode) => {
                                    // Ring the terminal bell on the channel back
                                    // to the user (never the PTY, so the app
                                    // never sees it) when the client opted in.
                                    // `try_send`: a bell is worth dropping,
                                    // and an awaited send would park this loop
                                    // behind a stalled binding.
                                    if self.chord_matcher.keys().bell_on_leader
                                        && let Some((tx, ..)) = self.remote.as_ref()
                                    {
                                        let _ = tx.try_send(BindingMsg::Stdin(vec![0x07]));
                                    }
                                }
                                FeedOutcome::Action(KeyAction::Detach) => {
                                    // Bounded, because the detach chord is also
                                    // how a user gets out of an attach whose
                                    // output has stalled, and then the mailbox
                                    // is full. A binding that cannot take the
                                    // detach in time is shed, which closes its
                                    // channel all the same.
                                    let uc = self.unwind_codes();
                                    if let Some((tx, ..)) = self.remote.as_ref() {
                                        match tx
                                            .send_timeout(
                                                BindingMsg::TeardownDueToDetach(uc),
                                                crate::session::HOST_PROBE_TIMEOUT,
                                            )
                                            .await
                                        {
                                            Ok(()) => self.remote = None,
                                            Err(e) => {
                                                tracing::warn!("shedding binding that could not take the detach: {e}");
                                                self.shed_binding();
                                            }
                                        };
                                    }
                                }
                                FeedOutcome::Action(KeyAction::ForwardLeader) => {
                                    // Queue a verbatim leader byte in the PTY
                                    // stream, handing the next keystroke to the
                                    // layer below (a nested daemon *that
                                    // negotiated the same leader*, if any).
                                    // Safe to over-send: a stray leader past the
                                    // deepest layer hits the app's own
                                    // non-destructive leader binding.
                                    forward.push(self.chord_matcher.keys().leader.plain_byte());
                                }
                            }
                        }
                        if !forward.is_empty() {
                            queue_stdin(&mut self.stdin_buf, forward);
                        }

                        // Arm (or clear) the idle-flush timer: a chunk that
                        // leaves the matcher holding a split candidate (a lone
                        // `ESC`, a prefix of every kitty form) must not wedge
                        // that candidate forever — flush it to the PTY as data
                        // once the stream goes quiet.
                        self.chord_flush_deadline = self
                            .chord_matcher
                            .has_pending()
                            .then(|| tokio::time::Instant::now() + CHORD_FLUSH_IDLE);
                    }
                    StdinMsgKind::TerminalUpdate(sz) => {
                        self.set_size(WinSize::from(&sz));
                    },
                    StdinMsgKind::WindowChange{ col_width, row_height, pix_height, pix_width } => {
                        self.set_size(WinSize {
                            rows: row_height as u16,
                            cols: col_width as u16,
                            xpixel: pix_width as u16,
                            ypixel: pix_height as u16,
                        });
                    },
                }
            },
            // Write buffered keystrokes into the pty, if any,
            w = self.master.writable(), if self.stdin_buf.is_some() => {
                let mut guard = match w {
                    Ok(g) => g,
                    Err(e) => {
                        // The io reactor failed to report writability; the master
                        // is unusable, so unwind rather than panic.
                        self.record_pty_err(PtyOp::Writable, e);
                        return Err(());
                    }
                };
                let (buff, n) = self.stdin_buf.as_mut().unwrap();
                let res = guard.try_io(|fd| fd.get_ref().write(&buff[*n..]));
                match res {
                    Ok(Ok(extra)) => {
                        if (*n+extra) == buff.len() {
                            self.stdin_buf = None;
                        } else {
                            *n += extra;
                        }
                    }
                    // A write failure means the slave side is gone (the process
                    // died, e.g. on kill): EIO closes every slave fd. Tear the
                    // host down so it gets reaped, instead of panicking and
                    // leaking the process as a zombie.
                    Ok(Err(e)) => {
                        self.record_pty_err(PtyOp::Write, e);
                        return Err(());
                    }
                    Err(_would_block) => {},
                }
            }
            // Flush a held chord-matcher split candidate once the stream goes
            // quiet. A lone `ESC` is a strict prefix of every kitty form, so
            // the matcher holds it for the next chunk; without this, a bare
            // `ESC` (e.g. leaving vim insert mode) would be held until the
            // user's next keystroke. `pending()` keeps the arm inert while no
            // candidate is held.
            _ = async {
                match chord_flush_deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            } => {
                self.chord_flush_deadline = None;
                // Appended after anything already queued: forwarded input
                // still waiting on an unwritable pty predates the candidate
                // the flush releases, and replacing the buffer would drop it
                // (see `queue_stdin`).
                let flushed = self.chord_matcher.flush();
                if !flushed.is_empty() {
                    queue_stdin(&mut self.stdin_buf, flushed);
                }
            }

        }

        Ok(())
    }

    async fn attach(
        &mut self,
        channel: Channel<Msg>,
        sz: WinSize,
        skip_flush: bool,
        connection: ConnectionEnv,
        keys: SessionKeys,
    ) {
        // Merge the connection facts rather than replacing the stored map.
        // Every attach carries the banner's detach hint (derived from this
        // channel's keys), but only some carry a terminal — replacing
        // wholesale would let a terminal-less attach drop the last published
        // `TERM` (see the attach-side log about keeping it). Merging updates
        // whatever this attach declares and leaves the rest standing.
        self.connection_env.extend(connection);
        self.publish_connection_env().await;

        // A new channel means a fresh matcher: fresh key negotiation, idle
        // command-mode state, and no pending split candidate — two clients
        // with different configs on the same session each get their own
        // chord, and a reattach never inherits a stale awaiting-subcommand
        // state.
        self.chord_matcher = ChordMatcher::new(keys);
        // A fresh matcher holds no candidate, so any pending idle-flush
        // deadline from the previous channel is stale.
        self.chord_flush_deadline = None;

        // Bump before spawning the new binding: anything the superseded
        // binding already queued into the shared stdin channel carries the
        // old generation from here on, so the stdin arm drops it instead of
        // interpreting those keystrokes under this channel's fresh keys.
        self.binding_generation += 1;

        if !skip_flush {
            self.parser.screen_mut().set_size(sz.rows, sz.cols);
            let _ = channel
                .make_writer()
                .write_all(&self.parser.screen().state_formatted())
                .await;
        }
        let new_binding = Binding::spawn(
            channel,
            self.remote_tx.clone(),
            self.binding_generation,
            self.control.clone(),
            self.delta.clone(),
            self.session_name.clone(),
            self.archives_dir.clone(),
        )
        .await;

        if let Some(old_binding) = self.remote.replace(new_binding) {
            // If there was a binding we just swapped out, tell it to
            // shut down and wait for it to finish.
            let unwind_codes = self.unwind_codes();
            retire_binding(
                old_binding,
                BindingMsg::TeardownDueToSuperceded(unwind_codes),
            )
            .await;
        }

        self.set_size(sz);

        // After the binding is installed and sized, so a hook writing to
        // the terminal reaches the client that just attached.
        self.run_hooks_for(crate::hooks::HookEvent::Attach).await;
    }
    /// Rewrites the session's per-attach environment files from
    /// [`Self::connection_env`].
    ///
    /// Takes `&mut self` rather than `&self` deliberately: a `Host` holds a
    /// non-`Sync` `dyn NetGuard`, so a `&Host` held across the write's await
    /// would make the whole session future non-`Send` (the same constraint
    /// [`HookPlan`] snapshots around).
    async fn publish_connection_env(&mut self) {
        write_connection_env(self.home_dir.clone(), self.connection_env.clone()).await;
    }

    /// Drops the attached binding without waiting for it, for when it has
    /// stopped taking what the host hands it.
    ///
    /// Cancels the binding's shed token rather than aborting its task: an
    /// aborted task drops its channel halves, and russh sends no close for a
    /// dropped channel, so the client would stay connected with nothing
    /// behind it. A shed binding instead leaves through its own exit path,
    /// which sends EOF, an exit status and a close.
    ///
    /// Bumps the generation first. Stdin that the shed binding already queued
    /// into the shared stdin channel still carries the old generation, so the
    /// stdin arm drops it instead of handing a dead channel's keystrokes to
    /// the shell (or to a later re-attach's fresh chord).
    fn shed_binding(&mut self) {
        self.binding_generation += 1;
        self.output_stall_deadline = None;
        if let Some((_tx, _task, shed)) = self.remote.take() {
            shed.cancel();
        }
    }

    fn set_size(&mut self, sz: WinSize) {
        // If the terminal size changed, reconfigure the pty.
        if sz != self.sz {
            if let Err(e) = set_winsize(self.master.as_raw_fd(), sz) {
                tracing::warn!(error = %e, "set_winsize failed, ignoring");
            }
            self.parser.screen_mut().set_size(sz.rows, sz.cols);
            self.sz = sz;
        }
    }

    /// Computes terminal escape sequences to return the outer terminal
    /// to a normal state on detach.
    ///
    /// Deliberately *narrow*: the host has a screen model, so it emits only
    /// what this session actually turned on. That matters most for
    /// [`LEAVE_ALT_SCREEN`](sessions::terminal::LEAVE_ALT_SCREEN), which is
    /// not inert against a terminal that never left the normal buffer — see
    /// its docs. The `min` client's blind fallback exists only for the case
    /// where these bytes cannot reach the tty at all.
    fn unwind_codes(&self) -> Vec<u8> {
        use sessions::terminal as term;

        let live = self.parser.screen();
        let clean = vt100::Parser::new(live.size().0, live.size().1, 0)
            .screen()
            .clone();

        // app keypad/cursor, paste, mouse
        let mut out = clean.input_mode_diff(live);
        // disable alternate screen
        if live.alternate_screen() {
            out.extend_from_slice(term::LEAVE_ALT_SCREEN.as_bytes());
        }
        // disable hidden cursor
        if live.hide_cursor() {
            out.extend_from_slice(term::SHOW_CURSOR.as_bytes());
        }

        // blind: reset text colors etc ('SGR')
        out.extend_from_slice(term::SGR_RESET.as_bytes());
        // blind: disable focus reporting
        out.extend_from_slice(term::FOCUS_REPORTING_OFF.as_bytes());
        out
    }
}

#[cfg(test)]
mod tests;
