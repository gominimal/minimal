//! The running state of an active session.
//!
//! The [`Pty`] struct owns a master/slave pseudo-terminal pair created via
//! `openpty(3)`, exposing its file descriptors and window-size controls.
//!
//! The [`Host`] struct holds the running state of an active session.

use async_dialog::Selection;
use either::Either;
use russh::Channel;
use russh::server::Msg;
#[cfg(not(test))]
use sandbox2::Network;
#[cfg(not(test))]
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use std::time::SystemTime;
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tracing::Instrument as _;

use crate::RequestedPty;
use crate::session::SessionPaths;
use crate::sessions::SessionControl;
#[cfg(not(test))]
use sessions::NetworkMode;

/// Command sequence for the ctrl-w key chord, when the kitty keyboard protocol
/// is negotiated.
///
/// Corresponds to: Kitty: CSI 119 ; 5 u
const CTRL_W_CSI_U: &[u8] = b"\x1b[119;5u";
/// Command sequence for the ctrl-w key chord, when the modifyOtherKeys key
/// sequences are used by the outer terminal.
///
/// Corrsponds to: modifyOtherKeys: CSI 27 ; 5 ; 119 ~
const CTRL_W_CSI_27: &[u8] = b"\x1b[27;5;119~";

/// Header of the prompt shown over the channel when a session's shell process
/// exits, offering to detach or delete. Exposed so tests can await its
/// appearance in the channel output before answering.
pub(crate) const SHELL_EXIT_PROMPT: &str =
    "Session shell process exited. What would you like to do with this session?";

/// The dimensions of a terminal.
///
/// This is the libc-facing view of a terminal size, mirroring `libc::winsize`.
/// The SSH layer's [`RequestedPty`] carries the same dimensions (plus `term`
/// and terminal modes) as `u32`s; convert via [`From`] when opening a PTY.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinSize {
    pub rows: u16,
    pub cols: u16,
    pub xpixel: u16,
    pub ypixel: u16,
}

impl From<&RequestedPty> for WinSize {
    /// Extracts the terminal dimensions, clamping SSH's `u32` to
    /// `u16` and replacing any zero dimension with a 24×80 default
    /// (avoids a vt100 panic on unprobed clients).
    fn from(pty: &RequestedPty) -> Self {
        let (cols, rows) = pty.char_sizes;
        let (xpixel, ypixel) = pty.pixel_sizes;
        let rows = rows.min(u16::MAX as u32) as u16;
        let cols = cols.min(u16::MAX as u32) as u16;
        Self {
            rows: if rows == 0 { 24 } else { rows },
            cols: if cols == 0 { 80 } else { cols },
            xpixel: xpixel.min(u16::MAX as u32) as u16,
            ypixel: ypixel.min(u16::MAX as u32) as u16,
        }
    }
}

/// A pseudo-terminal pair (master + slave).
#[derive(Debug)]
pub struct Pty {
    master: OwnedFd,
    slave: OwnedFd,
}

impl Pty {
    /// Creates a new PTY pair via `openpty(3)` with the given initial size.
    pub fn open(size: WinSize) -> io::Result<Self> {
        let mut master: RawFd = -1;
        let mut slave: RawFd = -1;

        let ws = libc::winsize {
            ws_row: size.rows,
            ws_col: size.cols,
            ws_xpixel: size.xpixel,
            ws_ypixel: size.ypixel,
        };

        // SAFETY: We pass valid pointers for the output fds and winsize, and
        // NULL for the optional name/termios parameters.
        let ret = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &ws,
            )
        };
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `openpty` returned successfully, so both fds are valid and
        // open. We take ownership immediately.
        let master = unsafe { OwnedFd::from_raw_fd(master) };
        let slave = unsafe { OwnedFd::from_raw_fd(slave) };

        // `openpty` returns fds without close-on-exec. Set it so these fds
        // don't leak into unrelated child processes that happen to `fork`
        // concurrently: a leaked slave fd would keep this master from ever
        // seeing EOF when our own child exits, stalling teardown. The child we
        // intend to wire up still gets its stdio via `dup2`, which is unaffected
        // by the source fd's close-on-exec flag.
        set_cloexec(master.as_raw_fd())?;
        set_cloexec(slave.as_raw_fd())?;

        Ok(Self { master, slave })
    }

    /// Returns the raw file descriptor for the master side.
    pub fn master_fd(&self) -> RawFd {
        self.master.as_raw_fd()
    }

    /// Returns the raw file descriptor for the slave side.
    pub fn slave_fd(&self) -> RawFd {
        self.slave.as_raw_fd()
    }

    /// Returns a duplicate file descriptor for the slave side.
    pub fn dup_slave_fd(&self) -> io::Result<OwnedFd> {
        dup_fd(&self.slave)
    }

    /// Consumes the PTY pair, returning the owned master and slave fds.
    pub fn into_fds(self) -> (OwnedFd, OwnedFd) {
        (self.master, self.slave)
    }

    /// Gets the current terminal size of the slave side.
    pub fn get_size(&self) -> io::Result<WinSize> {
        get_winsize(self.master.as_raw_fd())
    }

    /// Sets the terminal size of the slave side.
    pub fn set_size(&self, size: WinSize) -> io::Result<()> {
        set_winsize(self.master.as_raw_fd(), size)
    }
}

/// Emit one `tracing::info!` per item the launcher folds into the
/// session — packages, vars, patches, and lifecycle hooks —
/// tagging each with its provenance so an operator can trace
/// "where did `EDITOR=hx` come from?" back to the loadout /
/// project / package that contributed it.
///
/// Baseline items (the launcher-defaults `PS1`, `base`, `coreutils`,
/// `socat`) log with `source = "launcher-baseline"` so they can be
/// distinguished from composition contributions. Patches and hooks
/// still log even though the launcher can't act on them yet — an
/// operator inspecting a session should see the intent even when
/// the plumbing is deferred.
///
/// Var values are logged at `debug` (separate call) rather than
/// `info` so an accidentally-inherited secret doesn't sit in the
/// default log stream.
#[cfg(not(test))]
fn log_session_contents(
    session_name: &str,
    baseline_packages: &[&str],
    baseline_var_names: &[&str],
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
    for k in baseline_var_names {
        tracing::info!(
            session = session_name,
            domain = "var",
            name = k,
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
    for h in comp.lifecycle_hooks() {
        let src = sessions::core::source::Provenanced::source(h);
        let hook = h.hook();
        [
            ("on_activate", hook.on_activate()),
            ("on_destroy", hook.on_destroy()),
            ("on_failure", hook.on_failure()),
        ]
        .into_iter()
        .filter_map(|(event, script)| script.map(|s| (event, s)))
        .for_each(|(event, script)| {
            let kind = match script {
                sessions::core::lifecyclehook::HookScript::Inline(_) => "inline",
                sessions::core::lifecyclehook::HookScript::External(_) => "external",
            };
            tracing::info!(
                session = session_name,
                domain = "lifecycle_hook",
                event = event,
                script_kind = kind,
                source = ?src,
                deferred = true,
                "session content (lifecycle hook: exec plumbing deferred)",
            );
        });
    }
}

/// Duplicate `fd` into a new close-on-exec `OwnedFd` via
/// `F_DUPFD_CLOEXEC`, so a concurrent `fork` can't inherit and hold
/// the pty open past our child's exit.
fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fcntl(F_DUPFD_CLOEXEC)` succeeded, so `raw` is a valid, open fd.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// Reads the terminal window size for the given fd.
fn get_winsize(fd: RawFd) -> io::Result<WinSize> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `ws` is a valid, zeroed `winsize` struct and `fd` is an open fd.
    let ret = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(WinSize {
        rows: ws.ws_row,
        cols: ws.ws_col,
        xpixel: ws.ws_xpixel,
        ypixel: ws.ws_ypixel,
    })
}

/// Sets the terminal window size for the given fd.
fn set_winsize(fd: RawFd, size: WinSize) -> io::Result<()> {
    let ws = libc::winsize {
        ws_row: size.rows,
        ws_col: size.cols,
        ws_xpixel: size.xpixel,
        ws_ypixel: size.ypixel,
    };
    // SAFETY: `ws` is a valid `winsize` struct and `fd` is an open fd.
    let ret = unsafe { libc::ioctl(fd, libc::TIOCSWINSZ, &ws) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

enum BindingMsg {
    Stdin(Vec<u8>),
    /// The session process ended, so the binding should tear down and raise the
    /// shell-exit prompt. Carries the pty error when teardown was triggered by
    /// an *unexpected* master read/write failure (surfaced to the user); `None`
    /// when the process was reaped cleanly or the master reported the expected
    /// `EIO`-on-exit.
    TeardownDueToProcessExit(Option<std::io::Error>),
    TeardownDueToSuperceded(Vec<u8>),
    TeardownDueToDetach(Vec<u8>),
}

/// A connection between a [`Host`] and an SSH channel.
///
/// The [`Binding`] is owned by the spawned async task, but the
/// host owns (and communicates via) the [`mpsc::Receiver`] end of
/// `stdin_tx`, and the [`mpsc::Sender`] end of `receiver`.
struct Binding {
    /// The remote end of this binding.
    channel: Channel<Msg>,
    /// Channel the binding writes down to communicate stdin to the host.
    stdin_tx: mpsc::Sender<Either<bytes::Bytes, RequestedPty>>,
    /// Channel the [`Host`] uses to communicate with this [`Binding`].
    receiver: mpsc::Receiver<BindingMsg>,
    /// Capability to destroy the owning session, exercised when the user picks
    /// "delete" on the shell-exit prompt. `None` for hosts spawned without a
    /// manager (the test harness), where "delete" degrades to a detach.
    control: Option<SessionControl>,
}

impl Binding {
    /// Spawns a new binding task for a given channel, returning objects
    /// which the owning [`Host`] should own to communicate with it.
    pub(crate) async fn spawn(
        channel: Channel<Msg>,
        stdin_tx: mpsc::Sender<Either<bytes::Bytes, RequestedPty>>,
        control: Option<SessionControl>,
    ) -> (mpsc::Sender<BindingMsg>, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(4);

        let binding = Self {
            channel,
            stdin_tx,
            receiver: rx,
            control,
        };

        // The channel id ties every line this binding logs back to the
        // connection span's `accepted connection`/`closed` lines — field
        // analysis stalls without that correlation.
        let span = tracing::info_span!("binding", channel = %binding.channel.id());
        (tx, tokio::spawn(binding.run().instrument(span)))
    }

    async fn run(mut self) {
        tracing::info!("binding attached to session channel");
        let (mut rs, ws) = self.channel.split();
        let mut w = ws.make_writer();

        #[derive(Debug, PartialEq, Eq)]
        enum MainloopExitReason {
            HostGone,
            Detach,
            Superceded,
            ProcessExited,
        }

        // Reading from the remote stops once it sends EOF;
        // the loop lives on to keep forwarding stdout.
        let mut remote_open = true;
        let exit_reason = loop {
            tokio::select! {
                // Remote (ssh channel) => session stdin.
                res = rs.wait(), if remote_open => match res {
                    None => remote_open = false,
                    Some(msg) => {
                        match msg {
                            russh::ChannelMsg::Data{ data } => {
                                let _ = self.stdin_tx.send(Either::Left(data)).await;
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
                                let _ = self.stdin_tx.send(Either::Right(RequestedPty {
                                    char_sizes: (col_width, row_height),
                                    pixel_sizes: (pix_width, pix_height),
                                    term: term.to_string(),
                                    modes: terminal_modes.to_vec(),
                                })).await;
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
                // Session stdout => remote (ssh channel).
                // A closed channel means the host is gone;
                // tear the attachment down.
                msg = self.receiver.recv() => {
                    let Some(msg) = msg else { break MainloopExitReason::HostGone; };
                    match msg {
                        BindingMsg::Stdin(b) => {
                            let _ = w.write_all(&b).await;
                        },
                        BindingMsg::TeardownDueToProcessExit(err) => {
                            // Surface only a genuine, unexpected master error; the
                            // expected `EIO`-on-exit (os error 5) and clean reaps
                            // stay silent — the shell-exit prompt speaks for them.
                            if let Some(e) = err
                                && e.raw_os_error() != Some(5)
                            {
                                let _ = w.write_all(format!("Error reading stdout: {e}\n").as_bytes()).await;
                            }
                            break MainloopExitReason::ProcessExited;
                        }
                        BindingMsg::TeardownDueToSuperceded(unwind_codes) => {
                            let _ = w.write_all(&unwind_codes).await;
                            let _ = w.write_all(b"\r\nDisconnecting - session attached to from a different connection\r\n").await;
                            break MainloopExitReason::Superceded;
                        }
                        BindingMsg::TeardownDueToDetach(unwind_codes) => {
                            let _ = w.write_all(&unwind_codes).await;
                            let _ = w.write_all(b"\r\nDetaching due to ctrl-w.\r\n").await;
                            break MainloopExitReason::Detach;
                        }
                    };

                }
            }
        };

        tracing::info!(reason = ?exit_reason, "binding leaving mainloop");

        if exit_reason == MainloopExitReason::ProcessExited {
            // The shell process exited. For a bash shell, this usually meant someone pressed ctrl-d absent-mindedly.
            // We presume they didnt want to completely destroy the session, perhaps just detach, but lets prompt
            // to see where they wanted to go from here.
            let _ = w.write_all(b"\r\n").await;
            match async_dialog::Select::new()
                .with_prompt(SHELL_EXIT_PROMPT)
                .items([
                    "Detach, leaving the session running",
                    "Delete, all in-session files permanently deleted",
                ])
                .interact(rs.make_reader(), &mut w)
                .await
            {
                // User selected detach, keep going to disconnect
                Ok(Selection::At(0)) => {}
                // User cancelled selection, safest option is to detach
                Ok(Selection::Cancelled) => {}
                // User selected delete: ask the manager to tear the whole
                // session down (kill the host, remove the on-disk record) before
                // we close the channel. Awaiting is deadlock-free here — the
                // destroy cascade waits on the host runtime loop (already exiting
                // now that the process has ended), never on this binding task.
                Ok(Selection::At(1)) => match &self.control {
                    Some(control) => {
                        let _ = w.write_all(b"\r\nDeleting session...\r\n").await;
                        if let Err(e) = control.destroy().await {
                            tracing::warn!(error = %e, "session delete failed");
                            let _ = w
                                .write_all(format!("Failed to delete session: {e}\r\n").as_bytes())
                                .await;
                        }
                    }
                    // No manager wired (test harness): degrade to a detach.
                    None => tracing::warn!("delete selected but no session control available"),
                },
                Ok(Selection::At(_)) => unreachable!(),
                Err(e) => tracing::warn!(error = %e, "session-exit prompt failed"),
            }
        }

        let _ = ws.eof().await;
        let _ = ws.exit_status(0).await;
        let _ = ws.close().await; // needed to release the remote
    }
}

/// A handle to a launched session process.
///
/// Abstracts the process the [`Host`] supervises so its runtime loop can be
/// driven against a real sandboxed process or a test double. The unused
/// `hakoniwa::ExitStatus` payload is reduced to a portable exit code.
pub(crate) trait SessionProcess: Send + 'static {
    /// Returns `Some(code)` if the process has exited, `None` if still running.
    fn try_wait(&mut self) -> io::Result<Option<i32>>;
    /// Blocks until the process exits, returning its exit code.
    fn wait(&mut self) -> io::Result<i32>;
    /// Sends a kill signal to the process.
    fn kill(&mut self) -> io::Result<()>;
}

/// Opens a PTY of the requested size, launches the session process
/// wired to the slave side, and yields the master side plus a
/// handle to the process. The seam between the generic [`Host`]
/// runtime and the process-creation backend.
pub(crate) trait SessionLauncher {
    /// The running-process handle this launcher produces.
    type Process: SessionProcess;
    /// A value held for the session's lifetime purely for its `Drop` (e.g. the
    /// sandbox files backing the running process's rootfs). Dropped after
    /// [`Self::Process`].
    type Guard: Send + 'static;

    fn launch(
        self,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
    ) -> impl Future<Output = io::Result<Launched<Self::Process, Self::Guard>>> + Send;
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
    /// `None` for `HostNet`/`NoNet` and for the mock launcher.
    net_guard: Option<Box<dyn sandbox2::NetGuard>>,
}

/// Actor messages to a [`Host`].
enum Message {
    Kill,
    Attach(Channel<Msg>, WinSize),
    GetAttrs(oneshot::Sender<HostAttrs>),

    SetTitleCallback(String),
    VisualBellCallback,
    AudibleBellCallback,
}

/// Handles callback events from the terminal parser, transmitting them to the host.
struct ParserEventHandler(WeakHostHandle);

impl vt100_ctt::Callbacks for ParserEventHandler {
    fn set_window_title(&mut self, _: &mut vt100_ctt::Screen, title: &[u8]) {
        self.0.set_title_cb(title);
    }
    fn audible_bell(&mut self, _: &mut vt100_ctt::Screen) {
        self.0.audible_bell_cb();
    }
    fn visual_bell(&mut self, _: &mut vt100_ctt::Screen) {
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

/// The handle to the session host - the running process.
#[derive(Debug, Clone)]
pub struct HostHandle {
    sender: mpsc::Sender<Message>,
}

impl HostHandle {
    fn make_weak(&self) -> WeakHostHandle {
        WeakHostHandle {
            sender: self.sender.downgrade(),
        }
    }

    pub async fn kill(&self) -> Result<(), ()> {
        match self.sender.send(Message::Kill).await {
            Ok(()) => Ok(()),
            Err(_e) => Err(()), // closed
        }
    }
    pub async fn attach(
        &self,
        c: Channel<Msg>,
        sz: WinSize,
    ) -> Result<(), (Channel<Msg>, WinSize)> {
        match self.sender.send(Message::Attach(c, sz)).await {
            Ok(()) => Ok(()),
            Err(SendError(Message::Attach(c, sz))) => Err((c, sz)),
            Err(e) => unreachable!("{:?}", e),
        }
    }

    /// Returns the terminal attributes.
    pub async fn get_attrs(&self) -> Result<HostAttrs, ()> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        match self.sender.send(Message::GetAttrs(send)).await {
            Ok(()) => Ok(recv.await.expect("host died")),
            Err(SendError(Message::GetAttrs(_))) => Err(()),
            Err(e) => unreachable!("{:?}", e),
        }
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
}

/// The state of the session process.
///
/// Generic over the [`SessionProcess`] it supervises and the [`SessionLauncher`]
/// guard kept alive for the session, so the runtime loop can be driven against a
/// real sandboxed process or a test double.
pub(crate) struct Host<P: SessionProcess, G: Send + 'static> {
    /// Channel for actor messages via [`HostHandle`].
    receiver: mpsc::Receiver<Message>,

    /// The async task and its channel that wires the session
    /// to the ssh channel, if currently attached.
    remote: Option<(mpsc::Sender<BindingMsg>, JoinHandle<()>)>,

    /// The last-set pty terminal size.
    sz: WinSize,
    /// In-memory representation of the terminal state.
    parser: vt100_ctt::Parser<ParserEventHandler>,
    /// The session process.
    process: P,
    /// The master-side fd of the Pty.
    master: AsyncFd<std::fs::File>,
    /// Various attributes about the running terminal.
    attrs: HostAttrs,

    // Writer for bytes coming from the remote - i.e. 'stdin' keystrokes
    // that need to get written to the pty. Clones of this sender are
    // given to [`Binding::spawn`].
    remote_tx: mpsc::Sender<Either<bytes::Bytes, RequestedPty>>,
    // Recieve-end for bytes coming from the remote - i.e. 'stdin' keystrokes.
    // We process this end.
    remote_rx: mpsc::Receiver<Either<bytes::Bytes, RequestedPty>>,

    // Temporary buffer for reading from the pty master (i.e. 'stdout').
    stdout_buf: Vec<u8>,
    // Bytes that need to be written to the pty master (i.e. 'stdin').
    //
    // (<buffer>, <number of bytes from buffer already written>)
    stdin_buf: Option<(bytes::Bytes, usize)>,

    // The per-sandbox network attachment (own-IP switch wiring), if any. Torn
    // down explicitly in `mainloop` when the session ends, before `_guard` (and
    // thus the sandbox files) is dropped. `None` for `HostNet`/`NoNet` and tests.
    net_guard: Option<Box<dyn sandbox2::NetGuard>>,

    // Destroy capability handed to each binding this host spawns, so a
    // shell-exit "delete" can tear the whole session down. `None` for hosts
    // built without a manager (the test harness).
    control: Option<SessionControl>,

    // Keeps launcher-owned resources (the session's `Env`, which owns the
    // sandbox files backing the running process's rootfs along with the context
    // and graph) alive for as long as this host (and thus the session process)
    // lives. Declared last so it is dropped after `process`: the process is torn
    // down before the sandbox files backing its rootfs are removed. Never read;
    // held purely for its `Drop`.
    _guard: G,
}

/// A launched session process backed by a sandboxed [`hakoniwa::Child`].
#[cfg(not(test))]
pub(crate) struct SandboxProcess(hakoniwa::Child);

#[cfg(not(test))]
impl SessionProcess for SandboxProcess {
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        self.0
            .try_wait()
            .map(|status| {
                status.map(|s| {
                    if s.code != 0 {
                        tracing::warn!(
                            code = s.code,
                            exit_code = ?s.exit_code,
                            reason = %s.reason,
                            "DIAG hakoniwa container/process exited non-zero"
                        );
                    }
                    s.code
                })
            })
            .map_err(|e| io::Error::other(format!("wait failed: {e}")))
    }

    fn wait(&mut self) -> io::Result<i32> {
        self.0
            .wait()
            .map(|s| {
                if s.code != 0 {
                    tracing::warn!(
                        code = s.code,
                        exit_code = ?s.exit_code,
                        reason = %s.reason,
                        "DIAG hakoniwa container/process exited non-zero"
                    );
                }
                s.code
            })
            .map_err(|e| io::Error::other(format!("wait failed: {e}")))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.0
            .kill()
            .map_err(|e| io::Error::other(format!("kill failed: {e}")))
    }
}

/// Packages every session sandbox gets unconditionally, regardless of
/// the client's contribution: `base` for the shell, `coreutils` for
/// `ls`/`cat`/etc, and `socat` for the `min` command bridge (the
/// helper installed at `/usr/bin/min` speaks to `/run/minenv_sock`
/// via `socat`).
#[cfg(not(test))]
const BASELINE_PACKAGES: &[&str] = &["base", "coreutils", "socat"];

/// Env vars every session sandbox gets unconditionally, regardless of
/// the client's contribution. `PS1` is here so the shell prompt is
/// styled the same whether a composition sets it or not.
#[cfg(not(test))]
const BASELINE_VARS: &[(&str, &str)] = &[(
    "PS1",
    r"\[\033[01;32m\]\u@\h\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ ",
)];

/// The real [`SessionLauncher`]: evaluates a minimal context into a graph,
/// builds a sandboxed `/bin/bash`, and wires it to a freshly opened PTY.
#[cfg(not(test))]
pub(crate) struct SandboxLauncher {
    pub(crate) ctx: mctx::Context,
    pub(crate) network_mode: NetworkMode,
    /// Shared per-host gvproxy switch. Used only for
    /// [`NetworkMode::OwnIp`] launches.
    pub(crate) net_switch: std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>>,
    /// Static ingress port mappings applied on the switch once this
    /// `OwnIp` PTask attaches, removed on exit. `None` for other
    /// network modes.
    pub(crate) ingress: Option<sessions::IngressPolicy>,
    /// Composition to merge into the launcher's baseline packages and
    /// vars. Patches and lifecycle hooks are ignored today.
    pub(crate) composition: Option<std::sync::Arc<sessions::core::compose::Composition>>,
    /// Weak handle back to the owning session actor, for  `min` commands
    /// (e.g. `min build`) to drive session side-ops.
    pub(crate) session: crate::session::WeakSessionHandle,
}

/// Rolls back a native-own-IP phase-1 switch attach if the launch is abandoned
/// before the attach is handed off to an [`OwnIpGuard`].
///
/// Phase 1 (`SwitchClient::attach`) bumps gvproxy's attach count before the slow
/// env build + spawn, so an early `Err` return *or* a dropped/cancelled launch
/// future (e.g. the client disconnects mid-build) would otherwise leak the count
/// and keep gvproxy running. The existing `Err` arms are covered, but `Drop` is
/// what catches cancellation. `SwitchClient::detach` is async and `Drop` cannot
/// await, so an armed drop spawns the detach on the current runtime; on the
/// success path the guard is disarmed and `OwnIpGuard` owns teardown instead.
#[cfg(not(test))]
struct PhaseOneAttachGuard {
    switch: std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>>,
    armed: bool,
}

#[cfg(not(test))]
impl PhaseOneAttachGuard {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

#[cfg(not(test))]
impl Drop for PhaseOneAttachGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let switch = std::sync::Arc::clone(&self.switch);
        // Detach off the current runtime — `Drop` cannot `.await`. If no runtime
        // is running (the daemon is shutting down) the refcount no longer matters,
        // so a failed spawn is harmless.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(async move {
                if let Err(e) = switch.lock().await.detach().await {
                    tracing::warn!(error = %e, "detaching OwnIp PTask after launch was abandoned");
                }
            });
        }
    }
}

#[cfg(not(test))]
impl SessionLauncher for SandboxLauncher {
    type Process = SandboxProcess;
    // The session env, kept alive for the session's lifetime (it owns the
    // sandbox files backing the running process's rootfs). The own-IP switch
    // attachment, when present, travels separately as `Launched::net_guard` and
    // is torn down explicitly at session end.
    type Guard = crate::env::Env;

    async fn launch(
        self,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
    ) -> io::Result<Launched<SandboxProcess, Self::Guard>> {
        let ctx = self.ctx;
        // Move the ingress policy out of `self` up front so it can be applied
        // after the switch attach below (the rest of `self` is consumed first).
        let ingress = self.ingress;
        let network_mode = self.network_mode;
        let net_switch = self.net_switch;
        // The session name, registered as this PTask's `*.min.internal` hostname on
        // an own-IP attach (finding #3 / UC6); cloned because `name` is consumed by
        // the sandbox env below.
        let session_name = name.clone();
        let composition = self.composition;
        let session = self.session;
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

        // Phase 1 (pre-spawn): for own-IP, snapshot the switch's DNS server from
        // its live subnet (needed by *every* own-IP sandbox — both transports).
        // A native (DM2/`LocalSpawn`) PTask must additionally allocate its lease
        // and ensure gvproxy is up *now*, because hakoniwa builds the tap (and
        // assigns its address) inside the sandbox namespace before the process is
        // spawned; we snapshot the lease IP + control socket for the post-spawn
        // relay and the tap params for the sandbox to configure. DM1/3/4
        // (`HostShuttle`, root-in-VM) keep the post-spawn open-tap-then-move-into-
        // netns path and allocate their lease there, so `own_ip_tap`/
        // `local_own_ip` stay `None` — but `own_ip_dns` is still set for them.
        let mut local_own_ip: Option<(std::net::Ipv4Addr, std::path::PathBuf)> = None;
        let mut own_ip_tap: Option<sandbox2::config::OwnIpTap> = None;
        let mut own_ip_dns: Option<std::net::Ipv4Addr> = None;
        if matches!(network_mode, NetworkMode::OwnIp) {
            let mut s = net_switch.lock().await;
            let subnet = s.subnet();
            own_ip_dns = Some(subnet.dns_server());
            if matches!(s.transport(), crate::net::SwitchTransport::LocalSpawn) {
                let attach = s.attach().await.map_err(|e| {
                    io::Error::other(format!("attaching OwnIp PTask to switch: {e}"))
                })?;
                let sock = s.control_socket();
                let prefix = subnet.prefix();
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                own_ip_tap = Some(sandbox2::config::OwnIpTap {
                    address: attach.lease.ip,
                    netmask: std::net::Ipv4Addr::from(mask),
                    gateway: subnet.gateway(),
                    mtu: crate::net::DEFAULT_MTU,
                });
                local_own_ip = Some((attach.lease.ip, sock));
            }
        }

        // Guard the phase-1 attach for the whole window until it is handed to an
        // `OwnIpGuard`: an early `Err` return *or* a cancelled launch future now
        // rolls the gvproxy attach count back (see `PhaseOneAttachGuard`). Armed
        // only on the LocalSpawn path that did a pre-spawn attach; disarmed on the
        // success handoff below.
        let mut attach_guard = local_own_ip.as_ref().map(|_| PhaseOneAttachGuard {
            switch: std::sync::Arc::clone(&net_switch),
            armed: true,
        });

        // Package + env-var union of the launcher baseline and every
        // contribution the composer collected. Packages: baseline set
        // (required for a usable interactive shell) unioned with
        // everything the composition asks for, dedup-preserving-order
        // so the base packages install first. Env vars: baseline
        // `PS1` first, composition vars overwrite on the same key.
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
        let mut env_vars: HashMap<String, String> = BASELINE_VARS
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        if let Some(comp) = &composition {
            for p in comp.packages() {
                let name = p.package();
                if package_set.insert(name.to_string()) {
                    packages.push(name.to_string());
                }
            }
            for v in comp.vars() {
                let var = v.var();
                env_vars.insert(var.name().to_string(), var.value().to_string());
            }
        }
        // Log every item that will (or would) end up in the session,
        // tagged with its provenance. Patches and lifecycle hooks are
        // included even though the launcher can't act on them yet —
        // an operator inspecting logs should see the intent.
        let baseline_var_names: Vec<&str> = BASELINE_VARS.iter().map(|(k, _)| *k).collect();
        log_session_contents(
            &name,
            BASELINE_PACKAGES,
            &baseline_var_names,
            composition.as_deref(),
        );

        // Build the env + container and spawn the process. Any failure here (env
        // build, container build, spawn) leaves no process to reap; the phase-1
        // attach, if any, is rolled back by `attach_guard` on the `Err` return.
        let build_and_spawn = async {
            // The env owns the context, graph and the sandbox files backing the
            // running process's rootfs, so it is `Send + 'static` and can be moved
            // into the host as the guard that keeps those files alive.
            let mut env = crate::env::Env::build(
                ctx,
                graph,
                crate::env::EnvArgs::new(name, paths.working, paths.home, paths.cache, session)
                    .with_packages(packages)
                    .with_resolved_env_vars(env_vars)
                    // Session envs source package attrs (env_state_wiring,
                    // env_dir/file_mappings) exclusively through the
                    // composer so they're subject to user policy. Task-run
                    // uses a different `Env::build` (mctx::env::Env) and
                    // keeps the legacy un-gated wiring for now.
                    .without_package_attr_wiring()
                    .with_network_mode(network_mode)
                    .with_own_ip_tap(own_ip_tap)
                    .with_own_ip_dns(own_ip_dns)
                    .with_username(username),
            )
            .await?;

            let mut container = env
                .container()
                .map_err(|e| io::Error::other(format!("container build: {e}")))?;
            container.set_session_leader();

            let pty = Pty::open(sz).map_err(|e| io::Error::other(format!("pty open: {e}")))?;
            // The `bash` package installs to `/usr/bin/bash` (--prefix=/usr) and
            // the generic rootfs has no `/bin/bash`, so exec the absolute path
            // that exists rather than `/bin/bash` (which fails with ENOENT).
            let mut command = env
                .command(&container, "/usr/bin/bash", ["--noprofile", "-l"])
                .map_err(|e| io::Error::other(format!("build command: {e}")))?;
            command.stdin(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
            command.stdout(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
            let (master, slave) = pty.into_fds();
            command.stderr(hakoniwa::Stdio::from(slave));

            let process = command
                .spawn()
                .map_err(|e| io::Error::other(format!("exec failed: {e}")))?;
            // `command`/`container` no longer borrow `env`, so it can be moved
            // into the host to keep its backing files alive.
            drop(container);
            Ok::<_, io::Error>((env, master, process))
        }
        .await;

        let (env, master, mut process) = match build_and_spawn {
            // `attach_guard` (if armed) rolls the phase-1 attach back on this
            // `Err` return when it drops.
            Ok(parts) => parts,
            Err(e) => return Err(e),
        };

        // Reap a sandbox process whose own-IP attach failed. A `hakoniwa::Child`
        // does not terminate when dropped — it would orphan the sandbox process —
        // so kill and reap it explicitly. `kill` and `wait` are independent: when
        // `kill` fails with `ESRCH` because the process already exited during the
        // attach window, the child still needs reaping, so `wait` runs regardless.
        let reap = |process: &mut hakoniwa::Child| {
            if let Err(kill_err) = process.kill() {
                tracing::warn!(error = %kill_err, "killing sandbox process after OwnIp attach failure");
            }
            if let Err(wait_err) = process.wait() {
                tracing::warn!(error = %wait_err, "reaping sandbox process after OwnIp attach failure");
            }
        };

        // Phase 2 (post-spawn): wire the freshly-unshared netns onto the switch.
        // Native (DM2): hakoniwa already built + configured the tap in-namespace
        // (rootless), so we only relay its fd. DM1/3/4: the post-spawn open-tap +
        // move-into-netns + vsock relay behind the `GvproxyNetwork` abstraction.
        //
        // Until this returns, an own-IP PTask's egress isn't up yet, but a shell
        // PTask never probes the network in this window (the SSH layer dispatches
        // commands only after `Launched` is returned).
        let net_guard: Option<Box<dyn sandbox2::NetGuard>> =
            if let Some((lease_ip, sock)) = local_own_ip {
                // hakoniwa hands us ownership of the tap fd (its `Child` has no
                // `Drop`, so it never closes it); a missing fd means the in-VM
                // RustSlirp setup did not run — `attach_guard` rolls the phase-1
                // attach back on the `Err` return.
                let Some(raw) = process.rustslirp_tapfd else {
                    reap(&mut process);
                    return Err(io::Error::other(
                        "own-IP sandbox produced no in-namespace tap fd",
                    ));
                };
                // SAFETY: `raw` is a live, owned tap fd handed out exactly once by
                // hakoniwa; wrapping it transfers ownership to the relay, which
                // closes it on teardown.
                let tap_fd = unsafe { OwnedFd::from_raw_fd(raw) };
                match crate::net::gvproxy_network::complete_local_own_ip_attach(
                    &net_switch,
                    tap_fd,
                    sock,
                    lease_ip,
                    &session_name,
                    ingress.as_ref(),
                )
                .await
                {
                    Ok(guard) => {
                        // Ownership of the attach now lives in `OwnIpGuard`, which
                        // detaches at session end — disarm so the guard doesn't
                        // also roll it back.
                        if let Some(g) = attach_guard.as_mut() {
                            g.disarm();
                        }
                        Some(Box::new(guard) as Box<dyn sandbox2::NetGuard>)
                    }
                    // `complete_local_own_ip_attach` leaves rollback to
                    // `attach_guard` (this `Err` return), so only reap the process.
                    Err(e) => {
                        reap(&mut process);
                        return Err(io::Error::other(e));
                    }
                }
            } else if matches!(network_mode, NetworkMode::OwnIp) {
                let network = crate::net::gvproxy_network::GvproxyNetwork::new(
                    std::sync::Arc::clone(&net_switch),
                    session_name,
                    ingress,
                );
                match network.attach(process.id()).await {
                    Ok(guard) => Some(guard),
                    Err(e) => {
                        reap(&mut process);
                        return Err(io::Error::other(e));
                    }
                }
            } else {
                None
            };

        Ok(Launched {
            master,
            process: SandboxProcess(process),
            guard: env,
            net_guard,
        })
    }
}

/// A launched session process backed by a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) struct MockProcess(std::process::Child);

#[cfg(test)]
impl SessionProcess for MockProcess {
    fn try_wait(&mut self) -> io::Result<Option<i32>> {
        Ok(self.0.try_wait()?.map(|s| s.code().unwrap_or(-1)))
    }

    fn wait(&mut self) -> io::Result<i32> {
        Ok(self.0.wait()?.code().unwrap_or(-1))
    }

    fn kill(&mut self) -> io::Result<()> {
        self.0.kill()
    }
}

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
pub(crate) struct MockLauncher;

#[cfg(test)]
impl SessionLauncher for MockLauncher {
    type Process = MockProcess;
    type Guard = ();

    async fn launch(
        self,
        _name: String,
        _username: String,
        _paths: SessionPaths,
        sz: WinSize,
    ) -> io::Result<Launched<MockProcess, ()>> {
        let pty = Pty::open(sz)?;

        let script = format!(
            r#"while read line; do [ "$line" = {MOCK_EXIT_LINE} ] && exit 0; printf 'got:%s\n' "$line"; done"#
        );
        let mut command = std::process::Command::new("/bin/sh");
        command.arg("-c").arg(&script);
        command.stdin(std::process::Stdio::from(pty.dup_slave_fd()?));
        command.stdout(std::process::Stdio::from(pty.dup_slave_fd()?));
        let (master, slave) = pty.into_fds();
        command.stderr(std::process::Stdio::from(slave));

        let process = command.spawn()?;

        Ok(Launched {
            master,
            process: MockProcess(process),
            guard: (),
            net_guard: None,
        })
    }
}

impl<P: SessionProcess, G: Send + 'static> Host<P, G> {
    /// Spawns a session host from the given launcher, wiring it to `channel` if
    /// one is supplied, and drives its runtime loop on a background task.
    ///
    /// Returns the [`HostHandle`] alongside the [`JoinHandle`] of the runtime
    /// loop, so the owner can await full teardown (process reaped, sandbox guard
    /// dropped) after issuing a [`HostHandle::kill`].
    pub async fn spawn<L>(
        launcher: L,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
        channel: Option<Channel<Msg>>,
        control: Option<SessionControl>,
    ) -> Result<(HostHandle, JoinHandle<Result<i32, std::io::Error>>), std::io::Error>
    where
        L: SessionLauncher<Process = P, Guard = G>,
    {
        let (host, handle) =
            Self::build(launcher, name, username, paths, sz, channel, control).await?;
        let task = tokio::spawn(host.mainloop());
        Ok((handle, task))
    }

    /// Builds the host and its handle from a launcher without spawning the
    /// runtime loop, so callers (notably tests) can drive [`Self::step`]
    /// directly and observe the host's state.
    async fn build<L>(
        launcher: L,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
        channel: Option<Channel<Msg>>,
        control: Option<SessionControl>,
    ) -> Result<(Self, HostHandle), std::io::Error>
    where
        L: SessionLauncher<Process = P, Guard = G>,
    {
        let Launched {
            master,
            process,
            guard,
            net_guard,
        } = launcher.launch(name, username, paths, sz).await?;

        let (sender, receiver) = mpsc::channel(8);
        let handle = HostHandle { sender };

        let parser = vt100_ctt::Parser::new_with_callbacks(
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
            sz,
            parser,
            process,
            master,
            attrs: HostAttrs::default(),

            remote_tx,
            remote_rx,
            stdout_buf: vec![0u8; 8 * 1024],
            stdin_buf: None,
            net_guard,
            control,
            _guard: guard,
        };

        if let Some(channel) = channel {
            host.attach(channel, sz, true).await;
        }

        Ok((host, handle))
    }

    pub async fn mainloop(mut self) -> Result<i32, std::io::Error> {
        let result = loop {
            match self.process.try_wait() {
                Ok(Some(exit_code)) => {
                    // `try_wait` already warns on a non-zero exit with the richer
                    // hakoniwa diagnostics; keep this routine and unconditional.
                    tracing::debug!(exit_code, "session process exited");
                    // The process was reaped here before the pty surfaced its
                    // death as an `EIO`. Still notify the attached binding so the
                    // shell-exit prompt renders (and a "delete" choice can tear
                    // the session down); otherwise the binding only observes the
                    // host drop and silently detaches. Without this the prompt is
                    // lost whenever `try_wait` wins the race against the master's
                    // `EIO` — a flaky detach under CPU load.
                    self.notify_remote_process_exit();
                    break Ok(exit_code);
                }
                Ok(None) => {}
                Err(e) => break Err(e),
            }

            if self.step().await.is_err() {
                let code = self.process.wait();
                tracing::warn!(?code, "session process reaped after pty/step error");
                break code;
            }
        };

        // Tear down the per-sandbox network attachment explicitly (own-IP switch
        // detach + ingress removal) on this live runtime, before `_guard` drops
        // the sandbox files. No-op for `HostNet`/`NoNet` and the mock launcher.
        if let Some(net_guard) = self.net_guard.take() {
            net_guard.teardown().await;
        }

        result
    }

    /// Notifies the attached binding (if any) that the pty master has errored,
    /// so it can tear the ssh channel down.
    ///
    /// Used on any pty read/write failure — in practice the process dying closes
    /// every slave fd, so the master reports `EIO`; this is the signal to unwind
    /// the host. The binding suppresses the (expected) `EIO` text on its end.
    ///
    /// The notice is sent best-effort with `try_send`, never awaited: the
    /// binding drains this queue in the same `select!` as its (potentially
    /// blocking) write to the ssh remote, so awaiting a full queue could wedge
    /// teardown behind a stuck remote. If the queue is full the notice is
    /// dropped — the host returns regardless, and dropping its sender closes the
    /// binding on its next turn.
    async fn notify_remote_pty_err(&mut self, e: std::io::Error) {
        tracing::warn!(error = %e, "pty master error; tearing down host");
        if let Some((tx, _hnd)) = self.remote.as_mut() {
            let _ = tx.try_send(BindingMsg::TeardownDueToProcessExit(Some(e)));
        }
    }

    /// Notifies the attached binding that the session process has been reaped,
    /// so it tears down and raises the shell-exit prompt. Unlike
    /// [`Self::notify_remote_pty_err`] there is no error to surface — the process
    /// simply exited, and the pty may never report the death (the reap can win
    /// the race against the master's `EIO`).
    ///
    /// Best-effort `try_send` for the same reason as `notify_remote_pty_err`: the
    /// notice is never awaited, so a full queue can't wedge teardown. The message
    /// stays buffered even as this host drops, and an mpsc receiver drains its
    /// buffer before observing the closed sender — so the binding sees the exit
    /// before it would fall through to `HostGone`.
    fn notify_remote_process_exit(&mut self) {
        if let Some((tx, _hnd)) = self.remote.as_mut() {
            let _ = tx.try_send(BindingMsg::TeardownDueToProcessExit(None));
        }
    }

    pub async fn step(&mut self) -> Result<(), ()> {
        tokio::select! {
            // Read actor messages.
            Some(msg) = self.receiver.recv() => {
                match msg {
                    Message::Kill => {
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
                    Message::Attach(channel, sz) => {
                        self.attach(channel, sz, false).await;
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
                }
            },
            // Read from master - stdout of session process => ssh channel (if any)
            r = self.master.readable() => {
                let mut guard = match r {
                    Ok(g) => g,
                    Err(e) => {
                        // The io reactor failed to report readiness; the master
                        // is unusable, so unwind rather than panic.
                        self.notify_remote_pty_err(e).await;
                        return Err(());
                    }
                };
                match guard.try_io(|fd| fd.get_ref().read(&mut self.stdout_buf)) {
                    Ok(Ok(0)) => {},
                    Ok(Ok(n)) => {
                        let b = &self.stdout_buf[..n];
                        self.attrs.stdout_last = Some(SystemTime::now());
                        self.parser.process(b);
                        if let Some((tx, _hnd)) = self.remote.as_mut() {
                            match tx.send(BindingMsg::Stdin(b.to_vec())).await {
                                Ok(()) => {},
                                Err(e) => {
                                    tracing::warn!("failed stdout=>remote send: {e}");
                                    self.remote = None;
                                }
                            };
                        }
                    }
                    Ok(Err(e)) => {
                        self.notify_remote_pty_err(e).await;
                        return Err(());
                    },
                    Err(_would_block) => {},
                }
            },
            // Read from remote (ssh channel) - these keystrokes need writing to the pty.
            //
            // To ensure we never block service of reads from the master side of the pty ('stdout'),
            // we only consume new keystrokes if we have none waiting to be written to the pty, and
            // pending writes to the pty are serviced async by their own select arm (below).
            Some(msg) = self.remote_rx.recv(), if self.stdin_buf.is_none() => {
                match msg {
                    Either::Left(b) => {
                        self.attrs.stdin_last = Some(SystemTime::now());

                        // ctrl-w
                        let is_detach = b.len() == 1 && b[0] == 0x17 ||
                            b == CTRL_W_CSI_U ||
                            b == CTRL_W_CSI_27;

                        if is_detach {
                            let uc = self.unwind_codes();
                            if let Some((tx, _hnd)) = self.remote.as_mut() {
                                match tx.send(BindingMsg::TeardownDueToDetach(uc)).await {
                                    Ok(()) => {},
                                    Err(e) => {
                                        tracing::warn!("failed sending detach signal to remote: {e}");
                                    }
                                };
                                self.remote = None;
                            }
                        } else {
                            self.stdin_buf = Some((b, 0));
                        };
                    }
                    Either::Right(sz) => {
                        self.set_size(WinSize::from(&sz));
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
                        self.notify_remote_pty_err(e).await;
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
                        self.notify_remote_pty_err(e).await;
                        return Err(());
                    }
                    Err(_would_block) => {},
                }
            }

        }

        Ok(())
    }

    async fn attach(&mut self, channel: Channel<Msg>, sz: WinSize, skip_flush: bool) {
        if !skip_flush {
            self.parser.screen_mut().set_size(sz.rows, sz.cols);
            let _ = channel
                .make_writer()
                .write_all(&self.parser.screen().state_formatted())
                .await;
        }
        let new_binding =
            Binding::spawn(channel, self.remote_tx.clone(), self.control.clone()).await;

        if let Some((old_tx, old_join_hnd)) = self.remote.replace(new_binding) {
            // If there was a binding we just swapped out, tell it to
            // shut down and wait for it to finish.
            let _ = old_tx
                .send(BindingMsg::TeardownDueToSuperceded(self.unwind_codes()))
                .await;
            let _ = old_join_hnd.await;
        }

        self.set_size(sz);
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
    fn unwind_codes(&self) -> Vec<u8> {
        let live = self.parser.screen();
        let clean = vt100_ctt::Parser::new(live.size().0, live.size().1, 0)
            .screen()
            .clone();

        // app keypad/cursor, paste, mouse
        let mut out = clean.input_mode_diff(live);
        // disable alternate screen
        if live.alternate_screen() {
            out.extend_from_slice(b"\x1b[?1049l");
        }
        // disable hidden cursor
        if live.hide_cursor() {
            out.extend_from_slice(b"\x1b[?25h");
        }

        // blind: reset text colors etc ('SGR')
        out.extend_from_slice(b"\x1b[m");
        // blind: disable focus reporting
        out.extend_from_slice(b"\x1b[?1004l");
        out
    }
}

/// Puts a file descriptor into non-blocking mode.
fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is a valid open file descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Marks a file descriptor close-on-exec (`FD_CLOEXEC`).
fn set_cloexec(fd: RawFd) -> io::Result<()> {
    // SAFETY: fd is a valid open file descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let ret = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use paths::DaemonAbsPath;

    use super::*;
    use std::time::Duration;

    const DEFAULT_SIZE: WinSize = WinSize {
        rows: 24,
        cols: 80,
        xpixel: 0,
        ypixel: 0,
    };

    #[test]
    fn open_and_get_fds() {
        let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
        assert!(pty.master_fd() >= 0);
        assert!(pty.slave_fd() >= 0);
        assert_ne!(pty.master_fd(), pty.slave_fd());
    }

    #[test]
    fn open_sets_initial_size() {
        let size = WinSize {
            rows: 40,
            cols: 120,
            xpixel: 0,
            ypixel: 0,
        };
        let pty = Pty::open(size).expect("failed to open pty");

        let got = pty.get_size().expect("failed to get size");
        assert_eq!(got.rows, 40);
        assert_eq!(got.cols, 120);
    }

    #[test]
    fn dup_fd_produces_independent_fd() {
        let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
        let (master, _slave) = pty.into_fds();
        let duped = dup_fd(&master).expect("failed to dup fd");
        assert!(duped.as_raw_fd() >= 0);
        assert_ne!(master.as_raw_fd(), duped.as_raw_fd());
    }

    #[test]
    fn win_size_from_requested_pty_clamps_oversized() {
        let requested = RequestedPty {
            char_sizes: (u32::MAX, u32::MAX),
            pixel_sizes: (0, 0),
            term: String::new(),
            modes: Vec::new(),
        };
        let size = WinSize::from(&requested);
        assert_eq!(size.cols, u16::MAX);
        assert_eq!(size.rows, u16::MAX);
    }

    #[test]
    fn set_and_get_size() {
        let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");

        let size = WinSize {
            rows: 50,
            cols: 200,
            xpixel: 0,
            ypixel: 0,
        };
        pty.set_size(size).expect("failed to set size");

        let got = pty.get_size().expect("failed to get size");
        assert_eq!(got.rows, 50);
        assert_eq!(got.cols, 200);
    }

    /// Drives a host backed by the mock echo program and confirms the terminal
    /// attributes are tracked and surfaced via [`HostHandle::get_attrs`]:
    /// feeding stdin an OSC "set window title" escape makes the mock echo it
    /// back onto the terminal, where the parser records the title; the round
    /// trip also stamps the stdin/stdout activity times.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn get_attrs_tracks_title_and_io_times() {
        // Build the host directly (no SSH binding) so the test can feed stdin
        // through a clone of the host's own remote sender, then drive its
        // runtime loop on a background task.
        let (host, handle) = Host::build(
            MockLauncher,
            "test-session".to_string(),
            "user".to_string(),
            SessionPaths {
                working: DaemonAbsPath::root(),
                cache: DaemonAbsPath::root(),
                home: DaemonAbsPath::root(),
                patches: DaemonAbsPath::root(),
            },
            DEFAULT_SIZE,
            None,
            None,
        )
        .await
        .expect("failed to build host");
        let stdin = host.remote_tx.clone();
        tokio::spawn(host.mainloop());

        // OSC "set window title" (ESC ] 0 ; <title> BEL), sent as one line. The
        // mock echoes the line back (prefixed with `got:`), so the raw escape
        // reaches the host's terminal parser on stdout and fires the set-title
        // callback. The trailing newline is what makes the mock's `read` return
        // and echo via `printf`, carrying the escape bytes through unmangled.
        let title = "hello-title";
        let osc = format!("\x1b]0;{title}\x07\n");
        stdin
            .send(Either::Left(bytes::Bytes::from(osc.into_bytes())))
            .await
            .expect("failed to send stdin");

        // Poll until the title has been recorded (or time out).
        let attrs = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let attrs = handle.get_attrs().await.unwrap();
                if attrs.title.is_some() {
                    break attrs;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("timed out waiting for the terminal title to be recorded");

        let (got_title, _when) = attrs.title.expect("title should be set");
        assert_eq!(
            got_title, title,
            "the parsed title should match what was set"
        );

        // The stdin write and the echoed stdout should both have stamped their
        // last-activity times.
        assert!(
            attrs.stdin_last.is_some(),
            "stdin_last should be stamped after feeding stdin",
        );
        assert!(
            attrs.stdout_last.is_some(),
            "stdout_last should be stamped after the echo arrived",
        );
    }

    /// Killing a host tears it down cleanly: the runtime loop observes the
    /// process die (its slave fds close, so the master reports `EIO`), reaps it,
    /// and returns — the task terminates without panicking or leaking a zombie.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn kill_tears_down_host_and_reaps_process() {
        let (host, handle) = Host::build(
            MockLauncher,
            "test-session".to_string(),
            "user".to_string(),
            SessionPaths {
                working: DaemonAbsPath::root(),
                cache: DaemonAbsPath::root(),
                home: DaemonAbsPath::root(),
                patches: DaemonAbsPath::root(),
            },
            DEFAULT_SIZE,
            None,
            None,
        )
        .await
        .expect("failed to build host");
        let task = tokio::spawn(host.mainloop());

        handle.kill().await.expect("kill should reach the host");

        // The mainloop must terminate (task resolves) without panicking. A
        // `JoinError` here would mean the host task panicked during teardown.
        let outcome = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("host mainloop should terminate after kill")
            .expect("host task should not panic during teardown");
        assert!(
            outcome.is_ok(),
            "mainloop should return the reaped exit status, got: {outcome:?}",
        );
    }

    /// A [`sandbox2::NetGuard`] that records whether its teardown ran, so a test
    /// can assert the session's network is released exactly when the shell
    /// process ends — and left up while it is merely detached.
    struct RecordingNetGuard {
        torn_down: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl sandbox2::NetGuard for RecordingNetGuard {
        fn teardown(
            self: Box<Self>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
            self.torn_down
                .store(true, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async {})
        }
    }

    /// Like [`MockLauncher`], but attaches a [`RecordingNetGuard`] so a test can
    /// observe network teardown. The shared `torn_down` flag lets the test assert
    /// when the network is released relative to detach vs. exit.
    struct MockLauncherWithNet {
        torn_down: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl SessionLauncher for MockLauncherWithNet {
        type Process = MockProcess;
        type Guard = ();

        async fn launch(
            self,
            _name: String,
            _username: String,
            _paths: SessionPaths,
            sz: WinSize,
        ) -> std::io::Result<Launched<MockProcess, ()>> {
            let pty = Pty::open(sz)?;
            let script = format!(
                r#"while read line; do [ "$line" = {MOCK_EXIT_LINE} ] && exit 0; printf 'got:%s\n' "$line"; done"#
            );
            let mut command = std::process::Command::new("/bin/sh");
            command.arg("-c").arg(&script);
            command.stdin(std::process::Stdio::from(pty.dup_slave_fd()?));
            command.stdout(std::process::Stdio::from(pty.dup_slave_fd()?));
            let (master, slave) = pty.into_fds();
            command.stderr(std::process::Stdio::from(slave));
            let process = command.spawn()?;
            Ok(Launched {
                master,
                process: MockProcess(process),
                guard: (),
                net_guard: Some(Box::new(RecordingNetGuard {
                    torn_down: self.torn_down,
                })),
            })
        }
    }

    fn test_paths() -> SessionPaths {
        SessionPaths {
            working: DaemonAbsPath::root(),
            cache: DaemonAbsPath::root(),
            home: DaemonAbsPath::root(),
            patches: DaemonAbsPath::root(),
        }
    }

    /// The load-bearing half of "detach != exit": when the shell process exits,
    /// the session network is torn down. Pins the teardown in `mainloop` so a
    /// refactor cannot silently leave a lease/switch attachment leaked after exit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn exit_releases_the_network() {
        let torn_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (host, _handle) = Host::build(
            MockLauncherWithNet {
                torn_down: torn_down.clone(),
            },
            "test-session".to_string(),
            "user".to_string(),
            test_paths(),
            DEFAULT_SIZE,
            None,
            None,
        )
        .await
        .expect("failed to build host");
        let stdin = host.remote_tx.clone();
        let task = tokio::spawn(host.mainloop());

        // While the shell is alive the network must stay up.
        assert!(
            !torn_down.load(std::sync::atomic::Ordering::SeqCst),
            "network must not be torn down while the shell is running",
        );

        // Make the shell exit; the network must then be released.
        stdin
            .send(Either::Left(bytes::Bytes::from(
                format!("{MOCK_EXIT_LINE}\n").into_bytes(),
            )))
            .await
            .expect("failed to send exit line");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("mainloop should terminate after the shell exits")
            .expect("host task should not panic during teardown")
            .expect("mainloop should return the reaped exit status");
        assert!(
            torn_down.load(std::sync::atomic::Ordering::SeqCst),
            "network must be torn down once the shell exits",
        );
    }

    /// The other half of "detach != exit": a ctrl-w (detach) keystroke is
    /// swallowed as a detach signal — never forwarded to the shell — and does not
    /// end the session or release the network. The shell keeps running (a later
    /// line still round-trips) and only an explicit kill/exit releases the network.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn detach_keystroke_holds_the_session_and_network() {
        let torn_down = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (host, handle) = Host::build(
            MockLauncherWithNet {
                torn_down: torn_down.clone(),
            },
            "test-session".to_string(),
            "user".to_string(),
            test_paths(),
            DEFAULT_SIZE,
            None,
            None,
        )
        .await
        .expect("failed to build host");
        let stdin = host.remote_tx.clone();
        let task = tokio::spawn(host.mainloop());

        // A bare ctrl-w (0x17) is the detach chord. It must be consumed as a
        // detach signal rather than written to the pty.
        stdin
            .send(Either::Left(bytes::Bytes::from(vec![0x17])))
            .await
            .expect("failed to send ctrl-w");

        // The shell survived the detach: a normal line still echoes back, which
        // stamps stdout activity. (If ctrl-w had been forwarded or had killed the
        // process, no echo would ever arrive.)
        stdin
            .send(Either::Left(bytes::Bytes::from(b"ping\n".to_vec())))
            .await
            .expect("failed to send line after detach");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let attrs = handle.get_attrs().await.unwrap();
                if attrs.stdout_last.is_some() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("echo should arrive, proving the shell survived the detach keystroke");
        assert!(
            !torn_down.load(std::sync::atomic::Ordering::SeqCst),
            "detach must not tear down the network while the shell is still running",
        );

        // Only now, on an explicit kill (destroy), is the network released.
        handle.kill().await.expect("kill should reach the host");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("mainloop should terminate after kill")
            .expect("host task should not panic during teardown")
            .expect("mainloop should return the reaped exit status");
        assert!(
            torn_down.load(std::sync::atomic::Ordering::SeqCst),
            "kill/destroy must release the network",
        );
    }
}
