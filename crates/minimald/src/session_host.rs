//! The running state of an active session.
//!
//! The [`Pty`] struct owns a master/slave pseudo-terminal pair created via
//! `openpty(3)`, exposing its file descriptors and window-size controls.
//!
//! The [`Host`] struct holds the running state of an active session.

use async_dialog::Selection;
use russh::Channel;
use russh::server::Msg;
#[cfg(not(test))]
use sandbox2::Network;
use std::collections::BTreeMap;
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
use crate::session_delta::DeltaSource;
use crate::sessions::SessionControl;
#[cfg(not(test))]
use sessions::NetworkMode;
use std::sync::Arc;

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

/// Line rendered above the shell-exit prompt when nothing in the workspace
/// changed since activation. Exposed for the same test-await purpose as
/// [`SHELL_EXIT_PROMPT`].
pub(crate) const SHELL_EXIT_NO_CHANGES: &str = "No files changed since activation.";

/// How many changed-file rows the shell-exit prompt lists before folding the
/// rest into an "and N more" line, keeping the prompt readable on a 24-row
/// terminal.
const DELTA_ROWS_SHOWN: usize = 10;

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
    /// Filesystem path of the slave side (`/dev/pts/N`), captured at
    /// open.
    ///
    /// Exists so a caller that needs the terminal *later* — a lifecycle
    /// hook wanting a real tty for `[ -t 1 ]` and `tput` — can open a
    /// short-lived descriptor and close it again, instead of retaining
    /// a spare slave fd for the session's lifetime. Retaining one is
    /// precisely the leak the `set_cloexec` comment below warns about:
    /// while any slave fd stays open the master never sees EOF, so the
    /// host never observes the shell exiting and the session is never
    /// reaped.
    slave_path: std::path::PathBuf,
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

        // `ptsname_r`, not `ptsname`: the latter returns a pointer to a
        // static buffer, which is not safe to call from a daemon that
        // opens PTYs from more than one task.
        let slave_path = {
            let mut buf = [0 as libc::c_char; 128];
            // SAFETY: `master` is a live PTY master fd; `buf` is a valid
            // writable array of the length passed alongside it.
            let ret = unsafe { libc::ptsname_r(master.as_raw_fd(), buf.as_mut_ptr(), buf.len()) };
            if ret != 0 {
                return Err(io::Error::from_raw_os_error(ret));
            }
            // SAFETY: on success `ptsname_r` wrote a NUL-terminated
            // string into `buf`.
            let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
            std::path::PathBuf::from(
                std::str::from_utf8(cstr.to_bytes())
                    .map_err(|_| io::Error::other("pty slave path is not valid UTF-8"))?,
            )
        };

        Ok(Self {
            master,
            slave,
            slave_path,
        })
    }

    /// Path of the slave side, for opening a short-lived terminal
    /// descriptor after the pair has been wired to a process. See
    /// [`Pty::slave_path`](Self::slave_path) on the struct for why this
    /// is a path rather than a retained descriptor.
    pub fn slave_path(&self) -> &std::path::Path {
        &self.slave_path
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
#[cfg(not(test))]
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
    TeardownDueToDaemonShutdown(Vec<u8>),
}

/// Messages from the binding (user terminal) to the shell process / host.
enum StdinMsg {
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

/// A connection between a [`Host`] and an SSH channel.
///
/// The [`Binding`] is owned by the spawned async task, but the
/// host owns (and communicates via) the [`mpsc::Receiver`] end of
/// `stdin_tx`, and the [`mpsc::Sender`] end of `receiver`.
struct Binding {
    /// The remote end of this binding.
    channel: Channel<Msg>,
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
}

impl Binding {
    /// Spawns a new binding task for a given channel, returning objects
    /// which the owning [`Host`] should own to communicate with it.
    pub(crate) async fn spawn(
        channel: Channel<Msg>,
        stdin_tx: mpsc::Sender<StdinMsg>,
        control: Option<SessionControl>,
        delta: Option<Arc<DeltaSource>>,
        name: String,
        archives_dir: std::path::PathBuf,
    ) -> (mpsc::Sender<BindingMsg>, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(4);

        let binding = Self {
            channel,
            stdin_tx,
            receiver: rx,
            control,
            delta,
            name,
            archives_dir,
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
            Shutdown,
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
                                let _ = self.stdin_tx.send(StdinMsg::Bytes(data)).await;
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
                                let _ = self.stdin_tx.send(StdinMsg::TerminalUpdate(RequestedPty {
                                    char_sizes: (col_width, row_height),
                                    pixel_sizes: (pix_width, pix_height),
                                    term: term.to_string(),
                                    modes: terminal_modes.to_vec(),
                                })).await;
                            },
                            russh::ChannelMsg::WindowChange{
                                col_width,
                                row_height,
                                pix_width,
                                pix_height,
                            } => {
                                let _ = self.stdin_tx.send(StdinMsg::WindowChange{
                                    col_width, row_height, pix_width, pix_height,
                                }).await;
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
                        BindingMsg::TeardownDueToDaemonShutdown(unwind_codes) => {
                            let _ = w.write_all(&unwind_codes).await;
                            let _ = w.write_all(b"\r\nDisconnecting - minimald is shutting down\r\n").await;
                            break MainloopExitReason::Shutdown;
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

        // Whether the session outlives this binding, and so should run its
        // `on_detach` hooks. `HostGone` leaves no session to detach from,
        // and a shell exit resolved as "delete" flows into destruction,
        // which runs its own hooks instead.
        let session_outlives_us = match exit_reason {
            MainloopExitReason::HostGone => false,
            MainloopExitReason::ProcessExited => {
                Self::shell_exit_prompt(
                    self.delta.as_ref(),
                    self.control.as_ref(),
                    &self.archives_dir,
                    &self.name,
                    rs.make_reader(),
                    &mut w,
                )
                .await
                    == ExitDisposition::Kept
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
        };

        // Asked of the session actor rather than run here: a detach hook is
        // not the departing shell's to run — on the shell-exit path that
        // shell is already gone, which is what ended the sandbox — so the
        // actor mints a host for it exactly as activation does. Awaited, so
        // the hooks are not racing this binding's teardown.
        if session_outlives_us && let Some(control) = self.control.as_ref() {
            control.detached().await;
        }

        let _ = ws.eof().await;
        let _ = ws.exit_status(0).await;
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

/// A handle to a launched session process.
///
/// Abstracts the process the [`Host`] supervises so its runtime loop can be
/// driven against a real sandboxed process or a test double. The unused
/// `hakoniwa::ExitStatus` payload is reduced to a portable exit code.
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

    fn launch(
        self,
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

#[cfg(not(test))]
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
    /// `None` for `HostNet`/`NoNet` and for the mock launcher.
    net_guard: Option<Box<dyn sandbox2::NetGuard>>,
    /// Path of the session PTY's slave side, so hooks can open the
    /// terminal briefly rather than the host retaining a descriptor.
    tty_path: std::path::PathBuf,
}

/// Actor messages to a [`Host`].
enum Message {
    Kill(bool),
    Attach(Channel<Msg>, WinSize),
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

    SetTitleCallback(String),
    VisualBellCallback,
    AudibleBellCallback,
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

    pub async fn kill(&self, for_shutdown: bool) -> Result<(), ()> {
        match self.sender.send(Message::Kill(for_shutdown)).await {
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
pub(crate) struct Host<P: SessionProcess, G: SessionGuard> {
    /// Channel for actor messages via [`HostHandle`].
    receiver: mpsc::Receiver<Message>,

    /// The async task and its channel that wires the session
    /// to the ssh channel, if currently attached.
    remote: Option<(mpsc::Sender<BindingMsg>, JoinHandle<()>)>,

    /// The last-set pty terminal size.
    sz: WinSize,
    /// In-memory representation of the terminal state.
    parser: vt100::Parser<ParserEventHandler>,
    /// The session process.
    process: P,
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

    // The session's display name, handed to each binding so the shell-exit
    // prompt's save-then-delete lane can name its archive.
    session_name: String,

    // Daemon-side directory the save-then-delete lane archives into, handed
    // to each binding alongside `delta`.
    archives_dir: std::path::PathBuf,

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

/// A launched session process backed by a sandboxed [`hakoniwa::Child`].
#[cfg(not(test))]
pub(crate) struct SandboxProcess(hakoniwa::Child);

#[cfg(not(test))]
impl SessionProcess for SandboxProcess {
    fn container_pid(&self) -> u32 {
        self.0.id()
    }

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

/// Environment folded into a session shell at the launching attach, over and
/// above the composition. Both halves are captured from the SSH channel that
/// mints the shell (see [`crate::session::Session::attach`]); a re-attach to an
/// already-running shell does not revisit them.
///
/// The two halves sit on opposite sides of the composition in precedence:
/// `inherited` are defaults the composition may override, `connection` are
/// authoritative facts that override the composition.
///
/// The fields are read only by the real [`SandboxLauncher`] (`cfg(not(test))`);
/// the mock launcher ignores them, so tolerate them being unread under `test`.
#[derive(Debug, Default, Clone)]
#[cfg_attr(test, allow(dead_code))]
pub(crate) struct AttachEnv {
    /// Locale/timezone vars the client forwarded from its shell (`LANG`,
    /// `LC_*`, `TZ`) — OpenSSH's `AcceptEnv` set. Applied as defaults *below*
    /// the composition, so a loadout's explicit locale still wins.
    pub(crate) inherited: Vec<(String, String)>,
    /// Per-connection facts — currently just `TERM` from the PTY request.
    /// Applied *above* the composition, the way sshd sets `TERM`
    /// authoritatively regardless of shell dotfiles. (`SSH_TTY` and
    /// `SSH_CONNECTION`/`SSH_CLIENT` are deliberately not set: the session
    /// sandbox has no host `/dev/pts` and the Unix-socket transport has no peer
    /// address, so any value would name something that doesn't exist in-session.)
    pub(crate) connection: Vec<(String, String)>,
}

/// Trigger half of the launcher-baseline orientation banner: evaluates the
/// [`BASELINE_MOTD`] payload at the first interactive prompt, then unsets
/// both vars so the banner prints exactly once and never for
/// non-interactive commands. Identical to the MOTD recipe the built-in
/// `default` loadout ships and `docs/reference/loadouts.md` ("Vars in the
/// attach shell") documents.
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
    r#"[ -t 1 ] && { printf 'minimal · session %s · loadout %s\ndetach: ctrl-w' "${MINIMAL_SESSION_NAME:-unnamed}" "${MINIMAL_LOADOUTS:-none}"; [ -f "#,
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
#[cfg(not(test))]
pub(crate) struct SandboxLauncher {
    pub(crate) ctx: mctx::Context,
    /// Env captured from the SSH channel that mints this shell; see
    /// [`AttachEnv`].
    pub(crate) attach_env: AttachEnv,
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
/// [`PhaseOneAttachGuard`] this needs no runtime to do its work in
/// `Drop`.
#[cfg(not(test))]
struct SpawnedProcessGuard {
    /// `None` once the process has been handed off — see
    /// [`Self::release`].
    process: Option<hakoniwa::Child>,
}

#[cfg(not(test))]
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

#[cfg(not(test))]
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
        let attach_env = self.attach_env;
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
        // Log every item that will (or would) end up in the session,
        // tagged with its provenance. Patches and lifecycle hooks are
        // included even though the launcher can't act on them yet —
        // an operator inspecting logs should see the intent.
        log_session_contents(&name, BASELINE_PACKAGES, composition.as_deref());

        // Build the env + container and spawn the process. Any failure here (env
        // build, container build, spawn) leaves no process to reap; the phase-1
        // attach, if any, is rolled back by `attach_guard` on the `Err` return.
        let build_and_spawn = async {
            // The env owns the context, graph and the sandbox files backing the
            // running process's rootfs, so it is `Send + 'static` and can be moved
            // into the host as the guard that keeps those files alive.
            // Boxed: inlined, this reaches the cache fetchers' client stack and
            // the launch future's layout overruns rustc's query depth (128).
            let mut env = Box::pin(crate::env::Env::build(
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
            ))
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
            let tty_path = pty.slave_path().to_path_buf();
            let (master, slave) = pty.into_fds();
            command.stderr(hakoniwa::Stdio::from(slave));

            let process = command
                .spawn()
                .map_err(|e| io::Error::other(format!("exec failed: {e}")))?;
            // `command`/`container` no longer borrow `env`, so it can be moved
            // into the host to keep its backing files alive.
            drop(container);
            Ok::<_, io::Error>((env, master, process, tty_path))
        }
        .await;

        let (env, master, process, tty_path) = match build_and_spawn {
            // `attach_guard` (if armed) rolls the phase-1 attach back on this
            // `Err` return when it drops. Nothing spawned, so there is no
            // process to reap on this arm.
            Ok(parts) => parts,
            Err(e) => return Err(e),
        };

        // From here the process exists, so every way out of this function
        // has to account for it — including the one no `return` covers, a
        // cancelled future. `SpawnedProcessGuard` owns it until the
        // handoff at the bottom; an `Err` return or a drop reaps it.
        let mut process = SpawnedProcessGuard::new(process);

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
                let Some(raw) = process.get_mut().rustslirp_tapfd else {
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
                    // `complete_local_own_ip_attach` leaves the switch
                    // rollback to `attach_guard` and the process to
                    // `process`, both on this `Err` return.
                    Err(e) => return Err(io::Error::other(e)),
                }
            } else if matches!(network_mode, NetworkMode::OwnIp) {
                let network = crate::net::gvproxy_network::GvproxyNetwork::new(
                    std::sync::Arc::clone(&net_switch),
                    session_name,
                    ingress,
                );
                match network.attach(process.get_mut().id()).await {
                    Ok(guard) => Some(guard),
                    Err(e) => return Err(io::Error::other(e)),
                }
            } else {
                None
            };

        Ok(Launched {
            master,
            process: SandboxProcess(process.release()),
            guard: env,
            net_guard,
            tty_path,
        })
    }
}

/// A launched session process backed by a plain host [`std::process::Child`].
#[cfg(test)]
pub(crate) struct MockProcess(std::process::Child);

#[cfg(test)]
impl SessionProcess for MockProcess {
    fn container_pid(&self) -> u32 {
        self.0.id()
    }

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
        let tty_path = pty.slave_path().to_path_buf();
        let (master, slave) = pty.into_fds();
        command.stderr(std::process::Stdio::from(slave));

        let process = command.spawn()?;

        Ok(Launched {
            master,
            process: MockProcess(process),
            guard: (),
            net_guard: None,
            tty_path,
        })
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
        // here: session variables first, `extra_env` layered over them.
        let mut vars = environment.vars;
        vars.extend(extra_env);
        crate::nsenter::Injection::new(self.session_leader_pid()?, program, args)
            .with_cwd(environment.cwd)
            .with_env(vars)
            .command()
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
    /// dropped) after issuing a [`HostHandle::kill`].
    #[allow(clippy::too_many_arguments)]
    pub async fn spawn<L>(
        launcher: L,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
        channel: Option<Channel<Msg>>,
        control: Option<SessionControl>,
        archives_dir: std::path::PathBuf,
        session_id: sessions::SessionId,
        composition: Option<Arc<sessions::core::compose::Composition>>,
    ) -> Result<(HostHandle, JoinHandle<Result<i32, std::io::Error>>), std::io::Error>
    where
        L: SessionLauncher<Process = P, Guard = G>,
    {
        let (host, handle) = Self::build(
            launcher,
            name,
            username,
            paths,
            sz,
            channel,
            control,
            archives_dir,
            session_id,
            composition,
        )
        .await?;
        let task = tokio::spawn(host.mainloop());
        Ok((handle, task))
    }

    /// Builds the host and its handle from a launcher without spawning the
    /// runtime loop, so callers (notably tests) can drive [`Self::step`]
    /// directly and observe the host's state.
    #[allow(clippy::too_many_arguments)]
    async fn build<L>(
        launcher: L,
        name: String,
        username: String,
        paths: SessionPaths,
        sz: WinSize,
        channel: Option<Channel<Msg>>,
        control: Option<SessionControl>,
        archives_dir: std::path::PathBuf,
        session_id: sessions::SessionId,
        composition: Option<Arc<sessions::core::compose::Composition>>,
    ) -> Result<(Self, HostHandle), std::io::Error>
    where
        L: SessionLauncher<Process = P, Guard = G>,
    {
        // Baseline the workspace before the process launches, so nothing the
        // session writes can leak into the "since activation" reference point.
        let workspace_root = paths.working.as_utf8_path().as_std_path().to_path_buf();
        // Kept before `launch` consumes `paths`.
        let hooks_dir = paths.hooks.clone();
        let workspace_dir = paths.working.clone();
        let delta = DeltaSource::arm(workspace_root.clone()).await;

        // The launcher consumes `name`; the bindings need it too, to name the
        // archives the shell-exit prompt's save-then-delete lane writes.
        let session_name = name.clone();
        let Launched {
            master,
            process,
            guard,
            net_guard,
            tty_path,
        } = launcher.launch(name, username, paths, sz).await?;

        let (sender, receiver) = mpsc::channel(8);
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
            guard,
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

    /// Snapshots the visible terminal screen into the structured
    /// [`minimald_rpc::ScreenSnapshot`] wire type: dimensions, the cursor
    /// position (omitted when the session hid its cursor), and every cell
    /// of the grid. Read-only — no PTY resize and no I/O relay, unlike
    /// `attach`.
    fn screen_snapshot(&self) -> minimald_rpc::ScreenSnapshot {
        screen_to_snapshot(self.parser.screen())
    }

    pub async fn step(&mut self) -> Result<(), ()> {
        tokio::select! {
            // Read actor messages.
            Some(msg) = self.receiver.recv() => {
                match msg {
                    Message::Kill(for_shutdown) => {
                        if for_shutdown
                            && let Some((old_tx, old_join_hnd)) = self.remote.take() {
                                // If there was a binding we just swapped out, tell it to
                                // shut down and wait for it to finish.
                                let _ = old_tx
                                    .send(BindingMsg::TeardownDueToDaemonShutdown(self.unwind_codes()))
                                    .await;
                                let _ = old_join_hnd.await;
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
                    Message::GetScreen(s) => {
                        let _ = s.send(self.screen_snapshot());
                    }
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
                    StdinMsg::Bytes(b) => {
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
                    StdinMsg::TerminalUpdate(sz) => {
                        self.set_size(WinSize::from(&sz));
                    },
                    StdinMsg::WindowChange{ col_width, row_height, pix_height, pix_width } => {
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
        let new_binding = Binding::spawn(
            channel,
            self.remote_tx.clone(),
            self.control.clone(),
            self.delta.clone(),
            self.session_name.clone(),
            self.archives_dir.clone(),
        )
        .await;

        if let Some((old_tx, old_join_hnd)) = self.remote.replace(new_binding) {
            // If there was a binding we just swapped out, tell it to
            // shut down and wait for it to finish.
            let _ = old_tx
                .send(BindingMsg::TeardownDueToSuperceded(self.unwind_codes()))
                .await;
            let _ = old_join_hnd.await;
        }

        self.set_size(sz);

        // After the binding is installed and sized, so a hook writing to
        // the terminal reaches the client that just attached.
        self.run_hooks_for(crate::hooks::HookEvent::Attach).await;
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
        let clean = vt100::Parser::new(live.size().0, live.size().1, 0)
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

    /// Precedence: the launcher `baseline` sits below the client-forwarded
    /// `inherited`, which sits below the composition, which sits below the
    /// per-connection `connection` facts. Later layers win on a shared key;
    /// non-colliding keys from every layer survive.
    #[test]
    fn layer_session_env_precedence() {
        let sv = |k: &str, v: &str| (k.to_string(), v.to_string());
        let env = layer_session_env(
            // baseline: its LANG is overridden by inherited; NAME survives.
            vec![sv("LANG", "C"), sv("NAME", "box-1")],
            // inherited: LANG is overridden by composition; TZ survives.
            vec![sv("LANG", "de_DE.UTF-8"), sv("TZ", "Europe/Berlin")],
            // composition: beats inherited LANG; its TERM is overridden by the
            // connection; EDITOR survives.
            vec![
                sv("LANG", "fr_FR.UTF-8"),
                sv("TERM", "dumb"),
                sv("EDITOR", "hx"),
            ],
            // connection: authoritative TERM.
            vec![sv("TERM", "xterm-256color")],
        );

        assert_eq!(env.get("LANG").map(String::as_str), Some("fr_FR.UTF-8")); // composition > inherited > baseline
        assert_eq!(env.get("NAME").map(String::as_str), Some("box-1")); // baseline-only survives
        assert_eq!(env.get("TZ").map(String::as_str), Some("Europe/Berlin")); // inherited-only survives
        assert_eq!(env.get("TERM").map(String::as_str), Some("xterm-256color")); // connection > composition
        assert_eq!(env.get("EDITOR").map(String::as_str), Some("hx")); // composition-only survives
        assert_eq!(env.len(), 5);
    }

    /// The launcher baseline seeds the session's identity plus the
    /// once-only orientation banner pair: the session name verbatim in
    /// `MINIMAL_SESSION_NAME`, the self-unsetting `PROMPT_COMMAND`
    /// trigger, and a STATIC `MINIMAL_MOTD` template that defers the
    /// dynamic parts to print time — env interpolation for the name and
    /// loadout list (with `${VAR:-fallback}` unset-safety), a direct
    /// in-shell filesystem test of the session workspace for the
    /// blueprint clause (never a var: the client can't know the
    /// workspace's state).
    #[test]
    fn layer_session_env_seeds_baseline_banner() {
        let env = layer_session_env(
            session_baseline_env("api-server-4f2a", Some("default (built-in)")),
            vec![],
            vec![],
            vec![],
        );

        assert_eq!(
            env.get("MINIMAL_SESSION_NAME").map(String::as_str),
            Some("api-server-4f2a")
        );
        // The loadout list is seeded daemon-side from the composition's
        // first-class orientation field — never from a user var.
        assert_eq!(
            env.get("MINIMAL_LOADOUTS").map(String::as_str),
            Some("default (built-in)")
        );
        let pc = env.get("PROMPT_COMMAND").expect("baseline PROMPT_COMMAND");
        assert!(pc.contains(r#"eval "$MINIMAL_MOTD""#));
        assert!(pc.contains("unset PROMPT_COMMAND MINIMAL_MOTD"));

        let motd = env.get("MINIMAL_MOTD").expect("baseline MINIMAL_MOTD");
        assert!(motd.starts_with("[ -t 1 ]"), "banner must be TTY-gated");
        // Static template, dynamic vars: interpolated in-shell, unset-safe.
        assert!(motd.contains("${MINIMAL_SESSION_NAME:-"));
        assert!(motd.contains("${MINIMAL_LOADOUTS:-"));
        // The blueprint clause tests the session workspace itself at
        // print time — both mfile layouts — pinned to the same constant
        // that is the shell's initial cwd.
        assert!(motd.contains("[ -f /workbench/minimal.toml ]"));
        assert!(motd.contains("[ -f /workbench/.minimal/minimal.toml ]"));
        assert!(
            !motd.contains("MINIMAL_BLUEPRINT"),
            "blueprint is a session-filesystem fact, not an env var"
        );
        assert!(motd.contains("detach: ctrl-w"));
        assert!(motd.contains("min init"));
    }

    /// A missing loadout display (old client / no composition) leaves
    /// `MINIMAL_LOADOUTS` unset so the templates' own `${…:-}` fallbacks
    /// render, each correct for its surface.
    #[test]
    fn baseline_env_omits_loadouts_var_when_display_unknown() {
        let env = layer_session_env(session_baseline_env("box-1", None), vec![], vec![], vec![]);
        assert!(!env.contains_key("MINIMAL_LOADOUTS"));
        assert!(env.contains_key("MINIMAL_SESSION_NAME"));
    }

    /// A composed `PROMPT_COMMAND` — a user loadout's, or the built-in
    /// default's — overrides the baseline banner trigger cleanly, while
    /// the baseline identity vars survive for that override to
    /// interpolate.
    #[test]
    fn composed_prompt_command_overrides_baseline_banner() {
        let env = layer_session_env(
            session_baseline_env("box-1", Some("helix, fish")),
            vec![],
            vec![(
                "PROMPT_COMMAND".to_string(),
                r#"eval "$MY_MOTD""#.to_string(),
            )],
            vec![],
        );

        assert_eq!(
            env.get("PROMPT_COMMAND").map(String::as_str),
            Some(r#"eval "$MY_MOTD""#)
        );
        assert_eq!(
            env.get("MINIMAL_SESSION_NAME").map(String::as_str),
            Some("box-1")
        );
        assert_eq!(
            env.get("MINIMAL_LOADOUTS").map(String::as_str),
            Some("helix, fish")
        );
    }

    #[test]
    fn open_and_get_fds() {
        let pty = Pty::open(DEFAULT_SIZE).expect("failed to open pty");
        assert!(pty.master_fd() >= 0);
        assert!(pty.slave_fd() >= 0);
        assert_ne!(pty.master_fd(), pty.slave_fd());
    }

    /// A wide glyph occupies two grid cells; the snapshot must emit only the
    /// glyph itself, not a placeholder space for its continuation cell, so
    /// the flattened row keeps the terminal's display width.
    #[test]
    fn screen_snapshot_drops_wide_continuation_cells() {
        let mut parser = vt100::Parser::new(2, 10, 0);
        parser.process("abあcd".as_bytes());
        let snapshot = screen_to_snapshot(parser.screen());
        let text: String = snapshot.lines[0].cells.iter().map(|c| c.ch).collect();
        assert_eq!(text.trim_end(), "abあcd");
    }

    #[test]
    fn hvp_positions_like_cup() {
        // btop positions exclusively with HVP (`f`); it must behave like CUP
        // (gominimal/minimal#1197). Guards the gominimal/vt100-rust fork's
        // patch against being dropped.
        let mut parser = vt100::Parser::new(5, 10, 0);
        parser.process("\u{1b}[3;7fX\u{1b}[fY".as_bytes());
        assert_eq!(parser.screen().cell(2, 6).unwrap().contents(), "X");
        assert_eq!(parser.screen().cell(0, 0).unwrap().contents(), "Y");
        assert_eq!(parser.screen().cursor_position(), (0, 1));
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
                hooks: DaemonAbsPath::root(),
            },
            DEFAULT_SIZE,
            None,
            None,
            std::env::temp_dir(),
            sessions::SessionId::nil(),
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
            .send(StdinMsg::Bytes(bytes::Bytes::from(osc.into_bytes())))
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
                hooks: DaemonAbsPath::root(),
            },
            DEFAULT_SIZE,
            None,
            None,
            std::env::temp_dir(),
            sessions::SessionId::nil(),
            None,
        )
        .await
        .expect("failed to build host");
        let task = tokio::spawn(host.mainloop());

        handle
            .kill(false)
            .await
            .expect("kill should reach the host");

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
            let tty_path = pty.slave_path().to_path_buf();
            let (master, slave) = pty.into_fds();
            command.stderr(std::process::Stdio::from(slave));
            let process = command.spawn()?;
            Ok(Launched {
                master,
                process: MockProcess(process),
                guard: (),
                tty_path,
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
            hooks: DaemonAbsPath::root(),
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
            std::env::temp_dir(),
            sessions::SessionId::nil(),
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
            .send(StdinMsg::Bytes(bytes::Bytes::from(
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
            std::env::temp_dir(),
            sessions::SessionId::nil(),
            None,
        )
        .await
        .expect("failed to build host");
        let stdin = host.remote_tx.clone();
        let task = tokio::spawn(host.mainloop());

        // A bare ctrl-w (0x17) is the detach chord. It must be consumed as a
        // detach signal rather than written to the pty.
        stdin
            .send(StdinMsg::Bytes(bytes::Bytes::from(vec![0x17])))
            .await
            .expect("failed to send ctrl-w");

        // The shell survived the detach: a normal line still echoes back, which
        // stamps stdout activity. (If ctrl-w had been forwarded or had killed the
        // process, no echo would ever arrive.)
        stdin
            .send(StdinMsg::Bytes(bytes::Bytes::from(b"ping\n".to_vec())))
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
        handle.kill(true).await.expect("kill should reach the host");
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
