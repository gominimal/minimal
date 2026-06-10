//! The running state of an active session.
//!
//! The [`Pty`] struct owns a master/slave pseudo-terminal pair created via
//! `openpty(3)`, exposing its file descriptors and window-size controls.
//!
//! The [`Host`] struct holds the running state of an active session.

use either::Either;
use russh::Channel;
use russh::server::Msg;
use std::io;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd, RawFd};
use tokio::io::AsyncWriteExt;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::sync::mpsc::error::SendError;
use tokio::task::JoinHandle;

use crate::RequestedPty;
use crate::session::SessionHandle;

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
    /// Extracts the terminal dimensions, ignoring `term` and modes.
    ///
    /// SSH carries sizes as `u32`; terminal dimensions never exceed `u16`, so
    /// out-of-range values are clamped rather than wrapped.
    fn from(pty: &RequestedPty) -> Self {
        let (cols, rows) = pty.char_sizes;
        let (xpixel, ypixel) = pty.pixel_sizes;
        Self {
            rows: rows.min(u16::MAX as u32) as u16,
            cols: cols.min(u16::MAX as u32) as u16,
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

/// Duplicates an `OwnedFd` into a new, independent `OwnedFd` via `dup(2)`.
fn dup_fd(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::dup(fd.as_raw_fd()) };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `dup` succeeded, so `raw` is a valid, open fd.
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
    TeardownDueToStdoutErr(std::io::Error),
    TeardownDueToSuperceded,
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
}

impl Binding {
    /// Spawns a new binding task for a given channel, returning objects
    /// which the owning [`Host`] should own to communicate with it.
    pub(crate) async fn spawn(
        channel: Channel<Msg>,
        stdin_tx: mpsc::Sender<Either<bytes::Bytes, RequestedPty>>,
    ) -> (mpsc::Sender<BindingMsg>, JoinHandle<()>) {
        let (tx, rx) = mpsc::channel(4);

        let binding = Self {
            channel,
            stdin_tx,
            receiver: rx,
        };

        (tx, tokio::spawn(binding.run()))
    }

    async fn run(mut self) {
        let (mut rs, ws) = self.channel.split();
        let mut w = ws.make_writer();

        // Reading from the remote stops once it sends EOF;
        // the loop lives on to keep forwarding stdout.
        let mut remote_open = true;
        loop {
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
                            _ => tracing::warn!("skipping msg: {:?}", msg),
                        };
                    }
                },
                // Session stdout => remote (ssh channel).
                // A closed channel means the host is gone;
                // tear the attachment down.
                msg = self.receiver.recv() => {
                    let Some(msg) = msg else { break };
                    match msg {
                        BindingMsg::Stdin(b) => {
                            let _ = w.write_all(&b).await;
                        },
                        BindingMsg::TeardownDueToStdoutErr(e) => {
                            if e.raw_os_error() != Some(5) {
                                let _ = w.write_all(format!("Error reading stdout: {e}\n").as_bytes()).await;
                            }
                            break;
                        }
                        BindingMsg::TeardownDueToSuperceded => {
                            let _ = w.write_all(b"\r\nDisconnecting - session attached to from a different connection\r\n").await;
                            break;
                        }
                    };

                }
            }
        }

        tracing::debug!("Binding shutting down");
        let _ = ws.eof().await;
        let _ = ws.exit_status(0).await; // TODO: Only report this if process terminates
        let _ = ws.close().await; // needed to release the remote
    }
}

/// Actor messages to a [`Host`].
enum Message {
    Kill,
    Attach(Channel<Msg>, WinSize),
}

/// The handle to the session host - the running process.
#[derive(Debug, Clone)]
pub struct HostHandle {
    sender: mpsc::Sender<Message>,
}

impl HostHandle {
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
}

/// The state of the session process.
pub struct Host {
    /// Channel for actor messages via [`HostHandle`].
    receiver: mpsc::Receiver<Message>,

    /// The async task and its channel that wires the session
    /// to the ssh channel, if currently attached.
    remote: Option<(mpsc::Sender<BindingMsg>, JoinHandle<()>)>,

    /// The last-set pty terminal size.
    sz: WinSize,
    /// In-memory representation of the terminal state.
    parser: vt100_ctt::Parser,
    /// The session process.
    process: hakoniwa::Child,
    /// The master-side fd of the Pty.
    master: AsyncFd<std::fs::File>,

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

    // Keeps the session's `Env` — and the `Context` and `Graph` it borrows —
    // alive for as long as this host (and thus the session process) lives.
    // Declared last so it is dropped after `process`: the process is torn down
    // before the sandbox files backing its rootfs are removed. Never read; held
    // purely for its `Drop`.
    _session_env: SessionEnv,
}

/// Owns the [`mctx::Env`] for a session, along with the [`mctx::Context`] and
/// [`graph::Graph`] it borrows, keeping all three alive for the session.
///
/// `Env<'a>` borrows the context and graph mutably and owns the temp dirs and
/// sandbox base directory that hold the running process's rootfs. We can't
/// store the env next to the values it borrows (that would be a self-referential
/// struct), so the context and graph are leaked to obtain `'static` borrows for
/// the env; the raw pointers are retained here so the leaked allocations can be
/// reclaimed once the env is dropped.
struct SessionEnv {
    /// `Some` for the whole lifetime of the value; taken in `drop` so the env
    /// is dropped before the context and graph it borrows are freed.
    env: Option<mctx::Env<'static>>,
    ctx: *mut mctx::Context,
    graph: *mut graph::Graph,
}

// SAFETY: `mctx::Context`, `graph::Graph`, and `mctx::Env` are all `Send`
// (the context and graph round-trip through `spawn_blocking`, and the env is
// held across `.await` in `Host::spawn`). The raw pointers merely retain
// ownership of the leaked allocations so they can be freed in `drop`; they are
// never dereferenced concurrently with the `&'static mut` borrows held by `env`.
unsafe impl Send for SessionEnv {}

impl Drop for SessionEnv {
    fn drop(&mut self) {
        // Drop the env first, so its sandbox (and the listener thread holding
        // the borrowed context/graph) is torn down while the context and graph
        // are still valid.
        self.env = None;
        // SAFETY: `ctx`/`graph` were produced by `Box::into_raw` in
        // `Host::spawn` and have not been freed. Their only borrower, `env`,
        // was just dropped above, so no references into them remain.
        unsafe {
            drop(Box::from_raw(self.graph));
            drop(Box::from_raw(self.ctx));
        }
    }
}

impl Host {
    pub async fn spawn(
        sz: WinSize,
        channel: Option<Channel<Msg>>,
        mut ctx: mctx::Context,
        _session: SessionHandle,
    ) -> Result<HostHandle, std::io::Error> {
        // `graph_from_all_packages` is CPU-heavy (nickel evaluation,
        // graph construction) — run it on the blocking pool so it
        // doesn't stall the async executor.
        let (ctx, graph_result) = tokio::task::spawn_blocking(move || {
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());
            (ctx, r)
        })
        .await
        .map_err(io::Error::other)?;
        let graph = graph_result.map_err(io::Error::other)?;

        // Leak the context and graph so the env can borrow them for `'static`.
        // The env owns the sandbox base dir and temp dirs backing the running
        // process's rootfs; if it (and the values it borrows) were dropped when
        // `spawn` returns, those files would be deleted out from under the live
        // process. The returned `SessionEnv` keeps all three alive for the
        // session and frees the leaked allocations when the host is dropped.
        // The addresses are carried as `usize` (not `*mut`) so this future
        // stays `Send` across the `make_env` await below; they are cast back to
        // pointers only when building the `SessionEnv`.
        let ctx_addr = Box::into_raw(Box::new(ctx)) as usize;
        let graph_addr = Box::into_raw(Box::new(graph)) as usize;
        // SAFETY: both addresses were just produced by `Box::into_raw`, so they
        // point to valid, aligned, uniquely owned allocations. We hand out a
        // single `&'static mut` for each to `make_env`; the allocations are not
        // accessed again through these addresses until `SessionEnv::drop`
        // reclaims them, after the borrowing env has been dropped.
        let (ctx_ref, graph_ref) = unsafe {
            (
                &mut *(ctx_addr as *mut mctx::Context),
                &mut *(graph_addr as *mut graph::Graph),
            )
        };

        let mut env = ctx_ref
            .make_env(
                "session",
                graph_ref,
                None,
                Some(&"default-state".to_string()),
                None,
                None,
                vec![
                    "base".to_string(),
                    "bash".to_string(),
                    "socat".to_string(),
                    "coreutils".to_string(),
                ],
            )
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        let container = env
            .container()
            .map_err(|e| io::Error::other(format!("building container failed: {}", e)))?;

        let pty = Pty::open(sz)?;
        let mut command = env
            .command(&container, "/bin/bash", ["--noprofile", "-l"])
            .map_err(|e| io::Error::other(format!("building command failed: {}", e)))?;
        command.stdin(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
        command.stdout(hakoniwa::Stdio::from(pty.dup_slave_fd()?));
        let (master, slave) = pty.into_fds();
        command.stderr(hakoniwa::Stdio::from(slave));

        let parser = vt100_ctt::Parser::new(sz.rows, sz.cols, 0);
        let (sender, receiver) = mpsc::channel(8);
        let (remote_tx, remote_rx) = mpsc::channel(4);
        let master = {
            set_nonblocking(master.as_raw_fd())?;
            let file = unsafe { std::fs::File::from_raw_fd(master.into_raw_fd()) };
            AsyncFd::new(file)?
        };
        let process = command
            .spawn()
            .map_err(|e| io::Error::other(format!("exec failed: {}", e)))?;
        // `command`/`container` no longer borrow `env`, so it can be moved into
        // the host (via `SessionEnv`) to keep its backing files alive.
        drop(container);

        let mut host = Host {
            receiver,
            remote: None,
            sz,
            parser,
            process,
            master,

            remote_tx,
            remote_rx,
            stdout_buf: vec![0u8; 8 * 1024],
            stdin_buf: None,
            _session_env: SessionEnv {
                env: Some(env),
                ctx: ctx_addr as *mut mctx::Context,
                graph: graph_addr as *mut graph::Graph,
            },
        };
        if let Some(channel) = channel {
            host.attach(channel, sz, true).await;
        }
        tokio::spawn(host.mainloop());

        Ok(HostHandle { sender })
    }

    pub async fn mainloop(mut self) -> Result<hakoniwa::ExitStatus, std::io::Error> {
        loop {
            match self
                .process
                .try_wait()
                .map_err(|e| io::Error::other(format!("wait failed: {}", e)))?
            {
                None => {}
                Some(exit_status) => return Ok(exit_status),
            }

            if let Err(()) = self.step().await {
                return self
                    .process
                    .wait()
                    .map_err(|e| io::Error::other(format!("wait failed: {}", e)));
            };
        }
    }

    pub async fn step(&mut self) -> Result<(), ()> {
        tokio::select! {
            // Read actor messages.
            Some(msg) = self.receiver.recv() => {
                match msg {
                    Message::Kill => {
                        tracing::info!("kill res: {:?}", self.process.kill());
                    }
                    Message::Attach(channel, sz) => {
                        self.attach(channel, sz, false).await;
                    }
                }
            },
            // Read from master - stdout of session process => ssh channel (if any)
            r = self.master.readable() => {
                match r.expect("todo read handle error").try_io(|fd| fd.get_ref().read(&mut self.stdout_buf)) {
                    Ok(Ok(0)) => {},
                    Ok(Ok(n)) => {
                        let b = &self.stdout_buf[..n];
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
                        tracing::warn!(error = %e, "Reading pty master");
                        if let Some((tx, _hnd)) = self.remote.as_mut() {
                            let _ = tx.send(BindingMsg::TeardownDueToStdoutErr(e)).await;
                        }
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
                        self.stdin_buf = Some((b, 0));
                    }
                    Either::Right(sz) => {
                        self.set_size(WinSize::from(&sz));
                    },
                }
            },
            // Write buffered keystrokes into the pty, if any,
            w = self.master.writable(), if self.stdin_buf.is_some() => {
                let (buff, n) = self.stdin_buf.as_mut().unwrap();
                match w.expect("todo write handle error").try_io(|fd|fd.get_ref().write(&buff[*n..])) {
                    Ok(Ok(extra)) => {
                        if (*n+extra) == buff.len() {
                            self.stdin_buf = None;
                        } else {
                            *n += extra;
                        }
                    }
                    Ok(Err(e)) => {
                        todo!("handle error writing to stdin: {e}");
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
        let new_binding = Binding::spawn(channel, self.remote_tx.clone()).await;

        if let Some((old_tx, old_join_hnd)) = self.remote.replace(new_binding) {
            // If there was a binding we just swapped out, tell it to
            // shut down and wait for it to finish.
            let _ = old_tx.send(BindingMsg::TeardownDueToSuperceded).await;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
