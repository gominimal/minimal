//! The client-owned terminal relay for interactive attaches.
//!
//! `min session attach` (interactive) used to wait on ssh with the user's
//! terminal handed over wholesale: ssh owned the tty, put it in its own raw
//! mode and restored it on exit. That works until the client needs the
//! terminal *during* the attach. The dynamic-ingress `ask` prompt (NET-045)
//! has to interrupt the session output and borrow the real tty to ask the
//! attached human something, and nothing can do that from outside ssh.
//!
//! So the attach moves behind a relay the client owns:
//!
//! ```text
//!   real tty ──┐
//!   (stdin or  │  read/write, termios owned by the relay
//!   /dev/tty) ─┘
//!        │
//!      poll(2) pump ─── pty master ─── pty slave = ssh's stdio and ctty (-tt)
//! ```
//!
//! ssh is spawned on the slave end of an [`openpty`] pair, as the leader of
//! a new session whose controlling terminal is that slave, the way a
//! terminal emulator starts a shell. The slave starts with the real
//! terminal's own termios and size, so what ssh reads off its stdin (and
//! sends as the remote pty's modes) is what it read off the real terminal
//! before. The relay keeps the *real* terminal in exactly the raw set ssh
//! applied to it ([`ssh_raw_termios`]), so the session-key chord still
//! arrives as data ([`sessions::keys`]'s raw-tty premise) and every byte
//! flows through in full chunks, in order, with no line discipline in the
//! way.
//!
//! Restore discipline: the termios captured at attach start is put back on
//! *every* exit path: ssh exiting, the transport dropping, SIGINT/SIGTERM
//! forwarded to ssh's process group, SIGHUP closing the master, and a panic
//! anywhere in the relay (a drop guard the pump thread holds). A
//! [`RelayHandle::suspend`] hands the real tty back to the caller (with
//! attach-start termios) while the relay keeps draining ssh, buffered
//! head-first up to [`SUSPEND_OUTPUT_BUFFER_BYTES`] and never applying
//! backpressure, so the daemon never sheds an attach waiting on a prompt.
//!
//! All of this is invisible to a plain `min session attach`: same bytes,
//! same sizes, same exit status.

use std::io::IsTerminal as _;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use anyhow::Context as _;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::pty::{Winsize, openpty};
use nix::sys::stat::Mode;
use nix::sys::termios::{
    InputFlags, LocalFlags, OutputFlags, SetArg, SpecialCharacterIndices, Termios, tcgetattr,
    tcsetattr,
};
use nix::unistd::{pipe, read, write};

/// While a suspend is up, ssh's output is buffered up to this many bytes:
/// the head is kept for replay on resume and the tail beyond is dropped and
/// counted. Bounded so a chatty session cannot wedge the client on memory,
/// and a *fixed* bound because the prompt, not the session, owns the
/// terminal while it is up.
pub const SUSPEND_OUTPUT_BUFFER_BYTES: usize = 1024 * 1024;

/// The visible line [`RelayHandle::resume`] prints on the tty when output
/// past the suspend bound had to be dropped, with the byte count up front.
pub const DROP_LINE_SUFFIX: &str = " bytes of session output dropped while the prompt was up";

/// The largest chunk the pump moves per direction in one turn. Bytes flow
/// in full chunks: a read is handed off as one write, split only if the
/// kernel takes part of it (then the remainder is the first thing the next
/// turn writes, so order is preserved by the pending buffers).
const IO_CHUNK_BYTES: usize = 64 * 1024;

/// While relaying live (not suspended), the pump stops reading the
/// session's output once this much is undelivered to the terminal. The
/// pty's own kernel buffer then absorbs the rest, and once that fills ssh
/// blocks in its write, exactly as it did against the real tty. Suspended,
/// the pump reads regardless: see [`SUSPEND_OUTPUT_BUFFER_BYTES`].
const LIVE_OUTPUT_HIGH_WATER: usize = 4 * 1024 * 1024;

/// How long the resume's winsize nudge holds `rows − 1` before putting the
/// size back. ssh reads the size when its SIGWINCH is serviced, so two
/// changes inside one turn of its loop would collapse into "no change" and
/// the session would never be told to repaint.
const NUDGE_SETTLE: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------------
// Signals
//
// The handlers do only what is async-signal-safe: raise a flag and write
// one byte to the pump's wake pipe. A signal lands on whichever thread the
// kernel picks, so the pipe is what gets the pump out of poll(2).
// ---------------------------------------------------------------------------

static SIGWINCH_SEEN: AtomicBool = AtomicBool::new(false);
static SIGINT_SEEN: AtomicBool = AtomicBool::new(false);
static SIGTERM_SEEN: AtomicBool = AtomicBool::new(false);
static SIGHUP_SEEN: AtomicBool = AtomicBool::new(false);

/// The write end of the running relay's wake pipe, or -1 when none runs.
static WAKE_FD: AtomicI32 = AtomicI32::new(-1);

fn wake_from_signal() {
    let fd = WAKE_FD.load(Ordering::Acquire);
    if fd >= 0 {
        // SAFETY: write(2) is async-signal-safe; `fd` is the nonblocking
        // write end of the wake pipe, kept open for as long as WAKE_FD
        // names it, and the one-byte buffer is a valid static.
        let _ = unsafe { libc::write(fd, b"!".as_ptr().cast(), 1) };
    }
}

extern "C" fn on_sigwinch(_: libc::c_int) {
    SIGWINCH_SEEN.store(true, Ordering::Release);
    wake_from_signal();
}

extern "C" fn on_sigint(_: libc::c_int) {
    SIGINT_SEEN.store(true, Ordering::Release);
    wake_from_signal();
}

extern "C" fn on_sigterm(_: libc::c_int) {
    SIGTERM_SEEN.store(true, Ordering::Release);
    wake_from_signal();
}

extern "C" fn on_sighup(_: libc::c_int) {
    SIGHUP_SEEN.store(true, Ordering::Release);
    wake_from_signal();
}

/// The dispositions the relay replaced, put back when the relay exits. A
/// plain process-global stack: one relay per process at a time (the CLI
/// attaches once; the TUI attaches one session at a time).
static SAVED_SIGNALS: Mutex<Vec<(libc::c_int, libc::sigaction)>> = Mutex::new(Vec::new());

/// Install the relay's handlers, waking the pump through `wake`; the saved
/// dispositions are put back by [`restore_relay_signals`], which the caller
/// owes on every path once this has been called, error included. Wired
/// over `libc` directly because the crate's nix features are exactly
/// `term` and `poll`.
fn install_relay_signals(wake: &OwnedFd) -> Result<(), anyhow::Error> {
    for flag in [&SIGWINCH_SEEN, &SIGINT_SEEN, &SIGTERM_SEEN, &SIGHUP_SEEN] {
        flag.store(false, Ordering::Release);
    }
    WAKE_FD.store(wake.as_raw_fd(), Ordering::Release);
    let mut saved = SAVED_SIGNALS
        .lock()
        .expect("the saved-signal stack is never held across a panic");
    for (sig, handler) in [
        (libc::SIGWINCH, on_sigwinch as extern "C" fn(libc::c_int)),
        (libc::SIGINT, on_sigint),
        (libc::SIGTERM, on_sigterm),
        (libc::SIGHUP, on_sighup),
    ] {
        // SAFETY: an all-zero `sigaction` is a valid value (no flags, empty
        // mask, SIG_DFL), and sigemptyset only writes the mask it is given.
        let action = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as usize;
            // SA_RESTART: the wake pipe, not EINTR, is how the pump learns
            // of a signal, so every other thread's blocking call (the TUI's
            // event reader, the runtime's) carries on as it did before the
            // relay took the signal over.
            action.sa_flags = libc::SA_RESTART;
            libc::sigemptyset(&mut action.sa_mask);
            action
        };
        // SAFETY: as above, zeroed is a valid `sigaction` to be overwritten.
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
        // SAFETY: both pointers are to live, initialised `sigaction`s, and
        // the handler only touches atomics and calls write(2).
        let rc = unsafe { libc::sigaction(sig, &action, &mut previous) };
        if rc != 0 {
            return Err(anyhow::anyhow!(
                "installing the relay's signal handler {sig}: {}",
                std::io::Error::last_os_error()
            ));
        }
        saved.push((sig, previous));
    }
    Ok(())
}

/// Put back every disposition [`install_relay_signals`] replaced.
fn restore_relay_signals() {
    WAKE_FD.store(-1, Ordering::Release);
    let saved = {
        let mut saved = SAVED_SIGNALS
            .lock()
            .expect("the saved-signal stack is never held across a panic");
        std::mem::take(&mut *saved)
    };
    for (sig, action) in saved.into_iter().rev() {
        // SAFETY: `action` is the disposition sigaction(2) itself handed
        // back at install time. Failure leaves the relay's flag-raising
        // handler in place, which is harmless, so the result is ignored.
        let _ = unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
    }
}

/// Signal `pgid`'s whole group. ssh leads its own session and group (see
/// [`Relay::start`]), so a forwarded SIGINT/SIGTERM reaches ssh *and* the
/// proxy it forked: everyone the terminal's signal was for.
fn killpg(pgid: u32, sig: libc::c_int) -> bool {
    let Ok(pgid) = libc::pid_t::try_from(pgid) else {
        return false;
    };
    // SAFETY: killpg(2) has no memory-safety preconditions.
    unsafe { libc::killpg(pgid, sig) == 0 }
}

// ---------------------------------------------------------------------------
// winsize
// ---------------------------------------------------------------------------

/// Read a terminal's size.
fn get_winsize(fd: &impl AsFd) -> Result<Winsize, anyhow::Error> {
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: TIOCGWINSZ writes one `winsize` through the pointer, which
    // points at a live `Winsize` (nix's alias of `libc::winsize`).
    let rc = unsafe { libc::ioctl(fd.as_fd().as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "reading the terminal size: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(ws)
}

/// Set the size of the terminal `fd` is an end of. On the pty pair the
/// ioctl is made against the master; the kernel sends SIGWINCH to the
/// slave's foreground group (ssh), which tells the remote end.
fn set_winsize(fd: &impl AsFd, ws: Winsize) -> Result<(), anyhow::Error> {
    // SAFETY: TIOCSWINSZ reads one `winsize` through the pointer, which
    // points at a live `Winsize`.
    let rc = unsafe { libc::ioctl(fd.as_fd().as_raw_fd(), libc::TIOCSWINSZ, &ws) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "setting the terminal size: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ssh's raw set
// ---------------------------------------------------------------------------

/// The termios the relay keeps the real terminal in while an interactive
/// attach runs: exactly the set OpenSSH's `enter_raw_mode` (sshtty.c)
/// applied to it before this change, so the session-key leader rule's
/// raw-tty premise ([`sessions::keys`]: the chord must reach the app as
/// data) still holds.
///
/// That is: IGNPAR on; ISTRIP, INLCR, IGNCR, ICRNL, IXON, IXANY, IXOFF
/// (and IUCLC where it exists) off; ISIG, ICANON, ECHO, ECHOE, ECHOK,
/// ECHONL and IEXTEN off; OPOST off; VMIN 1, VTIME 0. Everything else
/// (character size, parity, the control characters) keeps its attach-start
/// value, as it did under ssh.
pub fn ssh_raw_termios(base: &Termios) -> Termios {
    let mut raw = base.clone();
    raw.input_flags.insert(InputFlags::IGNPAR);
    raw.input_flags.remove(
        InputFlags::ISTRIP
            | InputFlags::INLCR
            | InputFlags::IGNCR
            | InputFlags::ICRNL
            | InputFlags::IXON
            | InputFlags::IXANY
            | InputFlags::IXOFF,
    );
    #[cfg(any(target_os = "linux", target_os = "android"))]
    raw.input_flags.remove(InputFlags::IUCLC);
    raw.local_flags.remove(
        LocalFlags::ISIG
            | LocalFlags::ICANON
            | LocalFlags::ECHO
            | LocalFlags::ECHOE
            | LocalFlags::ECHOK
            | LocalFlags::ECHONL
            | LocalFlags::IEXTEN,
    );
    raw.output_flags.remove(OutputFlags::OPOST);
    raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 1;
    raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 0;
    raw
}

/// The few termios bits worth naming in a log line: what the relay put on
/// the terminal and what it will put back.
fn describe_termios(t: &Termios) -> String {
    let named = [
        (t.local_flags.contains(LocalFlags::ECHO), "echo"),
        (t.local_flags.contains(LocalFlags::ICANON), "icanon"),
        (t.local_flags.contains(LocalFlags::ISIG), "isig"),
        (t.local_flags.contains(LocalFlags::IEXTEN), "iexten"),
        (t.input_flags.contains(InputFlags::IXON), "ixon"),
        (t.output_flags.contains(OutputFlags::OPOST), "opost"),
    ];
    let on: Vec<&str> = named
        .iter()
        .filter(|(set, _)| *set)
        .map(|(_, name)| *name)
        .collect();
    if on.is_empty() {
        "raw (none of echo/icanon/isig/iexten/ixon/opost)".to_string()
    } else {
        format!("[{}]", on.join(","))
    }
}

// ---------------------------------------------------------------------------
// The real terminal
// ---------------------------------------------------------------------------

/// The terminal the relay owns for the duration of an attach: the fd the
/// user's keystrokes come from, and the fd session output goes to.
///
/// The input fd follows crossterm's `tty_fd()` rule so the relay and the
/// TUI can never disagree about which terminal is "the real one": stdin
/// when it is a terminal, `/dev/tty` otherwise. crossterm's raw-mode
/// release acts on exactly that fd, so a relay started *after* crossterm
/// leaves raw mode captures the pre-TUI state, never crossterm's.
#[derive(Debug)]
pub struct RealTty {
    input: OwnedFd,
    output: OwnedFd,
}

impl RealTty {
    /// Take the real terminal: the user's stdin when it is a tty, the
    /// controlling terminal otherwise; output always goes to stdout, which
    /// is where ssh put the session's bytes.
    pub fn acquire() -> Result<Self, anyhow::Error> {
        let input = if std::io::stdin().is_terminal() {
            std::io::stdin()
                .as_fd()
                .try_clone_to_owned()
                .context("duplicating stdin as the real terminal")?
        } else {
            nix::fcntl::open(
                "/dev/tty",
                OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .context("opening /dev/tty as the real terminal: the interactive attach needs one")?
        };
        let output = std::io::stdout()
            .as_fd()
            .try_clone_to_owned()
            .context("duplicating stdout as the session's output")?;
        Ok(Self { input, output })
    }

    /// Build a relay target out of an explicit fd pair: `input` is the
    /// terminal whose termios and size the relay owns, `output` where the
    /// session's bytes go. [`Self::acquire`] is the production choice; this
    /// is for a caller (or a test) that already holds the terminal.
    pub fn from_fds(input: OwnedFd, output: OwnedFd) -> Self {
        Self { input, output }
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// A command from the handle to the pump. Wakes the pump through the wake
/// pipe; the condvar handshake says when each side is done with it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ctl {
    /// Stop forwarding input, restore attach-start termios, start buffering.
    Suspend,
    /// Replay the buffered head, reassert raw mode, keep relaying.
    Resume,
    /// The relay is being dropped mid-attach: stop and restore.
    Exit,
}

#[derive(Default)]
struct SharedState {
    command: Option<Ctl>,
    suspended: bool,
    /// The pump is done; every handle call is a no-op or an error now.
    finished: bool,
}

/// What the caller and the pump share. The pump thread is the only writer
/// of the real terminal and its termios while the relay runs (a suspend
/// hands that role to the lease holder until resume), so the captured
/// termios moves *into* the pump instead of living here: nix's `Termios`
/// is not `Sync`.
struct RelayInner {
    state: Mutex<SharedState>,
    cv: Condvar,
    tty: RealTty,
    /// True while the real terminal is in its attach-start state; the
    /// pump's drop guard restores unless it already is.
    restored: AtomicBool,
    /// Bytes of session output dropped past [`SUSPEND_OUTPUT_BUFFER_BYTES`]
    /// during the current (or most recent) suspension.
    dropped: AtomicU64,
    /// Bytes currently held in the suspend buffer, head-first.
    buffered: AtomicU64,
    /// SIGHUP was seen: the exit-cause line says so.
    hangup: AtomicBool,
    /// The write end of the wake pipe; the pump polls the read end. A byte
    /// wakes the pump out of poll so it services commands and signals.
    wake: OwnedFd,
}

impl RelayInner {
    fn lock(&self) -> std::sync::MutexGuard<'_, SharedState> {
        self.state
            .lock()
            .expect("the relay state lock is never held across a panic")
    }

    fn wake(&self) {
        // A full pipe already holds a pending wakeup, so a refused byte
        // loses nothing.
        let _ = write(&self.wake, b"k");
    }

    /// Queue a command and wake the pump.
    fn command(&self, ctl: Ctl) {
        self.lock().command = Some(ctl);
        self.wake();
    }
}

// ---------------------------------------------------------------------------
// Handle & lease
// ---------------------------------------------------------------------------

/// The prompt hook [`crate::attach::run_interactive_attach`] runs beside a
/// relay: called once, from its own thread, with the relay's handle, and
/// free to [`RelayHandle::suspend`] the relay, own the terminal for as long
/// as it takes, and [`RelayHandle::resume`] it. Owned (`Box`) because it
/// runs on its own thread and must not borrow the caller's stack.
pub type SuspendHook = Box<dyn FnOnce(&RelayHandle) + Send>;

/// The caller's hold on a running relay: enough to suspend it, hand the
/// terminal to a prompt, and take it back, and nothing else. Cheap to
/// clone, usable from any thread, and inert once the attach ended.
#[derive(Clone)]
pub struct RelayHandle {
    inner: Arc<RelayInner>,
}

impl RelayHandle {
    /// Stop forwarding input and put the real terminal back into its
    /// attach-start termios, then hand it to the caller.
    ///
    /// Blocks until the pump acknowledges, so the caller holds the terminal
    /// exclusively on return: nothing of the session reaches the real tty
    /// and nothing of the caller's reaches the session. ssh's output is
    /// drained into a buffer the whole time: the head (up to
    /// [`SUSPEND_OUTPUT_BUFFER_BYTES`]) is replayed on resume, the tail is
    /// dropped and counted, and ssh never blocks.
    ///
    /// Idempotent: suspending an already-suspended relay hands out another
    /// lease of the same terminal. Errors once the attach has ended.
    pub fn suspend(&self) -> Result<TtyLease, anyhow::Error> {
        let mut st = self.inner.lock();
        if st.finished {
            anyhow::bail!("the attach already ended; there is no terminal to suspend");
        }
        if !st.suspended {
            st.command = Some(Ctl::Suspend);
            drop(st);
            self.inner.wake();
            st = self.inner.lock();
            while !st.suspended {
                if st.finished {
                    anyhow::bail!("the attach ended while the relay was suspending");
                }
                st = self
                    .inner
                    .cv
                    .wait(st)
                    .expect("the relay state lock is never held across a panic");
            }
        }
        Ok(TtyLease {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Take the terminal back from a prompt and resume relaying.
    ///
    /// Idempotent: resuming a relay that is already running is a no-op, and
    /// so is resuming after the attach ended.
    pub fn resume(&self) {
        let mut st = self.inner.lock();
        if st.finished || !st.suspended {
            return;
        }
        st.command = Some(Ctl::Resume);
        drop(st);
        self.inner.wake();
        st = self.inner.lock();
        while st.suspended && !st.finished {
            st = self
                .inner
                .cv
                .wait(st)
                .expect("the relay state lock is never held across a panic");
        }
    }

    /// The suspend accounting: `(bytes buffered head-first, bytes dropped
    /// past the bound)` for the current suspension, zero when none is up.
    pub fn suspended_output(&self) -> (u64, u64) {
        (
            self.inner.buffered.load(Ordering::Acquire),
            self.inner.dropped.load(Ordering::Acquire),
        )
    }

    /// Whether a suspend is currently up.
    pub fn is_suspended(&self) -> bool {
        self.inner.lock().suspended
    }
}

/// The real terminal, handed back by [`RelayHandle::suspend`].
///
/// While a suspend is up the relay forwards nothing in either direction;
/// the terminal is in its attach-start termios and the caller may read and
/// write it through [`Self::as_fd`].
pub struct TtyLease {
    inner: Arc<RelayInner>,
}

impl TtyLease {
    /// The real terminal's fd: the stdin tty, or the `/dev/tty` crossterm
    /// would have used, in its attach-start termios.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.tty.input.as_fd()
    }

    /// Hand the terminal back to the relay (same as [`RelayHandle::resume`]).
    pub fn resume(self) {
        RelayHandle { inner: self.inner }.resume();
    }
}

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

/// A running interactive attach: the pump thread, the ssh child and the
/// caller's handle. [`Relay::join`] runs it to ssh's exit and returns
/// ssh's status unchanged: the code, or death by signal, exactly as a
/// plain wait would.
pub struct Relay {
    inner: Arc<RelayInner>,
    pump: Option<std::thread::JoinHandle<()>>,
    child: Option<Child>,
}

/// Put back the termios captured at attach start if it is not already in
/// force. The pump thread holds one for its whole life, so every exit path
/// (a normal break, an EOF, a signal, a panic unwinding the pump) restores
/// before the pump thread ends, and so before [`Relay::join`] returns.
struct TermiosRestore {
    inner: Arc<RelayInner>,
    attach_start: Termios,
}

impl Drop for TermiosRestore {
    fn drop(&mut self) {
        if self.inner.restored.swap(true, Ordering::AcqRel) {
            return;
        }
        match tcsetattr(&self.inner.tty.input, SetArg::TCSADRAIN, &self.attach_start) {
            // Best-effort, like ssh's own leave_raw_mode: a terminal that
            // refuses tcsetattr (a hung-up one) is beyond repair.
            Err(e) => {
                tracing::warn!("could not restore the terminal's termios after the attach: {e}")
            }
            Ok(()) => tracing::debug!(
                "tty relay: restored the real terminal's termios to {}",
                describe_termios(&self.attach_start)
            ),
        }
    }
}

/// The ends of the wake pipe, both close-on-exec and nonblocking (so a
/// signal handler never blocks on a full pipe). `pipe2` is not on macOS.
fn wake_pipe() -> Result<(OwnedFd, OwnedFd), anyhow::Error> {
    let (read_end, write_end) = pipe().context("opening the relay's wake pipe")?;
    for fd in [&read_end, &write_end] {
        fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .context("marking the relay's wake pipe close-on-exec")?;
        set_nonblocking(fd).context("making the relay's wake pipe nonblocking")?;
    }
    Ok((read_end, write_end))
}

/// Set `O_NONBLOCK` on `fd`. Only ever on fds the relay itself opened:
/// never on the real terminal, whose open file description is shared with
/// the user's shell (OpenSSH leaves ttys blocking for the same reason).
fn set_nonblocking(fd: &impl AsFd) -> Result<(), nix::Error> {
    let flags = fcntl(fd, FcntlArg::F_GETFL)?;
    fcntl(
        fd,
        FcntlArg::F_SETFL(OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK),
    )?;
    Ok(())
}

impl Relay {
    /// Spawn `cmd` (the ssh attach) on the slave end of a fresh pty pair,
    /// put the real terminal into ssh's raw set, and start the pump.
    ///
    /// On return the raw set is already in force, and every exit path from
    /// here on restores the termios captured now.
    pub(crate) fn start(mut cmd: Command, real: RealTty) -> Result<Self, anyhow::Error> {
        let attach_start = tcgetattr(&real.input)
            .context("reading the terminal's termios before the interactive attach")?;
        let raw = ssh_raw_termios(&attach_start);
        let initial_winsize =
            get_winsize(&real.input).context("reading the terminal size before the attach")?;

        // The slave starts as a copy of the real terminal, termios and size:
        // ssh reads both off its stdin, sends them as the remote pty's modes
        // and size, then puts the slave into its raw set itself, exactly as
        // it did with the real terminal.
        let pty = openpty(Some(&initial_winsize), Some(&attach_start))
            .context("opening the attach's pty pair")?;
        let (master, slave) = (pty.master, pty.slave);
        fcntl(&master, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .context("marking the pty master close-on-exec")?;
        set_nonblocking(&master).context("making the pty master nonblocking")?;
        cmd.stdin(Stdio::from(
            slave
                .try_clone()
                .context("duplicating the pty slave for ssh's stdin")?,
        ));
        cmd.stdout(Stdio::from(
            slave
                .try_clone()
                .context("duplicating the pty slave for ssh's stdout")?,
        ));
        // ssh's stderr stays inherited, as before. ssh leads a new session
        // whose controlling terminal is the slave: the kernel then delivers
        // SIGWINCH on a resize and SIGHUP when the master closes, and an
        // ssh prompt on /dev/tty goes through the relay rather than
        // stopping on SIGTTIN against a terminal it no longer leads.
        //
        // SAFETY: the closure runs in the forked child before exec and only
        // calls setsid(2) and ioctl(2), both async-signal-safe; stdio is
        // already in place, so fd 0 is the slave.
        unsafe {
            std::os::unix::process::CommandExt::pre_exec(&mut cmd, || {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let (wake_read, wake_write) = wake_pipe()?;
        if let Err(e) = install_relay_signals(&wake_write) {
            restore_relay_signals();
            return Err(e);
        }
        let mut child = match cmd.spawn() {
            Ok(child) => child,
            Err(e) => {
                restore_relay_signals();
                return Err(anyhow::Error::new(e).context("spawning the ssh attach"));
            }
        };
        // The master must be the only handle left on our side: while any
        // slave fd stays open the master never sees EOF, and EOF is how the
        // relay observes ssh exiting.
        drop(slave);
        let child_pid = child.id();

        if let Err(e) = tcsetattr(&real.input, SetArg::TCSADRAIN, &raw) {
            // Raw never went on, so the terminal is still as found.
            killpg(child_pid, libc::SIGKILL);
            // Reaping only; the attach failed either way.
            let _ = child.wait();
            restore_relay_signals();
            return Err(
                anyhow::Error::new(e).context("putting the terminal into raw mode for the attach")
            );
        }
        tracing::debug!(
            "tty relay: started ssh (pid {child_pid}) on a pty; real terminal now {}; \
             captured for restore {}; winsize {}x{}",
            describe_termios(&raw),
            describe_termios(&attach_start),
            initial_winsize.ws_col,
            initial_winsize.ws_row,
        );

        let inner = Arc::new(RelayInner {
            state: Mutex::new(SharedState::default()),
            cv: Condvar::new(),
            tty: real,
            restored: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            buffered: AtomicU64::new(0),
            hangup: AtomicBool::new(false),
            wake: wake_write,
        });
        let guard = TermiosRestore {
            inner: Arc::clone(&inner),
            attach_start: attach_start.clone(),
        };
        let pump_inner = Arc::clone(&inner);
        let spawned = std::thread::Builder::new()
            .name("tty-relay".into())
            .spawn(move || {
                pump(
                    master,
                    pump_inner,
                    wake_read,
                    child_pid,
                    attach_start,
                    raw,
                    guard,
                )
            });
        let pump = match spawned {
            Ok(t) => t,
            Err(e) => {
                // The closure (and with it the guard) was dropped unrun,
                // which already restored the termios and closed the master.
                let _ = child.wait();
                restore_relay_signals();
                return Err(anyhow::Error::new(e).context("starting the tty relay's pump thread"));
            }
        };

        Ok(Self {
            inner,
            pump: Some(pump),
            child: Some(child),
        })
    }

    /// The caller's hold on this relay.
    pub fn handle(&self) -> RelayHandle {
        RelayHandle {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Run to ssh's exit and return its status unchanged.
    ///
    /// `deadline` is a guard for tests: when it passes, ssh's group is
    /// killed and the failure is reported instead of hanging. On return the
    /// real terminal's termios is already restored, before any unwind codes
    /// the caller may still owe the tty.
    pub(crate) fn join(
        mut self,
        deadline: Option<Instant>,
    ) -> Result<std::process::ExitStatus, anyhow::Error> {
        let pump = self
            .pump
            .take()
            .expect("join is the only consumer of the pump thread");
        let pump_result = match deadline {
            None => pump.join(),
            Some(at) => {
                while !pump.is_finished() {
                    if Instant::now() >= at {
                        if let Some(child) = self.child.as_ref() {
                            killpg(child.id(), libc::SIGKILL);
                        }
                        self.inner.command(Ctl::Exit);
                        // The pump ends once the master closes; its guard
                        // restores on the way out.
                        let _ = pump.join();
                        restore_relay_signals();
                        anyhow::bail!("the tty relay did not exit before its deadline");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                pump.join()
            }
        };

        let mut child = self
            .child
            .take()
            .expect("join is the only consumer of the child");
        let status = child.wait().context("waiting for the ssh attach to exit")?;

        let cause = if pump_result.is_err() {
            "panic in the relay"
        } else if self.inner.hangup.load(Ordering::Acquire) {
            "hangup: SIGHUP of the real terminal closed the pty master"
        } else {
            match status.code() {
                None => "ssh died by a signal",
                Some(255) => "ssh transport drop (exit 255)",
                Some(_) => "ssh exited",
            }
        };
        tracing::debug!(
            "tty relay: exited, cause: {cause}; ssh status {status}; \
             termios restored on the real terminal"
        );
        restore_relay_signals();
        Ok(status)
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // Reached with the pump still running only on a panic or an early
        // return on the caller's side: the terminal must not outlive the
        // relay in raw mode. Tell the pump to stop and wait for its guard;
        // closing the master then hangs up ssh.
        if let Some(pump) = self.pump.take() {
            self.inner.command(Ctl::Exit);
            // A pump panic has already restored through its guard.
            let _ = pump.join();
            restore_relay_signals();
        }
    }
}

// ---------------------------------------------------------------------------
// The pump
// ---------------------------------------------------------------------------

/// Add `fd` to the poll set, returning its index.
fn push<'a>(fds: &mut Vec<PollFd<'a>>, fd: BorrowedFd<'a>, flags: PollFlags) -> Option<usize> {
    fds.push(PollFd::new(fd, flags));
    Some(fds.len() - 1)
}

/// Whether `idx`'s poll entry reported any of `wanted`.
fn ready(fds: &[PollFd<'_>], idx: Option<usize>, wanted: PollFlags) -> bool {
    idx.and_then(|i| fds.get(i))
        .and_then(PollFd::revents)
        .is_some_and(|e| e.intersects(wanted))
}

/// What every readiness check also accepts: a hung-up or broken fd is
/// "ready" so the read or write that follows can observe it, instead of
/// poll returning it forever unserviced.
fn ready_or_broken(want: PollFlags) -> PollFlags {
    want | PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL
}

/// The pump's mutable state across turns.
struct PumpState {
    /// Session output read from the master but not yet written to the real
    /// terminal. Frozen while suspended; replayed first on resume.
    pending_out: Vec<u8>,
    /// User keystrokes read from the real terminal but not yet written to
    /// the pty master. Order is preserved by never reading more input
    /// while this is non-empty.
    pending_in: Vec<u8>,
    /// The suspension's buffer: the head of ssh's output, replayed on
    /// resume; the tail past the bound is dropped and counted.
    suspend_buf: Vec<u8>,
    dropped: u64,
    suspended: bool,
    input_open: bool,
    /// The session's end of the pty has closed (ssh is gone).
    saw_eof: bool,
    /// When the resume's `rows − 1` nudge is due to be put back.
    nudge_back_at: Option<Instant>,
}

/// The relay loop. All of the real terminal's reads, writes and tcsetattr
/// live on this thread while the relay runs.
fn pump(
    master: OwnedFd,
    inner: Arc<RelayInner>,
    wake: OwnedFd,
    child_pid: u32,
    attach_start: Termios,
    raw: Termios,
    _restore: TermiosRestore,
) {
    let mut s = PumpState {
        pending_out: Vec::new(),
        pending_in: Vec::new(),
        suspend_buf: Vec::new(),
        dropped: 0,
        suspended: false,
        input_open: true,
        saw_eof: false,
        nudge_back_at: None,
    };
    let mut scratch = vec![0u8; IO_CHUNK_BYTES];

    loop {
        // 1. Commands from the handle.
        let command = inner.lock().command.take();
        match command {
            Some(Ctl::Exit) => break,
            Some(Ctl::Suspend) => {
                if !s.suspended {
                    suspend(&inner, &attach_start, &mut s);
                }
                inner.lock().suspended = true;
                inner.cv.notify_all();
            }
            Some(Ctl::Resume) => {
                if s.suspended {
                    resume(&inner, &master, &raw, &mut s);
                }
                inner.lock().suspended = false;
                inner.cv.notify_all();
            }
            None => {}
        }

        // 2. Signals: each flag is cleared before its work, so a signal
        // arriving mid-handling is not lost.
        if SIGWINCH_SEEN.swap(false, Ordering::AcqRel) {
            forward_winsize(&inner, &master);
        }
        if let Some(at) = s.nudge_back_at
            && Instant::now() >= at
        {
            s.nudge_back_at = None;
            forward_winsize(&inner, &master);
        }
        for (seen, sig) in [(&SIGINT_SEEN, libc::SIGINT), (&SIGTERM_SEEN, libc::SIGTERM)] {
            if seen.swap(false, Ordering::AcqRel) {
                tracing::debug!("tty relay: forwarding signal {sig} to ssh's process group");
                killpg(child_pid, sig);
            }
        }
        if SIGHUP_SEEN.swap(false, Ordering::AcqRel) {
            // The terminal is gone. Leaving the loop drops the master, so
            // ssh sees the hangup on its side, as it would have on the real
            // terminal.
            tracing::debug!("tty relay: SIGHUP, closing the pty master so ssh sees the hangup");
            inner.hangup.store(true, Ordering::Release);
            break;
        }

        // 3. The session is gone and everything read from it has reached
        // the terminal. A suspend up at that point keeps the terminal with
        // the prompt: the attach ends with ssh's status, and what the
        // suspension buffered has no session left to belong to.
        if s.saw_eof && (s.suspended || s.pending_out.is_empty()) {
            if s.suspended {
                tracing::debug!(
                    "tty relay: ssh exited while suspended; {} buffered bytes discarded",
                    s.suspend_buf.len()
                );
            }
            break;
        }

        // 4. Poll. The wake pipe makes commands and signals prompt; ssh's
        // exit arrives as EOF/hangup on the master. The only timeout is a
        // pending nudge.
        let mut fds = Vec::with_capacity(5);
        let wake_idx = push(&mut fds, wake.as_fd(), PollFlags::POLLIN);
        let input_idx = if s.input_open && !s.suspended && s.pending_in.is_empty() {
            push(&mut fds, inner.tty.input.as_fd(), PollFlags::POLLIN)
        } else {
            None
        };
        // Suspended, ssh's output is always read: no backpressure while a
        // prompt is up. Live, past high water the pty's kernel buffer is
        // the backpressure, as the real terminal's was.
        let read_master =
            !s.saw_eof && (s.suspended || s.pending_out.len() < LIVE_OUTPUT_HIGH_WATER);
        let master_read_idx = if read_master {
            push(&mut fds, master.as_fd(), PollFlags::POLLIN)
        } else {
            None
        };
        if !s.pending_in.is_empty() {
            // Only a wakeup: step 6 writes whenever input is pending.
            push(&mut fds, master.as_fd(), PollFlags::POLLOUT);
        }
        let output_idx = if s.suspended || s.pending_out.is_empty() {
            None
        } else {
            push(&mut fds, inner.tty.output.as_fd(), PollFlags::POLLOUT)
        };
        let timeout = match s.nudge_back_at {
            None => PollTimeout::NONE,
            Some(at) => {
                let left = at.saturating_duration_since(Instant::now()) + Duration::from_millis(1);
                PollTimeout::try_from(left).unwrap_or(PollTimeout::MAX)
            }
        };
        match poll(&mut fds, timeout) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(e) => {
                tracing::warn!("tty relay: poll failed, stopping: {e}");
                break;
            }
        }

        if ready(&fds, wake_idx, PollFlags::POLLIN) {
            // Drain every queued wakeup; the pipe is nonblocking.
            while read(&wake, &mut scratch).is_ok_and(|n| n > 0) {}
        }

        // 5. Real-tty input: read a chunk, hand it off to the pty in full.
        if ready(&fds, input_idx, ready_or_broken(PollFlags::POLLIN)) {
            match read(&inner.tty.input, &mut scratch) {
                Ok(0) | Err(nix::errno::Errno::EIO) => {
                    // The terminal went away without a SIGHUP; ssh keeps
                    // running until it exits on its own.
                    s.input_open = false;
                }
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
                Err(e) => {
                    tracing::warn!("tty relay: reading the real terminal failed: {e}");
                    s.input_open = false;
                }
                Ok(n) => s
                    .pending_in
                    .extend_from_slice(scratch.get(..n).unwrap_or_default()),
            }
        }

        // 6. Pending input to the pty master. The master is nonblocking:
        // EAGAIN leaves the rest for the next POLLOUT.
        while !s.pending_in.is_empty() {
            match write(&master, &s.pending_in) {
                Ok(n) => {
                    s.pending_in.drain(..n);
                }
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => break,
                Err(e) => {
                    // EIO: the slave is gone (ssh exited); the master read
                    // observes it.
                    if e != nix::errno::Errno::EIO {
                        tracing::warn!("tty relay: writing to the session's pty failed: {e}");
                    }
                    s.pending_in.clear();
                    break;
                }
            }
        }

        // 7. The pty master: ssh's session output, and, as EOF or EIO,
        // ssh's exit.
        if ready(&fds, master_read_idx, ready_or_broken(PollFlags::POLLIN)) {
            match read(&master, &mut scratch) {
                Ok(0) | Err(nix::errno::Errno::EIO) => {
                    s.saw_eof = true;
                    s.input_open = false;
                    s.pending_in.clear();
                }
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
                Err(e) => {
                    tracing::warn!("tty relay: reading the session's pty failed: {e}");
                    s.saw_eof = true;
                    s.input_open = false;
                    s.pending_in.clear();
                }
                Ok(n) => {
                    let chunk = scratch.get(..n).unwrap_or_default();
                    if s.suspended {
                        buffer_suspended(&inner, &mut s, chunk);
                    } else {
                        s.pending_out.extend_from_slice(chunk);
                    }
                }
            }
        }

        // 8. Pending output to the real terminal, one chunk per turn. The
        // real terminal stays blocking (see `set_nonblocking`), so a write
        // waits for the terminal to drain, as ssh's did.
        if ready(&fds, output_idx, ready_or_broken(PollFlags::POLLOUT)) {
            let end = s.pending_out.len().min(IO_CHUNK_BYTES);
            match write(
                &inner.tty.output,
                s.pending_out.get(..end).unwrap_or_default(),
            ) {
                Ok(n) => {
                    s.pending_out.drain(..n);
                }
                Err(nix::errno::Errno::EAGAIN | nix::errno::Errno::EINTR) => {}
                Err(e) => {
                    tracing::warn!("tty relay: writing the session's output failed: {e}");
                    s.pending_out.clear();
                }
            }
        }
    }

    // Finished: mark the relay inert and wake every handle waiter. The
    // guard restores the termios as this function returns.
    let mut st = inner.lock();
    st.finished = true;
    st.command = None;
    inner.cv.notify_all();
}

/// Copy the real terminal's current size to the session's pty.
fn forward_winsize(inner: &RelayInner, master: &impl AsFd) {
    match get_winsize(&inner.tty.input).and_then(|ws| set_winsize(master, ws).map(|()| ws)) {
        Ok(ws) => tracing::debug!(
            "tty relay: forwarded the terminal size to the session's pty: {}x{}",
            ws.ws_col,
            ws.ws_row
        ),
        Err(e) => tracing::warn!("tty relay: could not forward the terminal size: {e:#}"),
    }
}

/// Keep the head of a suspended session's output, drop and count the tail.
fn buffer_suspended(inner: &RelayInner, s: &mut PumpState, chunk: &[u8]) {
    let room = SUSPEND_OUTPUT_BUFFER_BYTES.saturating_sub(s.suspend_buf.len());
    let take = room.min(chunk.len());
    s.suspend_buf
        .extend_from_slice(chunk.get(..take).unwrap_or_default());
    let over = (chunk.len() - take) as u64;
    s.dropped += over;
    inner
        .buffered
        .store(s.suspend_buf.len() as u64, Ordering::Release);
    inner.dropped.store(s.dropped, Ordering::Release);
    if over > 0 {
        tracing::debug!(
            "tty relay: {over} bytes of session output dropped past the \
             {SUSPEND_OUTPUT_BUFFER_BYTES}-byte suspend bound ({} so far)",
            s.dropped
        );
    }
}

/// The pump's half of [`RelayHandle::suspend`]: everything the caller needs
/// true before they touch the terminal.
fn suspend(inner: &RelayInner, attach_start: &Termios, s: &mut PumpState) {
    s.suspended = true;
    s.suspend_buf.clear();
    s.dropped = 0;
    inner.buffered.store(0, Ordering::Release);
    inner.dropped.store(0, Ordering::Release);
    match tcsetattr(&inner.tty.input, SetArg::TCSADRAIN, attach_start) {
        Err(e) => tracing::warn!("tty relay: could not restore termios for the suspend: {e}"),
        Ok(()) => {
            inner.restored.store(true, Ordering::Release);
            tracing::debug!(
                "tty relay: suspended; real terminal handed back in {}",
                describe_termios(attach_start)
            );
        }
    }
}

/// The pump's half of [`RelayHandle::resume`]: queue the head, own up to
/// the dropped tail, nudge the session to repaint, and put the raw set and
/// the current size back. The queued bytes reach the terminal only after
/// raw is back on, from the pump's next turns.
fn resume(inner: &RelayInner, master: &impl AsFd, raw: &Termios, s: &mut PumpState) {
    s.suspended = false;
    // In order: whatever predates the prompt, then the buffered head, then
    // (only when bytes were dropped) the one visible line.
    s.pending_out.append(&mut s.suspend_buf);
    if s.dropped > 0 {
        let line = format!("\r\n{}{DROP_LINE_SUFFIX}\r\n", s.dropped);
        s.pending_out.extend_from_slice(line.as_bytes());
        // The warn mirrors the visible line, so the log and the tty tell
        // the same story about what the prompt cost.
        tracing::warn!("{}{DROP_LINE_SUFFIX}", s.dropped);
    }

    match tcsetattr(&inner.tty.input, SetArg::TCSADRAIN, raw) {
        Err(e) => tracing::warn!("tty relay: could not re-enter raw mode after the resume: {e}"),
        Ok(()) => inner.restored.store(false, Ordering::Release),
    }

    // Nudge the pty size (rows − 1 now, the current size after
    // NUDGE_SETTLE) so the session repaints on its own SIGWINCH: its screen
    // moved on while the user could not see it. Never an unwind or reset
    // code: this is the session's pty, not the user's terminal.
    match get_winsize(&inner.tty.input) {
        Ok(ws) if ws.ws_row >= 2 => {
            let smaller = Winsize {
                ws_row: ws.ws_row - 1,
                ..ws
            };
            if let Err(e) = set_winsize(master, smaller) {
                tracing::warn!("tty relay: could not nudge the session's size: {e:#}");
            }
            s.nudge_back_at = Some(Instant::now() + NUDGE_SETTLE);
        }
        _ => forward_winsize(inner, master),
    }
    tracing::debug!(
        "tty relay: resumed; {} bytes of session output dropped while the prompt was up",
        s.dropped
    );
    s.dropped = 0;
    inner.buffered.store(0, Ordering::Release);
    inner.dropped.store(0, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};
    use std::os::unix::process::ExitStatusExt as _;
    use std::sync::MutexGuard;

    /// The relay owns process-wide signal dispositions, so its tests run one
    /// at a time even under a threaded test runner.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn serial() -> MutexGuard<'static, ()> {
        SERIAL.lock().unwrap_or_else(|e| e.into_inner())
    }

    const WAIT: Duration = Duration::from_secs(20);

    /// A stand-in for the user's terminal: a pty pair whose slave the relay
    /// takes as the real tty, and whose master the test types into and
    /// reads the screen from. A reader thread drains the master the whole
    /// time, as a terminal emulator would.
    struct FakeTerminal {
        master: std::fs::File,
        slave: OwnedFd,
        screen: Arc<Mutex<Vec<u8>>>,
    }

    impl FakeTerminal {
        fn new(rows: u16, cols: u16) -> Self {
            let ws = Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            let pty = openpty(Some(&ws), None).unwrap();
            let master = std::fs::File::from(pty.master);
            let screen = Arc::new(Mutex::new(Vec::new()));
            let mut reader = master.try_clone().unwrap();
            let sink = Arc::clone(&screen);
            std::thread::spawn(move || {
                let mut buf = [0u8; 65536];
                loop {
                    match reader.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => sink.lock().unwrap().extend_from_slice(&buf[..n]),
                        // A signal can interrupt this read on some
                        // targets (emulated ones among them).
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            });
            Self {
                master,
                slave: pty.slave,
                screen,
            }
        }

        fn real(&self) -> RealTty {
            RealTty::from_fds(
                self.slave.try_clone().unwrap(),
                self.slave.try_clone().unwrap(),
            )
        }

        fn termios(&self) -> Termios {
            tcgetattr(&self.slave).unwrap()
        }

        fn resize(&self, rows: u16, cols: u16) {
            let ws = Winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            set_winsize(&self.master, ws).unwrap();
        }

        fn type_bytes(&self, bytes: &[u8]) {
            let mut master = self.master.try_clone().unwrap();
            let bytes = bytes.to_vec();
            // Its own thread: a large paste outruns the pty's buffer and
            // must not block the test that is reading the echo.
            std::thread::spawn(move || master.write_all(&bytes).unwrap());
        }

        fn screen(&self) -> Vec<u8> {
            self.screen.lock().unwrap().clone()
        }

        fn wait_for(&self, what: &str, pred: impl Fn(&[u8]) -> bool) -> Vec<u8> {
            let until = Instant::now() + WAIT;
            loop {
                let screen = self.screen();
                if pred(&screen) {
                    return screen;
                }
                assert!(
                    Instant::now() < until,
                    "timed out waiting for {what}; screen so far: {:?}",
                    String::from_utf8_lossy(&screen)
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }

        fn wait_for_text(&self, text: &str) -> Vec<u8> {
            self.wait_for(text, |s| contains(s, text.as_bytes()))
        }
    }

    /// A termios as the modes it sets. Compared field by field because nix
    /// keeps a stale copy of the raw struct inside; with macOS's PENDIN
    /// masked (the kernel sets that bit on its own when there is input to
    /// reprint, it is no mode anyone chose); and over the named control
    /// characters only (Linux's kernel keeps fewer than libc's `NCCS`, so
    /// the tail of the array is whatever was on the stack).
    type Mode = (
        InputFlags,
        OutputFlags,
        nix::sys::termios::ControlFlags,
        LocalFlags,
        Vec<u8>,
    );

    fn mode(t: &Termios) -> Mode {
        use SpecialCharacterIndices as C;
        let named = [
            C::VEOF,
            C::VEOL,
            C::VERASE,
            C::VINTR,
            C::VKILL,
            C::VMIN,
            C::VQUIT,
            C::VSTART,
            C::VSTOP,
            C::VSUSP,
            C::VTIME,
            C::VLNEXT,
            C::VWERASE,
            C::VREPRINT,
            C::VDISCARD,
        ];
        (
            t.input_flags,
            t.output_flags,
            t.control_flags,
            t.local_flags - LocalFlags::PENDIN,
            named.iter().map(|&i| t.control_chars[i as usize]).collect(),
        )
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    /// The session side: a shell that puts its pty into the raw set ssh
    /// would, prints `R` to say so, then runs `script`.
    fn session(script: &str) -> Command {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(format!("stty raw -echo -iexten; printf R; {script}"));
        cmd
    }

    fn deadline() -> Option<Instant> {
        Some(Instant::now() + WAIT)
    }

    fn raise(sig: libc::c_int) {
        // SAFETY: kill(2) on our own pid has no memory-safety preconditions.
        assert_eq!(unsafe { libc::kill(libc::getpid(), sig) }, 0);
    }

    fn seq_output(n: u32) -> Vec<u8> {
        (1..=n)
            .flat_map(|i| format!("{i}\n").into_bytes())
            .collect()
    }

    #[test]
    fn relay_copies_bytes_both_ways_in_order() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        // A paste far larger than any pty buffer, with all 256 byte values
        // in a pattern whose order is checkable.
        let paste: Vec<u8> = (0..256 * 1024u32).map(|i| (i * 7 % 256) as u8).collect();
        let relay =
            Relay::start(session(&format!("head -c {}", paste.len())), term.real()).unwrap();
        term.wait_for_text("R");
        term.type_bytes(&paste);
        let screen = term.wait_for("the paste's echo", |s| s.len() > paste.len());
        let status = relay.join(deadline()).unwrap();
        assert!(status.success());
        assert_eq!(
            &screen[1..],
            &paste[..],
            "bytes lost or reordered in the relay"
        );
    }

    #[test]
    fn chord_bytes_pass_through_unmodified() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let keys = sessions::keys::SessionKeys::default();
        // Every control byte (the termios specials among them: ^C ^Z ^\
        // ^S ^Q ^V ^O ^D ^T), DEL, and each encoding of the default leader
        // and detach key.
        let mut chord: Vec<u8> = (0x00..=0x1f).chain([0x7f]).collect();
        for enc in keys.leader.encodings() {
            chord.extend(enc);
        }
        for enc in keys.detach_key.encodings() {
            chord.extend(enc);
        }
        let relay =
            Relay::start(session(&format!("head -c {}", chord.len())), term.real()).unwrap();
        term.wait_for_text("R");
        term.type_bytes(&chord);
        let screen = term.wait_for("the chord's echo", |s| s.len() > chord.len());
        assert!(relay.join(deadline()).unwrap().success());
        assert_eq!(&screen[1..], &chord[..]);
    }

    #[test]
    fn client_raw_mode_matches_ssh_raw_set() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let start = term.termios();
        let raw = ssh_raw_termios(&start);

        // OpenSSH's enter_raw_mode, flag by flag.
        assert!(raw.input_flags.contains(InputFlags::IGNPAR));
        for flag in [
            InputFlags::ISTRIP,
            InputFlags::INLCR,
            InputFlags::IGNCR,
            InputFlags::ICRNL,
            InputFlags::IXON,
            InputFlags::IXANY,
            InputFlags::IXOFF,
        ] {
            assert!(!raw.input_flags.contains(flag), "{flag:?} still set");
        }
        for flag in [
            LocalFlags::ISIG,
            LocalFlags::ICANON,
            LocalFlags::ECHO,
            LocalFlags::ECHOE,
            LocalFlags::ECHOK,
            LocalFlags::ECHONL,
            LocalFlags::IEXTEN,
        ] {
            assert!(!raw.local_flags.contains(flag), "{flag:?} still set");
        }
        assert!(!raw.output_flags.contains(OutputFlags::OPOST));
        assert_eq!(raw.control_chars[SpecialCharacterIndices::VMIN as usize], 1);
        assert_eq!(
            raw.control_chars[SpecialCharacterIndices::VTIME as usize],
            0
        );
        // Nothing ssh leaves alone moves.
        assert_eq!(raw.control_flags, start.control_flags);
        assert_eq!(
            raw.control_chars[SpecialCharacterIndices::VINTR as usize],
            start.control_chars[SpecialCharacterIndices::VINTR as usize]
        );

        // And that set is what the real terminal is in while attached.
        let relay = Relay::start(session("head -c 1 >/dev/null"), term.real()).unwrap();
        term.wait_for_text("R");
        assert_eq!(mode(&term.termios()), mode(&raw));
        term.type_bytes(b"x");
        assert!(relay.join(deadline()).unwrap().success());
        assert_eq!(mode(&term.termios()), mode(&start));
    }

    #[test]
    fn winsize_follows_sigwinch() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let relay = Relay::start(
            session(r#"stty size; while c=$(head -c 1); [ "$c" != q ]; do stty size; done"#),
            term.real(),
        )
        .unwrap();
        // The session starts at the real terminal's size.
        term.wait_for_text("24 80\n");

        term.resize(40, 100);
        raise(libc::SIGWINCH);
        let until = Instant::now() + WAIT;
        while !contains(&term.screen(), b"40 100\n") {
            assert!(
                Instant::now() < until,
                "the resize never reached the session"
            );
            term.type_bytes(b"s");
            std::thread::sleep(Duration::from_millis(50));
        }
        term.type_bytes(b"q");
        assert!(relay.join(deadline()).unwrap().success());
    }

    #[test]
    fn termios_restored_on_transport_drop() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let start = term.termios();
        // ssh reports a dropped transport as 255.
        let relay = Relay::start(session("head -c 1 >/dev/null; exit 255"), term.real()).unwrap();
        term.wait_for_text("R");
        assert_ne!(mode(&term.termios()), mode(&start));
        term.type_bytes(b"x");
        let status = relay.join(deadline()).unwrap();
        assert_eq!(status.code(), Some(255));
        assert_eq!(mode(&term.termios()), mode(&start));
    }

    #[test]
    fn termios_restored_on_panic() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let start = term.termios();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _relay = Relay::start(session("while :; do sleep 1; done"), term.real()).unwrap();
            term.wait_for_text("R");
            assert_ne!(mode(&term.termios()), mode(&start));
            panic!("a caller panicking mid-attach");
        }));
        assert!(outcome.is_err());
        assert_eq!(mode(&term.termios()), mode(&start));
    }

    #[test]
    fn client_signal_restores_termios_and_reaches_ssh() {
        let _serial = serial();
        for (sig, name) in [(libc::SIGTERM, "TERM"), (libc::SIGINT, "INT")] {
            let term = FakeTerminal::new(24, 80);
            let start = term.termios();
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c").arg(format!(
                "trap 'printf {name}; exit 7' {name}; stty raw -echo -iexten; printf R; \
                 while :; do sleep 1; done"
            ));
            let relay = Relay::start(cmd, term.real()).unwrap();
            term.wait_for_text("R");
            raise(sig);
            // ssh's side saw the very signal the client got.
            term.wait_for_text(name);
            let status = relay.join(deadline()).unwrap();
            assert_eq!(status.code(), Some(7), "{name}");
            assert_eq!(mode(&term.termios()), mode(&start), "{name}");
        }
    }

    #[test]
    fn ssh_exit_status_maps_unchanged() {
        let _serial = serial();
        for script in [
            "exit 0",
            "exit 3",
            "exit 255",
            "kill -KILL $$",
            "kill -TERM $$",
        ] {
            let plain = Command::new("/bin/sh")
                .arg("-c")
                .arg(script)
                .status()
                .unwrap();
            let term = FakeTerminal::new(24, 80);
            let relayed = Relay::start(session(script), term.real())
                .unwrap()
                .join(deadline())
                .unwrap();
            assert_eq!(relayed, plain, "{script}");
            assert_eq!(relayed.signal(), plain.signal(), "{script}");
        }
    }

    #[test]
    fn suspend_hands_back_attach_start_termios() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let start = term.termios();
        let relay = Relay::start(session("head -c 1 >/dev/null"), term.real()).unwrap();
        term.wait_for_text("R");
        let handle = relay.handle();

        let lease = handle.suspend().unwrap();
        assert_eq!(mode(&term.termios()), mode(&start));
        assert_eq!(mode(&tcgetattr(lease.as_fd()).unwrap()), mode(&start));
        lease.resume();
        assert_eq!(mode(&term.termios()), mode(&ssh_raw_termios(&start)));

        term.type_bytes(b"x");
        assert!(relay.join(deadline()).unwrap().success());
        assert_eq!(mode(&term.termios()), mode(&start));
    }

    /// Suspend while the session is about to print `seq 1 200000` (about
    /// 1.2 MiB) and wait for all of it, plus the `Z` after it, to land in
    /// the relay with nothing resumed: ssh never blocked.
    fn suspend_through_a_flood(term: &FakeTerminal, then: &str) -> (Relay, RelayHandle) {
        let relay = Relay::start(
            session(&format!(
                "head -c 1 >/dev/null; printf G; sleep 1; seq 1 200000; printf Z; {then}"
            )),
            term.real(),
        )
        .unwrap();
        term.wait_for_text("R");
        term.type_bytes(b"g");
        term.wait_for_text("G");
        let handle = relay.handle();
        handle.suspend().unwrap();
        let total = seq_output(200_000).len() as u64 + 1;
        let until = Instant::now() + WAIT;
        while {
            let (buffered, dropped) = handle.suspended_output();
            buffered + dropped < total
        } {
            assert!(
                Instant::now() < until,
                "the session blocked while suspended"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        (relay, handle)
    }

    #[test]
    fn suspend_keeps_head_and_drops_tail_past_bound() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let (relay, handle) = suspend_through_a_flood(&term, "head -c 1 >/dev/null");
        let flood = seq_output(200_000);
        let total = flood.len() as u64 + 1;
        let (buffered, dropped) = handle.suspended_output();
        assert_eq!(buffered, SUSPEND_OUTPUT_BUFFER_BYTES as u64);
        assert_eq!(dropped, total - buffered);
        // Nothing reached the terminal while the prompt held it.
        assert_eq!(term.screen(), b"RG");

        handle.resume();
        let line = format!("\r\n{dropped}{DROP_LINE_SUFFIX}\r\n");
        let screen = term.wait_for_text(&line);
        let replay = &screen[2..];
        assert_eq!(
            &replay[..SUSPEND_OUTPUT_BUFFER_BYTES],
            &flood[..SUSPEND_OUTPUT_BUFFER_BYTES],
            "the head was not kept in order"
        );
        assert_eq!(&replay[SUSPEND_OUTPUT_BUFFER_BYTES..], line.as_bytes());

        term.type_bytes(b"x");
        assert!(relay.join(deadline()).unwrap().success());
    }

    #[test]
    fn resume_after_drop_prints_line_and_nudges_winsize() {
        let _serial = serial();
        let term = FakeTerminal::new(30, 90);
        let start = term.termios();
        let (relay, handle) = suspend_through_a_flood(
            &term,
            "i=0; while [ $i -lt 60 ]; do stty size; sleep 0.05; i=$((i+1)); done",
        );
        let (_, dropped_at_least) = handle.suspended_output();
        assert!(dropped_at_least > 0);

        handle.resume();
        assert_eq!(mode(&term.termios()), mode(&ssh_raw_termios(&start)));
        let screen = term.wait_for("the nudge and the size back", |s| {
            let Some(at) = s.windows(9).position(|w| w == b"29 90\n30 ") else {
                return false;
            };
            contains(&s[at..], b"30 90\n")
        });
        let text = String::from_utf8_lossy(&screen);
        assert_eq!(
            text.matches(DROP_LINE_SUFFIX).count(),
            1,
            "exactly one drop line: {text}"
        );
        let line_at = text.find(DROP_LINE_SUFFIX).unwrap();
        let count: u64 = text[..line_at]
            .rsplit("\r\n")
            .next()
            .unwrap()
            .parse()
            .unwrap();
        assert!(count >= dropped_at_least);
        // The session's size only ever read 30x90, or 29x90 while nudged,
        // and it came back.
        let after = &text[line_at..];
        assert!(after.contains("29 90\n"));
        assert!(after.rsplit("29 90\n").next().unwrap().contains("30 90\n"));
        // No unwind or reset codes: nothing the relay wrote is an escape.
        assert!(
            !screen.contains(&0x1b),
            "the relay wrote an escape sequence"
        );

        assert!(relay.join(deadline()).unwrap().success());
    }

    #[test]
    fn suspend_and_resume_are_idempotent() {
        let _serial = serial();
        let term = FakeTerminal::new(24, 80);
        let start = term.termios();
        let raw = ssh_raw_termios(&start);
        let relay = Relay::start(session("head -c 1 >/dev/null"), term.real()).unwrap();
        term.wait_for_text("R");
        let handle = relay.handle();

        // Resuming a running relay is a no-op.
        handle.resume();
        assert!(!handle.is_suspended());
        assert_eq!(mode(&term.termios()), mode(&raw));

        let first = handle.suspend().unwrap();
        let second = handle.suspend().unwrap();
        assert!(handle.is_suspended());
        assert_eq!(mode(&term.termios()), mode(&start));
        drop(first);
        drop(second);

        handle.resume();
        handle.resume();
        assert!(!handle.is_suspended());
        assert_eq!(mode(&term.termios()), mode(&raw));

        term.type_bytes(b"x");
        assert!(relay.join(deadline()).unwrap().success());
        // Once the attach ended: no terminal to suspend, nothing to resume.
        assert!(handle.suspend().is_err());
        handle.resume();
        assert_eq!(mode(&term.termios()), mode(&start));
    }
}
