//! The client-owned terminal relay for interactive attaches.
//!
//! `min session attach` (interactive) used to `exec()` ssh, or wait on it
//! with the user's terminal handed over wholesale: ssh owned the tty, put
//! it in its own raw mode and restored it on exit. That works until the
//! client needs the terminal *during* the attach — the dynamic-ingress
//! `ask` prompt (NET-045) has to interrupt the session output and borrow
//! the real tty to ask the attached human something, and nothing can do
//! that from outside ssh.
//!
//! So the attach moves behind a relay the client owns:
//!
//! ```text
//!   real tty ──┐
//!   (stdin or  │  read/write, termios owned by the relay
//!   /dev/tty) ─┘
//!        │
//!      poll(2) pump ─── pty master ─── pty slave = ssh's stdio (-tt)
//! ```
//!
//! ssh is spawned on the slave end of an [`openpty`] pair and the relay
//! keeps the *real* terminal in the same raw set ssh applied itself
//! ([`ssh_raw_termios`]: `cfmakeraw`, ISIG/IXON/IEXTEN off) — so the
//! session-key chord still arrives as data ([`sessions::keys`]'s raw-tty
//! premise) and every byte flows through in full chunks, in order, with
//! no line discipline in the way.
//!
//! Restore discipline: the termios captured at attach start is put back on
//! *every* exit path — ssh exiting, the transport dropping, SIGINT/SIGTERM
//! forwarded to ssh's process group, SIGHUP closing the master, and a
//! panic anywhere in the relay (a drop guard the pump thread holds). A
//! [`RelayHandle::suspend`] hands the real tty back to the caller (with
//! attach-start termios) while the relay keeps draining ssh — buffered
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
use std::time::Instant;

use anyhow::Context as _;
use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
use nix::poll::{PollFd, PollFlags, PollTimeout, poll};
use nix::pty::{Winsize, openpty};
use nix::sys::stat::Mode;
use nix::sys::termios::{
    InputFlags, LocalFlags, OutputFlags, SetArg, Termios, cfmakeraw, tcgetattr, tcsetattr,
};
use nix::unistd::{pipe2, read, write};

/// While a suspend is up, ssh's output is buffered up to this many bytes:
/// the head is kept for replay on resume and the tail beyond is dropped and
/// counted. Bounded so a chatty session cannot wedge the client on memory,
/// and a *fixed* bound because the prompt — not the session — owns the
/// terminal while it is up.
pub const SUSPEND_OUTPUT_BUFFER_BYTES: usize = 1024 * 1024;

/// The visible line [`RelayHandle::resume`] prints on the tty when output
/// past the suspend bound had to be dropped, with the byte count up front.
pub const DROP_LINE_SUFFIX: &str = " bytes of session output dropped while the prompt was up";

/// The largest chunk the pump reads per direction in one turn. Bytes flow
/// in full chunks: a read is handed off as one write, split only if the
/// kernel refuses part of it (then the remainder is the first thing the
/// next turn writes — order is preserved by the pending buffers).
const IO_CHUNK_BYTES: usize = 64 * 1024;

/// While relaying live (not suspended), the pump stops reading the
/// session's output once this much is undelivered to the terminal. The
/// pty's own kernel buffer then absorbs the rest — and once that fills,
/// ssh blocks in its write, exactly as it would against a plain tty. The
/// bound keeps the relay's memory flat without ever shedding session
/// bytes that were already owed to the terminal. Comfortably above
/// [`SUSPEND_OUTPUT_BUFFER_BYTES`] so a suspend's replay (which lands in
/// the same queue) never trips it.
const LIVE_OUTPUT_HIGH_WATER: usize = 4 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Signals
//
// The handlers do only what is async-signal-safe: raise a flag, and kick the
// pump's ctl pipe. The pump runs without SA_RESTART, so a signal that
// interrupts its own poll(2) surfaces as EINTR; one delivered to any other
// thread of the process (a multi-threaded CLI has several) surfaces as the
// kick byte. Either way the pump services the flags on its next turn, which
// is the same turn. No locks, no allocation.
// ---------------------------------------------------------------------------

static SIGWINCH_SEEN: AtomicBool = AtomicBool::new(false);
static SIGINT_SEEN: AtomicBool = AtomicBool::new(false);
static SIGTERM_SEEN: AtomicBool = AtomicBool::new(false);
static SIGHUP_SEEN: AtomicBool = AtomicBool::new(false);

/// The relay's ctl-pipe write end, published for the signal handlers as a
/// raw fd: a signal is out-of-band to poll(2) — the kernel may deliver it to
/// any thread, and one that lands off the pump never interrupts the pump's
/// wait — so each handler also writes one byte into the pipe, making the
/// signal a poll event the pump services at once (the self-pipe trick).
/// Published only while a relay runs, and cleared before its fd is ever
/// closed, so a handler can never touch a stale descriptor number.
static SIGNAL_KICK: AtomicI32 = AtomicI32::new(-1);

/// Best-effort one-byte kick to the pump: a failed write (no relay running)
/// only means the flags wait for a pump that is gone too.
fn kick_pump() {
    let fd = SIGNAL_KICK.load(Ordering::Acquire);
    if fd >= 0 {
        let byte = 1u8;
        // SAFETY: write(2) is async-signal-safe, and the fd is valid for as
        // long as it is published (see `SIGNAL_KICK`).
        let _ = unsafe { libc::write(fd, &byte as *const u8 as *const libc::c_void, 1) };
    }
}

extern "C" fn on_sigwinch(_: libc::c_int) {
    SIGWINCH_SEEN.store(true, Ordering::Release);
    kick_pump();
}

extern "C" fn on_sigint(_: libc::c_int) {
    SIGINT_SEEN.store(true, Ordering::Release);
    kick_pump();
}

extern "C" fn on_sigterm(_: libc::c_int) {
    SIGTERM_SEEN.store(true, Ordering::Release);
    kick_pump();
}

extern "C" fn on_sighup(_: libc::c_int) {
    SIGHUP_SEEN.store(true, Ordering::Release);
    kick_pump();
}

/// The dispositions the relay replaced, put back when the relay exits. A
/// plain process-global stack: one relay per process at a time (the CLI
/// attaches once; nextest runs one test per process).
static SAVED_SIGNALS: Mutex<Vec<(libc::c_int, libc::sigaction)>> = Mutex::new(Vec::new());

/// Install the relay's flag-raising handlers; saved dispositions are
/// restored by [`restore_relay_signals`]. Wired over `libc` directly
/// because the crate's nix features are exactly `term` and `poll` — the
/// `signal` feature is not part of that set.
fn install_relay_signals() -> Result<(), anyhow::Error> {
    // No SA_RESTART on purpose: the pump must see EINTR to service the
    // flags promptly.
    let mut saved = SAVED_SIGNALS.lock().unwrap();
    for (sig, handler) in [
        (libc::SIGWINCH, on_sigwinch as extern "C" fn(libc::c_int)),
        (libc::SIGINT, on_sigint),
        (libc::SIGTERM, on_sigterm),
        (libc::SIGHUP, on_sighup),
    ] {
        let action = unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = handler as usize;
            libc::sigemptyset(&mut action.sa_mask);
            action
        };
        let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
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
    // Retract the handlers' kick fd before anything can close it, so a late
    // signal writes nowhere.
    SIGNAL_KICK.store(-1, Ordering::Release);
    let saved = {
        let mut saved = SAVED_SIGNALS.lock().unwrap();
        std::mem::take(&mut *saved)
    };
    for (sig, action) in saved.into_iter().rev() {
        let _ = unsafe { libc::sigaction(sig, &action, std::ptr::null_mut()) };
    }
}

/// Signal `pgid`'s whole group. The relay's children run in their own
/// group (see [`Relay::start`]), so a forwarded SIGINT/SIGTERM reaches ssh
/// *and* the proxy it forked — everyone the terminal's signal was for.
fn killpg(pgid: u32, sig: libc::c_int) -> bool {
    unsafe { libc::killpg(pgid as libc::pid_t, sig) == 0 }
}

// ---------------------------------------------------------------------------
// winsize
// ---------------------------------------------------------------------------

/// Read a terminal's size. The relay mirrors ssh: it resizes the *pty* the
/// session runs on, and the size it copies is the real terminal's.
fn get_winsize(fd: &impl AsFd) -> Result<Winsize, anyhow::Error> {
    let mut ws = Winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let rc = unsafe { libc::ioctl(fd.as_fd().as_raw_fd(), libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 {
        return Err(anyhow::anyhow!(
            "reading the terminal size: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(ws)
}

/// Set the size of the terminal `fd` is an end of. On a pty pair the ioctl
/// is made against the master; the slave (the session's terminal) follows.
fn set_winsize(fd: &impl AsFd, ws: Winsize) -> Result<(), anyhow::Error> {
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
/// attach runs: exactly the set ssh applied itself before this change, so
/// the session-key leader rule's raw-tty premise
/// ([`sessions::keys`]: the chord must reach the app as data) still holds.
///
/// `cfmakeraw` (what ssh's `enter_raw_mode` calls) clears ISIG, IXON and
/// IEXTEN among its set; the removals are restated because the whole point
/// is those three: no SIGINT/SIGQUIT/SIGTSTP from control bytes, no flow
/// control eating ctrl-S/ctrl-Q, and no extended input processing — the
/// leader byte is data, end to end.
pub fn ssh_raw_termios(base: &Termios) -> Termios {
    let mut raw = base.clone();
    cfmakeraw(&mut raw);
    raw.input_flags.remove(InputFlags::IXON);
    raw.local_flags
        .remove(LocalFlags::ISIG | LocalFlags::IEXTEN);
    raw
}

/// The few termios bits worth naming in a log line: what the relay put on
/// the terminal and what it will put back.
fn describe_termios(t: &Termios) -> String {
    let mut bits = Vec::new();
    let mut flag = |on: bool, name: &str| {
        if on {
            bits.push(name.to_string());
        }
    };
    flag(t.local_flags.contains(LocalFlags::ECHO), "echo");
    flag(t.local_flags.contains(LocalFlags::ICANON), "icanon");
    flag(t.local_flags.contains(LocalFlags::ISIG), "isig");
    flag(t.local_flags.contains(LocalFlags::IEXTEN), "iexten");
    flag(t.input_flags.contains(InputFlags::IXON), "ixon");
    flag(t.output_flags.contains(OutputFlags::OPOST), "opost");
    if bits.is_empty() {
        "raw: none of echo/icanon/isig/iexton/ixon/opost".to_string()
    } else {
        format!("raw set: none of [{}]", bits.join(","))
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
/// release and alternate-screen leave act on exactly that fd, so the relay
/// capturing its restore termios *after* crossterm leaves raw mode
/// captures the pre-TUI state — never crossterm's.
#[derive(Debug)]
pub struct RealTty {
    input: OwnedFd,
    output: OwnedFd,
}

impl RealTty {
    /// Take the real terminal: the user's stdin when it is a tty, the
    /// controlling terminal otherwise; output always goes to stdout, which
    /// is where ssh put the session's bytes today.
    pub fn acquire() -> Result<Self, anyhow::Error> {
        let input = if std::io::stdin().is_terminal() {
            nix::unistd::dup(std::io::stdin().as_fd())
                .context("duplicating stdin as the real terminal")?
        } else {
            nix::fcntl::open(
                "/dev/tty",
                OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC,
                Mode::empty(),
            )
            .context("opening /dev/tty as the real terminal: the interactive attach needs one")?
        };
        let output = nix::unistd::dup(std::io::stdout().as_fd())
            .context("duplicating stdout as the session's output")?;
        Ok(Self { input, output })
    }

    /// Build a relay target out of an explicit fd pair. Production goes
    /// through [`Self::acquire`]; tests drive the relay over their own pty.
    #[cfg(test)]
    pub(crate) fn from_fds(input: OwnedFd, output: OwnedFd) -> Self {
        Self { input, output }
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

/// A command from the handle to the pump. Wakes the pump through the ctl
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

#[derive(Default)]
struct Shared {
    mutex: Mutex<SharedState>,
    cv: Condvar,
}

/// What the caller and the pump share. The pump thread is the only writer
/// of the real terminal and its termios — single-writer discipline keeps
/// the reads, writes and tcsetattr race-free — so the captured termios
/// (`attach_start`, `raw`) moves *into* the pump instead of living here:
/// nix's `Termios` is not `Sync` (it hides a `RefCell`), and nothing but
/// the pump ever needs it anyway.
struct RelayInner {
    shared: Shared,
    tty: RealTty,
    /// True while the real terminal is in its attach-start state (never
    /// mind who put it there); the pump's drop guard restores unless it
    /// already is.
    restored: AtomicBool,
    /// Bytes of session output dropped past [`SUSPEND_OUTPUT_BUFFER_BYTES`]
    /// during the current (or most recent) suspension.
    dropped: AtomicU64,
    /// Bytes currently held in the suspend buffer, head-first.
    buffered: AtomicU64,
    /// SIGHUP was seen: the exit-cause line says so.
    hangup: AtomicBool,
    /// One end of the ctl pipe; the pump holds the other. Writing a byte
    /// wakes the pump out of poll so it services the command queue.
    kick: OwnedFd,
}

impl RelayInner {
    /// Queue a command and wake the pump.
    fn command(&self, ctl: Ctl) {
        {
            let mut st = self.shared.mutex.lock().unwrap();
            st.command = Some(ctl);
        }
        // One byte is one wakeup; the pump drains the pipe each turn.
        let _ = write(&self.kick, b"k");
    }
}

// ---------------------------------------------------------------------------
// Handle & lease
// ---------------------------------------------------------------------------

/// The prompt hook [`crate::attach::run_interactive_attach`] runs beside a
/// relay: called once, from its own thread, with the relay's handle — free
/// to [`RelayHandle::suspend`] the relay, own the terminal for as long as
/// it takes, and [`RelayHandle::resume`] it. Owned (`Box`) because it runs
/// on its own thread and must not borrow the caller's stack.
pub type SuspendHook = Box<dyn Fn(&RelayHandle) + Send + Sync>;

/// The caller's hold on a running relay: enough to suspend it, hand the
/// terminal to a prompt, and take it back — and nothing else. Cheap to
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
    /// drained into a buffer the whole time — the head (up to
    /// [`SUSPEND_OUTPUT_BUFFER_BYTES`]) is replayed on resume, the tail is
    /// dropped and counted, and ssh never blocks.
    ///
    /// Idempotent: suspending an already-suspended relay hands out another
    /// lease of the same terminal. Errors once the attach has ended.
    pub fn suspend(&self) -> Result<TtyLease, anyhow::Error> {
        let mut st = self.inner.shared.mutex.lock().unwrap();
        if st.finished {
            drop(st);
            anyhow::bail!("the attach already ended; there is no terminal to suspend");
        }
        if !st.suspended {
            st.command = Some(Ctl::Suspend);
            drop(st);
            let _ = write(&self.inner.kick, b"s");
            let mut st = self.inner.shared.mutex.lock().unwrap();
            while !st.suspended {
                if st.finished {
                    anyhow::bail!("the attach ended while the relay was suspending");
                }
                st = self.inner.shared.cv.wait(st).unwrap();
            }
        }
        Ok(TtyLease {
            inner: Arc::clone(&self.inner),
        })
    }

    /// Take the terminal back from a prompt and resume relaying.
    ///
    /// Idempotent: resuming a relay that is already running is a no-op, and
    /// so is resuming after the attach ended. See [`TtyLease::resume`] for
    /// the lease-consuming form.
    pub fn resume(&self) {
        let mut st = self.inner.shared.mutex.lock().unwrap();
        if st.finished || !st.suspended {
            return;
        }
        st.command = Some(Ctl::Resume);
        drop(st);
        let _ = write(&self.inner.kick, b"r");
        let mut st = self.inner.shared.mutex.lock().unwrap();
        while st.suspended {
            if st.finished {
                return;
            }
            st = self.inner.shared.cv.wait(st).unwrap();
        }
    }

    /// The suspend accounting: `(bytes buffered head-first, bytes dropped
    /// past the bound)` for the current or most recent suspension.
    pub fn suspended_output(&self) -> (u64, u64) {
        (
            self.inner.buffered.load(Ordering::Acquire),
            self.inner.dropped.load(Ordering::Acquire),
        )
    }

    /// Whether a suspend is currently up.
    pub fn is_suspended(&self) -> bool {
        self.inner.shared.mutex.lock().unwrap().suspended
    }
}

/// The real terminal, handed back by [`RelayHandle::suspend`].
///
/// While this exists the relay forwards nothing in either direction; the
/// terminal is in its attach-start termios and the caller may read and
/// write it through [`Self::as_fd`] (a tty is readable and writable).
/// [`Self::resume`] returns it.
pub struct TtyLease {
    inner: Arc<RelayInner>,
}

impl TtyLease {
    /// The real terminal's fd: the stdin tty, or the `/dev/tty` crossterm
    /// would have used, in its attach-start termios.
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.inner.tty.input.as_fd()
    }

    /// Hand the terminal back to the relay. Consumes the lease so the
    /// relay's single-writer discipline is not a promise, but a type.
    pub fn resume(self) {
        RelayHandle { inner: self.inner }.resume();
    }
}

// ---------------------------------------------------------------------------
// The relay
// ---------------------------------------------------------------------------

/// A running interactive attach: the pump thread, the ssh child and the
/// caller's handle. [`Relay::join`] runs it to ssh's exit and returns
/// ssh's status unchanged — the code, or death by signal, exactly as a
/// plain wait would.
pub struct Relay {
    inner: Arc<RelayInner>,
    pump: Option<std::thread::JoinHandle<()>>,
    child: Option<Child>,
}

/// Put back the termios captured at attach start if it is not already in
/// force. The pump thread holds one for its whole life, so every exit path
/// — a normal break, an EOF, a signal, a panic unwinding the pump —
/// restores before anything else runs. It owns the saved termios by value
/// (nix's `Termios` is not `Sync`, and only this thread ever needs it).
struct TermiosRestore {
    inner: Arc<RelayInner>,
    attach_start: Termios,
}

impl TermiosRestore {
    fn new(inner: Arc<RelayInner>, attach_start: Termios) -> Self {
        Self {
            inner,
            attach_start,
        }
    }

    fn restore(&self) {
        let already = self.inner.restored.swap(true, Ordering::AcqRel);
        if already {
            return;
        }
        match tcsetattr(&self.inner.tty.input, SetArg::TCSADRAIN, &self.attach_start) {
            Err(e) => {
                // Best-effort, like ssh's own leave_raw_mode: a terminal
                // that refuses tcsetattr is beyond repair and the process
                // is on its way out either way. Say so loudly once, since
                // the user's terminal is the thing at stake.
                tracing::warn!("could not restore the terminal's termios after the attach: {e}");
            }
            Ok(()) => tracing::debug!(
                "tty relay: restored the real terminal's termios (was: {})",
                describe_termios(&self.attach_start)
            ),
        }
    }
}

impl Drop for TermiosRestore {
    fn drop(&mut self) {
        self.restore();
    }
}

impl Relay {
    /// Spawn `cmd` (the ssh attach) on the slave end of a fresh pty pair,
    /// put the real terminal into ssh's raw set, and start the pump.
    ///
    /// On return the raw mode is already in force — a caller can tcgetattr
    /// and see it. `attach_start` (in the shared state) is what every exit
    /// path restores.
    pub(crate) fn start(mut cmd: Command, real: RealTty) -> Result<Self, anyhow::Error> {
        let attach_start = tcgetattr(&real.input)
            .context("reading the terminal's termios before the interactive attach")?;
        let raw = ssh_raw_termios(&attach_start);
        let initial_winsize =
            get_winsize(&real.input).context("reading the terminal size before the attach")?;
        // Nonblocking output so the pump can never wedge inside a write to a
        // terminal that stopped draining: a refused write stays in
        // `pending_out` for the next turn. (Poll-before-write alone does not
        // promise this — a poll-ready pty accepts *some* bytes, not the
        // whole chunk, and a blocking write would then block in the pump.)
        set_nonblocking(&real.output);

        // The pty pair starts in the same raw set: ssh re-asserts its own
        // (identical) raw mode on its side soon after, but until it does
        // the line discipline would eat the chord and echo the user's
        // keystrokes twice — the daemon's pty module notes the same
        // slave-hygiene traps. ssh's stdio is the slave end; ssh's stderr
        // stays inherited, as today.
        let pty =
            openpty(Some(&initial_winsize), Some(&raw)).context("opening the attach's pty pair")?;
        let (master, slave) = (pty.master, pty.slave);
        set_cloexec(&master);
        set_nonblocking(&master);
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
        // ssh in its own process group: SIGINT/SIGTERM forwarded to the
        // group reach ssh *and* the proxy it forked, exactly the processes
        // the terminal's signal was for.
        std::os::unix::process::CommandExt::process_group(&mut cmd, 0);
        let child = cmd.spawn().context("spawning the ssh attach")?;
        // The master must be the only handle left on our side: while any
        // slave fd stays open the master never sees EOF, and EOF is how
        // the relay observes ssh exiting.
        drop(slave);
        let child_pid = child.id();
        install_relay_signals()?;

        // Raw goes on now, on this thread, so a returned relay always has
        // it applied (the pump's guard owns the restore). From here on,
        // every failure path must put the terminal and the signals back.
        let result = Self::start_pump(
            raw,
            real,
            attach_start,
            child,
            child_pid,
            master,
            initial_winsize,
        );
        if result.is_err() {
            restore_relay_signals();
        }
        result
    }

    /// Post-spawn start: apply raw, build the shared state, run the pump.
    fn start_pump(
        raw: Termios,
        real: RealTty,
        attach_start: Termios,
        mut child: Child,
        child_pid: u32,
        master: OwnedFd,
        initial_winsize: Winsize,
    ) -> Result<Self, anyhow::Error> {
        if let Err(e) = tcsetattr(&real.input, SetArg::TCSADRAIN, &raw) {
            let _ = killpg(child_pid, libc::SIGKILL);
            let _ = child.wait();
            // Raw never went on, so this restore puts back a termios that
            // is almost surely already current — belt and braces.
            tcsetattr(&real.input, SetArg::TCSADRAIN, &attach_start).ok();
            return Err(
                anyhow::Error::new(e).context("putting the terminal into raw mode for the attach")
            );
        }
        tracing::debug!(
            "tty relay: started ssh (pid {child_pid}) on a pty; real terminal now: {}; \
             captured for restore: {}; winsize {}x{}",
            describe_termios(&raw),
            describe_termios(&attach_start),
            initial_winsize.ws_col,
            initial_winsize.ws_row,
        );

        let (ctl_read, kick) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
            .context("opening the relay's control pipe")?;
        // Publish the kick end for the signal handlers before the pump can
        // exist: from here on a signal is a poll event, not a lost wakeup.
        SIGNAL_KICK.store(kick.as_fd().as_raw_fd(), Ordering::Release);
        let inner = Arc::new(RelayInner {
            shared: Shared::default(),
            tty: real,
            restored: AtomicBool::new(false),
            dropped: AtomicU64::new(0),
            buffered: AtomicU64::new(0),
            hangup: AtomicBool::new(false),
            kick,
        });
        let pump_inner = Arc::clone(&inner);
        let pump_attach_start = attach_start.clone();
        let pump_raw = raw.clone();
        let pump = match std::thread::Builder::new()
            .name("tty-relay".into())
            .spawn(move || {
                pump(
                    master,
                    pump_inner,
                    ctl_read,
                    child_pid,
                    pump_attach_start,
                    pump_raw,
                )
            }) {
            Ok(t) => t,
            Err(e) => {
                // The guard never existed; restore explicitly before
                // unwinding the relay for good.
                let _ = killpg(child_pid, libc::SIGKILL);
                let _ = child.wait();
                tcsetattr(&inner.tty.input, SetArg::TCSADRAIN, &attach_start).ok();
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
    /// `deadline` is a guard for tests (and nothing else): when it passes,
    /// ssh's group is killed and the failure is reported instead of
    /// hanging. On return the real terminal's termios is already restored —
    /// before any unwind codes the caller may still owe the tty.
    pub(crate) fn join(
        mut self,
        deadline: Option<Instant>,
    ) -> Result<std::process::ExitStatus, anyhow::Error> {
        let pump = self
            .pump
            .take()
            .expect("join is the only consumer of the pump thread");

        // `None` waits forever (a real attach runs until the session
        // ends); a deadline turns a broken relay into a failed test
        // instead of a hung one. The notifier thread turns the pump's
        // panic, if any, into the cause line.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<Option<String>>();
        let notifier = std::thread::Builder::new()
            .name("tty-relay-join".into())
            .spawn(move || {
                let _ = done_tx.send(match pump.join() {
                    Ok(()) => None,
                    Err(_) => Some("panic in the relay".to_string()),
                });
            });
        let pump_panic = match notifier {
            Ok(_) => match deadline {
                None => done_rx.recv().ok().flatten(),
                Some(at) => {
                    match done_rx.recv_timeout(at.saturating_duration_since(Instant::now())) {
                        Ok(p) => p,
                        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if let Some(child) = self.child.as_mut() {
                                let _ = killpg(child.id(), libc::SIGKILL);
                            }
                            anyhow::bail!("the tty relay did not exit before its deadline");
                        }
                    }
                }
            },
            // Fork limits. The pump stays detached: it still restores the
            // real terminal's termios on its way out (its own guard), so
            // reporting the failure beats hanging on a thread that cannot
            // be spawned.
            Err(e) => anyhow::bail!("spawning the relay's join helper: {e}"),
        };

        let mut child = self
            .child
            .take()
            .expect("join is the only consumer of the child");
        let status = child.wait().context("waiting for the ssh attach to exit")?;

        let cause = if self.inner.hangup.load(Ordering::Acquire) {
            "hangup: SIGHUP of the real terminal closed the pty master"
        } else if let Some(panic) = &pump_panic {
            panic.as_str()
        } else {
            match status.code() {
                None => "ssh died by a signal",
                Some(255) => "ssh transport drop (exit 255)",
                Some(_) => "ssh exited",
            }
        };
        tracing::debug!(
            "tty relay: exited — cause: {cause}; ssh status {status}; \
             termios restored on the real terminal"
        );
        restore_relay_signals();
        Ok(status)
    }
}

/// Set `FD_CLOEXEC` on `fd`. Nothing the relay spawns may inherit the
/// master: a leaked master keeps the pty's EIO/hangup semantics from ever
/// reaching ssh.
fn set_cloexec(fd: &impl AsFd) {
    let _ = fcntl(fd, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC));
}

/// Nonblocking master so the pump's reads and writes never wedge on a peer
/// that stopped draining — partial work goes to the pending buffers and
/// the next poll turn retries.
fn set_nonblocking(fd: &impl AsFd) {
    if let Ok(flags) = fcntl(fd, FcntlArg::F_GETFL) {
        let flags = OFlag::from_bits_retain(flags) | OFlag::O_NONBLOCK;
        let _ = fcntl(fd, FcntlArg::F_SETFL(flags));
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // The only way here is a panic or an early `?` on the caller's
        // side: the pump may still be running, and the terminal must not
        // outlive the relay in raw mode. Tell the pump to stop and wait
        // for its guard to restore before the fds go away.
        if let Some(pump) = self.pump.take() {
            self.inner.command(Ctl::Exit);
            let _ = pump.join();
        }
        restore_relay_signals();
    }
}

// ---------------------------------------------------------------------------
// The pump
// ---------------------------------------------------------------------------

/// What the pump does each turn, in order: serve commands, serve signals,
/// poll, move bytes. All of the real terminal's reads, writes and
/// tcsetattr live on this thread, which is why the saved termios is moved
/// in rather than shared.
fn pump(
    master: OwnedFd,
    inner: Arc<RelayInner>,
    ctl: OwnedFd,
    child_pid: u32,
    attach_start: Termios,
    raw: Termios,
) {
    let _restore = TermiosRestore::new(Arc::clone(&inner), attach_start.clone());

    // Session output read from the master but not yet written to the real
    // terminal; while suspended nothing is written and the new bytes go to
    // the bounded suspend buffer instead.
    let mut pending_out: Vec<u8> = Vec::new();
    // User keystrokes read from the real terminal but not yet written to
    // the pty master. Order is preserved by never reading more input
    // while this is non-empty.
    let mut pending_in: Vec<u8> = Vec::new();
    // The suspension's buffer: the head of ssh's output, replayed on
    // resume; the tail past the bound is dropped and counted.
    let mut suspend_buf: Vec<u8> = Vec::new();
    let mut dropped: u64 = 0;
    let mut suspended = false;
    let mut input_open = true;
    // The session's end of the pty has closed (ssh is gone): stop reading
    // the master — polling it again would spin on POLLHUP — but keep
    // relaying until what was already read has reached the terminal. A
    // plain ssh's last bytes sit in the kernel's tty buffer when it exits;
    // the relay must not lose the ones it had already picked up.
    let mut saw_eof = false;
    let mut scratch = vec![0u8; IO_CHUNK_BYTES];

    loop {
        // 1. Commands from the handle.
        let command = {
            let mut st = inner.shared.mutex.lock().unwrap();
            st.command.take()
        };
        match command {
            Some(Ctl::Exit) => break,
            Some(Ctl::Suspend) => {
                if !suspended {
                    suspend(&inner, &attach_start, &mut suspend_buf, &mut dropped);
                    suspended = true;
                }
                let mut st = inner.shared.mutex.lock().unwrap();
                st.suspended = true;
                st.command = None;
                inner.shared.cv.notify_all();
            }
            Some(Ctl::Resume) => {
                if suspended {
                    resume(
                        &inner,
                        &master,
                        &raw,
                        &mut suspend_buf,
                        &mut dropped,
                        &mut pending_out,
                    );
                    suspended = false;
                }
                let mut st = inner.shared.mutex.lock().unwrap();
                st.suspended = false;
                st.command = None;
                inner.shared.cv.notify_all();
            }
            None => {}
        }

        // 2. Signals: each flag is cleared before its work, so a signal
        // arriving mid-handling is not lost.
        if SIGWINCH_SEEN.swap(false, Ordering::AcqRel) {
            match get_winsize(&inner.tty.input) {
                Ok(ws) => match set_winsize(&master, ws) {
                    Ok(()) => tracing::debug!(
                        "tty relay: forwarded SIGWINCH to the session's pty: {}x{}",
                        ws.ws_col,
                        ws.ws_row
                    ),
                    Err(e) => {
                        tracing::warn!("tty relay: could not forward the terminal resize: {e}")
                    }
                },
                Err(e) => tracing::warn!("tty relay: could not read the terminal size: {e}"),
            }
        }
        for (seen, sig) in [(&SIGINT_SEEN, libc::SIGINT), (&SIGTERM_SEEN, libc::SIGTERM)] {
            if seen.swap(false, Ordering::AcqRel) {
                tracing::debug!("tty relay: forwarding signal {sig} to ssh's process group");
                let _ = killpg(child_pid, sig);
            }
        }
        if SIGHUP_SEEN.swap(false, Ordering::AcqRel) {
            // The terminal is gone. Leaving the loop drops the master, so
            // ssh sees the hangup on its side and dies like the terminal's
            // own child would.
            tracing::debug!("tty relay: SIGHUP — closing the pty master so ssh sees the hangup");
            inner.hangup.store(true, Ordering::Release);
            break;
        }

        // 3. Poll. The ctl pipe is what makes commands prompt; a signal that
        // interrupts the pump surfaces as EINTR (no SA_RESTART), and one
        // delivered to any other thread as a kick byte in the same pipe;
        // ssh's exit arrives as EOF on the master. Never a timeout:
        // everything that matters wakes it.
        let mut fds = Vec::with_capacity(4);
        let input_idx = if input_open && !suspended && pending_in.is_empty() {
            fds.push(PollFd::new(inner.tty.input.as_fd(), PollFlags::POLLIN));
            Some(0usize)
        } else {
            None
        };
        let master_read_idx = if saw_eof || pending_out.len() >= LIVE_OUTPUT_HIGH_WATER {
            // Over high water: the pty's kernel buffer (and then ssh's own
            // blocked write) is the backpressure, as it would be against a
            // plain tty. Once the terminal drains, reading resumes — and
            // ssh's exit is seen then. (Dropping the PollFd rather than
            // polling-and-not-reading: poll would return instantly while
            // data waits, and that busy-spin has no exit.)
            None
        } else {
            let idx = fds.len();
            fds.push(PollFd::new(master.as_fd(), PollFlags::POLLIN));
            Some(idx)
        };
        let master_write_idx = if !pending_in.is_empty() {
            let idx = fds.len();
            fds.push(PollFd::new(master.as_fd(), PollFlags::POLLOUT));
            Some(idx)
        } else {
            None
        };
        // The real terminal: never a write while a prompt owns it — bytes
        // read before the suspend stay in `pending_out` (the replay keeps
        // its order), and the terminal the caller leased stays theirs alone.
        let output_idx = if !suspended && !pending_out.is_empty() {
            let idx = fds.len();
            fds.push(PollFd::new(inner.tty.output.as_fd(), PollFlags::POLLOUT));
            Some(idx)
        } else {
            None
        };
        let ctl_idx = {
            let idx = fds.len();
            fds.push(PollFd::new(ctl.as_fd(), PollFlags::POLLIN));
            idx
        };

        match poll(&mut fds, PollTimeout::NONE) {
            Ok(_) | Err(nix::errno::Errno::EINTR) => {}
            Err(e) => {
                tracing::warn!("tty relay: poll failed, stopping: {e}");
                break;
            }
        }

        let revents = |fds: &[PollFd<'_>], idx: Option<usize>, wanted: PollFlags| {
            idx.and_then(|i| fds[i].revents())
                .map(|e| e.intersects(wanted))
                .unwrap_or(false)
        };

        if revents(&fds, Some(ctl_idx), PollFlags::POLLIN) {
            while read(&ctl, &mut scratch).map(|n| n > 0).unwrap_or(false) {}
        }

        // 4. Real-tty input: read a chunk, hand it off to the pty in full.
        if input_open
            && !suspended
            && pending_in.is_empty()
            && revents(&fds, input_idx, PollFlags::POLLIN)
        {
            match read(&inner.tty.input, &mut scratch) {
                Ok(0) | Err(nix::errno::Errno::EIO) => {
                    // The terminal went away without the courtesy of a
                    // SIGHUP (a test closing its end does this); ssh keeps
                    // running until it exits on its own.
                    input_open = false;
                }
                Err(e) => {
                    tracing::warn!("tty relay: reading the real terminal failed: {e}");
                    input_open = false;
                }
                Ok(n) => pending_in.extend_from_slice(&scratch[..n]),
            }
        }

        // 5. Drain pending input to the pty master (nonblocking writes;
        // EAGAIN means the session is not draining, which is backpressure
        // the user's keystrokes, not the pump's loop).
        if pending_in.is_empty() || revents(&fds, master_write_idx, PollFlags::POLLOUT) {
            while !pending_in.is_empty() {
                match write(&master, &pending_in) {
                    Ok(n) => {
                        pending_in.drain(..n);
                    }
                    Err(nix::errno::Errno::EAGAIN) => break,
                    Err(nix::errno::Errno::EIO) => {
                        // The slave is gone — ssh exited; the master read
                        // observes it this same turn.
                        pending_in.clear();
                        break;
                    }
                    Err(e) => {
                        tracing::warn!("tty relay: writing to the session's pty failed: {e}");
                        pending_in.clear();
                        break;
                    }
                }
            }
        }

        // 6. The pty master: ssh's session output, and — as EOF — ssh's
        // exit.
        if let Some(idx) = master_read_idx
            && revents(&fds, Some(idx), PollFlags::POLLIN | PollFlags::POLLHUP)
        {
            match read(&master, &mut scratch) {
                Ok(0) | Err(nix::errno::Errno::EIO) => {
                    // All slave fds are closed: ssh is gone. The rest
                    // of this turn (and the next ones) drain what was
                    // already read to the terminal before the loop
                    // breaks below.
                    saw_eof = true;
                    input_open = false;
                    pending_in.clear();
                }
                Err(nix::errno::Errno::EAGAIN) => {}
                Err(e) => {
                    tracing::warn!("tty relay: reading the session's pty failed: {e}");
                    saw_eof = true;
                    input_open = false;
                    pending_in.clear();
                }
                Ok(n) => {
                    let chunk = &scratch[..n];
                    if suspended {
                        // Keep the head, drop the tail past the bound.
                        let room = SUSPEND_OUTPUT_BUFFER_BYTES.saturating_sub(suspend_buf.len());
                        let take = room.min(chunk.len());
                        suspend_buf.extend_from_slice(&chunk[..take]);
                        let over = (chunk.len() - take) as u64;
                        dropped += over;
                        inner
                            .buffered
                            .store(suspend_buf.len() as u64, Ordering::Release);
                        inner.dropped.store(dropped, Ordering::Release);
                        if over > 0 {
                            tracing::debug!(
                                "tty relay: {over} bytes of session output dropped \
                                     past the {SUSPEND_OUTPUT_BUFFER_BYTES}-byte suspend \
                                     bound ({dropped} dropped so far)"
                            );
                        }
                    } else {
                        pending_out.extend_from_slice(chunk);
                    }
                }
            }
        }

        // 7. Drain pending output to the real terminal: one write per turn,
        // polled writable first. The fd is nonblocking (see `start`), so a
        // terminal that stops draining leaves the bytes in `pending_out`
        // instead of wedging the pump inside write(2).
        if revents(&fds, output_idx, PollFlags::POLLOUT) {
            match write(&inner.tty.output, &pending_out) {
                Ok(0) => {
                    tracing::warn!("tty relay: writing the session's output hit a zero-write");
                    pending_out.clear();
                }
                Ok(n) => {
                    pending_out.drain(..n);
                }
                Err(nix::errno::Errno::EAGAIN) => {}
                Err(e) => {
                    tracing::warn!("tty relay: writing the session's output failed: {e}");
                    pending_out.clear();
                }
            }
        }

        // 8. The session is gone and everything read from it has reached
        // the terminal (unless a prompt still holds it, in which case the
        // loop waits for its Resume or Exit). This is the pump's only
        // exit: SIGHUP above is the one exception, and its terminal
        // cannot take output anyway.
        if saw_eof && !suspended && pending_out.is_empty() {
            break;
        }
    }

    // Finished: wake every handle waiter and mark the relay inert.
    let mut st = inner.shared.mutex.lock().unwrap();
    st.finished = true;
    st.command = None;
    inner.shared.cv.notify_all();
}

/// The two sizes the resume nudge walks the session's pty through: rows−1,
/// then back to the current size. A size change is the one repaint trigger
/// that costs the session nothing — it repaints on its own SIGWINCH — and
/// ending on the current size is what makes the nudge invisible except as
/// the repaint itself. A one-row terminal cannot shrink; writing the same
/// size changes nothing, which is the honest best it offers.
fn repaint_nudge_sizes(ws: Winsize) -> [Winsize; 2] {
    let mut smaller = ws;
    if ws.ws_row >= 2 {
        smaller.ws_row -= 1;
    }
    [smaller, ws]
}

/// The pump's half of [`RelayHandle::suspend`]: everything the caller needs
/// true before they touch the terminal.
fn suspend(
    inner: &Arc<RelayInner>,
    attach_start: &Termios,
    suspend_buf: &mut Vec<u8>,
    dropped: &mut u64,
) {
    suspend_buf.clear();
    *dropped = 0;
    inner.buffered.store(0, Ordering::Release);
    inner.dropped.store(0, Ordering::Release);
    match tcsetattr(&inner.tty.input, SetArg::TCSADRAIN, attach_start) {
        Err(e) => tracing::warn!("tty relay: could not restore termios for the suspend: {e}"),
        Ok(()) => {
            inner.restored.store(true, Ordering::Release);
            tracing::debug!(
                "tty relay: suspended — real terminal handed back to the caller ({})",
                describe_termios(attach_start)
            );
        }
    }
}

/// The pump's half of [`RelayHandle::resume`]: replay the head, own up to
/// the dropped tail, force the session to repaint, and put the raw set
/// back.
fn resume(
    inner: &Arc<RelayInner>,
    master: &impl AsFd,
    raw: &Termios,
    suspend_buf: &mut Vec<u8>,
    dropped: &mut u64,
    pending_out: &mut Vec<u8>,
) {
    // Replay in order: whatever predates the prompt, then the buffered
    // head, then — only when bytes were dropped — the one visible line.
    pending_out.append(suspend_buf);
    if *dropped > 0 {
        let line = format!("\r\n{dropped}{DROP_LINE_SUFFIX}\r\n");
        pending_out.extend_from_slice(line.as_bytes());
        // The warn mirrors the visible line, so the log and the tty tell
        // the same story about what the prompt cost.
        tracing::warn!("{dropped}{DROP_LINE_SUFFIX}");
    }

    // Nudge the pty size so the session repaints on its own SIGWINCH: its
    // cursor is somewhere in output the user never saw. Never a single
    // unwind or reset code — this is the session's pty, not the user's
    // terminal.
    if let Ok(ws) = get_winsize(&inner.tty.input) {
        for nudge in repaint_nudge_sizes(ws) {
            let _ = set_winsize(master, nudge);
        }
    }

    // Reassert the raw set and the current size — the terminal may have
    // been resized while the prompt owned it.
    match tcsetattr(&inner.tty.input, SetArg::TCSADRAIN, raw) {
        Err(e) => tracing::warn!("tty relay: could not re-enter raw mode after the resume: {e}"),
        Ok(()) => inner.restored.store(false, Ordering::Release),
    }
    if let Ok(ws) = get_winsize(&inner.tty.input) {
        let _ = set_winsize(master, ws);
    }
    tracing::debug!(
        "tty relay: resumed — {dropped} bytes of session output dropped while the prompt was up"
    );
    inner.buffered.store(0, Ordering::Release);
    *dropped = 0;
    inner.dropped.store(0, Ordering::Release);
}

// ---------------------------------------------------------------------------
// Driven terminals for the relay's callers' tests
//
// The relay's callers — the CLI's attach wait and the TUI's dash attach — own
// no pty or termios dependency of their own (the CLI's nix features carry no
// `term`, the TUI has no nix at all), yet their tests must drive the relay
// end to end over a real terminal and assert its restore discipline in
// before/after terms. This is that surface: a fresh pty pair to play the
// terminal with, and an opaque-but-comparable termios snapshot. It is the
// same machinery the relay itself is built on, so the tests drive exactly
// what production drives.
// ---------------------------------------------------------------------------

/// A snapshot of a terminal's termios, opaque but comparable: callers' tests
/// assert "restored to what it was before the attach" without taking on
/// nix's `term` types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TermiosSnapshot(Termios);

/// Capture the current termios of the terminal `fd` is an end of.
pub fn termios_snapshot(fd: impl AsFd) -> Result<TermiosSnapshot, anyhow::Error> {
    Ok(TermiosSnapshot(
        tcgetattr(fd.as_fd()).context("reading the terminal's termios")?,
    ))
}

/// A fresh pty pair for driving a relay from the outside: the master end
/// reads and writes as "the user at the keyboard", the slave end is moved
/// onto the driven process's fds to play "the real terminal" (and the relay
/// it spawns takes over from there).
///
/// The pair starts in the platform's default cooked termios, like a terminal
/// a user opens before `min` ever touches it.
pub struct DrivenPty {
    master: OwnedFd,
    slave: OwnedFd,
    path: std::path::PathBuf,
}

impl DrivenPty {
    /// Open the pair.
    pub fn open() -> Result<Self, anyhow::Error> {
        let pty = openpty(None, None).context("opening a driven pty pair")?;
        // nix 0.31's own ptsname wants its `PtyMaster` wrapper while its
        // openpty hands back plain fds, so ask libc for the slave's name.
        let path = unsafe {
            let raw = libc::ptsname(pty.master.as_fd().as_raw_fd());
            if raw.is_null() {
                return Err(anyhow::anyhow!(
                    "naming the driven pty's slave: {}",
                    std::io::Error::last_os_error()
                ));
            }
            std::ffi::CStr::from_ptr(raw).to_string_lossy().into_owned()
        };
        Ok(Self {
            master: pty.master,
            slave: pty.slave,
            path: path.into(),
        })
    }

    /// The "user" end: reading here watches what the terminal was shown,
    /// writing here types.
    pub fn master(&self) -> BorrowedFd<'_> {
        self.master.as_fd()
    }

    /// The "terminal" end: the fd to move onto stdio (or hand to a relay as
    /// its real terminal, in this crate's own tests).
    pub fn slave(&self) -> BorrowedFd<'_> {
        self.slave.as_fd()
    }

    /// The slave's device path, so a test can tell a process that inherited
    /// this terminal from one the relay put on its own pty.
    pub fn slave_path(&self) -> &std::path::Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::termios::ControlFlags;
    use std::os::unix::process::ExitStatusExt as _;
    use std::time::Duration;

    /// One relay at a time per process: a relay installs process-global
    /// signal dispositions, and the public-entry test moves stdio's fds.
    /// Under nextest — the lane this crate's tests run in — every test owns
    /// its process anyway; this keeps a plain `cargo test` run honest too.
    static RELAY_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    const WINSIZE: Winsize = Winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    /// `sh -c <script>`: the child standing in for ssh.
    fn sh(script: impl AsRef<str>) -> Command {
        let mut cmd = Command::new("sh");
        cmd.arg("-c").arg(script.as_ref());
        cmd
    }

    /// A full cooked set — the state a user's terminal is in before `min`
    /// ever touches it — on the fd named, returned so every restore below is
    /// measured against it.
    fn cooked(fd: &OwnedFd) -> Termios {
        let mut t = tcgetattr(fd).expect("reading the driven pty's termios");
        t.local_flags |=
            LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG | LocalFlags::IEXTEN;
        t.input_flags |= InputFlags::IXON | InputFlags::ICRNL;
        t.output_flags |= OutputFlags::OPOST | OutputFlags::ONLCR;
        tcsetattr(fd, SetArg::TCSADRAIN, &t).expect("setting the driven pty to a cooked set");
        t
    }

    /// One relay over a driven pty: the outer pair's slave plays the real
    /// terminal (the relay's input and output), the master is where the test
    /// reads what the terminal was shown and types what the user types, and
    /// `probe` is a spare handle on the terminal for termios assertions.
    struct Driven {
        master: OwnedFd,
        probe: OwnedFd,
        relay: Relay,
        handle: RelayHandle,
        attach_start: Termios,
    }

    fn start_driven(cmd: Command) -> Driven {
        let pty = openpty(None, None).expect("opening the driven pty");
        let (master, slave) = (pty.master, pty.slave);
        let probe = slave
            .try_clone()
            .expect("duplicating the driven pty's slave");
        let attach_start = cooked(&probe);
        set_winsize(&master, WINSIZE).expect("sizing the driven pty");
        let real = RealTty::from_fds(
            slave
                .try_clone()
                .expect("duplicating the slave as the relay's input"),
            slave,
        );
        let relay = Relay::start(cmd, real).expect("starting the relay");
        let handle = relay.handle();
        Driven {
            master,
            probe,
            relay,
            handle,
            attach_start,
        }
    }

    /// Read from the driven pty's master until `want` bytes arrived, `secs`
    /// pass, or the pty has nothing more to give. Tolerates EINTR: the
    /// signal tests raise real signals into this process while it polls.
    fn read_for(master: &OwnedFd, want: usize, secs: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(want);
        let deadline = Instant::now() + Duration::from_secs(secs);
        while out.len() < want && Instant::now() < deadline {
            let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, PollTimeout::from(250u16)) {
                Ok(_) | Err(nix::errno::Errno::EINTR) => {}
                Err(e) => panic!("polling the driven pty's master: {e}"),
            }
            if !fds[0]
                .revents()
                .map(|e| e.intersects(PollFlags::POLLIN))
                .unwrap_or(false)
            {
                continue;
            }
            let mut scratch = [0u8; 4096];
            match read(master, &mut scratch) {
                Ok(n) if n > 0 => out.extend_from_slice(&scratch[..n]),
                Ok(_) | Err(nix::errno::Errno::EAGAIN) => {}
                Err(_) => break, // the pty's far end is gone
            }
        }
        out
    }

    /// Type into the driven pty's master until every byte is in: a pty
    /// accepts what its reader has drained and blocks the rest, so a
    /// looping writer loses nothing (this is the relay's own discipline —
    /// never read more than can be handed off).
    fn type_bytes(master: &OwnedFd, bytes: &[u8]) {
        let mut off = 0;
        while off < bytes.len() {
            match write(master, &bytes[off..]) {
                Ok(n) => off += n,
                Err(nix::errno::Errno::EINTR) => {}
                Err(e) => panic!("writing to the driven pty's master: {e}"),
            }
        }
    }

    /// Read from the master until `quiet_ms` pass with nothing arriving.
    fn drain(master: &OwnedFd, quiet_ms: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut quiet = 0u64;
        while quiet < quiet_ms {
            let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, PollTimeout::from(50u16)) {
                Ok(n) if n > 0 => {
                    let mut scratch = [0u8; 8192];
                    match read(master, &mut scratch) {
                        Ok(n) if n > 0 => {
                            out.extend_from_slice(&scratch[..n]);
                            quiet = 0;
                        }
                        _ => quiet += 50,
                    }
                }
                Ok(_) | Err(nix::errno::Errno::EINTR) => quiet += 50,
                Err(e) => panic!("polling the driven pty's master: {e}"),
            }
        }
        out
    }

    /// End an attach: kill the child's group (the only way to end a `cat`),
    /// keep reading — the pump can only finish once every byte it read from
    /// the session has reached the terminal — then join for ssh's status.
    fn finish(d: Driven) -> std::process::ExitStatus {
        let Driven {
            master,
            probe,
            relay,
            handle,
            ..
        } = d;
        if let Some(child) = relay.child.as_ref() {
            let _ = killpg(child.id(), libc::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        while Instant::now() < deadline {
            if handle.inner.shared.mutex.lock().unwrap().finished {
                break;
            }
            let _ = drain(&master, 100);
        }
        let status = relay
            .join(Some(deadline))
            .expect("the relay must finish once the session is dead and the terminal drained");
        assert_eq!(
            tcgetattr(&probe).unwrap(),
            d.attach_start,
            "the attach-start termios must be back once the relay ends"
        );
        status
    }

    /// The `y\n` payload used by the flood tests: deterministic, position
    /// homogeneous, and printable in a failure message.
    fn yes_payload(len: usize) -> Vec<u8> {
        b"y\n".iter().copied().cycle().take(len).collect()
    }

    #[test]
    fn relay_copies_bytes_both_ways_in_order() {
        let _guard = RELAY_LOCK.lock().unwrap();
        // Position-coded: every 4-byte group is its own index, so a dropped,
        // duplicated or reordered chunk cannot compare equal.
        let payload: Vec<u8> = (0..65536u32).flat_map(|i| i.to_le_bytes()).collect();
        assert_eq!(payload.len(), 262144);

        let d = start_driven(sh("cat"));
        // While the relay runs, the real terminal sits in ssh's raw set —
        // the premise the session-key chord rides on.
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            ssh_raw_termios(&d.attach_start),
            "the real terminal must be in ssh's raw set mid-relay"
        );

        type_bytes(&d.master, &payload);
        let echoed = read_for(&d.master, payload.len(), 20);
        assert_eq!(echoed, payload, "the round trip must be byte-exact");

        let status = finish(d);
        // `cat` only ends when killed; its death-by-signal is the status a
        // plain wait would see, which is the mapping under test.
        assert_eq!(status.signal(), Some(9));
    }

    #[test]
    fn client_raw_mode_matches_ssh_raw_set() {
        let pty = openpty(None, None).expect("opening a driven pty");
        let base = cooked(&pty.slave);
        assert!(
            base.local_flags
                .contains(LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG),
            "the base must be cooked, or the raw set below proves nothing"
        );

        let raw = ssh_raw_termios(&base);
        // ssh's own enter_raw_mode is cfmakeraw; the explicit removals
        // restate the three flags that carry the chord as data end to end.
        let mut expect = base.clone();
        cfmakeraw(&mut expect);
        expect.input_flags.remove(InputFlags::IXON);
        expect
            .local_flags
            .remove(LocalFlags::ISIG | LocalFlags::IEXTEN);
        assert_eq!(raw, expect, "the raw set must be exactly ssh's own");
        assert!(!raw.local_flags.intersects(
            LocalFlags::ECHO | LocalFlags::ICANON | LocalFlags::ISIG | LocalFlags::IEXTEN
        ));
        assert!(!raw.input_flags.intersects(InputFlags::IXON));
        assert!(!raw.output_flags.intersects(OutputFlags::OPOST));
        assert!(raw.control_flags.contains(ControlFlags::CS8));
    }

    #[test]
    fn winsize_follows_sigwinch() {
        let _guard = RELAY_LOCK.lock().unwrap();
        let d = start_driven(sh("while :; do stty size; sleep 0.2; done"));

        // The relay copies the terminal's size to the session's pty at start.
        let first = read_for(&d.master, 8, 20);
        let text = String::from_utf8_lossy(&first).to_string();
        assert!(
            text.contains("24 80"),
            "the session must see the starting size; saw {text:?}"
        );

        // A resize of the real terminal arrives as a SIGWINCH to the client,
        // which owns the terminal; the relay forwards it to the session's
        // pty as a TIOCSWINSZ.
        let grown = Winsize {
            ws_row: 60,
            ws_col: 200,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        set_winsize(&d.master, grown).expect("resizing the driven pty");
        unsafe { libc::raise(libc::SIGWINCH) };
        let second = read_for(&d.master, 64, 20);
        let text = String::from_utf8_lossy(&second).to_string();
        assert!(
            text.contains("60 200"),
            "the session must see the resized size; saw {text:?}"
        );

        let status = finish(d);
        assert_eq!(
            status.signal(),
            Some(9),
            "the looping child is killed to end the attach"
        );
    }

    #[test]
    fn termios_restored_on_transport_drop() {
        let _guard = RELAY_LOCK.lock().unwrap();
        // ssh exit 255 is the transport-drop signature.
        let d = start_driven(sh("exit 255"));
        let status = d
            .relay
            .join(Some(Instant::now() + Duration::from_secs(10)))
            .expect("the relay must end with the session");
        assert_eq!(status.code(), Some(255));
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            d.attach_start,
            "the attach-start termios must be back after the transport dropped"
        );
    }

    #[test]
    fn termios_restored_on_panic() {
        let _guard = RELAY_LOCK.lock().unwrap();
        let d = start_driven(sh("sleep 1"));

        // Poison the shared state from a thread that holds the mutex while
        // panicking: the pump's next turn dies at its first lock, and the
        // drop guard it holds is what must put the terminal back.
        let inner = Arc::clone(&d.handle.inner);
        let poisoner = std::thread::spawn(move || {
            let _held = inner.shared.mutex.lock().unwrap();
            panic!("poisoning the relay's shared state");
        });
        assert!(
            poisoner.join().is_err(),
            "the poisoning thread must panic while holding the mutex"
        );
        // Kick the pump out of poll; its turn starts by taking the lock.
        let _ = write(&d.handle.inner.kick, b"p").ok();

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if tcgetattr(&d.probe)
                .map(|t| t == d.attach_start)
                .unwrap_or(false)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the pump's drop guard must restore the terminal after a panic"
            );
        }

        // A dead pump and a poisoned mutex: join still reaps the child and
        // the failure is a report, not a hang.
        let status = d
            .relay
            .join(Some(deadline))
            .expect("join must survive a panicking pump");
        assert_eq!(status.code(), Some(0));
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            d.attach_start,
            "the terminal must still be in its attach-start set"
        );
    }

    #[test]
    fn client_signal_restores_termios_and_reaches_ssh() {
        let _guard = RELAY_LOCK.lock().unwrap();
        // ssh runs on the relay's pty, outside the terminal's foreground
        // group — so the client owns the terminal's signals and must forward
        // them. The child proves receipt by trapping and acting on it.
        let d = start_driven(sh(concat!(
            "echo READY; ",
            "trap 'echo CAUGHT_INT; exit 7' INT; ",
            "while :; do sleep 0.2; done",
        )));
        // Wait for the child to announce itself: raising before the trap is
        // installed would kill a plain loop child instead of exercising the
        // forwarding this test is about.
        let seen = read_for(&d.master, b"READY\n".len(), 20);
        assert_eq!(
            seen, b"READY\n",
            "the session must be running (the relay holds the terminal raw)"
        );
        unsafe { libc::raise(libc::SIGINT) };

        let seen = read_for(&d.master, b"CAUGHT_INT\n".len(), 20);
        assert_eq!(
            seen, b"CAUGHT_INT\n",
            "the forwarded SIGINT must reach the session's process group"
        );

        let status = d
            .relay
            .join(Some(Instant::now() + Duration::from_secs(10)))
            .expect("the relay must end with the session");
        assert_eq!(
            status.code(),
            Some(7),
            "the session's own exit status must come back through the relay"
        );
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            d.attach_start,
            "the terminal must be back in its attach-start set after the signal round trip"
        );
    }

    #[test]
    fn ssh_exit_status_maps_unchanged() {
        let _guard = RELAY_LOCK.lock().unwrap();
        let a = start_driven(sh("exit 42"));
        let status = a
            .relay
            .join(Some(Instant::now() + Duration::from_secs(10)))
            .expect("the relay must end with the session");
        assert_eq!(status.code(), Some(42), "a plain exit code maps unchanged");
        assert_eq!(tcgetattr(&a.probe).unwrap(), a.attach_start);

        let b = start_driven(sh("kill -9 $$"));
        let status = b
            .relay
            .join(Some(Instant::now() + Duration::from_secs(10)))
            .expect("the relay must end with the session");
        assert_eq!(status.code(), None);
        assert_eq!(
            status.signal(),
            Some(9),
            "death by signal must map as death by signal, never as a code"
        );
        assert_eq!(tcgetattr(&b.probe).unwrap(), b.attach_start);
    }

    #[test]
    fn suspend_hands_back_attach_start_termios() {
        let _guard = RELAY_LOCK.lock().unwrap();
        const SENT: usize = 512 * 1024;
        // 512KiB of session output, then silence. The test reads nothing
        // before suspending, so at the suspend the relay is holding most of
        // that undelivered — and a lease must hold back not just fresh output
        // but the parked backlog too: while the prompt owns the terminal,
        // nothing of the session may reach it.
        let d = start_driven(sh(format!("sleep 0.2; yes | head -c {SENT}; sleep 30")));
        std::thread::sleep(Duration::from_millis(700));

        let lease = d.handle.suspend().expect("suspending the relay");
        assert!(d.handle.is_suspended());
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            d.attach_start,
            "the leased terminal must be in its attach-start set"
        );

        // The kernel may still hold a little of the backlog in the pty's
        // buffer; drain it and confirm the flow stops. A pump that kept
        // draining here would empty all 512KiB onto the prompt's terminal.
        let parked = drain(&d.master, 400);
        assert!(
            parked.len() <= 64 * 1024,
            "nothing of the session may reach the terminal while the lease is up; \
             got {} bytes",
            parked.len()
        );
        let payload = yes_payload(SENT);
        assert_eq!(&parked, &payload[..parked.len()]);

        // The leased terminal behaves like the user's terminal: it echoes.
        type_bytes(&d.master, b"PROMPT> \n");
        let echo = drain(&d.master, 200);
        assert!(
            echo.starts_with(b"PROMPT>"),
            "the leased terminal must still behave like a terminal; saw {echo:?}"
        );

        lease.resume();
        assert!(!d.handle.is_suspended());
        // The parked backlog replays now, and every byte the session wrote
        // arrives exactly once, head first.
        let rest = read_for(&d.master, SENT - parked.len(), 20);
        assert_eq!(
            rest.len(),
            SENT - parked.len(),
            "the replay must be complete"
        );
        assert_eq!(
            &rest,
            &payload[parked.len()..],
            "the replay must be in order"
        );

        let status = finish(d);
        assert_eq!(
            status.code(),
            None,
            "the parked child is killed to end the attach"
        );
    }

    #[test]
    fn suspend_keeps_head_and_drops_tail_past_bound() {
        let _guard = RELAY_LOCK.lock().unwrap();
        const SENT: usize = 3 * 512 * 1024; // the bound, plus 512KiB of tail
        // The child produces everything AFTER the suspension is up, so the
        // relay never has the option of delivering it live.
        let d = start_driven(sh(format!("sleep 1.0; yes | head -c {SENT}")));
        let lease = d.handle.suspend().expect("suspending before any output");
        assert_eq!(
            d.handle.suspended_output(),
            (0, 0),
            "a fresh suspension buffers nothing yet"
        );

        // All of it arrives — the head fills the bound, the tail is dropped
        // and counted, and the child never blocks: a suspension applies no
        // backpressure to the session.
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let (buffered, dropped) = d.handle.suspended_output();
            if buffered as usize == SUSPEND_OUTPUT_BUFFER_BYTES
                && dropped as usize == SENT - SUSPEND_OUTPUT_BUFFER_BYTES
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the child's output must all arrive; so far {:?}",
                d.handle.suspended_output()
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        lease.resume();
        let head = yes_payload(SUSPEND_OUTPUT_BUFFER_BYTES);
        let line = format!(
            "\r\n{}{DROP_LINE_SUFFIX}\r\n",
            SENT - SUSPEND_OUTPUT_BUFFER_BYTES
        );
        let replayed = read_for(&d.master, head.len() + line.len(), 20);
        assert_eq!(
            &replayed[..head.len()],
            &head[..],
            "the buffered head must replay byte-exact"
        );
        assert_eq!(
            &replayed[head.len()..],
            line.as_bytes(),
            "the one visible line must say exactly what was dropped"
        );
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            ssh_raw_termios(&d.attach_start),
            "resume must reassert the raw set before replaying"
        );

        let status = d
            .relay
            .join(Some(deadline))
            .expect("the relay must end with the session");
        assert_eq!(status.code(), Some(0));
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            d.attach_start,
            "the attach-start termios must be back after the replay"
        );
    }

    #[test]
    fn resume_after_drop_prints_line_and_nudges_winsize() {
        let _guard = RELAY_LOCK.lock().unwrap();
        // The nudge itself, pure: rows−1 then back, and a one-row terminal
        // cannot shrink.
        let [smaller, back] = repaint_nudge_sizes(WINSIZE);
        assert_eq!((smaller.ws_row, smaller.ws_col), (23, 80));
        assert_eq!((back.ws_row, back.ws_col), (24, 80));
        let one_row = Winsize {
            ws_row: 1,
            ..WINSIZE
        };
        let [a, b] = repaint_nudge_sizes(one_row);
        assert_eq!((a.ws_row, b.ws_row), (1, 1), "a one-row pty cannot shrink");

        // End to end: the session must see the nudge as its own SIGWINCH —
        // the repaint trigger — and end at the current size. Observing that
        // needs a session that owns the pty as its controlling terminal, so
        // it leads its own session (setsid) and counts the signals.
        const SENT: usize = 3 * 512 * 1024;
        let script = "trap 'W=$((W+1))' WINCH; W=0; \
                     sleep 1.0; \
                     yes | head -c 1572864; \
                     read -r x; \
                     printf 'WINS=%s SIZE=%s\\n' \"$W\" \"$(stty size)\"";
        let mut cmd = Command::new("setsid");
        cmd.arg("-w").arg("sh").arg("-c").arg(script);
        let d = start_driven(cmd);

        let lease = d.handle.suspend().expect("suspending before any output");
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let (buffered, dropped) = d.handle.suspended_output();
            if buffered as usize + dropped as usize == SENT {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the child's output must all arrive; so far {:?}",
                d.handle.suspended_output()
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        lease.resume();
        type_bytes(&d.master, b"r\n");
        let head = yes_payload(SUSPEND_OUTPUT_BUFFER_BYTES);
        let line = format!(
            "\r\n{}{DROP_LINE_SUFFIX}\r\n",
            SENT - SUSPEND_OUTPUT_BUFFER_BYTES
        );
        let mut shown = read_for(&d.master, head.len() + line.len(), 20);
        // Then the child's report arrives once its `read` returns.
        shown.extend(drain(&d.master, 600));
        assert_eq!(
            &shown[..head.len()],
            &head[..],
            "the replayed head must be intact"
        );
        assert_eq!(&shown[head.len()..head.len() + line.len()], line.as_bytes());
        let report = String::from_utf8_lossy(&shown[head.len() + line.len()..]).to_string();
        let winches: u32 = report
            .split("WINS=")
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        assert!(
            (1..=2).contains(&winches),
            "the nudge must reach the session as its own SIGWINCH; report: {report:?}"
        );
        assert!(
            report.contains("SIZE=24 80"),
            "the nudge must end at the terminal's current size; report: {report:?}"
        );

        let status = d
            .relay
            .join(Some(Instant::now() + Duration::from_secs(15)))
            .expect("the relay must end with the session");
        assert_eq!(status.code(), Some(0));
    }

    #[test]
    fn suspend_and_resume_are_idempotent() {
        let _guard = RELAY_LOCK.lock().unwrap();
        let d = start_driven(sh("sleep 3"));

        // Suspending twice hands out two leases of the same terminal.
        let first = d.handle.suspend().expect("first suspend");
        let _second = d.handle.suspend().expect("suspending a suspended relay");
        assert!(d.handle.is_suspended());
        assert_eq!(tcgetattr(&d.probe).unwrap(), d.attach_start);

        // Resuming twice — once through the lease, once through the handle —
        // leaves one running relay, not an error.
        first.resume();
        assert!(!d.handle.is_suspended());
        d.handle.resume();
        assert!(!d.handle.is_suspended());

        // A second round, resumed through the handle.
        let _third = d.handle.suspend().expect("re-suspending");
        assert!(d.handle.is_suspended());
        d.handle.resume();
        assert!(!d.handle.is_suspended());

        // The child exits on its own; the relay must go inert.
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if d.handle.inner.shared.mutex.lock().unwrap().finished {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the relay must end with the attach"
            );
        }

        // Both calls are well-defined after the end: suspend errors, resume
        // is a no-op.
        assert!(
            d.handle.suspend().is_err(),
            "suspending a finished attach must error"
        );
        d.handle.resume();
        assert_eq!(d.handle.suspended_output(), (0, 0));

        let status = d
            .relay
            .join(Some(deadline))
            .expect("the relay must end with the attach");
        assert_eq!(status.code(), Some(0));
        assert_eq!(
            tcgetattr(&d.probe).unwrap(),
            d.attach_start,
            "the attach-start termios must be back once the relay ends"
        );
    }

    #[test]
    fn chord_bytes_pass_through_unmodified() {
        let _guard = RELAY_LOCK.lock().unwrap();
        let d = start_driven(sh("cat"));
        // The shipped detach chord plus every control byte a cooked line
        // discipline would have eaten, in one write: with the relay holding
        // both ends in ssh's raw set they must round-trip as data.
        let typed: Vec<u8> = [
            0x1d, b'd', // the detach chord: leader, then its subcommand
            0x11, 0x13, // XON/XOFF — flow control while IXON is set
            0x16, 0x03, // LNEXT, and the INTR byte it would shield
            0x1a, 0x04, // SUSP, and EOF in canonical mode
            0x00, // NUL
            b'h', b'i', b'\r', b'\n',
        ]
        .to_vec();
        type_bytes(&d.master, &typed);
        let back = read_for(&d.master, typed.len(), 20);
        assert_eq!(
            back, typed,
            "the raw set must pass every byte through, exactly once and in order"
        );

        let status = finish(d);
        assert_eq!(
            status.code(),
            None,
            "the relayed cat is killed to end the attach"
        );
    }

    #[test]
    fn exec_path_keeps_inherited_stdio() {
        let _guard = RELAY_LOCK.lock().unwrap();
        // The interactive relay re-homes the child's stdio onto its own pty:
        // a relay's child sees a terminal on both ends no matter what this
        // process's stdio is.
        let d = start_driven(sh("test -t 0 && test -t 1; exit $?"));
        let status = d
            .relay
            .join(Some(Instant::now() + Duration::from_secs(10)))
            .expect("the relay must end with the session");
        assert_eq!(
            status.code(),
            Some(0),
            "the relay's child runs on the pty pair: both ends must be terminals"
        );

        // The exec path spawns ssh the plain way, so whatever this process's
        // stdio is the child inherits it unchanged — the child's view must
        // equal this process's view, here and on any host.
        let expected =
            2 * (std::io::stdin().is_terminal() as i32) + (std::io::stdout().is_terminal() as i32);
        let status = sh(
            "A=$([ -t 0 ] && echo 1 || echo 0); B=$([ -t 1 ] && echo 1 || echo 0); \
             exit $((2*A + B))",
        )
        .status()
        .expect("spawning the exec-path child");
        assert_eq!(
            status.code(),
            Some(expected),
            "the exec path must leave the child's stdio exactly as it inherited it"
        );
    }

    /// The public entry, driven with a real hook: the hook suspends the relay
    /// from its own thread, owns the terminal for its prompt, and hands it
    /// back — and the attach then runs to the child's exit.
    #[test]
    fn run_interactive_attach_runs_a_suspend_hook_to_completion() {
        use crate::attach::run_interactive_attach;

        let _guard = RELAY_LOCK.lock().unwrap();
        let pty = openpty(None, None).expect("opening the driven pty");
        let (master, slave) = (pty.master, pty.slave);
        let probe = slave
            .try_clone()
            .expect("duplicating the driven pty's slave");
        let attach_start = cooked(&probe);
        set_winsize(&master, WINSIZE).expect("sizing the driven pty");

        // run_interactive_attach takes the real terminal from this process's
        // stdio, so play the terminal on fds 0 and 1 for the duration.
        let saved_in = nix::unistd::dup(std::io::stdin()).expect("saving stdin");
        let saved_out = nix::unistd::dup(std::io::stdout()).expect("saving stdout");
        struct RestoreStdio {
            saved_in: OwnedFd,
            saved_out: OwnedFd,
        }
        impl Drop for RestoreStdio {
            fn drop(&mut self) {
                let _ = nix::unistd::dup2_stdin(&self.saved_in);
                let _ = nix::unistd::dup2_stdout(&self.saved_out);
            }
        }
        let _restore = RestoreStdio {
            saved_in,
            saved_out,
        };
        nix::unistd::dup2_stdin(&slave).expect("moving the pty onto stdin");
        nix::unistd::dup2_stdout(&slave).expect("moving the pty onto stdout");

        let resumed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_resumed = Arc::clone(&resumed);
        let hook: SuspendHook = Box::new(move |handle| {
            let lease = handle.suspend().expect("the hook suspends the relay");
            // A prompt writes to the terminal it was handed.
            let _ = write(lease.as_fd(), b"HOOK_PROMPT\n");
            std::thread::sleep(Duration::from_millis(200));
            lease.resume();
            hook_resumed.store(true, Ordering::Release);
        });

        let status = run_interactive_attach(sh("sleep 1.5"), Some(hook))
            .expect("the interactive attach runs to the child's exit");
        assert_eq!(status.code(), Some(0));
        assert!(
            resumed.load(Ordering::Acquire),
            "the hook must have run to its resume"
        );

        let shown = drain(&master, 300);
        let text = String::from_utf8_lossy(&shown).to_string();
        assert!(
            text.contains("HOOK_PROMPT"),
            "the prompt's output must land on the real terminal; saw {text:?}"
        );
        assert_eq!(
            tcgetattr(&probe).unwrap(),
            attach_start,
            "the attach-start termios must be back after the interactive attach"
        );
    }
}
