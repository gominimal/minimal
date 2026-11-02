//! The bridge between a running [`Process`] and its SSH channel: stdin
//! pumping with held-input bounds, stdout and stderr relay, and exit
//! reporting.

use super::*;

/// An async task which binds some program execution to an ssh channel.
///
/// The `exec` field carries every parameter the process needs (argv,
/// cwd, env); `ExecTask` itself is just the wiring that connects it to
/// the SSH channel.
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct ExecTask<S: Exec> {
    pub(super) channel_id: ChannelId,
    pub(super) exec: S,

    pub(super) serv: ServerStateHandle,
    pub(super) conn: ConnectionHandle,
    pub(super) session: BoxHandle,
}

impl<S: Exec> ExecTask<S> {
    /// Drives the exec to completion over the channel and reports the
    /// SSH-encoded exit code it ended with. The status is on the wire and
    /// the channel is closed once this returns — the point at which a box
    /// created for the run can end (NET-131).
    pub async fn run(self, channel: Channel<Msg>) -> u32 {
        let (rs, ws) = channel.split();
        // SSH_EXTENDED_DATA_STDERR (RFC 4254 §5.2) — selects the stderr
        // stream on the same channel as a separate extended-data type.
        let mut w = ws.make_writer();
        let mut e = ws.make_writer_ext(Some(1));

        // Drive `rs.wait()` directly rather than `rs.make_reader()` so we
        // see `ChannelMsg::Close` and `None` (sender dropped) — the signals
        // that the SSH client is gone. `make_reader()` reduces the read half
        // to a bare `AsyncRead`, which only surfaces `ChannelMsg::Data` and
        // `ChannelMsg::Eof`; a lost client then looks like a normal stdin
        // EOF, and a silent child (sleep, quiet build) keeps running
        // indefinitely (gominimal/inbox#813).
        // An in-memory pipe: unlike pipe(2) it cannot fail (no fds to run
        // out of), and dropping the pump's half still gives the bridge EOF.
        let held = HeldInput::new(HeldInputLimits::for_daemon());
        let mut stdin_r = HeldInputReader(Arc::clone(&held));
        let (end_tx, end_rx) = watch::channel(None);
        let unread = self.exec.unread_stdin();

        let msgs = Box::pin(stream::unfold(rs, |mut rs| async move {
            rs.wait().await.map(|msg| (msg, rs))
        }));
        let pump = spawn(pump_channel_input(msgs, held, end_tx));

        let stream = self.exec.exec(self.session.clone());
        let mngr = self.serv.sessions_manager().await;
        let (exit_status, late_start) = bridge_noting_reason(
            self.channel_id,
            stream,
            &mut stdin_r,
            &mut w,
            &mut e,
            end_rx.clone(),
            unread,
            destroy_signal::<S>(|| self.session.destroy_signal()),
            || mngr.is_shutting_down(),
        )
        .await;

        pump.abort();
        // Awaited to its end, so no push of the pump's is still in flight
        // when the reader is dropped and the held input is cleared; an
        // aborted task joins as cancelled, which is the expected outcome.
        if let Err(err) = pump.await
            && !err.is_cancelled()
        {
            tracing::warn!(error = %err, "exec: the input pump ended abnormally");
        }
        // The notice names the bound; a command that happened to finish on
        // its own in the same instant still gets it, which is the rarer
        // wrong of the two (the other being no notice for an ended exec).
        let notice = match *end_rx.borrow() {
            Some(ExecEnd::InputHeldOver(bound)) => Some(held_input_notice(bound)),
            Some(ExecEnd::InputHeldUnstarted(bound)) => Some(unstarted_input_notice(bound)),
            Some(ExecEnd::ClientLost) | None => None,
        };
        if let Some(notice) = notice
            && e.write_all(notice.as_bytes()).await.is_err()
        {
            tracing::debug!("exec: the held-input notice was not written; the client is gone");
        }
        let _ = w.flush().await;
        let _ = e.flush().await;

        drop(stdin_r);
        let _ = ws.eof().await;
        let _ = ws.exit_status(exit_status).await; // otherwise considered -1
        let _ = ws.close().await; // needed to release the remote
        // An exec that ended while its command was still starting has
        // answered its client already; the command that start yields, if it
        // ever does, is ended here rather than left running unbridged.
        if let Some(mut late) = late_start {
            reap_late_start(&mut late).await;
        }
        exit_status
    }
}

/// Ends the command a start already in flight yields, once it does: the exec
/// it was for ended while it was starting ([`bridge_until_end`]). Takes one
/// item only, the start that was pending, so no further command of a
/// sequence is started. A start that never returns keeps this waiting, with
/// the client already answered and its channel closed.
pub(super) async fn reap_late_start<S, P>(stream: &mut S)
where
    P: Process,
    S: Stream<Item = io::Result<P>> + Unpin,
{
    if let Some(Ok(mut process)) = stream.next().await {
        tracing::info!("exec: a command started after its exec had ended; ending it");
        let _ = process.start_kill();
        let _ = process.wait().await;
    }
}

/// The line an exec the daemon's shutdown ended leaves on stderr, so the
/// client is told why its command stopped rather than handed a bare 137.
pub(super) const SHUTDOWN_NOTICE: &[u8] = b"minimald is shutting down; the command was stopped\n";

/// The line an exec the session's destroy ended leaves on stderr, for the
/// same reason: the client is told why its command stopped, not handed a
/// bare 137 with nothing on the wire to explain it.
pub(super) const DESTROYED_NOTICE: &[u8] = b"the session was destroyed; the command was stopped\n";

/// The destroy token the bridge watches for an exec of kind `S`.
///
/// Only an exec whose process the destroy ends gets one
/// ([`Exec::ENDED_BY_BOX_DESTROY`]). A process outside the box outlives the
/// destroy, so the bridge does not stop it and does not name the destroy.
pub(super) fn destroy_signal<S: Exec>(
    token: impl FnOnce() -> CancellationToken,
) -> Option<CancellationToken> {
    S::ENDED_BY_BOX_DESTROY.then(token)
}

/// The notice an exec leaves on stderr when it ends.
///
/// A daemon shutdown comes first. It names a command that ended with a
/// kill-shaped status. The destroy notice names only a command that the
/// bridge stopped because the destroy token fired.
pub(super) fn exit_notice(
    shutting_down: bool,
    exit_status: u32,
    stopped_by_destroy: bool,
) -> Option<&'static [u8]> {
    if shutting_down && exit_status >= KILLED_STATUS_MIN {
        Some(SHUTDOWN_NOTICE)
    } else if stopped_by_destroy {
        Some(DESTROYED_NOTICE)
    } else {
        None
    }
}

/// The lowest exit status that is kill-shaped: `128 + signo` is how a
/// signal-terminated command reports, in the shell convention.
pub(super) const KILLED_STATUS_MIN: u32 = 128;

/// A [`Process`] that the bridge stops when the box's destroy starts.
///
/// `wait` races the inner process against the destroy token. When the
/// token fires first, it calls `start_kill` and sets `stopped`. Then it
/// waits for the inner process to end. A process that already ended wins
/// the race, so a command that exits on its own never sets `stopped`.
pub(super) struct StoppedOnDestroy<P> {
    pub(super) inner: P,
    /// `None` for a process the destroy does not stop: `wait` is then the
    /// inner wait, and `stopped` is never set.
    pub(super) destroyed: Option<CancellationToken>,
    pub(super) stopped: Arc<AtomicBool>,
}

impl<P: Process> Process for StoppedOnDestroy<P> {
    type Stdin = P::Stdin;
    type Stdout = P::Stdout;
    type Stderr = P::Stderr;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        self.inner.take_stdio()
    }

    // Cancel-safe: the inner `wait` is, and `stopped` is set before the
    // next await point.
    async fn wait(&mut self) -> io::Result<Option<i32>> {
        if let Some(destroyed) = &self.destroyed
            && !self.stopped.load(Ordering::SeqCst)
        {
            tokio::select! {
                biased;
                status = self.inner.wait() => return status,
                () = destroyed.cancelled() => {
                    self.stopped.store(true, Ordering::SeqCst);
                    tracing::info!("exec: session destroy started; stopping the command");
                    if let Err(err) = self.inner.start_kill() {
                        tracing::warn!(error = %err, "exec: failed to stop the command for the destroy");
                    }
                }
            }
        }
        self.inner.wait().await
    }

    fn start_kill(&mut self) -> io::Result<()> {
        self.inner.start_kill()
    }
}

/// Runs [`bridge`] and writes the notice for why the command ended to `e`
/// before it returns the exit status. The status always passes through.
///
/// `destroyed` is the box's destroy token, for an exec whose process the
/// destroy ends. When it fires while a command runs, the bridge stops the
/// command and notes the destroy. A command that exits on its own, with
/// any status, gets no destroy notice.
///
/// `shutting_down` is asked once the bridge returns, and only for a
/// kill-shaped status (128 or more, the shell convention for a signal).
/// The sessions manager sets its shutdown state before it stops any box.
#[expect(
    clippy::too_many_arguments,
    reason = "the channel's three halves, the three ways an exec ends, and the shutdown probe"
)]
pub(super) async fn bridge_noting_reason<C, S, P, R, W, E, F>(
    channel_id: C,
    stream: S,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    client_lost: watch::Receiver<Option<ExecEnd>>,
    unread: UnreadStdin,
    destroyed: Option<CancellationToken>,
    shutting_down: F,
) -> (
    u32,
    Option<impl Stream<Item = io::Result<StoppedOnDestroy<P>>> + Unpin + use<C, S, P, R, W, E, F>>,
)
where
    C: Display + Clone,
    F: FnOnce() -> bool,
    P: Process,
    S: Stream<Item = io::Result<P>> + Unpin,
    R: ExecInput,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let stopped = Arc::new(AtomicBool::new(false));
    // Every process is wrapped, with or without a token, so the stream the
    // bridge hands back for a late start has one type either way.
    let stream = {
        let stopped = Arc::clone(&stopped);
        stream.map(move |process| {
            process.map(|inner| StoppedOnDestroy {
                inner,
                destroyed: destroyed.clone(),
                stopped: Arc::clone(&stopped),
            })
        })
    };
    let (exit_status, late_start) =
        bridge_until_end(channel_id, stream, r, w, e, client_lost, unread).await;
    // A shutdown stops a command only by tearing down what runs it: a
    // box exec is SIGKILLed with the container and the injection shim
    // reports `128 + signo`, and a task exec is killed through its
    // handle. A command that ends on its own during a shutdown — a
    // graceful exit, a failure — was not stopped by it, so only a
    // kill-shaped status (see `KILLED_STATUS_MIN`) gets the notice.
    // Nothing the shutdown stops is silenced: every exec kind it stops
    // reports a status of 128 or more. (The host-side git exec is
    // signalled by nothing here — a signal-terminated `TokioProcess`
    // maps to 1 — and it is the one kind the shutdown never stops.)
    let shutting_down = exit_status >= KILLED_STATUS_MIN && shutting_down();
    if let Some(notice) = exit_notice(shutting_down, exit_status, stopped.load(Ordering::SeqCst)) {
        let _ = e.write_all(notice).await;
    }
    (exit_status, late_start)
}

/// How much of an exec's input the daemon holds for a command that is not
/// reading it, before the exec is ended instead (gominimal/inbox#1089, the
/// second half of #866; Eugeny/russh#730).
///
/// russh grants the client's send window on receipt and gives the server
/// no way to hold it back, so the client is never slowed down from here:
/// what the command has not read is held in the daemon or the connection
/// hangs. At this much the pump stops taking from the channel, which parks
/// the connection for a bounded time: until the command starts (at most
/// [`EXEC_INPUT_UNSTARTED`]), and then
/// for at most [`EXEC_INPUT_STALL`] without it reading a byte, after which
/// the exec ends with a notice on its stderr ([`held_input_notice`]), an
/// active reject rather than a hang.
pub(super) const EXEC_INPUT_HELD_MAX: usize = 256 * 1024 * 1024;

/// How long a running command may leave its held input at a bound without
/// reading any of it before the exec ends. While the pump waits it takes
/// nothing from the channel, so the connection is parked for at most this
/// long per bound hit. A command that reads at least a byte within each
/// such window releases it and is never ended; one that reads nothing for
/// a whole window is. The window counts this exec's own reads only: another
/// exec's release never restarts it. At the daemon bound an exec holding
/// input of its own is the one ended; one that holds nothing waits for the
/// others, up to [`EXEC_INPUT_STARVED`].
pub(super) const EXEC_INPUT_STALL: Duration = Duration::from_secs(10);

/// How long an exec that holds no input of its own waits at the daemon bound
/// for the execs that do. Each of those is ended within its own stall unless
/// it reads, so the wait is normally short; but execs that each read a byte
/// per window keep the budget full forever, and the waiting exec's channel —
/// with the connection behind it — would be parked as long. Past this the
/// waiting exec ends with the daemon-bound notice instead.
pub(super) const EXEC_INPUT_STARVED: Duration = Duration::from_secs(60);

/// How long the pump waits at a bound for a command that has not started.
/// A fast client puts the cap in flight before a cold box has spawned the
/// command, and that wait normally ends with the start; this bounds it for
/// a spawn that never returns. Past it the held input is released, the pump
/// lets go of the channel (so the connection is no longer parked), and the
/// exec is ended with [`ExecEnd::InputHeldUnstarted`] at once: the bridge
/// races each start against the exec's end ([`bridge_until_end`]), and the
/// command a late start yields is ended when it comes ([`reap_late_start`]).
pub(super) const EXEC_INPUT_UNSTARTED: Duration = Duration::from_secs(300);

/// The most unread exec input this daemon holds across all its execs. The
/// per-exec cap alone would let N stalled execs hold N times it in a guest
/// with bounded memory; past this total the exec that would cross it ends,
/// the same way, and the others are untouched.
pub(super) const EXEC_INPUT_HELD_DAEMON_MAX: usize = 512 * 1024 * 1024;

/// Unread exec input held across this daemon's execs, in bytes.
pub(super) static EXEC_INPUT_HELD_DAEMON: AtomicUsize = AtomicUsize::new(0);

/// Woken whenever any exec releases held input: a pump waiting at the
/// daemon bound is waiting on other execs, so their releases must reach it.
pub(super) static EXEC_INPUT_PROGRESS: tokio::sync::Notify = tokio::sync::Notify::const_new();

/// How much of what it holds a command at a bound must read per stall
/// window for the window to restart: a share, not a byte. A real reader
/// clears it by orders of magnitude; a command that reads one byte per
/// window used to keep an exec at its cap alive forever, holding its share
/// of the daemon's budget from every other exec (#2238). An exec that holds
/// less than this must read everything it holds.
pub(super) const EXEC_INPUT_DRAIN_QUANTUM: usize = EXEC_INPUT_HELD_MAX / 64;

/// Every live exec's held input with the handle that ends it, so a pump
/// starved at the daemon bound can end the holder that is not draining
/// rather than itself (#2238). Entries are weak: a gone exec is skipped on
/// the next walk, and each pump removes its own entry when it returns.
pub(super) type ExecRegistry = std::sync::Mutex<Vec<RegisteredExec>>;

/// One registry entry: the exec's held input and the sender the bridge
/// watches for how the exec is to end.
pub(super) struct RegisteredExec {
    pub(super) held: std::sync::Weak<HeldInput>,
    pub(super) end: Arc<watch::Sender<Option<ExecEnd>>>,
}

pub(super) static EXEC_INPUT_REGISTRY: ExecRegistry = std::sync::Mutex::new(Vec::new());

/// Which bound an exec's held input crossed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HeldBound {
    /// The exec's own cap ([`EXEC_INPUT_HELD_MAX`]).
    Exec,
    /// The daemon's total ([`EXEC_INPUT_HELD_DAEMON_MAX`]).
    Daemon,
}

/// Why the bridge ends an exec before its command is done.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecEnd {
    /// The SSH client is gone (channel close, or the sender dropped with
    /// the connection).
    ClientLost,
    /// Input held for a command that was not reading it crossed a bound.
    InputHeldOver(HeldBound),
    /// Input reached a bound before the command started, and the command
    /// had still not started when [`EXEC_INPUT_UNSTARTED`] ran out.
    InputHeldUnstarted(HeldBound),
}

/// What the bridge does with input that arrives while the current command
/// has closed its stdin: for a single program there is nobody else to read
/// it, so it is read and dropped (it is not held against the command); for
/// a sequence it is kept for the next command, and a command that closes
/// its stdin and runs on while input keeps coming is bounded like any other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnreadStdin {
    Discard,
    Keep,
}

/// The bounds on input held for a command that is not reading it: one for
/// the exec, one for the daemon as a whole (shared through `daemon_held`).
#[derive(Clone, Copy)]
pub(super) struct HeldInputLimits {
    pub(super) per_exec: usize,
    pub(super) daemon: usize,
    pub(super) daemon_held: &'static AtomicUsize,
    /// Woken on every release into `daemon_held`, by any exec.
    pub(super) daemon_progress: &'static tokio::sync::Notify,
    /// The stall a running command is allowed at a bound.
    pub(super) stall: Duration,
    /// The wait an exec holding nothing is allowed at the daemon bound.
    pub(super) starved: Duration,
    /// The wait at a bound for a command that has not started.
    pub(super) unstarted: Duration,
    /// What a command at a bound must read per `stall` window for the window
    /// to restart ([`EXEC_INPUT_DRAIN_QUANTUM`]), or everything it holds if
    /// that is less.
    pub(super) quantum: usize,
    /// The daemon's live execs, for the holder-ending walk at the daemon bound.
    pub(super) registry: &'static ExecRegistry,
}

impl HeldInputLimits {
    pub(super) fn for_daemon() -> Self {
        Self {
            per_exec: EXEC_INPUT_HELD_MAX,
            daemon: EXEC_INPUT_HELD_DAEMON_MAX,
            daemon_held: &EXEC_INPUT_HELD_DAEMON,
            daemon_progress: &EXEC_INPUT_PROGRESS,
            stall: EXEC_INPUT_STALL,
            starved: EXEC_INPUT_STARVED,
            unstarted: EXEC_INPUT_UNSTARTED,
            quantum: EXEC_INPUT_DRAIN_QUANTUM,
            registry: &EXEC_INPUT_REGISTRY,
        }
    }

    pub(super) fn registry(&self) -> std::sync::MutexGuard<'_, Vec<RegisteredExec>> {
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The line an exec gets on its stderr when its command had not started by
/// the end of the wait at a bound ([`ExecEnd::InputHeldUnstarted`]).
pub(super) fn unstarted_input_notice(bound: HeldBound) -> String {
    let mib = |n: usize| n / (1024 * 1024);
    let waited = EXEC_INPUT_UNSTARTED.as_secs();
    match bound {
        HeldBound::Exec => format!(
            "minimald: this command had not started {waited} s after its input reached the {} MiB \
             minimald holds for one exec, so the exec was ended\n",
            mib(EXEC_INPUT_HELD_MAX)
        ),
        HeldBound::Daemon => format!(
            "minimald: this command had not started {waited} s after unread exec input across \
             this daemon's execs reached {} MiB, so the exec was ended\n",
            mib(EXEC_INPUT_HELD_DAEMON_MAX)
        ),
    }
}

/// The line an exec whose held input crossed a bound gets on its stderr;
/// the numbers are the caps themselves, so a retuned cap cannot leave the
/// notice behind.
pub(super) fn held_input_notice(bound: HeldBound) -> String {
    let mib = |n: usize| n / (1024 * 1024);
    match bound {
        HeldBound::Exec => format!(
            "minimald: {} MiB of this command's input was still unread; minimald holds no more \
             than that for one exec, so the exec was ended\n",
            mib(EXEC_INPUT_HELD_MAX)
        ),
        HeldBound::Daemon => format!(
            "minimald: unread exec input across this daemon's execs reached {} MiB and stayed \
             there, so this exec could take no more of its input and was ended\n",
            mib(EXEC_INPUT_HELD_DAEMON_MAX)
        ),
    }
}

/// Input taken off the SSH channel and not yet read by the command. The
/// pump pushes as packets arrive; the bridge reads through
/// [`HeldInputReader`]; every byte is charged to the exec's and the daemon's
/// held counts from push to read (or to [`HeldInput::clear`]), so the counts
/// are the memory this holds, in `Vec`s rather than russh's power-of-two
/// locked buffers.
pub(super) struct HeldInput {
    pub(super) inner: std::sync::Mutex<HeldInner>,
    pub(super) waker: futures::task::AtomicWaker,
    pub(super) held: AtomicUsize,
    /// Bytes ever released from `held`, monotonic: what a window's drain is
    /// measured against.
    pub(super) released: AtomicUsize,
    pub(super) limits: HeldInputLimits,
    /// Set once nothing will read what arrives: pushes are dropped uncharged.
    pub(super) discarding: std::sync::atomic::AtomicBool,
    /// Set once the command is running: a bound is then a stall, not a wait.
    pub(super) started: std::sync::atomic::AtomicBool,
    /// Woken when bytes are released, the queue is cleared, or the command
    /// starts: what a pump waiting at a bound needs to try again.
    pub(super) progress: tokio::sync::Notify,
}

pub(super) struct HeldInner {
    pub(super) chunks: VecDeque<Vec<u8>>,
    /// Bytes of the front chunk already read.
    pub(super) offset: usize,
    /// No more pushes: the reader reports EOF once the chunks are read.
    pub(super) eof: bool,
}

impl HeldInput {
    pub(super) fn new(limits: HeldInputLimits) -> Arc<Self> {
        Arc::new(Self {
            inner: std::sync::Mutex::new(HeldInner {
                chunks: VecDeque::new(),
                offset: 0,
                eof: false,
            }),
            waker: futures::task::AtomicWaker::new(),
            held: AtomicUsize::new(0),
            released: AtomicUsize::new(0),
            limits,
            discarding: std::sync::atomic::AtomicBool::new(false),
            started: std::sync::atomic::AtomicBool::new(false),
            progress: tokio::sync::Notify::new(),
        })
    }

    pub(super) fn lock(&self) -> std::sync::MutexGuard<'_, HeldInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Charges and queues `data`, or refuses it (charging nothing) with the
    /// bound it would cross. Once the rest is to be discarded it is dropped
    /// here, uncharged.
    pub(super) fn push(&self, data: &[u8]) -> Result<(), HeldBound> {
        let n = data.len();
        if n == 0 || self.discarding.load(Ordering::Acquire) {
            return Ok(());
        }
        let exec_total = self.held.fetch_add(n, Ordering::AcqRel) + n;
        let daemon_total = self.limits.daemon_held.fetch_add(n, Ordering::AcqRel) + n;
        let over = if exec_total > self.limits.per_exec {
            Some(HeldBound::Exec)
        } else if daemon_total > self.limits.daemon {
            Some(HeldBound::Daemon)
        } else {
            None
        };
        if let Some(bound) = over {
            // Undo the charge only: nothing was read, so this is not a
            // release (a refused push must not count as the window's drain,
            // nor wake a pump as a read would).
            self.held.fetch_sub(n, Ordering::AcqRel);
            self.limits.daemon_held.fetch_sub(n, Ordering::AcqRel);
            return Err(bound);
        }
        self.lock().chunks.push_back(data.to_vec());
        self.waker.wake();
        Ok(())
    }

    pub(super) fn release(&self, n: usize) {
        self.held.fetch_sub(n, Ordering::AcqRel);
        self.released.fetch_add(n, Ordering::AcqRel);
        self.limits.daemon_held.fetch_sub(n, Ordering::AcqRel);
        self.progress.notify_waiters();
        self.limits.daemon_progress.notify_waiters();
    }

    /// Bytes this exec holds unread.
    pub(super) fn held_bytes(&self) -> usize {
        self.held.load(Ordering::Acquire)
    }

    /// Bytes ever released from this exec's held input.
    pub(super) fn released_bytes(&self) -> usize {
        self.released.load(Ordering::Acquire)
    }

    /// What this exec must release over a window that starts now for the
    /// window to count as drained: the quantum, or all it holds if less.
    pub(super) fn drain_due(&self) -> usize {
        self.limits.quantum.min(self.held_bytes())
    }

    /// The command is running: from here a bound is a stall, not a wait for
    /// the start. The permit is stored, so a pump that reaches the bound
    /// first is not missed.
    pub(super) fn command_started(&self) {
        self.started.store(true, Ordering::Release);
        self.progress.notify_one();
    }

    pub(super) fn started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    /// No more input will arrive; what is queued is still read, then EOF.
    pub(super) fn close(&self) {
        self.lock().eof = true;
        self.waker.wake();
    }

    /// Drops everything queued, releasing it from both counts at once, and
    /// closes: the reader sees EOF.
    pub(super) fn clear(&self) {
        // From here nothing is read: a push that races this (the pump is
        // aborted, not awaited to its end) must not be charged either.
        self.discarding.store(true, Ordering::Release);
        let dropped = {
            let mut g = self.lock();
            let queued: usize = g.chunks.iter().map(Vec::len).sum();
            let dropped = queued.saturating_sub(g.offset);
            g.chunks.clear();
            g.offset = 0;
            g.eof = true;
            dropped
        };
        self.release(dropped);
        self.waker.wake();
    }

    /// Nothing will read what arrives from here on: what is queued is
    /// dropped and released, later pushes are dropped uncharged, and the
    /// reader sees EOF. A single program that closed its stdin is not held
    /// to input it will never read, however fast the client sends it.
    pub(super) fn discard_rest(&self) {
        self.discarding.store(true, Ordering::Release);
        self.clear();
    }

    #[cfg(test)]
    pub(super) fn discarding(&self) -> bool {
        self.discarding.load(Ordering::Acquire)
    }
}

impl Drop for HeldInput {
    /// Whatever this exec still counts leaves the daemon's total with it:
    /// no path may leave the shared budget overstated.
    fn drop(&mut self) {
        let left = self.held.swap(0, Ordering::AcqRel);
        if left > 0 {
            self.limits.daemon_held.fetch_sub(left, Ordering::AcqRel);
            self.limits.daemon_progress.notify_waiters();
        }
    }
}

/// Where the bridge reads a command's input from.
pub(super) trait ExecInput: AsyncRead + Unpin {
    /// The command is running and can read from here on.
    fn command_started(&mut self) {}
    /// Nothing will read what arrives from here on; stop holding it.
    fn discard_rest(&mut self) {}
}

impl ExecInput for HeldInputReader {
    fn command_started(&mut self) {
        self.0.command_started();
    }
    fn discard_rest(&mut self) {
        self.0.discard_rest();
    }
}

#[cfg(test)]
impl ExecInput for tokio::io::DuplexStream {}

/// The bridge's stdin: reads the held input in order, releasing each byte
/// from the counts as it is read; EOF once the pump has closed the input
/// (or cleared it) and the queue is empty. Dropping it clears what is left.
pub(super) struct HeldInputReader(pub(super) Arc<HeldInput>);

impl AsyncRead for HeldInputReader {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let held = &self.0;
        let mut g = held.lock();
        let offset = g.offset;
        let taken = g.chunks.front().map(|front| {
            let avail = front.get(offset..).unwrap_or_default();
            let n = avail.len().min(buf.remaining());
            buf.put_slice(avail.get(..n).unwrap_or_default());
            (n, offset + n >= front.len())
        });
        let read = if let Some((n, done)) = taken {
            if done {
                g.chunks.pop_front();
                g.offset = 0;
            } else {
                g.offset += n;
            }
            Some(n)
        } else if g.eof {
            Some(0)
        } else {
            // Registered under the lock, so a push that lands after the
            // check cannot slip between it and the registration.
            held.waker.register(cx.waker());
            None
        };
        drop(g);
        match read {
            Some(n) => {
                held.release(n);
                std::task::Poll::Ready(Ok(()))
            }
            None => std::task::Poll::Pending,
        }
    }
}

impl Drop for HeldInputReader {
    fn drop(&mut self) {
        self.0.clear();
    }
}

/// Takes the SSH channel's read half off the channel as it arrives into
/// `held` (the bridge reads it from there) and reports how the exec is to
/// end, if the client goes or the held input crosses a bound.
///
/// The channel is read without ever waiting on the command. russh delivers
/// each packet by awaiting a bounded per-channel queue, and a session loop
/// parked on that queue delivers nothing to *any* channel, including this
/// command's own output, whose draining is what lets the command read its
/// stdin again (gominimal/inbox#1089, Eugeny/russh#730). So `Data` is
/// queued, bounded per exec and for the daemon as a whole
/// ([`HeldInputLimits`]): past either, the queue is cleared (its bytes
/// released at once), the command sees EOF, and `end` carries the bound so
/// the bridge ends the exec under that reason.
///
/// `Eof` closes the held input (the command sees EOF once it has read what
/// is queued) but keeps watching the channel: `min task run` from a
/// terminal half-closes stdin straight away, so a disconnect almost always
/// arrives *after* EOF and must still be seen. `Close`, or the end of `msgs`
/// (the channel's sender dropped with the connection), sends
/// [`ExecEnd::ClientLost`] and returns.
pub(super) async fn pump_channel_input<M>(
    mut msgs: M,
    held: Arc<HeldInput>,
    end: watch::Sender<Option<ExecEnd>>,
) where
    M: Stream<Item = russh::ChannelMsg> + Unpin,
{
    let end = Arc::new(end);
    let _registered = Registered::new(&held, &end);
    // The wait at a bound, kept across channel chunks: a client that feeds
    // one byte per chunk while the command reads one byte per window would
    // otherwise get every chunk in after one read and a fresh window for
    // the next, and an exec at its cap would never be ended (#2238's
    // trickle, in small chunks). The wait begins at the first chunk refused
    // and ends only when a quantum has drained since it began.
    let mut wait: Option<BoundWait> = None;
    let mut open = true;
    loop {
        match msgs.next().await {
            Some(russh::ChannelMsg::Data { data }) => {
                if !open {
                    continue;
                }
                // At a bound the pump stops taking from the channel, which
                // parks the connection behind russh's buffer, for a bounded
                // time: until the command starts (a fast client puts the cap
                // in flight before a command spawns), up to `unstarted`, and once it runs, for
                // at most `stall` without this exec reading a byte, or, for
                // an exec that holds nothing at the daemon bound, `starved`.
                // The window restarts only on this exec's own reads; another
                // exec's release wakes the pump to retry, at the daemon bound
                // only, and leaves the window where it was.
                loop {
                    let bound = match held.push(&data) {
                        Ok(()) => {
                            // A chunk that fits ends the wait only once a
                            // quantum has drained since it began; a byte
                            // read per chunk keeps the window where it is,
                            // paused: the window counts time at the bound,
                            // not the gap until the client's next chunk.
                            match wait.as_mut() {
                                Some(w) if w.window.drained(&held) => wait = None,
                                Some(w) => w.paused = Some(tokio::time::Instant::now()),
                                None => {}
                            }
                            break;
                        }
                        Err(bound) => bound,
                    };
                    let w = wait.get_or_insert_with(|| BoundWait::begin(&held));
                    if let Some(paused) = w.paused.take() {
                        // Back at the bound: the time away does not count
                        // against the window, and a starved wait's holders
                        // are looked at afresh.
                        w.since += paused.elapsed();
                        w.holders = None;
                    }
                    let since = w.since;
                    // The unstarted grace runs from the first refusal and is
                    // not moved by wake-ups: another exec's release wakes
                    // this wait, and must not keep an unstarted command's
                    // exec alive past its grace.
                    let unstarted_from = w.began;
                    if !held.started() {
                        tokio::select! {
                            _ = held.progress.notified() => {}
                            _ = held.limits.daemon_progress.notified() => {}
                            () = tokio::time::sleep_until(unstarted_from + held.limits.unstarted) => {
                                tracing::warn!(
                                    ?bound,
                                    waited_ms = u64::try_from(held.limits.unstarted.as_millis())
                                        .unwrap_or(u64::MAX),
                                    "exec: the command had not started when the wait at an input bound ran out; ending the exec",
                                );
                                held.clear();
                                end.send_replace(Some(ExecEnd::InputHeldUnstarted(bound)));
                                return;
                            }
                        }
                        let began = w.began;
                        *w = BoundWait::begin(&held);
                        w.began = began;
                        continue;
                    }
                    let daemon_bound = matches!(bound, HeldBound::Daemon);
                    // The daemon's budget is full of other execs' input and
                    // this one holds nothing: it is not the one not reading,
                    // and it waits for them, up to `starved`.
                    let starved = daemon_bound && held.held_bytes() == 0;
                    if starved && !w.starved_warned {
                        w.starved_warned = true;
                        tracing::warn!(
                            daemon = held.limits.daemon,
                            "exec: the daemon's input budget is held by other execs; this one waits for it",
                        );
                    }
                    let allowed = if starved {
                        if w.holders.is_none() {
                            w.holders = Some(HolderAtWindow::snapshot(&held));
                        }
                        held.limits.starved
                    } else {
                        held.limits.stall
                    };
                    tokio::select! {
                        _ = held.progress.notified() => {
                            // The window restarts on a quantum, not a byte:
                            // a read that drains less keeps the window where
                            // it was, and the retry below still happens.
                            if w.window.drained(&held) {
                                *w = BoundWait::begin(&held);
                            }
                            continue;
                        }
                        _ = held.limits.daemon_progress.notified(), if daemon_bound => continue,
                        () = tokio::time::sleep_until(since + allowed) => {}
                    }
                    // Starved by holders that are not draining: the largest
                    // of them is the one ended, not this exec, and the wait
                    // goes on with a fresh window. Only when every holder
                    // is draining (a genuinely busy daemon) does the wait
                    // end this exec, as the ceiling always did.
                    if starved
                        && let Some(victim) =
                            w.holders.take().and_then(HolderAtWindow::not_draining)
                    {
                        tracing::warn!(
                            held = victim.held.held_bytes(),
                            waited_ms = u64::try_from(allowed.as_millis()).unwrap_or(u64::MAX),
                            "exec: the daemon's input budget is held by an exec that read none of it for the whole window; ending that exec, not this one",
                        );
                        victim.held.clear();
                        victim
                            .end
                            .send_replace(Some(ExecEnd::InputHeldOver(HeldBound::Daemon)));
                        *w = BoundWait::begin(&held);
                        continue;
                    }
                    tracing::warn!(
                        ?bound,
                        starved,
                        per_exec = held.limits.per_exec,
                        daemon = held.limits.daemon,
                        waited_ms = u64::try_from(allowed.as_millis()).unwrap_or(u64::MAX),
                        "exec: the command's input stayed at a bound for the whole window; ending the exec",
                    );
                    held.clear();
                    end.send_replace(Some(ExecEnd::InputHeldOver(bound)));
                    return;
                }
            }
            Some(russh::ChannelMsg::Eof) => {
                open = false;
                held.close();
            }
            Some(russh::ChannelMsg::Close) | None => {
                // Released at once, as the bound-over path does: nothing of
                // a gone client's is held against the daemon's budget while
                // its command is still being ended.
                held.clear();
                end.send_replace(Some(ExecEnd::ClientLost));
                return;
            }
            Some(_) => {}
        }
    }
}

/// Where an exec's drain stood when its stall window began, and what it
/// owed: the window counts as drained once the exec has released that much
/// since ([`HeldInput::drain_due`]).
pub(super) struct DrainWindow {
    pub(super) released_at_start: usize,
    pub(super) due: usize,
}

impl DrainWindow {
    pub(super) fn begin(held: &HeldInput) -> Self {
        Self {
            released_at_start: held.released_bytes(),
            due: held.drain_due(),
        }
    }

    pub(super) fn drained(&self, held: &HeldInput) -> bool {
        held.released_bytes().saturating_sub(self.released_at_start) >= self.due
    }
}

/// The pump's wait at a bound, kept across channel chunks until a quantum
/// drains ([`DrainWindow`]): when it began, the drain it is owed, the
/// holders a starved wait is waiting on (taken once per window) and whether
/// the starved warning went out.
pub(super) struct BoundWait {
    /// When the wait first hit a bound; the unstarted grace runs from here.
    pub(super) began: tokio::time::Instant,
    pub(super) since: tokio::time::Instant,
    pub(super) window: DrainWindow,
    pub(super) holders: Option<Vec<HolderAtWindow>>,
    pub(super) starved_warned: bool,
    /// Set while the last chunk fit and no quantum has drained: the window
    /// is paused, and the time until the next refusal is not counted.
    pub(super) paused: Option<tokio::time::Instant>,
}

impl BoundWait {
    pub(super) fn begin(held: &HeldInput) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            began: now,
            since: now,
            window: DrainWindow::begin(held),
            holders: None,
            starved_warned: false,
            paused: None,
        }
    }
}

/// A holder of the daemon's budget as a starved wait found it: the exec,
/// its end handle, and the drain it owes over the wait's window.
pub(super) struct HolderAtWindow {
    pub(super) held: Arc<HeldInput>,
    pub(super) end: Arc<watch::Sender<Option<ExecEnd>>>,
    pub(super) window: DrainWindow,
}

impl HolderAtWindow {
    /// Every other live exec holding input right now, whose command is
    /// running. One whose command has not started holds input it cannot read
    /// yet and is under its own `unstarted` grace, which ends it on its own
    /// terms; it is not a holder another exec may end.
    ///
    /// The registry spans every session of this daemon, and the daemon
    /// serves one user (`rpc.rs` refuses any peer whose uid is not the
    /// daemon's own, and the socket is mode 0600): every exec here is that
    /// user's, so ending the one
    /// that is not reading is a fairness rule among their own commands, not
    /// a boundary between tenants.
    pub(super) fn snapshot(waiter: &Arc<HeldInput>) -> Vec<Self> {
        waiter
            .limits
            .registry()
            .iter()
            .filter_map(|entry| {
                let held = entry.held.upgrade()?;
                if Arc::ptr_eq(&held, waiter) || held.held_bytes() == 0 || !held.started() {
                    return None;
                }
                let window = DrainWindow::begin(&held);
                Some(Self {
                    held,
                    end: Arc::clone(&entry.end),
                    window,
                })
            })
            .collect()
    }

    /// The largest holder that did not drain what it owed over the window,
    /// if any did not.
    pub(super) fn not_draining(seen: Vec<Self>) -> Option<Self> {
        seen.into_iter()
            .filter(|holder| holder.held.held_bytes() > 0 && !holder.window.drained(&holder.held))
            .max_by_key(|holder| holder.held.held_bytes())
    }
}

/// An exec's entry in its daemon's [`ExecRegistry`] for as long as its pump
/// runs; removed when the pump returns.
pub(super) struct Registered {
    pub(super) held: std::sync::Weak<HeldInput>,
    pub(super) registry: &'static ExecRegistry,
}

impl Registered {
    pub(super) fn new(held: &Arc<HeldInput>, end: &Arc<watch::Sender<Option<ExecEnd>>>) -> Self {
        held.limits.registry().push(RegisteredExec {
            held: Arc::downgrade(held),
            end: Arc::clone(end),
        });
        Self {
            held: Arc::downgrade(held),
            registry: held.limits.registry,
        }
    }
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.registry
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retain(|entry| !std::sync::Weak::ptr_eq(&entry.held, &self.held));
    }
}

/// Bridges a [`Stream`] of [`Process`]es with the SSH channel halves,
/// running each child to completion before pulling the next.
///
/// The SSH channel reader/writers (`r`, `w`, `e`) are borrowed across
/// the whole sequence; only child stdio is re-grabbed per step. If the
/// SSH client sends stdin EOF mid-sequence, subsequent children get
/// immediate EOF on their stdin without us having to keep reading.
///
/// `client_lost` is a watch receiver set to `true` when the SSH client
/// disconnects (channel close or sender drop). The bridge kills the
/// current child and stops the sequence when it fires, whatever exit
/// code that child reports.
///
/// On any non-zero exit the sequence stops and that code is returned —
/// matching `set -e` shell semantics for chained task invocations. If
/// the stream yields an `Err` item (e.g. setup failed in the producer),
/// the message is written to the SSH stderr stream and the bridge
/// returns exit 1.
///
/// Returns the SSH-encoded exit code of the last process run (or 0 if
/// the stream was empty).
#[cfg(test)]
pub(super) async fn bridge<S, P, R, W, E>(
    channel_id: impl Display + Clone,
    stream: S,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    client_lost: watch::Receiver<Option<ExecEnd>>,
    unread: UnreadStdin,
) -> u32
where
    P: Process,
    S: Stream<Item = io::Result<P>> + Unpin,
    R: ExecInput,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    bridge_until_end(channel_id, stream, r, w, e, client_lost, unread)
        .await
        .0
}

/// Resolves once the exec's end is set; never, if its sender is gone with
/// none set. Reads with `borrow`, not `borrow_and_update`, so the end stays
/// unseen for the `changed()` of [`bridge_one`] in the race where a command
/// starts in the same instant.
pub(super) async fn until_ended(end: &mut watch::Receiver<Option<ExecEnd>>) {
    loop {
        if end.borrow().is_some() {
            return;
        }
        if end.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// [`bridge`], and the stream back when the exec's end came while a command
/// was still starting. The wait for each command's start is raced against
/// the end ([`ExecEnd`]), so an exec whose client goes, or whose input's
/// wait at a bound runs out ([`ExecEnd::InputHeldUnstarted`]), ends at once
/// rather than once a spawn that may never return does. It reports exit 1,
/// as a spawn that fails does. The start in flight lives in the stream, not
/// in the abandoned `next()`, so the caller can finish it later and end
/// what it yields ([`reap_late_start`]): dropping it instead could orphan a
/// task's sandboxed child.
pub(super) async fn bridge_until_end<S, P, R, W, E>(
    channel_id: impl Display + Clone,
    mut stream: S,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    mut client_lost: watch::Receiver<Option<ExecEnd>>,
    unread: UnreadStdin,
) -> (u32, Option<S>)
where
    P: Process,
    S: Stream<Item = io::Result<P>> + Unpin,
    R: ExecInput,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let mut stdin_open = true;
    let mut last_exit: u32 = 0;
    loop {
        let next = tokio::select! {
            // A command that starts in the same instant as the end is
            // bridged, and `bridge_one` ends it at once.
            biased;
            next = stream.next() => next,
            () = until_ended(&mut client_lost) => {
                tracing::warn!(
                    %channel_id,
                    end = ?*client_lost.borrow(),
                    "exec: ended while its command was starting; the start is ended when it returns",
                );
                return (1, Some(stream));
            }
        };
        let process = match next {
            Some(Ok(p)) => p,
            None => break,
            Some(Err(err)) => {
                tracing::warn!(
                    %channel_id, error = %err,
                    "exec: failed to spawn next process in sequence; reporting exit 1",
                );
                let _ = e
                    .write_all(format!("minimald: failed to spawn process: {err}\n").as_bytes())
                    .await;
                last_exit = 1;
                break;
            }
        };
        r.command_started();
        last_exit = bridge_one(
            channel_id.clone(),
            process,
            r,
            w,
            e,
            &mut stdin_open,
            &mut client_lost,
            unread,
        )
        .await;
        // `changed()` fires once per transition, so a later step would
        // never see a disconnect an earlier step already consumed: a child
        // that exits 0 just as the client goes must still end the sequence.
        if last_exit != 0 || client_lost.borrow().is_some() {
            break;
        }
    }
    (last_exit, None)
}

/// Drives one [`Process`] to completion: pumps `r → child stdin` and
/// `child stdout/stderr → w/e` concurrently, and returns the
/// SSH-encoded exit code once **the child exits** — not once its pipes
/// close (gominimal/inbox#566).
///
/// The two are usually the same event: when the child exits the kernel
/// closes its stdio fds and our read side sees EOF. They come apart
/// when the child forks a grandchild that inherits stdout/stderr and
/// outlives it — `sh -c 'sleep 20 & echo STARTED'`. The write ends stay
/// open, so waiting for EOF would hold the caller for as long as the
/// grandchild lives. Note that the direct child here is the `nsenter`
/// shim, which itself blocks in `Child::wait` on the session shell, so
/// "the child exited" already means "the user's command finished";
/// pipelines and foreground jobs are waited on by that shell and are
/// unaffected.
///
/// So the loop ends on the *first* of: both output streams at EOF, the
/// child exiting, the SSH client disconnecting, or an SSH-channel write
/// failing. On child exit we then, in order:
///
/// 1. **Drain what is already buffered** ([`drain_ready`]): everything
///    the child wrote before exiting is sitting in the pipe and still
///    belongs to the caller. Reads stop the moment a pipe would block,
///    so this costs nothing when there is no grandchild.
/// 2. **Return the exit code.**
/// 3. **Hand any still-open read end to a detached drain-and-discard
///    task** ([`spawn_pipe_drain`]). Dropping it instead would leave
///    the grandchild writing into a pipe with no reader — EPIPE, and
///    SIGPIPE, which kills a detached service on its first log line.
///
/// The trade is that a grandchild's output after we return is silently
/// discarded; `nohup cmd >/dev/null 2>&1 &` is the way to detach
/// cleanly (documented in `docs/reference/cli-min.md`). A `nohup`'d job
/// stays in the exec's process group, which a client lost mid-exec ends
/// (see `nsenter::GROUP_GRACE`), so a job that must survive the client
/// going away is started with `setsid`: `setsid nohup cmd >/dev/null 2>&1 &`.
///
/// Polling the I/O sources in a single `select!` lets a slow consumer
/// on one side apply backpressure without starving the others, which is
/// why the branches stay unbiased rather than ranking `process.wait()`
/// last. The cost is that `wait` can win a race against readable
/// output; step 1 is what makes that harmless. Nothing is lost to the
/// branches `select!` cancels either way: `read` and the child-stdin
/// `write` are cancel-safe, and the SSH-channel writes live in branch
/// *handlers*, which run after the `select!` has already resolved.
///
/// On an SSH-channel write failure or client disconnect we stop and
/// `start_kill` the child: with no one reading its output the pipe
/// buffer would fill, the child would block on write, and `wait` would
/// never resolve.
///
/// `stdin_open` is threaded by `&mut` so once the SSH client closes
/// stdin (EOF or read error), every subsequent child in the sequence
/// sees immediate EOF on its stdin without re-reading from `r`.
#[expect(
    clippy::too_many_arguments,
    reason = "the channel's three halves, the sequence's stdin state, and the two ways an exec ends"
)]
pub(super) async fn bridge_one<P, R, W, E>(
    channel_id: impl Display,
    mut process: P,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    stdin_open: &mut bool,
    client_lost: &mut watch::Receiver<Option<ExecEnd>>,
    unread: UnreadStdin,
) -> u32
where
    P: Process,
    R: ExecInput,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let (stdin, mut child_stdout, mut child_stderr) = process
        .take_stdio()
        .expect("freshly spawned Process must yield stdio on first take_stdio");
    // If the SSH client already sent EOF in an earlier step, drop the
    // child's stdin straight away so it sees EOF immediately.
    let mut child_stdin = if *stdin_open { Some(stdin) } else { None };

    let mut stdin_buf = vec![0u8; 8 * 1024];
    let mut stdout_buf = vec![0u8; 8 * 1024];
    let mut stderr_buf = vec![0u8; 8 * 1024];

    let mut stdout_open = true;
    let mut stderr_open = true;
    // Set when a write to the SSH channel fails. The channel is gone,
    // so there is nothing left to relay and the child has to be killed
    // rather than left to block on a pipe nobody drains.
    let mut ssh_write_failed = false;
    // `Some` once the child has been reaped; also the loop's exit
    // signal, since anything still holding the pipes open past this
    // point is a grandchild we do not wait for.
    let mut child_exit: Option<io::Result<Option<i32>>> = None;
    // Cleared once the client-loss sender is dropped without signalling:
    // `changed()` would then resolve `Err` on every poll and spin the loop.
    let mut client_watch_open = true;
    // A stdin read parked behind a full child pipe. The bytes are copied
    // out of `stdin_buf` because the read branch borrows it on the next
    // iteration. Cleared by the write branch as it drains the slice.
    let mut pending: Option<(Vec<u8>, usize)> = None;

    while (stdout_open || stderr_open) && !ssh_write_failed && child_exit.is_none() {
        tokio::select! {
            // Gated on `child_stdin.is_some()`: if the current child's
            // stdin pipe broke mid-step (write failure below) we stop
            // reading from `r` for the rest of this step, but leave
            // `*stdin_open` set so the next child in the sequence picks
            // up where we left off. Gated on a drained `pending` so at
            // most one chunk the child has not accepted is ever queued.
            // `select!` evaluates every gate before it builds any branch
            // future, so a gate may borrow what a future later holds.
            // With `UnreadStdin::Discard` the held input is told to drop
            // the rest once the command's stdin is found closed (the write
            // branch), and the read goes on only to see the EOF that gives:
            // a single program has no other reader, and input it never
            // reads must not be held against it.
            read_res = r.read(&mut stdin_buf), if *stdin_open && pending.is_none()
                && (child_stdin.is_some() || unread == UnreadStdin::Discard) => {
                match read_res {
                    Ok(0) => {
                        *stdin_open = false;
                        // Dropping the write half closes the pipe so
                        // the child sees EOF on its stdin.
                        child_stdin = None;
                    }
                    Err(err) => {
                        tracing::warn!(
                            %channel_id, error = %err,
                            "exec: failed to read stdin from ssh channel; closing child stdin",
                        );
                        *stdin_open = false;
                        child_stdin = None;
                    }
                    Ok(n) => {
                        if child_stdin.is_some() {
                            pending = Some((stdin_buf.get(..n).unwrap_or_default().to_vec(), 0));
                        }
                    }
                }
            }
            // Drives a parked stdin write to the child from inside the
            // select, so a slow child cannot keep the loop from polling
            // the child's stdout and stderr. `write` is cancel-safe: a
            // branch that loses the select loses nothing the child has
            // not already accepted, which the offset below accounts for.
            write_res = async {
                match (child_stdin.as_mut(), pending.as_mut()) {
                    (Some(cs), Some((data, offset))) => cs.write(&data[*offset..]).await,
                    _ => std::future::pending::<io::Result<usize>>().await,
                }
            }, if pending.is_some() && child_stdin.is_some() => {
                match write_res {
                    Ok(0) => {
                        tracing::warn!(
                            %channel_id,
                            "exec: child accepted zero bytes of stdin; closing child stdin",
                        );
                        child_stdin = None;
                        pending = None;
                        if unread == UnreadStdin::Discard {
                            r.discard_rest();
                        }
                    }
                    Err(err) => {
                        tracing::warn!(
                            %channel_id, error = %err,
                            "exec: failed to write stdin to child; closing child stdin",
                        );
                        child_stdin = None;
                        pending = None;
                        if unread == UnreadStdin::Discard {
                            r.discard_rest();
                        }
                    }
                    Ok(n) => {
                        let (data, offset) = pending.as_mut().expect("gated on a pending write");
                        *offset += n;
                        if *offset >= data.len() {
                            pending = None;
                        }
                    }
                }
            }
            read_res = child_stdout.read(&mut stdout_buf), if stdout_open => {
                match read_res {
                    Ok(0) => stdout_open = false,
                    Err(err) => {
                        tracing::warn!(
                            %channel_id, error = %err,
                            "exec: failed to read child stdout; treating as eof",
                        );
                        stdout_open = false;
                    }
                    Ok(n) => {
                        if let Err(err) = w.write_all(&stdout_buf[..n]).await {
                            tracing::warn!(
                                %channel_id, error = %err,
                                "exec: failed to forward child stdout to ssh channel; killing child",
                            );
                            ssh_write_failed = true;
                        }
                    }
                }
            }
            read_res = child_stderr.read(&mut stderr_buf), if stderr_open => {
                match read_res {
                    Ok(0) => stderr_open = false,
                    Err(err) => {
                        tracing::warn!(
                            %channel_id, error = %err,
                            "exec: failed to read child stderr; treating as eof",
                        );
                        stderr_open = false;
                    }
                    Ok(n) => {
                        if let Err(err) = e.write_all(&stderr_buf[..n]).await {
                            tracing::warn!(
                                %channel_id, error = %err,
                                "exec: failed to forward child stderr to ssh channel; killing child",
                            );
                            ssh_write_failed = true;
                        }
                    }
                }
            }
            // Lowest-value branch but deliberately unbiased: `select!`
            // picks at random among ready branches, so this can win a
            // race with pending output. That is what the post-loop
            // `drain_ready` covers. Nothing here touches `process`, so
            // the `&mut process` this future holds is uncontended.
            status = process.wait() => child_exit = Some(status),

            // The SSH client disconnected (channel close or sender
            // drop). Kill the child and stop — same path as a failed
            // SSH write (gominimal/inbox#813).
            res = client_lost.changed(), if client_watch_open => {
                if res.is_err() {
                    client_watch_open = false;
                } else if let Some(end) = *client_lost.borrow() {
                    match end {
                        ExecEnd::ClientLost => tracing::warn!(
                            %channel_id,
                            "exec: ssh client disconnected; killing child",
                        ),
                        ExecEnd::InputHeldOver(bound) => tracing::warn!(
                            %channel_id, ?bound,
                            "exec: the command's unread input crossed a bound; ending the exec",
                        ),
                        ExecEnd::InputHeldUnstarted(bound) => tracing::warn!(
                            %channel_id, ?bound,
                            "exec: the command started after its wait at an input bound ran out; ending the exec",
                        ),
                    }
                    ssh_write_failed = true;
                }
            }
        }
    }
    // Stdin still in `pending` when the child exits or both output pipes
    // close is dropped here, as bytes left unread in the child's pipe are.

    // Nobody is reading the child's output any more, so it would wedge
    // on a full pipe and never be reapable. Kill, then fall through to
    // the `wait` below.
    if ssh_write_failed {
        // A `--detach` exec, if one is ever added, must not reach this client-loss kill.
        let _ = process.start_kill();
    }

    // The child is gone but a grandchild may still hold the write ends.
    // Everything the child itself wrote is already in the pipe buffer
    // and still belongs to the caller — take it before returning.
    if child_exit.is_some() {
        let relayed = drain_ready(
            &channel_id,
            &mut child_stdout,
            &mut stdout_open,
            w,
            &mut stdout_buf,
            "stdout",
        )
        .await;
        // A dead SSH channel takes stderr with it; skip the second
        // drain rather than log the same failure twice. Neither flag is
        // cleared — a pipe we stopped reading is exactly the one the
        // background drain below has to keep alive.
        if relayed {
            drain_ready(
                &channel_id,
                &mut child_stderr,
                &mut stderr_open,
                e,
                &mut stderr_buf,
                "stderr",
            )
            .await;
        }
    }

    // Let anything still attached see EOF on its stdin; `*stdin_open`
    // is untouched, so the next child in the sequence still reads `r`.
    drop(child_stdin);

    // Hand off before returning: an orphan writing into a pipe whose
    // read end we dropped takes SIGPIPE and dies. See `spawn_pipe_drain`.
    spawn_pipe_drain(
        channel_id.to_string(),
        stdout_open.then_some(child_stdout),
        stderr_open.then_some(child_stderr),
    );

    let status = match child_exit {
        Some(status) => status,
        // Already killed, or no disconnect signal left to watch.
        None if ssh_write_failed || !client_watch_open => process.wait().await,
        // The loop also ends when the child closes stdout and stderr but
        // keeps running; a disconnect from then on must still kill it.
        None => {
            tokio::select! {
                status = process.wait() => status,
                // Reduced to a bool in the branch: the `watch::Ref` it
                // yields is not `Send` and must not live across the wait.
                lost = async { client_lost.wait_for(|end| end.is_some()).await.is_ok() } => {
                    if lost {
                        tracing::warn!(
                            %channel_id,
                            "exec: ssh client disconnected; killing child",
                        );
                        // A `--detach` exec, if one is ever added, must not reach this
                        // client-loss kill.
                        let _ = process.start_kill();
                    }
                    process.wait().await
                }
            }
        }
    };
    match status {
        Ok(code) => code.unwrap_or(1) as u32,
        Err(err) => {
            tracing::warn!(
                %channel_id, error = %err,
                "exec: failed to wait for child; reporting exit status 1",
            );
            1
        }
    }
}

/// How long [`drain_ready`] waits for a pipe to produce something after
/// the child has been reaped, before concluding that whatever still
/// holds the write end is a grandchild whose output we do not owe the
/// caller.
///
/// Only paid when a grandchild really is holding the pipe: in the
/// ordinary case EOF is already pending and the read returns at once.
pub(super) const DRAIN_GRACE: Duration = Duration::from_millis(100);

/// Relays whatever `src` already has buffered to `sink`, stopping once
/// `src` goes quiet for [`DRAIN_GRACE`].
///
/// Called once the child has been reaped, when a grandchild may be
/// holding the write end open: the bytes the child wrote before exiting
/// are still owed to the caller, but there is nothing beyond them worth
/// waiting for.
///
/// The stopping condition is a short timeout rather than a single
/// `now_or_never` poll, and that distinction is load-bearing. Tokio
/// learns a pipe is readable from a reactor turn, so a lone poll issued
/// on the turn where `wait()` resolved can report "would block" for a
/// pipe that already holds the child's output — silently truncating the
/// common `min session exec echo hi` case. Waiting for readiness
/// instead of guessing at it costs nothing when EOF is already pending
/// (the overwhelmingly common shape) and at most one [`DRAIN_GRACE`]
/// when a grandchild really is holding the write end open.
///
/// Sets `*open = false` on EOF or a read error. Returns `false` if a
/// write to the SSH channel failed, so the caller can stop relaying.
pub(super) async fn drain_ready<S, W>(
    channel_id: &impl Display,
    src: &mut S,
    open: &mut bool,
    sink: &mut W,
    buf: &mut [u8],
    stream_name: &'static str,
) -> bool
where
    S: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    // Bound the drain: a grandchild writing faster than we relay could
    // otherwise keep every read succeeding forever and reintroduce the
    // very hang this function exists to end. 64 rounds of an 8 KiB
    // buffer is many times a pipe's capacity, so a real backlog always
    // fits.
    const MAX_ROUNDS: usize = 64;

    for _ in 0..MAX_ROUNDS {
        if !*open {
            return true;
        }
        // An elapsed timeout means the pipe went quiet: whatever is
        // still holding the write end is not the child we just reaped,
        // so its output is not ours to relay. `read` is cancel-safe, so
        // losing the race here drops no bytes.
        let Ok(read_res) = tokio::time::timeout(DRAIN_GRACE, src.read(buf)).await else {
            return true;
        };
        match read_res {
            Ok(0) => *open = false,
            Err(err) => {
                tracing::warn!(
                    %channel_id, error = %err, stream = stream_name,
                    "exec: failed to read child output while draining; treating as eof",
                );
                *open = false;
            }
            Ok(n) => {
                if let Err(err) = sink.write_all(&buf[..n]).await {
                    tracing::warn!(
                        %channel_id, error = %err, stream = stream_name,
                        "exec: failed to forward drained child output to ssh channel",
                    );
                    return false;
                }
            }
        }
    }
    true
}

/// Reads and discards a grandchild's inherited stdio for as long as it
/// holds the write end open.
///
/// Handed the read ends of an exited child's stdout/stderr once
/// [`bridge_one`] has stopped relaying. Simply dropping them would
/// point the orphan's next write at a pipe with no reader: EPIPE, and
/// SIGPIPE, whose default disposition kills the process — turning a
/// visible hang into a backgrounded service that dies on its first log
/// line. Draining costs two fds and one task for the orphan's life,
/// which is what the blocking bridge held anyway.
///
/// Does nothing (and spawns nothing) when both handles are `None`, the
/// case for every child that closes its pipes on exit.
pub(super) fn spawn_pipe_drain<O, E>(channel_id: String, stdout: Option<O>, stderr: Option<E>)
where
    O: AsyncRead + Unpin + Send + 'static,
    E: AsyncRead + Unpin + Send + 'static,
{
    if stdout.is_none() && stderr.is_none() {
        return;
    }
    tracing::debug!(
        %channel_id,
        "exec: child exited with its stdio still held open; draining in the background",
    );
    // Detached: a grandchild holding the pipes can keep this draining for
    // as long as it likes, and the exec's span must not stay open for it.
    let drain = tracing::info_span!(parent: None, "exec.drain", %channel_id);
    crate::traced::spawn_detached(drain, async move {
        async fn discard<S: AsyncRead + Unpin>(src: Option<S>) {
            let Some(mut src) = src else { return };
            let mut buf = [0u8; 8 * 1024];
            while let Ok(n) = src.read(&mut buf).await {
                if n == 0 {
                    break;
                }
            }
        }
        tokio::join!(discard(stdout), discard(stderr));
        tracing::debug!(%channel_id, "exec: background stdio drain finished");
    });
}
