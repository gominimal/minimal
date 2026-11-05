//! The pipes of an entrypoint that runs without a terminal (T43).
//!
//! A box whose spec does not set `io.pty_enabled` runs its argv entrypoint
//! on three pipes (see [`super::LaunchSpec::runs_on_pipes`]). The host reads
//! the stdout pipe where it reads a terminal's master, and reads the stderr
//! pipe beside it. Both land in the box's output log. A task run takes the
//! streams from the host ([`super::HostHandle::take_entrypoint_io`]) and
//! relays them to its client: stdin in, stdout and stderr out, as three
//! streams.

use super::*;

/// How long a host whose entrypoint runs on pipes holds its output for the
/// task run that started it. The run takes the streams right after the
/// launch returns. Until it does, the output waits in the pipes, so the run
/// gets every byte. A host that no run takes by then reads its output into
/// the log only, and closes the entrypoint's stdin.
pub(super) const FIRST_RELAY_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// How often a host whose entrypoint runs on pipes checks for the
/// entrypoint's exit. A pipe gives no hangup when the process ends while
/// another process holds its write end, so the host loop polls.
pub(super) const PIPE_EXIT_POLL: std::time::Duration = std::time::Duration::from_millis(100);

/// How many chunks of output a relay holds for a run that reads slowly.
/// A full relay stops the host reading the pipe, so the entrypoint waits
/// on its own write.
const RELAY_CHUNKS: usize = 16;

/// How long the host's last drain waits for a run that reads slowly.
const DRAIN_SEND_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

/// What a task run takes from a host whose entrypoint runs on pipes.
pub(crate) struct EntrypointIo {
    /// The write end of the entrypoint's stdin. Only the first run that
    /// takes the streams gets it. Dropping it closes the entrypoint's stdin.
    pub(crate) stdin: Option<std::fs::File>,
    /// What the entrypoint writes to its stdout, from the moment the run
    /// took the streams. Ends when the host ends.
    pub(crate) stdout: mpsc::Receiver<Vec<u8>>,
    /// What the entrypoint writes to its stderr, in the same way.
    pub(crate) stderr: mpsc::Receiver<Vec<u8>>,
}

/// What [`super::HostHandle::take_entrypoint_io`] gets from the host.
pub(crate) enum EntrypointIoTake {
    /// The entrypoint's streams.
    Taken(EntrypointIo),
    /// The entrypoint runs on a terminal, so it has no streams to take.
    OnTerminal,
    /// The host ended before it answered: the entrypoint ended, and no run
    /// took its output while the host held it, or the box was stopped.
    HostGone,
}

/// The run a host relays its entrypoint's output to.
struct PipeRelay {
    stdout: mpsc::Sender<Vec<u8>>,
    stderr: mpsc::Sender<Vec<u8>>,
}

/// Which output stream of the entrypoint a chunk came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PipeStream {
    Stdout,
    Stderr,
}

/// The host's side of an entrypoint that runs on pipes. The stdout pipe is
/// the host's `master`, so it is not here.
pub(super) struct HostPipes {
    /// The write end of the entrypoint's stdin, until a run takes it.
    stdin: Option<std::fs::File>,
    /// The read end of the entrypoint's stderr. `None` once it reads EOF.
    stderr: Option<AsyncFd<std::fs::File>>,
    /// Whether the stdout pipe (the host's master) read EOF.
    pub(super) stdout_eof: bool,
    /// The run the output goes to, beside the log.
    relay: Option<PipeRelay>,
    /// Until when the host holds the output for the first run.
    pub(super) first_relay_deadline: Option<tokio::time::Instant>,
}

impl HostPipes {
    /// The host's side of `pipes`.
    ///
    /// # Errors
    ///
    /// When the stderr pipe cannot be set non-blocking or registered.
    pub(super) fn new(pipes: EntrypointPipes) -> io::Result<Self> {
        set_nonblocking(pipes.stderr.as_raw_fd())?;
        // SAFETY: the `AsyncFd` owns the `File` for its whole life, and
        // nothing reaches the `File` through it to close or replace its fd,
        // so the fd names the same pipe until it is dropped.
        let stderr = unsafe { AsyncFd::register(std::fs::File::from(pipes.stderr)) }?;
        Ok(Self {
            stdin: Some(std::fs::File::from(pipes.stdin)),
            stderr: Some(stderr),
            stdout_eof: false,
            relay: None,
            first_relay_deadline: Some(tokio::time::Instant::now() + FIRST_RELAY_WAIT),
        })
    }

    /// Whether the host holds its output for the first run.
    pub(super) fn holds_output(&self) -> bool {
        self.first_relay_deadline.is_some()
    }

    /// The relay's sender that has no free slot, if one has none. The host
    /// reads no pipe until a slot frees, so the entrypoint waits on its
    /// write and no output is lost.
    pub(super) fn full_relay(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        let relay = self.relay.as_ref()?;
        [&relay.stdout, &relay.stderr]
            .into_iter()
            .find(|tx| tx.capacity() == 0)
            .cloned()
    }

    /// Whether the host reads its pipes now.
    pub(super) fn reads(&self) -> bool {
        !self.holds_output() && self.full_relay().is_none()
    }

    /// The stderr pipe, while it is open and the host reads.
    pub(super) fn stderr_to_read(&self) -> Option<&AsyncFd<std::fs::File>> {
        self.stderr.as_ref().filter(|_| self.reads())
    }

    /// Notes that the stderr pipe read EOF.
    pub(super) fn stderr_ended(&mut self) {
        self.stderr = None;
    }

    /// The first run did not take the output in time: the host reads it
    /// into the log only, and closes the entrypoint's stdin, which no run
    /// can write now.
    pub(super) fn first_relay_missed(&mut self, session: &str) {
        self.first_relay_deadline = None;
        if self.relay.is_none() {
            self.stdin = None;
            tracing::info!(
                session,
                "no task run took the entrypoint's streams; its output goes to the box log only"
            );
        }
    }

    /// Hands a run the entrypoint's streams. A run that takes them later
    /// replaces the earlier one, whose streams end.
    pub(super) fn take_io(&mut self) -> EntrypointIo {
        let (stdout_tx, stdout) = mpsc::channel(RELAY_CHUNKS);
        let (stderr_tx, stderr) = mpsc::channel(RELAY_CHUNKS);
        self.relay = Some(PipeRelay {
            stdout: stdout_tx,
            stderr: stderr_tx,
        });
        self.first_relay_deadline = None;
        EntrypointIo {
            stdin: self.stdin.take(),
            stdout,
            stderr,
        }
    }

    /// Sends `bytes` to the run, when one relays. The caller reads only
    /// while the relay has a free slot ([`Self::reads`]), so the send never
    /// waits. A run that went away is dropped, and the output goes on to
    /// the log (BOX-015).
    pub(super) fn relay(&mut self, stream: PipeStream, bytes: &[u8]) {
        let Some(relay) = self.relay.as_ref() else {
            return;
        };
        let tx = match stream {
            PipeStream::Stdout => &relay.stdout,
            PipeStream::Stderr => &relay.stderr,
        };
        if tx.try_send(bytes.to_vec()).is_err() {
            tracing::debug!("the task run stopped reading the entrypoint's output");
            self.relay = None;
        }
    }

    /// Drops the relay of a run whose receiver is gone.
    pub(super) fn relay_gone(&mut self) {
        self.relay = None;
    }

    /// Reads what is left in both pipes once the entrypoint ended, into
    /// `log` and to the run, and then ends the run's streams. Reads stop at
    /// EOF, or where a pipe has nothing more now: a process that the
    /// entrypoint left behind can hold a write end.
    pub(super) async fn drain(&mut self, stdout: &AsyncFd<std::fs::File>, log: &mut BoxOutputLog) {
        let mut buf = vec![0u8; 8 * 1024];
        for stream in [PipeStream::Stdout, PipeStream::Stderr] {
            loop {
                let fd = match stream {
                    PipeStream::Stdout if !self.stdout_eof => stdout,
                    PipeStream::Stderr => match self.stderr.as_ref() {
                        Some(fd) => fd,
                        None => break,
                    },
                    PipeStream::Stdout => break,
                };
                let n = match fd.get_ref().read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                log.write(&buf[..n]);
                if let Some(relay) = self.relay.as_ref() {
                    let tx = match stream {
                        PipeStream::Stdout => &relay.stdout,
                        PipeStream::Stderr => &relay.stderr,
                    };
                    if tx
                        .send_timeout(buf[..n].to_vec(), DRAIN_SEND_WAIT)
                        .await
                        .is_err()
                    {
                        self.relay = None;
                    }
                }
            }
        }
        self.relay = None;
        self.stdin = None;
    }
}

/// Waits until `fd` is readable and reads one chunk from it. `Ok` with no
/// bytes is EOF.
pub(super) async fn read_ready(fd: &AsyncFd<std::fs::File>) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let mut guard = fd.readable().await?;
        match guard.try_io(|fd| fd.get_ref().read(&mut buf)) {
            Ok(Ok(n)) => {
                buf.truncate(n);
                return Ok(buf);
            }
            Ok(Err(e)) => return Err(e),
            Err(_would_block) => {}
        }
    }
}
