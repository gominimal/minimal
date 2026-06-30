//! SSH `exec` request handling: spawns a process and bridges its stdio
//! over an SSH channel.
//!
//! Process spawning is abstracted via the [`Exec`] / [`Process`] traits
//! so the bridge logic can be exercised with a mock in tests without
//! going through `tokio::process` or russh.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io;
use std::process::Stdio;

use futures::{
    StreamExt,
    stream::{self, BoxStream, Stream},
};
use paths::DaemonAbsPath;
use russh::{
    Channel, ChannelId,
    server::{Msg, Session},
};
use sessions::SessionId;
use tempfile::TempDir;
use tokio::net::unix::pipe;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    spawn,
};

use crate::{
    ChannelConfig, MINIMAL_SESSION_ID_ENV,
    connection::{ConnectionError, ConnectionHandle},
    server::ServerStateHandle,
    session::SessionHandle,
    sessions::SessionKeyPredicate,
};

/// "What to run." Turns into a [`Stream`] of one or more process
/// spawns, run back-to-back.
///
/// Modelling as a `Stream` rather than a two-trait `IntoIter`/`Iter`
/// split is a deliberate choice: some impls (notably [`TaskExec`]) need
/// stateful resources to outlive every spawned process — that state has
/// no honest home in a separate "resolution" step, so we let it live on
/// the stack frame of the impl's producer (or on the stream's state
/// directly). Trivial impls like [`TokioExec`] use [`stream::once`].
///
/// Setup errors and per-spawn errors both surface as `Err` items in the
/// stream; the bridge handles them uniformly.
pub trait Exec: Send + 'static {
    type Process: Process;

    fn exec(self, session: SessionHandle) -> BoxStream<'static, io::Result<Self::Process>>;
}

/// A handle to one spawned process: stdio plus lifecycle controls.
///
/// `wait` MUST be cancel-safe — callers poll it inside `tokio::select!`,
/// so the future may be dropped and re-awaited across loop iterations.
pub trait Process: Send + 'static {
    type Stdin: AsyncWrite + Unpin + Send + 'static;
    type Stdout: AsyncRead + Unpin + Send + 'static;
    type Stderr: AsyncRead + Unpin + Send + 'static;

    /// Returns all three stdio handles the first time it's called,
    /// `None` thereafter (per-handle `Option::take` semantics, matching
    /// `tokio::process::Child`).
    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)>;

    /// Resolves when the process exits. `Ok(None)` means the process
    /// was terminated by a signal rather than exiting with a numeric
    /// code.
    async fn wait(&mut self) -> io::Result<Option<i32>>;

    /// Request termination. Idempotent. Returns immediately — the
    /// caller is expected to follow up with `wait` for the actual exit.
    fn start_kill(&mut self) -> io::Result<()>;
}

/// An [`Exec`] that runs a minimal task wired to ssh.
#[derive(Debug, Clone)]
pub struct TaskExec {
    pub task: String,
    pub args: Option<args::ArgsSet>,
}

impl Exec for TaskExec {
    type Process = HakoniwaProcess;

    fn exec(self, session: SessionHandle) -> BoxStream<'static, io::Result<Self::Process>> {
        // 1-slot request/response channels: the producer only spawns
        // the next child once the consumer pulls. Dropping a
        // `HakoniwaProcess` orphans the child, so we don't want to
        // spawn one we may never deliver.
        let (req_tx, req_rx) = mpsc::channel::<()>(1);
        let (proc_tx, proc_rx) = mpsc::channel::<io::Result<HakoniwaProcess>>(1);

        // Producer task: holds `env`, `container`, and the invocation
        // list on its stack frame. `env` owns the temp dirs and the
        // `ClaudeMdPatch` whose `Drop` must run only after every
        // spawned child has finished — which is exactly when the
        // consumer drops the stream, the channels close, this task
        // exits, and `env` falls out of scope.
        tokio::spawn(task_producer(self, session, req_rx, proc_tx));

        // Pull-based stream: each `poll_next` sends a request and waits
        // for the producer's response. `None` from either channel ends
        // the stream.
        stream::unfold((req_tx, proc_rx), |(req_tx, mut proc_rx)| async move {
            req_tx.send(()).await.ok()?;
            let item = proc_rx.recv().await?;
            Some((item, (req_tx, proc_rx)))
        })
        .boxed()
    }
}

/// Producer side of [`TaskExec::exec`]. Inlined in one async fn so that
/// `env` lives on a single stack frame across every spawn — that frame
/// is alive for the whole life of this tokio task, which in turn is
/// governed by the consumer's stream.
async fn task_producer(
    exec: TaskExec,
    session: SessionHandle,
    mut req_rx: mpsc::Receiver<()>,
    proc_tx: mpsc::Sender<io::Result<HakoniwaProcess>>,
) {
    // Wrap the whole body in a fallible async block so setup errors
    // short-circuit with `?`. An `Err` outcome triggers the
    // "wait for the first request, deliver error, exit" branch below.
    let outcome: io::Result<()> = async {
        let mut ctx = session.context().await.map_err(io::Error::other)?;
        // `graph_from_all_packages` is CPU-heavy (nickel evaluation,
        // graph construction) — run it on the blocking pool so it
        // doesn't stall the async executor.
        let (mut ctx, graph_result) = tokio::task::spawn_blocking(move || {
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());
            (ctx, r)
        })
        .await
        .map_err(io::Error::other)?;
        let graph = graph_result.map_err(io::Error::other)?;
        let (task, mut graph) = ctx
            .task(graph, &exec.task)
            .map_err(|e| io::Error::other(e.to_string()))?
            .ok_or_else(|| io::Error::other(format!("No such task: {}", exec.task)))?;
        // A task inherits its session's network isolation, through the same
        // sandbox2 `Network` seam the interactive session uses, rather than the
        // old hardcoded `HostNet` (which leaked host egress to a no-net
        // session's tasks). `NoNet`/`HostNet` are fully handled by sandbox2's
        // netns decision. `OwnIp` additionally needs the per-PTask tap/switch
        // attach (as `attach_own_ip` does for sessions); wiring that into the
        // task-exec producer/consumer is a follow-up (and is blocked by the
        // guest rootfs lacking `ip`/`nsenter`), so an `OwnIp` session's task
        // falls back to `HostNet` here instead of running in an empty,
        // egress-less netns.
        let network_mode = match session.record().await.network {
            m @ (sandbox2::NetworkMode::HostNet | sandbox2::NetworkMode::NoNet) => m,
            // OwnIp falls back to HostNet (the per-PTask tap/switch attach for the
            // task producer is a follow-up); `NetworkMode` is #[non_exhaustive],
            // so any future mode also takes the safe HostNet default.
            _ => sandbox2::NetworkMode::HostNet,
        };
        let mut env = ctx
            .make_env_with_network(
                &exec.task,
                &mut graph,
                None,
                task.state_key.as_ref(),
                Some(&task.patch),
                Some(&task.vars),
                task.packages.clone(),
                network_mode,
            )
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let (_interactive, invocations) = env
            .task_invocations(&task, exec.args.as_ref())
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let container = env
            .container()
            .map_err(|e| io::Error::other(format!("building container failed: {}", e)))?;

        for inv in invocations {
            // Wait for the consumer to ask. `None` means the consumer
            // dropped the stream; exit cleanly so `env` drops.
            if req_rx.recv().await.is_none() {
                return Ok(());
            }
            let result = (|| -> io::Result<HakoniwaProcess> {
                let mut cmd = env
                    .command(&container, &inv.executable, inv.args.iter())
                    .map_err(|e| io::Error::other(format!("building command failed: {}", e)))?;
                cmd.stdin(hakoniwa::Stdio::piped())
                    .stdout(hakoniwa::Stdio::piped())
                    .stderr(hakoniwa::Stdio::piped());
                let child = cmd
                    .spawn()
                    .map_err(|e| io::Error::other(format!("command launch failed: {}", e)))?;
                Ok(HakoniwaProcess::new(child))
            })();
            if let Err(send_err) = proc_tx.send(result).await {
                // Receiver dropped between our `recv` returning `Some`
                // and our `send`. If we just spawned a child, kill it
                // before `env` drops so it doesn't outlive its sandbox
                // rootfs.
                if let Ok(mut proc) = send_err.0 {
                    let _ = proc.start_kill();
                }
                return Ok(());
            }
        }
        // All invocations delivered. Park here until the consumer drops
        // the stream so `env` outlives every child the bridge is still
        // running.
        let _ = req_rx.recv().await;
        Ok(())
    }
    .await;

    if let Err(err) = outcome
        && req_rx.recv().await.is_some()
    {
        let _ = proc_tx.send(Err(err)).await;
    }
}

/// `Process` implementation backed by [`hakoniwa::Child`].
///
/// `hakoniwa` exposes a blocking `wait`, so the wait runs on the tokio
/// blocking pool. The blocking task owns the inner `Child` while it's
/// alive, so signalling has to bypass `Child::kill` and go straight to
/// the pid — hence the saved [`libc`] pid kept alongside the state.
///
/// Lifecycle is an explicit state machine:
///
/// ```text
///   Spawned(Child) ──wait()──▶ Waiting(JoinHandle) ──ok─▶ Exited(code)
///                                                     └──err─▶ Failed
/// ```
///
/// `Exited` and `Failed` are terminal; further `wait()` calls observe
/// the cached outcome. `take_stdio` is only meaningful in `Spawned`.
pub struct HakoniwaProcess {
    pid: libc::pid_t,
    state: WaitState,
}

enum WaitState {
    /// Just spawned. Stdio handles still attached to the inner `Child`
    /// and ready for `take_stdio`. Boxed because `hakoniwa::Child` is
    /// hundreds of bytes — without indirection the other variants
    /// would inherit that footprint.
    Spawned(Box<hakoniwa::Child>),
    /// `wait()` has been kicked off; the blocking task owns the
    /// `Child`. The `JoinHandle` is retained across calls so a dropped
    /// `wait` future can be re-polled (`&mut JoinHandle` is cancel-safe).
    Waiting(JoinHandle<Result<hakoniwa::ExitStatus, hakoniwa::Error>>),
    /// Cached numeric exit (or `None` for signal termination).
    Exited(Option<i32>),
    /// Wait itself errored. The original `io::Error` isn't `Clone`, so
    /// repeat `wait()` calls get a generic "previously failed" error
    /// rather than the original cause.
    Failed,
}

impl HakoniwaProcess {
    fn new(child: hakoniwa::Child) -> Self {
        Self {
            pid: child.id() as libc::pid_t,
            state: WaitState::Spawned(Box::new(child)),
        }
    }
}

impl Process for HakoniwaProcess {
    type Stdin = pipe::Sender;
    type Stdout = pipe::Receiver;
    type Stderr = pipe::Receiver;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        let WaitState::Spawned(child) = &mut self.state else {
            return None;
        };
        let stdin = pipe::Sender::from_owned_fd(child.stdin.take()?.into()).ok()?;
        let stdout = pipe::Receiver::from_owned_fd(child.stdout.take()?.into()).ok()?;
        let stderr = pipe::Receiver::from_owned_fd(child.stderr.take()?.into()).ok()?;
        Some((stdin, stdout, stderr))
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        // Spawned → Waiting: hand the child to the blocking pool.
        // `State::Failed` is a benign mem::replace sentinel; the next
        // line always overwrites it before any yield point.
        if matches!(self.state, WaitState::Spawned(_)) {
            let WaitState::Spawned(child) = std::mem::replace(&mut self.state, WaitState::Failed)
            else {
                unreachable!();
            };
            let mut child = *child;
            self.state = WaitState::Waiting(tokio::task::spawn_blocking(move || child.wait()));
        }

        // Waiting → Exited / Failed. The `await` is the cancel point —
        // if dropped mid-poll, the state stays `Waiting` and a fresh
        // `wait()` call resumes the same `JoinHandle`.
        if let WaitState::Waiting(handle) = &mut self.state {
            self.state = match handle.await {
                Ok(Ok(status)) => WaitState::Exited(status.exit_code),
                Ok(Err(_)) | Err(_) => WaitState::Failed,
            };
        }

        match &self.state {
            WaitState::Exited(code) => Ok(*code),
            WaitState::Failed => Err(io::Error::other("hakoniwa wait previously failed")),
            WaitState::Spawned(_) | WaitState::Waiting(_) => {
                unreachable!("state must be terminal after the transitions above")
            }
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        // The blocking-wait task owns the `Child` once `wait` has been
        // called, so we can't go through `Child::kill`. Send SIGKILL
        // directly; ESRCH (process already reaped) is benign.
        // SAFETY: `kill(2)` is async-signal-safe and has no Rust-side
        // invariants beyond the pid being a valid `pid_t`, which we
        // captured from `Child::id()` at construction time.
        unsafe { libc::kill(self.pid, libc::SIGKILL) };
        Ok(())
    }
}

/// Production [`Exec`]: runs the SSH `exec_request` argv through
/// `/bin/sh -c`, matching what OpenSSH would do for the same request.
/// Always produces a single process.
#[derive(Debug, Clone)]
pub struct TokioExec {
    pub argv: String,
    pub cwd: DaemonAbsPath,
    pub env: BTreeMap<String, String>,
}

impl Exec for TokioExec {
    type Process = TokioProcess;

    fn exec(self, _session: SessionHandle) -> BoxStream<'static, io::Result<Self::Process>> {
        stream::once(async move {
            let mut cmd = Command::new("/bin/sh");
            cmd.arg("-c")
                .arg(&self.argv)
                .current_dir(<DaemonAbsPath as AsRef<std::path::Path>>::as_ref(&self.cwd))
                .envs(&self.env)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            cmd.spawn().map(TokioProcess)
        })
        .boxed()
    }
}

/// `Process` implementation backed by [`tokio::process::Child`].
#[derive(Debug)]
pub struct TokioProcess(Child);

impl Process for TokioProcess {
    type Stdin = ChildStdin;
    type Stdout = ChildStdout;
    type Stderr = ChildStderr;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        Some((
            self.0.stdin.take()?,
            self.0.stdout.take()?,
            self.0.stderr.take()?,
        ))
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        self.0.wait().await.map(|s| s.code())
    }

    fn start_kill(&mut self) -> io::Result<()> {
        self.0.start_kill()
    }
}

/// An async task which binds some program execution to an ssh channel.
///
/// The `exec` field carries every parameter the process needs (argv,
/// cwd, env); `ExecTask` itself is just the wiring that connects it to
/// the SSH channel.
#[derive(Debug)]
#[allow(dead_code)]
struct ExecTask<S: Exec> {
    channel_id: ChannelId,
    exec: S,

    serv: ServerStateHandle,
    conn: ConnectionHandle,
    session: SessionHandle,
}

impl<S: Exec> ExecTask<S> {
    pub async fn run(self, channel: Channel<Msg>) {
        let (mut rs, ws) = channel.split();
        // SSH_EXTENDED_DATA_STDERR (RFC 4254 §5.2) — selects the stderr
        // stream on the same channel as a separate extended-data type.
        let mut w = ws.make_writer();
        let mut e = ws.make_writer_ext(Some(1));
        let mut r = rs.make_reader();

        let stream = self.exec.exec(self.session.clone());
        let exit_status = bridge(self.channel_id, stream, &mut r, &mut w, &mut e).await;

        let _ = w.flush().await;
        let _ = e.flush().await;

        drop(r);
        let _ = ws.eof().await;
        let _ = ws.exit_status(exit_status).await; // otherwise considered -1
        let _ = ws.close().await; // needed to release the remote
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
/// On any non-zero exit the sequence stops and that code is returned —
/// matching `set -e` shell semantics for chained task invocations. If
/// the stream yields an `Err` item (e.g. setup failed in the producer),
/// the message is written to the SSH stderr stream and the bridge
/// returns exit 1.
///
/// Returns the SSH-encoded exit code of the last process run (or 0 if
/// the stream was empty).
async fn bridge<S, P, R, W, E>(
    channel_id: impl Display + Clone,
    mut stream: S,
    r: &mut R,
    w: &mut W,
    e: &mut E,
) -> u32
where
    P: Process,
    S: Stream<Item = io::Result<P>> + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let mut stdin_open = true;
    let mut last_exit: u32 = 0;
    loop {
        let process = match stream.next().await {
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
        last_exit = bridge_one(channel_id.clone(), process, r, w, e, &mut stdin_open).await;
        if last_exit != 0 {
            break;
        }
    }
    last_exit
}

/// Drives one [`Process`] to completion: pumps `r → child stdin` and
/// `child stdout/stderr → w/e` concurrently until both output streams
/// hit EOF, then reaps the child and returns the SSH-encoded exit code.
///
/// EOF on both stdout and stderr is the exit signal. When the child
/// exits (or is killed), the kernel closes its stdio fds, which surfaces
/// as EOF on our read side — so once both are drained the subsequent
/// `process.wait()` resolves promptly. The one case this misses is a
/// child that forks a grandchild and lets it inherit stdout/stderr;
/// then the pipes stay open past the child's own exit and we drain
/// until the grandchild exits too. That matches the existing semantics
/// (drain everything before returning) and is fine for `min run` and
/// `sh -c` usage.
///
/// Polling the three I/O sources in a single `select!` lets a slow
/// consumer on one side apply backpressure without starving the others.
/// On an SSH-channel write failure we also `start_kill` the child: with
/// no one reading its output the pipe buffer would fill, the child
/// would block on write, and EOF (and `wait`) would never resolve.
///
/// `stdin_open` is threaded by `&mut` so once the SSH client closes
/// stdin (EOF or read error), every subsequent child in the sequence
/// sees immediate EOF on its stdin without re-reading from `r`.
async fn bridge_one<P, R, W, E>(
    channel_id: impl Display,
    mut process: P,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    stdin_open: &mut bool,
) -> u32
where
    P: Process,
    R: AsyncRead + Unpin,
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

    while stdout_open || stderr_open {
        tokio::select! {
            // Gated on `child_stdin.is_some()`: if the current child's
            // stdin pipe broke mid-step (write failure below) we stop
            // reading from `r` for the rest of this step, but leave
            // `*stdin_open` set so the next child in the sequence picks
            // up where we left off.
            read_res = r.read(&mut stdin_buf), if *stdin_open && child_stdin.is_some() => {
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
                        if let Some(cs) = child_stdin.as_mut()
                            && let Err(err) = cs.write_all(&stdin_buf[..n]).await
                        {
                            tracing::warn!(
                                %channel_id, error = %err,
                                "exec: failed to write stdin to child; closing child stdin",
                            );
                            child_stdin = None;
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
                            stdout_open = false;
                            let _ = process.start_kill();
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
                            stderr_open = false;
                            let _ = process.start_kill();
                        }
                    }
                }
            }
        }
    }

    match process.wait().await {
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

/// Handles a request to run a program on an SSH channel.
///
/// Looks up the target session via the `MINIMAL_SESSION_ID` env var the
/// client previously set on this channel, fetches its workspace, accepts the
/// request, and spawns an async task to take over the
/// channel for the lifetime of the conversation.
pub(crate) async fn handle_exec(
    argv: &[u8],
    serv: ServerStateHandle,
    conn: ConnectionHandle,
    id: ChannelId,
    session: &mut Session,
) -> Result<(), ConnectionError> {
    let argv = match String::from_utf8(argv.to_vec()) {
        Ok(argv) => argv,
        Err(e) => {
            tracing::warn!("channel {id}: argv was not utf8: {e}");
            session.channel_failure(id)?;
            return Ok(());
        }
    };

    let mut conn_lock = conn.lock().await;
    let Some((channel, config)) = conn_lock.take(id) else {
        session.channel_failure(id)?;
        return Ok(());
    };
    drop(conn_lock);

    if let Some(ident) = argv.strip_prefix("git-receive-pack min://") {
        return handle_git_receive(ident, serv, conn, id, session, channel, config).await;
    }

    if config.pty.is_some() {
        tracing::warn!("channel {id}: pty requested but not yet supported",);
        session.channel_failure(id)?;
        return Ok(());
    }

    let Some(session_id_str) = config.env_vars.get(MINIMAL_SESSION_ID_ENV) else {
        tracing::warn!(
            "execution request rejected on channel {id}: missing {MINIMAL_SESSION_ID_ENV}",
        );
        session.channel_failure(id)?;
        return Ok(());
    };
    let Ok(session_id) = SessionId::parse_str(session_id_str) else {
        tracing::warn!(
            value = %session_id_str,
            "execution request rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
        );
        session.channel_failure(id)?;
        return Ok(());
    };

    let mngr = serv.sessions_manager().await;
    let session_handle = match mngr.get_session(SessionKeyPredicate::Id(session_id)).await {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::warn!(%session_id, "execution request rejected: unknown session");
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(%session_id, error = %e, "execution request rejected: lookup failed");
            session.channel_failure(id)?;
            return Ok(());
        }
    };

    session.channel_success(id)?;

    spawn(async move {
        if let Some(task) = argv.strip_prefix("min run ") {
            let exec_task = ExecTask {
                conn,
                serv,
                session: session_handle,
                channel_id: id,
                exec: TaskExec {
                    args: None,
                    task: task.to_string(),
                },
            };
            exec_task.run(channel).await;
        } else {
            let paths = session_handle.paths().await;
            let exec_task = ExecTask {
                conn,
                serv,
                session: session_handle,
                channel_id: id,
                exec: TokioExec {
                    argv,
                    cwd: paths.working,
                    env: config.env_vars,
                },
            };
            exec_task.run(channel).await;
        };
    });

    Ok(())
}

async fn handle_git_receive(
    ident: &str,
    serv: ServerStateHandle,
    conn: ConnectionHandle,
    id: ChannelId,
    session: &mut Session,
    channel: Channel<Msg>,
    config: ChannelConfig,
) -> Result<(), ConnectionError> {
    let session_pred = {
        match config.env_vars.get(MINIMAL_SESSION_ID_ENV) {
            Some(id_str) => match SessionId::parse_str(id_str) {
                Ok(id) => SessionKeyPredicate::Id(id),
                Err(_e) => {
                    tracing::warn!(
                        value = %id_str,
                        "git-receive-pack rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
                    );
                    session.channel_failure(id)?;
                    return Ok(());
                }
            },
            None => match SessionId::parse_str(ident) {
                Ok(id) => SessionKeyPredicate::Id(id),
                Err(_e) => SessionKeyPredicate::Name(ident.to_string()),
            },
        }
    };

    let mngr = serv.sessions_manager().await;
    let session_handle = match mngr.get_session(session_pred).await {
        Ok(Some(h)) => h,
        Ok(None) => {
            tracing::warn!("git-receive-pack rejected: unknown session");
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            tracing::warn!(error = %e, "git-receive-pack rejected: lookup failed");
            session.channel_failure(id)?;
            return Ok(());
        }
    };
    session.channel_success(id)?;

    spawn(async move {
        let paths = session_handle.paths().await;

        let dotgit_dir = paths.working.as_utf8_path().join(".git");
        if let Ok(false) = tokio::fs::try_exists(&dotgit_dir).await {
            // No .git directory exists, so this is likely
            // the first push to populate. Create an empty git
            // repo, and make sure its configured to checkout
            // the ref it recieves.
            let res = tokio::process::Command::new("git")
                .arg("init")
                .current_dir(paths.working.as_utf8_path())
                .output()
                .await;
            if let Err(e) = res {
                tracing::warn!(error = %e, "git init failed");
                channel.close().await.unwrap();
                return;
            }
        }
        let hooks_tmp = TempDir::new().unwrap();
        tokio::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o755)
            .open(hooks_tmp.path().join("post-receive"))
            .await
            .unwrap()
            .write_all(
                r#"#!/bin/sh
                GIT_DIR_ABS=$(pwd -P)
                WORK_TREE=$(dirname "$GIT_DIR_ABS")
                unset GIT_DIR GIT_WORK_TREE GIT_QUARANTINE_PATH
                g() { git --git-dir="$GIT_DIR_ABS" --work-tree="$WORK_TREE" "$@"; }

                while read -r old new ref; do
                    case "$ref" in refs/heads/*) ;; *) continue ;; esac
                    branch=${ref#refs/heads/}

                    if ! g diff --quiet || ! g diff --cached --quiet; then
                        echo "remote worktree has uncommitted changes; skipping checkout of $branch" >&2
                        continue
                    fi
                    g checkout -f "$branch"
                done"#
                    .as_bytes(),
            )
            .await
            .unwrap();

        let exec_task = ExecTask {
            conn,
            serv,
            session: session_handle,
            channel_id: id,
            exec: TokioExec {
                argv: format!(
                    "git -c core.hooksPath={} receive-pack .",
                    hooks_tmp.path().to_str().unwrap()
                ),
                cwd: paths.working,
                env: BTreeMap::new(),
            },
        };
        exec_task.run(channel).await;
        drop(hooks_tmp);
    });

    Ok(())
}

#[cfg(test)]
pub(crate) mod testing {
    //! Mock `Process` for testing the exec bridge without spawning a
    //! real subprocess. The test side holds a [`MockController`] for
    //! driving exit and observing `start_kill`, plus duplex endpoints
    //! mirroring each stdio stream.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use futures::stream::{self, BoxStream, StreamExt};
    use tokio::io::{DuplexStream, duplex};
    use tokio::sync::{Mutex, Notify};

    use super::Process;

    /// Stdio buffer size. Chosen well above the bridge's 8 KiB read
    /// buffer so a single test write never blocks on backpressure.
    const PIPE_CAPACITY: usize = 64 * 1024;

    #[derive(Default)]
    struct MockInner {
        exit: Mutex<Option<i32>>,
        notify: Notify,
        kill_requested: AtomicBool,
    }

    /// Test-side handle for driving and observing a [`MockProcess`].
    /// Cheaply cloneable — both sides share the same `Arc`.
    #[derive(Clone, Default)]
    pub struct MockController {
        inner: Arc<MockInner>,
    }

    impl MockController {
        /// Signal that the mock process has exited with this code. Wakes
        /// any pending `wait` future.
        pub async fn signal_exit(&self, code: i32) {
            *self.inner.exit.lock().await = Some(code);
            // notify_one stores a permit if no waiter is parked yet,
            // which sidesteps the "set exit before bridge polls wait"
            // race that would otherwise leave the bridge hanging.
            self.inner.notify.notify_one();
        }

        /// Whether the bridge has called `start_kill` on the process.
        pub fn was_killed(&self) -> bool {
            self.inner.kill_requested.load(Ordering::SeqCst)
        }
    }

    /// Test-side endpoints — counterparts to the streams the bridge
    /// owns after `take_stdio`.
    pub struct MockEndpoints {
        /// Reads bytes the bridge wrote to "child stdin".
        pub stdin_reader: DuplexStream,
        /// Writes bytes the bridge will read as "child stdout".
        pub stdout_writer: DuplexStream,
        /// Writes bytes the bridge will read as "child stderr".
        pub stderr_writer: DuplexStream,
        pub ctrl: MockController,
    }

    /// Bridge-side `Process` impl. The bridge calls `take_stdio` to
    /// grab the inner halves, then drives them like any other stdio.
    pub struct MockProcess {
        stdin: Option<DuplexStream>,
        stdout: Option<DuplexStream>,
        stderr: Option<DuplexStream>,
        ctrl: MockController,
    }

    /// A single bridge-side mock paired with its test-side endpoint.
    fn build_mock_pair() -> (MockProcess, MockEndpoints) {
        let (stdin_bridge, stdin_test) = duplex(PIPE_CAPACITY);
        let (stdout_bridge, stdout_test) = duplex(PIPE_CAPACITY);
        let (stderr_bridge, stderr_test) = duplex(PIPE_CAPACITY);
        let ctrl = MockController::default();
        (
            MockProcess {
                stdin: Some(stdin_bridge),
                stdout: Some(stdout_bridge),
                stderr: Some(stderr_bridge),
                ctrl: ctrl.clone(),
            },
            MockEndpoints {
                stdin_reader: stdin_test,
                stdout_writer: stdout_test,
                stderr_writer: stderr_test,
                ctrl,
            },
        )
    }

    /// A boxed stream of mock processes, shaped to match the trait
    /// surface (`io::Result` items so test fixtures can inject failures
    /// alongside successes).
    pub type MockStream = BoxStream<'static, std::io::Result<MockProcess>>;

    /// Build a single-process mock stream and its test-side endpoints.
    /// Convenience for the common case where a test only needs one
    /// process in the sequence.
    pub fn build_mock() -> (MockStream, MockEndpoints) {
        let (proc, endpoints) = build_mock_pair();
        (stream::iter(vec![Ok(proc)]).boxed(), endpoints)
    }

    /// Build a multi-process mock stream and the corresponding ordered
    /// endpoints. `endpoints[i]` drives the i-th process the bridge
    /// pulls from the stream.
    pub fn build_mock_seq(n: usize) -> (MockStream, Vec<MockEndpoints>) {
        let (procs, endpoints): (Vec<_>, Vec<_>) = (0..n).map(|_| build_mock_pair()).unzip();
        (stream::iter(procs.into_iter().map(Ok)).boxed(), endpoints)
    }

    impl Process for MockProcess {
        type Stdin = DuplexStream;
        type Stdout = DuplexStream;
        type Stderr = DuplexStream;

        fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
            Some((self.stdin.take()?, self.stdout.take()?, self.stderr.take()?))
        }

        async fn wait(&mut self) -> std::io::Result<Option<i32>> {
            loop {
                if let Some(code) = *self.ctrl.inner.exit.lock().await {
                    return Ok(Some(code));
                }
                // A killed process winds down with no numeric code (the
                // shell would report it as signal termination). Model
                // that as `Ok(None)` so the bridge maps it to exit 1.
                if self.ctrl.inner.kill_requested.load(Ordering::SeqCst) {
                    return Ok(None);
                }
                self.ctrl.inner.notify.notified().await;
            }
        }

        fn start_kill(&mut self) -> std::io::Result<()> {
            self.ctrl.inner.kill_requested.store(true, Ordering::SeqCst);
            self.ctrl.inner.notify.notify_one();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::bridge;
    use super::testing::{MockEndpoints, build_mock, build_mock_seq};

    /// Bytes flow client→child stdin and child stdout/stderr→client,
    /// and the child's exit code propagates to the bridge's return.
    #[tokio::test]
    async fn bridge_round_trips_stdio_and_propagates_exit_code() {
        let (
            process,
            MockEndpoints {
                mut stdin_reader,
                mut stdout_writer,
                mut stderr_writer,
                ctrl,
            },
        ) = build_mock();

        let (mut client_stdin, mut bridge_stdin) = duplex(64 * 1024);
        let (mut bridge_stdout, mut client_stdout) = duplex(64 * 1024);
        let (mut bridge_stderr, mut client_stderr) = duplex(64 * 1024);

        let bridge_task = tokio::spawn(async move {
            bridge(
                "test",
                process,
                &mut bridge_stdin,
                &mut bridge_stdout,
                &mut bridge_stderr,
            )
            .await
        });

        client_stdin.write_all(b"hello\n").await.unwrap();
        client_stdin.shutdown().await.unwrap();

        let mut received_stdin = Vec::new();
        stdin_reader.read_to_end(&mut received_stdin).await.unwrap();
        assert_eq!(received_stdin, b"hello\n");

        stdout_writer.write_all(b"out!").await.unwrap();
        stderr_writer.write_all(b"err!").await.unwrap();
        drop(stdout_writer);
        drop(stderr_writer);

        ctrl.signal_exit(42).await;

        let exit = bridge_task.await.unwrap();
        assert_eq!(exit, 42);

        let mut out = Vec::new();
        client_stdout.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"out!");

        let mut err = Vec::new();
        client_stderr.read_to_end(&mut err).await.unwrap();
        assert_eq!(err, b"err!");

        assert!(!ctrl.was_killed());
    }

    /// When the SSH-channel write side fails, the bridge must call
    /// `start_kill` so the child unblocks and `wait` resolves —
    /// otherwise the loop would hang waiting on the now-dead channel.
    #[tokio::test]
    async fn bridge_kills_child_when_ssh_write_fails() {
        let (
            process,
            MockEndpoints {
                stdin_reader: _stdin_reader,
                mut stdout_writer,
                stderr_writer,
                ctrl,
            },
        ) = build_mock();
        // Model a process with nothing on stderr — bridge sees EOF on
        // child_stderr immediately and never writes to bridge_stderr.
        drop(stderr_writer);

        // SSH-side stdout reader dropped, so every bridge write to
        // bridge_stdout errors with BrokenPipe.
        let (broken_reader, mut bridge_stdout) = duplex(64);
        drop(broken_reader);

        // bridge_stderr exists only because the signature requires it;
        // the bridge will never touch it in this test.
        let (_unused_stderr_peer, mut bridge_stderr) = duplex(64);

        // SSH stdin closed: bridge sees EOF immediately.
        let (closed_stdin_w, mut bridge_stdin) = duplex(64);
        drop(closed_stdin_w);

        let bridge_task = tokio::spawn(async move {
            bridge(
                "test",
                process,
                &mut bridge_stdin,
                &mut bridge_stdout,
                &mut bridge_stderr,
            )
            .await
        });

        stdout_writer.write_all(b"output").await.unwrap();
        drop(stdout_writer);

        let exit = bridge_task.await.unwrap();
        // A killed mock returns Ok(None) from wait, which the bridge
        // maps to exit status 1.
        assert_eq!(exit, 1);
        assert!(ctrl.was_killed());
    }

    /// A two-process sequence: the first child exits non-zero, so the
    /// bridge must stop and report that code without ever pulling the
    /// second process from the iter. If it tried to drive process 2,
    /// `bridge_task.await` would hang (proc 2's ctrl is never signalled)
    /// and the test would time out.
    #[tokio::test]
    async fn bridge_stops_sequence_on_first_non_zero_exit() {
        let (iter, mut endpoints) = build_mock_seq(2);
        let second = endpoints.pop().unwrap();
        let MockEndpoints {
            stdin_reader: _stdin_reader,
            stdout_writer: mut first_stdout,
            stderr_writer: mut first_stderr,
            ctrl: first_ctrl,
        } = endpoints.pop().unwrap();

        let (closed_stdin_w, mut bridge_stdin) = duplex(64);
        drop(closed_stdin_w);
        let (_unused_stdout_peer, mut bridge_stdout) = duplex(64 * 1024);
        let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

        let bridge_task = tokio::spawn(async move {
            bridge(
                "test",
                iter,
                &mut bridge_stdin,
                &mut bridge_stdout,
                &mut bridge_stderr,
            )
            .await
        });

        // Drive the first child to exit non-zero. Closing the writers
        // gives the bridge EOF on both child stdout and stderr.
        first_stdout.write_all(b"first").await.unwrap();
        first_stderr.write_all(b"oops").await.unwrap();
        drop(first_stdout);
        drop(first_stderr);
        first_ctrl.signal_exit(5).await;

        let exit = bridge_task.await.unwrap();
        assert_eq!(exit, 5);
        // The second process was never spawned, so its kill flag should
        // still be unset.
        assert!(!second.ctrl.was_killed());
    }

    /// A two-process sequence where both children exit cleanly: the
    /// bridge runs them back-to-back, concatenates their stdout to the
    /// SSH channel, and returns the second's exit code.
    #[tokio::test]
    async fn bridge_runs_sequence_to_completion_and_concatenates_stdout() {
        let (iter, mut endpoints) = build_mock_seq(2);
        let MockEndpoints {
            stdin_reader: _r2,
            stdout_writer: mut second_stdout,
            stderr_writer: second_stderr,
            ctrl: second_ctrl,
        } = endpoints.pop().unwrap();
        let MockEndpoints {
            stdin_reader: _r1,
            stdout_writer: mut first_stdout,
            stderr_writer: first_stderr,
            ctrl: first_ctrl,
        } = endpoints.pop().unwrap();
        drop(first_stderr);
        drop(second_stderr);

        let (closed_stdin_w, mut bridge_stdin) = duplex(64);
        drop(closed_stdin_w);
        let (mut client_stdout, mut bridge_stdout) = duplex(64 * 1024);
        let (_unused_stderr_peer, mut bridge_stderr) = duplex(64 * 1024);

        let bridge_task = tokio::spawn(async move {
            bridge(
                "test",
                iter,
                &mut bridge_stdin,
                &mut bridge_stdout,
                &mut bridge_stderr,
            )
            .await
        });

        first_stdout.write_all(b"AAA").await.unwrap();
        drop(first_stdout);
        first_ctrl.signal_exit(0).await;

        second_stdout.write_all(b"BBB").await.unwrap();
        drop(second_stdout);
        second_ctrl.signal_exit(0).await;

        let exit = bridge_task.await.unwrap();
        assert_eq!(exit, 0);

        let mut out = Vec::new();
        client_stdout.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"AAABBB");
    }

    mod end_to_end {
        //! Tests that exercise the full ssh-exec stack against a real
        //! `TestServer`: russh transport, `ConnectionHandler` dispatch,
        //! `handle_exec`, and a real `/bin/sh -c` child.
        use sessions::SessionId;

        use minimald_rpc::CreateSession;

        use crate::MINIMAL_SESSION_ID_ENV;
        use crate::sessions::SessionKeyPredicate;
        use crate::test_harness::{TestClient, TestServer, create_session_req, unwrap_ready};

        /// Creates a fresh session through the public CreateSession RPC
        /// and returns its id, mirroring how a real client sets up state
        /// before running commands against the session.
        async fn fresh_session(client: &mut TestClient) -> SessionId {
            unwrap_ready(
                client
                    .call::<CreateSession>(&create_session_req("exec-test", "/tmp"))
                    .await
                    .unwrap(),
            )
        }

        #[tokio::test]
        async fn exec_round_trips_stdout_stderr_and_exit_code() {
            let server = TestServer::new().await;
            let mut client = server.connect().await;
            let session_id = fresh_session(&mut client).await;
            let session_str = session_id.to_string();

            let out = client
                .exec(
                    &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                    false,
                    "printf out; printf err 1>&2; exit 7",
                    &[],
                )
                .await
                .expect("exec request should be accepted");

            assert_eq!(out.stdout, b"out");
            assert_eq!(out.stderr, b"err");
            assert_eq!(out.exit_status, Some(7));
        }

        #[tokio::test]
        async fn exec_pipes_stdin_to_child() {
            let server = TestServer::new().await;
            let mut client = server.connect().await;
            let session_id = fresh_session(&mut client).await;
            let session_str = session_id.to_string();

            let payload: &[u8] = b"hello from stdin\n";
            let out = client
                .exec(
                    &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                    false,
                    "cat",
                    payload,
                )
                .await
                .expect("exec request should be accepted");

            assert_eq!(out.stdout, payload);
            assert_eq!(out.exit_status, Some(0));
            assert!(
                out.stderr.is_empty(),
                "unexpected stderr from cat: {:?}",
                out.stderr,
            );
        }

        #[tokio::test]
        async fn exec_runs_in_session_workspace() {
            let server = TestServer::new().await;
            let mut client = server.connect().await;
            let session_id = fresh_session(&mut client).await;
            let session_str = session_id.to_string();

            // Fetch the workspace path the server will hand to the
            // child, so we can compare with what `pwd` reports.
            let mngr = server.state.sessions_manager().await;
            let session_handle = mngr
                .get_session(SessionKeyPredicate::Id(session_id))
                .await
                .unwrap()
                .expect("freshly-created session should be retrievable");
            let paths = session_handle.paths().await;
            // getcwd resolves symlinks (e.g. /tmp -> /private/tmp on some
            // platforms); canonicalize both sides so the comparison is
            // about the same inode rather than spelling.
            let expected = std::fs::canonicalize(paths.working.as_str()).unwrap();

            let out = client
                .exec(
                    &[(MINIMAL_SESSION_ID_ENV, session_str.as_str())],
                    false,
                    "pwd",
                    &[],
                )
                .await
                .expect("exec request should be accepted");

            assert_eq!(out.exit_status, Some(0));
            let observed = String::from_utf8(out.stdout).unwrap();
            let observed = std::path::PathBuf::from(observed.trim_end());
            assert_eq!(observed, expected);
        }

        /// End-to-end: `git push min://<session-id>` driven by an
        /// OpenSSH process going through a modified `git-remote-min`
        /// helper lands the pushed commit in the session workspace, with
        /// the post-receive hook checking out the branch on disk.
        #[ignore]
        #[tokio::test]
        async fn git_receive_pack_lands_pushed_commit_in_workspace() {
            use std::os::unix::fs::PermissionsExt;

            use tempfile::TempDir;
            use tokio::process::Command;

            async fn run_git(cwd: &std::path::Path, args: &[&str]) {
                let out = Command::new("git")
                    .current_dir(cwd)
                    .args(args)
                    .output()
                    .await
                    .expect("git should be invocable");
                assert!(
                    out.status.success(),
                    "git {args:?} failed: {}",
                    String::from_utf8_lossy(&out.stderr),
                );
            }

            let server = TestServer::new().await;
            let sock_dir = TempDir::new().unwrap();
            let sock_path = sock_dir.path().join("ssh.sock");
            server.listen_on_uds(&sock_path).await;

            let mut client = server.connect().await;
            let session_id = fresh_session(&mut client).await;

            // Drop a `git-remote-min` into a tempdir and prepend that
            // tempdir to PATH so `git push min://…` resolves to it. The
            // script is the production one with its hard-coded socket
            // path swapped for the test server's UDS.
            let helpers_dir = TempDir::new().unwrap();
            let helper_path = helpers_dir.path().join("git-remote-min");
            let template = include_str!("../git-remote-min");
            let script = template.replace(
                "$HOME/.local/state/minimal/providers/local-0/ssh.sock",
                sock_path.to_str().unwrap(),
            );
            tokio::fs::write(&helper_path, script).await.unwrap();
            tokio::fs::set_permissions(&helper_path, std::fs::Permissions::from_mode(0o755))
                .await
                .unwrap();

            // Source repo with a single commit on `main`. Local
            // user.email/user.name to keep the test independent of any
            // global git config.
            let src_dir = TempDir::new().unwrap();
            let src_path = src_dir.path();
            run_git(src_path, &["init", "-q", "-b", "main"]).await;
            run_git(src_path, &["config", "user.email", "t@example.com"]).await;
            run_git(src_path, &["config", "user.name", "Test"]).await;
            tokio::fs::write(src_path.join("hello.txt"), b"hi there\n")
                .await
                .unwrap();
            run_git(src_path, &["add", "hello.txt"]).await;
            run_git(src_path, &["commit", "-q", "-m", "first commit"]).await;

            let inherited_path = std::env::var("PATH").unwrap_or_default();
            let path_with_helper = format!("{}:{}", helpers_dir.path().display(), inherited_path);
            let url = format!("min://{session_id}");
            let push = Command::new("git")
                .current_dir(src_path)
                .env("PATH", &path_with_helper)
                .args(["push", &url, "main"])
                .output()
                .await
                .expect("git push should run");
            assert!(
                push.status.success(),
                "git push failed: stdout={} stderr={}",
                String::from_utf8_lossy(&push.stdout),
                String::from_utf8_lossy(&push.stderr),
            );

            // The post-receive hook checks out `refs/heads/main` into
            // the worktree, so the pushed file should be readable from
            // the session workspace.
            let mngr = server.state.sessions_manager().await;
            let session_handle = mngr
                .get_session(SessionKeyPredicate::Id(session_id))
                .await
                .unwrap()
                .expect("session should be retrievable");
            let paths = session_handle.paths().await;
            let pushed = paths.working.as_utf8_path().join("hello.txt");
            let contents = tokio::fs::read(&pushed)
                .await
                .unwrap_or_else(|e| panic!("reading pushed file {pushed} failed: {e}"));
            assert_eq!(contents, b"hi there\n");
        }
    }
}
