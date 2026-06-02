//! SSH `exec` request handling: spawns a process and bridges its stdio
//! over an SSH channel.
//!
//! Process spawning is abstracted via the [`Spawnable`] / [`Process`]
//! traits so the bridge logic can be exercised with a mock in tests
//! without going through `tokio::process` or russh.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io;
use std::process::Stdio;

use paths::DaemonAbsPath;
use russh::{
    Channel, ChannelId,
    server::{Msg, Session},
};
use sessions::SessionId;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
    spawn,
};

use crate::{
    MINIMAL_SESSION_ID_ENV,
    connection::{ConnectionError, ConnectionHandle},
    server::ServerStateHandle,
    session::SessionHandle,
    sessions::SessionKeyPredicate,
};

/// One process invocation, ready to be turned into a running [`Process`].
///
/// Stateful by design — the spawnable carries every parameter it needs
/// to run (argv, cwd, env), so `spawn` takes only `self` and the caller
/// doesn't have to thread parameters separately.
pub trait Spawnable: Send + 'static {
    type Process: Process;

    /// Consume the spawnable and start the process.
    async fn spawn(self) -> io::Result<Self::Process>;
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

/// Production `Spawnable`: runs the SSH `exec_request` argv through
/// `/bin/sh -c`, matching what OpenSSH would do for the same request.
#[derive(Debug, Clone)]
pub struct TokioSpawn {
    pub argv: String,
    pub cwd: DaemonAbsPath,
    pub env: BTreeMap<String, String>,
}

impl Spawnable for TokioSpawn {
    type Process = TokioProcess;

    async fn spawn(self) -> io::Result<Self::Process> {
        let mut cmd = Command::new("/bin/sh");
        cmd.arg("-c")
            .arg(&self.argv)
            .current_dir(<DaemonAbsPath as AsRef<std::path::Path>>::as_ref(&self.cwd))
            .envs(&self.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        Ok(TokioProcess(cmd.spawn()?))
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
/// The `spawnable` field carries every parameter the process needs
/// (argv, cwd, env); `ExecTask` itself is just the wiring that
/// connects it to the SSH channel.
#[derive(Debug)]
#[allow(dead_code)]
struct ExecTask<S: Spawnable> {
    channel_id: ChannelId,
    spawnable: S,

    serv: ServerStateHandle,
    conn: ConnectionHandle,
    session: SessionHandle,
}

impl<S: Spawnable> ExecTask<S> {
    pub async fn run(self, channel: Channel<Msg>) {
        let (mut rs, ws) = channel.split();
        // SSH_EXTENDED_DATA_STDERR (RFC 4254 §5.2) — selects the stderr
        // stream on the same channel as a separate extended-data type.
        let mut w = ws.make_writer();
        let mut e = ws.make_writer_ext(Some(1));
        let mut r = rs.make_reader();

        let process = match self.spawnable.spawn().await {
            Ok(p) => p,
            Err(err) => {
                tracing::warn!(
                    channel_id = %self.channel_id,
                    error = %err,
                    "failed to spawn process for exec request",
                );
                let _ = e
                    .write_all(format!("minimald: failed to spawn process: {err}\n").as_bytes())
                    .await;
                let _ = e.flush().await;
                let _ = ws.eof().await;
                let _ = ws.exit_status(1).await;
                let _ = ws.close().await;
                return;
            }
        };

        let exit_status = bridge(self.channel_id, process, &mut r, &mut w, &mut e).await;

        let _ = w.flush().await;
        let _ = e.flush().await;

        drop(r);
        let _ = ws.eof().await;
        let _ = ws.exit_status(exit_status).await; // otherwise considered -1
        let _ = ws.close().await; // needed to release the remote
    }
}

/// Bridges a spawned [`Process`] with the SSH channel halves: pumps
/// `r → child stdin` and `child stdout/stderr → w/e` concurrently
/// until both output streams have drained AND the child has reported
/// an exit status, then returns the SSH-encoded exit code.
///
/// Polling all four sources in a single `select!` lets a slow consumer
/// on one side apply backpressure without starving the others. On an
/// SSH-channel write failure we also `start_kill` the child: with no
/// one reading its output the pipe buffer would fill, the child would
/// block on write, and `wait` would never resolve.
///
/// Factored out of [`ExecTask::run`] so the bridge logic can be tested
/// against a mock process without going through russh.
async fn bridge<P, R, W, E>(
    channel_id: impl Display,
    mut process: P,
    r: &mut R,
    w: &mut W,
    e: &mut E,
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
    let mut child_stdin = Some(stdin);

    let mut stdin_buf = vec![0u8; 8 * 1024];
    let mut stdout_buf = vec![0u8; 8 * 1024];
    let mut stderr_buf = vec![0u8; 8 * 1024];

    let mut stdin_open = true;
    let mut stdout_open = true;
    let mut stderr_open = true;
    let mut exit_status: Option<i32> = None;

    while stdout_open || stderr_open || exit_status.is_none() {
        tokio::select! {
            read_res = r.read(&mut stdin_buf), if stdin_open => {
                match read_res {
                    Ok(0) => {
                        stdin_open = false;
                        // Dropping the write half closes the pipe so
                        // the child sees EOF on its stdin.
                        child_stdin = None;
                    }
                    Err(err) => {
                        tracing::warn!(
                            %channel_id, error = %err,
                            "exec: failed to read stdin from ssh channel; closing child stdin",
                        );
                        stdin_open = false;
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
                            stdin_open = false;
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
            wait_res = process.wait(), if exit_status.is_none() => {
                match wait_res {
                    Ok(code) => exit_status = Some(code.unwrap_or(1)),
                    Err(err) => {
                        tracing::warn!(
                            %channel_id, error = %err,
                            "exec: failed to wait for child; reporting exit status 1",
                        );
                        exit_status = Some(1);
                    }
                }
            }
        }
    }

    exit_status.unwrap_or(1) as u32
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
    let workspace = session_handle.workspace_path().await;

    session.channel_success(id)?;

    spawn(async move {
        let spawnable = TokioSpawn {
            argv,
            cwd: workspace,
            env: config.env_vars,
        };
        let exec_task = ExecTask {
            conn,
            serv,
            session: session_handle,
            channel_id: id,
            spawnable,
        };
        exec_task.run(channel).await;
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

    /// Build a paired (bridge-side, test-side) mock. The bridge gets
    /// `MockProcess`; the test drives behaviour via [`MockEndpoints`].
    pub fn build_mock() -> (MockProcess, MockEndpoints) {
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
    use super::testing::{MockEndpoints, build_mock};

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

    mod end_to_end {
        //! Tests that exercise the full ssh-exec stack against a real
        //! `TestServer`: russh transport, `ConnectionHandler` dispatch,
        //! `handle_exec`, and a real `/bin/sh -c` child.
        use paths::HostAbsPath;
        use sessions::SessionId;

        use crate::MINIMAL_SESSION_ID_ENV;
        use crate::rpc::{CreateSession, CreateSessionRequest};
        use crate::sessions::SessionKeyPredicate;
        use crate::test_harness::{TestClient, TestServer};

        /// Creates a fresh session through the public CreateSession RPC
        /// and returns its id, mirroring how a real client sets up state
        /// before running commands against the session.
        async fn fresh_session(client: &mut TestClient) -> SessionId {
            client
                .call::<CreateSession>(&CreateSessionRequest {
                    record: sessions::Record {
                        id: SessionId::nil(),
                        name: Some("exec-test".to_string()),
                        username: None,
                        project_path: HostAbsPath::try_new("/tmp").unwrap(),
                        attrs: Default::default(),
                    },
                })
                .await
                .id
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
            let workspace = session_handle.workspace_path().await;
            // getcwd resolves symlinks (e.g. /tmp -> /private/tmp on some
            // platforms); canonicalize both sides so the comparison is
            // about the same inode rather than spelling.
            let expected = std::fs::canonicalize(workspace.as_str()).unwrap();

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
    }
}
