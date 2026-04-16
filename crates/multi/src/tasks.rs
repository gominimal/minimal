//! A task running in an environment.

use std::io::{Read as _, Write as _};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};

use graph::Graph;
use mctx::{Context, Env, Invocation};
use std::mem::ManuallyDrop;
use std::sync::Arc;
use tokio::io::unix::AsyncFd;
use tokio::sync::{Mutex, MutexGuard, broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::{
    environment::EnvironmentHandle,
    mux::{self, Pty, WinSize},
    shared_resources::SharedResourcesHandle,
};

/// A command sent to the background driver via the input channel.
pub enum MuxCommand {
    /// Raw bytes to write to the child's PTY (keystrokes, paste, etc.).
    Input(Vec<u8>),
    /// Resize the PTY and parser to the given dimensions.
    Resize(WinSize),
}

/// Shared terminal screen.  The [`Driver`] writes to it; RPC handlers read.
pub type Screen = Arc<std::sync::Mutex<vt100_ctt::Parser>>;

/// A live subscription to a running task's terminal output.
pub struct Subscription {
    /// Bytes that reconstruct the current screen state (escape sequences
    /// included).  Write these first, then stream from `rx`.
    pub initial_state: Vec<u8>,
    /// Receives raw byte chunks as the child produces them.  If the
    /// receiver falls behind, [`broadcast::error::RecvError::Lagged`] is
    /// returned — the subscriber should re-snapshot via a new subscription.
    pub rx: broadcast::Receiver<Vec<u8>>,
}

// ---------------------------------------------------------------------------
// Task state
// ---------------------------------------------------------------------------

/// Lifecycle state of a [`Task`].
pub(crate) enum TaskState {
    /// Configured but not yet started.
    #[allow(private_interfaces)]
    Ready { inner: TaskRuntime },
    /// A background driver is running invocations.
    Running {
        /// Channel for sending input / resize commands to the driver.
        input_tx: mpsc::Sender<MuxCommand>,
        /// Broadcast of raw bytes from the child — used by [`Task::subscribe`].
        output_tx: broadcast::Sender<Vec<u8>>,
        /// Trigger this to kill the child and stop the driver. Also cancelled
        /// upon completion by the driver.
        cancel: CancellationToken,
    },
    /// All invocations have finished (or the driver encountered an error).
    Finished { exit_status: hakoniwa::ExitStatus },
}

/// An initialized task environment. Owns [Graph] and [Context] on the heap with an Env that borrows from them.
///
/// # Safety
///
/// This is a self-referential struct. `env` holds mutable references into the
/// heap allocations behind `_graph` and `_ctx`. Invariants:
///
/// 1. `_graph` and `_ctx` are heap-allocated ([`Box`]), so their addresses are
///    stable across moves of `TaskRuntime`.
/// 2. `env` is wrapped in [`ManuallyDrop`] and our [`Drop`] impl drops it
///    **before** `_graph` and `_ctx`, releasing the mutable borrows first.
/// 3. `_graph` and `_ctx` are never accessed while `env` is alive.
pub(crate) struct TaskRuntime {
    env: ManuallyDrop<Env<'static>>,
    _ctx: Box<Context>,
    _graph: Box<Graph>,

    invocations: Vec<Invocation>,
}

impl TaskRuntime {
    /// Builds a task runtime based on the given graph, context, and task.
    pub(crate) async fn build(
        graph: Graph,
        ctx: Context,
        name: &str,
        task: &mfile::Task,
        task_args: Option<&std::collections::HashMap<String, args::Arg>>,
    ) -> Result<Self, mctx::Error> {
        let mut graph = Box::new(graph);
        let mut ctx = Box::new(ctx);

        // SAFETY: see struct-level doc.
        let mut env: Env<'static> = {
            let graph_ref = &mut *graph;
            let ctx_ref = &mut *ctx;
            let env = ctx_ref
                .make_env(
                    name,
                    graph_ref,
                    None,
                    task.state_key.as_ref(),
                    Some(&task.patch),
                    Some(&task.vars),
                    task.packages.clone(),
                )
                .await?;
            unsafe { std::mem::transmute::<Env<'_>, Env<'static>>(env) }
        };

        let (_interactive, invocations) = env.task_invocations(task, task_args).await?;

        Ok(Self {
            env: ManuallyDrop::new(env),
            _ctx: ctx,
            _graph: graph,
            invocations,
        })
    }
}

impl Drop for TaskRuntime {
    fn drop(&mut self) {
        // SAFETY: Drop env first to release its mutable borrows into _ctx and
        // _graph before they are dropped by the compiler's implicit field drops.
        unsafe { ManuallyDrop::drop(&mut self.env) };
    }
}

/// The source of configuration for a task.
#[derive(Debug)]
#[allow(dead_code)]
pub enum ConfigSource {
    /// Execution of a task with the specified name.
    NamedTask { name: String },
}

/// Describes a runnable (possibly running) task. Interact via [`TaskHandle`].
pub struct Task {
    /// A unique id that identifies this task.
    pub(crate) id: Uuid,
    /// Where the configuration of the task comes from.
    config_source: ConfigSource,
    /// The environment in which this task runs.
    environment: EnvironmentHandle,

    state: TaskState,

    /// Terminal screen, shared with the driver.  `None` before the task is
    /// started; `Some` from start through (and after) finish, so the final
    /// screen contents remain readable.
    screen: Option<Screen>,

    #[allow(dead_code)] // Held to keep the shared state alive.
    shared: SharedResourcesHandle,
}

impl Task {
    /// Creates a new named task, building a fresh Env from the given Context and Graph.
    pub(crate) async fn new_named(
        name: String,
        task_args: Option<&std::collections::HashMap<String, args::Arg>>,
        graph: Graph,
        mut ctx: Context,
        environment: EnvironmentHandle,
        shared: SharedResourcesHandle,
    ) -> Result<Self, mctx::Error> {
        let (mfile_task, graph) = ctx
            .task(graph, &name)?
            .ok_or_else(|| mctx::Error::Other(anyhow::anyhow!("no such task: {}", name)))?;

        let inner = TaskRuntime::build(graph, ctx, &name, &mfile_task, task_args).await?;

        Ok(Self {
            id: Uuid::new_v4(),
            config_source: ConfigSource::NamedTask { name },
            environment,
            state: TaskState::Ready { inner },
            screen: None,
            shared,
        })
    }

    /// Returns the shared screen handle, if the task has been started.
    ///
    /// Lock the returned mutex to read the screen contents.  The screen
    /// remains available after the task finishes, reflecting final output.
    pub fn screen(&self) -> Option<&Screen> {
        self.screen.as_ref()
    }

    /// Enqueues input bytes to be written to the child's PTY.
    pub fn send_input(&self, data: Vec<u8>) -> Result<(), mpsc::error::TrySendError<MuxCommand>> {
        match &self.state {
            TaskState::Running { input_tx, .. } => input_tx.try_send(MuxCommand::Input(data)),
            _ => Err(mpsc::error::TrySendError::Closed(MuxCommand::Input(data))),
        }
    }

    /// Enqueues a resize command for the child's PTY and parser.
    pub fn send_resize(&self, size: WinSize) -> Result<(), mpsc::error::TrySendError<MuxCommand>> {
        match &self.state {
            TaskState::Running { input_tx, .. } => input_tx.try_send(MuxCommand::Resize(size)),
            _ => Err(mpsc::error::TrySendError::Closed(MuxCommand::Resize(size))),
        }
    }

    /// Subscribes to the live terminal output of a running task.
    ///
    /// Returns the current screen state (as escape sequences that can be
    /// written to a terminal to reproduce it) plus a broadcast receiver
    /// that yields raw byte chunks as the child produces them.
    ///
    /// Returns `None` if the task is not running.
    pub fn subscribe(&self) -> Option<Subscription> {
        let TaskState::Running { output_tx, .. } = &self.state else {
            return None;
        };
        let screen = self.screen.as_ref()?;

        // Snapshot the screen *while holding the screen lock* so nothing
        // can sneak in between the snapshot and the subscribe call.
        let parser = screen.lock().unwrap();
        let initial_state = parser.screen().state_formatted();
        let rx = output_tx.subscribe();
        drop(parser);

        Some(Subscription { initial_state, rx })
    }

    /// Returns the current lifecycle state.
    #[allow(dead_code)]
    pub(crate) fn state(&self) -> &TaskState {
        &self.state
    }

    pub(crate) fn into_handle(self) -> TaskHandle {
        TaskHandle {
            task: Arc::new(Mutex::new(self)),
            done: CancellationToken::new(),
        }
    }
}

impl std::fmt::Debug for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ready { .. } => write!(f, "Ready"),
            Self::Running { .. } => write!(f, "Running"),
            Self::Finished { exit_status } => {
                write!(f, "Finished(code={})", exit_status.code)
            }
        }
    }
}

impl std::fmt::Debug for Task {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Task")
            .field("id", &self.id)
            .field("config_source", &self.config_source)
            .field("state", &self.state)
            .field("environment", &self.environment)
            .finish_non_exhaustive()
    }
}

/// A thread-safe handle to a task.
#[derive(Debug, Clone)]
pub struct TaskHandle {
    task: Arc<Mutex<Task>>,
    /// Cancelled by the driver when the task reaches [`TaskState::Finished`].
    done: CancellationToken,
}

impl TaskHandle {
    /// Takes the lock, allowing access to the [`Task`].
    ///
    /// Drop the guard as quickly as possible.
    pub async fn lock(&self) -> MutexGuard<'_, Task> {
        self.task.lock().await
    }

    /// Subscribes to the live terminal output of a running task.
    ///
    /// Convenience wrapper that briefly locks the task. Returns `None` if
    /// the task is not currently running.
    pub async fn subscribe(&self) -> Option<Subscription> {
        self.task.lock().await.subscribe()
    }

    /// Waits for the task to reach [`TaskState::Finished`].
    ///
    /// Returns immediately if already finished. Safe to call from multiple
    /// tasks concurrently.
    pub async fn wait(&self) {
        self.done.cancelled().await;
    }

    /// Starts the task, launching a background [`Driver`].
    ///
    /// Moves the sandbox env and invocation list into the driver so it is
    /// fully self-contained.  The only shared state is the terminal screen,
    /// otherwise interaction must be via the channels in TaskState::Running.
    pub async fn start(&self, size: WinSize) -> Result<(), mctx::Error> {
        let driver = {
            let mut task = self.task.lock().await;

            // Take inner out of Ready.
            let state = std::mem::replace(
                &mut task.state,
                // Temporary — overwritten below.
                TaskState::Finished {
                    exit_status: hakoniwa::ExitStatus {
                        code: -1,
                        reason: String::new(),
                        exit_code: None,
                        rusage: None,
                        proc_pid_smaps_rollup: None,
                        proc_pid_status: None,
                    },
                },
            );
            let TaskState::Ready { inner } = state else {
                // Put the original state back.
                task.state = state;
                return Err(mctx::Error::Other(anyhow::anyhow!(
                    "task is not in Ready state"
                )));
            };

            let screen: Screen = Arc::new(std::sync::Mutex::new(vt100_ctt::Parser::new(
                size.rows, size.cols, 0,
            )));
            let (input_tx, input_rx) = mpsc::channel::<MuxCommand>(64);
            let (output_tx, _) = broadcast::channel::<Vec<u8>>(64);
            let cancel = CancellationToken::new();

            let driver = Driver::new(
                self.clone(),
                inner,
                screen.clone(),
                input_rx,
                output_tx.clone(),
                cancel.clone(),
                size,
            )?;

            task.screen = Some(screen);
            task.state = TaskState::Running {
                input_tx,
                output_tx,
                cancel,
            };

            driver
        };
        // Lock is dropped.
        tokio::spawn(driver.run());
        Ok(())
    }

    /// Kills the running child process and stops the background driver.
    ///
    /// No-op if the task is not currently running.
    pub async fn kill(&self) {
        let task = self.task.lock().await;
        if let TaskState::Running { cancel, .. } = &task.state {
            cancel.cancel();
        }
    }
}

/// Drives the I/O for task, owning all state & ferrying input/output data.
///
/// Lifecycle:
///   1. [`new`](Self::new)  — take ownership of inner, spawn first child
///   2. [`run`](Self::run)  — `tokio::spawn` this; loops through invocations
///   3. on completion/cancel — sets `Finished` on the task, returns
struct Driver {
    task: TaskHandle,
    /// Cancelled when the task reaches Finished, waking [`TaskHandle::wait`].
    done: CancellationToken,
    inner: TaskRuntime,
    screen: Screen,
    master: AsyncFd<std::fs::File>,
    child: hakoniwa::Child,
    input_rx: mpsc::Receiver<MuxCommand>,
    output_tx: broadcast::Sender<Vec<u8>>,
    cancel: CancellationToken,
    size: WinSize,
}

impl Driver {
    /// Takes ownership of `inner`, spawns the first invocation.
    fn new(
        task: TaskHandle,
        mut inner: TaskRuntime,
        screen: Screen,
        input_rx: mpsc::Receiver<MuxCommand>,
        output_tx: broadcast::Sender<Vec<u8>>,
        cancel: CancellationToken,
        size: WinSize,
    ) -> Result<Self, mctx::Error> {
        let inv = inner.invocations.remove(0);
        let container = inner.env.container()?;
        let (master, child) = Self::spawn_child(&mut inner.env, &container, &inv, size)?;
        let done = task.done.clone();

        Ok(Self {
            task,
            done,
            inner,
            screen,
            master,
            child,
            input_rx,
            output_tx,
            cancel,
            size,
        })
    }

    /// Main loop — drives invocations until done or cancelled.
    async fn run(mut self) {
        loop {
            match self.run_invocation().await {
                Err(_) if self.cancel.is_cancelled() => {
                    self.kill_child().await;
                    return;
                }
                Err(e) => {
                    tracing::warn!("unexpected invocation error: {}", e);
                    self.kill_child().await;
                    return;
                }
                Ok(status) => {
                    if !self.advance(status).await {
                        return;
                    }
                }
            }
        }
    }

    /// Drives a single invocation: reads output, handles input, detects exit.
    async fn run_invocation(&mut self) -> Result<hakoniwa::ExitStatus, std::io::Error> {
        let mut buf = [0u8; 4096];

        loop {
            tokio::select! {
                _ = self.cancel.cancelled() => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::Interrupted,
                        "task cancelled",
                    ));
                }

                readable = self.master.readable() => {
                    let mut guard = readable?;
                    match guard.try_io(|fd| fd.get_ref().read(&mut buf)) {
                        Ok(Ok(0)) => {
                            return self.child.wait().map_err(std::io::Error::other);
                        }
                        Ok(Ok(n)) => {
                            self.push_bytes(&buf[..n]);
                        }
                        Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => {
                            // EIO on a PTY master means the slave side was
                            // closed (normal when the child exits).
                            return self.child.wait().map_err(std::io::Error::other);
                        }
                        Ok(Err(e)) => return Err(e),
                        Err(_would_block) => {}
                    }
                }

                Some(cmd) = self.input_rx.recv() => {
                    self.handle_command(cmd);
                }
            }

            if let Ok(Some(status)) = self.child.try_wait() {
                self.drain_output();
                return Ok(status);
            }
        }
    }

    /// Spawns the next invocation, or sets `Finished` if none remain.
    /// Returns `true` if the loop should continue.
    async fn advance(&mut self, last_status: hakoniwa::ExitStatus) -> bool {
        if self.inner.invocations.is_empty() {
            self.finish(last_status).await;
            return false;
        }

        let inv = self.inner.invocations.remove(0);
        let container = match self.inner.env.container() {
            Ok(c) => c,
            Err(_) => return false,
        };

        match Self::spawn_child(&mut self.inner.env, &container, &inv, self.size) {
            Ok((master, child)) => {
                self.master = master;
                self.child = child;
                true
            }
            Err(_) => false,
        }
    }

    /// SIGKILL the child, reap it, and transition to Finished.
    async fn kill_child(&mut self) {
        let _ = self.child.kill();
        if let Ok(s) = self.child.wait() {
            self.finish(s).await;
        }
    }

    /// Briefly locks the task to set Finished, then signals waiters.
    async fn finish(&self, exit_status: hakoniwa::ExitStatus) {
        let mut task = self.task.task.lock().await;
        task.state = TaskState::Finished { exit_status };
        drop(task);
        self.done.cancel();
    }

    /// Pushes bytes into the shared parser and broadcasts to subscribers.
    fn push_bytes(&self, bytes: &[u8]) {
        self.screen.lock().unwrap().process(bytes);
        // Ignore send errors — just means no active subscribers.
        let _ = self.output_tx.send(bytes.to_vec());
    }

    /// Drains remaining buffered output from the master fd.
    fn drain_output(&self) {
        let mut buf = [0u8; 4096];
        loop {
            match self.master.get_ref().read(&mut buf) {
                Ok(0) | Err(_) => return,
                Ok(n) => self.push_bytes(&buf[..n]),
            }
        }
    }

    /// Handles a command from the input channel.
    fn handle_command(&mut self, cmd: MuxCommand) {
        match cmd {
            MuxCommand::Input(data) => {
                let _ = self.master.get_ref().write(&data);
            }
            MuxCommand::Resize(new_size) => {
                let _ = mux::set_winsize(self.master.as_raw_fd(), new_size);
                self.size = new_size;
                self.screen
                    .lock()
                    .unwrap()
                    .screen_mut()
                    .set_size(new_size.rows, new_size.cols);
            }
        }
    }

    /// Builds a command from an invocation, wires a PTY, spawns the child.
    fn spawn_child(
        env: &mut Env<'_>,
        container: &sandbox2::Container,
        inv: &Invocation,
        size: WinSize,
    ) -> Result<(AsyncFd<std::fs::File>, hakoniwa::Child), mctx::Error> {
        let mut cmd = env.command(container, &inv.executable, inv.args.iter())?;
        for (k, v) in &inv.envs {
            cmd.env(k, v);
        }

        let pty = Pty::open(size).map_err(|e| mctx::Error::Other(e.into()))?;
        let (master, slave) = pty.into_fds();

        let slave_for_stdout = mux::dup_fd(&slave).map_err(|e| mctx::Error::Other(e.into()))?;
        let slave_for_stderr = mux::dup_fd(&slave).map_err(|e| mctx::Error::Other(e.into()))?;
        cmd.stdin(hakoniwa::Stdio::from(slave));
        cmd.stdout(hakoniwa::Stdio::from(slave_for_stdout));
        cmd.stderr(hakoniwa::Stdio::from(slave_for_stderr));

        let child = cmd
            .spawn()
            .map_err(|e| mctx::Error::Other(anyhow::anyhow!("{}", e)))?;

        mux::set_nonblocking(master.as_raw_fd()).map_err(|e| mctx::Error::Other(e.into()))?;
        let file = unsafe { std::fs::File::from_raw_fd(master.into_raw_fd()) };
        let master = AsyncFd::new(file).map_err(|e| mctx::Error::Other(e.into()))?;

        Ok((master, child))
    }
}
