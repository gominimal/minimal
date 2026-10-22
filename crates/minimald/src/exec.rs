//! SSH `exec` request handling: Launching tasks defined in the session,
//! git recieve-pack, and launching side ops.
//!
//! Process spawning is abstracted via the [`Exec`] / [`Process`] traits
//! so the bridge logic can be exercised with a mock in tests without
//! going through `tokio::process` or russh.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Display;
use std::io;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use boxes::SessionId;
use futures::{
    StreamExt,
    stream::{self, BoxStream, Stream},
};
use paths::DaemonAbsPath;
use russh::{
    Channel, ChannelId,
    server::{Msg, Session},
};
use tempfile::TempDir;
use tokio::net::unix::pipe;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, ChildStderr, ChildStdin, ChildStdout, Command},
};
use tokio_util::sync::CancellationToken;
use tracing::Instrument as _;

// Every task this module spawns carries the caller's span (TEL-022): the
// clippy `disallowed-methods` for the crate names tokio's own spawn.
use crate::traced::spawn;

use diagnostics::redact::scrub_secrets;

use crate::{
    ChannelConfig, MINIMAL_SESSION_ID_ENV,
    box_actor::BoxHandle,
    box_manager::BoxKeyPredicate,
    connection::{ConnectionError, ConnectionHandle},
    server::ServerStateHandle,
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

    /// Whether a destroy of the box ends this exec's process. True for a
    /// process inside the box, which the destroy's host teardown stops.
    /// False for a process outside the box — on the daemon's host, or in a
    /// task's own sandbox — which outlives it.
    const ENDED_BY_BOX_DESTROY: bool = true;

    fn exec(self, session: BoxHandle) -> BoxStream<'static, io::Result<Self::Process>>;
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
    /// The task's declared arguments, as the client typed them after the
    /// task name. Parsed against the task's `args` schema in
    /// [`task_producer`], where the schema is first available. Empty when
    /// the client sent none — an older `min`, or a task that declares no
    /// args — in which case the task's defaults apply.
    pub args: Vec<String>,
    /// The task's `env_vars`, already resolved against the invoking shell
    /// by the client and carried on the channel environment (see
    /// [`minimald_rpc::taskenv`]). Applied over the task's own
    /// declarations, so an `inherit` entry never reaches the daemon-side
    /// `std::env::var` that cannot see the user's `export` (#585).
    ///
    /// Empty when the client sent none — an older `min`, or any caller
    /// other than `min task run` — in which case resolution falls back to
    /// the daemon-side path exactly as before.
    pub env: BTreeMap<String, String>,
    /// Names the client's `[vars] ignore` policy matched, to be removed
    /// from the task's declarations outright.
    ///
    /// Omitting a name from [`Self::env`] cannot express this: the overlay
    /// only inserts, so an omitted name keeps whatever `minimal.toml`
    /// declared and an `inherit` among them would be resolved against the
    /// daemon's own environment — the very indirection #585 removes. A
    /// dropped name has to be named.
    pub drop_env: BTreeSet<String>,
    /// The client's invocation directory relative to the uploaded tree,
    /// already refused by [`minimald_rpc::exec::ExecRequest::parse`] if it
    /// is absolute or holds a `..`. A task that declares `inherit_cwd`
    /// starts there (see [`task_start_dir`]); empty means the root.
    pub cwd: String,
}

/// Where a task starts inside its session-layout sandbox, when not at the
/// default `/workbench`.
///
/// `Ok(Some(dir))` is `/workbench/<cwd>` for a task that declares
/// `inherit_cwd` when `<cwd>` is a directory of the uploaded tree at
/// `working`. `Ok(None)` keeps the default: the task does not inherit, or
/// the client ran from the root. `Err(notice)` also keeps the default, with
/// the one-line notice to show on the task's stderr: the directory is not in
/// the uploaded tree (an upload that was skipped, or a path the upload
/// excluded).
fn task_start_dir(
    inherit_cwd: bool,
    cwd: &str,
    working: &std::path::Path,
) -> Result<Option<String>, String> {
    if !inherit_cwd || cwd.is_empty() {
        return Ok(None);
    }
    if working.join(cwd).is_dir() {
        Ok(Some(format!("/{}/{cwd}", sandbox::SESSION_DEFAULT_WD)))
    } else {
        Err(format!(
            "minimal: {cwd} is not in the uploaded tree; running the task at /{}\n",
            sandbox::SESSION_DEFAULT_WD
        ))
    }
}

impl Exec for TaskExec {
    type Process = TaskProcess;

    // A task runs in a sandbox of its own, beside the box rather than in
    // it: the destroy's host teardown (`BoxActor::stop_running`) does not
    // stop it, so a task that ends during a destroy was not ended by it.
    const ENDED_BY_BOX_DESTROY: bool = false;

    fn exec(self, session: BoxHandle) -> BoxStream<'static, io::Result<Self::Process>> {
        // 1-slot request/response channels: the producer only spawns
        // the next child once the consumer pulls. Dropping a
        // `HakoniwaProcess` orphans the child, so we don't want to
        // spawn one we may never deliver.
        let (req_tx, req_rx) = mpsc::channel::<()>(1);
        let (proc_tx, proc_rx) = mpsc::channel::<io::Result<TaskProcess>>(1);

        // Producer task: holds `env`, `container`, and the invocation
        // list on its stack frame. `env` owns the temp dirs and the
        // `ClaudeMdPatch` whose `Drop` must run only after every
        // spawned child has finished — which is exactly when the
        // consumer drops the stream, the channels close, this task
        // exits, and `env` falls out of scope.
        crate::traced::spawn(task_producer(self, session, req_rx, proc_tx));

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

/// The network a task gets: the provider for its session's mode (017-005),
/// carrying the session's *effective* egress (NET-074) — a task in an
/// own-address session runs under whatever the session's own gate enforces:
/// the deny-all default in force, allow-all behind the opt-out — and none of
/// its ingress. Shared by the two ways a
/// task starts — over an exec channel here, and from inside the session
/// (`env::BoxChannel::run_task`).
///
/// The mode, not the identity: an own-IP task is a second PTask beside the
/// session's, on the same switch at the same time, so it registers under its
/// own name and carries none of the session's ingress — forwards a task
/// applied would come down again at its teardown. It carries no registry
/// handle either: a task owns no proxy route of its own, so no lease is ever
/// reported for it. `phase` is the rollout phase to resolve the egress under
/// — both callers pass [`boxes::EGRESS_DEFAULT_PHASE`], the phase this
/// build ships, while the tests pass the phase by name so each arm's posture
/// stays proven — and `deny_all_opt_out` is the daemon's opt-out (NET-077),
/// read through the session handle so a task resolves its egress exactly as
/// the launcher did. It carries no classifier decision either (NET-079):
/// a task places no leaf in the cohort's subtrees, so no per-box verdict
/// is its plan's to follow.
///
/// A gate is attached only where that egress has rules to enforce: the
/// deny-all section the in-force default resolves an absent declaration to,
/// or the box's own declaration. An absent section — the allow-all the
/// opt-out (or the announced phase) leaves in place — passes `None`, as
/// every task did before the deny-all default: a gate with no ingress
/// declaration blocks a task's *inbound* too (`allowed`/`udp_allowed` empty),
/// so attaching one where nothing needs gating would change behaviour the
/// opt-out exists to keep.
pub(crate) fn task_network(
    record: &boxes::Record,
    switch: &std::sync::Arc<tokio::sync::Mutex<crate::net::SwitchClient>>,
    phase: boxes::EgressDefaultPhase,
    deny_all_opt_out: bool,
) -> std::sync::Arc<dyn sandbox::Network> {
    let id = record.id.to_string();
    let session = record.name.as_deref().unwrap_or(&id);
    let egress = crate::box_actor::effective_egress_section(
        &record.policy,
        record.network,
        phase,
        deny_all_opt_out,
    );
    crate::net::provider::task_network_for(
        record.network,
        switch,
        &format!("{session}-task"),
        egress.map(|section| boxes::BoxPolicy::new(Some(section), None)),
        // Never the record's handed box addresses (T66): the task's sandbox
        // is not the box the registration named — attaching it at the
        // session box's address would key its frames to the session's row.
        // A task attaches at one of the task addresses the same
        // registration filed with the box (NET-138), each a host-side row
        // carrying the box's id and egress, so no daemon-side draw happens
        // once a control socket exists. A native daemon, whose record holds
        // none, draws from its reserve (`crate::net::self_allocation_run`);
        // an in-VM one refuses the draw (`SwitchClient::attach`). There is
        // no classifier decision to carry (NET-079): a task places no leaf
        // in the cohort's subtrees.
        record.task_addresses.clone(),
    )
}

/// Refuses a task run of a registered box whose host-side row is not its
/// own any more (NET-138): a task attaches at one of the task addresses
/// filed with the box's row, and those task rows stand exactly as long as
/// the box's row, so the run asks the VM host daemon whether the row of
/// the box's id still stands at its switch address before it attaches. A
/// row the host handed another box at that address answers no, so the run
/// never attaches under another box's row. A record that names no box id,
/// and a host that cannot be asked, read as no row: fail-closed. A box the
/// host registered nothing for (a native host, a `host_ip` or `none` box)
/// asks nothing.
async fn ensure_task_rows_stand(
    record: &boxes::Record,
    switch: &tokio::sync::Mutex<crate::net::SwitchClient>,
) -> io::Result<()> {
    let Some(addresses) = record.box_addresses else {
        return Ok(());
    };
    let standing = match record.box_id {
        Some(box_id) => {
            let control = crate::box_actor::switch_control_of(switch).await;
            crate::net::listeners::host_row_standing(&control, addresses.switch_address, box_id)
                .await
                == Some(true)
        }
        None => false,
    };
    if standing {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "the VM host daemon could not confirm session {}'s network addresses, so \
             the task was not run; destroy the session with `min session destroy <session>`, \
             then start it again with `min session activate`",
            record.name.as_deref().unwrap_or("(unnamed)")
        )))
    }
}

/// The slice of `hakoniwa::Child` the attach-failure arm needs, so the arm can
/// be tested without a container.
trait Reapable {
    /// Kill the process and wait for it, so it does not outlive its sandbox.
    fn kill_and_reap(&mut self);
}

impl Reapable for hakoniwa::Child {
    fn kill_and_reap(&mut self) {
        // `wait` runs regardless of `kill`: the process may have already exited.
        let _ = self.kill();
        let _ = self.wait();
    }
}

/// Step 3 of a task launch: wire the process's namespace, or kill and reap the
/// process so it does not run on with the network it failed to get — as
/// `sandbox::run_with_cancel` does. `PlannedLaunch`'s drop releases the plan.
async fn attach_or_reap<P: Reapable>(
    planned: sandbox::PlannedLaunch,
    spawned: sandbox::Spawned,
    child: &mut P,
) -> io::Result<Box<dyn sandbox::NetGuard>> {
    match planned.attach(spawned).await {
        Ok(guard) => Ok(guard),
        Err(e) => {
            child.kill_and_reap();
            Err(io::Error::other(format!(
                "connecting the task's network failed: {e}"
            )))
        }
    }
}

/// Parse a task run's argv against the task's declared `args` schema.
///
/// Returns `None` when the task declares no args (nothing to bind), and
/// `Some` otherwise — even for an empty argv, which `parse_argv_named`
/// fills with the task's defaults. This mirrors the in-sandbox path in
/// `mctx::env`, so a task using `%{arg}` resolves the same way whether it
/// runs in-box or through the daemon.
///
/// `name` is the task's name, so a usage error shows the command the user
/// can copy (`min task run <name> --arg <value>`), as `mip run` does.
fn parse_task_args(
    name: &str,
    task: &mfile::Task,
    argv: &[String],
) -> Result<Option<args::ArgsSet>, String> {
    if task.args.is_empty() {
        return Ok(None);
    }
    task.args
        .parse_argv_named(&format!("min task run {name}"), argv.iter().cloned())
        .map(Some)
        .map_err(|e| e.to_string())
}

/// Producer side of [`TaskExec::exec`]. Inlined in one async fn so that
/// `env` lives on a single stack frame across every spawn — that frame
/// is alive for the whole life of this tokio task, which in turn is
/// governed by the consumer's stream.
async fn task_producer(
    exec: TaskExec,
    session: BoxHandle,
    mut req_rx: mpsc::Receiver<()>,
    proc_tx: mpsc::Sender<io::Result<TaskProcess>>,
) {
    // Wrap the whole body in a fallible async block so setup errors
    // short-circuit with `?`. An `Err` outcome triggers the
    // "wait for the first request, deliver error, exit" branch below.
    let outcome: io::Result<()> = async {
        let mut ctx = session.context().await.map_err(io::Error::other)?;

        // An `echo` task's output lives entirely in its declaration, so it
        // needs no package graph or sandbox: emit it straight from the
        // daemon and skip the heavy path below. Only mfile-local tasks are
        // matched; a stack-provided echo task falls through to the sandbox.
        if let Some(task) = ctx.minimal_file().task(&exec.task)
            && task.action.as_echo().is_some()
        {
            let parsed_args = parse_task_args(&exec.task, &task, &exec.args)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let task = mctx::interpolate_task_strings(&task, parsed_args.as_ref())
                .map_err(|e| io::Error::other(e.to_string()))?;
            let text = task.action.as_echo().unwrap_or_default().to_string();
            if req_rx.recv().await.is_some() {
                let _ = proc_tx
                    .send(Ok(TaskProcess::Echo(EchoProcess::new(&text))))
                    .await;
            }
            // Park until the consumer drops the stream, mirroring the
            // sandbox path's tail so the bridge sees a clean end-of-stream.
            let _ = req_rx.recv().await;
            return Ok(());
        }

        // `graph_from_all_packages` is CPU-heavy (nickel evaluation,
        // graph construction) — run it on the blocking pool so it
        // doesn't stall the async executor.
        let (mut ctx, graph_result) = crate::traced::spawn_blocking(move || {
            let r = ctx.graph_from_all_packages().map_err(|e| e.to_string());
            (ctx, r)
        })
        .await
        .map_err(io::Error::other)?;
        let graph = graph_result.map_err(io::Error::other)?;
        let (mut task, mut graph) = ctx
            .task(graph, &exec.task)
            .map_err(|e| io::Error::other(e.to_string()))?
            .ok_or_else(|| io::Error::other(format!("No such task: {}", exec.task)))?;
        // Parse the client's args against the task's declared schema. This
        // is where the schema is first available: the dispatch arm only has
        // the raw argv off the wire. An empty argv still parses, applying
        // the task's defaults — the all-defaults case the issue reports.
        let parsed_args = parse_task_args(&exec.task, &task, &exec.args)
            .map_err(|e| io::Error::other(e.to_string()))?;
        // Values the client resolved against the invoking shell win over the
        // task's own declarations. That is what turns `{ inherit = true }`
        // into something the daemon can apply: resolving it here would read
        // *this* process's environment, which the user's `export` never
        // reaches (#585). An entry the client did not send keeps whatever
        // the task declared, so the daemon-side path still serves in-box
        // `min run` and older clients.
        // Removals first. The two sets are disjoint, so the order is not
        // load-bearing, but reading it in policy order — drop, then apply —
        // matches how the client decided.
        for name in &exec.drop_env {
            task.vars.remove(name);
        }
        for (name, value) in &exec.env {
            task.vars
                .insert(name.clone(), mfile::EnvVarValue::Value(value.clone()));
        }
        let record = session.record().await?;
        let switch = session.net_switch().await?;
        ensure_task_rows_stand(&record, &switch).await?;
        let network = task_network(
            &record,
            &switch,
            boxes::EGRESS_DEFAULT_PHASE,
            session.deny_all_opt_out().await?,
        );
        // A task's `~/` resolves against the session's home, the same
        // directory the interactive session sees at `/home`. The daemon's own
        // ambient home is `/` inside the guest, and expanding against that
        // dropped package-declared files onto the read-only rootfs (#1204).
        // The task then runs in the session layout (home at `/home`, tree at
        // `/workbench`), and a patch that expanded into either directory is
        // mounted at the matching path there, keeping its declared mode.
        let session_paths = session.paths().await?;
        // `inherit_cwd`: start where the client was invoked, inside the
        // uploaded tree, or fall back to the root with a notice.
        let (start_dir, mut start_notice) = match task_start_dir(
            task.inherit_cwd,
            &exec.cwd,
            session_paths.working.as_utf8_path().as_std_path(),
        ) {
            Ok(dir) => (dir, None),
            Err(notice) => (None, Some(notice)),
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
                network,
                mctx::PatchHome::Session(session_paths.home.clone()),
                mctx::WdLayout::Session {
                    home: session_paths.home.as_utf8_path().to_path_buf().into(),
                    working: session_paths.working.as_utf8_path().to_path_buf().into(),
                },
            )
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;
        let (_interactive, invocations) = env
            .task_invocations(&task, parsed_args.as_ref())
            .await
            .map_err(|e| io::Error::other(e.to_string()))?;

        for inv in invocations {
            // Wait for the consumer to ask. `None` means the consumer
            // dropped the stream; exit cleanly so `env` drops.
            if req_rx.recv().await.is_none() {
                return Ok(());
            }
            let result = async {
                // One plan, container and attach per invocation: hakoniwa
                // unshares per `spawn()`, so each needs its own address.
                let planned = env.plan_launch().await.map_err(|e| {
                    io::Error::other(format!("setting up the task's network failed: {e}"))
                })?;
                let container = env
                    .container(planned.plan())
                    .map_err(|e| io::Error::other(format!("building container failed: {}", e)))?;
                let mut cmd = env
                    .invocation_command(&container, &inv)
                    .map_err(|e| io::Error::other(format!("building command failed: {}", e)))?;
                if let Some(dir) = &start_dir {
                    cmd.current_dir(dir);
                }
                cmd.stdin(hakoniwa::Stdio::piped())
                    .stdout(hakoniwa::Stdio::piped())
                    .stderr(hakoniwa::Stdio::piped());
                let mut child = cmd
                    .spawn()
                    .map_err(|e| io::Error::other(format!("command launch failed: {}", e)))?;
                let spawned = sandbox::Spawned::from_child(&mut child);
                let guard = attach_or_reap(planned, spawned, &mut child).await?;
                let mut process = HakoniwaProcess::new(child, guard);
                // The fallback notice leads the first invocation's stderr.
                process.stderr_notice = start_notice.take();
                Ok(TaskProcess::Sandbox(process))
            }
            .await;
            if let Err(send_err) = proc_tx.send(result).await {
                // Receiver dropped between our `recv` returning `Some`
                // and our `send`. If we just spawned a child, kill it
                // before `env` drops so it doesn't outlive its sandbox
                // rootfs — and reap it, which is what releases its network.
                if let Ok(mut proc) = send_err.0 {
                    let _ = proc.start_kill();
                    crate::traced::spawn(async move {
                        let _ = proc.wait().await;
                    });
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
    /// The network wiring this task's namespace got, released at the end of
    /// [`wait`](Process::wait).
    net: NetRelease,
    /// A line the daemon shows ahead of the child's own stderr, such as the
    /// `inherit_cwd` fallback notice (see [`task_start_dir`]).
    stderr_notice: Option<String>,
}

/// The release of a task's network, owed once its process is gone.
///
/// [`Process::wait`] is polled inside a `select!` and may be dropped at any
/// await, so the teardown cannot be awaited in place: dropped mid-teardown, a
/// guard would never detach. It runs on its own task instead, and `wait`
/// awaits the handle, which survives being dropped and re-awaited.
struct NetRelease {
    guard: Option<Box<dyn sandbox::NetGuard>>,
    /// The teardown in flight, once started.
    running: Option<JoinHandle<()>>,
}

impl Drop for NetRelease {
    /// A process dropped before its `wait` completed — an aborted bridge —
    /// still owes its network back. `Drop` cannot await, so the teardown goes
    /// onto the runtime; with none running there is nothing to release to.
    fn drop(&mut self) {
        if let Some(guard) = self.guard.take()
            && let Ok(handle) = tokio::runtime::Handle::try_current()
        {
            handle.spawn(guard.teardown());
        }
    }
}

impl NetRelease {
    fn new(guard: Box<dyn sandbox::NetGuard>) -> Self {
        Self {
            guard: Some(guard),
            running: None,
        }
    }

    /// Runs the teardown to completion, once. Cancel-safe: a dropped call
    /// leaves the teardown running, and the next call waits for it.
    async fn release(&mut self) {
        if let Some(guard) = self.guard.take() {
            self.running = Some(crate::traced::spawn(guard.teardown()));
        }
        if let Some(running) = &mut self.running {
            let _ = running.await;
            self.running = None;
        }
    }
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
    /// Cached exit status, shell-convention (`128 + signo` for a signal
    /// death). `Option` for the terminal-state machinery; the success
    /// path always fills it.
    Exited(Option<i32>),
    /// Wait itself errored. The original `io::Error` isn't `Clone`, so
    /// repeat `wait()` calls get a generic "previously failed" error
    /// rather than the original cause.
    Failed,
}

impl HakoniwaProcess {
    fn new(child: hakoniwa::Child, net_guard: Box<dyn sandbox::NetGuard>) -> Self {
        Self {
            pid: child.id() as libc::pid_t,
            state: WaitState::Spawned(Box::new(child)),
            net: NetRelease::new(net_guard),
            stderr_notice: None,
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
            self.state = WaitState::Waiting(crate::traced::spawn_blocking(move || child.wait()));
        }

        // Waiting → Exited / Failed. The `await` is the cancel point —
        // if dropped mid-poll, the state stays `Waiting` and a fresh
        // `wait()` call resumes the same `JoinHandle`.
        if let WaitState::Waiting(handle) = &mut self.state {
            self.state = match handle.await {
                // `code` is the shell-convention status (`128 + signo` for a
                // signal death), so a SIGKILL reports 137 rather than 1. The
                // `exit_code` field is `None` for signals and would collapse
                // to 1 downstream; `code` is what the session path reports too.
                Ok(Ok(status)) => WaitState::Exited(Some(status.code)),
                Ok(Err(_)) | Err(_) => WaitState::Failed,
            };
        }

        // Terminal either way, so the network goes back now — on the `Failed`
        // arm too, where the process is equally gone.
        self.net.release().await;

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

/// The [`Process`] produced by a [`TaskExec`]: either a real sandboxed child
/// ([`HakoniwaProcess`]) or a synthetic [`EchoProcess`] for `echo` tasks.
///
/// Stdio is boxed so the two variants' differing handle types unify behind
/// one associated type; the bridge only ever sees `dyn AsyncRead`/`AsyncWrite`.
pub enum TaskProcess {
    Sandbox(HakoniwaProcess),
    Echo(EchoProcess),
}

impl Process for TaskProcess {
    type Stdin = std::pin::Pin<Box<dyn AsyncWrite + Send + Unpin>>;
    type Stdout = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;
    type Stderr = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        match self {
            TaskProcess::Sandbox(p) => {
                let (i, o, e) = p.take_stdio()?;
                let notice = p.stderr_notice.take().unwrap_or_default();
                let e = std::io::Cursor::new(notice.into_bytes()).chain(e);
                Some((Box::pin(i), Box::pin(o), Box::pin(e)))
            }
            TaskProcess::Echo(p) => p.take_stdio(),
        }
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        match self {
            TaskProcess::Sandbox(p) => p.wait().await,
            TaskProcess::Echo(p) => p.wait().await,
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        match self {
            TaskProcess::Sandbox(p) => p.start_kill(),
            TaskProcess::Echo(p) => p.start_kill(),
        }
    }
}

/// A synthetic [`Process`] that emits a fixed string on stdout and exits 0,
/// without spawning anything. Backs `echo` tasks, whose entire output is
/// known from the task declaration — so no package graph or sandbox is built.
///
/// The stdout carries `text` plus a trailing newline, matching what
/// `/bin/echo "text"` would produce.
pub struct EchoProcess {
    /// `Some` until `take_stdio` hands the streams out; `None` thereafter.
    stdout: Option<Vec<u8>>,
}

impl EchoProcess {
    fn new(text: &str) -> Self {
        Self {
            stdout: Some(format!("{text}\n").into_bytes()),
        }
    }
}

impl Process for EchoProcess {
    type Stdin = std::pin::Pin<Box<dyn AsyncWrite + Send + Unpin>>;
    type Stdout = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;
    type Stderr = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        let bytes = self.stdout.take()?;
        Some((
            // Client stdin is accepted and discarded, as a real fast-exiting
            // process would leave it unread.
            Box::pin(tokio::io::sink()),
            Box::pin(std::io::Cursor::new(bytes)),
            Box::pin(tokio::io::empty()),
        ))
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        Ok(Some(0))
    }

    fn start_kill(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Runs an unsandboxed process to service an ssh execution. See [`TaskExec`],
/// this must only be used to service specific safe invocations like `git recieve-pack`.
#[derive(Debug, Clone)]
pub struct TokioExec {
    pub argv: String,
    pub cwd: DaemonAbsPath,
    pub env: BTreeMap<String, String>,
    /// Environment variables to strip from the child process. Used to
    /// keep Git repository-location variables inherited from the daemon
    /// from redirecting `git init` / `git upload-pack` away from the
    /// session workspace.
    pub drop_env: BTreeSet<String>,
}

impl Exec for TokioExec {
    type Process = TokioProcess;

    // The process runs on the daemon's host, not in the box, so the
    // destroy's host teardown does not stop it.
    const ENDED_BY_BOX_DESTROY: bool = false;

    fn exec(self, _session: BoxHandle) -> BoxStream<'static, io::Result<Self::Process>> {
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
            for name in &self.drop_env {
                cmd.env_remove(name);
            }
            cmd.spawn().map(TokioProcess::new)
        })
        .boxed()
    }
}

/// Git environment variables that relocate a repository away from the
/// process working directory. Inheriting any of these from the daemon
/// would make `git init` / `git upload-pack` target a repository other
/// than the session workspace, so they are stripped from the child
/// process.
fn git_repo_location_env() -> BTreeSet<String> {
    [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_NAMESPACE",
        "GIT_CEILING_DIRECTORIES",
        "GIT_DISCOVERY_ACROSS_FILESYSTEM",
        "GIT_QUARANTINE_PATH",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// What to run inside the session, and whether a shell stands between the
/// client's words and the process.
#[derive(Debug, Clone)]
pub enum BoxProgram {
    /// A command line for the session's shell. The client wrote a shell
    /// command, so quoting, globs, pipes and redirections are part of what it
    /// means — matching what `ssh host '...'` does everywhere else.
    Shell(String),
    /// An argv to exec directly. Nothing re-splits these words, which is the
    /// whole point: a shell in the middle would undo the quoting the client
    /// already resolved. Guaranteed non-empty by
    /// [`minimald_rpc::exec::ExecRequest::parse`].
    Argv(Vec<String>),
}

impl BoxProgram {
    /// The program and arguments to hand the session, resolving a shell
    /// command into an explicit `bash -c` argv.
    fn argv(self) -> (String, Vec<String>) {
        match self {
            Self::Shell(cmd) => (SESSION_SHELL.to_string(), vec!["-c".to_string(), cmd]),
            Self::Argv(mut words) => {
                // Non-empty by construction; `remove(0)` cannot panic.
                let program = words.remove(0);
                (program, words)
            }
        }
    }
}

/// An [`Exec`] that runs a command *inside* the session's sandbox, joining the
/// namespaces of the running session process.
#[derive(Debug, Clone)]
pub struct BoxExec {
    pub program: BoxProgram,
    /// Variables layered over the session's own for this one process: the
    /// exec's `TRACEPARENT` on telemetry opt-in ([`minimald_rpc::taskenv::trace_env`]).
    pub extra_env: BTreeMap<String, String>,
    /// The SSH username, needed only if the session has no host running and one
    /// has to be launched to service this request.
    pub conn_username: String,
}

/// The shell a session's exec requests run under — the same absolute path the
/// session launcher execs for an interactive shell, since the generic rootfs
/// has no `/bin/bash`.
const SESSION_SHELL: &str = "/usr/bin/bash";

impl Exec for BoxExec {
    type Process = TokioProcess;

    fn exec(self, session: BoxHandle) -> BoxStream<'static, io::Result<Self::Process>> {
        stream::once(async move {
            // Launching the sandbox is part of servicing the request: an exec
            // against an idle session should work, not fail because nobody
            // happens to be holding a terminal open.
            let host = session
                .ensure_host(self.conn_username)
                .await
                .map_err(|e| io::Error::other(format!("{e}")))?;
            let (program, args) = self.program.argv();
            let command = host
                .command_in_session_env(&program, &args, self.extra_env)
                .await?;

            let mut command = Command::from(command);
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .kill_on_drop(true);
            // This spawns the shim — us, re-exec'd — not the user's command, so
            // a bare ENOENT reads as a missing shell. Name the path (#1175).
            let shim = command.as_std().get_program().to_owned();
            command.spawn().map(TokioProcess::shim).map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!(
                        "re-execing {} as the session-namespace shim: {e}",
                        std::path::Path::new(&shim).display()
                    ),
                )
            })
        })
        .boxed()
    }
}

/// `Process` implementation backed by [`tokio::process::Child`].
#[derive(Debug)]
pub struct TokioProcess {
    child: Child,
    /// Whether [`Process::start_kill`] sends SIGTERM, with a SIGKILL
    /// escalation in [`Process::wait`], rather than an immediate SIGKILL.
    /// Only the injection shim handles SIGTERM by killing its whole process
    /// group; any other child gets the immediate SIGKILL.
    graceful: bool,
    /// Whether a graceful [`Process::start_kill`] has asked the child to
    /// exit, which arms the escalation in [`Process::wait`].
    terminating: bool,
}

impl TokioProcess {
    /// A child that [`Process::start_kill`] SIGKILLs at once.
    fn new(child: Child) -> Self {
        Self {
            child,
            graceful: false,
            terminating: false,
        }
    }

    /// The injection shim, which [`Process::start_kill`] SIGTERMs so its
    /// handler can kill the injected process's whole group.
    fn shim(child: Child) -> Self {
        Self {
            graceful: true,
            ..Self::new(child)
        }
    }
}

impl Process for TokioProcess {
    type Stdin = ChildStdin;
    type Stdout = ChildStdout;
    type Stderr = ChildStderr;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        Some((
            self.child.stdin.take()?,
            self.child.stdout.take()?,
            self.child.stderr.take()?,
        ))
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        // Never asked to die: a plain wait, as before.
        if !self.terminating {
            return self.child.wait().await.map(|s| s.code());
        }
        // Longer than the shim's own grace period for the group, so the shim
        // always delivers the group's SIGKILL itself; this one is the fallback
        // for a wedged shim (see `nsenter::GROUP_GRACE`).
        match tokio::time::timeout(crate::nsenter::SHIM_ESCALATION, self.child.wait()).await {
            Ok(status) => status.map(|s| s.code()),
            // The shim did not exit: escalate to SIGKILL and wait it out.
            Err(_elapsed) => {
                self.child.start_kill()?;
                self.child.wait().await.map(|s| s.code())
            }
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        if !self.graceful {
            return self.child.start_kill();
        }
        // The shim is the direct child; SIGTERM reaches it and, through the
        // handler it installs, its whole process group, which the shim SIGKILLs
        // after its grace period. If the shim itself does not exit within
        // `SHIM_ESCALATION`, `wait` escalates to SIGKILL (above).
        // `id()` is `None` once the child has been reaped; nothing to signal.
        if let Some(pid) = self.child.id() {
            // SAFETY: `pid` is the live shim pid `Child` holds; `kill(2)` is
            // async-signal-safe and has no Rust-side invariants.
            if unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) } == -1 {
                let err = io::Error::last_os_error();
                // ESRCH means it already exited between `id()` and `kill`; that
                // is success, not an error the caller must handle.
                if err.raw_os_error() != Some(libc::ESRCH) {
                    return Err(err);
                }
            }
        }
        self.terminating = true;
        Ok(())
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
    session: BoxHandle,
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
        let (stdin_tx, mut stdin_rx) = tokio::io::duplex(64 * 1024);
        let (client_lost_tx, client_lost_rx) = watch::channel(false);

        let msgs = Box::pin(stream::unfold(rs, |mut rs| async move {
            rs.wait().await.map(|msg| (msg, rs))
        }));
        let pump = spawn(pump_channel_input(msgs, stdin_tx, client_lost_tx));

        let stream = self.exec.exec(self.session.clone());
        let mngr = self.serv.sessions_manager().await;
        let exit_status = bridge_noting_reason(
            self.channel_id,
            stream,
            &mut stdin_rx,
            &mut w,
            &mut e,
            client_lost_rx,
            destroy_signal::<S>(|| self.session.destroy_signal()),
            || mngr.is_shutting_down(),
        )
        .await;

        pump.abort();
        let _ = w.flush().await;
        let _ = e.flush().await;

        drop(stdin_rx);
        let _ = ws.eof().await;
        let _ = ws.exit_status(exit_status).await; // otherwise considered -1
        let _ = ws.close().await; // needed to release the remote
        exit_status
    }
}

/// The line an exec the daemon's shutdown ended leaves on stderr, so the
/// client is told why its command stopped rather than handed a bare 137.
const SHUTDOWN_NOTICE: &[u8] = b"minimald is shutting down; the command was stopped\n";

/// The line an exec the session's destroy ended leaves on stderr, for the
/// same reason: the client is told why its command stopped, not handed a
/// bare 137 with nothing on the wire to explain it.
const DESTROYED_NOTICE: &[u8] = b"the session was destroyed; the command was stopped\n";

/// The destroy token the bridge watches for an exec of kind `S`.
///
/// Only an exec whose process the destroy ends gets one
/// ([`Exec::ENDED_BY_BOX_DESTROY`]). A process outside the box outlives the
/// destroy, so the bridge does not stop it and does not name the destroy.
fn destroy_signal<S: Exec>(token: impl FnOnce() -> CancellationToken) -> Option<CancellationToken> {
    S::ENDED_BY_BOX_DESTROY.then(token)
}

/// The notice an exec leaves on stderr when it ends.
///
/// A daemon shutdown comes first. It names a command that ended with a
/// kill-shaped status. The destroy notice names only a command that the
/// bridge stopped because the destroy token fired.
fn exit_notice(
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
const KILLED_STATUS_MIN: u32 = 128;

/// A [`Process`] that the bridge stops when the box's destroy starts.
///
/// `wait` races the inner process against the destroy token. When the
/// token fires first, it calls `start_kill` and sets `stopped`. Then it
/// waits for the inner process to end. A process that already ended wins
/// the race, so a command that exits on its own never sets `stopped`.
struct StoppedOnDestroy<P> {
    inner: P,
    destroyed: CancellationToken,
    stopped: Arc<AtomicBool>,
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
        if !self.stopped.load(Ordering::SeqCst) {
            tokio::select! {
                biased;
                status = self.inner.wait() => return status,
                () = self.destroyed.cancelled() => {
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
    reason = "the bridge's own arguments, plus the two reasons it can name"
)]
async fn bridge_noting_reason<S, P, R, W, E>(
    channel_id: impl Display + Clone,
    stream: S,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    client_lost: watch::Receiver<bool>,
    destroyed: Option<CancellationToken>,
    shutting_down: impl FnOnce() -> bool,
) -> u32
where
    P: Process,
    S: Stream<Item = io::Result<P>> + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
    E: AsyncWrite + Unpin,
{
    let stopped = Arc::new(AtomicBool::new(false));
    let exit_status = match destroyed {
        Some(destroyed) => {
            let stopped = Arc::clone(&stopped);
            let stream = stream.map(move |process| {
                process.map(|inner| StoppedOnDestroy {
                    inner,
                    destroyed: destroyed.clone(),
                    stopped: Arc::clone(&stopped),
                })
            });
            bridge(channel_id, stream, r, w, e, client_lost).await
        }
        None => bridge(channel_id, stream, r, w, e, client_lost).await,
    };
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
    exit_status
}

/// Forwards the SSH channel's read half into the exec's stdin pipe and
/// reports when the client is gone.
///
/// `Data` is written to `stdin`. `Eof` closes `stdin` (the child sees
/// EOF) but keeps watching the channel: `min task run` from a terminal
/// half-closes stdin straight away, so a disconnect almost always
/// arrives *after* EOF and must still be seen. `Close`, or the end of
/// `msgs` (the channel's sender dropped with the connection), sets
/// `client_lost` to `true` and returns.
async fn pump_channel_input<M, W>(mut msgs: M, stdin: W, client_lost: watch::Sender<bool>)
where
    M: Stream<Item = russh::ChannelMsg> + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut stdin = Some(stdin);
    loop {
        match msgs.next().await {
            Some(russh::ChannelMsg::Data { data }) => {
                // A failed write means the pipe's read end is gone; drop
                // the data but keep watching for a disconnect.
                if let Some(w) = stdin.as_mut()
                    && w.write_all(&data).await.is_err()
                {
                    stdin = None;
                }
            }
            Some(russh::ChannelMsg::Eof) => stdin = None,
            Some(russh::ChannelMsg::Close) | None => {
                let _ = client_lost.send(true);
                return;
            }
            Some(_) => {}
        }
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
async fn bridge<S, P, R, W, E>(
    channel_id: impl Display + Clone,
    mut stream: S,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    mut client_lost: watch::Receiver<bool>,
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
        last_exit = bridge_one(
            channel_id.clone(),
            process,
            r,
            w,
            e,
            &mut stdin_open,
            &mut client_lost,
        )
        .await;
        // `changed()` fires once per transition, so a later step would
        // never see a disconnect an earlier step already consumed: a child
        // that exits 0 just as the client goes must still end the sequence.
        if last_exit != 0 || *client_lost.borrow() {
            break;
        }
    }
    last_exit
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
async fn bridge_one<P, R, W, E>(
    channel_id: impl Display,
    mut process: P,
    r: &mut R,
    w: &mut W,
    e: &mut E,
    stdin_open: &mut bool,
    client_lost: &mut watch::Receiver<bool>,
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
            read_res = r.read(&mut stdin_buf), if *stdin_open && child_stdin.is_some() && pending.is_none() => {
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
                        pending = Some((stdin_buf[..n].to_vec(), 0));
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
                    }
                    Err(err) => {
                        tracing::warn!(
                            %channel_id, error = %err,
                            "exec: failed to write stdin to child; closing child stdin",
                        );
                        child_stdin = None;
                        pending = None;
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
                } else if *client_lost.borrow() {
                    tracing::warn!(
                        %channel_id,
                        "exec: ssh client disconnected; killing child",
                    );
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
                lost = async { client_lost.wait_for(|lost| *lost).await.is_ok() } => {
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
const DRAIN_GRACE: Duration = Duration::from_millis(100);

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
async fn drain_ready<S, W>(
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
fn spawn_pipe_drain<O, E>(channel_id: String, stdout: Option<O>, stderr: Option<E>)
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

/// Handles a request to run a program on an SSH channel.
///
/// Looks up the target session via the `MINIMAL_SESSION_ID` env var the
/// client previously set on this channel, fetches its workspace, accepts the
/// request, and spawns an async task to take over the
/// channel for the lifetime of the conversation.
///
/// Accepted forms are:
///  * `git-receive-pack min://<session ID>` - handles a git receive-pack, routing
///    with the trailing session ID. Matched before the vocabulary below, and
///    not part of it: git speaks the pack protocol, not exec requests.
///  * `git-upload-pack min://<session ID>` - handles a git upload-pack, routing
///    with the trailing session ID the same way.
///  * a [`minimald_rpc::exec::ExecRequest`], which is where the rest of the
///    vocabulary is defined. The daemon-serviced forms — `min://task/run`,
///    `min://package/build` and `min://check` — are each routed via a
///    `MINIMAL_SESSION_ID` env var that must be set on the channel by the
///    client. `min://shell` and `min://argv` are handed to the session.
///  * anything else: a shell command for the session. Nothing about a
///    command's text routes it, so a session command can never be mistaken
///    for one of the daemon's own (gominimal/inbox#558).
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
    let conn_username = conn_lock.ssh_username.clone().unwrap_or_default();
    drop(conn_lock);

    if let Some(ident) = argv.strip_prefix("git-receive-pack min://") {
        return handle_git_receive(ident, serv, conn, id, session, channel, config).await;
    }

    if let Some(ident) = argv.strip_prefix("git-upload-pack min://") {
        return handle_git_upload(ident, serv, conn, id, session, channel, config).await;
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

    // The exec span (which adopts the client's TRACEPARENT) is opened before
    // the session lookup, so the manager's GetSession is a child of the
    // caller's trace instead of a root of its own.
    let (span, traceparent) = exec_span(&config, session_id, &argv);
    let trace_env = minimald_rpc::taskenv::trace_env(
        mlog::otel::exporting(),
        traceparent,
        minimald_rpc::trace::opted_out(&config.env_vars),
    );
    let mngr = serv.sessions_manager().await;
    let session_handle = match mngr
        .get_session(BoxKeyPredicate::Id(session_id))
        .instrument(span.clone())
        .await
    {
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

    // Logged for every accepted form, before the dispatch that decides which
    // one it is: an operator reading the log should see what a client asked to
    // run, whether it was serviced by the daemon, handed to the session, or
    // refused below. The command is scrubbed so a credential passed as an
    // argument never lands in the log verbatim. For a client that opted out
    // of telemetry the line says so and carries no command at all: the log
    // exporter would otherwise ship the one record of what it ran.
    if minimald_rpc::trace::opted_out(&config.env_vars) {
        tracing::info!(%session_id, telemetry = OPT_OUT, "exec request (command not recorded)");
    } else {
        tracing::info!(%session_id, command = %scrub_secrets(&argv), "exec request");
    }

    // Parsed, never sniffed. The vocabulary in `minimald_rpc::exec` is the only
    // way to ask for one of the daemon's own forms, so a session command can no
    // longer be mistaken for one — `min --version` names the session's `min`
    // and reaches it, where the old `strip_prefix("min ")` claimed and refused
    // it (gominimal/inbox#558).
    let request = match minimald_rpc::exec::ExecRequest::parse(&argv) {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!(%session_id, error = %e, "execution request rejected");
            // Accept-then-report, as the bad-flag path does: a bare
            // `channel_failure` would reach the client as an opaque "exec
            // request failed" with none of the detail the error carries.
            session.channel_success(id)?;
            spawn(async move {
                reject_unsupported_exec(channel, e.to_string()).await;
            });
            return Ok(());
        }
    };

    use minimald_rpc::exec::ExecRequest;
    match request {
        ExecRequest::Shell(_) | ExecRequest::Argv(_) => {
            let program = match request {
                ExecRequest::Shell(cmd) => BoxProgram::Shell(cmd),
                ExecRequest::Argv(words) => BoxProgram::Argv(words),
                _ => unreachable!("the match arm admits only Shell and Argv"),
            };
            let span = span.clone();
            session.channel_success(id)?;
            spawn(
                run_in_session(
                    serv,
                    conn,
                    session_handle,
                    id,
                    channel,
                    program,
                    conn_username,
                    trace_env,
                )
                .instrument(span),
            );
        }
        ExecRequest::TaskRun {
            task,
            owns_box,
            args,
            cwd,
        } => {
            let task = task.trim().to_string();
            if task.is_empty() {
                tracing::warn!(%session_id, "execution request rejected: task/run names no task");
                session.channel_failure(id)?;
                return Ok(());
            }
            // A task's `env_vars`, resolved by the client against the invoking
            // shell and carried on the channel environment (#585). Empty from a
            // client that predates it — in which case the task path resolves
            // them the old way, daemon-side.
            // Plus the exec span's TRACEPARENT on opt-in (TEL-023):
            // a `min` the task runs joins the caller's trace.
            let task_env = minimald_rpc::taskenv::with_trace(
                minimald_rpc::taskenv::from_channel_env(&config.env_vars),
                trace_env.clone(),
            );
            let drop_env = minimald_rpc::taskenv::drops_from_channel_env(&config.env_vars);
            let span = span.clone();
            session.channel_success(id)?;
            spawn(tracing::Instrument::instrument(
                async move {
                    // `ExecTask::run` consumes the server handle; the box's end
                    // needs one after the bridge returns.
                    let end_serv = serv.clone();
                    let exec_task = ExecTask {
                        conn,
                        serv,
                        session: session_handle,
                        channel_id: id,
                        exec: TaskExec {
                            args,
                            // The name stays behind for the run-box-end log line.
                            task: task.clone(),
                            env: task_env,
                            drop_env,
                            cwd,
                        },
                    };
                    let exit_status = exec_task.run(channel).await;
                    // The exit status is on the wire and the channel closed: the
                    // run is over whether or not its client is still here, so a
                    // box created for it ends now (NET-131).
                    if owns_box {
                        end_run_box(&end_serv, session_id, &task, exit_status).await;
                    }
                },
                span,
            ));
        }
        ExecRequest::PackageBuild(args) => {
            let span = span.clone();
            session.channel_success(id)?;
            let build_args = args.trim().to_string();
            spawn(tracing::Instrument::instrument(
                async move {
                    run_build_exec(session_handle, id, channel, build_args).await;
                },
                span,
            ));
        }
        ExecRequest::Check(args) => {
            session.channel_success(id)?;
            let check_args = args.trim().to_string();
            spawn(tracing::Instrument::instrument(
                async move {
                    run_check_exec(session_handle, id, channel, check_args).await;
                },
                span,
            ));
        }
    }

    Ok(())
}

/// Accepts the channel and reports an exec request the daemon cannot serve on
/// the SSH stderr stream, then exits non-zero. A bare `channel_failure` would
/// reach the client only as an opaque "exec request failed", so — mirroring the
/// accept-then-report shape `run_check_exec` uses for a bad flag — this relays
/// the parse error, which already names the form asked for and lists the ones
/// this daemon serves. The command is still refused; nothing is spawned.
async fn reject_unsupported_exec(channel: Channel<Msg>, reason: String) {
    let (_rs, ws) = channel.split();
    let mut e = ws.make_writer_ext(Some(1));
    let _ = e
        .write_all(unsupported_command_message(&reason).as_bytes())
        .await;
    let _ = e.flush().await;
    let _ = ws.eof().await;
    let _ = ws.exit_status(1).await; // otherwise considered -1
    let _ = ws.close().await; // needed to release the remote
}

/// The stderr copy for an exec request the daemon cannot serve. The reason
/// comes from [`minimald_rpc::exec::ExecParseError`], which already names the
/// form that was asked for and the ones this daemon serves.
fn unsupported_command_message(reason: &str) -> String {
    format!("minimald: {reason}\n")
}

/// The tracing span an in-session exec runs under, mirroring the `rpc` span in
/// [`crate::rpc::handle_ssh_rpc`].
///
/// The client's propagated trace context is adopted — same trace id, fresh span
/// id, the client's span as parent — so one `trace_id` grep joins the CLI's log
/// with the daemon's. A missing or malformed value mints a fresh context:
/// propagation is a diagnostic aid and must never fail a request. The command
/// rides on the span, so every record the exec emits names what was asked for.
/// The exec span, and its context as a `TRACEPARENT` (what a box gets on
/// opt-in, so a `min` run inside joins this trace) — `None` unless the span
/// is actually recorded (see [`box_traceparent`]).
fn exec_span(
    config: &ChannelConfig,
    session_id: SessionId,
    argv: &str,
) -> (tracing::Span, Option<String>) {
    // Two callsites, not one span with a recorded field: the opted-out
    // request's span never carries the command, not even in the file log's
    // span fields, and the recorded one is what the exec-span tests read
    // at creation.
    let span = if minimald_rpc::trace::opted_out(&config.env_vars) {
        tracing::info_span!(
            "exec",
            %session_id,
            command = tracing::field::Empty,
            telemetry = OPT_OUT,
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            parent_span_id = tracing::field::Empty,
        )
    } else {
        tracing::info_span!(
            "exec",
            %session_id,
            command = %scrub_secrets(argv),
            telemetry = tracing::field::Empty,
            trace_id = tracing::field::Empty,
            span_id = tracing::field::Empty,
            parent_span_id = tracing::field::Empty,
        )
    };
    let adopted = adopt_client_trace(&span, config);
    let tp = box_traceparent(&adopted);
    (span, tp)
}

/// The value of a request span's `telemetry` field when its client opted
/// out: the one mark the file log keeps of such a request (the span is
/// recorded nowhere else).
pub(crate) const OPT_OUT: &str = "opt-out";

/// A span's trace context, and whether that span is recorded by the export
/// (its ids are the exported span's ids).
pub(crate) struct AdoptedTrace {
    ctx: minimald_rpc::trace::TraceContext,
    /// False with export off, and with the export filter not admitting the
    /// span (`MINIMAL_OTEL_FILTER=warn` against an info-level span): the ids
    /// were minted for the file log only, and no exporter or spool ever sees
    /// a span with them.
    recorded: bool,
}

/// The `TRACEPARENT` a box may be given for `adopted`: only one that names a
/// recorded span. Under `MINIMAL_OTEL_FILTER=warn`
/// the daemon handed the box a `TRACEPARENT` whose span id was spooled and
/// exported nowhere, so a `min` run inside parented itself to an orphan. A
/// trace nobody can follow is worse than a fresh one: hand the box nothing.
fn box_traceparent(adopted: &AdoptedTrace) -> Option<String> {
    adopted.recorded.then(|| adopted.ctx.traceparent())
}

/// Makes `span` a child of the client's `TRACEPARENT` (channel env) and
/// records its ids. With OTel export on and the span admitted, the exported
/// span's ids are the ids; otherwise adopt-or-mint exactly as before. The
/// span must declare the `trace_id`, `span_id` and `parent_span_id` fields.
pub(crate) fn adopt_client_trace(span: &tracing::Span, config: &ChannelConfig) -> AdoptedTrace {
    use minimald_rpc::trace::{TRACEPARENT_ENV, TraceContext};

    if minimald_rpc::trace::opted_out(&config.env_vars) {
        return adopt_opt_out(span);
    }
    let client_ctx = config
        .env_vars
        .get(TRACEPARENT_ENV)
        .and_then(|v| TraceContext::parse_traceparent(v));
    adopt_trace(span, client_ctx)
}

/// The client opted out of telemetry (`MINIMAL_OTEL=off` on the channel,
/// or in a forward's originator field): make `span`, and every span under
/// it, non-recording ([`mlog::otel::opt_out`]), mark it `telemetry =
/// opt-out`, and give it ids for the file log only. Nothing is adopted: an
/// opted-out client sends no `TRACEPARENT`, and one that did would still
/// get no span in its trace. The result is never `recorded`, so the box
/// gets no `TRACEPARENT` either ([`box_traceparent`]). The span must
/// declare the `trace_id`, `span_id`, `parent_span_id` and `telemetry`
/// fields.
pub(crate) fn adopt_opt_out(span: &tracing::Span) -> AdoptedTrace {
    use minimald_rpc::trace::TraceContext;

    // `record` drops a field the span did not declare without a word, and
    // the opt-out mark would be lost (the `git_receive`/`git_upload` spans
    // once lacked it): fail loudly in tests instead.
    debug_assert!(
        span.metadata()
            .is_none_or(|m| m.fields().field("telemetry").is_some()),
        "span {:?} must declare `telemetry` to be opted out",
        span.metadata().map(tracing::Metadata::name)
    );
    let ctx = mlog::otel::opt_out(span)
        .map(|(t, s, f)| TraceContext::from_parts(t, s, f))
        .unwrap_or_else(|| TraceContext::mint().unsampled());
    span.record("telemetry", OPT_OUT);
    span.record("trace_id", tracing::field::display(ctx.trace_id_hex()));
    span.record("span_id", tracing::field::display(ctx.span_id_hex()));
    // The mailbox messages sent from inside carry these unsampled ids, so
    // the `*.message` spans they open are opted out too (`adopt_trace`
    // aligns them under a flags-00 parent).
    crate::traced::remember(span, ctx);
    AdoptedTrace {
        ctx,
        recorded: false,
    }
}

/// Makes `span` a child of `client_ctx` — the client's context however it
/// travelled (the channel env for session channels and RPCs, the open
/// request's originator field for a direct-tcpip forward) — and records its
/// ids. With OTel export on and the span admitted, the exported span's ids
/// are the ids; otherwise adopt-or-mint exactly as before. The span must
/// declare the `trace_id`, `span_id` and `parent_span_id` fields.
pub(crate) fn adopt_trace(
    span: &tracing::Span,
    client_ctx: Option<minimald_rpc::trace::TraceContext>,
) -> AdoptedTrace {
    use minimald_rpc::trace::TraceContext;

    let aligned = mlog::otel::align(span, client_ctx.as_ref().map(TraceContext::parts))
        .map(|(t, s, f)| TraceContext::from_parts(t, s, f));
    let recorded = aligned.is_some();
    let ctx = aligned.unwrap_or_else(|| {
        client_ctx
            .as_ref()
            .map(TraceContext::child)
            .unwrap_or_else(TraceContext::mint)
    });
    span.record("trace_id", tracing::field::display(ctx.trace_id_hex()));
    span.record("span_id", tracing::field::display(ctx.span_id_hex()));
    if let Some(client_ctx) = &client_ctx {
        span.record(
            "parent_span_id",
            tracing::field::display(client_ctx.span_id_hex()),
        );
    }
    // For a mailbox message sent from inside this span (or anything it
    // encloses) to carry these ids: see `traced::caller_context`.
    crate::traced::remember(span, ctx);
    AdoptedTrace { ctx, recorded }
}

#[cfg(test)]
mod box_traceparent_tests {
    use super::{AdoptedTrace, box_traceparent};

    /// A box gets a `TRACEPARENT` only for a recorded span: with export off,
    /// or the export filter not admitting the exec span, the context exists
    /// (the file log uses it) but names a span no exporter or spool sees.
    #[test]
    fn an_unrecorded_exec_span_gives_the_box_no_traceparent() {
        let ctx = minimald_rpc::trace::TraceContext::mint();
        assert_eq!(
            box_traceparent(&AdoptedTrace {
                ctx,
                recorded: false
            }),
            None
        );
        assert_eq!(
            box_traceparent(&AdoptedTrace {
                ctx,
                recorded: true
            }),
            Some(ctx.traceparent())
        );
    }

    /// Without an exporter installed (this test process), `align` admits
    /// nothing, so the adopted trace is never marked recorded.
    #[test]
    fn without_an_exporter_nothing_is_recorded() {
        assert!(!mlog::otel::exporting());
        let span = tracing::info_span!("exec");
        assert!(mlog::otel::align(&span, None).is_none());
    }
}

/// Runs `argv` inside the session's sandbox, streamed over the SSH channel.
///
/// The fallback for every exec request the daemon does not service itself. It
/// needs the session's sandbox up, which [`BoxExec`] arranges — launching a
/// host for an idle session if there isn't one.
// Left positional: a single call site that immediately packs the arguments into
// an `ExecTask`, so a struct would be single-use ceremony.
#[allow(clippy::too_many_arguments)]
async fn run_in_session(
    serv: ServerStateHandle,
    conn: ConnectionHandle,
    session: BoxHandle,
    channel_id: ChannelId,
    channel: Channel<Msg>,
    program: BoxProgram,
    conn_username: String,
    extra_env: BTreeMap<String, String>,
) {
    let exec_task = ExecTask {
        conn,
        serv,
        session,
        channel_id,
        exec: BoxExec {
            program,
            conn_username,
            extra_env,
        },
    };
    exec_task.run(channel).await;
}

/// Ends the box a task run owns, from the daemon's side of the exec's exit
/// (NET-131). The destroy used to be the client's, issued after a normal
/// run; left there, a client killed mid-run would strand its session — the
/// abandoned-launch reap covers only un-finalized sessions and there is no
/// idle stop to catch one. The teardown is the `DestroySession` RPC's own
/// path, so the box ends exactly as a client-issued destroy ends it.
///
/// The one info line this emits on success is what a diagnostic bundle's
/// daemon-log tail reads the end of a run box from: it names the session,
/// the run and the exit code.
async fn end_run_box(
    serv: &ServerStateHandle,
    session_id: SessionId,
    task: &str,
    exit_status: u32,
) {
    let mngr = serv.sessions_manager().await;
    // The name for the log line, resolved before the delete for the same
    // reason `serve_destroy_session` resolves it there: once the record is
    // gone there is nothing left to resolve it against.
    let session_name = mngr
        .get_record(BoxKeyPredicate::Id(session_id))
        .await
        .ok()
        .flatten()
        .and_then(|record| record.name);
    match mngr.delete_session(session_id).await {
        Ok(_) => tracing::info!(
            session_id = %session_id,
            session_name = session_name.as_deref().unwrap_or("<anonymous>"),
            task = %task,
            exit = exit_status,
            "run box ended",
        ),
        // Most plausibly the interrupt path's own destroy won the race; the
        // error names what actually blocked the teardown.
        Err(e) => tracing::warn!(
            session_id = %session_id,
            task = %task,
            exit = exit_status,
            error = %e,
            "ending the run's box failed",
        ),
    }
}

/// Streams a `min package build [--verbose] [--rebuild] [pkgs...]` exec over the SSH
/// channel. Kicks off a session side-op build based on an existing session.
async fn run_build_exec(
    session: BoxHandle,
    channel_id: ChannelId,
    channel: Channel<Msg>,
    args: String,
) {
    use orchestrator::{BuildLineKind, BuildRenderer};

    let mut verbose = false;
    let mut rebuild = false;
    let mut pkgs: Vec<String> = Vec::new();
    for token in args.split_whitespace() {
        match token {
            "--verbose" => verbose = true,
            "--rebuild" => rebuild = true,
            _ => pkgs.push(token.to_string()),
        }
    }

    // Same channel-half handling as `ExecTask::run`: stdout on the data
    // stream, stderr on SSH extended-data type 1.
    let (_rs, ws) = channel.split();
    let mut w = ws.make_writer();
    let mut e = ws.make_writer_ext(Some(1));

    let exit_status = match session.start_build(rebuild, pkgs).await {
        Ok(mut events) => {
            use crate::box_ops::{BuildOutcome, BuildUpdate};
            let mut renderer = BuildRenderer::new(verbose);
            let mut outcome = None;
            while let Some(update) = events.recv().await {
                let event = match update {
                    BuildUpdate::Event(event) => event,
                    BuildUpdate::Finished(o) => {
                        outcome = Some(o);
                        continue;
                    }
                };
                let Some(line) = renderer.render(event) else {
                    continue;
                };
                let out: &mut (dyn AsyncWrite + Unpin + Send) = match line.kind {
                    BuildLineKind::Stderr => &mut e,
                    BuildLineKind::Status => &mut w,
                };
                if let Err(err) = out.write_all(format!("{}\n", line.text).as_bytes()).await {
                    // No reader on the channel — the client went away. Stop
                    // streaming; the side-op keeps running independently.
                    tracing::warn!(%channel_id, error = %err, "min package build: channel write failed");
                    break;
                }
            }
            // Map the propagated outcome to an exit code, reporting a
            // failure/cancellation on the SSH stderr stream. Only success
            // exits 0.
            match outcome {
                Some(BuildOutcome::Success) => 0,
                Some(BuildOutcome::Failed(msg)) => {
                    let _ = e
                        .write_all(format!("build failed: {msg}\n").as_bytes())
                        .await;
                    1
                }
                Some(BuildOutcome::Cancelled) => {
                    let _ = e.write_all(b"build cancelled\n").await;
                    130
                }
                None => {
                    let _ = e
                        .write_all(b"build ended without reporting an outcome\n")
                        .await;
                    1
                }
            }
        }
        Err(err) => {
            let _ = e
                .write_all(format!("minimald: failed to start build: {err}\n").as_bytes())
                .await;
            1
        }
    };

    let _ = w.flush().await;
    let _ = e.flush().await;
    let _ = ws.eof().await;
    let _ = ws.exit_status(exit_status).await; // otherwise considered -1
    let _ = ws.close().await; // needed to release the remote
}

/// Streams a `min check [--packages] [--profiles] [--stacks] [--fix] [names...]`
/// exec over the SSH channel. Kicks off a session side-op check run based on an
/// existing session.
async fn run_check_exec(
    session: BoxHandle,
    channel_id: ChannelId,
    channel: Channel<Msg>,
    args: String,
) {
    use crate::box_ops::{CheckOpts, CheckOutcome, CheckUpdate};

    let (_rs, ws) = channel.split();
    let mut w = ws.make_writer();
    let mut e = ws.make_writer_ext(Some(1));

    // A bad flag is reported here rather than refused at the request layer:
    // a `channel_failure` would only tell the client "rejected", where this
    // path gets the message across and still exits non-zero.
    let opts = match CheckOpts::from_args(&args) {
        Ok(opts) => opts,
        Err(msg) => {
            let _ = e.write_all(format!("minimald: {msg}\n").as_bytes()).await;
            let _ = e.flush().await;
            let _ = ws.eof().await;
            let _ = ws.exit_status(1).await;
            let _ = ws.close().await;
            return;
        }
    };

    let exit_status = match session.start_check(opts).await {
        Ok(mut updates) => {
            let mut outcome = None;
            'drain: while let Some(update) = updates.recv().await {
                if let CheckUpdate::Finished(o) = &update {
                    outcome = Some(o.clone());
                }
                for line in update.render() {
                    if let Err(err) = w.write_all(format!("{line}\n").as_bytes()).await {
                        // No reader on the channel — the client went away. Stop
                        // streaming; the side-op keeps running independently.
                        tracing::warn!(%channel_id, error = %err, "min check: channel write failed");
                        break 'drain;
                    }
                }
            }

            // Only a clean run exits 0; everything else reports on stderr.
            let (status, message) = CheckOutcome::summarize(outcome.as_ref());
            let out: &mut (dyn AsyncWrite + Unpin + Send) = match status {
                0 => &mut w,
                _ => &mut e,
            };
            let _ = out.write_all(format!("{message}\n").as_bytes()).await;
            status
        }
        Err(err) => {
            let _ = e
                .write_all(format!("minimald: failed to start check: {err}\n").as_bytes())
                .await;
            1
        }
    };

    let _ = w.flush().await;
    let _ = e.flush().await;
    let _ = ws.eof().await;
    let _ = ws.exit_status(exit_status).await; // otherwise considered -1
    let _ = ws.close().await; // needed to release the remote
}

/// Serves `git-receive-pack min://<session>` (a `min` push to a session's
/// workspace) on channel `id`.
///
/// Runs in a `git_receive` span that adopts the client's `TRACEPARENT`: the
/// session lookup and the spawned receive-pack process's work are its
/// children, so a push is one trace with the CLI's (TEL-022).
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
                Ok(id) => BoxKeyPredicate::Id(id),
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
                Ok(id) => BoxKeyPredicate::Id(id),
                Err(_e) => BoxKeyPredicate::Name(ident.to_string()),
            },
        }
    };

    // The lookup runs in this push's span, so its manager message is not a
    // trace root of its own (as for an exec: see `handle_exec`).
    let span = tracing::info_span!(
        "git_receive",
        telemetry = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
    );
    adopt_client_trace(&span, &config);
    let mngr = serv.sessions_manager().await;
    let session_handle = match mngr
        .get_session(session_pred)
        .instrument(span.clone())
        .await
    {
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

    // The receive-pack process ends with this channel: request-bounded work,
    // so it runs as the span's child (`traced::spawn` carries the entered
    // span), not as a root of its own.
    let task = async move {
        let paths = match session_handle.paths().await {
            Ok(paths) => paths,
            // The actor died between resolve and this call (raced an
            // abort/destroy); the channel was already acked, so just drop it.
            Err(e) => {
                tracing::warn!(error = %e, "git-receive-pack aborted: session is gone");
                return;
            }
        };

        let dotgit_dir = paths.working.as_utf8_path().join(".git");
        if let Ok(false) = tokio::fs::try_exists(&dotgit_dir).await {
            // No .git directory exists, so this is likely
            // the first push to populate. Create an empty git
            // repo, and make sure its configured to checkout
            // the ref it recieves.
            let mut init = tokio::process::Command::new("git");
            init.arg("init").current_dir(paths.working.as_utf8_path());
            for name in git_repo_location_env() {
                init.env_remove(name);
            }
            let res = init.output().await;
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
                # The branch currently checked out in the worktree, and
                # whether HEAD resolves to a commit (`born`). The first push
                # into a fresh workspace has no commit on HEAD, so the first
                # pushed branch that checks out cleanly populates the
                # worktree and becomes HEAD. After that, a push to any branch
                # other than the checked-out one must not move HEAD or touch
                # the worktree. post-receive runs after the refs moved, so a
                # first push that includes HEAD's own branch already reads as
                # born, and that branch is the one checked out.
                cur=$(g symbolic-ref -q HEAD)
                born=
                detached_moved=
                g rev-parse -q --verify HEAD >/dev/null && born=yes

                zero=0000000000000000000000000000000000000000
                while read -r old new ref; do
                    case "$ref" in refs/heads/*) ;; *) continue ;; esac
                    # A deleted branch (new = zeros) has nothing to check out.
                    # Deleting the CURRENT branch never reaches here: git's own
                    # receive.denyDeleteCurrent refuses it during receive-pack.
                    [ "$new" = "$zero" ] && continue
                    branch=${ref#refs/heads/}

                    # A push to a branch that is not the one checked out
                    # leaves HEAD and the worktree alone: the ref itself has
                    # already moved in receive-pack, so there is nothing more
                    # to do. Only on the still-unborn first push does the
                    # hook check out the first arriving branch.
                    # A detached HEAD (`cur` empty) matches no branch, so
                    # every push lands here; note it for the message below.
                    if [ "$ref" != "$cur" ] && [ -n "$born" ]; then
                        [ -z "$cur" ] && detached_moved=yes
                        continue
                    fi

                    if [ "$old" = "$zero" ]; then
                        # Previously-unborn branch: nothing tracked, so tracked
                        # dirtiness cannot exist — but uploaded/untracked files
                        # may collide with the pushed tree, and -f would
                        # silently clobber them. -B pins the branch at the
                        # pushed tip and checks it out; WITHOUT -f, git refuses
                        # to overwrite untracked files (its stderr names them),
                        # and we surface the skip like the dirty case below.
                        if g checkout -q -B "$branch" "$new"; then
                            # HEAD is born now: later refs in this same push
                            # are other branches and must not move it.
                            cur=$ref
                            born=yes
                        else
                            echo "remote worktree has local files the push would overwrite; skipping checkout of $branch" >&2
                        fi
                        continue
                    fi

                    # Dirtiness is measured against the PRE-push tip ($old):
                    # post-receive runs after the ref has already moved, so a
                    # plain `diff --cached` (index vs the NEW tip) would flag
                    # the pushed delta itself and skip every checkout.
                    if ! g diff --quiet "$old" || ! g diff --cached --quiet "$old"; then
                        echo "remote worktree has uncommitted changes; skipping checkout of $branch" >&2
                        continue
                    fi
                    g checkout -qf "$branch"
                done

                # A detached HEAD stays detached, as with plain git; say so
                # once, so the pusher knows the worktree did not change.
                if [ -n "$detached_moved" ]; then
                    echo "remote worktree HEAD is detached; moved refs without checking out (run git switch <branch> in the session)" >&2
                fi"#
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
                // receive.denyCurrentBranch=ignore: the workspace is a
                // non-bare repo with the pushed branch typically checked
                // out, and stock git refuses that ref update outright —
                // before any hook runs. `ignore` accepts it silently; the
                // post-receive hook above then syncs the worktree (or
                // warns and skips when it is dirty). NOT `updateInstead`:
                // that rejects the whole push on a dirty worktree, while
                // the hook's contract is "ref lands, checkout best-effort".
                argv: format!(
                    "git -c core.hooksPath={} -c receive.denyCurrentBranch=ignore receive-pack .",
                    hooks_tmp.path().to_str().unwrap()
                ),
                cwd: paths.working,
                env: BTreeMap::new(),
                drop_env: git_repo_location_env(),
            },
        };
        exec_task.run(channel).await;
        drop(hooks_tmp);
    };
    span.in_scope(|| crate::traced::spawn(task));

    Ok(())
}

/// Serves `git-upload-pack min://<session>` (a `min` fetch, clone or
/// ls-remote of a session's workspace) on channel `id`.
///
/// Runs in a `git_upload` span that adopts the client's `TRACEPARENT`, as a
/// push runs in `git_receive`: the session lookup and the spawned pack
/// process's work are its children, so a fetch is one trace with the CLI's
/// (TEL-022) rather than a root `GetSession` of its own.
async fn handle_git_upload(
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
                Ok(id) => BoxKeyPredicate::Id(id),
                Err(_e) => {
                    tracing::warn!(
                        value = %id_str,
                        "git-upload-pack rejected on channel {id}: {MINIMAL_SESSION_ID_ENV} is not a uuid",
                    );
                    session.channel_failure(id)?;
                    return Ok(());
                }
            },
            None => match SessionId::parse_str(ident) {
                Ok(id) => BoxKeyPredicate::Id(id),
                Err(_e) => BoxKeyPredicate::Name(ident.to_string()),
            },
        }
    };

    // The lookup runs in this fetch's span, so its manager message is not a
    // trace root of its own (as for a push: see `handle_git_receive`).
    let span = tracing::info_span!(
        "git_upload",
        telemetry = tracing::field::Empty,
        trace_id = tracing::field::Empty,
        span_id = tracing::field::Empty,
        parent_span_id = tracing::field::Empty,
    );
    adopt_client_trace(&span, &config);
    let mngr = serv.sessions_manager().await;
    let lookup = mngr
        .get_session(session_pred)
        .instrument(span.clone())
        .await;
    let session_handle = match lookup {
        Ok(Some(h)) => h,
        Ok(None) => {
            span.in_scope(|| tracing::warn!("git-upload-pack rejected: unknown session"));
            session.channel_failure(id)?;
            return Ok(());
        }
        Err(e) => {
            span.in_scope(|| tracing::warn!(error = %e, "git-upload-pack rejected: lookup failed"));
            session.channel_failure(id)?;
            return Ok(());
        }
    };
    session.channel_success(id)?;

    // The pack process ends with this channel: request-bounded work, so it
    // runs as the span's child (`traced::spawn` carries the entered span).
    let task = async move {
        let paths = match session_handle.paths().await {
            Ok(paths) => paths,
            Err(e) => {
                tracing::warn!(error = %e, "git-upload-pack aborted: session is gone");
                let _ = channel.close().await;
                return;
            }
        };

        let dotgit_dir = paths.working.as_utf8_path().join(".git");
        if let Ok(false) = tokio::fs::try_exists(&dotgit_dir).await {
            // A read-only request (ls-remote, fetch, clone) must not create
            // a repository in the session workspace: `git init` would write
            // a `.git` directory as the daemon user on an operation the
            // client believes is read-only, and would turn an
            // uploaded/generated workspace into a repo with an unborn
            // branch. Reject instead of initializing.
            let msg = "minimald: session has no repository yet\n";
            tracing::warn!("git-upload-pack rejected: session has no repository");
            let _ = channel.extended_data(1, msg.as_bytes()).await;
            let _ = channel.exit_status(1).await;
            let _ = channel.eof().await;
            let _ = channel.close().await;
            return;
        }

        let exec_task = ExecTask {
            conn,
            serv,
            session: session_handle,
            channel_id: id,
            exec: TokioExec {
                argv: "git upload-pack .".to_string(),
                cwd: paths.working,
                env: BTreeMap::new(),
                drop_env: git_repo_location_env(),
            },
        };
        exec_task.run(channel).await;
    };
    span.in_scope(|| crate::traced::spawn(task));

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
        exit_on_kill: Mutex<Option<i32>>,
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

        /// Set the code the mock process reports once `start_kill` is
        /// called. Without it a killed mock reports no numeric code.
        pub async fn exit_on_kill(&self, code: i32) {
            *self.inner.exit_on_kill.lock().await = Some(code);
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
                    return Ok(*self.ctrl.inner.exit_on_kill.lock().await);
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
#[expect(
    clippy::disallowed_methods,
    reason = "upstream's tests spawn plain tokio tasks; the traced-spawn rule is for request handling"
)]
mod tests;

/// The exec channel's spans (OTel TEL-021, TEL-022, TEL-043): the client's
/// `TRACEPARENT` reaches the `exec` and `git_*` spans, and the session
/// lookup those channels make runs inside them. Export is off here, so the
/// ids are the ones `adopt_trace` records for the file log; with export on
/// they are the exported ids (the same code path, see `adopt_trace`).
#[cfg(test)]
mod trace_tests {
    use crate::test_harness::{ExecRejected, SpanLog, TestServer};
    use tracing_subscriber::layer::SubscriberExt as _;

    const TRACE: &str = "0af7651916cd43dd8448eb211c80319c";
    const PARENT: &str = "b7ad6b7169203331";
    /// A session id no fresh server knows.
    const UNKNOWN: &str = "6f1c1f9e-5a1b-4c2d-8e3f-000000000001";

    fn traceparent() -> String {
        format!("00-{TRACE}-{PARENT}-01")
    }

    /// `command` on `argv`'s channel of a fresh server, with the client's
    /// `TRACEPARENT` and `MINIMAL_SESSION_ID` naming no session: the request
    /// is refused after the lookup. Returns what the spans looked like.
    async fn exec_unknown_session(command: &str) -> SpanLog {
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session = UNKNOWN.to_owned();
        let tp = traceparent();
        let env = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::TRACEPARENT_ENV, tp.as_str()),
        ];
        let outcome = client.exec(&env, false, command, b"").await;
        assert_eq!(outcome.err(), Some(ExecRejected), "an unknown session");
        log
    }

    /// `verb min://<session>` on a channel of a fresh server's configured
    /// session, with the client's `TRACEPARENT`: the lookup succeeds and the
    /// pack task runs (to whatever end; its outcome is not the point).
    /// Returns what the spans looked like.
    async fn exec_known_session(verb: &str) -> SpanLog {
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session =
            crate::test_harness::create_configured_session(&mut client, "git-trace", "/tmp")
                .await
                .to_string();
        let tp = traceparent();
        let env = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::TRACEPARENT_ENV, tp.as_str()),
        ];
        let command = format!("{verb} min://{session}");
        let run = client.exec(&env, false, &command, b"");
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(60), run)
            .await
            .expect("the pack task ends with its channel");
        assert!(outcome.is_ok(), "a known session is accepted");
        log
    }

    /// The span `name`, in the client's trace, is the parent of the pack
    /// task's `GetPaths` session message: the task runs in it.
    fn assert_task_in(log: &SpanLog, name: &str) {
        let span = log.one(name, "trace_id", TRACE);
        let paths: Vec<_> = log
            .find("session.message", "kind", "GetPaths")
            .into_iter()
            .filter(|m| m.field("trace_id") == Some(TRACE))
            .collect();
        assert_eq!(
            paths.len(),
            1,
            "one GetPaths in the client's trace: {paths:#?}"
        );
        assert_eq!(
            paths[0].field("parent_span_id"),
            span.field("span_id"),
            "the pack task runs in {name}: {paths:?}"
        );
    }

    /// The span `name` is the client's span's child, and the manager's
    /// `GetSession` message (the session lookup) is that span's child, all
    /// in the client's trace.
    fn assert_lookup_in(log: &SpanLog, name: &str) -> crate::test_harness::LoggedSpan {
        let span = log.one(name, "trace_id", TRACE);
        assert_eq!(span.field("parent_span_id"), Some(PARENT), "{span:?}");
        let lookup = log.one("sessions.manager.message", "kind", "GetSession");
        assert_eq!(lookup.field("trace_id"), Some(TRACE), "{lookup:?}");
        assert_eq!(
            lookup.field("parent_span_id"),
            span.field("span_id"),
            "the lookup is a child of {name}: {lookup:?}"
        );
        span
    }

    /// TEL-021, TEL-022: an exec adopts the client's `TRACEPARENT`,
    /// and its session lookup is a child of the exec span. TEL-043: the command
    /// line on the span is scrubbed of secrets.
    #[tokio::test]
    async fn an_exec_session_lookup_runs_in_the_exec_span() {
        let log =
            exec_unknown_session("curl -H 'Authorization: Bearer abc123def456' https://x/").await;
        let exec = assert_lookup_in(&log, "exec");
        let command = exec.field("command").unwrap_or_default();
        assert!(!command.contains("abc123def456"), "{command}");
        assert!(
            command.contains("Authorization: Bearer <redacted"),
            "{command}"
        );
    }

    /// An exec whose client opted out of telemetry
    /// (`MINIMAL_OTEL=off` on the channel, no `TRACEPARENT`) leaves no
    /// span in the daemon's export: a tracer under the daemon's subscriber
    /// sees nothing of it or of what ran in it, while the same exec from a
    /// client that did not opt out exports its `exec` span. The file log
    /// still has the span, marked `telemetry=opt-out`, with unsampled ids
    /// its session lookup shares, and no command line.
    ///
    /// The lookup's own `sessions.manager.message` span is a root that
    /// adopts the request's ids through `mlog::otel::align`, which asks the
    /// process-wide tracer and so cannot be driven by this test's; the
    /// flags-00 ids it adopts are the mechanism TEL-024 proves.
    #[tokio::test]
    async fn an_opted_out_request_leaves_no_daemon_span() {
        use opentelemetry::trace::TracerProvider as _;
        use opentelemetry_sdk::trace::{InMemorySpanExporter, SdkTracerProvider};

        let exporter = InMemorySpanExporter::default();
        let provider = SdkTracerProvider::builder()
            .with_simple_exporter(exporter.clone())
            .build();
        let log = SpanLog::default();
        let _g = tracing::subscriber::set_default(
            tracing_subscriber::registry()
                .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("t")))
                .with(log.clone()),
        );
        let exported = || -> Vec<(String, String)> {
            exporter
                .get_finished_spans()
                .unwrap()
                .iter()
                .map(|s| (s.name.to_string(), s.span_context.trace_id().to_string()))
                .collect()
        };
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session = UNKNOWN.to_owned();
        let command = "curl -H 'Authorization: Bearer abc123def456' https://x/";

        let off = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::OTEL_ENV, minimald_rpc::trace::OTEL_OFF),
        ];
        let outcome = client.exec(&off, false, command, b"").await;
        assert_eq!(outcome.err(), Some(ExecRejected), "an unknown session");
        let exec = log.one("exec", "telemetry", super::OPT_OUT);
        assert_eq!(exec.field("command"), None, "no command line: {exec:?}");
        assert_eq!(exec.field("parent_span_id"), None, "{exec:?}");
        let trace_id = exec
            .field("trace_id")
            .expect("ids for the file log")
            .to_owned();
        let lookup = log.one("sessions.manager.message", "kind", "GetSession");
        assert_eq!(
            lookup.field("trace_id"),
            Some(trace_id.as_str()),
            "the lookup joins the request in the file log: {lookup:?}"
        );
        let sent = exporter
            .get_finished_spans()
            .unwrap()
            .iter()
            .filter(|s| s.name == "exec" || s.span_context.trace_id().to_string() == trace_id)
            .count();
        assert_eq!(
            sent,
            0,
            "nothing of the request was exported: {:?}",
            exported()
        );

        let tp = traceparent();
        let on = [
            (crate::MINIMAL_SESSION_ID_ENV, session.as_str()),
            (minimald_rpc::trace::TRACEPARENT_ENV, tp.as_str()),
        ];
        let outcome = client.exec(&on, false, command, b"").await;
        assert_eq!(outcome.err(), Some(ExecRejected), "an unknown session");
        assert!(
            exported().iter().any(|(name, _)| name == "exec"),
            "a client that did not opt out is exported: {:?}",
            exported()
        );
        assert!(
            log.one("exec", "trace_id", TRACE)
                .field("command")
                .is_some_and(|c| c.contains("<redacted")),
            "and its span carries the scrubbed command"
        );
    }

    /// TEL-022: a push's session lookup runs in the
    /// `git_receive` span, in the client's trace.
    #[tokio::test]
    async fn a_git_receive_lookup_runs_in_its_span() {
        let log = exec_unknown_session(&format!("git-receive-pack min://{UNKNOWN}")).await;
        assert_lookup_in(&log, "git_receive");
    }

    /// TEL-022: a fetch's session lookup runs in the
    /// `git_upload` span, in the client's trace.
    #[tokio::test]
    async fn a_git_upload_lookup_runs_in_its_span() {
        let log = exec_unknown_session(&format!("git-upload-pack min://{UNKNOWN}")).await;
        assert_lookup_in(&log, "git_upload");
    }

    /// TEL-022: a push's receive-pack task runs in `git_receive`,
    /// so its session messages join the client's trace instead of rooting
    /// their own.
    #[tokio::test]
    async fn a_git_receive_task_runs_in_its_span() {
        let log = exec_known_session("git-receive-pack").await;
        assert_task_in(&log, "git_receive");
    }

    /// TEL-022: a fetch's upload-pack task runs in `git_upload`
    /// (here it refuses a session with no repository, after `GetPaths`).
    #[tokio::test]
    async fn a_git_upload_task_runs_in_its_span() {
        let log = exec_known_session("git-upload-pack").await;
        assert_task_in(&log, "git_upload");
    }

    /// A push or a fetch from a client that opted out
    /// (`MINIMAL_OTEL=off` on the channel) marks its git span
    /// `telemetry=opt-out`, with ids for the file log and no parent. This
    /// runs `adopt_opt_out` on both git spans, so its debug assertion that
    /// the span declares `telemetry` fails here if either span loses it.
    #[tokio::test]
    async fn an_opted_out_git_span_is_marked_opt_out() {
        for (verb, name) in [
            ("git-receive-pack", "git_receive"),
            ("git-upload-pack", "git_upload"),
        ] {
            let log = SpanLog::default();
            let _g =
                tracing::subscriber::set_default(tracing_subscriber::registry().with(log.clone()));
            let server = TestServer::new().await;
            let mut client = server.connect().await;
            let env = [
                (crate::MINIMAL_SESSION_ID_ENV, UNKNOWN),
                (minimald_rpc::trace::OTEL_ENV, minimald_rpc::trace::OTEL_OFF),
            ];
            let outcome = client
                .exec(&env, false, &format!("{verb} min://{UNKNOWN}"), b"")
                .await;
            assert_eq!(
                outcome.err(),
                Some(ExecRejected),
                "{verb}: an unknown session"
            );
            let span = log.one(name, "telemetry", super::OPT_OUT);
            assert_eq!(span.field("parent_span_id"), None, "{span:?}");
            assert!(span.field("trace_id").is_some(), "file-log ids: {span:?}");
        }
    }
}
