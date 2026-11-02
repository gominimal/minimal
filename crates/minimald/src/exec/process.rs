//! The [`Exec`] and [`Process`] implementations: what a request runs
//! (a task, a box shell or argv, a host process) and the handles that
//! wait on and signal it.

use super::*;

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
pub(super) fn task_start_dir(
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
pub(crate) async fn ensure_task_rows_stand(
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
pub(super) trait Reapable {
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
pub(super) async fn attach_or_reap<P: Reapable>(
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
pub(super) fn parse_task_args(
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

/// Refuses the package builds of a task (NET-155) when the box's launch
/// placed it in a classifier leaf (`enforcement` is
/// [`boxes::HostIpEnforcement::PerBox`]) and the task's context has no leaf.
/// Such a build would run outside the box's egress verdict. A box that was
/// never placed builds in the daemon's own cgroup, as before.
pub(crate) fn task_build_refusal(
    enforcement: Option<boxes::HostIpEnforcement>,
    box_name: &str,
    has_leaf: bool,
) -> io::Result<()> {
    if enforcement == Some(boxes::HostIpEnforcement::PerBox) && !has_leaf {
        tracing::warn!(
            box_name = %box_name,
            "refusing a task's package builds for a placed box whose classifier leaf is missing",
        );
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            crate::box_actor::placed_box_build_refusal(box_name),
        ));
    }
    Ok(())
}

/// Producer side of [`TaskExec::exec`]. Inlined in one async fn so that
/// `env` lives on a single stack frame across every spawn — that frame
/// is alive for the whole life of this tokio task, which in turn is
/// governed by the consumer's stream.
pub(super) async fn task_producer(
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

        // NET-155: a task's package builds run in the box's leaf. A box
        // whose launch placed it in a leaf never builds outside it, so a
        // placed box whose leaf is gone has its task refused here. The
        // context lookup does not refuse, because a relaunch uses it too.
        {
            let record = session.record().await?;
            let box_name = record.name.clone().unwrap_or_else(|| record.id.to_string());
            task_build_refusal(
                record.host_ip_enforcement,
                &box_name,
                ctx.classifier_leaf().is_some(),
            )?;
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
                // On the fork thread, never this one: hakoniwa arms
                // `PR_SET_PDEATHSIG(SIGKILL)` in the container, so it dies
                // with the thread that forked it, and a runtime worker is
                // retired ~10 s after any `block_in_place` displaces it (see
                // `sandbox::forker`). #1748 moved the session launch and
                // `Sandbox::run_with_cancel` there; this spawn, a task run's,
                // stayed on the worker, and idle task sessions died with it
                // (inbox#710).
                let mut child = sandbox::forker::on_fork_thread(move || cmd.spawn())
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
    pub(super) pid: libc::pid_t,
    pub(super) state: WaitState,
    /// The network wiring this task's namespace got, released at the end of
    /// [`wait`](Process::wait).
    pub(super) net: NetRelease,
    /// A line the daemon shows ahead of the child's own stderr, such as the
    /// `inherit_cwd` fallback notice (see [`task_start_dir`]).
    pub(super) stderr_notice: Option<String>,
}

/// The release of a task's network, owed once its process is gone.
///
/// [`Process::wait`] is polled inside a `select!` and may be dropped at any
/// await, so the teardown cannot be awaited in place: dropped mid-teardown, a
/// guard would never detach. It runs on its own task instead, and `wait`
/// awaits the handle, which survives being dropped and re-awaited.
pub(super) struct NetRelease {
    pub(super) guard: Option<Box<dyn sandbox::NetGuard>>,
    /// The teardown in flight, once started.
    pub(super) running: Option<JoinHandle<()>>,
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
    pub(super) fn new(guard: Box<dyn sandbox::NetGuard>) -> Self {
        Self {
            guard: Some(guard),
            running: None,
        }
    }

    /// Runs the teardown to completion, once. Cancel-safe: a dropped call
    /// leaves the teardown running, and the next call waits for it.
    pub(super) async fn release(&mut self) {
        if let Some(guard) = self.guard.take() {
            self.running = Some(crate::traced::spawn(guard.teardown()));
        }
        if let Some(running) = &mut self.running {
            let _ = running.await;
            self.running = None;
        }
    }
}

pub(super) enum WaitState {
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
    pub(super) fn new(child: hakoniwa::Child, net_guard: Box<dyn sandbox::NetGuard>) -> Self {
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
    pub(super) stdout: Option<Vec<u8>>,
}

impl EchoProcess {
    pub(super) fn new(text: &str) -> Self {
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

    /// One program (`git receive-pack`, `git upload-pack`): input it leaves
    /// unread after closing its stdin has no other reader, as for a
    /// session exec.
    fn unread_stdin(&self) -> UnreadStdin {
        UnreadStdin::Discard
    }

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
pub(super) fn git_repo_location_env() -> BTreeSet<String> {
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
    pub(super) fn argv(self) -> (String, Vec<String>) {
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
pub(super) const SESSION_SHELL: &str = "/usr/bin/bash";

impl Exec for BoxExec {
    type Process = TokioProcess;

    /// One program: input it leaves unread after closing its stdin has no
    /// other reader.
    fn unread_stdin(&self) -> UnreadStdin {
        UnreadStdin::Discard
    }

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
    pub(super) child: Child,
    /// Whether [`Process::start_kill`] sends SIGTERM, with a SIGKILL
    /// escalation in [`Process::wait`], rather than an immediate SIGKILL.
    /// Only the injection shim handles SIGTERM by killing its whole process
    /// group; any other child gets the immediate SIGKILL.
    pub(super) graceful: bool,
    /// Whether a graceful [`Process::start_kill`] has asked the child to
    /// exit, which arms the escalation in [`Process::wait`].
    pub(super) terminating: bool,
}

impl TokioProcess {
    /// A child that [`Process::start_kill`] SIGKILLs at once.
    pub(super) fn new(child: Child) -> Self {
        Self {
            child,
            graceful: false,
            terminating: false,
        }
    }

    /// The injection shim, which [`Process::start_kill`] SIGTERMs so its
    /// handler can kill the injected process's whole group.
    pub(super) fn shim(child: Child) -> Self {
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

/// Mints an exec id (BOX-149): a UUIDv7, whatever the exec's mode.
pub(crate) fn mint_exec_id() -> ExecId {
    ExecId::parse(&uuid::Uuid::now_v7().hyphenated().to_string())
        .expect("a hyphenated UUIDv7 always parses as an exec id")
}

/// The program and arguments an exec's argv runs as, with no shell between
/// the client's words and the process (BOX-149). The box host joins them to
/// the box's namespaces and cgroup ([`crate::nsenter::Injection`]).
pub(crate) fn exec_argv(argv: Vec<String>) -> (String, Vec<String>) {
    BoxProgram::Argv(argv).argv()
}

/// The box an exec runs in, as the exec's events and transcript need it.
#[derive(Debug, Clone)]
pub(crate) struct ExecBox {
    /// The box's record, for the id and parent its events carry.
    pub(crate) record: boxes::Record,
    /// The box's state directory, where its record, its events and its
    /// exec transcripts live.
    pub(crate) dir: camino::Utf8PathBuf,
}

impl ExecBox {
    /// The box `session` names, read from its live actor.
    pub(crate) async fn of(session: &BoxHandle) -> io::Result<Self> {
        let record = session.record().await?;
        let paths = session.paths().await?;
        // Every directory in `BoxPaths` sits in the box's state directory,
        // beside `record.json`.
        let dir = paths
            .home
            .as_utf8_path()
            .parent()
            .ok_or_else(|| io::Error::other("the box's home directory has no parent"))?
            .to_path_buf();
        Ok(Self { record, dir })
    }

    /// Writes one exec event about `id` to the box's events file. A failed
    /// write is logged and never ends the exec.
    pub(crate) fn write_event(
        &self,
        kind: boxes::events::BoxEventType,
        id: &ExecId,
        mode: ExecMode,
        exit: Option<ExecExit>,
    ) {
        let mut event = boxes::events::BoxEvent::for_record(&self.record, kind);
        event.data.insert("exec_id".into(), id.as_str().into());
        event.data.insert("mode".into(), mode.name().into());
        event
            .data
            .insert("pty".into(), (mode == ExecMode::Tty).into());
        if let Some(exit) = exit {
            event.data.insert(
                "exit_code".into(),
                exit.code
                    .map_or(serde_json_lenient::Value::Null, Into::into),
            );
            event
                .data
                .insert("reason".into(), exit.reason.name().into());
        }
        let path = self.dir.join(boxes::events::EVENTS_FILE);
        if let Err(error) = boxes::store::append_event_at(&path, &event) {
            tracing::warn!(
                exec_id = %id,
                event_type = kind.name(),
                %error,
                "exec: could not write the box event"
            );
        }
    }
}

/// What a tty or a detached exec needs to start (BOX-149).
#[derive(Debug)]
pub(crate) struct ManagedStart {
    pub(crate) id: ExecId,
    pub(crate) mode: ExecMode,
    pub(crate) exec_box: ExecBox,
    /// The exec's own timeout. `None` leaves it to the box's ceilings.
    pub(crate) timeout: Option<Duration>,
    /// The terminal's rows and columns, for a tty exec.
    pub(crate) winsize: (u16, u16),
}

/// Starts a tty or a detached exec from `command`, which runs the exec's
/// argv in the box, and returns its entry at once. The exec then runs on
/// its own, with no client: a supervisor waits for it, ends it at its own
/// timeout, records its exit and writes its `exec_exited` event.
///
/// A detached exec gets `/dev/null` for stdin, so its stdin is closed at
/// creation, and one pipe for its stdout and stderr. A pump copies the pipe
/// to its transcript. A tty exec gets a fresh terminal for all three, and a
/// pump copies the terminal to the transcript and to every attached client.
/// The transcript holds at most [`TRANSCRIPT_CAP`] bytes, the newest.
///
/// `graceful` is true for the injection shim, which a stop SIGTERMs so it
/// can end the exec's whole process group, then SIGKILLs.
pub(crate) fn start_managed_exec(
    start: ManagedStart,
    mut command: std::process::Command,
    graceful: bool,
) -> io::Result<Arc<ExecEntry>> {
    let ManagedStart {
        id,
        mode,
        exec_box,
        timeout,
        winsize,
    } = start;
    let transcript_path = boxes::store::exec_transcript_path(&exec_box.dir, id.as_str());
    if let Some(dir) = transcript_path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let transcript = CappedTranscript::create(&transcript_path)?;

    let source = match mode {
        ExecMode::Tty => {
            let (master, slave) = open_terminal(winsize)?;
            command
                .stdin(Stdio::from(slave.try_clone()?))
                .stdout(Stdio::from(slave.try_clone()?))
                .stderr(Stdio::from(slave));
            master
        }
        ExecMode::Detached | ExecMode::Attached => {
            // `std::io::pipe` makes both ends close-on-exec. The copies the
            // command gets through `dup2` are not.
            let (reader, writer) = std::io::pipe()?;
            command
                .stdin(Stdio::null())
                .stdout(Stdio::from(writer.try_clone()?))
                .stderr(Stdio::from(writer));
            std::fs::File::from(std::os::fd::OwnedFd::from(reader))
        }
    };
    let mut command = Command::from(command);
    command.kill_on_drop(true);
    let child = command.spawn()?;
    // The command holds the parent's copies of the terminal's slave side or
    // the pipe's write end. Dropped now, so the pump sees the end of the
    // output when the exec ends.
    drop(command);
    let process = if graceful {
        TokioProcess::shim(child)
    } else {
        TokioProcess::new(child)
    };

    let (terminal, feed) = match mode {
        ExecMode::Tty => {
            let (terminal, input) = ExecTerminal::new();
            let writer = source.try_clone()?;
            (Some(terminal), Some((writer, input)))
        }
        ExecMode::Detached | ExecMode::Attached => (None, None),
    };
    let entry = Arc::new(ExecEntry::new(
        id.clone(),
        exec_box.record.id,
        mode,
        transcript_path,
        terminal,
    ));
    register_exec(Arc::clone(&entry));
    exec_box.write_event(boxes::events::BoxEventType::ExecStarted, &id, mode, None);
    tracing::info!(
        exec_id = %id,
        mode = mode.name(),
        timeout_secs = timeout.map(|t| t.as_secs()),
        transcript = %entry.transcript,
        "exec started"
    );

    let pump = spawn(pump_output(Arc::clone(&entry), source, transcript));
    if let Some((writer, input)) = feed {
        spawn(feed_terminal(writer, input));
    }
    spawn(supervise_managed_exec(
        Arc::clone(&entry),
        process,
        timeout,
        pump,
        exec_box,
    ));
    Ok(entry)
}

/// How long the supervisor of an exec waits, after the exec exits, for the
/// pump to copy what the terminal or the pipe still holds. A descendant that
/// keeps the terminal or the pipe open must not hold the exit back.
const TERMINAL_DRAIN: Duration = Duration::from_secs(1);

/// Waits for a managed exec, ends it at its own timeout, and records how it
/// ended: on its entry for a wait, in the daemon log, and as the box's
/// `exec_exited` event. The box itself is not touched.
async fn supervise_managed_exec(
    entry: Arc<ExecEntry>,
    mut process: TokioProcess,
    timeout: Option<Duration>,
    mut pump: JoinHandle<()>,
    exec_box: ExecBox,
) {
    let (status, reason) = wait_with_timeout(&mut process, timeout).await;
    entry.close_input();
    // A tty pump stops at the drain. A detached pump keeps on, so the
    // transcript still gets what a descendant writes after the exit.
    if tokio::time::timeout(TERMINAL_DRAIN, &mut pump)
        .await
        .is_err()
        && entry.mode == ExecMode::Tty
    {
        pump.abort();
    }
    let code = status.unwrap_or_else(|error| {
        tracing::warn!(exec_id = %entry.id, %error, "exec: failed to wait for the command");
        None
    });
    let exit = ExecExit { code, reason };
    exec_box.write_event(
        boxes::events::BoxEventType::ExecExited,
        &entry.id,
        entry.mode,
        Some(exit),
    );
    tracing::info!(
        exec_id = %entry.id,
        mode = entry.mode.name(),
        exit_code = code,
        reason = reason.name(),
        "exec ended"
    );
    entry.finish(exit);
}

/// Waits for `process`, and ends it once `timeout` runs out (BOX-149):
/// [`Process::start_kill`] (for the shim, SIGTERM to the exec's process
/// group, its grace period, then SIGKILL), then a wait for the end.
pub(crate) async fn wait_with_timeout<P: Process>(
    process: &mut P,
    timeout: Option<Duration>,
) -> (io::Result<Option<i32>>, ExecExitReason) {
    let Some(timeout) = timeout else {
        return (process.wait().await, ExecExitReason::Exited);
    };
    match tokio::time::timeout(timeout, process.wait()).await {
        Ok(status) => (status, ExecExitReason::Exited),
        Err(_elapsed) => {
            tracing::info!(
                timeout_secs = timeout.as_secs(),
                "exec: the command ran past its timeout; stopping it"
            );
            if let Err(error) = process.start_kill() {
                tracing::warn!(%error, "exec: failed to stop the command at its timeout");
            }
            (wait_after_stop(process).await, ExecExitReason::Timeout)
        }
    }
}

/// How long a wait for a command lasts after its timeout asked it to stop.
/// Longer than the shim's own escalation to SIGKILL, so a command that the
/// stop reaches always ends inside it.
pub(crate) const STOP_BOUND: Duration =
    Duration::from_secs(crate::nsenter::SHIM_ESCALATION.as_secs() + 5);

/// Waits for `process` after a stop at its timeout, for at most
/// [`STOP_BOUND`]. A command that the stop did not reach, or that does not
/// end, gives an error in place of a wait that never returns, so the exec
/// still records an end.
pub(crate) async fn wait_after_stop<P: Process>(process: &mut P) -> io::Result<Option<i32>> {
    match tokio::time::timeout(STOP_BOUND, process.wait()).await {
        Ok(status) => status,
        Err(_elapsed) => {
            // A last SIGKILL; an error here changes nothing we can act on.
            let _ = process.start_kill();
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the command did not end after it was stopped at its timeout",
            ))
        }
    }
}

/// Opens a terminal pair of `rows` by `cols`, both sides close-on-exec. The
/// slave side becomes the exec's stdio through `dup2`, which clears the flag
/// on the copies the exec gets.
fn open_terminal((rows, cols): (u16, u16)) -> io::Result<(std::fs::File, std::fs::File)> {
    use std::os::fd::{FromRawFd as _, OwnedFd};

    let mut master: libc::c_int = -1;
    let mut slave: libc::c_int = -1;
    let size = libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: valid out-pointers for both descriptors and the size, and
    // NULL for the optional name and termios.
    let ret = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &size,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `openpty` succeeded, so both descriptors are open and ours.
    let (master, slave) = unsafe { (OwnedFd::from_raw_fd(master), OwnedFd::from_raw_fd(slave)) };
    for fd in [&master, &slave] {
        use std::os::fd::AsRawFd as _;
        // SAFETY: `fd` is a live descriptor this function owns.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == -1 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((std::fs::File::from(master), std::fs::File::from(slave)))
}

/// Copies an exec's output to its transcript until the output ends. For a
/// tty exec, `source` is the terminal: the pump also sends each chunk to
/// every attached client, and the terminal ends with `EIO` once the last
/// slave descriptor is gone. For a detached exec, `source` is the read end
/// of its pipe, which ends when the last writer closes it.
async fn pump_output(
    entry: Arc<ExecEntry>,
    source: std::fs::File,
    mut transcript: CappedTranscript,
) {
    let mut source = tokio::fs::File::from_std(source);
    let mut buf = vec![0u8; 8192];
    loop {
        match source.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => entry.record_output(&mut transcript, &buf[..n]),
            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
            Err(error) => {
                tracing::warn!(exec_id = %entry.id, %error, "exec: output read failed");
                break;
            }
        }
    }
}

/// Writes what attached clients type to a tty exec's terminal, until the
/// exec ends and its entry drops the input's sender.
async fn feed_terminal(master: std::fs::File, mut input: mpsc::UnboundedReceiver<Vec<u8>>) {
    let mut master = tokio::fs::File::from_std(master);
    while let Some(bytes) = input.recv().await {
        if master.write_all(&bytes).await.is_err() || master.flush().await.is_err() {
            break;
        }
    }
}

/// An [`Exec`] for an attached exec with its own timeout: a [`BoxExec`]
/// whose process ends once the timeout runs out (BOX-149).
#[derive(Debug, Clone)]
pub struct TimedBoxExec {
    pub inner: BoxExec,
    pub timeout: Option<Duration>,
    /// Set when the timeout ended the exec, for its `exec_exited` reason.
    pub timed_out: Arc<AtomicBool>,
}

impl Exec for TimedBoxExec {
    type Process = TimedProcess<TokioProcess>;

    fn unread_stdin(&self) -> UnreadStdin {
        UnreadStdin::Discard
    }

    fn exec(self, session: BoxHandle) -> BoxStream<'static, io::Result<Self::Process>> {
        let Self {
            inner,
            timeout,
            timed_out,
        } = self;
        inner
            .exec(session)
            .map(move |spawned| {
                spawned.map(|inner| TimedProcess {
                    inner,
                    deadline: timeout.map(|t| tokio::time::Instant::now() + t),
                    timed_out: Arc::clone(&timed_out),
                })
            })
            .boxed()
    }
}

/// A [`Process`] that [`Process::start_kill`]s itself at its deadline.
#[derive(Debug)]
pub struct TimedProcess<P> {
    pub(super) inner: P,
    pub(super) deadline: Option<tokio::time::Instant>,
    pub(super) timed_out: Arc<AtomicBool>,
}

impl<P: Process> Process for TimedProcess<P> {
    type Stdin = P::Stdin;
    type Stdout = P::Stdout;
    type Stderr = P::Stderr;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        self.inner.take_stdio()
    }

    // Cancel-safe: the deadline is fixed at the spawn, the inner `wait` is
    // cancel-safe, and `timed_out` is set before the next await point.
    async fn wait(&mut self) -> io::Result<Option<i32>> {
        if let Some(deadline) = self.deadline
            && !self.timed_out.load(Ordering::SeqCst)
        {
            match tokio::time::timeout_at(deadline, self.inner.wait()).await {
                Ok(status) => return status,
                Err(_elapsed) => {
                    self.timed_out.store(true, Ordering::SeqCst);
                    tracing::info!("exec: the command ran past its timeout; stopping it");
                    if let Err(error) = self.inner.start_kill() {
                        tracing::warn!(%error, "exec: failed to stop the command at its timeout");
                    }
                }
            }
        }
        if self.timed_out.load(Ordering::SeqCst) {
            // The timeout ended the exec, so its status is the timeout's,
            // whatever the stop left behind (BOX-149).
            if let Err(error) = wait_after_stop(&mut self.inner).await {
                tracing::warn!(%error, "exec: the command did not end after its timeout");
            }
            return Ok(Some(TIMEOUT_STATUS));
        }
        self.inner.wait().await
    }

    fn start_kill(&mut self) -> io::Result<()> {
        self.inner.start_kill()
    }
}
