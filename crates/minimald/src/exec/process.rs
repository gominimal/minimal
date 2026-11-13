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
    /// The client resolved the task's `env_vars` itself and said so
    /// ([`minimald_rpc::taskenv::TASK_ENV_RESOLVED`]), as `min session run`
    /// does (inbox#778). An `inherit` that [`Self::env`] and
    /// [`Self::drop_env`] leave in the task's declarations then refuses the
    /// run: the daemon's own environment never answers it.
    pub client_resolved: bool,
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
        // T43: a task box runs its task as its entrypoint. The run relays
        // that entrypoint, and runs nothing beside the box. Any other
        // request takes the older path below, kept for one release.
        stream::once(async move {
            match task_entrypoint_box(&self, &session).await {
                Some(run) => stream::once(async move { run.start(self, session).await }).boxed(),
                None => self.sandboxed(session),
            }
        })
        .flatten()
        .boxed()
    }
}

impl TaskExec {
    /// The older task path: the task runs in a sandbox of its own, beside
    /// the box. Kept for one release, for a client that sends its task's
    /// arguments on the request, as a `min` from before T43 does, and for
    /// a box that is not a task box.
    fn sandboxed(self, session: BoxHandle) -> BoxStream<'static, io::Result<TaskProcess>> {
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

/// Applies the client's resolution of a task's `env_vars` over the task's
/// own declarations: the names the client dropped go, then the values it
/// resolved are set.
///
/// When the client said it resolved them ([`TaskExec::client_resolved`]),
/// an `inherit` left over refuses the run with [`UnansweredInherit`],
/// where the task's sandbox would otherwise read the daemon's environment
/// for it. The client read the task from the session's project on the
/// host, and the session runs its own copy of the project, so the name
/// never passed the user's `[vars]` policy (inbox#778).
pub(super) fn overlay_client_env(
    exec: &TaskExec,
    vars: &mut BTreeMap<String, mfile::EnvVarValue>,
) -> Result<(), UnansweredInherit> {
    // Removals first. The two sets are disjoint, so the order is not
    // load-bearing, but reading it in policy order — drop, then apply —
    // matches how the client decided.
    for name in &exec.drop_env {
        vars.remove(name);
    }
    for (name, value) in &exec.env {
        vars.insert(name.clone(), mfile::EnvVarValue::Value(value.clone()));
    }
    if exec.client_resolved
        && let Some((name, _)) = vars
            .iter()
            .find(|(_, value)| matches!(value, mfile::EnvVarValue::Inherit))
    {
        return Err(UnansweredInherit {
            task: exec.task.clone(),
            var: name.clone(),
        });
    }
    Ok(())
}

/// A resolved run's `inherit` that the client sent no value for: the
/// session's copy of the project declares it, and the copy the client read
/// on the host does not.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct UnansweredInherit {
    pub task: String,
    pub var: String,
}

impl UnansweredInherit {
    /// The refusal the person running `min session run` sees, for the
    /// session `id`, named `name` if it has one, of the project at
    /// `project` on the host.
    ///
    /// It names what was refused, the two ways the client can miss a
    /// variable the session's copy declares (that copy predates a change
    /// on the host, or a stack provides the task, which the client cannot
    /// read), and the commands that replace the session with one of the
    /// project as it is now. A second `min session activate` alone would
    /// leave this session in place and still out of date.
    pub(super) fn refusal(&self, name: Option<&str>, id: &str, project: &str) -> String {
        let Self { task, var } = self;
        let project = shell_word(project);
        let destroy = format!("min session destroy {}", shell_word(name.unwrap_or(id)));
        let activate = match name.map(shell_word) {
            Some(name) => format!("min session activate --name {name} {project}"),
            None => format!("min session activate {project}"),
        };
        format!(
            "refused to run task '{task}': the session's copy of the project declares \
             `env_vars.{var} = {{ inherit = true }}` for it, and `min session run` sent \
             no value for {var}. `min` reads the task from the minimal.toml of {project} \
             on the host, which does not declare {var} for this task. Either that file \
             changed after the session was activated, or a stack provides the task, and \
             `min session run` cannot pass an inherited variable to a stack's task. If \
             the file changed, run `{destroy}`, then `{activate}`."
        )
    }
}

/// `s` as one word a POSIX shell reads back unchanged: as it is when every
/// character is plain, single-quoted otherwise.
fn shell_word(s: &str) -> String {
    let plain = !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "/._-+,:@%=".contains(c));
    if plain {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r#"'\''"#))
    }
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
        let record = session.record().await?;
        overlay_client_env(&exec, &mut task.vars).map_err(|unanswered| {
            io::Error::other(unanswered.refusal(
                record.name.as_deref(),
                &record.id.to_string(),
                record.project_path.as_ref(),
            ))
        })?;
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
    /// hakoniwa's account of a sandbox that failed, for the client's
    /// stderr ([`Process::exit_notice`]).
    pub(super) failure: Option<String>,
    /// Set by [`Process::start_kill`]: the daemon ended this task, so its
    /// status is not read as a sandbox failure.
    pub(super) killed: bool,
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
            failure: None,
            killed: false,
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
                Ok(Ok(status)) => {
                    self.failure = sandbox_failure(&status, self.killed);
                    if let Some(reason) = &self.failure {
                        tracing::warn!(pid = self.pid, %reason, "task: the sandbox failed");
                    }
                    WaitState::Exited(Some(status.code))
                }
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
        self.killed = true;
        Ok(())
    }

    fn exit_notice(&mut self) -> Option<String> {
        self.failure
            .take()
            .map(|reason| sandbox_failure_notice(&reason))
    }
}

/// hakoniwa's exit code for a container that failed itself, rather than a
/// command that ran (`ExitStatus::FAILURE`).
pub(super) const SANDBOX_FAILURE_CODE: i32 = 125;

/// hakoniwa's reason for a container that a SIGKILL ended. It reports that
/// as [`SANDBOX_FAILURE_CODE`] with no inner exit code, the same shape as a
/// sandbox failure, whether or not the command had started.
pub(super) const CONTAINER_SIGKILL_REASON: &str = "container received signal SIGKILL";

/// The reason a task's sandbox failed, or `None` for any other end of the
/// task. hakoniwa reports a sandbox failure as code 125 with no inner
/// exit code. A command that itself exits 125 carries its own exit code, and
/// a signalled one reports `128 + signo`, so neither is taken for it. A
/// container that was killed, by the daemon (`killed`) or by anything else,
/// is not a sandbox failure either.
pub(super) fn sandbox_failure(status: &hakoniwa::ExitStatus, killed: bool) -> Option<String> {
    (!killed
        && status.code == SANDBOX_FAILURE_CODE
        && status.exit_code.is_none()
        && status.reason != CONTAINER_SIGKILL_REASON)
        .then(|| status.reason.clone())
}

/// The line on the client's stderr for a task whose sandbox failed: the
/// command's own output may be empty, so this is the only account of why the
/// task ended with 125. The reason can quote a path the box chose, so its
/// control characters are escaped and it stays one line.
pub(super) fn sandbox_failure_notice(reason: &str) -> String {
    format!(
        "the task's sandbox failed: {}\n",
        crate::env::one_line(reason)
    )
}

/// The [`Process`] produced by a [`TaskExec`]: either a real sandboxed child
/// ([`HakoniwaProcess`]) or a synthetic [`EchoProcess`] for `echo` tasks.
///
/// Stdio is boxed so the two variants' differing handle types unify behind
/// one associated type; the bridge only ever sees `dyn AsyncRead`/`AsyncWrite`.
pub enum TaskProcess {
    Sandbox(HakoniwaProcess),
    Echo(EchoProcess),
    Entrypoint(EntrypointProcess),
    Refused(RefusedProcess),
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
            TaskProcess::Entrypoint(p) => p.take_stdio(),
            TaskProcess::Refused(p) => p.take_stdio(),
        }
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        match self {
            TaskProcess::Sandbox(p) => p.wait().await,
            TaskProcess::Echo(p) => p.wait().await,
            TaskProcess::Entrypoint(p) => p.wait().await,
            TaskProcess::Refused(p) => p.wait().await,
        }
    }

    fn start_kill(&mut self) -> io::Result<()> {
        match self {
            TaskProcess::Sandbox(p) => p.start_kill(),
            TaskProcess::Echo(p) => p.start_kill(),
            TaskProcess::Entrypoint(p) => p.start_kill(),
            TaskProcess::Refused(p) => p.start_kill(),
        }
    }

    fn exit_notice(&mut self) -> Option<String> {
        match self {
            TaskProcess::Sandbox(p) => p.exit_notice(),
            TaskProcess::Echo(p) => p.exit_notice(),
            TaskProcess::Entrypoint(p) => p.exit_notice(),
            TaskProcess::Refused(p) => p.exit_notice(),
        }
    }
}

/// A task box whose entrypoint a task run relays (T43), as
/// [`task_entrypoint_box`] finds it.
pub(super) struct TaskEntrypointBox {
    record: boxes::Record,
    dir: boxes::store::BoxDir,
}

/// The task box `exec` runs in, when its entrypoint is the task: a box
/// whose stored spec sets `lifetime = "until_complete"`, names an argv as
/// its entrypoint and this task as its entry. The spec's settings decide,
/// never its Box Type. `None` sends the request down the older path: a
/// request that carries the task's arguments (a client from before T43
/// sends them there, not in the spec), a box whose spec says otherwise,
/// or a box with no spec that can be read. A request's directory is no reason for
/// the older path: the entrypoint starts there (see
/// [`TaskEntrypointBox::start`]).
pub(super) async fn task_entrypoint_box(
    exec: &TaskExec,
    session: &BoxHandle,
) -> Option<TaskEntrypointBox> {
    if !exec.args.is_empty() {
        return None;
    }
    let paths = session.paths().await.ok()?;
    let dir = boxes::store::BoxDir::for_tree(&paths.working)?;
    let record = session.record().await.ok()?;
    let bytes = std::fs::read(
        paths
            .home
            .as_utf8_path()
            .parent()?
            .join(boxes::store::SPEC_FILE),
    )
    .ok()?;
    let spec = crate::box_runtime::stored_spec(&bytes).ok()?;
    let is_task_entrypoint =
        crate::box_actor::entry_run_as_entrypoint(&spec) == Some(exec.task.as_str());
    is_task_entrypoint.then_some(TaskEntrypointBox { record, dir })
}

/// The refusal of a task run whose box's entrypoint another run relays:
/// the host hands the entrypoint's streams to one run at a time
/// ([`crate::box_runtime::EntrypointIoTake::Relayed`]).
pub(crate) fn entrypoint_relayed_refusal(task: &str, box_name: &str) -> String {
    format!(
        "Task {task} is already running in box {box_name}, and another min task run shows its \
         output. Only one run at a time can show a task's output."
    )
}

/// How often a task run checks whether its box's entrypoint ended, and
/// whether the box's record keeps the end.
const ENTRYPOINT_POLL: Duration = Duration::from_millis(100);

/// How long the run waits for the box's actor to write the ended record
/// after the entrypoint's host ends.
const ENTRYPOINT_RECORD_WAIT: Duration = Duration::from_secs(30);

impl TaskEntrypointBox {
    /// Starts the box's entrypoint, or joins it when it already runs, and
    /// relays its stdin, stdout and stderr. The task's resolved variables
    /// go to the launch that starts the entrypoint (see
    /// [`crate::box_actor::entrypoint_env`]).
    async fn start(self, exec: TaskExec, session: BoxHandle) -> io::Result<TaskProcess> {
        let box_id = self.record.id;
        let box_name = self
            .record
            .name
            .clone()
            .unwrap_or_else(|| box_id.to_string());
        let span = tracing::info_span!(
            "task_run",
            box_id = %box_id,
            box_name = %box_name,
            task = %exec.task,
            stdin = tracing::field::Empty,
        );
        // `inherit_cwd`: the client sends a directory only for a task that
        // declares it. The entrypoint starts there, so the in-box `min task
        // run` reads it as its `$PWD`. A directory that is not in the
        // uploaded tree starts the entrypoint at the root, with a notice.
        let working = session.paths().await?.working;
        let (start_dir, start_notice) =
            match task_start_dir(true, &exec.cwd, working.as_utf8_path().as_std_path()) {
                Ok(dir) => (dir, None),
                Err(notice) => (None, Some(notice)),
            };
        crate::box_actor::entrypoint_env::stage(
            box_id,
            exec.env.into_iter().collect(),
            start_dir.clone(),
            exec.drop_env.clone(),
        );
        let username = self
            .record
            .username
            .clone()
            .unwrap_or_else(|| "user".to_string());
        let ensured = session.ensure_host(username).instrument(span.clone()).await;
        if ensured.is_err() {
            // An `ensure_host` that failed before the box's actor took the
            // staged values leaves them staged. Nothing launches for this
            // run, so no later launch of the box may take them.
            drop(crate::box_actor::entrypoint_env::take(&box_id));
        }
        let host = match ensured {
            Ok(host) => host,
            // The box's actor refused the start. The run says so in plain
            // words, without the spawn-failure prefix, and exits 1.
            Err(error) if crate::box_actor::EntrypointBehindHookShell::is(&error) => {
                span.in_scope(|| {
                    tracing::info!("task box: the entrypoint did not start behind a hook shell");
                });
                return Ok(TaskProcess::Refused(RefusedProcess::new(&format!(
                    "Task {task} did not start in box {box_name}. {why}",
                    task = exec.task,
                    why = crate::box_actor::ENTRYPOINT_BEHIND_HOOK_SHELL,
                ))));
            }
            Err(error) => return Err(io::Error::other(format!("{error}"))),
        };
        // The box runs its entrypoint on three pipes (T43): the run's stdin
        // goes to the entrypoint's stdin, and its stdout and stderr come
        // back as two streams.
        let io = match host.take_entrypoint_io().await {
            crate::box_runtime::EntrypointIoTake::Taken(io) => io,
            crate::box_runtime::EntrypointIoTake::OnTerminal => {
                span.in_scope(|| {
                    tracing::warn!(
                        "task box: the entrypoint has a terminal, so the run cannot relay it"
                    );
                });
                return Err(io::Error::other(
                    "The task's box runs its command on a terminal, so the run cannot pass its \
                     input and output.",
                ));
            }
            crate::box_runtime::EntrypointIoTake::Relayed => {
                // The run that started the entrypoint, or one that took its
                // place, still reads it. That run keeps the output and the
                // exit code. This run takes nothing, and its staged values
                // went with the join (see `ensure_host`).
                span.in_scope(|| {
                    tracing::info!("task box: another run relays the entrypoint; refused the run");
                });
                return Ok(TaskProcess::Refused(RefusedProcess::with_code(
                    &entrypoint_relayed_refusal(&exec.task, &box_name),
                    2,
                )));
            }
            crate::box_runtime::EntrypointIoTake::HostGone => {
                span.in_scope(|| {
                    tracing::warn!(
                        "task box: the box's host ended before the run took the entrypoint's \
                         streams"
                    );
                });
                return Err(io::Error::other(format!(
                    "Box {box_name} ended before the run connected to the task's input and \
                     output. The run cannot show the task's output."
                )));
            }
        };
        // Whether this run passes its stdin to the entrypoint, whose in-box
        // `min task run` forwards it to the task (T123).
        span.record("stdin", io.stdin.is_some());
        span.in_scope(|| {
            tracing::info!(
                drop_env = exec.drop_env.len(),
                start_dir = ?start_dir,
                stdin = io.stdin.is_some(),
                "task box: the run relays the box's entrypoint"
            );
        });

        // `None` for a run that joins an entrypoint another run started:
        // that run has the entrypoint's stdin.
        let stdin = io
            .stdin
            .map(tokio::net::unix::pipe::Sender::from_file)
            .transpose()?;
        let (stdout, stdout_writer) = tokio::io::duplex(64 * 1024);
        let (stderr, mut stderr_writer) = tokio::io::duplex(64 * 1024);
        if let Some(notice) = start_notice {
            stderr_writer.write_all(notice.as_bytes()).await?;
        }
        let relays = vec![
            spawn(relay_entrypoint_stream(io.stdout, stdout_writer).instrument(span.clone())),
            spawn(relay_entrypoint_stream(io.stderr, stderr_writer).instrument(span.clone())),
        ];
        Ok(TaskProcess::Entrypoint(EntrypointProcess {
            host,
            record_dir: self.dir.clone(),
            box_id,
            box_name,
            task: exec.task,
            span,
            stdio: Some((stdin, stdout, stderr)),
            relays,
            released: false,
        }))
    }
}

/// Copies one output stream of the box's entrypoint to `out` until the
/// host ends the stream, then closes `out`. A pipe is no terminal, so the
/// bytes are the entrypoint's own.
async fn relay_entrypoint_stream(
    mut chunks: tokio::sync::mpsc::Receiver<Vec<u8>>,
    mut out: tokio::io::DuplexStream,
) {
    while let Some(chunk) = chunks.recv().await {
        if out.write_all(&chunk).await.is_err() {
            // Nobody reads the run any more. The entrypoint runs on, and
            // its output goes on to the box's log.
            return;
        }
    }
    let _ = out.shutdown().await;
}

/// The stdin that the in-box `min task run` forwards over its minenv
/// connection, as it goes to the task's stdin pipe (T123). The in-box run
/// is a task box's entrypoint, so this is how the run's own stdin reaches
/// the task.
///
/// A thread copies the connection to the pipe and closes the pipe at the
/// connection's EOF, so the task reads EOF. When the task closes its stdin
/// or ends first, the thread reads on and drops the rest until the helper
/// closes its side. So the helper's writes never fail, and the run's last
/// lines (its `exit:` line among them) reach it.
///
/// With [`Self::start_pipe`], the copy feeds a pipe that each invocation of
/// a multi-invocation task reads in turn. The next invocation reads the
/// input that the one before it left unread. Call [`Self::task_ended`] only
/// after the last invocation ends.
pub(crate) struct ForwardedStdin {
    connection: std::os::unix::net::UnixStream,
    done: std::sync::mpsc::Receiver<io::Result<()>>,
    ended: bool,
    task_ended: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ForwardedStdin {
    /// Starts the copy of `connection` to `task_stdin`.
    pub(crate) fn start(
        connection: &std::os::unix::net::UnixStream,
        task_stdin: impl io::Write + Send + 'static,
    ) -> io::Result<Self> {
        let reader = connection.try_clone()?;
        let connection = connection.try_clone()?;
        let (tx, done) = std::sync::mpsc::channel();
        let task_ended = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let ended_flag = task_ended.clone();
        std::thread::Builder::new()
            .name("task-stdin".to_string())
            .spawn(move || {
                let _ = tx.send(copy_forwarded_stdin(reader, task_stdin, &ended_flag));
            })?;
        Ok(Self {
            connection,
            done,
            ended: false,
            task_ended,
        })
    }

    /// Starts the copy of `connection` to a new pipe, and returns the
    /// pipe's read end. Give each invocation of the task a `try_clone` of
    /// it as its stdin, one after the other. Drop it after the last
    /// invocation ends: the copy then drops the rest of the input.
    pub(crate) fn start_pipe(
        connection: &std::os::unix::net::UnixStream,
    ) -> io::Result<(Self, std::io::PipeReader)> {
        let (reader, writer) = std::io::pipe()?;
        Ok((Self::start(connection, writer)?, reader))
    }

    /// Records that the task ended. For a task with more than one
    /// invocation, that is after its last invocation ends. A read of the connection that fails
    /// after this is not an error: the task no longer reads its stdin.
    pub(crate) fn task_ended(&self) {
        self.task_ended
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }

    /// Waits for the copy to end, and keeps its result for [`Self::failure`].
    #[cfg(test)]
    pub(crate) fn wait_for_copy_end(&mut self) {
        let result = self.done.recv().unwrap_or(Ok(()));
        let (tx, done) = std::sync::mpsc::channel();
        let _ = tx.send(result);
        self.done = done;
    }

    /// The error that stopped the copy while the task still read its
    /// stdin, if the copy ended with one. Does not wait.
    pub(crate) fn failure(&mut self) -> Option<io::Error> {
        match self.done.try_recv() {
            Ok(Err(error)) => {
                self.ended = true;
                Some(error)
            }
            Ok(Ok(())) | Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                self.ended = true;
                None
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
        }
    }

    /// Waits, up to `wait`, for the helper to close its side once the run
    /// sent its last line. Past `wait`, the connection's read side closes
    /// and the copy ends. Blocks, so call it off the runtime.
    pub(crate) fn finish(self, wait: Duration) {
        if self.ended {
            return;
        }
        if self.done.recv_timeout(wait).is_err() {
            tracing::warn!(
                wait_secs = wait.as_secs(),
                "the in-box min task run did not close its forwarded stdin; closed it"
            );
            let _ = self.connection.shutdown(std::net::Shutdown::Read);
            let _ = self.done.recv();
        }
    }
}

/// Copies `from` to `to` until `from` ends, and closes `to` then. A write
/// that fails means the task closed its stdin or ended. The copy then
/// drops the rest of `from` and reads on to its end. Only a read that
/// fails while the task reads its stdin is an error. A read that fails
/// once `task_ended` is set is not.
fn copy_forwarded_stdin(
    mut from: impl io::Read,
    to: impl io::Write,
    task_ended: &std::sync::atomic::AtomicBool,
) -> io::Result<()> {
    let mut to = Some(to);
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match from.read(&mut buf) {
            Ok(0) => return Ok(()),
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if to.is_some() && !task_ended.load(std::sync::atomic::Ordering::SeqCst) => {
                return Err(e);
            }
            Err(_) => return Ok(()),
        };
        if let Some(pipe) = to.as_mut()
            && pipe
                .write_all(&buf[..n])
                .and_then(|()| pipe.flush())
                .is_err()
        {
            to = None;
        }
    }
}

/// The [`Process`] of a task run whose task is its box's entrypoint (T43).
/// Its stdin, stdout and stderr are the entrypoint's, through the pipes it
/// runs on, and its exit code is the one the box's record keeps when the
/// entrypoint returns.
///
/// The run does not own the entrypoint. A client that goes away, or a
/// kill of the run, stops the relay, and the box runs on (BOX-015). The
/// box ends when its entrypoint returns (BOX-038), and keeps its record.
pub struct EntrypointProcess {
    /// The entrypoint's host. The run reads the exit code once it ends.
    host: crate::box_runtime::HostHandle,
    /// Where the box's record is read from once the entrypoint ends: the
    /// box's actor stops with the box, so its handle answers no more.
    record_dir: boxes::store::BoxDir,
    box_id: SessionId,
    box_name: String,
    task: String,
    span: tracing::Span,
    stdio: Option<(
        Option<tokio::net::unix::pipe::Sender>,
        tokio::io::DuplexStream,
        tokio::io::DuplexStream,
    )>,
    /// The copies of the entrypoint's stdout and stderr to the run.
    relays: Vec<JoinHandle<()>>,
    released: bool,
}

/// The exit code a task run returns for the end its box's record keeps,
/// as `min` gives it for each end. `None` while the record keeps no end.
fn entrypoint_end_code(state: boxes::core::record::RecordState) -> Option<i32> {
    use boxes::core::record::{ExitEnding, RecordState, StopEnding};
    match state {
        RecordState::Exited(ExitEnding::Exit { exit_code })
        | RecordState::Stopped(StopEnding::ExitedFirst { exit_code }) => Some(exit_code),
        // 124 for a run past its timeout, and the 137 the record keeps for
        // an OOM kill (BOX-011).
        RecordState::Exited(ExitEnding::Timeout) => Some(124),
        RecordState::Exited(ExitEnding::Oom) => Some(137),
        // A stop by a signal borrows the shell's 128 + signal, so a `min
        // box stop` (SIGTERM) gives 143. A box the daemon found running at
        // its start was killed with it, as SIGKILL ends a process: 137.
        RecordState::Stopped(StopEnding::Signalled { signal }) => Some(128 + signal),
        RecordState::Stopped(StopEnding::AtDaemonStart) => Some(137),
        _ => None,
    }
}

impl EntrypointProcess {
    /// The exit code for the end the box's record keeps once its
    /// entrypoint ended ([`entrypoint_end_code`]).
    async fn recorded_code(&self) -> io::Result<Option<i32>> {
        let deadline = tokio::time::Instant::now() + ENTRYPOINT_RECORD_WAIT;
        loop {
            let dir = self.record_dir.clone();
            let record = crate::traced::spawn_blocking(move || dir.record())
                .await
                .map_err(io::Error::other)??;
            if let Some(code) = record.state().ok().and_then(entrypoint_end_code) {
                return Ok(Some(code));
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(io::Error::other(
                    "the task box's entrypoint ended, and its record keeps no exit code",
                ));
            }
            tokio::time::sleep(ENTRYPOINT_POLL).await;
        }
    }
}

impl Process for EntrypointProcess {
    type Stdin = std::pin::Pin<Box<dyn AsyncWrite + Send + Unpin>>;
    type Stdout = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;
    type Stderr = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        // The client's stdin goes to the entrypoint's stdin, and the
        // bridge closes it at the client's EOF. Stdout and stderr are the
        // entrypoint's, as two streams.
        let (stdin, stdout, stderr) = self.stdio.take()?;
        let stdin: Self::Stdin = match stdin {
            Some(stdin) => Box::pin(stdin),
            None => Box::pin(tokio::io::sink()),
        };
        Some((stdin, Box::pin(stdout), Box::pin(stderr)))
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        if self.released {
            return Ok(None);
        }
        // One at a time, and each removed once it ended: the bridge can
        // drop this future and poll `wait` again.
        while let Some(relay) = self.relays.first_mut() {
            let _ = relay.await;
            self.relays.remove(0);
        }
        // A relay can stop before the entrypoint ends, when nobody reads
        // the run. The code comes only when the host ends, so wait for that.
        while self.host.is_alive() {
            tokio::time::sleep(ENTRYPOINT_POLL).await;
        }
        let code = self.recorded_code().await;
        let _entered = self.span.enter();
        match &code {
            Ok(code) => tracing::info!(
                box_id = %self.box_id,
                box_name = %self.box_name,
                task = %self.task,
                exit_code = ?code,
                "task run: returned the entrypoint's exit code"
            ),
            Err(error) => tracing::warn!(
                box_id = %self.box_id,
                box_name = %self.box_name,
                task = %self.task,
                %error,
                "task run: the entrypoint ended, and the run has no exit code"
            ),
        }
        code
    }

    fn start_kill(&mut self) -> io::Result<()> {
        // BOX-015: the loss of the run's client never stops the box. The
        // relay stops, and the box's entrypoint runs on.
        self.released = true;
        for relay in self.relays.drain(..) {
            relay.abort();
        }
        let _entered = self.span.enter();
        tracing::info!(
            box_id = %self.box_id,
            task = %self.task,
            "task run: the client left; the box runs on"
        );
        Ok(())
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

/// A synthetic [`Process`] for a task run the daemon refused to start: it
/// writes the refusal on stderr and exits with its code, 1 unless set,
/// without spawning anything.
pub struct RefusedProcess {
    /// `Some` until `take_stdio` hands the streams out; `None` thereafter.
    stderr: Option<Vec<u8>>,
    /// The exit code the run returns.
    code: i32,
}

impl RefusedProcess {
    fn new(text: &str) -> Self {
        Self::with_code(text, 1)
    }

    /// A refusal that exits with `code`.
    fn with_code(text: &str, code: i32) -> Self {
        Self {
            stderr: Some(format!("{text}\n").into_bytes()),
            code,
        }
    }
}

impl Process for RefusedProcess {
    type Stdin = std::pin::Pin<Box<dyn AsyncWrite + Send + Unpin>>;
    type Stdout = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;
    type Stderr = std::pin::Pin<Box<dyn AsyncRead + Send + Unpin>>;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        let bytes = self.stderr.take()?;
        Some((
            Box::pin(tokio::io::sink()),
            Box::pin(tokio::io::empty()),
            Box::pin(std::io::Cursor::new(bytes)),
        ))
    }

    async fn wait(&mut self) -> io::Result<Option<i32>> {
        Ok(Some(self.code))
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

    /// Whether the spec stored beside the box's record lets the box run
    /// commands (BOX-153). It reads only `io.exec_enabled`, as the PTY
    /// check of a resume reads `io.pty_enabled`. A box with no stored spec,
    /// or a spec without a `false` key, takes commands. The gate fails
    /// closed: a stored spec that cannot be read or does not parse refuses.
    pub(crate) fn exec_gate(&self) -> ExecGate {
        match std::fs::read(self.dir.join(boxes::store::SPEC_FILE)) {
            Ok(bytes) => match stored_spec_disables_exec(&bytes) {
                Some(true) => ExecGate::Disabled,
                Some(false) => ExecGate::Enabled,
                None => {
                    tracing::warn!(
                        box_id = %self.record.id,
                        "exec: the box's stored spec does not parse; exec refused"
                    );
                    ExecGate::SpecUnreadable
                }
            },
            Err(error) if error.kind() == io::ErrorKind::NotFound => ExecGate::Enabled,
            Err(error) => {
                tracing::warn!(
                    box_id = %self.record.id,
                    %error,
                    "exec: could not read the box's stored spec; exec refused"
                );
                ExecGate::SpecUnreadable
            }
        }
    }

    /// Writes one exec event about `id` to the box's events file
    /// (BOX-152): the exec's id, mode, PTY flag, principal and argv, and
    /// for an `exec_exited` event its exit code and reason. A failed write
    /// is logged and never ends the exec.
    pub(crate) fn write_event(
        &self,
        kind: boxes::events::BoxEventType,
        id: &ExecId,
        mode: ExecMode,
        facts: &ExecFacts,
        exit: Option<ExecExit>,
    ) {
        use boxes::events::exec_data;
        let mut event = boxes::events::BoxEvent::for_record(&self.record, kind);
        event
            .data
            .insert(exec_data::EXEC_ID.into(), id.as_str().into());
        event
            .data
            .insert(exec_data::MODE.into(), mode.name().into());
        event
            .data
            .insert(exec_data::PTY.into(), (mode == ExecMode::Tty).into());
        event
            .data
            .insert(exec_data::PRINCIPAL.into(), facts.principal.as_str().into());
        event.data.insert(
            exec_data::ARGV.into(),
            serde_json_lenient::Value::Array(
                facts.argv.iter().map(|word| word.as_str().into()).collect(),
            ),
        );
        if let Some(exit) = exit {
            event.data.insert(
                exec_data::EXIT_CODE.into(),
                exit.code
                    .map_or(serde_json_lenient::Value::Null, Into::into),
            );
            event
                .data
                .insert(exec_data::REASON.into(), exit.reason.name().into());
        }
        #[cfg(test)]
        if kind == boxes::events::BoxEventType::ExecStarted {
            stop_at_start::observe(self.record.id, id);
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

/// What the stored spec says about exec (BOX-153).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExecGate {
    /// The box takes commands.
    Enabled,
    /// The spec sets `io.exec_enabled = false`.
    Disabled,
    /// A stored spec exists but cannot be read or parsed, so the gate
    /// refuses.
    SpecUnreadable,
}

/// Whether the spec `bytes` set `io.exec_enabled = false` (BOX-153).
/// `None` when the bytes do not parse as a JSON object.
pub(crate) fn stored_spec_disables_exec(bytes: &[u8]) -> Option<bool> {
    let spec = serde_json_lenient::from_slice::<serde_json_lenient::Value>(bytes).ok()?;
    if !spec.is_object() {
        return None;
    }
    Some(
        spec.get("io")
            .and_then(|io| io.get("exec_enabled")?.as_bool())
            == Some(false),
    )
}

/// Who ran an exec and what it ran, as its events carry them (BOX-152).
#[derive(Debug, Clone, Default)]
pub(crate) struct ExecFacts {
    /// The user the exec request came from.
    pub(crate) principal: String,
    /// The exec's argv, as the client sent it.
    pub(crate) argv: Vec<String>,
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
    /// Who ran the exec and what it runs, for its events.
    pub(crate) facts: ExecFacts,
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
    command: std::process::Command,
    graceful: bool,
) -> io::Result<Arc<ExecEntry>> {
    start_managed_exec_within(start, command, graceful, HeldInputLimits::for_daemon())
}

/// [`start_managed_exec`], with the bounds on what a tty exec's terminal
/// holds of the input that clients type.
pub(super) fn start_managed_exec_within(
    start: ManagedStart,
    mut command: std::process::Command,
    graceful: bool,
    input_limits: HeldInputLimits,
) -> io::Result<Arc<ExecEntry>> {
    let ManagedStart {
        id,
        mode,
        exec_box,
        timeout,
        winsize,
        facts,
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
    // The pump and the feed wait for the descriptor in the runtime, not in a
    // blocking thread, so the supervisor can stop them. A write to a terminal
    // whose program reads nothing would otherwise hold a thread for good.
    crate::net::switch::set_nonblocking(std::os::fd::AsRawFd::as_raw_fd(&source))?;
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
            let (terminal, input) = ExecTerminal::new(input_limits);
            let writer = source.try_clone()?;
            (Some(terminal), Some((writer, input)))
        }
        ExecMode::Detached | ExecMode::Attached => (None, None),
    };
    // The stop is registered before the entry, and both before
    // `exec_started`. A stop of the id that a follower of the events sees
    // first then finds the exec and ends it (BOX-151).
    let stop = register_stop(&id);
    let entry = Arc::new(ExecEntry::new(
        id.clone(),
        exec_box.record.id,
        mode,
        facts.argv.clone(),
        transcript_path,
        terminal,
    ));
    register_exec(Arc::clone(&entry));
    exec_box.write_event(
        boxes::events::BoxEventType::ExecStarted,
        &id,
        mode,
        &facts,
        None,
    );
    tracing::info!(
        exec_id = %id,
        mode = mode.name(),
        timeout_secs = timeout.map(|t| t.as_secs()),
        transcript = %entry.transcript,
        "exec started"
    );

    let pump = spawn(pump_output(Arc::clone(&entry), source, transcript));
    let feed = feed.map(|(writer, input)| spawn(feed_terminal(writer, input)));
    spawn(supervise_managed_exec(
        Arc::clone(&entry),
        process,
        timeout,
        pump,
        feed,
        exec_box,
        facts,
        stop,
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
#[expect(
    clippy::too_many_arguments,
    reason = "the exec's process, its helpers and its facts, from one call site"
)]
async fn supervise_managed_exec(
    entry: Arc<ExecEntry>,
    mut process: TokioProcess,
    timeout: Option<Duration>,
    mut pump: JoinHandle<()>,
    feed: Option<JoinHandle<()>>,
    exec_box: ExecBox,
    facts: ExecFacts,
    stop: CancellationToken,
) {
    let (status, reason) = wait_or_stop(&mut process, timeout, &stop, &entry.id).await;
    forget_stop(&entry.id);
    entry.close_input();
    // Nothing reads the terminal now. A feed that waits to write ends here.
    if let Some(feed) = feed {
        feed.abort();
    }
    // The pump stops at the drain, in every mode. A descendant that keeps
    // the terminal or the pipe open must not hold the pump, its descriptor
    // and its transcript file for the daemon's life. The pump waits in the
    // runtime, not in a blocking thread, so the abort ends it.
    if tokio::time::timeout(TERMINAL_DRAIN, &mut pump)
        .await
        .is_err()
    {
        tracing::info!(
            exec_id = %entry.id,
            mode = entry.mode.name(),
            "exec: output still open after the exit; the transcript stops here"
        );
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
        &facts,
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

/// The stop of every exec that still runs, by its id (BOX-151): a tty or a
/// detached exec, and an attached one.
/// The supervisor of the exec removes its token when the exec ends.
static STOPS: std::sync::LazyLock<std::sync::Mutex<BTreeMap<ExecId, CancellationToken>>> =
    std::sync::LazyLock::new(Default::default);

pub(crate) fn register_stop(id: &ExecId) -> CancellationToken {
    let token = CancellationToken::new();
    STOPS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id.clone(), token.clone());
    token
}

pub(crate) fn forget_stop(id: &ExecId) {
    STOPS.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
}

/// How a stop of one exec ended (BOX-151).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExecStopAnswer {
    /// How the exec ended.
    pub(crate) exit: ExecExit,
    /// Set when the exec had already ended before the stop, so the stop
    /// sent no signal.
    pub(crate) already_ended: bool,
}

/// Fires the stop of the exec `id` of the box `box_id` (BOX-151). Answers
/// the exec's entry, and whether a stop token was still there to fire.
/// `None` when this daemon holds no entry for that exec.
fn fire_stop(box_id: SessionId, id: &ExecId) -> Option<(Arc<ExecEntry>, bool)> {
    let entry = find_exec(box_id, id)?;
    let token = STOPS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(id)
        .cloned();
    let fired = match token {
        Some(token) => {
            tracing::info!(exec_id = %id, %box_id, "exec stop requested");
            token.cancel();
            true
        }
        None => {
            tracing::info!(exec_id = %id, %box_id, "exec stop: the exec already ended");
            false
        }
    };
    Some((entry, fired))
}

/// Stops the exec `id` of the box `box_id` and waits for its end (BOX-151):
/// SIGTERM to its process group, a wait, then SIGKILL, through
/// [`Process::start_kill`] of the injection shim. Only that exec ends. The
/// box and its other execs keep running. An exec that already ended
/// answers with its exit. `None` when this daemon holds no entry for exec
/// `id` in that box. The caller then reads the box's events for an exec
/// that a daemon before a restart started, with [`stored_exec_exit`].
pub(crate) async fn stop_exec(box_id: SessionId, id: &ExecId) -> Option<ExecStopAnswer> {
    let (entry, fired) = fire_stop(box_id, id)?;
    Some(ExecStopAnswer {
        exit: entry.wait().await,
        already_ended: !fired,
    })
}

/// A test hook that stops an exec at the earliest point its id is
/// observable: when its `exec_started` event is written (BOX-151).
#[cfg(test)]
pub(crate) mod stop_at_start {
    use super::*;

    /// The boxes whose execs the hook stops, and for each exec it saw,
    /// whether the stop found the exec and fired.
    static ARMED: std::sync::LazyLock<
        std::sync::Mutex<BTreeMap<SessionId, BTreeMap<ExecId, bool>>>,
    > = std::sync::LazyLock::new(Default::default);

    /// Stops every exec of `box_id` as its `exec_started` is written.
    pub(crate) fn arm(box_id: SessionId) {
        ARMED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(box_id, BTreeMap::new());
    }

    /// The execs of `box_id` the hook saw, and whether each stop fired.
    pub(crate) fn seen(box_id: SessionId) -> BTreeMap<ExecId, bool> {
        ARMED
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&box_id)
            .cloned()
            .unwrap_or_default()
    }

    pub(super) fn observe(box_id: SessionId, id: &ExecId) {
        let mut armed = ARMED.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(seen) = armed.get_mut(&box_id) {
            let fired = matches!(fire_stop(box_id, id), Some((_, true)));
            seen.insert(id.clone(), fired);
        }
    }
}

/// Waits for `process` as [`wait_with_timeout`] does, and ends it when
/// `stop` fires (BOX-151).
async fn wait_or_stop<P: Process>(
    process: &mut P,
    timeout: Option<Duration>,
    stop: &CancellationToken,
    id: &ExecId,
) -> (io::Result<Option<i32>>, ExecExitReason) {
    let ended = tokio::select! {
        out = wait_with_timeout(process, timeout) => Some(out),
        () = stop.cancelled() => None,
    };
    if let Some(out) = ended {
        return out;
    }
    if let Err(error) = process.start_kill() {
        tracing::warn!(exec_id = %id, %error, "exec: failed to stop the command");
    }
    let status = wait_after_stop(process).await;
    tracing::info!(exec_id = %id, "exec stopped");
    (status, ExecExitReason::Exited)
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
pub(super) fn open_terminal(
    (rows, cols): (u16, u16),
) -> io::Result<(std::fs::File, std::fs::File)> {
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
    use std::io::Read as _;

    // SAFETY: the `AsyncFd` owns `source` for its whole life, and nothing
    // else closes or reuses the descriptor while it is registered.
    let source = match unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(source, tokio::io::Interest::READABLE)
    } {
        Ok(source) => source,
        Err(error) => {
            tracing::warn!(exec_id = %entry.id, %error, "exec: could not watch the output");
            return;
        }
    };
    let mut buf = vec![0u8; 8192];
    loop {
        let mut ready = match source.readable().await {
            Ok(ready) => ready,
            Err(error) => {
                tracing::warn!(exec_id = %entry.id, %error, "exec: output read failed");
                break;
            }
        };
        let closed = ready.ready().is_read_closed();
        match ready.try_io(|fd| fd.get_ref().read(&mut buf)) {
            // A closed state is never cleared, so a wait for it returns at
            // once: with nothing to read, the output has ended.
            Err(_would_block) if closed => break,
            Err(_would_block) => continue,
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => entry.record_output(&mut transcript, &buf[..n]),
            Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => continue,
            Ok(Err(e)) if e.raw_os_error() == Some(libc::EIO) => break,
            Ok(Err(error)) => {
                tracing::warn!(exec_id = %entry.id, %error, "exec: output read failed");
                break;
            }
        }
    }
}

/// Writes what attached clients type to a tty exec's terminal, until the
/// exec ends: its supervisor then clears the input and stops this feed.
/// Each read releases its bytes from the held counts, so a terminal that
/// takes nothing leaves the rest held, within the bounds.
async fn feed_terminal(master: std::fs::File, mut input: HeldInputReader) {
    use std::io::Write as _;

    // SAFETY: the `AsyncFd` owns `master` for its whole life, and nothing
    // else closes or reuses the descriptor while it is registered.
    let Ok(master) = (unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(master, tokio::io::Interest::WRITABLE)
    }) else {
        return;
    };
    let mut buf = vec![0u8; 8192];
    loop {
        let n = match input.read(&mut buf).await {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let mut rest = &buf[..n];
        while !rest.is_empty() {
            let Ok(mut ready) = master.writable().await else {
                return;
            };
            let closed = ready.ready().is_write_closed();
            match ready.try_io(|fd| fd.get_ref().write(rest)) {
                // A closed state is never cleared, so a wait for it returns
                // at once: the program is gone and nothing reads the
                // terminal. Without this the feed spins in one poll.
                Err(_would_block) if closed => return,
                Err(_would_block) => {}
                Ok(Ok(0)) => return,
                Ok(Ok(written)) => rest = &rest[written..],
                Ok(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {}
                Ok(Err(_)) => return,
            }
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
    /// Fires when a stop of the exec's id ends it (BOX-151).
    pub stop: CancellationToken,
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
            stop,
        } = self;
        inner
            .exec(session)
            .map(move |spawned| {
                spawned.map(|inner| TimedProcess {
                    inner,
                    deadline: timeout_deadline(timeout),
                    timed_out: Arc::clone(&timed_out),
                    stop: stop.clone(),
                    stopped: false,
                })
            })
            .boxed()
    }
}

/// When an exec's own `timeout` runs out, from now. A timeout too far out
/// for the clock to hold is no deadline: the box's own ceilings still
/// apply, and the exec is not refused after its process started.
pub(crate) fn timeout_deadline(timeout: Option<Duration>) -> Option<tokio::time::Instant> {
    timeout.and_then(|t| tokio::time::Instant::now().checked_add(t))
}

/// A [`Process`] that [`Process::start_kill`]s itself at its deadline, or
/// when a stop of its exec fires.
#[derive(Debug)]
pub struct TimedProcess<P> {
    pub(super) inner: P,
    pub(super) deadline: Option<tokio::time::Instant>,
    pub(super) timed_out: Arc<AtomicBool>,
    pub(super) stop: CancellationToken,
    /// Set once the stop asked the process to end.
    pub(super) stopped: bool,
}

impl<P: Process> Process for TimedProcess<P> {
    type Stdin = P::Stdin;
    type Stdout = P::Stdout;
    type Stderr = P::Stderr;

    fn take_stdio(&mut self) -> Option<(Self::Stdin, Self::Stdout, Self::Stderr)> {
        self.inner.take_stdio()
    }

    // Cancel-safe: the deadline is fixed at the spawn, the inner `wait` is
    // cancel-safe, and `timed_out` and `stopped` are set before the next
    // await point.
    async fn wait(&mut self) -> io::Result<Option<i32>> {
        if !self.timed_out.load(Ordering::SeqCst) && !self.stopped {
            let deadline = self.deadline;
            let stop = self.stop.clone();
            let at_deadline = async move {
                match deadline {
                    Some(deadline) => tokio::time::sleep_until(deadline).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                status = self.inner.wait() => return status,
                () = at_deadline => {
                    self.timed_out.store(true, Ordering::SeqCst);
                    tracing::info!("exec: the command ran past its timeout; stopping it");
                    if let Err(error) = self.inner.start_kill() {
                        tracing::warn!(%error, "exec: failed to stop the command at its timeout");
                    }
                }
                () = stop.cancelled() => {
                    self.stopped = true;
                    tracing::info!("exec: a stop of the exec asked the command to end");
                    if let Err(error) = self.inner.start_kill() {
                        tracing::warn!(%error, "exec: failed to stop the command");
                    }
                }
            }
        }
        if self.stopped {
            let status = wait_after_stop(&mut self.inner).await;
            tracing::info!("exec stopped");
            return status;
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
    fn exit_notice(&mut self) -> Option<String> {
        self.inner.exit_notice()
    }
}

#[cfg(test)]
mod entrypoint_end_code_tests {
    use super::entrypoint_end_code;
    use boxes::core::record::{ExitEnding, RecordState, StopEnding};

    // BOX-038, T43: a task run returns a code for every end the box's
    // record keeps. A `min box stop` of a running task sends SIGTERM, so the
    // run returns 143.
    #[test]
    fn until_complete_ends_on_entrypoint_return_without_client_maps_each_end_to_a_code() {
        let end = |state| entrypoint_end_code(state);
        assert_eq!(
            end(RecordState::Stopped(StopEnding::Signalled { signal: 15 })),
            Some(143)
        );
        assert_eq!(
            end(RecordState::Stopped(StopEnding::Signalled { signal: 9 })),
            Some(137)
        );
        assert_eq!(
            end(RecordState::Stopped(StopEnding::AtDaemonStart)),
            Some(137)
        );
        assert_eq!(
            end(RecordState::Stopped(StopEnding::ExitedFirst {
                exit_code: 3
            })),
            Some(3)
        );
        assert_eq!(
            end(RecordState::Exited(ExitEnding::Exit { exit_code: 7 })),
            Some(7)
        );
        assert_eq!(end(RecordState::Exited(ExitEnding::Timeout)), Some(124));
        assert_eq!(end(RecordState::Exited(ExitEnding::Oom)), Some(137));
        assert_eq!(end(RecordState::Running), None);
    }
}
