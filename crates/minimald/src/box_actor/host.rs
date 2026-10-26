use super::*;

/// A launched host: its handle, paired with the `JoinHandle` of its runtime
/// loop so teardown can be awaited on destroy.
pub(super) type LaunchedHost = (
    box_runtime::HostHandle,
    JoinHandle<Result<i32, std::io::Error>>,
);

/// The `host_ip` launch's half of the cohort's QUIC stance (BEP-018): the
/// launched box joins the daemon's cohort with its resolved `quic443`
/// stance, and its processes move into the cohort's blocked leaf while any
/// member blocks. A box that is not a host-address box (no
/// `host_ip_enforcement`) shares no address and joins nothing.
///
/// # Errors
///
/// A [`crate::net::classifier::CohortPlaceError`] when the cohort blocks
/// and a member's processes cannot all be placed in the blocked leaf. The
/// box has left the cohort again by then, so a block it alone asked for is
/// lifted, and the caller fails the launch.
pub(super) fn join_quic443_cohort(
    record: &Record,
    host_ip_enforcement: Option<minimald_rpc::HostIpEnforcement>,
    root: &std::path::Path,
    cohort: &std::sync::Mutex<crate::net::classifier::CohortQuic443>,
    moves: &dyn crate::net::classifier::CgroupMoves,
) -> Result<(), crate::net::classifier::CohortPlaceError> {
    if host_ip_enforcement.is_none() || record.network != boxes::NetworkMode::HostNet {
        return Ok(());
    }
    let box_id = record.id.to_string();
    let blocked = crate::net::classifier::resolved_quic443_blocked(&record.policy);
    let placed =
        crate::net::classifier::cohort_quic443_admit_over(cohort, root, &box_id, blocked, moves);
    if let Err(error) = &placed {
        tracing::warn!(
            box_id,
            %error,
            "a host-address box could not be placed under the cohort's UDP 443 block; \
             its launch fails"
        );
        crate::net::classifier::cohort_quic443_depart_over(cohort, &box_id, moves);
    }
    placed
}

/// The refusal a launch ends with when [`join_quic443_cohort`] fails.
fn quic443_placement_refused(error: &crate::net::classifier::CohortPlaceError) -> std::io::Error {
    std::io::Error::other(format!(
        "the session was stopped because QUIC (UDP to port 443) could not be blocked for it. \
         Every session that runs with the host's address gets this block while the \
         quic443 setting of one of them blocks QUIC. The cause: {error}"
    ))
}

/// The stop's half of the cohort's QUIC stance (BEP-018): the box
/// `box_id` leaves the cohort, and when it was the last blocking member
/// every other member's processes move back to their own leaves.
pub(super) fn leave_quic443_cohort(
    box_id: &str,
    cohort: &std::sync::Mutex<crate::net::classifier::CohortQuic443>,
    moves: &dyn crate::net::classifier::CgroupMoves,
) {
    crate::net::classifier::cohort_quic443_depart_over(cohort, box_id, moves);
}

/// Which launch of each box holds its `host_ip` cohort membership
/// (BEP-018). A launch takes a new number before it joins, so the runtime
/// loop of a host it replaced cannot take the new launch's membership away
/// when that loop ends late.
#[derive(Debug, Default)]
pub(super) struct Quic443Launches {
    /// The number the next launch takes.
    next: u64,
    /// The launch that holds each member's place, by box id.
    current: std::collections::BTreeMap<String, u64>,
}

impl Quic443Launches {
    /// An empty table, for the daemon's one static.
    const fn new() -> Self {
        Self {
            next: 0,
            current: std::collections::BTreeMap::new(),
        }
    }
}

/// The daemon's one table of cohort launches.
static QUIC443_LAUNCHES: std::sync::Mutex<Quic443Launches> =
    std::sync::Mutex::new(Quic443Launches::new());

/// The daemon's one table of cohort launches, for the launch and stop paths.
pub(super) fn quic443_launches() -> &'static std::sync::Mutex<Quic443Launches> {
    &QUIC443_LAUNCHES
}

fn lock_launches(
    launches: &std::sync::Mutex<Quic443Launches>,
) -> std::sync::MutexGuard<'_, Quic443Launches> {
    launches
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether a launch of `record` joins the `host_ip` cohort: a host-address
/// box that the launch placed. [`join_quic443_cohort`] joins exactly these.
pub(super) fn joins_quic443_cohort(
    record: &Record,
    host_ip_enforcement: Option<minimald_rpc::HostIpEnforcement>,
) -> bool {
    host_ip_enforcement.is_some() && record.network == boxes::NetworkMode::HostNet
}

/// Gives the box `box_id` a new launch number, before that launch joins the
/// cohort. Any earlier launch of the box stops holding its place.
pub(super) fn begin_quic443_launch(
    box_id: &str,
    launches: &std::sync::Mutex<Quic443Launches>,
) -> u64 {
    let mut launches = lock_launches(launches);
    launches.next += 1;
    let launch = launches.next;
    launches.current.insert(box_id.to_string(), launch);
    launch
}

/// The stop's departure, with the launch table: the box `box_id` leaves the
/// cohort whichever launch joined it, and no launch holds its place after.
pub(super) fn stop_quic443_launch(
    box_id: &str,
    launches: &std::sync::Mutex<Quic443Launches>,
    cohort: &std::sync::Mutex<crate::net::classifier::CohortQuic443>,
    moves: &dyn crate::net::classifier::CgroupMoves,
) {
    let mut launches = lock_launches(launches);
    launches.current.remove(box_id);
    leave_quic443_cohort(box_id, cohort, moves);
}

/// The exit path's half of the cohort's QUIC stance (BEP-018): the host
/// process of launch `launch` ended on its own, so the box `box_id` leaves
/// the cohort as a stop makes it leave. When it was the last blocking
/// member, the other members move back to their own leaves. A launch that
/// no longer holds the box's place changes nothing. Returns whether the box
/// left.
pub(super) fn exit_quic443_launch(
    box_id: &str,
    launch: u64,
    launches: &std::sync::Mutex<Quic443Launches>,
    cohort: &std::sync::Mutex<crate::net::classifier::CohortQuic443>,
    moves: &dyn crate::net::classifier::CgroupMoves,
) -> bool {
    let mut launches = lock_launches(launches);
    if launches.current.get(box_id) != Some(&launch) {
        return false;
    }
    launches.current.remove(box_id);
    leave_quic443_cohort(box_id, cohort, moves);
    let blocking: Vec<String> = cohort
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .blocking_members()
        .map(str::to_string)
        .collect();
    drop(launches);
    tracing::info!(
        box_id,
        blocking_members = ?blocking,
        "a host-address box's shell exited on its own; the box left the cohort's \
         UDP 443 stance"
    );
    true
}

/// Where a host's exit is observed for the cohort: the launch, the box and
/// the cohort it leaves.
pub(super) struct Quic443Exit {
    pub(super) box_id: String,
    pub(super) launch: u64,
    pub(super) launches: &'static std::sync::Mutex<Quic443Launches>,
    pub(super) cohort: &'static std::sync::Mutex<crate::net::classifier::CohortQuic443>,
    pub(super) moves: &'static (dyn crate::net::classifier::CgroupMoves + Sync),
}

/// Aborts the host's runtime loop when the task that watches it is
/// aborted, so an abort of the watched handle reaches the loop as before.
struct AbortLoopOnDrop(Option<tokio::task::AbortHandle>);

impl AbortLoopOnDrop {
    /// The loop ended by itself: nothing is left to abort.
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for AbortLoopOnDrop {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

/// Watches a `host_ip` box's runtime loop `task`. When the loop ends, the
/// host process exited, and the box leaves the cohort
/// ([`exit_quic443_launch`]). The handle it returns stands in for `task`:
/// it yields the loop's result, and an abort of it aborts the loop. An
/// aborted loop leaves nothing here, because the stop that aborts it leaves
/// the cohort itself.
pub(super) fn watch_quic443_exit(
    task: JoinHandle<Result<i32, std::io::Error>>,
    exit: Quic443Exit,
) -> JoinHandle<Result<i32, std::io::Error>> {
    let mut abort_loop = AbortLoopOnDrop(Some(task.abort_handle()));
    // The watcher lives as long as the loop it watches: its own root, as the
    // loop has.
    let root = tracing::info_span!(
        parent: None,
        "session.host.quic443_exit",
        box_id = %exit.box_id,
    );
    crate::traced::spawn_detached(root, async move {
        let result = task.await;
        abort_loop.disarm();
        // Leave before a panic unwinds: a loop that panicked still ends the
        // launch, and a blocking member must not keep the block in place.
        exit_quic443_launch(
            &exit.box_id,
            exit.launch,
            exit.launches,
            exit.cohort,
            exit.moves,
        );
        match result {
            Ok(result) => result,
            Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
            Err(error) => Err(std::io::Error::other(error)),
        }
    })
}

/// Where in the session lifecycle a host launch is happening, which decides
/// whether the launch has to wait for an `Active` record.
///
/// Only [`BoxActor::finalize`]'s launch is `Activating`. Every other
/// launch happens after the session is attachable and keeps the status gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchPhase {
    /// A launch against a session that is already `Active`: an attach, or an
    /// exec's [`BoxActor::ensure_host`]. Both check the record's status
    /// themselves before getting here; the gate in [`BoxActor::context`] is
    /// their backstop.
    Attached,
    /// The pre-activation launch inside [`BoxActor::finalize`]. It runs while
    /// the record is still `Materializing` by construction — promoting to
    /// `Active` is what finalize does *after* the activation hooks this host
    /// exists to run — so it cannot take the `Active` gate without
    /// deadlocking against itself.
    Activating,
}

/// How long *all* of a teardown transition's hooks get, together.
///
/// A hook's own timeout is capped at
/// [`MAX_HOOK_TIMEOUT`](boxes::core::lifecyclehook::MAX_HOOK_TIMEOUT)
/// to keep one from holding a session open, but nothing bounds how many
/// hooks a composition may carry — so without a total, N of them at the
/// cap would hold a destroy for N×5 minutes and defeat the point. This
/// is that total. Wide enough that an honest teardown never meets it;
/// the hooks are a courtesy, and the destroy is the contract.
pub(super) const TEARDOWN_HOOK_BUDGET: std::time::Duration = std::time::Duration::from_secs(120);

/// How long a teardown transition will wait for the sandbox it needs to
/// run its hooks in.
///
/// Nothing else about a host launch is time-bounded, because every other
/// caller is a user waiting on their own attach. A teardown is not: the
/// hooks are a courtesy and the destroy is the contract, so the launch
/// gets a deadline and the session is torn down either way. Generous
/// enough to cover a cold cache on a loaded box — this is a backstop
/// against a wedge, not a performance budget.
pub(super) const HOOK_LAUNCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// Deadline for a read-only probe of a session's host — the terminal
/// attributes and the screen snapshot.
///
/// Spawning those probes off the session actor (see
/// [`BoxActor::handle_message`]) keeps the *actor* responsive, but says
/// nothing about the spawned task: against a host that never answers, an
/// unbounded probe outlives every caller that gave up on it. Nor does it
/// stay parked in the same place:
/// [`HOST_MAILBOX_CAPACITY`](crate::box_runtime::HOST_MAILBOX_CAPACITY)
/// messages in, a wedged host's mailbox is full and the probe blocks in
/// `send` rather than `recv` — still forever, and still one stranded task
/// per poll. `min dash` polls the focused session's screen on every refresh
/// tick, which makes that leak unbounded in the one case the bound exists
/// for.
///
/// So the probe is bounded here too, not only at its callers: a task that
/// cannot answer within the deadline ends, and the caller reads the same
/// `None` a session with no running host already reports.
///
/// [`crate::box_manager::BoxManager`] bounds these probes again on its own
/// mainloop. That is not redundant — this deadline covers a wedged *host*,
/// and the manager's covers a wedged *session actor*, which can be parked in
/// an inline `EnsureHost`, `Attach`, or `ConfigureLoadout` and never reach
/// the spawn at all.
pub(crate) const HOST_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Awaits a host probe under [`HOST_PROBE_TIMEOUT`], collapsing both a
/// missed deadline and a dead host to `None`.
pub(crate) async fn probe_host<T>(
    probe: impl std::future::Future<Output = Result<T, ()>>,
) -> Option<T> {
    tokio::time::timeout(HOST_PROBE_TIMEOUT, probe)
        .await
        .ok()?
        .ok()
}

/// The PTY size a host minted with nothing attached starts at. A client that
/// attaches later resizes it; until then only an unattached shell sees it.
pub(super) const UNATTACHED_WIN_SIZE: WinSize = WinSize {
    rows: 24,
    cols: 80,
    xpixel: 0,
    ypixel: 0,
};

/// Why a session host was launched.
///
/// The sandbox and the interactive shell are one spawn — the shell *is* the
/// sandbox's session leader — so a launch that only wanted the sandbox still
/// creates the shell a user may later attach to, and that shell's `environ`
/// is fixed for its lifetime. This records which case a live host is in, so
/// an attach can tell "the shell was made for a terminal" from "the shell was
/// made for a hook, and no terminal has ever described itself to it".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostOrigin {
    /// Minted by an attach, from a client with a PTY. Its environment already
    /// describes a terminal.
    Interactive,
    /// Minted by [`BoxActor::launch_host_for_hooks`] to run lifecycle hooks.
    /// Nothing of the user's runs in it: its shell waits at the launch's
    /// start gate, before it execs, until an attach releases it (see
    /// `box_runtime::Launched::start_gate`), so neither the shell nor its
    /// startup files have run when an attach arrives, and it is safe to
    /// replace. A host kept instead ([`replaces_host_for_terminal`]) starts
    /// its shell at that attach, after the activate hooks.
    Hooks,
    /// Minted by [`BoxActor::ensure_host`] to serve an exec. The command is
    /// live inside that sandbox, so replacing the shell would kill it — this
    /// one is never respawned, and the attaching terminal's facts reach it
    /// through the per-attach environment instead.
    Exec,
}

/// Whether replacing a live host for an attaching terminal is safe for the
/// box it serves. A [`HostOrigin::Hooks`] host is replaceable — nothing of
/// the user's runs in it — unless the record holds a registered host-side
/// row: on a VM-backed host, ending that host's PTask ends the shuttle
/// connection the row is tied to, and the in-VM daemon cannot re-register
/// it, so a respawn would strand the box with no row. The guard is the
/// record's handed `box_addresses`, not a VM check, so any registered box is
/// kept, native ones included: keeping costs nothing, because the terminal
/// rides the per-attach environment the host republishes, exactly as it does
/// for an [`HostOrigin::Exec`] host.
pub(super) fn replaces_host_for_terminal(
    origin: HostOrigin,
    declares_terminal: bool,
    holds_host_row: bool,
) -> bool {
    origin == HostOrigin::Hooks && declares_terminal && !holds_host_row
}

impl BoxActor {
    /// Kills `host` and stops its runtime loop `task`, bounded so a wedged
    /// host cannot park the caller. Both the kill and the wait for the loop to
    /// act on it are bounded: `HostHandle::kill`'s `send_timeout` only bounds
    /// the wait for mailbox *capacity*, so a loop parked mid-`step()` (mailbox
    /// nearly empty) queues the kill yet never processes it, and awaiting that
    /// loop unbounded would park the caller behind it forever.
    ///
    /// When the kill cannot be queued the loop is aborted. When the kill
    /// landed but the loop does not finish within `HOST_PROBE_TIMEOUT`, the
    /// task is detached rather than aborted so the `NetGuard` teardown at the
    /// end of `Host::mainloop` can still run once the loop drains.
    pub(super) async fn kill_and_stop_loop(
        host: &box_runtime::HostHandle,
        task: &mut JoinHandle<Result<i32, std::io::Error>>,
        for_shutdown: bool,
    ) {
        let killed = host.kill(for_shutdown).await.is_ok();
        if !killed {
            // The kill could not be queued — the host is wedged past the
            // mailbox-capacity deadline. Abort the loop; the NetGuard
            // teardown in mainloop is skipped, but the host was already
            // unreachable.
            task.abort();
        } else if tokio::time::timeout(HOST_PROBE_TIMEOUT, &mut *task)
            .await
            .is_err()
        {
            // The kill landed but the loop did not finish within the
            // deadline. Detach rather than abort: the task continues
            // running and will run the NetGuard teardown at the end of
            // mainloop once it drains. Dropping the JoinHandle (when the
            // caller's `task` binding goes out of scope) detaches it.
            //
            // worker-iterate: declined CodeRabbit's "keep timed-out hosts
            // owned until cleanup is coordinated" finding. The suggested
            // change — retain the timed-out JoinHandle under supervision and
            // coordinate sandbox/NetGuard teardown before Destroy deletes the
            // session or terminal-triggered replacement mints a second host —
            // is a heavy architectural lift, not a behavior-preserving patch.
            // It would restructure `BoxInner` to hold and later await the
            // detached task and thread teardown coordination through both the
            // Destroy and replacement paths, a change that cannot be validated
            // here (the wedged-host scenario is not reproducible in this
            // environment) and that risks regressing the bounded-caller
            // response (`HOST_PROBE_TIMEOUT`) this function exists to
            // preserve. The detach-on-timeout trade-off is deliberate and
            // documented; full reclamation is a tracked follow-up.
        }
    }

    /// The actor's own answer to "is a box running behind this session": an
    /// `active` session holding a live host. A stopped box's record still
    /// reads `active`, but the actor resurrected for it holds no host — so
    /// this, not the record's status, is what a publish must consult (and
    /// what `IsBusy` consults for the same reason).
    pub(super) fn has_live_host(&self) -> bool {
        matches!(
            &self.inner,
            BoxInner::Active { host: Some((h, _)), .. } if h.is_alive()
        )
    }

    /// Tears down any runtime objects, such as the host or side ops. Shutdown
    /// of these objects is complete once awaited.
    ///
    /// `for_shutdown` is threaded to the host's kill so attached clients get
    /// the daemon-shutdown message (and a terminal reset) rather than a bare
    /// disconnect when the session dies because the daemon is going away.
    pub(super) async fn stop_running(&mut self, for_shutdown: bool) {
        // The session's forwards relay into its box: a session that is going
        // away takes them with it, rather than leaving live relays pointed at
        // a box that is being torn down. Both teardown paths — `Stop` and
        // `Destroy` — come through here.
        for forward in std::mem::take(&mut self.forwards) {
            forward.abort();
        }

        // The ports the box published at runtime go with it too (NET-044):
        // unbind each forward the switch accepted, so a box that stops leaves
        // no live publish behind. Best-effort, like the declared forwards'
        // teardown — `remove_ingress` logs a failed unexpose and moves on,
        // since there is no caller left to propagate to. This is the box's
        // one ingress *revocation*: it takes every runtime publication down
        // whoever published it — the expose surface's request-published
        // forwards above, the watcher's listener-published forwards in the
        // stop the host runs beside this — and the box's shared publication
        // set is revoked with them, without asking who owns what: the set
        // stops naming ports the revocation unbound, in the same turn, so a
        // publish asked in the window between this stop and the next launch
        // answers what stopped the box, not an entry whose publication came
        // down with it.
        let forwarders = self.live_ingress.take_all();
        self.publications.revoke_all();
        // A declared port bound for this box at a shared-address port's
        // hand-over (NET-129) goes the way the forwards its attach bound
        // go: unbound here on a native host, left for the host on a
        // VM-backed one.
        let handed = self.live_ingress.take_handed();
        if !handed.is_empty() {
            let control = self.switch_control().await;
            crate::net::policy::release_declared_ingress(&control, &handed).await;
        }
        if !forwarders.is_empty() {
            // The expose's revocation withdraws its admission at the box's
            // gate first (NET-044), so no new connection crosses the gap
            // between a port the gate still admits and a forward that is
            // coming down. A relay already gone took its gate with it.
            if let Some(gate) = self
                .reported_switch_address
                .and_then(crate::net::switch::live_gate)
            {
                for forwarder in &forwarders {
                    gate.withdraw_exposed(forwarder.internal_port());
                }
            }
            let control = self.switch_control().await;
            crate::net::policy::remove_ingress(&control, &forwarders).await;
            // The VM host daemon's row entries go with the forwards (T94,
            // NET-138): each port this box admitted against the host-held
            // grant is withdrawn once its forward is down — best-effort like
            // the unexpose beside it, because a report that fails leaves a
            // stale row entry, never a live forward, and the box's own
            // destroy clears the row whole. The revocation takes both runtime
            // surfaces' publishes down in one sweep and the runtime cell does
            // not keep which surface published what, so every withdrawal
            // rides the expose label: a withdrawal is never refused, and the
            // host removes the port whatever the label says — it is the
            // log's word, not the row's key.
            // The address the publishes were admitted under, kept from the
            // publish; the record's handed address only when no publish of
            // this surface was admitted (a listen-published port's watcher
            // withdraws its own).
            let switch_address = match self.reported_switch_address {
                Some(address) => Some(address),
                None => self.record.record().await.ok().and_then(|record| {
                    record
                        .box_addresses
                        .map(|addresses| addresses.switch_address)
                }),
            };
            if switch_address.is_none()
                && matches!(control, crate::net::policy::ControlChannel::Vsock { .. })
            {
                tracing::warn!(
                    session_id = %self.record.id(),
                    ports = forwarders.len(),
                    "no switch address to withdraw a stopped box's runtime ports from the \
                     VM host daemon; the host's row keeps them until the box is destroyed \
                     (see gominimal/inbox#914)"
                );
            }
            // The withdrawals run side by side under one shared bound: the
            // guest report door serves one connection at a time, so a door
            // that accepts and never answers would otherwise hold each
            // withdrawal's own deadline in turn. Past the bound the rest are
            // abandoned, best-effort like every withdrawal here.
            if let Some(switch_address) = switch_address {
                let withdrawals = forwarders.iter().map(|forwarder| {
                    let control = &control;
                    async move {
                        let port = forwarder.internal_port();
                        if let Err(error) = crate::net::listeners::report_withdrawn_port(
                            control,
                            switch_address,
                            port,
                            minimald_rpc::PortReportSource::Expose,
                        )
                        .await
                        {
                            tracing::warn!(
                                port,
                                reason = %error,
                                "reporting a stopped box's port withdrawal to the \
                                 VM host daemon failed; the host's row still names it"
                            );
                        }
                    }
                });
                if tokio::time::timeout(
                    crate::net::listeners::WITHDRAW_REPORT_DEADLINE,
                    futures::future::join_all(withdrawals),
                )
                .await
                .is_err()
                {
                    tracing::warn!(
                        ports = forwarders.len(),
                        "the stopped box's port withdrawals did not finish inside \
                         their shared deadline; the host's row may still name some"
                    );
                }
            }
        }

        // Runtime port-publish asks still waiting on a human (NET-045) fail
        // closed with the typed nobody-is-attached refusal: a session that is
        // going away has no attached human to answer them, and no caller can
        // be left parked on a reply that will never come. The decision is
        // audited like every other (NET-046) — and a late answer from the
        // task the ask routed through finds no ask left to answer.
        for ask in std::mem::take(&mut self.pending_asks) {
            if let Some(host_ask) = &ask.host_ask {
                host_ask.abort();
            }
            self.answer_expose(
                &ask.box_name,
                ask.port,
                boxes::DynamicIngress::Ask,
                crate::audit::DecidedBy::Daemon,
                Err(crate::net::policy::ExposeFailure::Refused(
                    crate::net::policy::ExposeRefusal::AskNeedsAnswer,
                )),
                ask.reply,
            )
            .await;
        }

        let inner = match &mut self.inner {
            BoxInner::Active { host, sops, .. } => Some((host.take(), std::mem::take(sops))),
            BoxInner::Draft { .. } => None,
        };
        // The host is out of the actor's hands now: out of the slot too, so a
        // handle that outlives a `Stop` reads no host rather than probing the
        // one being stopped.
        self.publish_host();
        if let Some((host, mut sops)) = inner {
            for s in sops.drain(..) {
                s.shutdown().await;
            }
            if let Some((host, mut task)) = host {
                // Signal the process to die, then stop its runtime loop so the
                // sandbox files backing its rootfs are released before the
                // caller removes the session's directory tree. The wait is
                // bounded and aborts a wedged loop rather than parking shutdown
                // behind it — see [`BoxActor::kill_and_stop_loop`].
                Self::kill_and_stop_loop(&host, &mut task, for_shutdown).await;
            }
        }
        // BEP-018: the stopped box leaves the `host_ip` cohort. When it was
        // the last blocking member, the other members move back to their
        // own leaves and send UDP 443 again. A box that never joined
        // changes nothing.
        stop_quic443_launch(
            &self.record.id().to_string(),
            quic443_launches(),
            crate::net::classifier::cohort_quic443(),
            &crate::net::classifier::KernelMoves,
        );
    }

    /// Launches a host for this session.
    ///
    /// The one path all callers take: [`Self::attach`], which has a client
    /// channel and passes it in as `progress` so the sandbox coming up is
    /// rendered on the client's terminal, [`Self::ensure_host`], which has
    /// no channel at all, and [`Self::launch_host_for_hooks`], which
    /// runs before the session is `Active` (hence `phase`). The channel goes
    /// in and comes back out because progress rendering borrows it for the
    /// duration; storing the result is left to the caller, since attach only
    /// keeps a host it could bind to.
    ///
    /// `for_hooks` says what the launch is *for*, which `phase` cannot say:
    /// the phase records the status-gate posture (an attach and a teardown
    /// hook launch are both `Attached`; finalize's activation launch is
    /// `Activating`), while this flag marks the launches minted only for
    /// lifecycle hooks, whose pty nobody reads. It is the launcher's to
    /// carry, so the launch-scoped decisions downstream (the
    /// unenforced-placement advisory) can tell a session start from a hook
    /// run.
    // Left positional: three call sites, each naming every argument it means,
    // so a struct would be ceremony rather than clarity.
    #[expect(
        clippy::too_many_arguments,
        reason = "three call sites, each naming every argument it means"
    )]
    pub(super) async fn launch_host(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
        sz: WinSize,
        attach_env: box_runtime::AttachEnv,
        progress: Option<ChannelProgress>,
        phase: LaunchPhase,
        for_hooks: bool,
    ) -> Result<(Option<Channel<Msg>>, LaunchedHost), AttachError> {
        // Taken first, so a confirmation never outlives the launch it was
        // read for, whichever way that launch ends.
        let rejoins_row = std::mem::take(&mut self.relaunch_row_confirmed) && !for_hooks;
        let record = self.record.record().await.unwrap();
        let paths = self.paths().await;
        // Kept before the launcher consumes `attach_env`: the launch folds
        // these into the shell's environment, and the host keeps them so it
        // can layer them onto everything it later runs in the session and
        // republish them for the shell to re-read. BEP-007: the grants'
        // sealed values join this layer here, so the shell's launch
        // environment holds them before its entrypoint runs.
        let mut attach_env = attach_env;
        // BEP-012: the proxy variables join the same layer, at the proxy's
        // address on this daemon's switch subnet.
        let subnet = self.net_switch.lock().await.subnet();
        box_runtime::place_launch_proxy_env(
            &mut attach_env,
            record.id,
            &box_runtime::launch_proxy_env(&record, subnet),
        );
        let connection_env = box_runtime::place_launch_deliveries(
            &mut attach_env,
            record.id,
            &box_runtime::launch_deliveries(&record),
        );
        let launcher = self
            .session_launcher(session_hnd, &record, attach_env, phase, for_hooks)
            .await?;
        // Where the shell-exit prompt's save-then-delete lane archives the
        // changed files. Daemon-side and session-independent; created on
        // demand at save time.
        let archives_dir = self
            .minimal_state_dir
            .as_utf8_path()
            .as_std_path()
            .join("archives");
        // Arm the workspace baseline once, before this session's first host
        // launches; a host rebuilt on reattach reuses it rather than
        // re-snapshotting the already-modified workspace. See
        // [`WorkspaceBaseline`].
        let delta = match &self.workspace_baseline {
            WorkspaceBaseline::Armed(delta) => delta.clone(),
            WorkspaceBaseline::Unarmed => {
                let workspace_root = paths.working.as_utf8_path().as_std_path().to_path_buf();
                let delta = self.load_or_arm_baseline(workspace_root).await;
                self.workspace_baseline = WorkspaceBaseline::Armed(delta.clone());
                delta
            }
        };
        // NET-129: the shared-address ports this box holds are the ones
        // this launch binds forwards for. Marked before the spawn binds
        // them, so no publish takes one from under the bind, and recorded
        // below so a restarted daemon gives them back to this box.
        #[cfg(target_os = "linux")]
        let bound_ports = matches!(record.network, boxes::NetworkMode::OwnIp).then(|| {
            self.hostnames
                .write()
                .expect("hostname registry lock poisoned")
                .mark_held_ports_bound(record.id)
        });
        let spawn = Box::pin(box_runtime::Host::spawn(
            launcher,
            box_runtime::HostParams {
                name: registry_name(&record),
                username: conn_username,
                paths,
                sz,
                channel: None,
                // Mint a handle to this session ID in the sessions actor/manager.
                control: Some(BoxControl::new(self.manager.clone(), record.id)),
                delta,
                archives_dir,
                // A registered box: its shell-exit prompt says a kept session's
                // network registration is restored on its next attach or exec
                // (NET-138).
                holds_host_row: record.box_addresses.is_some(),
                session_id: record.id,
                // The host runs attach and detach itself: it owns the terminal
                // they write to and the process whose namespaces they join.
                composition: self.composition(),
                connection_env,
                // The host owns the box's name-lifecycle half (NET-128): its
                // `mainloop` marks the name running on the way in and stopped
                // on the way out, so a shared-address name answers NODATA while
                // no host is alive to answer it.
                #[cfg(target_os = "linux")]
                name_marker: Some(box_runtime::NameMarker::new(
                    Arc::clone(&self.hostnames),
                    record.id,
                )),
            },
        ));

        let (channel, spawned) = match progress {
            Some(progress) => {
                let (channel, spawned) = progress.run(spawn).await;
                (Some(channel), spawned)
            }
            None => (None, spawn.await),
        };
        let (host, task, host_ip_enforcement) = spawned.map_err(|e| {
            AttachError::SpawnFailed(with_userns_hint(e, userns_spawn_hint().as_deref()))
        })?;
        // The confirmation was a read, not a reservation: the VM host daemon
        // may have withdrawn the row at its grace's end between that read
        // and this launch (NET-138). Read it again now the new host is up,
        // before the slot is marked as holding it; a row gone in between
        // ends the launch as the read before it would have.
        if rejoins_row && !self.host_row_stands(&record).await {
            let _ = host.kill(false).await;
            return Err(AttachError::BoxHostRowEnded);
        }
        // Whatever this launch replaces, the slot it goes into no longer
        // holds the launch that bound the box's host-side row; only the
        // binding launch itself, below, sets this again — or a relaunch the
        // VM host daemon just confirmed its standing row for, which rejoins
        // the switch under that row.
        self.slot_holds_row =
            record.box_addresses.is_some() && record.host_row_bound && rejoins_row;
        // The first launch of a registered box binds its host-side row
        // (NET-138). Recorded on the record, so a restarted daemon knows the
        // row is gone, before anything else can fail the launch: the kill
        // below ends the switch attachment, and with it the row, so a
        // binding not yet recorded by then would let a later launch run
        // rowless. A binding that cannot be recorded fails the launch the
        // same way.
        if record.box_addresses.is_some()
            && !record.host_row_bound
            && let Err(e) = self.record_host_row_bound().await
        {
            let _ = host.kill(false).await;
            return Err(AttachError::LaunchRecordUnwritable(e));
        }
        // NET-079: the launch that just ran records its own outcome for
        // this session's box on the box's record here — the one path every
        // launch takes, so an attach, an exec, an activation and a hook run
        // all record the placement they each made. A launch that cannot
        // record its outcome does not hand its box back: the reads would
        // answer the host's state for a box that did launch, which is what
        // a record exists to outrank, so the box is killed here and the
        // attach fails — and a record with no outcome keeps meaning "never
        // launched", the state a created session's reads answer.
        if let Err(e) = self.record_launch_outcome(host_ip_enforcement).await {
            let _ = host.kill(false).await;
            return Err(AttachError::LaunchRecordUnwritable(e));
        }
        // BEP-018: a `host_ip` box joins the cohort that shares its address,
        // with its resolved `quic443` stance. One blocked member moves the
        // cohort into the leaf the table rejects UDP 443 from. The move runs
        // after the spawn, because the launcher places the first process in
        // the box's own leaf.
        // A launch whose box cannot be placed under the block fails here,
        // and its box is killed: a blocked stance never fails open.
        // The launch number is taken before the join, so the loop of a host
        // this launch replaced cannot take the new membership away.
        let box_id = record.id.to_string();
        let joins = joins_quic443_cohort(&record, host_ip_enforcement);
        let launch = joins.then(|| begin_quic443_launch(&box_id, quic443_launches()));
        if let Err(error) = join_quic443_cohort(
            &record,
            host_ip_enforcement,
            std::path::Path::new(sandbox::classifier::TREE_ROOT),
            crate::net::classifier::cohort_quic443(),
            &crate::net::classifier::KernelMoves,
        ) {
            stop_quic443_launch(
                &box_id,
                quic443_launches(),
                crate::net::classifier::cohort_quic443(),
                &crate::net::classifier::KernelMoves,
            );
            let _ = host.kill(false).await;
            return Err(AttachError::SpawnFailed(quic443_placement_refused(&error)));
        }
        // BEP-018: a shell that exits on its own ends the host's loop with no
        // Stop. The box leaves the cohort then, as a stop makes it leave.
        let task = match launch {
            Some(launch) => watch_quic443_exit(
                task,
                Quic443Exit {
                    box_id,
                    launch,
                    launches: quic443_launches(),
                    cohort: crate::net::classifier::cohort_quic443(),
                    moves: &crate::net::classifier::KernelMoves,
                },
            ),
            None => task,
        };
        // A write that fails costs only the restart's memory of who bound
        // the port, never this launch: said, and the box is handed back.
        #[cfg(target_os = "linux")]
        if let Some(bound_ports) = bound_ports
            && let Err(error) = self.record_bound_ports(bound_ports).await
        {
            tracing::warn!(
                session_id = %record.id,
                %error,
                "the launch could not record the shared-address ports it bound; \
                 a daemon restart may hand them to another box"
            );
        }
        Ok((channel, (host, task)))
    }

    /// Records on this session's record that a launch bound the box's
    /// host-side row, and marks the slot's coming host as that launch. See
    /// [`Self::host_row_lost`].
    pub(super) async fn record_host_row_bound(&mut self) -> Result<(), std::io::Error> {
        let mut record = self.record.record().await?;
        record.host_row_bound = true;
        self.record.write(record).await?;
        self.slot_holds_row = true;
        Ok(())
    }

    /// Whether this registered box's host-side row is gone (NET-138): the
    /// record says a launch bound it, and the slot does not hold that
    /// launch's host alive. The row lives exactly as long as the binding
    /// launch's switch attachment and the daemon never registers it again,
    /// so a box in this state must not be handed a host — every one would
    /// be rowless, and the host gate silently drops a rowless box's frames.
    /// False for a box that carries no host-handed addresses, and for a
    /// registered box no launch has bound yet: its first launch binds it.
    ///
    /// When the binding launch's host is gone, the VM host daemon is asked
    /// whether its row still stands ([`crate::net::listeners::host_row_standing`]):
    /// the host detaches a row at the end of its box's attachment and
    /// withdraws it only after a grace, and the box's creator may resume a
    /// withdrawn one, so a row that stands is the host's own word that a
    /// relaunch rejoins the switch under it. The answer is the host's
    /// table, never a fact this daemon asserts; a host that cannot be asked
    /// — a native host, or a door that does not answer — reads as no row.
    ///
    /// A row the host confirms while the slot holds no live host is left
    /// for the relaunch that follows ([`Self::relaunch_row_confirmed`]), so
    /// later attaches and execs reuse that host without asking again.
    pub(super) async fn host_row_lost(&mut self, record: &Record) -> bool {
        self.relaunch_row_confirmed = false;
        let slot_alive = matches!(
            &self.inner,
            BoxInner::Active { host: Some((h, _)), .. } if h.is_alive()
        );
        if record.box_addresses.is_none()
            || !record.host_row_bound
            || (self.slot_holds_row && slot_alive)
        {
            return false;
        }
        let standing = self.host_row_stands(record).await;
        self.relaunch_row_confirmed = standing && !slot_alive;
        !standing
    }

    /// Whether the VM host daemon says this registered box's row stands
    /// ([`crate::net::listeners::host_row_standing`]), read for the box id
    /// the record names. A record naming no box id cannot be told from
    /// another box handed its address, so it reads as no row without
    /// asking: fail-closed. A host that cannot be asked reads as no row.
    pub(super) async fn host_row_stands(&mut self, record: &Record) -> bool {
        let (Some(addresses), Some(box_id)) = (record.box_addresses, record.box_id) else {
            return false;
        };
        let control = self.switch_control().await;
        crate::net::listeners::host_row_standing(&control, addresses.switch_address, box_id).await
            == Some(true)
    }

    /// Records the launch's own placement outcome on this session's record
    /// (NET-079): `per_box` when the launch placed this session's
    /// host-address box in a classifier leaf of the host's tree, `none` when
    /// it did not. The box's record of its own launch, in the daemon-owned
    /// field the read surfaces show, rather than the host's state as it
    /// stands now — so a box launched unenforced stays `none` for its life,
    /// whatever a later launch of another box decided.
    ///
    /// The write is not best-effort: the box is running by the time this
    /// runs, but a box whose outcome cannot be recorded must not run as
    /// though it had one, so the caller kills the box this launch minted
    /// and fails the launch on `Err`. That is what keeps a record with no
    /// outcome meaning "never launched", which is the state the reads'
    /// fall-back answers for a created session
    /// (`displayed_host_ip_enforcement`).
    pub(super) async fn record_launch_outcome(
        &self,
        host_ip_enforcement: Option<minimald_rpc::HostIpEnforcement>,
    ) -> Result<(), std::io::Error> {
        let Some(enforcement) = host_ip_enforcement else {
            // Not a host-address box: its verdict is decided on address
            // leases, never on the host's cgroup tree, so there is no
            // per-box outcome to record and nothing to lower it by.
            return Ok(());
        };
        let mut record = self.record.record().await?;
        record.host_ip_enforcement = Some(enforcement);
        #[cfg(test)]
        if launch_record_seam::write_fails(self.record.id()) {
            return Err(std::io::Error::other(
                "the test seam failed this session's launch-record write",
            ));
        }
        self.record.write(record).await?;
        // NET-079's observability: one info line per host-address box launch,
        // carrying what this launch recorded in the machine spelling every
        // surface and log line share — so the bundle's tail says each box's
        // own outcome beside the launch lines that decided it. Said after
        // the write it describes, so the line's presence says the record
        // carries the outcome it names.
        tracing::info!(
            session_id = %self.record.id(),
            host_ip_enforcement = %enforcement.machine_str(),
            "the launch recorded its host-address box's egress \
             enforcement on the session record",
        );
        Ok(())
    }

    /// Hands back this session's host, launching one if none is running.
    ///
    /// Unlike [`Self::attach`] there is no channel: the host is minted with
    /// nothing bound to it, because the caller wants the *sandbox* — to run a
    /// command inside it — not a terminal. A client that attaches later reuses
    /// this host and resizes its PTY, so the placeholder size is only ever what
    /// an unattached session's shell sees.
    ///
    /// Gated on the same `Active` record status as `attach`, without its
    /// draft-session shortcut: composing a loadout is a client-driven flow, and
    /// an exec request is not the place to start one.
    pub(super) async fn ensure_host(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
    ) -> Result<box_runtime::HostHandle, AttachError> {
        {
            let record = self
                .record
                .record()
                .await
                .map_err(AttachError::LoadoutFailed)?;
            if record.status != BoxState::Active {
                return Err(AttachError::SessionPending);
            }
            // Attach's refusal, for the same reason: neither the host a
            // later launch left in the slot nor a fresh one would hold the
            // registered box's host-side row.
            if self.host_row_lost(&record).await {
                return Err(AttachError::BoxHostRowEnded);
            }
        }

        let running = match &self.inner {
            BoxInner::Draft { .. } => return Err(AttachError::SessionPending),
            BoxInner::Active {
                host: Some((h, _)), ..
            } if h.is_alive() => Some(h.clone()),
            BoxInner::Active { .. } => None,
        };
        if let Some(host) = running {
            // Same claim as the launch below, for a host this call did not
            // mint: an exec is about to run in this sandbox, so a later
            // attach must not replace the shell out from under it. Without
            // this, a host minted for lifecycle hooks stays `Hooks` through
            // every exec that reuses it, and the first interactive attach
            // would respawn it — killing a command that is still running.
            self.host_origin = HostOrigin::Exec;
            return Ok(host);
        }

        let (_, launched) = self
            .launch_host(
                session_hnd,
                conn_username,
                UNATTACHED_WIN_SIZE,
                box_runtime::AttachEnv::default(),
                None,
                LaunchPhase::Attached,
                false,
            )
            .await?;

        let host = launched.0.clone();
        let BoxInner::Active { host: slot, .. } = &mut self.inner else {
            unreachable!("ensure_host returns early on a Draft session");
        };
        *slot = Some(launched);
        // Minted for an exec: a command is about to run in this sandbox, so a
        // later attach must not replace it. See [`HostOrigin::Exec`].
        self.host_origin = HostOrigin::Exec;
        self.publish_host();
        Ok(host)
    }

    pub(super) async fn mint_session_host(
        &mut self,
        session_hnd: BoxHandle,
        conn_username: String,
        channel: Channel<Msg>,
        sz: WinSize,
        attach_env: box_runtime::AttachEnv,
        session_keys: SessionKeys,
    ) -> Result<(), AttachError> {
        let progress = ChannelProgress::new(channel, self.tracker.clone(), (sz.cols, sz.rows));
        let (channel, launched) = self
            .launch_host(
                session_hnd,
                conn_username,
                sz,
                attach_env,
                Some(progress),
                LaunchPhase::Attached,
                false,
            )
            .await?;
        let channel = channel.expect("progress hands back the channel it was given");

        #[cfg(test)]
        let launched = mint_attach_seam::apply(*self.record.id(), launched).await;

        // Wire the channel to the freshly launched host. A failure here is
        // one of two things: the host died in the window between launch and
        // attach, or it is alive but wedged and its mailbox stayed full past
        // the attach deadline. The first is surfaced as a spawn failure rather
        // than leaving a dead, channel-less host — which is why a host whose
        // loop already ended is never stored. The second must not read as
        // death: it is the same wedged case the re-attach path refuses with
        // `SessionBusy`, and the host is stored before refusing, so a retry
        // reaches it through that path instead of minting a second host over
        // it, and teardown stops it instead of a dropped `JoinHandle`
        // detaching a live loop.
        //
        // The launch already folded this attach's connection facts into the
        // shell's environment, so nothing new is passed here: the host holds
        // them, and an empty map means "no revision", not "no terminal".
        let outcome = match launched
            .0
            .attach(channel, sz, box_runtime::ConnectionEnv::new(), session_keys)
            .await
        {
            Ok(()) => Ok(()),
            // The host's loop ended before the attach could be delivered.
            Err(box_runtime::HostAttachError::Closed(..)) => {
                return Err(AttachError::SpawnFailed(spawn_failed_error(
                    userns_spawn_hint().as_deref(),
                )));
            }
            // The host is alive but its mailbox stayed full past the attach
            // deadline: the same wedged case the re-attach path refuses with
            // `SessionBusy`, and for the same reason — re-minting would abort
            // a busy-but-healthy shell. The host is still stored below.
            Err(box_runtime::HostAttachError::Timeout) => Err(AttachError::SessionBusy),
        };
        let BoxInner::Active { host, .. } = &mut self.inner else {
            unreachable!("mint_session_host is only reachable from the Active state");
        };
        // A wedged-but-alive host can reach here via attach's re-mint branch
        // (`box_runtime.rs` `SendTimeoutError::Timeout`): its loop task is
        // still running. Dropping the replaced `(HostHandle, JoinHandle)`
        // would detach that task, leaking the old sandbox process, pty master,
        // and `NetGuard` for the daemon's lifetime — one leak per attach to the
        // same wedged host. Abort the task being replaced, mirroring
        // `stop_running` (a no-op when the old loop had already exited).
        if let Some((_, task)) = host.replace(launched) {
            task.abort();
        }
        // Minted by an attach: its environment describes the terminal that is
        // here, so nothing may replace it out from under that client.
        self.host_origin = HostOrigin::Interactive;
        self.publish_host();
        outcome
    }

    /// True when this session's composition declares at least one script for
    /// `event`. Gates the headless host launches ([`Self::finalize`]'s and
    /// [`Self::run_detach_hooks`]'s): without it, a transition would pay for
    /// a sandbox no hook is going to use.
    pub(super) fn has_hooks_for(&self, event: crate::hooks::HookEvent) -> bool {
        let BoxInner::Active {
            composition: Some(c),
            ..
        } = &self.inner
        else {
            return false;
        };
        c.lifecycle_hooks()
            .iter()
            .any(|ph| event.script_of(ph.hook()).is_some())
    }

    /// Runs this session's hooks for `event` headlessly, minting a host
    /// first when none is running.
    ///
    /// The launch is what makes this reliable. A hook runs *inside* the
    /// session, so it needs a process whose namespaces it can join, and
    /// neither teardown transition is guaranteed one: the host slot outlives
    /// the host process, so a session whose shell has exited still holds a
    /// handle to a host that can no longer run anything, and a session that
    /// was never attached may have no host at all. Minting here — the same
    /// launch [`Self::finalize`] does for activation — covers both, and a
    /// session whose shell is still up (the ctrl-w detach, a destroy from a
    /// second terminal) reuses it rather than starting a second one.
    ///
    /// Best effort, and *bounded*: a teardown that cannot run its hooks
    /// still happens, so every failure is logged, none is propagated, and
    /// nothing here may block indefinitely — see [`HOOK_LAUNCH_TIMEOUT`].
    /// Activation is the exception and keeps its own path in
    /// [`Self::finalize`] — a failed activate hook aborts the activation
    /// rather than being logged past.
    ///
    /// Returns the outcomes of the hooks that ran, for a caller that
    /// reports them (destroy does); empty when none could.
    pub(super) async fn run_hooks_headless(
        &mut self,
        event: crate::hooks::HookEvent,
    ) -> Vec<crate::hooks::HookOutcome> {
        if !self.has_hooks_for(event) {
            return Vec::new();
        }
        // `Attached`, not `Activating`: both transitions only happen once the
        // session is `Active`, so neither has reason to skip the status gate.
        // A session torn down before it activated (an aborted finalize leaves
        // it `Materializing`) is refused here and skips its hooks — teardown
        // for setup that never completed.
        //
        // Timed out rather than simply awaited: this runs on the destroy
        // path, and building a sandbox reaches the filesystem, the package
        // cache, and (for an own-IP session) the network switch. A session
        // must always be destroyable, so a launch that wedges has to cost
        // its hooks rather than the whole teardown.
        match tokio::time::timeout(
            HOOK_LAUNCH_TIMEOUT,
            self.launch_host_for_hooks(LaunchPhase::Attached),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                tracing::warn!(
                    event = event.as_str(),
                    error = %e,
                    "launching the session to run its hooks failed; skipping them",
                );
                return Vec::new();
            }
            Err(_elapsed) => {
                tracing::warn!(
                    event = event.as_str(),
                    timeout_secs = HOOK_LAUNCH_TIMEOUT.as_secs(),
                    "launching the session to run its hooks timed out; skipping them",
                );
                return Vec::new();
            }
        }
        run_session_hooks(&self.inner, &self.record, event).await
    }

    /// Launch the session host so lifecycle hooks have namespaces to
    /// join, and keep it as the session's host.
    ///
    /// Headless: there is no client channel, no PTY negotiated, and no
    /// forwarded locale — neither the activating RPC nor a departing
    /// binding is an attach. The window size is a placeholder the first
    /// real attach replaces.
    ///
    /// A host that is still *running* (an attach raced the finalize; a
    /// ctrl-w detach left the shell up) is left alone. A dead one is
    /// replaced rather than reused: the slot outlives the process, so a
    /// session whose shell exited still holds a handle to a host that can no
    /// longer run anything — which is exactly the state a detach hook meets
    /// on the shell-exit path. Mirrors [`Self::ensure_host`]'s liveness
    /// check for the same reason.
    pub(super) async fn launch_host_for_hooks(
        &mut self,
        phase: LaunchPhase,
    ) -> Result<(), std::io::Error> {
        if matches!(
            &self.inner,
            BoxInner::Active { host: Some((h, _)), .. } if h.is_alive()
        ) {
            return Ok(());
        }
        let session_hnd = self.weak_self.upgrade().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is shutting down; cannot run lifecycle hooks",
            )
        })?;
        let username = self
            .record
            .record()
            .await?
            .username
            .unwrap_or_else(|| "user".to_string());
        let launched = self
            .launch_host(
                session_hnd,
                username,
                WinSize {
                    rows: 24,
                    cols: 80,
                    xpixel: 0,
                    ypixel: 0,
                },
                box_runtime::AttachEnv::default(),
                None,
                phase,
                // This launch exists only so the hooks have namespaces to
                // join — a hook run, not a session start. See
                // [`BoxActor::launch_host`].
                true,
            )
            .await
            .map_err(|e| {
                std::io::Error::other(format!("launching the session to run its hooks: {e}"))
            })?
            .1;
        let BoxInner::Active { host, .. } = &mut self.inner else {
            unreachable!("a headless hook launch only reaches here from the Active state");
        };
        *host = Some(launched);
        // Minted for hooks, with no terminal to describe: an interactive
        // attach may replace this shell rather than inherit its blank `TERM`.
        // See [`HostOrigin::Hooks`].
        self.host_origin = HostOrigin::Hooks;
        self.publish_host();
        Ok(())
    }
}

#[cfg(test)]
mod quic443_cohort_tests {
    use super::{join_quic443_cohort, leave_quic443_cohort, quic443_placement_refused};
    use crate::net::classifier::{CohortQuic443, StandinMoves, quic443_blocked_leaf};
    use boxes::{BoxId, HostIpEnforcement, NetworkMode, Record};
    use sandbox::config::Verdict;

    /// A launched `host_ip` box's record: `quic443` is its declared stance.
    fn host_ip_record(quic443: Option<boxes::core::bep::Quic443>) -> Record {
        Record {
            id: BoxId::mint(),
            name: Some("box".to_string()),
            username: Some("alice".to_string()),
            project_path: paths::HostAbsPath::try_new("/home/alice/proj").unwrap(),
            network: NetworkMode::HostNet,
            policy: boxes::BoxPolicy {
                quic443,
                ..Default::default()
            },
            task_addresses: Vec::new(),
            box_addresses: None,
            hooks_enabled: true,
            status: boxes::BoxState::default(),
            host_ip_enforcement: Some(HostIpEnforcement::PerBox),
            box_id: None,
            host_row_bound: false,
            bound_ports: std::collections::BTreeSet::new(),
            sealed_deliveries: Vec::new(),
            root_certificate: None,
            attrs: Default::default(),
        }
    }

    /// BEP-018 over the launch and stop paths: a cohort with one blocked
    /// member has every member's processes in the blocked leaf the table
    /// rejects UDP 443 from, and when that member stops they go back to
    /// their own leaves, where UDP 443 leaves again.
    #[test]
    fn host_ip_cohort_join_block_leave_drives_the_rule() {
        use boxes::core::bep::Quic443;

        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        for dir in [sandbox::config::DENY_DIR, sandbox::config::ALLOW_DIR] {
            std::fs::create_dir_all(root.join(sandbox::classifier::BOXES_DIR).join(dir)).unwrap();
        }
        let blocked_leaf = quic443_blocked_leaf(root);
        std::fs::create_dir(&blocked_leaf).unwrap();
        let cohort = std::sync::Mutex::new(CohortQuic443::default());
        let moves = StandinMoves::default();
        let launch = |record: &Record, pid: i32| {
            let leaf =
                sandbox::classifier::create_box_leaf(root, &record.id.to_string(), Verdict::Allow)
                    .unwrap();
            moves.spawn_in(pid, &leaf);
            join_quic443_cohort(record, record.host_ip_enforcement, root, &cohort, &moves)
                .expect("the box is placed");
            leaf
        };

        // An `auto` box with no grant resolves to allowed: nothing moves.
        let plain = host_ip_record(None);
        let plain_leaf = launch(&plain, 100);
        assert!(!cohort.lock().unwrap().blocked());
        assert_eq!(moves.where_is(100), plain_leaf);

        // A `block` box joins: the whole cohort moves into the blocked leaf.
        let strict = host_ip_record(Some(Quic443::Block));
        launch(&strict, 200);
        assert!(cohort.lock().unwrap().blocked());
        assert_eq!(moves.where_is(100), blocked_leaf);
        assert_eq!(moves.where_is(200), blocked_leaf);

        // A box that joins a blocked cohort moves at once, and a process
        // forked while blocked is born in the blocked leaf.
        let late = host_ip_record(Some(Quic443::Allow));
        let late_leaf = launch(&late, 300);
        assert_eq!(moves.where_is(300), blocked_leaf);
        moves.fork(100, 101);
        moves.fork(101, 102);
        assert_eq!(moves.where_is(102), blocked_leaf);

        // An own-address box shares no address and joins nothing.
        let mut own = host_ip_record(Some(Quic443::Block));
        own.network = NetworkMode::OwnIp;
        own.host_ip_enforcement = None;
        join_quic443_cohort(&own, None, root, &cohort, &moves).expect("nothing to place");
        assert_eq!(
            cohort.lock().unwrap().blocking_members().count(),
            1,
            "only the host-address box blocks"
        );

        // The blocking member stops: everyone else goes home, the forked
        // processes with their box.
        moves.kill(200);
        leave_quic443_cohort(&strict.id.to_string(), &cohort, &moves);
        assert!(!cohort.lock().unwrap().blocked());
        assert_eq!(moves.where_is(100), plain_leaf);
        assert_eq!(moves.where_is(101), plain_leaf);
        assert_eq!(moves.where_is(102), plain_leaf);
        assert_eq!(moves.where_is(300), late_leaf);

        // A box that never joined changes nothing when it stops.
        leave_quic443_cohort(&own.id.to_string(), &cohort, &moves);
        assert!(!cohort.lock().unwrap().blocked());
    }

    /// BEP-018, review finding 4370595764: a launch that cannot place the
    /// cohort under its block fails, and the box that asked for the block
    /// leaves the cohort again, so nobody stays half moved.
    #[test]
    fn host_ip_cohort_join_block_leave_drives_the_rule_or_fails_the_launch() {
        use boxes::core::bep::Quic443;

        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        for dir in [sandbox::config::DENY_DIR, sandbox::config::ALLOW_DIR] {
            std::fs::create_dir_all(root.join(sandbox::classifier::BOXES_DIR).join(dir)).unwrap();
        }
        let cohort = std::sync::Mutex::new(CohortQuic443::default());
        let moves = StandinMoves::default();
        let plain = host_ip_record(None);
        let plain_leaf =
            sandbox::classifier::create_box_leaf(root, &plain.id.to_string(), Verdict::Allow)
                .unwrap();
        moves.spawn_in(100, &plain_leaf);
        join_quic443_cohort(&plain, plain.host_ip_enforcement, root, &cohort, &moves)
            .expect("nothing to place");

        // This host's tree has no blocked leaf: the blocked box fails.
        let strict = host_ip_record(Some(Quic443::Block));
        let strict_leaf =
            sandbox::classifier::create_box_leaf(root, &strict.id.to_string(), Verdict::Allow)
                .unwrap();
        moves.spawn_in(200, &strict_leaf);
        let error = join_quic443_cohort(&strict, strict.host_ip_enforcement, root, &cohort, &moves)
            .expect_err("no leaf to place the cohort in");
        assert!(
            !cohort.lock().unwrap().blocked(),
            "the block left with its box"
        );
        let refusal = quic443_placement_refused(&error).to_string();
        assert!(
            refusal.contains("QUIC (UDP to port 443) could not be blocked")
                && refusal.contains("quic443")
                && refusal.contains("boxes/quic443-blocked"),
            "the refusal says what failed and why: {refusal}"
        );

        // The leaf is there, but the other member's process cannot move.
        let blocked_leaf = quic443_blocked_leaf(root);
        std::fs::create_dir(&blocked_leaf).unwrap();
        moves.refused.lock().unwrap().insert(100);
        join_quic443_cohort(&strict, strict.host_ip_enforcement, root, &cohort, &moves)
            .expect_err("a member that cannot move fails the launch");
        let guard = cohort.lock().unwrap();
        assert!(!guard.blocked(), "the block left with its box");
        assert_eq!(guard.blocking_members().count(), 0);
        drop(guard);
        assert_eq!(moves.where_is(100), plain_leaf, "the member stays home");
    }

    /// BEP-018 over the exit path: the only blocked member's shell exits on
    /// its own, with no Stop and no destroy. Its host's loop ends, the box
    /// leaves the cohort, and the other member's processes go home, where
    /// UDP 443 leaves again. A loop of a launch that a later launch replaced
    /// changes nothing when it ends, and an abort of the watched handle
    /// still reaches the loop.
    #[tokio::test]
    async fn host_ip_cohort_shell_exit_leaves_and_lifts_the_block() {
        use super::{
            Quic443Exit, Quic443Launches, begin_quic443_launch, joins_quic443_cohort,
            watch_quic443_exit,
        };
        use boxes::core::bep::Quic443;

        let tree = tempfile::tempdir().unwrap();
        let root = tree.path();
        for dir in [sandbox::config::DENY_DIR, sandbox::config::ALLOW_DIR] {
            std::fs::create_dir_all(root.join(sandbox::classifier::BOXES_DIR).join(dir)).unwrap();
        }
        let blocked_leaf = quic443_blocked_leaf(root);
        std::fs::create_dir(&blocked_leaf).unwrap();
        let cohort: &'static std::sync::Mutex<CohortQuic443> =
            Box::leak(Box::new(std::sync::Mutex::new(CohortQuic443::default())));
        let launches: &'static std::sync::Mutex<Quic443Launches> =
            Box::leak(Box::new(std::sync::Mutex::new(Quic443Launches::default())));
        let moves: &'static StandinMoves = Box::leak(Box::new(StandinMoves::default()));

        // A launch as `launch_host` makes it: a number, the join, and the
        // loop handed back behind its watcher. The loop ends when its
        // shell exits, which the sender stands in for.
        let launch = |record: &Record, pid: i32| {
            assert!(joins_quic443_cohort(record, record.host_ip_enforcement));
            let box_id = record.id.to_string();
            let leaf = sandbox::classifier::box_leaf(root, &box_id, Verdict::Allow);
            if !leaf.is_dir() {
                sandbox::classifier::create_box_leaf(root, &box_id, Verdict::Allow).unwrap();
            }
            moves.spawn_in(pid, &leaf);
            let number = begin_quic443_launch(&box_id, launches);
            join_quic443_cohort(record, record.host_ip_enforcement, root, cohort, moves)
                .expect("the box is placed");
            let (exit, exited) = tokio::sync::oneshot::channel::<i32>();
            // A negative code stands in for a loop that panics.
            let task = crate::traced::spawn(async move {
                let code = exited.await.unwrap_or(137);
                assert!(code >= 0, "the host loop panics");
                Ok(code)
            });
            let watched = watch_quic443_exit(
                task,
                Quic443Exit {
                    box_id,
                    launch: number,
                    launches,
                    cohort,
                    moves,
                },
            );
            (leaf, exit, watched)
        };

        let plain = host_ip_record(None);
        let (plain_leaf, _plain_exit, plain_task) = launch(&plain, 100);
        let strict = host_ip_record(Some(Quic443::Block));
        let (_, strict_exit, strict_task) = launch(&strict, 200);
        assert!(cohort.lock().unwrap().blocked());
        assert_eq!(moves.where_is(100), blocked_leaf);

        // The blocked member's shell exits on its own: its loop ends with
        // the shell's code, and the block lifts with no Stop.
        moves.kill(200);
        strict_exit.send(0).unwrap();
        assert_eq!(strict_task.await.unwrap().unwrap(), 0);
        assert!(!cohort.lock().unwrap().blocked(), "the block lifted");
        assert_eq!(cohort.lock().unwrap().blocking_members().count(), 0);
        assert_eq!(moves.where_is(100), plain_leaf, "UDP 443 leaves again");

        // A relaunch of the blocked box replaces a loop that ends late: the
        // late end leaves the relaunch's block in place.
        let (_, stale_exit, stale_task) = launch(&strict, 300);
        moves.kill(300);
        let (_, mut relaunch_exit, relaunch_task) = launch(&strict, 400);
        assert_eq!(moves.where_is(100), blocked_leaf);
        stale_exit.send(0).unwrap();
        stale_task.await.unwrap().unwrap();
        assert!(
            cohort.lock().unwrap().blocked(),
            "the relaunch still blocks"
        );
        assert_eq!(moves.where_is(100), blocked_leaf);

        // An abort of the watched handle reaches the loop, as a stop's
        // abort did before the watcher, and leaves the cohort to the stop.
        relaunch_task.abort();
        assert!(relaunch_task.await.unwrap_err().is_cancelled());
        tokio::time::timeout(std::time::Duration::from_secs(5), relaunch_exit.closed())
            .await
            .expect("the loop under the watcher is aborted too");
        assert!(cohort.lock().unwrap().blocked(), "the stop's to lift");

        // A loop that panics still ends the launch: the box leaves before
        // the panic reaches the watched handle, and the block lifts.
        let (_, panic_exit, panic_task) = launch(&strict, 500);
        assert_eq!(moves.where_is(100), blocked_leaf);
        moves.kill(500);
        panic_exit.send(-1).unwrap();
        assert!(panic_task.await.unwrap_err().is_panic());
        assert!(!cohort.lock().unwrap().blocked(), "the block lifted");
        assert_eq!(moves.where_is(100), plain_leaf, "UDP 443 leaves again");
        plain_task.abort();
    }
}
