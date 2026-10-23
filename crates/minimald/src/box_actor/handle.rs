use super::*;

/// The host a box actor last published, read by its handle: a listing's
/// attrs probe goes to the host through this slot rather than through the
/// actor's mailbox, so an actor that is parked (a `ConfigureLoadout` inside
/// its package-graph clone, an inline attach) costs the listing nothing, and
/// a box with no host reads as `None` at once instead of after
/// [`HOST_PROBE_TIMEOUT`]. The actor refreshes it after every message it
/// handles ([`BoxActor::publish_host`]).
pub(crate) type HostSlot = Arc<std::sync::Mutex<Option<AttrsProbe>>>;

/// Empties a [`HostSlot`] when the actor that publishes it ends, however it
/// ends: a teardown's `break` (which publishes nothing after it), or a panic
/// unwinding the actor's task. A listing then reads no host for an actor
/// that is gone, and the slot holds no sender that would keep the host's
/// mailbox open.
pub(super) struct ClearSlotOnExit(pub(super) HostSlot);

impl Drop for ClearSlotOnExit {
    fn drop(&mut self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// What the [`HostSlot`] hands out: a host's attrs, and nothing else. The
/// slot is read by every holder of a [`BoxHandle`], so it carries no way to
/// kill, attach to or rename the host: those stay with the actor, which
/// serializes them and checks an attach before binding a channel.
#[derive(Debug, Clone)]
pub(crate) struct AttrsProbe(pub(super) crate::box_runtime::HostHandle);

impl AttrsProbe {
    async fn get_attrs(&self) -> Result<HostAttrs, ()> {
        self.0.get_attrs().await
    }
}

/// The handle to the session.
#[derive(Debug, Clone)]
pub struct BoxHandle(
    pub(super) crate::traced::Sender<BoxMessage>,
    pub(super) CancellationToken,
    pub(super) HostSlot,
);

impl BoxHandle {
    /// Returns a non-owning handle to this session.
    #[must_use]
    pub fn downgrade(&self) -> WeakBoxHandle {
        WeakBoxHandle(self.0.downgrade(), self.1.clone(), Arc::clone(&self.2))
    }

    /// Whether this session is being destroyed.
    ///
    /// The destroy sets this after its hooks run. It sets it before it
    /// stops the host. So a command that the destroy ends can see why.
    #[must_use]
    pub fn is_destroying(&self) -> bool {
        self.1.is_cancelled()
    }

    /// A token that is cancelled when this session's destroy starts, at
    /// the same point [`Self::is_destroying`] becomes true.
    ///
    /// The token is a child token. Cancelling it does not destroy the
    /// session.
    #[must_use]
    pub fn destroy_signal(&self) -> CancellationToken {
        self.1.child_token()
    }

    /// The session's composition, if it has one. See
    /// [`BoxMessage::GetComposition`].
    pub async fn composition(&self) -> Result<Option<Arc<Composition>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        let _ = self.0.send(BoxMessage::GetComposition(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Handle to the per-session patches-upload lock, owned by the session
    /// actor.
    ///
    /// Workspace patches are accumulated in a fixed per-session directory,
    /// so this lock is used to serialize `WorkspacePatchesTarZst` RPCs so
    /// they dont race and stomp each other.
    pub async fn patches_upload_lock(&self) -> Result<Arc<Mutex<()>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::GetPatchesUploadLock(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Handle to the per-session hook-scripts-upload lock, owned by the
    /// session actor. Serializes `WorkspaceHookScriptsTarZst` RPCs the
    /// same way [`Self::patches_upload_lock`] serializes patch uploads.
    pub async fn hook_scripts_upload_lock(&self) -> Result<Arc<Mutex<()>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::GetHookScriptsUploadLock(send))
            .await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Marks one `WorkspaceFilesTarZst` upload into the session as started
    /// (true) or finished (false); every accepted `true` must be paired with
    /// exactly one `false`. The reply is awaited — the actor's ack fires
    /// once the change is applied, so a `true` returns only once an attach
    /// racing the upload will see it. A dead actor maps to `NotConnected`;
    /// a `true` into a session that is no longer unconfigured maps to
    /// `PermissionDenied` and marks nothing.
    pub async fn set_workspace_upload_in_flight(
        &self,
        in_flight: bool,
    ) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::SetWorkspaceUploadInFlight(in_flight, send))
            .await;
        match recv.await {
            Ok(true) => Ok(()),
            Ok(false) => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "session is already configured; a workspace upload is accepted \
                 only while the session is being created",
            )),
            Err(_) => Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            )),
        }
    }

    /// The `false` half of [`Self::set_workspace_upload_in_flight`] for a
    /// caller that cannot await, such as a `Drop`. The message is enqueued
    /// synchronously when the mailbox has room, so it is ordered ahead of
    /// anything sent after this returns; a full mailbox hands it to a
    /// detached task instead. A dead actor needs no clear and is ignored.
    pub fn end_workspace_upload_detached(&self) {
        let (send, _) = oneshot::channel();
        let msg = BoxMessage::SetWorkspaceUploadInFlight(false, send);
        if let Err(mpsc::error::TrySendError::Full(msg)) = self.0.try_send(msg)
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let sender = self.0.clone();
            runtime.spawn(async move {
                let _ = sender.send(msg).await;
            });
        }
    }

    /// Kicks off a background package build as a session side-op, returning the
    /// receiver end of the build's event stream. Events flow until the build
    /// finishes (success or cancellation), at which point the channel closes.
    /// A `Draft` session is refused with `InvalidInput`; a dead actor maps to
    /// `NotConnected`.
    pub async fn start_build(
        &self,
        rebuild: bool,
        pkgs: Vec<String>,
    ) -> Result<mpsc::Receiver<BuildUpdate>, std::io::Error> {
        let (reply, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::StartBuild {
                rebuild,
                pkgs,
                reply,
            })
            .await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })?
    }

    /// Kicks off a background check run as a session side-op, returning the
    /// receiver end of the run's result stream. Results flow until the run
    /// finishes (completion, failure, or cancellation), at which point the
    /// channel closes. A `Draft` session is refused with `InvalidInput`; a dead
    /// actor maps to `NotConnected`.
    pub(crate) async fn start_check(
        &self,
        opts: CheckOpts,
    ) -> Result<mpsc::Receiver<CheckUpdate>, std::io::Error> {
        let (reply, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::StartCheck { opts, reply }).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })?
    }

    /// Kicks off a background materialize run as a session side-op, returning
    /// the receiver end of the run's stream. An unknown output name is refused
    /// with `NotFound`; a `Draft` session with `InvalidInput`; a dead actor
    /// maps to `NotConnected`.
    pub async fn start_materialize(
        &self,
        opts: MaterializeOpts,
    ) -> Result<mpsc::Receiver<MaterializeUpdate>, std::io::Error> {
        let (reply, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::StartMaterialize { opts, reply })
            .await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })?
    }

    /// Returns paths on the daemon backing various internals of the session.
    /// A dead actor (self-terminated abort/failed-verdict/create-failure, or
    /// mid-teardown) maps to `NotConnected` — callers race actor death.
    pub async fn paths(&self) -> Result<BoxPaths, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::GetPaths(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }
    /// Returns the host attributes of the running session, if any: `None`
    /// for a session without a host, a dead host, or a host that misses
    /// [`HOST_PROBE_TIMEOUT`]. Read through the host slot, not the actor's
    /// mailbox (see [`HostSlot`]): the manager polls this for every running
    /// session on each listing, and an actor parked in a long message held
    /// every `min ls` for the probe's full deadline (710d: 2 s per call
    /// through a stalled clone, on every distro).
    pub async fn get_attrs(&self) -> Option<HostAttrs> {
        let host = self
            .2
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        probe_host(host?.get_attrs()).await
    }

    /// Test-only: puts `host` in the slot a listing reads, as the actor does
    /// after a message; the actor's next message overwrites it.
    #[cfg(test)]
    pub(crate) fn put_host_for_test(&self, host: crate::box_runtime::HostHandle) {
        *self
            .2
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(AttrsProbe(host));
    }

    /// Test-only: parks the actor for `d`, the shape of a message that holds
    /// its mailbox (a clone inside `ConfigureLoadout`, an inline attach).
    /// Returns once the actor is inside the park, so every earlier message
    /// and the slot publish after it are done.
    #[cfg(test)]
    pub(crate) async fn park_for(&self, d: std::time::Duration) {
        let (entered, entered_recv) = oneshot::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a gone actor cannot be parked, and the recv below says so"
        )]
        let _ = self.0.send(BoxMessage::Park(d, entered)).await;
        entered_recv
            .await
            .expect("the session actor should enter the park");
    }

    /// Returns the workspace's at-risk report (what a destroy would lose),
    /// or `Unavailable` when it cannot be computed — no running host, no
    /// baseline, failed bounded computation, or a dead actor. Never an
    /// error: the destroy confirm renders with or without the listing.
    pub async fn workspace_at_risk(&self) -> minimald_rpc::SessionDeltaResponse {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::GetWorkspaceDelta(send)).await;
        recv.await
            .unwrap_or(minimald_rpc::SessionDeltaResponse::Unavailable)
    }
    /// Returns a snapshot of the running session's terminal screen, if any.
    /// Same dead-actor semantics as [`Self::get_attrs`].
    pub async fn get_screen(&self) -> Option<minimald_rpc::ScreenSnapshot> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::GetHostScreen(send)).await;
        recv.await.ok().flatten()
    }

    /// Runs this session's `on_detach` hooks, awaiting them so a departing
    /// binding doesn't race its own teardown. A dead actor means there is
    /// no session to run them against, which is not an error worth raising
    /// on a path whose whole job is leaving.
    pub async fn run_detach_hooks(&self) {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::RunDetachHooks(send)).await;
        let _ = recv.await;
    }

    /// Returns a minimal context initialized on this sessions' worktree.
    pub async fn context(&self) -> Result<mctx::Context, String> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::MakeContext(send)).await;
        recv.await
            .unwrap_or_else(|_| Err("session actor is gone".to_string()))
    }

    /// The spec hash of every package this session's project needs: its tasks,
    /// its stack, and its `[session]` block.
    ///
    /// Resolved through this session's own workspace context, so the answer
    /// reflects the `minimal.toml` currently in its worktree. Spec hashes
    /// rather than `BuildSpecRef`s because a ref only means something against
    /// the graph it was resolved in — see [`mctx::Context::needed_packages`].
    ///
    /// Runs off the actor: the resolve is nickel evaluation plus a graph
    /// build, which has no business sitting in the session's mainloop, so it
    /// goes to the blocking pool like every other graph build in the daemon.
    pub async fn needed_packages(&self) -> Result<HashSet<SpecHash>, String> {
        let mut ctx = self.context().await?;
        // `mctx::Error` isn't `Send` (it carries nickel-language types), so it
        // is rendered to a string inside the task.
        crate::traced::spawn_blocking(move || ctx.needed_packages().map_err(|e| e.to_string()))
            .await
            .map_err(|e| format!("resolving needed packages: {e}"))?
    }

    /// Returns the session record currently held by the live session actor
    /// (the in-memory copy, not the on-disk record). Used by the task-exec path
    /// to read the session's network mode, and by tests to assert propagation.
    /// A dead actor maps to `NotConnected`.
    pub(crate) async fn record(&self) -> Result<Record, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::GetRecord(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// The daemon's shared gvproxy switch, for the task path's network
    /// provider. A dead actor maps to `NotConnected`.
    pub(crate) async fn net_switch(
        &self,
    ) -> Result<Arc<Mutex<crate::net::SwitchClient>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::GetNetSwitch(send)).await;
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Publishes `port` for this box at runtime (NET-043) — the request the
    /// in-box `min net expose` sends, decided against the box's
    /// `dynamic_ingress` setting. Answers with the published mapping, or the
    /// typed reason the request was refused. A dead actor is its own typed
    /// failure — `ActorGone`, not `Publish` — because it never reached the
    /// bind: the box that would own the mapping is gone, so no publish was
    /// attempted and none could be reported as failed.
    pub(crate) async fn expose_dynamic(
        &self,
        port: u16,
    ) -> Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; the recv below reports that"
        )]
        let _ = self
            .0
            .send(BoxMessage::ExposeDynamic { port, reply: send })
            .await;
        match recv.await {
            Ok(reply) => reply,
            Err(_) => Err(crate::net::policy::ExposeFailure::ActorGone { port }),
        }
    }

    /// Tells the session's actor it took a shared-address port over
    /// (NET-129), so it binds the port's forward if its box is running. Not
    /// answered: a box that is gone, stopped or no longer the holder binds
    /// nothing, and the port is bound at the holder's next attach.
    #[cfg(target_os = "linux")]
    pub(crate) async fn bind_handed_port(&self, address: std::net::Ipv4Addr, port: u16) {
        #[expect(
            clippy::let_underscore_must_use,
            reason = "an actor that is gone has no box to bind the port for"
        )]
        let _ = self
            .0
            .send(BoxMessage::BindHandedPort { address, port })
            .await;
    }

    /// Continues a parked runtime port-publish ask (NET-045) with the attached
    /// human's answer, or its absence — sent by the task
    /// [`BoxActor::route_ask`] spawned, never by the actor itself. Keyed by the
    /// ask's [`AskId`] so the answer reaches the ask it answers. Best-effort
    /// by shape: a session that has already stopped has answered its asks
    /// fail-closed, so a message that does not land is the normal end of a
    /// late answer, not a loss.
    pub(crate) async fn ask_answered(&self, id: AskId, port: u16, answer: impl Into<AskEnd>) {
        let answer = answer.into();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the session may already be gone; its asks were answered fail-closed then"
        )]
        let _ = self
            .0
            .send(BoxMessage::AskAnswered { id, port, answer })
            .await;
    }

    /// Test-only: the ids of the runtime port-publish asks still parked on a
    /// human (NET-045), in route order, paired with their ports. Lets a test
    /// answer a specific ask through [`Self::ask_answered`] — the same path
    /// the routed task's answer takes — without guessing which park it
    /// reached.
    #[cfg(test)]
    pub(crate) async fn pending_ask_ids(&self) -> Vec<(AskId, u16)> {
        let (send, recv) = oneshot::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; an empty peek is the honest answer then"
        )]
        let _ = self.0.send(BoxMessage::PeekPendingAsks(send)).await;
        // A dead actor has no asks parked, and `Vec`'s default says exactly
        // that — which is also the truth about a session that stopped, since
        // `stop_running` answered them all fail-closed first.
        recv.await.unwrap_or_default()
    }

    /// Test-only: clones of the box's shared runtime ingress cell and
    /// publication set (see [`BoxMessage::PeekIngressCells`]). `None` once
    /// the actor is gone.
    #[cfg(test)]
    pub(crate) async fn ingress_cells(
        &self,
    ) -> Option<(
        crate::net::provider::RuntimeIngress,
        crate::net::listeners::BoxPublications,
    )> {
        let (send, recv) = oneshot::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; the recv below reports that"
        )]
        let _ = self.0.send(BoxMessage::PeekIngressCells(send)).await;
        recv.await.ok()
    }

    /// The live dynamic-ingress mappings this box published at runtime
    /// (NET-044) — the rows `min session policy` lists. Empty for a box that
    /// published none. A dead actor maps to `NotConnected`.
    pub(crate) async fn live_ingress(&self) -> Result<LiveIngressRows, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; the recv below reports that"
        )]
        let _ = self.0.send(BoxMessage::LiveIngress(send)).await;
        #[expect(
            clippy::map_err_ignore,
            reason = "a closed oneshot carries no cause beyond the actor being gone"
        )]
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Whether this daemon opted out of the deny-all egress default
    /// (NET-077), for the task path's effective-egress resolution. A dead
    /// actor maps to `NotConnected`.
    pub(crate) async fn deny_all_opt_out(&self) -> Result<bool, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        #[expect(
            clippy::let_underscore_must_use,
            reason = "the actor may already be gone; the recv below reports that"
        )]
        let _ = self.0.send(BoxMessage::GetDenyAllOptOut(send)).await;
        #[expect(
            clippy::map_err_ignore,
            reason = "a closed oneshot carries no cause beyond the actor being gone"
        )]
        recv.await.map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::NotConnected, "session actor is gone")
        })
    }

    /// Configure the session's loadout from the client's wire contribution:
    /// `Ok(None)` means the composition finalized and the session is now
    /// `Active`; `Ok(Some(response))` means the client must gate the returned
    /// items and come back with a verdict. `AlreadyExists` if the loadout is
    /// already configured; a dead actor maps to `NotConnected`.
    pub(crate) async fn configure_loadout(
        &self,
        contribution: WireContribution,
    ) -> Result<Option<ContributionResponse>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::ConfigureLoadout(contribution, send))
            .await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Submit the client's contribution verdict against a `Draft` session.
    /// On success the actor promotes its record from `Pending` to
    /// `Materializing` and replies with [`BoxStep::Materialized`]; the
    /// client still has to upload patches and call `FinalizeSession`
    /// before the session becomes attachable. Structured failures
    /// (wrong state, an unresumable verdict) come back as
    /// [`BoxStep::Fault`]. A dead actor maps to `NotConnected`
    /// (the caller reads it as unknown-session).
    pub(crate) async fn submit_verdict(
        &self,
        verdict: ContributionVerdict,
    ) -> Result<BoxStep, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::SubmitVerdict(Box::new((verdict, send))))
            .await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Promote a `Materializing` session to `Active`, gating on the
    /// patches-ready marker having been written by a completed
    /// `WorkspacePatchesTarZst` upload. Idempotent on already-Active
    /// sessions. See [`BoxActor::finalize`] for the state-machine
    /// contract.
    pub(crate) async fn finalize(
        &self,
    ) -> Result<minimald_rpc::FinalizeSessionResponse, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::Finalize(send)).await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Abort a `Draft` session: the actor deletes its on-disk record and
    /// stops. `InvalidInput` if the session is `Active` (use destroy);
    /// a dead actor maps to `NotConnected`.
    pub(crate) async fn abort(&self) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::Abort(send)).await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Whether this session blocks an unforced daemon shutdown: awaiting a
    /// contribution verdict mid create flow, or hosting a live shell. A dead
    /// actor is not busy.
    pub(crate) async fn is_busy(&self) -> bool {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::IsBusy(send)).await;
        recv.await.unwrap_or(false)
    }

    /// Test-only: holds the actor in a message until the returned sender
    /// fires or drops (see [`BoxMessage::HoldUntil`]). Returns once the
    /// actor is in the hold.
    #[cfg(test)]
    pub(crate) async fn hold_for_test(&self) -> oneshot::Sender<()> {
        let (entered, entered_recv) = oneshot::channel();
        let (release, release_recv) = oneshot::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a dead actor fails the recv below"
        )]
        let _ = self
            .0
            .send(BoxMessage::HoldUntil(entered, release_recv))
            .await;
        entered_recv
            .await
            .expect("the session actor should enter the hold");
        release
    }

    /// Test-only: waits until `n` messages are queued in this session's
    /// mailbox, behind the one being handled.
    #[cfg(test)]
    pub(crate) async fn until_queued(&self, n: usize) {
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while self.0.queued() < n {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{n} messages never queued in the session's mailbox"));
    }

    /// Test-only: turn on the finalize package check for this session,
    /// bounded by `deadline` (see [`BoxMessage::CheckPackagesAtFinalize`]
    /// and [`PACKAGE_CHECK_DEADLINE`]).
    #[cfg(test)]
    pub(crate) async fn check_packages_at_finalize(&self, deadline: std::time::Duration) {
        let (send, recv) = oneshot::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a dead actor fails the recv below"
        )]
        let _ = self
            .0
            .send(BoxMessage::CheckPackagesAtFinalize(deadline, send))
            .await;
        recv.await.expect("the session actor should ack the switch");
    }

    /// Test-only: drop the compose-time graph names (see
    /// [`BoxMessage::ForgetComposedGraphNames`]).
    #[cfg(test)]
    pub(crate) async fn forget_composed_graph_names(&self) {
        let (send, recv) = oneshot::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a dead actor fails the recv below"
        )]
        let _ = self
            .0
            .send(BoxMessage::ForgetComposedGraphNames(send))
            .await;
        recv.await.expect("the session actor should ack the drop");
    }

    /// Test-only peek at the actor's held [`Composition`]. Bumps the
    /// refcount rather than moving it, so the caller can assert on contents
    /// without disturbing the lifecycle.
    #[cfg(test)]
    pub(crate) async fn peek_composition(&self) -> Option<Arc<Composition>> {
        let (send, recv) = oneshot::channel();
        let _ = self.0.send(BoxMessage::PeekComposition(send)).await;
        recv.await.ok().flatten()
    }

    /// Renames the session: the actor persists the new name through its
    /// record handle (name collision → `AlreadyExists`) and relinks its PTask
    /// hostname. A dead actor maps to `NotConnected`.
    pub(crate) async fn rename(&self, new_name: String) -> Result<(), std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::Rename(new_name, send)).await;
        recv.await.unwrap_or_else(|_| {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotConnected,
                "session actor is gone",
            ))
        })
    }

    /// Shutdown-stop: kills the host (if any), withdraws the hostname, and
    /// stops the actor — the on-disk record is kept. A dead actor is already
    /// stopped, so send/recv failures read as success.
    pub(crate) async fn stop(&self) {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::Stop(send)).await;
        // If the actor died before acking, it is stopped all the same.
        let _ = recv.await;
    }

    /// Tears down the session: kills its host (if any), waits for teardown,
    /// deletes the on-disk record, and stops the actor. The handle is dead
    /// once this returns. A dead actor reads as `Ok` — whatever terminated it
    /// already ran its teardown.
    ///
    /// On success, returns one line per `on_destroy` hook that failed.
    pub(crate) async fn destroy(&self) -> Result<Vec<String>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::Destroy(send)).await;
        recv.await.unwrap_or(Ok(Vec::new()))
    }

    /// [`Self::destroy`], only if the session has not finished activating:
    /// `Ok(None)` when it had, and it is left as it is. The actor decides
    /// after whatever is ahead of this in its mailbox — a finalize in flight
    /// included. A dead actor reads as destroyed, as for [`Self::destroy`].
    pub(crate) async fn destroy_if_unfinalized(
        &self,
    ) -> Result<Option<Vec<String>>, std::io::Error> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(BoxMessage::DestroyIfUnfinalized(send)).await;
        recv.await.unwrap_or(Ok(Some(Vec::new())))
    }

    /// This session's host, launching one with nothing bound to it if the
    /// session has none running.
    ///
    /// For callers that need the session's *sandbox* rather than its terminal —
    /// an SSH exec request runs its command inside the sandbox, which means the
    /// session process whose namespaces it joins has to exist.
    ///
    /// # Errors
    ///
    /// [`AttachError::SessionPending`] on a session that is not yet `Active`,
    /// and [`AttachError::SpawnFailed`] if the host cannot be launched or the
    /// session actor is gone.
    pub async fn ensure_host(
        &self,
        conn_username: String,
    ) -> Result<box_runtime::HostHandle, AttachError> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::EnsureHost(send, self.clone(), conn_username))
            .await;
        match recv.await {
            Ok(result) => result,
            Err(_) => Err(AttachError::SpawnFailed(std::io::Error::other(
                "session actor terminated before the host could be launched",
            ))),
        }
    }

    /// Registers a forward relay with the session it forwards for, so the
    /// session aborts it at teardown.
    ///
    /// Best-effort by design: a send error means the session actor is
    /// already gone, in which case the relay is about to learn the same
    /// thing its client does — there is no session to outlive. The
    /// connection layer ignores the outcome.
    pub async fn track_forward(&self, forward: tokio::task::AbortHandle) {
        // Ignore send errors - a session that is gone has nothing left to
        // track, and the forward ends with it.
        let _ = self.0.send(BoxMessage::TrackForward(forward)).await;
    }

    /// `attacher` is the attaching connection's liveness: while the session
    /// is still unconfigured, only its creating connection may attach.
    pub async fn attach(
        &self,
        conn_username: String,
        channel: Channel<Msg>,
        config: ChannelConfig,
        attacher: Option<std::sync::Weak<()>>,
    ) -> Result<(), AttachError> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(BoxMessage::Attach(
                send,
                self.clone(),
                conn_username,
                channel,
                config,
                attacher,
            ))
            .await;
        // A dead session actor (it panicked or was dropped mid-attach) drops the
        // reply sender. Surface that as an attach error rather than panicking the
        // daemon worker — the SSH layer reports it to the client and closes.
        match recv.await {
            Ok(result) => result,
            Err(_) => Err(AttachError::SpawnFailed(std::io::Error::other(
                "session actor terminated before the attach completed",
            ))),
        }
    }
}

/// A non-owning handle to the [`BoxActor`] actor.
#[derive(Debug, Clone)]
pub struct WeakBoxHandle(
    pub(super) crate::traced::WeakSender<BoxMessage>,
    pub(super) CancellationToken,
    pub(super) HostSlot,
);

impl WeakBoxHandle {
    /// Promotes to a strong [`BoxHandle`], or `None` if the session actor
    /// has already shut down (all strong senders dropped).
    #[must_use]
    pub fn upgrade(&self) -> Option<BoxHandle> {
        Some(BoxHandle(
            self.0.upgrade()?,
            self.1.clone(),
            Arc::clone(&self.2),
        ))
    }

    /// A dangling handle whose actor is already gone (`upgrade` always yields
    /// `None`). Test-only: lets fixtures that never exercise the session
    /// round-trip satisfy an `EnvArgs`/`BoxChannel` that now requires a
    /// handle, without standing up a live actor.
    #[cfg(test)]
    pub(crate) fn dangling() -> Self {
        let (tx, _rx) = crate::traced::channel::<BoxMessage>(1);
        let weak = tx.downgrade();
        // Drop the only strong sender so `upgrade()` returns `None`.
        drop(tx);
        Self(weak, CancellationToken::new(), HostSlot::default())
    }

    /// A handle to a stand-in "actor" that answers each expose request with
    /// the next of `answers`, and drops the reply channel for any request
    /// past them — the dead-actor path no live actor can be made to take on
    /// demand. Test-only: lets the env channel's tests drive the typed
    /// failures [`BoxHandle::expose_dynamic`] hands back, without
    /// standing up a session whose publish genuinely fails. The stand-in
    /// keeps its strong sender alive for the test's runtime, so `upgrade()`
    /// holds; only messages it answers reach a reply.
    #[cfg(test)]
    pub(crate) fn answering(
        answers: Vec<Result<minimald_rpc::LiveMapping, crate::net::policy::ExposeFailure>>,
    ) -> Self {
        let (tx, mut rx) = crate::traced::channel::<BoxMessage>(1);
        let weak = tx.downgrade();
        crate::traced::spawn(async move {
            // Hold the strong sender for the runtime the test lives in:
            // without a live sender the channel closes and the asker's
            // `upgrade()` fails before any answer is reached.
            let _hold = tx;
            let mut answers = answers.into_iter();
            while let Some((message, _span)) = rx.recv().await {
                // Past the script, no answer is sent: `reply` drops
                // unanswered, which the asker types as the actor being gone.
                if let BoxMessage::ExposeDynamic { reply, .. } = message
                    && let Some(answer) = answers.next()
                {
                    #[expect(
                        clippy::let_underscore_must_use,
                        reason = "the asker whose request was answered is the env \
                                  channel, which has no use for a send receipt"
                    )]
                    let _ = reply.send(answer);
                }
            }
        });
        Self(weak, CancellationToken::new(), HostSlot::default())
    }
}
