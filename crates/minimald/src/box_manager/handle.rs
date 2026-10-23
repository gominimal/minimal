//! The handles other actors hold to reach the [`BoxManager`](super::BoxManager) actor.

use std::collections::HashSet;
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;

use boxes::SessionId;
use common::SpecHash;
use tokio_util::sync::CancellationToken;

use super::{
    BoxInfo, BoxKeyPredicate, BoxManagerError, CreateSessionMsg, ManagerMessage, Responder,
};
use crate::box_actor::BoxHandle;

/// The handle to the session manager.
#[derive(Debug, Clone)]
pub struct BoxManagerHandle {
    pub(super) sender: crate::traced::Sender<ManagerMessage>,
    /// The actor's [`BoxManager::in_shutdown`](super::BoxManager::in_shutdown).
    pub(super) in_shutdown: CancellationToken,
    /// A clone of the actor's shared PTask hostname registry, handed to the
    /// host-side proxies so they resolve `Host:` headers without a round-trip
    /// through the actor mainloop.
    #[cfg(target_os = "linux")]
    pub(super) hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
    /// The actor's lease book, held only for the one test seam below: a test
    /// that needs this daemon to be in the state a daemon whose deferred
    /// probe is still walking holds its book in. Production callers reach
    /// the book through the manager actor, which owns it.
    #[cfg(all(test, target_os = "linux"))]
    pub(super) loopback: Arc<crate::net::dns::LoopbackLeaseBook>,
}

/// A non-owning handle to the [`BoxManager`](super::BoxManager) actor.
///
/// Held by per-session machinery that must be able to reach the manager
/// (notably a session's [`Binding`](crate::box_runtime), to request its own
/// destruction) without keeping the actor alive. See [`BoxManager::weak_self`](super::BoxManager::weak_self) for
/// why the path back to the manager must be weak.
#[derive(Debug, Clone)]
pub struct WeakBoxManagerHandle {
    pub(super) sender: crate::traced::WeakSender<ManagerMessage>,
    /// Mirrors [`BoxManagerHandle::in_shutdown`].
    pub(super) in_shutdown: CancellationToken,
    /// Mirrors [`BoxManagerHandle::hostnames`]; the registry `Arc` is held so an
    /// [`upgrade`](Self::upgrade) can reconstruct a full handle. This does not
    /// keep the actor alive (only live senders do).
    #[cfg(target_os = "linux")]
    pub(super) hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
    /// Mirrors [`BoxManagerHandle::loopback`], for the same reason: the test seam
    /// must survive an upgrade.
    #[cfg(all(test, target_os = "linux"))]
    pub(super) loopback: Arc<crate::net::dns::LoopbackLeaseBook>,
}

impl WeakBoxManagerHandle {
    /// Promotes to a strong [`BoxManagerHandle`], or `None` if the manager actor
    /// has already shut down (all strong senders dropped).
    #[must_use]
    pub fn upgrade(&self) -> Option<BoxManagerHandle> {
        Some(BoxManagerHandle {
            sender: self.sender.upgrade()?,
            in_shutdown: self.in_shutdown.clone(),
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&self.hostnames),
            #[cfg(all(test, target_os = "linux"))]
            loopback: Arc::clone(&self.loopback),
        })
    }
}

/// A non-owning handle to manipulate a specific session on a sessions actor.
///
/// Used by downstream actors (i.e. [`Binding`](crate::box_runtime)) to
/// manipulate the session itself, such as deletion.
#[derive(Debug, Clone)]
pub struct BoxControl {
    pub(super) manager: WeakBoxManagerHandle,
    pub(super) id: SessionId,
}

impl BoxControl {
    /// Binds the destroy capability to a specific session.
    #[must_use]
    pub fn new(manager: WeakBoxManagerHandle, id: SessionId) -> Self {
        Self { manager, id }
    }

    /// Requests the manager delete this session: kills the host and removes the
    /// on-disk record. Errors if the manager has already shut down, or if the
    /// delete itself fails (e.g. the manager is mid-shutdown).
    pub async fn destroy(&self) -> Result<(), BoxManagerError> {
        match self.manager.upgrade() {
            Some(mngr) => mngr.delete_session(self.id).await.map(drop),
            None => Err(BoxManagerError::new(
                std::io::ErrorKind::NotConnected,
                "sessions manager is gone",
            )),
        }
    }

    /// Reports that a binding has left a session that outlives it, so the
    /// session runs its `on_detach` hooks.
    ///
    /// Returns nothing: leaving is not a fallible operation from the
    /// departing side, and every way this can come up empty — the manager
    /// already shut down, the session already gone — means there is nothing
    /// left to run hooks against. Those are logged where they can be
    /// explained, not raised here.
    pub async fn detached(&self) {
        let Some(mngr) = self.manager.upgrade() else {
            return;
        };
        match mngr.get_session(BoxKeyPredicate::Id(self.id)).await {
            Ok(Some(session)) => session.run_detach_hooks().await,
            Ok(None) => {}
            Err(e) => tracing::warn!(
                error = %e,
                session = %self.id,
                "could not reach the session to run its detach hooks",
            ),
        }
    }
}

impl BoxManagerHandle {
    /// Whether a shutdown is under way: set before the shutdown stops any
    /// session, so a command it ends can still see why when it returns.
    #[must_use]
    pub fn is_shutting_down(&self) -> bool {
        self.in_shutdown.is_cancelled()
    }

    /// Returns a non-owning handle to this manager.
    #[must_use]
    pub fn downgrade(&self) -> WeakBoxManagerHandle {
        WeakBoxManagerHandle {
            sender: self.sender.downgrade(),
            in_shutdown: self.in_shutdown.clone(),
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&self.hostnames),
            #[cfg(all(test, target_os = "linux"))]
            loopback: Arc::clone(&self.loopback),
        }
    }

    /// Returns a shared handle to the in-memory PTask hostname registry, for the
    /// daemon's host-side proxies ([`crate::net::proxy`]) to route by `Host:`
    /// header.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn hostnames(&self) -> Arc<RwLock<crate::net::dns::HostnameRegistry>> {
        Arc::clone(&self.hostnames)
    }

    /// Puts this daemon's verdict over the reserved local range back in the
    /// state a daemon whose forwarder-conducted probe is still walking holds
    /// its book in ([`crate::net::dns::RangeVerdict::Pending`]) — the window a
    /// microVM daemon is already serving RPCs in, and the one a box resumed
    /// by the first of them must still be answered in (NET-013).
    ///
    /// Test-only: no production path needs to *un-know* a verdict it has, and
    /// one that did would want a message, not a setter.
    ///
    /// The daemon's one verdict deadline restarts with it, as it does for a
    /// daemon that has just started, so the window is the full
    /// [`crate::net::dns::HAND_VERDICT_WAIT`] however long the harness took
    /// to come up.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn hold_range_verdict_pending(&self) {
        self.loopback
            .set_range_verdict(crate::net::dns::RangeVerdict::Pending);
        self.loopback
            .reset_hand_verdict_deadline(crate::net::dns::HAND_VERDICT_WAIT.as_millis() as u64);
    }

    /// Lands a range verdict with the arms the deferred walk runs when it
    /// lands one — the state change and the re-publishes that follow it — so
    /// a test drives the window's endings the way the walk does.
    /// [`Self::hold_range_verdict_pending`] opens the window; this closes it,
    /// over whatever the window published.
    ///
    /// Test-only: the production path that lands a verdict is the walk
    /// itself, and it lands the probe's answer, never a test's.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn land_range_verdict(&self, verdict: crate::net::dns::RangeVerdict) {
        super::land_range_verdict(&self.loopback, &self.hostnames, verdict);
    }

    /// The daemon's answerer lease book, for the tests that drive a
    /// landing's two halves apart — the draw and the apply between which a
    /// box can die — the way the walk's single landing never does.
    ///
    /// Test-only: production code reaches the book through the paths that
    /// ask it, not by handle.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn loopback_book(&self) -> &std::sync::Arc<crate::net::dns::LoopbackLeaseBook> {
        &self.loopback
    }

    /// Moves the daemon's one verdict deadline to `millis` from now, so a
    /// test proves the expiry shape — the interim published when the
    /// deadline runs out — without paying the real deadline, or holds the
    /// window open long enough to tell a registration that waited from one
    /// that did not.
    ///
    /// Test-only: no production path changes a deadline it is itself bounded
    /// by.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn reset_hand_verdict_deadline(&self, millis: u64) {
        self.loopback.reset_hand_verdict_deadline(millis);
    }

    /// How many registrations are waiting on the range verdict right now
    /// ([`crate::net::dns::LoopbackLeaseBook::verdict_waiters`]), so a test
    /// lands the verdict only once a registration provably waits for it.
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn verdict_waiters(&self) -> usize {
        self.loopback.verdict_waiters()
    }

    /// Enqueues the resume of every active session restored from the store
    /// (see [`BoxManager::resume_active_sessions`](super::BoxManager::resume_active_sessions)) and returns the future that
    /// answers with how many actors it started. The message is in the
    /// manager's mailbox when this returns, so any message sent after it —
    /// an RPC's lookup of a restored session, say — is served once the
    /// resume has registered the restored names; the answer can be awaited
    /// later, or not at all.
    ///
    /// [`crate::server::Server::run`] enqueues this once, before its accept
    /// loop opens, and awaits the answer off that path. It is a message
    /// rather than part of [`BoxManager::init`](super::BoxManager::init) so the test harness, which
    /// builds the manager without `Server::run`, can open a window (a
    /// pending range verdict, say) before the resume.
    #[cfg(target_os = "linux")]
    pub async fn enqueue_resume_active_sessions(
        &self,
    ) -> impl Future<Output = Result<usize, BoxManagerError>> + Send + 'static {
        let (send, recv) = Responder::channel();
        #[expect(
            clippy::let_underscore_must_use,
            reason = "a closed manager is the one way the send can fail, and the recv \
                      reports it — the send's own receipt has nothing to add"
        )]
        let _ = self.sender.send(ManagerMessage::ResumeActive(send)).await;
        async move { recv.await.expect("corresponding sessions manager is dead") }
    }

    /// [`Self::enqueue_resume_active_sessions`], awaited: starts the actor
    /// of every active session restored from the store and returns how many
    /// it started.
    #[cfg(target_os = "linux")]
    pub async fn resume_active_sessions(&self) -> Result<usize, BoxManagerError> {
        self.enqueue_resume_active_sessions().await.await
    }

    /// Lists the sessions known to this (minimald) instance.
    pub async fn list(&self) -> Result<Vec<BoxInfo>, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.sender.send(ManagerMessage::List(send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// How many session actors are live. See
    /// [`ManagerMessage::RunningCount`].
    #[cfg(test)]
    pub(crate) async fn running_count(&self) -> usize {
        let (send, recv) = Responder::channel();
        let _ = self.sender.send(ManagerMessage::RunningCount(send)).await;
        recv.await
            .expect("corresponding sessions manager is dead")
            .expect("counting live actors cannot fail")
    }

    /// Reads a session's persisted composition snapshot.
    ///
    /// Read-only: unlike [`Self::get_session`] this never brings the
    /// session's actor up, so a query about a stopped session does not
    /// start it. `None` for an unknown session and for one with no
    /// snapshot — the two are indistinguishable here on purpose, since
    /// both mean "nothing recorded to report".
    pub async fn get_composition(
        &self,
        pred: BoxKeyPredicate,
    ) -> Result<Option<boxes::core::compose::Composition>, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetComposition(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets the session record which corresponds to the given predicate.
    pub async fn get_record(
        &self,
        pred: BoxKeyPredicate,
    ) -> Result<Option<boxes::Record>, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetRecord(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Creates a session from the given config, returning its allocated id.
    /// The session comes up live but unconfigured — [`configure_loadout`]
    /// against the returned id composes its loadout and finalizes it.
    ///
    /// `username` is the authenticated SSH user from the connection context;
    /// pass `None` for non-SSH callers (e.g. in-process daemon callers and
    /// tests).
    ///
    /// [`configure_loadout`]: crate::box_actor::BoxHandle::configure_loadout
    pub async fn create_session(
        &self,
        config: minimald_rpc::BoxConfig,
        username: Option<String>,
    ) -> Result<SessionId, BoxManagerError> {
        self.create_session_by(config, username, None).await
    }

    /// [`Self::create_session`] for a session created over a connection:
    /// `creator` is that connection's liveness. While it still upgrades the
    /// session's activation belongs to its creator, so an attach to the
    /// still-unconfigured session is refused instead of configuring it (see
    /// the `Draft` shortcut in `BoxActor::attach`). Passed at creation, not
    /// afterwards, so there is no window in which the actor exists without it.
    pub async fn create_session_by(
        &self,
        config: minimald_rpc::BoxConfig,
        username: Option<String>,
        creator: Option<std::sync::Weak<()>>,
    ) -> Result<SessionId, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::CreateSession(Box::new(CreateSessionMsg {
                config,
                username,
                creator,
                responder: send,
            })))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// The union of what every active session needs: the spec hash of each package
    /// reachable from any session's tasks, stack, or `[session]` block.
    ///
    /// Resolving a session brings its actor up if it isn't running, exactly as
    /// [`get_session`](Self::get_session) does.
    pub async fn needed_packages(&self) -> Result<HashSet<SpecHash>, BoxManagerError> {
        let mut out = HashSet::new();
        for info in self.list().await? {
            if info.status != boxes::BoxState::Active {
                continue;
            }
            // Deleted between the list and the lookup: gone, so needs nothing.
            let Some(session) = self.get_session(BoxKeyPredicate::Id(info.id)).await? else {
                continue;
            };
            let pkgs = session
                .needed_packages()
                .await
                .map_err(|e| BoxManagerError::other(format!("session {}: {e}", info.id)))?;
            out.extend(pkgs);
        }

        Ok(out)
    }

    /// Gets a handle to the session corresponding with the given predicate.
    pub async fn get_session(
        &self,
        pred: BoxKeyPredicate,
    ) -> Result<Option<BoxHandle>, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetSession(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Snapshots the terminal screen of a running session. `Ok(None)` when
    /// the session is unknown or has no live host — never starts an actor.
    pub async fn get_screen(
        &self,
        pred: BoxKeyPredicate,
    ) -> Result<Option<minimald_rpc::ScreenSnapshot>, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetScreen(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Deletes the session with the given ID, cascadingly tearing down its
    /// running host and actor (if any) before removing its on-disk record.
    ///
    /// On success, returns one line per `on_destroy` hook that failed.
    /// Returns a `NotFound` error if no session with that ID is known.
    pub async fn delete_session(&self, id: SessionId) -> Result<Vec<String>, BoxManagerError> {
        self.delete(id, false).await.map(Option::unwrap_or_default)
    }

    /// [`Self::delete_session`] for a session that has not finished
    /// activating: `Ok(None)`, with the session left as it is, when it had —
    /// decided by the session after any finalize already in flight. The
    /// cleanup a client or the connection-close reap sends for an activation
    /// that was given up on (inbox#690).
    pub async fn delete_session_if_unfinalized(
        &self,
        id: SessionId,
    ) -> Result<Option<Vec<String>>, BoxManagerError> {
        self.delete(id, true).await
    }

    async fn delete(
        &self,
        id: SessionId,
        only_if_unfinalized: bool,
    ) -> Result<Option<Vec<String>>, BoxManagerError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::DeleteSession(id, only_if_unfinalized, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Shuts down all sessions for process termination. If force is true, live sessions are killed.
    /// If force is false but there are live sessions, an error is returned.
    pub async fn shutdown(&self, force: bool) -> Result<(), ()> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::Shutdown(force, send))
            .await;
        recv.await
            .expect("corresponding sessions manager is dead")
            .expect("no SessionError expected from shutdown msg")
    }

    /// Drop the `running` entry for a session whose actor terminated on its
    /// own (abort, failed verdict resume, create failure). Fire-and-forget:
    /// never awaits a reply, so a self-terminating actor can call it without
    /// any risk of a cycle with a manager that might be awaiting the actor.
    pub(crate) async fn evict(&self, id: SessionId) {
        let _ = self.sender.send(ManagerMessage::Evict(id)).await;
    }
}
