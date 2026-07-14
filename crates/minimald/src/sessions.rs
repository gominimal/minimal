use std::{collections::BTreeMap, io::ErrorKind::NotFound};

use crate::{
    session::{Session, SessionHandle},
    session_host::HostAttrs,
};
use paths::DaemonAbsPath;
use sessions::{
    SessionId,
    daemon::composer::{ComposeOutcome, PendingComposeState, resume_from_verdict},
    store::{DiskLoader, Loader, SessionKey, SessionObject},
    wire::request::{ContributionVerdict, SessionStep, WireContribution},
};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;
use tokio::sync::{Mutex, mpsc, oneshot};

mod composables;
#[cfg(test)]
use composables::ProjectResolution;
use composables::{build_composables, resolve_project_ctx_and_graph, run_composer};

/// A short summary of the metadata of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    pub name: Option<String>,
    pub attrs: Option<HostAttrs>,
}

/// A key you can use to identify a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKeyPredicate {
    Id(SessionId),
    Name(String),
}

/// Transport / internal error when communicating with the sessions actor.
type SessionsError = std::io::Error;

/// The name a PTask hostname is registered under: the session's assigned name,
/// or the project directory's basename when unnamed (matching how a session
/// host derives its display name).
#[cfg(target_os = "linux")]
fn registry_name(record: &sessions::Record) -> String {
    match &record.name {
        Some(s) => s.clone(),
        None => record
            .project_path
            .file_name()
            .map(|s| s.to_string())
            .unwrap_or_else(|| "session".to_string()),
    }
}

/// Assemble a [`sessions::Record`] from the out-of-band session
/// config and the SSH-supplied username, then validate its policy.
/// Returns `Err(io::InvalidInput)` if the policy is incompatible
/// with the network mode (R2.1) — so an invalid session is never
/// written to the store. The `id` field is left as `nil`; the store
/// allocates the real id at `create` time.
///
/// Shared by the `Ready` and `Pending` branches of the
/// `CreateSession` handler so both paths persist the same record
/// shape, differing only in their initial `status`.
fn build_record(
    config: minimald_rpc::SessionConfig,
    username: Option<String>,
    status: sessions::SessionStatus,
) -> Result<sessions::Record, std::io::Error> {
    let record = sessions::Record {
        id: SessionId::nil(),
        name: config.name,
        username,
        project_path: config.project_path,
        network: config.network,
        policy: config.policy,
        status,
        attrs: config.attrs,
    };
    record
        .validate_policy()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
    Ok(record)
}

/// Encapsulates the return channel for messages back from the actor.
#[derive(Debug)]
struct Responder<T>(oneshot::Sender<Result<T, SessionsError>>);

impl<T> Responder<T> {
    /// Constructs both ends of the return channel.
    pub fn channel() -> (Self, oneshot::Receiver<Result<T, SessionsError>>) {
        let (send, recv) = oneshot::channel();
        (Self(send), recv)
    }

    /// Awaits the provided future, transmitting its result to the caller.
    pub async fn handle<F>(self, fut: F)
    where
        F: Future<Output = Result<T, SessionsError>>,
    {
        let _ = self.0.send(fut.await);
    }
}

/// Maximum number of in-flight `Pending` sessions the manager will
/// stash before refusing further `CreateSession` requests that
/// produce a [`ComposeOutcome::Pending`].
///
/// Each entry holds a [`PendingComposeState`] (a few KB of vectors,
/// the client's wire contribution, and the by-id pending stash). A
/// misbehaving or abandoned client could otherwise call
/// `CreateSession` repeatedly without ever sending `SubmitVerdict`,
/// growing the stash without bound; the cap exists as a backstop.
///
/// `Ready` outcomes never consume stash capacity, so this bound
/// only matters once daemon-side contributors are wired in.
const MAX_PENDING_SESSIONS: usize = 1024;

/// CreateSession payload — boxed so it doesn't dominate
/// `ManagerMessage`'s size (the variant carries a full session
/// config + an optional contribution; other variants are just a
/// few words).
#[derive(Debug)]
struct CreateSessionMsg {
    config: minimald_rpc::SessionConfig,
    /// Authenticated SSH username, supplied by the RPC handler from
    /// the SSH connection context (never the client).
    username: Option<String>,
    /// Client-side Phase 1 contribution. Fed into `SessionComposer`
    /// in the handler: the composer either finalizes a `Composition`
    /// (persist Active, ship `Ready { id }`) or routes items back to
    /// the client for gating (persist Pending, stash state, ship
    /// `Pending { id, response }`). A cross-process merge conflict
    /// or malformed wire item surfaces as `InvalidInput`.
    contribution: WireContribution,
    responder: Responder<minimald_rpc::CreateSessionResponse>,
}

/// SubmitVerdict payload — boxed for the same size-balance reason as
/// [`CreateSessionMsg`]. Carries the client's per-item decisions for
/// a `Pending` session id; the handler pops the matching stash from
/// `Manager::pending`, calls [`resume_from_verdict`], promotes the
/// record `Pending → Active`, and replies with [`SessionStep::Active`].
#[derive(Debug)]
struct SubmitVerdictMsg {
    verdict: ContributionVerdict,
    responder: Responder<SessionStep>,
}

enum ManagerMessage {
    List(Responder<Vec<SessionInfo>>),
    GetRecord(SessionKeyPredicate, Responder<Option<sessions::Record>>),
    GetSession(SessionKeyPredicate, Responder<Option<SessionHandle>>),
    CreateSession(Box<CreateSessionMsg>),
    SubmitVerdict(Box<SubmitVerdictMsg>),
    RenameSession(SessionId, String, Responder<()>),
    DestroySession(SessionId, Responder<()>),
    AbortSession(SessionId, Responder<()>),
    Shutdown(bool, Responder<Result<(), ()>>),
    /// Test-only inspection: reply with the current size of the
    /// `compositions` stash. Used to assert stash lifecycle
    /// transitions (insert on Ready → drain on GetSession →
    /// cleanup on Destroy/Abort) without exposing the internal
    /// map to production callers.
    #[cfg(test)]
    CompositionsLen(Responder<usize>),
    /// Test-only inspection: reply with an [`Arc`] clone of the
    /// stashed [`Composition`] for a given [`SessionId`], or `None`
    /// if absent. Used to assert that composables actually reached
    /// the composition with the expected contents (packages, vars),
    /// not just that a stash entry exists.
    #[cfg(test)]
    PeekComposition(
        SessionId,
        Responder<Option<Arc<sessions::core::compose::Composition>>>,
    ),
}

/// Manages session instances, and session state on disk.
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct Manager<L: Loader = DiskLoader> {
    in_shutdown: bool,
    receiver: mpsc::Receiver<ManagerMessage>,
    running: BTreeMap<L::Key, SessionHandle>,
    store: L,

    /// A weak handle to this manager, handed down to each session it spawns so
    /// a session's [`Binding`](crate::session_host) can ask the manager to
    /// destroy it (the "delete" choice on the shell-exit prompt) without owning
    /// the manager. It must be weak: a strong self-handle would keep the
    /// manager's own `recv` loop from ever seeing all senders dropped (wedging
    /// shutdown) and would close an ownership cycle
    /// (manager → session → host → binding → manager).
    weak_self: WeakManagerHandle,

    /// Per-session stash for in-flight `CreateSession` flows that
    /// reached [`ComposeOutcome::Pending`]. Keyed by the daemon's
    /// allocated [`SessionId`]; the matching `SubmitVerdict` pops
    /// the entry and finalizes. The stash is in-memory only — if
    /// the daemon restarts mid-flow the on-disk
    /// `SessionStatus::Pending` record loses its match and is
    /// reaped by [`Manager::reap_orphan_pending`] at startup.
    pending: BTreeMap<SessionId, PendingComposeState>,

    /// Per-session stash of finalized [`Composition`]s awaiting
    /// their `Session` actor. Populated on `CreateSession` / post-
    /// verdict, drained on first `GetSession`. In-memory only; a
    /// daemon restart drops the stash and post-restart spawns fall
    /// back to the launcher's baseline.
    ///
    /// `DestroySession` / `AbortSession` also drain the stash
    /// defensively — without those drains a client that activates
    /// then destroys without ever attaching would leak an entry per
    /// cycle.
    ///
    /// [`Composition`]: sessions::core::compose::Composition
    compositions: BTreeMap<SessionId, Arc<sessions::core::compose::Composition>>,

    /// Daemon-scoped mctx state (config, stdlib_dir, vcs, cache) shared
    /// with each per-session `mctx::Context` the manager builds at
    /// `CreateSession` time. Held behind `Arc` so the daemon-level
    /// setup work runs once per process rather than per session.
    daemon_ctx: Arc<mctx::DaemonContext>,

    minimal_state_dir: DaemonAbsPath,
    minimal_cache_dir: DaemonAbsPath,
    /// The daemon-scoped gvproxy switch, handed to each session it starts so an
    /// `OwnIp` PTask attaches to the one per-host switch (R1.4/R1.5/R1.6).
    net_switch: Arc<Mutex<crate::net::SwitchClient>>,

    /// In-memory PTask hostname registry (Unit 3). Shared behind an `Arc<RwLock>`
    /// so the daemon's host-side proxies ([`crate::net::proxy`]) can resolve a
    /// `Host:` header without routing through the actor mainloop, while the
    /// manager still mutates it under `&mut self`. The lock is only ever held for
    /// a synchronous register/deregister/resolve, never across an `.await`.
    /// `HostNet` PTasks register on launch and withdraw on teardown.
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
}

impl Manager {
    /// Launches a sessions manager managing sessions in
    /// the given minimal state dir.
    pub async fn init(
        minimal_state_dir: DaemonAbsPath,
        minimal_cache_dir: DaemonAbsPath,
        mctx_config: mctx::Config,
        net_switch: Arc<Mutex<crate::net::SwitchClient>>,
    ) -> Result<ManagerHandle, std::io::Error> {
        let mut l = DiskLoader::new(minimal_state_dir.clone())?;
        Self::reap_orphan_pending(&mut l)?;

        // Build the daemon-scoped mctx state once at startup. Each
        // `CreateSession` will build a per-session `Context` on top of
        // this via `Context::from_daemon` rather than repeating the
        // setup (dir upsert / VCS init / cache init / stdlib
        // materialization) per session. The caller supplies the
        // `mctx::Config` so daemon-level flags (offline, num-parallel-
        // builds, stdlib override, remote cache bucket) propagate.
        // `mctx::Error` isn't `Send + Sync` (it carries nickel-language
        // `Rc`s), so we can't preserve the source chain across the
        // `io::Error` boundary. Stringify and move on; this only fires
        // at daemon startup, at which point failure aborts the process.
        let daemon_ctx = Arc::new(
            mctx::DaemonContext::init(mctx_config)
                .map_err(|e| std::io::Error::other(format!("mctx daemon init: {e}")))?,
        );

        let running = BTreeMap::new();
        let (sender, receiver) = mpsc::channel(8);
        // Shared so the host-side proxies can resolve `Host:` headers directly;
        // a clone is held by both the actor (which mutates it) and the handle
        // (which hands it to the proxies via `hostnames()`).
        #[cfg(target_os = "linux")]
        let hostnames = Arc::new(RwLock::new(crate::net::dns::HostnameRegistry::new(
            crate::net::dns::DEFAULT_HOST_ID,
        )));
        let handle = ManagerHandle {
            sender,
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&hostnames),
        };
        // A non-owning path back to this actor, handed to each spawned session
        // so its binding can request destruction (see `weak_self`).
        let weak_self = handle.downgrade();
        let mngr = Self {
            in_shutdown: false,
            receiver,
            running,
            store: l,
            weak_self,
            pending: BTreeMap::new(),
            compositions: BTreeMap::new(),
            daemon_ctx,
            minimal_state_dir,
            minimal_cache_dir,
            net_switch,
            #[cfg(target_os = "linux")]
            hostnames,
        };

        tokio::spawn(mngr.mainloop());
        Ok(handle)
    }
}

impl<L: Loader> Manager<L> {
    fn key_for(&self, pred: &SessionKeyPredicate) -> Result<Option<L::Key>, std::io::Error> {
        match pred {
            SessionKeyPredicate::Id(id) => self.store.find_by_id(id),
            SessionKeyPredicate::Name(name) => self.store.find_by_name(name),
        }
    }

    /// Delete any on-disk `Pending` records at startup. Their
    /// in-memory `PendingComposeState` didn't survive the restart,
    /// so they can never transition to `Active`.
    fn reap_orphan_pending(store: &mut L) -> Result<(), std::io::Error> {
        let mut reaped = 0u64;
        let keys: Vec<L::Key> = store.keys().collect();
        for k in keys {
            let obj = store.get(&k)?;
            if obj.record().status == sessions::SessionStatus::Pending {
                let id = obj.record().id;
                store.delete(&k)?;
                tracing::info!(
                    session_id = %id,
                    "reaped orphan Pending session on startup",
                );
                reaped += 1;
            }
        }
        if reaped > 0 {
            tracing::info!(count = reaped, "orphan Pending reap complete");
        }
        Ok(())
    }

    /// The async task which handles interactions with the
    /// manager.
    async fn mainloop(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }

    /// Handles a specific message recieved by the manager.
    async fn handle_message(&mut self, msg: ManagerMessage) {
        match msg {
            // Lists all sessions.
            ManagerMessage::List(r) => {
                r.handle(async {
                    let mut out = Vec::with_capacity(32);
                    for k in self.store.keys() {
                        out.push({
                            let s = self.store.get(&k)?;
                            let r = s.record();
                            SessionInfo {
                                id: r.id,
                                name: r.name.clone(),
                                attrs: match self.running.get(&k) {
                                    Some(h) => h.get_attrs().await,
                                    None => None,
                                },
                            }
                        });
                    }
                    Ok(out)
                })
                .await;
            }
            // Gets the record for a specific session.
            ManagerMessage::GetRecord(pred, r) => {
                r.handle(async {
                    Ok::<_, SessionsError>(match pred {
                        SessionKeyPredicate::Id(id) => self
                            .store
                            .find_by_id(&id)?
                            .map(|k| self.store.get(&k).unwrap().record().clone()),
                        SessionKeyPredicate::Name(name) => self
                            .store
                            .find_by_name(&name)?
                            .map(|k| self.store.get(&k).unwrap().record().clone()),
                    })
                })
                .await;
            }
            // Get the session actor for the predicate, starting it
            // if the session is known but not running. `Pending`
            // records return `None` (they have no `Composition`
            // yet, so attaching would give a half-built session).
            ManagerMessage::GetSession(pred, r) => {
                r.handle(async {
                    if self.in_shutdown {
                        return Err(SessionsError::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "in shutdown",
                        ));
                    }
                    match self.key_for(&pred)? {
                        None => Ok(None),
                        Some(k) => {
                            let obj = self.store.get(&k)?;
                            if obj.record().status != sessions::SessionStatus::Active {
                                tracing::info!(
                                    session_id = %obj.record().id,
                                    status = ?obj.record().status,
                                    "refused GetSession on non-Active session",
                                );
                                return Ok(None);
                            }
                            let session_handle = match self.running.get(&k) {
                                Some(h) => h.clone(),
                                None => {
                                    // Not running, start it!
                                    let obj = self.store.get(&k)?;
                                    // Register a PTask's hostname on launch so it
                                    // routes host-side (R3.1/R3.6). Both HostNet and
                                    // OwnIp resolve to loopback: a HostNet PTask's
                                    // listeners are on host loopback; an OwnIp PTask
                                    // is reached through a gvproxy-published loopback
                                    // port (#542, the published-loopback model). A
                                    // NoNet PTask exposes no services, so it is not
                                    // registered. Capture id + name + mode before
                                    // `obj` moves into `Session::run`.
                                    #[cfg(target_os = "linux")]
                                    let ptask_reg = {
                                        let net = obj.record().network;
                                        matches!(
                                            net,
                                            sessions::NetworkMode::HostNet
                                                | sessions::NetworkMode::OwnIp
                                        )
                                        .then(|| {
                                            (obj.record().id, registry_name(obj.record()), net)
                                        })
                                    };
                                    // Hand over the finalized composition,
                                    // if it's still in the manager's stash.
                                    // Absent after a daemon restart — the
                                    // actor spawns without one, and the
                                    // record is still usable.
                                    //
                                    // Clone the `Arc` rather than draining
                                    // now, so that a `Session::run` failure
                                    // below leaves the stash intact: the
                                    // next `GetSession` retry will still
                                    // see the composition and run
                                    // identically. Drain happens only on
                                    // the success path just after the
                                    // spawn returns.
                                    let session_id = obj.record().id;
                                    let composition = self.compositions.get(&session_id).cloned();
                                    // A spawn failure at this point (only
                                    // I/O failures on `mkdir` of the
                                    // workspace / home / cache dirs today)
                                    // means the session can't be brought
                                    // up — surface as an `io::Error` to
                                    // the client rather than panicking the
                                    // actor. Leaves the record on disk and
                                    // the composition in the stash; the
                                    // next GetSession retries the same
                                    // setup and either succeeds or errors
                                    // identically.
                                    let h = Session::run(
                                        self.minimal_state_dir.clone(),
                                        self.minimal_cache_dir.clone(),
                                        obj,
                                        Arc::clone(&self.net_switch),
                                        composition,
                                        self.weak_self.clone(),
                                    )
                                    .await?;
                                    // Spawn succeeded — safe to drain the
                                    // stash. If the entry is already gone
                                    // (post-restart spawn with a `None`
                                    // composition), the remove is a
                                    // no-op.
                                    self.compositions.remove(&session_id);
                                    #[cfg(target_os = "linux")]
                                    if let Some((id, name, net)) = ptask_reg {
                                        let mut reg = self
                                            .hostnames
                                            .write()
                                            .expect("hostname registry lock poisoned");
                                        match net {
                                            sessions::NetworkMode::OwnIp => {
                                                reg.register_own_ip(id, &name)
                                            }
                                            _ => reg.register_host_net(id, &name),
                                        };
                                    }
                                    self.running.insert(k, h.clone());
                                    h
                                }
                            };
                            Ok(Some(session_handle))
                        }
                    }
                })
                .await;
            }
            // Create a session: resolve the project, build the
            // composables, and drive the composer. Failures pre-mapped
            // to `InvalidInput`.
            ManagerMessage::CreateSession(msg) => {
                let CreateSessionMsg {
                    config,
                    username,
                    contribution,
                    responder,
                } = *msg;
                // Capture `in_shutdown` by value before we take
                // `&mut self` borrows below — the async move needs
                // to see it without holding a `self` reference.
                let in_shutdown = self.in_shutdown;

                let outcome = resolve_project_ctx_and_graph(&self.daemon_ctx, &config.project_path)
                    .and_then(|resolution| {
                        let (project_composable, package_composables) =
                            build_composables(&config.project_path, &resolution, &contribution)?;
                        run_composer(contribution, project_composable, package_composables)
                    });
                let pending = &mut self.pending;
                let compositions = &mut self.compositions;
                let store = &mut self.store;
                responder
                    .handle(async move {
                        if in_shutdown {
                            return Err(SessionsError::new(
                                std::io::ErrorKind::ConnectionRefused,
                                "in shutdown",
                            ));
                        }
                        // Phase 2: branch on the composer outcome.
                        //
                        // `Ready` — composition is complete; persist
                        // the record as `Active`, stash the
                        // [`Composition`] against its allocated id so
                        // the [`Session`] actor picks it up on its
                        // first spawn, and ship
                        // `CreateSessionResponse::Ready { id }`.
                        //
                        // `Pending` — the client must gate items
                        // before composition completes. Allocate the
                        // id by persisting the record as `Pending`,
                        // stash the daemon-side resume state under
                        // that id, overwrite the placeholder
                        // `session_id` on the wire response, and ship
                        // `CreateSessionResponse::Pending { id, response }`.
                        //
                        // `Err` — a composable failed to contribute
                        // (e.g. an `Inherit`-shaped project var the
                        // daemon couldn't resolve; malformed package
                        // state_wiring), a cross-process merge
                        // conflict, or a malformed wire item. All are
                        // pre-mapped to [`std::io::ErrorKind::InvalidInput`]
                        // at the call site above.
                        match outcome {
                            Ok(ComposeOutcome::Ready(composition)) => {
                                let record = build_record(
                                    config,
                                    username,
                                    sessions::SessionStatus::Active,
                                )?;
                                let k = store.create(record)?;
                                let id = *k.id();
                                compositions.insert(id, Arc::new(composition));
                                Ok(minimald_rpc::CreateSessionResponse::Ready { id })
                            }
                            Ok(ComposeOutcome::Pending {
                                mut response,
                                state,
                            }) => {
                                // Bound the in-memory stash. Check
                                // before `store.create` so a refusal
                                // doesn't leave a half-allocated record
                                // on disk that the next daemon restart
                                // would have to reap.
                                if pending.len() >= MAX_PENDING_SESSIONS {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::ResourceBusy,
                                        format!(
                                            "daemon pending-session stash is full \
                                             (cap {MAX_PENDING_SESSIONS}); the daemon \
                                             will accept new sessions as in-flight ones \
                                             finalize or are aborted",
                                        ),
                                    ));
                                }
                                let record = build_record(
                                    config,
                                    username,
                                    sessions::SessionStatus::Pending,
                                )?;
                                let k = store.create(record)?;
                                let id = *k.id();
                                response.session_id = id;
                                pending.insert(id, state);
                                Ok(minimald_rpc::CreateSessionResponse::Pending { id, response })
                            }
                            Err(e) => Err(e),
                        }
                    })
                    .await;
            }
            // Resume a `Pending` session with the client's verdict.
            // Pops the matching `PendingComposeState` from the stash,
            // resumes composition, promotes the record `Pending →
            // Active`, and replies with `SessionStep::Active { id }`.
            // A verdict for an id with no stash → `UnknownSessionId`;
            // a record present but already `Active` (or otherwise not
            // `Pending`) → `WrongState`.
            ManagerMessage::SubmitVerdict(msg) => {
                let SubmitVerdictMsg { verdict, responder } = *msg;
                let session_id = verdict.session_id;
                // Capture by value; async move can't hold `self`.
                let in_shutdown = self.in_shutdown;
                // Only pop the stash if we're actually going to resume —
                // otherwise a shutdown-refused verdict would drop the
                // stash entry without cleanup.
                let stash_hit = if in_shutdown {
                    None
                } else {
                    self.pending.remove(&session_id)
                };
                let store = &mut self.store;
                let compositions = &mut self.compositions;
                responder
                    .handle(async move {
                        if in_shutdown {
                            return Err(SessionsError::new(
                                std::io::ErrorKind::ConnectionRefused,
                                "in shutdown",
                            ));
                        }
                        let state = match stash_hit {
                            Some(s) => s,
                            None => {
                                return Ok(SessionStep::Fault {
                                    error: sessions::wire::errors::WireError::UnknownSessionId,
                                });
                            }
                        };
                        // Run Phase 4 resume. A verdict that the
                        // composer can't apply (mismatched
                        // PendingIds, denied items, etc.) maps to a
                        // `Fault` via `WireError::from(ComposeError)`.
                        // On success the composition lands in the
                        // manager's stash so the Session actor picks
                        // it up on its first spawn (same path as the
                        // `CreateSession` Ready branch).
                        let composition = match resume_from_verdict(state, verdict) {
                            Ok(c) => c,
                            Err(e) => {
                                // Verdict couldn't be applied — the
                                // session is dead. Destroy the
                                // matching on-disk Pending record so
                                // the name is freed, `list()` doesn't
                                // show a phantom entry, and the next
                                // reap pass has nothing to clean up.
                                // A delete failure here is logged but
                                // doesn't override the verdict-level
                                // error returned to the client.
                                if let Some(k) = store.find_by_id(&session_id)?
                                    && let Err(del_err) = store.delete(&k)
                                {
                                    tracing::warn!(
                                        session_id = %session_id,
                                        error = %del_err,
                                        "failed to delete Pending record after \
                                         resume failure; record will be reaped on \
                                         next daemon restart",
                                    );
                                }
                                return Ok(SessionStep::Fault { error: e.into() });
                            }
                        };
                        // Promote the on-disk record `Pending →
                        // Active`. A mid-flight delete or a status
                        // already past `Pending` is degenerate but
                        // surfaces as a structured `WrongState`.
                        let k = match store.find_by_id(&session_id)? {
                            Some(k) => k,
                            None => {
                                return Ok(SessionStep::Fault {
                                    error: sessions::wire::errors::WireError::UnknownSessionId,
                                });
                            }
                        };
                        let mut record = store.get(&k)?.record().clone();
                        if record.status != sessions::SessionStatus::Pending {
                            return Ok(SessionStep::Fault {
                                error: sessions::wire::errors::WireError::WrongState {
                                    what: format!("expected Pending, found {:?}", record.status,),
                                },
                            });
                        }
                        record.status = sessions::SessionStatus::Active;
                        store.save(&k, &record)?;
                        compositions.insert(session_id, Arc::new(composition));
                        Ok(SessionStep::Active { id: session_id })
                    })
                    .await;
            }
            // Renames an existing session with the given ID.
            ManagerMessage::RenameSession(id, new_name, r) => {
                r.handle(async {
                    if self.in_shutdown {
                        return Err(SessionsError::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "in shutdown",
                        ));
                    }
                    match self.store.find_by_id(&id)? {
                        None => Err(std::io::Error::new(
                            NotFound,
                            format!("no session with ID `{}`", id.as_ref()),
                        )),
                        Some(k) => {
                            // Snapshot the live route (id + pre-rename name + mode)
                            // before the rename mutates the record. Only a running
                            // session has a route (registered on launch), and both
                            // HostNet and OwnIp carry one (R3.1/R3.6).
                            #[cfg(target_os = "linux")]
                            let relink: Option<(
                                SessionId,
                                String,
                                sessions::NetworkMode,
                            )> = if self.running.contains_key(&k) {
                                let rec = self.store.get(&k)?;
                                let net = rec.record().network;
                                matches!(
                                    net,
                                    sessions::NetworkMode::HostNet | sessions::NetworkMode::OwnIp
                                )
                                .then(|| (rec.record().id, registry_name(rec.record()), net))
                            } else {
                                None
                            };

                            self.store.rename(&k, new_name.clone())?;
                            if let Some(hnd) = self.running.get(&k) {
                                hnd.apply_record(self.store.get(&k)?.record().clone()).await;
                            }

                            // Follow the rename in the hostname registry so
                            // `<new>.local.min.internal` routes and the old name
                            // stops (R3.6) — otherwise the route is stranded
                            // under the launch name.
                            #[cfg(target_os = "linux")]
                            if let Some((id, old_name, net)) = relink {
                                let new_reg = registry_name(self.store.get(&k)?.record());
                                let mut reg = self
                                    .hostnames
                                    .write()
                                    .expect("hostname registry lock poisoned");
                                reg.deregister(&old_name);
                                match net {
                                    sessions::NetworkMode::OwnIp => {
                                        reg.register_own_ip(id, &new_reg)
                                    }
                                    _ => reg.register_host_net(id, &new_reg),
                                };
                            }
                            Ok(())
                        }
                    }
                })
                .await
            }
            // Abort a `Pending` session: drop its stash entry and
            // delete the on-disk record. Refuses `Active` (use
            // `DestroySession`) or unknown ids. Never touches
            // `running`: a Pending record can't be running.
            ManagerMessage::AbortSession(id, r) => {
                r.handle(async {
                    if self.in_shutdown {
                        return Err(SessionsError::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "in shutdown",
                        ));
                    }
                    let k = self.store.find_by_id(&id)?.ok_or_else(|| {
                        std::io::Error::new(
                            NotFound,
                            format!("no session with ID `{}`", id.as_ref()),
                        )
                    })?;
                    let record = self.store.get(&k)?.record().clone();
                    if record.status != sessions::SessionStatus::Pending {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            format!(
                                "cannot abort session `{}`: status is {:?}, expected Pending",
                                id.as_ref(),
                                record.status,
                            ),
                        ));
                    }
                    // Stash may be absent (post-restart orphan reached
                    // us before the reap pass, or the pending path was
                    // never populated). Delete the record either way.
                    self.pending.remove(&id);
                    // Called for symmetry with `DestroySession`.
                    // `compositions` is only populated on the Ready
                    // (post-Active) path, so a Pending abort always
                    // finds nothing here; the call is a no-op today.
                    self.compositions.remove(&id);
                    self.store.delete(&k)?;
                    Ok(())
                })
                .await
            }
            // Destroys a session: tears down its running host and actor (if
            // any), then removes its on-disk record.
            ManagerMessage::DestroySession(id, r) => {
                r.handle(async {
                    if self.in_shutdown {
                        return Err(SessionsError::new(
                            std::io::ErrorKind::ConnectionRefused,
                            "in shutdown",
                        ));
                    }
                    let k = self.store.find_by_id(&id)?.ok_or_else(|| {
                        std::io::Error::new(
                            NotFound,
                            format!("no session with ID `{}`", id.as_ref()),
                        )
                    })?;
                    // Derive the hostname registry key from the record up front,
                    // letting a read error propagate before anything is torn
                    // down. `deregister` is a no-op for a session that never
                    // registered one, so it is called unconditionally.
                    #[cfg(target_os = "linux")]
                    let host_net_name = registry_name(self.store.get(&k)?.record());
                    // Drain the composition stash before teardown. A
                    // session that never advanced to `GetSession`
                    // (created + destroyed without an attach) would
                    // otherwise leak its `Composition` in the
                    // manager's in-memory map until daemon shutdown.
                    self.compositions.remove(&id);
                    // Stop the live session first (killing its host and waiting
                    // for the sandbox to be released) so the on-disk tree is
                    // free to remove.
                    if let Some(hnd) = self.running.remove(&k) {
                        hnd.destroy().await;
                    }
                    // Withdraw the PTask hostname (R3.5) before the fallible
                    // on-disk delete, so a `delete` failure leaves a stale
                    // on-disk record (repairable on restart) but never a stale
                    // routing entry pointing at a destroyed session.
                    #[cfg(target_os = "linux")]
                    self.hostnames
                        .write()
                        .expect("hostname registry lock poisoned")
                        .deregister(&host_net_name);
                    self.store.delete(&k)?;
                    Ok(())
                })
                .await
            }
            ManagerMessage::Shutdown(force, r) => {
                r.handle(async {
                    // Sessions are live but force not given, send false to signal
                    // we didnt shutdown and continue.
                    if !self.running.is_empty() && !force {
                        return Ok(Err(()));
                    }

                    self.in_shutdown = true;
                    // Withdraw the PTask hostnames (R3.5) for every live session
                    // before tearing them down, mirroring DestroySession, so the
                    // shutdown drain never leaves stale routing entries pointing
                    // at destroyed sessions. Names are derived up front via
                    // synchronous store reads so the registry lock is never held
                    // across `destroy().await`. `deregister` is a no-op for a
                    // session that never registered a hostname.
                    #[cfg(target_os = "linux")]
                    {
                        let names: Vec<String> = self
                            .running
                            .keys()
                            .filter_map(|k| self.store.get(k).ok())
                            .map(|obj| registry_name(obj.record()))
                            .collect();
                        let mut reg = self
                            .hostnames
                            .write()
                            .expect("hostname registry lock poisoned");
                        for name in &names {
                            reg.deregister(name);
                        }
                    }
                    // Stop live sessions
                    for hnd in self.running.values() {
                        hnd.destroy().await;
                    }
                    self.running.clear();
                    // Drop any stashed compositions for symmetry with
                    // `running.clear()`. The process is exiting, so
                    // the map dies with it either way; the explicit
                    // clear documents the intent and future-proofs
                    // against a not-yet-existing "restart in place"
                    // flow.
                    self.compositions.clear();
                    // Release the cache's held-open alog fd: it lives on the
                    // state volume, and a surviving write-open fd there makes
                    // the post-drain quiesce (R2.1 syncfs + unmount) fail
                    // EBUSY, leaving the ext4 journal dirty on clean stops.
                    self.daemon_ctx.release_cache_read_tracker();
                    Ok(Ok(()))
                })
                .await
            }
            #[cfg(test)]
            ManagerMessage::CompositionsLen(r) => {
                let n = self.compositions.len();
                r.handle(async move { Ok(n) }).await;
            }
            #[cfg(test)]
            ManagerMessage::PeekComposition(id, r) => {
                let comp = self.compositions.get(&id).cloned();
                r.handle(async move { Ok(comp) }).await;
            }
        }
    }
}

/// The handle to the session manager.
#[derive(Debug, Clone)]
pub struct ManagerHandle {
    sender: mpsc::Sender<ManagerMessage>,
    /// A clone of the actor's shared PTask hostname registry, handed to the
    /// host-side proxies so they resolve `Host:` headers without a round-trip
    /// through the actor mainloop.
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
}

/// A non-owning handle to the [`Manager`] actor.
///
/// Held by per-session machinery that must be able to reach the manager
/// (notably a session's [`Binding`](crate::session_host), to request its own
/// destruction) without keeping the actor alive. See [`Manager::weak_self`] for
/// why the path back to the manager must be weak.
#[derive(Debug, Clone)]
pub struct WeakManagerHandle {
    sender: mpsc::WeakSender<ManagerMessage>,
    /// Mirrors [`ManagerHandle::hostnames`]; the registry `Arc` is held so an
    /// [`upgrade`](Self::upgrade) can reconstruct a full handle. This does not
    /// keep the actor alive (only live senders do).
    #[cfg(target_os = "linux")]
    hostnames: Arc<RwLock<crate::net::dns::HostnameRegistry>>,
}

impl WeakManagerHandle {
    /// Promotes to a strong [`ManagerHandle`], or `None` if the manager actor
    /// has already shut down (all strong senders dropped).
    #[must_use]
    pub fn upgrade(&self) -> Option<ManagerHandle> {
        Some(ManagerHandle {
            sender: self.sender.upgrade()?,
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&self.hostnames),
        })
    }
}

/// The capability handed to a session's [`Binding`](crate::session_host) to
/// tear its own session down — the "delete" choice on the shell-exit prompt.
///
/// Bundles a [`WeakManagerHandle`] with the [`SessionId`] to destroy, so the
/// binding neither owns the manager nor needs to know how destruction is
/// carried out.
#[derive(Debug, Clone)]
pub struct SessionControl {
    manager: WeakManagerHandle,
    id: SessionId,
}

impl SessionControl {
    /// Binds the destroy capability to a specific session.
    #[must_use]
    pub fn new(manager: WeakManagerHandle, id: SessionId) -> Self {
        Self { manager, id }
    }

    /// Requests the manager destroy this session: kills the host and removes the
    /// on-disk record. Errors if the manager has already shut down, or if the
    /// destroy itself fails (e.g. the manager is mid-shutdown).
    pub async fn destroy(&self) -> Result<(), SessionsError> {
        match self.manager.upgrade() {
            Some(mngr) => mngr.destroy_session(self.id).await,
            None => Err(SessionsError::new(
                std::io::ErrorKind::NotConnected,
                "sessions manager is gone",
            )),
        }
    }
}

impl ManagerHandle {
    /// Returns a non-owning handle to this manager.
    #[must_use]
    pub fn downgrade(&self) -> WeakManagerHandle {
        WeakManagerHandle {
            sender: self.sender.downgrade(),
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&self.hostnames),
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

    /// Lists the sessions known to this (minimald) instance.
    pub async fn list(&self) -> Result<Vec<SessionInfo>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.sender.send(ManagerMessage::List(send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets the session record which corresponds to the given predicate.
    pub async fn get_record(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<sessions::Record>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetRecord(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Creates a session from the given config + client wire
    /// contribution. `username` is the authenticated SSH user from
    /// the connection context; pass `None` for non-SSH callers (e.g.
    /// in-process daemon callers and tests).
    pub async fn create_session(
        &self,
        config: minimald_rpc::SessionConfig,
        username: Option<String>,
        contribution: WireContribution,
    ) -> Result<minimald_rpc::CreateSessionResponse, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::CreateSession(Box::new(CreateSessionMsg {
                config,
                username,
                contribution,
                responder: send,
            })))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Submit a client verdict against a `Pending` session. On
    /// success the daemon promotes the record to `Active` and replies
    /// with [`SessionStep::Active`]. A verdict against an unknown id
    /// or a non-`Pending` record surfaces as a [`SessionStep::Fault`]
    /// — see the SubmitVerdict handler arm in [`Self::mainloop`].
    pub async fn submit_verdict(
        &self,
        verdict: ContributionVerdict,
    ) -> Result<SessionStep, SessionsError> {
        let (send, recv) = Responder::channel();
        let _ = self
            .sender
            .send(ManagerMessage::SubmitVerdict(Box::new(SubmitVerdictMsg {
                verdict,
                responder: send,
            })))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets a handle to the session corresponding with the given predicate.
    pub async fn get_session(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<SessionHandle>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::GetSession(pred, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Renames the given session to the given name.
    pub async fn rename_session(
        &self,
        id: SessionId,
        new_name: String,
    ) -> Result<(), SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::RenameSession(id, new_name, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Destroys the session with the given ID, cascadingly tearing down its
    /// running host and actor (if any) before removing its on-disk record.
    ///
    /// Returns a `NotFound` error if no session with that ID is known.
    pub async fn destroy_session(&self, id: SessionId) -> Result<(), SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .sender
            .send(ManagerMessage::DestroySession(id, send))
            .await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Aborts a `Pending` session: drops the daemon's stash entry and
    /// deletes the on-disk record. Used by the client when its
    /// Phase 3 gating produces no verdict (e.g. user cancelled at a
    /// prompt).
    ///
    /// `NotFound` if the id is unknown; `InvalidInput` if the record
    /// exists but its status isn't `Pending`
    /// (use [`Self::destroy_session`] on an `Active` session).
    pub async fn abort_session(&self, id: SessionId) -> Result<(), SessionsError> {
        let (send, recv) = Responder::channel();
        let _ = self
            .sender
            .send(ManagerMessage::AbortSession(id, send))
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

    /// Test-only inspection of the manager's in-memory
    /// `compositions` stash. Used to assert stash lifecycle
    /// transitions (insert on Ready → drain on GetSession →
    /// cleanup on Destroy/Abort). Not exposed to production
    /// callers.
    #[cfg(test)]
    pub async fn compositions_len(&self) -> usize {
        let (send, recv) = Responder::channel();
        let _ = self
            .sender
            .send(ManagerMessage::CompositionsLen(send))
            .await;
        recv.await
            .expect("corresponding sessions manager is dead")
            .expect("infallible")
    }

    /// Test-only peek at a stashed [`Composition`] by session id.
    /// Bumps the refcount rather than draining the entry, so the
    /// caller can assert on contents without disturbing the
    /// lifecycle.
    #[cfg(test)]
    pub async fn peek_composition(
        &self,
        id: SessionId,
    ) -> Option<Arc<sessions::core::compose::Composition>> {
        let (send, recv) = Responder::channel();
        let _ = self
            .sender
            .send(ManagerMessage::PeekComposition(id, send))
            .await;
        recv.await
            .expect("corresponding sessions manager is dead")
            .expect("infallible")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use paths::HostAbsPath;
    use std::io::ErrorKind;
    use tempfile::TempDir;

    fn daemon_dir(tmp: &TempDir) -> DaemonAbsPath {
        DaemonAbsPath::try_new(tmp.path().to_str().unwrap()).unwrap()
    }

    fn sample_config() -> minimald_rpc::SessionConfig {
        minimald_rpc::SessionConfig {
            name: Some("doomed".to_string()),
            project_path: HostAbsPath::try_new("/proj").unwrap(),
            network: sessions::NetworkMode::default(),
            policy: Default::default(),
            attrs: Default::default(),
        }
    }

    /// Test helper: send via the in-process manager actor (not RPC),
    /// then unwrap the `Ready` arm via the shared test_harness helper.
    async fn create_and_unwrap_id(mngr: &ManagerHandle) -> SessionId {
        crate::test_harness::unwrap_ready(
            mngr.create_session(sample_config(), None, WireContribution::default())
                .await
                .unwrap(),
        )
    }

    async fn manager() -> (TempDir, TempDir, ManagerHandle) {
        let state = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        // These tests never start an `OwnIp` launch (they use the mock
        // launcher), so the switch is never spawned; a placeholder binary path
        // is sufficient.
        let switch = Arc::new(Mutex::new(crate::net::SwitchClient::new(
            "/nonexistent/gvproxy",
            state.path().join("gvproxy"),
        )));
        // Tests use per-TempDir cache/state dirs so they don't pollute the
        // shared daemon paths a real invocation would touch.
        let mctx_config = mctx::ConfigBuilder::new()
            .with_cache_dir(cache.path())
            .with_state_dir(state.path())
            .build()
            .unwrap();
        let mngr = Manager::init(daemon_dir(&state), daemon_dir(&cache), mctx_config, switch)
            .await
            .unwrap();
        (state, cache, mngr)
    }

    /// Destroying a known-but-not-running session removes its record so it no
    /// longer resolves or lists, and frees its name for reuse.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroy_removes_a_non_running_session() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_and_unwrap_id(&mngr).await;

        mngr.destroy_session(id).await.unwrap();

        assert!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "the record should be gone after destroy"
        );
        assert!(mngr.list().await.unwrap().is_empty());
        // The name index entry was dropped, so the name can be taken again.
        let _ = create_and_unwrap_id(&mngr).await;
    }

    /// Destroying a session that has been brought up (its actor is running, but
    /// no host is attached) tears the actor down and removes the record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroy_tears_down_a_running_session() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_and_unwrap_id(&mngr).await;

        // Bring the session actor up (populating the running map) without
        // attaching a host.
        let handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .unwrap()
            .expect("session should resolve");

        mngr.destroy_session(id).await.unwrap();

        // The destroy cascade completed: the record is gone, and a fresh
        // get_session no longer resolves the (now removed) session.
        assert!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            mngr.get_session(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_none(),
            "the session should no longer resolve after destroy"
        );
        drop(handle);
    }

    /// Destroying an unknown ID is a `NotFound` error.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroy_unknown_id_errors() {
        let (_state, _cache, mngr) = manager().await;
        let err = mngr
            .destroy_session(SessionId::nil())
            .await
            .expect_err("destroying an unknown id should error");
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// A non-empty `WireContribution` from the client is accepted:
    /// the composer produces a non-empty [`Composition`], the
    /// [`Manager`] stashes it against the allocated session id, and
    /// the record persists as `Active`. The stashed composition is
    /// handed to the [`Session`] actor the first time
    /// [`GetSession`] spawns it.
    ///
    /// Replaces an earlier test that asserted the opposite while
    /// no apply layer existed to consume the composition; that
    /// silent-data-loss guard is gone now that the manager keeps
    /// the composition against a live actor.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_session_accepts_non_empty_client_contribution() {
        use sessions::core::source::Source;
        use sessions::wire::primitives::{WireResolvedVar, WireSessionVar, WireSource};

        let (_state, _cache, mngr) = manager().await;
        let mut contribution = WireContribution::default();
        contribution.vars.push(WireSessionVar {
            var: WireResolvedVar {
                name: "EDITOR".into(),
                value: "hx".into(),
            },
            source: WireSource::from(Source::UserLoadout {
                name: "test".into(),
            }),
        });

        let resp = mngr
            .create_session(sample_config(), None, contribution)
            .await
            .expect("non-empty composition should now finalize as Active");
        assert!(matches!(
            resp,
            minimald_rpc::CreateSessionResponse::Ready { .. }
        ));
    }

    /// `reap_orphan_pending` deletes `Pending` records on disk —
    /// they have no in-memory stash post-restart and can't be
    /// resumed. `Active` records pass through untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reap_orphan_pending_deletes_pending_records() {
        let tmp = TempDir::new().unwrap();
        let mut loader = DiskLoader::new(daemon_dir(&tmp)).unwrap();

        let pending_key = loader
            .create(sessions::Record {
                id: SessionId::nil(),
                name: Some("pending".into()),
                username: None,
                project_path: HostAbsPath::try_new("/p").unwrap(),
                network: sessions::NetworkMode::default(),
                policy: Default::default(),
                status: sessions::SessionStatus::Pending,
                attrs: Default::default(),
            })
            .unwrap();
        let active_key = loader
            .create(sessions::Record {
                id: SessionId::nil(),
                name: Some("active".into()),
                username: None,
                project_path: HostAbsPath::try_new("/p2").unwrap(),
                network: sessions::NetworkMode::default(),
                policy: Default::default(),
                status: sessions::SessionStatus::Active,
                attrs: Default::default(),
            })
            .unwrap();

        let pending_id = *pending_key.id();
        let active_id = *active_key.id();
        Manager::<DiskLoader>::reap_orphan_pending(&mut loader).unwrap();

        assert!(
            loader.find_by_id(&pending_id).unwrap().is_none(),
            "the Pending record should be reaped from the index",
        );
        let active_key_again = loader
            .find_by_id(&active_id)
            .unwrap()
            .expect("Active record's index entry should remain");
        assert_eq!(
            loader.get(&active_key_again).unwrap().record().status,
            sessions::SessionStatus::Active,
            "the Active record should remain",
        );
    }

    /// `AbortSession` on an unknown id → `NotFound`, mirrors
    /// `DestroySession`'s error shape so clients can uniformly
    /// handle "no such session".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_unknown_id_errors() {
        let (_state, _cache, mngr) = manager().await;
        let err = mngr
            .abort_session(SessionId::nil())
            .await
            .expect_err("aborting an unknown id should error");
        assert_eq!(err.kind(), ErrorKind::NotFound);
    }

    /// `AbortSession` refuses `Active` records — abort is for
    /// `Pending` only; `DestroySession` handles `Active`. Guards
    /// against a client accidentally tearing down a running session
    /// via the wrong RPC.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn abort_refuses_active_session() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_and_unwrap_id(&mngr).await;
        let err = mngr
            .abort_session(id)
            .await
            .expect_err("aborting an Active session should error");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        // Record is untouched.
        assert!(
            mngr.get_record(SessionKeyPredicate::Id(id))
                .await
                .unwrap()
                .is_some(),
            "the Active record should survive a refused abort"
        );
    }

    /// `SubmitVerdict` for an id with no stash entry → terminal
    /// `Fault::UnknownSessionId`. The stash is the single source of
    /// truth for in-flight sessions; a verdict for an id that was
    /// never `Pending` (or has already been resumed) reads as
    /// "unknown" to the daemon.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn submit_verdict_unknown_id_returns_unknown_session_id() {
        let (_state, _cache, mngr) = manager().await;
        let step = mngr
            .submit_verdict(ContributionVerdict {
                session_id: SessionId::nil(),
                vars: vec![],
                patches: vec![],
            })
            .await
            .expect("actor reply should succeed");
        match step {
            SessionStep::Fault {
                error: sessions::wire::errors::WireError::UnknownSessionId,
            } => {}
            other => panic!("expected Fault::UnknownSessionId, got {other:?}"),
        }
    }

    /// `CreateSession` against a `project_path` that has a real
    /// `minimal.toml` shouldn't error out — the mfile parse
    /// succeeds and graph resolution is attempted; both feed
    /// nowhere (yet), and the session persists `Active` on the
    /// empty-contribution fast path.
    ///
    /// The graph-resolution outcome isn't observed by the test —
    /// depending on how `Graph::new_from_chain` handles a bare
    /// `minimal.toml` in a scratch dir, it may return an empty
    /// graph or an error. Either branch must leave `CreateSession`
    /// returning `Ready`; that's the invariant guarded here.
    /// Guards against a regression where the mfile parse or graph
    /// pipeline breaks creation for real projects. Once composition
    /// consumes the parsed mfile + graph, this test evolves.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_session_with_real_project_mfile_succeeds() {
        use std::io::Write;

        // Set up a temp project directory with a minimal `minimal.toml`.
        let project = TempDir::new().unwrap();
        let mfile_path = project.path().join(mfile::MFILE_NAME);
        let mut f = std::fs::File::create(&mfile_path).unwrap();
        writeln!(f, "[stack]\nuse = \"empty\"").unwrap();
        drop(f);

        let (_state, _cache, mngr) = manager().await;
        let mut config = sample_config();
        config.project_path = HostAbsPath::try_new(project.path().to_str().unwrap()).unwrap();

        let resp = mngr
            .create_session(config, None, WireContribution::default())
            .await
            .expect("create with valid project mfile should succeed");
        assert!(matches!(
            resp,
            minimald_rpc::CreateSessionResponse::Ready { .. }
        ));
    }

    /// `CreateSession` against a `project_path` with no `minimal.toml`
    /// still succeeds — the parse fails silently (debug log), the
    /// graph resolve is short-circuited (no `Context` to resolve
    /// against), no project contribution lands, and the
    /// empty-contribution fast path completes as before. Guards the
    /// DM1 / empty-workspace path against regressions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_session_with_missing_mfile_still_succeeds() {
        let empty_project = TempDir::new().unwrap();
        let (_state, _cache, mngr) = manager().await;
        let mut config = sample_config();
        config.project_path = HostAbsPath::try_new(empty_project.path().to_str().unwrap()).unwrap();

        let resp = mngr
            .create_session(config, None, WireContribution::default())
            .await
            .expect("create with missing mfile should still succeed");
        assert!(matches!(
            resp,
            minimald_rpc::CreateSessionResponse::Ready { .. }
        ));
    }

    /// A `[session]` block that contributes a package is picked up
    /// by [`ProjectComposable`] and lands in the composition. With
    /// the non-empty-composition guard gone, the record now
    /// persists as `Active` and the composition lands in the
    /// manager's per-session stash for the [`Session`] actor to
    /// pick up.
    ///
    /// Uses a package contribution rather than a var so no
    /// env-resolution (or graph presence) is needed — the test
    /// stays a pure-parse exercise regardless of stdlib config.
    ///
    /// [`ProjectComposable`]: mfile::ProjectComposable
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn project_composable_contribution_reaches_composer() {
        use std::io::Write;

        let project = TempDir::new().unwrap();
        let mfile_path = project.path().join(mfile::MFILE_NAME);
        let mut f = std::fs::File::create(&mfile_path).unwrap();
        writeln!(f, "[session]\npackages = [\"rustc\"]").unwrap();
        drop(f);

        let (_state, _cache, mngr) = manager().await;
        let mut config = sample_config();
        config.project_path = HostAbsPath::try_new(project.path().to_str().unwrap()).unwrap();

        let resp = mngr
            .create_session(config, None, WireContribution::default())
            .await
            .expect(
                "project composable contributes a package; \
                 without the non-empty-composition guard, the \
                 session finalizes as Active",
            );
        assert!(matches!(
            resp,
            minimald_rpc::CreateSessionResponse::Ready { .. }
        ));
    }

    /// A Ready CreateSession stashes the composition against the
    /// allocated id — `compositions_len` bumps by exactly one.
    /// Baseline for the drain-and-cleanup tests below.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compositions_stash_populated_on_ready() {
        let (_state, _cache, mngr) = manager().await;
        assert_eq!(mngr.compositions_len().await, 0);
        let _id = create_and_unwrap_id(&mngr).await;
        assert_eq!(mngr.compositions_len().await, 1);
    }

    /// `GetSession` on an Active record drains its composition out
    /// of the stash and hands it to `Session::run`. The next
    /// `compositions_len` reads zero — the entry was moved, not
    /// cloned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compositions_stash_drained_on_first_spawn() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_and_unwrap_id(&mngr).await;
        assert_eq!(mngr.compositions_len().await, 1);
        let _handle = mngr
            .get_session(SessionKeyPredicate::Id(id))
            .await
            .expect("get_session succeeds")
            .expect("session resolves");
        assert_eq!(mngr.compositions_len().await, 0);
    }

    /// `DestroySession` on a session that was never spawned via
    /// `GetSession` still drops its composition — the entry would
    /// otherwise leak because the spawn path never ran to drain
    /// it. Regression guard for the create-and-forget-then-destroy
    /// case.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn compositions_stash_drained_on_destroy_before_spawn() {
        let (_state, _cache, mngr) = manager().await;
        let id = create_and_unwrap_id(&mngr).await;
        assert_eq!(mngr.compositions_len().await, 1);
        mngr.destroy_session(id).await.expect("destroy succeeds");
        assert_eq!(mngr.compositions_len().await, 0);
    }

    /// The stashed [`Composition`] actually carries the project
    /// composable's packages — not just an entry-shaped placeholder.
    /// Guards against a `run_composer` refactor that would produce
    /// a well-shaped-but-empty composition and silently pass the
    /// existing lifecycle tests.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stashed_composition_carries_project_packages() {
        use std::io::Write;

        let project = TempDir::new().unwrap();
        let mfile_path = project.path().join(mfile::MFILE_NAME);
        let mut f = std::fs::File::create(&mfile_path).unwrap();
        writeln!(f, "[session]\npackages = [\"ripgrep\", \"jq\"]").unwrap();
        drop(f);

        let (_state, _cache, mngr) = manager().await;
        let mut config = sample_config();
        config.project_path = HostAbsPath::try_new(project.path().to_str().unwrap()).unwrap();

        let resp = mngr
            .create_session(config, None, WireContribution::default())
            .await
            .expect("create with project mfile should succeed");
        let id = match resp {
            minimald_rpc::CreateSessionResponse::Ready { id } => id,
            other => panic!("expected Ready, got {other:?}"),
        };

        let comp = mngr
            .peek_composition(id)
            .await
            .expect("stashed composition should be present");
        let package_names: std::collections::BTreeSet<&str> =
            comp.packages().iter().map(|p| p.package()).collect();
        assert!(
            package_names.contains("ripgrep"),
            "ripgrep should be in composition packages, got {package_names:?}"
        );
        assert!(
            package_names.contains("jq"),
            "jq should be in composition packages, got {package_names:?}"
        );
    }

    /// `[stack] build_packages` and `runtime_packages` land in the
    /// composition alongside any `[session] packages`, so a project
    /// declaring stack extras (or having no `[session]` block at
    /// all) still gets those packages into its sessions.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stashed_composition_includes_stack_packages() {
        use std::io::Write;

        let project = TempDir::new().unwrap();
        let mfile_path = project.path().join(mfile::MFILE_NAME);
        let mut f = std::fs::File::create(&mfile_path).unwrap();
        writeln!(
            f,
            "[stack]\n\
             use = \"shell\"\n\
             build_packages = [\"cmake\"]\n\
             runtime_packages = [\"postgres\"]\n"
        )
        .unwrap();
        drop(f);

        let (_state, _cache, mngr) = manager().await;
        let mut config = sample_config();
        config.project_path = HostAbsPath::try_new(project.path().to_str().unwrap()).unwrap();

        let resp = mngr
            .create_session(config, None, WireContribution::default())
            .await
            .expect("create with stack-only mfile should succeed");
        let id = match resp {
            minimald_rpc::CreateSessionResponse::Ready { id } => id,
            other => panic!("expected Ready, got {other:?}"),
        };

        let comp = mngr
            .peek_composition(id)
            .await
            .expect("stashed composition should be present");
        let package_names: std::collections::BTreeSet<&str> =
            comp.packages().iter().map(|p| p.package()).collect();
        assert!(
            package_names.contains("cmake"),
            "stack build_packages should reach the composition, got {package_names:?}"
        );
        assert!(
            package_names.contains("postgres"),
            "stack runtime_packages should reach the composition, got {package_names:?}"
        );
    }

    /// [`build_composables`] with a [`ProjectResolution::NoMFile`]
    /// yields no composables regardless of the wire contribution.
    /// The wire contribution isn't discarded by the composer — it
    /// still lands via `SessionComposer::new(contribution)`; this
    /// helper is only responsible for daemon-side additions.
    #[test]
    fn build_composables_no_mfile_yields_nothing() {
        use sessions::wire::primitives::{WirePackageRef, WireSource};

        let path = HostAbsPath::try_new("/proj").unwrap();
        let mut contribution = WireContribution::default();
        contribution.requested_packages.push(WirePackageRef {
            name: "helix".into(),
            source: WireSource::UserLoadout {
                name: "test".into(),
            },
        });
        let (project, packages) =
            build_composables(&path, &ProjectResolution::NoMFile, &contribution).unwrap();
        assert!(project.is_none(), "NoMFile → no ProjectComposable");
        assert!(packages.is_empty(), "NoMFile → no PackageComposables");
    }

    /// [`build_composables`] with an [`ProjectResolution::MFileOnly`]
    /// carrying a `[session]` block produces a [`ProjectComposable`];
    /// package composables stay empty because the graph is absent.
    /// The MFileOnly path exercises the "graph resolve failed but
    /// project still declares packages" branch — project packages
    /// don't get their own PackageComposables, they just wait for
    /// the composer to see them via the ProjectComposable's
    /// contribution.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn build_composables_mfile_only_yields_project_composable_and_no_packages() {
        use std::io::Write;

        let project = TempDir::new().unwrap();
        let mfile_path = project.path().join(mfile::MFILE_NAME);
        let mut f = std::fs::File::create(&mfile_path).unwrap();
        writeln!(f, "[session]\npackages = [\"cargo\"]").unwrap();
        drop(f);

        // Build a `Context` directly (no graph); the manager sets
        // the same shape internally on the MFileOnly branch.
        let cache = TempDir::new().unwrap();
        let state = TempDir::new().unwrap();
        let mctx_config = mctx::ConfigBuilder::new()
            .with_cache_dir(cache.path())
            .with_state_dir(state.path())
            .build()
            .unwrap();
        let daemon = std::sync::Arc::new(mctx::DaemonContext::init(mctx_config).unwrap());
        let mfile = mctx::MFileSearchStrategy::Override(project.path().to_path_buf())
            .find_mfile()
            .unwrap();
        let ctx = mctx::Context::from_daemon(daemon, mfile);

        let path = HostAbsPath::try_new(project.path().to_str().unwrap()).unwrap();
        let (project_composable, packages) = build_composables(
            &path,
            &ProjectResolution::MFileOnly(ctx),
            &WireContribution::default(),
        )
        .unwrap();
        assert!(
            project_composable.is_some(),
            "MFileOnly with [session] block → ProjectComposable present",
        );
        assert!(
            packages.is_empty(),
            "MFileOnly → no PackageComposables (no graph to walk)",
        );
    }

    /// [`run_composer`] with an empty client contribution and no
    /// daemon-side composables produces a Ready outcome with an
    /// empty [`Composition`]. Baseline for the composer wiring.
    #[test]
    fn run_composer_empty_inputs_yield_ready_empty() {
        let outcome =
            run_composer(WireContribution::default(), None, Vec::new()).expect("no failures");
        match outcome {
            ComposeOutcome::Ready(composition) => {
                assert!(composition.packages().is_empty());
                assert!(composition.vars().is_empty());
                assert!(composition.patches().is_empty());
                assert!(composition.lifecycle_hooks().is_empty());
            }
            other => panic!("expected Ready, got {other:?}"),
        }
    }
}
