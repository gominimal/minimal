use std::{collections::BTreeMap, io::ErrorKind::NotFound};

use crate::{
    session::{Session, SessionHandle},
    session_host::HostAttrs,
};
use paths::DaemonAbsPath;
use sessions::{
    SessionId,
    core::compose::ComposeOptions,
    daemon::composer::{ComposeOutcome, PendingComposeState, SessionComposer, resume_from_verdict},
    store::{DiskLoader, Loader, SessionKey, SessionObject},
    wire::request::{ContributionVerdict, SessionStep, WireContribution},
};
use std::sync::Arc;
#[cfg(target_os = "linux")]
use std::sync::RwLock;
use tokio::sync::{Mutex, mpsc, oneshot};

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

    /// Per-session stash for in-flight `CreateSession` flows that
    /// reached [`ComposeOutcome::Pending`]. Keyed by the daemon's
    /// allocated [`SessionId`]; the matching `SubmitVerdict` pops
    /// the entry and finalizes. The stash is in-memory only — if
    /// the daemon restarts mid-flow the on-disk
    /// `SessionStatus::Pending` record loses its match and is
    /// reaped by [`Manager::reap_orphan_pending`] at startup.
    pending: BTreeMap<SessionId, PendingComposeState>,

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
        net_switch: Arc<Mutex<crate::net::SwitchClient>>,
    ) -> Result<ManagerHandle, std::io::Error> {
        let mut l = DiskLoader::new(minimal_state_dir.clone())?;
        // Reap any on-disk `SessionStatus::Pending` records left over
        // from a previous daemon process — the in-memory stash that
        // would have let them resume is gone, so they're unresumable.
        Self::reap_orphan_pending(&mut l)?;
        let running = BTreeMap::new();
        let (sender, receiver) = mpsc::channel(8);
        // Shared so the host-side proxies can resolve `Host:` headers directly;
        // a clone is held by both the actor (which mutates it) and the handle
        // (which hands it to the proxies via `hostnames()`).
        #[cfg(target_os = "linux")]
        let hostnames = Arc::new(RwLock::new(crate::net::dns::HostnameRegistry::new(
            crate::net::dns::DEFAULT_HOST_ID,
        )));
        let mngr = Self {
            in_shutdown: false,
            receiver,
            running,
            store: l,
            pending: BTreeMap::new(),
            minimal_state_dir,
            minimal_cache_dir,
            net_switch,
            #[cfg(target_os = "linux")]
            hostnames: Arc::clone(&hostnames),
        };

        tokio::spawn(mngr.mainloop());
        Ok(ManagerHandle {
            sender,
            #[cfg(target_os = "linux")]
            hostnames,
        })
    }
}

impl<L: Loader> Manager<L> {
    fn key_for(&self, pred: &SessionKeyPredicate) -> Result<Option<L::Key>, std::io::Error> {
        match pred {
            SessionKeyPredicate::Id(id) => self.store.find_by_id(id),
            SessionKeyPredicate::Name(name) => self.store.find_by_name(name),
        }
    }

    /// Delete any on-disk record whose status is
    /// [`sessions::SessionStatus::Pending`]. Run once at startup —
    /// the matching in-memory `PendingComposeState` lives only on
    /// the previous daemon process, so a `Pending` record post-restart
    /// has no path to `Active` and a client waiting on `SubmitVerdict`
    /// would hang. Cheap correctness floor; daemon-restart-survives-
    /// pending is a separate concern.
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
            // Gets the session actor corresponding to the predicate.
            //
            // If the session is known but not running, it is started.
            //
            // `SessionStatus::Pending` records are filtered out here —
            // they have no composed `Composition` yet, so spinning up
            // the session host would attach a client to a half-built
            // session. The filter returns `None` (caller sees the
            // same shape as "unknown id") and logs the reason at info
            // level. exec/sftp call sites surface the `None` as a
            // channel failure, which is the correct user-facing
            // behavior in either case.
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
                                    let h = Session::run(
                                        self.minimal_state_dir.clone(),
                                        self.minimal_cache_dir.clone(),
                                        obj,
                                        Arc::clone(&self.net_switch),
                                    )
                                    .await
                                    .expect("TODO handle error");
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
            // Creates a session from a config + (optional) client wire
            // contribution.
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
                let outcome = SessionComposer::new(contribution)
                    .compose(SessionId::nil(), ComposeOptions::default());
                let pending = &mut self.pending;
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
                        // the record as `Active` in one write and ship
                        // `CreateSessionResponse::Ready { id }`. Guard
                        // against silent data loss: no apply layer
                        // yet consumes the `Composition`, so a
                        // non-empty one would be discarded. Reject
                        // until apply plumbing lands — the fast path
                        // (empty client contribution, no daemon
                        // contributors) still passes.
                        //
                        // `Pending` — the client must gate items
                        // before composition completes. Allocate the
                        // id by persisting the record as `Pending`,
                        // stash the daemon-side resume state under
                        // that id, overwrite the placeholder
                        // `session_id` on the wire response, and ship
                        // `CreateSessionResponse::Pending { id, response }`.
                        //
                        // `Err` — a cross-process merge conflict or a
                        // malformed wire item. Both are
                        // declaration-time bugs — `InvalidInput`.
                        match outcome {
                            Ok(ComposeOutcome::Ready(composition)) => {
                                if !composition.vars().is_empty()
                                    || !composition.patches().is_empty()
                                    || !composition.packages().is_empty()
                                    || !composition.lifecycle_hooks().is_empty()
                                {
                                    return Err(std::io::Error::new(
                                        std::io::ErrorKind::InvalidInput,
                                        "CreateSession composed a non-empty \
                                         Composition, but the apply layer that \
                                         would consume it is not wired yet",
                                    ));
                                }
                                let record = build_record(
                                    config,
                                    username,
                                    sessions::SessionStatus::Active,
                                )?;
                                let k = store.create(record)?;
                                Ok(minimald_rpc::CreateSessionResponse::Ready { id: *k.id() })
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
                            Err(e) => Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                e.to_string(),
                            )),
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
                        // The resumed composition is dropped today:
                        // session activation doesn't yet consume it.
                        let _composition = match resume_from_verdict(state, verdict) {
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
                    Ok(Ok(()))
                })
                .await
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

impl ManagerHandle {
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
        let mngr = Manager::init(daemon_dir(&state), daemon_dir(&cache), switch)
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

    /// A non-empty `WireContribution` from the client is rejected —
    /// the composer would produce a non-empty `Composition`, and
    /// there is no apply layer yet to consume it. Accepting would
    /// silently discard the client's contribution while the on-disk
    /// Record only carries the out-of-band `SessionConfig`.
    /// Prevents the silent data loss until apply plumbing lands.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_session_rejects_non_empty_client_contribution() {
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

        let err = mngr
            .create_session(sample_config(), None, contribution)
            .await
            .expect_err("non-empty composition should be rejected until apply plumbing lands");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
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
}
