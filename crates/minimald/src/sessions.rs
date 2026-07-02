use std::{collections::BTreeMap, io::ErrorKind::NotFound};

use crate::{
    session::{Session, SessionHandle},
    session_host::HostAttrs,
};
use paths::DaemonAbsPath;
use sessions::{
    SessionId,
    store::{DiskLoader, Loader, SessionKey, SessionObject},
    wire::request::WireContribution,
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
    /// Client-side Phase 1 contribution. Today the handler rejects
    /// anything other than the default; the composition pipeline will
    /// consume it when Phase 2 lands.
    contribution: WireContribution,
    responder: Responder<minimald_rpc::CreateSessionResponse>,
}

enum ManagerMessage {
    List(Responder<Vec<SessionInfo>>),
    GetRecord(SessionKeyPredicate, Responder<Option<sessions::Record>>),
    GetSession(SessionKeyPredicate, Responder<Option<SessionHandle>>),
    CreateSession(Box<CreateSessionMsg>),
    RenameSession(SessionId, String, Responder<()>),
    DestroySession(SessionId, Responder<()>),
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
        let l = DiskLoader::new(minimal_state_dir.clone())?;
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
                responder
                    .handle(async {
                        if self.in_shutdown {
                            return Err(SessionsError::new(
                                std::io::ErrorKind::ConnectionRefused,
                                "in shutdown",
                            ));
                        }

                        // Until daemon-side Phase 2 routing lands, the only
                        // valid contribution is the empty default. Silently
                        // dropping a non-empty contribution would let clients
                        // believe their composed vars/patches/packages/hooks
                        // were honored — they would not be. Reject explicitly
                        // so the failure surfaces at the call site instead
                        // of as missing items in the assembled session.
                        //
                        // TODO(composition): when Phase 2 lands, the
                        // composition pipeline consumes this field instead.
                        // The seam is here: replace this check with the
                        // partition + ContributionResponse flow.
                        if contribution != WireContribution::default() {
                            return Err(SessionsError::new(
                                std::io::ErrorKind::InvalidInput,
                                "non-empty WireContribution is not supported \
                                 by this daemon — daemon-side composition \
                                 (Phase 2) is not wired yet",
                            ));
                        }
                        // Assemble the on-disk Record from out-of-band config
                        // + the SSH-supplied username. Persists `Active`
                        // immediately on the empty-contribution fast path.
                        let record = sessions::Record {
                            id: SessionId::nil(),
                            name: config.name,
                            username,
                            project_path: config.project_path,
                            network: config.network,
                            policy: config.policy,
                            status: sessions::SessionStatus::Active,
                            attrs: config.attrs,
                        };
                        // R2.1: reject a policy incompatible with the network
                        // mode (e.g. egress on a non-`OwnIp` PTask) at
                        // declaration time, so an invalid session is never
                        // written to the store rather than only failing when
                        // a client later attaches.
                        record.validate_policy().map_err(|e| {
                            std::io::Error::new(std::io::ErrorKind::InvalidInput, e)
                        })?;
                        let k = self.store.create(record)?;
                        Ok(minimald_rpc::CreateSessionResponse::Ready { id: *k.id() })
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

    /// A non-empty `WireContribution` must be refused with
    /// `InvalidInput` until daemon-side Phase 2 routing lands.
    /// Silently dropping it would let clients believe their
    /// composed items were honored.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn create_session_rejects_non_empty_contribution() {
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
            .expect_err("non-empty contribution must be rejected today");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
    }
}
