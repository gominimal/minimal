use std::{collections::BTreeMap, io::ErrorKind::NotFound};

use crate::{
    session::{Session, SessionHandle},
    session_host::HostAttrs,
};
use paths::DaemonAbsPath;
use sessions::{
    SessionId,
    store::{DiskLoader, Loader, SessionKey, SessionObject},
};
use std::sync::Arc;
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

enum ManagerMessage {
    List(Responder<Vec<SessionInfo>>),
    GetRecord(SessionKeyPredicate, Responder<Option<sessions::Record>>),
    GetSession(SessionKeyPredicate, Responder<Option<SessionHandle>>),
    CreateSession(sessions::Record, Responder<SessionId>),
    RenameSession(SessionId, String, Responder<()>),
    DestroySession(SessionId, Responder<()>),
    /// Hands back a clone of the daemon-scoped gvproxy switch `Arc`, so the
    /// `attach --command` exec path can attach a one-shot `OwnIp` PTask to the
    /// same per-host switch the interactive launcher uses (R1.5).
    ///
    // Only the production (`cfg(not(test))`) exec path consumes this; under test
    // the plain-command path runs through host `/bin/sh`, so the variant is
    // unused there.
    #[cfg_attr(test, allow(dead_code))]
    GetNetSwitch(oneshot::Sender<Arc<Mutex<crate::net::GvproxySwitch>>>),
}

/// Manages session instances, and session state on disk.
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct Manager<L: Loader = DiskLoader> {
    receiver: mpsc::Receiver<ManagerMessage>,
    running: BTreeMap<L::Key, SessionHandle>,
    store: L,

    minimal_state_dir: DaemonAbsPath,
    minimal_cache_dir: DaemonAbsPath,
    /// The daemon-scoped gvproxy switch, handed to each session it starts so an
    /// `OwnIp` PTask attaches to the one per-host switch (R1.4/R1.5/R1.6).
    net_switch: Arc<Mutex<crate::net::GvproxySwitch>>,

    /// In-memory PTask hostname registry (Unit 3, DM2). Owned directly because
    /// the manager is an actor with exclusive `&mut self` access, so no lock is
    /// needed. `HostNet` PTasks register on launch and withdraw on teardown.
    #[cfg(target_os = "linux")]
    hostnames: crate::net::dns::HostnameRegistry,
}

impl Manager {
    /// Launches a sessions manager managing sessions in
    /// the given minimal state dir.
    pub async fn init(
        minimal_state_dir: DaemonAbsPath,
        minimal_cache_dir: DaemonAbsPath,
        net_switch: Arc<Mutex<crate::net::GvproxySwitch>>,
    ) -> Result<ManagerHandle, std::io::Error> {
        let l = DiskLoader::new(minimal_state_dir.clone())?;
        let running = BTreeMap::new();
        let (sender, receiver) = mpsc::channel(8);
        let mngr = Self {
            receiver,
            running,
            store: l,
            minimal_state_dir,
            minimal_cache_dir,
            net_switch,
            #[cfg(target_os = "linux")]
            hostnames: crate::net::dns::HostnameRegistry::new(crate::net::dns::DEFAULT_HOST_ID),
        };

        tokio::spawn(mngr.mainloop());
        Ok(ManagerHandle(sender))
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
                    match self.key_for(&pred)? {
                        None => Ok(None),
                        Some(k) => {
                            let session_handle = match self.running.get(&k) {
                                Some(h) => h.clone(),
                                None => {
                                    // Not running, start it!
                                    let obj = self.store.get(&k)?;
                                    // Register a `HostNet` PTask's hostname on
                                    // launch (R3.6); it routes to loopback.
                                    // `OwnIp` registration is deferred to #542.
                                    // Capture the id and name before `obj` is
                                    // moved into `Session::run`.
                                    #[cfg(target_os = "linux")]
                                    let host_net_reg = (obj.record().network
                                        == sessions::NetworkMode::HostNet)
                                        .then(|| (obj.record().id, registry_name(obj.record())));
                                    let h = Session::run(
                                        self.minimal_state_dir.clone(),
                                        self.minimal_cache_dir.clone(),
                                        obj,
                                        Arc::clone(&self.net_switch),
                                    )
                                    .await
                                    .expect("TODO handle error");
                                    #[cfg(target_os = "linux")]
                                    if let Some((id, name)) = host_net_reg {
                                        self.hostnames.register_host_net(id, &name);
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
            // Creates a session using the given record.
            ManagerMessage::CreateSession(record, r) => {
                r.handle(async {
                    // R2.1: reject a policy incompatible with the network mode
                    // (e.g. egress on a non-`OwnIp` PTask) at declaration time,
                    // so an invalid session is never written to the store
                    // rather than only failing when a client later attaches.
                    record
                        .validate_policy()
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                    let k = self.store.create(record)?;
                    Ok(*k.id())
                })
                .await;
            }
            // Renames an existing session with the given ID.
            ManagerMessage::RenameSession(id, new_name, r) => {
                r.handle(async {
                    match self.store.find_by_id(&id)? {
                        None => Err(std::io::Error::new(
                            NotFound,
                            format!("no session with ID `{}`", id.as_ref()),
                        )),
                        Some(k) => {
                            self.store.rename(&k, new_name.clone())?;
                            if let Some(hnd) = self.running.get(&k) {
                                hnd.apply_record(self.store.get(&k)?.record().clone()).await;
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
                    self.hostnames.deregister(&host_net_name);
                    self.store.delete(&k)?;
                    Ok(())
                })
                .await
            }
            // Hands back the shared switch `Arc` (a cheap clone) for the exec
            // path to attach a one-shot `OwnIp` PTask to.
            ManagerMessage::GetNetSwitch(r) => {
                let _ = r.send(Arc::clone(&self.net_switch));
            }
        }
    }
}

/// The handle to the session manager.
#[derive(Debug, Clone)]
pub struct ManagerHandle(mpsc::Sender<ManagerMessage>);

impl ManagerHandle {
    /// Lists the sessions known to this (minimald) instance.
    pub async fn list(&self) -> Result<Vec<SessionInfo>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::List(send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets the session record which corresponds to the given predicate.
    pub async fn get_record(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<sessions::Record>, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::GetRecord(pred, send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Creates a session based on the given record.
    pub async fn create_session(
        &self,
        record: sessions::Record,
    ) -> Result<SessionId, SessionsError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(ManagerMessage::CreateSession(record, send))
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
        let _ = self.0.send(ManagerMessage::GetSession(pred, send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Returns a clone of the daemon-scoped gvproxy switch `Arc`.
    ///
    /// The exec path (`attach --command`) uses this to attach a one-shot
    /// `OwnIp` PTask to the same per-host switch the interactive launcher
    /// attaches to (R1.5), keeping a single gvproxy and address allocator for
    /// the host.
    // Only the production exec path calls this; under test the plain-command
    // path runs through host `/bin/sh`.
    #[cfg_attr(test, allow(dead_code))]
    pub(crate) async fn net_switch(&self) -> Arc<Mutex<crate::net::GvproxySwitch>> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::GetNetSwitch(send)).await;
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
            .0
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
        let _ = self.0.send(ManagerMessage::DestroySession(id, send)).await;
        recv.await.expect("corresponding sessions manager is dead")
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

    fn sample_record() -> sessions::Record {
        sessions::Record {
            id: SessionId::nil(),
            name: Some("doomed".to_string()),
            username: None,
            project_path: HostAbsPath::try_new("/proj").unwrap(),
            network: sessions::NetworkMode::default(),
            policy: Default::default(),
            attrs: Default::default(),
        }
    }

    async fn manager() -> (TempDir, TempDir, ManagerHandle) {
        let state = TempDir::new().unwrap();
        let cache = TempDir::new().unwrap();
        // These tests never start an `OwnIp` launch (they use the mock
        // launcher), so the switch is never spawned; a placeholder binary path
        // is sufficient.
        let switch = Arc::new(Mutex::new(crate::net::GvproxySwitch::new(
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
        let id = mngr.create_session(sample_record()).await.unwrap();

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
        mngr.create_session(sample_record()).await.unwrap();
    }

    /// Destroying a session that has been brought up (its actor is running, but
    /// no host is attached) tears the actor down and removes the record.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn destroy_tears_down_a_running_session() {
        let (_state, _cache, mngr) = manager().await;
        let id = mngr.create_session(sample_record()).await.unwrap();

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
}
