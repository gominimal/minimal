use std::collections::BTreeMap;

use crate::session::{Session, SessionHandle};
use sessions::{
    paths::DaemonAbsPath,
    store::{DiskLoader, Loader, SessionObject},
};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

/// A short summary of the metadata of a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: Uuid,
    pub name: Option<String>,
}

/// A key you can use to identify a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKeyPredicate {
    Id(Uuid),
    Name(String),
}

enum ManagerMessage {
    List(oneshot::Sender<Vec<SessionInfo>>),
    GetRecord(
        SessionKeyPredicate,
        oneshot::Sender<Option<sessions::Record>>,
    ),
    GetSession(SessionKeyPredicate, oneshot::Sender<Option<SessionHandle>>),
}

/// Manages session instances, and session state on disk.
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct Manager<L: Loader = DiskLoader> {
    receiver: mpsc::Receiver<ManagerMessage>,
    running: BTreeMap<L::Key, SessionHandle>,
    store: L,
}

impl Manager {
    /// Launches a sessions manager managing sessions in
    /// the given minimal state dir.
    pub async fn init(minimal_state_dir: DaemonAbsPath) -> Result<ManagerHandle, std::io::Error> {
        let l = DiskLoader::new(minimal_state_dir)?;
        let running = BTreeMap::new();
        let (sender, receiver) = mpsc::channel(8);
        let mngr = Self {
            receiver,
            running,
            store: l,
        };

        tokio::spawn(mngr.mainloop());
        Ok(ManagerHandle(sender))
    }
}

impl<L: Loader> Manager<L> {
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
                let _ = r.send(
                    self.store
                        .list()
                        .map(|k| {
                            let s = self.store.get(&k).unwrap();
                            let r = s.record();
                            SessionInfo {
                                id: r.id,
                                name: r.name.clone(),
                            }
                        })
                        .collect(),
                );
            }
            // Gets the record for a specific session.
            ManagerMessage::GetRecord(pred, r) => {
                let _ = r.send(match pred {
                    SessionKeyPredicate::Id(id) => self
                        .store
                        .find_by_uuid(&id)
                        .unwrap()
                        .map(|k| self.store.get(&k).unwrap().record().clone()),
                    SessionKeyPredicate::Name(name) => self
                        .store
                        .find_by_name(&name)
                        .unwrap()
                        .map(|k| self.store.get(&k).unwrap().record().clone()),
                });
            }
            // Gets the session actor corresponding to the predicate.
            //
            // If the session is known but not running, it is started.
            ManagerMessage::GetSession(pred, r) => {
                let k = match pred {
                    SessionKeyPredicate::Id(id) => self.store.find_by_uuid(&id).unwrap(),
                    SessionKeyPredicate::Name(name) => self.store.find_by_name(&name).unwrap(),
                };
                let _ = match k {
                    None => r.send(None),
                    Some(k) => {
                        let session_handle = match self.running.get(&k) {
                            Some(h) => h.clone(),
                            None => {
                                // Not running, start it!
                                let h = Session::run(self.store.get(&k).unwrap()).await.unwrap();
                                self.running.insert(k, h.clone());
                                h
                            }
                        };
                        r.send(Some(session_handle))
                    }
                };
            }
        }
    }
}

/// The handle to the session manager.
#[derive(Debug, Clone)]
pub struct ManagerHandle(mpsc::Sender<ManagerMessage>);

impl ManagerHandle {
    /// Lists the sessions known to this (minimald) instance.
    pub async fn list(&self) -> Vec<SessionInfo> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::List(send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets the session record which corresponds to the given predicate.
    pub async fn get_record(&self, pred: SessionKeyPredicate) -> Option<sessions::Record> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::GetRecord(pred, send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets a handle to the session corresponding with the given predicate.
    pub async fn get_session(&self, pred: SessionKeyPredicate) -> Option<SessionHandle> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::GetSession(pred, send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }
}
