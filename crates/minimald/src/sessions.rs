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

/// Transport / internal error when communicating with the sessions actor.
pub type ResponseError = std::io::Error;

/// Encapsulates the return channel for messages back from the actor.
struct Responder<T>(oneshot::Sender<Result<T, ResponseError>>);

impl<T> Responder<T> {
    /// Constructs both ends of the return channel.
    pub fn channel() -> (Self, oneshot::Receiver<Result<T, ResponseError>>) {
        let (send, recv) = oneshot::channel();
        (Self(send), recv)
    }

    /// Awaits the provided future, transmitting its result to the caller.
    pub async fn handle<F>(self, fut: F)
    where
        F: Future<Output = Result<T, ResponseError>>,
    {
        let _ = self.0.send(fut.await);
    }
}

enum ManagerMessage {
    List(Responder<Vec<SessionInfo>>),
    GetRecord(SessionKeyPredicate, Responder<Option<sessions::Record>>),
    GetSession(SessionKeyPredicate, Responder<Option<SessionHandle>>),
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
    fn key_for(&self, pred: &SessionKeyPredicate) -> Result<Option<L::Key>, std::io::Error> {
        match pred {
            SessionKeyPredicate::Id(id) => self.store.find_by_uuid(id),
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
                    self.store
                        .list()
                        .map(|k| {
                            let s = self.store.get(&k)?;
                            let r = s.record();
                            Ok::<_, ResponseError>(SessionInfo {
                                id: r.id,
                                name: r.name.clone(),
                            })
                        })
                        .collect::<Result<_, _>>()
                })
                .await;
            }
            // Gets the record for a specific session.
            ManagerMessage::GetRecord(pred, r) => {
                r.handle(async {
                    Ok::<_, ResponseError>(match pred {
                        SessionKeyPredicate::Id(id) => self
                            .store
                            .find_by_uuid(&id)?
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
                                    let h = Session::run(self.store.get(&k)?)
                                        .await
                                        .expect("TODO handle error");
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
        }
    }
}

/// The handle to the session manager.
#[derive(Debug, Clone)]
pub struct ManagerHandle(mpsc::Sender<ManagerMessage>);

impl ManagerHandle {
    /// Lists the sessions known to this (minimald) instance.
    pub async fn list(&self) -> Result<Vec<SessionInfo>, ResponseError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::List(send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets the session record which corresponds to the given predicate.
    pub async fn get_record(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<sessions::Record>, ResponseError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::GetRecord(pred, send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }

    /// Gets a handle to the session corresponding with the given predicate.
    pub async fn get_session(
        &self,
        pred: SessionKeyPredicate,
    ) -> Result<Option<SessionHandle>, ResponseError> {
        let (send, recv) = Responder::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(ManagerMessage::GetSession(pred, send)).await;
        recv.await.expect("corresponding sessions manager is dead")
    }
}
