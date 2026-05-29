use sessions::{paths::DaemonAbsPath, store::SessionObject};
use tokio::sync::{mpsc, oneshot};

enum SessionMessage {
    GetWorkspacePath(oneshot::Sender<DaemonAbsPath>),
}

/// Manages a running session.
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct Session<S: SessionObject> {
    receiver: mpsc::Receiver<SessionMessage>,
    session: S,
}

impl<S: SessionObject> Session<S> {
    /// Launches the actor for the given session.
    pub async fn run(session: S) -> Result<SessionHandle, std::io::Error> {
        let (sender, receiver) = mpsc::channel(8);
        let mngr = Self { receiver, session };

        tokio::spawn(mngr.mainloop());
        Ok(SessionHandle(sender))
    }

    /// The async task which handles interactions with the
    /// session.
    async fn mainloop(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            self.handle_message(msg).await;
        }
    }
    /// Handles a specific message recieved by the session.
    async fn handle_message(&mut self, msg: SessionMessage) {
        match msg {
            SessionMessage::GetWorkspacePath(r) => {
                let wsp = self.session.workspace_path();
                std::fs::create_dir_all(&wsp).unwrap();
                let _ = r.send(wsp);
            }
        }
    }
}

/// The handle to the session.
#[derive(Debug, Clone)]
pub struct SessionHandle(mpsc::Sender<SessionMessage>);

impl SessionHandle {
    /// Returns the path where the session workspace is located.
    pub async fn workspace_path(&self) -> DaemonAbsPath {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetWorkspacePath(send)).await;
        recv.await.expect("corresponding session is dead")
    }
}
