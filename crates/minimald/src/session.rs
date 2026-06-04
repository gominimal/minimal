use mctx::ConfigBuilder;
use paths::DaemonAbsPath;
use sessions::store::SessionObject;
use tokio::sync::{mpsc, oneshot};

enum SessionMessage {
    GetWorkspacePath(oneshot::Sender<DaemonAbsPath>),
    MakeContext(oneshot::Sender<Result<mctx::Context, String>>),
}

/// Manages a running session.
///
/// Follows the actor pattern.
#[derive(Debug)]
pub struct Session<S: SessionObject> {
    receiver: mpsc::Receiver<SessionMessage>,
    minimal_state_dir: DaemonAbsPath,
    minimal_cache_dir: DaemonAbsPath,
    session: S,
}

impl<S: SessionObject> Session<S> {
    /// Launches the actor for the given session.
    pub async fn run(
        minimal_state_dir: DaemonAbsPath,
        minimal_cache_dir: DaemonAbsPath,
        session: S,
    ) -> Result<SessionHandle, std::io::Error> {
        let (sender, receiver) = mpsc::channel(8);
        let mngr = Self {
            receiver,
            session,
            minimal_state_dir,
            minimal_cache_dir,
        };

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
            SessionMessage::MakeContext(r) => {
                let wsp = self.session.workspace_path();
                std::fs::create_dir_all(&wsp).unwrap();
                let config = match ConfigBuilder::new()
                    .with_repo_dir(wsp.as_utf8_path())
                    .with_cache_dir(self.minimal_cache_dir.as_utf8_path())
                    .with_state_dir(self.minimal_state_dir.as_utf8_path())
                    .build()
                {
                    Err(e) => {
                        let _ = r.send(Err(mctx::Error::from(e).to_string()));
                        return;
                    }
                    Ok(c) => c,
                };
                let _ = r.send(mctx::Context::new(config).map_err(|e| e.to_string()));
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

    /// Returns a minimal context initialized on this sessions' worktree.
    pub async fn context(&self) -> Result<mctx::Context, String> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::MakeContext(send)).await;
        recv.await.expect("corresponding session is dead")
    }
}
