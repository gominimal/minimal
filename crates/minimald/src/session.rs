use mctx::ConfigBuilder;
use paths::DaemonAbsPath;
use russh::{Channel, server::Msg};
use sessions::store::SessionObject;
use tokio::sync::{mpsc, oneshot};

use crate::{
    ChannelConfig,
    session_host::{self, WinSize},
};

enum SessionMessage {
    GetWorkspacePath(oneshot::Sender<DaemonAbsPath>),
    MakeContext(oneshot::Sender<Result<mctx::Context, String>>),
    Attach(SessionHandle, Channel<Msg>, ChannelConfig),
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

    host: Option<session_host::HostHandle>,
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
            host: None,
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
                let _ = r.send(self.context());
            }
            SessionMessage::Attach(session_hnd, channel, config) => {
                self.attach(session_hnd, channel, config).await
            }
        }
    }

    async fn attach(
        &mut self,
        session_hnd: SessionHandle,
        channel: Channel<Msg>,
        config: ChannelConfig,
    ) {
        let sz = WinSize::from(config.pty.as_ref().unwrap());
        match &mut self.host {
            None => self.mint_session_host(session_hnd, channel, sz).await,
            Some(h) => {
                match h.attach(channel, sz).await {
                    Ok(()) => {}
                    Err((channel, sz)) => {
                        // session host is dead
                        self.mint_session_host(session_hnd, channel, sz).await;
                    }
                };
            }
        }
    }

    async fn mint_session_host(
        &mut self,
        session_hnd: SessionHandle,
        channel: Channel<Msg>,
        sz: WinSize,
    ) {
        let h = Box::pin(crate::session_host::Host::spawn(
            sz,
            Some(channel),
            self.context().unwrap(),
            session_hnd,
        ))
        .await
        .unwrap();
        self.host = Some(h);
    }

    fn context(&mut self) -> Result<mctx::Context, String> {
        let wsp = self.session.workspace_path();
        std::fs::create_dir_all(&wsp).unwrap();
        match ConfigBuilder::new()
            .with_repo_dir(wsp.as_utf8_path())
            .with_cache_dir(self.minimal_cache_dir.as_utf8_path())
            .with_state_dir(self.minimal_state_dir.as_utf8_path())
            .build()
        {
            Err(e) => Err(mctx::Error::from(e).to_string()),
            Ok(c) => mctx::Context::new(c).map_err(|e| e.to_string()),
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

    pub async fn attach(&self, channel: Channel<Msg>, config: ChannelConfig) {
        self.0
            .send(SessionMessage::Attach(self.clone(), channel, config))
            .await
            .expect("corresponding session is dead");
    }
}
