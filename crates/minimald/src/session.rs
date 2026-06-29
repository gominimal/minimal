use crate::channel_progress::ChannelProgress;
use crate::{
    ChannelConfig,
    session_host::{self, HostAttrs, WinSize},
};
use mctx::ConfigBuilder;
use ot::OpTracker;
use paths::DaemonAbsPath;
use russh::{Channel, server::Msg};
use sessions::{Record, store::SessionObject};
use std::fmt::{self};
use std::ops::ControlFlow;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc, oneshot};
use tokio::task::JoinHandle;

/// An error that occurred when attaching to a running session/its-shell.
#[derive(Debug)]
pub enum AttachError {
    SpawnFailed(std::io::Error),
    NoPty,
    ContextCreationFailed(String),
    /// The session's networking policy is incompatible with its network mode
    /// (R2.1): e.g. an egress section on a non-`OwnIp` PTask.
    InvalidPolicy(sessions::PolicyError),
}

impl std::error::Error for AttachError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AttachError::InvalidPolicy(e) => Some(e),
            _ => None,
        }
    }
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttachError::ContextCreationFailed(e) => {
                write!(f, "init of minimal context: {e}")
            }
            AttachError::NoPty => write!(f, "SSH channel did not configure a PTY"),
            AttachError::SpawnFailed(e) => write!(f, "session spawn: {e}"),
            AttachError::InvalidPolicy(e) => write!(f, "invalid session policy: {e}"),
        }
    }
}

pub struct SessionPaths {
    pub working: DaemonAbsPath,
    pub cache: DaemonAbsPath,
    pub home: DaemonAbsPath,
}

enum SessionMessage {
    GetPaths(oneshot::Sender<SessionPaths>),
    MakeContext(oneshot::Sender<Result<mctx::Context, String>>),
    Attach(
        oneshot::Sender<Result<(), AttachError>>,
        SessionHandle,
        String,
        Channel<Msg>,
        ChannelConfig,
    ),
    GetHostAttrs(oneshot::Sender<Option<HostAttrs>>),
    RefreshRecord(Record),
    Destroy(oneshot::Sender<()>),
    #[cfg(test)]
    GetRecord(oneshot::Sender<Record>),
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

    /// The daemon-scoped gvproxy switch, injected into each `SandboxLauncher`
    /// this session mints so an `OwnIp` PTask attaches to the one per-host
    /// switch (R1.5). Read only by the production `session_launcher`
    /// (`cfg(not(test))`); the `cfg(test)` mock launcher ignores it, so the
    /// unused-field lint is silenced under test rather than threaded through.
    #[cfg_attr(test, allow(dead_code))]
    net_switch: Arc<Mutex<crate::net::GvproxySwitch>>,

    /// The running host, if minted, paired with the `JoinHandle` of its runtime
    /// loop so teardown can be awaited on destroy.
    host: Option<(
        session_host::HostHandle,
        JoinHandle<Result<i32, std::io::Error>>,
    )>,

    /// The root of this session's operation tree. Created once for the session
    /// and wired into the context each launch builds against, so package
    /// fetches/builds report into it; the channel renderer paints it onto the
    /// SSH channel while a host is being minted.
    tracker: OpTracker,
}

impl<S: SessionObject> Session<S> {
    /// Launches the actor for the given session.
    pub async fn run(
        minimal_state_dir: DaemonAbsPath,
        minimal_cache_dir: DaemonAbsPath,
        session: S,
        net_switch: Arc<Mutex<crate::net::GvproxySwitch>>,
    ) -> Result<SessionHandle, std::io::Error> {
        std::fs::create_dir_all(session.workspace_path())?;
        std::fs::create_dir_all(session.home_path())?;
        std::fs::create_dir_all(session.cache_path())?;

        let (sender, receiver) = mpsc::channel(8);
        let mngr = Self {
            host: None,
            receiver,
            session,
            minimal_state_dir,
            minimal_cache_dir,
            net_switch,
            tracker: OpTracker::new_root(),
        };

        tokio::spawn(mngr.mainloop());
        Ok(SessionHandle(sender))
    }

    /// The async task which handles interactions with the
    /// session.
    async fn mainloop(mut self) {
        while let Some(msg) = self.receiver.recv().await {
            if self.handle_message(msg).await.is_break() {
                break;
            }
        }
    }

    /// Handles a specific message recieved by the session.
    ///
    /// Returns [`ControlFlow::Break`] when the session has been destroyed and
    /// the actor loop should exit.
    async fn handle_message(&mut self, msg: SessionMessage) -> ControlFlow<()> {
        match msg {
            SessionMessage::GetPaths(r) => {
                let _ = r.send(self.paths());
            }
            SessionMessage::MakeContext(r) => {
                let _ = r.send(self.context());
            }
            SessionMessage::Attach(r, session_hnd, conn_username, channel, config) => {
                let _ = r.send(
                    self.attach(session_hnd, conn_username, channel, config)
                        .await,
                );
            }
            SessionMessage::GetHostAttrs(r) => {
                let _ = r.send(match self.host.as_ref() {
                    None => None,
                    Some((h, _)) => h.get_attrs().await.ok(),
                });
            }
            SessionMessage::RefreshRecord(r) => {
                self.session.refresh_from_record(r);
            }
            SessionMessage::Destroy(r) => {
                self.destroy().await;
                let _ = r.send(());
                return ControlFlow::Break(());
            }
            #[cfg(test)]
            SessionMessage::GetRecord(r) => {
                let _ = r.send(self.session.record().clone());
            }
        }
        ControlFlow::Continue(())
    }

    /// Tears down the running host, if any, waiting for the process to be reaped
    /// and the sandbox guard to be dropped before returning.
    async fn destroy(&mut self) {
        if let Some((host, task)) = self.host.take() {
            // Signal the process to die, then await the runtime loop so the
            // sandbox files backing its rootfs are released before the caller
            // removes the session's directory tree.
            let _ = host.kill().await;
            let _ = task.await;
        }
    }

    async fn attach(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
        channel: Channel<Msg>,
        config: ChannelConfig,
    ) -> Result<(), AttachError> {
        let sz = WinSize::from(match config.pty.as_ref() {
            Some(pty) => pty,
            None => return Err(AttachError::NoPty),
        });

        match &mut self.host {
            None => {
                self.mint_session_host(session_hnd, conn_username, channel, sz)
                    .await
            }
            Some((h, _)) => {
                match h.attach(channel, sz).await {
                    Ok(()) => Ok(()),
                    Err((channel, sz)) => {
                        // session host is dead
                        self.mint_session_host(session_hnd, conn_username, channel, sz)
                            .await
                    }
                }
            }
        }
    }

    async fn mint_session_host(
        &mut self,
        session_hnd: SessionHandle,
        conn_username: String,
        channel: Channel<Msg>,
        sz: WinSize,
    ) -> Result<(), AttachError> {
        let name = {
            let record = self.session.record();
            match &record.name {
                Some(s) => s.clone(),
                None => record
                    .project_path
                    .file_name()
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| "session".to_string()),
            }
        };

        // The launcher's context reports into this session's operation tree (see
        // `context`). Render that tree onto the channel for the duration of the
        // launch (graph build + package builds + sandbox assembly), then take
        // the channel back. The host is spawned without a channel so the
        // renderer has exclusive use of it while building; once the bars are
        // cleared we attach the channel to the now-running host.
        let launcher = self.session_launcher(session_hnd)?;
        let progress = ChannelProgress::new(channel, self.tracker.clone(), (sz.cols, sz.rows));
        let (channel, spawned) = progress
            .run(Box::pin(session_host::Host::spawn(
                launcher,
                name,
                conn_username,
                self.paths(),
                sz,
                None,
            )))
            .await;
        let h = spawned.map_err(AttachError::SpawnFailed)?;

        // Wire the channel to the freshly launched host. A failure here means
        // the host died in the window between launch and attach; surface it as
        // a spawn failure rather than leaving a dead, channel-less host.
        h.0.attach(channel, sz).await.map_err(|_| {
            AttachError::SpawnFailed(std::io::Error::other(
                "session host exited before its channel could attach",
            ))
        })?;
        self.host = Some(h);
        Ok(())
    }

    /// Builds the session launcher used to mint a session host: the real
    /// sandboxed shell in production.
    #[cfg(not(test))]
    fn session_launcher(
        &mut self,
        session: SessionHandle,
    ) -> Result<session_host::SandboxLauncher, AttachError> {
        let record = self.session.record();
        // R2.1: reject a policy that is incompatible with the network mode
        // (e.g. egress on a non-`OwnIp` PTask) before launching the host.
        record
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        let network_mode = record.network;
        // Only an `OwnIp` PTask attaches to the switch, so ingress forwards are
        // only carried for that mode; `validate_policy` has already rejected
        // ingress configured on any other mode.
        let ingress = record.policy.ingress.clone();
        Ok(session_host::SandboxLauncher {
            ctx: self.context().map_err(AttachError::ContextCreationFailed)?,
            network_mode,
            net_switch: Arc::clone(&self.net_switch),
            ingress,
            session,
        })
    }

    /// Under test, swap in a mock launcher that runs a plain host process wired
    /// to the pty, exercising the session-host runtime without building a real
    /// sandbox (which needs packages unavailable in the unit-test tempdir).
    #[cfg(test)]
    fn session_launcher(
        &mut self,
        _session: SessionHandle,
    ) -> Result<session_host::MockLauncher, AttachError> {
        // Mirror the production R2.1 gate so test launches reject a
        // policy/network-mode mismatch the same way production does.
        self.session
            .record()
            .validate_policy()
            .map_err(AttachError::InvalidPolicy)?;
        Ok(session_host::MockLauncher)
    }

    fn context(&mut self) -> Result<mctx::Context, String> {
        let wsp = self.session.workspace_path();
        match ConfigBuilder::new()
            .with_repo_dir(wsp.as_utf8_path())
            .with_cache_dir(self.minimal_cache_dir.as_utf8_path())
            .with_state_dir(self.minimal_state_dir.as_utf8_path())
            // Every context this session builds reports into its operation tree.
            // The host-mint path renders that tree onto the SSH channel; the
            // task-exec path (via `MakeContext`) also feeds it, so task builds
            // surface on the same tracker even though only a mint renders it.
            .with_operation_tracker(self.tracker.clone())
            .build()
        {
            Err(e) => Err(mctx::Error::from(e).to_string()),
            Ok(c) => mctx::Context::new(c).map_err(|e| e.to_string()),
        }
    }
    fn paths(&self) -> SessionPaths {
        SessionPaths {
            working: self.session.workspace_path(),
            cache: self.session.cache_path(),
            home: self.session.home_path(),
        }
    }
}

/// The handle to the session.
#[derive(Debug, Clone)]
pub struct SessionHandle(mpsc::Sender<SessionMessage>);

impl SessionHandle {
    /// Returns paths on the daemon backing various internals of the session.
    pub async fn paths(&self) -> SessionPaths {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetPaths(send)).await;
        recv.await.expect("corresponding session is dead")
    }
    /// Returns the host attributes of the running session, if any.
    pub async fn get_attrs(&self) -> Option<HostAttrs> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetHostAttrs(send)).await;
        recv.await.expect("corresponding session is dead")
    }

    /// Returns a minimal context initialized on this sessions' worktree.
    pub async fn context(&self) -> Result<mctx::Context, String> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::MakeContext(send)).await;
        recv.await.expect("corresponding session is dead")
    }

    /// Returns the session record currently held by the live session actor.
    ///
    /// This reads the actor's in-memory copy, not the on-disk record, so
    /// tests can assert that updates have propagated into the running session.
    #[cfg(test)]
    pub(crate) async fn record(&self) -> Record {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::GetRecord(send)).await;
        recv.await.expect("corresponding session is dead")
    }

    /// Tell the session that the underlying session record was updated.
    pub(crate) async fn apply_record(&self, new_record: Record) {
        self.0
            .send(SessionMessage::RefreshRecord(new_record))
            .await
            .expect("corresponding session is dead");
    }

    /// Tears down the session: kills its host (if any), waits for teardown, and
    /// stops the actor. The handle is dead once this returns.
    pub(crate) async fn destroy(&self) {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self.0.send(SessionMessage::Destroy(send)).await;
        // If the actor died before acking, the session is gone all the same.
        let _ = recv.await;
    }

    pub async fn attach(
        &self,
        conn_username: String,
        channel: Channel<Msg>,
        config: ChannelConfig,
    ) -> Result<(), AttachError> {
        let (send, recv) = oneshot::channel();
        // Ignore send errors - the recv will also fail.
        let _ = self
            .0
            .send(SessionMessage::Attach(
                send,
                self.clone(),
                conn_username,
                channel,
                config,
            ))
            .await;
        recv.await.expect("corresponding session is dead")
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use paths::HostAbsPath;
    use russh::ChannelMsg;
    use sessions::SessionId;

    use minimald_rpc::{CreateSession, CreateSessionRequest};

    use crate::test_harness::{TestClient, TestServer};

    /// Creates a fresh session on the server and returns its id.
    async fn create_session(client: &mut TestClient) -> SessionId {
        client
            .call::<CreateSession>(&CreateSessionRequest {
                record: sessions::Record {
                    id: SessionId::nil(),
                    name: Some("shell-test".to_string()),
                    username: None,
                    project_path: HostAbsPath::try_new("/uwu").unwrap(),
                    network: Default::default(),
                    policy: Default::default(),
                    attrs: Default::default(),
                },
            })
            .await
            .unwrap()
            .id
    }

    /// Drives the full SSH path into the session host with the mock launcher:
    /// create a session, request a pty + shell, feed stdin, observe the echoed
    /// stdout, then confirm the host tears down when the process exits.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shell_round_trips_stdin_to_stdout_then_tears_down() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        let mut channel = client.open_shell(session_id).await;

        // Echo round trip: the mock echoes each line back as `got:<line>`.
        // Read until we observe the echo, proving the stdin -> program ->
        // stdout path works while the process is still alive.
        channel.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut stdout = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    stdout.extend_from_slice(&data);
                    if String::from_utf8_lossy(&stdout).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => {
                    let stdout = String::from_utf8_lossy(&stdout);
                    panic!("channel closed before the echo arrived; stdout: {stdout:?}");
                }
            }
        }

        // Now ask the mock to exit and confirm the host tears the channel down.
        channel
            .data_bytes(format!("{}\n", crate::session_host::MOCK_EXIT_LINE).into_bytes())
            .await
            .unwrap();
        let mut saw_exit_status = false;
        let mut closed = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(10), channel.wait()).await {
            match msg {
                Some(ChannelMsg::ExitStatus { .. }) => saw_exit_status = true,
                Some(_) => {}
                None => {
                    closed = true;
                    break;
                }
            }
        }
        assert!(closed, "channel should close once the mock process exits");
        assert!(saw_exit_status, "expected an exit status on teardown");
    }

    /// A second shell request to the same session takes over the running host:
    /// the new channel is flushed the current terminal state (so it sees the
    /// earlier `hello` output), and the original channel is disconnected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn second_shell_takes_over_session_and_closes_the_first() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        // First attachment: drive an echo so the host's terminal state holds
        // `got:hello`, confirming it before we take the session over.
        let mut first = client.open_shell(session_id).await;
        first.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut first_out = Vec::new();
        loop {
            match first.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    first_out.extend_from_slice(&data);
                    if String::from_utf8_lossy(&first_out).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => {
                    let first_out = String::from_utf8_lossy(&first_out);
                    panic!("first channel closed before the echo arrived; got: {first_out:?}");
                }
            }
        }

        // Second attachment to the same session takes over.
        let mut second = client.open_shell(session_id).await;

        // The takeover flushes the current terminal state to the new channel,
        // so the earlier `got:hello` shows up in what it's sent on attach. The
        // session stays live (no teardown), so read with a timeout rather than
        // draining to close.
        let mut flushed = Vec::new();
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), second.wait()).await
        {
            if let ChannelMsg::Data { data } = msg {
                flushed.extend_from_slice(&data);
                if String::from_utf8_lossy(&flushed).contains("got:hello") {
                    break;
                }
            }
        }
        let flushed = String::from_utf8_lossy(&flushed);
        assert!(
            flushed.contains("got:hello"),
            "takeover should flush prior terminal state to the new channel, got: {flushed:?}",
        );

        // The original channel should have been disconnected by the takeover.
        let mut first_closed = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), first.wait()).await {
            if msg.is_none() {
                first_closed = true;
                break;
            }
        }
        assert!(
            first_closed,
            "first channel should be closed once the session is taken over",
        );
    }

    /// The ctrl-w detach chord (a single `0x17` byte) detaches the current
    /// channel — sending a detach notice down it before it closes — without
    /// tearing the session down, so a later channel resumes it (the earlier
    /// `got:hello` is flushed on reattach).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn ctrl_w_detaches_channel_then_session_resumes_on_reattach() {
        let server = TestServer::new().await;
        let mut client = server.connect().await;
        let session_id = create_session(&mut client).await;

        // First attachment: drive an echo so the terminal state holds
        // `got:hello` before we detach.
        let mut first = client.open_shell(session_id).await;
        first.data_bytes(b"hello\n".to_vec()).await.unwrap();
        let mut first_out = Vec::new();
        loop {
            match first.wait().await {
                Some(ChannelMsg::Data { data }) => {
                    first_out.extend_from_slice(&data);
                    if String::from_utf8_lossy(&first_out).contains("got:hello") {
                        break;
                    }
                }
                Some(_) => {}
                None => {
                    let first_out = String::from_utf8_lossy(&first_out);
                    panic!("first channel closed before the echo arrived; got: {first_out:?}");
                }
            }
        }

        // Send the detach chord. The host writes a detach notice down the
        // channel and then closes it.
        first.data_bytes(vec![0x17]).await.unwrap();
        let mut detach_out = Vec::new();
        let mut first_closed = false;
        while let Ok(msg) = tokio::time::timeout(Duration::from_secs(5), first.wait()).await {
            match msg {
                Some(ChannelMsg::Data { data }) => detach_out.extend_from_slice(&data),
                Some(_) => {}
                None => {
                    first_closed = true;
                    break;
                }
            }
        }
        let detach_out = String::from_utf8_lossy(&detach_out);
        assert!(
            detach_out.contains("Detaching due to ctrl-w."),
            "expected a detach notice on the channel before it closed, got: {detach_out:?}",
        );
        assert!(first_closed, "channel should close after the detach chord");

        // Reattach: a second channel resumes the same (still-live) session, so
        // the earlier `got:hello` is flushed to it on connect.
        let mut second = client.open_shell(session_id).await;
        let mut flushed = Vec::new();
        while let Ok(Some(msg)) = tokio::time::timeout(Duration::from_secs(5), second.wait()).await
        {
            if let ChannelMsg::Data { data } = msg {
                flushed.extend_from_slice(&data);
                if String::from_utf8_lossy(&flushed).contains("got:hello") {
                    break;
                }
            }
        }
        let flushed = String::from_utf8_lossy(&flushed);
        assert!(
            flushed.contains("got:hello"),
            "reattaching should flush prior terminal state, got: {flushed:?}",
        );
    }
}
