//! Test scaffolding for exercising RPC handlers end-to-end.
//!
//! This module spins up a real [`ServerStateHandle`] backed by a tempdir
//! and a real russh client connected over an in-memory `UnixStream` pair,
//! then exposes a single typed entrypoint:
//!
//! ```ignore
//! let server = TestServer::new().await;
//! let mut client = server.connect().await;
//! let resp = client.call::<GetVersion>(&()).await;
//! ```
//!
//! Every layer the production server exercises — russh transport, the
//! `ConnectionHandler` impl, `handle_ssh_rpc` dispatch, the concrete
//! handler's JSON codec, and the sessions actor — runs unmodified. No
//! mocking.

#![cfg(any(test, feature = "test-support"))]

use std::path::Path;
use std::sync::Arc;

use camino::Utf8PathBuf;
use paths::DaemonAbsPath;
use russh::keys::ssh_key;
use sessions::SessionId;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

use minimald_rpc::OneshotSshRpc;

use crate::connection::Connection;
use crate::server::{Config, HostKey, ServerStateHandle};

/// A minimald instance running against a tempdir, ready to accept
/// in-memory ssh connections.
pub struct TestServer {
    /// Public so tests can poke at server state directly (e.g. create
    /// sessions via the manager handle) before issuing RPCs.
    pub state: ServerStateHandle,
    russh_config: Arc<russh::server::Config>,
    _temp: TempDir,
}

impl TestServer {
    /// Spins up a fresh server backed by an empty tempdir. The tempdir
    /// lives as long as the [`TestServer`].
    pub async fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let path = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let state_dir = DaemonAbsPath::try_new(path.clone()).unwrap();
        let cache_dir = DaemonAbsPath::try_new(path).unwrap();
        let config = Config {
            host_key: HostKey::Ephemeral,
            minimal_state_dir: state_dir,
            minimal_cache_dir: cache_dir,
            gvproxy_bin: None,
            in_microvm: false,
            state_volume_mounted: false,
        };
        let state = ServerStateHandle::new(config, None).await.unwrap();

        let host_key = state.host_key().await.unwrap();
        let russh_config = Arc::new(russh::server::Config {
            keys: vec![host_key],
            auth_rejection_time_initial: Some(std::time::Duration::ZERO),
            nodelay: true,
            ..Default::default()
        });

        Self {
            state,
            russh_config,
            _temp: temp,
        }
    }

    /// Opens an authenticated ssh session against this server, using a
    /// `UnixStream` pair to bridge the two halves in-process.
    ///
    /// The server-side task is detached; it stays alive as long as the
    /// returned [`TestClient`] keeps its half of the pair open.
    pub async fn connect(&self) -> TestClient {
        let (server_side, client_side) = UnixStream::pair().unwrap();

        // `russh::server::run_stream` (called inside `Connection::from_socket`)
        // performs the initial SSH-id read before returning, so we have to
        // drive it concurrently with `connect_stream` on the client side
        // — otherwise the two halves deadlock against the empty pipe.
        //
        // `was_local_uds = true` mirrors how the real server marks
        // local-domain-socket connections; it flips `auth_none` to
        // accept without prompting for a credential.
        let russh_config = self.russh_config.clone();
        let state = self.state.clone();
        let server_setup = async move {
            let (_conn, session_fut) =
                Connection::from_stream(server_side, russh_config, state, true)
                    .await
                    .expect("handshake in test harness");
            tokio::spawn(session_fut);
        };

        let client_config = Arc::new(russh::client::Config::default());
        let client_setup =
            russh::client::connect_stream(client_config, client_side, TestClientHandler);

        let (_, handle) = tokio::join!(server_setup, client_setup);
        let mut handle = handle.unwrap();
        let auth = handle.authenticate_none("test").await.unwrap();
        assert!(auth.success(), "auth_none should succeed on local UDS");

        TestClient { handle }
    }

    /// Binds a `UnixListener` at `sock` and spawns an accept loop wired
    /// through the same russh stack `connect()` uses, so external clients
    /// (e.g. an OpenSSH process driven by `git push`) can dial the test
    /// server over a real UDS rather than the in-memory pair.
    pub async fn listen_on_uds(&self, sock: &Path) {
        let listener = UnixListener::bind(sock).unwrap();
        let russh_config = self.russh_config.clone();
        let state = self.state.clone();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let russh_config = russh_config.clone();
                let state = state.clone();
                tokio::spawn(async move {
                    let (_conn, session_fut) =
                        match Connection::from_stream(socket, russh_config, state, true).await {
                            Ok(conn) => conn,
                            Err(_) => return,
                        };
                    let _ = session_fut.await;
                });
            }
        });
    }

    /// Bring a session up (make it "live") by looking it up in the
    /// sessions manager. A persisted session is not "live" until
    /// `get_session` is called, which starts the session actor.
    pub async fn bring_session_up(&self, session_id: sessions::SessionId) {
        let mngr = self.state.sessions_manager().await;
        mngr.get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .expect("get_session RPC should succeed")
            .expect("session should be retrievable");
    }

    /// Seed a project mfile into a session's daemon-side workspace,
    /// standing in for the client's `WorkspaceFilesTarZst` upload.
    ///
    /// The composer reads a session's project config out of its workspace,
    /// never from the record's `project_path` — that's a path on the
    /// *client's* machine. So a test that wants `ConfigureLoadout` to see a
    /// project seeds it here, between `CreateSession` and `ConfigureLoadout`,
    /// exactly where a real client streams its files up.
    pub async fn seed_workspace_mfile(&self, session_id: sessions::SessionId, contents: &str) {
        let mngr = self.state.sessions_manager().await;
        let paths = mngr
            .get_session(crate::sessions::SessionKeyPredicate::Id(session_id))
            .await
            .expect("get_session RPC should succeed")
            .expect("session should be retrievable")
            .paths()
            .await
            .expect("the session actor should be live");
        tokio::fs::write(
            paths.working.as_utf8_path().join(mfile::MFILE_NAME),
            contents,
        )
        .await
        .expect("seeding the workspace mfile should succeed");
    }
}

/// Dials an already-listening minimald UDS and returns an authenticated
/// [`TestClient`].
///
/// Unlike [`TestServer::connect`], which bridges an in-memory pair straight
/// into `Connection::from_stream`, this drives a real `UnixStream` against a
/// server's `UnixListener` — so it exercises the actual `Server::run` accept
/// loop, which is what the shutdown-drain tests need.
pub async fn connect_uds(sock: &Path) -> TestClient {
    let stream = UnixStream::connect(sock).await.unwrap();
    let client_config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(client_config, stream, TestClientHandler)
        .await
        .unwrap();
    let auth = handle.authenticate_none("test").await.unwrap();
    assert!(auth.success(), "auth_none should succeed on local UDS");
    TestClient { handle }
}

/// An authenticated client connection against a [`TestServer`].
pub struct TestClient {
    handle: russh::client::Handle<TestClientHandler>,
}

impl TestClient {
    /// Performs a single oneshot RPC end-to-end.
    ///
    /// Opens a session channel, requests the subsystem named by `R`,
    /// writes the JSON-serialized request, half-closes the write side,
    /// reads the response to EOF, and decodes it.
    ///
    /// Panics on any transport or codec failure — appropriate for unit
    /// tests, which want loud failure rather than recovery.
    pub async fn call<R: OneshotSshRpc>(&mut self, req: &R::Request<'_>) -> R::Response {
        let channel = self.handle.channel_open_session().await.unwrap();
        channel.request_subsystem(false, R::NAME).await.unwrap();

        let body = serde_json::to_vec(req).expect("request serializes");
        let mut stream = channel.into_stream();
        stream.write_all(&body).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut response_buf = Vec::with_capacity(1024);
        stream.read_to_end(&mut response_buf).await.unwrap();
        serde_json::from_slice(&response_buf).expect("response deserializes")
    }

    /// Opens an SFTP session attached to the given minimald session.
    ///
    /// Sets `MINIMAL_SESSION_ID` on the channel (the env-var contract the
    /// server uses to scope the SFTP subsystem to a session), then requests
    /// the `sftp` subsystem and hands the channel stream to the SFTP client.
    pub async fn open_sftp(&mut self, session_id: SessionId) -> russh_sftp::client::SftpSession {
        let channel = self.handle.channel_open_session().await.unwrap();
        channel
            .set_env(true, "MINIMAL_SESSION_ID", session_id.to_string())
            .await
            .unwrap();
        channel.request_subsystem(true, "sftp").await.unwrap();
        russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .unwrap()
    }

    /// Opens a session channel, applies `env`, and requests the named
    /// subsystem, returning the live channel so the caller can stream
    /// arbitrary bytes through it (e.g. a zstd-compressed tarball).
    pub async fn open_subsystem(
        &mut self,
        subsystem: &str,
        env: &[(&str, &str)],
    ) -> russh::Channel<russh::client::Msg> {
        let channel = self.handle.channel_open_session().await.unwrap();
        for (name, value) in env {
            channel.set_env(true, *name, *value).await.unwrap();
        }
        channel.request_subsystem(true, subsystem).await.unwrap();
        channel
    }

    /// Opens an interactive shell channel attached to the given minimald
    /// session, mirroring what a real client does: sets `MINIMAL_SESSION_ID`,
    /// negotiates a PTY, then issues a `shell` request. Returns the live
    /// channel so the caller can write stdin and drain stdout/teardown itself.
    pub async fn open_shell(
        &mut self,
        session_id: SessionId,
    ) -> russh::Channel<russh::client::Msg> {
        let channel = self.handle.channel_open_session().await.unwrap();
        channel
            .set_env(true, crate::MINIMAL_SESSION_ID_ENV, session_id.to_string())
            .await
            .unwrap();
        channel
            .request_pty(true, "xterm", 80, 24, 0, 0, &[])
            .await
            .unwrap();
        channel.request_shell(true).await.unwrap();
        channel
    }

    /// Opens a fresh session channel, applies `env` and optionally a PTY,
    /// fires an `exec` request for `command`, writes `stdin`, then drains
    /// the channel to completion.
    ///
    /// `Ok(ExecOutcome)` when the server accepted the exec request — the
    /// process ran (with whatever exit code or signal). `Err(ExecRejected)`
    /// when the server returned `SSH_MSG_CHANNEL_FAILURE`, i.e. the request
    /// was refused before a process ever started.
    pub async fn exec(
        &mut self,
        env: &[(&str, &str)],
        request_pty: bool,
        command: &str,
        stdin: &[u8],
    ) -> Result<ExecOutcome, ExecRejected> {
        use russh::ChannelMsg;

        let mut channel = self.handle.channel_open_session().await.unwrap();
        for (name, value) in env {
            channel.set_env(true, *name, *value).await.unwrap();
        }
        if request_pty {
            // Any plausible pty params will do; the server only cares
            // that *some* pty was negotiated.
            channel
                .request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .unwrap();
        }
        channel.exec(true, command).await.unwrap();
        if !stdin.is_empty() {
            channel.data_bytes(stdin.to_vec()).await.unwrap();
        }
        // Close write half so `cat`-style commands see EOF and exit.
        channel.eof().await.unwrap();

        // Replies arrive in request order on a single channel: one per
        // set_env, optionally one for request_pty, then one for exec.
        // env/pty requests on a fresh channel can't fail, so any
        // CHANNEL_FAILURE we see is necessarily the exec request's.
        let expected_replies_before_exec = env.len() + usize::from(request_pty);
        let mut seen_request_reply = 0usize;
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_status = None;

        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Success => seen_request_reply += 1,
                ChannelMsg::Failure => {
                    assert!(
                        seen_request_reply >= expected_replies_before_exec,
                        "unexpected CHANNEL_FAILURE before exec request reply \
                         (saw {seen_request_reply}, expected at least \
                         {expected_replies_before_exec})",
                    );
                    return Err(ExecRejected);
                }
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                _ => {}
            }
        }

        Ok(ExecOutcome {
            stdout,
            stderr,
            exit_status,
        })
    }
}

/// Result of a successful SSH `exec` request — the server accepted the
/// request, the process ran (possibly aborted), and the channel closed
/// cleanly.
#[derive(Debug)]
pub struct ExecOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// `Some` when the server reported a numeric exit code; `None` when
    /// the channel closed without one (e.g. signal-terminated).
    pub exit_status: Option<u32>,
}

/// Marker for an exec request the server refused at the request layer
/// via `SSH_MSG_CHANNEL_FAILURE`, before any process was spawned.
#[derive(Debug, PartialEq, Eq)]
pub struct ExecRejected;

struct TestClientHandler;

impl russh::client::Handler for TestClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        // Tests run against an ephemeral key we just generated, so
        // there is nothing to check.
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// CreateSession test helpers
// ---------------------------------------------------------------------------

/// Build a `CreateSessionRequest` with sensible defaults for tests
/// that only care about `name` and `project_path`.
pub fn create_session_req(name: &str, project: &str) -> minimald_rpc::CreateSessionRequest {
    minimald_rpc::CreateSessionRequest {
        config: minimald_rpc::SessionConfig {
            name: Some(name.to_string()),
            project_path: paths::HostAbsPath::try_new(project).unwrap(),
            network: sessions::NetworkMode::default(),
            policy: Default::default(),
            attrs: Default::default(),
        },
    }
}

/// Unwrap the `Ready` arm of a [`minimald_rpc::ConfigureLoadoutResponse`],
/// for a caller that expects its contribution to compose in one shot.
pub fn unwrap_ready(resp: minimald_rpc::ConfigureLoadoutResponse) {
    match resp {
        minimald_rpc::ConfigureLoadoutResponse::Ready => {}
        minimald_rpc::ConfigureLoadoutResponse::Pending { .. } => {
            panic!("expected Ready variant, got Pending")
        }
    }
}

/// Drive the client half of the whole create flow — `CreateSession` plus
/// the `ConfigureLoadout` that finalizes it — and return the session's id.
///
/// A session isn't usable until its loadout is configured (a `Draft` refuses
/// attach and context creation), so any test that goes on to *use* the
/// session wants this rather than a bare `CreateSession`. The workspace is
/// left empty, so the loadout composes to an empty `Ready` in one shot; a
/// test that wants a project in the mix seeds the workspace in between and
/// calls the two RPCs itself.
pub async fn create_configured_session(
    client: &mut TestClient,
    name: &str,
    project: &str,
) -> SessionId {
    use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, CreateSession};
    let id = client
        .call::<CreateSession>(&create_session_req(name, project))
        .await
        .unwrap()
        .id;
    unwrap_ready(
        client
            .call::<ConfigureLoadout>(&ConfigureLoadoutRequest {
                session_id: id,
                contribution: Default::default(),
            })
            .await
            .unwrap(),
    );
    id
}
