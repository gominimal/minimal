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

#![cfg(test)]

use std::sync::Arc;

use camino::Utf8PathBuf;
use russh::keys::ssh_key;
use sessions::paths::DaemonAbsPath;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::connection::Connection;
use crate::rpc::OneshotSshRpc;
use crate::server::{Config, HostKey, ServerStateHandle};

/// A minimald instance running against a tempdir, ready to accept
/// in-memory ssh connections.
pub(crate) struct TestServer {
    /// Public so tests can poke at server state directly (e.g. create
    /// sessions via the manager handle) before issuing RPCs.
    pub(crate) state: ServerStateHandle,
    russh_config: Arc<russh::server::Config>,
    _temp: TempDir,
}

impl TestServer {
    /// Spins up a fresh server backed by an empty tempdir. The tempdir
    /// lives as long as the [`TestServer`].
    pub(crate) async fn new() -> Self {
        let temp = TempDir::new().unwrap();
        let path = Utf8PathBuf::from_path_buf(temp.path().to_path_buf()).unwrap();
        let state_dir = DaemonAbsPath::try_new(path.clone()).unwrap();
        let cache_dir = DaemonAbsPath::try_new(path).unwrap();
        let config = Config {
            host_key: HostKey::Ephemeral,
            minimal_state_dir: state_dir,
            minimal_cache_dir: cache_dir,
        };
        let state = ServerStateHandle::new(config).await.unwrap();

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
    pub(crate) async fn connect(&self) -> TestClient {
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
                Connection::from_socket(server_side, russh_config, state, true).await;
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
}

/// An authenticated client connection against a [`TestServer`].
pub(crate) struct TestClient {
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
    pub(crate) async fn call<R: OneshotSshRpc>(&mut self, req: &R::Request<'_>) -> R::Response {
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
}

struct TestClientHandler;

impl russh::client::Handler for TestClientHandler {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
        // Tests run against an ephemeral key we just generated, so
        // there is nothing to check.
        Ok(true)
    }
}
