//! SSH client transport for talking to minimald over the UDS bridge.
//!
//! Provides a `russh`-based client that connects to `minimald` over the UNIX
//! domain socket, authenticates (passwordless), and invokes oneshot RPCs
//! defined in the `minimald-rpc` wire contract.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use minimald_rpc::OneshotSshRpc;
use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Max retries when connecting to the daemon UDS.
const CONNECT_RETRIES: u32 = 20;
/// Delay between connection retries.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// russh client handler that accepts any ephemeral host key.
///
/// The daemon generates a fresh host key on every boot. Since we connect over
/// a local UDS (not the network), TOFU trust is acceptable here.
struct MinimalClientHandler;

impl russh::client::Handler for MinimalClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// An authenticated SSH session to minimald.
pub struct Client {
    handle: russh::client::Handle<MinimalClientHandler>,
}

impl Client {
    /// Connect to minimald over the UDS at `sock_path`, authenticate, and
    /// return a ready [`Client`].
    ///
    /// Retries the UDS connect for up to ~2 seconds to absorb the post-boot
    /// race on macOS where the libkrun bridge UDS appears slightly after the
    /// `vm-up` line.
    pub async fn connect(sock_path: &Path) -> Result<Self, String> {
        let stream = {
            let mut conn = None;
            let mut last_err = None;
            for _ in 0..CONNECT_RETRIES {
                match tokio::net::UnixStream::connect(sock_path).await {
                    Ok(s) => {
                        conn = Some(s);
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e);
                        tokio::time::sleep(CONNECT_RETRY_DELAY).await;
                    }
                }
            }
            conn.ok_or_else(|| {
                format!(
                    "connect to daemon at {}: {}",
                    sock_path.display(),
                    last_err.unwrap()
                )
            })?
        };

        let config = Arc::new(russh::client::Config::default());
        let mut handle = russh::client::connect_stream(config, stream, MinimalClientHandler)
            .await
            .map_err(|e| format!("ssh connect: {e}"))?;

        let auth = handle
            .authenticate_none("minimal-cli")
            .await
            .map_err(|e| format!("authenticate: {e}"))?;

        if !auth.success() {
            return Err("authentication rejected by daemon".into());
        }

        Ok(Client { handle })
    }

    /// Execute a command in the context of a session.
    ///
    /// Opens a new SSH channel, sets `MINIMAL_SESSION_ID` to the given
    /// session ID, execs the command, and returns `(stdout, exit_status)`.
    pub async fn exec_in_session(
        &mut self,
        session_id: &str,
        command: &str,
    ) -> Result<(String, Option<u32>), String> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open exec channel: {e}"))?;

        channel
            .set_env(true, "MINIMAL_SESSION_ID", session_id)
            .await
            .map_err(|e| format!("set_env MINIMAL_SESSION_ID: {e}"))?;

        channel
            .exec(true, command)
            .await
            .map_err(|e| format!("exec: {e}"))?;

        channel
            .eof()
            .await
            .map_err(|e| format!("eof: {e}"))?;

        let mut stdout = Vec::new();
        let mut exit_status = None;
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Failure => return Err("exec request rejected (CHANNEL_FAILURE)".into()),
                _ => {}
            }
        }

        Ok((String::from_utf8_lossy(&stdout).into_owned(), exit_status))
    }

    /// Issue a oneshot RPC: open a channel, request the subsystem, write the
    /// serialized request, half-close, and decode the response.
    ///
    /// The type parameter `R` picks the RPC from the wire contract; `request`
    /// is serialized to JSON and the response is deserialized from JSON.
    pub async fn oneshot_rpc<R: OneshotSshRpc>(
        &mut self,
        request: R::Request<'_>,
    ) -> Result<R::Response, String>
    where
        <R as OneshotSshRpc>::Response: serde::de::DeserializeOwned,
    {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open channel for {}: {e}", R::NAME))?;

        channel
            .request_subsystem(false, R::NAME)
            .await
            .map_err(|e| format!("request subsystem {}: {e}", R::NAME))?;

        let body =
            serde_json::to_vec(&request).map_err(|e| format!("serialize request: {e}"))?;

        let mut rpc = channel.into_stream();
        rpc.write_all(&body)
            .await
            .map_err(|e| format!("write request: {e}"))?;
        rpc.shutdown()
            .await
            .map_err(|e| format!("shutdown write half: {e}"))?;

        let mut resp_buf = Vec::with_capacity(256);
        rpc.read_to_end(&mut resp_buf)
            .await
            .map_err(|e| format!("read response: {e}"))?;

        serde_json::from_slice(&resp_buf)
            .map_err(|e| format!("decode response for {}: {e}", R::NAME))
    }
}

/// Resolve the daemon socket path, defaulting to `minvmd::sock::resolve_uds_path()`.
///
/// If `--minimal-dir` is set, use `<minimal_dir>/minimald.sock` instead.
pub fn resolve_socket_path(minimal_dir_override: Option<&std::path::Path>) -> std::io::Result<std::path::PathBuf> {
    if let Some(dir) = minimal_dir_override {
        return Ok(dir.join("minimald.sock"));
    }
    minvmd::sock::resolve_uds_path()
}
