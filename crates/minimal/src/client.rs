//! SSH client transport for talking to minimald over the UDS bridge.
//!
//! Provides a `russh`-based client that connects to `minimald` over the UNIX
//! domain socket, authenticates (passwordless), and invokes oneshot RPCs
//! defined in the `minimald-rpc` wire contract.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use minimald_rpc::OneshotSshRpc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Max retries when connecting to the daemon UDS.
const CONNECT_RETRIES: u32 = 20;
/// Delay between connection retries.
const CONNECT_RETRY_DELAY: Duration = Duration::from_millis(100);
/// Deadline for the SSH handshake + auth once the socket has accepted.
///
/// A connect is not proof that anyone is home: on the VM backend the socket is
/// libkrun's bridge, which accepts even when the guest behind it is wedged, so
/// only a completed handshake proves there is a live server. Without a deadline
/// the CLI blocks there forever (#730). Generous — a healthy endpoint answers in
/// milliseconds, so this only bounds the pathological case. Mirrors `minvmd`'s
/// own client, which guards the same bridge.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
    /// `vm-up` line, and bounds the handshake by [`HANDSHAKE_TIMEOUT`] so a
    /// wedged daemon behind an accepting socket fails instead of hanging.
    pub async fn connect(sock_path: &Path) -> Result<Self, anyhow::Error> {
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
                anyhow::anyhow!(
                    "connect to daemon at {}: {}",
                    sock_path.display(),
                    last_err.unwrap()
                )
            })?
        };

        // The client deliberately runs without keepalives: a laptop closed
        // for an hour should reconnect transparently on wake rather than have
        // the link torn down mid-sleep. The server's long-interval keepalive
        // is the only liveness mechanism, and it no longer reaps
        // idle-but-alive sessions.
        let config = Arc::new(russh::client::Config::default());
        let handshake = async {
            let mut handle = russh::client::connect_stream(config, stream, MinimalClientHandler)
                .await
                .context("ssh connect")?;

            let auth = handle
                .authenticate_none("minimal-cli")
                .await
                .context("authenticate")?;

            if !auth.success() {
                return Err(anyhow::anyhow!("authentication rejected by daemon"));
            }
            Ok(handle)
        };

        let handle = tokio::time::timeout(HANDSHAKE_TIMEOUT, handshake)
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "connect to {}: SSH handshake timed out after {HANDSHAKE_TIMEOUT:?}",
                    sock_path.display()
                )
            })??;

        Ok(Client { handle })
    }

    /// Issue a oneshot RPC: open a channel, request the subsystem, write the
    /// serialized request, half-close, and decode the response.
    ///
    /// The type parameter `R` picks the RPC from the wire contract; `request`
    /// is serialized to JSON and the response is deserialized from JSON.
    pub async fn oneshot_rpc<R: OneshotSshRpc>(
        &mut self,
        request: R::Request<'_>,
    ) -> Result<R::Response, anyhow::Error>
    where
        <R as OneshotSshRpc>::Response: serde::de::DeserializeOwned,
    {
        let channel = self
            .handle
            .channel_open_session()
            .await
            .with_context(|| format!("open channel for {}", R::NAME))?;

        channel
            .request_subsystem(false, R::NAME)
            .await
            .with_context(|| format!("request subsystem {}", R::NAME))?;

        let body = serde_json::to_vec(&request).context("serialize request")?;

        let mut rpc = channel.into_stream();
        rpc.write_all(&body).await.context("write request")?;
        rpc.shutdown().await.context("shutdown write half")?;

        let mut resp_buf = Vec::with_capacity(256);
        rpc.read_to_end(&mut resp_buf)
            .await
            .context("read response")?;

        serde_json::from_slice(&resp_buf)
            .with_context(|| format!("decode response for {}", R::NAME))
    }

    /// Open a session channel and issue an `exec` request for `command`,
    /// returning the channel once the daemon has acknowledged it.
    ///
    /// The daemon replies to the exec request before the process produces
    /// any output, so everything after the ack is the process conversation:
    /// data, extended data, and finally an exit status.
    pub async fn open_exec_channel(
        &mut self,
        command: &str,
    ) -> Result<russh::Channel<russh::client::Msg>, anyhow::Error> {
        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .context("open exec channel")?;
        channel
            .exec(true, command)
            .await
            .with_context(|| format!("exec request for {command:?}"))?;

        loop {
            match channel.wait().await {
                Some(russh::ChannelMsg::Success) => return Ok(channel),
                Some(russh::ChannelMsg::Failure) => {
                    anyhow::bail!("daemon rejected exec request {command:?}")
                }
                // Window adjustments and the like can precede the ack;
                // process output cannot, since the server acks first.
                Some(_) => continue,
                None => anyhow::bail!("channel closed before the exec request was acknowledged"),
            }
        }
    }

    /// Stream a zstd-compressed tarball of `dir` to the daemon's
    /// `WorkspaceFilesTarZst` subsystem, which unpacks it into the
    /// session's workspace directory.
    ///
    /// `session_id` is set as the `MINIMAL_SESSION_ID` env var on the
    /// channel so the daemon can scope the upload to the correct session.
    pub async fn upload_workspace_files(
        &mut self,
        session_id: sessions::SessionId,
        dir: &Path,
    ) -> Result<(), anyhow::Error> {
        let subsystem =
            constcat::concat!(minimald_rpc::RPC_SUBSYSTEM_PREFIX, "WorkspaceFilesTarZst");

        let channel = self
            .handle
            .channel_open_session()
            .await
            .context("open channel for workspace file upload")?;

        channel
            .set_env(true, "MINIMAL_SESSION_ID", session_id.to_string())
            .await
            .context("set MINIMAL_SESSION_ID env")?;

        channel
            .request_subsystem(true, subsystem)
            .await
            .context("request WorkspaceFilesTarZst subsystem")?;

        let stream = channel.into_stream();

        // Stream a tar+zstd archive directly to the daemon channel,
        // avoiding buffering the entire archive in memory.
        crate::file_upload::stream_tar_zstd(dir, stream).await
    }
}

/// Resolve the provider-instance dir (`<state dir>/providers/local-0`) the
/// daemon and CLI agree on: `--minimal-dir` when set, else the default
/// minimal state dir.
pub(crate) fn resolve_provider_dir(
    minimal_dir_override: Option<&std::path::Path>,
) -> std::io::Result<std::path::PathBuf> {
    let base = match minimal_dir_override {
        Some(dir) => {
            let abs = std::path::absolute(dir)?;
            let utf8 = abs
                .to_str()
                .ok_or_else(|| std::io::Error::other("--minimal-dir is not valid UTF-8"))?;
            paths::DaemonAbsPath::try_new(utf8).map_err(std::io::Error::other)?
        }
        None => paths::minimal_state_dir(),
    };
    Ok(paths::provider_instance_dir(&base, 0)
        .as_utf8_path()
        .as_std_path()
        .to_path_buf())
}

/// Resolve the daemon socket path: `<provider dir>/ssh.sock`. Both backends
/// (native minimald and the minvmd bridge) serve the same endpoint, so the
/// backend choice only matters for spawning, not for connecting.
pub fn resolve_socket_path(
    minimal_dir_override: Option<&std::path::Path>,
) -> std::io::Result<std::path::PathBuf> {
    Ok(resolve_provider_dir(minimal_dir_override)?.join(paths::SSH_SOCK_FILE))
}

#[cfg(test)]
mod tests {
    use super::{Client, resolve_socket_path};
    use std::path::Path;

    #[test]
    fn socket_path_honors_override() {
        let sock = resolve_socket_path(Some(Path::new("/tmp/minimal-test"))).unwrap();
        assert_eq!(
            sock,
            Path::new("/tmp/minimal-test/providers/local-0/ssh.sock")
        );
    }

    /// A socket that accepts but never speaks SSH — a wedged guest behind
    /// libkrun's always-accepting bridge — must fail at the handshake deadline
    /// instead of blocking the CLI forever (#730).
    #[tokio::test(start_paused = true)]
    async fn connect_fails_at_the_handshake_deadline_on_a_mute_listener() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("mute.sock");
        let _listener = tokio::net::UnixListener::bind(&sock).unwrap();

        // `start_paused` auto-advances time while nothing is runnable, so the
        // deadline elapses in virtual time — the test does not wait it out.
        let err = Client::connect(&sock).await.map(|_| ()).unwrap_err();
        assert!(
            err.to_string().contains("SSH handshake timed out"),
            "expected a handshake-deadline error, got: {err:#}"
        );
    }
}
