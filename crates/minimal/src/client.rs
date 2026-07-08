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

        let config = Arc::new(russh::client::Config::default());
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
}

/// Resolve the daemon socket path.
///
/// On Linux: `$XDG_STATE_HOME/minimal/providers/local-0/ssh.sock` (matching
/// `minimald`'s `listen_on()`).
///
/// On macOS: delegates to `minvmd::sock::resolve_uds_path()` (the bridge
/// socket created by the minvmd host daemon).
///
/// If `--minimal-dir` is set, use `<minimal_dir>/providers/local-0/ssh.sock`
/// on Linux (native), or `<minimal_dir>/minimald.sock` on macOS / Linux+minvmd.
///
/// `use_minvmd` selects the backend on Linux: `false` (default) resolves the
/// native minimald UDS; `true` resolves the minvmd host-UDS bridge. On macOS the
/// bridge is the only backend, so `use_minvmd` is ignored.
pub fn resolve_socket_path(
    minimal_dir_override: Option<&std::path::Path>,
    use_minvmd: bool,
) -> std::io::Result<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    let _ = use_minvmd;
    if let Some(dir) = minimal_dir_override {
        #[cfg(target_os = "linux")]
        return Ok(if use_minvmd {
            dir.join("minimald.sock")
        } else {
            dir.join("providers/local-0/ssh.sock")
        });
        #[cfg(target_os = "macos")]
        return Ok(dir.join("minimald.sock"));
    }
    #[cfg(target_os = "linux")]
    {
        if use_minvmd {
            return minvmd::sock::resolve_uds_path();
        }
        Ok(paths::minimal_state_dir()
            .as_utf8_path()
            .as_std_path()
            .join("providers/local-0/ssh.sock"))
    }
    #[cfg(target_os = "macos")]
    minvmd::sock::resolve_uds_path()
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::resolve_socket_path;
    use std::path::Path;

    #[test]
    fn linux_socket_path_honors_backend_with_override() {
        let dir = Path::new("/tmp/minimal-test");
        let native = resolve_socket_path(Some(dir), false).unwrap();
        let bridged = resolve_socket_path(Some(dir), true).unwrap();
        assert!(native.ends_with("providers/local-0/ssh.sock"), "{native:?}");
        assert!(bridged.ends_with("minimald.sock"), "{bridged:?}");
    }
}
