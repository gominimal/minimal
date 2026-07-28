//! Blocking oneshot-RPC client for the in-VM minimald over the bridge UDS.
//!
//! `minvmd`'s command paths are synchronous, so this wraps a short-lived
//! current-thread tokio runtime around the same russh flow as the async
//! client in `crates/minimal/src/client.rs`. The two cannot be shared:
//! `minimal` depends on `minvmd`, so importing its client here would be a
//! dependency cycle (dedup would move the client below both — out of scope).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use minimald_rpc::OneshotSshRpc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// russh client handler that accepts any host key. The daemon generates a
/// fresh host key on every boot and the connection is a local UDS (the
/// libkrun vsock bridge), so TOFU trust is acceptable.
struct AnyHostKey;

impl russh::client::Handler for AnyHostKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// Issue a single oneshot RPC to the in-VM minimald over the UDS at
/// `uds_path`, with two independent deadlines: `connect_timeout` covers
/// connect + SSH handshake + auth (short — libkrun accepts the UDS connect
/// even when the guest is wedged, so only a completed handshake proves a
/// live daemon), and `rpc_timeout` covers the request/response exchange
/// (long — the handler may do real work, e.g. draining sessions, before it
/// answers).
pub(crate) fn call_oneshot_blocking<R: OneshotSshRpc>(
    uds_path: &Path,
    request: R::Request<'_>,
    connect_timeout: Duration,
    rpc_timeout: Duration,
) -> anyhow::Result<R::Response> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building RPC client runtime")?;
    rt.block_on(async {
        let mut handle = tokio::time::timeout(connect_timeout, connect(uds_path))
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "no live minimald behind {} after {connect_timeout:?}",
                    uds_path.display()
                )
            })??;
        tokio::time::timeout(rpc_timeout, call_oneshot::<R>(&mut handle, request))
            .await
            .map_err(|_| anyhow::anyhow!("RPC {} timed out after {rpc_timeout:?}", R::NAME))?
    })
}

/// Ask the in-VM minimald to shut down: drain sessions and quiesce the state
/// volume (R2.3). `force: true` because the caller is tearing the VM down
/// regardless — a refused non-force shutdown would only trade a clean drain
/// for an unclean SIGTERM.
pub(crate) fn shutdown_guest(
    uds_path: &Path,
    connect_timeout: Duration,
    rpc_timeout: Duration,
) -> anyhow::Result<minimald_rpc::ShutdownResponse> {
    call_oneshot_blocking::<minimald_rpc::Shutdown>(
        uds_path,
        minimald_rpc::ShutdownRequest { force: true },
        connect_timeout,
        rpc_timeout,
    )
}

async fn connect(uds_path: &Path) -> anyhow::Result<russh::client::Handle<AnyHostKey>> {
    let stream = tokio::net::UnixStream::connect(uds_path)
        .await
        .with_context(|| format!("connect to minimald at {}", uds_path.display()))?;

    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(config, stream, AnyHostKey)
        .await
        .context("ssh connect")?;

    let auth = handle
        .authenticate_none("minvmd")
        .await
        .context("authenticate")?;
    if !auth.success() {
        anyhow::bail!("authentication rejected by daemon");
    }
    Ok(handle)
}

async fn call_oneshot<R: OneshotSshRpc>(
    handle: &mut russh::client::Handle<AnyHostKey>,
    request: R::Request<'_>,
) -> anyhow::Result<R::Response> {
    let channel = handle
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

    serde_json::from_slice(&resp_buf).with_context(|| format!("decode response for {}", R::NAME))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_guest_errors_fast_on_absent_socket() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no-such.sock");
        let started = std::time::Instant::now();
        let err =
            shutdown_guest(&missing, Duration::from_secs(5), Duration::from_secs(60)).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must fail on connect, not wait out the timeout"
        );
        assert!(
            err.to_string().contains("connect to minimald"),
            "got: {err:#}"
        );
    }

    /// A socket that accepts but never speaks SSH (a wedged guest behind
    /// libkrun's always-accepting bridge) must fail within the connect
    /// deadline, not the (much longer) RPC deadline.
    #[test]
    fn shutdown_guest_fails_within_connect_deadline_on_mute_listener() {
        let tmp = tempfile::tempdir().unwrap();
        let sock = tmp.path().join("mute.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();

        let started = std::time::Instant::now();
        let err =
            shutdown_guest(&sock, Duration::from_millis(300), Duration::from_secs(60)).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "must give up at the connect deadline, not the RPC deadline"
        );
        assert!(err.to_string().contains("no live minimald"), "got: {err:#}");
    }
}
