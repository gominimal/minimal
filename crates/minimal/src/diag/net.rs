//! The staged daemon-socket probe for `min bug`.
//!
//! The network *mechanics* — listening tables, interfaces, routes — live in
//! [`diagnostics::net`] and are collected for the host as a whole. What lives
//! here is the one network question only the CLI can ask: can this machine
//! actually reach the daemon behind `providers/<name>/ssh.sock`, and if not,
//! at which step does contact break?

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::Serialize;

use diagnostics::{BundleWriter, Redaction};

/// Deadline for the `GetVersion` RPC once the connection is handshaken. A
/// healthy daemon answers in milliseconds; this only bounds the case where it
/// accepted, authenticated, and then stopped answering.
const GET_VERSION_TIMEOUT: Duration = Duration::from_secs(5);

/// Result of one probe stage: what happened and how long it took.
#[derive(Debug, Serialize)]
pub struct Stage {
    outcome: String,
    duration_ms: u64,
}

impl Stage {
    fn run(started: Instant, result: Result<(), String>) -> Self {
        Self {
            outcome: result.err().unwrap_or_else(|| "ok".to_string()),
            duration_ms: started.elapsed().as_millis() as u64,
        }
    }

    fn skipped() -> Self {
        Self {
            outcome: "skipped: prior stage failed".to_string(),
            duration_ms: 0,
        }
    }

    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.outcome == "ok"
    }
}

/// A staged connection-health record for one provider's daemon socket.
///
/// Reaching the daemon has four steps, each a prerequisite for the next:
/// `stat()` the socket file, `connect()`, complete the SSH handshake + auth,
/// then issue a `GetVersion` RPC. The probe attempts them in order and records
/// how far it got — the *failing* stage is the diagnosis: no socket file
/// (daemon never ran / cleaned up), connect refused (stale socket after a
/// crash), handshake timeout (wedged guest behind libkrun's always-accepting
/// bridge), RPC failure (daemon up but unhealthy).
#[derive(Debug, Serialize)]
pub struct SocketProbe {
    socket_path: String,
    /// `stat()` the socket file.
    stat: Stage,
    /// One raw `connect()` attempt — no retries; we are probing, not waiting
    /// for a boot.
    connect: Stage,
    /// Full SSH handshake + auth (bounded by the client's own deadline).
    handshake: Stage,
    /// `GetVersion` RPC over the handshaken connection.
    get_version: Stage,
    version: Option<minimald_rpc::GetVersionResponse>,
}

/// Probes `sock_path` stage by stage, never failing — every outcome is data.
///
/// Returns the probe record and, when the handshake succeeded, the live client
/// so the caller can reuse the connection for the guest-bundle download
/// instead of handshaking again (R7.1).
pub async fn probe_socket(sock_path: &Path) -> (SocketProbe, Option<crate::client::Client>) {
    let mut probe = SocketProbe {
        socket_path: sock_path.display().to_string(),
        stat: Stage::skipped(),
        connect: Stage::skipped(),
        handshake: Stage::skipped(),
        get_version: Stage::skipped(),
        version: None,
    };

    let t = Instant::now();
    probe.stat = Stage::run(
        t,
        tokio::fs::metadata(sock_path)
            .await
            .map(drop)
            .map_err(|e| e.to_string()),
    );
    if !probe.stat.is_ok() {
        return (probe, None);
    }

    let t = Instant::now();
    probe.connect = Stage::run(
        t,
        tokio::net::UnixStream::connect(sock_path)
            .await
            .map(drop)
            .map_err(|e| e.to_string()),
    );
    if !probe.connect.is_ok() {
        return (probe, None);
    }

    let t = Instant::now();
    let mut client = match crate::client::Client::connect(sock_path).await {
        Ok(client) => {
            probe.handshake = Stage::run(t, Ok(()));
            client
        }
        Err(e) => {
            // `Client::connect` opens its own connection rather than adopting
            // the one probed above, so a daemon that died in between fails
            // *here* — and filing that as a handshake fault is precisely the
            // misdiagnosis this staged probe exists to prevent. Re-test the
            // cheaper layer to tell "stopped accepting" from "accepted but
            // would not handshake".
            match tokio::net::UnixStream::connect(sock_path).await {
                Ok(_) => probe.handshake = Stage::run(t, Err(format!("{e:#}"))),
                Err(again) => {
                    probe.connect = Stage::run(
                        t,
                        Err(format!(
                            "accepted once, then stopped: {again} \
                             (handshake never attempted: {e:#})"
                        )),
                    );
                }
            }
            return (probe, None);
        }
    };

    let t = Instant::now();
    match tokio::time::timeout(
        GET_VERSION_TIMEOUT,
        client.oneshot_rpc::<minimald_rpc::GetVersion>(()),
    )
    .await
    {
        Ok(Ok(resp)) => {
            probe.get_version = Stage::run(t, Ok(()));
            probe.version = Some(resp);
        }
        Ok(Err(e)) => probe.get_version = Stage::run(t, Err(format!("{e:#}"))),
        Err(_) => {
            probe.get_version =
                Stage::run(t, Err(format!("timed out after {GET_VERSION_TIMEOUT:?}")))
        }
    }

    (probe, Some(client))
}

/// Records `probe` as `providers/<provider>/socket-probe.json`.
pub async fn add_probe(
    w: &mut BundleWriter,
    provider: &str,
    probe: &SocketProbe,
) -> Result<(), anyhow::Error> {
    let json = serde_json::to_vec_pretty(probe).context("serializing socket probe")?;
    w.add_bytes(
        &format!("providers/{provider}/socket-probe.json"),
        &json,
        Redaction::None,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn probe_reports_missing_socket_at_the_stat_stage() {
        let tmp = tempfile::TempDir::new().unwrap();
        let (probe, client) = probe_socket(&tmp.path().join("nope.sock")).await;
        assert!(!probe.stat.is_ok());
        assert!(probe.connect.outcome.starts_with("skipped"));
        assert!(client.is_none());
    }

    /// A socket file that nothing is listening on (stale after a daemon
    /// crash) must fail at the connect stage — the signature of the
    /// stale-socket failure class.
    #[tokio::test]
    async fn probe_reports_stale_socket_at_the_connect_stage() {
        let tmp = tempfile::TempDir::new().unwrap();
        let sock = tmp.path().join("stale.sock");
        drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());

        let (probe, client) = probe_socket(&sock).await;
        assert!(probe.stat.is_ok());
        assert!(!probe.connect.is_ok(), "got: {}", probe.connect.outcome);
        assert!(probe.handshake.outcome.starts_with("skipped"));
        assert!(client.is_none());
    }

    /// An accepting-but-mute listener (wedged guest behind the libkrun
    /// bridge) must fail at the handshake stage, not hang.
    #[tokio::test(start_paused = true)]
    async fn probe_reports_mute_listener_at_the_handshake_stage() {
        let tmp = tempfile::TempDir::new().unwrap();
        let sock = tmp.path().join("mute.sock");
        let _listener = tokio::net::UnixListener::bind(&sock).unwrap();

        let (probe, client) = probe_socket(&sock).await;
        assert!(probe.stat.is_ok());
        assert!(probe.connect.is_ok());
        assert!(
            probe.handshake.outcome.contains("timed out"),
            "got: {}",
            probe.handshake.outcome
        );
        assert!(client.is_none());
    }
}
