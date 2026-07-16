//! Network-state capture: listening sockets and the per-provider socket
//! probe.
//!
//! The staged socket probe is the highest-signal item in the bundle: which
//! stage fails distinguishes the classic field failures — no socket file
//! (daemon never ran / cleaned up), connect refused (stale socket after a
//! crash), handshake timeout (wedged guest behind libkrun's always-accepting
//! bridge, #730), RPC failure (daemon up but unhealthy).

use std::path::Path;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use serde::Serialize;

use super::bundle::BundleWriter;
use super::manifest::Redaction;

// ── host/net/listening.txt ───────────────────────────────────────────────────

pub async fn listening_sockets(w: &mut BundleWriter) -> Result<(), anyhow::Error> {
    let attempts: &[(&str, &[&str])] = if cfg!(target_os = "linux") {
        &[("ss", &["-ltnup"]), ("netstat", &["-ltnp"])]
    } else {
        &[("netstat", &["-anv", "-p", "tcp"])]
    };

    let mut last_err = None;
    for (cmd, args) in attempts {
        match command_output(cmd, args).await {
            Ok(text) => {
                let text = format!("$ {cmd} {}\n{text}", args.join(" "));
                return w
                    .add_bytes("host/net/listening.txt", text.as_bytes(), Redaction::None)
                    .await;
            }
            Err(e) => last_err = Some(e),
        }
    }

    let last_err = last_err.unwrap_or_else(|| anyhow::anyhow!("no listening-socket source"));
    #[cfg(target_os = "linux")]
    {
        let tables = proc_net_listeners().await.context("/proc/net fallback")?;
        let text = format!("(commands unavailable: {last_err:#})\n{tables}");
        return w
            .add_bytes("host/net/listening.txt", text.as_bytes(), Redaction::None)
            .await;
    }
    #[cfg(not(target_os = "linux"))]
    Err(last_err)
}

async fn command_output(cmd: &str, args: &[&str]) -> Result<String, anyhow::Error> {
    let out = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::process::Command::new(cmd).args(args).output(),
    )
    .await
    .with_context(|| format!("{cmd} timed out"))?
    .with_context(|| format!("spawning {cmd}"))?;
    if !out.status.success() {
        anyhow::bail!("{cmd} exited with {}", out.status);
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Raw `/proc/net` tables. Not parsed — the dev team can decode hex
/// address:port pairs; fidelity beats prettiness in a fallback.
#[cfg(target_os = "linux")]
async fn proc_net_listeners() -> Result<String, anyhow::Error> {
    let mut text = String::new();
    for table in ["tcp", "tcp6", "udp", "unix"] {
        let path = format!("/proc/net/{table}");
        text.push_str(&format!("=== {path} ===\n"));
        match tokio::fs::read_to_string(&path).await {
            Ok(t) => text.push_str(&t),
            Err(e) => text.push_str(&format!("<unreadable: {e}>\n")),
        }
    }
    Ok(text)
}

// ── providers/local-<n>/socket-probe.json ────────────────────────────────────

/// Result of one probe stage: what happened and how long it took.
#[derive(Serialize)]
pub struct Stage {
    outcome: String,
    duration_ms: u64,
}

impl Stage {
    fn run(started: Instant, result: Result<(), String>) -> Self {
        Self {
            outcome: match result {
                Ok(()) => "ok".to_string(),
                Err(e) => e,
            },
            duration_ms: started.elapsed().as_millis() as u64,
        }
    }

    fn skipped() -> Self {
        Self {
            outcome: "skipped: prior stage failed".to_string(),
            duration_ms: 0,
        }
    }

    pub fn is_ok(&self) -> bool {
        self.outcome == "ok"
    }
}

/// The staged probe record for one provider socket.
#[derive(Serialize)]
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
/// Returns the probe record and, when the handshake succeeded, the live
/// client so the caller can reuse the connection for the guest bundle
/// download instead of handshaking again.
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
            .map(|_| ())
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
            .map(|_| ())
            .map_err(|e| e.to_string()),
    );
    if !probe.connect.is_ok() {
        return (probe, None);
    }

    let t = Instant::now();
    let mut client = match crate::client::Client::connect(sock_path).await {
        Ok(c) => {
            probe.handshake = Stage::run(t, Ok(()));
            c
        }
        Err(e) => {
            probe.handshake = Stage::run(t, Err(format!("{e:#}")));
            return (probe, None);
        }
    };

    let t = Instant::now();
    match tokio::time::timeout(
        Duration::from_secs(5),
        client.oneshot_rpc::<minimald_rpc::GetVersion>(()),
    )
    .await
    {
        Ok(Ok(resp)) => {
            probe.get_version = Stage::run(t, Ok(()));
            probe.version = Some(resp);
        }
        Ok(Err(e)) => probe.get_version = Stage::run(t, Err(format!("{e:#}"))),
        Err(_) => probe.get_version = Stage::run(t, Err("timed out after 5s".to_string())),
    }

    (probe, Some(client))
}

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
