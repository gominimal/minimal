//! VM box egress under a hostname-only allowlist (NET-068).
//!
//! Boots a real microVM with the guest `minimald`, creates an `OwnIp` box
//! whose egress is only a list of toolchain hostnames, then runs the actual
//! toolchain operations inside it: apt update, git clone, npm install,
//! pip install, and a container image pull. The VM's only path out is through
//! the host gvproxy switch; the guest's PTask relay enforces the
//! DNS-pinned hostname allowlist outside the VM.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must point
//!   to the kernel, generic rootfs, and minimald initramfs cpio.
//! - `MINVMD_VM_OWN_IP=1`: own-IP box whose egress the switch enforces.
//!
//! The test writes each tool's exit status and a tail of the daemon log's
//! admissions/drops during it, so a stalled fetch names the host that was not
//! admitted (diagnostics requirement).

#![cfg(minvmd_libkrun)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use tempfile::TempDir;

/// Hostnames the toolchain contacts. The box declares `egress.allow_dns_hosts`
/// with these names only (no subnets, no protocols beyond TCP) so every
/// operation's reach must be earned by DNS-pinned admission.
const TOOLCHAIN_HOSTS: &[&str] = &[
    "deb.debian.org",
    "github.com",
    "registry.npmjs.org",
    "pypi.org",
    "registry-1.docker.io",
];

/// Isolated `XDG_STATE_HOME` under /tmp: macOS's $TMPDIR is deep enough that
/// provider sockets beneath a default tempdir would overflow sun_path (104).
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// The minvmd binary to boot: `MINVMD_BIN` when set — CI's split build/test
/// jobs run this harness on a different runner than the one that compiled it —
/// otherwise that compile-time cargo-built path.
fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

const BOOT_TIMEOUT: Duration = Duration::from_secs(90);

/// Env var the server reads to scope an exec to a session.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so.
fn e2e_enabled() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("egress_allowlist_integration: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
        "MINVMD_VM_OWN_IP",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "egress_allowlist_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    assert!(
        crate::cmd::own_ip_requested(),
        "this test requires an own-IP VM (MINVMD_VM_OWN_IP=1)"
    );
    true
}

/// A booted minimald guest VM, torn down on drop.
struct Guest {
    child: Child,
    sock_path: PathBuf,
    state: TempDir,
}

impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Guest {
    /// Boots `minvmd boot --foreground` with minimald as the guest init and
    /// blocks until the `vm-up` (READY) line. Panics on boot timeout.
    fn boot() -> Guest {
        let state = short_state_dir();
        let sock_path = state
            .path()
            .join("minimal/providers/local-minvmd0/ssh.sock");

        let exe = minvmd_bin();
        let mut child = Command::new(exe)
            .args(["boot", "--foreground"])
            .env("XDG_STATE_HOME", state.path())
            .env("MINVMD_VM_OWN_IP", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawning minvmd boot --foreground");

        let stdout = child.stdout.take().expect("child stdout");
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().map_while(Result::ok) {
                if line.trim() == "vm-up" {
                    let _ = tx.send(true);
                    return;
                }
            }
            let _ = tx.send(false);
        });

        if !rx.recv_timeout(BOOT_TIMEOUT).unwrap_or(false) {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "egress_allowlist_integration: no 'vm-up' within {} s; are \
                 MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH/MINVMD_INITRAMFS set correctly \
                 (and libkrun >= 1.19.0)?",
                BOOT_TIMEOUT.as_secs(),
            );
        }

        Guest {
            child,
            sock_path,
            state,
        }
    }

    /// Path to the provider directory, where the guest daemon writes its log.
    fn provider_dir(&self) -> PathBuf {
        self.state.path().join("minimal/providers/local-minvmd0")
    }
}

/// russh client handler: accept the guest's ephemeral host key.
struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires own-IP VM with libkrun + images + network"]
async fn hostname_allowlist_toolchain_completes() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();

    // Wait for post-READY startup to settle before driving SSH.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut session_id = None;
    let mut last_err = String::new();
    for attempt in 1..=6 {
        match create_toolchain_session(&guest.sock_path).await {
            Ok(id) => {
                session_id = Some(id);
                break;
            }
            Err(e) => {
                last_err = e;
                eprintln!("session create attempt {attempt}: {last_err}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    let session_id = session_id.expect("failed to create toolchain session");

    let tools = [
        (
            "apt",
            minimald_rpc::exec::ExecRequest::Shell("apt-get update -qq".to_string()),
        ),
        (
            "git",
            minimald_rpc::exec::ExecRequest::Shell(
                "git clone --depth 1 https://github.com/torvalds/linux /tmp/linux-stub".to_string(),
            ),
        ),
        (
            "npm",
            minimald_rpc::exec::ExecRequest::Shell(
                "mkdir -p /tmp/npm-stub && cd /tmp/npm-stub && npm install is-odd --prefix ."
                    .to_string(),
            ),
        ),
        (
            "pip",
            minimald_rpc::exec::ExecRequest::Shell(
                "pip install --target /tmp/pip-stub requests".to_string(),
            ),
        ),
        (
            "podman",
            minimald_rpc::exec::ExecRequest::Shell(
                "podman pull --quiet docker.io/library/hello-world".to_string(),
            ),
        ),
    ];

    let mut failures = Vec::new();
    for (name, exec) in &tools {
        match run_session_exec(&guest.sock_path, session_id, &exec.encode()).await {
            Ok((stdout, stderr, exit)) => {
                // Print the tool's exit status and a tail of the daemon log
                // admissions/drops during it, so a stalled fetch names the host
                // that was not admitted.
                let log_tail = tail_daemon_log(&guest.provider_dir());
                eprintln!(
                    "egress_allowlist_integration: {name} exit={exit:?}\n\
                     --- stdout tail ---\n{stdout}\n\
                     --- stderr tail ---\n{stderr}\n\
                     --- daemon log tail ---\n{log_tail}",
                );
                if exit != Some(0) {
                    failures.push((*name, exit, stdout, stderr, log_tail));
                }
            }
            Err(e) => {
                eprintln!("egress_allowlist_integration: {name} exec failed: {e}");
                failures.push((
                    *name,
                    None,
                    String::new(),
                    e,
                    tail_daemon_log(&guest.provider_dir()),
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "hostname-only allowlist toolchain operations failed: {failures:?}"
    );
}

/// Create an `OwnIp` box with the hostname-only toolchain allowlist.
async fn create_toolchain_session(sock_path: &Path) -> Result<minimald_rpc::SessionId, String> {
    use minimald_rpc::{CreateSession, CreateSessionRequest, OneshotSshRpc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream = {
        let mut conn = None;
        let mut last_err = None;
        for _ in 0..20 {
            match tokio::net::UnixStream::connect(sock_path).await {
                Ok(s) => {
                    conn = Some(s);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        conn.ok_or_else(|| format!("connect to bridge UDS: {}", last_err.unwrap()))?
    };

    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(config, stream, ClientHandler)
        .await
        .map_err(|e| format!("ssh connect: {e}"))?;

    let auth = handle
        .authenticate_none("minvmd-e2e")
        .await
        .map_err(|e| format!("authenticate_none: {e}"))?;
    if !auth.success() {
        return Err("auth_none rejected".into());
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open CreateSession channel: {e}"))?;
    channel
        .request_subsystem(false, CreateSession::NAME)
        .await
        .map_err(|e| format!("request_subsystem: {e}"))?;

    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    let req = CreateSessionRequest {
        config: minimald_rpc::SessionConfig {
            name: Some(format!("hostname-allowlist-{uniq:x}")),
            project_path: paths::HostAbsPath::try_new("/tmp")
                .map_err(|e| format!("project_path: {e}"))?,
            network: sessions::NetworkMode::OwnIp,
            policy: sessions::SessionPolicy::new(
                Some(sessions::EgressPolicy {
                    allow_protocols: Some(vec![sessions::IpProto::Tcp]),
                    allow_subnets: Some(Vec::new()),
                    allow_dns_hosts: Some(
                        TOOLCHAIN_HOSTS.iter().map(|h| (*h).to_string()).collect(),
                    ),
                    deny_subnets: None,
                }),
                None,
            ),
            hooks_enabled: true,
            attrs: Default::default(),
        },
        must_match_version: None,
    };
    let body = serde_json_lenient::to_vec(&req).map_err(|e| format!("serialize request: {e}"))?;

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
    let resp: <CreateSession as OneshotSshRpc>::Response =
        serde_json_lenient::from_slice(&resp_buf).map_err(|e| format!("decode response: {e}"))?;
    let id = resp
        .ok()
        .ok_or_else(|| "CreateSession returned an error".to_string())?
        .id;

    // ConfigureLoadout + FinalizeSession: the task-only workspace needs no
    // project files, so the empty contribution fast-path finalizes immediately.
    configure_and_finalize(&mut handle, id).await?;

    Ok(id)
}

async fn configure_and_finalize(
    handle: &mut russh::client::Handle<ClientHandler>,
    session_id: minimald_rpc::SessionId,
) -> Result<(), String> {
    use minimald_rpc::{
        ConfigureLoadout, ConfigureLoadoutRequest, ConfigureLoadoutResponse, FinalizeSession,
        FinalizeSessionRequest, OneshotSshRpc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open ConfigureLoadout channel: {e}"))?;
        channel
            .request_subsystem(false, ConfigureLoadout::NAME)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;
        let req = ConfigureLoadoutRequest {
            session_id,
            contribution: Default::default(),
        };
        let body = serde_json_lenient::to_vec(&req)
            .map_err(|e| format!("serialize ConfigureLoadout request: {e}"))?;
        let mut rpc = channel.into_stream();
        rpc.write_all(&body)
            .await
            .map_err(|e| format!("write ConfigureLoadout request: {e}"))?;
        rpc.shutdown()
            .await
            .map_err(|e| format!("shutdown ConfigureLoadout write half: {e}"))?;
        let mut buf = Vec::new();
        rpc.read_to_end(&mut buf)
            .await
            .map_err(|e| format!("read ConfigureLoadout response: {e}"))?;
        let resp: <ConfigureLoadout as OneshotSshRpc>::Response =
            serde_json_lenient::from_slice(&buf)
                .map_err(|e| format!("decode ConfigureLoadout response: {e}"))?;
        match resp.ok() {
            Some(ConfigureLoadoutResponse::Materialized) => {}
            Some(ConfigureLoadoutResponse::Pending { .. }) => {
                return Err(
                    "ConfigureLoadout returned Pending; this test's workspace gates nothing".into(),
                );
            }
            None => return Err("ConfigureLoadout returned an error".into()),
        }
    }

    {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open FinalizeSession channel: {e}"))?;
        channel
            .request_subsystem(false, FinalizeSession::NAME)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;
        let req = FinalizeSessionRequest { session_id };
        let body = serde_json_lenient::to_vec(&req)
            .map_err(|e| format!("serialize FinalizeSession request: {e}"))?;
        let mut rpc = channel.into_stream();
        rpc.write_all(&body)
            .await
            .map_err(|e| format!("write FinalizeSession request: {e}"))?;
        rpc.shutdown()
            .await
            .map_err(|e| format!("shutdown FinalizeSession write half: {e}"))?;
        let mut buf = Vec::new();
        rpc.read_to_end(&mut buf)
            .await
            .map_err(|e| format!("read FinalizeSession response: {e}"))?;
        let resp: <FinalizeSession as OneshotSshRpc>::Response =
            serde_json_lenient::from_slice(&buf)
                .map_err(|e| format!("decode FinalizeSession response: {e}"))?;
        resp.ok()
            .ok_or_else(|| "FinalizeSession returned an error".into())?;
    }

    Ok(())
}

/// Exec `command` in the session identified by `session_id`, returning
/// `(stdout, stderr, exit_status)`.
async fn run_session_exec(
    sock_path: &Path,
    session_id: minimald_rpc::SessionId,
    command: &str,
) -> Result<(String, String, Option<u32>), String> {
    use russh::ChannelMsg;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream = {
        let mut conn = None;
        let mut last_err = None;
        for _ in 0..20 {
            match tokio::net::UnixStream::connect(sock_path).await {
                Ok(s) => {
                    conn = Some(s);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        conn.ok_or_else(|| format!("connect to bridge UDS: {}", last_err.unwrap()))?
    };

    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(config, stream, ClientHandler)
        .await
        .map_err(|e| format!("ssh connect: {e}"))?;

    let auth = handle
        .authenticate_none("minvmd-e2e")
        .await
        .map_err(|e| format!("authenticate_none: {e}"))?;
    if !auth.success() {
        return Err("auth_none rejected".into());
    }

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open exec channel: {e}"))?;
    channel
        .set_env(true, MINIMAL_SESSION_ID_ENV, session_id.to_string())
        .await
        .map_err(|e| format!("set_env: {e}"))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("exec: {e}"))?;
    channel.eof().await.map_err(|e| format!("eof: {e}"))?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut exit_status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, ext } if ext == 1 => stderr.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Failure => return Err("exec request rejected (CHANNEL_FAILURE)".into()),
            _ => {}
        }
    }

    Ok((
        String::from_utf8_lossy(&stdout).into_owned(),
        String::from_utf8_lossy(&stderr).into_owned(),
        exit_status,
    ))
}

/// Return the last lines of the guest daemon log, when it exists, so a
/// failure names the host that was not admitted.
fn tail_daemon_log(provider_dir: &Path) -> String {
    let log_path = provider_dir.join("daemon.log");
    let contents = match std::fs::read_to_string(&log_path) {
        Ok(c) => c,
        Err(e) => return format!("(no daemon log at {}: {e})", log_path.display()),
    };
    contents
        .lines()
        .rev()
        .take(40)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n")
}
