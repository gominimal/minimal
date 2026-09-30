//! VM box egress under a hostname-only allowlist (NET-068).
//!
//! Boots a real microVM with the guest `minimald`, creates an `OwnIp` box whose
//! egress is only a list of toolchain hostnames, then runs the actual toolchain
//! operations inside it: git clone, npm install, pip install, and a container
//! image pull with `skopeo`. The VM's only path out is through the host gvproxy
//! switch; the guest's relay enforces the DNS-pinned hostname allowlist at the
//! VM boundary. The composed box has no Debian userland, so apt is not exercised
//! (recorded as a NET-068 deviation in the PR body).
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must point to
//!   the kernel, generic rootfs, and minimald initramfs cpio.
//! - `MINVMD_GVPROXY_BIN` must point to the host gvproxy switch: `just test-vm`
//!   fetches it and exports this variable, and the test skips with a reason
//!   when the variable is unset.
//!
//! The test writes each tool's exit status and the boot-log admissions/drops
//! that arrived during it, so a stalled fetch names the host that was not
//! admitted (diagnostics requirement).

#![cfg(minvmd_libkrun)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use tempfile::TempDir;

/// Hostnames the box declares in `egress.allow_dns_hosts` only (no subnets, no
/// protocols beyond TCP). Every operation's reach must be earned by DNS-pinned
/// admission. The list is shared with the `minimald` unit fixture so the two
/// cannot drift.
const TOOLCHAIN_HOSTS: &[&str] = sessions::NET068_TOOLCHAIN_EGRESS_HOSTS;

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
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// Env var the server reads to scope an exec to a session.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Host-side boot-console path. `std::env::var_os` result is empty-safe.
const MINVMD_BOOT_LOG_ENV: &str = "MINVMD_BOOT_LOG";

/// Host-side gvproxy path env.
const MINVMD_GVPROXY_BIN_ENV: &str = "MINVMD_GVPROXY_BIN";

/// Guest log filter that promotes the DNS-gate admission lines to debug.
const GUEST_LOG_FILTER: &str = "info,minimald::net::dns_gate=debug";

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so. Skips quietly when gvproxy is not
/// available, because an own-IP boot without it has no host-side switch.
fn e2e_enabled() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("egress_allowlist_integration: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "egress_allowlist_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    if std::env::var_os(MINVMD_GVPROXY_BIN_ENV).is_none() {
        eprintln!(
            "egress_allowlist_integration: {MINVMD_GVPROXY_BIN_ENV} is not set, \
             skipping own-IP test (gvproxy is opt-in in CI)"
        );
        return false;
    }
    true
}

/// A booted minimald guest VM, torn down on drop.
struct Guest {
    child: Child,
    sock_path: PathBuf,
    boot_log_path: PathBuf,
    boot_log_offset: usize,
    _state: TempDir,
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
        let boot_log_path = std::env::var_os(MINVMD_BOOT_LOG_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                state
                    .path()
                    .join("minimal/providers/local-minvmd0/boot.log")
            });

        let exe = minvmd_bin();
        let mut cmd = Command::new(exe);
        cmd.args(["boot", "--foreground"])
            // minimald boots as the initramfs `/init` (MINVMD_INITRAMFS, set by
            // the caller); the rootfs stays generic.
            .env("XDG_STATE_HOME", state.path())
            .env("MINVMD_VM_OWN_IP", "1")
            .env("RUST_LOG", GUEST_LOG_FILTER)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        if let Some(gvproxy) = std::env::var_os(MINVMD_GVPROXY_BIN_ENV) {
            cmd.env(MINVMD_GVPROXY_BIN_ENV, gvproxy);
        }

        let mut child = cmd.spawn().expect("spawning minvmd boot --foreground");

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
            boot_log_path,
            boot_log_offset: 0,
            _state: state,
        }
    }

    /// Return the lines appended to the guest boot log since the last call,
    /// so each tool failure is paired with the admissions/drops that happened
    /// while it ran. The tail is filtered to DNS-gate and policy lines so a
    /// chatty tool cannot push the admission/refusal evidence out of the cap,
    /// and invalid UTF-8 is replaced rather than losing the whole tail.
    fn tail_boot_log(&mut self) -> String {
        let contents = match std::fs::read(&self.boot_log_path) {
            Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
            Err(e) => return format!("(no boot log at {}: {e})", self.boot_log_path.display()),
        };
        let total_len = contents.len();
        let tail = if total_len >= self.boot_log_offset {
            &contents[self.boot_log_offset..]
        } else {
            // Log was truncated/rotated; just print the whole current contents.
            &contents[..]
        };
        self.boot_log_offset = total_len;
        // Keep only the evidence the DNS gate and policy warnings emit; the
        // diagnostics requirement is to name the host that was not admitted.
        let mut lines: Vec<&str> = tail
            .lines()
            .filter(|line| {
                line.contains("dns-gate")
                    || line.contains("admitted")
                    || line.contains("refused")
                    || line.contains("rule_matched")
            })
            .rev()
            .take(120)
            .collect();
        lines.reverse();
        lines.join("\n")
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
#[ignore = "gated MINVMD_E2E=1; requires own-IP VM with libkrun + images + gvproxy + network"]
async fn hostname_allowlist_toolchain_completes() {
    if !e2e_enabled() {
        return;
    }
    let mut guest = Guest::boot();

    // Wait for post-READY startup to settle before driving SSH.
    tokio::time::sleep(Duration::from_millis(1000)).await;

    let mut session_id = None;
    for attempt in 1..=6 {
        match create_toolchain_session(&guest.sock_path).await {
            Ok(id) => {
                session_id = Some(id);
                break;
            }
            Err(e) => {
                eprintln!("session create attempt {attempt}: {e}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    let session_id = session_id.expect("failed to create toolchain session");

    // Toolchain exercises: git, npm, pip, and a container pull. The composed
    // box has no Debian userland or `apt` package, so the apt leg NET-068 named
    // is not exercised here; the hostname-only allowlist still must admit every
    // host these four tools contact.
    let tools = [
        (
            "git",
            "git clone --depth 1 https://github.com/octocat/Hello-World /tmp/hello-world",
        ),
        (
            "npm",
            "mkdir -p /tmp/npm-stub && cd /tmp/npm-stub && npm install is-odd --prefix .",
        ),
        ("pip", "pip3 install --target /tmp/pip-stub requests"),
        (
            "skopeo",
            "skopeo --insecure-policy copy docker://docker.io/library/hello-world dir:/tmp/hw",
        ),
    ];

    let mut failures = Vec::new();
    for (name, command) in &tools {
        let encoded = minimald_rpc::exec::ExecRequest::Shell((*command).to_string()).encode();
        let result = tokio::time::timeout(
            EXEC_TIMEOUT,
            run_session_exec(&guest.sock_path, session_id, &encoded),
        )
        .await;
        match result {
            Ok(Ok((stdout, stderr, exit))) => {
                // Print the tool's exit status and the boot-log tail that
                // accumulated while it ran, so a stalled fetch names the host
                // that was not admitted.
                let log_tail = guest.tail_boot_log();
                eprintln!(
                    "egress_allowlist_integration: {name} exit={exit:?}\n\
                     --- stdout tail ---\n{stdout}\n\
                     --- stderr tail ---\n{stderr}\n\
                     --- boot log tail ---\n{log_tail}",
                );
                if exit != Some(0) {
                    failures.push((*name, exit, stdout, stderr, log_tail));
                }
            }
            Ok(Err(e)) => {
                let log_tail = guest.tail_boot_log();
                eprintln!("egress_allowlist_integration: {name} exec failed: {e}");
                failures.push((*name, None, String::new(), e, log_tail));
            }
            Err(_) => {
                let log_tail = guest.tail_boot_log();
                eprintln!("egress_allowlist_integration: {name} timed out after {EXEC_TIMEOUT:?}");
                failures.push((
                    *name,
                    None,
                    String::new(),
                    format!("timed out after {EXEC_TIMEOUT:?}"),
                    log_tail,
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "hostname-only allowlist toolchain operations failed: {failures:?}\n\
         note: apt is not exercised because the composed box has no Debian userland"
    );
}

/// Project file to upload into the session workspace. Its `[session]` packages
/// provide the toolchain binaries the test execs; `[upstream]` points at the
/// shared package repo the composer needs to resolve them.
fn toolchain_project_toml() -> String {
    let upstream = r#"
[upstream]
repo = "https://github.com/gominimal/pkgs"
branch = "main"
locked_commit = "f4de33d06dada4edcf5076dded10e9c303cf597e"
"#;
    format!(
        r#"{}

[session]
packages = [
    "base",
    "coreutils",
    "git",
    "python",
    "node",
    "skopeo",
    "ca-certificates",
]
"#,
        upstream.trim()
    )
}

/// Open a russh client over the bridge UDS, authenticate, create a session,
/// upload a `minimal.toml` with the toolchain packages, compose the loadout, and
/// finalize it. Returns the session id.
async fn create_toolchain_session(sock_path: &Path) -> Result<sessions::SessionId, String> {
    use minimald_rpc::{CreateSession, CreateSessionRequest, OneshotSshRpc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut handle = connect_and_auth(sock_path).await?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open CreateSession channel: {e}"))?;
    channel
        .request_subsystem(false, CreateSession::NAME)
        .await
        .map_err(|e| format!("request_subsystem: {e}"))?;

    // Unique name per invocation — minimald dedups sessions by name, so the
    // outer retry loop would otherwise collide on `AlreadyExists` after any
    // prior attempt persisted a record.
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
    let session_id = resp
        .ok()
        .ok_or_else(|| "CreateSession returned an error".to_string())?
        .id;

    // Upload the project's `minimal.toml` into the session workspace, then
    // configure and finalize the loadout. The workspace must contain the
    // project file before `ConfigureLoadout` composes the packages into the box.
    upload_workspace_file(
        &mut handle,
        session_id,
        "/workbench/minimal.toml",
        &toolchain_project_toml(),
    )
    .await?;
    configure_and_finalize(&mut handle, session_id).await?;

    Ok(session_id)
}

/// Reusable SSH connect + none-auth over the bridge UDS.
async fn connect_and_auth(
    sock_path: &Path,
) -> Result<russh::client::Handle<ClientHandler>, String> {
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
    Ok(handle)
}

/// Upload a string into the session workspace over SFTP. The path is absolute
/// in the workspace (the SFTP subsystem presents `/workbench` as the root).
async fn upload_workspace_file(
    handle: &mut russh::client::Handle<ClientHandler>,
    session_id: sessions::SessionId,
    remote_path: &str,
    contents: &str,
) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open sftp channel: {e}"))?;
    channel
        .set_env(true, MINIMAL_SESSION_ID_ENV, session_id.to_string())
        .await
        .map_err(|e| format!("sftp set_env: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("request sftp subsystem: {e}"))?;
    let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("open sftp session: {e}"))?;
    // `create` (CREATE|WRITE|TRUNCATE), not the high-level `write` helper —
    // the latter opens WRITE-only and so fails on a not-yet-existing file.
    let mut file = sftp
        .create(remote_path)
        .await
        .map_err(|e| format!("sftp create {remote_path}: {e}"))?;
    file.write_all(contents.as_bytes())
        .await
        .map_err(|e| format!("sftp write {remote_path}: {e}"))?;
    file.shutdown()
        .await
        .map_err(|e| format!("sftp close {remote_path}: {e}"))?;
    sftp.close()
        .await
        .map_err(|e| format!("close sftp session: {e}"))?;

    Ok(())
}

async fn configure_and_finalize(
    handle: &mut russh::client::Handle<ClientHandler>,
    session_id: sessions::SessionId,
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
                    "ConfigureLoadout returned Pending; the project file should need no gating"
                        .into(),
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
        // The response is `FinalizeSessionResponse`; the outer `Errorable`
        // only carries success/failure here. Returning `Ok(())` discards the
        // empty-ish hook list, which is fine for this test.
        resp.ok()
            .ok_or_else(|| "FinalizeSession returned an error".to_string())?;
    }

    Ok(())
}

/// Exec `command` in the session identified by `session_id`, returning
/// `(stdout, stderr, exit_status)`.
async fn run_session_exec(
    sock_path: &Path,
    session_id: sessions::SessionId,
    command: &str,
) -> Result<(String, String, Option<u32>), String> {
    use russh::ChannelMsg;

    let handle = connect_and_auth(sock_path).await?;

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
            ChannelMsg::ExtendedData { data, ext: 1 } => stderr.extend_from_slice(&data),
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
