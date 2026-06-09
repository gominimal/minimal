//! minimald session end-to-end over the libkrun bridge (Stage 2).
//!
//! Reliable counterpart to ad-hoc `ssh`/`socat`/`nc` testing, which does NOT
//! round-trip the libkrun host-UDS↔vsock bridge (even the socat-echo stub
//! returns nothing via the CLI, while a Rust `UnixStream` client works).
//!
//! `minimald_exec_over_bridge` drives a real russh client over a `UnixStream`
//! to the bridge UDS: it authenticates, creates a session (`CreateSession` RPC
//! over an SSH subsystem), execs a command in that session, and asserts the
//! stdout + exit status that come back — proving the full path host UDS →
//! libkrun bridge → guest vsock → socat relay → minimald SSH → session exec.
//!
//! Gates:
//! - `#[cfg(target_os = "macos")]`: libkrun is macOS-only.
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH` + `MINVMD_ROOTFS_PATH` must point to the kernel and a
//!   rootfs with `minimald` baked in at `/sbin/minimald` plus the
//!   `/sbin/minimald-init` wrapper. The test sets `MINVMD_EXEC` to that wrapper.

#![cfg(target_os = "macos")]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use tempfile::TempDir;

const BOOT_TIMEOUT: Duration = Duration::from_secs(15);

/// SSH subsystem name for the CreateSession RPC (mirrors
/// `minimald::rpc::RPC_SUBSYSTEM_PREFIX` + "CreateSession"; minimald is
/// Linux-only so it cannot be imported into this macOS test).
const CREATE_SESSION_SUBSYSTEM: &str = "minimald-v1-CreateSession";
/// Env var the server reads to scope an exec to a session
/// (mirrors `minimald::MINIMAL_SESSION_ID_ENV`).
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so.
fn e2e_enabled() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("minimald_session_e2e: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &["MINVMD_KERNEL_PATH", "MINVMD_ROOTFS_PATH"] {
        assert!(
            std::env::var(var).is_ok(),
            "minimald_session_e2e: {var} must be set when MINVMD_E2E=1"
        );
    }
    true
}

/// A booted minimald guest VM, torn down on drop.
struct Guest {
    child: Child,
    sock_path: PathBuf,
    _runtime: TempDir,
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
        let runtime = TempDir::new().expect("creating isolated runtime dir");
        let state = TempDir::new().expect("creating isolated state dir");
        let sock_path = runtime.path().join("minimal/minimald.sock");

        let exe = env!("CARGO_BIN_EXE_minvmd");
        let mut child = Command::new(exe)
            .args(["boot", "--foreground"])
            // Run minimald as the guest init (the wrapper execs `minimald run --guest`).
            .env("MINVMD_EXEC", "/sbin/minimald-init")
            .env("XDG_RUNTIME_DIR", runtime.path())
            .env("XDG_STATE_HOME", state.path())
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
                "minimald_session_e2e: no 'vm-up' within {} s; is minimald baked into the rootfs \
                 at /sbin/minimald(-init) and MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH correct?",
                BOOT_TIMEOUT.as_secs(),
            );
        }

        Guest {
            child,
            sock_path,
            _runtime: runtime,
            _state: state,
        }
    }
}

// --- Full session: russh client → CreateSession → exec → stdout ---

/// CreateSession request payload (mirrors `minimald::rpc::CreateSessionRequest`).
#[derive(serde::Serialize)]
struct CreateSessionRequest {
    record: sessions::Record,
}

/// CreateSession response payload (mirrors `minimald::rpc::CreateSessionResponse`).
#[derive(serde::Deserialize)]
struct CreateSessionResponse {
    id: sessions::SessionId,
}

/// russh client handler: accept the guest's ephemeral host key.
struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, and a minimald rootfs"]
async fn minimald_exec_over_bridge() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();
    let sentinel = "MINIMALD_SESSION_OK";

    // Retry the whole session to absorb the post-READY startup race.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut result = Err("not attempted".to_string());
    for attempt in 1..=6 {
        result = run_session_exec(&guest.sock_path, &format!("echo {sentinel}")).await;
        if result.is_ok() {
            break;
        }
        eprintln!("session attempt {attempt}: {result:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let (stdout, exit) = result.unwrap_or_else(|e| panic!("minimald_session_e2e: {e}"));
    eprintln!("minimald_session_e2e: exec stdout={stdout:?} exit={exit:?}");
    assert!(
        stdout.trim() == sentinel,
        "expected stdout {sentinel:?}, got {stdout:?}"
    );
    assert_eq!(exit, Some(0), "expected exit status 0, got {exit:?}");
}

/// Open a russh client over the bridge UDS, authenticate, create a session,
/// and exec `command` in it. Returns `(stdout, exit_status)`.
async fn run_session_exec(
    sock_path: &Path,
    command: &str,
) -> Result<(String, Option<u32>), String> {
    use russh::ChannelMsg;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connect (retry briefly in case the relay is not yet wired up).
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

    // CreateSession: open a channel, request the subsystem, write the JSON
    // request, half-close, read the JSON response.
    let session_id = {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open CreateSession channel: {e}"))?;
        channel
            .request_subsystem(false, CREATE_SESSION_SUBSYSTEM)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;

        let req = CreateSessionRequest {
            record: sessions::Record {
                id: sessions::SessionId::nil(),
                name: Some("minvmd-e2e".to_string()),
                username: None,
                project_path: paths::HostAbsPath::try_new("/tmp")
                    .map_err(|e| format!("project_path: {e}"))?,
                attrs: Default::default(),
            },
        };
        let body = serde_json::to_vec(&req).map_err(|e| format!("serialize request: {e}"))?;

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
        let resp: CreateSessionResponse =
            serde_json::from_slice(&resp_buf).map_err(|e| format!("decode response: {e}"))?;
        resp.id
    };

    // Exec the command in that session.
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
