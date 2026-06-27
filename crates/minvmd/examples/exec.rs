//! Demo client — run a command *inside the minimald guest* over the libkrun
//! bridge, from the macOS host.
//!
//! Boot a VM first (another terminal):
//!
//! ```text
//! MINVMD_KERNEL_PATH=… MINVMD_ROOTFS_PATH=… MINVMD_INITRAMFS=… \
//!   target/debug/minvmd boot --foreground
//! ```
//!
//! Then run commands in it:
//!
//! ```text
//! cargo run -q -p minvmd --example exec -- uname -a
//! cargo run -q -p minvmd --example exec -- cat /etc/os-release
//! cargo run -q -p minvmd --example exec -- 'echo hello from $(hostname)'
//! ```
//!
//! It connects to the host↔guest bridge UDS (the same path `minvmd` registers;
//! override with `MINVMD_BRIDGE_SOCK`), opens a session, and execs the command
//! in the guest — printing its stdout and propagating its exit status.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use russh::ChannelMsg;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use minimald_rpc::{CreateSessionRequest, CreateSessionResponse, SessionConfig};

/// SSH subsystem for the CreateSession RPC (mirrors minimald's
/// `RPC_SUBSYSTEM_PREFIX` + "CreateSession").
const CREATE_SESSION_SUBSYSTEM: &str = "minimald-v1-CreateSession";
/// Env var minimald reads to scope an exec to a session.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

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

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    let command = std::env::args().skip(1).collect::<Vec<_>>().join(" ");
    if command.trim().is_empty() {
        eprintln!("usage: cargo run -p minvmd --example exec -- <command...>");
        std::process::exit(2);
    }

    let sock = match std::env::var("MINVMD_BRIDGE_SOCK") {
        Ok(p) if !p.is_empty() => PathBuf::from(p),
        _ => minvmd::sock::resolve_uds_path().expect("resolving bridge socket path"),
    };
    if !sock.exists() {
        eprintln!(
            "bridge socket not found at {} — is `minvmd boot` running?\n\
             (set MINVMD_BRIDGE_SOCK to point elsewhere)",
            sock.display()
        );
        std::process::exit(1);
    }
    eprintln!("\x1b[2m→ {}  ::  {}\x1b[0m", sock.display(), command);

    // A couple of attempts to absorb a just-booted guest still settling.
    let mut result = Err("not attempted".to_string());
    for attempt in 1..=4 {
        result = run_session_exec(&sock, &command).await;
        if result.is_ok() {
            break;
        }
        if attempt < 4 {
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
    }

    match result {
        Ok((stdout, exit)) => {
            print!("{stdout}");
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
            eprintln!(
                "\x1b[2m→ exit {}\x1b[0m",
                exit.map(|c| c as i32).unwrap_or(-1)
            );
            std::process::exit(exit.map(|c| c as i32).unwrap_or(1));
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

/// Open a russh client over the bridge UDS, authenticate, create a session, and
/// exec `command` in it. Returns `(stdout, exit_status)`.
async fn run_session_exec(
    sock_path: &Path,
    command: &str,
) -> Result<(String, Option<u32>), String> {
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
        .authenticate_none("minvmd-demo")
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

        // Unique name per invocation — minimald dedups sessions by name, so a
        // fixed name would only let the first command through.
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let req = CreateSessionRequest {
            config: SessionConfig {
                name: Some(format!("minvmd-demo-{uniq:x}")),
                project_path: paths::HostAbsPath::try_new("/tmp")
                    .map_err(|e| format!("project_path: {e}"))?,
                network: sessions::NetworkMode::default(),
                policy: Default::default(),
                attrs: Default::default(),
            },
            contribution: Default::default(),
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
        match resp {
            CreateSessionResponse::Ready { id } => id,
            CreateSessionResponse::Pending { .. } => {
                return Err("CreateSession returned Pending; \
                            this example only handles Ready"
                    .to_string());
            }
        }
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
