//! minimald session end-to-end over the libkrun bridge (Stage 2).
//!
//! Reliable counterpart to ad-hoc `ssh`/`socat`/`nc` testing, which does NOT
//! round-trip the libkrun host-UDS↔vsock bridge (even the socat-echo stub
//! returns nothing via the CLI, while a Rust `UnixStream` client works).
//!
//! `minimald_exec_over_bridge` drives a real russh client over a `UnixStream`
//! to the bridge UDS: it authenticates, creates a session (`CreateSession` RPC
//! over an SSH subsystem), uploads a task-only `minimal.toml` into the session
//! workspace over SFTP, runs `min run echo_ok` in that session, and asserts the
//! stdout + exit status that come back — proving the full path host UDS →
//! libkrun bridge → guest vsock → minimald SSH (`run_on_vsock`, direct, no socat
//! relay) → session task exec. The `echo` task is serviced without a package
//! graph or sandbox, so the guest needs no network. Requires libkrun >= 1.19.0
//! on the host.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must point to
//!   the kernel, the GENERIC rootfs, and the minimald initramfs cpio (minimald
//!   boots as the initramfs `/init`; nothing is baked into the rootfs).

#![cfg(minvmd_libkrun)]

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

use serial_test::serial;
use tempfile::TempDir;

/// Isolated `XDG_STATE_HOME` under /tmp: macOS's $TMPDIR is deep enough that
/// `<tempdir>/minimal/providers/local-minvmd0/*.sock` would overflow sun_path (104).
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// The minvmd binary to boot: `MINVMD_BIN` when set — CI's split build/test
/// jobs run this harness on a different runner than the one that compiled it,
/// where the absolute path baked by `CARGO_BIN_EXE_minvmd` does not exist —
/// otherwise that compile-time cargo-built path.
fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

const BOOT_TIMEOUT: Duration = Duration::from_secs(15);

/// Env var the server reads to scope an exec to a session
/// (mirrors `minimald::MINIMAL_SESSION_ID_ENV`).
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so.
fn e2e_enabled() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("minimald_session_integration: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "minimald_session_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    true
}

/// A booted minimald guest VM, torn down on drop.
struct Guest {
    child: Child,
    sock_path: PathBuf,
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

        let exe = minvmd_bin();
        let mut child = Command::new(exe)
            .args(["boot", "--foreground"])
            // minimald boots as the initramfs `/init` (MINVMD_INITRAMFS, set by
            // the caller); the rootfs stays generic.
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
                "minimald_session_integration: no 'vm-up' within {} s; are \
                 MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH/MINVMD_INITRAMFS set correctly \
                 (and libkrun >= 1.19.0)?",
                BOOT_TIMEOUT.as_secs(),
            );
        }

        Guest {
            child,
            sock_path,
            _state: state,
        }
    }
}

// --- Full session: russh client → CreateSession → exec → stdout ---

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
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun >=1.19, kernel, rootfs, initramfs"]
async fn minimald_exec_over_bridge() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();
    let sentinel = "MINIMALD_SESSION_OK";
    // A task-only `minimal.toml` uploaded into the session workspace over
    // SFTP. `min run echo_ok` is serviced straight from this declaration —
    // no `[upstream]`, package graph, or sandbox — so the guest needs no
    // network and nothing baked into the rootfs beyond minimald itself.
    let mfile = format!("[tasks.echo_ok]\necho = \"{sentinel}\"\n");

    // Retry the whole session to absorb the post-READY startup race.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut result = Err("not attempted".to_string());
    for attempt in 1..=6 {
        result = run_session_exec(&guest.sock_path, Some(&mfile), "min run echo_ok").await;
        if result.is_ok() {
            break;
        }
        eprintln!("session attempt {attempt}: {result:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let (stdout, exit) = result.unwrap_or_else(|e| panic!("minimald_session_integration: {e}"));
    eprintln!("minimald_session_integration: exec stdout={stdout:?} exit={exit:?}");
    assert!(
        stdout.trim() == sentinel,
        "expected stdout {sentinel:?}, got {stdout:?}"
    );
    assert_eq!(exit, Some(0), "expected exit status 0, got {exit:?}");
}

/// Open a russh client over the bridge UDS, authenticate, create a session,
/// optionally upload a `minimal.toml` into its workspace over SFTP, then exec
/// `command` in it. Returns `(stdout, exit_status)`.
async fn run_session_exec(
    sock_path: &Path,
    mfile: Option<&str>,
    command: &str,
) -> Result<(String, Option<u32>), String> {
    use minimald_rpc::{CreateSession, CreateSessionRequest, OneshotSshRpc};
    use russh::ChannelMsg;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Connect (retry briefly in case the guest vsock listener is not yet up).
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
            .request_subsystem(false, CreateSession::NAME)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;

        // Unique name per invocation — minimald dedups sessions by
        // name, so the outer retry loop would otherwise collide on
        // `AlreadyExists` after any prior attempt persisted a record.
        // Matches the convention in `crates/minvmd/examples/exec.rs`.
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let req = CreateSessionRequest {
            config: minimald_rpc::SessionConfig {
                name: Some(format!("minvmd-e2e-{uniq:x}")),
                project_path: paths::HostAbsPath::try_new("/tmp")
                    .map_err(|e| format!("project_path: {e}"))?,
                network: sessions::NetworkMode::default(),
                policy: Default::default(),
                // The serde default, and what every non-`--no-hooks`
                // activation sends. This session only runs an exec, so
                // it declares no hooks either way.
                hooks_enabled: true,
                attrs: Default::default(),
            },
        };
        let body =
            serde_json_lenient::to_vec(&req).map_err(|e| format!("serialize request: {e}"))?;

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
            serde_json_lenient::from_slice(&resp_buf)
                .map_err(|e| format!("decode response: {e}"))?;
        resp.ok()
            .ok_or_else(|| "CreateSession returned an error".to_string())?
            .id
    };

    // Upload the project's `minimal.toml` into the session workspace over
    // SFTP (the subsystem presents the session's working tree at
    // `/workbench` and its home at `/home`, and reads the same session-id env
    // the exec path does).
    if let Some(contents) = mfile {
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
            .create("/workbench/minimal.toml")
            .await
            .map_err(|e| format!("sftp create minimal.toml: {e}"))?;
        file.write_all(contents.as_bytes())
            .await
            .map_err(|e| format!("sftp write minimal.toml: {e}"))?;
        file.shutdown()
            .await
            .map_err(|e| format!("sftp close minimal.toml: {e}"))?;
        sftp.close()
            .await
            .map_err(|e| format!("close sftp session: {e}"))?;
    }

    // ConfigureLoadout: compose the session's loadout now that its workspace
    // holds the project files, finalizing it `Pending → Active`. This is the
    // ordering the create flow is split for, and it has to happen before the
    // exec below — a session with an unconfigured loadout has no context to
    // resolve a task against.
    {
        use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, ConfigureLoadoutResponse};
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
        let body =
            serde_json_lenient::to_vec(&req).map_err(|e| format!("serialize request: {e}"))?;

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
        let resp: <ConfigureLoadout as OneshotSshRpc>::Response =
            serde_json_lenient::from_slice(&resp_buf)
                .map_err(|e| format!("decode response: {e}"))?;
        match resp.ok() {
            // The uploaded mfile declares only tasks, so nothing needs a
            // client gate and the loadout finalizes in one shot.
            Some(ConfigureLoadoutResponse::Materialized) => {}
            Some(ConfigureLoadoutResponse::Pending { .. }) => {
                return Err("ConfigureLoadout returned Pending; \
                            this test's mfile gates nothing"
                    .to_string());
            }
            None => return Err("ConfigureLoadout returned an error".to_string()),
        }
    }

    // FinalizeSession: promote the record `Materializing → Active` so the
    // exec below passes minimald's status gate. The task-only mfile yields an
    // empty composition, so there are no patches to upload first — but
    // FinalizeSession is still required: the daemon takes the
    // composition-has-no-patches shortcut past the patches-ready marker check
    // and writes the record `Active`. (See crates/minvmd/examples/exec.rs.)
    {
        use minimald_rpc::{FinalizeSession, FinalizeSessionRequest};
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open FinalizeSession channel: {e}"))?;
        channel
            .request_subsystem(false, FinalizeSession::NAME)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;

        let req = FinalizeSessionRequest { session_id };
        let body =
            serde_json_lenient::to_vec(&req).map_err(|e| format!("serialize request: {e}"))?;

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
        let resp: <FinalizeSession as OneshotSshRpc>::Response =
            serde_json_lenient::from_slice(&resp_buf)
                .map_err(|e| format!("decode response: {e}"))?;
        resp.ok()
            .ok_or_else(|| "FinalizeSession returned an error".to_string())?;
    }

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
