//! Session-index end-to-end test for Unit 3 (spec R3.4/R3.5).
//!
//! Boots a VM under the `run` supervisor with a fast poll interval, creates
//! and destroys sessions in the guest over the bridge UDS, and asserts the
//! host-side `session_index.json` tracks them — and that entries persist
//! across `minvmd stop` (the index maps sessions to volume images precisely
//! so a stopped VM's sessions stay routable).
//!
//! Gates match `boot_e2e.rs`: `#[cfg(minvmd_libkrun)]`, `#[ignore]`, and
//! `MINVMD_E2E=1` with `MINVMD_KERNEL_PATH`/`MINVMD_ROOTFS_PATH`/
//! `MINVMD_INITRAMFS` set.

#![cfg(minvmd_libkrun)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::{Duration, Instant};

use minimald_rpc::OneshotSshRpc;
use serial_test::serial;
use sessions::SessionId;

fn e2e_enabled(test: &str) -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("{test}: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "{test}: {var} must be set when MINVMD_E2E=1"
        );
    }
    true
}

/// Isolated per-test environment: a fresh state dir holding everything
/// (volume image, state file, locks, bridge socket, session index). Short
/// `/tmp` paths, matching `boot_e2e::short_state_dir` — the bridge UDS lives
/// inside the state dir and must fit `sun_path`.
struct TestEnv {
    _state: tempfile::TempDir,
    state_home: PathBuf,
}

impl TestEnv {
    fn new() -> Self {
        let state = tempfile::Builder::new()
            .prefix("mnl")
            .tempdir_in("/tmp")
            .expect("state tempdir");
        Self {
            state_home: state.path().to_path_buf(),
            _state: state,
        }
    }

    fn command(&self, args: &[&str]) -> Command {
        let bin =
            std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into());
        let mut cmd = Command::new(bin);
        // HOME too, not just XDG_STATE_HOME, as belt-and-braces: any
        // `dirs`-based fallback that ignores XDG on macOS must also land in
        // the tempdir, never the developer's real state dir.
        cmd.args(args)
            .env("HOME", &self.state_home)
            .env("XDG_STATE_HOME", &self.state_home);
        cmd
    }

    /// Everything lives in the provider-instance dir under the state base.
    fn provider_dir(&self) -> PathBuf {
        self.state_home.join("minimal/providers/local-0")
    }

    fn bridge_uds(&self) -> PathBuf {
        self.provider_dir().join("ssh.sock")
    }

    fn volume_path(&self) -> PathBuf {
        self.provider_dir().join("data-vol.raw")
    }

    fn session_index_path(&self) -> PathBuf {
        self.provider_dir().join("session_index.json")
    }
}

fn wait_until_running(env: &TestEnv, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let out = env
            .command(&["status", "--json"])
            .output()
            .expect("running minvmd status");
        if String::from_utf8_lossy(&out.stdout).contains("running") {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "VM did not reach Running within {timeout:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Read the on-disk index, empty when absent.
fn read_index(path: &Path) -> BTreeMap<SessionId, serde_json::Value> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).expect("session_index.json must parse"),
        Err(_) => BTreeMap::new(),
    }
}

/// Poll until `pred(index)` holds (or panic with the last state).
fn wait_for_index(
    path: &Path,
    what: &str,
    pred: impl Fn(&BTreeMap<SessionId, serde_json::Value>) -> bool,
) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let index = read_index(path);
        if pred(&index) {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "session index never became {what}; last state: {index:?}"
        );
        std::thread::sleep(Duration::from_millis(250));
    }
}

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

/// Minimal oneshot RPC over the bridge UDS (test-local twin of the client in
/// `minimal`/`minvmd`, which are not visible to integration tests).
async fn oneshot<R: OneshotSshRpc>(uds: &Path, request: R::Request<'_>) -> R::Response {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let stream = {
        let mut conn = None;
        for _ in 0..20 {
            match tokio::net::UnixStream::connect(uds).await {
                Ok(s) => {
                    conn = Some(s);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
        conn.expect("connect to bridge UDS")
    };
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(config, stream, AnyHostKey)
        .await
        .expect("ssh connect");
    assert!(
        handle
            .authenticate_none("session-index-e2e")
            .await
            .expect("authenticate")
            .success()
    );
    let channel = handle
        .channel_open_session()
        .await
        .expect("open rpc channel");
    channel
        .request_subsystem(false, R::NAME)
        .await
        .expect("request subsystem");
    let body = serde_json::to_vec(&request).expect("serialize request");
    let mut rpc = channel.into_stream();
    rpc.write_all(&body).await.expect("write request");
    rpc.shutdown().await.expect("shutdown write half");
    let mut resp = Vec::with_capacity(256);
    rpc.read_to_end(&mut resp).await.expect("read response");
    serde_json::from_slice(&resp).expect("decode response")
}

async fn create_session(uds: &Path, name: &str) -> SessionId {
    let req = minimald_rpc::CreateSessionRequest {
        config: minimald_rpc::SessionConfig {
            name: Some(name.to_string()),
            project_path: paths::HostAbsPath::try_new("/tmp").unwrap(),
            network: sessions::NetworkMode::default(),
            policy: Default::default(),
            attrs: Default::default(),
        },
        contribution: Default::default(),
    };
    match oneshot::<minimald_rpc::CreateSession>(uds, req)
        .await
        .ok()
        .expect("CreateSession errored")
    {
        minimald_rpc::CreateSessionResponse::Ready { id } => id,
        minimald_rpc::CreateSessionResponse::Pending { .. } => {
            panic!("CreateSession returned Pending; e2e only handles Ready")
        }
    }
}

/// Panic-safe teardown: stops the VM on drop, so a failed assertion after
/// `run --detach` never leaks a detached supervisor whose state dir the
/// `TempDir` then unlinks out from under it. Idempotent — the test's own
/// asserted `stop` leaves this a no-op. Declared after the [`TestEnv`] it
/// borrows, so it drops (and stops the VM) before the tempdirs go.
struct StopOnDrop<'a>(&'a TestEnv);

impl Drop for StopOnDrop<'_> {
    fn drop(&mut self) {
        let _ = self.0.command(&["stop"]).status();
    }
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun, kernel, rootfs, initramfs"]
fn session_index_tracks_lifecycle_and_survives_stop() {
    if !e2e_enabled("session_index_e2e") {
        return;
    }
    let env = TestEnv::new();

    let status = env
        .command(&["run", "--detach", "--timeout", "120"])
        .env("MINVMD_VOLUME_BYTES", "1073741824") // 1 GiB
        .env("MINVMD_SESSION_POLL_SECS", "1")
        .status()
        .expect("spawning minvmd run --detach");
    assert!(status.success(), "minvmd run --detach failed: {status}");
    let _teardown = StopOnDrop(&env);
    wait_until_running(&env, Duration::from_secs(60));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let uds = env.bridge_uds();
    let index_path = env.session_index_path();

    // Create → the poller records the session against this VM's image.
    let id_a = rt.block_on(create_session(&uds, "session-index-e2e-a"));
    wait_for_index(&index_path, "tracking session A", |idx| {
        idx.contains_key(&id_a)
    });
    let entry = &read_index(&index_path)[&id_a];
    assert_eq!(
        entry["image_path"],
        serde_json::json!(env.volume_path()),
        "entry must name this VM's volume image"
    );
    assert_eq!(entry["vm_id"], serde_json::json!("local-0"));

    // Destroy → the entry is removed.
    rt.block_on(async {
        oneshot::<minimald_rpc::DestroySession>(
            &uds,
            minimald_rpc::DestroySessionRequest { id: id_a },
        )
        .await
        .ok()
        .expect("DestroySession errored");
    });
    wait_for_index(&index_path, "cleared of session A", |idx| {
        !idx.contains_key(&id_a)
    });

    // A session live at stop time persists in the index: it still exists on
    // the volume image, and the mapping is what future routing needs.
    let id_b = rt.block_on(create_session(&uds, "session-index-e2e-b"));
    wait_for_index(&index_path, "tracking session B", |idx| {
        idx.contains_key(&id_b)
    });
    let status = env
        .command(&["stop"])
        .status()
        .expect("running minvmd stop");
    assert!(status.success(), "minvmd stop failed: {status}");
    assert!(
        read_index(&index_path).contains_key(&id_b),
        "index entry must survive VM stop"
    );
}
