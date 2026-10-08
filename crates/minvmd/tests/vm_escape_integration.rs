//! The root-in-VM spoofer's bound at the VM boundary (NET-085).
//!
//! The escape bound the architecture names: a process with root inside the VM
//! that spoofs another box's address reaches only destinations in the union of
//! resident boxes' declared egress plus the node-plane baseline set (design
//! §5.1). This test drives that spoofer's two paths at the VM boundary:
//!
//! - **On the guest's own interface.** A frame a box's relay is handed whose
//!   source is not the lease the relay was attached with never leaves the box
//!   — `egress::foreign_source` rejects it before any family or rule is
//!   consulted (NET-084), the property minimald's own suite pins
//!   (`relay_rejects_non_lease_source`). This test asserts the precondition a
//!   raw-socket route would need and does not have: a box's process holds
//!   neither `CAP_NET_RAW` nor `CAP_NET_ADMIN`, dropped from the bounding set
//!   the box is launched with (NET-083) — the one capability set an exec does
//!   not clear — so the box's own interface offers no route around the relay.
//!
//! - **On the shuttle port directly.** The guest shuttle's vsock port dials
//!   the host's egress gate socket, and the gate decides every frame it is
//!   handed by the source address the frame carries — it cannot tell a
//!   frame a vsock connection carried from one a host process wrote to the
//!   same socket. The test's spoofer is a host client that connects to the
//!   gate socket and speaks the shuttle's own protocol — the `/connect`
//!   upgrade head, then length-framed Ethernet frames — with a spoofed
//!   source address: byte-identical to what a root escapee's vsock
//!   connection carries past this edge.
//!
//! This tree offers no root-exec surface in the guest to spawn the escapee
//! from (session execs run in the box's sandbox, the guest daemon has no
//! arbitrary-exec RPC), so the test speaks for the escapee at the edges above
//! rather than pretending to exec it.
//!
//! **The shipped posture.** The host-side gate drops a frame whose source is
//! an address the plan could hand to a box but no published row holds — no
//! rules consulted, no phase gating the decision — because a lease the plan
//! could mint but no box holds is exactly the address a root escapee forges
//! (NET-085). So today a spoofed in-plan source never leaves the VM, and the
//! test says so. What holds at this branch:
//!
//! - an address **outside** the plan's lease block is refused outright
//!   (`egress-unknown-source`): outside the plan there is no lease to
//!   spoof — the rule-0 refusal;
//! - a **resident box's own** declared traffic reaches its declared
//!   destination — the positive controls, admitted by their own rows;
//! - a spoofed **in-plan** source no row holds is dropped under the gate's
//!   unregistered rule (`egress-unregistered-source`), toward every
//!   destination the baseline set's own included.
//!
//! Diagnostics: after the spoofs the test prints the host-side gate's own
//! lines for the spoofed sources (the drop lines), so the
//! bound can be read off the test output; observability: every spoofed
//! destination attempt is recorded with the verdict its arrival gave it.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must
//!   point to the kernel, the GENERIC rootfs, and the minimald initramfs.
//! - The gvproxy switch, from `common::gvproxy_bin`: `MINVMD_GVPROXY_BIN`
//!   when set, else under `MINVMD_E2E=1` the pinned binary fetched by
//!   `scripts/fetch-gvproxy.sh`, SHA-256-checked against
//!   `vendor/gvproxy/gvproxy.lock`. Without the switch minvmd boots the VM
//!   switchless and the bound's landing edge does not exist to test, so under
//!   `MINVMD_E2E=1` a switch that cannot be had fails the test; the skip is
//!   only for a run without `MINVMD_E2E=1`.
//!
//! The VM is brought up through the supervisor path (`minvmd run --detach`,
//! then `status --json` until Running, `stop` on drop): only `run` stands up
//! the switch and the gate before the VMM child boots. The boxes' project
//! file carries the pinned package source (`common::PKGS_UPSTREAM`), which
//! the guest daemon fetches over the switch as node-plane traffic when the
//! first exec launches a box; under `MINVMD_E2E=1` a failed fetch fails the
//! test, its exec's stderr naming why.

#![cfg(minvmd_libkrun)]

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serial_test::serial;
use sessions::core::decision::ItemDecision;
use sessions::core::hooks::{HookResult, PolicyHooks, Unapproved};
use sessions::core::policy::{HooksPolicy, PatchesPolicy, VarsPolicy};
use tempfile::TempDir;

mod common;

/// Isolated `XDG_STATE_HOME` under /tmp: macOS's $TMPDIR is deep enough that
/// `<tempdir>/minimal/providers/local-minvmd0/*.sock` would overflow sun_path.
fn short_state_dir() -> TempDir {
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

/// `run --detach --timeout`: a cold multi-GiB VM can run 40–70 s before
/// pid-1 starts (the AGENTS.md boot footgun), so this waits the justfile's
/// 150 s.
const DETACH_TIMEOUT_SECS: &str = "150";
/// How long `status --json` may take to report Running after `run --detach`
/// returns (it returns once the bridge UDS accepts, slightly ahead of the
/// Starting -> Running write).
const RUNNING_TIMEOUT: Duration = Duration::from_secs(90);
/// Bound on any one `minvmd` subcommand (`run --detach`, `status`, `stop`) so
/// a wedged daemon fails the test instead of hanging it.
const SUBPROC_TIMEOUT: Duration = Duration::from_secs(180);
/// How long a gate line may take to reach the supervisor's log file, which
/// a non-blocking writer fills behind the gate.
const LOG_DEADLINE: Duration = Duration::from_secs(5);
/// How long a flow expected to be dropped is waited for before its silence is
/// read as the verdict. The gate decides before any frame leaves the VM, so
/// the silence is available well within this.
const DROP_DEADLINE: Duration = Duration::from_secs(3);
/// The env var the guest scopes an exec to a session with.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";
/// The `/connect` upgrade head the guest shuttle speaks to the switch, and
/// the gate reads as the frame stream's opening: mirrors
/// `egress_gate::CONNECT_REQUEST` (crate-private there), and the gate refuses
/// any head it does not classify as the frame stream.
const GATE_SHUTTLE_HEAD: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// The gvproxy switch to boot with when the e2e suite is enabled
/// (`MINVMD_E2E=1`), asserting the required env vars are present when so;
/// `None` when the suite skips.
fn e2e_enabled() -> Option<PathBuf> {
    if !common::e2e() {
        common::skip_or_fail("vm_escape_integration", "MINVMD_E2E != 1");
        return None;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "vm_escape_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    // The switch is the gate's far end: without it the VM boots switchless and
    // there is no egress for anything — declared, spoofed, or otherwise — to
    // reach. Under MINVMD_E2E=1 the helper fetches the pinned switch or panics.
    let gvproxy = common::gvproxy_bin();
    if gvproxy.is_none() {
        common::skip_or_fail(
            "vm_escape_integration",
            "no gvproxy switch, so no egress gate to test the bound at",
        );
    }
    gvproxy
}

/// A booted minimald guest VM under a detached supervisor, stopped on drop.
struct Guest {
    sock_path: PathBuf,
    gate_sock: PathBuf,
    /// The VM host daemon's box control socket, where each box is registered
    /// before its session is created, as `min session activate` does.
    control_sock: PathBuf,
    gvproxy: PathBuf,
    /// The VMM child's pid from `status --json`, killed directly when
    /// `minvmd stop` fails.
    vmm_pid: Option<u32>,
    _state: TempDir,
}

impl Drop for Guest {
    fn drop(&mut self) {
        // Teardown that never panics (it may run while a failed assertion
        // unwinds) and never leaks: a failed assertion must not leave the
        // detached supervisor, its VMM child, or its switch running. Bounded,
        // so a wedged daemon cannot hang the teardown either; when `stop`
        // fails, the recorded VMM is killed, and the supervisor exits with it.
        let stopped = match try_minvmd(self._state.path(), &self.gvproxy, &["stop"]) {
            Ok(out) if out.status.success() => return,
            Ok(out) => format!(
                "exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => e,
        };
        eprintln!("vm_escape_integration: minvmd stop failed ({stopped})");
        if let Some(pid) = self.vmm_pid.and_then(|p| libc::pid_t::try_from(p).ok()) {
            eprintln!("vm_escape_integration: killing VMM pid {pid}");
            // SAFETY: kill only sends a signal to the pid `status` reported.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
    }
}

/// Run one `minvmd` subcommand against the isolated state dir, bounded by
/// [`SUBPROC_TIMEOUT`]; panics when it cannot be run or does not exit.
fn minvmd(state: &Path, gvproxy: &Path, args: &[&str]) -> Output {
    try_minvmd(state, gvproxy, args).unwrap_or_else(|e| {
        #[expect(clippy::panic, reason = "a subcommand that cannot run fails the test")]
        {
            panic!("vm_escape_integration: {e}")
        }
    })
}

/// [`minvmd`] without the panic. The env the VM needs (`MINVMD_VM_OWN_IP`,
/// `MINVMD_GVPROXY_BIN`, `MINVMD_READY_TIMEOUT_SECS`) is inherited by the
/// detached supervisor and its VMM child, so it is set on every call. stdin
/// is off the terminal, or libkrun's console setup stops the process group.
/// stdout and stderr are drained on reader threads while the child runs, so
/// a chatty child cannot fill a pipe and stall into the timeout.
#[expect(
    clippy::let_underscore_must_use,
    reason = "a wedged subcommand is killed and reaped best-effort"
)]
fn try_minvmd(state: &Path, gvproxy: &Path, args: &[&str]) -> Result<Output, String> {
    let mut child = Command::new(minvmd_bin())
        .args(args)
        // HOME too, not just XDG_STATE_HOME: any `dirs`-based fallback that
        // ignores XDG on macOS must also land in the tempdir.
        .env("HOME", state)
        .env("XDG_STATE_HOME", state)
        .env("MINVMD_VM_OWN_IP", "1")
        .env("MINVMD_GVPROXY_BIN", gvproxy)
        // `--timeout` bounds only `run --detach`'s own poll; the supervisor's
        // READY wait reads this (60 s by default), and a cold boot can
        // outrun that, so give it the same budget.
        .env("MINVMD_READY_TIMEOUT_SECS", DETACH_TIMEOUT_SECS)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning minvmd {args:?}: {e}"))?;
    let drain = |pipe: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut pipe) = pipe {
                let _ = pipe.read_to_end(&mut buf);
            }
            buf
        })
    };
    let stdout = drain(
        child
            .stdout
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let stderr = drain(
        child
            .stderr
            .take()
            .map(|p| Box::new(p) as Box<dyn Read + Send>),
    );
    let deadline = Instant::now() + SUBPROC_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "minvmd {args:?} did not exit within {SUBPROC_TIMEOUT:?} (wedged daemon?)"
                ));
            }
            Err(e) => return Err(format!("polling minvmd {args:?}: {e}")),
        }
    };
    Ok(Output {
        status,
        stdout: stdout.join().unwrap_or_default(),
        stderr: stderr.join().unwrap_or_default(),
    })
}

/// Renders one JSON log record as `key=value` pairs, nested objects
/// flattened, so the gate's fields read as they do on a console
/// (`source=100.64.0.99 rule_matched=egress-unknown-source`).
fn render_record(value: &serde_json_lenient::Value, out: &mut String) {
    if let serde_json_lenient::Value::Object(map) = value {
        for (key, value) in map {
            match value {
                serde_json_lenient::Value::Object(_) => render_record(value, out),
                serde_json_lenient::Value::String(text) => {
                    out.push_str(&format!("{key}={text} "));
                }
                other => out.push_str(&format!("{key}={other} ")),
            }
        }
    }
}

impl Guest {
    /// Boots the supervised VM with minimald as the guest init (`minvmd run
    /// --detach`, which stands up the host gvproxy switch and the egress gate
    /// before the VMM child boots) and polls `status --json` until Running.
    /// Panics past the deadlines, quoting the supervisor's `run.log`.
    fn boot(gvproxy: &Path) -> Guest {
        let state = short_state_dir();
        let provider_dir = state.path().join("minimal/providers/local-minvmd0");
        let guest = Guest {
            sock_path: provider_dir.join("ssh.sock"),
            // The gate binds the socket beside the switch socket, which sits
            // beside the bridge socket.
            gate_sock: provider_dir.join("gvproxy-gate.sock"),
            control_sock: provider_dir.join(minvmd::control::CONTROL_SOCK_FILE),
            gvproxy: gvproxy.to_path_buf(),
            vmm_pid: None,
            _state: state,
        };
        let run = guest.minvmd(&["run", "--detach", "--timeout", DETACH_TIMEOUT_SECS]);
        assert!(
            run.status.success(),
            "vm_escape_integration: minvmd run --detach failed: {}\n--- run.log ---\n{}\n\
             are MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH/MINVMD_INITRAMFS set correctly \
             (and libkrun >= 1.19.0)?",
            String::from_utf8_lossy(&run.stderr),
            guest.run_log(),
        );
        let mut guest = guest;
        let deadline = Instant::now() + RUNNING_TIMEOUT;
        loop {
            let status = guest.minvmd(&["status", "--json"]);
            let status: serde_json_lenient::Value = serde_json_lenient::from_slice(&status.stdout)
                .unwrap_or(serde_json_lenient::Value::Null);
            let vmm_pid = status
                .get("vmm_pid")
                .and_then(serde_json_lenient::Value::as_u64)
                .and_then(|p| u32::try_from(p).ok());
            if vmm_pid.is_some() {
                // Recorded before Running too, so a boot that never gets
                // there is still torn down.
                guest.vmm_pid = vmm_pid;
            }
            if status.get("state").is_some_and(|s| s == "running") && vmm_pid.is_some() {
                return guest;
            }
            assert!(
                Instant::now() < deadline,
                "vm_escape_integration: VM never reached Running within {RUNNING_TIMEOUT:?}; \
                 last status: {status}\n--- run.log ---\n{}",
                guest.run_log(),
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn minvmd(&self, args: &[&str]) -> Output {
        minvmd(self._state.path(), &self.gvproxy, args)
    }

    /// The detached supervisor's stderr (boot-failure diagnosis), for panics.
    fn run_log(&self) -> String {
        let path = self
            ._state
            .path()
            .join("minimal/providers/local-minvmd0/run.log");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| format!("(no run.log at {}: {e})", path.display()))
    }

    /// The supervisor's tracing so far — where the host-side gate's drop
    /// lines land — one rendered record per line. A detached
    /// supervisor writes JSON records to `<state>/minimal/logs/minvmd.log.*`.
    fn log(&self) -> String {
        let dir = self._state.path().join("minimal/logs");
        let mut text = String::new();
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            if !entry
                .file_name()
                .to_string_lossy()
                .starts_with("minvmd.log")
            {
                continue;
            }
            let contents = std::fs::read_to_string(entry.path()).unwrap_or_default();
            for line in contents.lines() {
                match serde_json_lenient::from_str(line) {
                    Ok(record) => render_record(&record, &mut text),
                    Err(_) => text.push_str(line),
                }
                text.push('\n');
            }
        }
        text
    }

    /// Whether `needle` appears in the supervisor's log within
    /// [`LOG_DEADLINE`].
    fn log_contains(&self, needle: &str) -> bool {
        let end = Instant::now() + LOG_DEADLINE;
        loop {
            if self.log().contains(needle) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The supervisor's log lines that carry any of `needles` — the gate's own
    /// lines for the spoofed sources, as the test leaves them.
    fn log_lines(&self, needles: &[&str]) -> Vec<String> {
        self.log()
            .lines()
            .filter(|line| needles.iter().any(|needle| line.contains(needle)))
            .map(std::string::ToString::to_string)
            .collect()
    }
}

// --- resident boxes: a session per box, over the SSH bridge ---

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

/// One resident box: a session the guest daemon launched in its own network
/// namespace on the switch, whose declared egress this test set at creation.
/// The SSH handle is kept open for the box's lifetime; every exec joins the
/// session's sandbox (the box), so the box's first exec is the one that
/// attaches its tap and relay.
struct BoxSession {
    handle: russh::client::Handle<ClientHandler>,
    /// The session record's id: scoping the execs' env and naming the box.
    session_id: String,
}

impl BoxSession {
    /// Opens one resident box: creates the session over the bridge UDS with
    /// `network` and the declared egress policy, uploads a `minimal.toml`
    /// carrying the pinned package source over SFTP, composes the loadout
    /// (gating whatever comes back pending), finalizes the record, and keeps
    /// the handle for execs.
    async fn open(
        sock_path: &Path,
        control_sock: &Path,
        network: sessions::NetworkMode,
        egress: sessions::EgressPolicy,
        label: &str,
    ) -> Result<BoxSession, String> {
        use minimald_rpc::{
            ConfigureLoadout, ConfigureLoadoutRequest, ConfigureLoadoutResponse, CreateSession,
            CreateSessionRequest, FinalizeSession, FinalizeSessionRequest, OneshotSshRpc,
        };
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        // Connect (retry briefly in case the guest vsock listener is not yet
        // up past the READY line).
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

        // CreateSession with the declared egress: the box's policy as the
        // session record carries it, which the box's own relay enforces
        // in-guest (NET-084) and which its registration with the VM host
        // files as the host-side row the egress gate decides the box's
        // frames by.
        let session_id = {
            let channel = handle
                .channel_open_session()
                .await
                .map_err(|e| format!("open CreateSession channel: {e}"))?;
            channel
                .request_subsystem(false, CreateSession::NAME)
                .await
                .map_err(|e| format!("request_subsystem: {e}"))?;

            let policy = sessions::SessionPolicy {
                egress: Some(egress.clone()),
                ..Default::default()
            };
            // Unique per invocation — minimald dedups sessions by name and
            // rejects a duplicate CreateSession (`AlreadyExists`), and a
            // record persists once created even when a later step of this
            // open fails, so the outer retry loop in `open_box` would
            // otherwise collide on a fixed name after any prior attempt got
            // as far as CreateSession. Matches the convention in
            // `crates/minvmd/tests/minimald_session_integration.rs`.
            let uniq = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            let name = format!("vm-escape-{label}-{uniq:x}");
            // The box's row, filed with the VM host the way `min session
            // activate` files it: a box with no row is an unregistered
            // source the gate drops unconditionally (NET-085), so a box
            // whose own declared traffic is a positive control must hold one.
            let addresses = common::register_box(control_sock, &name, Some(egress))?;
            let req = CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some(name),
                    project_path: paths::HostAbsPath::try_new("/tmp")
                        .map_err(|e| format!("project_path: {e}"))?,
                    network,
                    policy,
                    // The addresses the registration handed back, so the
                    // in-VM daemon attaches the box at its row's lease.
                    task_addresses: Vec::new(),
                    box_addresses: Some(addresses),
                    // The serde default, and what every non-`--no-hooks`
                    // activation sends. This session only runs execs, so it
                    // declares no hooks either way.
                    hooks_enabled: true,
                    attrs: Default::default(),
                },
                must_match_version: None,
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

        // The project's `minimal.toml` over SFTP. Its `[upstream]` is the
        // package graph the box's sandbox resolves its baseline packages
        // (`base`, `coreutils`, `socat`, `bash`) against when the first exec
        // launches it; without one the box cannot launch at all.
        {
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
            let mut file = sftp
                .create("/workbench/minimal.toml")
                .await
                .map_err(|e| format!("sftp create minimal.toml: {e}"))?;
            let contents = common::PKGS_UPSTREAM;
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

        // ConfigureLoadout, then FinalizeSession: the record `Materializing →
        // Active`, so the execs below pass the daemon's status gate — the
        // ordering the session harness proves (crates/minvmd/tests/
        // minimald_session_integration.rs).
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
                Some(ConfigureLoadoutResponse::Materialized) => {}
                Some(ConfigureLoadoutResponse::Pending { response }) => {
                    submit_verdict(&mut handle, response).await?;
                }
                None => return Err("ConfigureLoadout returned an error".to_string()),
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
            let req = FinalizeSessionRequest {
                session_id,
                report_shared_port_collisions: false,
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
            let resp: <FinalizeSession as OneshotSshRpc>::Response =
                serde_json_lenient::from_slice(&resp_buf)
                    .map_err(|e| format!("decode response: {e}"))?;
            resp.ok()
                .ok_or_else(|| "FinalizeSession returned an error".to_string())?;
        }

        Ok(BoxSession {
            handle,
            session_id: session_id.to_string(),
        })
    }

    /// Runs one command in the box — the session's sandbox — and returns
    /// `(stdout, stderr, exit_status)`. The daemon reports a box that cannot
    /// launch on stderr, so a nonzero exit's message carries its cause.
    async fn exec(&mut self, command: &str) -> Result<(String, String, Option<u32>), String> {
        use russh::ChannelMsg;

        let mut channel = self
            .handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open exec channel: {e}"))?;
        channel
            .set_env(true, MINIMAL_SESSION_ID_ENV, self.session_id.clone())
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
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
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
}

/// Client-side gate for the pending items `ConfigureLoadout` routes back,
/// answering the way the CLI's `--no-prompt` hook does for vars (allow once)
/// and failing the test, naming the items, on any patch or hook: a box here
/// declares none, and this harness cannot upload a patch's host file.
struct NoPromptVars;

impl PolicyHooks for NoPromptVars {
    fn on_var_unapproved(
        &self,
        _policy: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        HookResult::decided(vec![ItemDecision::AllowOnce; items.len()])
    }

    fn on_patch_unapproved(
        &self,
        _policy: PatchesPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<PatchesPolicy> {
        refuse_unexpected("patch", items)
    }

    fn on_hook_unapproved(
        &self,
        _policy: HooksPolicy,
        items: &[Unapproved<'_, camino::Utf8Path>],
    ) -> HookResult<HooksPolicy> {
        refuse_unexpected("hook", items)
    }
}

/// Fails the test naming every item in a domain the harness expects empty.
#[expect(clippy::panic, reason = "an unexpected pending item fails the test")]
fn refuse_unexpected<T, P>(domain: &str, items: &[Unapproved<'_, T>]) -> HookResult<P>
where
    T: ?Sized + std::fmt::Display,
{
    let named: Vec<String> = items
        .iter()
        .map(|item| format!("`{}` from {}", item.item(), item.source()))
        .collect();
    panic!(
        "vm_escape_integration: unexpected pending {domain}(s): {}",
        named.join(", ")
    );
}

/// Gates a `Pending` `ConfigureLoadout` response with [`NoPromptVars`] and
/// ships the verdict with `SubmitVerdict`, which composes the loadout.
async fn submit_verdict(
    handle: &mut russh::client::Handle<ClientHandler>,
    response: sessions::wire::request::ContributionResponse,
) -> Result<(), String> {
    use minimald_rpc::{OneshotSshRpc, SubmitVerdict};
    use sessions::wire::request::SessionStep;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    eprintln!(
        "vm_escape_integration: ConfigureLoadout pending: {} vars, {} patches, {} hooks",
        response.vars.len(),
        response.patches.len(),
        response.lifecycle_hooks.len(),
    );
    let (verdict, _policy) = sessions::client::handler::handle_response(
        response,
        &[],
        sessions::core::policy::UserPolicy::empty(),
        &NoPromptVars,
        sessions::core::compose::ComposeOptions::default(),
        &|name| std::env::var(name),
    )
    .map_err(|e| format!("gating pending items: {e}"))?;

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open SubmitVerdict channel: {e}"))?;
    channel
        .request_subsystem(false, SubmitVerdict::NAME)
        .await
        .map_err(|e| format!("request_subsystem: {e}"))?;
    let body =
        serde_json_lenient::to_vec(&verdict).map_err(|e| format!("serialize verdict: {e}"))?;
    let mut rpc = channel.into_stream();
    rpc.write_all(&body)
        .await
        .map_err(|e| format!("write verdict: {e}"))?;
    rpc.shutdown()
        .await
        .map_err(|e| format!("shutdown write half: {e}"))?;
    let mut buf = Vec::new();
    rpc.read_to_end(&mut buf)
        .await
        .map_err(|e| format!("read SubmitVerdict response: {e}"))?;
    let resp: <SubmitVerdict as OneshotSshRpc>::Response = serde_json_lenient::from_slice(&buf)
        .map_err(|e| format!("decode SubmitVerdict response: {e}"))?;
    match resp.ok() {
        Some(SessionStep::Materialized { .. }) => Ok(()),
        Some(SessionStep::Fault { error }) => Err(format!("SubmitVerdict faulted: {error:?}")),
        None => Err("SubmitVerdict returned an error".into()),
    }
}

/// Opens one resident box, retrying the whole open to absorb the post-READY
/// startup race the session harness documents.
async fn open_box(
    guest: &Guest,
    network: sessions::NetworkMode,
    egress: sessions::EgressPolicy,
    label: &str,
) -> BoxSession {
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut last = "not attempted".to_string();
    for attempt in 1..=6 {
        match BoxSession::open(
            &guest.sock_path,
            &guest.control_sock,
            network,
            egress.clone(),
            label,
        )
        .await
        {
            Ok(session) => return session,
            Err(e) => {
                last = e;
                eprintln!("vm_escape_integration: box {label} open attempt {attempt}: {last}");
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    panic!("vm_escape_integration: could not open box {label}: {last}");
}

// --- the spoofer's voice at the gate's landing edge ---

/// One spoofed flow the test drives at the gate socket: the source address it
/// wears and the Ethernet source MAC it announces that address from, the
/// destination it tries to reach, and the marker whose arrival at the host
/// listener is the verdict the flow records.
struct SpoofedFlow {
    src: Ipv4Addr,
    src_mac: [u8; 6],
    dst: Ipv4Addr,
    dst_port: u16,
    src_port: u16,
    marker: String,
}

const TCP_SYN: u8 = 0x02;
const TCP_PSH: u8 = 0x08;
const TCP_ACK: u8 = 0x10;
/// The spoofed flow's initial sequence number. The SYN carries it; the ACK
/// and the marker's push go out at the next sequence number, and the switch
/// acknowledges the marker at that number plus the marker's length — one
/// constant, so the push and the acknowledgement the flow waits for cannot
/// drift apart.
const SPOOF_ISN: u32 = 0x0050_1001;
/// How often the flow resends the marker's push while it waits for the
/// switch to acknowledge it.
const SPOOF_RESEND: Duration = Duration::from_millis(500);
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_ARP: [u8; 2] = [0x08, 0x06];
const ARP_REQUEST: u16 = 1;
const ARP_REPLY: u16 = 2;

/// An Ethernet+IPv4+TCP frame with real checksums: the host switch is the
/// real gvproxy here, whose stack validates the IPv4 and TCP checksums —
/// unlike the in-crate gate tests, whose frame builder leaves them zero
/// because the gate and the summarizer never read them.
#[allow(
    clippy::too_many_arguments,
    reason = "every field names one header field the frame carries; a struct \
              would repeat the flow's own fields"
)]
fn tcp_frame(
    src_mac: [u8; 6],
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    // TCP header: ports, sequence, acknowledge, offset (20 bytes), flags,
    // window, checksum (filled below), urgent.
    let mut tcp = Vec::with_capacity(20 + payload.len());
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.extend_from_slice(&[0x50, flags]);
    tcp.extend_from_slice(&0xFFFFu16.to_be_bytes());
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(&[0, 0]);
    tcp.extend_from_slice(payload);
    let tcp_checksum = tcp_checksum(src_ip, dst_ip, &tcp);
    tcp[16..18].copy_from_slice(&tcp_checksum.to_be_bytes());

    // IPv4 header: version 4, IHL 5, no options, total length, checksum.
    let total_len = (20 + tcp.len()) as u16;
    let mut ip = Vec::with_capacity(20);
    ip.extend_from_slice(&[0x45, 0x00]);
    ip.extend_from_slice(&total_len.to_be_bytes());
    ip.extend_from_slice(&[0x00, 0x01]); // id
    ip.extend_from_slice(&[0x00, 0x00]); // no fragment flags
    ip.push(64); // ttl
    ip.push(6); // proto TCP
    ip.extend_from_slice(&[0, 0]); // checksum, filled below
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let ip_checksum = ipv4_checksum(&ip);
    ip[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let mut frame = Vec::with_capacity(14 + ip.len());
    // Destination MAC: the gateway's, the address the switch answers from and
    // the one every egress frame to the fabric is addressed to.
    frame.extend_from_slice(&switch::GATEWAY_MAC.0);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV4);
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&tcp);
    frame
}

/// An ARP reply claiming `claimed` for `my_mac`, addressed to the MAC that
/// asked: the answer a root spoofer gives the switch's neighbor resolution
/// for the address it wears.
fn arp_reply(
    requester_mac: [u8; 6],
    claimed: Ipv4Addr,
    requester_ip: Ipv4Addr,
    my_mac: [u8; 6],
) -> Vec<u8> {
    let mut arp = Vec::with_capacity(28);
    arp.extend_from_slice(&1u16.to_be_bytes()); // htype: ethernet
    arp.extend_from_slice(&ETHERTYPE_IPV4); // ptype
    arp.push(6); // hlen
    arp.push(4); // plen
    arp.extend_from_slice(&ARP_REPLY.to_be_bytes());
    arp.extend_from_slice(&my_mac);
    arp.extend_from_slice(&claimed.octets());
    arp.extend_from_slice(&requester_mac);
    arp.extend_from_slice(&requester_ip.octets());

    let mut frame = Vec::with_capacity(14 + arp.len());
    frame.extend_from_slice(&requester_mac);
    frame.extend_from_slice(&my_mac);
    frame.extend_from_slice(&ETHERTYPE_ARP);
    frame.extend_from_slice(&arp);
    frame
}

/// The IPv4 header checksum: one's-complement sum over the header as
/// big-endian words, folded, complemented.
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in header.chunks(2) {
        let word = match pair {
            [a, b] => u16::from_be_bytes([*a, *b]),
            [a] => u16::from_be_bytes([*a, 0]),
            _ => unreachable!("chunks(2) yields slices of one or two bytes"),
        };
        sum += u32::from(word);
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// The TCP checksum over the pseudo-header the IPv4 layer spells: source,
/// destination, protocol, TCP length, then the TCP segment. A computed zero
/// is a valid TCP checksum (the all-ones rewrite is UDP's rule), and this
/// wire never rewrites one.
fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut words: Vec<u16> = Vec::with_capacity(6 + tcp.len() / 2 + 1);
    for word in src.octets().chunks(2) {
        words.push(u16::from_be_bytes([word[0], word[1]]));
    }
    for word in dst.octets().chunks(2) {
        words.push(u16::from_be_bytes([word[0], word[1]]));
    }
    words.push(6); // proto TCP
    let tcp_len = tcp.len() as u16;
    words.push(tcp_len);
    let mut bytes = tcp.to_vec();
    if bytes.len() % 2 == 1 {
        bytes.push(0);
    }
    for pair in bytes.chunks(2) {
        words.push(u16::from_be_bytes([pair[0], pair[1]]));
    }
    let mut sum = 0u32;
    for word in words {
        sum += u32::from(word);
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// One length-framed frame to the gate: the shuttle's own framing, a
/// little-endian `u16` length and the raw frame, the form the gate reads
/// (`relay_frames_to_switch`) and the guest relay writes.
fn write_frame(sock: &mut UnixStream, frame: &[u8]) -> Result<(), String> {
    let mut framed = Vec::with_capacity(2 + frame.len());
    let len = u16::try_from(frame.len()).map_err(|_| "frame too long for the shuttle framing")?;
    framed.extend_from_slice(&len.to_le_bytes());
    framed.extend_from_slice(frame);
    sock.write_all(&framed)
        .map_err(|e| format!("write frame: {e}"))
}

/// Reads one length-framed frame, or `None` when the deadline passed first.
/// A read that times out mid-frame is retried within the deadline — the
/// deadline is the frame's, not the chunk's.
fn read_frame(sock: &mut UnixStream, deadline: Instant) -> Result<Option<Vec<u8>>, String> {
    let mut len_buf = [0u8; 2];
    if !read_exact_until(sock, &mut len_buf, deadline)? {
        return Ok(None);
    }
    let n = u16::from_le_bytes(len_buf) as usize;
    if n == 0 {
        // The gate skips zero-length claims; so does this reader.
        return Ok(Some(Vec::new()));
    }
    let mut frame = vec![0u8; n];
    if !read_exact_until(sock, &mut frame, deadline)? {
        return Ok(None);
    }
    Ok(Some(frame))
}

/// Reads exactly `buf.len()` bytes, retrying timeouts within the deadline.
fn read_exact_until(
    sock: &mut UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<bool, String> {
    let mut off = 0;
    while off < buf.len() {
        if Instant::now() >= deadline {
            return Ok(false);
        }
        match sock.read(&mut buf[off..]) {
            Ok(0) => return Err("the gate closed the connection".to_string()),
            Ok(n) => off += n,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => return Err(format!("read: {e}")),
        }
    }
    Ok(true)
}

/// What one frame off the gate is to the spoofed flow: the ARP request for
/// the address the flow wears, the SYN-ACK answering the flow's SYN, a bare
/// ACK on the flow's connection, or nothing the flow cares about.
enum Incoming {
    /// `(requester MAC, requester IP, requested IP)`: an ARP request the flow
    /// answers when it names the address the flow wears.
    ArpRequest([u8; 6], Ipv4Addr, Ipv4Addr),
    /// The SYN-ACK's sequence number: the handshake's second leg arrived.
    SynAck(u32),
    /// A bare ACK's acknowledgement number, in the flow's own sequence space.
    Ack(u32),
}

fn classify(frame: &[u8], flow: &SpoofedFlow) -> Option<Incoming> {
    if frame.len() < 14 {
        return None;
    }
    let ethertype = [frame[12], frame[13]];
    if ethertype == ETHERTYPE_ARP && frame.len() >= 42 {
        let oper = u16::from_be_bytes([frame[20], frame[21]]);
        if oper != ARP_REQUEST {
            return None;
        }
        let mut requester_mac = [0u8; 6];
        requester_mac.copy_from_slice(&frame[22..28]);
        let requester_ip = Ipv4Addr::new(frame[28], frame[29], frame[30], frame[31]);
        let requested_ip = Ipv4Addr::new(frame[38], frame[39], frame[40], frame[41]);
        return Some(Incoming::ArpRequest(
            requester_mac,
            requester_ip,
            requested_ip,
        ));
    }
    if ethertype != ETHERTYPE_IPV4 || frame.len() < 14 + 20 {
        return None;
    }
    let ihl = usize::from(frame[14] & 0x0F) * 4;
    let l4 = 14 + ihl;
    if frame.len() < l4 + 20 {
        return None;
    }
    if frame[14 + 9] != 6 {
        return None; // not TCP
    }
    let dst = Ipv4Addr::new(
        frame[14 + 16],
        frame[14 + 17],
        frame[14 + 18],
        frame[14 + 19],
    );
    if dst != flow.src {
        return None; // a reply to some other address — not this flow's
    }
    let dst_port = u16::from_be_bytes([frame[l4 + 2], frame[l4 + 3]]);
    if dst_port != flow.src_port {
        return None;
    }
    let flags = frame[l4 + 13];
    if flags & TCP_ACK == 0 {
        return None;
    }
    if flags & TCP_SYN != 0 {
        let synack_seq =
            u32::from_be_bytes([frame[l4 + 4], frame[l4 + 5], frame[l4 + 6], frame[l4 + 7]]);
        return Some(Incoming::SynAck(synack_seq));
    }
    let src_port = u16::from_be_bytes([frame[l4], frame[l4 + 1]]);
    if src_port != flow.dst_port {
        return None;
    }
    let ack = u32::from_be_bytes([frame[l4 + 8], frame[l4 + 9], frame[l4 + 10], frame[l4 + 11]]);
    Some(Incoming::Ack(ack))
}

/// Whether the switch acknowledged every byte of the marker's push.
enum MarkerAck {
    Acked,
    /// Why not: no acknowledgement within the deadline, or the gate
    /// connection failed while the flow waited for one.
    NotAcked(String),
}

impl std::fmt::Display for MarkerAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Acked => f.write_str("the switch acknowledged every byte of the marker"),
            Self::NotAcked(why) => write!(f, "the switch never acknowledged the marker ({why})"),
        }
    }
}

/// `seq` is at or past `target` in TCP's wrapping sequence space.
fn seq_at_or_past(seq: u32, target: u32) -> bool {
    seq.wrapping_sub(target) < 0x8000_0000
}

/// Holds the flow open after the marker's push until the switch acknowledges
/// all of it, resending the push every [`SPOOF_RESEND`] — what any TCP sender
/// does. Returning on the push and dropping the socket instead lost the
/// marker to any frame lost in the relay's or the switch's teardown of the
/// connection, with nothing to say where. The answer splits the two: a marker
/// acknowledged but never at the listener was lost past the switch's stack;
/// one never acknowledged was lost before it.
fn await_marker_ack(
    sock: &mut UnixStream,
    flow: &SpoofedFlow,
    push: &[u8],
    deadline: Duration,
) -> MarkerAck {
    let Ok(marker_len) = u32::try_from(flow.marker.len()) else {
        return MarkerAck::NotAcked("the marker is longer than a sequence space".to_string());
    };
    let want = SPOOF_ISN.wrapping_add(1).wrapping_add(marker_len);
    let end = Instant::now() + deadline;
    let mut next_resend = Instant::now() + SPOOF_RESEND;
    loop {
        let now = Instant::now();
        if now >= end {
            return MarkerAck::NotAcked(format!("no acknowledgement within {deadline:?}"));
        }
        if now >= next_resend {
            if let Err(e) = write_frame(sock, push) {
                return MarkerAck::NotAcked(format!("resending the push failed: {e}"));
            }
            next_resend = now + SPOOF_RESEND;
        }
        let frame = match read_frame(sock, next_resend.min(end)) {
            Ok(Some(frame)) => frame,
            Ok(None) => continue,
            Err(e) => return MarkerAck::NotAcked(e),
        };
        match classify(&frame, flow) {
            Some(Incoming::Ack(ack)) if seq_at_or_past(ack, want) => return MarkerAck::Acked,
            // The switch may resolve the flow's address again before its
            // acknowledgement can leave; the claim still has to answer.
            Some(Incoming::ArpRequest(requester_mac, requester_ip, requested_ip))
                if requested_ip == flow.src =>
            {
                let reply = arp_reply(requester_mac, flow.src, requester_ip, flow.src_mac);
                if let Err(e) = write_frame(sock, &reply) {
                    return MarkerAck::NotAcked(format!("writing the ARP answer failed: {e}"));
                }
            }
            _ => {}
        }
    }
}

/// Drives one spoofed flow at the gate's landing edge: the `/connect` upgrade
/// head, a SYN wearing the flow's source, the ARP answer claiming that source
/// for the flow's MAC (both the pre-emptive claim and the answer to whatever
/// request the switch's neighbor resolution sends), and on the SYN-ACK the
/// ACK and the marker-carrying push, held open until the switch acknowledges
/// the marker ([`await_marker_ack`]). `Ok` is the handshake completing,
/// carrying whether the marker was acknowledged; whether the marker then
/// reaches the host listener is the caller's record.
fn spoofed_flow(
    gate_sock: &Path,
    flow: &SpoofedFlow,
    deadline: Duration,
) -> Result<MarkerAck, String> {
    let mut sock =
        UnixStream::connect(gate_sock).map_err(|e| format!("connect to gate socket: {e}"))?;
    sock.set_read_timeout(Some(Duration::from_millis(200)))
        .map_err(|e| format!("set read timeout: {e}"))?;
    sock.set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|e| format!("set write timeout: {e}"))?;
    sock.write_all(GATE_SHUTTLE_HEAD)
        .map_err(|e| format!("write upgrade head: {e}"))?;

    let end = Instant::now() + deadline;
    // The SYN, then up to three claim rounds: a gratuitous ARP reply before
    // each SYN, plus the answer to any request the switch sends for the
    // address the flow wears. The claim is the spoofer's own act — the
    // switch's neighbor cache has no entry for an address no box holds, and
    // the reply is what aims the SYN-ACK back at this flow.
    let mut sent_syn = false;
    loop {
        if Instant::now() >= end {
            return Err(format!(
                "no SYN-ACK for spoofed source {} within {deadline:?}; the flow's \
                 frames were decided before they left the VM",
                flow.src
            ));
        }
        // The claim: announce the spoofed address for this flow's MAC.
        let claim = arp_reply(flow.src_mac, flow.src, flow.dst, flow.src_mac);
        write_frame(&mut sock, &claim).map_err(|e| format!("write ARP claim: {e}"))?;
        if !sent_syn {
            let syn = tcp_frame(
                flow.src_mac,
                flow.src,
                flow.src_port,
                flow.dst,
                flow.dst_port,
                SPOOF_ISN,
                0,
                TCP_SYN,
                &[],
            );
            write_frame(&mut sock, &syn).map_err(|e| format!("write SYN: {e}"))?;
            sent_syn = true;
        }
        let remaining = end.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            continue;
        }
        let frame = match read_frame(&mut sock, end)? {
            Some(frame) => frame,
            None => continue,
        };
        match classify(&frame, flow) {
            Some(Incoming::ArpRequest(requester_mac, requester_ip, requested_ip)) => {
                if requested_ip == flow.src {
                    let reply = arp_reply(requester_mac, flow.src, requester_ip, flow.src_mac);
                    write_frame(&mut sock, &reply).map_err(|e| format!("write ARP answer: {e}"))?;
                }
            }
            Some(Incoming::SynAck(synack_seq)) => {
                // The handshake's last leg: ACK, then the marker on a push.
                let ack = tcp_frame(
                    flow.src_mac,
                    flow.src,
                    flow.src_port,
                    flow.dst,
                    flow.dst_port,
                    SPOOF_ISN.wrapping_add(1),
                    synack_seq.wrapping_add(1),
                    TCP_ACK,
                    &[],
                );
                write_frame(&mut sock, &ack).map_err(|e| format!("write ACK: {e}"))?;
                let push = tcp_frame(
                    flow.src_mac,
                    flow.src,
                    flow.src_port,
                    flow.dst,
                    flow.dst_port,
                    SPOOF_ISN.wrapping_add(1),
                    synack_seq.wrapping_add(1),
                    TCP_PSH | TCP_ACK,
                    flow.marker.as_bytes(),
                );
                write_frame(&mut sock, &push).map_err(|e| format!("write push: {e}"))?;
                return Ok(await_marker_ack(&mut sock, flow, &push, deadline));
            }
            // A bare ACK before the SYN-ACK answers nothing this flow sent.
            Some(Incoming::Ack(_)) | None => {}
        }
    }
}

// --- the destination: a host TCP listener behind the switch's NAT ---

/// How long an accepted connection is held open waiting for its sender's
/// bytes. The NAT dials this listener when the SYN arrives, *before* the
/// handshake it is proxying has completed — gvisor-tap-vsock's TCP forwarder
/// dials the backend and only then creates the endpoint that answers the SYN
/// — so a connection's clock starts before its sender has seen the SYN-ACK it
/// must answer before it can push. Any budget shorter than the longest
/// `wait_for` closes the connection under a sender still mid-handshake, and
/// the marker it then pushes has nowhere to land (#1845).
const CONNECTION_BUDGET: Duration = Duration::from_secs(30);

/// The host's own non-loopback IPv4 address: the source address of its
/// default route, read by connecting a UDP socket (no packet is sent) toward
/// a TEST-NET-1 address. A box reaches it as ordinary egress through the
/// switch's NAT, the way it reaches any host on the runner's network.
///
/// The address must sit outside every range the relay drops or reserves on
/// its own — loopback, the switch plan's 100.64/10, and the reserved local
/// range — so a verdict at it is the box's declared union's and never an
/// infrastructure drop. Any other answer fails the test rather than skip it.
fn host_interface_address() -> Ipv4Addr {
    let probe = UdpSocket::bind(("0.0.0.0", 0)).expect("binding the route probe");
    probe
        .connect(("192.0.2.1", 9))
        .expect("the runner has no default IPv4 route to read its address from");
    let IpAddr::V4(addr) = probe.local_addr().expect("route probe address").ip() else {
        panic!("vm_escape_integration: the runner's default route has no IPv4 source");
    };
    let in_block = |base: Ipv4Addr, prefix: u32| {
        let mask = u32::MAX.checked_shl(32 - prefix).unwrap_or(0);
        u32::from(addr) & mask == u32::from(base) & mask
    };
    let (reserved, reserved_prefix) = sessions::core::loopback::RESERVED_LOCAL_RANGE;
    assert!(
        !addr.is_unspecified()
            && !in_block(Ipv4Addr::new(127, 0, 0, 0), 8)
            && !in_block(Ipv4Addr::new(100, 64, 0, 0), 10)
            && !in_block(reserved, u32::from(reserved_prefix)),
        "vm_escape_integration: the runner's interface address {addr} is loopback, \
         inside the switch plan's 100.64/10, or in the reserved local range \
         {reserved}/{reserved_prefix}; the relay decides those by its own drops, \
         not the boxes' declared union, so this harness cannot use it"
    );
    addr
}

/// A host TCP listener on the host's own interface address, which a box
/// reaches through the fabric's NAT as ordinary egress. Every
/// connection's first bytes are the marker its sender sent; the shared list
/// is what the test's verdicts read. Each connection is read on its own
/// thread, so a sender slow to push — or one that never pushes — holds up
/// neither the accept loop nor another sender's marker.
struct HostListener {
    seen: Arc<Mutex<Vec<String>>>,
    /// What each connection did, in arrival order: the account a failure
    /// reads to say whether a marker's connection was never dialed, was
    /// dialed and stayed silent, or arrived after the wait gave up.
    log: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

/// The gate's own account of a connection, for an assertion that cannot find
/// the line it expects. Which lines are present is the discriminator: an
/// `egress-unregistered-source` line and nothing else means the gate dropped
/// the frames at its own edge, while an ingress-leg line means the relay
/// came off on the switch side and anything the guest had buffered went with
/// it (#1847).
fn gate_account(guest: &Guest) -> String {
    let lines = guest.log_lines(&[
        "egress-unregistered-source",
        "egress-unknown-source",
        "egress gate",
        "ingress leg",
        "switch closed its side",
    ]);
    if lines.is_empty() {
        return "nothing; the gate logged no line for this flow".to_string();
    }
    lines.join(" | ")
}

/// Reads one accepted connection, recording what arrives as it arrives. A
/// read timeout is not an end: the sender may still be completing the
/// handshake this connection was dialed for, so the read is retried until the
/// sender closes, the connection's budget runs out, or the listener stops.
fn read_marker(
    mut conn: TcpStream,
    seen: &Mutex<Vec<String>>,
    log: &Mutex<Vec<String>>,
    stop: &AtomicBool,
    started: Instant,
) {
    let accepted = started.elapsed();
    // Logged on arrival, not only on departure: a connection still open when
    // a wait gives up is the whole distinction between a marker the fabric
    // never carried and one it carried too late.
    log.lock()
        .expect("log lock is held only across an append")
        .push(format!(
            "a connection was accepted at +{:.1}s",
            accepted.as_secs_f64()
        ));
    conn.set_nonblocking(false)
        .expect("setting the connection blocking");
    conn.set_read_timeout(Some(Duration::from_millis(200)))
        .expect("setting the connection read timeout");
    let end = Instant::now() + CONNECTION_BUDGET;
    let mut buf = [0u8; 256];
    let mut got = 0;
    let ended = loop {
        if stop.load(Ordering::Relaxed) {
            break "the listener stopped";
        }
        if Instant::now() >= end {
            break "the connection budget ran out";
        }
        match conn.read(&mut buf[got..]) {
            Ok(0) => break "the sender closed its side",
            Ok(n) => {
                got += n;
                // Pushed on every read, not once at the end: a marker is
                // readable the moment its bytes are, and the wait that reads
                // it is already running.
                seen.lock()
                    .expect("seen lock is held only across an append")
                    .push(String::from_utf8_lossy(&buf[..got]).into_owned());
                if got >= buf.len() {
                    break "the buffer filled";
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(_) => break "the read failed",
        }
    };
    log.lock()
        .expect("log lock is held only across an append")
        .push(format!(
            "the connection accepted at +{:.1}s read {got} bytes and ended at \
             +{:.1}s because {ended}",
            accepted.as_secs_f64(),
            started.elapsed().as_secs_f64()
        ));
}

impl HostListener {
    fn spawn(listener: TcpListener) -> HostListener {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let started = Instant::now();
        let handle = {
            let seen = Arc::clone(&seen);
            let log = Arc::clone(&log);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                listener
                    .set_nonblocking(true)
                    .expect("setting the listener nonblocking");
                let mut readers = Vec::new();
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match listener.accept() {
                        Ok((conn, _)) => {
                            let seen = Arc::clone(&seen);
                            let log = Arc::clone(&log);
                            let stop = Arc::clone(&stop);
                            readers.push(std::thread::spawn(move || {
                                read_marker(conn, &seen, &log, &stop, started);
                            }));
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(_) => break,
                    }
                }
                // The readers come off with the accept loop: the stop they
                // poll is the one that ended it, so each is at most one read
                // timeout from returning.
                for reader in readers {
                    let _ = reader.join();
                }
            })
        };
        HostListener {
            seen,
            log,
            stop,
            handle: Some(handle),
        }
    }

    /// What every connection that reached the listener did — the account a
    /// failed wait reads to say why its marker never arrived.
    fn report(&self) -> String {
        let log = self
            .log
            .lock()
            .expect("log lock is held only across this read");
        if log.is_empty() {
            return "no connection has finished at the listener".to_string();
        }
        log.join("; ")
    }

    /// Whether a marker whose text contains `needle` has arrived yet.
    fn seen_any(&self, needle: &str) -> bool {
        self.seen
            .lock()
            .expect("seen lock is held only across this read")
            .iter()
            .any(|marker| marker.contains(needle))
    }

    /// Polls for a marker containing `needle` until it arrives or the
    /// deadline passes.
    fn wait_for(&self, needle: &str, deadline: Duration) -> bool {
        let end = Instant::now() + deadline;
        while Instant::now() < end {
            if self.seen_any(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        false
    }
}

impl Drop for HostListener {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// One recorded spoof attempt: what the frame wore, where it was headed, and
/// the verdict its arrival gave it — the observability the bound is read
/// through.
struct Attempt {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    port: u16,
    verdict: String,
}

/// NET-085, at the VM boundary: the spoofer's two paths, against the
/// resident union.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn vm_escape_bounded_to_resident_union() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);

    // The destination: a host listener on the host's own interface address,
    // live for the whole of the test, reached through the switch's NAT as
    // ordinary egress — relay, gate, switch, NAT. Not the host alias: box→host
    // reach over the alias is default-deny except configured host exposures
    // (design §7.1, gominimal/inbox#867), so a box's own relay drops it
    // whatever the box declares, and the positive controls could never pass.
    let host = host_interface_address();
    let listener = TcpListener::bind((host, 0)).expect("binding the host listener");
    let port = listener.local_addr().expect("listener address").port();
    let listener = HostListener::spawn(listener);
    let host_cidr = format!("{host}/32");

    // Two resident boxes with disjoint declared egress. Both declare the
    // host listener's address (the destination their own probes reach: a
    // box's own declared traffic, admitted by its own declaration) and the
    // fabric, and each declares a private range the other does not — the
    // disjoint half the cross-box spoof would have to buy.
    let mut box_a = open_box(
        &guest,
        sessions::NetworkMode::OwnIp,
        sessions::EgressPolicy {
            allow_protocols: Some(vec![sessions::IpProto::Tcp, sessions::IpProto::Udp]),
            allow_subnets: Some(vec![
                "10.0.0.0/8".to_string(),
                "100.64.0.0/16".to_string(),
                host_cidr.clone(),
            ]),
            allow_dns_hosts: None,
            deny_subnets: None,
        },
        "box-a",
    )
    .await;
    let mut box_b = open_box(
        &guest,
        sessions::NetworkMode::OwnIp,
        sessions::EgressPolicy {
            allow_protocols: Some(vec![sessions::IpProto::Tcp, sessions::IpProto::Udp]),
            allow_subnets: Some(vec![
                "192.168.0.0/16".to_string(),
                "100.64.0.0/16".to_string(),
                host_cidr.clone(),
            ]),
            allow_dns_hosts: None,
            deny_subnets: None,
        },
        "box-b",
    )
    .await;

    // Path (a)'s precondition: the box holds neither CAP_NET_RAW (13) nor
    // CAP_NET_ADMIN (12) — dropped from the bounding set the box is launched
    // with (NET-083), the one capability set an exec does not clear — so no
    // process on the guest's own interface has the raw-socket route around
    // the relay, and the relay's own lease check (NET-084) bounds whatever
    // it does send. `0x3000` is both bits.
    const CAPEFF_COMMAND: &str = "while read -r k v; do case \"$k\" in CapEff*) \
                                  echo \"$v\";; esac; done < /proc/self/status";
    for (label, box_session) in [("box-a", &mut box_a), ("box-b", &mut box_b)] {
        let (stdout, stderr, exit) = box_session
            .exec(CAPEFF_COMMAND)
            .await
            .unwrap_or_else(|e| panic!("vm_escape_integration: {label} CapEff exec: {e}"));
        assert_eq!(
            exit,
            Some(0),
            "{label} CapEff read exited nonzero; stderr: {stderr}"
        );
        let caps = stdout
            .trim()
            .lines()
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();
        let caps = u64::from_str_radix(&caps, 16)
            .unwrap_or_else(|e| panic!("vm_escape_integration: {label} CapEff {caps:?}: {e}"));
        assert_eq!(
            caps & 0x3000,
            0,
            "{label} holds CAP_NET_RAW/CAP_NET_ADMIN; the box's own interface \
             offers a raw-socket route the relay cannot bound (NET-083)"
        );
    }

    let mut attempts: Vec<Attempt> = Vec::new();

    // The positive controls: each box's own declared traffic reaches the
    // listener — the whole chain working, relay to gate to switch to NAT —
    // and the bound's own row-decided arm. The marker names its sender.
    for (label, box_session, marker) in [
        ("box-a", &mut box_a, "own-a-reached"),
        ("box-b", &mut box_b, "own-b-reached"),
    ] {
        let command = format!("echo {marker} > /dev/tcp/{host}/{port}");
        let (_, stderr, exit) = box_session
            .exec(&command)
            .await
            .unwrap_or_else(|e| panic!("vm_escape_integration: {label} own probe: {e}"));
        assert_eq!(
            exit,
            Some(0),
            "{label}'s own probe to {host}:{port} failed; stderr: {stderr}"
        );
        assert!(
            listener.wait_for(marker, Duration::from_secs(10)),
            "{label}'s own declared traffic never reached the host listener"
        );
        attempts.push(Attempt {
            source: Ipv4Addr::UNSPECIFIED,
            destination: host,
            port,
            verdict: format!("{label}'s own declared traffic arrived (positive control)"),
        });
    }

    // The spoofed attempts at the gate's landing edge — path (b). Each flow
    // wears one source and drives the shuttle's own protocol at the gate
    // socket, byte-identical to what a root escapee's vsock connection
    // carries past that edge.
    //
    // In-plan made-up leases — addresses the plan could hand to a box and no
    // row holds: the gate drops these frames under its own unregistered
    // source rule, toward every destination alike — no rules consulted, no
    // phase gating the decision (NET-085), because a lease the plan could
    // mint but no box holds is exactly the address a root escapee forges.
    // The flow never completes, nothing arrives, and the gate's own line
    // names the source (`egress-unregistered-source`).
    //
    // The sources are written here, not read off the boxes' own leases: the
    // arm under test is an in-plan address *no row holds*, which the boxes'
    // real leases cannot name — each box's lease is row-held by definition,
    // and its cross-box pair is unobservable today (see below), so a read off
    // the routing tables would serve nothing this test can assert.
    for src in [Ipv4Addr::new(100, 64, 0, 99), Ipv4Addr::new(100, 64, 0, 88)] {
        let flow = SpoofedFlow {
            src,
            src_mac: [0x02, 0x50, 0x64, 0x00, 0x64, src.octets()[3]],
            dst: host,
            dst_port: port,
            src_port: 40_000 + u16::from(src.octets()[3]),
            marker: format!("spoof-{src}-arrived"),
        };
        // The one arm this posture leaves: refused before any frame leaves
        // the VM — silence at the listener, and the unregistered-source line
        // naming the source. A completed flow here means the gate stopped
        // dropping a source no row holds, so it is a failure, not a verdict.
        let verdict = match spoofed_flow(&guest.gate_sock, &flow, DROP_DEADLINE) {
            Ok(marker_ack) => panic!(
                "vm_escape_integration: a spoofed in-plan source no row holds \
                 ({src}) completed a flow to {host}:{port}; the gate must drop \
                 it (NET-085) [{marker_ack}]"
            ),
            Err(e) => {
                // The flow was decided before it left the VM — nothing
                // arrives, and the drop line names the source.
                assert!(
                    !listener.seen_any(&flow.marker),
                    "the spoofed flow from {src} was refused at the gate, but \
                     its marker reached the host listener; the listener saw: {}",
                    listener.report()
                );
                assert!(
                    guest.log_contains("egress-unregistered-source")
                        && guest.log_contains(&format!("source={src}")),
                    "the gate dropped spoofed source {src} without its \
                     unregistered-source line naming it; the gate said: {}",
                    gate_account(&guest)
                );
                format!(
                    "spoofed source {src} refused at the gate (silence, and \
                         the unregistered-source line) [{e}]"
                )
            }
        };
        attempts.push(Attempt {
            source: src,
            destination: host,
            port,
            verdict,
        });
    }

    // Out of the plan's lease block: refused outright — outside the plan
    // there is no lease to spoof. The rule-0 refusal: the gate drops the SYN
    // before any frame leaves the VM, so the flow gets silence, no marker
    // arrives, and the gate's drop line names the source.
    let outside_plan = Ipv4Addr::new(203, 0, 113, 7);
    let flow = SpoofedFlow {
        src: outside_plan,
        src_mac: [0x02, 0x50, 0x64, 0x00, 0x00, 0x07],
        dst: host,
        dst_port: port,
        src_port: 40_000,
        marker: "spoof-203.0.113.7-arrived".to_string(),
    };
    let verdict = match spoofed_flow(&guest.gate_sock, &flow, DROP_DEADLINE) {
        Ok(_) => panic!(
            "vm_escape_integration: a spoofed source outside the plan's lease \
             block ({outside_plan}) completed a flow; the gate must refuse it"
        ),
        Err(e) => {
            assert!(
                !listener.seen_any(&flow.marker),
                "a source outside the plan's lease block left a marker at the \
                 host listener"
            );
            format!(
                "spoofed source {outside_plan} refused at the gate (silence; \
                     {e})"
            )
        }
    };
    attempts.push(Attempt {
        source: outside_plan,
        destination: host,
        port,
        verdict,
    });
    assert!(
        guest.log_contains("egress-unknown-source")
            && guest.log_contains(&format!("source={outside_plan}")),
        "the gate dropped spoofed source {outside_plan} without its \
         unknown-source line naming it"
    );
    // And for the source, not the destination: the runner's address is no
    // address the gate holds as infrastructure, so no refusal here is
    // `egress-infrastructure-destination` — every negative above is the
    // bound's own, never an infrastructure drop passing for it.
    let host_text = host.to_string();
    let infrastructure: Vec<String> = guest
        .log_lines(&["egress-infrastructure-destination"])
        .into_iter()
        .filter(|line| line.contains(&host_text))
        .collect();
    assert!(
        infrastructure.is_empty(),
        "the gate refused the runner's address {host} as infrastructure, so the \
         harness's refusals would not be the resident union's: {infrastructure:?}"
    );

    // The cross-box pairs — a spoofed box address tried at a destination only
    // the other box declared — leave no arrival this test can attribute to
    // itself: the destinations have nothing listening, and a frame the row
    // that holds the worn source refuses dies at the gate with no listener
    // behind it to say so. What bounds them is the decision the unit case pins
    // (spoofed_source_bounded_to_resident_union): the row that holds the
    // spoofed source decides it, so a spoof of box-a's address reaches
    // box-a's declared egress and nothing else. This test does not send
    // unobservable frames; the record above is what the VM boundary can say
    // today.

    // The record, then the host-side gate's own lines for the spoofed
    // sources: the attempt table and the drop lines beside it, so the
    // bound can be read off the test output.
    eprintln!("vm_escape_integration: spoof attempts against the resident union:");
    for attempt in &attempts {
        eprintln!(
            "  source={} destination={}:{} verdict={}",
            attempt.source, attempt.destination, attempt.port, attempt.verdict
        );
    }
    eprintln!("vm_escape_integration: the host-side gate's own lines:");
    for line in guest.log_lines(&[
        "egress-unregistered-source",
        "egress-unknown-source",
        "egress-undeclared-subnet",
    ]) {
        eprintln!("  {line}");
    }
}
