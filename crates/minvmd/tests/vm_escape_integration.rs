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
//! **The shipped posture.** The host-side gate decides a frame whose source
//! is an address the plan could hand to a box but no published row holds as
//! the announced interim's admit — no rules consulted — because the rows that
//! would bound it are T66's (#1711, the creator-side registration), whose
//! flip also replaces the interim with a per-box default. So today a spoofed
//! in-plan source is admitted end-to-end, and the test says so — the way the
//! tree's own interim tests pin both arms (`unknown_source_default_deny`) —
//! with a comment naming the in-force arm each shipped admit becomes. What
//! holds at this branch and holds after the flip:
//!
//! - an address **outside** the plan's lease block is refused outright
//!   (`egress-unknown-source`), under either phase: outside the plan there
//!   is no lease to spoof — the rule-0 refusal, flip-stable;
//! - a **resident box's own** declared traffic reaches its declared
//!   destination — the positive controls, flip-stable under T66's rows;
//! - a spoofed **in-plan** source admitted by the shipped interim — the gap
//!   the flip closes, named per attempt.
//!
//! Diagnostics: after the spoofs the test prints the host-side gate's own
//! lines for the spoofed sources (the drop and interim-admit lines), so the
//! bound can be read off the test output; observability: every spoofed
//! destination attempt is recorded with the verdict its arrival gave it.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must
//!   point to the kernel, the GENERIC rootfs, and the minimald initramfs.
//! - `MINVMD_GVPROXY_BIN` points at gvproxy when a switch is provided. When
//!   it is absent the test skips like the other gates: minvmd boots the VM
//!   switchless, there is no egress — declared, spoofed, or otherwise — and
//!   the bound's landing edge does not exist to test. The harness lanes set
//!   `MINVMD_E2E=1` but fetch gvproxy only for the session-e2e step after
//!   them, so the absence is a skip, not a failure; the bound is proved
//!   where the switch is provided (`just test-vm`, the nightly).

#![cfg(minvmd_libkrun)]

use std::io::{BufRead, ErrorKind, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serial_test::serial;
use tempfile::TempDir;

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

/// How long the harness waits for the `vm-up` (READY) line. The line comes
/// only after `minvmd boot`'s own READY wait completes — 60 s by default, 150
/// s under `just`, which exports `MINVMD_READY_TIMEOUT_SECS=150` for every
/// recipe because a cold multi-GiB VM can run 40–70 s before pid-1 starts
/// (the AGENTS.md boot footgun). This harness drives `boot --foreground` and
/// must absorb that cold boot on its own, so it waits the justfile's 150 s.
const BOOT_TIMEOUT: Duration = Duration::from_secs(150);
/// How long one spoofed flow may take to produce its verdict: the ARP claim,
/// the SYN, and the handshake across the real switch and the host listener.
const FLOW_DEADLINE: Duration = Duration::from_secs(10);
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

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so.
fn e2e_enabled() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("vm_escape_integration: MINVMD_E2E != 1, skipping");
        return false;
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
    // reach, so the bound's landing edge does not exist to test. The harness
    // lanes that run the ignored tests (`test-kvm`, the macOS harness step)
    // set `MINVMD_E2E=1` but fetch gvproxy only for the session-e2e step
    // after them, so an absent variable is a skip, like `MINVMD_E2E != 1`:
    // the bound is proved where the switch is provided, and the lane stays
    // green where it is not.
    match std::env::var_os("MINVMD_GVPROXY_BIN") {
        Some(_) => true,
        None => {
            eprintln!(
                "vm_escape_integration: MINVMD_GVPROXY_BIN is not set, skipping: \
                 without the switch there is no egress gate to test the bound at \
                 (set it to the gvproxy binary to run the suite)"
            );
            false
        }
    }
}

/// A booted minimald guest VM, torn down on drop.
struct Guest {
    child: Child,
    sock_path: PathBuf,
    gate_sock: PathBuf,
    /// Everything the daemon wrote to its stdout, shared with the reader
    /// thread: the host-side gate's drop and interim lines live here, and are
    /// the diagnostics this test prints and asserts on.
    log: Arc<Mutex<String>>,
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
    /// blocks until the `vm-up` (READY) line, capturing the daemon's stdout
    /// into the shared log. Panics on boot timeout.
    fn boot() -> Guest {
        let state = short_state_dir();
        let sock_path = state
            .path()
            .join("minimal/providers/local-minvmd0/ssh.sock");
        // The gate binds the socket beside the switch socket, which sits
        // beside the bridge socket this path names.
        let gate_sock = sock_path
            .parent()
            .expect("the bridge socket always has a parent")
            .join("gvproxy-gate.sock");

        let exe = minvmd_bin();
        let mut child = Command::new(exe)
            .args(["boot", "--foreground"])
            .env("XDG_STATE_HOME", state.path())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawning minvmd boot --foreground");

        let stdout = child.stdout.take().expect("child stdout");
        let log = Arc::new(Mutex::new(String::new()));
        let (tx, rx) = std::sync::mpsc::channel::<bool>();
        let log_for_reader = Arc::clone(&log);
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let mut line = String::new();
            loop {
                line.clear();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) => {
                        if line.trim() == "vm-up" {
                            let _ = tx.send(true);
                            // Keep draining: the gate's lines land on the
                            // same stdout for the rest of the VM's life.
                        }
                        log_for_reader
                            .lock()
                            .expect("log lock is held only across an append")
                            .push_str(&line);
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(false);
        });

        if !rx.recv_timeout(BOOT_TIMEOUT).unwrap_or(false) {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "vm_escape_integration: no 'vm-up' within {} s; are \
                 MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH/MINVMD_INITRAMFS set correctly \
                 (and libkrun >= 1.19.0)?",
                BOOT_TIMEOUT.as_secs(),
            );
        }

        Guest {
            child,
            sock_path,
            gate_sock,
            log,
            _state: state,
        }
    }

    /// Whether `needle` has appeared in the daemon's stdout yet.
    fn log_contains(&self, needle: &str) -> bool {
        self.log
            .lock()
            .expect("log lock is held only across this read")
            .contains(needle)
    }

    /// The daemon's stdout lines that carry any of `needles` — the gate's own
    /// lines for the spoofed sources, as the test leaves them.
    fn log_lines(&self, needles: &[&str]) -> Vec<String> {
        self.log
            .lock()
            .expect("log lock is held only across this read")
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
    /// `network` and the declared egress policy, uploads a task-only
    /// `minimal.toml` over SFTP so the loadout composes in one shot,
    /// finalizes the record, and keeps the handle for execs.
    async fn open(
        sock_path: &Path,
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
        // in-guest (NET-084) and which T66 (#1711) will publish as the
        // host-side row the egress gate decides the box's frames by.
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
                egress: Some(egress),
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
            let req = CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some(format!("vm-escape-{label}-{uniq:x}")),
                    project_path: paths::HostAbsPath::try_new("/tmp")
                        .map_err(|e| format!("project_path: {e}"))?,
                    network,
                    policy,
                    // No registration happened on this path: the box attaches
                    // as an unregistered one always has.
                    box_addresses: None,
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

        // A task-only `minimal.toml` over SFTP: the loadout composes from it
        // in one shot, the same shape the session harness proves.
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
            // Task-only: no package graph, no sandbox needed for it.
            let contents = "[tasks.echo_ok]\necho = \"MINIMALD_SESSION_OK\"\n";
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
                Some(ConfigureLoadoutResponse::Pending { .. }) => {
                    return Err("ConfigureLoadout returned Pending; this test's mfile \
                                gates nothing"
                        .to_string());
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

        Ok(BoxSession {
            handle,
            session_id: session_id.to_string(),
        })
    }

    /// Runs one command in the box — the session's sandbox — and returns
    /// `(stdout, exit_status)`.
    async fn exec(&mut self, command: &str) -> Result<(String, Option<u32>), String> {
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
        match BoxSession::open(&guest.sock_path, network, egress.clone(), label).await {
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
/// (`relay_guest_to_switch`) and the guest relay writes.
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
/// the address the flow wears, the SYN-ACK answering the flow's SYN, or
/// nothing the flow cares about.
enum Incoming {
    /// `(requester MAC, requester IP, requested IP)`: an ARP request the flow
    /// answers when it names the address the flow wears.
    ArpRequest([u8; 6], Ipv4Addr, Ipv4Addr),
    /// The SYN-ACK's sequence number: the handshake's second leg arrived.
    SynAck(u32),
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
    if flags & TCP_SYN == 0 || flags & TCP_ACK == 0 {
        return None;
    }
    let synack_seq =
        u32::from_be_bytes([frame[l4 + 4], frame[l4 + 5], frame[l4 + 6], frame[l4 + 7]]);
    Some(Incoming::SynAck(synack_seq))
}

/// Drives one spoofed flow at the gate's landing edge: the `/connect` upgrade
/// head, a SYN wearing the flow's source, the ARP answer claiming that source
/// for the flow's MAC (both the pre-emptive claim and the answer to whatever
/// request the switch's neighbor resolution sends), and on the SYN-ACK the
/// ACK and the marker-carrying push. `Ok(())` is the handshake completing;
/// whether the marker then reaches the host listener is the caller's record.
fn spoofed_flow(gate_sock: &Path, flow: &SpoofedFlow, deadline: Duration) -> Result<(), String> {
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
                0x0050_1001,
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
                    0x0050_1002,
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
                    0x0050_1002,
                    synack_seq.wrapping_add(1),
                    TCP_PSH | TCP_ACK,
                    flow.marker.as_bytes(),
                );
                write_frame(&mut sock, &push).map_err(|e| format!("write push: {e}"))?;
                return Ok(());
            }
            None => {}
        }
    }
}

// --- the destination: a host TCP listener behind the switch's NAT ---

/// A host TCP listener the fabric's NAT maps the host alias's port to. Every
/// connection's first bytes are the marker its sender sent; the shared list
/// is what the test's verdicts read.
struct HostListener {
    seen: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl HostListener {
    fn spawn(listener: TcpListener) -> HostListener {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let handle = {
            let seen = Arc::clone(&seen);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                listener
                    .set_nonblocking(true)
                    .expect("setting the listener nonblocking");
                loop {
                    if stop.load(Ordering::Relaxed) {
                        break;
                    }
                    match listener.accept() {
                        Ok((mut conn, _)) => {
                            conn.set_nonblocking(false)
                                .expect("setting the connection blocking");
                            conn.set_read_timeout(Some(Duration::from_secs(2)))
                                .expect("setting the connection read timeout");
                            let mut buf = [0u8; 256];
                            let mut got = 0;
                            loop {
                                match conn.read(&mut buf[got..]) {
                                    Ok(0) => break,
                                    Ok(n) => {
                                        got += n;
                                        if got >= buf.len() {
                                            break;
                                        }
                                    }
                                    Err(e)
                                        if matches!(
                                            e.kind(),
                                            ErrorKind::WouldBlock | ErrorKind::TimedOut
                                        ) =>
                                    {
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                            if got > 0 {
                                seen.lock()
                                    .expect("seen lock is held only across an append")
                                    .push(String::from_utf8_lossy(&buf[..got]).into_owned());
                            }
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(100));
                        }
                        Err(_) => break,
                    }
                }
            })
        };
        HostListener {
            seen,
            stop,
            handle: Some(handle),
        }
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
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and MINVMD_GVPROXY_BIN"]
async fn vm_escape_bounded_to_resident_union() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();
    let subnet = switch::DEFAULT_SUBNET;
    let alias = subnet.host_alias();

    // The destination: a host listener the switch's NAT maps the host alias
    // to, live for the whole of the test.
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("binding the host listener");
    let port = listener.local_addr().expect("listener address").port();
    let listener = HostListener::spawn(listener);

    // Two resident boxes with disjoint declared egress. Both declare the
    // fabric (which carries the host alias their own probes reach, the
    // flip-stable arm: a box's own declared traffic, admitted by its own
    // declaration under either phase), and each declares a private range the
    // other does not — the disjoint half the cross-box spoof would have to
    // buy.
    let mut box_a = open_box(
        &guest,
        sessions::NetworkMode::OwnIp,
        sessions::EgressPolicy {
            allow_protocols: Some(vec![sessions::IpProto::Tcp, sessions::IpProto::Udp]),
            allow_subnets: Some(vec!["10.0.0.0/8".to_string(), "100.64.0.0/16".to_string()]),
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
        let (stdout, exit) = box_session
            .exec(CAPEFF_COMMAND)
            .await
            .unwrap_or_else(|e| panic!("vm_escape_integration: {label} CapEff exec: {e}"));
        assert_eq!(exit, Some(0), "{label} CapEff read exited nonzero");
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
    // and the flip-stable arm of the bound. The marker names its sender.
    for (label, box_session, marker) in [
        ("box-a", &mut box_a, "own-a-reached"),
        ("box-b", &mut box_b, "own-b-reached"),
    ] {
        let command = format!("echo {marker} > /dev/tcp/{alias}/{port}");
        let (_, exit) = box_session
            .exec(&command)
            .await
            .unwrap_or_else(|e| panic!("vm_escape_integration: {label} own probe: {e}"));
        assert_eq!(
            exit,
            Some(0),
            "{label}'s own probe to {alias}:{port} failed"
        );
        assert!(
            listener.wait_for(marker, Duration::from_secs(10)),
            "{label}'s own declared traffic never reached the host listener"
        );
        attempts.push(Attempt {
            source: Ipv4Addr::UNSPECIFIED,
            destination: alias,
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
    // row holds: under the shipped interim the gate admits these frames
    // without consulting any rules, so the flow completes and its marker
    // arrives at the host listener; the gate's own line names the source
    // (`egress-unregistered-source`). When T66 (#1711) lands — box rows
    // published, the interim replaced by the per-box default — every one of
    // these becomes an unknown-source drop, because a made-up lease has no
    // row to be decided by: the flip turns each admit below into
    // `egress-unknown-source`, and the reach a made-up lease buys goes to
    // nothing.
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
            dst: alias,
            dst_port: port,
            src_port: 40_000 + u16::from(src.octets()[3]),
            marker: format!("spoof-{src}-arrived"),
        };
        // Both arms of the in-plan source are pinned: the shipped interim
        // admits it — the flow completes, the marker arrives, and the gate's
        // interim line names the source — and the per-box default T66 (#1711)
        // flips in refuses it before any frame leaves the VM — silence at the
        // listener, and the gate's unknown-source line naming the source.
        // When the flip lands this arm strengthens instead of breaking: the
        // Err arm becomes the in-force verdict, recorded like any other.
        let verdict = match spoofed_flow(&guest.gate_sock, &flow, FLOW_DEADLINE) {
            Ok(()) => {
                assert!(
                    listener.wait_for(&flow.marker, Duration::from_secs(10)),
                    "the spoofed flow from {src} completed its handshake but its \
                     marker never reached the host listener"
                );
                // The gate's own line for the admit: the diagnostics a host
                // reads the interim's posture out of, naming the source the
                // frame wore.
                assert!(
                    guest.log_contains("egress-unregistered-source")
                        && guest.log_contains(&format!("source={src}")),
                    "the gate admitted spoofed source {src} without its interim \
                     line naming it"
                );
                format!(
                    "spoofed source {src} reached {alias}:{port} (the shipped \
                         interim's admit; T66's flip makes it an unknown-source drop)"
                )
            }
            Err(e) => {
                // The in-force arm: the flow was decided before it left the
                // VM — nothing arrives, and the drop line names the source.
                assert!(
                    !listener.seen_any(&flow.marker),
                    "the spoofed flow from {src} was refused at the gate, but \
                     its marker reached the host listener"
                );
                assert!(
                    guest.log_contains("egress-unknown-source")
                        && guest.log_contains(&format!("source={src}")),
                    "the gate refused spoofed source {src} without its \
                     unknown-source line naming it"
                );
                format!(
                    "spoofed source {src} refused at the gate (the per-box \
                         default; silence, and the unknown-source line) [{e}]"
                )
            }
        };
        attempts.push(Attempt {
            source: src,
            destination: alias,
            port,
            verdict,
        });
    }

    // Out of the plan's lease block: refused outright, under either phase —
    // outside the plan there is no lease to spoof. The rule-0 refusal,
    // flip-stable: the gate drops the SYN before any frame leaves the VM, so
    // the flow gets silence, no marker arrives, and the gate's drop line
    // names the source.
    let outside_plan = Ipv4Addr::new(203, 0, 113, 7);
    let flow = SpoofedFlow {
        src: outside_plan,
        src_mac: [0x02, 0x50, 0x64, 0x00, 0x00, 0x07],
        dst: alias,
        dst_port: port,
        src_port: 40_000,
        marker: "spoof-203.0.113.7-arrived".to_string(),
    };
    let verdict = match spoofed_flow(&guest.gate_sock, &flow, DROP_DEADLINE) {
        Ok(()) => panic!(
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
        destination: alias,
        port,
        verdict,
    });
    assert!(
        guest.log_contains("egress-unknown-source")
            && guest.log_contains(&format!("source={outside_plan}")),
        "the gate dropped spoofed source {outside_plan} without its \
         unknown-source line naming it"
    );

    // The cross-box pairs — a spoofed box address tried at a destination only
    // the other box declared — have no observable today: the shipped interim
    // admits them without rules, and the destinations have nothing listening,
    // so neither an arrival nor a gate line can attribute the frame to this
    // test. What bounds them is the decision the unit case pins
    // (spoofed_source_bounded_to_resident_union): the row that holds the
    // spoofed source decides it, so after T66's flip a spoof of box-a's
    // address reaches box-a's declared egress and nothing else. This test
    // does not send unobservable frames; the record above is what the VM
    // boundary can say today.

    // The record, then the host-side gate's own lines for the spoofed
    // sources: the attempt table and the drop/admit lines beside it, so the
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
