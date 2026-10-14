//! The guest kernel's half of the classifier (NET-079, T75): the VM-host
//! proof that the table the guest daemon renders and loads at boot is the
//! table the native installer renders for the same parameters, and that a
//! loaded table decides a deny-all host-address box per box — refusing what
//! the box originates, keeping the one carve-out (the node's DNS layer at
//! the gateway, port 53 over UDP and TCP) answering, and recording the
//! effect probe's per-family errno.
//!
//! Eight proofs, one VM boot each, all through the supervisor path
//! (`minvmd run --detach`, `status --json` until Running, `stop` on drop):
//! only `run` stands up the host gvproxy switch before the VMM child boots.
//!
//! - `guest_kernel_accepts_rendered_ruleset`: the boot's `nft -c -f -` line
//!   says the guest kernel accepted the rendered text, and the load line
//!   carries the digest of exactly the bytes piped to `nft -f -`; a check
//!   that refused fails the test quoting the error line, which carries
//!   nft's own words naming the missing expression — the line the guest
//!   image's builder reads.
//! - `guest_loaded_ruleset_matches_native_print_ruleset`: that digest equals
//!   the sha256 of the native installer's `--print-ruleset` output for the
//!   same parameters — the same render function whose bytes the installer's
//!   own load path pipes and prints the digest of, so the guest's table and
//!   the native installer's are one ruleset, never a re-render.
//! - `guest_classifier_table_present`: the table is listed in the guest —
//!   the daemon's own `nft list` recheck, run before every host-address
//!   launch, must name `inet minimal_class` and its `deny_out` chain, and
//!   the deny-all box that launches is the listing's observable: no box
//!   holds `CAP_NET_ADMIN` and the guest has no root-exec surface
//!   (see `vm_escape_integration.rs`), so the daemon is the only caller
//!   that can list the table at all.
//! - `guest_deny_all_probe_refused`: the box's own outbound probe to an
//!   address off the guest is refused, and the errno the box reads is
//!   EHOSTUNREACH — the `reject with icmpx admin-prohibited` verdict as
//!   IPv4 surfaces it.
//! - `guest_deny_all_resolver_reachable`: the same box resolves
//!   `host.min.internal` through the node's DNS layer at the gateway
//!   (100.64.0.1), the one carve-out the deny chain admits on port 53 over
//!   UDP and TCP; its AAAA lookup is answered NODATA by that layer on the
//!   daemon's relay; and its connect to the address it resolved is refused.
//! - `guest_deny_all_box_answers_inbound_through_the_proxy`: a connection
//!   another box opens to it through the hostname proxy is answered — the
//!   reply-direction admission that lets a deny-all box serve what reaches
//!   it while everything it originates is still refused.
//! - `guest_host_ip_enforcement_per_box_after_load`: the launch's own
//!   record says `host_ip_enforcement=per_box`. The field is `pub(crate)`
//!   and not on the wire (issue #1773), so the per-launch classifier line
//!   on the guest's console is the record that carries it.
//! - `guest_effect_probe_errno_per_family`: every effect probe the guest
//!   ran reads a refusal with an errno inside EHOSTUNREACH, EACCES and
//!   EPERM — EHOSTUNREACH on 127.0.0.1, EACCES on ::1 wherever IPv6
//!   loopback is enabled — the per-family evidence a `per_box` verdict
//!   rests on, named in the probe's own log record.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must
//!   point at the kernel, generic rootfs, and minimald initramfs cpio.
//! - The gvproxy switch: `MINVMD_GVPROXY_BIN` when set, else the pinned
//!   fetch (see `common::gvproxy_bin`).
//!
//! A missing precondition is reported as a skip, one stderr line, and the
//! test returns; under `MINVMD_VM_LANE` the same precondition panics instead,
//! so a lane that declared itself a VM lane cannot go green on an unexported
//! image — the arm `egress_allowlist_integration.rs` defines for the same
//! reason.
//!
//! The guest's node ports are pinned (`MINVMD_NODE_PROXY_PORT=7654`,
//! `MINVMD_NODE_ANSWERER_PORT=7656`) on every supervisor call, so the
//! proxy the inbound proof rides is at its documented default whatever else
//! the host holds.
//!
//! These proofs are the lane's answer to the image dependency the task
//! waits on: the guest's `/usr/sbin/nft` and the kernel expressions it
//! needs come from the gominimal/pkgs pin, and against an image without
//! them the load lines say so in nft's own words and the deny-all box is
//! refused — the failures this file turns into the lane's evidence.

#![cfg(minvmd_libkrun)]

mod common;

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serial_test::serial;
use sessions::core::decision::ItemDecision;
use sessions::core::hooks::{HookResult, PolicyHooks, Unapproved};
use sessions::core::policy::{HooksPolicy, PatchesPolicy, VarsPolicy};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

/// Isolated `XDG_STATE_HOME` under /tmp: macOS's $TMPDIR is deep enough that
/// provider sockets beneath a default tempdir would overflow sun_path (104).
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// The minvmd binary to boot: `MINVMD_BIN` when set — CI's split build/test
/// jobs run this harness on a different runner than the one that compiled it
/// — otherwise that compile-time cargo-built path.
fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

/// `run --detach --timeout`: the justfile exports 150 s for cold boots.
const DETACH_TIMEOUT_SECS: &str = "150";
/// How long `status --json` may take to report Running after `run --detach`
/// returns (it returns once the bridge UDS accepts, slightly ahead of the
/// Starting -> Running write).
const RUNNING_TIMEOUT: Duration = Duration::from_secs(90);
/// Bound on any one `minvmd` subcommand (`run --detach`, `status`, `stop`) so
/// a wedged daemon fails the test instead of hanging it.
const SUBPROC_TIMEOUT: Duration = Duration::from_secs(180);
/// Bound on any one exec inside a box, measured as silence on the channel.
/// A session's first exec launches its box, and the launch fetches the box's
/// package closure from the remote cache onto the guest's freshly formatted
/// data volume before the command runs. On the KVM lane two concurrent first
/// launches have taken 84-122 s; one launch alone usually finishes in under
/// 40 s, so the bound covers it with headroom. A guest that stays silent for
/// two minutes is wedged, not slow.
const EXEC_TIMEOUT: Duration = Duration::from_secs(120);
/// How long a boot-log line may take to appear after the guest is Running:
/// the guest daemon writes them at boot, before it serves, so this only
/// covers the console flush.
const LOG_DEADLINE: Duration = Duration::from_secs(30);

/// The guest daemon's log filter: info everywhere, with the classifier's, the
/// answerer's and the DNS gate's debug lines promoted — the probe's
/// per-family record and the node's DNS layer's per-lookup lines are
/// evidence these proofs read off the guest's console.
const GUEST_LOG_FILTER: &str = "info,minimald::net::classifier=debug,minimald::net::answerer=debug,\
                                minimald::net::dns_gate=debug";

/// Env var the server reads to scope an exec to a session.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// The in-guest ports this harness pins on every supervisor call, so the
/// proxy is at its documented default whatever else the host holds. Mirrors `minvmd`'s own overrides (`MINVMD_NODE_PROXY_PORT` /
/// `MINVMD_NODE_ANSWERER_PORT`, `crates/minvmd/src/vm.rs`).
const NODE_PROXY_PORT: &str = "7654";
const NODE_ANSWERER_PORT: &str = "7656";

/// The classifier tree the guest daemon mounts and renders for:
/// `sandbox::classifier::TREE_ROOT` (the sandbox layer is not a `minvmd`
/// dependency, so the one path is spelled here beside the digest that would
/// catch it drifting).
const GUEST_TREE_ROOT: &str = "/sys/fs/cgroup/minimald.slice";

/// The ct-mark bits the guest's boot renders with: `GUEST_CT_MARK_MASK` in
/// `minimald::net::classifier`, spelled here as the argv the render takes —
/// same reason as the tree root above.
const GUEST_CT_MARK_MASK_ARG: &str = "0x30000000";

/// The errnos by which the loaded table's `reject with icmpx
/// admin-prohibited` reads inside the guest (design §4.1): EHOSTUNREACH over
/// IPv4, EACCES over IPv6, EPERM an output-hook verdict. Pinned by their
/// Linux numbers — the guest kernel is always Linux, whatever host runs this
/// harness (macOS's own EHOSTUNREACH is 65 and would pin the wrong number).
const ERRNO_EHOSTUNREACH: i32 = 113;
const ERRNO_EACCES: i32 = 13;
const ERRNO_EPERM: i32 = 1;
const ERRNO_ECONNREFUSED: i32 = 111;

/// The loopback families the probe reads, as its own record spells them
/// (`Family::name` in `minimald::net::classifier`).
const FAMILY_V4: &str = "127.0.0.1";
const FAMILY_V6: &str = "::1";

/// Set by a lane that declares itself a VM lane: a missing precondition then
/// fails the test instead of skipping it.
const MINVMD_VM_LANE_ENV: &str = "MINVMD_VM_LANE";

/// A precondition is missing. Under [`MINVMD_VM_LANE`] that is a failure: the
/// lane declared itself a VM lane and `lane_fault` says what it did not
/// provide. Otherwise print the skip line carrying `skip_reason` and return
/// `false` so the test returns early.
#[expect(
    clippy::panic,
    reason = "test support: a lane that declared itself a VM lane cannot skip"
)]
fn skip_or_fail_lane(skip_reason: &str, lane_fault: &str) -> bool {
    if std::env::var_os(MINVMD_VM_LANE_ENV).is_some() {
        panic!(
            "guest_classifier_integration: {MINVMD_VM_LANE_ENV} is set: the lane \
             declared itself a VM lane and {lane_fault}"
        );
    }
    eprintln!("guest_classifier_integration: SKIPPED: {skip_reason}");
    false
}

/// The gvproxy switch to boot with when the e2e suite is enabled
/// (`MINVMD_E2E=1`), asserting the required env vars are present when so;
/// `None` when the suite skips.
fn e2e_enabled() -> Option<PathBuf> {
    if !common::e2e() {
        skip_or_fail_lane(
            "MINVMD_E2E != 1; the VM harness is opt-in",
            "did not opt into the VM harness (MINVMD_E2E != 1)",
        );
        return None;
    }
    for var in [
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "guest_classifier_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    // The switch is the guest's whole fabric: without it nothing can reach
    // out and nothing can be answered. Under MINVMD_E2E=1 the helper fetches
    // the pinned switch or panics.
    let Some(gvproxy) = common::gvproxy_bin() else {
        skip_or_fail_lane(
            "no gvproxy switch, so the guest has no fabric to reach out on",
            "exported no switch binary and none could be fetched",
        );
        return None;
    };
    Some(gvproxy)
}

/// A booted minimald guest VM under a detached supervisor, stopped on drop.
struct Guest {
    sock_path: PathBuf,
    boot_log_path: PathBuf,
    gvproxy: PathBuf,
    /// The VMM child's pid from `status --json`, killed directly when
    /// `minvmd stop` fails.
    vmm_pid: Option<u32>,
    _state: TempDir,
}

impl Drop for Guest {
    fn drop(&mut self) {
        // Panic-safe teardown that never leaks the detached supervisor (and
        // its gvproxy) whose state dir the `TempDir` then unlinks out from
        // under it; bounded, so a wedged daemon cannot hang the teardown.
        let stopped = match try_minvmd(self._state.path(), &self.gvproxy, &["stop"]) {
            Ok(out) if out.status.success() => return,
            Ok(out) => format!(
                "exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ),
            Err(e) => e,
        };
        eprintln!("guest_classifier_integration: minvmd stop failed ({stopped})");
        if let Some(pid) = self.vmm_pid.and_then(|p| libc::pid_t::try_from(p).ok()) {
            eprintln!("guest_classifier_integration: killing VMM pid {pid}");
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
            panic!("guest_classifier_integration: {e}")
        }
    })
}

/// [`minvmd`] without the panic. The env the VM needs (`MINVMD_VM_OWN_IP`,
/// the guest `RUST_LOG`, the pinned node ports, `MINVMD_GVPROXY_BIN`) is
/// inherited by the detached supervisor and its VMM child, so it is set on
/// every call. stdin is off the terminal, or libkrun's console setup stops
/// the process group. stdout and stderr are drained on reader threads while
/// the child runs, so a chatty child cannot fill a pipe and stall into the
/// timeout.
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
        // The guest's node ports, pinned, so the inbound proof's proxy is
        // at its documented default.
        .env("MINVMD_NODE_PROXY_PORT", NODE_PROXY_PORT)
        .env("MINVMD_NODE_ANSWERER_PORT", NODE_ANSWERER_PORT)
        // `--timeout` bounds only `run --detach`'s own poll; the VMM
        // parent's guest READY wait reads this env (60 s default), and a
        // cold boot can spend 40-70 s before pid-1, so pin it here rather
        // than rely on the justfile's export reaching a bare nextest run.
        .env("MINVMD_READY_TIMEOUT_SECS", DETACH_TIMEOUT_SECS)
        .env("RUST_LOG", GUEST_LOG_FILTER)
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
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(50));
            }
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

impl Guest {
    /// Boots the supervised VM with minimald as the guest init (`minvmd run
    /// --detach`, which stands up the host gvproxy switch before the VMM
    /// child boots) and polls `status --json` until Running. Panics past the
    /// deadlines, quoting the supervisor's `run.log`.
    fn boot(gvproxy: &Path) -> Guest {
        let state = short_state_dir();
        let provider_dir = state.path().join("minimal/providers/local-minvmd0");
        let boot_log_path = std::env::var_os("MINVMD_BOOT_LOG")
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| provider_dir.join("boot.log"));
        let mut guest = Guest {
            sock_path: provider_dir.join("ssh.sock"),
            boot_log_path,
            gvproxy: gvproxy.to_path_buf(),
            vmm_pid: None,
            _state: state,
        };
        let run = minvmd(
            guest._state.path(),
            gvproxy,
            &["run", "--detach", "--timeout", DETACH_TIMEOUT_SECS],
        );
        assert!(
            run.status.success(),
            "guest_classifier_integration: minvmd run --detach failed: {}\n--- run.log ---\n{}\n\
             are MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH/MINVMD_INITRAMFS set correctly \
             (and libkrun >= 1.19.0)?",
            String::from_utf8_lossy(&run.stderr),
            guest.run_log(),
        );
        let deadline = Instant::now() + RUNNING_TIMEOUT;
        loop {
            let status = minvmd(guest._state.path(), gvproxy, &["status", "--json"]);
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
                "guest_classifier_integration: VM never reached Running within {RUNNING_TIMEOUT:?}; \
                 last status: {status}\n--- run.log ---\n{}",
                guest.run_log(),
            );
            std::thread::sleep(Duration::from_millis(200));
        }
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

    /// The guest daemon's own console so far — pid-1's stdout rides the
    /// serial console into the boot log, so the classifier's boot lines and
    /// per-launch records read here. Invalid UTF-8 is replaced rather than
    /// losing the whole log.
    fn boot_log(&self) -> String {
        match std::fs::read(&self.boot_log_path) {
            Ok(bytes) => strip_ansi(&String::from_utf8_lossy(&bytes)),
            Err(e) => format!("(no boot log at {}: {e})", self.boot_log_path.display()),
        }
    }

    /// The boot-log lines carrying any of `needles`.
    fn boot_log_lines(&self, needles: &[&str]) -> Vec<String> {
        self.boot_log()
            .lines()
            .filter(|line| needles.iter().any(|needle| line.contains(needle)))
            .map(str::to_string)
            .collect()
    }

    /// Whether `needle` appears on the guest's console within
    /// [`LOG_DEADLINE`] — the classifier's lines are written at boot, before
    /// the guest serves, so a healthy guest has them by the time this is
    /// asked and the deadline only covers the flush.
    fn boot_log_contains(&self, needle: &str) -> bool {
        let end = Instant::now() + LOG_DEADLINE;
        loop {
            if self.boot_log().contains(needle) {
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    /// The digest of the exact bytes the guest piped to `nft -f -`, off the
    /// load line the boot wrote it on — `sha256=<hex>` on the line that says
    /// the table loaded and the marker was written.
    fn load_digest(&self) -> Option<String> {
        let line = self
            .boot_log_lines(&["loaded the guest's classifier table and wrote its presence marker"])
            .pop()?;
        let hex = line.split("sha256=").nth(1)?.split_whitespace().next()?;
        (hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hex.to_ascii_lowercase())
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

/// One resident box: a session the guest daemon launched, whose declared
/// egress this test set at creation. The SSH handle is kept open for the
/// box's lifetime; every exec joins the session's sandbox (the box).
struct BoxSession {
    handle: russh::client::Handle<ClientHandler>,
    /// The session record's id: scoping the execs' env.
    session_id: String,
    /// The session's name: the zone name it registered, `<name>.min.internal`.
    name: String,
}

impl BoxSession {
    /// Opens one resident box: creates the session over the bridge UDS with
    /// `network` and the declared egress policy, uploads a `minimal.toml`
    /// carrying the pinned package source (plus the `packages` this test's
    /// execs need), composes the loadout (gating whatever comes back
    /// pending), finalizes the record, and keeps the handle for execs.
    async fn open(
        sock_path: &Path,
        network: sessions::NetworkMode,
        egress: Option<sessions::EgressPolicy>,
        label: &str,
        packages: &[&str],
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

        // Unique per invocation — minimald dedups sessions by name and
        // rejects a duplicate CreateSession (`AlreadyExists`), and a record
        // persists once created even when a later step of this open fails.
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let name = format!("guest-classifier-{label}-{uniq:x}");

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
                egress,
                ..Default::default()
            };
            let req = CreateSessionRequest {
                config: minimald_rpc::SessionConfig {
                    name: Some(name.clone()),
                    project_path: paths::HostAbsPath::try_new("/tmp")
                        .map_err(|e| format!("project_path: {e}"))?,
                    network,
                    policy,
                    // No registration happened on this path: the box attaches
                    // as an unregistered one always has.
                    task_addresses: Vec::new(),
                    box_id: None,
                    box_addresses: None,
                    // The serde default; this session only runs execs, so it
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

        // The project's `minimal.toml` over SFTP: the pinned package source
        // the composer resolves the packages below against, plus the
        // packages this test's execs need (`python` carries the interpreter
        // the probes run in).
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
            let mut contents = common::PKGS_UPSTREAM.to_string();
            if !packages.is_empty() {
                contents.push_str(&format!(
                    "\n[session]\npackages = [{}]\n",
                    packages
                        .iter()
                        .map(|p| format!("\"{p}\""))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
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

        // ConfigureLoadout, then FinalizeSession: the record
        // `Materializing -> Active`, so the execs below pass the daemon's
        // status gate, and the session's name is registered in the zone
        // (which is what its own lookups and the proxy route by).
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
                .map_err(|e| format!("read ConfigureLoadout response: {e}"))?;
            let resp: <ConfigureLoadout as OneshotSshRpc>::Response =
                serde_json_lenient::from_slice(&resp_buf)
                    .map_err(|e| format!("decode ConfigureLoadout response: {e}"))?;
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
                .map_err(|e| format!("read FinalizeSession response: {e}"))?;
            let resp: <FinalizeSession as OneshotSshRpc>::Response =
                serde_json_lenient::from_slice(&resp_buf)
                    .map_err(|e| format!("decode FinalizeSession response: {e}"))?;
            resp.ok()
                .ok_or_else(|| "FinalizeSession returned an error".to_string())?;
        }

        Ok(BoxSession {
            handle,
            session_id: session_id.to_string(),
            name,
        })
    }

    /// Runs one command in the box — the session's sandbox — and returns
    /// `(stdout, stderr, exit_status)`. Bounded by [`EXEC_TIMEOUT`]; the
    /// daemon reports a box that cannot launch on stderr, so a nonzero
    /// exit's message carries its cause.
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
        loop {
            let msg = tokio::time::timeout(EXEC_TIMEOUT, channel.wait())
                .await
                .map_err(|_| format!("exec did not finish within {EXEC_TIMEOUT:?}"))?;
            let Some(msg) = msg else {
                break;
            };
            match msg {
                ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                ChannelMsg::ExtendedData { data, .. } => stderr.extend_from_slice(&data),
                ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
                ChannelMsg::Failure => {
                    return Err("exec request rejected (CHANNEL_FAILURE)".into());
                }
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

/// Opens one resident box, retrying the whole open to absorb the post-READY
/// startup race the session harness documents. A refusal that is not the
/// race — the guest refusing a deny-all box it cannot decide per box — fails
/// every attempt with the same words and surfaces as this test's failure.
/// The guest's console with its ANSI escape sequences removed. The daemon's
/// tracing output is coloured, so a structured field reads
/// `key\x1b[0m\x1b[2m=\x1b[0mvalue` on the console, and a plain `key=value`
/// needle would never match it.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

async fn open_box(
    guest: &Guest,
    network: sessions::NetworkMode,
    egress: Option<sessions::EgressPolicy>,
    label: &str,
    packages: &[&str],
) -> Result<BoxSession, String> {
    let mut last = String::new();
    for _ in 1..=6 {
        match BoxSession::open(&guest.sock_path, network, egress.clone(), label, packages).await {
            Ok(box_session) => return Ok(box_session),
            Err(e) => {
                last = e;
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(format!(
        "{last}\n--- guest boot log ---\n{}",
        guest.boot_log()
    ))
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
        "guest_classifier_integration: unexpected pending {domain}(s): {}",
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
        "guest_classifier_integration: ConfigureLoadout pending: {} vars, {} patches, {} hooks",
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
    let body = serde_json_lenient::to_vec(&verdict)
        .map_err(|e| format!("serialize SubmitVerdict request: {e}"))?;
    let mut rpc = channel.into_stream();
    rpc.write_all(&body)
        .await
        .map_err(|e| format!("write SubmitVerdict request: {e}"))?;
    rpc.shutdown()
        .await
        .map_err(|e| format!("shutdown SubmitVerdict write half: {e}"))?;
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

// --- the proofs ---

/// `nft -c`'s verdict on the rendered table, as the guest's boot logged it —
/// the check line the guest image's builder reads, and the load line that
/// follows it with the digest of exactly the bytes piped to `nft -f -`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_kernel_accepts_rendered_ruleset() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);

    // The check is the guest kernel's own verdict on the rendered text — the
    // one expression the image is being fixed to carry — and it is logged as
    // its own line, with nft's own error when it refuses.
    if !guest.boot_log_contains("the guest's nft -c accepted the rendered classifier table") {
        // The refusal branch: the image owes the kernel expressions the
        // table uses, and nft's own words — naming the missing expression —
        // are the diagnosis this test fails carrying, never a quiet miss.
        let refusal =
            guest.boot_log_lines(&["nft -c did not accept the rendered classifier table"]);
        panic!(
            "the guest's nft -c did not accept the rendered classifier table; \
             the boot log carries {} refusal line(s) for the image's builder:\n{}\n\
             --- whole boot log ---\n{}",
            refusal.len(),
            refusal.join("\n"),
            guest.boot_log(),
        );
    }
    // A check that accepted is only half the proof: the load must have run
    // too, in the one transaction after it, and the load line is where the
    // boot records that the table is in the kernel now.
    assert!(
        guest
            .boot_log_contains("loaded the guest's classifier table and wrote its presence marker"),
        "the guest's nft -c accepted the rendered table but no load line followed; \
         the boot log should carry the load's outcome and digest:\n{}",
        guest.boot_log(),
    );
}

/// The digest the guest's boot logged over the bytes it piped to `nft`'s
/// stdin equals the sha256 of the native installer's `--print-ruleset`
/// output for the same parameters: the same render function whose bytes the
/// installer's own load path pipes straight into `nft -f -` and prints the
/// digest of, so a guest table that drifted from the native installer's —
/// a different script, a different render, a re-render — fails here by
/// naming both digests.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_loaded_ruleset_matches_native_print_ruleset() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);

    let Some(loaded) = guest.load_digest() else {
        panic!(
            "the guest's boot logged no load digest; the load line should carry \
             sha256=<hex> over the exact bytes piped to nft:\n{}",
            guest.boot_log(),
        );
    };
    let native = native_ruleset_digest();
    assert_eq!(
        loaded,
        native,
        "the guest's loaded table is not the native installer's render for the same \
         parameters: the digest the guest logged over the bytes it piped to nft must \
         equal the sha256 of the installer's --print-ruleset output (the same render \
         function whose bytes the installer's own load path pipes and digests)\n\
         --- guest boot log ---\n{}",
        guest.boot_log(),
    );
}

/// The table the guest's marker vouches for is listed in the guest's own
/// kernel: the daemon's recheck before a host-address launch runs
/// `nft list table inet minimal_class` and requires its `deny_out` chain, so
/// the deny-all box that launches is the listing's observable — a table gone
/// behind its marker is its own warn line and refuses the box instead.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_classifier_table_present() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);

    assert!(
        guest
            .boot_log_contains("loaded the guest's classifier table and wrote its presence marker"),
        "the guest's boot did not load the classifier table:\n{}",
        guest.boot_log(),
    );
    // The launch that rechecks the listing: a deny-all host-address box,
    // whose leaf the table's verdict decides and whose own probe the next
    // tests read. A guest whose table was gone behind its marker warns here
    // and refuses the box, so the open failing is the recheck's negative.
    open_box(
        &guest,
        sessions::NetworkMode::HostNet,
        Some(sessions::EgressPolicy::deny_all()),
        "denyall",
        &["python"],
    )
    .await
    .expect("a deny-all box launches over a listed table");
    let gone = guest.boot_log_lines(&["the guest's marker stands over a table that is not there"]);
    assert!(
        gone.is_empty(),
        "the box launched but the launch's own table recheck warned the table away:\n{}",
        gone.join("\n"),
    );
}

/// A deny-all host-address box's outbound probe to an address off the guest —
/// the switch's gateway, the fabric's own far end — is refused by the loaded
/// table, and the errno the box reads is EHOSTUNREACH: `reject with icmpx
/// admin-prohibited` as IPv4 surfaces it, the same errno the daemon's own
/// effect probe reads per family.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_deny_all_probe_refused() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);
    let mut box_session = open_box(
        &guest,
        sessions::NetworkMode::HostNet,
        Some(sessions::EgressPolicy::deny_all()),
        "denyall",
        &["python"],
    )
    .await
    .expect("a deny-all box launches on a guest whose table is loaded");

    // The gateway is the address off the guest its fabric answers at: the
    // one destination a box's egress would have to traverse, refused by the
    // deny chain before any translation.
    let gateway = switch::DEFAULT_SUBNET.gateway();
    let probe = format!(
        "python3 -c 'import socket\n\
         s = socket.socket()\n\
         s.settimeout(10)\n\
         print(s.connect_ex((\"{gateway}\", 443)))'"
    );
    let (stdout, stderr, exit) = box_session
        .exec(&probe)
        .await
        .expect("the box runs its own probe");
    let errno = stdout.trim().parse::<i32>().unwrap_or(i32::MAX);
    assert_eq!(
        exit,
        Some(0),
        "the probe did not run in the box; stderr: {stderr}"
    );
    assert_eq!(
        errno,
        ERRNO_EHOSTUNREACH,
        "the deny-all box's outbound probe must read EHOSTUNREACH ({ERRNO_EHOSTUNREACH}), \
         the icmpx admin-prohibited verdict as IPv4 surfaces it; got errno {errno}\n\
         --- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- guest boot log ---\n{}",
        guest.boot_log(),
    );
}

/// A deny-all host-address box still resolves (NET-003, NET-079): its one
/// carve-out is the resolver Minimal owns for it, which on a VM-backed host is
/// the node's DNS layer at the gateway, port 53 over UDP and TCP. Four reads
/// from inside the box:
///
/// - `a`: its lookup of `host.min.internal` through its own `/etc/resolv.conf`
///   answers the switch's host alias, the address the zone holds for the host;
/// - `aaaa`: a raw AAAA query to the gateway comes back NOERROR with no
///   answers, the NODATA the node's DNS layer on the daemon's relay answers
///   itself (NET-136), and the guest's console carries that layer's own line
///   for it under the node's label, so the lookup travelled the layer;
/// - `tcp`: a TCP connect to the gateway's port 53 is not refused by the
///   table (it connects, or the resolver itself resets it), so the TCP half
///   of the carve-out is rendered;
/// - `reach`: a connect to the address it resolved is refused with an errno
///   in the reject set, so the box resolves the name and reaches nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_deny_all_resolver_reachable() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);
    let mut box_session = open_box(
        &guest,
        sessions::NetworkMode::HostNet,
        Some(sessions::EgressPolicy::deny_all()),
        "denydns",
        &["python"],
    )
    .await
    .expect("a deny-all box launches on a guest whose table is loaded");

    assert!(
        guest.boot_log_contains(
            "deny-all host-address box on VM host: resolver carve-out is the node's DNS \
             layer at the gateway, port 53 over udp and tcp"
        ),
        "the guest's render did not log the gateway resolver carve-out:\n{}",
        guest.boot_log(),
    );

    // Python's blocks need their indentation, which a `\`-continued Rust
    // literal strips, so the script is joined from lines that keep it. The
    // AAAA query for example.com is hex, so no quoting reaches it.
    let gateway = switch::DEFAULT_SUBNET.gateway();
    let host_alias = switch::DEFAULT_SUBNET.host_alias();
    let script = [
        "import socket".to_string(),
        "def a():".to_string(),
        "    infos = socket.getaddrinfo(\"host.min.internal\", 80, socket.AF_INET, \
         socket.SOCK_STREAM)"
            .to_string(),
        "    return \",\".join(sorted({i[4][0] for i in infos}))".to_string(),
        "def aaaa():".to_string(),
        "    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)".to_string(),
        "    u.settimeout(5)".to_string(),
        format!("    u.connect((\"{gateway}\", 53))"),
        "    q = bytes.fromhex(\"123401000001000000000000076578616d706c6503636f6d00001c0001\")"
            .to_string(),
        "    try:".to_string(),
        "        u.send(q)".to_string(),
        "        r = u.recv(512)".to_string(),
        "    except socket.timeout:".to_string(),
        "        return \"timeout\"".to_string(),
        "    except OSError as e:".to_string(),
        "        return \"errno \" + str(e.errno)".to_string(),
        "    return str(r[3] & 15) + \" \" + str(int.from_bytes(r[6:8], \"big\"))".to_string(),
        "def tcp():".to_string(),
        "    t = socket.socket()".to_string(),
        "    t.settimeout(5)".to_string(),
        "    try:".to_string(),
        format!("        return str(t.connect_ex((\"{gateway}\", 53)))"),
        "    except socket.timeout:".to_string(),
        "        return \"timeout\"".to_string(),
        "def reach(addr):".to_string(),
        "    s = socket.socket()".to_string(),
        "    s.settimeout(10)".to_string(),
        "    try:".to_string(),
        "        return str(s.connect_ex((addr, 80)))".to_string(),
        "    except socket.timeout:".to_string(),
        "        return \"timeout\"".to_string(),
        "resolved = a()".to_string(),
        "print(\"a\", resolved)".to_string(),
        "print(\"aaaa\", aaaa())".to_string(),
        "print(\"tcp\", tcp())".to_string(),
        "print(\"reach\", reach(resolved.split(\",\")[0]))".to_string(),
    ]
    .join("\n");
    let (stdout, stderr, exit) = box_session
        .exec(&format!("python3 -c '{script}'"))
        .await
        .expect("the box runs its own lookups");
    assert_eq!(
        exit,
        Some(0),
        "the lookups did not run in the box; stderr: {stderr}"
    );
    let read = |what: &str| {
        stdout
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{what} ")))
            .unwrap_or("missing")
            .to_string()
    };
    let context = || {
        format!(
            "--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}\n--- guest boot log ---\n{}",
            guest.boot_log()
        )
    };

    let resolved = read("a");
    assert_eq!(
        resolved,
        host_alias.to_string(),
        "a deny-all box must resolve host.min.internal to the host alias through the \
         gateway's resolver\n{}",
        context(),
    );

    let aaaa = read("aaaa");
    assert_eq!(
        aaaa,
        "0 0",
        "the AAAA lookup must come back NODATA (rcode 0, no answers) from the node's \
         DNS layer\n{}",
        context(),
    );
    assert!(
        guest
            .boot_log_lines(&["answered a lookup at the relay"])
            .iter()
            .any(|line| line.contains("switch_addr=node")
                && line.contains("example.com")
                && line.contains("answer=NoError")),
        "the node's DNS layer on the daemon's relay never answered the box's AAAA lookup; \
         the lookup did not travel it\n{}",
        context(),
    );

    let reject_set = [
        ERRNO_EHOSTUNREACH.to_string(),
        ERRNO_EACCES.to_string(),
        ERRNO_EPERM.to_string(),
    ];
    let tcp = read("tcp");
    assert!(
        tcp == "0" || tcp == ERRNO_ECONNREFUSED.to_string(),
        "a deny-all box's tcp 53 to the gateway {gateway} must pass the table (connect, or \
         the resolver's own reset); read {tcp}\n{}",
        context(),
    );

    let reach = read("reach");
    assert!(
        reject_set.contains(&reach),
        "a deny-all box must reach nothing it resolves: its connect to {resolved}:80 must \
         read an errno in EHOSTUNREACH, EACCES and EPERM; read {reach}\n{}",
        context(),
    );
}

/// A deny-all box answers what reaches it: a connection another box opens to
/// it through the hostname proxy — the proxy's connect from outside the deny
/// subtree, the box's own reply admitted in the reply direction — so the box
/// serves while everything it originates is still refused.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_deny_all_box_answers_inbound_through_the_proxy() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);
    let mut serving = open_box(
        &guest,
        sessions::NetworkMode::HostNet,
        Some(sessions::EgressPolicy::deny_all()),
        "denysrv",
        &["python"],
    )
    .await
    .expect("the deny-all box that serves is a box this guest decided per box");
    // A second, plain host-address box as the client: its own egress is
    // unenforced (no declaration, so the allow subtree), and its request to
    // the deny-all box's name rides the hostname proxy the guest serves at
    // the pinned in-guest port.
    let mut client = open_box(
        &guest,
        sessions::NetworkMode::HostNet,
        None,
        "client",
        &["python"],
    )
    .await
    .expect("the plain box that asks is an ordinary launch");
    // Launch each box with a no-op exec, one after the other. A box's first
    // exec fetches its package closure, so the second launch reads the cache
    // the first one filled. Otherwise both fetches run inside the concurrent
    // exchange below, where they have outrun EXEC_TIMEOUT.
    for (label, session) in [("server", &mut serving), ("client", &mut client)] {
        let (_, stderr, exit) = session
            .exec("true")
            .await
            .unwrap_or_else(|e| panic!("the {label} box's launch exec ran: {e}"));
        assert_eq!(
            exit,
            Some(0),
            "the {label} box did not launch; stderr: {stderr}"
        );
    }

    const SERVE_PORT: u16 = 8412;
    // One-shot server in the deny-all box: bind, accept one, answer, exit.
    let server_cmd = format!(
        "python3 -c 'import socket\n\
         s = socket.socket()\n\
         s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n\
         s.bind((\"127.0.0.1\", {SERVE_PORT}))\n\
         s.listen(1)\n\
         s.settimeout(20)\n\
         c, _ = s.accept()\n\
         c.recv(4096)\n\
         c.sendall(b\"HTTP/1.1 200 OK\\r\\nContent-Length: 2\\r\\nConnection: close\\r\\n\\r\\nok\")\n\
         c.close()\n\
         print(\"served\")'"
    );
    // The client's request through the proxy, retried until the server is
    // accepting: the proxy connects to the box only once it has the head,
    // and a connect that beat the server's bind reads as a gateway error
    // the client simply tries again.
    let fqdn = format!("{}.min.internal", serving.name);
    // Python's blocks need their indentation, which a `\`-continued Rust
    // literal strips from every continued line, so the script is joined
    // from lines that keep it.
    let client_script = [
        "import socket, time".to_string(),
        "deadline = time.time() + 20".to_string(),
        "last = \"none\"".to_string(),
        "while True:".to_string(),
        "    try:".to_string(),
        format!(
            "        s = socket.create_connection((\"127.0.0.1\", {NODE_PROXY_PORT}), timeout=10)"
        ),
        format!(
            "        s.sendall(\"GET http://{fqdn}:{SERVE_PORT}/ HTTP/1.1\\r\\nHost: {fqdn}:{SERVE_PORT}\\r\\nConnection: close\\r\\n\\r\\n\".encode())"
        ),
        "        buf = b\"\"".to_string(),
        "        while True:".to_string(),
        "            chunk = s.recv(4096)".to_string(),
        "            if not chunk:".to_string(),
        "                break".to_string(),
        "            buf += chunk".to_string(),
        "        s.close()".to_string(),
        "        if b\"200 OK\" in buf:".to_string(),
        "            print(buf.decode(errors=\"replace\"))".to_string(),
        "            break".to_string(),
        "        last = buf.decode(errors=\"replace\").splitlines()[:1]".to_string(),
        "    except OSError as e:".to_string(),
        "        last = repr(e)".to_string(),
        "    if time.time() > deadline:".to_string(),
        "        print(\"no-answer\", last)".to_string(),
        "        break".to_string(),
        "    time.sleep(1)".to_string(),
    ]
    .join("\n");
    let client_cmd = format!("python3 -c '{client_script}'");
    let (served, asked) = tokio::join!(
        tokio::time::timeout(EXEC_TIMEOUT * 2, serving.exec(&server_cmd)),
        tokio::time::timeout(EXEC_TIMEOUT * 2, client.exec(&client_cmd)),
    );
    // The client's result first: a request the proxy never delivered is
    // named by what the client met, not by the server's idle accept.
    let (asked_out, asked_err, asked_exit) = asked
        .expect("the client exec did not time out")
        .expect("the client exec ran");
    assert_eq!(
        asked_exit,
        Some(0),
        "the plain box's request did not run; stderr: {asked_err}"
    );
    assert!(
        asked_out.contains("200 OK") && asked_out.contains("ok"),
        "a connection another box opened to the deny-all box through the proxy \
         was not answered; the deny-all box must serve what reaches it\n\
         --- stdout ---\n{asked_out}\n--- stderr ---\n{asked_err}\n--- guest boot log ---\n{}",
        guest.boot_log(),
    );
    let (served_out, served_err, served_exit) = served
        .expect("the server exec did not time out")
        .expect("the server exec ran");
    assert_eq!(
        served_exit,
        Some(0),
        "the deny-all box's server did not run; stderr: {served_err}"
    );
    assert!(
        served_out.contains("served"),
        "the deny-all box never served the connection that reached it\n\
         --- stdout ---\n{served_out}\n--- stderr ---\n{served_err}"
    );
}

/// The launch's own record says `host_ip_enforcement=per_box`: the per-launch
/// classifier line names the subtree the declaration picked, the leaf the
/// launch placed it in, and the fresh fact the launch's probe just read — the
/// field is `pub(crate)` and not on the wire (issue #1773), so this console
/// line is the record that carries it, and the session's own name ties it to
/// the one box this test launched.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_host_ip_enforcement_per_box_after_load() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);
    let mut box_session = open_box(
        &guest,
        sessions::NetworkMode::HostNet,
        Some(sessions::EgressPolicy::deny_all()),
        "denyall",
        &["python"],
    )
    .await
    .expect("a deny-all box launches on a guest whose table is loaded");

    // The per-launch classifier line is written when the box's leaf is
    // placed, which is at its first launch, not at create: run one command
    // so the launch happens, then read its line within the log deadline.
    let (_, stderr, exit) = box_session
        .exec("true")
        .await
        .expect("the box runs a command");
    assert_eq!(exit, Some(0), "the box's launch failed; stderr: {stderr}");
    let launch_lines = |guest: &Guest| {
        guest
            .boot_log_lines(&["host_ip_enforcement="])
            .into_iter()
            .filter(|line| line.contains(&box_session.name))
            .collect::<Vec<_>>()
    };
    let end = Instant::now() + LOG_DEADLINE;
    let mut recorded = launch_lines(&guest);
    while recorded.is_empty() && Instant::now() < end {
        tokio::time::sleep(Duration::from_millis(200)).await;
        recorded = launch_lines(&guest);
    }
    assert!(
        !recorded.is_empty(),
        "the launch of {} recorded no per-launch classifier line; on a guest whose \
         table is loaded the launch's own record must exist and say per_box:\n{}",
        box_session.name,
        guest.boot_log(),
    );
    for line in &recorded {
        assert!(
            line.contains("host_ip_enforcement=per_box"),
            "a launch of this box must be decided per box on a guest whose table is \
             loaded — never `none`:\n{line}\n--- guest boot log ---\n{}",
            guest.boot_log(),
        );
        assert!(
            line.contains(
                "the host-address box's egress verdict is decided on its classifier leaf"
            ),
            "the launch's own record must name the decision it made:\n{line}",
        );
        assert!(
            line.contains("deny"),
            "a deny-all declaration places its leaf in the deny subtree, and the line \
             names the subtree it picked:\n{line}",
        );
    }
}

/// Every effect probe the guest ran reads a refusal per family with an errno
/// inside EHOSTUNREACH, EACCES and EPERM — EHOSTUNREACH on 127.0.0.1,
/// EACCES on ::1 wherever IPv6 loopback is enabled (the guest boots with
/// `ipv6.disable=1`, so it probes IPv4 only) — and no probe connected,
/// timed out or read an errno the chain never reads as, which is what makes
/// every `per_box` verdict above rest on a family-by-family refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun, kernel/rootfs/initramfs images, and the gvproxy switch"]
async fn guest_effect_probe_errno_per_family() {
    let Some(gvproxy) = e2e_enabled() else {
        return;
    };
    let guest = Guest::boot(&gvproxy);
    // A host-address launch is what reads the table's effect; the start-time
    // probe at boot has already run one.
    open_box(
        &guest,
        sessions::NetworkMode::HostNet,
        Some(sessions::EgressPolicy::deny_all()),
        "denyall",
        &["python"],
    )
    .await
    .expect("a deny-all box launches on a guest whose table is loaded");

    let refused =
        guest.boot_log_lines(&["refused the probe out of a deny leaf on every family read"]);
    assert!(
        !refused.is_empty(),
        "no effect probe the guest ran recorded a refusal; the per-family evidence a \
         per_box verdict rests on is missing from the console:\n{}",
        guest.boot_log(),
    );
    for line in &refused {
        let families = probe_families(line);
        assert!(
            families.iter().any(|(family, _)| *family == FAMILY_V4),
            "a probe record must name the IPv4 family it read:\n{line}",
        );
        for (family, observed) in families {
            let errno = observed
                .strip_prefix("refused, errno ")
                .and_then(|digits| digits.parse::<i32>().ok());
            let Some(errno) = errno else {
                panic!(
                    "the probe's {family} leg was not refused: {observed:?} — a family that \
                     connected, timed out or failed outside the reject set makes the whole \
                     probe read none, never per_box:\n{line}"
                );
            };
            assert!(
                errno == ERRNO_EHOSTUNREACH || errno == ERRNO_EACCES || errno == ERRNO_EPERM,
                "the probe's {family} leg read errno {errno}, outside EHOSTUNREACH \
                 ({ERRNO_EHOSTUNREACH}), EACCES ({ERRNO_EACCES}) and EPERM ({ERRNO_EPERM}):\n{line}",
            );
            let expected = if family == FAMILY_V4 {
                ERRNO_EHOSTUNREACH
            } else {
                ERRNO_EACCES
            };
            assert_eq!(
                errno, expected,
                "the {family} family's admin-prohibited refusal surfaces as {expected}, \
                 the design's per-family expectation:\n{line}",
            );
        }
    }
    // The readings that would have made the guest report none instead: a
    // probe that connected, timed out or read an errno outside the set, a
    // control leg the daemon could not place, or a probe that never ran
    // because the boot loaded no table. None may appear on a guest whose
    // boxes launched per_box.
    let not_refused = guest.boot_log_lines(&[
        "did not refuse the probe",
        "effect could not be read",
        "the table's effect was never read",
    ]);
    assert!(
        not_refused.is_empty(),
        "a probe the guest ran did not read the loaded table's refusal:\n{}",
        not_refused.join("\n"),
    );
}

/// The per-family observations one probe record carries: the record's
/// parenthesised tail, one `(family, observation)` pair per family the probe
/// read, the observation verbatim as the probe spelled it (`refused, errno
/// 113`, `connected`, …). The observation itself contains commas, so the
/// entries are delimited by the next family's name, never by a naive split.
fn probe_families(record: &str) -> Vec<(&str, &str)> {
    let Some(open) = record.rfind('(') else {
        return Vec::new();
    };
    let tail = &record[open + 1..];
    let tail = tail.split(')').next().unwrap_or_default();
    let mut spots: Vec<(usize, &str)> = Vec::new();
    for family in [FAMILY_V4, FAMILY_V6] {
        let mut from = 0;
        while let Some(at) = tail[from..].find(family) {
            spots.push((from + at, family));
            from += at + family.len();
        }
    }
    spots.sort_unstable();
    spots
        .iter()
        .enumerate()
        .map(|(i, (at, family))| {
            let end = spots.get(i + 1).map_or(tail.len(), |(next, _)| *next);
            (*family, tail[at + family.len()..end].trim())
        })
        .collect()
}

/// The sha256 of the native installer's `--print-ruleset` output for the
/// guest's own parameters: the same tree root, the gateway's resolver as the
/// carve-out, the
/// two source identities the guest's boot hands as its one address
/// (NET-078), and the same ct-mark bits — rendered over a stand-in mount
/// table that spells the guest's own cgroup2 mount (`/sys/fs/cgroup`, root
/// `/`, nsdelegate), which is the one fact the render is told rather than
/// reads, and the only way this host-side render can name the guest's
/// hierarchy paths as the guest's own render derives them.
fn native_ruleset_digest() -> String {
    let workspace = common::workspace_root();
    let script = workspace.join("scripts/install-host-classifier.sh");
    let dir = tempfile::tempdir().expect("a scratch dir for the stand-in mount table");
    let mountinfo = dir.path().join("mountinfo");
    std::fs::write(
        &mountinfo,
        // The guest's own mount line, as its kernel wrote it: root `/` (the
        // initial namespace's view, which verify_mount requires), mountpoint
        // `/sys/fs/cgroup`, fs cgroup2, nsdelegate. The id numbers are the
        // stand-in's — the render reads only the covering mountpoint.
        "35 30 0:26 / /sys/fs/cgroup rw,relatime shared:2 - cgroup2 cgroup2 rw,nsdelegate\n",
    )
    .expect("writing the stand-in mount table");

    // NET-078 on an un-enrolled guest: the cohort's and the node plane's
    // source identities are both the guest's own address — the daemon's
    // switch address on the default subnet, which is what the guest's boot
    // renders with (`DEFAULT_SUBNET.daemon_ip()` in its `main`).
    let identity = switch::DEFAULT_SUBNET.daemon_ip();
    // The guest's resolver carve-out: the node's DNS layer at the switch
    // gateway (`DEFAULT_SUBNET.dns_server()` in its `main`).
    let resolver = switch::DEFAULT_SUBNET.dns_server();
    let out = Command::new("bash")
        .arg(&script)
        .args([
            "--print-ruleset",
            "--root",
            GUEST_TREE_ROOT,
            "--gateway-resolver",
            &resolver.to_string(),
            "--cohort-address",
            &identity.to_string(),
            "--node-plane-address",
            &identity.to_string(),
            "--ct-mark-mask",
            GUEST_CT_MARK_MASK_ARG,
        ])
        .env("MINIMAL_OVERRIDE_CGROUP_MOUNTINFO", &mountinfo)
        .output()
        .expect("running the installer's print-ruleset mode");
    assert!(
        out.status.success(),
        "the installer's --print-ruleset refused to render: {}",
        String::from_utf8_lossy(&out.stderr),
    );
    let digest = Sha256::digest(&out.stdout);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}
