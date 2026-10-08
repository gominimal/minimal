//! VM box egress under a hostname-only allowlist (NET-068).
//!
//! Boots a real microVM with the guest `minimald`, creates an `OwnIp` box whose
//! egress is only a list of toolchain hostnames, then runs NET-068's toolchain
//! inside it: `git clone`, `npm install`, `pip install`, and a container image
//! pull (with `skopeo`). The VM's only path out is through the host gvproxy
//! switch; the guest's relay enforces the DNS-pinned hostname allowlist at the
//! VM boundary. Every one of the four operations must exit 0 for the test to
//! pass.
//!
//! The `apt` leg the requirement text named before gominimal/minimal#1707 is
//! deliberately absent: the composed base at `gominimal/pkgs@f4de33d0` is not
//! a Debian userland and no package upstream carries apt, so an apt leg could
//! never exit 0 here. The spec change that trims NET-068 to these four tools
//! is the owner decision this test supplies the facts for.
//!
//! The VM is brought up through the supervisor path (`minvmd run --detach`,
//! then `status --json` until Running, `stop` on drop), like the sibling
//! harnesses: only `run` stands up the host gvproxy switch before the VMM
//! child boots, so a `boot --foreground` VM has no switch to dial and no
//! guest egress at all.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must point to
//!   the kernel, generic rootfs, and minimald initramfs cpio.
//! - `MINVMD_GVPROXY_BIN` must point to the host gvproxy switch: `just test-vm`
//!   fetches it and exports this variable.
//!
//! A missing precondition is reported as a skip, one stderr line of the form
//! `SKIPPED: hostname_allowlist_toolchain_completes: <reason>`, and the test
//! returns; it never claims a pass without the switch. A lane that exports
//! `MINVMD_VM_LANE` has declared itself a VM lane, and there the same missing
//! precondition panics instead of skipping, so the lane cannot go green on an
//! unexported switch binary.
//!
//! The test writes each tool's exit status and the boot-log admissions/drops
//! that arrived during it, so a stalled fetch names the host that was not
//! admitted (diagnostics requirement).

#![cfg(minvmd_libkrun)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serial_test::serial;
use sessions::core::decision::ItemDecision;
use sessions::core::hooks::{HookResult, PolicyHooks, Unapproved};
use sessions::core::policy::{HooksPolicy, PatchesPolicy, VarsPolicy};
use tempfile::TempDir;

mod common;

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

/// `run --detach --timeout`: the justfile exports 150 s for cold boots.
const DETACH_TIMEOUT_SECS: &str = "150";
/// How long `status --json` may take to report Running after `run --detach`
/// returns (it returns once the bridge UDS accepts, slightly ahead of the
/// Starting -> Running write).
const RUNNING_TIMEOUT: Duration = Duration::from_secs(90);
/// Bound on any one `minvmd` subcommand (`run --detach`, `status`, `stop`) so
/// a wedged daemon fails the test instead of hanging it.
const SUBPROC_TIMEOUT: Duration = Duration::from_secs(180);
const EXEC_TIMEOUT: Duration = Duration::from_secs(60);

/// Env var the server reads to scope an exec to a session.
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Host-side boot-console path. `std::env::var_os` result is empty-safe.
const MINVMD_BOOT_LOG_ENV: &str = "MINVMD_BOOT_LOG";

/// Host-side gvproxy path env.
const MINVMD_GVPROXY_BIN_ENV: &str = "MINVMD_GVPROXY_BIN";

/// Set by a lane that declares itself a VM lane: a missing precondition then
/// fails the test instead of skipping it.
const MINVMD_VM_LANE_ENV: &str = "MINVMD_VM_LANE";

/// A precondition is missing. Under `MINVMD_VM_LANE` that is a failure: the
/// lane declared itself a VM lane and `lane_fault` says what it did not
/// provide. Otherwise print the skip line carrying `skip_reason` and return
/// `false` so the test returns early.
fn skip_or_fail_lane(skip_reason: &str, lane_fault: &str) -> bool {
    if std::env::var_os(MINVMD_VM_LANE_ENV).is_some() {
        panic!(
            "hostname_allowlist_toolchain_completes: {MINVMD_VM_LANE_ENV} is set: the lane \
             declared itself a VM lane and {lane_fault}"
        );
    }
    eprintln!("SKIPPED: hostname_allowlist_toolchain_completes: {skip_reason}");
    false
}

/// Guest log filter that promotes the DNS-gate admission lines to debug.
const GUEST_LOG_FILTER: &str = "info,minimald::net::dns_gate=debug";

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so. Skips quietly when gvproxy is not
/// available, because an own-IP boot without it has no host-side switch.
fn e2e_enabled() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        return skip_or_fail_lane(
            "MINVMD_E2E != 1; the VM harness is opt-in",
            "did not opt into the VM harness (MINVMD_E2E != 1)",
        );
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
        return skip_or_fail_lane(
            "MINVMD_GVPROXY_BIN is not set; the host switch is required (see #1809)",
            "exported no switch binary (MINVMD_GVPROXY_BIN is not set)",
        );
    }
    true
}

/// A booted minimald guest VM, stopped on drop.
struct Guest {
    sock_path: PathBuf,
    /// The VM host daemon's box control socket, where the box is registered
    /// before its session is created, as `min session activate` does.
    control_sock: PathBuf,
    boot_log_path: PathBuf,
    boot_log_offset: usize,
    _state: TempDir,
}

impl Drop for Guest {
    fn drop(&mut self) {
        // Panic-safe teardown: a failed assertion must not leak the detached
        // supervisor (and its gvproxy) whose state dir the `TempDir` then
        // unlinks out from under it. Bounded, so a wedged daemon cannot hang
        // the teardown either.
        let _ = minvmd(self._state.path(), &["stop"]);
    }
}

/// Run one `minvmd` subcommand against the isolated state dir, bounded by
/// [`SUBPROC_TIMEOUT`]. The env the VM needs (`MINVMD_VM_OWN_IP`, the guest
/// `RUST_LOG`, `MINVMD_GVPROXY_BIN`) is inherited by the detached supervisor
/// and its VMM child, so it is set here on every call.
fn minvmd(state: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new(minvmd_bin());
    cmd.args(args)
        // HOME too, not just XDG_STATE_HOME, as belt-and-braces: any
        // `dirs`-based fallback that ignores XDG on macOS must also land in
        // the tempdir, never the developer's real state dir.
        .env("HOME", state)
        .env("XDG_STATE_HOME", state)
        .env("MINVMD_VM_OWN_IP", "1")
        // `--timeout` bounds only the detach poll; the VMM parent's guest
        // READY wait reads this env (60 s default), and a cold boot can
        // spend 40-70 s before pid-1, so pin it here rather than rely on
        // the justfile's export reaching a bare `cargo nextest` run.
        .env("MINVMD_READY_TIMEOUT_SECS", DETACH_TIMEOUT_SECS)
        .env("RUST_LOG", GUEST_LOG_FILTER)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(gvproxy) = std::env::var_os(MINVMD_GVPROXY_BIN_ENV) {
        cmd.env(MINVMD_GVPROXY_BIN_ENV, gvproxy);
    }
    let mut child = cmd.spawn().expect("spawning minvmd");
    let deadline = Instant::now() + SUBPROC_TIMEOUT;
    loop {
        if child.try_wait().expect("polling minvmd").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("minvmd {args:?} did not exit within {SUBPROC_TIMEOUT:?} (wedged daemon?)");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("collecting minvmd output")
}

fn json(out: &Output) -> serde_json_lenient::Value {
    serde_json_lenient::from_slice(&out.stdout).unwrap_or(serde_json_lenient::Value::Null)
}

impl Guest {
    /// Boots the supervised VM with minimald as the guest init
    /// (`minvmd run --detach`, which spawns the host gvproxy switch before the
    /// VMM child) and polls `status --json` until Running. Panics past the
    /// deadlines, quoting the supervisor's `run.log`.
    fn boot() -> Guest {
        let state = short_state_dir();
        let provider_dir = state.path().join("minimal/providers/local-minvmd0");
        let sock_path = provider_dir.join("ssh.sock");
        let control_sock = provider_dir.join(minvmd::control::CONTROL_SOCK_FILE);
        let boot_log_path = std::env::var_os(MINVMD_BOOT_LOG_ENV)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| provider_dir.join("boot.log"));

        // minimald boots as the initramfs `/init` (MINVMD_INITRAMFS, set by
        // the caller); the rootfs stays generic.
        let run = minvmd(
            state.path(),
            &["run", "--detach", "--timeout", DETACH_TIMEOUT_SECS],
        );
        let guest = Guest {
            sock_path,
            control_sock,
            boot_log_path,
            boot_log_offset: 0,
            _state: state,
        };
        assert!(
            run.status.success(),
            "egress_allowlist_integration: minvmd run --detach failed: {}\n--- run.log ---\n{}\n\
             are MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH/MINVMD_INITRAMFS set correctly \
             (and libkrun >= 1.19.0)?",
            String::from_utf8_lossy(&run.stderr),
            guest.run_log(),
        );

        let deadline = Instant::now() + RUNNING_TIMEOUT;
        loop {
            let status = json(&minvmd(guest._state.path(), &["status", "--json"]));
            if status.get("state").is_some_and(|s| s == "running")
                && status.get("vmm_pid").is_some_and(|p| p.is_number())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "egress_allowlist_integration: VM never reached Running within {RUNNING_TIMEOUT:?}; \
                 last status: {status}\n--- run.log ---\n{}",
                guest.run_log(),
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        guest
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

    /// Return the lines appended to the guest boot log since the last call,
    /// so each tool failure is paired with the admissions/drops that happened
    /// while it ran. The tail is filtered to the DNS-gate and policy messages
    /// so a chatty tool cannot push the admission/refusal evidence out of the
    /// cap; when nothing matched, the last 40 unfiltered lines are returned
    /// instead so the console is still visible. Invalid UTF-8 is replaced
    /// rather than losing the whole tail.
    fn tail_boot_log(&mut self) -> String {
        let bytes = match std::fs::read(&self.boot_log_path) {
            Ok(bytes) => bytes,
            Err(e) => return format!("(no boot log at {}: {e})", self.boot_log_path.display()),
        };
        // The offset counts raw bytes, never decoded ones: a lossy decode
        // widens each invalid byte to a three-byte replacement character, so
        // an offset taken from it could land past the next read's new bytes
        // or inside a character.
        let total_len = bytes.len();
        let new_bytes = if total_len >= self.boot_log_offset {
            &bytes[self.boot_log_offset..]
        } else {
            // Log was truncated/rotated; just print the whole current contents.
            &bytes[..]
        };
        self.boot_log_offset = total_len;
        let tail = String::from_utf8_lossy(new_bytes);
        // Keep only the evidence the DNS gate and policy warnings emit; the
        // diagnostics requirement is to name the host that was not admitted.
        // Match on the message text alone ("admitted a resolved name's
        // addresses for the window", "refused a resolved name's answers past
        // the per-name cap", "an allowed name resolved into a refused range",
        // and the switch's `rule_matched` refusals), never on a tracing target
        // or component field, which the guest console may not print.
        let mut lines: Vec<&str> = tail
            .lines()
            .filter(|line| {
                line.contains("admitted")
                    || line.contains("refused")
                    || line.contains("rule_matched")
            })
            .rev()
            .take(120)
            .collect();
        if lines.is_empty() {
            lines = tail.lines().rev().take(40).collect();
            lines.reverse();
            return format!(
                "(no admission/refusal lines; last {} unfiltered lines)\n{}",
                lines.len(),
                lines.join("\n")
            );
        }
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
        match create_toolchain_session(&guest.sock_path, &guest.control_sock).await {
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

    // NET-068's toolchain: git clone, npm install, pip install, and a container
    // pull. The hostname-only allowlist must admit every host these four tools
    // contact, and each must exit 0.
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
        "hostname-only allowlist toolchain operations failed: {failures:?}"
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
async fn create_toolchain_session(
    sock_path: &Path,
    control_sock: &Path,
) -> Result<sessions::SessionId, String> {
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

    let name = format!("hostname-allowlist-{uniq:x}");
    let egress = sessions::EgressPolicy {
        allow_protocols: Some(vec![sessions::IpProto::Tcp]),
        allow_subnets: Some(Vec::new()),
        allow_dns_hosts: Some(TOOLCHAIN_HOSTS.iter().map(|h| (*h).to_string()).collect()),
        deny_subnets: None,
    };
    // The box's row, filed with the VM host the way `min session activate`
    // files it: a box with no row is an unregistered source the gate drops
    // unconditionally (NET-085), its resolver queries included.
    let addresses = common::register_box(control_sock, &name, Some(egress.clone()))?;

    let req = CreateSessionRequest {
        config: minimald_rpc::SessionConfig {
            name: Some(name),
            project_path: paths::HostAbsPath::try_new("/tmp")
                .map_err(|e| format!("project_path: {e}"))?,
            network: sessions::NetworkMode::OwnIp,
            policy: sessions::SessionPolicy::new(Some(egress), None),
            // The addresses the registration handed back, so the in-VM
            // daemon attaches the box at its row's lease.
            box_addresses: Some(addresses),
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

/// The one variable the toolchain packages route back for approval: the
/// `node` package wires `NPM_CONFIG_CACHE` to a state-volume path through its
/// `env_state_wiring` attr (gominimal/pkgs `packages/node/build.ncl`), and no
/// other package in the set or its transitive closure declares any.
const EXPECTED_PENDING_VAR: &str = "NPM_CONFIG_CACHE";

/// Client-side policy gate for the pending items the daemon routes back. It
/// approves exactly [`EXPECTED_PENDING_VAR`] and fails the test on anything
/// else, naming the item, so a package that starts contributing another var,
/// a patch, or a hook surfaces here instead of being waved through.
struct ApproveExpectedVar;

impl PolicyHooks for ApproveExpectedVar {
    fn on_var_unapproved(
        &self,
        _policy: VarsPolicy,
        items: &[Unapproved<'_, str>],
    ) -> HookResult<VarsPolicy> {
        let decisions = items
            .iter()
            .map(|item| {
                assert_eq!(
                    item.item(),
                    EXPECTED_PENDING_VAR,
                    "unexpected pending var `{}` from {}",
                    item.item(),
                    item.source()
                );
                ItemDecision::AllowOnce
            })
            .collect();
        HookResult::decided(decisions)
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

/// Fail the test naming every item in a domain the harness expects to stay
/// empty. The gate only calls a hook with a non-empty batch, so this never
/// returns in practice.
fn refuse_unexpected<T, P>(domain: &str, items: &[Unapproved<'_, T>]) -> HookResult<P>
where
    T: ?Sized + std::fmt::Display,
{
    let named: Vec<String> = items
        .iter()
        .map(|item| format!("`{}` from {}", item.item(), item.source()))
        .collect();
    assert!(
        named.is_empty(),
        "unexpected pending {domain}(s): {}",
        named.join(", ")
    );
    HookResult::decided(Vec::new())
}

/// Phase 3 of the compose flow (see `crates/sessions/docs/COMPOSITION.md`):
/// gate the daemon's pending items with [`ApproveExpectedVar`] and ship the verdict
/// with `SubmitVerdict`. Package patches whose source does not exist on this
/// host come back `Ignored`; an `Approved` patch would need the
/// `WorkspacePatchesTarZst` upload the CLI performs, which this harness does
/// not, so it is reported rather than left to fail at `FinalizeSession`.
async fn submit_gated_verdict(
    handle: &mut russh::client::Handle<ClientHandler>,
    response: sessions::wire::request::ContributionResponse,
) -> Result<(), String> {
    use minimald_rpc::{OneshotSshRpc, SubmitVerdict};
    use sessions::wire::policy::WirePatchVerdict;
    use sessions::wire::request::SessionStep;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    eprintln!(
        "egress_allowlist_integration: ConfigureLoadout pending: {} vars, {} patches, {} hooks",
        response.vars.len(),
        response.patches.len(),
        response.lifecycle_hooks.len(),
    );
    let (verdict, _policy) = sessions::client::handler::handle_response(
        response,
        &[],
        sessions::core::policy::UserPolicy::empty(),
        &ApproveExpectedVar,
        sessions::core::compose::ComposeOptions::default(),
        &|name| std::env::var(name),
    )
    .map_err(|e| format!("gating pending items: {e}"))?;
    let approved_patches: Vec<String> = verdict
        .patches
        .iter()
        .filter_map(|p| match p {
            WirePatchVerdict::Approved { host_path, .. } => Some(host_path.as_str().to_owned()),
            _ => None,
        })
        .collect();
    if !approved_patches.is_empty() {
        return Err(format!(
            "pending patches resolved to host files this harness cannot upload: \
             {approved_patches:?}"
        ));
    }

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

/// `ConfigureLoadout` (gating whatever comes back pending), then
/// `FinalizeSession`.
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
            Some(ConfigureLoadoutResponse::Pending { response }) => {
                submit_gated_verdict(handle, response).await?;
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

        let req = FinalizeSessionRequest {
            session_id,
            report_shared_port_collisions: false,
        };
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
