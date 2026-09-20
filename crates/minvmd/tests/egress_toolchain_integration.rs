//! Hostname-only egress allowlist proof: a real toolchain completes (NET-068).
//!
//! `hostname_allowlist_toolchain_completes` boots a real guest, creates an
//! own-IP session whose egress is a hostname-only allowlist (no CIDR allows,
//! TCP plus the UDP the box's own DNS needs, `allow_dns_hosts` naming exactly
//! the real infrastructure hosts `apt`, `git clone`, `npm install`, `pip`,
//! and a container pull contact),
//! then dials each of those hosts from inside the session at the literal
//! endpoint the real tool hits first (a repo index, a smart-HTTP `info/refs`,
//! a registry manifest, ...). The guest rootfs carries no shell at all
//! (`session_shell.rs`: "the generic rootfs has no `/bin`"), so the session
//! materializes the `shell` stack (curl, and nothing else) the same way
//! `scripts/session-e2e.sh`'s guest-egress proof does — curl against the exact
//! endpoint each tool would dial is what stands in for the tool itself here,
//! rather than materializing five more toolchains just to prove a firewall
//! rule admits their traffic.
//!
//! Reuses the boot-and-bridge-exec shape `minimald_session_integration.rs`
//! established (no shared test-support module exists yet to pull it from).
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `MINVMD_E2E=1`: a runtime, not a compile-time, gate — deliberately NOT
//!   `#[ignore]`. Verified empirically (a throwaway crate, `cargo-nextest
//!   0.9.140`): a name filter that matches only an `#[ignore]`d test still
//!   exits 4 ("no tests to run"), the same as matching zero tests — nextest
//!   does not distinguish "matched but skipped for ignore" from "no match"
//!   for that exit code. `#[ignore]` here would make this task's own proof
//!   line, the bare `cargo nextest run -p minvmd
//!   hostname_allowlist_toolchain_completes` with no `--run-ignored`, fail
//!   that way on any host that compiles this file in. The runtime check
//!   below is the only gate: it self-skips (returns, passing trivially)
//!   whenever `MINVMD_E2E` is unset, so the same bare command still exits 0
//!   there. CI's VM-integration-harness step does select this test by binary
//!   name with `--run-ignored all` (`ci-linux-kvm.yml`/`ci-macos.yml`), so
//!   `#[ignore]` would not matter there either — but that step runs *before*
//!   either lane's "Fetch pinned gvproxy switch binary" step and exports no
//!   `MINVMD_GVPROXY_BIN`, so today it hits the gvproxy self-skip below
//!   instead and passes trivially, proving nothing there. `just test-vm`
//!   (which depends on the `gvproxy` recipe and exports the override) is
//!   this test's real run today; giving the CI step itself a resolvable
//!   gvproxy needs reordering those frozen workflow files, which is out of
//!   this test's reach.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must point
//!   to the kernel, the GENERIC rootfs, and the minimald initramfs cpio.
//! - A resolvable gvproxy binary: an own-IP session has no egress at all
//!   without the switch it provisions. `MINVMD_GVPROXY_BIN` is an explicit
//!   override, but `image::resolve_gvproxy_path` falls back to the installed
//!   system/user gvproxy when it is unset (`cmd/run.rs` only bails an own-IP
//!   boot when the *resolved* path does not exist), so checking the env var
//!   alone would self-skip on a host that has gvproxy installed without it.
//!   This is a self-skip rather than an assert either way: nothing about a
//!   missing switch is this test's own bug, and asserting on it would turn
//!   red any lane that boots without one installed.
//! - Real internet egress to the eight hosts in [`TOOLCHAIN_PROBES`] from
//!   wherever the guest boots.

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

// Double `minimald_session_integration`'s 15 s: this boot also provisions
// the gvproxy switch for the own-IP session below, on top of the plain boot
// that constant was tuned for.
const BOOT_TIMEOUT: Duration = Duration::from_secs(30);

/// Env var the server reads to scope an exec to a session
/// (mirrors `minimald::MINIMAL_SESSION_ID_ENV`).
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// `(tool, host, url)`: every host one of `apt`, `git clone`, `npm install`,
/// `pip`, and a container pull contacts, each paired with the literal
/// endpoint the real tool dials first — a repo index, a smart-HTTP
/// `info/refs` negotiation, a registry package/manifest lookup, a v2 API
/// probe. `pip` and a container pull each need more than one host (the index
/// host plus the file/blob host they redirect to — for a container pull,
/// `registry-1.docker.io` 302s a real blob fetch to Docker Hub's Cloudflare
/// R2-backed CDN, `production.cloudflare.docker.com`), so every host in the
/// chain is dialed rather than leaving one entry in the allowlist unexercised.
const TOOLCHAIN_PROBES: &[(&str, &str, &str)] = &[
    (
        "apt",
        "deb.debian.org",
        "https://deb.debian.org/debian/dists/stable/Release",
    ),
    (
        "git clone",
        "github.com",
        "https://github.com/git/git.git/info/refs?service=git-upload-pack",
    ),
    (
        "npm install",
        "registry.npmjs.org",
        "https://registry.npmjs.org/left-pad",
    ),
    ("pip", "pypi.org", "https://pypi.org/simple/six/"),
    (
        "pip",
        "files.pythonhosted.org",
        "https://files.pythonhosted.org/",
    ),
    (
        "container pull",
        "registry-1.docker.io",
        "https://registry-1.docker.io/v2/",
    ),
    (
        "container pull",
        "auth.docker.io",
        "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/alpine:pull",
    ),
    (
        "container pull",
        "production.cloudflare.docker.com",
        "https://production.cloudflare.docker.com/",
    ),
];

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so.
fn e2e_enabled() -> bool {
    if std::env::var("MINVMD_E2E").as_deref() != Ok("1") {
        eprintln!("egress_toolchain_integration: MINVMD_E2E != 1, skipping");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "egress_toolchain_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    // A resolvable gvproxy binary is a self-skip, not a panic, unlike the
    // three vars above: `resolve_gvproxy_path` (image.rs) falls back to the
    // installed system/user gvproxy when `MINVMD_GVPROXY_BIN` is unset, and
    // `cmd/run.rs` only bails an own-IP boot when that resolved path does not
    // exist on disk — so checking the env var alone would wrongly self-skip
    // on a host that has gvproxy installed but not exported through it. An
    // own-IP session has no egress at all without the switch, so without a
    // resolvable binary this test cannot prove anything for real.
    let gvproxy = minvmd::image::resolve_gvproxy_path();
    if !gvproxy.exists() {
        eprintln!(
            "egress_toolchain_integration: no gvproxy binary at {} (set \
             MINVMD_GVPROXY_BIN, or install one), skipping (an own-IP session \
             has no egress without the gvproxy switch)",
            gvproxy.display()
        );
        return false;
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
            .env("XDG_STATE_HOME", state.path())
            // The session created below is NetworkMode::OwnIp: the VM itself
            // must boot own-IP too, or there is no gvproxy switch and no
            // per-PTask shuttle for it to attach to (cmd/mod.rs
            // `own_ip_requested`, cmd/run.rs's gvproxy spawn).
            .env(minvmd::cmd::OWN_IP_ENV, "1")
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
                "egress_toolchain_integration: no 'vm-up' within {} s; are \
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

/// Reads this workspace's own pinned `[upstream]` block verbatim, never a
/// hardcoded commit — the pin drifts as `.minimal/minimal.toml` is bumped —
/// so the seeded session's package fetch hits the same warmed cache keys CI
/// already keeps hot. The same technique `scripts/session-e2e.sh` uses (there,
/// an `awk` script) to seed its own guest-egress proof's `shell` stack.
///
/// `None` when `.minimal/minimal.toml` is not at the compile-time-baked repo
/// path — the same nextest-archive-plus-host-remap hazard `minvmd_bin` exists
/// to dodge for the binary path — so the caller can skip rather than panic.
fn repo_upstream_toml() -> Option<String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(Path::parent)
        .expect("crates/minvmd has two ancestors up to the repo root");
    let mfile = std::fs::read_to_string(repo_root.join(".minimal/minimal.toml")).ok()?;
    let mut out = String::new();
    let mut grabbing = false;
    for line in mfile.lines() {
        if line.starts_with("[upstream]") {
            grabbing = true;
        } else if grabbing && (line.trim().is_empty() || line.starts_with('[')) {
            break;
        }
        if grabbing {
            out.push_str(line);
            out.push('\n');
        }
    }
    assert!(
        out.contains("locked_commit"),
        "extracted [upstream] block has no locked_commit; got: {out:?}"
    );
    Some(out)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn hostname_allowlist_toolchain_completes() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();

    // The session's mfile: this repo's own [upstream] pin, plus the light
    // `shell` stack (curl, nothing else) — the guest rootfs has no `/bin` of
    // its own, so this is the only way curl exists to run the probes below.
    let Some(upstream) = repo_upstream_toml() else {
        eprintln!(
            "hostname_allowlist_toolchain_completes: repo .minimal/minimal.toml not \
             found at the compile-time path (nextest archive/remap host?), skipping"
        );
        return;
    };
    let mfile = format!("{upstream}\n[stack]\nuse = \"shell\"\n");

    // Hostname-only: no CIDR allow, and `allow_dns_hosts` naming exactly the
    // eight hosts the five tools contact — nothing wider. TCP carries every
    // probe's own traffic, but the box's DNS to the resolver carve-out is UDP
    // (net_verdict.rs's transport rule is universal, even to the resolver:
    // `udp_is_dropped_when_only_tcp_is_allowed`), so UDP must be allowed too
    // or the box cannot resolve any of the eight names in the first place.
    let allow_dns_hosts: Vec<String> = TOOLCHAIN_PROBES
        .iter()
        .map(|(_, host, _)| host.to_string())
        .collect();
    let egress = minimald_rpc::EgressPolicy {
        allow_subnets: Some(Vec::new()),
        allow_dns_hosts: Some(allow_dns_hosts),
        allow_protocols: Some(vec![minimald_rpc::IpProto::Tcp, minimald_rpc::IpProto::Udp]),
        deny_subnets: None,
    };

    // Retry the whole session to absorb the post-READY startup race (same
    // shape as `minimald_exec_over_bridge`).
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut result = Err("not attempted".to_string());
    for attempt in 1..=6 {
        result = run_toolchain_probes(&guest.sock_path, &mfile, &egress).await;
        if result.is_ok() {
            break;
        }
        eprintln!("hostname_allowlist_toolchain_completes: session attempt {attempt}: {result:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let outcomes = result.unwrap_or_else(|e| panic!("hostname_allowlist_toolchain_completes: {e}"));

    // Diagnostics: the admitted-address table, printed once per probe as it
    // completes, so a stalled fetch names the host that was not admitted.
    // Observability: each probe's own exit status, plus the running total of
    // probes the allowlist did not admit.
    let mut dropped = 0usize;
    for (tool, host, exit) in &outcomes {
        let admitted = *exit == Some(0);
        if !admitted {
            dropped += 1;
        }
        eprintln!("[toolchain] {tool}: host={host} admitted={admitted} exit={exit:?}");
    }
    assert_eq!(
        dropped,
        0,
        "{dropped}/{} toolchain probes were not admitted under the hostname-only \
         allowlist; see the [toolchain] lines above for which host stalled",
        outcomes.len(),
    );
}

/// Open a russh client over the bridge UDS, authenticate, create an own-IP
/// session with `egress` as its policy, upload `mfile` and materialize it,
/// then run every [`TOOLCHAIN_PROBES`] entry in it. Returns each probe's
/// `(tool, host, exit_status)`, in [`TOOLCHAIN_PROBES`] order.
async fn run_toolchain_probes(
    sock_path: &Path,
    mfile: &str,
    egress: &minimald_rpc::EgressPolicy,
) -> Result<Vec<(&'static str, &'static str, Option<u32>)>, String> {
    use minimald_rpc::{CreateSession, CreateSessionRequest, OneshotSshRpc};
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

    // CreateSession: own-IP, with the hostname-only egress policy.
    let session_id = {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open CreateSession channel: {e}"))?;
        channel
            .request_subsystem(false, CreateSession::NAME)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;

        // Unique name per invocation — minimald dedups sessions by name, so
        // the outer retry loop would otherwise collide on `AlreadyExists`
        // after any prior attempt persisted a record.
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let req = CreateSessionRequest {
            config: minimald_rpc::SessionConfig {
                name: Some(format!("minvmd-e2e-toolchain-{uniq:x}")),
                project_path: paths::HostAbsPath::try_new("/tmp")
                    .map_err(|e| format!("project_path: {e}"))?,
                network: minimald_rpc::NetworkMode::OwnIp,
                policy: minimald_rpc::SessionPolicy::new(Some(egress.clone()), None),
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

    // Upload the seeded `minimal.toml` into the session workspace over SFTP.
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
        file.write_all(mfile.as_bytes())
            .await
            .map_err(|e| format!("sftp write minimal.toml: {e}"))?;
        file.shutdown()
            .await
            .map_err(|e| format!("sftp close minimal.toml: {e}"))?;
        sftp.close()
            .await
            .map_err(|e| format!("close sftp session: {e}"))?;
    }

    // ConfigureLoadout: materialize the `shell` stack now that the workspace
    // holds the seeded project files.
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
            // The seeded mfile's `shell` stack gates nothing (no patches, no
            // vars), so it finalizes in one shot.
            Some(ConfigureLoadoutResponse::Materialized) => {}
            Some(ConfigureLoadoutResponse::Pending { .. }) => {
                return Err(
                    "ConfigureLoadout returned Pending; the shell stack should gate nothing"
                        .to_string(),
                );
            }
            None => return Err("ConfigureLoadout returned an error".to_string()),
        }
    }

    // FinalizeSession: promote the record `Materializing → Active` so the
    // probes below pass minimald's status gate.
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

    // Run every probe: curl the literal endpoint the real tool dials first,
    // exactly as `scripts/session-e2e.sh`'s guest-egress proof does — curl's
    // own exit status (0 only once the TLS handshake and the HTTP round trip
    // both completed) is what "admitted" means here, whatever status code
    // comes back. Two attempts each: real third-party hosts, not this test's
    // own infrastructure.
    let mut outcomes = Vec::with_capacity(TOOLCHAIN_PROBES.len());
    for &(tool, host, url) in TOOLCHAIN_PROBES {
        let command =
            format!("curl -sS -o /dev/null -w 'HTTP:%{{http_code}}' --max-time 20 '{url}'");
        let mut exit = None;
        for probe_attempt in 1..=2 {
            match exec_probe(&mut handle, session_id, &command).await {
                Ok((_, code)) if code == Some(0) => {
                    exit = code;
                    break;
                }
                Ok((out, code)) => {
                    exit = code;
                    eprintln!(
                        "hostname_allowlist_toolchain_completes: {tool} ({host}) attempt \
                         {probe_attempt}/2 got exit={code:?} out={out:?}"
                    );
                }
                Err(e) => {
                    eprintln!(
                        "hostname_allowlist_toolchain_completes: {tool} ({host}) attempt \
                         {probe_attempt}/2 failed: {e}"
                    );
                }
            }
            if probe_attempt < 2 {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
        outcomes.push((tool, host, exit));
    }

    Ok(outcomes)
}

/// Exec `command` on a fresh channel of the already-authenticated `handle`,
/// scoped to `session_id`. Returns `(stdout, exit_status)`.
async fn exec_probe(
    handle: &mut russh::client::Handle<ClientHandler>,
    session_id: sessions::SessionId,
    command: &str,
) -> Result<(String, Option<u32>), String> {
    use russh::ChannelMsg;

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
