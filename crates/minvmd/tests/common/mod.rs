//! Helpers shared by minvmd's test targets (`mod common;`).
//!
//! The VM harnesses (`tests/*_integration.rs`) run on the VM lanes with
//! `MINVMD_E2E=1`. Under it a harness that cannot run is a lane failure, never
//! a green skip: [`skip_or_fail`] is the one place that decides, and
//! [`gvproxy_bin`] provisions the switch the lanes do not hand the harness step.

#![allow(
    dead_code,
    reason = "each test target compiles its own copy of this module and uses a subset"
)]
#![allow(
    clippy::panic,
    reason = "test support: a harness that cannot be provisioned fails the test by panicking"
)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use sha2::{Digest, Sha256};

/// Whether this run is a VM-lane run (`MINVMD_E2E=1`).
pub fn e2e() -> bool {
    std::env::var("MINVMD_E2E").as_deref() == Ok("1")
}

/// A harness's skip arm. Under `MINVMD_E2E=1` the run was asked to prove the
/// harness, so a reason to skip is a failure and this panics; otherwise it
/// prints a SKIPPED line and the caller returns.
pub fn skip_or_fail(harness: &str, reason: &str) {
    assert!(!e2e(), "{harness}: cannot run under MINVMD_E2E=1: {reason}");
    eprintln!("{harness}: SKIPPED: {reason}");
}

/// The pinned package source a harness's `minimal.toml` carries when its box
/// must launch: a box's sandbox resolves the baseline packages against the
/// project's package graph, so a project without `[upstream]` has no `base` to
/// launch with. The guest daemon fetches it over the switch as node-plane
/// traffic, which no box's egress rules govern.
pub const PKGS_UPSTREAM: &str = r#"[upstream]
repo = "https://github.com/gominimal/pkgs"
branch = "main"
locked_commit = "f4de33d06dada4edcf5076dded10e9c303cf597e"
"#;

/// Kills the process group `child` leads, then reaps `child`. A harness that
/// spawns `minvmd boot --foreground` makes it a group leader
/// (`process_group(0)`) so its `__krun-vmm` child dies with it: killing the
/// parent alone reparents the VMM to init, where it keeps the VM running and
/// holds the harness's inherited stdio open. The parent is also killed
/// directly, so the reap cannot block on a group signal that missed.
#[expect(
    clippy::let_underscore_must_use,
    reason = "best-effort teardown: the group may already be gone"
)]
pub fn kill_group(child: &mut Child) {
    let pgid = libc::pid_t::try_from(child.id()).expect("a child pid fits pid_t");
    // SAFETY: killpg only sends a signal; `pgid` is the group `child` leads,
    // and `child` is not reaped yet, so its id cannot have been reused.
    unsafe { libc::killpg(pgid, libc::SIGKILL) };
    let _ = child.kill();
    let _ = child.wait();
}

/// The gvproxy switch binary a harness hands the minvmd it spawns as
/// `MINVMD_GVPROXY_BIN`, or `None` when the harness should skip (neither the
/// variable nor `MINVMD_E2E=1` is set).
///
/// Under `MINVMD_E2E=1` the switch comes from `MINVMD_GVPROXY_BIN` when set,
/// else from `scripts/fetch-gvproxy.sh` into a per-version cache, and in every
/// case its SHA-256 must match `vendor/gvproxy/gvproxy.lock`. Outside E2E an
/// unpinned `MINVMD_GVPROXY_BIN` is used as given.
pub fn gvproxy_bin() -> Option<PathBuf> {
    let set = std::env::var_os("MINVMD_GVPROXY_BIN")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    resolve_gvproxy(e2e(), set, &workspace_root())
}

/// [`gvproxy_bin`] with its inputs explicit.
pub fn resolve_gvproxy(e2e: bool, set: Option<PathBuf>, workspace: &Path) -> Option<PathBuf> {
    if !e2e {
        return set;
    }
    let lock = GvproxyLock::read(workspace);
    let bin = match set {
        Some(bin) => bin,
        None => fetch_cached(workspace, &lock),
    };
    lock.verify(&bin);
    Some(bin)
}

/// The repository root: nextest's runtime `CARGO_MANIFEST_DIR` (remapped by
/// `--workspace-remap` when replaying an archive on another machine), else
/// the compile-time one, two levels up.
pub fn workspace_root() -> PathBuf {
    std::env::var_os("CARGO_MANIFEST_DIR")
        .map_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")), PathBuf::from)
        .join("../..")
}

/// The pin in `vendor/gvproxy/gvproxy.lock` for this platform's asset.
pub struct GvproxyLock {
    pub version: String,
    pub asset: &'static str,
    pub sha256: String,
}

impl GvproxyLock {
    pub fn read(workspace: &Path) -> GvproxyLock {
        let path = workspace.join("vendor/gvproxy/gvproxy.lock");
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("reading {}: {e}", path.display()));
        // The same asset mapping as scripts/fetch-gvproxy.sh.
        let asset = match (std::env::consts::OS, std::env::consts::ARCH) {
            ("linux", "x86_64") => "gvproxy-linux-amd64",
            ("linux", "aarch64") => "gvproxy-linux-arm64",
            ("macos", _) => "gvproxy-darwin",
            (os, arch) => panic!("no pinned gvproxy asset for {os}-{arch}"),
        };
        let value = |key: &str| {
            text.lines()
                .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
                .map(str::to_owned)
                .unwrap_or_else(|| panic!("{} has no {key}= line", path.display()))
        };
        GvproxyLock {
            version: value("version"),
            asset,
            sha256: value(asset),
        }
    }

    /// Panics, naming both digests, unless `bin`'s SHA-256 is the pinned one.
    pub fn verify(&self, bin: &Path) {
        let bytes = std::fs::read(bin)
            .unwrap_or_else(|e| panic!("reading gvproxy at {}: {e}", bin.display()));
        let got: String = Sha256::digest(&bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert!(
            got == self.sha256,
            "gvproxy SHA-256 mismatch for {} at {} under MINVMD_E2E=1\n  got:  {got}\n  want: {}",
            self.asset,
            bin.display(),
            self.sha256,
        );
    }
}

/// The pinned gvproxy in a per-version cache under `$RUNNER_TEMP` (else the
/// system temp dir), fetched by `scripts/fetch-gvproxy.sh` when absent. The
/// fetch lands in a unique temp file renamed into place, so concurrent test
/// processes never see a partial binary.
fn fetch_cached(workspace: &Path, lock: &GvproxyLock) -> PathBuf {
    let dir = std::env::var_os("RUNNER_TEMP")
        .filter(|v| !v.is_empty())
        .map_or_else(std::env::temp_dir, PathBuf::from)
        .join("minimal-gvproxy")
        .join(&lock.version);
    let dest = dir.join("gvproxy");
    let executable = std::fs::metadata(&dest)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false);
    if executable {
        return dest;
    }
    std::fs::create_dir_all(&dir)
        .unwrap_or_else(|e| panic!("creating the gvproxy cache {}: {e}", dir.display()));
    let tmp = tempfile::Builder::new()
        .prefix("gvproxy.")
        .tempfile_in(&dir)
        .unwrap_or_else(|e| panic!("creating a temp file in {}: {e}", dir.display()))
        .into_temp_path();
    eprintln!(
        "fetching pinned gvproxy {} to {} (MINVMD_E2E=1, MINVMD_GVPROXY_BIN unset)",
        lock.version,
        dest.display(),
    );
    let script = workspace.join("scripts/fetch-gvproxy.sh");
    let status = Command::new(&script)
        .arg(&*tmp)
        .status()
        .unwrap_or_else(|e| panic!("running {}: {e}", script.display()));
    assert!(
        status.success(),
        "{} failed ({status}): under MINVMD_E2E=1 the gvproxy switch is required",
        script.display(),
    );
    tmp.persist(&dest)
        .unwrap_or_else(|e| panic!("moving the fetched gvproxy to {}: {e}", dest.display()));
    dest
}

/// Registers one box with the VM host daemon over its control socket: one
/// request line in, one reply line out, the exchange `min session activate`
/// makes before it creates the session. Returns the addresses the host's
/// table allocated for the row.
pub fn register_box(
    control_sock: &Path,
    name: &str,
    egress: Option<sessions::EgressPolicy>,
) -> Result<minimald_rpc::BoxAddresses, String> {
    let request = minimald_rpc::BoxControlRequest::Register(minimald_rpc::RegisterBoxRequest {
        name: name.to_string(),
        ingress_ports: Vec::new(),
        egress,
        credentialed_upstream: None,
        dynamic_ingress: None,
        dynamic_allowed_range: None,
        hold: false,
    });
    let mut line = serde_json_lenient::to_string(&request)
        .map_err(|e| format!("serialize the box registration: {e}"))?;
    line.push('\n');
    let mut stream = std::os::unix::net::UnixStream::connect(control_sock)
        .map_err(|e| format!("connect to the control socket: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(30)))
        .map_err(|e| format!("set the control socket's read timeout: {e}"))?;
    stream
        .write_all(line.as_bytes())
        .map_err(|e| format!("write the box registration: {e}"))?;
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .map_err(|e| format!("read the box registration's reply: {e}"))?;
    match serde_json_lenient::from_str(reply.trim())
        .map_err(|e| format!("parse the box registration's reply {reply:?}: {e}"))?
    {
        minimald_rpc::BoxControlReply::Registered(registered) => Ok(minimald_rpc::BoxAddresses {
            switch_address: registered.switch_address,
            loopback_address: registered.loopback_address,
        }),
        minimald_rpc::BoxControlReply::Addresses(addresses) => Ok(addresses),
        other => Err(format!(
            "the VM host refused the box registration: {other:?}"
        )),
    }
}
