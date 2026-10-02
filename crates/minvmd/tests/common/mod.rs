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

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

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
