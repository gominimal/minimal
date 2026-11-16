//! The `bep` binary against a real TPM (BEP-088, BEP-089).
//!
//! * `bep_keeps_its_tpm_keys_across_restarts` starts `bep` twice against
//!   the TPM that `BEP_TPM_TCTI` names, with no Secret Service. It checks
//!   that the first start makes each key in the TPM and that the second
//!   start publishes the same fingerprints. Then it removes the TPM, and
//!   checks that the next start refuses, keeps every key file, and leaves
//!   the published identity as it was.
//! * `bep_without_a_tpm_or_keyring_refuses_start` starts `bep` with
//!   `tpm2-tools` installed but no TPM behind them, and no Secret Service.
//!   It checks that the start refuses and says why.
//!
//! `bep` always reaches the TPM through `device:/dev/tpmrm0`. So each test
//! puts a wrapper for each `tpm2-tools` command first on `PATH`. The wrapper
//! runs the real command with the TCTI that the test chose. Without a
//! resource manager, such as `swtpm` in CI, it then flushes what the
//! command left in the TPM, as the kernel's resource manager does. A test
//! removes the TPM when it points the wrappers at a TCTI with no TPM.
//!
//! The tests need `tpm2-tools`, and the first one needs a TPM. They are
//! ignored by default, and return early when `BEP_TPM_TCTI` is not set.
//! Run them with `BEP_TPM_TCTI=<tcti> cargo nextest run -p bep
//! --run-ignored ignored-only <test>`.

#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use bep::keys::Role;
use bep::publish::Identity;
use tempfile::TempDir;

/// A TCTI with no TPM behind it.
const NO_TPM: &str = "device:/nonexistent/tpmrm0";

/// The refusal that `bep` prints when neither the TPM nor Secret Service
/// can hold a key.
const NO_STORE: &str = "The proxy did not start: this host has no usable TPM and no unlocked Secret Service keyring, so the proxy has nowhere to keep its keys.";

/// One host for `bep`: a home directory, and a `PATH` that holds the TPM
/// wrappers and a `secret-tool` with no session bus.
struct Host {
    dir: TempDir,
}

impl Host {
    /// A host whose wrappers run the `tpm2-tools` in `tools` against `tcti`.
    fn new(tools: &Path, tcti: &str) -> Self {
        let host = Self {
            dir: tempfile::tempdir().expect("tempdir"),
        };
        for dir in [host.home(), host.config(), host.bin()] {
            fs::create_dir_all(dir).expect("mkdir");
        }
        host.set_tcti(tcti);
        // The words GDBus prints when a session has no bus.
        script(
            &host.bin().join("secret-tool"),
            "printf '%s\\n' 'Cannot autolaunch D-Bus without X11 $DISPLAY' >&2\nexit 1\n",
        );
        let state = host.tcti_file();
        for entry in fs::read_dir(tools).expect("read the tpm2-tools directory") {
            let name = entry.expect("entry").file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("tpm2") {
                continue;
            }
            let real = tools.join(&*name);
            let flush = tools.join("tpm2_flushcontext");
            script(
                &host.bin().join(&*name),
                &format!(
                    "read -r tcti < '{state}'\n\
                     TPM2TOOLS_TCTI=\"$tcti\" '{real}' \"$@\"\n\
                     status=$?\n\
                     case \"$tcti\" in\n\
                     device:/dev/tpmrm*|tabrmd*) ;;\n\
                     *) for flag in -t -l -s; do TPM2TOOLS_TCTI=\"$tcti\" '{flush}' \"$flag\" >/dev/null 2>&1; done ;;\n\
                     esac\n\
                     exit $status\n",
                    state = state.display(),
                    real = real.display(),
                    flush = flush.display(),
                ),
            );
        }
        host
    }

    fn home(&self) -> PathBuf {
        self.dir.path().join("home")
    }

    fn config(&self) -> PathBuf {
        self.dir.path().join("config")
    }

    fn bin(&self) -> PathBuf {
        self.dir.path().join("bin")
    }

    fn tcti_file(&self) -> PathBuf {
        self.dir.path().join("tcti")
    }

    fn identity(&self) -> PathBuf {
        self.home().join(".minimal/bep/identity.json")
    }

    fn tpm_dir(&self) -> PathBuf {
        self.home().join(".minimal/bep/tpm")
    }

    /// Points the wrappers at `tcti`. [`NO_TPM`] removes the TPM.
    fn set_tcti(&self, tcti: &str) {
        fs::write(self.tcti_file(), format!("{tcti}\n")).expect("write tcti");
    }

    /// Runs `bep` once, and prints its output with the TCTI it ran
    /// against, for whoever reads a failure.
    fn start(&self) -> Output {
        let tcti = fs::read_to_string(self.tcti_file()).expect("read tcti");
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_bep"));
        cmd.env_clear()
            .env("HOME", self.home())
            .env("XDG_CONFIG_HOME", self.config())
            .env("PATH", self.bin())
            .env("RUST_LOG", "info");
        if let Some(runtime) = std::env::var_os("XDG_RUNTIME_DIR") {
            cmd.env("XDG_RUNTIME_DIR", runtime);
        }
        let out = cmd.output().expect("run bep");
        eprintln!(
            "bep against TPM {}: exit {:?}\n{}",
            tcti.trim(),
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        out
    }

    /// The names of the key and authorization files in the TPM store.
    fn key_files(&self) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(self.tpm_dir())
            .expect("read the TPM store")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.ends_with(".key") || name.ends_with(".auth"))
            .collect();
        names.sort();
        names
    }
}

/// Writes an executable shell script at `path`.
fn script(path: &Path, body: &str) {
    fs::write(path, format!("#!/bin/sh\n{body}")).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod script");
}

/// The directory of the installed `tpm2-tools`, from `PATH`.
fn tpm2_tools() -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .find(|dir| dir.join("tpm2_createprimary").is_file())
}

/// The `bep` log lines that name a key store, so a failure shows where each
/// key was found or made.
fn store_lines(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr)
        .lines()
        .filter(|line| line.contains("store="))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The published fingerprint and store of each role.
fn published(path: &Path, out: &Output) -> Vec<(Role, String, Option<String>)> {
    let identity = Identity::read(path)
        .unwrap_or_else(|err| panic!("no identity ({err}). Key stores:\n{}", store_lines(out)));
    Role::ALL
        .into_iter()
        .map(|role| {
            let entry = match role {
                Role::Sealing => identity.sealing.as_ref(),
                Role::Root => identity.root.as_ref(),
                Role::Signing => identity.signing.as_ref(),
            }
            .unwrap_or_else(|| panic!("no {role} key published"));
            (role, entry.kid.clone(), entry.store.clone())
        })
        .collect()
}

/// The TCTI and the tools for a test, or `None` when this host cannot run
/// it.
fn tpm_lane() -> Option<(String, PathBuf)> {
    let Ok(tcti) = std::env::var("BEP_TPM_TCTI") else {
        eprintln!("BEP_TPM_TCTI is not set, so this host has no TPM for the test. Skipped.");
        return None;
    };
    let Some(tools) = tpm2_tools() else {
        eprintln!("tpm2-tools is not on PATH, so this host cannot reach a TPM. Skipped.");
        return None;
    };
    Some((tcti, tools))
}

// BEP-088, BEP-089
#[test]
#[ignore = "needs a TPM: set BEP_TPM_TCTI"]
fn bep_keeps_its_tpm_keys_across_restarts() {
    let Some((tcti, tools)) = tpm_lane() else {
        return;
    };
    let host = Host::new(&tools, &tcti);

    // The first start makes each key in the TPM.
    let first = host.start();
    assert!(
        first.status.success(),
        "the first start failed. Key stores:\n{}",
        store_lines(&first)
    );
    let made = published(&host.identity(), &first);
    for (role, _, store) in &made {
        assert_eq!(
            store.as_deref(),
            Some("tpm"),
            "{role} key is not in the TPM. Key stores:\n{}",
            store_lines(&first)
        );
    }
    let files = host.key_files();
    assert_eq!(files.len(), 2 * Role::ALL.len(), "{files:?}");

    // The second start loads the same keys, and makes none.
    let second = host.start();
    assert!(
        second.status.success(),
        "the second start failed. Key stores:\n{}",
        store_lines(&second)
    );
    let loaded = published(&host.identity(), &second);
    assert_eq!(
        loaded,
        made,
        "the second start published other keys. Key stores:\n{}",
        store_lines(&second)
    );
    assert_eq!(host.key_files(), files);
    let log = String::from_utf8_lossy(&second.stderr);
    assert!(
        !log.contains("chose the key store for a new proxy key"),
        "the second start made a key. Key stores:\n{}",
        store_lines(&second)
    );

    // With the TPM gone, the start refuses and keeps every key.
    let identity = fs::read(host.identity()).expect("read identity");
    host.set_tcti(NO_TPM);
    let gone = host.start();
    let stderr = String::from_utf8_lossy(&gone.stderr);
    assert!(!gone.status.success(), "bep started with no TPM:\n{stderr}");
    assert!(
        stderr.contains("The key is kept") && stderr.contains("when the TPM is available"),
        "no kept-key refusal in:\n{stderr}"
    );
    assert!(
        !stderr.contains("--replace-key"),
        "the refusal names a replacement for a key that still exists:\n{stderr}"
    );
    assert!(
        !stderr.contains("chose the key store for a new proxy key"),
        "bep made a key with no TPM. Key stores:\n{}",
        store_lines(&gone)
    );
    assert_eq!(host.key_files(), files, "a key file went with the TPM");
    assert_eq!(
        fs::read(host.identity()).expect("read identity"),
        identity,
        "the refused start changed the published identity"
    );
}

// BEP-088
#[test]
#[ignore = "needs tpm2-tools: set BEP_TPM_TCTI"]
fn bep_without_a_tpm_or_keyring_refuses_start() {
    let Some((_, tools)) = tpm_lane() else {
        return;
    };
    let host = Host::new(&tools, NO_TPM);

    let out = host.start();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "bep started:\n{stderr}");
    assert!(
        stderr.lines().any(|line| line == NO_STORE),
        "no refusal line in:\n{stderr}"
    );
    assert!(
        !host.identity().exists(),
        "bep published an identity. Key stores:\n{}",
        store_lines(&out)
    );
    let files = if host.tpm_dir().exists() {
        host.key_files()
    } else {
        Vec::new()
    };
    assert!(files.is_empty(), "bep left key files: {files:?}");
}
