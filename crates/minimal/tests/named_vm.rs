//! The `--vm` flag must reach autospawn (NET-052): a named VM's state
//! directory is the one autospawn reads, and the `minvmd` it spawns is told
//! the name — otherwise `min --vm alpha` would boot a second default VM and
//! then connect to it, leaving `alpha` never started.
//!
//! The real `min` binary is driven against a stub `minvmd` that records its
//! argv, so the proof is the spawn itself, not a VM boot: this runs on every
//! lane that runs `-p minimal`, with no libkrun required.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Where the stub `minvmd` records the argv it was spawned with.
const ARGV_RECORD_ENV: &str = "MINIMAL_TEST_MINVMD_ARGV";

/// Writes a `minvmd` stub into `bin_dir` that records its argv to the file
/// named by [`ARGV_RECORD_ENV`] and exits 0. Autospawn treats exit 0 as "the
/// VM is serving", so the command under test then fails at its socket connect
/// — the fact this file asserts on is the argv, recorded before that failure.
fn stub_minvmd(bin_dir: &Path) {
    std::fs::create_dir_all(bin_dir).unwrap();
    let stub = bin_dir.join("minvmd");
    std::fs::write(
        &stub,
        format!("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"${{{ARGV_RECORD_ENV}}}\"\nexit 0\n"),
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt as _;
    let mut perms = std::fs::metadata(&stub).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&stub, perms)
        .unwrap_or_else(|e| panic!("chmod {} +x: {e}", stub.display()));
}

/// Run the real `min` binary: `--minimal-dir dir` plus `args`, with the stub's
/// `bin/` in front of `PATH` and its record path in the environment. The exit
/// status is the caller's to read — every command here ends in a connect
/// failure once the stub has been spawned, which is the expected shape.
fn run_min(dir: &Path, args: &[&str]) -> (std::process::Output, PathBuf) {
    let record = dir.join("argv.txt");
    let bin_dir = dir.join("stub-bin");
    stub_minvmd(&bin_dir);
    let path = std::env::join_paths(
        std::iter::once(bin_dir).chain(std::env::split_paths(&std::env::var("PATH").unwrap())),
    )
    .unwrap();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_min"));
    cmd.arg("--minimal-dir")
        .arg(dir)
        .args(args)
        .arg("session")
        .arg("list")
        // The stub is found through `PATH`, and the record path through the
        // environment, both of which the child inherits.
        .env("PATH", path)
        .env(ARGV_RECORD_ENV, &record)
        // Piped, so nothing this test runs needs (or gets) a terminal.
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let output = cmd.output().expect("running the real `min` binary");
    (output, record)
}

/// The argv the stub recorded, as lines. Panics with the run's captured output
/// when the stub was never spawned — that is the failure this test exists to
/// catch, and the output says which path the CLI took instead.
fn recorded_argv(output: &std::process::Output, record: &Path) -> Vec<String> {
    std::fs::read_to_string(record)
        .unwrap_or_else(|_| {
            panic!(
                "the stub minvmd was never spawned; min said:\n{}",
                String::from_utf8_lossy(&output.stderr)
            )
        })
        .lines()
        .map(str::to_string)
        .collect()
}

/// The value after `flag` in an argv, if the flag is present.
fn flag_value<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.windows(2)
        .find(|w| w[0] == flag)
        .map(|w| w[1].as_str())
}

/// A `--vm alpha` command must autospawn *alpha*: the stub `minvmd` is told
/// both the state-dir override and the VM name, autospawn reads alpha's state
/// directory (creating it), and the default VM's state directory is left
/// unwritten (NET-053).
#[test]
fn named_vm_reaches_autospawn() {
    let tmp = tempfile::tempdir().unwrap();
    let (output, record) = run_min(tmp.path(), &["--provider", "local-minvmd", "--vm", "alpha"]);

    let argv = recorded_argv(&output, &record);
    assert_eq!(
        flag_value(&argv, "--minimal-state-dir"),
        Some(tmp.path().to_str().unwrap()),
        "the state-dir override must reach the spawned daemon: {argv:?}"
    );
    assert_eq!(
        flag_value(&argv, "--vm"),
        Some("alpha"),
        "autospawn must tell the daemon which VM to boot: {argv:?}"
    );
    assert!(argv.contains(&"run".to_string()), "spawn shape: {argv:?}");
    assert!(
        argv.contains(&"--detach".to_string()),
        "spawn shape: {argv:?}"
    );
    assert!(
        flag_value(&argv, "--timeout").is_some(),
        "the boot deadline must still be forwarded: {argv:?}"
    );

    // Autospawn read the named VM's state dir — `StateDir::new` created it.
    assert!(
        tmp.path().join("providers/local-minvmd0/alpha").is_dir(),
        "autospawn must read the named VM's state dir, not the default one"
    );
    // The default VM's state was never written (NET-053).
    assert!(
        !tmp.path()
            .join("providers/local-minvmd0/minvmd.toml")
            .exists(),
        "a named VM's autospawn must not touch the default VM's state"
    );

    // And the connect that follows names alpha's socket, proving the CLI is
    // talking to the VM it just spawned rather than a default one.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("providers/local-minvmd0/alpha/ssh.sock"),
        "the connect must target alpha's socket, got: {stderr}"
    );
}

/// Without `--vm`, autospawn must behave exactly as before: no `--vm` in the
/// spawned daemon's argv, and the state dir read is the bare provider dir
/// (NET-053 — the default VM's paths are unchanged).
#[test]
fn default_vm_autospawn_is_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let (output, record) = run_min(tmp.path(), &["--provider", "local-minvmd"]);

    let argv = recorded_argv(&output, &record);
    assert!(
        flag_value(&argv, "--vm").is_none(),
        "the default VM must spawn without a --vm flag: {argv:?}"
    );
    assert!(
        tmp.path().join("providers/local-minvmd0").is_dir(),
        "the default VM's autospawn must read the provider dir itself"
    );
    assert!(
        !tmp.path().join("providers/local-minvmd0/alpha").exists(),
        "no per-name subdirectory may appear without --vm"
    );
}
