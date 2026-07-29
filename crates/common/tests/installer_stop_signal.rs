//! Convention-discovered gate pinning the one string the installer shares with
//! the `min` CLI.
//!
//! `scripts/install.sh` decides whether a `curl … | sh` upgrade is about to
//! destroy live work by matching `min stop`'s refusal message, not its exit
//! status (a bare non-zero also means no daemon, a failed connect, or a `min`
//! too old to know the subcommand). That reuses the CLI's existing signal
//! rather than adding a parallel session check, but it couples a shell literal
//! to a Rust one across crates with nothing in between. Reword the `bail!` and
//! the installer silently stops asking and goes back to force-stopping every
//! upgrade — the exact bug the prompt exists to prevent, with every installer
//! test still green, because the harness stubs `min` with its own copy of the
//! string and so cannot notice.
//!
//! Both files are read as text: this asserts the contract without `common`
//! taking a dependency on `minimal` or on the installer. It lives beside
//! `shell_lint.rs` for the same reason that one does — the workspace test run
//! is the reviewed-code extension point CI schedules over
//! (docs/ci-strategy.md §10), and `.github/workflows/` is frozen.

use std::path::PathBuf;

fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/common; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root two levels above crates/common")
        .to_path_buf()
}

#[test]
fn installer_matches_the_message_the_cli_actually_prints() {
    let root = repo_root();

    let installer_path = root.join("scripts/install.sh");
    let installer =
        std::fs::read_to_string(&installer_path).expect("failed to read scripts/install.sh");

    // The assignment the installer matches on, e.g.
    //   sessions_live_msg='daemon has active sessions'
    let needle = installer
        .lines()
        .find_map(|line| line.trim().strip_prefix("sessions_live_msg='"))
        .and_then(|rest| rest.strip_suffix('\''))
        .unwrap_or_else(|| {
            panic!(
                "no `sessions_live_msg='…'` assignment in {}; the upgrade prompt's signal moved \
                 or was renamed, and this gate must move with it",
                installer_path.display()
            )
        });

    assert!(
        !needle.is_empty(),
        "sessions_live_msg is empty: every `min stop` failure would match it and every upgrade \
         with a stopped daemon would prompt"
    );

    let cli_path = root.join("crates/minimal/src/lib.rs");
    let cli = std::fs::read_to_string(&cli_path).expect("failed to read crates/minimal/src/lib.rs");

    assert!(
        cli.contains(needle),
        "scripts/install.sh gates the upgrade prompt on the substring {needle:?}, which no longer \
         appears in {}. `min stop`'s active-sessions refusal is the installer's only signal that \
         an upgrade is about to end live sessions; with the wording changed the installer stops \
         asking and force-stops the daemon unconditionally. Update the literal on both sides \
         together.",
        cli_path.display(),
    );
}
