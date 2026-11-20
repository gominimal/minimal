//! Convention-discovered gate pinning the one string the installer shares with
//! the `min` CLI.
//!
//! `scripts/install.sh` decides whether a `curl … | sh` upgrade is about to
//! destroy live work by matching a refusal message, not an exit status. An
//! older `min` has bare `min stop`, which refuses while sessions are live with
//! `daemon has active sessions; pass --force to shut down anyway`. Those
//! releases are already on disk and cannot change, so the installer's literal
//! must keep matching their text. A `min` with `min host stop` has no bare
//! `min stop` (BCLI-042), and `min host stop` refuses nothing, so the
//! installer makes its own running-box check and prints the same literal for
//! its own refusal. Reword the literal and the installer silently stops asking
//! an older client's daemon, and goes back to force-stopping it: the exact bug
//! the prompt exists to prevent, with every installer test still green,
//! because the harness stubs `min` with its own copy of the string.
//!
//! The installer is read as text: this asserts the contract without `common`
//! taking a dependency on the installer. It lives beside `shell_lint.rs` for
//! the same reason that one does — the workspace test run is the
//! reviewed-code extension point CI schedules over (docs/ci-strategy.md §10),
//! and `.github/workflows/` is frozen.

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

    // The refusal an older `min stop` prints. Released clients carry it, so
    // it is fixed here rather than read from the current CLI source.
    let released = "daemon has active sessions; pass --force to shut down anyway";
    assert!(
        released.contains(needle),
        "scripts/install.sh gates the upgrade prompt on the substring {needle:?}, which the \
         refusal of an older `min stop` ({released:?}) does not contain. That refusal is the \
         installer's only signal that an upgrade over an older client is about to end live \
         sessions."
    );

    // A `min` with `min host stop` refuses nothing, so the installer prints
    // the refusal itself after its own running-box check.
    assert!(
        installer.contains("echo \"$sessions_live_msg\" >&2"),
        "{} no longer prints $sessions_live_msg for its own running-box check, so an upgrade \
         with `min host stop` never asks before it ends a box",
        installer_path.display(),
    );
}
