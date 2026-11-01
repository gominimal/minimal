//! The daily update check (gominimal/inbox#589): `min` learns whether its
//! channel has moved on and says so once, and the check is the first signal
//! of how many installs run `min` and where.
//!
//! Shape:
//!
//! - Every command first calls [`before_command`]. It reads the cached
//!   result in `<state>/minimal/update-check.json`, and when the last check
//!   is older than [`INTERVAL`] it spawns a detached `min update-check
//!   --background` and goes on at once. The parent never waits on the
//!   network: the notice lands on a later command, which a daily cadence
//!   tolerates.
//! - The child makes one `GET {endpoint}/<channel>/<key>?os&arch&install&id`
//!   with a [`REQUEST_BUDGET`] and no retry, writes the answer into the
//!   state file, and always exits 0. A 404, a timeout or an offline host
//!   produce no output.
//! - "Up to date" is `latest == key`, the key this build was installed from
//!   (the channel pointer at install time, written to `install.toml` by the
//!   installer), so the client never orders versions and a misbehaving
//!   endpoint cannot nag: an answer equal to the key is silence.
//! - The notice goes to stderr, only when stderr is a terminal, once per
//!   new pointer. stdout belongs to the command's own output.
//! - Off switches, any one wins: `[telemetry] enabled = false` in the user
//!   config, `MINIMAL_TELEMETRY` falsy, `DO_NOT_TRACK` set, or `CI` set
//!   (CI installs `min` per job and would mint an install id each time).
//! - On by default until 1.0. The first run with a terminal says so on
//!   stderr and makes no request; the request waits for a later command.
//!   An install whose commands are a script's or an agent's (no terminal)
//!   is counted from its second command without that text: the docs page
//!   and the installer's closing card carry it, and the decision to count
//!   those installs is inbox#589's. Its first command with a terminal still
//!   gets the disclosure, and makes no request that time either.

//!
//! Layout: this file is the per-command hook ([`before_command`]) and the
//! constants; `switches` is what turns the check off; `state` is what it
//! keeps on disk (the install description, the state file, the cadence and
//! the lock); `notice` is what the user reads; `request` is the one GET,
//! the detached child and the `min update-check` command.

use std::io::IsTerminal as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::cli::GlobalArgs;

mod notice;
mod request;
mod state;
mod switches;
#[cfg(test)]
mod tests;

pub use notice::{disclosure, disclosure_due, notice, notice_due};
use request::spawn_background;
pub use request::{cmd_update_check, fetch_latest, request_url};
pub use state::{
    Install, State, acquire_lock, build_key, due, now_secs, read_install, read_state,
    record_answer, record_notified, release_lock, valid_field, valid_install_id, write_state,
};
use state::{claim_install_id, record_disclosed};
pub use switches::{ConfigState, UpdateDisabledReason, off_switch};

/// The version endpoint; `MINIMAL_UPDATE_CHECK_URL` overrides it.
pub const ENDPOINT: &str = "https://update.minimal.dev/v1";
/// Overrides [`ENDPOINT`]: a stub in tests, a mirror behind a proxy.
pub const ENDPOINT_VAR: &str = "MINIMAL_UPDATE_CHECK_URL";
/// The state file, beside the installer's `installed` record.
pub const STATE_FILE: &str = "update-check.json";
/// The installer's (or a package's) description of this install.
pub const INSTALL_FILE: &str = "install.toml";
/// Held by the invocation that spawned the check, released by the child.
pub const LOCK_FILE: &str = "update-check.lock";
/// How often a check is made.
pub const INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);
/// A lock older than this belongs to a child that never finished.
pub const LOCK_STALE: Duration = Duration::from_secs(60 * 60);
/// The whole request, connect included. One attempt.
pub const REQUEST_BUDGET: Duration = Duration::from_secs(2);
/// Where the docs explain the check and the switches.
pub const DOCS_URL: &str = "https://docs.minimal.dev/reference/telemetry#update-check";
/// The channel of a build nobody installed from a channel: never notified.
pub const SOURCE_CHANNEL: &str = "source";
/// The channel the installer records for a `--version` install: it is
/// counted, and never told about another pointer (there is no
/// `go.minimal.dev/pinned` to run).
pub const PINNED_CHANNEL: &str = "pinned";

/// The state directory: `--minimal-dir`, else `$XDG_STATE_HOME/minimal`.
fn state_dir(global: &GlobalArgs) -> Option<PathBuf> {
    global
        .minimal_dir
        .clone()
        .or_else(|| paths::try_minimal_state_dir().map(|p| AsRef::<Path>::as_ref(&p).to_path_buf()))
}

/// The switch that turns the check off for this invocation, if any:
/// [`off_switch`]'s environment and config, then `--minimal-dir`.
fn off(global: &GlobalArgs) -> Option<UpdateDisabledReason> {
    off_switch(config_state(global), |n| std::env::var_os(n)).or_else(|| {
        global
            .minimal_dir
            .is_some()
            .then_some(UpdateDisabledReason::MinimalDir)
    })
}

/// What the user config says. A missing config is the default, on. A config
/// that exists but cannot be read or parsed turns the check off: it may well
/// carry `enabled = false` next to the typo, and a check that is skipped
/// until the file is fixed costs nothing. The check never fails the command
/// either way; the config's own error prints where the config is used.
fn config_state(global: &GlobalArgs) -> ConfigState {
    match crate::config::read_client_config(global) {
        Ok(c) if c.telemetry.enabled => ConfigState::Enabled,
        Ok(_) => ConfigState::Disabled,
        Err(_) => ConfigState::Unreadable,
    }
}

/// The commands that do not trigger the check: the check itself, the
/// completion machinery (hot path, non-interactive, per keystroke), and
/// `min version`, which must print only its own output.
pub fn skip_for(command: &Option<crate::cli::Command>) -> bool {
    use crate::cli::Command;
    matches!(
        command,
        Some(
            Command::UpdateCheck(_)
                | Command::Completions(_)
                | Command::CompleteSessionStr(_)
                | Command::Version
        )
    )
}

/// The commands that leave the terminal to a line written before them:
/// short ones whose output scrolls past. A command that takes the terminal
/// (bare `min`, which attaches to a box; a session attach; `run`; a task;
/// the dashboard; `proxy`, whose stderr is ssh's) paints over it, so the
/// disclosure and the notice wait for the next command of this kind, and
/// are recorded as shown only once printed before one.
pub fn leaves_the_notice_visible(command: &Option<crate::cli::Command>) -> bool {
    use crate::cli::Command;
    matches!(
        command,
        Some(
            Command::Ls(_)
                | Command::Stop(_)
                | Command::Loadout(_)
                | Command::Net(_)
                | Command::Dirs
                | Command::Init(_)
                | Command::Add(_)
                | Command::Update(_)
                | Command::Login(_)
                | Command::Auth(_)
                | Command::Secret(_)
                | Command::Bug(_)
                | Command::Diag(_)
        )
    )
}

/// The per-command hook: never waits, never fails the command. See the
/// module doc.
pub fn before_command(global: &GlobalArgs, command: &Option<crate::cli::Command>) {
    if skip_for(command) {
        return;
    }
    if off(global).is_some() {
        return;
    }
    let Some(dir) = state_dir(global) else {
        return;
    };
    let state_path = dir.join(STATE_FILE);
    let mut state = read_state(&state_path);
    let install = read_install(&dir, std::env::current_exe().ok().as_deref());
    let tty = std::io::stderr().is_terminal();

    // The id is minted under the spawn lock and written by re-reading the
    // file, so two first commands that run together mint one id between
    // them (the other finds it on disk, or finds the lock held and leaves
    // the minting to the next command) and neither clobbers the other's
    // write: a last-writer-wins here was one install counted twice.
    let first_run = state.install_id.is_none();
    if first_run {
        match claim_install_id(&dir, &state_path) {
            Some(claimed) => state = claimed,
            None => return,
        }
    }
    let visible = leaves_the_notice_visible(command);
    let disclose = disclosure_due(&state, tty) && visible;
    if disclose {
        state.disclosed = true;
        let _ = writeln!(std::io::stderr(), "{}", disclosure());
        if record_disclosed(&state_path).is_err() {
            return;
        }
    }
    // No request in the command that minted the id, nor in the one that
    // printed the disclosure: the request waits for a later command either
    // way. Without a terminal (an agent, a script, the installer's own
    // `finalize-install` call) the install is counted from its second
    // command, and its first command with a terminal still discloses, and
    // still sends nothing that time.
    if first_run || disclose {
        return;
    }
    // A terminal that has not read the disclosure yet (its commands so far
    // took the screen) sends nothing either: the first interactive command
    // that leaves the line visible discloses, and the request waits for the
    // one after. An install without a terminal is counted from its second
    // command, as the module doc says: that is inbox#589's decision, not a
    // gap here.
    if tty && !state.disclosed {
        return;
    }

    if due(&state, now_secs()) {
        let lock = dir.join(LOCK_FILE);
        // The child releases the lock when it is done; a child that never
        // started would otherwise hold it for LOCK_STALE.
        if acquire_lock(&lock) && !spawn_background(global) {
            release_lock(&lock);
        }
    }

    if tty
        && visible
        && let Some(latest) = notice_due(&state, &install)
    {
        let text = notice(&install, latest);
        let _ = writeln!(std::io::stderr(), "{text}");
        record_notified(&state_path, latest);
    }
}
