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

use serde::{Deserialize, Serialize};
use std::ffi::OsString;
use std::io::IsTerminal as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::cli::{GlobalArgs, UpdateCheckArgs};

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

/// What turned the check off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Off {
    /// `[telemetry] enabled = false` in the user config.
    Config,
    /// The user config exists but could not be read or parsed: the check
    /// fails closed until it is fixed, and says so rather than claiming a
    /// setting the file may not hold.
    ConfigUnreadable,
    /// An environment variable, named.
    Env(&'static str),
}

impl std::fmt::Display for Off {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Off::Config => f.write_str("[telemetry] enabled = false in config.toml"),
            Off::ConfigUnreadable => {
                f.write_str("a config.toml that could not be read or parsed (the check stays off until it is fixed)")
            }
            Off::Env(name) => write!(f, "{name} in the environment"),
        }
    }
}

/// The switch that turns the check off, if any. `DO_NOT_TRACK` (the
/// cross-tool convention) and `CI` win on presence; `MINIMAL_TELEMETRY`
/// turns it off when falsy (`0`, `false`, `no`, `off`; a truthy value is the
/// OpenTelemetry opt-in and says nothing here); then the config.
pub fn off_switch(config: ConfigState, var: impl Fn(&str) -> Option<OsString>) -> Option<Off> {
    let set = |name: &str| var(name).is_some_and(|v| !v.is_empty());
    if set("DO_NOT_TRACK") {
        return Some(Off::Env("DO_NOT_TRACK"));
    }
    if set("CI") {
        return Some(Off::Env("CI"));
    }
    let falsy = var("MINIMAL_TELEMETRY")
        .and_then(|v| v.into_string().ok())
        .is_some_and(|v| {
            ["0", "false", "no", "off"]
                .iter()
                .any(|t| v.trim().eq_ignore_ascii_case(t))
        });
    if falsy {
        return Some(Off::Env("MINIMAL_TELEMETRY"));
    }
    match config {
        ConfigState::Enabled => None,
        ConfigState::Disabled => Some(Off::Config),
        ConfigState::Unreadable => Some(Off::ConfigUnreadable),
    }
}

/// What the user config says about the check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigState {
    /// Missing, or present with the check on (the default).
    Enabled,
    /// `[telemetry] enabled = false`.
    Disabled,
    /// Present but not readable or not parsable.
    Unreadable,
}

/// How this binary was installed: the channel it came from, the method
/// (`installer`, `brew`, `apt`, `aur`, …) and the channel pointer at install
/// time, which is what the check compares against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Install {
    pub channel: String,
    pub method: String,
    pub key: String,
}

impl Install {
    /// A build with no install file: reports on the `source` channel with
    /// the build's own key, and is never notified.
    pub fn source() -> Self {
        Self {
            channel: SOURCE_CHANNEL.to_string(),
            method: SOURCE_CHANNEL.to_string(),
            key: build_key(version::VERSION),
        }
    }
}

/// The key a build with no install file compares by: the commit hash the
/// version string embeds (`0.8.0-dev.198.ge8f53f6e` → `e8f53f6e`), else the
/// version itself (a tagged release is `0.7.1`, and so is the stable
/// pointer).
pub fn build_key(version: &str) -> String {
    let hash = version.rsplit(".g").next().filter(|h| {
        version.contains(".g") && h.len() >= 7 && h.chars().all(|c| c.is_ascii_hexdigit())
    });
    hash.unwrap_or(version).to_string()
}

/// A field of the install file, as it may go into a request path, a query
/// or a terminal: the installer's own charset for a target or a version,
/// bounded.
pub fn valid_field(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

impl Install {
    fn valid(&self) -> bool {
        valid_field(&self.channel) && valid_field(&self.method) && valid_field(&self.key)
    }
}

/// The install description: the per-user file the installer wrote, else
/// the read-only one a package ships beside the binary
/// (`<prefix>/share/minimal/install.toml`, two levels up from `bin/min`),
/// else [`Install::source`]. A file that does not parse, or whose fields
/// are outside the charset a request path, query or terminal may carry,
/// counts as absent: a package's file is not this program's to trust.
pub fn read_install(state_dir: &Path, exe: Option<&Path>) -> Install {
    let per_user = state_dir.join(INSTALL_FILE);
    let packaged = exe
        .and_then(|e| e.parent())
        .and_then(|bin| bin.parent())
        .map(|prefix| prefix.join("share").join("minimal").join(INSTALL_FILE));
    [Some(per_user), packaged]
        .into_iter()
        .flatten()
        .find_map(|p| {
            let text = std::fs::read_to_string(p).ok()?;
            toml::from_str::<Install>(&text).ok().filter(Install::valid)
        })
        .unwrap_or_else(Install::source)
}

/// What the last check learned, and what this install has already been
/// told. Missing or unreadable: the default, as on a first run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct State {
    /// A random UUID v4 minted on the first run; deleting the file rotates it.
    pub install_id: Option<String>,
    /// Unix seconds of the last completed check (succeeded or not).
    pub checked_at: Option<u64>,
    /// The channel pointer the endpoint last answered with.
    pub latest: Option<String>,
    /// The channel that answer was for.
    pub latest_channel: Option<String>,
    /// The pointer the user was last told about: the notice prints once per
    /// new pointer.
    pub notified: Option<String>,
    /// The first-run disclosure has been printed.
    pub disclosed: bool,
}

pub fn read_state(path: &Path) -> State {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json_lenient::from_str(&t).ok())
        .unwrap_or_default()
}

/// Writes through a temp file and a rename, so a reader never sees a
/// partial file.
pub fn write_state(path: &Path, state: &State) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let tmp = dir.join(format!(".{}.{}", STATE_FILE, std::process::id()));
    let json = serde_json_lenient::to_vec_pretty(state).map_err(std::io::Error::other)?;
    std::fs::write(&tmp, json)?;
    std::fs::rename(&tmp, path)
}

/// Unix seconds now.
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// A check is due when none completed within [`INTERVAL`].
pub fn due(state: &State, now: u64) -> bool {
    state
        .checked_at
        .is_none_or(|t| now.saturating_sub(t) >= INTERVAL.as_secs())
}

/// Takes the lock that keeps two concurrent invocations from both spawning
/// a check: `O_EXCL` on [`LOCK_FILE`]. A lock older than [`LOCK_STALE`] is a
/// dead child's and is taken over. The child releases it ([`release_lock`]).
pub fn acquire_lock(path: &Path) -> bool {
    let try_create = || {
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .is_ok()
    };
    if try_create() {
        return true;
    }
    let stale = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .is_some_and(|age| age >= LOCK_STALE);
    stale && std::fs::remove_file(path).is_ok() && try_create()
}

pub fn release_lock(path: &Path) {
    let _ = std::fs::remove_file(path);
}

/// The state directory: `--minimal-dir`, else `$XDG_STATE_HOME/minimal`.
fn state_dir(global: &GlobalArgs) -> Option<PathBuf> {
    global
        .minimal_dir
        .clone()
        .or_else(|| paths::try_minimal_state_dir().map(|p| AsRef::<Path>::as_ref(&p).to_path_buf()))
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

/// The request the child makes.
pub fn request_url(base: &str, install: &Install, id: &str) -> String {
    format!(
        "{}/{}/{}?os={}&arch={}&install={}&id={}",
        base.trim_end_matches('/'),
        install.channel,
        install.key,
        std::env::consts::OS,
        std::env::consts::ARCH,
        install.method,
        id
    )
}

fn endpoint() -> String {
    std::env::var(ENDPOINT_VAR)
        .ok()
        .filter(|v| !v.trim().is_empty())
        .unwrap_or_else(|| ENDPOINT.to_string())
}

fn new_install_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The one line the first interactive run prints, before any request.
pub fn disclosure() -> String {
    format!(
        "min checks once a day whether a newer release of its channel exists, sending its channel, \
         version, OS, architecture, install method and a random install id to update.minimal.dev. \
         Off: MINIMAL_TELEMETRY=0, or [telemetry] enabled = false in config.toml. {DOCS_URL}"
    )
}

/// The notice: the newer pointer and the upgrade path for the recorded
/// install method. One function, so the text has one home (the verb a
/// self-update command gets is gominimal/arch#101's call; the installer
/// line needs none).
pub fn notice(install: &Install, latest: &str) -> String {
    let how = match install.method.as_str() {
        "installer" => format!("curl -fsSL https://go.minimal.dev/{} | sh", install.channel),
        "brew" => "brew upgrade min".to_string(),
        "apt" => "sudo apt update && sudo apt install --only-upgrade min".to_string(),
        "aur" => "update minimal-bin with your AUR helper".to_string(),
        _ => format!("see {DOCS_URL}"),
    };
    format!(
        "min {}: the {} channel is now at {latest}. To update: {how}",
        version::VERSION,
        install.channel
    )
}

/// Whether the disclosure is owed: not yet shown, and a terminal to show it
/// on. Independent of the install id, so an install whose first runs were a
/// script's (the installer's own `finalize-install` call, an agent) still
/// discloses on its first interactive run.
pub fn disclosure_due(state: &State, tty: bool) -> bool {
    tty && !state.disclosed
}

/// Whether a notice is owed: a channel install, an answer for that channel,
/// a pointer that is not the installed key, not yet told.
pub fn notice_due<'a>(state: &'a State, install: &Install) -> Option<&'a str> {
    if install.channel == SOURCE_CHANNEL {
        return None;
    }
    let latest = state.latest.as_deref()?;
    if state.latest_channel.as_deref() != Some(install.channel.as_str()) {
        return None;
    }
    if latest == install.key || state.notified.as_deref() == Some(latest) {
        return None;
    }
    Some(latest)
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

/// The per-command hook: never waits, never fails the command. See the
/// module doc.
pub fn before_command(global: &GlobalArgs, command: &Option<crate::cli::Command>) {
    if skip_for(command) {
        return;
    }
    if off_switch(config_state(global), |n| std::env::var_os(n)).is_some() {
        return;
    }
    let Some(dir) = state_dir(global) else {
        return;
    };
    let state_path = dir.join(STATE_FILE);
    let mut state = read_state(&state_path);
    let install = read_install(&dir, std::env::current_exe().ok().as_deref());
    let tty = std::io::stderr().is_terminal();

    let first_run = state.install_id.is_none();
    if first_run {
        state.install_id = Some(new_install_id());
    }
    let disclose = disclosure_due(&state, tty);
    if disclose {
        state.disclosed = true;
        let _ = writeln!(std::io::stderr(), "{}", disclosure());
    }
    if (first_run || disclose) && write_state(&state_path, &state).is_err() {
        return;
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

    if due(&state, now_secs()) {
        let lock = dir.join(LOCK_FILE);
        // The child releases the lock when it is done; a child that never
        // started would otherwise hold it for LOCK_STALE.
        if acquire_lock(&lock) && !spawn_background(global) {
            release_lock(&lock);
        }
    }

    if tty && let Some(latest) = notice_due(&state, &install) {
        let text = notice(&install, latest);
        state.notified = Some(latest.to_string());
        let _ = writeln!(std::io::stderr(), "{text}");
        let _ = write_state(&state_path, &state);
    }
}

/// The detached child: this binary, `update-check --background`, its own
/// process group, null stdio, never waited on. Whether it was spawned.
fn spawn_background(global: &GlobalArgs) -> bool {
    use std::os::unix::process::CommandExt as _;
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let mut cmd = std::process::Command::new(exe);
    if let Some(d) = &global.minimal_dir {
        cmd.arg("--minimal-dir").arg(d);
    }
    if let Some(d) = &global.config_dir {
        cmd.arg("--config-dir").arg(d);
    }
    // The child is bookkeeping, not a command of the user's: it must not
    // export or spool telemetry of its own under the parent's opt-in (an
    // integration test reading the parent's spool would see a stranger's
    // `cmd` span; a collector would count a trace nobody ran).
    // `OTEL_SDK_DISABLED` is the veto mlog honours ahead of the opt-in; the
    // check's own switch (`MINIMAL_TELEMETRY=0`) is left alone, since that
    // would stop the check itself.
    cmd.env("OTEL_SDK_DISABLED", "true")
        .env_remove(minimald_rpc::trace::TRACEPARENT_ENV)
        .args(["update-check", "--background"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .process_group(0);
    // Not waited on: a child that outlives a short command is reparented;
    // one that outlives a long one is reaped with it.
    cmd.spawn().is_ok()
}

/// Writes a check's outcome into the state file: `checked_at` now, and the
/// answer when there was one. The file is re-read first and only those
/// fields change: a command that ran during the request (up to
/// [`REQUEST_BUDGET`]) may have printed the notice and written `notified`,
/// and the state read before the request would put the stale value back.
pub fn record_answer(state_path: &Path, answer: Option<(String, String)>) {
    let mut state = read_state(state_path);
    if let Some((channel, latest)) = answer {
        state.latest = Some(latest);
        state.latest_channel = Some(channel);
    }
    state.checked_at = Some(now_secs());
    let _ = write_state(state_path, &state);
}

/// The endpoint's answer.
#[derive(Debug, Deserialize)]
struct Answer {
    channel: String,
    latest: String,
}

/// One GET within [`REQUEST_BUDGET`], no retry. Any failure is `None`.
pub async fn fetch_latest(url: &str) -> Option<(String, String)> {
    // One fixed-host GET: a redirect would carry the query (the install id,
    // the OS) to whatever host the answer named, over whatever scheme, so
    // none is followed.
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(REQUEST_BUDGET)
        .connect_timeout(REQUEST_BUDGET)
        .user_agent(format!("min/{}", version::VERSION))
        .build()
        .ok()?;
    let resp = client.get(url).send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    let text = resp.text().await.ok()?;
    let answer: Answer = serde_json_lenient::from_str(&text).ok()?;
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 64
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    };
    (ok(&answer.channel) && ok(&answer.latest)).then_some((answer.channel, answer.latest))
}

/// `min update-check`: the check, now. `--background` is the detached
/// child (silent, exit 0 whatever happens); `--dry-run` prints the request
/// that would be made and the switch that stops it, if any; neither flag
/// makes the request in the foreground and prints the answer.
pub async fn cmd_update_check(
    global: &GlobalArgs,
    args: UpdateCheckArgs,
) -> Result<(), anyhow::Error> {
    let off = off_switch(config_state(global), |n| std::env::var_os(n));
    let Some(dir) = state_dir(global) else {
        anyhow::bail!("no state directory (HOME is not set)");
    };
    let state_path = dir.join(STATE_FILE);
    let mut state = read_state(&state_path);
    let install = read_install(&dir, std::env::current_exe().ok().as_deref());
    // The placeholder is for the eye only: a request is never made with it.
    // A foreground check the user asked for on a fresh install mints the id
    // first, as a first command would; the background child never runs
    // without one (its parent minted it).
    // A disabled install keeps no id: the switches are read first.
    if state.install_id.is_none() && off.is_none() && !args.dry_run && !args.background {
        state.install_id = Some(new_install_id());
        // Sent only once it is on disk: an id that was not written would
        // be minted again next time, and the count would see two installs.
        write_state(&state_path, &state)
            .map_err(|e| anyhow::anyhow!("writing {}: {e}", state_path.display()))?;
    }
    let id = state
        .install_id
        .clone()
        .unwrap_or_else(|| "<minted on the first run>".to_string());
    let url = request_url(&endpoint(), &install, &id);

    if args.dry_run {
        println!("GET {url}");
        match off {
            Some(off) => println!("disabled by {off}: the request is not made"),
            None => println!("enabled: made at most once every 24 hours"),
        }
        println!(
            "channel {} via {}, installed key {}",
            install.channel, install.method, install.key
        );
        return Ok(());
    }
    if args.background {
        if off.is_none() && state.install_id.is_some() {
            let answer = fetch_latest(&url).await;
            record_answer(&state_path, answer);
        }
        release_lock(&dir.join(LOCK_FILE));
        return Ok(());
    }
    if let Some(off) = off {
        anyhow::bail!("the update check is disabled by {off}");
    }
    match fetch_latest(&url).await {
        Some((channel, latest)) => {
            let standing = if latest == install.key {
                "up to date"
            } else {
                "newer pointer available"
            };
            println!(
                "{channel}: {latest} ({standing}; installed key {})",
                install.key
            );
            if state.install_id.is_some() {
                record_answer(&state_path, Some((channel, latest)));
            }
            Ok(())
        }
        None => anyhow::bail!("no answer from {url} within {}s", REQUEST_BUDGET.as_secs()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<OsString> + 'a {
        move |n| {
            pairs
                .iter()
                .find(|(k, _)| *k == n)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn the_switches_each_turn_it_off_in_order() {
        assert_eq!(off_switch(ConfigState::Enabled, env(&[])), None);
        assert_eq!(
            off_switch(ConfigState::Enabled, env(&[("DO_NOT_TRACK", "1")])),
            Some(Off::Env("DO_NOT_TRACK"))
        );
        assert_eq!(
            off_switch(ConfigState::Enabled, env(&[("CI", "true")])),
            Some(Off::Env("CI"))
        );
        assert_eq!(
            off_switch(ConfigState::Enabled, env(&[("CI", "")])),
            None,
            "an empty CI is unset"
        );
        for v in ["0", "false", "NO", " off "] {
            assert_eq!(
                off_switch(ConfigState::Enabled, env(&[("MINIMAL_TELEMETRY", v)])),
                Some(Off::Env("MINIMAL_TELEMETRY")),
                "{v:?} is falsy"
            );
        }
        assert_eq!(
            off_switch(ConfigState::Enabled, env(&[("MINIMAL_TELEMETRY", "1")])),
            None,
            "the OTel opt-in is not a switch here"
        );
        assert_eq!(
            off_switch(ConfigState::Disabled, env(&[])),
            Some(Off::Config)
        );
        assert_eq!(
            off_switch(ConfigState::Unreadable, env(&[])),
            Some(Off::ConfigUnreadable),
            "an unreadable config fails closed, and says that, not a setting it may not hold"
        );
        assert!(
            Off::ConfigUnreadable
                .to_string()
                .contains("could not be read")
        );
        assert_eq!(
            off_switch(ConfigState::Disabled, env(&[("DO_NOT_TRACK", "1")])),
            Some(Off::Env("DO_NOT_TRACK")),
            "the environment is named ahead of the config"
        );
    }

    #[test]
    fn the_build_key_is_the_embedded_hash_else_the_version() {
        assert_eq!(build_key("0.8.0-dev.198.ge8f53f6e"), "e8f53f6e");
        assert_eq!(build_key("0.7.1"), "0.7.1");
        assert_eq!(
            build_key("0.7.1-dev.3.gzz"),
            "0.7.1-dev.3.gzz",
            "not a hash"
        );
    }

    #[test]
    fn the_install_file_precedence_is_user_then_package_then_source() {
        let tmp = tempfile::TempDir::new().unwrap();
        let state = tmp.path().join("state");
        let prefix = tmp.path().join("prefix");
        let exe = prefix.join("bin").join("min");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::create_dir_all(prefix.join("share").join("minimal")).unwrap();

        let source = read_install(&state, Some(&exe));
        assert_eq!(source.channel, SOURCE_CHANNEL);
        assert_eq!(source.key, build_key(version::VERSION));

        std::fs::write(
            prefix.join("share").join("minimal").join(INSTALL_FILE),
            "channel = \"stable\"\nmethod = \"brew\"\nkey = \"0.7.0\"\n",
        )
        .unwrap();
        let packaged = read_install(&state, Some(&exe));
        assert_eq!(
            (
                packaged.channel.as_str(),
                packaged.method.as_str(),
                packaged.key.as_str()
            ),
            ("stable", "brew", "0.7.0")
        );

        std::fs::write(
            state.join(INSTALL_FILE),
            "channel = \"nightly\"\nmethod = \"installer\"\nkey = \"5a93a07a\"\n",
        )
        .unwrap();
        let user = read_install(&state, Some(&exe));
        assert_eq!(
            (
                user.channel.as_str(),
                user.method.as_str(),
                user.key.as_str()
            ),
            ("nightly", "installer", "5a93a07a")
        );

        std::fs::write(state.join(INSTALL_FILE), "channel = \n").unwrap();
        assert_eq!(
            read_install(&state, Some(&exe)).method,
            "brew",
            "an unparsable user file is absent"
        );
        std::fs::write(
            state.join(INSTALL_FILE),
            "channel = \"../x?a=b\"\nmethod = \"installer\"\nkey = \"0.7.1\"\n",
        )
        .unwrap();
        assert_eq!(
            read_install(&state, Some(&exe)).method,
            "brew",
            "a field outside the charset makes the file absent"
        );
        std::fs::write(
            state.join(INSTALL_FILE),
            "channel = \"stable\"\nmethod = \"installer\"\nkey = \"0.7.1\\u001b[31m\"\n",
        )
        .unwrap();
        assert_eq!(
            read_install(&state, Some(&exe)).method,
            "brew",
            "a control character makes the file absent"
        );
    }

    #[test]
    fn install_fields_are_the_installer_charset_bounded() {
        for ok in [
            "stable",
            "0.7.1",
            "5a93a07a",
            "installer",
            "0.8.0-dev.198.ge8f53f6e",
        ] {
            assert!(valid_field(ok), "{ok}");
        }
        for bad in [
            "",
            "../x",
            "a?b=c",
            "a&b",
            "a b",
            "\u{1b}[31m",
            &"x".repeat(65),
        ] {
            assert!(!valid_field(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_state_round_trips_and_a_bad_file_is_the_default() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("sub").join(STATE_FILE);
        assert_eq!(read_state(&path), State::default());
        let state = State {
            install_id: Some("id".into()),
            checked_at: Some(7),
            latest: Some("0.7.2".into()),
            latest_channel: Some("stable".into()),
            notified: None,
            disclosed: true,
        };
        write_state(&path, &state).unwrap();
        assert_eq!(read_state(&path), state);
        assert!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count() == 1,
            "no temp file left behind"
        );
        std::fs::write(&path, "{not json").unwrap();
        assert_eq!(read_state(&path), State::default());
    }

    #[test]
    fn a_check_is_due_daily() {
        let day = INTERVAL.as_secs();
        assert!(due(&State::default(), 1_000_000));
        let s = State {
            checked_at: Some(1_000_000),
            ..State::default()
        };
        assert!(!due(&s, 1_000_000 + day - 1));
        assert!(due(&s, 1_000_000 + day));
        assert!(!due(&s, 999_000), "a clock that went backwards is not due");
    }

    #[test]
    fn the_lock_is_exclusive_until_stale() {
        let tmp = tempfile::TempDir::new().unwrap();
        let lock = tmp.path().join(LOCK_FILE);
        assert!(acquire_lock(&lock));
        assert!(!acquire_lock(&lock), "held");
        let old = SystemTime::now() - LOCK_STALE - Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&lock)
            .unwrap()
            .set_modified(old)
            .unwrap();
        assert!(acquire_lock(&lock), "a stale lock is taken over");
        release_lock(&lock);
        assert!(acquire_lock(&lock), "released");
    }

    #[test]
    fn the_disclosure_is_owed_on_the_first_terminal_run_whatever_came_before() {
        let fresh = State::default();
        assert!(disclosure_due(&fresh, true));
        assert!(!disclosure_due(&fresh, false), "no terminal, no text");
        let scripted_first = State {
            install_id: Some("id".into()),
            ..State::default()
        };
        assert!(
            disclosure_due(&scripted_first, true),
            "an id minted by a script's run does not count as disclosed"
        );
        let shown = State {
            disclosed: true,
            ..scripted_first
        };
        assert!(!disclosure_due(&shown, true), "once");
    }

    #[test]
    fn recording_an_answer_keeps_what_another_command_wrote_meanwhile() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join(STATE_FILE);
        write_state(
            &path,
            &State {
                install_id: Some("id".into()),
                ..State::default()
            },
        )
        .unwrap();
        // Between the child's read and its write, a command told the user
        // about 0.7.2 and wrote `notified`.
        write_state(
            &path,
            &State {
                install_id: Some("id".into()),
                notified: Some("0.7.2".into()),
                disclosed: true,
                ..State::default()
            },
        )
        .unwrap();
        record_answer(&path, Some(("stable".into(), "0.7.2".into())));
        let after = read_state(&path);
        assert_eq!(
            after.notified.as_deref(),
            Some("0.7.2"),
            "the notice is not printed again"
        );
        assert!(after.disclosed);
        assert_eq!(after.latest.as_deref(), Some("0.7.2"));
        assert!(after.checked_at.is_some());
        record_answer(&path, None);
        let failed = read_state(&path);
        assert_eq!(
            failed.latest.as_deref(),
            Some("0.7.2"),
            "a failed check keeps the last answer"
        );
        assert!(
            failed.checked_at.is_some(),
            "and still counts as a check, so there is no retry storm"
        );
    }

    #[test]
    fn the_notice_is_owed_once_per_new_pointer_on_a_channel_install() {
        let install = Install {
            channel: "stable".into(),
            method: "installer".into(),
            key: "0.7.1".into(),
        };
        let mut state = State {
            latest: Some("0.7.2".into()),
            latest_channel: Some("stable".into()),
            ..State::default()
        };
        assert_eq!(notice_due(&state, &install), Some("0.7.2"));
        state.notified = Some("0.7.2".into());
        assert_eq!(notice_due(&state, &install), None, "told already");
        state.latest = Some("0.7.3".into());
        assert_eq!(
            notice_due(&state, &install),
            Some("0.7.3"),
            "a newer pointer is told again"
        );
        state.latest = Some("0.7.1".into());
        assert_eq!(
            notice_due(&state, &install),
            None,
            "the installed key is up to date"
        );
        state.latest = Some("0.7.9".into());
        state.latest_channel = Some("nightly".into());
        assert_eq!(
            notice_due(&state, &install),
            None,
            "an answer for another channel is not this install's"
        );
        state.latest_channel = Some("source".into());
        let source = Install::source();
        state.latest = Some("anything".into());
        assert_eq!(
            notice_due(&state, &source),
            None,
            "a source build is never notified"
        );
    }

    #[test]
    fn the_notice_names_the_pointer_and_the_upgrade_path() {
        let install = Install {
            channel: "stable".into(),
            method: "installer".into(),
            key: "0.7.1".into(),
        };
        let text = notice(&install, "0.7.2");
        assert!(text.contains("0.7.2"), "{text}");
        assert!(
            text.contains("curl -fsSL https://go.minimal.dev/stable | sh"),
            "{text}"
        );
        let brew = Install {
            method: "brew".into(),
            ..install.clone()
        };
        assert!(notice(&brew, "0.7.2").contains("brew upgrade min"));
        let other = Install {
            method: "snap".into(),
            ..install
        };
        assert!(notice(&other, "0.7.2").contains(DOCS_URL));
        assert!(disclosure().contains("MINIMAL_TELEMETRY=0"));
    }

    #[test]
    fn the_request_carries_the_eight_fields_and_nothing_more() {
        let install = Install {
            channel: "stable".into(),
            method: "installer".into(),
            key: "0.7.1".into(),
        };
        let url = request_url("https://u.example/v1/", &install, "abc");
        let (path, query) = url.split_once('?').unwrap();
        assert_eq!(path, "https://u.example/v1/stable/0.7.1");
        let keys: Vec<_> = query
            .split('&')
            .map(|kv| kv.split_once('=').unwrap().0)
            .collect();
        assert_eq!(keys, ["os", "arch", "install", "id"]);
        assert!(query.ends_with("install=installer&id=abc"));
    }

    /// A stub answering `status` after `delay`, on 127.0.0.1; the URL to GET.
    fn stub(status: &'static str, body: &'static str, delay: Duration) -> String {
        use std::io::{Read as _, Write as _};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(1) {
                let mut s = stream.unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                std::thread::sleep(delay);
                let _ = write!(
                    s,
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        format!(
            "http://127.0.0.1:{port}/v1/stable/0.7.1?os=linux&arch=x86_64&install=installer&id=x"
        )
    }

    #[tokio::test]
    async fn a_good_answer_is_the_channel_and_the_pointer() {
        let url = stub(
            "200 OK",
            r#"{"channel":"stable","latest":"0.7.2"}"#,
            Duration::ZERO,
        );
        assert_eq!(
            fetch_latest(&url).await,
            Some(("stable".into(), "0.7.2".into()))
        );
    }

    #[tokio::test]
    async fn a_404_an_odd_body_and_a_slow_endpoint_are_silent_within_the_budget() {
        let url = stub("404 Not Found", "{}", Duration::ZERO);
        assert_eq!(fetch_latest(&url).await, None);
        let url = stub(
            "200 OK",
            r#"{"channel":"stable","latest":"../x"}"#,
            Duration::ZERO,
        );
        assert_eq!(
            fetch_latest(&url).await,
            None,
            "a pointer outside the charset is refused"
        );
        let url = stub(
            "200 OK",
            r#"{"channel":"stable","latest":"0.7.2"}"#,
            REQUEST_BUDGET + Duration::from_secs(2),
        );
        let t0 = std::time::Instant::now();
        assert_eq!(fetch_latest(&url).await, None);
        assert!(
            t0.elapsed() < REQUEST_BUDGET + Duration::from_millis(900),
            "gave up at the budget: {:?}",
            t0.elapsed()
        );
        let unreachable = "http://127.0.0.1:9/v1/stable/0.7.1";
        assert_eq!(fetch_latest(unreachable).await, None);
    }
}
