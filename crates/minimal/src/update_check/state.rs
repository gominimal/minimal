//! What the check keeps on disk: the install description the installer
//! wrote ([`Install`]), the state file ([`State`]) with its two writers
//! that never clobber a concurrent one ([`record_answer`],
//! [`record_notified`]), the daily cadence ([`due`]) and the lock between
//! two commands that would both spawn a check.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use super::{INSTALL_FILE, INTERVAL, LOCK_STALE, SOURCE_CHANNEL, STATE_FILE};

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

/// A field read back from the state file is trusted no further than one
/// read from the install file: the id goes into the request query and the
/// pointer onto the terminal, and the file is the user's to edit. A value
/// outside the charset is dropped (an id is minted again; a pointer is
/// fetched again).
pub fn read_state(path: &Path) -> State {
    let mut state: State = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| serde_json_lenient::from_str(&t).ok())
        .unwrap_or_default();
    state.install_id = state.install_id.filter(|id| valid_install_id(id));
    state.latest = state.latest.filter(|s| valid_field(s));
    state.latest_channel = state.latest_channel.filter(|s| valid_field(s));
    state.notified = state.notified.filter(|s| valid_field(s));
    state
}

/// The shape [`new_install_id`] mints: a hyphenated UUID, lowercase hex.
pub fn valid_install_id(id: &str) -> bool {
    id.len() == 36
        && id.chars().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                c == '-'
            } else {
                c.is_ascii_hexdigit() && !c.is_ascii_uppercase()
            }
        })
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

/// A check is due when none completed within [`INTERVAL`]. A `checked_at`
/// ahead of now by less than the interval is a clock that stepped back a
/// little and is not due (no extra request for skew); one ahead by more than
/// the interval (a clock set wrong once, a copied state file) is due, rather
/// than holding the check off until the clock catches up.
pub fn due(state: &State, now: u64) -> bool {
    let day = INTERVAL.as_secs();
    state
        .checked_at
        .is_none_or(|t| t > now + day || now.saturating_sub(t) >= day)
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

pub(super) fn new_install_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// The install id, minted if the file has none: taken under the spawn lock
/// ([`acquire_lock`]) so two first commands running together mint one id
/// between them, and written by re-reading the file so nothing another
/// command wrote meanwhile is put back. `None` when the lock is held (the
/// other command is minting, or has spawned the check; this command does
/// nothing and the next one finds the id) or the write failed.
pub(super) fn claim_install_id(dir: &Path, state_path: &Path) -> Option<State> {
    let lock = dir.join(super::LOCK_FILE);
    if !acquire_lock(&lock) {
        return None;
    }
    let mut state = read_state(state_path);
    let written = match state.install_id {
        Some(_) => Ok(()),
        None => {
            state.install_id = Some(new_install_id());
            write_state(state_path, &state)
        }
    };
    release_lock(&lock);
    written.ok().map(|()| state)
}

/// Records that the disclosure was printed. Re-read and one field changed,
/// as [`record_notified`] does, so a child's answer written meanwhile stays.
pub(super) fn record_disclosed(state_path: &Path) -> std::io::Result<()> {
    let mut state = read_state(state_path);
    state.disclosed = true;
    write_state(state_path, &state)
}

/// Records that the user was told about `latest`. The file is re-read and
/// only `notified` changes: the child this command may have just spawned
/// can finish in between, and its answer must not be overwritten with the
/// state read before it (then the next command would check again, and the
/// notice could repeat).
pub fn record_notified(state_path: &Path, latest: &str) {
    let mut state = read_state(state_path);
    state.notified = Some(latest.to_string());
    // A state file that cannot be written costs one repeated notice on a
    // later command; the command this runs before has nothing to say about it.
    let _ = write_state(state_path, &state);
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
    // Unwritable: the next command finds the check still due and tries again;
    // this is the silent background child, with nobody to tell.
    let _ = write_state(state_path, &state);
}
