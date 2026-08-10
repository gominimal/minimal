//! Last-session memory: a tiny JSON state file at
//! `$XDG_STATE_HOME/minimal/dash-state.json` so re-opening `min dash`
//! restores the cursor to the session it was last on.

use std::io;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// The persisted TUI state. Stores only a session id and provider label —
/// no credentials, no secrets.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DashState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_provider: Option<String>,
}

/// The state file's path: `<base>/dash-state.json`, where `base` is the
/// `--minimal-dir` override when given, else the platform minimal state dir
/// (`$XDG_STATE_HOME/minimal`, see [`paths::minimal_state_dir`]). Keying on
/// the override keeps an isolated daemon's cursor memory out of the user's
/// real state file.
pub fn state_path(base: Option<&std::path::Path>) -> PathBuf {
    match base {
        Some(dir) => dir.join("dash-state.json"),
        None => paths::minimal_state_dir()
            .as_utf8_path()
            .join("dash-state.json")
            .into(),
    }
}

/// Loads the state file. A missing or unreadable file reads as the default
/// (empty) state — the TUI simply starts on the first row instead.
pub fn load(base: Option<&std::path::Path>) -> DashState {
    let Ok(bytes) = std::fs::read(state_path(base)) else {
        return DashState::default();
    };
    serde_json_lenient::from_slice(&bytes).unwrap_or_default()
}

/// Writes the state file with owner-only permissions, matching the socket
/// directory convention. Creates the parent dir if needed.
pub fn save(base: Option<&std::path::Path>, state: &DashState) -> io::Result<()> {
    let path = state_path(base);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json_lenient::to_vec_pretty(state).map_err(io::Error::other)?;
    std::fs::write(&path, bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_round_trips_through_json() {
        let state = DashState {
            last_session_id: Some("a1b2".to_string()),
            last_provider: Some("host".to_string()),
        };
        let json = serde_json_lenient::to_string(&state).unwrap();
        assert_eq!(
            serde_json_lenient::from_str::<DashState>(&json).unwrap(),
            state
        );
    }

    #[test]
    fn empty_file_reads_as_default() {
        assert_eq!(
            serde_json_lenient::from_slice::<DashState>(b"").unwrap_or_default(),
            DashState::default()
        );
    }

    #[test]
    fn save_then_load_round_trips_under_an_override_dir() {
        let dir = std::env::temp_dir().join(format!("dash-state-test-{}", std::process::id()));
        let state = DashState {
            last_session_id: Some("a1b2".to_string()),
            last_provider: Some("host".to_string()),
        };
        save(Some(&dir), &state).unwrap();
        assert_eq!(load(Some(&dir)), state);
        // Owner-only, per the socket-directory convention.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(dir.join("dash-state.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
