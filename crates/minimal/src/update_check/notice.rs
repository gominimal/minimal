//! What the user reads: the one-time disclosure, the notice that the
//! channel moved on, and when each is owed.

use super::{DOCS_URL, Install, PINNED_CHANNEL, SOURCE_CHANNEL, State};

/// The one line the first interactive run prints, before any request.
pub fn disclosure() -> String {
    format!(
        "min checks once a day whether a newer release of its channel exists, sending its channel, \
         version, OS, architecture, install method and a random install id to update.minimal.dev. \
         UpdateDisabledReason: MINIMAL_TELEMETRY=0, or [telemetry] enabled = false in config.toml. {DOCS_URL}"
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
    if install.channel == SOURCE_CHANNEL || install.channel == PINNED_CHANNEL {
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
