//! What the user reads: the one-time disclosure, the notice that the
//! channel moved on, and when each is owed.

use super::{DOCS_URL, Install, PINNED_CHANNEL, SOURCE_CHANNEL, State};

/// The one line the first interactive run prints, before any request.
pub fn disclosure() -> String {
    format!(
        "min checks once a day whether a newer release of its channel exists, sending its channel, \
         version, OS, architecture, install method and a random install id to update.minimal.dev. \
         Off: MINIMAL_TELEMETRY=0, or [telemetry] enabled = false in config.toml. {DOCS_URL}"
    )
}

/// The notice: the newer pointer, and where the update paths are written
/// up. One function, so the text has one home. No command is printed: the
/// per-method upgrade lines named packages nothing ships yet (no package
/// writes an `install.toml`), and the installer line is gominimal/arch#101's
/// call; a line the user can run as written goes here once one exists.
pub fn notice(install: &Install, latest: &str) -> String {
    format!(
        "min {}: the {} channel is now at {latest}. How to update: {DOCS_URL}",
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
