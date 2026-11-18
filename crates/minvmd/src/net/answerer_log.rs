//! The macOS box-name service's log and the launchd unit that keeps it
//! bounded, defined once.
//!
//! `min finalize-install` installs both for a user's own service and checks
//! them afterwards; the macOS package installs the same two for the service
//! a Mac's users share, from a root postinstall that cannot run `min` (root
//! reads nothing from `/usr/local`). The postinstall asks the service's own
//! program, already checked and root-owned, for the unit (`minzoned
//! log-cap-unit`), so the text has one source and the check in `min` cannot
//! disagree with what a package wrote.

/// The root-owned directory the service's log lives in.
pub const MACOS_LOG_DIR: &str = "/private/var/log/minimal";

/// The file the service's stdout and stderr go to.
pub const MACOS_LOG_PATH: &str = "/private/var/log/minimal/minzoned.log";

/// The size past which the cap job cuts the log down: 1 MiB.
pub const MAX_BYTES: u64 = 1024 * 1024;

/// What the cap job keeps of an oversized log: its last 256 KiB.
pub const KEEP_BYTES: u64 = 256 * 1024;

/// How often the cap job runs, in seconds: hourly.
pub const CAP_INTERVAL_SECS: u32 = 3600;

/// launchd's job label for the log's size cap.
pub const CAP_LABEL: &str = "dev.gominimal.zone.logcap";

/// The plist of the log's size cap.
pub const CAP_PLIST_PATH: &str = "/Library/LaunchDaemons/dev.gominimal.zone.logcap.plist";

/// The launchd unit that keeps the log bounded. launchd has no size limit
/// for `StandardOutPath`, and the service holds the file open for as long
/// as it runs, so a rename-based rotation would leave it writing to the
/// renamed file. launchd opens the log for append, so a cut in place is
/// safe: every [`CAP_INTERVAL_SECS`], a log over [`MAX_BYTES`] is cut to
/// its last [`KEEP_BYTES`]. The job runs as the account that owns the log,
/// never as root. `__SCRIPT__` is XML-escaped text.
const CAP_TEMPLATE: &str = "\
<?xml version=\"1.0\" encoding=\"UTF-8\"?>
<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">
<plist version=\"1.0\">
<dict>
\t<key>Label</key>
\t<string>dev.gominimal.zone.logcap</string>
\t<key>ProgramArguments</key>
\t<array>
\t\t<string>/bin/sh</string>
\t\t<string>-c</string>
\t\t<string>__SCRIPT__</string>
\t</array>
\t<key>UserName</key>
\t<string>__USER__</string>
\t<key>StartInterval</key>
\t<integer>__INTERVAL__</integer>
\t<key>RunAtLoad</key>
\t<true/>
</dict>
</plist>
";

/// The shell line the cap job runs: when the log is over [`MAX_BYTES`],
/// copy its tail to a temp file and write it back over the log. The log's
/// owner cannot create a file in the root-owned log directory, so the temp
/// file is `mktemp`'s.
#[must_use]
pub fn cap_script() -> String {
    format!(
        "f={MACOS_LOG_PATH}; \
         [ \"$(stat -f %z \"$f\" 2>/dev/null || echo 0)\" -gt {MAX_BYTES} ] || exit 0; \
         t=$(mktemp) || exit 1; \
         tail -c {KEEP_BYTES} \"$f\" > \"$t\" && cat \"$t\" > \"$f\"; \
         rm -f \"$t\""
    )
}

/// The cap's launchd unit for the account `user`, which owns the log and
/// runs the service.
#[must_use]
pub fn cap_plist(user: &str) -> String {
    CAP_TEMPLATE
        .replace("__SCRIPT__", &xml_escape(&cap_script()))
        .replace("__USER__", &xml_escape(user))
        .replace("__INTERVAL__", &CAP_INTERVAL_SECS.to_string())
}

/// `text` with the five XML special characters escaped, for a value a
/// plist carries inside a `<string>`.
#[must_use]
pub fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unit names the label its path carries, the account it was
    /// rendered for, and the one shell line, escaped for XML.
    #[test]
    fn the_cap_unit_carries_its_label_user_and_script() {
        let unit = cap_plist("_minimal");
        assert!(CAP_PLIST_PATH.ends_with(&format!("{CAP_LABEL}.plist")));
        assert!(unit.contains(&format!("<string>{CAP_LABEL}</string>")));
        assert!(unit.contains("<key>UserName</key>\n\t<string>_minimal</string>"));
        assert!(unit.contains(&format!("<integer>{CAP_INTERVAL_SECS}</integer>")));
        assert!(unit.contains(&xml_escape(&cap_script())), "{unit}");
        assert!(!unit.contains("__"), "every placeholder is filled: {unit}");
        assert_eq!(MACOS_LOG_PATH, format!("{MACOS_LOG_DIR}/minzoned.log"));
    }
}
