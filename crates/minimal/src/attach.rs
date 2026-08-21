//! Smart session resolution and the interactive attach picker.
//!
//! When `min session attach` is invoked without a session reference (or `min` is
//! invoked bare), the client has to decide which session to attach to. The
//! rules (issue #837) prefer a session built from the current working
//! directory, fall back to the only session in the store when exactly one
//! exists, and otherwise present an interactive picker.
//!
//! The picker lives here rather than in `async-dialog` (which assumes the
//! terminal is already in raw mode, e.g. behind an SSH channel): a local
//! `min` invocation is attached to a real TTY, so we use `inquire`, which
//! owns its own raw-mode handling and fuzzy-filters by default.

use std::fmt;
use std::io::{IsTerminal as _, Write as _};

use anyhow::Context as _;
use minimald_rpc::ListSessionsEntry;

/// The escape sequences that put a terminal back into the state a shell
/// expects, whatever the session left it in: mouse reporting and its encodings
/// off, bracketed paste off, application cursor keys and keypad off, off the
/// alternate screen, cursor visible, drawing attributes and focus reporting
/// reset.
///
/// The same set `minimald` computes per session as its unwind codes, minus the
/// "only if currently set" narrowing — a client has no screen model to diff
/// against, and every sequence here is a no-op against a terminal that was
/// never in that mode.
const TERMINAL_UNWIND: &[u8] = concat!(
    // mouse reporting: press, press/release, button-motion, any-motion
    "\x1b[?9l\x1b[?1000l\x1b[?1002l\x1b[?1003l",
    // mouse encodings: utf-8, SGR, urxvt
    "\x1b[?1005l\x1b[?1006l\x1b[?1015l",
    // bracketed paste, application cursor keys, application keypad
    "\x1b[?2004l\x1b[?1l\x1b>",
    // leave the alternate screen, unhide the cursor
    "\x1b[?1049l\x1b[?25h",
    // blind: reset drawing attributes ('SGR') and focus reporting
    "\x1b[m\x1b[?1004l",
)
.as_bytes();

/// Restores the terminal on drop, unconditionally, around an attach.
///
/// `minimald` sends unwind codes with every teardown it initiates, but the
/// client cannot assume it will hear them: a daemon predating #1210 sends none
/// when the session process dies, and a transport that drops mid-session sends
/// nothing at all. By then this process is the only thing left that can still
/// reach the tty — ssh restores termios but knows nothing of the DEC private
/// modes the remote app set — so it writes the sequences itself on the way
/// out, and a session that died with mouse reporting on cannot leave the
/// user's shell spraying escape sequences whenever the mouse moves.
///
/// Writing them after a well-behaved teardown is harmless: the sequences are
/// idempotent, and the daemon has already written the same ones.
pub(crate) struct TerminalUnwind {
    /// Whether there is a terminal to write to at all. A redirected stdout
    /// gets nothing — the bytes would be data in whatever captured it, and a
    /// pipe has no modes to restore.
    armed: bool,
}

impl TerminalUnwind {
    pub(crate) fn arm() -> Self {
        Self {
            armed: std::io::stdout().is_terminal(),
        }
    }
}

impl Drop for TerminalUnwind {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Best-effort: this runs on the way out of an attach, and a terminal
        // that cannot be written to is already beyond repair.
        let mut out = std::io::stdout();
        let _ = out.write_all(TERMINAL_UNWIND);
        let _ = out.flush();
    }
}

/// The current working directory as a host path, respecting the `--repo-dir`
/// (`-C`) override. The result is canonicalized so it compares equal to a
/// `Record.project_path`, which `cmd_activate` canonicalizes at create time.
///
/// # Errors
///
/// Returns an error if the current directory cannot be read or resolved, or
/// the resolved path is not valid UTF-8.
pub(crate) fn cwd_host_path(
    global: &crate::GlobalArgs,
) -> Result<paths::HostAbsPath, anyhow::Error> {
    let raw = match &global.repo_dir {
        Some(dir) => dir.clone(),
        None => std::env::current_dir().context("determine current working directory")?,
    };
    let canonical = std::fs::canonicalize(&raw)
        .with_context(|| format!("cannot resolve path '{}'", raw.display()))?;
    let utf8 = camino::Utf8PathBuf::from_path_buf(canonical)
        .map_err(|_| anyhow::anyhow!("current working directory is not valid UTF-8"))?;
    paths::HostAbsPath::try_new(utf8).context("invalid current working directory")
}

/// The outcome of smart session resolution for attach.
#[derive(Debug)]
pub(crate) enum SmartResolve {
    /// Exactly one candidate matched (or only one session exists); attach
    /// directly to this session.
    Attach(ListSessionsEntry),
    /// No sessions exist at all. The caller decides whether to error
    /// (`min session attach`) or activate a new session (bare `min`).
    NoSessions,
    /// More than one candidate; the caller must pick. The candidates are
    /// already limited to cwd-matches when any matched, else the full list.
    Pick(Vec<ListSessionsEntry>),
}

/// Resolve which session to attach to, given the full session list and the
/// current working directory.
///
/// Rules (issue #837):
/// - Exactly one session shares the cwd → attach to it.
/// - More than one session shares the cwd → pick among the cwd matches.
/// - No cwd match, but exactly one session exists → attach to it.
/// - No cwd match, more than one session → pick among all sessions.
/// - No sessions → [`SmartResolve::NoSessions`].
///
/// Pure: performs no I/O, so it is straightforward to unit-test.
pub(crate) fn resolve_for_attach(
    entries: &[ListSessionsEntry],
    cwd: &paths::HostAbsPath,
) -> SmartResolve {
    if entries.is_empty() {
        return SmartResolve::NoSessions;
    }
    let cwd_matches: Vec<&ListSessionsEntry> = entries
        .iter()
        .filter(|e| e.project_path.as_ref() == Some(cwd))
        .collect();
    match cwd_matches.len() {
        0 => match entries.len() {
            1 => SmartResolve::Attach(entries[0].clone()),
            _ => SmartResolve::Pick(entries.to_vec()),
        },
        1 => SmartResolve::Attach(cwd_matches[0].clone()),
        _ => SmartResolve::Pick(cwd_matches.into_iter().cloned().collect()),
    }
}

/// The ` — created from <path>` suffix for the attach announcement. On the
/// no-cwd-match/single-session branch the operator is by definition somewhere
/// other than the session's project directory, so naming the origin is a
/// tripwire against working in the wrong box. Empty when the cwd matched (the
/// match is its own confirmation) or the record predates `project_path`.
pub(crate) fn created_from_suffix(entry: &ListSessionsEntry, cwd: &paths::HostAbsPath) -> String {
    match entry.project_path.as_ref() {
        Some(path) if path != cwd => format!(" — created from {path}"),
        _ => String::new(),
    }
}

/// Whether the picker can actually run: it draws to stdout and reads
/// keystrokes from stdin, so both must be a real terminal. A redirected
/// stdin (a script, a pipe) would hang waiting for a keypress that never
/// arrives, so we preempt it here and let the caller fall back to the
/// non-interactive error path.
pub(crate) fn can_pick_interactively() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

/// A pickable session. `Display` renders the row the user sees and fuzzy-
/// searches against; the carried entry preserves the id/name so the chosen
/// one can be attached without a follow-up round-trip.
#[derive(Clone)]
struct SessionCandidate {
    entry: ListSessionsEntry,
    label: String,
}

impl fmt::Display for SessionCandidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.label)
    }
}

/// One-row glyph for a session's lifecycle status, used as a visual prefix
/// in the picker. `Active` sessions are ready to attach; `Pending` and
/// `Materializing` ones aren't attachable yet — `Pending` is still awaiting
/// the client's verdict, `Materializing` has finalized its composition but
/// is still ingesting patches. Both render with the hollow glyph so the
/// picker communicates "not-yet-ready" uniformly.
fn state_glyph(status: sessions::SessionStatus) -> &'static str {
    match status {
        sessions::SessionStatus::Active => "●",
        sessions::SessionStatus::Pending | sessions::SessionStatus::Materializing => "◯",
    }
}

/// The most recent activity timestamp on a session, for ordering the picker
/// with the freshest session first. Falls back to `None` when the session has
/// no recorded activity (never attached, or running on an older daemon that
/// doesn't report attrs). Picks the later of stdout/stdin so a session that
/// received input after its last output still sorts first.
fn last_activity(entry: &ListSessionsEntry) -> Option<chrono::DateTime<chrono::Utc>> {
    entry
        .attrs
        .as_ref()
        .and_then(|a| a.last_stdout.into_iter().chain(a.last_stdin).max())
}

/// Formats a single session as a picker row: `glyph  name | title · path`,
/// eliding the title segment when the session has none, and tagging rows
/// built from the current working directory so the cwd match is visible at
/// a glance even in the "pick over all sessions" case. Unnamed sessions
/// render as `(unnamed) · <id-prefix>` — the first id segment is enough to
/// tell same-path rows apart without a full UUID.
fn format_candidate(entry: &ListSessionsEntry, cwd: &paths::HostAbsPath) -> String {
    let glyph = state_glyph(entry.status);
    let name = entry.name.clone().unwrap_or_else(|| {
        let id = entry.id.to_string();
        let short = id.split('-').next().unwrap_or(&id);
        format!("(unnamed) · {short}")
    });
    let title = entry
        .attrs
        .as_ref()
        .and_then(|a| a.title.as_ref())
        .map(|t| t.value.as_str())
        .unwrap_or("");
    let cwd_marker = if entry.project_path.as_ref() == Some(cwd) {
        " (cwd)"
    } else {
        ""
    };
    let head = if title.is_empty() {
        name
    } else {
        format!("{name} | {title}")
    };
    let path = entry
        .project_path
        .as_ref()
        .map(paths::HostAbsPath::to_string)
        .unwrap_or_else(|| "(unknown)".to_string());
    format!("{glyph} {head} · {path}{cwd_marker}")
}

/// A row in the attach picker: an existing session to attach to, or the
/// trailing affordance that creates a fresh session for the cwd. `Display`
/// renders the row the user sees and fuzzy-searches against.
#[derive(Clone)]
enum PickerRow {
    Session(SessionCandidate),
    CreateNew(String),
}

impl fmt::Display for PickerRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PickerRow::Session(c) => c.fmt(f),
            PickerRow::CreateNew(label) => f.write_str(label),
        }
    }
}

/// The user's choice from the attach picker.
pub(crate) enum Picked {
    /// Attach to this existing session.
    Session(ListSessionsEntry),
    /// The create row was chosen: activate a fresh session for the cwd and
    /// attach, exactly as `min session activate --attach .` would.
    CreateNew,
}

/// The trailing `+ Create a new session for <cwd>` picker row. Rendered without
/// a state glyph so it reads as an action rather than a session, and always
/// placed last so it never displaces an existing session.
fn create_row_label(cwd: &paths::HostAbsPath) -> String {
    format!("+ Create a new session for {cwd}")
}

/// Maps a chosen picker row to the attach outcome. Split out so the selection
/// arm is unit-testable without a live terminal.
fn resolve_pick(row: PickerRow) -> Picked {
    match row {
        PickerRow::Session(c) => Picked::Session(c.entry),
        PickerRow::CreateNew(_) => Picked::CreateNew,
    }
}

/// Runs the interactive session picker over `candidates`, ordered with the
/// most recently active session first and a trailing create-new row. Returns
/// the user's choice — an existing session or the create affordance — or
/// `None` if the user dismissed the prompt (Esc / Ctrl-C / Ctrl-D / EOF).
///
/// # Errors
///
/// Returns an error if the picker itself fails (e.g. a terminal I/O fault).
/// The "not a TTY" and "cancelled" cases are handled by the caller via
/// [`can_pick_interactively`] and the `Option` return respectively.
pub(crate) fn pick_session(
    candidates: &[ListSessionsEntry],
    cwd: &paths::HostAbsPath,
) -> Result<Option<Picked>, anyhow::Error> {
    // Most recently active first; sessions without activity sort last in a
    // stable order so the picker doesn't reshuffle between invocations.
    let mut ordered: Vec<&ListSessionsEntry> = candidates.iter().collect();
    ordered.sort_by_key(|e| std::cmp::Reverse(last_activity(e)));

    let mut items: Vec<PickerRow> = ordered
        .iter()
        .map(|e| {
            PickerRow::Session(SessionCandidate {
                entry: (*e).clone(),
                label: format_candidate(e, cwd),
            })
        })
        .collect();
    // Always last, so it never displaces an existing session.
    items.push(PickerRow::CreateNew(create_row_label(cwd)));

    let choice = match inquire::Select::new("Select a session to attach:", items).prompt_skippable()
    {
        Ok(c) => c,
        // `prompt_skippable` already maps Esc (OperationCanceled) to `Ok(None)`.
        // Ctrl-C (OperationInterrupted) is NOT covered by it — and because we
        // run crossterm in raw mode, Ctrl-C is captured by inquire rather than
        // delivered as SIGINT, so we must handle it here or the user sees
        // "session picker: The operation was interrupted by the user" instead
        // of a clean abort. Treat it like Esc: a dismissal returns `Ok(None)`,
        // and the caller surfaces "session selection cancelled".
        Err(inquire::InquireError::OperationInterrupted) => return Ok(None),
        Err(e) => return Err(e).context("session picker"),
    };
    Ok(choice.map(resolve_pick))
}

/// The error message shown when smart resolution is ambiguous but the picker
/// cannot run (`--no-input`, or stdin/stdout is not a terminal). Lists the
/// candidates so a script can see the ids to pass explicitly next time.
pub(crate) fn ambiguous_no_input_message(
    candidates: &[ListSessionsEntry],
    cwd: &paths::HostAbsPath,
) -> String {
    let mut out = String::from(
        "Multiple sessions match; cannot pick interactively \
         (--no-input is set, or stdin/stdout is not a terminal).\n\
         Candidates:\n",
    );
    for c in candidates {
        let name = c.name.as_deref().unwrap_or("-");
        let cwd_marker = if c.project_path.as_ref() == Some(cwd) {
            " (cwd)"
        } else {
            ""
        };
        let path = c
            .project_path
            .as_ref()
            .map(paths::HostAbsPath::to_string)
            .unwrap_or_else(|| "(unknown)".to_string());
        out.push_str(&format!("  {id}  {name}  {path}{cwd_marker}\n", id = c.id));
    }
    out.push_str("Pass a session id or name explicitly: `min session attach <id>`.");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimald_rpc::{ListSessionsEntry, RunningSessionAttrs};
    use paths::HostAbsPath;
    use sessions::SessionStatus;

    fn entry(id: &str, path: &str, status: SessionStatus) -> ListSessionsEntry {
        ListSessionsEntry {
            id: sessions::SessionId::parse_str(id).unwrap(),
            name: None,
            project_path: Some(HostAbsPath::try_new(path).unwrap()),
            status,
            attrs: None,
        }
    }

    /// Like [`entry`] but builds a session with no project_path, simulating an
    /// entry from an older daemon that predates the field.
    fn entry_no_path(id: &str, status: SessionStatus) -> ListSessionsEntry {
        ListSessionsEntry {
            id: sessions::SessionId::parse_str(id).unwrap(),
            name: None,
            project_path: None,
            status,
            attrs: None,
        }
    }

    fn cwd(path: &str) -> HostAbsPath {
        HostAbsPath::try_new(path).unwrap()
    }

    /// Every sequence the guard writes has to be a "put it back" form. The
    /// client has no screen model to diff against, so it writes the whole set
    /// blind and must never be able to put a terminal *into* a mode it was not
    /// already in: `l` on every DEC private mode but the cursor, and the
    /// keypad *reset* `ESC >`, never the set `ESC =`.
    #[test]
    fn terminal_unwind_only_ever_disables() {
        let seq = std::str::from_utf8(TERMINAL_UNWIND).expect("the unwind codes are ASCII");
        for tail in seq.split("\x1b[?").skip(1) {
            // A DEC private mode ends at its final byte, the first letter.
            let end = tail
                .find(char::is_alphabetic)
                .expect("a DEC private mode has a final byte");
            let mode = &tail[..=end];
            assert!(
                // `25h` unhides the cursor: the safe direction of that one.
                mode.ends_with('l') || mode == "25h",
                "the unwind turns something on: {mode:?} in {seq:?}",
            );
        }
        assert!(!seq.contains("\x1b="), "application keypad set: {seq:?}");
        // The modes the reported terminal corruption is actually about (#1210).
        for mouse in ["\x1b[?1000l", "\x1b[?1002l", "\x1b[?1003l"] {
            assert!(seq.contains(mouse), "missing {mouse:?} in {seq:?}");
        }
    }

    #[test]
    fn no_sessions_yields_no_sessions() {
        match resolve_for_attach(&[], &cwd("/a")) {
            SmartResolve::NoSessions => {}
            other => panic!("expected NoSessions, got {other:?}"),
        }
    }

    #[test]
    fn single_session_attaches_directly_even_without_cwd_match() {
        let entries = vec![entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            "/elsewhere",
            SessionStatus::Active,
        )];
        match resolve_for_attach(&entries, &cwd("/a")) {
            SmartResolve::Attach(e) => {
                assert_eq!(
                    e.id,
                    sessions::SessionId::parse_str("019f5d0f-0a99-78b1-9165-0809440f0052").unwrap()
                );
            }
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    #[test]
    fn single_cwd_match_attaches_directly() {
        let entries = vec![
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0052",
                "/a",
                SessionStatus::Active,
            ),
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0066",
                "/b",
                SessionStatus::Active,
            ),
        ];
        match resolve_for_attach(&entries, &cwd("/a")) {
            SmartResolve::Attach(e) => {
                assert_eq!(
                    e.id,
                    sessions::SessionId::parse_str("019f5d0f-0a99-78b1-9165-0809440f0052").unwrap()
                );
            }
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    #[test]
    fn multiple_cwd_matches_pick_among_cwd_matches_only() {
        let entries = vec![
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0052",
                "/a",
                SessionStatus::Active,
            ),
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0066",
                "/a",
                SessionStatus::Active,
            ),
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0077",
                "/b",
                SessionStatus::Active,
            ),
        ];
        match resolve_for_attach(&entries, &cwd("/a")) {
            SmartResolve::Pick(cands) => {
                assert_eq!(cands.len(), 2);
                assert!(cands.iter().all(|c| c.project_path == Some(cwd("/a"))));
            }
            other => panic!("expected Pick, got {other:?}"),
        }
    }

    #[test]
    fn no_cwd_match_but_multiple_sessions_picks_over_all() {
        let entries = vec![
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0052",
                "/a",
                SessionStatus::Active,
            ),
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0066",
                "/b",
                SessionStatus::Active,
            ),
        ];
        match resolve_for_attach(&entries, &cwd("/c")) {
            SmartResolve::Pick(cands) => assert_eq!(cands.len(), 2),
            other => panic!("expected Pick, got {other:?}"),
        }
    }

    #[test]
    fn format_candidate_elides_missing_title_and_tags_cwd() {
        let e = entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            "/a",
            SessionStatus::Active,
        );
        let label = format_candidate(&e, &cwd("/a"));
        assert!(label.starts_with("● "), "active glyph prefix: {label}");
        assert!(label.ends_with(" (cwd)"), "cwd marker: {label}");
        assert!(label.contains("/a"), "path present: {label}");

        let with_title = ListSessionsEntry {
            attrs: Some(RunningSessionAttrs {
                title: Some(minimald_rpc::Title {
                    value: "vim".to_string(),
                    updated_at: chrono::Utc::now(),
                }),
                last_stdout: None,
                last_stdin: None,
                audible_bell: None,
                visual_bell: None,
            }),
            ..e
        };
        let label = format_candidate(&with_title, &cwd("/other"));
        assert!(label.contains(" | vim "), "title segment: {label}");
        assert!(
            !label.contains("(cwd)"),
            "no cwd marker for non-match: {label}"
        );
    }

    #[test]
    fn pending_state_renders_open_circle() {
        let e = entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            "/a",
            SessionStatus::Pending,
        );
        let label = format_candidate(&e, &cwd("/a"));
        assert!(label.starts_with("◯ "), "pending glyph prefix: {label}");
    }

    #[test]
    fn ambiguous_message_lists_candidates() {
        let entries = vec![
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0052",
                "/a",
                SessionStatus::Active,
            ),
            entry(
                "019f5d0f-0a99-78b1-9165-0809440f0066",
                "/a",
                SessionStatus::Active,
            ),
        ];
        let msg = ambiguous_no_input_message(&entries, &cwd("/a"));
        assert!(msg.contains("019f5d0f-0a99-78b1-9165-0809440f0052"));
        assert!(msg.contains("019f5d0f-0a99-78b1-9165-0809440f0066"));
        assert!(msg.contains("(cwd)"));
        assert!(msg.contains("min session attach <id>"));
    }

    /// An entry from an older daemon that predates `project_path` (the field
    /// is `None`) must never match the cwd, but still participates in the
    /// single-session and pick-over-all paths so a mixed-version daemon farm
    /// degrades gracefully.
    #[test]
    fn entry_without_project_path_never_matches_cwd_but_still_attaches() {
        let entries = vec![entry_no_path(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            SessionStatus::Active,
        )];
        // Single session, no cwd match → attach directly.
        match resolve_for_attach(&entries, &cwd("/a")) {
            SmartResolve::Attach(e) => assert_eq!(
                e.id,
                sessions::SessionId::parse_str("019f5d0f-0a99-78b1-9165-0809440f0052").unwrap()
            ),
            other => panic!("expected Attach for pathless single session, got {other:?}"),
        }

        // Two pathless sessions → pick over all, none tagged as cwd.
        let entries = vec![
            entry_no_path(
                "019f5d0f-0a99-78b1-9165-0809440f0052",
                SessionStatus::Active,
            ),
            entry_no_path(
                "019f5d0f-0a99-78b1-9165-0809440f0066",
                SessionStatus::Active,
            ),
        ];
        match resolve_for_attach(&entries, &cwd("/a")) {
            SmartResolve::Pick(cands) => {
                assert_eq!(cands.len(), 2);
                assert!(cands.iter().all(|c| c.project_path.is_none()));
            }
            other => panic!("expected Pick for pathless sessions, got {other:?}"),
        }

        // The picker row shows "(unknown)" rather than panicking.
        let label = format_candidate(&entries[0], &cwd("/a"));
        assert!(label.contains("(unknown)"), "unknown path label: {label}");
        assert!(!label.contains("(cwd)"), "no cwd marker: {label}");
    }

    #[test]
    fn unnamed_session_shows_short_id_not_full_uuid() {
        let e = entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            "/a",
            SessionStatus::Active,
        );
        let label = format_candidate(&e, &cwd("/a"));
        assert!(
            label.contains("(unnamed) · 019f5d0f"),
            "short id form: {label}"
        );
        assert!(
            !label.contains("0a99-78b1"),
            "full uuid must not appear: {label}"
        );
    }

    #[test]
    fn created_from_suffix_names_origin_on_no_cwd_match() {
        let e = entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            "/elsewhere",
            SessionStatus::Active,
        );
        assert_eq!(
            created_from_suffix(&e, &cwd("/a")),
            " — created from /elsewhere"
        );
    }

    #[test]
    fn created_from_suffix_empty_when_cwd_matches() {
        let e = entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            "/a",
            SessionStatus::Active,
        );
        assert_eq!(created_from_suffix(&e, &cwd("/a")), "");
    }

    #[test]
    fn created_from_suffix_empty_when_project_path_absent() {
        let e = entry_no_path(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            SessionStatus::Active,
        );
        assert_eq!(created_from_suffix(&e, &cwd("/a")), "");
    }

    #[test]
    fn create_row_label_prefixes_plus_and_names_cwd() {
        assert_eq!(
            create_row_label(&cwd("/code/api-server")),
            "+ Create a new session for /code/api-server"
        );
    }

    #[test]
    fn selecting_create_row_yields_create_new() {
        let row = PickerRow::CreateNew(create_row_label(&cwd("/a")));
        assert!(matches!(resolve_pick(row), Picked::CreateNew));
    }

    #[test]
    fn selecting_session_row_yields_its_entry() {
        let e = entry(
            "019f5d0f-0a99-78b1-9165-0809440f0052",
            "/a",
            SessionStatus::Active,
        );
        let row = PickerRow::Session(SessionCandidate {
            entry: e.clone(),
            label: format_candidate(&e, &cwd("/a")),
        });
        match resolve_pick(row) {
            Picked::Session(got) => assert_eq!(got.id, e.id),
            Picked::CreateNew => panic!("expected the existing session, got create"),
        }
    }
}
