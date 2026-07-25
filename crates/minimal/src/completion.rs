//! Dynamic shell completion of session identifiers.
//!
//! Every session argument in the CLI takes "a UUID or a session name", and
//! both are known only at runtime — nothing a statically generated completion
//! script can enumerate. Two entry points share the one implementation here:
//!
//! - [`complete_session_arg`], attached to each session argument via
//!   [`ArgValueCompleter`] and reached when a shell runs
//!   `COMPLETE=<shell> min -- <words>` (see `CompleteEnv` in `main.rs`).
//! - `min complete-session-str [<prefix>]`, a hidden subcommand printing the
//!   same candidates one per line. It is what the completer would offer, minus
//!   the shell: scriptable, and the way to debug a completion that came back
//!   empty without a shell in the loop.
//!
//! Three rules hold for everything below, because the caller is a Tab press
//! and not a person:
//!
//! 1. **Never autospawn.** Deliberately asymmetric with every other command,
//!    for the same reason [`crate::cmd_stop`] is: the liveness probe runs
//!    first, and a daemon that is down yields no candidates. Completing a name
//!    is not worth booting a VM for, which is exactly what `ensure_daemon`
//!    would do on macOS.
//! 2. **Stay bounded.** The whole round-trip is capped at
//!    [`COMPLETION_TIMEOUT`]. A Tab that hangs is worse than one that
//!    completes nothing.
//! 3. **Never fail.** A daemon that is down, an RPC refused by a version-skewed
//!    server, a wedged socket — all of it degrades to an empty list. The
//!    alternative is an error printed over the user's half-typed prompt.

use std::ffi::OsStr;
use std::time::Duration;

use clap_complete::engine::{ArgValueCompleter, CompletionCandidate};
use minimald_rpc::{ListSessions, ListSessionsEntry};

use crate::GlobalArgs;

/// Ceiling on a completion's daemon round-trip.
const COMPLETION_TIMEOUT: Duration = Duration::from_millis(120);

/// The name of the hidden completion subcommand, as clap spells it.
pub const COMPLETE_SESSION_STR: &str = "complete-session-str";

/// One completion candidate: the string the shell inserts, plus the
/// description zsh and fish render beside it (bash discards it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionCandidate {
    /// The session name or UUID to insert.
    pub value: String,
    /// Human-facing context for disambiguating same-looking sessions.
    pub description: Option<String>,
}

/// The [`ArgValueCompleter`] to attach to a session argument.
///
/// A function rather than a closure so every session argument shares one
/// implementation and the `#[arg(add = ...)]` attributes stay one line each.
pub fn session_completer() -> ArgValueCompleter {
    ArgValueCompleter::new(complete_session_arg)
}

/// Complete a session argument whose typed-so-far value is `current`.
///
/// Runs on the shell's completion path, which is synchronous and — because
/// `CompleteEnv` is invoked before the CLI's runtime exists — has no reactor
/// on this thread. It therefore drives its own current-thread runtime rather
/// than blocking on an ambient one.
///
/// A non-UTF-8 prefix cannot prefix-match a name or a UUID, so it yields
/// nothing rather than lossily converting into a match the user did not type.
pub fn complete_session_arg(current: &OsStr) -> Vec<CompletionCandidate> {
    let Some(prefix) = current.to_str() else {
        return Vec::new();
    };

    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return Vec::new();
    };

    // The completer has no access to the rest of the command line: clap hands
    // a value completer the current word and nothing else, so a `--provider`
    // or `--minimal-dir` earlier in the line cannot be honoured here.
    let global = GlobalArgs::default();
    let candidates = runtime.block_on(session_candidates(&global, prefix));

    candidates
        .into_iter()
        .map(|c| CompletionCandidate::new(c.value).help(c.description.map(Into::into)))
        .collect()
}

/// The candidates for `prefix`, or an empty list when the daemon cannot be
/// reached within [`COMPLETION_TIMEOUT`].
pub async fn session_candidates(global: &GlobalArgs, prefix: &str) -> Vec<SessionCandidate> {
    match fetch_sessions(global).await {
        Some(sessions) => candidates_from(&sessions, prefix),
        None => Vec::new(),
    }
}

/// One `ListSessions` round-trip against an already-running daemon, or `None`
/// if there isn't one, it didn't answer in time, or it answered with an error.
async fn fetch_sessions(global: &GlobalArgs) -> Option<Vec<ListSessionsEntry>> {
    if !crate::autospawn::is_daemon_running(global.use_minvmd(), global.minimal_dir.as_deref())
        .unwrap_or(false)
    {
        return None;
    }

    let rpc = async {
        let mut client = crate::connect_daemon(global).await.ok()?;
        let response = client.oneshot_rpc::<ListSessions>(()).await.ok()?;
        Some(response.sessions)
    };

    tokio::time::timeout(COMPLETION_TIMEOUT, rpc).await.ok()?
}

/// Turn a session list into the candidates matching `prefix`.
///
/// Split from the RPC so the offering rules below are testable without a
/// daemon — they are the part with actual behaviour in them.
fn candidates_from(sessions: &[ListSessionsEntry], prefix: &str) -> Vec<SessionCandidate> {
    let mut candidates = Vec::new();

    for entry in sessions {
        let description = describe(entry);

        if let Some(name) = &entry.name
            && name.starts_with(prefix)
        {
            candidates.push(SessionCandidate {
                value: name.clone(),
                description: description.clone(),
            });
        }

        // A UUID is 36 characters of noise beside a handful of short names, so
        // an ID is offered only when it is the sole way to name the session,
        // or when the user has already typed something that could be an ID
        // prefix. That is the same line `SessionLookup::parse` draws between
        // the two forms, applied one keystroke earlier: an empty prefix means
        // "show me the sessions", which is the names.
        let id = entry.id.to_string();
        if (entry.name.is_none() || !prefix.is_empty()) && id.starts_with(prefix) {
            candidates.push(SessionCandidate {
                value: id,
                description,
            });
        }
    }

    candidates
}

/// The description shown beside a candidate: the session's terminal title if
/// it has one, else the project directory it was built from.
///
/// Both are the things that distinguish two sessions the user would otherwise
/// have to tell apart by UUID.
fn describe(entry: &ListSessionsEntry) -> Option<String> {
    if let Some(attrs) = &entry.attrs
        && let Some(title) = &attrs.title
        && !title.value.is_empty()
    {
        return Some(title.value.clone());
    }

    entry
        .project_path
        .as_ref()
        .map(|path| path.as_str().to_string())
}

/// Print the candidates for `prefix`, one per line as `value<TAB>description`.
///
/// Always succeeds, and prints nothing when there is nothing to offer — the
/// caller is a shell, and an exit code it would have to interpret is worse
/// than silence.
pub async fn cmd_complete_session_str(
    global: &GlobalArgs,
    args: crate::CompleteSessionStrArgs,
) -> Result<(), anyhow::Error> {
    let prefix = args.prefix.unwrap_or_default();
    let mut out = String::new();

    for candidate in session_candidates(global, &prefix).await {
        out.push_str(&candidate.value);
        if let Some(description) = &candidate.description {
            out.push('\t');
            out.push_str(description);
        }
        out.push('\n');
    }

    // One write, ignoring a closed stdout: a shell that has already collected
    // enough candidates closes the pipe, and EPIPE there is not an error worth
    // reporting to a user who is mid-keystroke.
    use std::io::Write as _;
    let _ = std::io::stdout().write_all(out.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sessions::SessionId;

    fn entry(id: &str, name: Option<&str>) -> ListSessionsEntry {
        ListSessionsEntry {
            id: SessionId::parse_str(id).expect("valid test uuid"),
            name: name.map(str::to_string),
            project_path: None,
            status: Default::default(),
            attrs: None,
        }
    }

    const ID_A: &str = "019f5d80-ff86-7322-8846-18b49b6aae89";
    const ID_B: &str = "abcdef01-0000-7000-8000-000000000000";

    #[test]
    fn empty_prefix_offers_names_but_not_their_ids() {
        let sessions = [entry(ID_A, Some("mars"))];
        let got = candidates_from(&sessions, "");

        assert_eq!(
            got.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(),
            ["mars"],
            "a bare Tab should list names, not pad them with 36-char UUIDs"
        );
    }

    #[test]
    fn a_nameless_session_offers_its_id_even_with_an_empty_prefix() {
        let sessions = [entry(ID_A, None)];
        let got = candidates_from(&sessions, "");

        assert_eq!(
            got.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(),
            [ID_A],
            "the ID is the only way to name an unnamed session"
        );
    }

    #[test]
    fn a_typed_prefix_matches_names_and_ids_alike() {
        let sessions = [entry(ID_A, Some("mars")), entry(ID_B, Some("moon"))];

        let by_name = candidates_from(&sessions, "ma");
        assert_eq!(
            by_name.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(),
            ["mars"]
        );

        let by_id = candidates_from(&sessions, "019");
        assert_eq!(
            by_id.iter().map(|c| c.value.as_str()).collect::<Vec<_>>(),
            [ID_A],
            "an ID prefix should reach the ID once the user commits to typing one"
        );
    }

    #[test]
    fn a_prefix_matching_nothing_yields_nothing() {
        let sessions = [entry(ID_A, Some("mars"))];
        assert!(candidates_from(&sessions, "zz").is_empty());
    }

    #[test]
    fn the_project_path_describes_a_session_without_a_title() {
        let mut e = entry(ID_A, Some("mars"));
        e.project_path =
            Some(paths::HostAbsPath::try_new("/home/dev/minimal").expect("absolute test path"));

        let got = candidates_from(&[e], "");
        assert_eq!(got[0].description.as_deref(), Some("/home/dev/minimal"));
    }
}
