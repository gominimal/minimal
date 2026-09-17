//! The exec-channel command vocabulary.
//!
//! SSH's `exec` request carries exactly one string (RFC 4254 §5.2), so every
//! form a client can ask for has to fit in it. This module is that encoding,
//! defined once and shared: clients build the string here, the daemon parses it
//! here, and neither can drift from the other.
//!
//! # Why the requests are tagged
//!
//! The daemon used to decide what a request meant by *looking at* the string —
//! anything starting with `min ` was one of its own commands, everything else
//! was a shell command for the session. That conflated three different things
//! in one untagged string, and both failure modes were real:
//!
//! * A session command was stolen. `min --version` names the session's own
//!   `min` binary, but the daemon claimed the prefix and refused it, so the
//!   binary was simply unreachable through exec.
//! * An argv could not be sent at all. ssh has no argv on the wire — it joins
//!   its trailing arguments with single spaces and the far side reshells the
//!   result — so `sh -c 'echo A B C'` arrived as `sh -c echo A B C` and `A`
//!   became `sh`'s `$0` (gominimal/inbox#558). Quoting the words on the client
//!   fixed the splitting but broke the `min ` sniffing, because both read the
//!   same bytes.
//!
//! Tagging separates them. A request reaches the daemon only by naming a form
//! explicitly, [`ExecRequest::Argv`] carries its words as data rather than as a
//! line for some shell to re-split, and — the rule that makes the hijack
//! impossible — **anything untagged belongs to the session**.
//!
//! # The forms
//!
//! ```text
//! min://shell <command>          run <command> with the session's shell
//! min://argv ["a","b"]           exec this argv in the session, no shell
//! min://task/run <task>          daemon-serviced: run a declared task
//! min://package/build [args]     daemon-serviced: build packages
//! min://check [args]             daemon-serviced: lint the session's config
//! <anything else>                a shell command for the session
//! ```
//!
//! `git-receive-pack min://<session>` is not part of this vocabulary: the git
//! remote helper speaks the pack protocol and the daemon routes it before it
//! gets here.

use std::fmt;

/// Prefix marking a request as one this vocabulary defines. A command that does
/// not start with it is a shell command for the session, never a daemon one.
pub const EXEC_SCHEME: &str = "min://";

/// What a client asked the daemon to run on an exec channel.
///
/// Build one with the constructors below and render it with
/// [`ExecRequest::encode`]; recover it with [`ExecRequest::parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecRequest {
    /// A command line for the session's shell, with its pipes, globs and
    /// `$VAR` intact. The `ssh host '<cmd>'` form.
    Shell(String),
    /// An argv to exec directly in the session. No shell stands between these
    /// words and the process, so nothing can re-split them.
    ///
    /// Never empty — [`ExecRequest::parse`] rejects an empty argv rather than
    /// handing the daemon a program-less request.
    Argv(Vec<String>),
    /// Run a task the session's project declares.
    TaskRun(String),
    /// Build packages against the session.
    PackageBuild(String),
    /// Lint the session's `minimal.toml`, packages, profiles and stacks.
    Check(String),
}

/// Tag for [`ExecRequest::Shell`].
const SHELL: &str = "shell";
/// Tag for [`ExecRequest::Argv`].
const ARGV: &str = "argv";
/// Tag for [`ExecRequest::TaskRun`].
const TASK_RUN: &str = "task/run";
/// Tag for [`ExecRequest::PackageBuild`].
const PACKAGE_BUILD: &str = "package/build";
/// Tag for [`ExecRequest::Check`].
const CHECK: &str = "check";

/// Every tag, for the error message that lists what the daemon accepts.
const TAGS: [&str; 5] = [SHELL, ARGV, TASK_RUN, PACKAGE_BUILD, CHECK];

impl ExecRequest {
    /// The wire string for this request.
    pub fn encode(&self) -> String {
        match self {
            Self::Shell(cmd) => format!("{EXEC_SCHEME}{SHELL} {cmd}"),
            Self::Argv(words) => {
                // JSON rather than a separator byte: argv strings reach `ssh`
                // as process arguments, so the one delimiter that could never
                // collide with the payload — NUL — is exactly the one that
                // cannot survive `execve`. JSON has no such hole, and it keeps
                // the daemon's `exec request` log line readable.
                let json = serde_json_lenient::to_string(words)
                    .expect("a Vec<String> always serializes to JSON");
                format!("{EXEC_SCHEME}{ARGV} {json}")
            }
            Self::TaskRun(task) => format!("{EXEC_SCHEME}{TASK_RUN} {task}"),
            Self::PackageBuild(args) => format!("{EXEC_SCHEME}{PACKAGE_BUILD} {args}"),
            Self::Check(args) => format!("{EXEC_SCHEME}{CHECK} {args}"),
        }
    }

    /// Recover a request from its wire string.
    ///
    /// An untagged command is a [`ExecRequest::Shell`] for the session: the
    /// daemon's own forms are reachable only by naming them, so no session
    /// command can be mistaken for one.
    ///
    /// # Errors
    ///
    /// [`ExecParseError`] when the scheme is present but the tag is unknown,
    /// or when an `argv` payload is not a JSON array of strings — both are a
    /// client asking for something this daemon does not serve, which is worth
    /// refusing rather than silently running in a shell.
    pub fn parse(command: &str) -> Result<Self, ExecParseError> {
        let Some(rest) = command.strip_prefix(EXEC_SCHEME) else {
            return Ok(Self::Shell(command.to_string()));
        };

        // The tag runs to the first space; everything after it is the payload,
        // verbatim. Splitting once (not on every space) is what lets a task
        // name or a shell command keep its own spaces.
        let (tag, payload) = match rest.split_once(' ') {
            Some((tag, payload)) => (tag, payload),
            None => (rest, ""),
        };

        match tag {
            SHELL => Ok(Self::Shell(payload.to_string())),
            ARGV => {
                let words: Vec<String> = serde_json_lenient::from_str(payload)
                    .map_err(|e| ExecParseError::Argv(e.to_string()))?;
                if words.is_empty() {
                    return Err(ExecParseError::EmptyArgv);
                }
                Ok(Self::Argv(words))
            }
            TASK_RUN => Ok(Self::TaskRun(payload.to_string())),
            PACKAGE_BUILD => Ok(Self::PackageBuild(payload.to_string())),
            CHECK => Ok(Self::Check(payload.to_string())),
            unknown => Err(ExecParseError::UnknownTag(unknown.to_string())),
        }
    }
}

/// Why an exec request naming the [`EXEC_SCHEME`] could not be understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecParseError {
    /// The scheme was present but the tag after it is not one this daemon
    /// serves — typically a newer client against an older daemon.
    UnknownTag(String),
    /// The `argv` payload was not a JSON array of strings.
    Argv(String),
    /// The `argv` payload was a well-formed but empty array, which names no
    /// program to run.
    EmptyArgv,
}

impl fmt::Display for ExecParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTag(tag) => write!(
                f,
                "unknown exec form '{EXEC_SCHEME}{tag}'; this daemon serves {}",
                TAGS.map(|t| format!("{EXEC_SCHEME}{t}")).join(", "),
            ),
            Self::Argv(e) => write!(
                f,
                "the {EXEC_SCHEME}{ARGV} payload is not a JSON array of strings: {e}"
            ),
            Self::EmptyArgv => write!(f, "the {EXEC_SCHEME}{ARGV} payload names no program"),
        }
    }
}

impl std::error::Error for ExecParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every form survives the round trip it exists for.
    #[test]
    fn each_form_round_trips() {
        for req in [
            ExecRequest::Shell("echo EXEC_OK $PWD".to_string()),
            ExecRequest::Argv(vec!["sh".into(), "-c".into(), "echo A B C".into()]),
            ExecRequest::TaskRun("build".to_string()),
            ExecRequest::PackageBuild("--verbose pkg".to_string()),
            ExecRequest::Check(String::new()),
        ] {
            assert_eq!(ExecRequest::parse(&req.encode()), Ok(req));
        }
    }

    /// The bug this vocabulary exists for: the words arrive as data, so the
    /// spaces inside `echo A B C` are part of one argument and no shell gets a
    /// chance to re-split them.
    #[test]
    fn an_argv_keeps_words_that_contain_spaces_whole() {
        let req = ExecRequest::Argv(vec!["sh".into(), "-c".into(), "echo A B C".into()]);
        let ExecRequest::Argv(back) = ExecRequest::parse(&req.encode()).unwrap() else {
            panic!("argv must parse back as an argv");
        };
        assert_eq!(back[2], "echo A B C");
    }

    /// The hijack that used to make a session's own `min` unreachable: an
    /// untagged command belongs to the session, however it happens to start.
    #[test]
    fn an_untagged_command_is_always_the_sessions() {
        for cmd in [
            "min --version",
            "min run build",
            "min check",
            "echo hi",
            "git status",
        ] {
            assert_eq!(
                ExecRequest::parse(cmd),
                Ok(ExecRequest::Shell(cmd.to_string())),
                "{cmd} must reach the session",
            );
        }
    }

    /// A payload keeps its own spaces: the tag is split off once, not on every
    /// space, so a shell command and a multi-word arg list arrive intact.
    #[test]
    fn the_payload_keeps_its_spaces() {
        assert_eq!(
            ExecRequest::parse("min://shell echo a  b; echo c"),
            Ok(ExecRequest::Shell("echo a  b; echo c".to_string()))
        );
        assert_eq!(
            ExecRequest::parse("min://package/build --verbose a b"),
            Ok(ExecRequest::PackageBuild("--verbose a b".to_string()))
        );
    }

    /// A tag with no payload at all — `min://check` — is the no-args form, not
    /// a parse error.
    #[test]
    fn a_bare_tag_is_the_empty_payload() {
        assert_eq!(
            ExecRequest::parse("min://check"),
            Ok(ExecRequest::Check(String::new()))
        );
    }

    /// A newer client's form against an older daemon is refused by name, so the
    /// error can say which form was asked for.
    #[test]
    fn an_unknown_tag_is_refused_rather_than_shelled() {
        let err = ExecRequest::parse("min://teleport now").unwrap_err();
        assert_eq!(err, ExecParseError::UnknownTag("teleport".to_string()));
        assert!(err.to_string().contains("min://teleport"), "{err}");
        // The message lists what this daemon does serve.
        assert!(err.to_string().contains("min://task/run"), "{err}");
    }

    /// A malformed or program-less argv is refused rather than guessed at.
    #[test]
    fn a_broken_argv_payload_is_refused() {
        assert!(matches!(
            ExecRequest::parse("min://argv not-json"),
            Err(ExecParseError::Argv(_))
        ));
        assert_eq!(
            ExecRequest::parse("min://argv []"),
            Err(ExecParseError::EmptyArgv)
        );
    }

    /// Quotes, backslashes and newlines in an argument are payload, not syntax:
    /// JSON carries them and the daemon gets the byte-exact word back.
    #[test]
    fn awkward_characters_survive_an_argv() {
        let nasty = vec![
            "sh".to_string(),
            "-c".to_string(),
            "it's \"quoted\"\\ and\nnewlined".to_string(),
        ];
        let req = ExecRequest::Argv(nasty.clone());
        assert_eq!(
            ExecRequest::parse(&req.encode()),
            Ok(ExecRequest::Argv(nasty))
        );
    }
}
