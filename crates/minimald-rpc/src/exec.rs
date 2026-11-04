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
//! min://task/run [--owns-box] <task> [args]
//!                                daemon-serviced: run a declared task;
//!                                --owns-box ends the box with the run (NET-131);
//!                                args is a JSON array of the task's arguments,
//!                                optionally followed by the invocation
//!                                directory relative to the uploaded tree
//! min://package/build [args]     daemon-serviced: build packages
//! min://check [args]             daemon-serviced: lint the session's config
//! min://exec {"argv":[..],"mode":"detached","timeout_secs":30}
//!                                exec this argv in the box, no shell, under
//!                                an exec id; mode is attached, tty or
//!                                detached, and timeout_secs is optional
//! min://exec/attach <exec-id>    resume a tty exec's terminal
//! min://exec/output <exec-id>    read an exec's captured output
//! min://exec/wait <exec-id>      wait for an exec and take its exit code
//! <anything else>                a shell command for the session
//! ```
//!
//! `git-receive-pack min://<session>` is not part of this vocabulary: the git
//! remote helper speaks the pack protocol and the daemon routes it before it
//! gets here.

use std::fmt;

use serde::{Deserialize, Serialize};

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
    ///
    /// On a task box whose spec names this task as its entry, with no
    /// `args`, the daemon runs the box's entrypoint, the in-box `min task
    /// run`, and relays its output and its exit code (T43). The task's
    /// arguments ride the entrypoint's argv. The entrypoint starts in `cwd`.
    /// `min task run` sends this form, with `owns_box` unset: the box ends
    /// when its entrypoint returns and keeps its record.
    ///
    /// `owns_box` is the older request, kept for one release: the run's
    /// claim on the session it was created for (NET-131). When it is set,
    /// the daemon ends the session once this task's exit status is on the
    /// wire, whether or not the client that started the run is still
    /// there. A `min task run` from before T43 sets it. `min session run`
    /// leaves it unset: its box is an attachable session someone else
    /// keeps. A payload without the marker parses as `owns_box: false`,
    /// which is also what a client from before the flag sends.
    TaskRun {
        /// The task name, as the client typed it; the daemon trims it.
        task: String,
        /// The run owns its box: the daemon ends the session with the run.
        /// Only a client from before T43 sets it on a task box's run.
        owns_box: bool,
        /// The task's declared arguments, as the client typed them after the
        /// task name. Empty when the client sent none — an older `min`, or a
        /// task that declares no args — in which case the daemon binds only
        /// the task's defaults.
        args: Vec<String>,
        /// Where the client was invoked, relative to the uploaded tree's
        /// root: `sub/inner` for a run started in that subdirectory. A task
        /// that declares `inherit_cwd` starts there. Empty when the client
        /// ran from the root, or sent none — an older `min` — in which case
        /// the task starts at the root, as before. Never absolute and never
        /// holding a `..` component: [`ExecRequest::parse`] refuses both.
        cwd: String,
    },
    /// Build packages against the session.
    PackageBuild(String),
    /// Lint the session's `minimal.toml`, packages, profiles and stacks.
    Check(String),
    /// An argv to exec in the box, no shell, under an exec id the daemon
    /// mints, with its mode and its own timeout (BOX-149).
    Exec(ExecSpec),
    /// Resume the terminal of a [`ExecMode::Tty`] exec by its id.
    ExecAttach(ExecId),
    /// Read the output an exec captured, by its id.
    ExecOutput(ExecId),
    /// Wait for an exec to end and take its exit code, by its id.
    ExecWait(ExecId),
}

/// How an exec's process meets its client (BOX-149).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecMode {
    /// Stdio on the channel's pipes, for as long as the client stays. The
    /// mode the older `min://argv` form always has.
    #[default]
    Attached,
    /// A terminal the daemon allocates. The request returns the exec id at
    /// once, and `min://exec/attach` resumes the terminal by it.
    Tty,
    /// Stdin closed at creation. The request returns the exec id at once,
    /// and the output and the exit code read back by it.
    Detached,
}

impl ExecMode {
    /// The mode as the wire and the daemon log spell it.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Attached => "attached",
            Self::Tty => "tty",
            Self::Detached => "detached",
        }
    }
}

/// The payload of [`ExecRequest::Exec`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecSpec {
    /// The argv to exec. Never empty: [`ExecRequest::parse`] refuses an
    /// empty one.
    pub argv: Vec<String>,
    /// How the process meets its client. Attached when the payload names
    /// none.
    #[serde(default)]
    pub mode: ExecMode,
    /// The exec's own timeout in whole seconds. `None` runs the exec under
    /// the box's ceilings only. Never zero: [`ExecRequest::parse`] refuses
    /// it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
}

/// An exec's id: a UUIDv7 the daemon mints when the exec starts, in its
/// hyphenated lowercase spelling (BOX-149).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExecId(String);

impl ExecId {
    /// Reads an exec id from its text.
    ///
    /// # Errors
    ///
    /// [`ExecParseError::ExecId`] when `text` is not a hyphenated UUID of
    /// version 7 and the RFC 9562 variant.
    pub fn parse(text: &str) -> Result<Self, ExecParseError> {
        let text = text.trim();
        let bytes = text.as_bytes();
        let shaped = bytes.len() == 36
            && bytes.iter().enumerate().all(|(i, b)| match i {
                8 | 13 | 18 | 23 => *b == b'-',
                _ => b.is_ascii_hexdigit(),
            });
        let v7 = shaped
            && bytes[14] == b'7'
            && matches!(bytes[19].to_ascii_lowercase(), b'8' | b'9' | b'a' | b'b');
        if !v7 {
            return Err(ExecParseError::ExecId(text.to_string()));
        }
        Ok(Self(text.to_ascii_lowercase()))
    }

    /// The id's text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ExecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Tag for [`ExecRequest::Shell`].
const SHELL: &str = "shell";
/// Tag for [`ExecRequest::Argv`].
const ARGV: &str = "argv";
/// Tag for [`ExecRequest::TaskRun`].
const TASK_RUN: &str = "task/run";
/// Payload marker for [`ExecRequest::TaskRun`] saying the run owns its box
/// (NET-131): the daemon ends the session once the task's exit status is on
/// the wire. The trailing space is part of the marker — it is read only when
/// a task name follows it, so a task actually named `--owns-box` still
/// round-trips through the unflagged spelling.
const TASK_RUN_OWNS_BOX: &str = "--owns-box ";
/// Tag for [`ExecRequest::PackageBuild`].
const PACKAGE_BUILD: &str = "package/build";
/// Tag for [`ExecRequest::Check`].
const CHECK: &str = "check";

/// Tag for [`ExecRequest::Exec`].
const EXEC: &str = "exec";
/// Tag for [`ExecRequest::ExecAttach`].
const EXEC_ATTACH: &str = "exec/attach";
/// Tag for [`ExecRequest::ExecOutput`].
const EXEC_OUTPUT: &str = "exec/output";
/// Tag for [`ExecRequest::ExecWait`].
const EXEC_WAIT: &str = "exec/wait";

/// Every tag, for the error message that lists what the daemon accepts.
const TAGS: [&str; 9] = [
    SHELL,
    ARGV,
    TASK_RUN,
    PACKAGE_BUILD,
    CHECK,
    EXEC,
    EXEC_ATTACH,
    EXEC_OUTPUT,
    EXEC_WAIT,
];

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
            Self::TaskRun {
                task,
                owns_box,
                args,
                cwd,
            } => {
                let marker = if *owns_box { TASK_RUN_OWNS_BOX } else { "" };
                // Args ride only when present: the bare form is the legacy
                // spelling every pre-args client sends, and it is also what
                // keeps a task actually named `--owns-box` from colliding
                // with the owns-box marker. When args are present the task
                // name and its args are framed together as one JSON array
                // `[task, args]`, so a task name containing spaces — or one
                // named exactly `--owns-box` — cannot be split off from its
                // args by the space delimiter. A non-empty cwd rides as a
                // third element of that array, `[task, args, cwd]`.
                if args.is_empty() && cwd.is_empty() {
                    format!("{EXEC_SCHEME}{TASK_RUN} {marker}{task}")
                } else if !cwd.is_empty() {
                    let json = serde_json_lenient::to_string(&(task, args, cwd))
                        .expect("a task name, its args and its cwd always serialize to JSON");
                    format!("{EXEC_SCHEME}{TASK_RUN} {marker}{json}")
                } else {
                    let json = serde_json_lenient::to_string(&(task, args))
                        .expect("a task name and its args always serialize to JSON");
                    format!("{EXEC_SCHEME}{TASK_RUN} {marker}{json}")
                }
            }
            Self::PackageBuild(args) => format!("{EXEC_SCHEME}{PACKAGE_BUILD} {args}"),
            Self::Check(args) => format!("{EXEC_SCHEME}{CHECK} {args}"),
            Self::Exec(spec) => {
                let json = serde_json_lenient::to_string(spec)
                    .expect("an exec spec always serializes to JSON");
                format!("{EXEC_SCHEME}{EXEC} {json}")
            }
            Self::ExecAttach(id) => format!("{EXEC_SCHEME}{EXEC_ATTACH} {id}"),
            Self::ExecOutput(id) => format!("{EXEC_SCHEME}{EXEC_OUTPUT} {id}"),
            Self::ExecWait(id) => format!("{EXEC_SCHEME}{EXEC_WAIT} {id}"),
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
            TASK_RUN => {
                // The owns-box marker rides in front of the task name when
                // the run owns its box (NET-131); without it the payload is
                // the task name itself, which is also every payload a client
                // from before the flag sends.
                let (owns_box, rest) = payload
                    .strip_prefix(TASK_RUN_OWNS_BOX)
                    .map_or((false, payload), |task| (true, task));
                // A payload starting with `[` is the framed form: one JSON
                // array `[task, args]` carrying the task name and its args
                // together, so neither the space delimiter nor the owns-box
                // marker can split them. Anything else is the legacy bare
                // form — a task name with no args, sent by every client from
                // before args. The framed array carries the cwd as an
                // optional third element; without it the cwd is empty.
                if rest.starts_with('[') {
                    let (task, args, cwd) =
                        match serde_json_lenient::from_str::<(String, Vec<String>, String)>(rest) {
                            Ok(framed) => framed,
                            Err(_) => {
                                let (task, args): (String, Vec<String>) =
                                    serde_json_lenient::from_str(rest)
                                        .map_err(|e| ExecParseError::TaskArgs(e.to_string()))?;
                                (task, args, String::new())
                            }
                        };
                    validate_task_cwd(&cwd)?;
                    return Ok(Self::TaskRun {
                        task,
                        owns_box,
                        args,
                        cwd,
                    });
                }
                Ok(Self::TaskRun {
                    task: rest.to_string(),
                    owns_box,
                    args: vec![],
                    cwd: String::new(),
                })
            }
            PACKAGE_BUILD => Ok(Self::PackageBuild(payload.to_string())),
            CHECK => Ok(Self::Check(payload.to_string())),
            EXEC => {
                let spec: ExecSpec = serde_json_lenient::from_str(payload)
                    .map_err(|e| ExecParseError::ExecSpec(e.to_string()))?;
                if spec.argv.is_empty() {
                    return Err(ExecParseError::EmptyArgv);
                }
                if spec.timeout_secs == Some(0) {
                    return Err(ExecParseError::ZeroTimeout);
                }
                Ok(Self::Exec(spec))
            }
            EXEC_ATTACH => Ok(Self::ExecAttach(ExecId::parse(payload)?)),
            EXEC_OUTPUT => Ok(Self::ExecOutput(ExecId::parse(payload)?)),
            EXEC_WAIT => Ok(Self::ExecWait(ExecId::parse(payload)?)),
            unknown => Err(ExecParseError::UnknownTag(unknown.to_string())),
        }
    }
}

/// Refuses a task-run cwd that could leave the uploaded tree: an absolute
/// path, or one with a `..` component. The empty cwd is the tree's root.
fn validate_task_cwd(cwd: &str) -> Result<(), ExecParseError> {
    let escapes = std::path::Path::new(cwd).components().any(|c| {
        !matches!(
            c,
            std::path::Component::Normal(_) | std::path::Component::CurDir
        )
    });
    if escapes {
        return Err(ExecParseError::TaskCwd(cwd.to_string()));
    }
    Ok(())
}

/// Why an exec request naming the [`EXEC_SCHEME`] could not be understood.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecParseError {
    /// The scheme was present but the tag after it is not one this daemon
    /// serves — typically a newer client against an older daemon.
    UnknownTag(String),
    /// The `argv` payload was not a JSON array of strings.
    Argv(String),
    /// The `task/run` argument payload was not a JSON array of strings.
    TaskArgs(String),
    /// The `task/run` cwd is absolute or has a `..` component, so it does
    /// not name a directory inside the uploaded tree.
    TaskCwd(String),
    /// The `argv` payload was a well-formed but empty array, which names no
    /// program to run.
    EmptyArgv,
    /// The `exec` payload was not a JSON object with an `argv` array.
    ExecSpec(String),
    /// The `exec` payload asked for a timeout of zero seconds.
    ZeroTimeout,
    /// The text that names an exec is not an exec id.
    ExecId(String),
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
            Self::TaskArgs(e) => write!(
                f,
                "the {EXEC_SCHEME}{TASK_RUN} argument payload is not a JSON array of strings: {e}"
            ),
            Self::TaskCwd(cwd) => write!(
                f,
                "the {EXEC_SCHEME}{TASK_RUN} cwd '{cwd}' must be a relative path without '..'"
            ),
            Self::EmptyArgv => write!(f, "the {EXEC_SCHEME}{ARGV} payload names no program"),
            Self::ExecSpec(e) => write!(
                f,
                "the {EXEC_SCHEME}{EXEC} payload is not a JSON object with an argv array: {e}"
            ),
            Self::ZeroTimeout => write!(
                f,
                "the {EXEC_SCHEME}{EXEC} timeout must be at least 1 second"
            ),
            Self::ExecId(text) => write!(f, "'{text}' is not an exec id"),
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
            ExecRequest::TaskRun {
                task: "build".to_string(),
                owns_box: false,
                args: vec![],
                cwd: String::new(),
            },
            ExecRequest::PackageBuild("--verbose pkg".to_string()),
            ExecRequest::Check(String::new()),
        ] {
            assert_eq!(ExecRequest::parse(&req.encode()), Ok(req));
        }
    }

    const AN_EXEC_ID: &str = "01928a3b-4c5d-7e6f-8a9b-0c1d2e3f4a5b";

    /// BOX-149: the exec form carries its argv as words, its mode and its
    /// own timeout, and each survives the round trip. A payload that names
    /// no mode is attached with no timeout. The id forms carry a UUIDv7.
    #[test]
    fn exec_request_carries_mode_and_timeout() {
        for mode in [ExecMode::Attached, ExecMode::Tty, ExecMode::Detached] {
            for timeout_secs in [None, Some(30)] {
                let req = ExecRequest::Exec(ExecSpec {
                    argv: vec!["sh".into(), "-c".into(), "echo A B C; echo $HOME".into()],
                    mode,
                    timeout_secs,
                });
                let wire = req.encode();
                assert!(wire.contains(mode.name()), "{wire}");
                assert_eq!(ExecRequest::parse(&wire), Ok(req));
            }
        }

        assert_eq!(
            ExecRequest::parse(r#"min://exec {"argv":["true"]}"#),
            Ok(ExecRequest::Exec(ExecSpec {
                argv: vec!["true".into()],
                mode: ExecMode::Attached,
                timeout_secs: None,
            })),
        );
        assert_eq!(
            ExecRequest::parse(
                r#"min://exec {"argv":["true"],"mode":"detached","timeout_secs":0}"#
            ),
            Err(ExecParseError::ZeroTimeout),
        );
        assert_eq!(
            ExecRequest::parse(r#"min://exec {"argv":[]}"#),
            Err(ExecParseError::EmptyArgv),
        );
        assert!(matches!(
            ExecRequest::parse(r#"min://exec {"argv":["true"],"mode":"background"}"#),
            Err(ExecParseError::ExecSpec(_)),
        ));

        let id = ExecId::parse(AN_EXEC_ID).unwrap();
        for req in [
            ExecRequest::ExecAttach(id.clone()),
            ExecRequest::ExecOutput(id.clone()),
            ExecRequest::ExecWait(id.clone()),
        ] {
            assert_eq!(ExecRequest::parse(&req.encode()), Ok(req));
        }
        // A v4 UUID is not an exec id, and neither is a box name.
        for text in ["01928a3b-4c5d-4e6f-8a9b-0c1d2e3f4a5b", "my-box", ""] {
            assert_eq!(
                ExecRequest::parse(&format!("min://exec/wait {text}")),
                Err(ExecParseError::ExecId(text.to_string())),
            );
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

    /// The owns-box flag (NET-131) rides the task-run request: it round-trips
    /// with the task name, the unflagged spelling stays byte-for-byte the
    /// legacy form every client from before the flag sends, and a task
    /// actually named like the marker is not read as the flag.
    #[test]
    fn a_task_run_round_trips_its_owns_box_flag() {
        let owned = ExecRequest::TaskRun {
            task: "build".to_string(),
            owns_box: true,
            args: vec![],
            cwd: String::new(),
        };
        assert_eq!(owned.encode(), "min://task/run --owns-box build");
        assert_eq!(
            ExecRequest::parse(&owned.encode()),
            Ok(owned),
            "the flag and the task name survive the round trip"
        );

        // The unflagged spelling is the legacy form.
        let plain = ExecRequest::TaskRun {
            task: "build".to_string(),
            owns_box: false,
            args: vec![],
            cwd: String::new(),
        };
        assert_eq!(plain.encode(), "min://task/run build");
        assert_eq!(ExecRequest::parse("min://task/run build"), Ok(plain));

        // The marker is read only when a task name follows it, so a task
        // named like the marker, sent the unflagged way, stays a task name.
        let marked = ExecRequest::TaskRun {
            task: "--owns-box".to_string(),
            owns_box: false,
            args: vec![],
            cwd: String::new(),
        };
        assert_eq!(
            ExecRequest::parse(&marked.encode()),
            Ok(marked),
            "a task named like the marker must not be read as the flag"
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

    /// A task run's declared arguments ride the request as one JSON array
    /// `[task, args]`, so they survive the wire byte-exact — spaces, quotes
    /// and newlines included — and a payload with no args parses as the
    /// empty list.
    #[test]
    fn a_task_run_round_trips_its_args() {
        let req = ExecRequest::TaskRun {
            task: "build".to_string(),
            owns_box: false,
            args: vec!["--count".into(), "42".into(), "it's \"quoted\"".into()],
            cwd: String::new(),
        };
        assert_eq!(
            ExecRequest::parse(&req.encode()),
            Ok(req),
            "the args survive the round trip"
        );

        // A task name with no args is the legacy form.
        let plain = ExecRequest::TaskRun {
            task: "build".to_string(),
            owns_box: false,
            args: vec![],
            cwd: String::new(),
        };
        assert_eq!(ExecRequest::parse("min://task/run build"), Ok(plain));

        // A malformed framed payload is refused rather than guessed at.
        assert!(matches!(
            ExecRequest::parse("min://task/run [\"build\", not-json]"),
            Err(ExecParseError::TaskArgs(_))
        ));
    }

    /// The framed form keeps a task name with spaces whole, and keeps a task
    /// actually named `--owns-box` from being read as the owns-box marker
    /// when args are present.
    #[test]
    fn a_task_run_with_args_keeps_awkward_task_names_whole() {
        // A task name containing spaces survives alongside its args.
        let spaced = ExecRequest::TaskRun {
            task: "deploy prod".to_string(),
            owns_box: false,
            args: vec!["--force".into()],
            cwd: String::new(),
        };
        assert_eq!(
            ExecRequest::parse(&spaced.encode()),
            Ok(spaced),
            "a task name with spaces must not be split from its args"
        );

        // A task named exactly like the owns-box marker, sent with args, is
        // still a task name — the framed form carries it inside the JSON.
        let marked = ExecRequest::TaskRun {
            task: "--owns-box".to_string(),
            owns_box: false,
            args: vec!["--count".into(), "42".into()],
            cwd: String::new(),
        };
        assert_eq!(
            ExecRequest::parse(&marked.encode()),
            Ok(marked),
            "a task named like the marker must not be read as the flag"
        );

        // The owns-box flag still rides in front of the framed form.
        let owned = ExecRequest::TaskRun {
            task: "build".to_string(),
            owns_box: true,
            args: vec!["--count".into(), "42".into()],
            cwd: String::new(),
        };
        assert_eq!(
            ExecRequest::parse(&owned.encode()),
            Ok(owned),
            "the flag and the framed task+args survive the round trip"
        );
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

    /// A task run carries the invocation directory relative to the uploaded
    /// tree, so a task declaring `inherit_cwd` can start there. A request
    /// without one — every older client — parses as the empty cwd, and a
    /// cwd that would leave the tree is refused rather than run.
    #[test]
    fn a_task_run_round_trips_its_cwd() {
        for args in [vec![], vec!["--count".to_string(), "42".to_string()]] {
            let req = ExecRequest::TaskRun {
                task: "ic".to_string(),
                owns_box: true,
                args,
                cwd: "sub/inner".to_string(),
            };
            assert_eq!(
                ExecRequest::parse(&req.encode()),
                Ok(req),
                "the cwd survives the round trip"
            );
        }

        // No cwd: the legacy spellings, bare and framed, parse as empty.
        for wire in ["min://task/run ic", "min://task/run [\"ic\",[\"a\"]]"] {
            let Ok(ExecRequest::TaskRun { cwd, .. }) = ExecRequest::parse(wire) else {
                panic!("{wire} must parse as a task run");
            };
            assert_eq!(cwd, "", "{wire}");
        }

        // A cwd that escapes the tree is refused.
        for bad in ["/etc", "..", "sub/../..", "sub/.."] {
            let wire = format!("min://task/run [\"ic\",[],\"{bad}\"]");
            assert_eq!(
                ExecRequest::parse(&wire),
                Err(ExecParseError::TaskCwd(bad.to_string())),
                "{bad} must be refused"
            );
        }
    }
}
