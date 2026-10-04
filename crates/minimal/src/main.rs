//! The minimal CLI which pairs/talks-with minimald.

use std::io::IsTerminal as _;
use std::io::Write as _;
use std::process::ExitCode;

use anyhow::Context as _;
use clap::{CommandFactory as _, Parser};
use minimal::{ExecArgs, PolicyArgs, PolicyOutputFormat};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

/// Custom main: handle shell completion requests before launching the async world.
fn main() -> ExitCode {
    clap_complete::CompleteEnv::with_factory(minimal::Cli::command)
        .var(minimal::COMPLETE_VAR)
        .complete();

    run()
}

#[tokio::main]
async fn run() -> ExitCode {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("warn")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("libcgroups=off".parse().unwrap())
    });

    // Invoked as `git-remote-min` (a symlink or copy of this binary): speak
    // the git remote-helper protocol on stdout, so logs must go to stderr.
    if minimal::git_remote::invoked_as_remote_helper() {
        tracing_subscriber::registry()
            .with(fmt::layer().with_writer(std::io::stderr))
            .with(filter)
            .init();

        let args: Vec<String> = std::env::args().skip(1).collect();
        return match minimal::git_remote::run(&args).await {
            Ok(code) => code,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        };
    }

    // Parse before installing the subscriber, so the shell completion handler can
    // be configured to log to stderr instead of stdout.
    let cli = minimal::Cli::parse();
    minimal::theme::install();

    // Publish `--vm` before any path resolution, so the socket, the state dir,
    // and any autospawn all name the same VM (NET-052).
    if let Err(e) = cli.global_args.publish_vm_name() {
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }

    let registry = tracing_subscriber::registry().with(filter);
    // `min dash` owns the terminal (alternate screen); a log line landing on
    // stdout/stderr would corrupt the frame. Log to <state>/dash.log
    // instead, discarding if the state dir can't be written.
    if matches!(cli.command, Some(minimal::Command::Dash)) {
        // Honor `--minimal-dir` so an isolated daemon's logs stay isolated.
        let base = cli
            .global_args
            .minimal_dir
            .clone()
            .unwrap_or_else(|| paths::minimal_state_dir().as_utf8_path().into());
        // Open the log file once; MakeWriter is per-write, so the closure
        // must not re-open it per log event.
        let file = {
            let path = base.join("dash.log");
            let _ = std::fs::create_dir_all(&base);
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .map(std::sync::Arc::new)
                .ok()
        };
        let log = move || -> Box<dyn std::io::Write + Send> {
            match &file {
                Some(f) => Box::new(DashLog(f.clone())),
                None => Box::new(std::io::sink()),
            }
        };
        registry
            .with(fmt::layer().with_writer(log).with_ansi(false))
            .init();
    } else if stdout_is_data_contract(&cli.command) {
        registry
            .with(
                fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(std::io::stderr().is_terminal()),
            )
            .init();
    } else {
        registry
            .with(
                fmt::layer()
                    .with_writer(ot::StdoutWriter::new)
                    .with_ansi(std::io::stdout().is_terminal()),
            )
            .init();
    }

    // The output mode the run is under, read before the CLI is consumed:
    // the error path keys on it (below), so a machine-output run answers a
    // failure with its own contract rather than a plain-text line.
    let output_mode = machine_output_mode(&cli);

    if let Err(e) = minimal::run(cli).await {
        // A task's non-zero exit (`min task run`) is a status to relay, not
        // an error to print — the task's own output already streamed through
        // (the git-remote helper's ExitCode precedent).
        if let Some(&minimal::task::TaskExit(code)) = e.downcast_ref::<minimal::task::TaskExit>() {
            return ExitCode::from(code);
        }
        // A machine-output run answers its failure with the one
        // `min/v1/error` object a client parses: the emitter below, keyed
        // on the output mode the run was under rather than on the command,
        // so the mechanism is one, shared by every command that takes
        // `-o json` — each fails its walk into the generic
        // [`minimal::MachineModeFailure`] payload, which is all this path
        // downcasts. The object is the contract, so there is no second,
        // plain-text line to print for the same failure, only the non-zero
        // status.
        if output_mode.is_some()
            && let Some(failure) = e.downcast_ref::<minimal::MachineModeFailure>()
        {
            emit_machine_mode_error(failure);
            return ExitCode::FAILURE;
        }
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// A cheaply clonable writer over the dash log file: every clone writes
/// through the same opened file (append mode) instead of re-opening it.
struct DashLog(std::sync::Arc<std::fs::File>);

impl std::io::Write for DashLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        (&*self.0).write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        (&*self.0).flush()
    }
}

/// Whether the command's stdout is a data contract that tracing must not
/// pollute, so its logs go to stderr instead. The `completions` handlers emit a
/// shell shim on stdout, `session exec` carries only the exec'd
/// command's output, and `task run` / `session run` stream the task's stdout —
/// a log line in any of them would be read as content. A bare `min` (no subcommand) is
/// one too: its non-TTY twin promises an empty stdout to pipelines, and its
/// interactive activate path prints only the session id there. So is
/// `session policy -o json`, whose stdout is one document a script parses.
fn stdout_is_data_contract(command: &Option<minimal::Command>) -> bool {
    matches!(
        command,
        None | Some(
            minimal::Command::CompleteSessionStr(_)
                | minimal::Command::Completions(_)
                | minimal::Command::Session(minimal::SessionArgs {
                    command: minimal::SessionCommand::Exec(ExecArgs { .. })
                        | minimal::SessionCommand::Run(_)
                        | minimal::SessionCommand::Policy(PolicyArgs {
                            output: Some(PolicyOutputFormat::Json),
                            ..
                        }),
                })
                | minimal::Command::Task(minimal::TaskArgs {
                    command: minimal::TaskCommand::Run(_),
                })
        )
    )
}

/// The machine output mode a run is under: the command's `-o`, the flag the
/// architecture's machine-output contract hangs on — `json` for
/// `min session policy -o json`, the one command that takes it today.
/// `None` for every text run, and for a command that has not taken `-o
/// json` yet, which is the same thing to the error path: its failure is a
/// plain-text line. Both gates below key on this, so a command joins the
/// machine mode by growing an `output` flag, and nothing else about its
/// error path changes.
fn machine_output_mode(cli: &minimal::Cli) -> Option<PolicyOutputFormat> {
    match &cli.command {
        Some(minimal::Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Policy(PolicyArgs { output, .. }),
        })) => *output,
        _ => None,
    }
}

/// The schema stamp of the machine-mode error object — the same kind of
/// stamp a document carries, on the object a failure answers with.
const MACHINE_ERROR_SCHEMA: &str = "min/v1/error";

/// The shape of the one `min/v1/error` object.
#[derive(serde::Serialize)]
struct MachineModeErrorDoc<'a> {
    schema: &'static str,
    code: &'a str,
    message: &'a str,
    hint: &'a str,
}

/// The machine-mode error object, encoded: the schema stamp, the `code` a
/// script branches on, the message, and the hint — nothing else on the
/// line, and no line beside it.
fn machine_mode_error_line(failure: &minimal::MachineModeFailure) -> anyhow::Result<String> {
    let object = MachineModeErrorDoc {
        schema: MACHINE_ERROR_SCHEMA,
        code: failure.code(),
        message: failure.message(),
        hint: failure.hint(),
    };
    serde_json_lenient::to_string(&object).context("encoding the machine-mode error object")
}

/// The machine-mode error emitter: writes the one `min/v1/error` object on
/// stderr, the only thing the mode puts there on any failure, so a client
/// parses a failure the same way it parses the document. Keyed on the
/// output mode the failed run was under (the gate in the error path
/// above), and generic over the payload: a command that takes `-o json`
/// fails its walk into [`minimal::MachineModeFailure`] — carried through
/// the `anyhow` chain, the way [`minimal::task::TaskExit`] is — and needs
/// nothing else; the walk's own kinds name the code, message and hint, and
/// this turns them into the object. `min ls --json` and its kin are
/// untouched: their failure stays the plain-text line it always was.
fn emit_machine_mode_error(failure: &minimal::MachineModeFailure) {
    let mut err = std::io::stderr();
    match machine_mode_error_line(failure) {
        // One object, one line — and a fallback the mode never wants, for
        // an encode that cannot happen: the exit code is non-zero either
        // way.
        Ok(line) => {
            let _ = writeln!(err, "{line}");
        }
        Err(error) => {
            let _ = writeln!(err, "error: {error:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimal::Command;

    /// A bare `min` (no subcommand) keeps stdout clean: the non-TTY twin
    /// promises pipelines an empty stdout, so its tracing must go to stderr.
    #[test]
    fn bare_min_is_a_stdout_contract() {
        assert!(stdout_is_data_contract(&None));
    }

    /// `min session run` streams the task's stdout over the exec channel, so
    /// tracing must route to stderr like the other stdout contracts.
    #[test]
    fn session_run_is_a_stdout_contract() {
        let cmd = Some(Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Run(minimal::SessionRunArgs {
                session: "web".to_string(),
                task: "build".to_string(),
            }),
        }));
        assert!(stdout_is_data_contract(&cmd));
    }

    /// `min task run` streams the task's stdout, so tracing must route to
    /// stderr there like the other stdout contracts.
    #[test]
    fn task_run_is_a_stdout_contract() {
        let cmd = Some(Command::Task(minimal::TaskArgs {
            command: minimal::TaskCommand::Run(minimal::TaskRunArgs {
                task: "build".to_string(),
                path: None,
                keep: false,
                args: vec![],
            }),
        }));
        assert!(stdout_is_data_contract(&cmd));
    }

    /// `min session policy -o json` writes one document a script parses, so
    /// its tracing must route to stderr — and the text rendering, whose
    /// stdout is for a person, must not be caught by the same gate.
    #[test]
    fn session_policy_json_is_a_stdout_contract() {
        let cmd = Some(Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Policy(PolicyArgs {
                session: "web".to_string(),
                output: Some(PolicyOutputFormat::Json),
            }),
        }));
        assert!(stdout_is_data_contract(&cmd));
        let cmd = Some(Command::Session(minimal::SessionArgs {
            command: minimal::SessionCommand::Policy(PolicyArgs {
                session: "web".to_string(),
                output: None,
            }),
        }));
        assert!(!stdout_is_data_contract(&cmd));
    }

    /// The error path's key: a `-o json` run is a machine-output run, a text
    /// run is not, and a command that has not taken `-o json` yet is not
    /// either — the same three-way split the subscriber gate makes, read
    /// before the CLI is consumed so the failed run can still be asked what
    /// mode it was in.
    #[test]
    fn machine_output_mode_keys_on_the_output_flag() {
        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: Some(Command::Session(minimal::SessionArgs {
                command: minimal::SessionCommand::Policy(PolicyArgs {
                    session: "web".to_string(),
                    output: Some(PolicyOutputFormat::Json),
                }),
            })),
        };
        assert_eq!(machine_output_mode(&cli), Some(PolicyOutputFormat::Json));

        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: Some(Command::Session(minimal::SessionArgs {
                command: minimal::SessionCommand::Policy(PolicyArgs {
                    session: "web".to_string(),
                    output: None,
                }),
            })),
        };
        assert_eq!(machine_output_mode(&cli), None);

        let cli = minimal::Cli {
            global_args: minimal::GlobalArgs::default(),
            command: None,
        };
        assert_eq!(machine_output_mode(&cli), None);
    }

    /// The one object a machine-output failure answers with: a
    /// `min/v1/error` stamp, the `code` a script branches on, the message,
    /// and the hint — one line, nothing else, so a client parses a failure
    /// the same way it parses the document. Pinned here, beside the emitter
    /// that writes it.
    #[test]
    fn machine_mode_error_object_is_one_stamped_line() {
        let failure = minimal::MachineModeFailure::new(
            "not_found",
            "No session found matching 'gone'".to_string(),
            "no session by that name or id exists; `min ls` lists the \
             sessions there are"
                .to_string(),
        );
        let line = machine_mode_error_line(&failure).unwrap();
        let document: serde_json_lenient::Value =
            serde_json_lenient::from_str(line.trim_end()).unwrap();
        assert_eq!(
            document["schema"].as_str(),
            Some("min/v1/error"),
            "the failure object carries its own schema stamp: {line}"
        );
        assert_eq!(
            document["code"].as_str(),
            Some("not_found"),
            "the failure's kind is a name, not a message to parse: {line}"
        );
        assert_eq!(
            document["message"].as_str(),
            Some("No session found matching 'gone'"),
            "the message beside it, the kind of thing that was missing: {line}"
        );
        assert_eq!(
            document["hint"].as_str(),
            Some("no session by that name or id exists; `min ls` lists the sessions there are"),
            "the hint names the remedy, and the kind of thing that was missing: {line}"
        );
        assert_eq!(
            line.lines().count(),
            1,
            "one object, one line, nothing else: {line}"
        );
    }
}
