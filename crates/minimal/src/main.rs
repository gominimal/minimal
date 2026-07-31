//! The minimal CLI which pairs/talks-with minimald.

use std::io::IsTerminal as _;
use std::process::ExitCode;

use clap::{CommandFactory as _, Parser};
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

    let registry = tracing_subscriber::registry().with(filter);
    // Commands whose stdout is a data contract route tracing to stderr, so a log
    // line never lands in captured output. ANSI is gated on the destination
    // being a real terminal, so a redirected stream carries no escape codes.
    if stdout_is_data_contract(&cli.command) {
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

    if let Err(e) = minimal::run(cli).await {
        // A task's non-zero exit (`min task run`) is a status to relay, not
        // an error to print — the task's own output already streamed through
        // (the git-remote helper's ExitCode precedent).
        if let Some(&minimal::task::TaskExit(code)) = e.downcast_ref::<minimal::task::TaskExit>() {
            return ExitCode::from(code);
        }
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// Whether the command's stdout is a data contract that tracing must not
/// pollute, so its logs go to stderr instead. The `completions` handlers emit a
/// shell shim on stdout, `session attach -c` carries only the exec'd
/// command's output, and `task run` streams the task's stdout — a log line
/// in any of them would be read as content.
fn stdout_is_data_contract(command: &Option<minimal::Command>) -> bool {
    matches!(
        command,
        Some(
            minimal::Command::CompleteSessionStr(_)
                | minimal::Command::Completions(_)
                | minimal::Command::Session(minimal::SessionArgs {
                    command: minimal::SessionCommand::Attach(minimal::AttachArgs {
                        command: Some(_),
                        ..
                    }),
                })
                | minimal::Command::Task(minimal::TaskArgs {
                    command: minimal::TaskCommand::Run(_),
                })
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use minimal::{AttachArgs, Command, SessionArgs, SessionCommand};

    fn attach(command: Option<&str>) -> Option<Command> {
        Some(Command::Session(SessionArgs {
            command: SessionCommand::Attach(AttachArgs {
                session: None,
                command: command.map(str::to_owned),
            }),
        }))
    }

    #[test]
    fn attach_with_command_is_a_stdout_contract() {
        assert!(stdout_is_data_contract(&attach(Some("min check"))));
    }

    #[test]
    fn interactive_attach_is_not_a_stdout_contract() {
        assert!(!stdout_is_data_contract(&attach(None)));
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
            }),
        }));
        assert!(stdout_is_data_contract(&cmd));
    }
}
