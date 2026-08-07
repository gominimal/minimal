//! The minimal CLI which pairs/talks-with minimald.

use std::io::IsTerminal as _;
use std::process::ExitCode;

use clap::{CommandFactory as _, Parser};
use minimal::ExecArgs;
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
/// command's output, and `task run` streams the task's stdout — a log line
/// in any of them would be read as content. A bare `min` (no subcommand) is
/// one too: its non-TTY twin promises an empty stdout to pipelines, and its
/// interactive activate path prints only the session id there.
fn stdout_is_data_contract(command: &Option<minimal::Command>) -> bool {
    matches!(
        command,
        None | Some(
            minimal::Command::CompleteSessionStr(_)
                | minimal::Command::Completions(_)
                | minimal::Command::Session(minimal::SessionArgs {
                    command: minimal::SessionCommand::Exec(ExecArgs { .. }),
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
    use minimal::Command;

    /// A bare `min` (no subcommand) keeps stdout clean: the non-TTY twin
    /// promises pipelines an empty stdout, so its tracing must go to stderr.
    #[test]
    fn bare_min_is_a_stdout_contract() {
        assert!(stdout_is_data_contract(&None));
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
