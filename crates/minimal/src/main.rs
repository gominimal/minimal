//! The minimal CLI which pairs/talks-with minimald.

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
        EnvFilter::new("info")
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

    let registry = tracing_subscriber::registry().with(filter);
    if matches!(cli.command, Some(minimal::Command::CompleteSessionStr(_))) {
        registry
            .with(fmt::layer().with_writer(std::io::stderr))
            .init();
    } else {
        registry
            .with(fmt::layer().with_writer(ot::StdoutWriter::new))
            .init();
    }

    if let Err(e) = minimal::run(cli).await {
        eprintln!("error: {e:#}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
