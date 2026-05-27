//! `minvmd` CLI entry point. T01.1 lands the skeleton only — subsequent tasks
//! add `boot`, `run`, `status`, `stop`, and the hidden `__krun-vmm` child
//! subcommand. Per R1.1 the crate compiles on macOS (real) and Linux (stub);
//! Linux-only `bail!` paths land alongside the subcommands that need them, so
//! they never silently no-op.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
#[command(name = "minvmd", version = env!("CARGO_PKG_VERSION"))]
#[command(about = "macOS-only host daemon that brings up a Linux microVM via libkrun")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate shell completion script.
    Completions {
        /// Shell to generate completions for.
        shell: Shell,
    },
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
    }
}
