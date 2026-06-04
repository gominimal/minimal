//! `minvmd` CLI entry point.

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
    /// Boot the microVM and wait until the guest is up.
    Boot {
        /// Stay in the foreground until the VMM child exits.
        #[arg(long)]
        foreground: bool,
    },
    /// Generate shell completion script.
    Completions {
        /// Shell to generate completions for.
        shell: Shell,
    },
    /// Hidden VMM child subcommand — spawned by `boot`, not for direct use.
    #[command(name = "__krun-vmm", hide = true)]
    KrunVmm,
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Boot { foreground } => minvmd::cmd::boot::run(foreground),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Command::KrunVmm => minvmd::cmd::vmm_child::run(),
    }
}
