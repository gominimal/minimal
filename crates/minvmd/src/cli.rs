//! CLI surface and command dispatch (macOS-only).

use clap::{Parser, Subcommand};

use crate::config;
use crate::error::UserFacing;

#[derive(Parser)]
#[command(name = "minvmd", about = "macOS VM host broker for minimald")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Boot the Linux VM.
    Up,
    /// Stop the Linux VM.
    Down,
    /// Print the VM status (Running, Stopped, or NotRunning).
    Status,
    /// Open a root shell inside the guest.
    DebugShell,
}

/// Parse argv and run the requested subcommand.
pub async fn run() -> anyhow::Result<()> {
    let cli = Cli::parse();
    tracing::info!("minvmd starting");
    match cli.command {
        Command::Up => {
            // Config loads here; the lifecycle/image work is wired in later.
            let _cfg = config::Config::load_default()?;
            Err(anyhow::Error::from(UserFacing::new(
                "not yet implemented: minvmd up",
            )))
        }
        Command::Down => Err(anyhow::Error::from(UserFacing::new(
            "not yet implemented: minvmd down",
        ))),
        Command::Status => Err(anyhow::Error::from(UserFacing::new(
            "not yet implemented: minvmd status",
        ))),
        Command::DebugShell => Err(anyhow::Error::from(UserFacing::new(
            "not yet implemented: minvmd debug-shell",
        ))),
    }
}
