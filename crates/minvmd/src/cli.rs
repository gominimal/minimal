//! CLI surface and command dispatch (macOS-only).

use clap::{Parser, Subcommand};

use crate::error::UserFacing;
use crate::{config, image};

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
            let cfg = config::Config::load_default()?;
            let vm_dir = image::default_vm_dir()?;
            image::ensure_image(&cfg, vm_dir.as_utf8_path().as_std_path()).await?;
            Err(anyhow::Error::from(UserFacing::new(
                "not yet implemented: minvmd up (lifecycle)",
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
