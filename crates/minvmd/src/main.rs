//! `minvmd` CLI entry point.

use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
#[command(name = "minvmd", version = env!("CARGO_PKG_VERSION"))]
#[command(
    about = "Host daemon that brings up a Linux microVM via libkrun (macOS/HVF or Linux/KVM)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Override the state dir base (default: $XDG_STATE_HOME/minimal).
    /// Runtime files live under `<dir>/providers/local-0/`.
    #[arg(long, global = true)]
    minimal_state_dir: Option<paths::CwdRelative<paths::Daemon>>,
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
    /// Start the microVM supervisor (foreground by default).
    Run {
        /// Spawn the supervisor in the background and return once the host UDS
        /// is accepting connections.
        #[arg(long)]
        detach: bool,
        /// Timeout in seconds to wait for the host UDS when using --detach.
        #[arg(long, default_value_t = minvmd::cmd::run::DEFAULT_DETACH_TIMEOUT_SECS)]
        timeout: u64,
    },
    /// Print daemon status (exit 0 if running, 1 if stopped, 2 on lock contention).
    Status {
        /// Print status as a JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Show or set persisted per-VM resource configuration (applied next boot).
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    /// Stop the running daemon gracefully.
    Stop,
    /// Hidden VMM child subcommand — spawned by `boot`, not for direct use.
    #[command(name = "__krun-vmm", hide = true)]
    KrunVmm,
}

#[derive(Subcommand)]
enum ConfigAction {
    /// Print the effective resource configuration and each value's source.
    Show {
        /// Print as a JSON object.
        #[arg(long)]
        json: bool,
    },
    /// Validate and persist resource parameters for the next boot.
    Set {
        /// Number of virtual CPUs.
        #[arg(long)]
        vcpus: Option<u8>,
        /// Guest RAM in MiB.
        #[arg(long)]
        ram_mib: Option<u32>,
    },
}

fn main() -> Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    let cli = Cli::parse();

    if let Some(dir) = &cli.minimal_state_dir {
        let dir = dir
            .resolve()
            .map_err(|e| anyhow::anyhow!("resolving --minimal-state-dir: {e}"))?;
        minvmd::state::set_state_dir_override(dir);
    }

    match cli.command {
        Command::Boot { foreground } => minvmd::cmd::boot::run(foreground),
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut std::io::stdout());
            Ok(())
        }
        Command::Run { detach, timeout } => minvmd::cmd::run::run(detach, timeout),
        Command::Status { json } => {
            let exit = minvmd::cmd::status::run(json)?;
            let code = exit.code();
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        Command::Config { action } => match action {
            ConfigAction::Show { json } => minvmd::cmd::config::run_show(json),
            ConfigAction::Set { vcpus, ram_mib } => minvmd::cmd::config::run_set(vcpus, ram_mib),
        },
        Command::Stop => minvmd::cmd::stop::run(),
        Command::KrunVmm => minvmd::cmd::vmm_child::run(),
    }
}
