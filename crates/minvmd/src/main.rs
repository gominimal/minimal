//! `minvmd` CLI entry point.

use anyhow::{Context as _, Result};
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
    /// Stop the running daemon gracefully.
    Stop,
    /// Hidden VMM child subcommand — spawned by `boot`, not for direct use.
    #[command(name = "__krun-vmm", hide = true)]
    KrunVmm,
}

fn main() -> Result<()> {
    // Parse and apply the state-dir override BEFORE installing tracing: the
    // detached log dir derives from the state dir. Nothing in between may
    // call `tracing::*` (it would be silently dropped); clap prints its own
    // parse errors to stderr, which is fine.
    let cli = Cli::parse();

    if let Some(dir) = &cli.minimal_state_dir {
        let dir = dir
            .resolve()
            .map_err(|e| anyhow::anyhow!("resolving --minimal-state-dir: {e}"))?;
        minvmd::state::set_state_dir_override(dir);
    }

    let _log_guard = init_tracing()?;

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
        Command::Stop => minvmd::cmd::stop::run(),
        Command::KrunVmm => minvmd::cmd::vmm_child::run(),
    }
}

/// Install the tracing subscriber. Foreground processes log to stdout;
/// detached supervisors (marked by [`minvmd::DETACHED_ENV`], set by
/// `run --detach` on its re-exec'd child) write to
/// `<state_dir>/logs/minvmd.log.<date>`, daily-rotated, mirroring minimald's
/// scheme so `min bug` finds both daemons' logs in one place. The returned
/// guard must outlive the process — dropping it flushes pending records.
fn init_tracing() -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if std::env::var_os(minvmd::DETACHED_ENV).is_none() {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(filter)
            .init();
        return Ok(None);
    }

    let log_dir = minvmd::state::state_base_dir()
        .as_utf8_path()
        .as_std_path()
        .join("logs");
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("creating minvmd log directory at {}", log_dir.display()))?;
    // 14 retained days matches minimald: long enough for "what happened
    // last week", bounded on disk.
    let appender = tracing_appender::rolling::Builder::new()
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .filename_prefix("minvmd.log")
        .max_log_files(14)
        .build(&log_dir)
        .context("building rolling log appender")?;
    let (writer, guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::registry()
        // ANSI escape codes are noise in a file.
        .with(fmt::layer().with_ansi(false).with_writer(writer))
        .with(filter)
        .init();
    tracing::info!(
        log_dir = %log_dir.display(),
        "detached minvmd: routing tracing output to daily-rotated log file",
    );
    Ok(Some(guard))
}
