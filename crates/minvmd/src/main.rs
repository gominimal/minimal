//! `minvmd` CLI entry point.

use anyhow::{Context as _, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

#[derive(Parser)]
#[command(name = "minvmd", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(
    about = "Host daemon that brings up a Linux microVM via libkrun (macOS/HVF or Linux/KVM)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    /// Override the state dir base (default: $XDG_STATE_HOME/minimal).
    /// Runtime files live under `<dir>/providers/local-minvmd0/`.
    #[arg(long, global = true)]
    minimal_state_dir: Option<paths::CwdRelative<paths::Daemon>>,

    /// Name the VM to act on (default: `default`).
    ///
    /// A named VM keeps its own state directory, socket, and daemon under
    /// `<dir>/providers/local-minvmd0/<NAME>/`; the default VM's paths are
    /// unchanged. Names are at most 24 bytes of ASCII lowercase letters,
    /// digits and `-`, starting with a letter or digit; `guest` is reserved.
    #[arg(long = "vm", global = true, value_name = "NAME")]
    vm: Option<String>,
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
    #[command(visible_alias = "start")]
    Run {
        /// Spawn the supervisor in the background and return once the host UDS
        /// is accepting connections.
        #[arg(long)]
        detach: bool,
        /// Timeout in seconds to wait for the host UDS when using --detach.
        #[arg(long)]
        timeout: Option<u64>,
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
    // Parse and apply the state-dir override and the VM name BEFORE installing
    // tracing: the detached log dir derives from the state dir, and every path
    // the process resolves derives from both. Nothing in between may call
    // `tracing::*` (it would be silently dropped); clap prints its own parse
    // errors to stderr, which is fine.
    let cli = Cli::parse();

    if let Some(dir) = &cli.minimal_state_dir {
        let dir = dir
            .resolve()
            .map_err(|e| anyhow::anyhow!("resolving --minimal-state-dir: {e}"))?;
        minvmd::state::set_state_dir_override(dir);
    }

    if let Some(vm) = &cli.vm {
        minvmd::state::set_vm_name(vm).map_err(|e| anyhow::anyhow!("--vm: {e}"))?;
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
        Command::Config { action } => match action {
            ConfigAction::Show { json } => minvmd::cmd::config::run_show(json),
            ConfigAction::Set { vcpus, ram_mib } => minvmd::cmd::config::run_set(vcpus, ram_mib),
        },
        Command::Stop => {
            // One line per VM stop, naming the VM and its state directory:
            // `stop` acts on exactly one VM, and which one is the whole
            // question a person reading the log is asking (NET-055).
            minvmd::cmd::log_stopping_vm(&minvmd::state::provider_dir());
            minvmd::cmd::stop::run()
        }
        Command::KrunVmm => minvmd::cmd::vmm_child::run(),
    }
}

/// Install the tracing subscriber. Foreground processes log to stdout;
/// detached supervisors (marked by [`minvmd::DETACHED_ENV`], set by
/// `run --detach` on its re-exec'd child) write to
/// `<state_dir>/logs/minvmd.log`, daily-rotated with bounded retention,
/// mirroring minimald's scheme so `min bug` finds both daemons' logs in one
/// place. The returned guard must outlive the process — dropping it flushes
/// pending records.
fn init_tracing() -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    if std::env::var_os(minvmd::DETACHED_ENV).is_none() {
        // Colours only on a terminal: piped output — CI logs, `boot.log`
        // captures, the e2e harnesses, `grep vm=` — must stay plain text, or
        // the VM name and state dir a line carries are not searchable.
        use std::io::IsTerminal as _;
        tracing_subscriber::registry()
            .with(fmt::layer().with_ansi(std::io::stdout().is_terminal()))
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
    let appender = minvmd::build_log_appender(&log_dir, "minvmd.log")
        .context("building rotating log appender")?;
    // lossy(false): a diagnostic log that drops records under load answers
    // the wrong question; the supervisor's log volume is nowhere near the
    // channel bound.
    let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(false)
        .finish(appender);
    tracing_subscriber::registry()
        .with(mlog::json_file_layer(writer, "minvmd"))
        .with(filter)
        .init();
    tracing::info!(
        log_dir = %log_dir.display(),
        "detached minvmd: routing tracing output to daily-rotated log file",
    );
    Ok(Some(guard))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `minvmd start` is a visible alias of `run`, so the lifecycle verbs
    /// `start`/`stop` are symmetric.
    #[test]
    fn start_is_an_alias_for_run() {
        let cli = Cli::try_parse_from(["minvmd", "start"]).expect("`start` should parse as `run`");
        assert!(matches!(cli.command, Command::Run { .. }));
    }
}
