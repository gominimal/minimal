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
    /// Hidden credential-lane broker — spawned and supervised by this daemon,
    /// not for direct use.
    ///
    /// A subcommand rather than a fifth binary: `release.yml` is frozen and
    /// lists every shipped artifact explicitly, so a new Mach-O could not ship.
    /// It belongs to `minvmd` because the broker must run wherever gvproxy
    /// does — the switch NATs its host alias to that machine's loopback.
    #[command(name = credlane::server::SUBCOMMAND, hide = true)]
    Broker(BrokerArgs),
}

/// Where the broker child listens. Both values are passed explicitly by the
/// supervisor so parent and child cannot derive two different sockets; the
/// defaults exist for a hand-run broker.
#[derive(Debug, clap::Args)]
struct BrokerArgs {
    /// Control socket to bind (default: the path `min` derives).
    #[arg(long)]
    control_socket: Option<std::path::PathBuf>,

    /// Box-facing loopback port.
    #[arg(long, default_value_t = credlane::server::DEFAULT_PORT)]
    port: u16,
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
        Command::Config { action } => match action {
            ConfigAction::Show { json } => minvmd::cmd::config::run_show(json),
            ConfigAction::Set { vcpus, ram_mib } => minvmd::cmd::config::run_set(vcpus, ram_mib),
        },
        Command::Stop => minvmd::cmd::stop::run(),
        Command::KrunVmm => minvmd::cmd::vmm_child::run(),
        Command::Broker(args) => run_broker(args),
    }
}

/// Runs the credential broker in the foreground until a listener fails.
///
/// Its own multi-threaded runtime: the broker proxies streams for however many
/// boxes hold lanes, and the rest of `minvmd`'s commands are synchronous.
fn run_broker(args: BrokerArgs) -> Result<()> {
    let control_socket = match args.control_socket {
        Some(path) => path,
        None => credlane::control_socket_path().context("resolving the broker control socket")?,
    };
    let config = credlane::BrokerConfig::new(control_socket).with_port(args.port);
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("building the broker runtime")?
        .block_on(credlane::server::run(config))
        .context("running the credential broker")
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

    /// The exact argv `credlane::server::BrokerProcess` spawns. The supervisor
    /// lives in another crate, so nothing but this test stops the two halves of
    /// that contract from drifting apart.
    #[test]
    fn the_broker_subcommand_parses_what_its_supervisor_spawns() {
        let cli = Cli::try_parse_from([
            "minvmd",
            credlane::server::SUBCOMMAND,
            "--control-socket",
            "/run/user/1000/minimal/credlane.sock",
            "--port",
            "7656",
        ])
        .expect("the supervisor's argv must parse");
        let Command::Broker(args) = cli.command else {
            panic!("expected the broker subcommand")
        };
        assert_eq!(
            args.control_socket.as_deref(),
            Some(std::path::Path::new("/run/user/1000/minimal/credlane.sock"))
        );
        assert_eq!(args.port, 7656);
    }

    /// Run bare, the broker lands on the port a box is handed by
    /// `BrokerEndpoint`, and on the socket `min` will connect to.
    #[test]
    fn a_bare_broker_takes_the_shared_defaults() {
        let cli = Cli::try_parse_from(["minvmd", credlane::server::SUBCOMMAND]).unwrap();
        let Command::Broker(args) = cli.command else {
            panic!("expected the broker subcommand")
        };
        assert!(args.control_socket.is_none());
        assert_eq!(args.port, credlane::server::DEFAULT_PORT);
    }
}
