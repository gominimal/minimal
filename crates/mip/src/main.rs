#![allow(clippy::result_large_err)]

use anyhow::anyhow;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use mctx::{ConfigBuilder, Context, Error};
use std::io;
use std::io::IsTerminal as _;
use std::path::PathBuf;
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

// `cmd_pkg` owns the `mip package` subcommand table and dispatches into the
// `cmd_pkg_*` modules below.
mod cmd_pkg;
mod cmd_pkg_build_plan;
mod cmd_pkg_dep;
mod cmd_pkg_patched_build;
mod cmd_pkg_upload_cache;
use cmd_pkg::{PkgCmd, cmd_pkg};
mod cmd_check;
use cmd_check::{CheckArgs, cmd_check};
mod cmd_materialize;
use cmd_materialize::{MaterializeArgs, cmd_materialize};
#[cfg(target_os = "linux")]
mod cmd_run;
#[cfg(target_os = "linux")]
use cmd_run::{RunArgs, cmd_run, cmd_run_by_spec};
mod cmd_update;
use cmd_update::{UpdateArgs, cmd_update};
mod cmd_init;
use cmd_init::{InitArgs, cmd_init};
mod cmd_add;
use cmd_add::{AddArgs, cmd_add};
mod cmd_dump;
use cmd_dump::{DumpArgs, cmd_dump};
mod cmd_status;
use cmd_status::{StatusArgs, cmd_status};
mod cmd_cache;
use cmd_cache::{CacheArgs, cmd_cache};
mod cmd_rexec;
use cmd_rexec::{RexecArgs, cmd_rexec};
mod cmd_remote_build;
use cmd_remote_build::{RemoteBuildArgs, cmd_remote_build};

#[derive(Parser)]
#[command(name = "mip", version = version::VERSION, long_version = version::LONG_VERSION)]
#[command(about = "Minimal-In-Process, the CLI for daemon-less Minimal operations")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global_args: GlobalArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Runs a task, such as one specified in `minimal.toml`.
    #[cfg(target_os = "linux")]
    Run(RunArgs),
    /// Refreshes local checkouts of upstream packages & the standard library.
    Update(UpdateArgs),
    /// Add a new tool or dependency.
    Add(AddArgs),
    /// Automatically initialize minimal configuration based on your source tree.
    Init(InitArgs),
    /// Shows the status of Minimal in this codebase.
    Status(StatusArgs),
    /// Materializes an output specified in `minimal.toml`.
    Materialize(MaterializeArgs),
    /// Package management operations, such as building.
    #[clap(subcommand, alias = "pkg", alias = "packages")]
    Package(PkgCmd),
    /// Execute a command on a remote build server.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    Rexec(RexecArgs),
    /// Build packages on a remote build server.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    RemoteBuild(RemoteBuildArgs),
    /// Manipulate the local cache.
    #[clap(subcommand)]
    Cache(CacheArgs),

    /// Validates minimal configuration including packages, stacks, and profiles
    Check(CheckArgs),
    /// Dumps out information about the supply chain in a machine-readable format.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    Dump(DumpArgs),

    /// Generate shell completion script
    #[command(
        long_about = "Generate a shell tab-completion script for the mip CLI for your shell.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(mip completions bash)"
    )]
    Completions(CompletionsArgs),
}

#[derive(Debug, clap::Args)]
struct CompletionsArgs {
    /// The shell type for a CLI completion script should be printed
    #[arg(value_parser)]
    shell: Shell,
}

/// Shared arguments and builders across all subcommands
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Use the given directory as the repository root, instead of searching from the current working directory.
    #[arg(long, short = 'C')]
    repo_dir: Option<PathBuf>,

    /// Override the base directory used for operations (default: ~/.cache/minimal)
    #[arg(long)]
    minimal_dir: Option<PathBuf>,
    /// Load the minimal standard library from the given path instead
    #[arg(long)]
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    stdlib_dir: Option<PathBuf>,

    /// Ignore locally-available binary artifacts (results in rebuilds unless present in a remote cache)
    #[arg(long, default_value_t = false, global = true)]
    no_cache: bool,

    /// Do not fetch binary artifacts from the internet
    #[arg(long, default_value_t = false, global = true)]
    no_fetch: bool,

    /// Use only what's already in the local cache for sources, VCS checkouts,
    /// and the remote artifact cache. On cache miss, fail with a clear error
    /// instead of attempting any network call. Useful for builds in
    /// network-isolated environments where every input is pre-staged.
    ///
    /// Composes with the other cache flags:
    ///   - implies the remote-artifact-cache-skip half of --no-fetch (you
    ///     can't reach the artifact cache when offline anyway), so
    ///     --offline alone is sufficient — no need for --offline --no-fetch
    ///   - orthogonal to --no-cache and --rebuild, which control whether to
    ///     use locally-built artifacts (--offline doesn't force a rebuild;
    ///     it just gates the network)
    #[arg(long, default_value_t = false, global = true)]
    offline: bool,

    /// Configure the number of parallel builds
    #[arg(short, long, global = true)]
    num_parallel_builds: Option<usize>,
}

pub(crate) fn enforce_science_mode() -> Result<(), Error> {
    if std::env::var("MINIMAL_SCIENCE_MODE").unwrap_or("".to_string()) != "yeppers" {
        eprintln!("You are using a command that is experimental or very unsafe!!");
        eprintln!(
            "No guarantees are given about the consistency of your minimal install following the execution of such commands, nor the stability of any such commands."
        );
        eprintln!(
            "If you are sure you want to continue, set the environment variable MINIMAL_SCIENCE_MODE=yeppers before continuing."
        );
        eprintln!();

        Err(Error::Other(anyhow!(
            "Aborting execution of unsafe command outside of science mode"
        )))
    } else {
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("libcgroups=off".parse().unwrap())
            .add_directive("build_events=off".parse().unwrap())
            .add_directive("build_events_proto=off".parse().unwrap())
    });

    tracing_subscriber::registry()
        .with(
            fmt::layer()
                .with_writer(ot::StderrWriter::new)
                .with_ansi(io::stderr().is_terminal()),
        )
        .with(filter)
        .init();

    let cli = Cli::parse();

    let result = run_cli(cli).await;

    if let Err(e) = result {
        e.report_to_stderr();
        std::process::exit(1);
    };
    Ok(())
}

async fn run_cli(cli: Cli) -> Result<(), Error> {
    let Cli {
        command,
        global_args,
    } = cli;

    // One operation tree for this CLI invocation, rendered to stderr. Threaded
    // into the Context so all operations attach to it (replacing the former
    // process-global root).
    let ot_root = ot::OpTracker::new_root();
    ot::render_to_stderr(ot_root.clone());

    let mut config = ConfigBuilder::new()
        .with_operation_tracker(ot_root)
        .with_no_cache(global_args.no_cache)
        .with_no_fetch(global_args.no_fetch)
        .with_offline(global_args.offline);
    if let Some(num_parallel_builds) = global_args.num_parallel_builds {
        config = config.with_num_parallel_builds(num_parallel_builds);
    }
    if let Some(repo_dir) = global_args.repo_dir {
        config = config.with_repo_dir(repo_dir);
    }
    if let Some(minimal_dir) = global_args.minimal_dir {
        config = config.with_state_dir(minimal_dir);
    }
    if let Some(stdlib_dir) = global_args.stdlib_dir {
        config = config.with_stdlib_dir(stdlib_dir);
    }
    let config = config.build()?;

    // Commands that don't need a minimal.toml / full Context.
    match command {
        Command::Completions(CompletionsArgs { shell }) => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            clap_complete::generate(shell, &mut cmd, name, &mut io::stdout());
            return Ok(());
        }
        Command::Init(args) => return cmd_init(args, config).await,
        #[cfg(target_os = "linux")]
        Command::Run(RunArgs {
            variant:
                cmd_run::RunVariant::BySpec {
                    upstream,
                    task_spec,
                },
            task_args,
        }) => return cmd_run_by_spec(upstream, task_spec, task_args, config).await,
        _ => {}
    }
    let mut ctx = Context::new(config)?;

    match command {
        Command::Package(args) => cmd_pkg(args, &mut ctx).await,
        Command::Check(args) => cmd_check(args, &mut ctx).await,
        Command::Add(args) => cmd_add(args, &mut ctx).await,
        Command::Materialize(args) => cmd_materialize(args, &mut ctx).await,
        #[cfg(target_os = "linux")]
        Command::Run(args) => cmd_run(args, &mut ctx).await,
        Command::Update(args) => cmd_update(args, &mut ctx).await,
        Command::Dump(args) => cmd_dump(args, &mut ctx).await,
        Command::Status(args) => cmd_status(args, &mut ctx).await,
        Command::Rexec(args) => cmd_rexec(args, &mut ctx).await,
        Command::RemoteBuild(args) => cmd_remote_build(args, &mut ctx).await,
        Command::Cache(args) => cmd_cache(args, &mut ctx).await,
        // Handled before Context::new
        Command::Completions(_) | Command::Init(_) => unreachable!(),
    }
}
