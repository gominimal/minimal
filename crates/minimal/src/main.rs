#![allow(clippy::result_large_err)]

use anyhow::anyhow;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use mctx::{ConfigBuilder, Context, Error};
use std::io;
use std::path::PathBuf;
use tracing_indicatif::IndicatifLayer;
use tracing_indicatif::{filter::IndicatifFilter, filter::hide_indicatif_span_fields};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod cmd_pkg;
use cmd_pkg::{PkgArgs, cmd_pkg};
mod cmd_check;
use cmd_check::{CheckArgs, cmd_check};
mod cmd_plan;
use cmd_plan::{PlanArgs, cmd_plan};
mod cmd_materialize;
use cmd_materialize::{MaterializeArgs, cmd_materialize};
mod cmd_upload_cache;
use cmd_upload_cache::{UploadArgs, cmd_upload_cache};
mod cmd_patched_build;
use cmd_patched_build::{PatchedBuildArgs, cmd_patched_build};
#[cfg(target_os = "linux")]
mod cmd_run;
#[cfg(target_os = "linux")]
use cmd_run::{RunArgs, cmd_run};
mod cmd_dep;
use cmd_dep::{DepArgs, cmd_dep};
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

#[derive(Parser)]
#[command(name = "minimal", version = env!("GIT_HASH"))]
#[command(about = "The Minimal CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global_args: GlobalArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Runs a task specified in `minimal.toml`.
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
    /// Launches a development shell. Shorthand for `minimal run shell`.
    Shell,
    /// Runs the build task. Shorthand for `minimal run build`.
    Build,
    /// Runs the test task. Shorthand for `minimal run test`.
    Test,
    /// Materializes an output specified in `minimal.toml`.
    Materialize(MaterializeArgs),
    /// Builds the specified package(s) in a clean room, making them available in the local cache.
    #[clap(alias = "pkg")]
    Package(PkgArgs),
    /// Manipulate the local cache.
    #[clap(subcommand)]
    Cache(CacheArgs),

    /// Validates minimal configuration including packages, harnesses, and profiles
    Check(CheckArgs),
    /// Prints the build plan for the specified package(s)
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    Plan(PlanArgs),
    /// Uploads the specified packages and their transitive needs to the cache.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    UploadCache(UploadArgs),
    /// Executes the build for a package, using stale dependencies.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    PatchedBuild(PatchedBuildArgs),
    /// Dumps out information about the supply chain in a machine-readable format.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    Dump(DumpArgs),
    /// Generates Graphviz source code of the dependency graph
    #[command(
        long_about = "Generate an image of the dependency graph using graphviz's \"dot\" program.\n\n  minimal dep --input_deps_depth=0 -p file | dot -Tpng > deps.png"
    )]
    Dep(DepArgs),

    /// Generate shell completion script
    #[command(
        long_about = "Generate a shell tab-completion script for the minimal CLI for your shell.\nSupported shells include bash, zsh, elvish and fish.\n\n   source <(minimal completions bash)"
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
    #[arg(long, default_value_t = false)]
    no_cache: bool,

    /// Do not fetch binary artifacts from the internet
    #[arg(long, default_value_t = false)]
    no_fetch: bool,

    /// Configure the number of parallel builds
    #[arg(short, long)]
    num_parallel_builds: Option<usize>,

    /// Write build events to a protobuf text format file
    #[arg(long)]
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    build_events_file: Option<PathBuf>,
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
    let build_timestamp: u64 = env!("BUILD_TIMESTAMP")
        .parse()
        .expect("Invalid BUILD_TIMESTAMP");
    let build_time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(build_timestamp);

    if build_time.elapsed().unwrap() > std::time::Duration::from_hours(30 * 24) {
        eprintln!("Error: This binary has expired (built more than 30 days ago).");
        eprintln!("Please rebuild to continue.");
        std::process::exit(1);
    }

    let indicatif_layer = IndicatifLayer::new()
        .with_max_progress_bars(32, None)
        .with_span_field_formatter(hide_indicatif_span_fields(fmt::format::DefaultFields::new()));

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new("info")
            .add_directive("topiary=off".parse().unwrap())
            .add_directive("build_events=off".parse().unwrap())
            .add_directive("build_events_proto=off".parse().unwrap())
    });

    tracing_subscriber::registry()
        .with(fmt::layer().with_writer(indicatif_layer.get_stderr_writer()))
        .with(indicatif_layer.with_filter(IndicatifFilter::new(false)))
        .with(filter)
        .init();

    let cli = Cli::parse();

    if let Command::Completions(CompletionsArgs { shell }) = &cli.command {
        let mut cmd = Cli::command();
        let name = cmd.get_name().to_string();
        clap_complete::generate(*shell, &mut cmd, name, &mut io::stdout());
        return Ok(());
    }

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

    let mut config = ConfigBuilder::new()
        .with_no_cache(global_args.no_cache)
        .with_no_fetch(global_args.no_fetch);
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

    // `minimal init` is typically run where there exists no `minimal.toml`, so
    // context setup will fail.
    if let Command::Init(args) = command {
        return cmd_init(args, config).await;
    }
    let mut ctx = Context::new(config)?;

    match command {
        Command::Package(args) => cmd_pkg(args, &mut ctx).await,
        Command::Check(args) => cmd_check(args, &mut ctx).await,
        Command::Plan(args) => cmd_plan(args, &mut ctx).await,
        Command::Add(args) => cmd_add(args, &mut ctx).await,
        Command::UploadCache(args) => cmd_upload_cache(args, &mut ctx).await,
        Command::Materialize(args) => cmd_materialize(args, &mut ctx).await,
        Command::PatchedBuild(args) => cmd_patched_build(args, &mut ctx).await,
        #[cfg(target_os = "linux")]
        Command::Run(args) => cmd_run(args, &mut ctx).await,
        Command::Shell => {
            cmd_run(
                RunArgs {
                    task_name: "shell".to_string(),
                },
                &mut ctx,
            )
            .await
        }
        Command::Build => {
            cmd_run(
                RunArgs {
                    task_name: "build".to_string(),
                },
                &mut ctx,
            )
            .await
        }
        Command::Test => {
            cmd_run(
                RunArgs {
                    task_name: "test".to_string(),
                },
                &mut ctx,
            )
            .await
        }
        Command::Update(args) => cmd_update(args, &mut ctx).await,
        Command::Dep(args) => cmd_dep(args, &mut ctx).await,
        Command::Dump(args) => cmd_dump(args, &mut ctx).await,
        Command::Status(args) => cmd_status(args, &mut ctx).await,
        Command::Cache(args) => cmd_cache(args, &mut ctx).await,
        // Handled earlier
        Command::Completions(_) => Ok(()),
        Command::Init(_) => Ok(()),
    }
}
