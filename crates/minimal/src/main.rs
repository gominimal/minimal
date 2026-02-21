#![allow(clippy::result_large_err)]

use anyhow::anyhow;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use graph::DepGraph;
use mctx::{ConfigBuilder, Context, Error};
use std::io;
use std::path::PathBuf;
use tracing_indicatif::IndicatifLayer;
use tracing_indicatif::{filter::IndicatifFilter, filter::hide_indicatif_span_fields};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use uuid::Uuid;

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
mod shim_listener;
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

    /// Validates and formats nickel build-spec files
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

/// Argument parser for `[--packages <package 1>[,<package N>]]`.
#[derive(Debug, Clone, Args)]
pub struct PackagesArg {
    /// Package names to build, comma-separated
    #[arg(short, long, alias="package", value_delimiter=',', num_args=0..)]
    packages: Option<Vec<String>>,
}

impl std::fmt::Display for PackagesArg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(packages) = &self.packages {
            write!(f, "{}", packages.join(","))
        } else {
            Ok(())
        }
    }
}

impl PackagesArg {
    pub fn names(&self) -> Vec<String> {
        match &self.packages {
            Some(packages) => {
                let mut names = packages.clone();
                names.sort();
                names.dedup();
                names
            }
            None => vec![],
        }
    }

    /// Returns a graph where the top-level is the packages the arguments represent.
    ///  - Non empty: resolve to packages of the specified names.
    ///  - Empty: resolve to all packages in the repo (i.e. not from upstream).
    pub fn resolve(&self, ctx: &mut Context) -> Result<DepGraph, Error> {
        if let Some(p) = &self.packages
            && !p.is_empty()
        {
            return ctx.graph_from_package_names(p.clone());
        }

        // Argument is empty or unset
        let mut graph = ctx.graph_from_all_packages()?;
        graph.top_levels = graph.from_origin(&ctx.repo_origin()?).collect();
        Ok(graph)
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

    // Generate invocation ID for this build
    let invocation_id = Uuid::new_v4().to_string();

    // Initialize global invocation ID and event bus
    build_events::initialize_invocation_id(invocation_id.clone());
    build_events::initialize_global_event_bus();

    let mut dispatcher =
        build_events::BuildEventDispatcher::new(build_events::event_bus().subscribe());

    // Add text file writer if requested
    if let Some(events_file) = &cli.global_args.build_events_file {
        let writer = build_events::subscribers::TextFileWriter::new(events_file)
            .map_err(|e| Error::Other(anyhow!("Failed to create events file writer: {}", e)))?;
        dispatcher.add_subscriber(Box::new(writer));
    }

    // Spawn dispatcher in background and store the join handle
    let dispatcher_handle = tokio::spawn(async move {
        dispatcher.run().await;
    });

    let result = run_cli(cli).await;

    // Close the event bus to signal the dispatcher to shut down gracefully
    build_events::event_bus().close();

    // Wait for dispatcher to complete (which will wait for SpongeBob to log the final URL)
    if let Err(e) = dispatcher_handle.await {
        tracing::warn!("Dispatcher task failed: {}", e);
    }

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

    let mut ctx = Context::new(config.build()?)?;

    match command {
        Command::Init(args) => cmd_init(args, &mut ctx).await,
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
        Command::Completions(_) => Ok(()),
    }
}
