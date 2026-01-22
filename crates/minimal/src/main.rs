#![allow(clippy::result_large_err)]

use anyhow::{Result, anyhow, bail};
use cache::{Cache, LocalDir, RemoteCache, RemoteError};
use checkouts::GitRef;
use clap::{Args, CommandFactory, Parser, Subcommand};
use clap_complete::Shell;
use common::SpecOrigin;
use google_cloud_storage::{Error as GcsError, client::Storage as GcsStorage};
use graph::{DepGraph, Error as GraphError, PlanErr};
use std::io;
use std::path::PathBuf;
use tracing::{trace, warn};
use tracing_indicatif::IndicatifLayer;
use tracing_indicatif::{filter::IndicatifFilter, filter::hide_indicatif_span_fields};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use uuid::Uuid;

mod paths;
use paths::PathConfig;

mod cmd_build;
use cmd_build::{BuildArgs, cmd_build};
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
    /// Builds package(s), making them available in the local cache.
    Build(BuildArgs),
    /// Runs a task specified in `minimal.toml`.
    #[cfg(target_os = "linux")]
    Run(RunArgs),
    /// Materializes an output specified in `minimal.toml`.
    Materialize(MaterializeArgs),
    /// Refreshes local checkouts of upstream packages & the standard library.
    Update(UpdateArgs),

    /// Prints the build plan for the specified package(s)
    Plan(PlanArgs),
    /// Validates and formats nickel build-spec files
    Check(CheckArgs),
    /// Uploads the specified packages and their transitive needs to the cache.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    UploadCache(UploadArgs),
    /// Executes the build for a package, using stale dependencies.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    PatchedBuild(PatchedBuildArgs),
    /// Generates Graphviz source code of the dependency graph
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
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
    /// Override the base directory used for operations (default: ~/.cache/minimal)
    #[arg(long)]
    minimal_dir: Option<PathBuf>,
    /// Override the directory where binary artifacts are cached (default: ~/.cache/minimal/builds)
    #[arg(long, hide = true)]
    cache_dir: Option<PathBuf>,
    /// Override the directory where builds are performed (default: ~/.cache/minimal/sandboxes)
    #[arg(long, hide = true)]
    builds_dir: Option<PathBuf>,
    /// Override the directory where run sandboxes are created (default: ~/.cache/minimal/runs)
    #[arg(long, hide = true)]
    runs_dir: Option<PathBuf>,
    /// Override the directory where downloads are cached (default: ~/.cache/minimal/downloads)
    #[arg(long, hide = true)]
    download_cache_dir: Option<PathBuf>,

    /// Load the minimal standard library from the given path instead
    #[arg(long)]
    stdlib_dir: Option<PathBuf>,
    /// Load the upstream from the given path instead of using `[base]` in `minimal.toml`
    #[arg(long)]
    upstream_dir: Option<PathBuf>,

    /// Ignore locally-available binary artifacts (results in rebuilds unless present in a remote cache)
    #[arg(long, default_value_t = false)]
    no_cache: bool,

    /// Do not fetch binary artifacts from the internet
    #[arg(long, default_value_t = false)]
    no_fetch: bool,

    /// Configure the number of parallel builds
    #[arg(short, long, default_value_t = default_parallelism())]
    num_parallel_builds: usize,

    /// Write build events to a protobuf text format file
    #[arg(long)]
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    build_events_file: Option<PathBuf>,
}

fn default_parallelism() -> usize {
    let rough_threadcount = std::thread::available_parallelism().unwrap().get();
    match rough_threadcount {
        1..=3 => 1,
        4 => 3,
        _ => rough_threadcount - 2,
    }
}

pub(crate) fn enforce_science_mode() -> Result<()> {
    if std::env::var("MINIMAL_SCIENCE_MODE").unwrap_or("".to_string()) != "yeppers" {
        eprintln!("You are using a command that is experimental or very unsafe!!");
        eprintln!(
            "No guarantees are given about the consistency of your minimal install following the execution of such commands, nor the stability of any such commands."
        );
        eprintln!(
            "If you are sure you want to continue, set the environment variable MINIMAL_SCIENCE_MODE=yeppers before continuing."
        );
        eprintln!();

        bail!("Aborting execution of unsafe command outside of science mode");
    }
    Ok(())
}

/// Shared state describing the invocation of minimal functions.
#[derive(Debug)]
pub struct Context {
    pub no_cache: bool,
    pub no_fetch: bool,
    pub num_parallel_builds: usize,

    upstream_dir_and_origin: Option<(PathBuf, SpecOrigin)>,
    stdlib_dir_and_origin: Option<(PathBuf, SpecOrigin)>,

    mfile: Option<mfile::File>,
    upstream_dir_override: Option<PathBuf>,
    stdlib_dir_override: Option<PathBuf>,
    paths: PathConfig,
    cache: Cache<LocalDir>,
    vcs: checkouts::Manager,
}

// Initialization of Context
impl Context {
    /// Consumes configuration arguments and sets up shared context for execution.
    pub fn new(args: GlobalArgs) -> Result<Self, Error> {
        let paths = Self::make_path_config(&args);
        paths.ensure_directories().map_err(anyhow::Error::from)?;

        // Setup VCS manager
        let vcs = checkouts::Manager::new(paths.vcs_dir()).map_err(anyhow::Error::from)?;

        // Setup local cache
        let cache_dir = paths.cache_dir().to_path_buf();
        match std::fs::create_dir_all(&cache_dir) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return Err(anyhow::Error::from(e).into());
                }
            }
        };
        let cache = Cache::at_dir(cache_dir).map_err(anyhow::Error::from)?;

        Ok(Self {
            no_cache: args.no_cache,
            no_fetch: args.no_fetch,
            num_parallel_builds: args.num_parallel_builds,
            upstream_dir_override: args.upstream_dir,
            stdlib_dir_override: args.stdlib_dir,

            upstream_dir_and_origin: None,
            stdlib_dir_and_origin: None,
            mfile: None,

            paths,
            cache,
            vcs,
        })
    }

    fn make_path_config(args: &GlobalArgs) -> PathConfig {
        let mut config = if let Some(base_dir) = &args.minimal_dir {
            PathConfig::new_with_base(base_dir.clone())
        } else {
            PathConfig::new()
        };

        if let Some(cache_dir) = &args.cache_dir {
            config = config.with_cache_dir(cache_dir.clone());
        }
        if let Some(download_cache_dir) = &args.download_cache_dir {
            config = config.with_download_cache_dir(download_cache_dir.clone());
        }
        if let Some(builds_dir) = &args.builds_dir {
            config = config.with_sandbox_base_dir(builds_dir.clone());
        }
        if let Some(runs_dir) = &args.runs_dir {
            config = config.with_run_base_dir(runs_dir.clone());
        }

        config
    }
}

// API surface of Context
impl Context {
    pub fn vcs_manager(&mut self) -> &mut checkouts::Manager {
        &mut self.vcs
    }
    pub fn local_cache(&self) -> Cache<LocalDir> {
        self.cache.clone()
    }
    pub fn paths(&self) -> &PathConfig {
        &self.paths
    }

    /// Returns the path to the stdlib directory as well as info about where its from.
    ///
    /// This is computed either from the `--stdlib-dir` argument or the minimal file.
    /// The result is cached for future invocations.
    pub fn stdlib_dir_and_origin(&mut self) -> Result<(PathBuf, SpecOrigin), Error> {
        if let Some(dir) = &self.stdlib_dir_override {
            return Ok((dir.clone(), SpecOrigin::from_dir(dir)));
        }
        if let Some(res) = &self.stdlib_dir_and_origin {
            return Ok(res.clone());
        }

        let minimal_file = self.minimal_file()?.clone();

        let git_ref: GitRef = (&minimal_file.stdlib).into();
        let (dir, git_hash) = self
            .vcs
            .checkout_of(&minimal_file.stdlib.repo, git_ref.clone())
            .map_err(anyhow::Error::from)?;
        self.stdlib_dir_and_origin = Some((
            dir,
            SpecOrigin::Repo(git_ref.as_repo(minimal_file.stdlib.repo, git_hash)),
        ));
        Ok(self.stdlib_dir_and_origin.as_ref().unwrap().clone())
    }

    /// Returns the path to the upstream directory as well as info about where its from.
    ///
    /// This is computed either from the `--upstream-dir` argument or the minimal file.
    /// The result is cached for future invocations.
    fn upstream_dir_and_origin(&mut self) -> Result<(PathBuf, SpecOrigin), Error> {
        if let Some(dir) = &self.upstream_dir_override {
            return Ok((dir.clone(), SpecOrigin::from_dir(dir)));
        }
        if let Some(res) = &self.upstream_dir_and_origin {
            return Ok(res.clone());
        }

        let minimal_file = self.minimal_file()?.clone();

        let git_ref: GitRef = (&minimal_file.upstream).into();
        let (dir, git_hash) = self
            .vcs
            .checkout_of(&minimal_file.upstream.repo, git_ref.clone())
            .map_err(anyhow::Error::from)?;

        self.upstream_dir_and_origin = Some((
            dir,
            SpecOrigin::Repo(git_ref.as_repo(minimal_file.upstream.repo, git_hash)),
        ));
        Ok(self.upstream_dir_and_origin.as_ref().unwrap().clone())
    }

    /// Returns the decoded minimal-file, reading it from disk if necessary.
    pub fn minimal_file(&mut self) -> Result<&mfile::File, Error> {
        if self.mfile.is_none() {
            trace!("loading minimal file");
            self.mfile = Some(mfile::File::from_dir(std::env::current_dir().unwrap())?);
        }
        Ok(self.mfile.as_ref().unwrap())
    }

    /// Builds and returns a remote cache with default configurations.
    pub async fn remote_cache(
        &self,
        auth: bool,
    ) -> Result<RemoteCache<GcsStorage>, RemoteError<GcsError>> {
        let backend = if auth {
            GcsStorage::builder().build().await.unwrap()
        } else {
            GcsStorage::builder()
                .with_credentials(google_cloud_auth::credentials::anonymous::Builder::new().build())
                .build()
                .await
                .unwrap()
        };

        RemoteCache::new_with_gcs_bucket(backend, "minimal-staging-cache").await
    }

    #[tracing::instrument]
    pub fn graph_from_package_names(&mut self, names: &[String]) -> Result<DepGraph, Error> {
        let mut graph = self.graph_from_all_packages()?;
        graph.top_levels = names
            .iter()
            .map(|n| match graph.by_name(n) {
                Some(bsr) => Ok(*bsr),
                None => Err(Error::Other(anyhow!("No such package: {}", n))),
            })
            .collect::<Result<_, _>>()?;

        Ok(graph)
    }

    pub fn graph_from_all_packages(&mut self) -> Result<DepGraph, Error> {
        let (_dir, origin) = self.upstream_dir_and_origin()?;

        let stdlib_dir = self.stdlib_dir_and_origin()?.0;
        DepGraph::new_from_chain(self.vcs_manager(), origin, stdlib_dir).map_err(Error::Graph)
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
    /// Returns a [DepGraph] containing the named packages, or all packages if none were specified.
    pub fn graph(&self, ctx: &mut Context) -> Result<DepGraph, Error> {
        match self.packages {
            Some(ref packages) => match packages.len() {
                0 => ctx.graph_from_all_packages(),
                _ => ctx.graph_from_package_names(packages),
            },
            None => ctx.graph_from_all_packages(),
        }
    }

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
}

/// Error variants for CLI subcommand results.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum Error {
    MFile(mfile::Error),
    Graph(GraphError),
    Other(anyhow::Error),
    PlanErr(DepGraph, PlanErr),
}

impl Error {
    fn report_to_stderr(&self) {
        match self {
            Error::Graph(e) => e.report_to_stderr(),
            Error::Other(e) => eprintln!("{:?}", e),
            Error::MFile(e) => eprintln!("minimal file: {:?}", e),
            Error::PlanErr(graph, err) => match err {
                PlanErr::Cycles(cycles) => {
                    eprintln!(
                        "Planning failed: unable to progress with unresolvable dependency cycles"
                    );
                    eprintln!("Cycles:");
                    for c in cycles {
                        eprintln!(
                            "\t{}",
                            c.iter()
                                .map(|bsr| graph.get(bsr).unwrap().name.clone())
                                .collect::<Vec<_>>()
                                .join(" -> "),
                        )
                    }
                }
            },
        }
    }
}

impl From<mfile::Error> for Error {
    fn from(e: mfile::Error) -> Self {
        Self::MFile(e)
    }
}
impl From<GraphError> for Error {
    fn from(e: GraphError) -> Self {
        Self::Graph(e)
    }
}
impl From<anyhow::Error> for Error {
    fn from(e: anyhow::Error) -> Self {
        Self::Other(e)
    }
}
impl From<common::GlobError> for Error {
    fn from(e: common::GlobError) -> Self {
        match e {
            common::GlobError::IO(e) => Self::Other(e.into()),
            common::GlobError::Glob(e) => Self::Other(e.into()),
        }
    }
}
impl From<op::Error> for Error {
    fn from(e: op::Error) -> Self {
        match e {
            op::Error::IO(e) => Self::Other(e.into()),
            op::Error::Cache(e) => Self::Other(e.into()),
            op::Error::Other(e) => Self::Other(e),
            op::Error::Plan(graph, e) => Self::PlanErr(graph, e),
        }
    }
}
impl From<orchestrator::Error> for Error {
    fn from(e: orchestrator::Error) -> Self {
        match e {
            orchestrator::Error::IO(e) => Self::Other(e.into()),
            orchestrator::Error::Cache(e) => Self::Other(e.into()),
            orchestrator::Error::Other(e) => Self::Other(e),
            orchestrator::Error::Plan(graph, e) => Self::PlanErr(graph, e),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
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

    // Initialize SpongeBob integration
    let mut dispatcher =
        build_events::BuildEventDispatcher::new(build_events::event_bus().subscribe());
    match build_events_proto::SpongeBob::new(invocation_id).await {
        Ok(sb) => {
            dispatcher.add_subscriber(Box::new(sb));
        }
        Err(e) => {
            warn!("Failed to create SpongeBob client: {}", e);
        }
    };

    // Add text file writer if requested
    if let Some(events_file) = &cli.global_args.build_events_file {
        let writer = build_events::subscribers::TextFileWriter::new(events_file)
            .map_err(|e| anyhow::anyhow!("Failed to create events file writer: {}", e))?;
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
    let mut ctx = Context::new(global_args)?;

    match command {
        Command::Build(args) => cmd_build(args, &mut ctx).await,
        Command::Check(args) => cmd_check(args, &mut ctx).await,
        Command::Plan(args) => cmd_plan(args, &mut ctx).await,
        Command::UploadCache(args) => cmd_upload_cache(args, &mut ctx).await,
        Command::Materialize(args) => cmd_materialize(args, &mut ctx).await,
        Command::PatchedBuild(args) => cmd_patched_build(args, &mut ctx).await,
        #[cfg(target_os = "linux")]
        Command::Run(args) => cmd_run(args, &mut ctx).await,
        Command::Update(args) => cmd_update(args, &mut ctx).await,
        Command::Dep(args) => cmd_dep(args, &mut ctx).await,
        Command::Completions(_) => Ok(()),
    }
}
