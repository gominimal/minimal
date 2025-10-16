#![allow(clippy::result_large_err)]

use anyhow::{Result, bail};
use cache::{Cache, LocalDir, RemoteCache, RemoteError};
use clap::{Args, Parser, Subcommand};
use google_cloud_storage::{Error as GcsError, client::Storage as GcsStorage};
use graph::{DepGraph, Error as GraphError, PlanErr, SpecReader, SpecReaderOptions};
use std::path::PathBuf;
use tracing::error;
use tracing_indicatif::{IndicatifLayer, TickSettings};
use tracing_indicatif::{filter::IndicatifFilter, filter::hide_indicatif_span_fields};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod lockfile;
mod paths;
mod remote_storage;
mod run;

use paths::PathConfig;

mod cmd_build;
use cmd_build::{BuildArgs, cmd_build};
mod cmd_check;
use cmd_check::{CheckArgs, cmd_check};
mod cmd_plan;
use cmd_plan::{PlanArgs, cmd_plan};
mod cmd_nw_update;
use cmd_nw_update::{NWUpdateArgs, cmd_new_world_update};
mod cmd_oci_image;
use cmd_oci_image::{OciImageArgs, cmd_oci_image};
mod cmd_upload_cache;
use cmd_upload_cache::{UploadArgs, cmd_upload_cache};
mod cmd_patched_build;
use cmd_patched_build::{PatchedBuildArgs, cmd_patched_build};
mod cmd_run;
use cmd_run::{RunArgs, cmd_run};

#[derive(Parser)]
#[command(name = "minimal", version = env!("GIT_HASH"))]
#[command(about = "A minimal package manager")]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global_args: GlobalArgs,
}

#[derive(Subcommand)]
enum Command {
    /// Builds package(s), making them available in the minimal build cache
    Build(BuildArgs),
    /// Prints the build plan for the specified package(s)
    Plan(PlanArgs),
    /// Builds packages which have a prebuilt cycle-breaker, and uploads then + updates their build-specs
    NewWorldUpdate(NWUpdateArgs),
    /// Materializes an OCI container image for executing the specified package
    OciImage(OciImageArgs),
    /// Validates and formats nickel build-spec files
    Check(CheckArgs),
    /// Uploads the specified packages and their transitive needs to the cache.
    UploadCache(UploadArgs),
    /// Updates refreshes local checkouts of the minimal package & standard library.
    Update,
    /// Executes the build for a package, using stale dependencies.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    PatchedBuild(PatchedBuildArgs),
    /// Runs a command using the given packages, in the current working directory.
    #[clap(hide = !std::env::var("MINIMAL_SCIENCE_MODE").is_ok())]
    Run(RunArgs),
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

    /// Override the packages/ directory where build-specs are loaded
    #[arg(long)]
    packages_dir: Option<PathBuf>,

    /// Ignore cached builds (forcing a rebuild)
    #[arg(long, default_value_t = false)]
    no_cache: bool,

    /// Do not fetch completed builds from the internet
    #[arg(long, default_value_t = false)]
    no_fetch: bool,

    /// Configure the number of parallel builds
    #[arg(short, long, default_value_t = default_parallelism())]
    num_parallel_builds: usize,
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

    paths: PathConfig,
    cache: Cache<LocalDir>,
    vcs: checkouts::Manager,

    // TODO: Move back into PathConfig
    stdlib_path: PathBuf,
}

// Initialization of Context
impl Context {
    /// Consumes configuration arguments and sets up shared context for execution.
    pub fn new(args: GlobalArgs) -> Result<Self, Error> {
        let paths = Self::make_path_config(&args);
        paths.ensure_directories().map_err(anyhow::Error::from)?;

        // Setup VCS manager
        let mut vcs = checkouts::Manager::new(paths.vcs_dir()).map_err(anyhow::Error::from)?;
        let stdlib_path = vcs
            .checkout_of(
                "git@github.com:gominimal/std.git",
                checkouts::GitRef::Branch("main".to_string()),
            )
            .map_err(anyhow::Error::from)?;

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

            paths,
            cache,
            vcs,
            stdlib_path,
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

        if let Some(packages_dir) = &args.packages_dir {
            config = config.with_packages_dir(packages_dir.clone());
        }

        config
    }
}

// API surface of Context
impl Context {
    fn stdlib_dir(&self) -> PathBuf {
        self.stdlib_path.clone()
    }

    pub fn vcs_manager(&mut self) -> &mut checkouts::Manager {
        &mut self.vcs
    }
    pub fn local_cache(&self) -> Cache<LocalDir> {
        self.cache.clone()
    }
    pub fn paths(&self) -> &PathConfig {
        &self.paths
    }

    /// Builds and returns a remote cache with default configurations.
    pub async fn remote_cache(&self) -> Result<RemoteCache<GcsStorage>, RemoteError<GcsError>> {
        RemoteCache::new_with_gcs_bucket(
            GcsStorage::builder().build().await.unwrap(),
            "minimal-staging-cache",
        )
        .await
    }

    /// Returns a [DepGraph] with the given package and its transitive dependencies loaded.
    pub fn graph_from_package_name(&self, package_name: &String) -> Result<DepGraph, GraphError> {
        let package_dir = self.paths.packages_dir().join(package_name);

        let build_ncl_path = {
            let normal_path = package_dir.join("build.ncl");
            if !normal_path.exists() {
                error!(
                    "Error: build.ncl not found in package directory: {}",
                    package_dir.display()
                );
                std::process::exit(1);
            }
            normal_path
        };

        let sr = SpecReader::new_with_path(
            &build_ncl_path,
            &SpecReaderOptions {
                minimal_lib_path: self.stdlib_dir(),
            },
        )?;

        DepGraph::new(sr)
    }

    #[tracing::instrument]
    pub fn graph_from_package_names(&self, names: &[String]) -> Result<DepGraph, GraphError> {
        let packages_dir = self.paths.packages_dir();

        let sr = SpecReader::new_with_pkgs(
            names,
            packages_dir,
            &SpecReaderOptions {
                minimal_lib_path: self.stdlib_dir(),
            },
        )?;

        DepGraph::new(sr)
    }

    pub fn graph_from_all_packages(&self) -> Result<DepGraph, GraphError> {
        let packages_dir = self.paths.packages_dir();

        let sr = SpecReader::new_with_all_pkgs(
            packages_dir,
            &SpecReaderOptions {
                minimal_lib_path: self.stdlib_dir(),
            },
        )?;

        DepGraph::new(sr)
    }
}

/// Argument parser for `[--packages <package 1>[,<package N>]]`.
#[derive(Debug, Args)]
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
    pub fn graph(&self, ctx: &mut Context) -> Result<DepGraph, graph::Error> {
        match self.packages {
            Some(ref packages) => match packages.len() {
                0 => ctx.graph_from_all_packages(),
                1 => ctx.graph_from_package_name(&packages[0]),
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
pub enum Error {
    Graph(GraphError),
    Other(anyhow::Error),
    PlanErr(DepGraph, PlanErr),
}

impl Error {
    fn report_to_stderr(&self) {
        match self {
            Error::Graph(e) => e.report_to_stderr(),
            Error::Other(e) => eprintln!("{:?}", e),
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

#[tokio::main]
async fn main() -> Result<()> {
    let indicatif_layer = IndicatifLayer::new()
        .with_max_progress_bars(99, None)
        .with_span_field_formatter(hide_indicatif_span_fields(fmt::format::DefaultFields::new()))
        .with_tick_settings(TickSettings {
            term_draw_hz: 10,
            default_tick_interval: Some(std::time::Duration::from_millis(500)),
            footer_tick_interval: None,
            ..Default::default()
        });
    tracing_subscriber::registry()
        // .with(fmt::layer().with_target(false).with_thread_ids(true))
        .with(fmt::layer().with_writer(indicatif_layer.get_stderr_writer()))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(indicatif_layer.with_filter(IndicatifFilter::new(false)))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new("debug").add_directive("topiary=off".parse().unwrap())
        }))
        .init();

    if let Err(e) = run_cli(Cli::parse()).await {
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
        Command::Check(args) => cmd_check(args, &mut ctx),
        Command::Plan(args) => cmd_plan(args, &mut ctx).await,
        Command::UploadCache(args) => cmd_upload_cache(args, &mut ctx).await,
        Command::NewWorldUpdate(args) => cmd_new_world_update(args, &mut ctx).await,
        Command::OciImage(args) => cmd_oci_image(args, &mut ctx).await,
        Command::PatchedBuild(args) => cmd_patched_build(args, &mut ctx).await,
        Command::Run(args) => cmd_run(args, &mut ctx).await,

        Command::Update => ctx
            .vcs_manager()
            .update()
            .map_err(|e| Error::Other(anyhow::Error::from(e))),
    }
}
