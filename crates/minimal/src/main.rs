#![allow(clippy::result_large_err)]

use anyhow::Result;
use cache::{Cache, LocalDir, RemoteCache, RemoteError};
use clap::{Args, Parser, Subcommand};
use google_cloud_storage::{Error as GcsError, client::Storage as GcsStorage};
use graph::{DepGraph, Error as GraphError, SpecReader, SpecReaderOptions};
use std::path::PathBuf;
use tracing::error;
use tracing_indicatif::IndicatifLayer;
use tracing_indicatif::TickSettings;
use tracing_indicatif::filter::IndicatifFilter;
use tracing_indicatif::filter::hide_indicatif_span_fields;
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
}

/// Shared arguments and builders across all subcommands
#[derive(Debug, Args)]
pub struct GlobalArgs {
    /// Override the directory where binary artifacts are cached
    #[arg(long)]
    cache_dir: Option<PathBuf>,

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
    #[arg(short, long, default_value_t = 4)]
    num_parallel_builds: usize,

    /// Override the output base directory for build workspaces (default: ~/.cache/minimal/sandboxes)
    #[arg(long)]
    output_base: Option<PathBuf>,

    /// Override the download cache directory (default: ~/.cache/minimal/downloads)
    #[arg(long)]
    download_cache_dir: Option<PathBuf>,
}

impl GlobalArgs {
    /// Create the PathConfig based on command line arguments
    pub fn path_config(&self) -> PathConfig {
        let mut config = PathConfig::new();

        if let Some(cache_dir) = &self.cache_dir {
            config = config.with_cache_dir(cache_dir.clone());
        }

        if let Some(download_cache_dir) = &self.download_cache_dir {
            config = config.with_download_cache_dir(download_cache_dir.clone());
        }

        if let Some(output_base) = &self.output_base {
            config = config.with_sandbox_base_dir(output_base.clone());
        }

        if let Some(packages_dir) = &self.packages_dir {
            config = config.with_packages_dir(packages_dir.clone());
        }

        config
    }

    /// Builds and returns an instance of the local cache.
    pub fn cache(&self) -> Result<Cache<LocalDir>, std::io::Error> {
        let path_config = self.path_config();
        let cache_dir = path_config.cache_dir().to_path_buf();

        match std::fs::create_dir_all(&cache_dir) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    panic!("failed to create build cache dir: {}", e);
                }
            }
        };

        Cache::at_dir(cache_dir)
    }

    /// Builds and returns a remote cache with default configurations.
    pub async fn remote_cache(&self) -> Result<RemoteCache<GcsStorage>, RemoteError<GcsError>> {
        RemoteCache::new_with_gcs_bucket(
            GcsStorage::builder().build().await.unwrap(),
            "minimal-staging-cache",
        )
        .await
    }

    pub fn packages_dir(&self) -> PathBuf {
        self.path_config().packages_dir().to_path_buf()
    }

    /// Returns a [DepGraph] with the given package and its transitive dependencies loaded.
    pub fn graph_from_package_name(&self, package_name: &String) -> Result<DepGraph, GraphError> {
        let package_dir = self.packages_dir().join(package_name);

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
                minimal_lib_path: "crates/graph/minimal-ncl".into(),
            },
        )?;

        DepGraph::new(sr)
    }

    #[tracing::instrument]
    pub fn graph_from_package_names(&self, names: &[String]) -> Result<DepGraph, GraphError> {
        let packages_dir = self.packages_dir();

        let sr = SpecReader::new_with_pkgs(
            names,
            packages_dir,
            &SpecReaderOptions {
                minimal_lib_path: "crates/graph/minimal-ncl".into(),
            },
        )?;

        DepGraph::new(sr)
    }

    pub fn graph_from_all_packages(&self) -> Result<DepGraph, GraphError> {
        let packages_dir = self.packages_dir();

        let sr = SpecReader::new_with_all_pkgs(
            packages_dir,
            &SpecReaderOptions {
                minimal_lib_path: "crates/graph/minimal-ncl".into(),
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
    pub fn graph(&self, globals: &GlobalArgs) -> Result<DepGraph, graph::Error> {
        match self.packages {
            Some(ref packages) => match packages.len() {
                0 => globals.graph_from_all_packages(),
                1 => globals.graph_from_package_name(&packages[0]),
                _ => globals.graph_from_package_names(packages),
            },
            None => globals.graph_from_all_packages(),
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
}

impl Error {
    fn report_to_stderr(&self) {
        match self {
            Error::Graph(e) => e.report_to_stderr(),
            Error::Other(e) => eprintln!("{:?}", e),
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

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Build(args) => cmd_build(args, &cli.global_args).await,
        Command::Check(args) => cmd_check(args, &cli.global_args),
        Command::Plan(args) => cmd_plan(args, &cli.global_args).await,
        Command::UploadCache(args) => cmd_upload_cache(args, &cli.global_args).await,
        Command::NewWorldUpdate(args) => cmd_new_world_update(args, &cli.global_args).await,
        Command::OciImage(args) => cmd_oci_image(args, &cli.global_args).await,
    };

    if let Err(e) = result {
        e.report_to_stderr();
        std::process::exit(1);
    }
    Ok(())
}
