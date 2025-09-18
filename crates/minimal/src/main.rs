use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use graph::{DepGraph, Error as GraphError, SpecReader, SpecReaderOptions};
use std::path::{Path, PathBuf};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod lockfile;
mod remote_storage;
mod run;

mod cmd_build;
use cmd_build::{BuildArgs, cmd_build};
mod cmd_plan;
use cmd_plan::{PlanArgs, cmd_plan};
mod cmd_nw_update;
use cmd_nw_update::{NWUpdateArgs, cmd_new_world_update};
mod cmd_oci_image;
use cmd_oci_image::{OciImageArgs, cmd_oci_image};

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
}

/// Shared arguments and builders across all subcommands
#[derive(Args)]
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

    /// Configure the number of parallel builds
    #[arg(short, long, default_value_t = 4)]
    num_parallel_builds: usize,
}

impl GlobalArgs {
    /// Builds and returns an instance of the local cache.
    pub fn cache(&self) -> Result<cache::Cache<cache::LocalDir>, std::io::Error> {
        let dir = match &self.cache_dir {
            None => {
                let dir = dirs::cache_dir().unwrap().join("minimal-builds");
                match std::fs::create_dir_all(&dir) {
                    Ok(_) => {}
                    Err(e) => {
                        if e.kind() != std::io::ErrorKind::AlreadyExists {
                            panic!("failed to create build cache dir: {}", e);
                        }
                    }
                };
                dir
            }
            Some(cache_dir) => cache_dir.to_path_buf(),
        };

        cache::Cache::at_dir(dir)
    }

    pub fn graph_from_package_name(&self, package_name: &String) -> Result<DepGraph, GraphError> {
        let package_dir = match &self.packages_dir {
            Some(dir) => dir,
            None => Path::new("packages"),
        }
        .join(package_name);

        let build_ncl_path = {
            let normal_path = package_dir.join("build.ncl");
            if !normal_path.exists() {
                eprintln!(
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

    pub fn graph_from_package_names(&self, names: &[String]) -> Result<DepGraph, GraphError> {
        let packages_dir = match &self.packages_dir {
            Some(dir) => dir,
            None => Path::new("packages"),
        };

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
        let packages_dir = match &self.packages_dir {
            Some(dir) => dir,
            None => Path::new("packages"),
        };

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
#[derive(Args)]
pub struct PackagesArg {
    /// Package names to build, comma-separated
    #[arg(short, long, alias="package", value_delimiter=',', num_args=0..)]
    packages: Option<Vec<String>>,
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
}

/// Error variants for CLI subcommand results.
pub enum Error {
    Graph(GraphError),
    Other(anyhow::Error),
}

impl Error {
    fn report_to_stderr(&self) {
        match self {
            Error::Graph(e) => e.report_to_stderr(),
            Error::Other(e) => eprintln!("{}", e),
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
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false).with_thread_ids(true))
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .init();

    let cli = Cli::parse();
    let result = match cli.command {
        Command::Build(args) => cmd_build(args, &cli.global_args).await,
        Command::Plan(args) => cmd_plan(args, &cli.global_args).map_err(Error::from),
        Command::NewWorldUpdate(args) => cmd_new_world_update(args, &cli.global_args).await,
        Command::OciImage(args) => cmd_oci_image(args, &cli.global_args).await,
    };

    if let Err(e) = result {
        e.report_to_stderr();
        std::process::exit(1);
    }
    Ok(())
}
