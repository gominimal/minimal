use clap::Parser;
use graph::{DepGraph, SpecReader, SpecReaderOptions};
use std::path::{Path, PathBuf};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};

mod run;

mod cmd_build;
use cmd_build::{BuildArgs, cmd_build};
mod cmd_plan;
use cmd_plan::{PlanArgs, cmd_plan};

#[derive(Parser)]
#[command(name = "minimal")]
#[command(about = "A minimal package manager")]
enum Cli {
    Build(BuildArgs),
    Plan(PlanArgs),
}

pub fn graph_from_package_name(package_name: &String) -> DepGraph {
    let package_dir = Path::new("packages").join(package_name);

    let build_ncl_path = package_dir.join("build.ncl");
    if !build_ncl_path.exists() {
        eprintln!(
            "Error: build.ncl not found in package directory: {}",
            package_dir.display()
        );
        std::process::exit(1);
    }

    let sr = SpecReader::new_with_path(
        build_ncl_path,
        &SpecReaderOptions {
            minimal_lib_path: "crates/graph/minimal-ncl".into(),
        },
    );

    sr.as_ref().err().into_iter().for_each(|e| {
        e.report_to_stderr();
        panic!("spec parsing failed");
    });
    let sr = sr.unwrap();

    DepGraph::new(sr).unwrap()
}

pub fn load_cache(
    cache_dir: Option<PathBuf>,
) -> Result<cache::Cache<cache::LocalDir>, std::io::Error> {
    cache::Cache::at_dir(cache_dir.unwrap_or_else(|| {
        let dir = dirs::cache_dir().unwrap().join("minimal-builds");
        match std::fs::create_dir(&dir) {
            Ok(_) => {}
            Err(e) => {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    panic!("failed to create build cache dir: {}", e);
                }
            }
        };
        dir
    }))
}

fn main() -> build_sandbox::Result<()> {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .init();

    match Cli::parse() {
        Cli::Build(args) => cmd_build(args),
        Cli::Plan(args) => cmd_plan(args),
    }
}
