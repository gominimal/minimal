use crate::run::Run;
use build_sandbox::Result;
use cache::Cache;
use graph::{SpecReader, SpecReaderOptions, dep_graph::DepGraph};
use std::path::{Path, PathBuf};

#[derive(clap::Args)]
pub struct BuildArgs {
    /// Package name to build
    #[arg(short, long)]
    package: String,

    /// Launch debug shell instead of building
    #[arg(short, long)]
    debug: bool,

    /// Path to a directory to cache build outputs in
    #[arg(long)]
    cache_dir: Option<PathBuf>,
}

pub fn cmd_build(args: BuildArgs) -> Result<()> {
    let base_package_dir = Path::new("packages");
    let package_name = &args.package;
    let package_dir = base_package_dir.join(package_name);

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

    let dp = DepGraph::new(sr).unwrap();

    let debug_bsr = if args.debug { Some(dp.top_level) } else { None };

    let cache = super::load_cache(args.cache_dir).unwrap();
    let mut run = Run::new(dp, cache);
    run.execute(debug_bsr).unwrap();

    Ok(())
}
